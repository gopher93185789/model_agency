package main

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/a-h/templ"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/gopher93185789/model_agency/pkg/types"
	"github.com/gopher93185789/model_agency/src/pages"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/patrickmn/go-cache"
	"golang.org/x/crypto/bcrypt"
)

//go:embed public/**
var staticFs embed.FS

const sessionCookieName string = "duke_dennis"
const sessionExp = 6 * time.Hour
const middlewareToken = "token"

// No object storage; images stored in Postgres as BYTEA.

type ServerContext struct {
	database *pgxpool.Pool
	cache    *cache.Cache
}

func NewServerContext(database *pgxpool.Pool) *ServerContext {
	return &ServerContext{
		database: database,
		cache:    cache.New(5*time.Minute, 1*time.Minute),
	}
}

/*****************************************************
 *                    JWT HELPERS                     *
 *****************************************************/

type Claims struct {
	UserID     string `json:"user_id"`
	Role       string `json:"role"`
	ProfileUrl string `json:"profile_url"`
	jwt.RegisteredClaims
}

var jwtKey []byte

func (s *ServerContext) createToken(userId uuid.UUID, role string, profileUrl string) (string, time.Time, error) {
	exp := time.Now().Add(sessionExp)
	claims := &Claims{
		UserID:     userId.String(),
		Role:       role,
		ProfileUrl: profileUrl,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(exp),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(jwtKey)
	return signed, exp, err
}

func (s *ServerContext) parseToken(tokenStr string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (any, error) {
		return jwtKey, nil
	})
	if err != nil {
		return nil, err
	}
	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}
	return nil, fmt.Errorf("invalid token")
}

/**
 *                  IMAGE HELPERS                   *
 */
func randomImageName() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func toBase64(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	return base64.StdEncoding.EncodeToString(data)
}

/***********************************************
 *                  HELPERS                    *
 ***********************************************/
func respondWithJson[P any](w http.ResponseWriter, code int, payload P) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	err := json.NewEncoder(w).Encode(payload)
	if err != nil {
		log.Printf("Error encoding JSON response: %v", err)
		return
	}
}

func hashPassword(password string) (hash []byte, err error) {
	return bcrypt.GenerateFromPassword([]byte(password), 5)
}

func (s *ServerContext) validateSession(r *http.Request) (string, bool) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil || cookie.Value == "" {
		return "", false
	}

	tokenStr := cookie.Value
	_, err = s.parseToken(tokenStr)
	if err != nil {
		return "", false
	}
	return tokenStr, true
}

// ---------------------- CACHE HELPERS ----------------------

// responseCapturer is a helper that lets us "steal" the HTML
// as it's being written so we can save it to the cache.
type responseCapturer struct {
	http.ResponseWriter
	body []byte
}

func (w *responseCapturer) Write(b []byte) (int, error) {
	w.body = append(w.body, b...)
	return w.ResponseWriter.Write(b)
}

// CacheRoute is the actual middleware function.
// It checks if we have the page saved. If yes, it shows it instantly.
// If no, it lets the page load, saves it, and then remembers it for next time.
func (s *ServerContext) CacheRoute(next http.HandlerFunc, duration time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Use the specific URL (e.g., "/model/alex") as the ID for the saved page
		key := "route_" + r.URL.String()

		// 1. Check if we already have this page saved
		if data, found := s.cache.Get(key); found {
			// Add a special sticker so you know it came from cache
			w.Header().Set("X-Cache", "HIT")
			w.Write(data.([]byte))
			return
		}

		// 2. If not found, prepare to capture the new page
		capturer := &responseCapturer{ResponseWriter: w}

		// Run the actual page logic
		next(capturer, r)

		// 3. Save the result for next time
		if len(capturer.body) > 0 {
			s.cache.Set(key, capturer.body, duration)
		}
	}
}

/**************************************************
 *                  MIDDLEWARE                    *
 **************************************************/

func (s *ServerContext) AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sessionid, ok := s.validateSession(r)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		r.Header.Set(middlewareToken, sessionid)
		next.ServeHTTP(w, r)
	}
}

/********************************************
 *                  AUTH                    *
 ********************************************/
// not allowed to signup as docent because we will manully protmote them
// to make the html form work change enc type to multipart
func (s *ServerContext) Signup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if err := r.ParseMultipartForm(3e+7); err != nil {
		http.Redirect(w, r, "/signup?err=Failed+to+parse+form", http.StatusSeeOther)
		return
	}

	var (
		schoolEmail = r.FormValue("school_email")
		name        = r.FormValue("name")
		password    = r.FormValue("password")
		role        = r.FormValue("role")
		hasFile     = false
		approved    = false
	)
	imageFile, _, err := r.FormFile("profile_image")
	if err == nil {
		hasFile = true
		defer imageFile.Close()
	}

	if schoolEmail == "" || name == "" || password == "" || role == "" {
		http.Redirect(w, r, "/signup?err=All+fields+are+required", http.StatusSeeOther)
		return
	}

	emailPattern := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@glr\.nl$`)
	if !emailPattern.MatchString(schoolEmail) {
		http.Redirect(w, r, "/signup?err=Email+must+end+with+@glr.nl", http.StatusSeeOther)
		return
	}

	if role != "model" && role != "fotograaf" {
		http.Redirect(w, r, "/signup?err=Invalid+role+selected", http.StatusSeeOther)
		return
	}

	if role == "fotograaf" {
		approved = true
	}

	passwordHash, err := hashPassword(password)
	if err != nil {
		log.Printf("Password hashing failed: %v", err)
		http.Redirect(w, r, "/signup?err=Internal+server+error", http.StatusSeeOther)
		return
	}

	query := `
		WITH user_i AS (
			INSERT INTO app_users (role, school_email, name, password_hash) 
			VALUES ($1, $2, $3, $4) 
			RETURNING id
		)
		INSERT INTO profile (user_id, approved) 
		SELECT id, $5
		FROM user_i
		RETURNING id
	`

	var profileId uuid.UUID
	err = s.database.QueryRow(ctx, query,
		role,
		schoolEmail,
		name,
		string(passwordHash),
		approved,
	).Scan(&profileId)

	// read file and store bytes directly
	if hasFile {
		imageData, err := io.ReadAll(imageFile)
		if err != nil {
			http.Redirect(w, r, "/signup?err=Failed+to+read+image", http.StatusSeeOther)
			return
		}

		// basic MIME allow-list
		mime := http.DetectContentType(imageData)
		switch {
		case strings.HasPrefix(mime, "image/jpeg"), strings.HasPrefix(mime, "image/png"), strings.HasPrefix(mime, "image/webp"):
			// ok
		default:
			http.Redirect(w, r, "/signup?err=Unsupported+image+type", http.StatusSeeOther)
			return
		}

		randomName, err := randomImageName()
		if err != nil {
			http.Redirect(w, r, "/signup?err=Failed+to+create+image+name", http.StatusSeeOther)
			return
		}

		q := `
			UPDATE profile
			SET profile_image_name = $2,
				profile_image_data = $3
			WHERE id = $1
		`

		_, err = s.database.Exec(ctx, q, profileId, randomName, imageData)
		if err != nil {
			http.Redirect(w, r, "/signup?err=Failed+to+save+image", http.StatusSeeOther)
			return
		}
	}

	if err != nil {
		log.Printf("Database insert failed: %v", err)
		if err.Error() == "duplicate key value violates unique constraint" {
			http.Redirect(w, r, "/signup?err=Email+already+registered", http.StatusSeeOther)
			return
		}

		http.Redirect(w, r, "/signup?err=Failed+to+create+account", http.StatusSeeOther)
		return
	}

	// maybe we can redirect oto home with a queryparam modal
	// that if not empty can show a modal popup sayting  "waiting for a docent to approve your profile" fr better UX
	http.Redirect(w, r, "/overview", http.StatusSeeOther)
}

func (s *ServerContext) Login(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/login?err=Failed+to+parse+form", http.StatusSeeOther)
		return
	}

	schoolEmail := r.FormValue("school_email")
	password := r.FormValue("password")

	if schoolEmail == "" || password == "" {
		http.Redirect(w, r, "/login?err=Email+and+password+required", http.StatusSeeOther)
		return
	}

	var (
		id           uuid.UUID
		passwordHash []byte
		role         string
		query        = `
		SELECT id, password_hash, role 
		FROM app_users 
		WHERE school_email=$1 
		`
	)

	err := s.database.QueryRow(ctx, query, schoolEmail).Scan(&id, &passwordHash, &role)
	if err != nil {
		if strings.Contains(err.Error(), "no rows in result set") {
			http.Redirect(w, r, "/signup", http.StatusSeeOther)
			return
		}

		log.Printf("Database query failed: %v", err)
		http.Redirect(w, r, "/login?err=Invalid+credentials", http.StatusSeeOther)
		return
	}

	if err := bcrypt.CompareHashAndPassword(passwordHash, []byte(password)); err != nil {
		http.Redirect(w, r, "/login?err=Invalid+credentials", http.StatusSeeOther)
		return
	}

	tokenStr, exp, err := s.createToken(id, role, "")
	if err != nil {
		log.Printf("Failed to create token: %v", err)
		http.Redirect(w, r, "/login?err=Internal+server+error", http.StatusSeeOther)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    tokenStr,
		Expires:  exp,
		HttpOnly: true,
		Secure:   true,
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
	})

	// Redirect to overview page on successful login
	http.Redirect(w, r, "/overview", http.StatusSeeOther)
}

func (s *ServerContext) Logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		MaxAge:   -1,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *ServerContext) GetModelInfo(userid uuid.UUID) (*types.ModelFullInfo, error) {
	q := `
	SELECT 
		u.id AS user_id,
		u.name,
		u.school_email,
		p.profile_image_name,
		p.profile_image_data,
		p.description,
		COALESCE(m.location, '') as location,
		COALESCE(m.total_shots, 0) as total_shots,
		COALESCE(m.height, 0) as height,
		COALESCE(m.bust, 0) as bust,
		COALESCE(m.waist, 0) as waist,
		COALESCE(m.hips, 0) as hips
	FROM app_users u
	JOIN profile p ON u.id = p.user_id
	LEFT JOIN model_info m ON p.id = m.id
	WHERE u.id = $1 AND u.role = 'model'
	`

	var (
		info       types.ModelFullInfo
		imageName  *string
		imageBytes []byte
		location   string
	)
	err := s.database.QueryRow(context.Background(), q, userid).Scan(
		&info.UserID,
		&info.Name,
		&info.SchoolEmail,
		&imageName,
		&imageBytes,
		&info.Description,
		&location,
		&info.TotalShots,
		&info.Height,
		&info.Bust,
		&info.Waist,
		&info.Hips,
	)
	if err != nil {
		return nil, err
	}

	info.ProfileImageName = imageName
	info.Location = &location
	if len(imageBytes) > 0 {
		b64 := toBase64(imageBytes)
		info.ProfileImageBase64 = &b64
	}

	return &info, nil
}

func (s *ServerContext) GetPortfolioImages(userID uuid.UUID) ([]types.PortfolioImage, error) {
	q := `
	SELECT pi.id, pi.image_data
	FROM portfolio_images pi
	JOIN profile p ON pi.profile_id = p.id
	WHERE p.user_id = $1
	ORDER BY pi.created_at DESC
	`

	rows, err := s.database.Query(context.Background(), q, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var images []types.PortfolioImage
	for rows.Next() {
		var img types.PortfolioImage
		var imageData []byte
		if err := rows.Scan(&img.ID, &imageData); err != nil {
			continue
		}
		if len(imageData) > 0 {
			img.Base64 = toBase64(imageData)
		}
		images = append(images, img)
	}

	return images, nil
}

func (s *ServerContext) GetFotograafInfo(userid uuid.UUID) (*types.FotograafInfo, error) {
	q := `
	SELECT 
		u.id AS user_id,
		u.name,
		u.school_email,
		p.profile_image_name,
		p.profile_image_data,
		p.description
	FROM app_users u
	JOIN profile p ON u.id = p.user_id
	WHERE u.id = $1 AND u.role = 'fotograaf'
	`

	var (
		info       types.FotograafInfo
		imageName  *string
		imageBytes []byte
	)
	err := s.database.QueryRow(context.Background(), q, userid).Scan(
		&info.UserID,
		&info.Name,
		&info.SchoolEmail,
		&imageName,
		&imageBytes,
		&info.Description,
	)
	if err != nil {
		return nil, err
	}

	info.ProfileImageName = imageName
	if len(imageBytes) > 0 {
		b64 := toBase64(imageBytes)
		info.ProfileImageBase64 = &b64
	}

	return &info, nil
}

func (s *ServerContext) GetFotograafOverviewInfo() ([]types.ModelOverviewInfo, error) {
	q := `
	SELECT 
		u.id,
		u.name,
		LOWER(REPLACE(REPLACE(u.name, ' ', '-'), '.', '')) as slug,
		p.description,
		p.profile_image_name,
		p.profile_image_data
	FROM app_users u
	JOIN profile p ON u.id = p.user_id
	WHERE u.role = 'model'
	`

	rows, err := s.database.Query(context.Background(), q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var models []types.ModelOverviewInfo
	for rows.Next() {
		var (
			info       types.ModelOverviewInfo
			imageName  *string
			imageBytes []byte
		)
		if err := rows.Scan(&info.UserID, &info.Name, &info.Slug, &info.Description, &imageName, &imageBytes); err != nil {
			return nil, err
		}
		info.ProfileImageName = imageName
		if len(imageBytes) > 0 {
			b64 := toBase64(imageBytes)
			info.ProfileImageBase64 = &b64
		}
		models = append(models, info)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return models, nil
}

func (s *ServerContext) GetModelBySlug(slug string) (*pages.ModelData, error) {
	q := `
	SELECT 
		u.id,
		u.name,
		u.school_email,
		COALESCE(p.description, '') as description,
		COALESCE(encode(p.profile_image_data, 'base64'), '') as profile_image_base64,
		COALESCE(m.height, 0) as height,
		COALESCE(m.bust, 0) as bust,
		COALESCE(m.waist, 0) as waist,
		COALESCE(m.hips, 0) as hips,
		COALESCE(m.location, '') as location,
		COALESCE(m.total_shots, 0) as total_shots
	FROM app_users u
	JOIN profile p ON u.id = p.user_id
	LEFT JOIN model_info m ON p.id = m.id
	WHERE u.role = 'model' AND LOWER(REPLACE(REPLACE(u.name, ' ', '-'), '.', '')) = $1
	`

	var userID uuid.UUID
	var name, email, description, profileImageBase64, location string
	var height, bust, waist, hips, totalShots int

	err := s.database.QueryRow(context.Background(), q, slug).Scan(
		&userID, &name, &email, &description, &profileImageBase64,
		&height, &bust, &waist, &hips, &location, &totalShots,
	)
	if err != nil {
		return nil, err
	}

	// Fetch portfolio images
	portfolioImages, _ := s.GetPortfolioImages(userID)
	var portfolioData []pages.PortfolioItem
	for _, img := range portfolioImages {
		portfolioData = append(portfolioData, pages.PortfolioItem{
			ID:     img.ID.String(),
			Base64: img.Base64,
		})
	}

	return &pages.ModelData{
		ProfileImageBase64: profileImageBase64,
		Name:               name,
		TotalShoots:        totalShots,
		Email:              email,
		Location:           location,
		Bio:                description,
		Portfolio:          portfolioData,
		Measurements: pages.Measurements{
			Height: fmt.Sprintf("%d", height),
			Bust:   fmt.Sprintf("%d", bust),
			Waist:  fmt.Sprintf("%d", waist),
			Hips:   fmt.Sprintf("%d", hips),
		},
		Editable: false,
	}, nil
}

func (s *ServerContext) GetFotograafBySlug(slug string) (*pages.FotograafData, error) {
	q := `
	SELECT 
		u.name,
		u.school_email,
		COALESCE(p.description, '') as description,
		COALESCE(encode(p.profile_image_data, 'base64'), '') as profile_image_base64
	FROM app_users u
	JOIN profile p ON u.id = p.user_id
	WHERE u.role = 'fotograaf' AND LOWER(REPLACE(REPLACE(u.name, ' ', '-'), '.', '')) = $1
	`

	var name, email, description, profileImageBase64 string

	err := s.database.QueryRow(context.Background(), q, slug).Scan(
		&name, &email, &description, &profileImageBase64,
	)
	if err != nil {
		return nil, err
	}

	return &pages.FotograafData{
		ProfileImageBase64: profileImageBase64,
		Name:               name,
		Email:              email,
		Bio:                description,
		Portfolio:          []string{},
	}, nil
}

/*********************************************
 *                  PAGES                    *
 *********************************************/
func (s *ServerContext) overviewPage(w http.ResponseWriter, r *http.Request) {
	var (
		page templ.Component
	)

	sid := r.Header.Get(middlewareToken)
	if sid == "" {
		if token, ok := s.validateSession(r); ok {
			sid = token
		} else {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
	}

	if p, ok := s.cache.Get(sid); ok {
		if v, ok := p.(templ.Component); ok {
			root(v).Render(r.Context(), w)
			return
		}
	}

	claims, err := s.parseToken(sid)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	switch claims.Role {
	case "docent":
		page = pages.Docent()
		s.cache.Set(sid, page, cache.DefaultExpiration)
	case "model":
		// Models don't have an overview page, redirect to their private profile
		http.Redirect(w, r, "/profile", http.StatusSeeOther)
		return
	case "fotograaf":
		// since the model will have multiple db results we can try to implement
		// https://templ.guide/server-side-rendering/streaming
		// never used it but it looks cool

		models, err := s.GetFotograafOverviewInfo()
		if err != nil {
			// TODO: handle error properly
			return
		}

		page = pages.Fotograaf(models)
		s.cache.Set(sid, page, cache.DefaultExpiration)
	default:
		http.Redirect(w, r, "/", http.StatusPermanentRedirect)
		return
	}

	root(page).Render(r.Context(), w)

}

func (s *ServerContext) modelPublicPage(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	if slug == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	modelData, err := s.GetModelBySlug(slug)
	if err != nil {
		log.Printf("Error fetching model by slug '%s': %v", slug, err)
		root(pages.NotFound()).Render(r.Context(), w)
		return
	}

	root(pages.ModelPublic(*modelData)).Render(r.Context(), w)
}

func (s *ServerContext) fotograafPublicPage(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	if slug == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	fotograafData, err := s.GetFotograafBySlug(slug)
	if err != nil {
		log.Printf("Error fetching fotograaf by slug '%s': %v", slug, err)
		root(pages.NotFound()).Render(r.Context(), w)
		return
	}

	root(pages.FotograafPublic(*fotograafData)).Render(r.Context(), w)
}

func (s *ServerContext) modelPrivatePage(w http.ResponseWriter, r *http.Request) {
	sid := r.Header.Get(middlewareToken)
	if sid == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	claims, err := s.parseToken(sid)
	if err != nil || claims.Role != "model" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	userID, err := uuid.Parse(claims.UserID)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	modelInfo, err := s.GetModelInfo(userID)
	if err != nil {
		log.Printf("Error fetching model info: %v", err)
		root(pages.NotFound()).Render(r.Context(), w)
		return
	}

	profileImage := ""
	if modelInfo.ProfileImageBase64 != nil {
		profileImage = *modelInfo.ProfileImageBase64
	}

	description := ""
	if modelInfo.Description != nil {
		description = *modelInfo.Description
	}

	location := ""
	if modelInfo.Location != nil {
		location = *modelInfo.Location
	}

	portfolioImages, _ := s.GetPortfolioImages(userID)
	var portfolioData []pages.PortfolioItem
	for _, img := range portfolioImages {
		portfolioData = append(portfolioData, pages.PortfolioItem{
			ID:     img.ID.String(),
			Base64: img.Base64,
		})
	}

	modelData := pages.ModelData{
		ProfileImageBase64: profileImage,
		Name:               modelInfo.Name,
		TotalShoots:        modelInfo.TotalShots,
		Email:              modelInfo.SchoolEmail,
		Location:           location,
		Bio:                description,
		Portfolio:          portfolioData,
		Measurements: pages.Measurements{
			Height: fmt.Sprintf("%d", modelInfo.Height),
			Bust:   fmt.Sprintf("%d", modelInfo.Bust),
			Waist:  fmt.Sprintf("%d", modelInfo.Waist),
			Hips:   fmt.Sprintf("%d", modelInfo.Hips),
		},
		Editable: true,
	}

	root(pages.ModelPrivate(modelData)).Render(r.Context(), w)
}

func (s *ServerContext) fotograafPrivatePage(w http.ResponseWriter, r *http.Request) {
	sid := r.Header.Get(middlewareToken)
	if sid == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	claims, err := s.parseToken(sid)
	if err != nil || claims.Role != "fotograaf" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	userID, err := uuid.Parse(claims.UserID)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	fotograafInfo, err := s.GetFotograafInfo(userID)
	if err != nil {
		log.Printf("Error fetching fotograaf info: %v", err)
		root(pages.NotFound()).Render(r.Context(), w)
		return
	}

	profileImage := ""
	if fotograafInfo.ProfileImageBase64 != nil {
		profileImage = *fotograafInfo.ProfileImageBase64
	}

	description := ""
	if fotograafInfo.Description != nil {
		description = *fotograafInfo.Description
	}

	fotograafData := pages.FotograafData{
		ProfileImageBase64: profileImage,
		Name:               fotograafInfo.Name,
		Email:              fotograafInfo.SchoolEmail,
		Bio:                description,
		Portfolio:          []string{},
	}

	root(pages.FotograafPrivate(fotograafData)).Render(r.Context(), w)
}

func (s *ServerContext) UpdateProfile(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sid := r.Header.Get(middlewareToken)
	if sid == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	claims, err := s.parseToken(sid)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	userID, err := uuid.Parse(claims.UserID)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	if err := r.ParseMultipartForm(10 << 20); err != nil {
		http.Redirect(w, r, "/profile?err=Failed+to+parse+form", http.StatusSeeOther)
		return
	}

	role := r.FormValue("role")
	bio := r.FormValue("bio")

	q := `UPDATE profile SET description = $2 WHERE user_id = $1`
	_, err = s.database.Exec(ctx, q, userID, bio)
	if err != nil {
		log.Printf("Failed to update profile: %v", err)
		http.Redirect(w, r, "/profile?err=Failed+to+update+profile", http.StatusSeeOther)
		return
	}

	imageFile, _, err := r.FormFile("profile_image")
	if err == nil {
		defer imageFile.Close()
		imageData, err := io.ReadAll(imageFile)
		if err == nil && len(imageData) > 0 {
			mime := http.DetectContentType(imageData)
			if strings.HasPrefix(mime, "image/") {
				randomName, _ := randomImageName()
				q := `UPDATE profile SET profile_image_name = $2, profile_image_data = $3 WHERE user_id = $1`
				s.database.Exec(ctx, q, userID, randomName, imageData)
			}
		}
	}

	if role == "model" {
		location := r.FormValue("location")
		height := r.FormValue("height")
		bust := r.FormValue("bust")
		waist := r.FormValue("waist")
		hips := r.FormValue("hips")

		var profileID uuid.UUID
		err := s.database.QueryRow(ctx, `SELECT id FROM profile WHERE user_id = $1`, userID).Scan(&profileID)
		if err != nil {
			log.Printf("Failed to get profile ID: %v", err)
			http.Redirect(w, r, "/profile?err=Failed+to+update+profile", http.StatusSeeOther)
			return
		}

		var exists bool
		err = s.database.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM model_info WHERE id = $1)`, profileID).Scan(&exists)
		if err != nil {
			log.Printf("Failed to check model_info: %v", err)
		}

		if exists {
			q := `UPDATE model_info SET height = $2, bust = $3, waist = $4, hips = $5, location = $6 WHERE id = $1`
			_, err = s.database.Exec(ctx, q, profileID, height, bust, waist, hips, location)
		} else {
			q := `INSERT INTO model_info (id, height, bust, waist, hips, location) VALUES ($1, $2, $3, $4, $5, $6)`
			_, err = s.database.Exec(ctx, q, profileID, height, bust, waist, hips, location)
		}
		if err != nil {
			log.Printf("Failed to update model_info: %v", err)
		}
	}

	s.cache.Delete(sid)

	http.Redirect(w, r, "/profile", http.StatusSeeOther)
}

func (s *ServerContext) DeleteProfile(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sid := r.Header.Get(middlewareToken)
	if sid == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	claims, err := s.parseToken(sid)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	userID, err := uuid.Parse(claims.UserID)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	q := `DELETE FROM app_users WHERE id = $1`
	_, err = s.database.Exec(ctx, q, userID)
	if err != nil {
		log.Printf("Failed to delete user: %v", err)
		http.Redirect(w, r, "/profile?err=Failed+to+delete+account", http.StatusSeeOther)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Secure:   true,
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
	})

	s.cache.Delete(sid)

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *ServerContext) UploadPortfolioImage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sid := r.Header.Get(middlewareToken)
	if sid == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	claims, err := s.parseToken(sid)
	if err != nil || claims.Role != "model" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	userID, err := uuid.Parse(claims.UserID)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	if err := r.ParseMultipartForm(10 << 20); err != nil {
		http.Redirect(w, r, "/profile?err=Failed+to+parse+form", http.StatusSeeOther)
		return
	}

	var profileID uuid.UUID
	err = s.database.QueryRow(ctx, `SELECT id FROM profile WHERE user_id = $1`, userID).Scan(&profileID)
	if err != nil {
		log.Printf("Failed to get profile ID: %v", err)
		http.Redirect(w, r, "/profile?err=Failed+to+upload+image", http.StatusSeeOther)
		return
	}

	imageFile, _, err := r.FormFile("portfolio_image")
	if err != nil {
		http.Redirect(w, r, "/profile?err=No+image+selected", http.StatusSeeOther)
		return
	}
	defer imageFile.Close()

	imageData, err := io.ReadAll(imageFile)
	if err != nil || len(imageData) == 0 {
		http.Redirect(w, r, "/profile?err=Failed+to+read+image", http.StatusSeeOther)
		return
	}

	mime := http.DetectContentType(imageData)
	if !strings.HasPrefix(mime, "image/") {
		http.Redirect(w, r, "/profile?err=Invalid+image+type", http.StatusSeeOther)
		return
	}

	randomName, _ := randomImageName()
	q := `INSERT INTO portfolio_images (profile_id, image_name, image_data) VALUES ($1, $2, $3)`
	_, err = s.database.Exec(ctx, q, profileID, randomName, imageData)
	if err != nil {
		log.Printf("Failed to insert portfolio image: %v", err)
		http.Redirect(w, r, "/profile?err=Failed+to+upload+image", http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/profile", http.StatusSeeOther)
}

func (s *ServerContext) DeletePortfolioImage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sid := r.Header.Get(middlewareToken)
	if sid == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	claims, err := s.parseToken(sid)
	if err != nil || claims.Role != "model" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	userID, err := uuid.Parse(claims.UserID)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/profile?err=Failed+to+parse+form", http.StatusSeeOther)
		return
	}

	imageID := r.FormValue("image_id")
	if imageID == "" {
		http.Redirect(w, r, "/profile?err=No+image+specified", http.StatusSeeOther)
		return
	}

	imageUUID, err := uuid.Parse(imageID)
	if err != nil {
		http.Redirect(w, r, "/profile?err=Invalid+image+id", http.StatusSeeOther)
		return
	}

	q := `DELETE FROM portfolio_images WHERE id = $1 AND profile_id IN (SELECT id FROM profile WHERE user_id = $2)`
	result, err := s.database.Exec(ctx, q, imageUUID, userID)
	if err != nil {
		log.Printf("Failed to delete portfolio image: %v", err)
		http.Redirect(w, r, "/profile?err=Failed+to+delete+image", http.StatusSeeOther)
		return
	}

	if result.RowsAffected() == 0 {
		http.Redirect(w, r, "/profile?err=Image+not+found", http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/profile", http.StatusSeeOther)
}

func (s *ServerContext) profilePage(w http.ResponseWriter, r *http.Request) {
	sid := r.Header.Get(middlewareToken)
	if sid == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	claims, err := s.parseToken(sid)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	switch claims.Role {
	case "model":
		s.modelPrivatePage(w, r)
	case "fotograaf":
		s.fotograafPrivatePage(w, r)
	default:
		http.Redirect(w, r, "/overview", http.StatusSeeOther)
	}
}

func (s *ServerContext) LoginPage(w http.ResponseWriter, r *http.Request) {
	_, ok := s.validateSession(r)
	if ok {
		http.Redirect(w, r, "/overview", http.StatusSeeOther)
		return
	}

	errMsg := r.URL.Query().Get("err")
	root(pages.Login(errMsg)).Render(r.Context(), w)
}

func (s *ServerContext) SignupPage(w http.ResponseWriter, r *http.Request) {
	_, ok := s.validateSession(r)
	if ok {
		http.Redirect(w, r, "/overview", http.StatusSeeOther)
		return
	}

	errMsg := r.URL.Query().Get("err")
	root(pages.Signup(errMsg)).Render(r.Context(), w)
}

/*********************************************
 *                  ENTRY                    *
 *********************************************/

func init() {
	jwtKey = []byte("soifhsloihsidjhljishai`sjrfhiajd")
}

func main() {
	mux := http.NewServeMux()
	dsn := os.Getenv("DSN")
	if dsn == "" {
		log.Fatalln("DSN env var not set")
	}
	conn, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		panic(err)
	}
	sctx := NewServerContext(conn)

	// pages
	// wrapped the function in sctx.CacheRoute
	mux.HandleFunc("GET /", sctx.CacheRoute(func(w http.ResponseWriter, r *http.Request) {
		root(pages.Home()).Render(r.Context(), w)
	}, 2*time.Minute)) // This keeps the home page in memory for 2 minutes

	mux.HandleFunc("GET /overview", sctx.AuthMiddleware(sctx.overviewPage))
	mux.HandleFunc("GET /model/{slug}", sctx.modelPublicPage)
	mux.HandleFunc("GET /fotograaf/{slug}", sctx.fotograafPublicPage)

	staticSubFS, err := fs.Sub(staticFs, "public")
	if err != nil {
		log.Fatalf("failed to start server: %v\n", err)
	}
	mux.Handle("GET /public/", http.StripPrefix("/public/", http.FileServerFS(staticSubFS)))
	mux.HandleFunc("GET /login", sctx.LoginPage)
	mux.HandleFunc("GET /signup", sctx.SignupPage)
	mux.HandleFunc("GET /profile", sctx.AuthMiddleware(sctx.profilePage))

	// api
	mux.HandleFunc("POST /api/login", sctx.Login)
	mux.HandleFunc("POST /api/signup", sctx.Signup)
	mux.HandleFunc("POST /api/logout", sctx.AuthMiddleware(sctx.Logout))
	mux.HandleFunc("POST /api/profile/update", sctx.AuthMiddleware(sctx.UpdateProfile))
	mux.HandleFunc("POST /api/profile/delete", sctx.AuthMiddleware(sctx.DeleteProfile))
	mux.HandleFunc("POST /api/portfolio/upload", sctx.AuthMiddleware(sctx.UploadPortfolioImage))
	mux.HandleFunc("POST /api/portfolio/delete", sctx.AuthMiddleware(sctx.DeletePortfolioImage))

	srv := &http.Server{
		Addr:    ":42069",
		Handler: mux,
	}

	go func() {
		log.Println("server listening on http://localhost:42069")
		srv.ListenAndServe()
	}()

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGTERM, syscall.SIGABRT, os.Interrupt)
	<-c
	fmt.Println("\nmi ah go sleep big man...")
	err = srv.Shutdown(context.TODO())
	if err != nil {
		log.Fatalln("meh cyant shut down da server ghee...")
	}
}
