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
		m.location,
		m.total_shots,
		m.height,
		m.bust,
		m.waist,
		m.hips
	FROM app_users u
	JOIN profile p ON u.id = p.user_id
	JOIN model_info m ON p.id = m.id
	WHERE u.id = $1 AND u.role = 'model'
	`

	var (
		info       types.ModelFullInfo
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
		&info.Location,
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
	if len(imageBytes) > 0 {
		b64 := toBase64(imageBytes)
		info.ProfileImageBase64 = &b64
	}

	return &info, nil
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
		u.name,
		u.school_email,
		COALESCE(p.description, '') as description
	FROM app_users u
	JOIN profile p ON u.id = p.user_id
	WHERE u.role = 'model' AND LOWER(REPLACE(REPLACE(u.name, ' ', '-'), '.', '')) = $1
	`

	var name, email, description string

	err := s.database.QueryRow(context.Background(), q, slug).Scan(
		&name, &email, &description,
	)
	if err != nil {
		return nil, err
	}

	return &pages.ModelData{
		Name:        name,
		TotalShoots: 0,
		Email:       email,
		Location:    "",
		Bio:         description,
		Portfolio:   []string{},
		Measurements: pages.Measurements{
			Height: "0",
			Bust:   "0",
			Waist:  "0",
			Hips:   "0",
		},
		Editable: false,
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
		modelData := pages.ModelData{
			Name:        "Alex Morgan",
			TotalShoots: 24,
			Email:       "alex.morgan@email.com",
			Location:    "New York, NY",
			Bio:         "Professional model with 5+ years of experience in fashion, editorial, and commercial photography. Available for studio and outdoor shoots. Portfolio available upon request.",
			Portfolio:   []string{"", "", "", "", "", ""},
			Measurements: pages.Measurements{
				Height: "167",
				Bust:   "34",
				Waist:  "24",
				Hips:   "36",
			},
			Editable: true,
		}
		page = pages.ModelPublic(modelData)
		s.cache.Set(sid, page, cache.DefaultExpiration)
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
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) { root(pages.Home()).Render(r.Context(), w) })
	mux.HandleFunc("GET /overview", sctx.AuthMiddleware(sctx.overviewPage))
	mux.HandleFunc("GET /model/{slug}", sctx.modelPublicPage)

	staticSubFS, err := fs.Sub(staticFs, "public")
	if err != nil {
		log.Fatalf("failed to start server: %v\n", err)
	}
	mux.Handle("GET /public/", http.StripPrefix("/public/", http.FileServerFS(staticSubFS)))
	mux.HandleFunc("GET /login", sctx.LoginPage)
	mux.HandleFunc("GET /signup", sctx.SignupPage)

	// api
	mux.HandleFunc("POST /api/login", sctx.Login)
	mux.HandleFunc("POST /api/signup", sctx.Signup)
	mux.HandleFunc("POST /api/logout", sctx.AuthMiddleware(sctx.Logout))

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
