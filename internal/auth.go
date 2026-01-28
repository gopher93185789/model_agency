package internal

import (
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

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
		approved     bool
		query        = `
		SELECT u.id, u.password_hash, u.role, COALESCE(p.approved, false) 
		FROM app_users u
		LEFT JOIN profile p ON u.id = p.user_id
		WHERE u.school_email=$1 
		`
	)

	err := s.database.QueryRow(ctx, query, schoolEmail).Scan(&id, &passwordHash, &role, &approved)
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

	// Check if user is approved (docents are always approved, but models/fotograafs need approval)
	if !approved {
		http.Redirect(w, r, "/login?err=Your+account+is+pending+approval", http.StatusSeeOther)
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

	http.Redirect(w, r, "/", http.StatusSeeOther)
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

	http.Redirect(w, r, "/profile", http.StatusSeeOther)
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
