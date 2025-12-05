package main

import (
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/a-h/templ"
	"github.com/google/uuid"
	"github.com/gopher93185789/model_agency/pages"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

//go:embed static/**
var staticFs embed.FS

const sessionCookieName string = "duke_dennis"
const sessionExp = 6 * time.Hour
const middlewareToken = "token"

type ServerContext struct {
	database *pgxpool.Pool
	store    *sessionStore
}

func NewServerContext(database *pgxpool.Pool) *ServerContext {
	return &ServerContext{
		database: database,
		store: &sessionStore{
			mu:    sync.RWMutex{},
			users: make(map[string]storePayload),
		},
	}
}

/*****************************************************
 *                  SESSION STORE                    *
 *****************************************************/
type storePayload struct {
	UserId     uuid.UUID
	Role       string
	Expiry     time.Time
	ProfileUrl string
}

type sessionStore struct {
	mu    sync.RWMutex
	users map[string]storePayload
}

func (s *sessionStore) Get(key string) (st storePayload, err error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	st, ok := s.users[key]
	if !ok {
		return st, fmt.Errorf("no value matches give key")
	}

	return st, nil
}

func (s *sessionStore) Set(key string, val storePayload) {
	s.mu.Lock()
	s.users[key] = val
	s.mu.Unlock()
}

func (s *sessionStore) Delete(key string) {
	s.mu.Lock()
	delete(s.users, key)
	s.mu.Unlock()
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
	return bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
}

/**************************************************
 *                  MIDDLEWARE                    *
 **************************************************/
/*
# to get user info easy for lazy nihg:

	info, err := s.store.Get(w.Header().Get(middlewareToken))
	if err != nil {
		return
	}
*/
func (s *ServerContext) AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var (
			sessionid string
		)

		cookie, err := r.Cookie(sessionCookieName)
		if err != nil || cookie.Value == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		sessionid = cookie.Value

		st, err := s.store.Get(sessionid)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		if time.Now().After(st.Expiry) {
			s.store.Delete(sessionid)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		r.Header.Set(middlewareToken, cookie.Value)
		next.ServeHTTP(w, r)
	}
}

/********************************************
 *                  AUTH                    *
 ********************************************/
// not allowed to signup as docent because we will manully protmote them
func (s *ServerContext) Signup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if err := r.ParseMultipartForm(3e+7); err != nil {
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	var (
		schoolId        = r.FormValue("school_id")
		name            = r.FormValue("name")
		password        = r.FormValue("password")
		role            = r.FormValue("role")
		hasFile         = false
		profileImageUrl = ""
		approved        = false
	)
	// imageFile, head, err := r.FormFile("profile_image")
	// if err == nil {
	// 	hasFile = true
	// }
	// defer imageFile.Close()

	if schoolId == "" || name == "" || password == "" || role == "" {
		http.Error(w, "School ID, name, password, and role are required", http.StatusBadRequest)
		return
	}

	if role != "model" && role != "fotograaf" {
		http.Error(w, "Role must be one of: model, fotograaf", http.StatusBadRequest)
		return
	}

	// email van opdracht gever:
	// goede vraag! nee ik bedoel inderdaad dat de docent, de aanvraag van het model moet goedkeuren.
	if role == "fotograaf" {
		approved = true
	}

	passwordHash, err := hashPassword(password)
	if err != nil {
		log.Printf("Password hashing failed: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// parse and uplad to r2 then reytn url
	if hasFile {
		// uplaod
	}

	query := `
		WITH user_i AS (
			INSERT INTO app_users (role, school_id, name, password_hash) 
			VALUES ($1, $2, $3, $4) 
			RETURNING id
		),
		profile_i AS (
			INSERT INTO profile (user_id, approved, profile_image_url) 
			SELECT id, $5, $6
			FROM user_i
			RETURNING id
		)
	`

	_, err = s.database.Exec(ctx, query,
		role,
		schoolId,
		name,
		string(passwordHash),
		approved,
		profileImageUrl,
	)

	if err != nil {
		log.Printf("Database insert failed: %v", err)
		if err.Error() == "duplicate key value violates unique constraint" {
			http.Error(w, "Someone with that school ID already exists", http.StatusConflict)
			return
		}

		http.Error(w, "Failed to create user", http.StatusInternalServerError)
		return
	}

	// maybe we can redirect oto home with a queryparam modal
	// that if not empty can show a modal popup sayting  "waiting for a docent to approve your profile" fr better UX
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *ServerContext) Login(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	stuNum := r.FormValue("stunum")
	password := r.FormValue("password")

	if stuNum == "" || password == "" {
		http.Error(w, "Student number and password are required", http.StatusBadRequest)
		return
	}

	var (
		id           uuid.UUID
		passwordHash string
		role         string
		query        = `
		SELECT id, password_hash, role 
		FROM app_users 
		WHERE school_id=$1 
		`
	)

	err := s.database.QueryRow(ctx, query, stuNum).Scan(&id, &passwordHash, &role)
	if err != nil {
		log.Printf("Database query failed: %v", err)
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	oldP, err := hashPassword(password)
	if err != nil {
		log.Printf("Password hashing failed: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if ok := subtle.ConstantTimeCompare(oldP, []byte(passwordHash)); ok == 0 {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	var buf = make([]byte, 12)
	_, err = rand.Read(buf)
	if err != nil {
		log.Printf("Failed to generate session ID: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	sid := hex.EncodeToString(buf)
	exp := time.Now().Add(sessionExp)

	s.store.Set(sid, storePayload{
		UserId: id,
		Role:   role,
		Expiry: exp,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    sid,
		Expires:  exp,
		HttpOnly: true,
		SameSite: http.SameSiteNoneMode,
	})

	// Redirect to overview page on successful login
	http.Redirect(w, r, "/overview", http.StatusSeeOther)
}

func (s *ServerContext) Logout(w http.ResponseWriter, r *http.Request) {
	s.store.Delete(middlewareToken)
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteNoneMode,
	})
}

/*********************************************
 *                  PAGES                    *
 *********************************************/
func (s *ServerContext) overviewHandler(w http.ResponseWriter, r *http.Request) {
	var (
		page templ.Component
	)

	st, err := s.store.Get(w.Header().Get(middlewareToken))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	switch st.Role {
	case "docent":
		page = pages.Docent()
	case "model":
		page = pages.Model()
	case "fotograaf":
		page = pages.Fotograaf()
	default:
		http.Redirect(w, r, "/", http.StatusPermanentRedirect)
		return
	}

	root(page).Render(r.Context(), w)
}

/*********************************************
 *                  ENTRY                    *
 *********************************************/
func main() {
	mux := http.NewServeMux()

	sctx := &ServerContext{}

	// api
	mux.HandleFunc("POST /api/login", sctx.Login)
	mux.HandleFunc("POST /api/signup", sctx.Signup)
	mux.HandleFunc("POST /api/logout", sctx.AuthMiddleware(sctx.Logout))

	// pages
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) { root(pages.Home()).Render(r.Context(), w) })
	mux.HandleFunc("GET /overview", sctx.AuthMiddleware(sctx.overviewHandler))
	mux.Handle("GET /static/", http.FileServerFS(staticFs))

	log.Println("server listening on http://localhost:42069")
	err := http.ListenAndServe(":42069", mux)
	if err != nil {
		log.Fatalf("failed to start server: %v", err)
	}
}
