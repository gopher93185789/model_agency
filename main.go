package main

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/a-h/templ"
	"github.com/google/uuid"
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

type ServerContext struct {
	database *pgxpool.Pool
	store    *sessionStore
	cache    *cache.Cache
}

func NewServerContext(database *pgxpool.Pool) *ServerContext {
	return &ServerContext{
		database: database,
		cache:    cache.New(5*time.Minute, 1*time.Minute),
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
	return bcrypt.GenerateFromPassword([]byte(password), 5)
}

func (s *ServerContext) validateSession(r *http.Request) (string, bool) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil || cookie.Value == "" {
		return "", false
	}
	sessionid := cookie.Value

	st, err := s.store.Get(sessionid)
	if err != nil {
		return "", false

	}

	if time.Now().After(st.Expiry) {
		s.store.Delete(sessionid)
		return "", false
	}

	return sessionid, true
}

/**************************************************
 *                  MIDDLEWARE                    *
 **************************************************/
/*
# to get user info easy for lazy nihg:
	st, err := s.store.Get(r.Header.Get(middlewareToken))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
*/
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
		schoolEmail     = r.FormValue("school_email")
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

	// parse and uplad to r2 then reytn url
	if hasFile {
		// uplaod
	}

	query := `
		WITH user_i AS (
			INSERT INTO app_users (role, school_email, name, password_hash) 
			VALUES ($1, $2, $3, $4) 
			RETURNING id
		)
		INSERT INTO profile (user_id, approved, profile_image_url) 
		SELECT id, $5, $6
		FROM user_iP
		RETURNING id
	`

	_, err = s.database.Exec(ctx, query,
		role,
		schoolEmail,
		name,
		string(passwordHash),
		approved,
		profileImageUrl,
	)

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

	var buf = make([]byte, 12)
	_, err = rand.Read(buf)
	if err != nil {
		log.Printf("Failed to generate session ID: %v", err)
		http.Redirect(w, r, "/login?err=Internal+server+error", http.StatusSeeOther)
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
		Secure:   true,
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
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

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

/*********************************************
 *                  PAGES                    *
 *********************************************/
func (s *ServerContext) overviewPage(w http.ResponseWriter, r *http.Request) {
	var (
		page templ.Component
	)

	sid := r.Header.Get(middlewareToken)
	p, ok := s.cache.Get(sid)
	if ok {
		if v, ok := p.(templ.Component); ok {
			root(v).Render(r.Context(), w)
			return
		}
	}

	st, err := s.store.Get(sid)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	switch st.Role {
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
		page = pages.Fotograaf()
		s.cache.Set(sid, page, cache.DefaultExpiration)
	default:
		http.Redirect(w, r, "/", http.StatusPermanentRedirect)
		return
	}

	root(page).Render(r.Context(), w)

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
