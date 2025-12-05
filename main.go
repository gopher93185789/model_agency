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

type storePayload struct {
	UserId     uuid.UUID
	Role       string
	Expiry     time.Time
	ProfileUrl string
}

type ErrResponse struct {
	Error string `json:"error"`
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

func respondWithJson[P any](w http.ResponseWriter, code int, payload P) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	err := json.NewEncoder(w).Encode(payload)
	if err != nil {
		log.Printf("Error encoding JSON response: %v", err)
		return
	}
}

type ServerContext struct {
	database *pgxpool.Pool
	tokenKey []byte
	store    *sessionStore
}

type loginRequest struct {
	StuNum   string
	Password string
	Role     string
}

func hashPassword(password string) (hash []byte, err error) {
	return bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
}



func (s *ServerContext) Login(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var info loginRequest
	if err := json.NewDecoder(r.Body).Decode(&info); err != nil {
		respondWithJson(w, http.StatusUnprocessableEntity, ErrResponse{Error: "failed to decode json"})
		return
	}

	if info.StuNum == "" || info.Password == "" {
		respondWithJson(w, http.StatusBadRequest, ErrResponse{Error: "student number and password are required"})
		return
	}

	if info.Role != "fotograaf" && info.Role != "model" && info.Role != "docent" {
		respondWithJson(w, http.StatusBadRequest, ErrResponse{Error: "invalid role specified"})
		return
	}

	var (
		id           uuid.UUID
		passwordHash string
		query        = `
		SELECT id, password_hash 
		FROM user 
		WHERE school_id=$1 
		AND role=$2
		`
	)

	err := s.database.QueryRow(ctx, query, info.StuNum, info.Role).Scan(&id, &passwordHash)
	if err != nil {
		log.Printf("Database query failed: %v", err)
		respondWithJson(w, http.StatusUnauthorized, ErrResponse{Error: "invalid credentials"})
		return
	}

	oldP, err := hashPassword(info.Password)
	if err != nil {
		log.Printf("Password hashing failed: %v", err)
		respondWithJson(w, http.StatusInternalServerError, ErrResponse{Error: "internal server error"})
		return
	}

	if ok := subtle.ConstantTimeCompare(oldP, []byte(passwordHash)); ok == 0 {
		respondWithJson(w, http.StatusUnauthorized, ErrResponse{Error: "invalid credentials"})
		return
	}

	var buf = make([]byte, 12)
	_, err = rand.Read(buf)
	if err != nil {
		log.Printf("Failed to generate session ID: %v", err)
		respondWithJson(w, http.StatusInternalServerError, ErrResponse{Error: "internal server error"})
		return
	}
	sid := hex.EncodeToString(buf)
	exp := time.Now().Add(sessionExp)

	s.store.Set(sid, storePayload{
		UserId: id,
		Role:   info.Role,
		Expiry: exp,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    sid,
		Expires:  exp,
		HttpOnly: true,
		SameSite: http.SameSiteNoneMode,
	})

	respondWithJson(w, http.StatusOK, struct {
		Message string `json:"message"`
		Role string `json:"role"`
	}{Message: "login successful", Role: info.Role})
}

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

func main() {
	mux := http.NewServeMux()

	sctx := &ServerContext{}

	// api
	mux.HandleFunc("POST /api/login", sctx.Login)

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
