package internal

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"

	"golang.org/x/crypto/bcrypt"
)

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
