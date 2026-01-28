package internal

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type Claims struct {
	UserID     string `json:"user_id"`
	Role       string `json:"role"`
	ProfileUrl string `json:"profile_url"`
	jwt.RegisteredClaims
}

var jwtKey []byte

func init() {
	jwtKey = []byte("soifhsloihsidjhljishai`sjrfhiajd")
}

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
