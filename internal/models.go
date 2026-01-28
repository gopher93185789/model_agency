package internal

import (
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/patrickmn/go-cache"
)

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

const sessionExp = 6 * time.Hour
const sessionCookieName string = "duke_dennis"
const middlewareToken = "token"
