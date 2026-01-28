package internal

import (
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type ServerContext struct {
	database *pgxpool.Pool
}

func NewServerContext(database *pgxpool.Pool) *ServerContext {
	return &ServerContext{
		database: database,
	}
}

const sessionExp = 6 * time.Hour
const sessionCookieName string = "duke_dennis"
const middlewareToken = "token"
