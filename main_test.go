package main

import (
	"bytes"
	"context"
	"fmt"
	"math/rand"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	dbUser        = "testAdmin"
	dbPassword    = "pass1234"
	dbName        = "testdb"
	containerPort = "5432"
	imageName     = "postgres:15"
)

var MOCK_SERVER *ServerContext

func setupPostgres(schema string, testdata ...string) (*pgxpool.Pool, string, func(), error) {
	containerName := fmt.Sprintf("test-postgres-%d", rand.Intn(1000000))
	hostPort := fmt.Sprintf("%d", 30000+rand.Intn(10000)) // random port between 30000-39999

	runArgs := []string{
		"run", "-d",
		"--rm",
		"--name", containerName,
		"-e", "POSTGRES_USER=" + dbUser,
		"-e", "POSTGRES_PASSWORD=" + dbPassword,
		"-e", "POSTGRES_DB=" + dbName,
		"-p", hostPort + ":" + containerPort,
		imageName,
	}

	// Stop any container with the same name just in case
	exec.Command("docker", "stop", containerName).Run()

	if err := exec.Command("docker", runArgs...).Run(); err != nil {
		return nil, "", nil, fmt.Errorf("failed to start Docker container: %w", err)
	}

	dsn := fmt.Sprintf("postgres://%s:%s@localhost:%s/%s?sslmode=disable", dbUser, dbPassword, hostPort, dbName)
	ctx := context.Background()

	var pool *pgxpool.Pool
	var err error

	for i := 0; i < 20; i++ {
		pool, err = pgxpool.New(ctx, dsn)
		if err == nil && pool.Ping(ctx) == nil {
			break
		}
		time.Sleep(time.Second)
	}
	if err != nil {
		_ = exec.Command("docker", "rm", "-f", containerName).Run()
		return nil, "", nil, fmt.Errorf("failed to connect to PostgreSQL: %w", err)
	}

	if _, err := pool.Exec(ctx, schema); err != nil {
		pool.Close()
		_ = exec.Command("docker", "rm", "-f", containerName).Run()
		return nil, "", nil, fmt.Errorf("failed to apply schema: %w", err)
	}

	for _, q := range testdata {
		if strings.TrimSpace(q) == "" {
			continue
		}
		if _, err := pool.Exec(ctx, q); err != nil {
			pool.Close()
			_ = exec.Command("docker", "rm", "-f", containerName).Run()
			return nil, "", nil, fmt.Errorf("failed to insert test data: %w", err)
		}
	}

	clean := func() {
		pool.Close()
		_ = exec.Command("docker", "rm", "-f", containerName).Run()
	}

	return pool, dsn, clean, nil
}

func TestMain(m *testing.M) {
	schema, err := os.ReadFile("init.sql")
	if err != nil {
		panic(err)
	}

	pool, _, clean, err := setupPostgres(string(schema))
	if err != nil {
		panic(err)
	}
	defer clean()

	MOCK_SERVER = NewServerContext(pool)
	code := m.Run()
	os.Exit(code)
}

func TestAuth(t *testing.T) {
	t.Run("signup", func(t *testing.T) {
		var buf bytes.Buffer
		writer := multipart.NewWriter(&buf)

		writer.WriteField("school_id", "102717")
		writer.WriteField("name", "Leon van Snoeptomaat")
		writer.WriteField("password", "HEllo@3948")
		writer.WriteField("role", "fotograaf")
		writer.Close()

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/api/signup", &buf)
		r.Header.Set("Content-Type", writer.FormDataContentType())

		start := time.Now()
		MOCK_SERVER.Signup(w, r)
		fmt.Println("Signup:", time.Since(start))

		if w.Code != http.StatusPermanentRedirect {
			t.Error("failed to redirect user")
		}

		var exists bool
		err := MOCK_SERVER.database.QueryRow(t.Context(), "SELECT EXISTS(SELECT id FROM app_users WHERE school_id = $1)", "102717").Scan(&exists)
		if err != nil {
			t.Error(err)
		}

		if !exists {
			t.Error("faield to add user to db")
		}
	})

	t.Run("login", func(t *testing.T) {
		writer := url.Values{}
		writer.Set("school_id", "102717")
		writer.Set("password", "HEllo@3948")

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(writer.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		start := time.Now()
		MOCK_SERVER.Login(w, r)
		fmt.Println("Login:", time.Since(start))

		if w.Code != http.StatusPermanentRedirect {
			t.Fatalf("failed to redirect user: %d - %v", w.Code, w.Body.String())
		}

	})

}