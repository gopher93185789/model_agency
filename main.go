package main

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/gopher93185789/model_agency/internal"
	"github.com/gopher93185789/model_agency/src"
	"github.com/gopher93185789/model_agency/src/pages"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed public/**
var staticFs embed.FS

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
	sctx := internal.NewServerContext(conn)

	// pages
	// wrapped the function in sctx.CacheRoute
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		src.Root(pages.Home()).Render(r.Context(), w)
	})

	mux.HandleFunc("GET /overview", sctx.AuthMiddleware(sctx.OverviewPage))
	// Public models listing page
	mux.HandleFunc("GET /models", sctx.ModelsPage)
	mux.HandleFunc("GET /model/{slug}", sctx.ModelPublicPage)


	mux.HandleFunc("GET /fotograaf/{slug}", sctx.FotograafPublicPage)
	mux.HandleFunc("GET /fotograaf", sctx.FotograafPage)


	staticSubFS, err := fs.Sub(staticFs, "public")
	if err != nil {
		log.Fatalf("failed to start server: %v\n", err)
	}
	mux.Handle("GET /public/", http.StripPrefix("/public/", http.FileServerFS(staticSubFS)))
	mux.HandleFunc("GET /login", sctx.LoginPage)
	mux.HandleFunc("GET /signup", sctx.SignupPage)
	mux.HandleFunc("GET /terms", func(w http.ResponseWriter, r *http.Request) {
		src.Root(pages.Terms()).Render(r.Context(), w)
	})
	mux.HandleFunc("GET /profile", sctx.AuthMiddleware(sctx.ProfilePage))

	// api
	mux.HandleFunc("POST /api/login", sctx.Login)
	mux.HandleFunc("POST /api/signup", sctx.Signup)
	mux.HandleFunc("POST /api/logout", sctx.AuthMiddleware(sctx.Logout))
	mux.HandleFunc("POST /api/profile/update", sctx.AuthMiddleware(sctx.UpdateProfile))
	mux.HandleFunc("POST /api/profile/delete", sctx.AuthMiddleware(sctx.DeleteProfile))
	mux.HandleFunc("POST /api/portfolio/upload", sctx.AuthMiddleware(sctx.UploadPortfolioImage))
	mux.HandleFunc("POST /api/portfolio/delete", sctx.AuthMiddleware(sctx.DeletePortfolioImage))

	// docent/admin api
	mux.HandleFunc("POST /api/admin/approve", sctx.AuthMiddleware(sctx.HandleApproveUser))
	mux.HandleFunc("POST /api/admin/revoke", sctx.AuthMiddleware(sctx.HandleRevokeUser))

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
