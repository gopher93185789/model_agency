package internal

import (
	"fmt"
	"log"
	"net/http"

	"github.com/a-h/templ"
	"github.com/google/uuid"
	"github.com/gopher93185789/model_agency/src"
	"github.com/gopher93185789/model_agency/src/pages"
	"github.com/patrickmn/go-cache"
)

func (s *ServerContext) OverviewPage(w http.ResponseWriter, r *http.Request) {
	var (
		page templ.Component
		ctx  = r.Context()
	)

	sid := r.Header.Get(middlewareToken)
	if sid == "" {
		if token, ok := s.validateSession(r); ok {
			sid = token
		} else {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
	}

	if p, ok := s.cache.Get(sid); ok {
		if v, ok := p.(templ.Component); ok {
			src.Root(v).Render(r.Context(), w)
			return
		}
	}

	claims, err := s.parseToken(sid)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	switch claims.Role {
	case "docent":
		// TODO: get page and limit from url params
		data, err := s.GetUsersForDocentPage(ctx, 50, 1)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
			// TODO: handke err
		}

		fmt.Println(len(data))
		page = pages.Docent(data)
		s.cache.Set(sid, page, cache.DefaultExpiration)
	case "model":
		// Models don't have an overview page, redirect to their private profile
		http.Redirect(w, r, "/profile", http.StatusSeeOther)
		return
	case "fotograaf":
		// since the model will have multiple db results we can try to implement
		// https://templ.guide/server-side-rendering/streaming
		// never used it but it looks cool

		models, err := s.GetFotograafOverviewInfo()
		if err != nil {
			// TODO: handle error properly
			return
		}

		page = pages.Fotograaf(models)
		s.cache.Set(sid, page, cache.DefaultExpiration)
	default:
		http.Redirect(w, r, "/", http.StatusPermanentRedirect)
		return
	}

	src.Root(page).Render(r.Context(), w)

}

func (s *ServerContext) ModelPublicPage(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	if slug == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	modelData, err := s.GetModelBySlug(slug)
	if err != nil {
		log.Printf("Error fetching model by slug '%s': %v", slug, err)
		src.Root(pages.NotFound()).Render(r.Context(), w)
		return
	}

	src.Root(pages.ModelPublic(*modelData)).Render(r.Context(), w)
}

func (s *ServerContext) FotograafPublicPage(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	if slug == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	fotograafData, err := s.GetFotograafBySlug(slug)
	if err != nil {
		log.Printf("Error fetching fotograaf by slug '%s': %v", slug, err)
		src.Root(pages.NotFound()).Render(r.Context(), w)
		return
	}

	src.Root(pages.FotograafPublic(*fotograafData)).Render(r.Context(), w)
}

func (s *ServerContext) ModelPrivatePage(w http.ResponseWriter, r *http.Request) {
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

	modelInfo, err := s.GetModelInfo(userID)
	if err != nil {
		log.Printf("Error fetching model info: %v", err)
		src.Root(pages.NotFound()).Render(r.Context(), w)
		return
	}

	profileImage := ""
	if modelInfo.ProfileImageBase64 != nil {
		profileImage = *modelInfo.ProfileImageBase64
	}

	description := ""
	if modelInfo.Description != nil {
		description = *modelInfo.Description
	}

	location := ""
	if modelInfo.Location != nil {
		location = *modelInfo.Location
	}

	portfolioImages, _ := s.GetPortfolioImages(userID)
	var portfolioData []pages.PortfolioItem
	for _, img := range portfolioImages {
		portfolioData = append(portfolioData, pages.PortfolioItem{
			ID:     img.ID.String(),
			Base64: img.Base64,
		})
	}

	modelData := pages.ModelData{
		ProfileImageBase64: profileImage,
		Name:               modelInfo.Name,
		TotalShoots:        modelInfo.TotalShots,
		Email:              modelInfo.SchoolEmail,
		Location:           location,
		Bio:                description,
		Portfolio:          portfolioData,
		Measurements: pages.Measurements{
			Height: fmt.Sprintf("%d", modelInfo.Height),
			Bust:   fmt.Sprintf("%d", modelInfo.Bust),
			Waist:  fmt.Sprintf("%d", modelInfo.Waist),
			Hips:   fmt.Sprintf("%d", modelInfo.Hips),
		},
		Editable: true,
	}

	src.Root(pages.ModelPrivate(modelData)).Render(r.Context(), w)
}

func (s *ServerContext) FotograafPrivatePage(w http.ResponseWriter, r *http.Request) {
	sid := r.Header.Get(middlewareToken)
	if sid == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	claims, err := s.parseToken(sid)
	if err != nil || claims.Role != "fotograaf" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	userID, err := uuid.Parse(claims.UserID)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	fotograafInfo, err := s.GetFotograafInfo(userID)
	if err != nil {
		log.Printf("Error fetching fotograaf info: %v", err)
		src.Root(pages.NotFound()).Render(r.Context(), w)
		return
	}

	profileImage := ""
	if fotograafInfo.ProfileImageBase64 != nil {
		profileImage = *fotograafInfo.ProfileImageBase64
	}

	description := ""
	if fotograafInfo.Description != nil {
		description = *fotograafInfo.Description
	}

	fotograafData := pages.FotograafData{
		ProfileImageBase64: profileImage,
		Name:               fotograafInfo.Name,
		Email:              fotograafInfo.SchoolEmail,
		Bio:                description,
		Portfolio:          []string{},
	}

	src.Root(pages.FotograafPrivate(fotograafData)).Render(r.Context(), w)
}

func (s *ServerContext) ProfilePage(w http.ResponseWriter, r *http.Request) {
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

	switch claims.Role {
	case "model":
		s.ModelPrivatePage(w, r)
	case "fotograaf":
		s.FotograafPrivatePage(w, r)
	default:
		http.Redirect(w, r, "/overview", http.StatusSeeOther)
	}
}

func (s *ServerContext) LoginPage(w http.ResponseWriter, r *http.Request) {
	_, ok := s.validateSession(r)
	if ok {
		http.Redirect(w, r, "/overview", http.StatusSeeOther)
		return
	}

	errMsg := r.URL.Query().Get("err")
	src.Root(pages.Login(errMsg)).Render(r.Context(), w)
}

func (s *ServerContext) SignupPage(w http.ResponseWriter, r *http.Request) {
	_, ok := s.validateSession(r)
	if ok {
		http.Redirect(w, r, "/overview", http.StatusSeeOther)
		return
	}

	errMsg := r.URL.Query().Get("err")
	src.Root(pages.Signup(errMsg)).Render(r.Context(), w)
}
