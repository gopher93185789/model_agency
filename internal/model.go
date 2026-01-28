package internal

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/gopher93185789/model_agency/pkg/types"
	"github.com/gopher93185789/model_agency/src/pages"
)

func (s *ServerContext) GetModelInfo(userid uuid.UUID) (*types.ModelFullInfo, error) {
	q := `
	SELECT 
		u.id AS user_id,
		u.name,
		u.school_email,
		p.profile_image_name,
		p.profile_image_data,
		p.description,
		COALESCE(m.location, '') as location,
		COALESCE(m.total_shots, 0) as total_shots,
		COALESCE(m.height, 0) as height,
		COALESCE(m.bust, 0) as bust,
		COALESCE(m.waist, 0) as waist,
		COALESCE(m.hips, 0) as hips
	FROM app_users u
	JOIN profile p ON u.id = p.user_id
	LEFT JOIN model_info m ON p.id = m.id
	WHERE u.id = $1 AND u.role = 'model'
	`

	var (
		info       types.ModelFullInfo
		imageName  *string
		imageBytes []byte
		location   string
	)
	err := s.database.QueryRow(context.Background(), q, userid).Scan(
		&info.UserID,
		&info.Name,
		&info.SchoolEmail,
		&imageName,
		&imageBytes,
		&info.Description,
		&location,
		&info.TotalShots,
		&info.Height,
		&info.Bust,
		&info.Waist,
		&info.Hips,
	)
	if err != nil {
		return nil, err
	}

	info.ProfileImageName = imageName
	info.Location = &location
	if len(imageBytes) > 0 {
		b64 := toBase64(imageBytes)
		info.ProfileImageBase64 = &b64
	}

	return &info, nil
}

func (s *ServerContext) GetModelBySlug(slug string) (*pages.ModelData, error) {
	q := `
	SELECT 
		u.id,
		u.name,
		u.school_email,
		COALESCE(p.description, '') as description,
		COALESCE(encode(p.profile_image_data, 'base64'), '') as profile_image_base64,
		COALESCE(m.height, 0) as height,
		COALESCE(m.bust, 0) as bust,
		COALESCE(m.waist, 0) as waist,
		COALESCE(m.hips, 0) as hips,
		COALESCE(m.location, '') as location,
		COALESCE(m.total_shots, 0) as total_shots
	FROM app_users u
	JOIN profile p ON u.id = p.user_id
	LEFT JOIN model_info m ON p.id = m.id
	WHERE u.role = 'model' AND LOWER(REPLACE(REPLACE(u.name, ' ', '-'), '.', '')) = $1
	`

	var userID uuid.UUID
	var name, email, description, profileImageBase64, location string
	var height, bust, waist, hips, totalShots int

	err := s.database.QueryRow(context.Background(), q, slug).Scan(
		&userID, &name, &email, &description, &profileImageBase64,
		&height, &bust, &waist, &hips, &location, &totalShots,
	)
	if err != nil {
		return nil, err
	}

	// Fetch portfolio images
	portfolioImages, _ := s.GetPortfolioImages(userID)
	var portfolioData []pages.PortfolioItem
	for _, img := range portfolioImages {
		portfolioData = append(portfolioData, pages.PortfolioItem{
			ID:     img.ID.String(),
			Base64: img.Base64,
		})
	}

	return &pages.ModelData{
		ProfileImageBase64: profileImageBase64,
		Name:               name,
		TotalShoots:        totalShots,
		Email:              email,
		Location:           location,
		Bio:                description,
		Portfolio:          portfolioData,
		Measurements: pages.Measurements{
			Height: fmt.Sprintf("%d", height),
			Bust:   fmt.Sprintf("%d", bust),
			Waist:  fmt.Sprintf("%d", waist),
			Hips:   fmt.Sprintf("%d", hips),
		},
		Editable: false,
	}, nil
}

func (s *ServerContext) GetPortfolioImages(userID uuid.UUID) ([]types.PortfolioImage, error) {
	q := `
	SELECT pi.id, pi.image_data
	FROM portfolio_images pi
	JOIN profile p ON pi.profile_id = p.id
	WHERE p.user_id = $1
	ORDER BY pi.created_at DESC
	`

	rows, err := s.database.Query(context.Background(), q, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var images []types.PortfolioImage
	for rows.Next() {
		var img types.PortfolioImage
		var imageData []byte
		if err := rows.Scan(&img.ID, &imageData); err != nil {
			continue
		}
		if len(imageData) > 0 {
			img.Base64 = toBase64(imageData)
		}
		images = append(images, img)
	}

	return images, nil
}
