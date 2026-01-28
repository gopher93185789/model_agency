package internal

import (
	"context"

	"github.com/google/uuid"
	"github.com/gopher93185789/model_agency/pkg/types"
	"github.com/gopher93185789/model_agency/src/pages"
)

func (s *ServerContext) GetFotograafInfo(userid uuid.UUID) (*types.FotograafInfo, error) {
	q := `
	SELECT 
		u.id AS user_id,
		u.name,
		u.school_email,
		p.profile_image_name,
		p.profile_image_data,
		p.description
	FROM app_users u
	JOIN profile p ON u.id = p.user_id
	WHERE u.id = $1 AND u.role = 'fotograaf'
	`

	var (
		info       types.FotograafInfo
		imageName  *string
		imageBytes []byte
	)
	err := s.database.QueryRow(context.Background(), q, userid).Scan(
		&info.UserID,
		&info.Name,
		&info.SchoolEmail,
		&imageName,
		&imageBytes,
		&info.Description,
	)
	if err != nil {
		return nil, err
	}

	info.ProfileImageName = imageName
	if len(imageBytes) > 0 {
		b64 := toBase64(imageBytes)
		info.ProfileImageBase64 = &b64
	}

	return &info, nil
}

func (s *ServerContext) GetFotograafOverviewInfo() ([]types.ModelOverviewInfo, error) {
	q := `
	SELECT 
		u.id,
		u.name,
		LOWER(REPLACE(REPLACE(u.name, ' ', '-'), '.', '')) as slug,
		p.description,
		p.profile_image_name,
		p.profile_image_data
	FROM app_users u
	JOIN profile p ON u.id = p.user_id
	WHERE u.role = 'model'
	`

	rows, err := s.database.Query(context.Background(), q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var models []types.ModelOverviewInfo
	for rows.Next() {
		var (
			info       types.ModelOverviewInfo
			imageName  *string
			imageBytes []byte
		)
		if err := rows.Scan(&info.UserID, &info.Name, &info.Slug, &info.Description, &imageName, &imageBytes); err != nil {
			return nil, err
		}
		info.ProfileImageName = imageName
		if len(imageBytes) > 0 {
			b64 := toBase64(imageBytes)
			info.ProfileImageBase64 = &b64
		}
		models = append(models, info)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return models, nil
}

func (s *ServerContext) GetFotograafBySlug(slug string) (*pages.FotograafData, error) {
	q := `
	SELECT 
		u.name,
		u.school_email,
		COALESCE(p.description, '') as description,
		COALESCE(encode(p.profile_image_data, 'base64'), '') as profile_image_base64
	FROM app_users u
	JOIN profile p ON u.id = p.user_id
	WHERE u.role = 'fotograaf' AND LOWER(REPLACE(REPLACE(u.name, ' ', '-'), '.', '')) = $1
	`

	var name, email, description, profileImageBase64 string

	err := s.database.QueryRow(context.Background(), q, slug).Scan(
		&name, &email, &description, &profileImageBase64,
	)
	if err != nil {
		return nil, err
	}

	return &pages.FotograafData{
		ProfileImageBase64: profileImageBase64,
		Name:               name,
		Email:              email,
		Bio:                description,
		Portfolio:          []string{},
	}, nil
}
