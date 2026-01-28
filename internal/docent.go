package internal

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/gopher93185789/model_agency/pkg/types"
)

func (s *ServerContext) GetUsersForDocentPage(ctx context.Context, limit, page int) (profile []types.UserProfile, err error) {
	const getUsersQuer = `
		SELECT u.id, u.school_email, u.name, u.role, p.approved, p.profile_image_name, p.profile_image_data
		FROM app_users u
		JOIN profile p ON u.id = p.user_id
		WHERE u.role != 'docent'
		LIMIT $1 OFFSET $2;
	`

	if page <= 0 {
		return nil, fmt.Errorf("invalid page param: provide a value greater or equal to 1. Got %d", page)
	}

	offset := 0
	rows, err := s.database.Query(ctx, getUsersQuer, limit, offset)
	if err != nil {
		return
	}
	defer rows.Close()

	profile = make([]types.UserProfile, 0, limit)
	var (
		p       = types.UserProfile{}
		pfpName sql.NullString
	)
	for rows.Next() {
		err := rows.Scan(&p.ID, &p.SchoolEmail, &p.Name, &p.Role, &p.Approved, &pfpName, &p.ProfileImageData)
		if err != nil {
			return nil, err
		}

		p.ProfileImageName = pfpName.String

		fmt.Println(p)

		profile = append(profile, p)
	}

	return
}
