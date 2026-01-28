package types

import "github.com/google/uuid"

type Role string

const (
	RoleModel     Role = "model"
	RoleFotograaf Role = "fotograaf"
	RoleDocent    Role = "docent"
)

type UserProfile struct {
	ID               uuid.UUID `json:"id"`
	SchoolEmail      string    `json:"school_email"`
	Name             string    `json:"name"`
	Role             string    `json:"role"`
	Approved         bool      `json:"approved"`
	ProfileImageName string    `json:"profile_image_name"`
	ProfileImageData []byte    `json:"profile_image_sata"`
}

type AppUser struct {
	ID           uuid.UUID `json:"id" db:"id"`
	Role         Role      `json:"role" db:"role"`
	SchoolEmail  string    `json:"school_email" db:"school_email"`
	Name         string    `json:"name" db:"name"`
	PasswordHash []byte    `json:"-" db:"password_hash"`
}

type Profile struct {
	ID                 uuid.UUID `json:"id" db:"id"`
	UserID             uuid.UUID `json:"user_id" db:"user_id"`
	Approved           bool      `json:"approved" db:"approved"`
	ProfileImageName   *string   `json:"profile_image_name" db:"profile_image_name"`
	ProfileImageBase64 *string   `json:"profile_image_base64" db:"profile_image_base64"`
	Description        *string   `json:"description" db:"description"`
}

type ModelInfo struct {
	ID         uuid.UUID `json:"id" db:"id"`
	Height     int       `json:"height" db:"height"`
	Bust       int       `json:"bust" db:"bust"`
	Waist      int       `json:"waist" db:"waist"`
	Hips       int       `json:"hips" db:"hips"`
	Location   *string   `json:"location" db:"location"`
	TotalShots int       `json:"total_shots" db:"total_shots"`
}

// Deprecated: URL-based image struct removed.

type ModelFullInfo struct {
	UserID             uuid.UUID `json:"user_id" db:"user_id"`
	Name               string    `json:"name" db:"name"`
	SchoolEmail        string    `json:"school_email" db:"school_email"`
	ProfileImageName   *string   `json:"profile_image_name" db:"profile_image_name"`
	ProfileImageBase64 *string   `json:"profile_image_base64" db:"profile_image_base64"`
	Description        *string   `json:"description" db:"description"`
	Location           *string   `json:"location" db:"location"`
	TotalShots         int       `json:"total_shots" db:"total_shots"`
	Height             int       `json:"height" db:"height"`
	Bust               int       `json:"bust" db:"bust"`
	Waist              int       `json:"waist" db:"waist"`
	Hips               int       `json:"hips" db:"hips"`
}

type FotograafInfo struct {
	UserID             uuid.UUID `json:"user_id" db:"user_id"`
	Name               string    `json:"name" db:"name"`
	SchoolEmail        string    `json:"school_email" db:"school_email"`
	ProfileImageName   *string   `json:"profile_image_name" db:"profile_image_name"`
	ProfileImageBase64 *string   `json:"profile_image_base64" db:"profile_image_base64"`
	Description        *string   `json:"description" db:"description"`
}

type ModelOverviewInfo struct {
	UserID             uuid.UUID `json:"user_id" db:"user_id"`
	Name               string    `json:"name" db:"name"`
	Slug               string    `json:"slug" db:"slug"`
	Description        *string   `json:"description" db:"description"`
	ProfileImageName   *string   `json:"profile_image_name" db:"profile_image_name"`
	ProfileImageBase64 *string   `json:"profile_image_base64" db:"profile_image_base64"`
}

type PortfolioImage struct {
	ID     uuid.UUID `json:"id" db:"id"`
	Base64 string    `json:"base64"`
}

type ApprovalUpdate struct {
	UserID uuid.UUID `json:"user_id"`
	Status bool      `json:"status"`
}
