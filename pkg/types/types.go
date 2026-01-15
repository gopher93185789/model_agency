package types

import "github.com/google/uuid"

type Role string

const (
	RoleModel     Role = "model"
	RoleFotograaf Role = "fotograaf"
	RoleDocent    Role = "docent"
)

type AppUser struct {
	ID           uuid.UUID `json:"id" db:"id"`
	Role         Role      `json:"role" db:"role"`
	SchoolEmail  string    `json:"school_email" db:"school_email"`
	Name         string    `json:"name" db:"name"`
	PasswordHash []byte    `json:"-" db:"password_hash"`
}

type Profile struct {
	ID              uuid.UUID `json:"id" db:"id"`
	UserID          uuid.UUID `json:"user_id" db:"user_id"`
	Approved        bool      `json:"approved" db:"approved"`
	ProfileImageURL *string   `json:"profile_image_url" db:"profile_image_url"`
	Description     *string   `json:"description" db:"description"`
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

type ProfileImage struct {
	ID        uuid.UUID `json:"id" db:"id"`
	ProfileID uuid.UUID `json:"profile_id" db:"profile_id"`
	ImageURL  string    `json:"image_url" db:"image_url"`
}

type ModelFullInfo struct {
	UserID          uuid.UUID `json:"user_id" db:"user_id"`
	Name            string    `json:"name" db:"name"`
	SchoolEmail     string    `json:"school_email" db:"school_email"`
	ProfileImageURL *string   `json:"profile_image_url" db:"profile_image_url"`
	Description     *string   `json:"description" db:"description"`
	Location        *string   `json:"location" db:"location"`
	TotalShots      int       `json:"total_shots" db:"total_shots"`
	Height          int       `json:"height" db:"height"`
	Bust            int       `json:"bust" db:"bust"`
	Waist           int       `json:"waist" db:"waist"`
	Hips            int       `json:"hips" db:"hips"`
}

type FotograafInfo struct {
	UserID          uuid.UUID `json:"user_id" db:"user_id"`
	Name            string    `json:"name" db:"name"`
	SchoolEmail     string    `json:"school_email" db:"school_email"`
	ProfileImageURL *string   `json:"profile_image_url" db:"profile_image_url"`
	Description     *string   `json:"description" db:"description"`
}

type ModelOverviewInfo struct {
	Name        string  `json:"name" db:"name"`
	Description *string `json:"description" db:"description"`
}
