package models

import (
	"time"

	"gorm.io/gorm"
)

// User represents a system user
type User struct {
	ID             string         `json:"id" gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	OrganisationID string         `json:"organisation_id" gorm:"type:uuid;not null;index" validate:"required"`
	Username       string         `json:"username" gorm:"not null;uniqueIndex" validate:"required,min=3,max=50"`
	Email          string         `json:"email" gorm:"not null;uniqueIndex" validate:"required,email"`
	PasswordHash   string         `json:"-" gorm:"not null"`
	Role           string         `json:"role" gorm:"not null" validate:"required,oneof=org_admin global_admin"`
	IsActive       bool           `json:"is_active" gorm:"default:true"`
	CreatedAt      time.Time      `json:"created_at"`
	UpdatedAt      time.Time      `json:"updated_at"`
	DeletedAt      gorm.DeletedAt `json:"-" gorm:"index"`

	// Relationships
	Organisation *Organisation `json:"organisation,omitempty" gorm:"foreignKey:OrganisationID"`
}

// TableName returns the table name for User
func (User) TableName() string {
	return "users"
}

// IsGlobalAdmin checks if the user has global admin privileges
func (u *User) IsGlobalAdmin() bool {
	return u.Role == "global_admin"
}

// IsOrgAdmin checks if the user has organisation admin privileges
func (u *User) IsOrgAdmin() bool {
	return u.Role == "org_admin"
}
