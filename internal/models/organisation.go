package models

import (
	"time"

	"gorm.io/gorm"
)

// Organisation represents a tenant entity in the system
type Organisation struct {
	ID        string         `json:"id" gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	Name      string         `json:"name" gorm:"not null;uniqueIndex" validate:"required,min=1,max=255"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `json:"-" gorm:"index"`
	IsActive  bool           `json:"is_active" gorm:"default:true"`

	// Relationships
	Users             []User             `json:"users,omitempty" gorm:"foreignKey:OrganisationID"`
	APIConfigurations []APIConfiguration `json:"api_configurations,omitempty" gorm:"foreignKey:OrganisationID"`
	Connectors        []Connector        `json:"connectors,omitempty" gorm:"foreignKey:OrganisationID"`
	RequestLogs       []RequestLog       `json:"request_logs,omitempty" gorm:"foreignKey:OrganisationID"`
}

// TableName returns the table name for Organisation
func (Organisation) TableName() string {
	return "organisations"
}
