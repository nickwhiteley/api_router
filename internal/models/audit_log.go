package models

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"time"
)

// AuditLog represents an immutable audit log entry for configuration changes
type AuditLog struct {
	ID             string    `json:"id" gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	OrganisationID string    `json:"organisation_id" gorm:"type:uuid;not null;index" validate:"required"`
	UserID         string    `json:"user_id" gorm:"type:uuid;not null;index" validate:"required"`
	Action         string    `json:"action" gorm:"not null" validate:"required,oneof=CREATE UPDATE DELETE"`
	ResourceType   string    `json:"resource_type" gorm:"not null" validate:"required"`
	ResourceID     string    `json:"resource_id" gorm:"not null;index" validate:"required"`
	OldValues      JSONMap   `json:"old_values,omitempty" gorm:"type:jsonb"`
	NewValues      JSONMap   `json:"new_values,omitempty" gorm:"type:jsonb"`
	Timestamp      time.Time `json:"timestamp" gorm:"not null;index"`
	IPAddress      string    `json:"ip_address,omitempty"`
	UserAgent      string    `json:"user_agent,omitempty"`
	CreatedAt      time.Time `json:"created_at"`

	// Relationships
	Organisation *Organisation `json:"organisation,omitempty" gorm:"foreignKey:OrganisationID"`
	User         *User         `json:"user,omitempty" gorm:"foreignKey:UserID"`
}

// TableName returns the table name for AuditLog
func (AuditLog) TableName() string {
	return "audit_logs"
}

// ConfigurationVersion represents a versioned configuration snapshot
type ConfigurationVersion struct {
	ID                string    `json:"id" gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	OrganisationID    string    `json:"organisation_id" gorm:"type:uuid;not null;index" validate:"required"`
	ResourceType      string    `json:"resource_type" gorm:"not null" validate:"required"`
	ResourceID        string    `json:"resource_id" gorm:"not null;index" validate:"required"`
	Version           int       `json:"version" gorm:"not null;index"`
	ConfigurationData JSONMap   `json:"configuration_data" gorm:"type:jsonb;not null"`
	CreatedBy         string    `json:"created_by" gorm:"type:uuid;not null" validate:"required"`
	CreatedAt         time.Time `json:"created_at"`
	IsActive          bool      `json:"is_active" gorm:"default:true"`

	// Relationships
	Organisation *Organisation `json:"organisation,omitempty" gorm:"foreignKey:OrganisationID"`
	Creator      *User         `json:"creator,omitempty" gorm:"foreignKey:CreatedBy"`
}

// TableName returns the table name for ConfigurationVersion
func (ConfigurationVersion) TableName() string {
	return "configuration_versions"
}

// JSONMap is a custom type for map[string]interface{} that implements GORM interfaces
type JSONMap map[string]interface{}

// Value implements driver.Valuer interface for GORM
func (m JSONMap) Value() (driver.Value, error) {
	if m == nil {
		return nil, nil
	}
	return json.Marshal(m)
}

// Scan implements sql.Scanner interface for GORM
func (m *JSONMap) Scan(value interface{}) error {
	if value == nil {
		*m = nil
		return nil
	}

	bytes, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("cannot scan %T into JSONMap", value)
	}

	return json.Unmarshal(bytes, m)
}
