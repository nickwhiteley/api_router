package models

import (
	"time"

	"gorm.io/gorm"
)

// FieldMapping represents a mapping between an inbound field and an outbound field
type FieldMapping struct {
	ID                string         `json:"id" gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	ConnectorID       string         `json:"connector_id" gorm:"type:uuid;not null;index" validate:"required"`
	InboundFieldPath  string         `json:"inbound_field_path" gorm:"not null" validate:"required"`
	OutboundFieldPath string         `json:"outbound_field_path" gorm:"not null" validate:"required"`
	TransformScript   string         `json:"transform_script,omitempty" gorm:"type:text"`
	IsActive          bool           `json:"is_active" gorm:"default:true"`
	CreatedAt         time.Time      `json:"created_at"`
	UpdatedAt         time.Time      `json:"updated_at"`
	DeletedAt         gorm.DeletedAt `json:"-" gorm:"index"`

	// Relationships
	Connector *Connector `json:"connector,omitempty" gorm:"foreignKey:ConnectorID"`
}

// TableName returns the table name for FieldMapping
func (FieldMapping) TableName() string {
	return "field_mappings"
}
