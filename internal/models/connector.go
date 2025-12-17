package models

import (
	"time"

	"gorm.io/gorm"
)

// Connector represents a Python-scripted transformation component
type Connector struct {
	ID             string         `json:"id" gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	OrganisationID string         `json:"organisation_id" gorm:"type:uuid;not null;index" validate:"required"`
	Name           string         `json:"name" gorm:"not null" validate:"required,min=1,max=255"`
	InboundAPIID   string         `json:"inbound_api_id" gorm:"type:uuid;not null;index" validate:"required"`
	OutboundAPIID  string         `json:"outbound_api_id" gorm:"type:uuid;not null;index" validate:"required"`
	PythonScript   string         `json:"python_script" gorm:"type:text" validate:"required"`
	IsActive       bool           `json:"is_active" gorm:"default:true"`
	CreatedAt      time.Time      `json:"created_at"`
	UpdatedAt      time.Time      `json:"updated_at"`
	DeletedAt      gorm.DeletedAt `json:"-" gorm:"index"`

	// Relationships
	Organisation *Organisation     `json:"organisation,omitempty" gorm:"foreignKey:OrganisationID"`
	InboundAPI   *APIConfiguration `json:"inbound_api,omitempty" gorm:"foreignKey:InboundAPIID"`
	OutboundAPI  *APIConfiguration `json:"outbound_api,omitempty" gorm:"foreignKey:OutboundAPIID"`
	RequestLogs  []RequestLog      `json:"request_logs,omitempty" gorm:"foreignKey:ConnectorID"`
}

// TableName returns the table name for Connector
func (Connector) TableName() string {
	return "connectors"
}
