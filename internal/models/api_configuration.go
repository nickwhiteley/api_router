package models

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"time"

	"gorm.io/gorm"
)

// APIConfiguration represents an API endpoint configuration
type APIConfiguration struct {
	ID             string               `json:"id" gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	OrganisationID string               `json:"organisation_id" gorm:"type:uuid;not null;index" validate:"required"`
	Name           string               `json:"name" gorm:"not null" validate:"required,min=1,max=255"`
	Type           string               `json:"type" gorm:"not null" validate:"required,oneof=REST SOAP"`
	Direction      string               `json:"direction" gorm:"not null" validate:"required,oneof=inbound outbound"`
	Endpoint       string               `json:"endpoint" gorm:"not null" validate:"required"`
	Authentication AuthenticationConfig `json:"authentication" gorm:"type:jsonb"`
	Headers        HeadersConfig        `json:"headers" gorm:"type:jsonb"`
	CreatedAt      time.Time            `json:"created_at"`
	UpdatedAt      time.Time            `json:"updated_at"`
	DeletedAt      gorm.DeletedAt       `json:"-" gorm:"index"`

	// Relationships
	Organisation       *Organisation `json:"organisation,omitempty" gorm:"foreignKey:OrganisationID"`
	InboundConnectors  []Connector   `json:"inbound_connectors,omitempty" gorm:"foreignKey:InboundAPIID"`
	OutboundConnectors []Connector   `json:"outbound_connectors,omitempty" gorm:"foreignKey:OutboundAPIID"`
}

// AuthenticationConfig holds authentication configuration
type AuthenticationConfig struct {
	Type       string            `json:"type" validate:"required,oneof=api_key oauth basic none"`
	Parameters map[string]string `json:"parameters"`
}

// HeadersConfig holds HTTP headers configuration
type HeadersConfig map[string]string

// Value implements driver.Valuer interface for GORM
func (a AuthenticationConfig) Value() (driver.Value, error) {
	return json.Marshal(a)
}

// Scan implements sql.Scanner interface for GORM
func (a *AuthenticationConfig) Scan(value interface{}) error {
	if value == nil {
		return nil
	}

	bytes, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("cannot scan %T into AuthenticationConfig", value)
	}

	return json.Unmarshal(bytes, a)
}

// Value implements driver.Valuer interface for GORM
func (h HeadersConfig) Value() (driver.Value, error) {
	if h == nil {
		return nil, nil
	}
	return json.Marshal(h)
}

// Scan implements sql.Scanner interface for GORM
func (h *HeadersConfig) Scan(value interface{}) error {
	if value == nil {
		*h = make(HeadersConfig)
		return nil
	}

	bytes, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("cannot scan %T into HeadersConfig", value)
	}

	return json.Unmarshal(bytes, h)
}

// TableName returns the table name for APIConfiguration
func (APIConfiguration) TableName() string {
	return "api_configurations"
}

// IsInbound checks if the API configuration is for inbound requests
func (a *APIConfiguration) IsInbound() bool {
	return a.Direction == "inbound"
}

// IsOutbound checks if the API configuration is for outbound requests
func (a *APIConfiguration) IsOutbound() bool {
	return a.Direction == "outbound"
}

// IsREST checks if the API configuration is for REST protocol
func (a *APIConfiguration) IsREST() bool {
	return a.Type == "REST"
}

// IsSOAP checks if the API configuration is for SOAP protocol
func (a *APIConfiguration) IsSOAP() bool {
	return a.Type == "SOAP"
}
