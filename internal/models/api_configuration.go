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
	Schema             *APISchema    `json:"schema,omitempty" gorm:"foreignKey:APIConfigurationID"`
}

// AuthenticationConfig holds authentication configuration
type AuthenticationConfig struct {
	Type       string            `json:"type" validate:"required,oneof=api_key oauth basic none"`
	Parameters map[string]string `json:"parameters"`
}

// HeadersConfig holds HTTP headers configuration
type HeadersConfig struct {
	// Static headers that are always sent/required
	Static map[string]string `json:"static"`
	// Required headers for inbound APIs (validation only)
	Required []string `json:"required"`
	// Dynamic headers that can be set per request
	Dynamic map[string]string `json:"dynamic"`
}

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
	return json.Marshal(h)
}

// Scan implements sql.Scanner interface for GORM
func (h *HeadersConfig) Scan(value interface{}) error {
	if value == nil {
		*h = HeadersConfig{
			Static:   make(map[string]string),
			Required: []string{},
			Dynamic:  make(map[string]string),
		}
		return nil
	}

	bytes, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("cannot scan %T into HeadersConfig", value)
	}

	// Try to unmarshal as new structure first
	if err := json.Unmarshal(bytes, h); err != nil {
		// Fallback: try to unmarshal as old map[string]string format for backward compatibility
		var oldHeaders map[string]string
		if err := json.Unmarshal(bytes, &oldHeaders); err != nil {
			return err
		}
		// Convert old format to new format
		*h = HeadersConfig{
			Static:   oldHeaders,
			Required: []string{},
			Dynamic:  make(map[string]string),
		}
	}

	// Initialize maps if nil
	if h.Static == nil {
		h.Static = make(map[string]string)
	}
	if h.Dynamic == nil {
		h.Dynamic = make(map[string]string)
	}
	if h.Required == nil {
		h.Required = []string{}
	}

	return nil
}

// GetAllHeaders returns all static and dynamic headers combined
func (h *HeadersConfig) GetAllHeaders() map[string]string {
	result := make(map[string]string)

	// Add static headers
	for k, v := range h.Static {
		result[k] = v
	}

	// Add dynamic headers (they can override static ones)
	for k, v := range h.Dynamic {
		result[k] = v
	}

	return result
}

// ValidateRequiredHeaders checks if all required headers are present in the request
func (h *HeadersConfig) ValidateRequiredHeaders(requestHeaders map[string][]string) []string {
	var missing []string

	for _, requiredHeader := range h.Required {
		found := false
		for headerName := range requestHeaders {
			if headerName == requiredHeader {
				found = true
				break
			}
		}
		if !found {
			missing = append(missing, requiredHeader)
		}
	}

	return missing
}

// AddStaticHeader adds a static header
func (h *HeadersConfig) AddStaticHeader(name, value string) {
	if h.Static == nil {
		h.Static = make(map[string]string)
	}
	h.Static[name] = value
}

// AddRequiredHeader adds a required header for validation
func (h *HeadersConfig) AddRequiredHeader(name string) {
	if h.Required == nil {
		h.Required = []string{}
	}

	// Check if already exists
	for _, existing := range h.Required {
		if existing == name {
			return
		}
	}

	h.Required = append(h.Required, name)
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
