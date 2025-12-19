package models

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"time"

	"gorm.io/gorm"
)

// APISchema represents the structure/schema of an API
type APISchema struct {
	ID                 string         `json:"id" gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	APIConfigurationID string         `json:"api_configuration_id" gorm:"type:uuid;not null;index" validate:"required"`
	SchemaType         string         `json:"schema_type" gorm:"not null" validate:"required,oneof=json_schema openapi_v3 wsdl custom"`
	SchemaContent      SchemaContent  `json:"schema_content" gorm:"type:jsonb"`
	ParsedFields       SchemaFields   `json:"parsed_fields" gorm:"type:jsonb"`
	CreatedAt          time.Time      `json:"created_at"`
	UpdatedAt          time.Time      `json:"updated_at"`
	DeletedAt          gorm.DeletedAt `json:"-" gorm:"index"`

	// Relationships
	APIConfiguration *APIConfiguration `json:"api_configuration,omitempty" gorm:"foreignKey:APIConfigurationID"`
}

// SchemaContent holds the raw schema definition
type SchemaContent struct {
	Raw         string                 `json:"raw,omitempty"`         // Raw schema text (JSON Schema, OpenAPI, WSDL, etc.)
	Parsed      map[string]interface{} `json:"parsed,omitempty"`      // Parsed schema object
	SampleData  map[string]interface{} `json:"sample_data,omitempty"` // Sample request/response data
	Description string                 `json:"description,omitempty"` // Human-readable description
}

// SchemaField represents a field in the API schema for field mapping
type SchemaField struct {
	Path        string                 `json:"path"`                  // JSON path (e.g., "user.name", "address.street")
	Type        string                 `json:"type"`                  // Data type (string, number, boolean, object, array)
	Required    bool                   `json:"required"`              // Whether the field is required
	Description string                 `json:"description,omitempty"` // Field description
	Example     interface{}            `json:"example,omitempty"`     // Example value
	Format      string                 `json:"format,omitempty"`      // Format (email, date, uuid, etc.)
	Enum        []interface{}          `json:"enum,omitempty"`        // Allowed values for enum fields
	Properties  map[string]interface{} `json:"properties,omitempty"`  // Additional properties
}

// SchemaFields is a custom type for handling GORM serialization
type SchemaFields []SchemaField

// Value implements driver.Valuer interface for GORM
func (s SchemaContent) Value() (driver.Value, error) {
	return json.Marshal(s)
}

// Scan implements sql.Scanner interface for GORM
func (s *SchemaContent) Scan(value interface{}) error {
	if value == nil {
		return nil
	}

	bytes, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("cannot scan %T into SchemaContent", value)
	}

	return json.Unmarshal(bytes, s)
}

// Value implements driver.Valuer interface for GORM
func (s SchemaFields) Value() (driver.Value, error) {
	return json.Marshal(s)
}

// Scan implements sql.Scanner interface for GORM
func (s *SchemaFields) Scan(value interface{}) error {
	if value == nil {
		*s = SchemaFields{}
		return nil
	}

	bytes, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("cannot scan %T into SchemaFields", value)
	}

	return json.Unmarshal(bytes, s)
}

// TableName returns the table name for APISchema
func (APISchema) TableName() string {
	return "api_schemas"
}

// GetFieldByPath returns a schema field by its path
func (a *APISchema) GetFieldByPath(path string) *SchemaField {
	for i, field := range a.ParsedFields {
		if field.Path == path {
			return &a.ParsedFields[i]
		}
	}
	return nil
}

// GetFieldPaths returns all available field paths
func (a *APISchema) GetFieldPaths() []string {
	paths := make([]string, len(a.ParsedFields))
	for i, field := range a.ParsedFields {
		paths[i] = field.Path
	}
	return paths
}

// AddField adds a new field to the schema
func (a *APISchema) AddField(field SchemaField) {
	// Check if field already exists
	for i, existingField := range a.ParsedFields {
		if existingField.Path == field.Path {
			// Update existing field
			a.ParsedFields[i] = field
			return
		}
	}
	// Add new field
	a.ParsedFields = append(a.ParsedFields, field)
}

// RemoveField removes a field from the schema
func (a *APISchema) RemoveField(path string) {
	for i, field := range a.ParsedFields {
		if field.Path == path {
			a.ParsedFields = append(a.ParsedFields[:i], a.ParsedFields[i+1:]...)
			return
		}
	}
}
