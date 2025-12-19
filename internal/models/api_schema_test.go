package models

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAPISchema(t *testing.T) {
	validator := NewValidationService()

	t.Run("Valid API schema", func(t *testing.T) {
		schema := &APISchema{
			APIConfigurationID: "api-123",
			SchemaType:         "json_schema",
			SchemaContent: SchemaContent{
				Raw:         `{"type": "object", "properties": {"name": {"type": "string"}}}`,
				Description: "Test schema",
			},
			ParsedFields: SchemaFields{
				{
					Path:        "name",
					Type:        "string",
					Required:    true,
					Description: "User name",
				},
			},
		}
		err := validator.ValidateStruct(schema)
		assert.NoError(t, err)
	})

	t.Run("Invalid schema - missing API configuration ID", func(t *testing.T) {
		schema := &APISchema{
			SchemaType: "json_schema",
		}
		err := validator.ValidateStruct(schema)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "api_configuration_id")
	})

	t.Run("Invalid schema - invalid schema type", func(t *testing.T) {
		schema := &APISchema{
			APIConfigurationID: "api-123",
			SchemaType:         "invalid_type",
		}
		err := validator.ValidateStruct(schema)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "schema_type")
	})

	t.Run("Schema field operations", func(t *testing.T) {
		schema := &APISchema{
			ParsedFields: SchemaFields{
				{Path: "user.name", Type: "string"},
				{Path: "user.email", Type: "string"},
			},
		}

		// Test GetFieldByPath
		field := schema.GetFieldByPath("user.name")
		assert.NotNil(t, field)
		assert.Equal(t, "user.name", field.Path)
		assert.Equal(t, "string", field.Type)

		// Test GetFieldPaths
		paths := schema.GetFieldPaths()
		assert.Len(t, paths, 2)
		assert.Contains(t, paths, "user.name")
		assert.Contains(t, paths, "user.email")

		// Test AddField (new field)
		newField := SchemaField{Path: "user.phone", Type: "string"}
		schema.AddField(newField)
		assert.Len(t, schema.ParsedFields, 3)

		// Test AddField (update existing field)
		updatedField := SchemaField{Path: "user.name", Type: "string", Required: true}
		schema.AddField(updatedField)
		assert.Len(t, schema.ParsedFields, 3) // Should not increase
		field = schema.GetFieldByPath("user.name")
		assert.True(t, field.Required)

		// Test RemoveField
		schema.RemoveField("user.email")
		assert.Len(t, schema.ParsedFields, 2)
		field = schema.GetFieldByPath("user.email")
		assert.Nil(t, field)
	})

	t.Run("Schema field validation", func(t *testing.T) {
		field := &SchemaField{
			Path:        "user.name",
			Type:        "string",
			Required:    true,
			Description: "User's full name",
			Example:     "John Doe",
			Format:      "text",
		}
		err := validator.ValidateStruct(field)
		assert.NoError(t, err)
	})

	t.Run("API schema table name", func(t *testing.T) {
		schema := APISchema{}
		assert.Equal(t, "api_schemas", schema.TableName())
	})
}
