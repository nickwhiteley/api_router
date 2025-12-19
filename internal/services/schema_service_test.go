package services

import (
	"context"
	"testing"

	"api-translation-platform/internal/config"
	"api-translation-platform/internal/logger"
	"api-translation-platform/internal/models"

	"github.com/stretchr/testify/assert"
)

func TestSchemaService_ParseSampleData(t *testing.T) {
	// Create test logger and config
	testLogger := logger.NewLogger(&config.Config{
		Logging: config.LoggingConfig{
			Level:  "info",
			Format: "json",
		},
	})

	// Create schema service (without repository for this test)
	service := &schemaService{
		logger: testLogger,
	}

	t.Run("Parse simple sample data", func(t *testing.T) {
		sampleData := map[string]interface{}{
			"user": map[string]interface{}{
				"name":  "John Doe",
				"email": "john@example.com",
				"age":   30,
			},
			"active": true,
		}

		fields, err := service.ParseSampleData(context.Background(), sampleData)

		assert.NoError(t, err)
		assert.NotEmpty(t, fields)

		// Check that we have the expected fields
		fieldPaths := make(map[string]string)
		for _, field := range fields {
			fieldPaths[field.Path] = field.Type
		}

		assert.Equal(t, "object", fieldPaths["user"])
		assert.Equal(t, "string", fieldPaths["user.name"])
		assert.Equal(t, "string", fieldPaths["user.email"])
		assert.Equal(t, "integer", fieldPaths["user.age"])
		assert.Equal(t, "boolean", fieldPaths["active"])
	})

	t.Run("Parse nested sample data", func(t *testing.T) {
		sampleData := map[string]interface{}{
			"customer": map[string]interface{}{
				"profile": map[string]interface{}{
					"firstName": "Jane",
					"lastName":  "Smith",
				},
				"address": map[string]interface{}{
					"street": "123 Main St",
					"city":   "Anytown",
				},
			},
		}

		fields, err := service.ParseSampleData(context.Background(), sampleData)

		assert.NoError(t, err)
		assert.NotEmpty(t, fields)

		// Check nested field paths
		fieldPaths := make(map[string]string)
		for _, field := range fields {
			fieldPaths[field.Path] = field.Type
		}

		assert.Equal(t, "object", fieldPaths["customer"])
		assert.Equal(t, "object", fieldPaths["customer.profile"])
		assert.Equal(t, "string", fieldPaths["customer.profile.firstName"])
		assert.Equal(t, "string", fieldPaths["customer.profile.lastName"])
		assert.Equal(t, "object", fieldPaths["customer.address"])
		assert.Equal(t, "string", fieldPaths["customer.address.street"])
		assert.Equal(t, "string", fieldPaths["customer.address.city"])
	})

	t.Run("Parse array sample data", func(t *testing.T) {
		sampleData := map[string]interface{}{
			"users": []interface{}{
				map[string]interface{}{
					"id":   1,
					"name": "User 1",
				},
			},
			"tags": []interface{}{"tag1", "tag2"},
		}

		fields, err := service.ParseSampleData(context.Background(), sampleData)

		assert.NoError(t, err)
		assert.NotEmpty(t, fields)

		// Check array field paths
		fieldPaths := make(map[string]string)
		for _, field := range fields {
			fieldPaths[field.Path] = field.Type
		}

		assert.Equal(t, "array", fieldPaths["users"])
		assert.Equal(t, "array", fieldPaths["tags"])
	})
}

func TestSchemaService_ParseJSONSchema(t *testing.T) {
	// Create test logger
	testLogger := logger.NewLogger(&config.Config{
		Logging: config.LoggingConfig{
			Level:  "info",
			Format: "json",
		},
	})

	service := &schemaService{
		logger: testLogger,
	}

	t.Run("Parse valid JSON schema", func(t *testing.T) {
		jsonSchema := `{
			"type": "object",
			"required": ["name", "email"],
			"properties": {
				"name": {
					"type": "string",
					"description": "User's full name"
				},
				"email": {
					"type": "string",
					"format": "email",
					"description": "User's email address"
				},
				"age": {
					"type": "integer",
					"minimum": 0
				}
			}
		}`

		fields, err := service.ParseJSONSchema(context.Background(), jsonSchema)

		assert.NoError(t, err)
		assert.NotEmpty(t, fields)

		// Check parsed fields
		fieldMap := make(map[string]*models.SchemaField)
		for i, field := range fields {
			fieldMap[field.Path] = &fields[i]
		}

		// Check name field
		nameField := fieldMap["name"]
		assert.NotNil(t, nameField)
		assert.Equal(t, "string", nameField.Type)
		assert.True(t, nameField.Required)
		assert.Equal(t, "User's full name", nameField.Description)

		// Check email field
		emailField := fieldMap["email"]
		assert.NotNil(t, emailField)
		assert.Equal(t, "string", emailField.Type)
		assert.True(t, emailField.Required)
		assert.Equal(t, "email", emailField.Format)

		// Check age field
		ageField := fieldMap["age"]
		assert.NotNil(t, ageField)
		assert.Equal(t, "integer", ageField.Type)
		assert.False(t, ageField.Required)
	})

	t.Run("Parse invalid JSON schema", func(t *testing.T) {
		invalidSchema := `{"invalid": json}`

		_, err := service.ParseJSONSchema(context.Background(), invalidSchema)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid JSON schema")
	})
}
