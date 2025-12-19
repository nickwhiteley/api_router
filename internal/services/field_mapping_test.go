package services

import (
	"context"
	"testing"

	"api-translation-platform/internal/config"
	"api-translation-platform/internal/logger"
	"api-translation-platform/internal/models"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// Use existing MockTransformationService from api_gateway_test.go

func TestFieldMappingTransformation(t *testing.T) {
	// Create test logger and config
	testLogger := logger.NewLogger(&config.Config{
		Logging: config.LoggingConfig{
			Level:  "info",
			Format: "json",
		},
	})

	// Create API gateway service with mock transformation service
	mockTransformService := &MockTransformationService{}

	service := &apiGatewayService{
		logger:           testLogger,
		transformService: mockTransformService,
	}

	t.Run("Simple field mapping without transformation", func(t *testing.T) {
		// Test data
		inputData := map[string]interface{}{
			"user": map[string]interface{}{
				"name":  "John Doe",
				"email": "john@example.com",
			},
		}

		// Field mappings
		mappings := []models.FieldMapping{
			{
				InboundFieldPath:  "user.name",
				OutboundFieldPath: "customer.fullName",
				IsActive:          true,
			},
			{
				InboundFieldPath:  "user.email",
				OutboundFieldPath: "customer.emailAddress",
				IsActive:          true,
			},
		}

		// Execute field mapping transformation
		result, err := service.processFieldMappings(context.Background(), inputData, mappings)

		// Assertions
		assert.NoError(t, err)
		assert.NotNil(t, result)

		// Check mapped values
		assert.Equal(t, "John Doe", result["customer"].(map[string]interface{})["fullName"])
		assert.Equal(t, "john@example.com", result["customer"].(map[string]interface{})["emailAddress"])
	})

	t.Run("Field mapping with transformation script", func(t *testing.T) {
		// Test data
		inputData := map[string]interface{}{
			"user": map[string]interface{}{
				"firstName": "john",
			},
		}

		// Mock transformation service to return uppercase value
		mockTransformService.On("ExecuteScript", mock.Anything, mock.Anything, mock.Anything).Return(
			map[string]interface{}{"value": "JOHN"}, nil,
		)

		// Field mappings with transformation
		mappings := []models.FieldMapping{
			{
				InboundFieldPath:  "user.firstName",
				OutboundFieldPath: "customer.name",
				TransformScript:   "return value.upper()",
				IsActive:          true,
			},
		}

		// Execute field mapping transformation
		result, err := service.processFieldMappings(context.Background(), inputData, mappings)

		// Assertions
		assert.NoError(t, err)
		assert.NotNil(t, result)

		// Check transformed value
		assert.Equal(t, "JOHN", result["customer"].(map[string]interface{})["name"])

		// Verify mock was called
		mockTransformService.AssertExpectations(t)
	})

	t.Run("Missing field should be skipped", func(t *testing.T) {
		// Test data without the expected field
		inputData := map[string]interface{}{
			"user": map[string]interface{}{
				"email": "john@example.com",
			},
		}

		// Field mappings including a missing field
		mappings := []models.FieldMapping{
			{
				InboundFieldPath:  "user.name", // This field doesn't exist
				OutboundFieldPath: "customer.fullName",
				IsActive:          true,
			},
			{
				InboundFieldPath:  "user.email",
				OutboundFieldPath: "customer.emailAddress",
				IsActive:          true,
			},
		}

		// Execute field mapping transformation
		result, err := service.processFieldMappings(context.Background(), inputData, mappings)

		// Assertions
		assert.NoError(t, err)
		assert.NotNil(t, result)

		// Check that only the existing field was mapped
		customer := result["customer"].(map[string]interface{})
		assert.Equal(t, "john@example.com", customer["emailAddress"])
		assert.Nil(t, customer["fullName"]) // Missing field should not be set
	})

	t.Run("Inactive mappings should be skipped", func(t *testing.T) {
		// Test data
		inputData := map[string]interface{}{
			"user": map[string]interface{}{
				"name":  "John Doe",
				"email": "john@example.com",
			},
		}

		// Field mappings with one inactive
		mappings := []models.FieldMapping{
			{
				InboundFieldPath:  "user.name",
				OutboundFieldPath: "customer.fullName",
				IsActive:          false, // Inactive
			},
			{
				InboundFieldPath:  "user.email",
				OutboundFieldPath: "customer.emailAddress",
				IsActive:          true,
			},
		}

		// Execute field mapping transformation
		result, err := service.processFieldMappings(context.Background(), inputData, mappings)

		// Assertions
		assert.NoError(t, err)
		assert.NotNil(t, result)

		// Check that only the active mapping was processed
		customer := result["customer"].(map[string]interface{})
		assert.Equal(t, "john@example.com", customer["emailAddress"])
		assert.Nil(t, customer["fullName"]) // Inactive mapping should not be processed
	})
}
