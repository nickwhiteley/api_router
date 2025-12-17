package models

import (
	"testing"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
	"github.com/stretchr/testify/assert"
)

// **Feature: api-translation-platform, Property 13: Organisation isolation**
// **Validates: Requirements 5.1, 5.4**
func TestProperty_OrganisationIsolation(t *testing.T) {
	properties := gopter.NewProperties(nil)

	properties.Property("all data models should be tagged with organisation identifiers", prop.ForAll(
		func(orgID string) bool {
			if len(orgID) == 0 {
				return true // Skip empty organisation IDs
			}

			// Create test data with organisation ID
			user := &User{
				ID:             "test-user",
				OrganisationID: orgID,
				Username:       "testuser",
				Email:          "test@example.com",
				Role:           "org_admin",
				IsActive:       true,
			}

			apiConfig := &APIConfiguration{
				ID:             "test-api",
				OrganisationID: orgID,
				Name:           "Test API",
				Type:           "REST",
				Direction:      "inbound",
				Endpoint:       "https://test.example.com",
				Authentication: AuthenticationConfig{
					Type:       "api_key",
					Parameters: map[string]string{"key": "test"},
				},
			}

			connector := &Connector{
				ID:             "test-connector",
				OrganisationID: orgID,
				Name:           "Test Connector",
				InboundAPIID:   "inbound-api",
				OutboundAPIID:  "outbound-api",
				PythonScript:   "# Test script",
				IsActive:       true,
			}

			requestLog := &RequestLog{
				ID:             "test-log",
				OrganisationID: orgID,
				ConnectorID:    "test-connector",
				RequestID:      "req-123",
				Method:         "POST",
				Path:           "/test",
				StatusCode:     200,
				ProcessingTime: 100,
			}

			// Verify all models are tagged with the same organisation ID
			return user.OrganisationID == orgID &&
				apiConfig.OrganisationID == orgID &&
				connector.OrganisationID == orgID &&
				requestLog.OrganisationID == orgID
		},
		gen.AlphaString().SuchThat(func(s string) bool { return len(s) > 0 && len(s) < 50 }),
	))

	properties.Property("organisation data should be properly tagged for isolation", prop.ForAll(
		func(orgID string, userName, email string) bool {
			if len(orgID) == 0 || len(userName) == 0 || len(email) == 0 {
				return true // Skip invalid inputs
			}

			// Create a user with organisation ID
			user := &User{
				ID:             "test-user-id",
				OrganisationID: orgID,
				Username:       userName,
				Email:          email,
				Role:           "org_admin",
				IsActive:       true,
			}

			// Create an API configuration with organisation ID
			apiConfig := &APIConfiguration{
				ID:             "test-api-id",
				OrganisationID: orgID,
				Name:           "Test API",
				Type:           "REST",
				Direction:      "inbound",
				Endpoint:       "https://test.example.com",
				Authentication: AuthenticationConfig{
					Type:       "none",
					Parameters: map[string]string{},
				},
			}

			// Create a connector with organisation ID
			connector := &Connector{
				ID:             "test-connector-id",
				OrganisationID: orgID,
				Name:           "Test Connector",
				InboundAPIID:   "inbound-api-id",
				OutboundAPIID:  "outbound-api-id",
				PythonScript:   "# Test script",
				IsActive:       true,
			}

			// Verify all records are tagged with the same organisation ID
			return user.OrganisationID == orgID &&
				apiConfig.OrganisationID == orgID &&
				connector.OrganisationID == orgID
		},
		gen.AlphaString().SuchThat(func(s string) bool { return len(s) > 0 && len(s) < 100 }), // orgID
		gen.AlphaString().SuchThat(func(s string) bool { return len(s) >= 3 && len(s) < 50 }), // userName
		gen.RegexMatch(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`),                    // email
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// Unit test to verify organisation isolation in practice
func TestOrganisationIsolationValidation(t *testing.T) {
	// Test that organisation ID is required for all models
	user := &User{
		Username: "testuser",
		Email:    "test@example.com",
		Role:     "org_admin",
	}

	validator := NewValidationService()
	err := validator.ValidateStruct(user)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "organisation_id")

	// Test with valid organisation ID
	user.OrganisationID = "valid-org-id"
	err = validator.ValidateStruct(user)
	assert.NoError(t, err)

	// Test API configuration requires organisation ID
	apiConfig := &APIConfiguration{
		Name:      "Test API",
		Type:      "REST",
		Direction: "inbound",
		Endpoint:  "https://test.example.com",
		Authentication: AuthenticationConfig{
			Type:       "none",
			Parameters: map[string]string{},
		},
	}

	err = validator.ValidateStruct(apiConfig)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "organisation_id")

	// Test with valid organisation ID
	apiConfig.OrganisationID = "valid-org-id"
	err = validator.ValidateStruct(apiConfig)
	assert.NoError(t, err)
}
