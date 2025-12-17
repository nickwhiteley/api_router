package services

import (
	"context"
	"testing"

	"api-translation-platform/internal/models"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
)

// **Feature: api-translation-platform, Property 16: Role-based data filtering**
// **Validates: Requirements 6.1, 6.2, 6.3, 6.4, 7.1, 7.3**
func TestProperty_RoleBasedDataFilteringOrganisation(t *testing.T) {
	properties := gopter.NewProperties(nil)

	properties.Property("organisation admins should only see data from their organisation", prop.ForAll(
		func(userOrgID, dataOrgID string) bool {
			// Create organisation admin user
			user := &models.User{
				ID:             "test-user",
				OrganisationID: userOrgID,
				Username:       "orgadmin",
				Email:          "admin@example.com",
				Role:           "org_admin",
				IsActive:       true,
			}

			// Create test data
			apiConfig := &models.APIConfiguration{
				ID:             "test-api",
				OrganisationID: dataOrgID,
				Name:           "Test API",
				Type:           "REST",
				Direction:      "inbound",
				Endpoint:       "https://test.example.com",
				Authentication: models.AuthenticationConfig{
					Type:       "api_key",
					Parameters: map[string]string{"key": "test"},
				},
			}

			// Create authorization service
			mockRepo := &MockRequestLogRepository{}
			testLogger := createTestLogger()
			authService := NewAuthorizationService(testLogger, mockRepo)

			ctx := context.Background()

			// Test filtering
			filteredAPI := authService.FilterByOrganisation(ctx, user, apiConfig)
			if userOrgID == dataOrgID {
				return filteredAPI != nil
			} else {
				return filteredAPI == nil
			}
		},
		gen.Identifier(),
		gen.Identifier(),
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}
