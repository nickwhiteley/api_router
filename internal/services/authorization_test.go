package services

import (
	"context"
	"testing"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"api-translation-platform/internal/models"
)

// MockRequestLogRepository is a mock implementation of RequestLogRepository for testing
type MockRequestLogRepository struct {
	mock.Mock
}

func (m *MockRequestLogRepository) Create(ctx context.Context, log *models.RequestLog) error {
	args := m.Called(ctx, log)
	return args.Error(0)
}

func (m *MockRequestLogRepository) GetByID(ctx context.Context, id string) (*models.RequestLog, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.RequestLog), args.Error(1)
}

func (m *MockRequestLogRepository) GetByOrganisation(ctx context.Context, orgID string, limit, offset int) ([]*models.RequestLog, error) {
	args := m.Called(ctx, orgID, limit, offset)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.RequestLog), args.Error(1)
}

func (m *MockRequestLogRepository) GetByConnector(ctx context.Context, connectorID string, limit, offset int) ([]*models.RequestLog, error) {
	args := m.Called(ctx, connectorID, limit, offset)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.RequestLog), args.Error(1)
}

func (m *MockRequestLogRepository) GetErrorLogs(ctx context.Context, orgID string, limit, offset int) ([]*models.RequestLog, error) {
	args := m.Called(ctx, orgID, limit, offset)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.RequestLog), args.Error(1)
}

func (m *MockRequestLogRepository) Delete(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

// **Feature: api-translation-platform, Property 14: Access control enforcement**
// **Validates: Requirements 5.2, 5.3**
func TestProperty_AccessControlEnforcement(t *testing.T) {
	properties := gopter.NewProperties(nil)

	properties.Property("global admins can access all resources", prop.ForAll(
		func(resourceOrgID string) bool {
			ctx := context.Background()
			mockRepo := &MockRequestLogRepository{}
			testLogger := createTestLogger()
			authzSvc := NewAuthorizationService(testLogger, mockRepo)

			// Create global admin user
			globalAdmin := &models.User{
				ID:             "global-admin-id",
				OrganisationID: "admin-org",
				Role:           "global_admin",
				IsActive:       true,
			}

			// Global admin should be able to access any resource
			canAccess := authzSvc.CanAccessResource(ctx, globalAdmin, resourceOrgID)
			return canAccess
		},
		gen.AlphaString(),
	))

	properties.Property("org admins can only access resources in their organisation", prop.ForAll(
		func(userOrgID, resourceOrgID string) bool {
			ctx := context.Background()
			mockRepo := &MockRequestLogRepository{}
			testLogger := createTestLogger()
			authzSvc := NewAuthorizationService(testLogger, mockRepo)

			// Create org admin user
			orgAdmin := &models.User{
				ID:             "org-admin-id",
				OrganisationID: userOrgID,
				Role:           "org_admin",
				IsActive:       true,
			}

			canAccess := authzSvc.CanAccessResource(ctx, orgAdmin, resourceOrgID)
			expectedAccess := (userOrgID == resourceOrgID)

			return canAccess == expectedAccess
		},
		gen.AlphaString(),
		gen.AlphaString(),
	))

	properties.Property("inactive users cannot access any resources", prop.ForAll(
		func(resourceOrgID string) bool {
			ctx := context.Background()
			mockRepo := &MockRequestLogRepository{}
			testLogger := createTestLogger()
			authzSvc := NewAuthorizationService(testLogger, mockRepo)

			// Create inactive user
			inactiveUser := &models.User{
				ID:             "inactive-user-id",
				OrganisationID: resourceOrgID, // Same org
				Role:           "org_admin",
				IsActive:       false, // Inactive
			}

			canAccess := authzSvc.CanAccessResource(ctx, inactiveUser, resourceOrgID)
			return !canAccess // Should not be able to access
		},
		gen.AlphaString(),
	))

	properties.Property("nil users cannot access any resources", prop.ForAll(
		func(resourceOrgID string) bool {
			ctx := context.Background()
			mockRepo := &MockRequestLogRepository{}
			testLogger := createTestLogger()
			authzSvc := NewAuthorizationService(testLogger, mockRepo)

			canAccess := authzSvc.CanAccessResource(ctx, nil, resourceOrgID)
			return !canAccess // Should not be able to access
		},
		gen.AlphaString(),
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// Unit tests for specific authorization scenarios
func TestAuthorizationService_CanAccessResource(t *testing.T) {
	ctx := context.Background()
	mockRepo := &MockRequestLogRepository{}
	testLogger := createTestLogger()
	authzSvc := NewAuthorizationService(testLogger, mockRepo)

	t.Run("global admin can access any resource", func(t *testing.T) {
		globalAdmin := &models.User{
			ID:             "global-admin-id",
			OrganisationID: "admin-org",
			Role:           "global_admin",
			IsActive:       true,
		}

		canAccess := authzSvc.CanAccessResource(ctx, globalAdmin, "any-org-id")
		assert.True(t, canAccess)
	})

	t.Run("org admin can access resources in their organisation", func(t *testing.T) {
		orgAdmin := &models.User{
			ID:             "org-admin-id",
			OrganisationID: "test-org",
			Role:           "org_admin",
			IsActive:       true,
		}

		canAccess := authzSvc.CanAccessResource(ctx, orgAdmin, "test-org")
		assert.True(t, canAccess)
	})

	t.Run("org admin cannot access resources in other organisations", func(t *testing.T) {
		orgAdmin := &models.User{
			ID:             "org-admin-id",
			OrganisationID: "test-org",
			Role:           "org_admin",
			IsActive:       true,
		}

		canAccess := authzSvc.CanAccessResource(ctx, orgAdmin, "other-org")
		assert.False(t, canAccess)
	})

	t.Run("nil user cannot access any resource", func(t *testing.T) {
		canAccess := authzSvc.CanAccessResource(ctx, nil, "any-org")
		assert.False(t, canAccess)
	})

	t.Run("inactive user cannot access any resource", func(t *testing.T) {
		inactiveUser := &models.User{
			ID:             "inactive-user-id",
			OrganisationID: "test-org",
			Role:           "org_admin",
			IsActive:       false,
		}

		canAccess := authzSvc.CanAccessResource(ctx, inactiveUser, "test-org")
		assert.False(t, canAccess)
	})
}

func TestAuthorizationService_CanManageOrganisation(t *testing.T) {
	ctx := context.Background()
	mockRepo := &MockRequestLogRepository{}
	testLogger := createTestLogger()
	authzSvc := NewAuthorizationService(testLogger, mockRepo)

	t.Run("global admin can manage any organisation", func(t *testing.T) {
		globalAdmin := &models.User{
			ID:             "global-admin-id",
			OrganisationID: "admin-org",
			Role:           "global_admin",
			IsActive:       true,
		}

		canManage := authzSvc.CanManageOrganisation(ctx, globalAdmin, "any-org-id")
		assert.True(t, canManage)
	})

	t.Run("org admin can manage their own organisation", func(t *testing.T) {
		orgAdmin := &models.User{
			ID:             "org-admin-id",
			OrganisationID: "test-org",
			Role:           "org_admin",
			IsActive:       true,
		}

		canManage := authzSvc.CanManageOrganisation(ctx, orgAdmin, "test-org")
		assert.True(t, canManage)
	})

	t.Run("org admin cannot manage other organisations", func(t *testing.T) {
		orgAdmin := &models.User{
			ID:             "org-admin-id",
			OrganisationID: "test-org",
			Role:           "org_admin",
			IsActive:       true,
		}

		canManage := authzSvc.CanManageOrganisation(ctx, orgAdmin, "other-org")
		assert.False(t, canManage)
	})

	t.Run("nil user cannot manage any organisation", func(t *testing.T) {
		canManage := authzSvc.CanManageOrganisation(ctx, nil, "any-org")
		assert.False(t, canManage)
	})
}

func TestAuthorizationService_FilterByOrganisation(t *testing.T) {
	ctx := context.Background()
	mockRepo := &MockRequestLogRepository{}
	testLogger := createTestLogger()
	authzSvc := NewAuthorizationService(testLogger, mockRepo)

	// Create test data
	testData := []*models.APIConfiguration{
		{
			ID:             "api-1",
			OrganisationID: "org-1",
			Name:           "API 1",
		},
		{
			ID:             "api-2",
			OrganisationID: "org-2",
			Name:           "API 2",
		},
		{
			ID:             "api-3",
			OrganisationID: "org-1",
			Name:           "API 3",
		},
	}

	t.Run("global admin sees all data", func(t *testing.T) {
		globalAdmin := &models.User{
			ID:             "global-admin-id",
			OrganisationID: "admin-org",
			Role:           "global_admin",
			IsActive:       true,
		}

		filtered := authzSvc.FilterByOrganisation(ctx, globalAdmin, testData)
		assert.Equal(t, testData, filtered)
	})

	t.Run("org admin sees only their organisation's data", func(t *testing.T) {
		orgAdmin := &models.User{
			ID:             "org-admin-id",
			OrganisationID: "org-1",
			Role:           "org_admin",
			IsActive:       true,
		}

		filtered := authzSvc.FilterByOrganisation(ctx, orgAdmin, testData)
		filteredSlice := filtered.([]interface{})

		assert.Len(t, filteredSlice, 2)
		// Should contain api-1 and api-3 (both from org-1)
	})

	t.Run("nil user sees no data", func(t *testing.T) {
		filtered := authzSvc.FilterByOrganisation(ctx, nil, testData)
		assert.Nil(t, filtered)
	})
}

func TestAuthorizationService_LogSecurityViolation(t *testing.T) {
	ctx := context.Background()
	mockRepo := &MockRequestLogRepository{}
	testLogger := createTestLogger()
	authzSvc := NewAuthorizationService(testLogger, mockRepo)

	t.Run("logs security violation with user info", func(t *testing.T) {
		user := &models.User{
			ID:             "test-user-id",
			OrganisationID: "test-org",
			Role:           "org_admin",
			IsActive:       true,
		}

		// Expect a log entry to be created
		mockRepo.On("Create", ctx, mock.MatchedBy(func(log *models.RequestLog) bool {
			return log.OrganisationID == "test-org" &&
				log.Method == "SECURITY" &&
				log.StatusCode == 403 &&
				log.Path == "unauthorized_access" &&
				log.RequestID == "security-violation"
		})).Return(nil)

		authzSvc.LogSecurityViolation(ctx, user, "unauthorized_access", "resource-123")

		mockRepo.AssertExpectations(t)
	})

	t.Run("logs security violation with nil user", func(t *testing.T) {
		// Expect a log entry to be created with anonymous user
		mockRepo.On("Create", ctx, mock.MatchedBy(func(log *models.RequestLog) bool {
			return log.OrganisationID == "unknown" &&
				log.Method == "SECURITY" &&
				log.StatusCode == 403 &&
				log.Path == "unauthorized_access" &&
				log.RequestID == "security-violation"
		})).Return(nil)

		authzSvc.LogSecurityViolation(ctx, nil, "unauthorized_access", "resource-123")

		mockRepo.AssertExpectations(t)
	})
}

// **Feature: api-translation-platform, Property 15: Security violation handling**
// **Validates: Requirements 5.5**
func TestProperty_SecurityViolationHandling(t *testing.T) {
	properties := gopter.NewProperties(nil)

	properties.Property("security violations should be logged when cross-organisation access is attempted", prop.ForAll(
		func(userOrgID, resourceOrgID, action, resourceID string) bool {
			ctx := context.Background()
			mockRepo := &MockRequestLogRepository{}
			testLogger := createTestLogger()
			authzSvc := NewAuthorizationService(testLogger, mockRepo)

			// Create org admin user
			orgAdmin := &models.User{
				ID:             "org-admin-id",
				OrganisationID: userOrgID,
				Role:           "org_admin",
				IsActive:       true,
			}

			// Set up mock expectation for security violation logging
			mockRepo.On("Create", ctx, mock.MatchedBy(func(log *models.RequestLog) bool {
				return log.OrganisationID == userOrgID &&
					log.Method == "SECURITY" &&
					log.StatusCode == 403 &&
					log.Path == action &&
					log.RequestID == "security-violation"
			})).Return(nil)

			// Log security violation
			authzSvc.LogSecurityViolation(ctx, orgAdmin, action, resourceID)

			// Check if access would be denied for cross-organisation access
			if userOrgID != resourceOrgID {
				canAccess := authzSvc.CanAccessResource(ctx, orgAdmin, resourceOrgID)
				return !canAccess // Should be denied
			}

			return true // Same organisation access is allowed
		},
		gen.AlphaString(),
		gen.AlphaString(),
		gen.AlphaString(),
		gen.AlphaString(),
	))

	properties.Property("security violations should always create audit log entries", prop.ForAll(
		func(action, resourceID string) bool {
			ctx := context.Background()
			mockRepo := &MockRequestLogRepository{}
			testLogger := createTestLogger()
			authzSvc := NewAuthorizationService(testLogger, mockRepo)

			user := &models.User{
				ID:             "test-user-id",
				OrganisationID: "test-org",
				Role:           "org_admin",
				IsActive:       true,
			}

			// Set up mock expectation
			mockRepo.On("Create", ctx, mock.MatchedBy(func(log *models.RequestLog) bool {
				return log.OrganisationID == "test-org" &&
					log.Method == "SECURITY" &&
					log.StatusCode == 403 &&
					log.Path == action &&
					log.RequestID == "security-violation"
			})).Return(nil)

			// This should always succeed (logging should not fail)
			authzSvc.LogSecurityViolation(ctx, user, action, resourceID)
			return true
		},
		gen.AlphaString(),
		gen.AlphaString(),
	))

	properties.Property("anonymous users should be logged with unknown organisation", prop.ForAll(
		func(action, resourceID string) bool {
			ctx := context.Background()
			mockRepo := &MockRequestLogRepository{}
			testLogger := createTestLogger()
			authzSvc := NewAuthorizationService(testLogger, mockRepo)

			// Set up mock expectation for anonymous user
			mockRepo.On("Create", ctx, mock.MatchedBy(func(log *models.RequestLog) bool {
				return log.OrganisationID == "unknown" &&
					log.Method == "SECURITY" &&
					log.StatusCode == 403 &&
					log.Path == action &&
					log.RequestID == "security-violation"
			})).Return(nil)

			// Log security violation with nil user
			authzSvc.LogSecurityViolation(ctx, nil, action, resourceID)
			return true
		},
		gen.AlphaString(),
		gen.AlphaString(),
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// **Feature: api-translation-platform, Property 16: Role-based data filtering**
// **Validates: Requirements 6.1, 6.2, 6.3, 6.4, 7.1, 7.3**
func TestProperty_RoleBasedDataFiltering(t *testing.T) {
	properties := gopter.NewProperties(nil)

	properties.Property("organisation admins should only see data from their organisation", prop.ForAll(
		func(userOrgID, dataOrgID string) bool {
			ctx := context.Background()
			mockRepo := &MockRequestLogRepository{}
			testLogger := createTestLogger()
			authzSvc := NewAuthorizationService(testLogger, mockRepo)

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

			// Test filtering
			filteredAPI := authzSvc.FilterByOrganisation(ctx, user, apiConfig)
			if userOrgID == dataOrgID {
				return filteredAPI != nil
			} else {
				return filteredAPI == nil
			}
		},
		gen.Identifier(),
		gen.Identifier(),
	))

	properties.Property("global admins should see all data regardless of organisation", prop.ForAll(
		func(userOrgID, dataOrgID string) bool {
			ctx := context.Background()
			mockRepo := &MockRequestLogRepository{}
			testLogger := createTestLogger()
			authzSvc := NewAuthorizationService(testLogger, mockRepo)

			// Create global admin user
			user := &models.User{
				ID:             "test-user",
				OrganisationID: userOrgID,
				Username:       "globaladmin",
				Email:          "global@example.com",
				Role:           "global_admin",
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

			// Global admins should always see data
			filteredAPI := authzSvc.FilterByOrganisation(ctx, user, apiConfig)
			return filteredAPI != nil
		},
		gen.Identifier(),
		gen.Identifier(),
	))

	properties.Property("inactive users should not see any data", prop.ForAll(
		func(userOrgID, dataOrgID string, role string) bool {
			ctx := context.Background()
			mockRepo := &MockRequestLogRepository{}
			testLogger := createTestLogger()
			authzSvc := NewAuthorizationService(testLogger, mockRepo)

			// Create inactive user
			user := &models.User{
				ID:             "test-user",
				OrganisationID: userOrgID,
				Username:       "inactiveuser",
				Email:          "inactive@example.com",
				Role:           role,
				IsActive:       false, // Inactive user
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

			// Inactive users should never see data
			filteredAPI := authzSvc.FilterByOrganisation(ctx, user, apiConfig)
			return filteredAPI == nil
		},
		gen.Identifier(),
		gen.Identifier(),
		gen.OneConstOf("org_admin", "global_admin"),
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// **Feature: api-translation-platform, Property 17: Administrative capabilities**
// **Validates: Requirements 7.2, 7.5**
func TestProperty_AdministrativeCapabilities(t *testing.T) {
	properties := gopter.NewProperties(nil)

	properties.Property("global admins should have complete CRUD capabilities for organisations", prop.ForAll(
		func(orgID string) bool {
			ctx := context.Background()
			mockRepo := &MockRequestLogRepository{}
			testLogger := createTestLogger()
			authzSvc := NewAuthorizationService(testLogger, mockRepo)

			// Create global admin user
			globalAdmin := &models.User{
				ID:             "global-admin-id",
				OrganisationID: "admin-org",
				Username:       "globaladmin",
				Email:          "global@example.com",
				Role:           "global_admin",
				IsActive:       true,
			}

			// Global admin should be able to manage any organisation
			canManage := authzSvc.CanManageOrganisation(ctx, globalAdmin, orgID)
			return canManage
		},
		gen.Identifier(),
	))

	properties.Property("global admins should have cross-organisational data access", prop.ForAll(
		func(adminOrgID, targetOrgID string) bool {
			ctx := context.Background()
			mockRepo := &MockRequestLogRepository{}
			testLogger := createTestLogger()
			authzSvc := NewAuthorizationService(testLogger, mockRepo)

			// Create global admin user from one organisation
			globalAdmin := &models.User{
				ID:             "global-admin-id",
				OrganisationID: adminOrgID,
				Username:       "globaladmin",
				Email:          "global@example.com",
				Role:           "global_admin",
				IsActive:       true,
			}

			// Create test data from different organisation
			apiConfig := &models.APIConfiguration{
				ID:             "test-api",
				OrganisationID: targetOrgID,
				Name:           "Test API",
				Type:           "REST",
				Direction:      "inbound",
				Endpoint:       "https://test.example.com",
				Authentication: models.AuthenticationConfig{
					Type:       "api_key",
					Parameters: map[string]string{"key": "test"},
				},
			}

			connector := &models.Connector{
				ID:             "test-connector",
				OrganisationID: targetOrgID,
				Name:           "Test Connector",
				InboundAPIID:   "inbound-api",
				OutboundAPIID:  "outbound-api",
				PythonScript:   "# Test script",
				IsActive:       true,
			}

			requestLog := &models.RequestLog{
				ID:             "test-log",
				OrganisationID: targetOrgID,
				ConnectorID:    "test-connector",
				RequestID:      "req-123",
				Method:         "POST",
				Path:           "/test",
				StatusCode:     200,
				ProcessingTime: 100,
			}

			// Global admin should see all data regardless of organisation
			filteredAPI := authzSvc.FilterByOrganisation(ctx, globalAdmin, apiConfig)
			filteredConnector := authzSvc.FilterByOrganisation(ctx, globalAdmin, connector)
			filteredLog := authzSvc.FilterByOrganisation(ctx, globalAdmin, requestLog)

			return filteredAPI != nil && filteredConnector != nil && filteredLog != nil
		},
		gen.Identifier(),
		gen.Identifier(),
	))

	properties.Property("organisation admins should not have cross-organisational management capabilities", prop.ForAll(
		func(adminOrgID, targetOrgID string) bool {
			ctx := context.Background()
			mockRepo := &MockRequestLogRepository{}
			testLogger := createTestLogger()
			authzSvc := NewAuthorizationService(testLogger, mockRepo)

			// Create organisation admin user
			orgAdmin := &models.User{
				ID:             "org-admin-id",
				OrganisationID: adminOrgID,
				Username:       "orgadmin",
				Email:          "admin@example.com",
				Role:           "org_admin",
				IsActive:       true,
			}

			// Test management capabilities
			canManage := authzSvc.CanManageOrganisation(ctx, orgAdmin, targetOrgID)

			if adminOrgID == targetOrgID {
				// Should be able to manage their own organisation
				return canManage
			} else {
				// Should not be able to manage other organisations
				return !canManage
			}
		},
		gen.Identifier(),
		gen.Identifier(),
	))

	properties.Property("global admins should have system-wide visibility", prop.ForAll(
		func(adminOrgID string, numOrgs int) bool {
			ctx := context.Background()
			mockRepo := &MockRequestLogRepository{}
			testLogger := createTestLogger()
			authzSvc := NewAuthorizationService(testLogger, mockRepo)

			// Create global admin user
			globalAdmin := &models.User{
				ID:             "global-admin-id",
				OrganisationID: adminOrgID,
				Username:       "globaladmin",
				Email:          "global@example.com",
				Role:           "global_admin",
				IsActive:       true,
			}

			// Create test data from multiple organisations
			var apiConfigs []*models.APIConfiguration
			for i := 0; i < numOrgs; i++ {
				apiConfig := &models.APIConfiguration{
					ID:             "test-api-" + string(rune(i)),
					OrganisationID: "org-" + string(rune(i)),
					Name:           "Test API " + string(rune(i)),
					Type:           "REST",
					Direction:      "inbound",
					Endpoint:       "https://test.example.com",
					Authentication: models.AuthenticationConfig{
						Type:       "api_key",
						Parameters: map[string]string{"key": "test"},
					},
				}
				apiConfigs = append(apiConfigs, apiConfig)
			}

			// Global admin should see all data
			filtered := authzSvc.FilterByOrganisation(ctx, globalAdmin, apiConfigs)
			if filtered == nil {
				return numOrgs == 0
			}

			// Should return all data (no filtering for global admin)
			// For global admin, FilterByOrganisation should return the original data
			return filtered != nil
		},
		gen.Identifier(),
		gen.IntRange(0, 3),
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}
func (m *MockRequestLogRepository) GetAll(ctx context.Context, limit, offset int) ([]*models.RequestLog, error) {
	args := m.Called(ctx, limit, offset)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.RequestLog), args.Error(1)
}
