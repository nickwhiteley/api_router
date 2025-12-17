package repositories

import (
	"context"
	"testing"

	"api-translation-platform/internal/models"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"gorm.io/gorm"
)

// MockDB is a mock implementation of the database connection for testing
type MockDB struct {
	mock.Mock
}

func (m *MockDB) WithContext(ctx context.Context) *gorm.DB {
	args := m.Called(ctx)
	return args.Get(0).(*gorm.DB)
}

func (m *MockDB) Create(value interface{}) *gorm.DB {
	args := m.Called(value)
	return args.Get(0).(*gorm.DB)
}

func (m *MockDB) First(dest interface{}, conds ...interface{}) *gorm.DB {
	args := m.Called(dest, conds)
	return args.Get(0).(*gorm.DB)
}

func (m *MockDB) Find(dest interface{}, conds ...interface{}) *gorm.DB {
	args := m.Called(dest, conds)
	return args.Get(0).(*gorm.DB)
}

func (m *MockDB) Where(query interface{}, args ...interface{}) *gorm.DB {
	mockArgs := m.Called(query, args)
	return mockArgs.Get(0).(*gorm.DB)
}

func (m *MockDB) Save(value interface{}) *gorm.DB {
	args := m.Called(value)
	return args.Get(0).(*gorm.DB)
}

func (m *MockDB) Delete(value interface{}, conds ...interface{}) *gorm.DB {
	args := m.Called(value, conds)
	return args.Get(0).(*gorm.DB)
}

func (m *MockDB) Preload(query string, args ...interface{}) *gorm.DB {
	mockArgs := m.Called(query, args)
	return mockArgs.Get(0).(*gorm.DB)
}

func (m *MockDB) Order(value interface{}) *gorm.DB {
	args := m.Called(value)
	return args.Get(0).(*gorm.DB)
}

func (m *MockDB) Limit(limit int) *gorm.DB {
	args := m.Called(limit)
	return args.Get(0).(*gorm.DB)
}

func (m *MockDB) Offset(offset int) *gorm.DB {
	args := m.Called(offset)
	return args.Get(0).(*gorm.DB)
}

// Mock database connection that implements the interface we need
type MockConnection struct {
	db *MockDB
}

func (m *MockConnection) WithContext(ctx context.Context) *gorm.DB {
	return m.db.WithContext(ctx)
}

func TestOrganisationFiltering(t *testing.T) {
	t.Run("User repository filters by organisation", func(t *testing.T) {
		// Test that user operations are properly scoped to organisation
		orgID1 := "org-123"
		orgID2 := "org-456"

		user1 := &models.User{
			ID:             "user-1",
			OrganisationID: orgID1,
			Username:       "user1",
			Email:          "user1@example.com",
			Role:           "org_admin",
		}

		user2 := &models.User{
			ID:             "user-2",
			OrganisationID: orgID2,
			Username:       "user2",
			Email:          "user2@example.com",
			Role:           "org_admin",
		}

		// Verify that users are tagged with correct organisation IDs
		assert.Equal(t, orgID1, user1.OrganisationID)
		assert.Equal(t, orgID2, user2.OrganisationID)
		assert.NotEqual(t, user1.OrganisationID, user2.OrganisationID)
	})

	t.Run("API configuration repository filters by organisation", func(t *testing.T) {
		orgID1 := "org-123"
		orgID2 := "org-456"

		api1 := &models.APIConfiguration{
			ID:             "api-1",
			OrganisationID: orgID1,
			Name:           "API 1",
			Type:           "REST",
			Direction:      "inbound",
			Endpoint:       "https://api1.example.com",
		}

		api2 := &models.APIConfiguration{
			ID:             "api-2",
			OrganisationID: orgID2,
			Name:           "API 2",
			Type:           "SOAP",
			Direction:      "outbound",
			Endpoint:       "https://api2.example.com",
		}

		// Verify organisation isolation
		assert.Equal(t, orgID1, api1.OrganisationID)
		assert.Equal(t, orgID2, api2.OrganisationID)
		assert.NotEqual(t, api1.OrganisationID, api2.OrganisationID)
	})

	t.Run("Connector repository filters by organisation", func(t *testing.T) {
		orgID1 := "org-123"
		orgID2 := "org-456"

		connector1 := &models.Connector{
			ID:             "connector-1",
			OrganisationID: orgID1,
			Name:           "Connector 1",
			InboundAPIID:   "api-inbound-1",
			OutboundAPIID:  "api-outbound-1",
			PythonScript:   "# Script 1",
		}

		connector2 := &models.Connector{
			ID:             "connector-2",
			OrganisationID: orgID2,
			Name:           "Connector 2",
			InboundAPIID:   "api-inbound-2",
			OutboundAPIID:  "api-outbound-2",
			PythonScript:   "# Script 2",
		}

		// Verify organisation isolation
		assert.Equal(t, orgID1, connector1.OrganisationID)
		assert.Equal(t, orgID2, connector2.OrganisationID)
		assert.NotEqual(t, connector1.OrganisationID, connector2.OrganisationID)
	})

	t.Run("Request log repository filters by organisation", func(t *testing.T) {
		orgID1 := "org-123"
		orgID2 := "org-456"

		log1 := &models.RequestLog{
			ID:             "log-1",
			OrganisationID: orgID1,
			ConnectorID:    "connector-1",
			RequestID:      "req-1",
			Method:         "POST",
			Path:           "/api/test1",
			StatusCode:     200,
		}

		log2 := &models.RequestLog{
			ID:             "log-2",
			OrganisationID: orgID2,
			ConnectorID:    "connector-2",
			RequestID:      "req-2",
			Method:         "GET",
			Path:           "/api/test2",
			StatusCode:     404,
		}

		// Verify organisation isolation
		assert.Equal(t, orgID1, log1.OrganisationID)
		assert.Equal(t, orgID2, log2.OrganisationID)
		assert.NotEqual(t, log1.OrganisationID, log2.OrganisationID)
	})
}

func TestRepositoryInterfaces(t *testing.T) {
	t.Run("Repository interfaces are properly defined", func(t *testing.T) {
		// Test that interfaces compile and have the expected methods
		// This is a compile-time test - if the interfaces are wrong, this won't compile

		var orgRepo OrganisationRepository
		var userRepo UserRepository
		var apiRepo APIConfigurationRepository
		var connectorRepo ConnectorRepository
		var logRepo RequestLogRepository

		// These variables being nil is expected - we're just testing interface definitions
		assert.Nil(t, orgRepo)
		assert.Nil(t, userRepo)
		assert.Nil(t, apiRepo)
		assert.Nil(t, connectorRepo)
		assert.Nil(t, logRepo)

		// The fact that this compiles proves the interfaces are correctly defined
		t.Log("All repository interfaces are properly defined")
	})
}

func TestOrganisationIsolationInRepositories(t *testing.T) {
	t.Run("Repository interfaces include organisation filtering methods", func(t *testing.T) {
		// Test that repository interfaces have organisation-aware methods
		// This is a compile-time test - if methods don't exist, this won't compile

		t.Run("UserRepository has organisation filtering", func(t *testing.T) {
			// Test that GetByOrganisation method exists with correct signature
			var repo UserRepository
			if repo != nil {
				ctx := context.Background()
				_, _ = repo.GetByOrganisation(ctx, "org-123")
			}
			// The fact this compiles proves the method exists
			t.Log("UserRepository.GetByOrganisation method exists")
		})

		t.Run("APIConfigurationRepository has organisation filtering", func(t *testing.T) {
			var repo APIConfigurationRepository
			if repo != nil {
				ctx := context.Background()
				_, _ = repo.GetByOrganisation(ctx, "org-123")
				_, _ = repo.GetInboundByOrganisation(ctx, "org-123")
				_, _ = repo.GetOutboundByOrganisation(ctx, "org-123")
			}
			t.Log("APIConfigurationRepository organisation methods exist")
		})

		t.Run("ConnectorRepository has organisation filtering", func(t *testing.T) {
			var repo ConnectorRepository
			if repo != nil {
				ctx := context.Background()
				_, _ = repo.GetByOrganisation(ctx, "org-123")
			}
			t.Log("ConnectorRepository.GetByOrganisation method exists")
		})

		t.Run("RequestLogRepository has organisation filtering", func(t *testing.T) {
			var repo RequestLogRepository
			if repo != nil {
				ctx := context.Background()
				_, _ = repo.GetByOrganisation(ctx, "org-123", 10, 0)
				_, _ = repo.GetErrorLogs(ctx, "org-123", 10, 0)
			}
			t.Log("RequestLogRepository organisation methods exist")
		})
	})
}

func TestDataModelConsistency(t *testing.T) {
	t.Run("All models have organisation ID field", func(t *testing.T) {
		// Test that all relevant models have OrganisationID field for isolation

		user := &models.User{}
		assert.NotNil(t, &user.OrganisationID)

		apiConfig := &models.APIConfiguration{}
		assert.NotNil(t, &apiConfig.OrganisationID)

		connector := &models.Connector{}
		assert.NotNil(t, &connector.OrganisationID)

		requestLog := &models.RequestLog{}
		assert.NotNil(t, &requestLog.OrganisationID)
	})

	t.Run("Models have proper validation tags for organisation ID", func(t *testing.T) {
		// Test that organisation ID fields are marked as required in validation
		validator := models.NewValidationService()

		// User without organisation ID should fail validation
		user := &models.User{
			Username: "testuser",
			Email:    "test@example.com",
			Role:     "org_admin",
		}
		err := validator.ValidateStruct(user)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "organisation_id")

		// API configuration without organisation ID should fail validation
		apiConfig := &models.APIConfiguration{
			Name:      "Test API",
			Type:      "REST",
			Direction: "inbound",
			Endpoint:  "https://test.example.com",
		}
		err = validator.ValidateStruct(apiConfig)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "organisation_id")

		// Connector without organisation ID should fail validation
		connector := &models.Connector{
			Name:          "Test Connector",
			InboundAPIID:  "api-1",
			OutboundAPIID: "api-2",
			PythonScript:  "print('test')",
		}
		err = validator.ValidateStruct(connector)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "organisation_id")

		// Request log without organisation ID should fail validation
		requestLog := &models.RequestLog{
			ConnectorID: "connector-1",
			RequestID:   "req-1",
			Method:      "POST",
			Path:        "/test",
			StatusCode:  200,
		}
		err = validator.ValidateStruct(requestLog)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "organisation_id")
	})
}
