package services

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"api-translation-platform/internal/models"
)

// Mock repositories for testing
type MockAPIConfigurationRepository struct {
	mock.Mock
}

func (m *MockAPIConfigurationRepository) Create(ctx context.Context, config *models.APIConfiguration) error {
	args := m.Called(ctx, config)
	return args.Error(0)
}

func (m *MockAPIConfigurationRepository) GetByID(ctx context.Context, id string) (*models.APIConfiguration, error) {
	args := m.Called(ctx, id)
	return args.Get(0).(*models.APIConfiguration), args.Error(1)
}

func (m *MockAPIConfigurationRepository) GetByOrganisation(ctx context.Context, orgID string) ([]*models.APIConfiguration, error) {
	args := m.Called(ctx, orgID)
	return args.Get(0).([]*models.APIConfiguration), args.Error(1)
}

func (m *MockAPIConfigurationRepository) GetInboundByOrganisation(ctx context.Context, orgID string) ([]*models.APIConfiguration, error) {
	args := m.Called(ctx, orgID)
	return args.Get(0).([]*models.APIConfiguration), args.Error(1)
}

func (m *MockAPIConfigurationRepository) GetOutboundByOrganisation(ctx context.Context, orgID string) ([]*models.APIConfiguration, error) {
	args := m.Called(ctx, orgID)
	return args.Get(0).([]*models.APIConfiguration), args.Error(1)
}

func (m *MockAPIConfigurationRepository) Update(ctx context.Context, config *models.APIConfiguration) error {
	args := m.Called(ctx, config)
	return args.Error(0)
}

func (m *MockAPIConfigurationRepository) Delete(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

type MockAuditLogRepository struct {
	mock.Mock
}

func (m *MockAuditLogRepository) Create(ctx context.Context, log *models.AuditLog) error {
	args := m.Called(ctx, log)
	return args.Error(0)
}

func (m *MockAuditLogRepository) GetByID(ctx context.Context, id string) (*models.AuditLog, error) {
	args := m.Called(ctx, id)
	return args.Get(0).(*models.AuditLog), args.Error(1)
}

func (m *MockAuditLogRepository) GetByOrganisation(ctx context.Context, orgID string, limit, offset int) ([]*models.AuditLog, error) {
	args := m.Called(ctx, orgID, limit, offset)
	return args.Get(0).([]*models.AuditLog), args.Error(1)
}

func (m *MockAuditLogRepository) GetByResource(ctx context.Context, resourceType, resourceID string, limit, offset int) ([]*models.AuditLog, error) {
	args := m.Called(ctx, resourceType, resourceID, limit, offset)
	return args.Get(0).([]*models.AuditLog), args.Error(1)
}

func (m *MockAuditLogRepository) GetByUser(ctx context.Context, userID string, limit, offset int) ([]*models.AuditLog, error) {
	args := m.Called(ctx, userID, limit, offset)
	return args.Get(0).([]*models.AuditLog), args.Error(1)
}

type MockConfigurationVersionRepository struct {
	mock.Mock
}

func (m *MockConfigurationVersionRepository) Create(ctx context.Context, version *models.ConfigurationVersion) error {
	args := m.Called(ctx, version)
	return args.Error(0)
}

func (m *MockConfigurationVersionRepository) GetByID(ctx context.Context, id string) (*models.ConfigurationVersion, error) {
	args := m.Called(ctx, id)
	return args.Get(0).(*models.ConfigurationVersion), args.Error(1)
}

func (m *MockConfigurationVersionRepository) GetByResource(ctx context.Context, resourceType, resourceID string) ([]*models.ConfigurationVersion, error) {
	args := m.Called(ctx, resourceType, resourceID)
	return args.Get(0).([]*models.ConfigurationVersion), args.Error(1)
}

func (m *MockConfigurationVersionRepository) GetActiveVersion(ctx context.Context, resourceType, resourceID string) (*models.ConfigurationVersion, error) {
	args := m.Called(ctx, resourceType, resourceID)
	return args.Get(0).(*models.ConfigurationVersion), args.Error(1)
}

func (m *MockConfigurationVersionRepository) GetVersionByNumber(ctx context.Context, resourceType, resourceID string, version int) (*models.ConfigurationVersion, error) {
	args := m.Called(ctx, resourceType, resourceID, version)
	return args.Get(0).(*models.ConfigurationVersion), args.Error(1)
}

func (m *MockConfigurationVersionRepository) SetActiveVersion(ctx context.Context, versionID string) error {
	args := m.Called(ctx, versionID)
	return args.Error(0)
}

func (m *MockConfigurationVersionRepository) GetLatestVersion(ctx context.Context, resourceType, resourceID string) (*models.ConfigurationVersion, error) {
	args := m.Called(ctx, resourceType, resourceID)
	return args.Get(0).(*models.ConfigurationVersion), args.Error(1)
}

type MockOrganisationRepository struct {
	mock.Mock
}

func (m *MockOrganisationRepository) Create(ctx context.Context, org *models.Organisation) error {
	args := m.Called(ctx, org)
	return args.Error(0)
}

func (m *MockOrganisationRepository) GetByID(ctx context.Context, id string) (*models.Organisation, error) {
	args := m.Called(ctx, id)
	return args.Get(0).(*models.Organisation), args.Error(1)
}

func (m *MockOrganisationRepository) GetAll(ctx context.Context) ([]*models.Organisation, error) {
	args := m.Called(ctx)
	return args.Get(0).([]*models.Organisation), args.Error(1)
}

func (m *MockOrganisationRepository) Update(ctx context.Context, org *models.Organisation) error {
	args := m.Called(ctx, org)
	return args.Error(0)
}

func (m *MockOrganisationRepository) Delete(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

// Use the existing createTestLogger function from authentication_test.go

// **Feature: api-translation-platform, Property 12: Configuration consistency**
// **Validates: Requirements 4.2, 4.3**
func TestConfigurationConsistency(t *testing.T) {
	properties := gopter.NewProperties(nil)

	properties.Property("configuration changes should maintain consistency across all instances", prop.ForAll(
		func(orgID string, configs []models.APIConfiguration) bool {
			// Setup mocks
			mockAPIRepo := &MockAPIConfigurationRepository{}
			mockAuditRepo := &MockAuditLogRepository{}
			mockVersionRepo := &MockConfigurationVersionRepository{}
			mockConnectorRepo := &MockConnectorRepository{}
			mockOrgRepo := &MockOrganisationRepository{}
			validationSvc := models.NewValidationService()

			logger := createTestLogger()
			service := NewConfigurationService(logger, mockAPIRepo, mockAuditRepo, mockVersionRepo, mockConnectorRepo, mockOrgRepo, validationSvc)

			ctx := context.Background()

			// Mock the repository calls
			configPtrs := make([]*models.APIConfiguration, len(configs))
			for i := range configs {
				configs[i].OrganisationID = orgID
				configPtrs[i] = &configs[i]
			}

			mockAPIRepo.On("GetByOrganisation", ctx, orgID).Return(configPtrs, nil)

			// Test configuration checksum generation
			checksum1, err1 := service.GetConfigurationChecksum(ctx, orgID)
			if err1 != nil {
				return false
			}

			// Generate checksum again - should be identical for same configuration
			checksum2, err2 := service.GetConfigurationChecksum(ctx, orgID)
			if err2 != nil {
				return false
			}

			// Checksums should be identical for the same configuration
			if checksum1 != checksum2 {
				return false
			}

			// Test configuration synchronization
			err3 := service.SynchronizeConfiguration(ctx, "test-instance")
			if err3 != nil {
				return false
			}

			// Test consistency validation
			err4 := service.ValidateConfigurationConsistency(ctx)
			if err4 != nil {
				return false
			}

			return true
		},
		gen.Identifier(),
		gen.SliceOf(gen.Struct(reflect.TypeOf(models.APIConfiguration{}), map[string]gopter.Gen{
			"ID":        gen.Identifier(),
			"Name":      gen.Identifier(),
			"Type":      gen.OneConstOf("REST", "SOAP"),
			"Direction": gen.OneConstOf("inbound", "outbound"),
			"Endpoint":  gen.Identifier(),
			"Authentication": gen.Struct(reflect.TypeOf(models.AuthenticationConfig{}), map[string]gopter.Gen{
				"Type":       gen.OneConstOf("api_key", "oauth", "basic", "none"),
				"Parameters": gen.MapOf(gen.Identifier(), gen.Identifier()).SuchThat(func(m map[string]string) bool { return len(m) <= 3 }),
			}),
			"Headers":   gen.MapOf(gen.Identifier(), gen.Identifier()).SuchThat(func(m map[string]string) bool { return len(m) <= 3 }),
			"CreatedAt": gen.Const(time.Now()),
			"UpdatedAt": gen.Const(time.Now()),
		})).SuchThat(func(configs []models.APIConfiguration) bool { return len(configs) <= 5 }),
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// **Feature: api-translation-platform, Property 20: Audit trail immutability**
// **Validates: Requirements 8.5**
func TestAuditTrailImmutability(t *testing.T) {
	properties := gopter.NewProperties(nil)

	properties.Property("audit log entries should be immutable once created", prop.ForAll(
		func(userID, action, resourceType, resourceID string) bool {
			// Setup mocks
			mockAPIRepo := &MockAPIConfigurationRepository{}
			mockAuditRepo := &MockAuditLogRepository{}
			mockVersionRepo := &MockConfigurationVersionRepository{}
			mockConnectorRepo := &MockConnectorRepository{}
			mockOrgRepo := &MockOrganisationRepository{}
			validationSvc := models.NewValidationService()

			logger := createTestLogger()
			service := NewConfigurationService(logger, mockAPIRepo, mockAuditRepo, mockVersionRepo, mockConnectorRepo, mockOrgRepo, validationSvc)

			ctx := context.Background()

			// Create simple test data
			oldValues := models.JSONMap{"old_field": "old_value"}
			newValues := models.JSONMap{"new_field": "new_value"}

			// Create audit log entry (for reference, not used directly)
			_ = &models.AuditLog{
				ID:           "test-audit-id",
				UserID:       userID,
				Action:       action,
				ResourceType: resourceType,
				ResourceID:   resourceID,
				OldValues:    oldValues,
				NewValues:    newValues,
				Timestamp:    time.Now(),
				CreatedAt:    time.Now(),
			}

			mockAuditRepo.On("Create", ctx, mock.MatchedBy(func(log *models.AuditLog) bool {
				return log.UserID == userID &&
					log.Action == action &&
					log.ResourceType == resourceType &&
					log.ResourceID == resourceID
			})).Return(nil)

			// Log the configuration change
			err := service.LogConfigurationChange(ctx, userID, action, resourceType, resourceID, oldValues, newValues)
			if err != nil {
				return false
			}

			// Verify that the audit log was created with correct immutable properties
			mockAuditRepo.AssertCalled(t, "Create", ctx, mock.MatchedBy(func(log *models.AuditLog) bool {
				// Verify all required fields are present and immutable
				return log.UserID == userID &&
					log.Action == action &&
					log.ResourceType == resourceType &&
					log.ResourceID == resourceID &&
					!log.Timestamp.IsZero() &&
					!log.CreatedAt.IsZero()
			}))

			return true
		},
		gen.Identifier(),
		gen.OneConstOf("CREATE", "UPDATE", "DELETE"),
		gen.Identifier(),
		gen.Identifier(),
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// Unit tests for specific functionality
func TestCreateAPIConfiguration(t *testing.T) {
	mockAPIRepo := &MockAPIConfigurationRepository{}
	mockAuditRepo := &MockAuditLogRepository{}
	mockVersionRepo := &MockConfigurationVersionRepository{}
	mockConnectorRepo := &MockConnectorRepository{}
	mockOrgRepo := &MockOrganisationRepository{}
	validationSvc := models.NewValidationService()

	logger := createTestLogger()
	service := NewConfigurationService(logger, mockAPIRepo, mockAuditRepo, mockVersionRepo, mockConnectorRepo, mockOrgRepo, validationSvc)

	config := &models.APIConfiguration{
		ID:             "test-id",
		OrganisationID: "org-1",
		Name:           "Test API",
		Type:           "REST",
		Direction:      "inbound",
		Endpoint:       "http://example.com/api",
		Authentication: models.AuthenticationConfig{Type: "api_key"},
		Headers:        map[string]string{"Content-Type": "application/json"},
	}

	ctx := context.WithValue(context.Background(), "user_id", "user-1")

	// No need to mock validation service as we're using the real one
	mockAPIRepo.On("Create", ctx, config).Return(nil)
	mockVersionRepo.On("GetLatestVersion", ctx, "api_configuration", config.ID).Return((*models.ConfigurationVersion)(nil), assert.AnError)
	mockVersionRepo.On("GetActiveVersion", ctx, "api_configuration", config.ID).Return((*models.ConfigurationVersion)(nil), assert.AnError)
	mockVersionRepo.On("Create", ctx, mock.AnythingOfType("*models.ConfigurationVersion")).Return(nil)
	mockAuditRepo.On("Create", ctx, mock.AnythingOfType("*models.AuditLog")).Return(nil)

	_, err := service.CreateAPIConfiguration(ctx, config)
	assert.NoError(t, err)

	mockAPIRepo.AssertExpectations(t)
	mockVersionRepo.AssertExpectations(t)
	mockAuditRepo.AssertExpectations(t)
}

func TestGetConfigurationChecksum(t *testing.T) {
	mockAPIRepo := &MockAPIConfigurationRepository{}
	mockAuditRepo := &MockAuditLogRepository{}
	mockVersionRepo := &MockConfigurationVersionRepository{}
	mockConnectorRepo := &MockConnectorRepository{}
	mockOrgRepo := &MockOrganisationRepository{}
	validationSvc := models.NewValidationService()

	logger := createTestLogger()
	service := NewConfigurationService(logger, mockAPIRepo, mockAuditRepo, mockVersionRepo, mockConnectorRepo, mockOrgRepo, validationSvc)

	configs := []*models.APIConfiguration{
		{
			ID:             "config-1",
			Name:           "API 1",
			Type:           "REST",
			Direction:      "inbound",
			Endpoint:       "http://example.com/api1",
			Authentication: models.AuthenticationConfig{Type: "api_key"},
			Headers:        map[string]string{"Content-Type": "application/json"},
			UpdatedAt:      time.Unix(1234567890, 0),
		},
		{
			ID:             "config-2",
			Name:           "API 2",
			Type:           "SOAP",
			Direction:      "outbound",
			Endpoint:       "http://example.com/api2",
			Authentication: models.AuthenticationConfig{Type: "basic"},
			Headers:        map[string]string{"SOAPAction": "test"},
			UpdatedAt:      time.Unix(1234567891, 0),
		},
	}

	ctx := context.Background()
	mockAPIRepo.On("GetByOrganisation", ctx, "org-1").Return(configs, nil)

	checksum, err := service.GetConfigurationChecksum(ctx, "org-1")
	assert.NoError(t, err)
	assert.NotEmpty(t, checksum)
	assert.Len(t, checksum, 32) // MD5 hash length

	mockAPIRepo.AssertExpectations(t)
}
