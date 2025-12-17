package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"api-translation-platform/internal/config"
	"api-translation-platform/internal/logger"
	"api-translation-platform/internal/models"
)

// Mock services for testing
type MockConfigurationService struct {
	mock.Mock
}

func (m *MockConfigurationService) CreateOrganisation(ctx context.Context, org *models.Organisation) (*models.Organisation, error) {
	args := m.Called(ctx, org)
	return args.Get(0).(*models.Organisation), args.Error(1)
}

func (m *MockConfigurationService) GetAllOrganisations(ctx context.Context) ([]*models.Organisation, error) {
	args := m.Called(ctx)
	return args.Get(0).([]*models.Organisation), args.Error(1)
}

func (m *MockConfigurationService) GetOrganisation(ctx context.Context, orgID string) (*models.Organisation, error) {
	args := m.Called(ctx, orgID)
	return args.Get(0).(*models.Organisation), args.Error(1)
}

func (m *MockConfigurationService) UpdateOrganisation(ctx context.Context, org *models.Organisation) (*models.Organisation, error) {
	args := m.Called(ctx, org)
	return args.Get(0).(*models.Organisation), args.Error(1)
}

func (m *MockConfigurationService) DeleteOrganisation(ctx context.Context, orgID string) error {
	args := m.Called(ctx, orgID)
	return args.Error(0)
}

func (m *MockConfigurationService) CreateAPIConfiguration(ctx context.Context, config *models.APIConfiguration) (*models.APIConfiguration, error) {
	args := m.Called(ctx, config)
	return args.Get(0).(*models.APIConfiguration), args.Error(1)
}

func (m *MockConfigurationService) GetAPIConfiguration(ctx context.Context, id string) (*models.APIConfiguration, error) {
	args := m.Called(ctx, id)
	return args.Get(0).(*models.APIConfiguration), args.Error(1)
}

func (m *MockConfigurationService) GetAPIConfigurationsByOrganisation(ctx context.Context, orgID string) ([]*models.APIConfiguration, error) {
	args := m.Called(ctx, orgID)
	return args.Get(0).([]*models.APIConfiguration), args.Error(1)
}

func (m *MockConfigurationService) UpdateAPIConfiguration(ctx context.Context, config *models.APIConfiguration) (*models.APIConfiguration, error) {
	args := m.Called(ctx, config)
	return args.Get(0).(*models.APIConfiguration), args.Error(1)
}

func (m *MockConfigurationService) DeleteAPIConfiguration(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockConfigurationService) TestAPIConfiguration(ctx context.Context, apiID string, testRequest map[string]interface{}) (map[string]interface{}, error) {
	args := m.Called(ctx, apiID, testRequest)
	return args.Get(0).(map[string]interface{}), args.Error(1)
}

func (m *MockConfigurationService) ValidateConfiguration(ctx context.Context, config *models.APIConfiguration) error {
	args := m.Called(ctx, config)
	return args.Error(0)
}

// Add other required methods with minimal implementations
func (m *MockConfigurationService) CreateConnector(ctx context.Context, connector *models.Connector) (*models.Connector, error) {
	args := m.Called(ctx, connector)
	return args.Get(0).(*models.Connector), args.Error(1)
}

func (m *MockConfigurationService) UpdateConnector(ctx context.Context, connector *models.Connector) (*models.Connector, error) {
	args := m.Called(ctx, connector)
	return args.Get(0).(*models.Connector), args.Error(1)
}

func (m *MockConfigurationService) DeleteConnector(ctx context.Context, connectorID string) error {
	args := m.Called(ctx, connectorID)
	return args.Error(0)
}

func (m *MockConfigurationService) GetConnector(ctx context.Context, connectorID string) (*models.Connector, error) {
	args := m.Called(ctx, connectorID)
	return args.Get(0).(*models.Connector), args.Error(1)
}

func (m *MockConfigurationService) GetConnectorsByOrganisation(ctx context.Context, orgID string) ([]*models.Connector, error) {
	args := m.Called(ctx, orgID)
	return args.Get(0).([]*models.Connector), args.Error(1)
}

func (m *MockConfigurationService) UpdateConnectorScript(ctx context.Context, connectorID, script string) error {
	args := m.Called(ctx, connectorID, script)
	return args.Error(0)
}

func (m *MockConfigurationService) CreateConfigurationVersion(ctx context.Context, resourceType, resourceID string, configData models.JSONMap, userID string) (*models.ConfigurationVersion, error) {
	args := m.Called(ctx, resourceType, resourceID, configData, userID)
	return args.Get(0).(*models.ConfigurationVersion), args.Error(1)
}

func (m *MockConfigurationService) GetConfigurationVersions(ctx context.Context, resourceType, resourceID string) ([]*models.ConfigurationVersion, error) {
	args := m.Called(ctx, resourceType, resourceID)
	return args.Get(0).([]*models.ConfigurationVersion), args.Error(1)
}

func (m *MockConfigurationService) GetConfigurationVersion(ctx context.Context, versionID string) (*models.ConfigurationVersion, error) {
	args := m.Called(ctx, versionID)
	return args.Get(0).(*models.ConfigurationVersion), args.Error(1)
}

func (m *MockConfigurationService) RollbackToVersion(ctx context.Context, versionID string, userID string) error {
	args := m.Called(ctx, versionID, userID)
	return args.Error(0)
}

func (m *MockConfigurationService) GetActiveConfigurationVersion(ctx context.Context, resourceType, resourceID string) (*models.ConfigurationVersion, error) {
	args := m.Called(ctx, resourceType, resourceID)
	return args.Get(0).(*models.ConfigurationVersion), args.Error(1)
}

func (m *MockConfigurationService) LogConfigurationChange(ctx context.Context, userID, action, resourceType, resourceID string, oldValues, newValues models.JSONMap) error {
	args := m.Called(ctx, userID, action, resourceType, resourceID, oldValues, newValues)
	return args.Error(0)
}

func (m *MockConfigurationService) GetAuditLogs(ctx context.Context, orgID string, limit, offset int) ([]*models.AuditLog, error) {
	args := m.Called(ctx, orgID, limit, offset)
	return args.Get(0).([]*models.AuditLog), args.Error(1)
}

func (m *MockConfigurationService) GetResourceAuditLogs(ctx context.Context, resourceType, resourceID string, limit, offset int) ([]*models.AuditLog, error) {
	args := m.Called(ctx, resourceType, resourceID, limit, offset)
	return args.Get(0).([]*models.AuditLog), args.Error(1)
}

func (m *MockConfigurationService) SynchronizeConfiguration(ctx context.Context, instanceID string) error {
	args := m.Called(ctx, instanceID)
	return args.Error(0)
}

func (m *MockConfigurationService) GetConfigurationChecksum(ctx context.Context, orgID string) (string, error) {
	args := m.Called(ctx, orgID)
	return args.String(0), args.Error(1)
}

func (m *MockConfigurationService) ValidateConfigurationConsistency(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

type MockAuthenticationService struct {
	mock.Mock
}

func (m *MockAuthenticationService) ValidateJWT(ctx context.Context, token string) (*models.User, error) {
	args := m.Called(ctx, token)
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockAuthenticationService) ValidateAPIKey(ctx context.Context, apiKey string, apiConfig *models.APIConfiguration) (*models.User, error) {
	args := m.Called(ctx, apiKey, apiConfig)
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockAuthenticationService) ValidateOAuth(ctx context.Context, token string, apiConfig *models.APIConfiguration) (*models.User, error) {
	args := m.Called(ctx, token, apiConfig)
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockAuthenticationService) ValidateBasicAuth(ctx context.Context, username, password string, apiConfig *models.APIConfiguration) (*models.User, error) {
	args := m.Called(ctx, username, password, apiConfig)
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockAuthenticationService) GenerateJWT(ctx context.Context, user *models.User) (string, error) {
	args := m.Called(ctx, user)
	return args.String(0), args.Error(1)
}

func (m *MockAuthenticationService) HashPassword(password string) (string, error) {
	args := m.Called(password)
	return args.String(0), args.Error(1)
}

type MockAuthorizationService struct {
	mock.Mock
}

func (m *MockAuthorizationService) CanAccessResource(ctx context.Context, user *models.User, resourceOrgID string) bool {
	args := m.Called(ctx, user, resourceOrgID)
	return args.Bool(0)
}

func (m *MockAuthorizationService) CanManageOrganisation(ctx context.Context, user *models.User, orgID string) bool {
	args := m.Called(ctx, user, orgID)
	return args.Bool(0)
}

func (m *MockAuthorizationService) FilterByOrganisation(ctx context.Context, user *models.User, data interface{}) interface{} {
	args := m.Called(ctx, user, data)
	return args.Get(0)
}

func (m *MockAuthorizationService) LogSecurityViolation(ctx context.Context, user *models.User, action string, resourceID string) {
	m.Called(ctx, user, action, resourceID)
}

type MockUserManagementService struct {
	mock.Mock
}

func (m *MockUserManagementService) CreateUser(ctx context.Context, user *models.User, password string) error {
	args := m.Called(ctx, user, password)
	return args.Error(0)
}

func (m *MockUserManagementService) GetUser(ctx context.Context, userID string) (*models.User, error) {
	args := m.Called(ctx, userID)
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserManagementService) GetUsersByOrganisation(ctx context.Context, orgID string) ([]*models.User, error) {
	args := m.Called(ctx, orgID)
	return args.Get(0).([]*models.User), args.Error(1)
}

func (m *MockUserManagementService) UpdateUser(ctx context.Context, user *models.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockUserManagementService) DeleteUser(ctx context.Context, userID string) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *MockUserManagementService) AssignUserToOrganisation(ctx context.Context, userID, orgID string) error {
	args := m.Called(ctx, userID, orgID)
	return args.Error(0)
}

func (m *MockUserManagementService) ChangeUserRole(ctx context.Context, userID, role string) error {
	args := m.Called(ctx, userID, role)
	return args.Error(0)
}

func (m *MockUserManagementService) ActivateUser(ctx context.Context, userID string) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *MockUserManagementService) DeactivateUser(ctx context.Context, userID string) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *MockUserManagementService) ChangePassword(ctx context.Context, userID, newPassword string) error {
	args := m.Called(ctx, userID, newPassword)
	return args.Error(0)
}

func (m *MockUserManagementService) GetAllUsers(ctx context.Context) ([]*models.User, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.User), args.Error(1)
}

func (m *MockUserManagementService) GetUserByUsername(ctx context.Context, username string) (*models.User, error) {
	args := m.Called(ctx, username)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserManagementService) VerifyPassword(hashedPassword, password string) error {
	args := m.Called(hashedPassword, password)
	return args.Error(0)
}

// Add additional methods to existing MockMonitoringService
func (m *MockMonitoringService) GetSystemHealth(ctx context.Context) (map[string]interface{}, error) {
	args := m.Called(ctx)
	return args.Get(0).(map[string]interface{}), args.Error(1)
}

func (m *MockMonitoringService) GetOrganisationMetrics(ctx context.Context, orgID string) (map[string]interface{}, error) {
	args := m.Called(ctx, orgID)
	return args.Get(0).(map[string]interface{}), args.Error(1)
}

func (m *MockMonitoringService) GetLogsByOrganisation(ctx context.Context, orgID string, limit, offset int) ([]*models.RequestLog, error) {
	args := m.Called(ctx, orgID, limit, offset)
	return args.Get(0).([]*models.RequestLog), args.Error(1)
}

func (m *MockMonitoringService) GetErrorLogs(ctx context.Context, orgID string, limit, offset int) ([]*models.RequestLog, error) {
	args := m.Called(ctx, orgID, limit, offset)
	return args.Get(0).([]*models.RequestLog), args.Error(1)
}

func (m *MockMonitoringService) GetSystemLogs(ctx context.Context, limit, offset int) ([]*models.RequestLog, error) {
	args := m.Called(ctx, limit, offset)
	return args.Get(0).([]*models.RequestLog), args.Error(1)
}

func (m *MockMonitoringService) GetRecentLogs(ctx context.Context, orgID string, limit int) ([]*models.RequestLog, error) {
	args := m.Called(ctx, orgID, limit)
	return args.Get(0).([]*models.RequestLog), args.Error(1)
}

// Test helper functions
func setupTestHandler() (*ManagementAPIHandler, *MockConfigurationService, *MockAuthenticationService, *MockAuthorizationService, *MockUserManagementService, *MockMonitoringService) {
	// Create a minimal config for logger
	cfg := &config.Config{
		Logging: config.LoggingConfig{
			Level:  "info",
			Format: "json",
		},
	}
	logger := logger.NewLogger(cfg)

	mockConfigSvc := &MockConfigurationService{}
	mockAuthSvc := &MockAuthenticationService{}
	mockAuthzSvc := &MockAuthorizationService{}
	mockUserMgmtSvc := &MockUserManagementService{}
	mockMonitoringSvc := &MockMonitoringService{}

	handler := NewManagementAPIHandler(
		logger,
		mockConfigSvc,
		mockAuthSvc,
		mockAuthzSvc,
		mockUserMgmtSvc,
		mockMonitoringSvc,
	)

	return handler, mockConfigSvc, mockAuthSvc, mockAuthzSvc, mockUserMgmtSvc, mockMonitoringSvc
}

func createTestUser() *models.User {
	return &models.User{
		ID:             "test-user-id",
		OrganisationID: "test-org-id",
		Username:       "testuser",
		Email:          "test@example.com",
		Role:           "global_admin",
		IsActive:       true,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}
}

func createTestOrganisation() *models.Organisation {
	return &models.Organisation{
		ID:        "test-org-id",
		Name:      "Test Organisation",
		IsActive:  true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

// Test Organisation Management

func TestCreateOrganisation(t *testing.T) {
	handler, mockConfigSvc, mockAuthSvc, _, _, _ := setupTestHandler()

	// Setup mocks
	testUser := createTestUser()
	testOrg := createTestOrganisation()

	mockAuthSvc.On("ValidateJWT", mock.Anything, "valid-token").Return(testUser, nil)
	mockConfigSvc.On("CreateOrganisation", mock.Anything, mock.AnythingOfType("*models.Organisation")).Return(testOrg, nil)

	// Create request
	orgData := map[string]interface{}{
		"name":      "Test Organisation",
		"is_active": true,
	}
	jsonData, _ := json.Marshal(orgData)

	req := httptest.NewRequest("POST", "/api/v1/organisations", bytes.NewBuffer(jsonData))
	req.Header.Set("Authorization", "Bearer valid-token")
	req.Header.Set("Content-Type", "application/json")

	// Add user to context (simulating authentication middleware)
	ctx := context.WithValue(req.Context(), "user", testUser)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()

	// Create router and register routes
	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	// Execute request
	router.ServeHTTP(rr, req)

	// Verify response
	assert.Equal(t, http.StatusCreated, rr.Code)

	var response models.Organisation
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, testOrg.Name, response.Name)
	assert.Equal(t, testOrg.IsActive, response.IsActive)

	// Verify mocks were called
	mockConfigSvc.AssertExpectations(t)
}

func TestGetOrganisations(t *testing.T) {
	handler, mockConfigSvc, mockAuthSvc, mockAuthzSvc, _, _ := setupTestHandler()

	// Setup mocks
	testUser := createTestUser()
	testOrgs := []*models.Organisation{createTestOrganisation()}

	mockAuthSvc.On("ValidateJWT", mock.Anything, "valid-token").Return(testUser, nil)
	mockConfigSvc.On("GetAllOrganisations", mock.Anything).Return(testOrgs, nil)
	mockAuthzSvc.On("FilterByOrganisation", mock.Anything, testUser, testOrgs).Return(testOrgs)

	// Create request
	req := httptest.NewRequest("GET", "/api/v1/organisations", nil)
	req.Header.Set("Authorization", "Bearer valid-token")

	// Add user to context
	ctx := context.WithValue(req.Context(), "user", testUser)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()

	// Create router and register routes
	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	// Execute request
	router.ServeHTTP(rr, req)

	// Verify response
	assert.Equal(t, http.StatusOK, rr.Code)

	var response []*models.Organisation
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Len(t, response, 1)
	assert.Equal(t, testOrgs[0].Name, response[0].Name)

	// Verify mocks were called
	mockConfigSvc.AssertExpectations(t)
	mockAuthzSvc.AssertExpectations(t)
}

func TestGetSystemHealth(t *testing.T) {
	handler, _, mockAuthSvc, _, _, mockMonitoringSvc := setupTestHandler()

	// Setup mocks
	testUser := createTestUser()
	healthData := map[string]interface{}{
		"status": "healthy",
		"components": map[string]interface{}{
			"database": map[string]interface{}{
				"status":  "healthy",
				"message": "Connected",
			},
		},
		"timestamp": time.Now().Format(time.RFC3339),
	}

	mockAuthSvc.On("ValidateJWT", mock.Anything, "valid-token").Return(testUser, nil)
	mockMonitoringSvc.On("GetSystemHealth", mock.Anything).Return(healthData, nil)

	// Create request
	req := httptest.NewRequest("GET", "/api/v1/system/health", nil)
	req.Header.Set("Authorization", "Bearer valid-token")

	// Add user to context
	ctx := context.WithValue(req.Context(), "user", testUser)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()

	// Create router and register routes
	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	// Execute request
	router.ServeHTTP(rr, req)

	// Verify response
	assert.Equal(t, http.StatusOK, rr.Code)

	var response map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "healthy", response["status"])

	// Verify mocks were called
	mockMonitoringSvc.AssertExpectations(t)
}

func TestGetOpenAPISpec(t *testing.T) {
	handler, _, _, _, _, _ := setupTestHandler()

	// Create request
	req := httptest.NewRequest("GET", "/api/v1/docs/openapi.json", nil)
	rr := httptest.NewRecorder()

	// Create router and register routes
	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	// Execute request
	router.ServeHTTP(rr, req)

	// Verify response
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))

	var response map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "3.0.3", response["openapi"])
	assert.Contains(t, response, "info")
	assert.Contains(t, response, "paths")
	assert.Contains(t, response, "components")
}

func TestGetSwaggerUI(t *testing.T) {
	handler, _, _, _, _, _ := setupTestHandler()

	// Create request
	req := httptest.NewRequest("GET", "/api/v1/docs/swagger", nil)
	rr := httptest.NewRecorder()

	// Create router and register routes
	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	// Execute request
	router.ServeHTTP(rr, req)

	// Verify response
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "text/html", rr.Header().Get("Content-Type"))
	assert.Contains(t, rr.Body.String(), "swagger-ui")
	assert.Contains(t, rr.Body.String(), "API Translation Platform")
}

func TestAPIVersioning(t *testing.T) {
	handler, mockConfigSvc, mockAuthSvc, mockAuthzSvc, _, _ := setupTestHandler()

	// Setup mocks
	testUser := createTestUser()
	testOrgs := []*models.Organisation{createTestOrganisation()}

	mockAuthSvc.On("ValidateJWT", mock.Anything, "valid-token").Return(testUser, nil)
	mockConfigSvc.On("GetAllOrganisations", mock.Anything).Return(testOrgs, nil)
	mockAuthzSvc.On("FilterByOrganisation", mock.Anything, testUser, testOrgs).Return(testOrgs)

	// Test both v1 and v2 endpoints
	testCases := []struct {
		name string
		path string
	}{
		{"v1 endpoint", "/api/v1/organisations"},
		{"v2 endpoint", "/api/v2/organisations"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tc.path, nil)
			req.Header.Set("Authorization", "Bearer valid-token")

			// Add user to context
			ctx := context.WithValue(req.Context(), "user", testUser)
			req = req.WithContext(ctx)

			rr := httptest.NewRecorder()

			// Create router and register routes
			router := mux.NewRouter()
			handler.RegisterRoutes(router)

			// Execute request
			router.ServeHTTP(rr, req)

			// Verify response
			assert.Equal(t, http.StatusOK, rr.Code)

			var response []*models.Organisation
			err := json.Unmarshal(rr.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Len(t, response, 1)
		})
	}
}
