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

// Integration tests for Management API
// **Feature: api-translation-platform, Property 11: API-driven configuration**
// **Validates: Requirements 4.1, 7.2, 7.5**

// Mock services for integration testing
type MockMgmtConfigurationService struct {
	mock.Mock
}

func (m *MockMgmtConfigurationService) CreateOrganisation(ctx context.Context, org *models.Organisation) (*models.Organisation, error) {
	args := m.Called(ctx, org)
	return args.Get(0).(*models.Organisation), args.Error(1)
}

func (m *MockMgmtConfigurationService) GetAllOrganisations(ctx context.Context) ([]*models.Organisation, error) {
	args := m.Called(ctx)
	return args.Get(0).([]*models.Organisation), args.Error(1)
}

func (m *MockMgmtConfigurationService) GetOrganisation(ctx context.Context, orgID string) (*models.Organisation, error) {
	args := m.Called(ctx, orgID)
	return args.Get(0).(*models.Organisation), args.Error(1)
}

func (m *MockMgmtConfigurationService) UpdateOrganisation(ctx context.Context, org *models.Organisation) (*models.Organisation, error) {
	args := m.Called(ctx, org)
	return args.Get(0).(*models.Organisation), args.Error(1)
}

func (m *MockMgmtConfigurationService) DeleteOrganisation(ctx context.Context, orgID string) error {
	args := m.Called(ctx, orgID)
	return args.Error(0)
}

// Add minimal implementations for other required methods
func (m *MockMgmtConfigurationService) CreateAPIConfiguration(ctx context.Context, config *models.APIConfiguration) (*models.APIConfiguration, error) {
	args := m.Called(ctx, config)
	return args.Get(0).(*models.APIConfiguration), args.Error(1)
}

func (m *MockMgmtConfigurationService) GetAPIConfiguration(ctx context.Context, id string) (*models.APIConfiguration, error) {
	args := m.Called(ctx, id)
	return args.Get(0).(*models.APIConfiguration), args.Error(1)
}

func (m *MockMgmtConfigurationService) GetAPIConfigurationsByOrganisation(ctx context.Context, orgID string) ([]*models.APIConfiguration, error) {
	args := m.Called(ctx, orgID)
	return args.Get(0).([]*models.APIConfiguration), args.Error(1)
}

func (m *MockMgmtConfigurationService) UpdateAPIConfiguration(ctx context.Context, config *models.APIConfiguration) (*models.APIConfiguration, error) {
	args := m.Called(ctx, config)
	return args.Get(0).(*models.APIConfiguration), args.Error(1)
}

func (m *MockMgmtConfigurationService) DeleteAPIConfiguration(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockMgmtConfigurationService) TestAPIConfiguration(ctx context.Context, apiID string, testRequest map[string]interface{}) (map[string]interface{}, error) {
	args := m.Called(ctx, apiID, testRequest)
	return args.Get(0).(map[string]interface{}), args.Error(1)
}

func (m *MockMgmtConfigurationService) ValidateConfiguration(ctx context.Context, config *models.APIConfiguration) error {
	args := m.Called(ctx, config)
	return args.Error(0)
}

func (m *MockMgmtConfigurationService) CreateConnector(ctx context.Context, connector *models.Connector) (*models.Connector, error) {
	args := m.Called(ctx, connector)
	return args.Get(0).(*models.Connector), args.Error(1)
}

func (m *MockMgmtConfigurationService) UpdateConnector(ctx context.Context, connector *models.Connector) (*models.Connector, error) {
	args := m.Called(ctx, connector)
	return args.Get(0).(*models.Connector), args.Error(1)
}

func (m *MockMgmtConfigurationService) DeleteConnector(ctx context.Context, connectorID string) error {
	args := m.Called(ctx, connectorID)
	return args.Error(0)
}

func (m *MockMgmtConfigurationService) GetConnector(ctx context.Context, connectorID string) (*models.Connector, error) {
	args := m.Called(ctx, connectorID)
	return args.Get(0).(*models.Connector), args.Error(1)
}

func (m *MockMgmtConfigurationService) GetConnectorsByOrganisation(ctx context.Context, orgID string) ([]*models.Connector, error) {
	args := m.Called(ctx, orgID)
	return args.Get(0).([]*models.Connector), args.Error(1)
}

func (m *MockMgmtConfigurationService) UpdateConnectorScript(ctx context.Context, connectorID, script string) error {
	args := m.Called(ctx, connectorID, script)
	return args.Error(0)
}

func (m *MockMgmtConfigurationService) CreateConfigurationVersion(ctx context.Context, resourceType, resourceID string, configData models.JSONMap, userID string) (*models.ConfigurationVersion, error) {
	args := m.Called(ctx, resourceType, resourceID, configData, userID)
	return args.Get(0).(*models.ConfigurationVersion), args.Error(1)
}

func (m *MockMgmtConfigurationService) GetConfigurationVersions(ctx context.Context, resourceType, resourceID string) ([]*models.ConfigurationVersion, error) {
	args := m.Called(ctx, resourceType, resourceID)
	return args.Get(0).([]*models.ConfigurationVersion), args.Error(1)
}

func (m *MockMgmtConfigurationService) GetConfigurationVersion(ctx context.Context, versionID string) (*models.ConfigurationVersion, error) {
	args := m.Called(ctx, versionID)
	return args.Get(0).(*models.ConfigurationVersion), args.Error(1)
}

func (m *MockMgmtConfigurationService) RollbackToVersion(ctx context.Context, versionID string, userID string) error {
	args := m.Called(ctx, versionID, userID)
	return args.Error(0)
}

func (m *MockMgmtConfigurationService) GetActiveConfigurationVersion(ctx context.Context, resourceType, resourceID string) (*models.ConfigurationVersion, error) {
	args := m.Called(ctx, resourceType, resourceID)
	return args.Get(0).(*models.ConfigurationVersion), args.Error(1)
}

func (m *MockMgmtConfigurationService) LogConfigurationChange(ctx context.Context, userID, action, resourceType, resourceID string, oldValues, newValues models.JSONMap) error {
	args := m.Called(ctx, userID, action, resourceType, resourceID, oldValues, newValues)
	return args.Error(0)
}

func (m *MockMgmtConfigurationService) GetAuditLogs(ctx context.Context, orgID string, limit, offset int) ([]*models.AuditLog, error) {
	args := m.Called(ctx, orgID, limit, offset)
	return args.Get(0).([]*models.AuditLog), args.Error(1)
}

func (m *MockMgmtConfigurationService) GetResourceAuditLogs(ctx context.Context, resourceType, resourceID string, limit, offset int) ([]*models.AuditLog, error) {
	args := m.Called(ctx, resourceType, resourceID, limit, offset)
	return args.Get(0).([]*models.AuditLog), args.Error(1)
}

func (m *MockMgmtConfigurationService) SynchronizeConfiguration(ctx context.Context, instanceID string) error {
	args := m.Called(ctx, instanceID)
	return args.Error(0)
}

func (m *MockMgmtConfigurationService) GetConfigurationChecksum(ctx context.Context, orgID string) (string, error) {
	args := m.Called(ctx, orgID)
	return args.String(0), args.Error(1)
}

func (m *MockMgmtConfigurationService) ValidateConfigurationConsistency(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

type MockMgmtAuthenticationService struct {
	mock.Mock
}

func (m *MockMgmtAuthenticationService) ValidateJWT(ctx context.Context, token string) (*models.User, error) {
	args := m.Called(ctx, token)
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockMgmtAuthenticationService) ValidateAPIKey(ctx context.Context, apiKey string, apiConfig *models.APIConfiguration) (*models.User, error) {
	args := m.Called(ctx, apiKey, apiConfig)
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockMgmtAuthenticationService) ValidateOAuth(ctx context.Context, token string, apiConfig *models.APIConfiguration) (*models.User, error) {
	args := m.Called(ctx, token, apiConfig)
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockMgmtAuthenticationService) ValidateBasicAuth(ctx context.Context, username, password string, apiConfig *models.APIConfiguration) (*models.User, error) {
	args := m.Called(ctx, username, password, apiConfig)
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockMgmtAuthenticationService) GenerateJWT(ctx context.Context, user *models.User) (string, error) {
	args := m.Called(ctx, user)
	return args.String(0), args.Error(1)
}

func (m *MockMgmtAuthenticationService) HashPassword(password string) (string, error) {
	args := m.Called(password)
	return args.String(0), args.Error(1)
}

type MockMgmtAuthorizationService struct {
	mock.Mock
}

func (m *MockMgmtAuthorizationService) CanAccessResource(ctx context.Context, user *models.User, resourceOrgID string) bool {
	args := m.Called(ctx, user, resourceOrgID)
	return args.Bool(0)
}

func (m *MockMgmtAuthorizationService) CanManageOrganisation(ctx context.Context, user *models.User, orgID string) bool {
	args := m.Called(ctx, user, orgID)
	return args.Bool(0)
}

func (m *MockMgmtAuthorizationService) FilterByOrganisation(ctx context.Context, user *models.User, data interface{}) interface{} {
	args := m.Called(ctx, user, data)
	return args.Get(0)
}

func (m *MockMgmtAuthorizationService) LogSecurityViolation(ctx context.Context, user *models.User, action string, resourceID string) {
	m.Called(ctx, user, action, resourceID)
}

type MockMgmtUserManagementService struct {
	mock.Mock
}

func (m *MockMgmtUserManagementService) CreateUser(ctx context.Context, user *models.User, password string) error {
	args := m.Called(ctx, user, password)
	return args.Error(0)
}

func (m *MockMgmtUserManagementService) GetUser(ctx context.Context, userID string) (*models.User, error) {
	args := m.Called(ctx, userID)
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockMgmtUserManagementService) GetUsersByOrganisation(ctx context.Context, orgID string) ([]*models.User, error) {
	args := m.Called(ctx, orgID)
	return args.Get(0).([]*models.User), args.Error(1)
}

func (m *MockMgmtUserManagementService) UpdateUser(ctx context.Context, user *models.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockMgmtUserManagementService) DeleteUser(ctx context.Context, userID string) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *MockMgmtUserManagementService) AssignUserToOrganisation(ctx context.Context, userID, orgID string) error {
	args := m.Called(ctx, userID, orgID)
	return args.Error(0)
}

func (m *MockMgmtUserManagementService) ChangeUserRole(ctx context.Context, userID, role string) error {
	args := m.Called(ctx, userID, role)
	return args.Error(0)
}

func (m *MockMgmtUserManagementService) ActivateUser(ctx context.Context, userID string) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *MockMgmtUserManagementService) DeactivateUser(ctx context.Context, userID string) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *MockMgmtUserManagementService) ChangePassword(ctx context.Context, userID, newPassword string) error {
	args := m.Called(ctx, userID, newPassword)
	return args.Error(0)
}

func (m *MockMgmtUserManagementService) GetAllUsers(ctx context.Context) ([]*models.User, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.User), args.Error(1)
}

func (m *MockMgmtUserManagementService) GetUserByUsername(ctx context.Context, username string) (*models.User, error) {
	args := m.Called(ctx, username)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockMgmtUserManagementService) VerifyPassword(hashedPassword, password string) error {
	args := m.Called(hashedPassword, password)
	return args.Error(0)
}

type MockMgmtMonitoringService struct {
	mock.Mock
}

func (m *MockMgmtMonitoringService) GetSystemHealth(ctx context.Context) (map[string]interface{}, error) {
	args := m.Called(ctx)
	return args.Get(0).(map[string]interface{}), args.Error(1)
}

func (m *MockMgmtMonitoringService) GetOrganisationMetrics(ctx context.Context, orgID string) (map[string]interface{}, error) {
	args := m.Called(ctx, orgID)
	return args.Get(0).(map[string]interface{}), args.Error(1)
}

func (m *MockMgmtMonitoringService) GetLogsByOrganisation(ctx context.Context, orgID string, limit, offset int) ([]*models.RequestLog, error) {
	args := m.Called(ctx, orgID, limit, offset)
	return args.Get(0).([]*models.RequestLog), args.Error(1)
}

func (m *MockMgmtMonitoringService) GetErrorLogs(ctx context.Context, orgID string, limit, offset int) ([]*models.RequestLog, error) {
	args := m.Called(ctx, orgID, limit, offset)
	return args.Get(0).([]*models.RequestLog), args.Error(1)
}

func (m *MockMgmtMonitoringService) GetSystemMetrics(ctx context.Context) (*models.SystemMetrics, error) {
	args := m.Called(ctx)
	return args.Get(0).(*models.SystemMetrics), args.Error(1)
}

func (m *MockMgmtMonitoringService) GetSystemLogs(ctx context.Context, limit, offset int) ([]*models.RequestLog, error) {
	args := m.Called(ctx, limit, offset)
	return args.Get(0).([]*models.RequestLog), args.Error(1)
}

func (m *MockMgmtMonitoringService) RecordMetric(ctx context.Context, orgID, name string, value float64, labels map[string]string) error {
	args := m.Called(ctx, orgID, name, value, labels)
	return args.Error(0)
}

func (m *MockMgmtMonitoringService) GetMetrics(ctx context.Context, orgID, metricName string, startTime, endTime time.Time) ([]*models.Metric, error) {
	args := m.Called(ctx, orgID, metricName, startTime, endTime)
	return args.Get(0).([]*models.Metric), args.Error(1)
}

func (m *MockMgmtMonitoringService) GetThroughputMetrics(ctx context.Context, orgID string, startTime, endTime time.Time) (*models.ThroughputMetrics, error) {
	args := m.Called(ctx, orgID, startTime, endTime)
	return args.Get(0).(*models.ThroughputMetrics), args.Error(1)
}

func (m *MockMgmtMonitoringService) GetRecentLogs(ctx context.Context, orgID string, limit int) ([]*models.RequestLog, error) {
	args := m.Called(ctx, orgID, limit)
	return args.Get(0).([]*models.RequestLog), args.Error(1)
}

func (m *MockMgmtMonitoringService) PerformHealthCheck(ctx context.Context, component string) (*models.HealthCheck, error) {
	args := m.Called(ctx, component)
	return args.Get(0).(*models.HealthCheck), args.Error(1)
}

func (m *MockMgmtMonitoringService) GetHealthStatus(ctx context.Context) (map[string]*models.HealthCheck, error) {
	args := m.Called(ctx)
	return args.Get(0).(map[string]*models.HealthCheck), args.Error(1)
}

func (m *MockMgmtMonitoringService) RegisterHealthCheck(component string, checkFunc func(ctx context.Context) (*models.HealthCheck, error)) {
	m.Called(component, checkFunc)
}

func (m *MockMgmtMonitoringService) CreateAlert(ctx context.Context, alert *models.Alert) error {
	args := m.Called(ctx, alert)
	return args.Error(0)
}

func (m *MockMgmtMonitoringService) EvaluateAlerts(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockMgmtMonitoringService) GetActiveAlerts(ctx context.Context, orgID string) ([]*models.Alert, error) {
	args := m.Called(ctx, orgID)
	return args.Get(0).([]*models.Alert), args.Error(1)
}

func (m *MockMgmtMonitoringService) CollectSystemMetrics(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockMgmtMonitoringService) StartMetricsCollection(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockMgmtMonitoringService) StopMetricsCollection() error {
	args := m.Called()
	return args.Error(0)
}

// Test helper functions
func setupMgmtTestHandler() (*ManagementAPIHandler, *MockMgmtConfigurationService, *MockMgmtAuthenticationService, *MockMgmtAuthorizationService, *MockMgmtUserManagementService, *MockMgmtMonitoringService) {
	// Create a minimal config for logger
	cfg := &config.Config{
		Logging: config.LoggingConfig{
			Level:  "info",
			Format: "json",
		},
	}
	logger := logger.NewLogger(cfg)

	mockConfigSvc := &MockMgmtConfigurationService{}
	mockAuthSvc := &MockMgmtAuthenticationService{}
	mockAuthzSvc := &MockMgmtAuthorizationService{}
	mockUserMgmtSvc := &MockMgmtUserManagementService{}
	mockMonitoringSvc := &MockMgmtMonitoringService{}

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

func createMgmtTestUser() *models.User {
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

func createMgmtTestOrganisation() *models.Organisation {
	return &models.Organisation{
		ID:        "test-org-id",
		Name:      "Test Organisation",
		IsActive:  true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

// Integration Tests

func TestManagementAPI_CreateOrganisation_Integration(t *testing.T) {
	handler, mockConfigSvc, mockAuthSvc, _, _, _ := setupMgmtTestHandler()

	// Setup mocks
	testUser := createMgmtTestUser()
	testOrg := createMgmtTestOrganisation()

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

func TestManagementAPI_GetOrganisations_Integration(t *testing.T) {
	handler, mockConfigSvc, mockAuthSvc, mockAuthzSvc, _, _ := setupMgmtTestHandler()

	// Setup mocks
	testUser := createMgmtTestUser()
	testOrgs := []*models.Organisation{createMgmtTestOrganisation()}

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

func TestManagementAPI_GetSystemHealth_Integration(t *testing.T) {
	handler, _, mockAuthSvc, _, _, mockMonitoringSvc := setupMgmtTestHandler()

	// Setup mocks
	testUser := createMgmtTestUser()
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

func TestManagementAPI_OpenAPISpec_Integration(t *testing.T) {
	handler, _, _, _, _, _ := setupMgmtTestHandler()

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

func TestManagementAPI_SwaggerUI_Integration(t *testing.T) {
	handler, _, _, _, _, _ := setupMgmtTestHandler()

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

func TestManagementAPI_APIVersioning_Integration(t *testing.T) {
	handler, mockConfigSvc, mockAuthSvc, mockAuthzSvc, _, _ := setupMgmtTestHandler()

	// Setup mocks
	testUser := createMgmtTestUser()
	testOrgs := []*models.Organisation{createMgmtTestOrganisation()}

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

// Test complete API workflows end-to-end
func TestManagementAPI_CompleteWorkflow_Integration(t *testing.T) {
	handler, mockConfigSvc, mockAuthSvc, mockAuthzSvc, _, _ := setupMgmtTestHandler()

	// Setup mocks
	testUser := createMgmtTestUser()
	testOrg := createMgmtTestOrganisation()

	// Mock for organisation creation
	mockAuthSvc.On("ValidateJWT", mock.Anything, "valid-token").Return(testUser, nil)
	mockConfigSvc.On("CreateOrganisation", mock.Anything, mock.AnythingOfType("*models.Organisation")).Return(testOrg, nil)

	// Mock for organisation retrieval
	mockConfigSvc.On("GetOrganisation", mock.Anything, testOrg.ID).Return(testOrg, nil)
	mockAuthzSvc.On("CanAccessResource", mock.Anything, testUser, testOrg.ID).Return(true)

	// Create router
	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	// Step 1: Create organisation
	orgData := map[string]interface{}{
		"name":      "Test Organisation",
		"is_active": true,
	}
	jsonData, _ := json.Marshal(orgData)

	req1 := httptest.NewRequest("POST", "/api/v1/organisations", bytes.NewBuffer(jsonData))
	req1.Header.Set("Authorization", "Bearer valid-token")
	req1.Header.Set("Content-Type", "application/json")
	ctx1 := context.WithValue(req1.Context(), "user", testUser)
	req1 = req1.WithContext(ctx1)

	rr1 := httptest.NewRecorder()
	router.ServeHTTP(rr1, req1)

	assert.Equal(t, http.StatusCreated, rr1.Code)

	var createdOrg models.Organisation
	err := json.Unmarshal(rr1.Body.Bytes(), &createdOrg)
	assert.NoError(t, err)

	// Step 2: Retrieve the created organisation
	req2 := httptest.NewRequest("GET", "/api/v1/organisations/"+createdOrg.ID, nil)
	req2.Header.Set("Authorization", "Bearer valid-token")
	ctx2 := context.WithValue(req2.Context(), "user", testUser)
	req2 = req2.WithContext(ctx2)

	rr2 := httptest.NewRecorder()
	router.ServeHTTP(rr2, req2)

	assert.Equal(t, http.StatusOK, rr2.Code)

	var retrievedOrg models.Organisation
	err = json.Unmarshal(rr2.Body.Bytes(), &retrievedOrg)
	assert.NoError(t, err)
	assert.Equal(t, createdOrg.ID, retrievedOrg.ID)
	assert.Equal(t, createdOrg.Name, retrievedOrg.Name)

	// Verify all mocks were called
	mockConfigSvc.AssertExpectations(t)
	mockAuthSvc.AssertExpectations(t)
	mockAuthzSvc.AssertExpectations(t)
}

// Test API documentation accuracy
func TestManagementAPI_DocumentationAccuracy_Integration(t *testing.T) {
	handler, _, _, _, _, _ := setupMgmtTestHandler()

	// Get OpenAPI spec
	req := httptest.NewRequest("GET", "/api/v1/docs/openapi.json", nil)
	rr := httptest.NewRecorder()

	router := mux.NewRouter()
	handler.RegisterRoutes(router)
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var spec map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &spec)
	assert.NoError(t, err)

	// Verify essential API documentation elements
	info := spec["info"].(map[string]interface{})
	assert.Equal(t, "API Translation Platform Management API", info["title"])
	assert.Equal(t, "1.0.0", info["version"])

	paths := spec["paths"].(map[string]interface{})

	// Verify key endpoints are documented
	assert.Contains(t, paths, "/organisations")
	assert.Contains(t, paths, "/organisations/{id}")
	assert.Contains(t, paths, "/system/health")
	assert.Contains(t, paths, "/analytics/usage")

	// Verify components section exists
	components := spec["components"].(map[string]interface{})
	schemas := components["schemas"].(map[string]interface{})

	// Verify key schemas are documented
	assert.Contains(t, schemas, "Organisation")
	assert.Contains(t, schemas, "APIConfiguration")
	assert.Contains(t, schemas, "SystemHealth")
	assert.Contains(t, schemas, "UsageAnalytics")

	// Verify security schemes
	securitySchemes := components["securitySchemes"].(map[string]interface{})
	assert.Contains(t, securitySchemes, "bearerAuth")
}
