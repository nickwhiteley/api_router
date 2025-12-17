package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"api-translation-platform/internal/config"
	"api-translation-platform/internal/logger"
	"api-translation-platform/internal/models"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// Mock services for testing
type MockAuthService struct {
	mock.Mock
}

func (m *MockAuthService) ValidateAPIKey(ctx context.Context, apiKey string, apiConfig *models.APIConfiguration) (*models.User, error) {
	args := m.Called(ctx, apiKey, apiConfig)
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockAuthService) ValidateOAuth(ctx context.Context, token string, apiConfig *models.APIConfiguration) (*models.User, error) {
	args := m.Called(ctx, token, apiConfig)
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockAuthService) ValidateBasicAuth(ctx context.Context, username, password string, apiConfig *models.APIConfiguration) (*models.User, error) {
	args := m.Called(ctx, username, password, apiConfig)
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockAuthService) GenerateJWT(ctx context.Context, user *models.User) (string, error) {
	args := m.Called(ctx, user)
	return args.String(0), args.Error(1)
}

func (m *MockAuthService) ValidateJWT(ctx context.Context, token string) (*models.User, error) {
	args := m.Called(ctx, token)
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockAuthService) HashPassword(password string) (string, error) {
	args := m.Called(password)
	return args.String(0), args.Error(1)
}

type MockAuthzService struct {
	mock.Mock
}

func (m *MockAuthzService) CanAccessResource(ctx context.Context, user *models.User, resourceOrgID string) bool {
	args := m.Called(ctx, user, resourceOrgID)
	return args.Bool(0)
}

func (m *MockAuthzService) CanManageOrganisation(ctx context.Context, user *models.User, orgID string) bool {
	args := m.Called(ctx, user, orgID)
	return args.Bool(0)
}

func (m *MockAuthzService) FilterByOrganisation(ctx context.Context, user *models.User, data interface{}) interface{} {
	args := m.Called(ctx, user, data)
	return args.Get(0)
}

func (m *MockAuthzService) LogSecurityViolation(ctx context.Context, user *models.User, action string, resourceID string) {
	m.Called(ctx, user, action, resourceID)
}

type MockConfigService struct {
	mock.Mock
}

func (m *MockConfigService) GetAPIConfigurationsByOrganisation(ctx context.Context, orgID string) ([]*models.APIConfiguration, error) {
	args := m.Called(ctx, orgID)
	return args.Get(0).([]*models.APIConfiguration), args.Error(1)
}

// Add other required methods as stubs
func (m *MockConfigService) CreateAPIConfiguration(ctx context.Context, config *models.APIConfiguration) (*models.APIConfiguration, error) {
	args := m.Called(ctx, config)
	return args.Get(0).(*models.APIConfiguration), args.Error(1)
}

func (m *MockConfigService) UpdateAPIConfiguration(ctx context.Context, config *models.APIConfiguration) (*models.APIConfiguration, error) {
	args := m.Called(ctx, config)
	return args.Get(0).(*models.APIConfiguration), args.Error(1)
}

func (m *MockConfigService) DeleteAPIConfiguration(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockConfigService) GetAPIConfiguration(ctx context.Context, id string) (*models.APIConfiguration, error) {
	args := m.Called(ctx, id)
	return args.Get(0).(*models.APIConfiguration), args.Error(1)
}

func (m *MockConfigService) ValidateConfiguration(ctx context.Context, config *models.APIConfiguration) error {
	args := m.Called(ctx, config)
	return args.Error(0)
}

func (m *MockConfigService) TestAPIConfiguration(ctx context.Context, apiID string, testRequest map[string]interface{}) (map[string]interface{}, error) {
	args := m.Called(ctx, apiID, testRequest)
	return args.Get(0).(map[string]interface{}), args.Error(1)
}

// Add stub implementations for other required methods
func (m *MockConfigService) CreateConnector(ctx context.Context, connector *models.Connector) (*models.Connector, error) {
	return nil, nil
}
func (m *MockConfigService) UpdateConnector(ctx context.Context, connector *models.Connector) (*models.Connector, error) {
	return nil, nil
}
func (m *MockConfigService) DeleteConnector(ctx context.Context, connectorID string) error {
	return nil
}
func (m *MockConfigService) GetConnector(ctx context.Context, connectorID string) (*models.Connector, error) {
	return nil, nil
}
func (m *MockConfigService) GetConnectorsByOrganisation(ctx context.Context, orgID string) ([]*models.Connector, error) {
	return nil, nil
}
func (m *MockConfigService) UpdateConnectorScript(ctx context.Context, connectorID, script string) error {
	return nil
}
func (m *MockConfigService) CreateOrganisation(ctx context.Context, org *models.Organisation) (*models.Organisation, error) {
	return nil, nil
}
func (m *MockConfigService) UpdateOrganisation(ctx context.Context, org *models.Organisation) (*models.Organisation, error) {
	return nil, nil
}
func (m *MockConfigService) DeleteOrganisation(ctx context.Context, orgID string) error { return nil }
func (m *MockConfigService) GetOrganisation(ctx context.Context, orgID string) (*models.Organisation, error) {
	return nil, nil
}
func (m *MockConfigService) GetAllOrganisations(ctx context.Context) ([]*models.Organisation, error) {
	return nil, nil
}

// Add other interface methods as stubs...
func (m *MockConfigService) CreateConfigurationVersion(ctx context.Context, resourceType, resourceID string, configData models.JSONMap, userID string) (*models.ConfigurationVersion, error) {
	return nil, nil
}
func (m *MockConfigService) GetConfigurationVersions(ctx context.Context, resourceType, resourceID string) ([]*models.ConfigurationVersion, error) {
	return nil, nil
}
func (m *MockConfigService) GetConfigurationVersion(ctx context.Context, versionID string) (*models.ConfigurationVersion, error) {
	return nil, nil
}
func (m *MockConfigService) RollbackToVersion(ctx context.Context, versionID string, userID string) error {
	return nil
}
func (m *MockConfigService) GetActiveConfigurationVersion(ctx context.Context, resourceType, resourceID string) (*models.ConfigurationVersion, error) {
	return nil, nil
}
func (m *MockConfigService) LogConfigurationChange(ctx context.Context, userID, action, resourceType, resourceID string, oldValues, newValues models.JSONMap) error {
	return nil
}
func (m *MockConfigService) GetAuditLogs(ctx context.Context, orgID string, limit, offset int) ([]*models.AuditLog, error) {
	return nil, nil
}
func (m *MockConfigService) GetResourceAuditLogs(ctx context.Context, resourceType, resourceID string, limit, offset int) ([]*models.AuditLog, error) {
	return nil, nil
}
func (m *MockConfigService) SynchronizeConfiguration(ctx context.Context, instanceID string) error {
	return nil
}
func (m *MockConfigService) GetConfigurationChecksum(ctx context.Context, orgID string) (string, error) {
	return "", nil
}
func (m *MockConfigService) ValidateConfigurationConsistency(ctx context.Context) error { return nil }

type MockMonitorService struct {
	mock.Mock
}

func (m *MockMonitorService) GetOrganisationMetrics(ctx context.Context, orgID string) (map[string]interface{}, error) {
	args := m.Called(ctx, orgID)
	return args.Get(0).(map[string]interface{}), args.Error(1)
}

// Add stub implementations for other required methods
func (m *MockMonitorService) RecordMetric(ctx context.Context, orgID, name string, value float64, labels map[string]string) error {
	return nil
}
func (m *MockMonitorService) GetMetrics(ctx context.Context, orgID, metricName string, startTime, endTime time.Time) ([]*models.Metric, error) {
	return nil, nil
}
func (m *MockMonitorService) GetThroughputMetrics(ctx context.Context, orgID string, startTime, endTime time.Time) (*models.ThroughputMetrics, error) {
	return nil, nil
}
func (m *MockMonitorService) GetSystemMetrics(ctx context.Context) (*models.SystemMetrics, error) {
	return nil, nil
}
func (m *MockMonitorService) GetRecentLogs(ctx context.Context, orgID string, limit int) ([]*models.RequestLog, error) {
	return nil, nil
}
func (m *MockMonitorService) GetLogsByOrganisation(ctx context.Context, orgID string, limit, offset int) ([]*models.RequestLog, error) {
	return nil, nil
}
func (m *MockMonitorService) GetErrorLogs(ctx context.Context, orgID string, limit, offset int) ([]*models.RequestLog, error) {
	return nil, nil
}
func (m *MockMonitorService) GetSystemLogs(ctx context.Context, limit, offset int) ([]*models.RequestLog, error) {
	return nil, nil
}
func (m *MockMonitorService) PerformHealthCheck(ctx context.Context, component string) (*models.HealthCheck, error) {
	return nil, nil
}
func (m *MockMonitorService) GetHealthStatus(ctx context.Context) (map[string]*models.HealthCheck, error) {
	return nil, nil
}
func (m *MockMonitorService) GetSystemHealth(ctx context.Context) (map[string]interface{}, error) {
	return nil, nil
}
func (m *MockMonitorService) RegisterHealthCheck(component string, checkFunc func(ctx context.Context) (*models.HealthCheck, error)) {
}
func (m *MockMonitorService) CreateAlert(ctx context.Context, alert *models.Alert) error { return nil }
func (m *MockMonitorService) EvaluateAlerts(ctx context.Context) error                   { return nil }
func (m *MockMonitorService) GetActiveAlerts(ctx context.Context, orgID string) ([]*models.Alert, error) {
	return nil, nil
}
func (m *MockMonitorService) CollectSystemMetrics(ctx context.Context) error { return nil }
func (m *MockMonitorService) StartMetricsCollection(ctx context.Context) error {
	return nil
}
func (m *MockMonitorService) StopMetricsCollection() error { return nil }

// createTestLogger creates a logger for testing
func createTestLogger() *logger.Logger {
	cfg := &config.Config{
		Logging: config.LoggingConfig{
			Level:  "info",
			Format: "text",
		},
	}
	return logger.NewLogger(cfg)
}

func TestWebUIHandler_OrganisationMiddleware(t *testing.T) {
	// Create mock services
	mockAuthService := &MockAuthService{}
	mockAuthzService := &MockAuthzService{}
	mockConfigService := &MockConfigService{}
	mockMonitorService := &MockMonitorService{}

	// Create handler
	handler := NewWebUIHandler(
		createTestLogger(),
		mockAuthService,
		mockAuthzService,
		mockConfigService,
		mockMonitorService,
	)

	// Create test user
	testUser := &models.User{
		ID:             "test-user-id",
		OrganisationID: "test-org",
		Role:           "org_admin",
		IsActive:       true,
	}

	// Test successful access
	t.Run("successful access to own organisation", func(t *testing.T) {
		// Set up mocks
		mockAuthzService.On("CanAccessResource", mock.Anything, testUser, "test-org").Return(true)

		// Create request with user in context
		req := httptest.NewRequest("GET", "/ui/test-org/dashboard", nil)
		req = req.WithContext(context.WithValue(req.Context(), "user", testUser))

		// Create response recorder
		rr := httptest.NewRecorder()

		// Create a simple handler for testing middleware
		testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("success"))
		})

		// Apply middleware and manually set the mux vars for the test
		middlewareHandler := handler.organisationMiddleware(testHandler)
		req = mux.SetURLVars(req, map[string]string{"orgID": "test-org"})
		middlewareHandler.ServeHTTP(rr, req)

		// Assert
		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Equal(t, "success", rr.Body.String())
		mockAuthzService.AssertExpectations(t)
	})

	// Test access denied
	t.Run("access denied to different organisation", func(t *testing.T) {
		// Set up mocks
		mockAuthzService.On("CanAccessResource", mock.Anything, testUser, "other-org").Return(false)
		mockAuthzService.On("LogSecurityViolation", mock.Anything, testUser, "unauthorized_org_access", "other-org").Return()

		// Create request with user in context
		req := httptest.NewRequest("GET", "/ui/other-org/dashboard", nil)
		req = req.WithContext(context.WithValue(req.Context(), "user", testUser))

		// Create response recorder
		rr := httptest.NewRecorder()

		// Create a simple handler for testing middleware
		testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("success"))
		})

		// Apply middleware
		middlewareHandler := handler.organisationMiddleware(testHandler)

		// Manually set the mux vars for the test
		req = mux.SetURLVars(req, map[string]string{"orgID": "other-org"})
		middlewareHandler.ServeHTTP(rr, req)

		// Assert
		assert.Equal(t, http.StatusForbidden, rr.Code)
		mockAuthzService.AssertExpectations(t)
	})
}

func TestWebUIHandler_GlobalAdminMiddleware(t *testing.T) {
	// Create mock services
	mockAuthService := &MockAuthService{}
	mockAuthzService := &MockAuthzService{}
	mockConfigService := &MockConfigService{}
	mockMonitorService := &MockMonitorService{}

	// Create handler
	handler := NewWebUIHandler(
		createTestLogger(),
		mockAuthService,
		mockAuthzService,
		mockConfigService,
		mockMonitorService,
	)

	// Test successful global admin access
	t.Run("successful global admin access", func(t *testing.T) {
		// Create global admin user
		globalAdmin := &models.User{
			ID:             "global-admin-id",
			OrganisationID: "admin-org",
			Role:           "global_admin",
			IsActive:       true,
		}

		// Create request with global admin in context
		req := httptest.NewRequest("GET", "/ui/admin/organisations", nil)
		req = req.WithContext(context.WithValue(req.Context(), "user", globalAdmin))

		// Create response recorder
		rr := httptest.NewRecorder()

		// Create a simple handler for testing middleware
		testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("success"))
		})

		// Apply middleware
		middlewareHandler := handler.globalAdminMiddleware(testHandler)
		middlewareHandler.ServeHTTP(rr, req)

		// Assert
		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Equal(t, "success", rr.Body.String())
	})

	// Test access denied for org admin
	t.Run("access denied for org admin", func(t *testing.T) {
		// Create org admin user
		orgAdmin := &models.User{
			ID:             "org-admin-id",
			OrganisationID: "test-org",
			Role:           "org_admin",
			IsActive:       true,
		}

		// Set up mocks
		mockAuthzService.On("LogSecurityViolation", mock.Anything, orgAdmin, "unauthorized_global_admin_access", "system").Return()

		// Create request with org admin in context
		req := httptest.NewRequest("GET", "/ui/admin/organisations", nil)
		req = req.WithContext(context.WithValue(req.Context(), "user", orgAdmin))

		// Create response recorder
		rr := httptest.NewRecorder()

		// Create a simple handler for testing middleware
		testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("success"))
		})

		// Apply middleware
		middlewareHandler := handler.globalAdminMiddleware(testHandler)
		middlewareHandler.ServeHTTP(rr, req)

		// Assert
		assert.Equal(t, http.StatusForbidden, rr.Code)
		mockAuthzService.AssertExpectations(t)
	})
}
