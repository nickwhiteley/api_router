package services

import (
	"context"
	"net/http"
	"time"

	"api-translation-platform/internal/models"
)

// APIGatewayService defines the interface for API gateway operations
type APIGatewayService interface {
	HandleInboundRequest(ctx context.Context, req *http.Request, apiConfig *models.APIConfiguration) (*http.Response, error)
	CreateDynamicEndpoint(ctx context.Context, apiConfig *models.APIConfiguration) error
	RemoveEndpoint(ctx context.Context, apiConfigID string) error
}

// TransformationService defines the interface for Python script execution
type TransformationService interface {
	ExecuteScript(ctx context.Context, script string, inputData interface{}) (interface{}, error)
	ValidateScript(ctx context.Context, script string) error
	ReloadScript(ctx context.Context, connectorID string) error
}

// OutboundClientService defines the interface for outbound API calls
type OutboundClientService interface {
	SendRESTRequest(ctx context.Context, apiConfig *models.APIConfiguration, method, path string, body interface{}, headers map[string]string) (*http.Response, error)
	SendSOAPRequest(ctx context.Context, apiConfig *models.APIConfiguration, action string, body interface{}) (*http.Response, error)
	TestConnection(ctx context.Context, apiConfig *models.APIConfiguration) error
}

// ConfigurationService defines the interface for configuration management
type ConfigurationService interface {
	CreateAPIConfiguration(ctx context.Context, config *models.APIConfiguration) (*models.APIConfiguration, error)
	UpdateAPIConfiguration(ctx context.Context, config *models.APIConfiguration) (*models.APIConfiguration, error)
	DeleteAPIConfiguration(ctx context.Context, id string) error
	GetAPIConfiguration(ctx context.Context, id string) (*models.APIConfiguration, error)
	GetAPIConfigurationsByOrganisation(ctx context.Context, orgID string) ([]*models.APIConfiguration, error)
	ValidateConfiguration(ctx context.Context, config *models.APIConfiguration) error
	TestAPIConfiguration(ctx context.Context, apiID string, testRequest map[string]interface{}) (map[string]interface{}, error)

	// Connector management
	CreateConnector(ctx context.Context, connector *models.Connector) (*models.Connector, error)
	UpdateConnector(ctx context.Context, connector *models.Connector) (*models.Connector, error)
	DeleteConnector(ctx context.Context, connectorID string) error
	GetConnector(ctx context.Context, connectorID string) (*models.Connector, error)
	GetConnectorsByOrganisation(ctx context.Context, orgID string) ([]*models.Connector, error)
	UpdateConnectorScript(ctx context.Context, connectorID, script string) error

	// Organisation management
	CreateOrganisation(ctx context.Context, org *models.Organisation) (*models.Organisation, error)
	UpdateOrganisation(ctx context.Context, org *models.Organisation) (*models.Organisation, error)
	DeleteOrganisation(ctx context.Context, orgID string) error
	GetOrganisation(ctx context.Context, orgID string) (*models.Organisation, error)
	GetAllOrganisations(ctx context.Context) ([]*models.Organisation, error)

	// Configuration versioning
	CreateConfigurationVersion(ctx context.Context, resourceType, resourceID string, configData models.JSONMap, userID string) (*models.ConfigurationVersion, error)
	GetConfigurationVersions(ctx context.Context, resourceType, resourceID string) ([]*models.ConfigurationVersion, error)
	GetConfigurationVersion(ctx context.Context, versionID string) (*models.ConfigurationVersion, error)
	RollbackToVersion(ctx context.Context, versionID string, userID string) error
	GetActiveConfigurationVersion(ctx context.Context, resourceType, resourceID string) (*models.ConfigurationVersion, error)

	// Audit logging
	LogConfigurationChange(ctx context.Context, userID, action, resourceType, resourceID string, oldValues, newValues models.JSONMap) error
	GetAuditLogs(ctx context.Context, orgID string, limit, offset int) ([]*models.AuditLog, error)
	GetResourceAuditLogs(ctx context.Context, resourceType, resourceID string, limit, offset int) ([]*models.AuditLog, error)

	// Configuration synchronization
	SynchronizeConfiguration(ctx context.Context, instanceID string) error
	GetConfigurationChecksum(ctx context.Context, orgID string) (string, error)
	ValidateConfigurationConsistency(ctx context.Context) error
}

// AuthenticationService defines the interface for authentication operations
type AuthenticationService interface {
	ValidateAPIKey(ctx context.Context, apiKey string, apiConfig *models.APIConfiguration) (*models.User, error)
	ValidateOAuth(ctx context.Context, token string, apiConfig *models.APIConfiguration) (*models.User, error)
	ValidateBasicAuth(ctx context.Context, username, password string, apiConfig *models.APIConfiguration) (*models.User, error)
	GenerateJWT(ctx context.Context, user *models.User) (string, error)
	ValidateJWT(ctx context.Context, token string) (*models.User, error)
	HashPassword(password string) (string, error)
}

// AuthorizationService defines the interface for authorization operations
type AuthorizationService interface {
	CanAccessResource(ctx context.Context, user *models.User, resourceOrgID string) bool
	CanManageOrganisation(ctx context.Context, user *models.User, orgID string) bool
	FilterByOrganisation(ctx context.Context, user *models.User, data interface{}) interface{}
	LogSecurityViolation(ctx context.Context, user *models.User, action string, resourceID string)
}

// UserManagementService defines the interface for user management operations
type UserManagementService interface {
	CreateUser(ctx context.Context, user *models.User, password string) error
	UpdateUser(ctx context.Context, user *models.User) error
	DeleteUser(ctx context.Context, userID string) error
	GetUser(ctx context.Context, userID string) (*models.User, error)
	GetUsersByOrganisation(ctx context.Context, orgID string) ([]*models.User, error)
	GetAllUsers(ctx context.Context) ([]*models.User, error)
	GetUserByUsername(ctx context.Context, username string) (*models.User, error)
	AssignUserToOrganisation(ctx context.Context, userID, orgID string) error
	ChangeUserRole(ctx context.Context, userID, role string) error
	ActivateUser(ctx context.Context, userID string) error
	DeactivateUser(ctx context.Context, userID string) error
	ChangePassword(ctx context.Context, userID, newPassword string) error
	VerifyPassword(hashedPassword, password string) error
}

// MonitoringService defines the interface for monitoring and metrics operations
type MonitoringService interface {
	// Metrics collection
	RecordMetric(ctx context.Context, orgID, name string, value float64, labels map[string]string) error
	GetMetrics(ctx context.Context, orgID, metricName string, startTime, endTime time.Time) ([]*models.Metric, error)
	GetThroughputMetrics(ctx context.Context, orgID string, startTime, endTime time.Time) (*models.ThroughputMetrics, error)
	GetSystemMetrics(ctx context.Context) (*models.SystemMetrics, error)
	GetOrganisationMetrics(ctx context.Context, orgID string) (map[string]interface{}, error)

	// Logs
	GetRecentLogs(ctx context.Context, orgID string, limit int) ([]*models.RequestLog, error)
	GetLogsByOrganisation(ctx context.Context, orgID string, limit, offset int) ([]*models.RequestLog, error)
	GetErrorLogs(ctx context.Context, orgID string, limit, offset int) ([]*models.RequestLog, error)
	GetSystemLogs(ctx context.Context, limit, offset int) ([]*models.RequestLog, error)

	// Health checks
	PerformHealthCheck(ctx context.Context, component string) (*models.HealthCheck, error)
	GetHealthStatus(ctx context.Context) (map[string]*models.HealthCheck, error)
	GetSystemHealth(ctx context.Context) (map[string]interface{}, error)
	RegisterHealthCheck(component string, checkFunc func(ctx context.Context) (*models.HealthCheck, error))

	// Alerting
	CreateAlert(ctx context.Context, alert *models.Alert) error
	EvaluateAlerts(ctx context.Context) error
	GetActiveAlerts(ctx context.Context, orgID string) ([]*models.Alert, error)

	// System monitoring
	CollectSystemMetrics(ctx context.Context) error
	StartMetricsCollection(ctx context.Context) error
	StopMetricsCollection() error
}
