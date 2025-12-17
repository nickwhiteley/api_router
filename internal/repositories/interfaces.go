package repositories

import (
	"context"
	"time"

	"api-translation-platform/internal/models"
)

// OrganisationRepository defines the interface for organisation data operations
type OrganisationRepository interface {
	Create(ctx context.Context, org *models.Organisation) error
	GetByID(ctx context.Context, id string) (*models.Organisation, error)
	GetAll(ctx context.Context) ([]*models.Organisation, error)
	Update(ctx context.Context, org *models.Organisation) error
	Delete(ctx context.Context, id string) error
}

// UserRepository defines the interface for user data operations
type UserRepository interface {
	Create(ctx context.Context, user *models.User) error
	GetByID(ctx context.Context, id string) (*models.User, error)
	GetByUsername(ctx context.Context, username string) (*models.User, error)
	GetByEmail(ctx context.Context, email string) (*models.User, error)
	GetByUsernameAndOrganisation(ctx context.Context, username, orgID string) (*models.User, error)
	GetByOrganisation(ctx context.Context, orgID string) ([]*models.User, error)
	GetByOrganisationID(ctx context.Context, orgID string) ([]*models.User, error)
	GetAll(ctx context.Context) ([]*models.User, error)
	Update(ctx context.Context, user *models.User) error
	Delete(ctx context.Context, id string) error
}

// APIConfigurationRepository defines the interface for API configuration data operations
type APIConfigurationRepository interface {
	Create(ctx context.Context, config *models.APIConfiguration) error
	GetByID(ctx context.Context, id string) (*models.APIConfiguration, error)
	GetByOrganisation(ctx context.Context, orgID string) ([]*models.APIConfiguration, error)
	GetInboundByOrganisation(ctx context.Context, orgID string) ([]*models.APIConfiguration, error)
	GetOutboundByOrganisation(ctx context.Context, orgID string) ([]*models.APIConfiguration, error)
	Update(ctx context.Context, config *models.APIConfiguration) error
	Delete(ctx context.Context, id string) error
}

// ConnectorRepository defines the interface for connector data operations
type ConnectorRepository interface {
	Create(ctx context.Context, connector *models.Connector) error
	GetByID(ctx context.Context, id string) (*models.Connector, error)
	GetByOrganisation(ctx context.Context, orgID string) ([]*models.Connector, error)
	GetByInboundAPI(ctx context.Context, apiID string) ([]*models.Connector, error)
	Update(ctx context.Context, connector *models.Connector) error
	Delete(ctx context.Context, id string) error
}

// RequestLogRepository defines the interface for request log data operations
type RequestLogRepository interface {
	Create(ctx context.Context, log *models.RequestLog) error
	GetByID(ctx context.Context, id string) (*models.RequestLog, error)
	GetByOrganisation(ctx context.Context, orgID string, limit, offset int) ([]*models.RequestLog, error)
	GetByConnector(ctx context.Context, connectorID string, limit, offset int) ([]*models.RequestLog, error)
	GetErrorLogs(ctx context.Context, orgID string, limit, offset int) ([]*models.RequestLog, error)
	GetAll(ctx context.Context, limit, offset int) ([]*models.RequestLog, error)
	Delete(ctx context.Context, id string) error
}

// AuditLogRepository defines the interface for audit log data operations
type AuditLogRepository interface {
	Create(ctx context.Context, log *models.AuditLog) error
	GetByID(ctx context.Context, id string) (*models.AuditLog, error)
	GetByOrganisation(ctx context.Context, orgID string, limit, offset int) ([]*models.AuditLog, error)
	GetByResource(ctx context.Context, resourceType, resourceID string, limit, offset int) ([]*models.AuditLog, error)
	GetByUser(ctx context.Context, userID string, limit, offset int) ([]*models.AuditLog, error)
}

// ConfigurationVersionRepository defines the interface for configuration version data operations
type ConfigurationVersionRepository interface {
	Create(ctx context.Context, version *models.ConfigurationVersion) error
	GetByID(ctx context.Context, id string) (*models.ConfigurationVersion, error)
	GetByResource(ctx context.Context, resourceType, resourceID string) ([]*models.ConfigurationVersion, error)
	GetActiveVersion(ctx context.Context, resourceType, resourceID string) (*models.ConfigurationVersion, error)
	GetVersionByNumber(ctx context.Context, resourceType, resourceID string, version int) (*models.ConfigurationVersion, error)
	SetActiveVersion(ctx context.Context, versionID string) error
	GetLatestVersion(ctx context.Context, resourceType, resourceID string) (*models.ConfigurationVersion, error)
}

// MetricsRepository defines the interface for metrics data operations
type MetricsRepository interface {
	CreateMetric(ctx context.Context, metric *models.Metric) error
	GetMetrics(ctx context.Context, orgID string, metricName string, startTime, endTime time.Time) ([]*models.Metric, error)
	GetMetricsByLabels(ctx context.Context, orgID string, labels map[string]string, startTime, endTime time.Time) ([]*models.Metric, error)
	DeleteOldMetrics(ctx context.Context, before time.Time) error
	GetAggregatedMetrics(ctx context.Context, orgID string, metricName string, startTime, endTime time.Time, interval string) (map[time.Time]float64, error)
}

// HealthCheckRepository defines the interface for health check data operations
type HealthCheckRepository interface {
	CreateHealthCheck(ctx context.Context, check *models.HealthCheck) error
	GetLatestHealthChecks(ctx context.Context) ([]*models.HealthCheck, error)
	GetHealthChecksByComponent(ctx context.Context, component string, limit int) ([]*models.HealthCheck, error)
	DeleteOldHealthChecks(ctx context.Context, before time.Time) error
}

// AlertRepository defines the interface for alert data operations
type AlertRepository interface {
	Create(ctx context.Context, alert *models.Alert) error
	GetByID(ctx context.Context, id string) (*models.Alert, error)
	GetByOrganisation(ctx context.Context, orgID string) ([]*models.Alert, error)
	GetActiveAlerts(ctx context.Context) ([]*models.Alert, error)
	Update(ctx context.Context, alert *models.Alert) error
	Delete(ctx context.Context, id string) error
}
