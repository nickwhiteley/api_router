package repositories

import (
	"context"
	"fmt"
	"time"

	"api-translation-platform/internal/models"
	"gorm.io/gorm"
)

// metricsRepository implements MetricsRepository interface
type metricsRepository struct {
	db *gorm.DB
}

// NewMetricsRepository creates a new metrics repository
func NewMetricsRepository(db *gorm.DB) MetricsRepository {
	return &metricsRepository{db: db}
}

// CreateMetric creates a new metric record
func (r *metricsRepository) CreateMetric(ctx context.Context, metric *models.Metric) error {
	return r.db.WithContext(ctx).Create(metric).Error
}

// GetMetrics retrieves metrics for a specific organisation and metric name within a time range
func (r *metricsRepository) GetMetrics(ctx context.Context, orgID string, metricName string, startTime, endTime time.Time) ([]*models.Metric, error) {
	var metrics []*models.Metric
	query := r.db.WithContext(ctx).Where("timestamp BETWEEN ? AND ?", startTime, endTime)

	if orgID != "" {
		query = query.Where("organisation_id = ?", orgID)
	}

	if metricName != "" {
		query = query.Where("name = ?", metricName)
	}

	err := query.Order("timestamp ASC").Find(&metrics).Error
	return metrics, err
}

// GetMetricsByLabels retrieves metrics filtered by labels
func (r *metricsRepository) GetMetricsByLabels(ctx context.Context, orgID string, labels map[string]string, startTime, endTime time.Time) ([]*models.Metric, error) {
	var metrics []*models.Metric
	query := r.db.WithContext(ctx).Where("timestamp BETWEEN ? AND ?", startTime, endTime)

	if orgID != "" {
		query = query.Where("organisation_id = ?", orgID)
	}

	// Filter by labels using JSONB queries
	for key, value := range labels {
		query = query.Where("labels ->> ? = ?", key, value)
	}

	err := query.Order("timestamp ASC").Find(&metrics).Error
	return metrics, err
}

// DeleteOldMetrics deletes metrics older than the specified time
func (r *metricsRepository) DeleteOldMetrics(ctx context.Context, before time.Time) error {
	return r.db.WithContext(ctx).Where("timestamp < ?", before).Delete(&models.Metric{}).Error
}

// GetAggregatedMetrics returns aggregated metrics over time intervals
func (r *metricsRepository) GetAggregatedMetrics(ctx context.Context, orgID string, metricName string, startTime, endTime time.Time, interval string) (map[time.Time]float64, error) {
	var results []struct {
		TimeInterval time.Time `json:"time_interval"`
		AvgValue     float64   `json:"avg_value"`
	}

	// Build the time truncation based on interval
	var truncateExpr string
	switch interval {
	case "minute":
		truncateExpr = "date_trunc('minute', timestamp)"
	case "hour":
		truncateExpr = "date_trunc('hour', timestamp)"
	case "day":
		truncateExpr = "date_trunc('day', timestamp)"
	default:
		return nil, fmt.Errorf("unsupported interval: %s", interval)
	}

	query := r.db.WithContext(ctx).Model(&models.Metric{}).
		Select(fmt.Sprintf("%s as time_interval, AVG(value) as avg_value", truncateExpr)).
		Where("timestamp BETWEEN ? AND ?", startTime, endTime).
		Group("time_interval").
		Order("time_interval ASC")

	if orgID != "" {
		query = query.Where("organisation_id = ?", orgID)
	}

	if metricName != "" {
		query = query.Where("name = ?", metricName)
	}

	err := query.Find(&results).Error
	if err != nil {
		return nil, err
	}

	aggregated := make(map[time.Time]float64)
	for _, result := range results {
		aggregated[result.TimeInterval] = result.AvgValue
	}

	return aggregated, nil
}

// healthCheckRepository implements HealthCheckRepository interface
type healthCheckRepository struct {
	db *gorm.DB
}

// NewHealthCheckRepository creates a new health check repository
func NewHealthCheckRepository(db *gorm.DB) HealthCheckRepository {
	return &healthCheckRepository{db: db}
}

// CreateHealthCheck creates a new health check record
func (r *healthCheckRepository) CreateHealthCheck(ctx context.Context, check *models.HealthCheck) error {
	return r.db.WithContext(ctx).Create(check).Error
}

// GetLatestHealthChecks retrieves the latest health check for each component
func (r *healthCheckRepository) GetLatestHealthChecks(ctx context.Context) ([]*models.HealthCheck, error) {
	var checks []*models.HealthCheck

	// Get the latest health check for each component
	subquery := r.db.Model(&models.HealthCheck{}).
		Select("component, MAX(timestamp) as max_timestamp").
		Group("component")

	err := r.db.WithContext(ctx).
		Joins("JOIN (?) as latest ON health_checks.component = latest.component AND health_checks.timestamp = latest.max_timestamp", subquery).
		Find(&checks).Error

	return checks, err
}

// GetHealthChecksByComponent retrieves health checks for a specific component
func (r *healthCheckRepository) GetHealthChecksByComponent(ctx context.Context, component string, limit int) ([]*models.HealthCheck, error) {
	var checks []*models.HealthCheck
	query := r.db.WithContext(ctx).Where("component = ?", component).Order("timestamp DESC")

	if limit > 0 {
		query = query.Limit(limit)
	}

	err := query.Find(&checks).Error
	return checks, err
}

// DeleteOldHealthChecks deletes health checks older than the specified time
func (r *healthCheckRepository) DeleteOldHealthChecks(ctx context.Context, before time.Time) error {
	return r.db.WithContext(ctx).Where("timestamp < ?", before).Delete(&models.HealthCheck{}).Error
}

// alertRepository implements AlertRepository interface
type alertRepository struct {
	db *gorm.DB
}

// NewAlertRepository creates a new alert repository
func NewAlertRepository(db *gorm.DB) AlertRepository {
	return &alertRepository{db: db}
}

// Create creates a new alert
func (r *alertRepository) Create(ctx context.Context, alert *models.Alert) error {
	return r.db.WithContext(ctx).Create(alert).Error
}

// GetByID retrieves an alert by ID
func (r *alertRepository) GetByID(ctx context.Context, id string) (*models.Alert, error) {
	var alert models.Alert
	err := r.db.WithContext(ctx).Where("id = ?", id).First(&alert).Error
	if err != nil {
		return nil, err
	}
	return &alert, nil
}

// GetByOrganisation retrieves alerts for a specific organisation
func (r *alertRepository) GetByOrganisation(ctx context.Context, orgID string) ([]*models.Alert, error) {
	var alerts []*models.Alert
	err := r.db.WithContext(ctx).Where("organisation_id = ? OR organisation_id IS NULL", orgID).Find(&alerts).Error
	return alerts, err
}

// GetActiveAlerts retrieves all active alerts
func (r *alertRepository) GetActiveAlerts(ctx context.Context) ([]*models.Alert, error) {
	var alerts []*models.Alert
	err := r.db.WithContext(ctx).Where("is_active = ?", true).Find(&alerts).Error
	return alerts, err
}

// Update updates an existing alert
func (r *alertRepository) Update(ctx context.Context, alert *models.Alert) error {
	return r.db.WithContext(ctx).Save(alert).Error
}

// Delete deletes an alert
func (r *alertRepository) Delete(ctx context.Context, id string) error {
	return r.db.WithContext(ctx).Where("id = ?", id).Delete(&models.Alert{}).Error
}
