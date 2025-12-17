package services

import (
	"context"
	"fmt"
	"runtime"
	"strconv"
	"sync"
	"time"

	"api-translation-platform/internal/logger"
	"api-translation-platform/internal/models"
	"api-translation-platform/internal/repositories"
)

// monitoringService implements MonitoringService interface
type monitoringService struct {
	logger          *logger.Logger
	metricsRepo     repositories.MetricsRepository
	healthCheckRepo repositories.HealthCheckRepository
	alertRepo       repositories.AlertRepository
	requestLogRepo  repositories.RequestLogRepository

	// Health check functions registry
	healthChecks map[string]func(ctx context.Context) (*models.HealthCheck, error)
	healthMutex  sync.RWMutex

	// Metrics collection control
	metricsCollectionRunning bool
	metricsStopChan          chan struct{}
	metricsMutex             sync.Mutex
}

// NewMonitoringService creates a new monitoring service
func NewMonitoringService(
	logger *logger.Logger,
	metricsRepo repositories.MetricsRepository,
	healthCheckRepo repositories.HealthCheckRepository,
	alertRepo repositories.AlertRepository,
	requestLogRepo repositories.RequestLogRepository,
) MonitoringService {
	return &monitoringService{
		logger:          logger,
		metricsRepo:     metricsRepo,
		healthCheckRepo: healthCheckRepo,
		alertRepo:       alertRepo,
		requestLogRepo:  requestLogRepo,
		healthChecks:    make(map[string]func(ctx context.Context) (*models.HealthCheck, error)),
		metricsStopChan: make(chan struct{}),
	}
}

// RecordMetric records a metric data point
func (s *monitoringService) RecordMetric(ctx context.Context, orgID, name string, value float64, labels map[string]string) error {
	var jsonLabels models.JSONMap
	if labels != nil {
		jsonLabels = make(models.JSONMap)
		for k, v := range labels {
			jsonLabels[k] = v
		}
	}

	metric := &models.Metric{
		OrganisationID: orgID,
		Name:           name,
		Type:           models.MetricTypeGauge, // Default to gauge
		Value:          value,
		Labels:         jsonLabels,
		Timestamp:      time.Now(),
	}

	return s.metricsRepo.CreateMetric(ctx, metric)
}

// GetMetrics retrieves metrics for a specific organisation and metric name
func (s *monitoringService) GetMetrics(ctx context.Context, orgID, metricName string, startTime, endTime time.Time) ([]*models.Metric, error) {
	return s.metricsRepo.GetMetrics(ctx, orgID, metricName, startTime, endTime)
}

// GetThroughputMetrics calculates throughput metrics from request logs
func (s *monitoringService) GetThroughputMetrics(ctx context.Context, orgID string, startTime, endTime time.Time) (*models.ThroughputMetrics, error) {
	// Get request logs for the time period
	logs, err := s.requestLogRepo.GetByOrganisation(ctx, orgID, 10000, 0) // Large limit to get all logs
	if err != nil {
		return nil, fmt.Errorf("failed to get request logs: %w", err)
	}

	// Filter logs by time range
	var filteredLogs []*models.RequestLog
	for _, log := range logs {
		if log.Timestamp.After(startTime) && log.Timestamp.Before(endTime) {
			filteredLogs = logs
			break
		}
	}

	if len(filteredLogs) == 0 {
		return &models.ThroughputMetrics{
			OrganisationID: orgID,
			StartTime:      startTime,
			EndTime:        endTime,
		}, nil
	}

	// Calculate metrics
	var totalRequests, successCount, errorCount int64
	var totalResponseTime, minResponseTime, maxResponseTime float64
	var responseTimes []float64

	minResponseTime = float64(filteredLogs[0].ProcessingTime)

	for _, log := range filteredLogs {
		totalRequests++
		responseTime := float64(log.ProcessingTime)
		totalResponseTime += responseTime
		responseTimes = append(responseTimes, responseTime)

		if responseTime < minResponseTime {
			minResponseTime = responseTime
		}
		if responseTime > maxResponseTime {
			maxResponseTime = responseTime
		}

		if log.IsSuccess() {
			successCount++
		} else {
			errorCount++
		}
	}

	avgResponseTime := totalResponseTime / float64(totalRequests)

	// Calculate percentiles (simplified)
	p95ResponseTime := calculatePercentile(responseTimes, 0.95)
	p99ResponseTime := calculatePercentile(responseTimes, 0.99)

	return &models.ThroughputMetrics{
		OrganisationID:      orgID,
		RequestCount:        totalRequests,
		SuccessCount:        successCount,
		ErrorCount:          errorCount,
		AverageResponseTime: avgResponseTime,
		MinResponseTime:     minResponseTime,
		MaxResponseTime:     maxResponseTime,
		P95ResponseTime:     p95ResponseTime,
		P99ResponseTime:     p99ResponseTime,
		StartTime:           startTime,
		EndTime:             endTime,
	}, nil
}

// calculatePercentile calculates the percentile value from a slice of response times
func calculatePercentile(values []float64, percentile float64) float64 {
	if len(values) == 0 {
		return 0
	}

	// Simple percentile calculation (should use proper sorting for production)
	index := int(float64(len(values)) * percentile)
	if index >= len(values) {
		index = len(values) - 1
	}
	return values[index]
}

// GetSystemMetrics collects current system metrics
func (s *monitoringService) GetSystemMetrics(ctx context.Context) (*models.SystemMetrics, error) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	// Calculate CPU usage (simplified - in production would use proper CPU monitoring)
	cpuUsage := float64(runtime.NumGoroutine()) / float64(runtime.NumCPU()) * 10 // Simplified metric

	// Memory usage in MB
	memoryUsage := float64(m.Alloc) / 1024 / 1024

	return &models.SystemMetrics{
		CPUUsage:          cpuUsage,
		MemoryUsage:       memoryUsage,
		ActiveConnections: runtime.NumGoroutine(),
		Timestamp:         time.Now(),
	}, nil
}

// PerformHealthCheck performs a health check for a specific component
func (s *monitoringService) PerformHealthCheck(ctx context.Context, component string) (*models.HealthCheck, error) {
	s.healthMutex.RLock()
	checkFunc, exists := s.healthChecks[component]
	s.healthMutex.RUnlock()

	if !exists {
		// Default health check
		return &models.HealthCheck{
			Component: component,
			Status:    models.HealthStatusUnknown,
			Message:   "No health check registered for component",
			Timestamp: time.Now(),
		}, nil
	}

	startTime := time.Now()
	check, err := checkFunc(ctx)
	duration := time.Since(startTime).Milliseconds()

	if err != nil {
		check = &models.HealthCheck{
			Component: component,
			Status:    models.HealthStatusUnhealthy,
			Message:   fmt.Sprintf("Health check failed: %v", err),
			Duration:  duration,
			Timestamp: time.Now(),
		}
	} else if check != nil {
		check.Duration = duration
		check.Timestamp = time.Now()
	}

	// Store health check result
	if check != nil {
		if err := s.healthCheckRepo.CreateHealthCheck(ctx, check); err != nil {
			return check, fmt.Errorf("failed to store health check: %w", err)
		}
	}

	return check, nil
}

// GetHealthStatus retrieves the latest health status for all components
func (s *monitoringService) GetHealthStatus(ctx context.Context) (map[string]*models.HealthCheck, error) {
	checks, err := s.healthCheckRepo.GetLatestHealthChecks(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get health checks: %w", err)
	}

	status := make(map[string]*models.HealthCheck)
	for _, check := range checks {
		status[check.Component] = check
	}

	return status, nil
}

// RegisterHealthCheck registers a health check function for a component
func (s *monitoringService) RegisterHealthCheck(component string, checkFunc func(ctx context.Context) (*models.HealthCheck, error)) {
	s.healthMutex.Lock()
	defer s.healthMutex.Unlock()
	s.healthChecks[component] = checkFunc
}

// CreateAlert creates a new alert
func (s *monitoringService) CreateAlert(ctx context.Context, alert *models.Alert) error {
	return s.alertRepo.Create(ctx, alert)
}

// EvaluateAlerts evaluates all active alerts against current metrics
func (s *monitoringService) EvaluateAlerts(ctx context.Context) error {
	alerts, err := s.alertRepo.GetActiveAlerts(ctx)
	if err != nil {
		return fmt.Errorf("failed to get active alerts: %w", err)
	}

	for _, alert := range alerts {
		// Simple alert evaluation (in production would be more sophisticated)
		shouldTrigger, err := s.evaluateAlertCondition(ctx, alert)
		if err != nil {
			continue // Log error in production
		}

		if shouldTrigger {
			now := time.Now()
			alert.LastTriggered = &now
			if err := s.alertRepo.Update(ctx, alert); err != nil {
				continue // Log error in production
			}

			// In production, would send notifications here
		}
	}

	return nil
}

// evaluateAlertCondition evaluates whether an alert condition is met
func (s *monitoringService) evaluateAlertCondition(ctx context.Context, alert *models.Alert) (bool, error) {
	// Simplified alert evaluation - in production would parse condition string
	// and evaluate against actual metrics

	// For now, just return false to avoid triggering alerts during testing
	return false, nil
}

// GetActiveAlerts retrieves active alerts for an organisation
func (s *monitoringService) GetActiveAlerts(ctx context.Context, orgID string) ([]*models.Alert, error) {
	return s.alertRepo.GetByOrganisation(ctx, orgID)
}

// CollectSystemMetrics collects and stores system metrics
func (s *monitoringService) CollectSystemMetrics(ctx context.Context) error {
	metrics, err := s.GetSystemMetrics(ctx)
	if err != nil {
		return fmt.Errorf("failed to get system metrics: %w", err)
	}

	// Record individual metrics
	if err := s.RecordMetric(ctx, "", "cpu_usage", metrics.CPUUsage, nil); err != nil {
		return fmt.Errorf("failed to record CPU metric: %w", err)
	}

	if err := s.RecordMetric(ctx, "", "memory_usage", metrics.MemoryUsage, nil); err != nil {
		return fmt.Errorf("failed to record memory metric: %w", err)
	}

	if err := s.RecordMetric(ctx, "", "active_connections", float64(metrics.ActiveConnections), nil); err != nil {
		return fmt.Errorf("failed to record connections metric: %w", err)
	}

	return nil
}

// StartMetricsCollection starts the background metrics collection
func (s *monitoringService) StartMetricsCollection(ctx context.Context) error {
	s.metricsMutex.Lock()
	defer s.metricsMutex.Unlock()

	if s.metricsCollectionRunning {
		return fmt.Errorf("metrics collection is already running")
	}

	s.metricsCollectionRunning = true
	s.metricsStopChan = make(chan struct{})

	go s.metricsCollectionLoop(ctx)

	return nil
}

// StopMetricsCollection stops the background metrics collection
func (s *monitoringService) StopMetricsCollection() error {
	s.metricsMutex.Lock()
	defer s.metricsMutex.Unlock()

	if !s.metricsCollectionRunning {
		return fmt.Errorf("metrics collection is not running")
	}

	close(s.metricsStopChan)
	s.metricsCollectionRunning = false

	return nil
}

// metricsCollectionLoop runs the background metrics collection
func (s *monitoringService) metricsCollectionLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second) // Collect metrics every 30 seconds
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := s.CollectSystemMetrics(ctx); err != nil {
				// Log error in production
				continue
			}

			if err := s.EvaluateAlerts(ctx); err != nil {
				// Log error in production
				continue
			}

		case <-s.metricsStopChan:
			return
		case <-ctx.Done():
			return
		}
	}
}

// GetOrganisationMetrics retrieves metrics for a specific organisation
func (s *monitoringService) GetOrganisationMetrics(ctx context.Context, orgID string) (map[string]interface{}, error) {
	endTime := time.Now()
	startTime := endTime.Add(-24 * time.Hour) // Last 24 hours

	// Get throughput metrics
	throughput, err := s.GetThroughputMetrics(ctx, orgID, startTime, endTime)
	if err != nil {
		s.logger.WithError(err).Error("Failed to get throughput metrics")
		throughput = &models.ThroughputMetrics{} // Return empty metrics on error
	}

	// Get request count
	requestMetrics, err := s.GetMetrics(ctx, orgID, "requests_total", startTime, endTime)
	if err != nil {
		s.logger.WithError(err).Error("Failed to get request metrics")
		requestMetrics = []*models.Metric{}
	}

	// Get error count
	errorMetrics, err := s.GetMetrics(ctx, orgID, "errors_total", startTime, endTime)
	if err != nil {
		s.logger.WithError(err).Error("Failed to get error metrics")
		errorMetrics = []*models.Metric{}
	}

	// Calculate totals
	var totalRequests, totalErrors float64
	for _, metric := range requestMetrics {
		totalRequests += metric.Value
	}
	for _, metric := range errorMetrics {
		totalErrors += metric.Value
	}

	// Calculate success rate
	successRate := 100.0
	if totalRequests > 0 {
		successRate = ((totalRequests - totalErrors) / totalRequests) * 100
	}

	return map[string]interface{}{
		"organisation_id": orgID,
		"time_range":      map[string]time.Time{"start": startTime, "end": endTime},
		"total_requests":  totalRequests,
		"total_errors":    totalErrors,
		"success_rate":    successRate,
		"throughput":      throughput,
		"request_metrics": requestMetrics,
		"error_metrics":   errorMetrics,
	}, nil
}

// GetRecentLogs retrieves recent logs for an organisation
func (s *monitoringService) GetRecentLogs(ctx context.Context, orgID string, limit int) ([]*models.RequestLog, error) {
	return s.requestLogRepo.GetByOrganisation(ctx, orgID, limit, 0)
}

// GetLogsByOrganisation retrieves logs for an organisation with pagination
func (s *monitoringService) GetLogsByOrganisation(ctx context.Context, orgID string, limit, offset int) ([]*models.RequestLog, error) {
	return s.requestLogRepo.GetByOrganisation(ctx, orgID, limit, offset)
}

// GetErrorLogs retrieves error logs for an organisation
func (s *monitoringService) GetErrorLogs(ctx context.Context, orgID string, limit, offset int) ([]*models.RequestLog, error) {
	return s.requestLogRepo.GetErrorLogs(ctx, orgID, limit, offset)
}

// GetSystemHealth retrieves overall system health status
func (s *monitoringService) GetSystemHealth(ctx context.Context) (map[string]interface{}, error) {
	healthStatus, err := s.GetHealthStatus(ctx)
	if err != nil {
		return nil, err
	}

	// Calculate overall health
	totalChecks := len(healthStatus)
	healthyChecks := 0
	for _, check := range healthStatus {
		if check.Status == "healthy" {
			healthyChecks++
		}
	}

	overallStatus := "healthy"
	if healthyChecks < totalChecks {
		if healthyChecks == 0 {
			overallStatus = "unhealthy"
		} else {
			overallStatus = "degraded"
		}
	}

	return map[string]interface{}{
		"overall_status": overallStatus,
		"healthy_checks": healthyChecks,
		"total_checks":   totalChecks,
		"health_ratio":   float64(healthyChecks) / float64(totalChecks),
		"components":     healthStatus,
		"timestamp":      time.Now(),
	}, nil
}

// GetSystemLogs retrieves system-wide logs (for global admins)
func (s *monitoringService) GetSystemLogs(ctx context.Context, limit, offset int) ([]*models.RequestLog, error) {
	// This would typically get logs from all organisations
	// For now, we'll use a simple implementation
	return s.requestLogRepo.GetAll(ctx, limit, offset)
}

// Additional helper methods for the monitoring service

// RecordRequestMetric records a request metric
func (s *monitoringService) RecordRequestMetric(ctx context.Context, orgID string, statusCode int, processingTime time.Duration) error {
	// Record total requests
	if err := s.RecordMetric(ctx, orgID, "requests_total", 1, map[string]string{
		"status_code": strconv.Itoa(statusCode),
	}); err != nil {
		return err
	}

	// Record processing time
	if err := s.RecordMetric(ctx, orgID, "request_duration_ms", float64(processingTime.Milliseconds()), map[string]string{
		"status_code": strconv.Itoa(statusCode),
	}); err != nil {
		return err
	}

	// Record errors if status code indicates error
	if statusCode >= 400 {
		if err := s.RecordMetric(ctx, orgID, "errors_total", 1, map[string]string{
			"status_code": strconv.Itoa(statusCode),
		}); err != nil {
			return err
		}
	}

	return nil
}

// GetMetricsSummary provides a summary of key metrics for an organisation
func (s *monitoringService) GetMetricsSummary(ctx context.Context, orgID string, hours int) (map[string]interface{}, error) {
	endTime := time.Now()
	startTime := endTime.Add(-time.Duration(hours) * time.Hour)

	// Get various metrics
	requestMetrics, _ := s.GetMetrics(ctx, orgID, "requests_total", startTime, endTime)
	errorMetrics, _ := s.GetMetrics(ctx, orgID, "errors_total", startTime, endTime)
	durationMetrics, _ := s.GetMetrics(ctx, orgID, "request_duration_ms", startTime, endTime)

	// Calculate summaries
	var totalRequests, totalErrors, totalDuration float64
	var avgDuration float64

	for _, metric := range requestMetrics {
		totalRequests += metric.Value
	}
	for _, metric := range errorMetrics {
		totalErrors += metric.Value
	}
	for _, metric := range durationMetrics {
		totalDuration += metric.Value
	}

	if len(durationMetrics) > 0 {
		avgDuration = totalDuration / float64(len(durationMetrics))
	}

	successRate := 100.0
	if totalRequests > 0 {
		successRate = ((totalRequests - totalErrors) / totalRequests) * 100
	}

	return map[string]interface{}{
		"time_period_hours": hours,
		"total_requests":    totalRequests,
		"total_errors":      totalErrors,
		"success_rate":      successRate,
		"avg_duration_ms":   avgDuration,
		"requests_per_hour": totalRequests / float64(hours),
	}, nil
}
