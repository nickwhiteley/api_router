package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"api-translation-platform/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockMonitoringService is a mock implementation of MonitoringService
type MockMonitoringService struct {
	mock.Mock
}

func (m *MockMonitoringService) RecordMetric(ctx context.Context, orgID, name string, value float64, labels map[string]string) error {
	args := m.Called(ctx, orgID, name, value, labels)
	return args.Error(0)
}

func (m *MockMonitoringService) GetMetrics(ctx context.Context, orgID, metricName string, startTime, endTime time.Time) ([]*models.Metric, error) {
	args := m.Called(ctx, orgID, metricName, startTime, endTime)
	return args.Get(0).([]*models.Metric), args.Error(1)
}

func (m *MockMonitoringService) GetThroughputMetrics(ctx context.Context, orgID string, startTime, endTime time.Time) (*models.ThroughputMetrics, error) {
	args := m.Called(ctx, orgID, startTime, endTime)
	return args.Get(0).(*models.ThroughputMetrics), args.Error(1)
}

func (m *MockMonitoringService) GetSystemMetrics(ctx context.Context) (*models.SystemMetrics, error) {
	args := m.Called(ctx)
	return args.Get(0).(*models.SystemMetrics), args.Error(1)
}

func (m *MockMonitoringService) PerformHealthCheck(ctx context.Context, component string) (*models.HealthCheck, error) {
	args := m.Called(ctx, component)
	return args.Get(0).(*models.HealthCheck), args.Error(1)
}

func (m *MockMonitoringService) GetHealthStatus(ctx context.Context) (map[string]*models.HealthCheck, error) {
	args := m.Called(ctx)
	return args.Get(0).(map[string]*models.HealthCheck), args.Error(1)
}

func (m *MockMonitoringService) RegisterHealthCheck(component string, checkFunc func(ctx context.Context) (*models.HealthCheck, error)) {
	m.Called(component, checkFunc)
}

func (m *MockMonitoringService) CreateAlert(ctx context.Context, alert *models.Alert) error {
	args := m.Called(ctx, alert)
	return args.Error(0)
}

func (m *MockMonitoringService) EvaluateAlerts(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockMonitoringService) GetActiveAlerts(ctx context.Context, orgID string) ([]*models.Alert, error) {
	args := m.Called(ctx, orgID)
	return args.Get(0).([]*models.Alert), args.Error(1)
}

func (m *MockMonitoringService) CollectSystemMetrics(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockMonitoringService) StartMetricsCollection(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockMonitoringService) StopMetricsCollection() error {
	args := m.Called()
	return args.Error(0)
}

// Test health check endpoint responses
func TestHealthHandler_HandleHealthCheck_AllHealthy(t *testing.T) {
	// Setup
	mockService := &MockMonitoringService{}
	handler := NewHealthHandler(mockService)

	// Mock healthy components
	healthyComponents := map[string]*models.HealthCheck{
		"database": {
			Component: "database",
			Status:    models.HealthStatusHealthy,
			Message:   "Database is healthy",
			Timestamp: time.Now(),
		},
		"api_gateway": {
			Component: "api_gateway",
			Status:    models.HealthStatusHealthy,
			Message:   "API Gateway is healthy",
			Timestamp: time.Now(),
		},
	}

	mockService.On("GetHealthStatus", mock.Anything).Return(healthyComponents, nil)

	// Create request
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	// Execute
	handler.HandleHealthCheck(w, req)

	// Assertions
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var response HealthResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "healthy", response.Status)
	assert.Len(t, response.Components, 2)
	assert.Equal(t, models.HealthStatusHealthy, response.Components["database"].Status)
	assert.Equal(t, models.HealthStatusHealthy, response.Components["api_gateway"].Status)

	mockService.AssertExpectations(t)
}

func TestHealthHandler_HandleHealthCheck_SomeUnhealthy(t *testing.T) {
	// Setup
	mockService := &MockMonitoringService{}
	handler := NewHealthHandler(mockService)

	// Mock mixed health components
	mixedComponents := map[string]*models.HealthCheck{
		"database": {
			Component: "database",
			Status:    models.HealthStatusHealthy,
			Message:   "Database is healthy",
			Timestamp: time.Now(),
		},
		"api_gateway": {
			Component: "api_gateway",
			Status:    models.HealthStatusUnhealthy,
			Message:   "API Gateway is down",
			Timestamp: time.Now(),
		},
	}

	mockService.On("GetHealthStatus", mock.Anything).Return(mixedComponents, nil)

	// Create request
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	// Execute
	handler.HandleHealthCheck(w, req)

	// Assertions
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var response HealthResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "unhealthy", response.Status)
	assert.Len(t, response.Components, 2)

	mockService.AssertExpectations(t)
}

func TestHealthHandler_HandleHealthCheck_WithSystemMetrics(t *testing.T) {
	// Setup
	mockService := &MockMonitoringService{}
	handler := NewHealthHandler(mockService)

	healthyComponents := map[string]*models.HealthCheck{
		"database": {
			Component: "database",
			Status:    models.HealthStatusHealthy,
			Message:   "Database is healthy",
			Timestamp: time.Now(),
		},
	}

	systemMetrics := &models.SystemMetrics{
		CPUUsage:          25.5,
		MemoryUsage:       512.0,
		ActiveConnections: 10,
		Timestamp:         time.Now(),
	}

	mockService.On("GetHealthStatus", mock.Anything).Return(healthyComponents, nil)
	mockService.On("GetSystemMetrics", mock.Anything).Return(systemMetrics, nil)

	// Create request with include_system parameter
	req := httptest.NewRequest("GET", "/health?include_system=true", nil)
	w := httptest.NewRecorder()

	// Execute
	handler.HandleHealthCheck(w, req)

	// Assertions
	assert.Equal(t, http.StatusOK, w.Code)

	var response HealthResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "healthy", response.Status)
	assert.NotNil(t, response.System)
	assert.Equal(t, 25.5, response.System.CPUUsage)
	assert.Equal(t, 512.0, response.System.MemoryUsage)
	assert.Equal(t, 10, response.System.ActiveConnections)

	mockService.AssertExpectations(t)
}

// Test liveness probe endpoint
func TestHealthHandler_HandleLivenessProbe(t *testing.T) {
	// Setup
	mockService := &MockMonitoringService{}
	handler := NewHealthHandler(mockService)

	// Create request
	req := httptest.NewRequest("GET", "/health/live", nil)
	w := httptest.NewRecorder()

	// Execute
	handler.HandleLivenessProbe(w, req)

	// Assertions
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "OK", w.Body.String())
}

// Test readiness probe endpoint
func TestHealthHandler_HandleReadinessProbe_Ready(t *testing.T) {
	// Setup
	mockService := &MockMonitoringService{}
	handler := NewHealthHandler(mockService)

	// Mock healthy critical components
	healthyComponents := map[string]*models.HealthCheck{
		"database": {
			Component: "database",
			Status:    models.HealthStatusHealthy,
			Message:   "Database is healthy",
			Timestamp: time.Now(),
		},
		"configuration": {
			Component: "configuration",
			Status:    models.HealthStatusHealthy,
			Message:   "Configuration service is healthy",
			Timestamp: time.Now(),
		},
	}

	mockService.On("GetHealthStatus", mock.Anything).Return(healthyComponents, nil)

	// Create request
	req := httptest.NewRequest("GET", "/health/ready", nil)
	w := httptest.NewRecorder()

	// Execute
	handler.HandleReadinessProbe(w, req)

	// Assertions
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "Ready", w.Body.String())

	mockService.AssertExpectations(t)
}

func TestHealthHandler_HandleReadinessProbe_NotReady(t *testing.T) {
	// Setup
	mockService := &MockMonitoringService{}
	handler := NewHealthHandler(mockService)

	// Mock unhealthy critical component
	unhealthyComponents := map[string]*models.HealthCheck{
		"database": {
			Component: "database",
			Status:    models.HealthStatusUnhealthy,
			Message:   "Database connection failed",
			Timestamp: time.Now(),
		},
		"configuration": {
			Component: "configuration",
			Status:    models.HealthStatusHealthy,
			Message:   "Configuration service is healthy",
			Timestamp: time.Now(),
		},
	}

	mockService.On("GetHealthStatus", mock.Anything).Return(unhealthyComponents, nil)

	// Create request
	req := httptest.NewRequest("GET", "/health/ready", nil)
	w := httptest.NewRecorder()

	// Execute
	handler.HandleReadinessProbe(w, req)

	// Assertions
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.Equal(t, "Service Unavailable", w.Body.String())

	mockService.AssertExpectations(t)
}

// Test component-specific health check
func TestHealthHandler_HandleComponentHealth_ValidComponent(t *testing.T) {
	// Setup
	mockService := &MockMonitoringService{}
	handler := NewHealthHandler(mockService)

	healthCheck := &models.HealthCheck{
		Component: "database",
		Status:    models.HealthStatusHealthy,
		Message:   "Database is healthy",
		Duration:  50,
		Timestamp: time.Now(),
	}

	mockService.On("PerformHealthCheck", mock.Anything, "database").Return(healthCheck, nil)

	// Create request
	req := httptest.NewRequest("GET", "/health/component?component=database", nil)
	w := httptest.NewRecorder()

	// Execute
	handler.HandleComponentHealth(w, req)

	// Assertions
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var response models.HealthCheck
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "database", response.Component)
	assert.Equal(t, models.HealthStatusHealthy, response.Status)
	assert.Equal(t, "Database is healthy", response.Message)
	assert.Equal(t, int64(50), response.Duration)

	mockService.AssertExpectations(t)
}

func TestHealthHandler_HandleComponentHealth_UnhealthyComponent(t *testing.T) {
	// Setup
	mockService := &MockMonitoringService{}
	handler := NewHealthHandler(mockService)

	healthCheck := &models.HealthCheck{
		Component: "database",
		Status:    models.HealthStatusUnhealthy,
		Message:   "Database connection failed",
		Duration:  100,
		Timestamp: time.Now(),
	}

	mockService.On("PerformHealthCheck", mock.Anything, "database").Return(healthCheck, nil)

	// Create request
	req := httptest.NewRequest("GET", "/health/component?component=database", nil)
	w := httptest.NewRecorder()

	// Execute
	handler.HandleComponentHealth(w, req)

	// Assertions
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var response models.HealthCheck
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "database", response.Component)
	assert.Equal(t, models.HealthStatusUnhealthy, response.Status)

	mockService.AssertExpectations(t)
}

func TestHealthHandler_HandleComponentHealth_MissingComponent(t *testing.T) {
	// Setup
	mockService := &MockMonitoringService{}
	handler := NewHealthHandler(mockService)

	// Create request without component parameter
	req := httptest.NewRequest("GET", "/health/component", nil)
	w := httptest.NewRecorder()

	// Execute
	handler.HandleComponentHealth(w, req)

	// Assertions
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "Component parameter is required")
}

// Verify health status reporting accuracy
func TestHealthHandler_HealthStatusReportingAccuracy(t *testing.T) {
	// Setup
	mockService := &MockMonitoringService{}
	handler := NewHealthHandler(mockService)

	// Test case 1: All components healthy should report "healthy"
	allHealthy := map[string]*models.HealthCheck{
		"database":    {Status: models.HealthStatusHealthy},
		"api_gateway": {Status: models.HealthStatusHealthy},
		"config":      {Status: models.HealthStatusHealthy},
	}

	mockService.On("GetHealthStatus", mock.Anything).Return(allHealthy, nil).Once()

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	handler.HandleHealthCheck(w, req)

	var response HealthResponse
	json.Unmarshal(w.Body.Bytes(), &response)
	assert.Equal(t, "healthy", response.Status)
	assert.Equal(t, http.StatusOK, w.Code)

	// Test case 2: Any component unhealthy should report "unhealthy"
	someUnhealthy := map[string]*models.HealthCheck{
		"database":    {Status: models.HealthStatusHealthy},
		"api_gateway": {Status: models.HealthStatusUnhealthy},
		"config":      {Status: models.HealthStatusHealthy},
	}

	mockService.On("GetHealthStatus", mock.Anything).Return(someUnhealthy, nil).Once()

	req2 := httptest.NewRequest("GET", "/health", nil)
	w2 := httptest.NewRecorder()
	handler.HandleHealthCheck(w2, req2)

	var response2 HealthResponse
	json.Unmarshal(w2.Body.Bytes(), &response2)
	assert.Equal(t, "unhealthy", response2.Status)
	assert.Equal(t, http.StatusServiceUnavailable, w2.Code)

	// Test case 3: Degraded components should report "unhealthy"
	degradedComponents := map[string]*models.HealthCheck{
		"database": {Status: models.HealthStatusDegraded},
		"config":   {Status: models.HealthStatusHealthy},
	}

	mockService.On("GetHealthStatus", mock.Anything).Return(degradedComponents, nil).Once()

	req3 := httptest.NewRequest("GET", "/health", nil)
	w3 := httptest.NewRecorder()
	handler.HandleHealthCheck(w3, req3)

	var response3 HealthResponse
	json.Unmarshal(w3.Body.Bytes(), &response3)
	assert.Equal(t, "unhealthy", response3.Status)
	assert.Equal(t, http.StatusServiceUnavailable, w3.Code)

	mockService.AssertExpectations(t)
}
