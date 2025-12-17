package services

import (
	"context"
	"testing"
	"time"

	"api-translation-platform/internal/models"
	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockMetricsRepository is a mock implementation of MetricsRepository
type MockMetricsRepository struct {
	mock.Mock
}

func (m *MockMetricsRepository) CreateMetric(ctx context.Context, metric *models.Metric) error {
	args := m.Called(ctx, metric)
	return args.Error(0)
}

func (m *MockMetricsRepository) GetMetrics(ctx context.Context, orgID string, metricName string, startTime, endTime time.Time) ([]*models.Metric, error) {
	args := m.Called(ctx, orgID, metricName, startTime, endTime)
	return args.Get(0).([]*models.Metric), args.Error(1)
}

func (m *MockMetricsRepository) GetMetricsByLabels(ctx context.Context, orgID string, labels map[string]string, startTime, endTime time.Time) ([]*models.Metric, error) {
	args := m.Called(ctx, orgID, labels, startTime, endTime)
	return args.Get(0).([]*models.Metric), args.Error(1)
}

func (m *MockMetricsRepository) DeleteOldMetrics(ctx context.Context, before time.Time) error {
	args := m.Called(ctx, before)
	return args.Error(0)
}

func (m *MockMetricsRepository) GetAggregatedMetrics(ctx context.Context, orgID string, metricName string, startTime, endTime time.Time, interval string) (map[time.Time]float64, error) {
	args := m.Called(ctx, orgID, metricName, startTime, endTime, interval)
	return args.Get(0).(map[time.Time]float64), args.Error(1)
}

// MockHealthCheckRepository is a mock implementation of HealthCheckRepository
type MockHealthCheckRepository struct {
	mock.Mock
}

func (m *MockHealthCheckRepository) CreateHealthCheck(ctx context.Context, check *models.HealthCheck) error {
	args := m.Called(ctx, check)
	return args.Error(0)
}

func (m *MockHealthCheckRepository) GetLatestHealthChecks(ctx context.Context) ([]*models.HealthCheck, error) {
	args := m.Called(ctx)
	return args.Get(0).([]*models.HealthCheck), args.Error(1)
}

func (m *MockHealthCheckRepository) GetHealthChecksByComponent(ctx context.Context, component string, limit int) ([]*models.HealthCheck, error) {
	args := m.Called(ctx, component, limit)
	return args.Get(0).([]*models.HealthCheck), args.Error(1)
}

func (m *MockHealthCheckRepository) DeleteOldHealthChecks(ctx context.Context, before time.Time) error {
	args := m.Called(ctx, before)
	return args.Error(0)
}

// MockAlertRepository is a mock implementation of AlertRepository
type MockAlertRepository struct {
	mock.Mock
}

func (m *MockAlertRepository) Create(ctx context.Context, alert *models.Alert) error {
	args := m.Called(ctx, alert)
	return args.Error(0)
}

func (m *MockAlertRepository) GetByID(ctx context.Context, id string) (*models.Alert, error) {
	args := m.Called(ctx, id)
	return args.Get(0).(*models.Alert), args.Error(1)
}

func (m *MockAlertRepository) GetByOrganisation(ctx context.Context, orgID string) ([]*models.Alert, error) {
	args := m.Called(ctx, orgID)
	return args.Get(0).([]*models.Alert), args.Error(1)
}

func (m *MockAlertRepository) GetActiveAlerts(ctx context.Context) ([]*models.Alert, error) {
	args := m.Called(ctx)
	return args.Get(0).([]*models.Alert), args.Error(1)
}

func (m *MockAlertRepository) Update(ctx context.Context, alert *models.Alert) error {
	args := m.Called(ctx, alert)
	return args.Error(0)
}

func (m *MockAlertRepository) Delete(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

// Using the existing MockRequestLogRepository from authorization_test.go

// **Feature: api-translation-platform, Property 19: Metrics calculation**
// **Validates: Requirements 6.5, 8.3**
func TestProperty_MetricsCalculation(t *testing.T) {
	properties := gopter.NewProperties(nil)

	properties.Property("For any time period and organisation scope, the system should accurately calculate throughput metrics including requests per second, response times, and success rates", prop.ForAll(
		func(orgID string, requestCount int, successCount int, processingTimes []int64) bool {
			// Ensure valid input constraints
			if requestCount <= 0 || successCount < 0 || successCount > requestCount {
				return true // Skip invalid inputs
			}

			if len(processingTimes) != requestCount {
				return true // Skip mismatched data
			}

			// Create mock repositories
			mockMetricsRepo := &MockMetricsRepository{}
			mockHealthRepo := &MockHealthCheckRepository{}
			mockAlertRepo := &MockAlertRepository{}
			mockRequestLogRepo := &MockRequestLogRepository{}

			// Create test request logs
			startTime := time.Now().Add(-1 * time.Hour)
			endTime := time.Now()

			var requestLogs []*models.RequestLog
			var totalProcessingTime int64
			errorCount := requestCount - successCount

			for i := 0; i < requestCount; i++ {
				processingTime := processingTimes[i]
				if processingTime < 0 {
					processingTime = -processingTime // Ensure positive processing time
				}
				totalProcessingTime += processingTime

				statusCode := 200 // Success
				if i >= successCount {
					statusCode = 500 // Error
				}

				log := &models.RequestLog{
					ID:             "test-id",
					OrganisationID: orgID,
					ConnectorID:    "test-connector",
					RequestID:      "test-request",
					Method:         "GET",
					Path:           "/test",
					StatusCode:     statusCode,
					ProcessingTime: processingTime,
					Timestamp:      startTime.Add(time.Duration(i) * time.Minute),
				}
				requestLogs = append(requestLogs, log)
			}

			// Setup mock expectations
			mockRequestLogRepo.On("GetByOrganisation", mock.Anything, orgID, 10000, 0).Return(requestLogs, nil)

			// Create monitoring service
			logger := createTestLogger()
			service := NewMonitoringService(logger, mockMetricsRepo, mockHealthRepo, mockAlertRepo, mockRequestLogRepo)

			// Get throughput metrics
			ctx := context.Background()
			metrics, err := service.GetThroughputMetrics(ctx, orgID, startTime, endTime)

			// Verify no error occurred
			if err != nil {
				return false
			}

			// Verify request count matches
			if metrics.RequestCount != int64(requestCount) {
				return false
			}

			// Verify success count matches
			if metrics.SuccessCount != int64(successCount) {
				return false
			}

			// Verify error count matches
			if metrics.ErrorCount != int64(errorCount) {
				return false
			}

			// Verify average response time calculation
			expectedAvgResponseTime := float64(totalProcessingTime) / float64(requestCount)
			if metrics.AverageResponseTime != expectedAvgResponseTime {
				return false
			}

			// Verify time range
			if !metrics.StartTime.Equal(startTime) || !metrics.EndTime.Equal(endTime) {
				return false
			}

			return true
		},
		gen.AlphaString().SuchThat(func(s string) bool { return len(s) > 0 && len(s) < 50 }), // orgID
		gen.IntRange(1, 100), // requestCount
		gen.IntRange(0, 100).SuchThat(func(i int) bool { return i <= 100 }), // successCount (will be constrained by requestCount in property)
		gen.SliceOfN(100, gen.Int64Range(1, 10000)),                         // processingTimes
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// Unit test for basic metrics calculation functionality
func TestMonitoringService_GetThroughputMetrics_BasicCalculation(t *testing.T) {
	// Create mock repositories
	mockMetricsRepo := &MockMetricsRepository{}
	mockHealthRepo := &MockHealthCheckRepository{}
	mockAlertRepo := &MockAlertRepository{}
	mockRequestLogRepo := &MockRequestLogRepository{}

	// Create test data
	orgID := "test-org"
	startTime := time.Now().Add(-1 * time.Hour)
	endTime := time.Now()

	requestLogs := []*models.RequestLog{
		{
			ID:             "log1",
			OrganisationID: orgID,
			StatusCode:     200,
			ProcessingTime: 100,
			Timestamp:      startTime.Add(10 * time.Minute),
		},
		{
			ID:             "log2",
			OrganisationID: orgID,
			StatusCode:     200,
			ProcessingTime: 200,
			Timestamp:      startTime.Add(20 * time.Minute),
		},
		{
			ID:             "log3",
			OrganisationID: orgID,
			StatusCode:     500,
			ProcessingTime: 300,
			Timestamp:      startTime.Add(30 * time.Minute),
		},
	}

	mockRequestLogRepo.On("GetByOrganisation", mock.Anything, orgID, 10000, 0).Return(requestLogs, nil)

	// Create service
	logger := createTestLogger()
	service := NewMonitoringService(logger, mockMetricsRepo, mockHealthRepo, mockAlertRepo, mockRequestLogRepo)

	// Test
	ctx := context.Background()
	metrics, err := service.GetThroughputMetrics(ctx, orgID, startTime, endTime)

	// Assertions
	assert.NoError(t, err)
	assert.Equal(t, int64(3), metrics.RequestCount)
	assert.Equal(t, int64(2), metrics.SuccessCount)
	assert.Equal(t, int64(1), metrics.ErrorCount)
	assert.Equal(t, float64(200), metrics.AverageResponseTime) // (100+200+300)/3 = 200
	assert.Equal(t, float64(100), metrics.MinResponseTime)
	assert.Equal(t, float64(300), metrics.MaxResponseTime)

	mockRequestLogRepo.AssertExpectations(t)
}

// Unit test for empty request logs
func TestMonitoringService_GetThroughputMetrics_EmptyLogs(t *testing.T) {
	// Create mock repositories
	mockMetricsRepo := &MockMetricsRepository{}
	mockHealthRepo := &MockHealthCheckRepository{}
	mockAlertRepo := &MockAlertRepository{}
	mockRequestLogRepo := &MockRequestLogRepository{}

	orgID := "test-org"
	startTime := time.Now().Add(-1 * time.Hour)
	endTime := time.Now()

	// Return empty logs
	mockRequestLogRepo.On("GetByOrganisation", mock.Anything, orgID, 10000, 0).Return([]*models.RequestLog{}, nil)

	// Create service
	logger := createTestLogger()
	service := NewMonitoringService(logger, mockMetricsRepo, mockHealthRepo, mockAlertRepo, mockRequestLogRepo)

	// Test
	ctx := context.Background()
	metrics, err := service.GetThroughputMetrics(ctx, orgID, startTime, endTime)

	// Assertions
	assert.NoError(t, err)
	assert.Equal(t, int64(0), metrics.RequestCount)
	assert.Equal(t, int64(0), metrics.SuccessCount)
	assert.Equal(t, int64(0), metrics.ErrorCount)
	assert.Equal(t, float64(0), metrics.AverageResponseTime)

	mockRequestLogRepo.AssertExpectations(t)
}
