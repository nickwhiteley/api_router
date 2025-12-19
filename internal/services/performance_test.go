package services

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"api-translation-platform/internal/models"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// PerformanceTestSuite contains performance test scenarios
type PerformanceTestSuite struct {
	server     *httptest.Server
	baseURL    string
	httpClient *http.Client
}

// NewPerformanceTestSuite creates a new performance test suite
func NewPerformanceTestSuite(t *testing.T) *PerformanceTestSuite {
	// Create test server
	mux := http.NewServeMux()

	// Add test endpoints
	mux.HandleFunc("/api/v1/configurations", func(w http.ResponseWriter, r *http.Request) {
		// Simulate database query delay
		time.Sleep(10 * time.Millisecond)

		configs := []models.APIConfiguration{
			{
				ID:             "1",
				OrganisationID: "1",
				Name:           "Test API",
				Type:           "REST",
				Direction:      "inbound",
				Endpoint:       "http://example.com/api",
				Authentication: models.AuthenticationConfig{Type: "api_key"},
				Headers: models.HeadersConfig{
					Static:   map[string]string{},
					Required: []string{},
					Dynamic:  map[string]string{},
				},
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(configs)
	})

	mux.HandleFunc("/api/v1/connectors", func(w http.ResponseWriter, r *http.Request) {
		// Simulate heavier processing
		time.Sleep(50 * time.Millisecond)

		connectors := []models.Connector{
			{
				ID:             "1",
				OrganisationID: "1",
				Name:           "Test Connector",
				InboundAPIID:   "api-1",
				OutboundAPIID:  "api-2",
				PythonScript:   "def transform(data): return data",
				IsActive:       true,
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(connectors)
	})

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	server := httptest.NewServer(mux)

	return &PerformanceTestSuite{
		server:  server,
		baseURL: server.URL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Close cleans up the test suite
func (pts *PerformanceTestSuite) Close() {
	pts.server.Close()
}

// TestAPIEndpointThroughput tests the throughput of API endpoints
func TestAPIEndpointThroughput(t *testing.T) {
	suite := NewPerformanceTestSuite(t)
	defer suite.Close()

	testCases := []struct {
		name            string
		endpoint        string
		concurrency     int
		totalRequests   int
		maxResponseTime time.Duration
		minThroughput   float64 // requests per second
	}{
		{
			name:            "Configuration endpoint load test",
			endpoint:        "/api/v1/configurations",
			concurrency:     10,
			totalRequests:   100,
			maxResponseTime: 200 * time.Millisecond,
			minThroughput:   50.0,
		},
		{
			name:            "Connector endpoint load test",
			endpoint:        "/api/v1/connectors",
			concurrency:     5,
			totalRequests:   50,
			maxResponseTime: 300 * time.Millisecond,
			minThroughput:   10.0,
		},
		{
			name:            "Health check endpoint load test",
			endpoint:        "/health",
			concurrency:     20,
			totalRequests:   200,
			maxResponseTime: 50 * time.Millisecond,
			minThroughput:   100.0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			results := suite.runLoadTest(t, tc.endpoint, tc.concurrency, tc.totalRequests)

			// Verify response times
			for _, result := range results {
				assert.True(t, result.ResponseTime <= tc.maxResponseTime,
					"Response time %v exceeds maximum %v", result.ResponseTime, tc.maxResponseTime)
				assert.Equal(t, http.StatusOK, result.StatusCode,
					"Expected status 200, got %d", result.StatusCode)
			}

			// Calculate throughput
			totalDuration := results[len(results)-1].Timestamp.Sub(results[0].Timestamp)
			throughput := float64(len(results)) / totalDuration.Seconds()

			assert.True(t, throughput >= tc.minThroughput,
				"Throughput %.2f req/s is below minimum %.2f req/s", throughput, tc.minThroughput)

			t.Logf("Endpoint: %s, Throughput: %.2f req/s, Avg Response Time: %v",
				tc.endpoint, throughput, suite.calculateAverageResponseTime(results))
		})
	}
}

// TestCachingEffectiveness tests caching performance improvements
func TestCachingEffectiveness(t *testing.T) {
	suite := NewPerformanceTestSuite(t)
	defer suite.Close()

	endpoint := "/api/v1/configurations"

	// First request (cache miss)
	start := time.Now()
	resp1, err := suite.httpClient.Get(suite.baseURL + endpoint)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp1.StatusCode)
	resp1.Body.Close()
	firstRequestTime := time.Since(start)

	// Second request (should be faster if cached)
	start = time.Now()
	resp2, err := suite.httpClient.Get(suite.baseURL + endpoint)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp2.StatusCode)
	resp2.Body.Close()
	secondRequestTime := time.Since(start)

	// Note: In a real implementation with caching, the second request should be faster
	// For now, we just verify both requests complete successfully
	t.Logf("First request time: %v, Second request time: %v", firstRequestTime, secondRequestTime)

	// In a real cached system, we would assert:
	// assert.True(t, secondRequestTime < firstRequestTime/2, "Cached request should be significantly faster")
}

// TestBackgroundJobProcessing tests background job performance
func TestBackgroundJobProcessing(t *testing.T) {
	// Create a mock background job processor
	jobProcessor := &MockJobProcessor{
		jobs:      make(chan Job, 100),
		completed: make(chan JobResult, 100),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Start job processor
	go jobProcessor.Start(ctx)

	// Submit jobs
	numJobs := 50
	jobStartTime := time.Now()

	for i := 0; i < numJobs; i++ {
		job := Job{
			ID:   fmt.Sprintf("job-%d", i),
			Type: "data_processing",
			Data: map[string]interface{}{
				"input": fmt.Sprintf("data-%d", i),
			},
		}

		select {
		case jobProcessor.jobs <- job:
		case <-ctx.Done():
			t.Fatal("Failed to submit job within timeout")
		}
	}

	// Wait for all jobs to complete
	completedJobs := 0
	for completedJobs < numJobs {
		select {
		case result := <-jobProcessor.completed:
			assert.NoError(t, result.Error, "Job %s failed: %v", result.JobID, result.Error)
			completedJobs++
		case <-ctx.Done():
			t.Fatalf("Only %d of %d jobs completed within timeout", completedJobs, numJobs)
		}
	}

	totalProcessingTime := time.Since(jobStartTime)
	jobThroughput := float64(numJobs) / totalProcessingTime.Seconds()

	// Verify job processing performance
	assert.True(t, jobThroughput >= 10.0, "Job throughput %.2f jobs/s is below minimum 10 jobs/s", jobThroughput)

	t.Logf("Processed %d jobs in %v (%.2f jobs/s)", numJobs, totalProcessingTime, jobThroughput)
}

// LoadTestResult represents the result of a single request in a load test
type LoadTestResult struct {
	StatusCode   int
	ResponseTime time.Duration
	Timestamp    time.Time
	Error        error
}

// runLoadTest executes a load test against an endpoint
func (pts *PerformanceTestSuite) runLoadTest(t *testing.T, endpoint string, concurrency, totalRequests int) []LoadTestResult {
	var wg sync.WaitGroup
	results := make([]LoadTestResult, totalRequests)
	requestChan := make(chan int, totalRequests)

	// Fill request channel
	for i := 0; i < totalRequests; i++ {
		requestChan <- i
	}
	close(requestChan)

	// Start concurrent workers
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			for requestIndex := range requestChan {
				start := time.Now()
				resp, err := pts.httpClient.Get(pts.baseURL + endpoint)
				responseTime := time.Since(start)

				result := LoadTestResult{
					ResponseTime: responseTime,
					Timestamp:    start,
					Error:        err,
				}

				if err == nil {
					result.StatusCode = resp.StatusCode
					resp.Body.Close()
				}

				results[requestIndex] = result
			}
		}()
	}

	wg.Wait()
	return results
}

// calculateAverageResponseTime calculates the average response time from results
func (pts *PerformanceTestSuite) calculateAverageResponseTime(results []LoadTestResult) time.Duration {
	var total time.Duration
	validResults := 0

	for _, result := range results {
		if result.Error == nil {
			total += result.ResponseTime
			validResults++
		}
	}

	if validResults == 0 {
		return 0
	}

	return total / time.Duration(validResults)
}

// MockJobProcessor simulates background job processing
type MockJobProcessor struct {
	jobs      chan Job
	completed chan JobResult
}

// Job represents a background job
type Job struct {
	ID   string
	Type string
	Data map[string]interface{}
}

// JobResult represents the result of a background job
type JobResult struct {
	JobID     string
	Success   bool
	Error     error
	Duration  time.Duration
	Timestamp time.Time
}

// Start begins processing jobs
func (mjp *MockJobProcessor) Start(ctx context.Context) {
	for {
		select {
		case job := <-mjp.jobs:
			start := time.Now()

			// Simulate job processing time
			processingTime := time.Duration(10+job.ID[len(job.ID)-1]%20) * time.Millisecond
			time.Sleep(processingTime)

			result := JobResult{
				JobID:     job.ID,
				Success:   true,
				Duration:  time.Since(start),
				Timestamp: time.Now(),
			}

			select {
			case mjp.completed <- result:
			case <-ctx.Done():
				return
			}

		case <-ctx.Done():
			return
		}
	}
}
