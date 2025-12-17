package services

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"api-translation-platform/internal/config"
	"api-translation-platform/internal/logger"
	"github.com/stretchr/testify/assert"
)

func createErrorHandlerTestLogger() *logger.Logger {
	cfg := &config.Config{
		Logging: config.LoggingConfig{
			Level:  "info",
			Format: "text",
		},
	}
	return logger.NewLogger(cfg)
}

func TestErrorClassification(t *testing.T) {
	logger := createErrorHandlerTestLogger()
	eh := NewErrorHandler(logger)

	tests := []struct {
		name          string
		err           error
		context       map[string]interface{}
		expectedType  ErrorType
		expectedCode  int
		expectedRetry bool
	}{
		{
			name:          "timeout error",
			err:           errors.New("context deadline exceeded"),
			expectedType:  ErrorTypeTimeout,
			expectedCode:  http.StatusGatewayTimeout,
			expectedRetry: true,
		},
		{
			name:          "connection error",
			err:           errors.New("connection refused"),
			expectedType:  ErrorTypeConnection,
			expectedCode:  http.StatusBadGateway,
			expectedRetry: true,
		},
		{
			name:          "authentication error",
			err:           errors.New("unauthorized access"),
			expectedType:  ErrorTypeAuth,
			expectedCode:  http.StatusUnauthorized,
			expectedRetry: false,
		},
		{
			name:          "rate limit error",
			err:           errors.New("rate limit exceeded"),
			expectedType:  ErrorTypeRateLimit,
			expectedCode:  http.StatusTooManyRequests,
			expectedRetry: true,
		},
		{
			name:          "validation error",
			err:           errors.New("invalid input provided"),
			expectedType:  ErrorTypeValidation,
			expectedCode:  http.StatusBadRequest,
			expectedRetry: false,
		},
		{
			name:          "script execution error",
			err:           errors.New("python script failed"),
			expectedType:  ErrorTypeScript,
			expectedCode:  http.StatusInternalServerError,
			expectedRetry: false,
		},
		{
			name: "HTTP 500 error",
			err:  errors.New("server error"),
			context: map[string]interface{}{
				"status_code": 500,
			},
			expectedType:  ErrorTypeTransient,
			expectedCode:  500,
			expectedRetry: true,
		},
		{
			name: "HTTP 429 error",
			err:  errors.New("too many requests"),
			context: map[string]interface{}{
				"status_code": 429,
			},
			expectedType:  ErrorTypeRateLimit,
			expectedCode:  429,
			expectedRetry: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			classified := eh.ClassifyError(tt.err, tt.context)

			assert.Equal(t, tt.expectedType, classified.Type)
			assert.Equal(t, tt.expectedCode, classified.StatusCode)
			assert.Equal(t, tt.expectedRetry, classified.Retryable)
			assert.NotZero(t, classified.Timestamp)
		})
	}
}

func TestCircuitBreakerFunctionality(t *testing.T) {
	logger := createErrorHandlerTestLogger()
	eh := NewErrorHandler(logger)

	// Test circuit breaker creation and initial state
	breaker := eh.getOrCreateCircuitBreaker("test_breaker")
	assert.Equal(t, ErrorCircuitBreakerClosed, breaker.GetState())
	assert.Equal(t, 0, breaker.GetFailures())

	// Test successful execution
	err := breaker.Execute(func() error {
		return nil
	})
	assert.NoError(t, err)
	assert.Equal(t, ErrorCircuitBreakerClosed, breaker.GetState())

	// Test failure accumulation
	for i := 0; i < 4; i++ {
		err = breaker.Execute(func() error {
			return errors.New("test failure")
		})
		assert.Error(t, err)
		assert.Equal(t, ErrorCircuitBreakerClosed, breaker.GetState())
	}

	// Test circuit breaker opening after threshold
	err = breaker.Execute(func() error {
		return errors.New("test failure")
	})
	assert.Error(t, err)
	assert.Equal(t, ErrorCircuitBreakerOpen, breaker.GetState())

	// Test that circuit breaker rejects calls when open
	err = breaker.Execute(func() error {
		return nil
	})
	assert.Error(t, err)

	var classifiedErr *ClassifiedError
	assert.True(t, errors.As(err, &classifiedErr))
	assert.Equal(t, ErrorTypeCircuit, classifiedErr.Type)
}

func TestRetryLogicWithVariousFailures(t *testing.T) {
	logger := createErrorHandlerTestLogger()
	eh := NewErrorHandler(logger)

	// Set a custom retry policy for testing
	eh.SetRetryPolicy(&RetryPolicy{
		MaxAttempts:   3,
		InitialDelay:  10 * time.Millisecond,
		MaxDelay:      100 * time.Millisecond,
		BackoffFactor: 2.0,
		RetryableErrors: []ErrorType{
			ErrorTypeTransient,
			ErrorTypeTimeout,
			ErrorTypeConnection,
		},
		Jitter: false, // Disable jitter for predictable testing
	})

	t.Run("successful retry after failures", func(t *testing.T) {
		attempts := 0
		err := eh.ExecuteWithRetry(context.Background(), func() error {
			attempts++
			if attempts < 3 {
				return errors.New("connection refused")
			}
			return nil
		}, "test_operation")

		assert.NoError(t, err)
		assert.Equal(t, 3, attempts)
	})

	t.Run("non-retryable error fails immediately", func(t *testing.T) {
		attempts := 0
		err := eh.ExecuteWithRetry(context.Background(), func() error {
			attempts++
			return errors.New("unauthorized access")
		}, "test_operation")

		assert.Error(t, err)
		assert.Equal(t, 1, attempts)

		var classifiedErr *ClassifiedError
		assert.True(t, errors.As(err, &classifiedErr))
		assert.Equal(t, ErrorTypeAuth, classifiedErr.Type)
	})

	t.Run("max retries exceeded", func(t *testing.T) {
		attempts := 0
		err := eh.ExecuteWithRetry(context.Background(), func() error {
			attempts++
			return errors.New("connection refused")
		}, "test_operation")

		assert.Error(t, err)
		assert.Equal(t, 3, attempts) // MaxAttempts
	})

	t.Run("context cancellation stops retry", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())

		attempts := 0
		go func() {
			time.Sleep(50 * time.Millisecond)
			cancel()
		}()

		err := eh.ExecuteWithRetry(ctx, func() error {
			attempts++
			time.Sleep(30 * time.Millisecond)
			return errors.New("connection refused")
		}, "test_operation")

		assert.Error(t, err)
		assert.True(t, attempts >= 1 && attempts < 3) // Should be interrupted
	})
}

func TestErrorStatusCodeMapping(t *testing.T) {
	logger := createErrorHandlerTestLogger()
	eh := NewErrorHandler(logger)

	tests := []struct {
		name         string
		errorType    ErrorType
		expectedCode int
	}{
		{"timeout", ErrorTypeTimeout, http.StatusGatewayTimeout},
		{"connection", ErrorTypeConnection, http.StatusBadGateway},
		{"auth", ErrorTypeAuth, http.StatusUnauthorized},
		{"rate_limit", ErrorTypeRateLimit, http.StatusTooManyRequests},
		{"validation", ErrorTypeValidation, http.StatusBadRequest},
		{"script", ErrorTypeScript, http.StatusInternalServerError},
		{"circuit", ErrorTypeCircuit, http.StatusServiceUnavailable},
		{"unknown", ErrorTypeUnknown, http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := errors.New("test error")
			classified := eh.ClassifyError(err, nil)

			// Manually set the type to test mapping
			classified.Type = tt.errorType
			eh.classifyByContent(classified)

			assert.Equal(t, tt.expectedCode, classified.StatusCode)
		})
	}
}

func TestFullProtectionIntegration(t *testing.T) {
	logger := createErrorHandlerTestLogger()
	eh := NewErrorHandler(logger)

	// Set a fast retry policy for testing
	eh.SetRetryPolicy(&RetryPolicy{
		MaxAttempts:   2,
		InitialDelay:  1 * time.Millisecond,
		MaxDelay:      10 * time.Millisecond,
		BackoffFactor: 2.0,
		RetryableErrors: []ErrorType{
			ErrorTypeTransient,
			ErrorTypeTimeout,
			ErrorTypeConnection,
		},
		Jitter: false,
	})

	t.Run("successful execution with full protection", func(t *testing.T) {
		attempts := 0
		err := eh.ExecuteWithFullProtection(context.Background(), func() error {
			attempts++
			if attempts == 1 {
				return errors.New("connection refused")
			}
			return nil
		}, "test_operation")

		assert.NoError(t, err)
		assert.Equal(t, 2, attempts)
	})

	t.Run("circuit breaker integration", func(t *testing.T) {
		// Force circuit breaker to open by causing multiple failures
		for i := 0; i < 6; i++ {
			eh.ExecuteWithFullProtection(context.Background(), func() error {
				return errors.New("connection refused")
			}, "failing_operation")
		}

		// Next call should be rejected by circuit breaker
		err := eh.ExecuteWithFullProtection(context.Background(), func() error {
			return nil
		}, "failing_operation")

		assert.Error(t, err)

		var classifiedErr *ClassifiedError
		assert.True(t, errors.As(err, &classifiedErr))
		assert.Equal(t, ErrorTypeCircuit, classifiedErr.Type)
	})
}

func TestErrorRecoveryProcedures(t *testing.T) {
	logger := createErrorHandlerTestLogger()
	eh := NewErrorHandler(logger)

	t.Run("rate limit recovery", func(t *testing.T) {
		err := &ClassifiedError{
			Type:     ErrorTypeRateLimit,
			Severity: SeverityMedium,
			Context: map[string]interface{}{
				"retry_after": 10 * time.Millisecond,
			},
		}

		start := time.Now()
		recoveryErr := eh.attemptRecovery(context.Background(), err)
		elapsed := time.Since(start)

		assert.NoError(t, recoveryErr)
		assert.True(t, elapsed >= 10*time.Millisecond)
	})

	t.Run("connection recovery", func(t *testing.T) {
		err := &ClassifiedError{
			Type:     ErrorTypeConnection,
			Severity: SeverityMedium,
		}

		recoveryErr := eh.attemptRecovery(context.Background(), err)
		assert.NoError(t, recoveryErr) // Default handler doesn't return error
	})

	t.Run("custom recovery handler", func(t *testing.T) {
		customHandlerCalled := false
		eh.AddRecoveryHandler(ErrorTypeScript, func(ctx context.Context, err *ClassifiedError) error {
			customHandlerCalled = true
			return nil
		})

		err := &ClassifiedError{
			Type:     ErrorTypeScript,
			Severity: SeverityHigh,
		}

		recoveryErr := eh.attemptRecovery(context.Background(), err)
		assert.NoError(t, recoveryErr)
		assert.True(t, customHandlerCalled)
	})
}

func TestCircuitBreakerStateTransitions(t *testing.T) {
	breaker := NewErrorCircuitBreaker("test", 3, 30*time.Second, 60*time.Second)

	// Initial state should be closed
	assert.Equal(t, ErrorCircuitBreakerClosed, breaker.GetState())

	// Record failures to open circuit
	for i := 0; i < 3; i++ {
		breaker.recordFailure()
	}
	assert.Equal(t, ErrorCircuitBreakerOpen, breaker.GetState())

	// Simulate timeout passing to allow half-open
	breaker.nextAttempt = time.Now().Add(-1 * time.Second)
	assert.True(t, breaker.canExecute())

	// Execute to transition to half-open
	err := breaker.Execute(func() error {
		return nil // Success
	})
	assert.NoError(t, err)
	assert.Equal(t, ErrorCircuitBreakerClosed, breaker.GetState())
}

func TestErrorSeverityClassification(t *testing.T) {
	logger := createErrorHandlerTestLogger()
	eh := NewErrorHandler(logger)

	tests := []struct {
		name             string
		errorType        ErrorType
		expectedSeverity ErrorSeverity
	}{
		{"auth error", ErrorTypeAuth, SeverityMedium},
		{"validation error", ErrorTypeValidation, SeverityMedium},
		{"timeout error", ErrorTypeTimeout, SeverityLow},
		{"rate limit error", ErrorTypeRateLimit, SeverityLow},
		{"connection error", ErrorTypeConnection, SeverityLow},
		{"circuit breaker error", ErrorTypeCircuit, SeverityHigh},
		{"script error", ErrorTypeScript, SeverityHigh},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := &ClassifiedError{
				Type: tt.errorType,
			}

			eh.classifyBySeverity(err)
			assert.Equal(t, tt.expectedSeverity, err.Severity)
		})
	}
}

func TestBackoffDelayCalculation(t *testing.T) {
	logger := createErrorHandlerTestLogger()
	eh := NewErrorHandler(logger)

	// Set specific retry policy for testing
	eh.SetRetryPolicy(&RetryPolicy{
		InitialDelay:  100 * time.Millisecond,
		MaxDelay:      5 * time.Second,
		BackoffFactor: 2.0,
		Jitter:        false,
	})

	tests := []struct {
		attempt     int
		expectedMin time.Duration
		expectedMax time.Duration
	}{
		{0, 100 * time.Millisecond, 100 * time.Millisecond},
		{1, 200 * time.Millisecond, 200 * time.Millisecond},
		{2, 400 * time.Millisecond, 400 * time.Millisecond},
		{3, 800 * time.Millisecond, 800 * time.Millisecond},
		{10, 5 * time.Second, 5 * time.Second}, // Should be capped at MaxDelay
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("attempt_%d", tt.attempt), func(t *testing.T) {
			delay := eh.calculateDelay(tt.attempt)
			assert.True(t, delay >= tt.expectedMin && delay <= tt.expectedMax,
				"Expected delay between %v and %v, got %v", tt.expectedMin, tt.expectedMax, delay)
		})
	}
}

func TestCircuitBreakerStatus(t *testing.T) {
	logger := createErrorHandlerTestLogger()
	eh := NewErrorHandler(logger)

	// Create some circuit breakers
	breaker1 := eh.getOrCreateCircuitBreaker("service1")
	_ = eh.getOrCreateCircuitBreaker("service2")

	// Open one circuit breaker
	for i := 0; i < 5; i++ {
		breaker1.recordFailure()
	}

	status := eh.GetCircuitBreakerStatus()

	assert.Len(t, status, 2)
	assert.Equal(t, ErrorCircuitBreakerOpen, status["service1"])
	assert.Equal(t, ErrorCircuitBreakerClosed, status["service2"])
}

// Benchmark tests for performance validation
func BenchmarkErrorClassification(b *testing.B) {
	logger := createErrorHandlerTestLogger()
	eh := NewErrorHandler(logger)
	err := errors.New("connection refused")
	context := map[string]interface{}{
		"operation": "test",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		eh.ClassifyError(err, context)
	}
}

func BenchmarkCircuitBreakerExecution(b *testing.B) {
	logger := createErrorHandlerTestLogger()
	eh := NewErrorHandler(logger)
	breaker := eh.getOrCreateCircuitBreaker("benchmark")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		breaker.Execute(func() error {
			return nil
		})
	}
}
