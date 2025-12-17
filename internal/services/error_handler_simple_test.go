package services

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"api-translation-platform/internal/config"
	"api-translation-platform/internal/logger"
	"github.com/stretchr/testify/assert"
)

func createSimpleTestLogger() *logger.Logger {
	cfg := &config.Config{
		Logging: config.LoggingConfig{
			Level:  "info",
			Format: "text",
		},
	}
	return logger.NewLogger(cfg)
}

func TestSimpleErrorClassification(t *testing.T) {
	logger := createSimpleTestLogger()
	eh := NewErrorHandler(logger)

	// Test timeout error classification
	err := errors.New("context deadline exceeded")
	classified := eh.ClassifyError(err, nil)

	assert.Equal(t, ErrorTypeTimeout, classified.Type)
	assert.Equal(t, http.StatusGatewayTimeout, classified.StatusCode)
	assert.True(t, classified.Retryable)

	// Test connection error classification
	err = errors.New("connection refused")
	classified = eh.ClassifyError(err, nil)

	assert.Equal(t, ErrorTypeConnection, classified.Type)
	assert.Equal(t, http.StatusBadGateway, classified.StatusCode)
	assert.True(t, classified.Retryable)

	// Test authentication error classification
	err = errors.New("unauthorized access")
	classified = eh.ClassifyError(err, nil)

	assert.Equal(t, ErrorTypeAuth, classified.Type)
	assert.Equal(t, http.StatusUnauthorized, classified.StatusCode)
	assert.False(t, classified.Retryable)
}

func TestSimpleCircuitBreaker(t *testing.T) {
	logger := createSimpleTestLogger()
	eh := NewErrorHandler(logger)

	breaker := eh.getOrCreateCircuitBreaker("test_service")

	// Initial state should be closed
	assert.Equal(t, ErrorCircuitBreakerClosed, breaker.GetState())

	// Test successful execution
	err := breaker.Execute(func() error {
		return nil
	})
	assert.NoError(t, err)

	// Test failure accumulation
	for i := 0; i < 5; i++ {
		breaker.Execute(func() error {
			return errors.New("test failure")
		})
	}

	// Circuit should be open now
	assert.Equal(t, ErrorCircuitBreakerOpen, breaker.GetState())

	// Next execution should be rejected
	err = breaker.Execute(func() error {
		return nil
	})
	assert.Error(t, err)

	var classifiedErr *ClassifiedError
	assert.True(t, errors.As(err, &classifiedErr))
	assert.Equal(t, ErrorTypeCircuit, classifiedErr.Type)
}

func TestSimpleRetryLogic(t *testing.T) {
	logger := createSimpleTestLogger()
	eh := NewErrorHandler(logger)

	// Set a fast retry policy for testing
	eh.SetRetryPolicy(&RetryPolicy{
		MaxAttempts:   3,
		InitialDelay:  1 * time.Millisecond,
		MaxDelay:      10 * time.Millisecond,
		BackoffFactor: 2.0,
		RetryableErrors: []ErrorType{
			ErrorTypeConnection,
		},
		Jitter: false,
	})

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
}

func TestSimpleStatusCodeMapping(t *testing.T) {
	logger := createSimpleTestLogger()
	eh := NewErrorHandler(logger)

	tests := []struct {
		errorMessage string
		errorType    ErrorType
		expectedCode int
	}{
		{"context deadline exceeded", ErrorTypeTimeout, http.StatusGatewayTimeout},
		{"connection refused", ErrorTypeConnection, http.StatusBadGateway},
		{"unauthorized access", ErrorTypeAuth, http.StatusUnauthorized},
		{"rate limit exceeded", ErrorTypeRateLimit, http.StatusTooManyRequests},
		{"invalid input provided", ErrorTypeValidation, http.StatusBadRequest},
		{"python script failed", ErrorTypeScript, http.StatusInternalServerError},
		{"circuit breaker is open", ErrorTypeCircuit, http.StatusServiceUnavailable},
	}

	for _, tt := range tests {
		t.Run(string(tt.errorType), func(t *testing.T) {
			originalErr := errors.New(tt.errorMessage)
			classified := eh.ClassifyError(originalErr, nil)
			assert.Equal(t, tt.errorType, classified.Type)
			assert.Equal(t, tt.expectedCode, classified.StatusCode)
		})
	}
}
