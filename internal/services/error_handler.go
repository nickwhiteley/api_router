package services

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"api-translation-platform/internal/logger"
)

// ErrorType represents different types of errors
type ErrorType string

const (
	ErrorTypeTransient  ErrorType = "transient"
	ErrorTypePermanent  ErrorType = "permanent"
	ErrorTypeTimeout    ErrorType = "timeout"
	ErrorTypeRateLimit  ErrorType = "rate_limit"
	ErrorTypeAuth       ErrorType = "authentication"
	ErrorTypeValidation ErrorType = "validation"
	ErrorTypeCircuit    ErrorType = "circuit_breaker"
	ErrorTypeScript     ErrorType = "script_execution"
	ErrorTypeConnection ErrorType = "connection"
	ErrorTypeUnknown    ErrorType = "unknown"
)

// ErrorSeverity represents error severity levels
type ErrorSeverity string

const (
	SeverityLow      ErrorSeverity = "low"
	SeverityMedium   ErrorSeverity = "medium"
	SeverityHigh     ErrorSeverity = "high"
	SeverityCritical ErrorSeverity = "critical"
)

// ClassifiedError represents an error with classification information
type ClassifiedError struct {
	OriginalError error
	Type          ErrorType
	Severity      ErrorSeverity
	StatusCode    int
	Message       string
	Retryable     bool
	Context       map[string]interface{}
	Timestamp     time.Time
}

func (e *ClassifiedError) Error() string {
	return fmt.Sprintf("[%s:%s] %s", e.Type, e.Severity, e.Message)
}

// ErrorCircuitBreakerState represents the state of a circuit breaker
type ErrorCircuitBreakerState string

const (
	ErrorCircuitBreakerClosed   ErrorCircuitBreakerState = "closed"
	ErrorCircuitBreakerOpen     ErrorCircuitBreakerState = "open"
	ErrorCircuitBreakerHalfOpen ErrorCircuitBreakerState = "half_open"
)

// ErrorCircuitBreaker implements the circuit breaker pattern
type ErrorCircuitBreaker struct {
	name            string
	maxFailures     int
	timeout         time.Duration
	resetTimeout    time.Duration
	state           ErrorCircuitBreakerState
	failures        int
	lastFailureTime time.Time
	nextAttempt     time.Time
	mutex           sync.RWMutex
	onStateChange   func(name string, from, to ErrorCircuitBreakerState)
}

// NewErrorCircuitBreaker creates a new circuit breaker
func NewErrorCircuitBreaker(name string, maxFailures int, timeout, resetTimeout time.Duration) *ErrorCircuitBreaker {
	return &ErrorCircuitBreaker{
		name:         name,
		maxFailures:  maxFailures,
		timeout:      timeout,
		resetTimeout: resetTimeout,
		state:        ErrorCircuitBreakerClosed,
	}
}

// Execute executes a function with circuit breaker protection
func (cb *ErrorCircuitBreaker) Execute(fn func() error) error {
	if !cb.canExecute() {
		return &ClassifiedError{
			OriginalError: errors.New("circuit breaker is open"),
			Type:          ErrorTypeCircuit,
			Severity:      SeverityHigh,
			StatusCode:    http.StatusServiceUnavailable,
			Message:       fmt.Sprintf("Circuit breaker '%s' is open", cb.name),
			Retryable:     false,
			Timestamp:     time.Now(),
		}
	}

	err := fn()
	if err != nil {
		cb.recordFailure()
		return err
	}

	cb.recordSuccess()
	return nil
}

// canExecute checks if the circuit breaker allows execution
func (cb *ErrorCircuitBreaker) canExecute() bool {
	cb.mutex.RLock()
	defer cb.mutex.RUnlock()

	switch cb.state {
	case ErrorCircuitBreakerClosed:
		return true
	case ErrorCircuitBreakerOpen:
		return time.Now().After(cb.nextAttempt)
	case ErrorCircuitBreakerHalfOpen:
		return true
	default:
		return false
	}
}

// recordFailure records a failure and potentially opens the circuit
func (cb *ErrorCircuitBreaker) recordFailure() {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	cb.failures++
	cb.lastFailureTime = time.Now()

	switch cb.state {
	case ErrorCircuitBreakerClosed:
		if cb.failures >= cb.maxFailures {
			cb.setState(ErrorCircuitBreakerOpen)
			cb.nextAttempt = time.Now().Add(cb.resetTimeout)
		}
	case ErrorCircuitBreakerHalfOpen:
		cb.setState(ErrorCircuitBreakerOpen)
		cb.nextAttempt = time.Now().Add(cb.resetTimeout)
	}
}

// recordSuccess records a success and potentially closes the circuit
func (cb *ErrorCircuitBreaker) recordSuccess() {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	cb.failures = 0

	switch cb.state {
	case ErrorCircuitBreakerHalfOpen:
		cb.setState(ErrorCircuitBreakerClosed)
	case ErrorCircuitBreakerOpen:
		cb.setState(ErrorCircuitBreakerHalfOpen)
	}
}

// setState changes the circuit breaker state and calls the callback
func (cb *ErrorCircuitBreaker) setState(newState ErrorCircuitBreakerState) {
	oldState := cb.state
	cb.state = newState

	if cb.onStateChange != nil && oldState != newState {
		go cb.onStateChange(cb.name, oldState, newState)
	}
}

// GetState returns the current state of the circuit breaker
func (cb *ErrorCircuitBreaker) GetState() ErrorCircuitBreakerState {
	cb.mutex.RLock()
	defer cb.mutex.RUnlock()
	return cb.state
}

// GetFailures returns the current failure count
func (cb *ErrorCircuitBreaker) GetFailures() int {
	cb.mutex.RLock()
	defer cb.mutex.RUnlock()
	return cb.failures
}

// RetryPolicy defines retry behavior
type RetryPolicy struct {
	MaxAttempts     int
	InitialDelay    time.Duration
	MaxDelay        time.Duration
	BackoffFactor   float64
	RetryableErrors []ErrorType
	Jitter          bool
}

// DefaultRetryPolicy returns a default retry policy
func DefaultRetryPolicy() *RetryPolicy {
	return &RetryPolicy{
		MaxAttempts:   3,
		InitialDelay:  100 * time.Millisecond,
		MaxDelay:      5 * time.Second,
		BackoffFactor: 2.0,
		RetryableErrors: []ErrorType{
			ErrorTypeTransient,
			ErrorTypeTimeout,
			ErrorTypeConnection,
		},
		Jitter: true,
	}
}

// ErrorHandler provides comprehensive error handling capabilities
type ErrorHandler struct {
	logger          *logger.Logger
	circuitBreakers map[string]*ErrorCircuitBreaker
	retryPolicy     *RetryPolicy
	mutex           sync.RWMutex

	// Error notification system
	notificationHandlers []func(*ClassifiedError)

	// Error recovery procedures
	recoveryHandlers map[ErrorType]func(context.Context, *ClassifiedError) error
}

// NewErrorHandler creates a new error handler
func NewErrorHandler(logger *logger.Logger) *ErrorHandler {
	eh := &ErrorHandler{
		logger:               logger,
		circuitBreakers:      make(map[string]*ErrorCircuitBreaker),
		retryPolicy:          DefaultRetryPolicy(),
		notificationHandlers: make([]func(*ClassifiedError), 0),
		recoveryHandlers:     make(map[ErrorType]func(context.Context, *ClassifiedError) error),
	}

	// Set up default recovery handlers
	eh.setupDefaultRecoveryHandlers()

	return eh
}

// ClassifyError classifies an error based on its type and context
func (eh *ErrorHandler) ClassifyError(err error, context map[string]interface{}) *ClassifiedError {
	if err == nil {
		return nil
	}

	// Check if it's already a classified error
	if classifiedErr, ok := err.(*ClassifiedError); ok {
		return classifiedErr
	}

	classified := &ClassifiedError{
		OriginalError: err,
		Context:       context,
		Timestamp:     time.Now(),
	}

	// Classify based on error content and context
	eh.classifyByContent(classified)
	eh.classifyByHTTPStatus(classified)
	eh.classifyBySeverity(classified)

	return classified
}

// classifyByContent classifies error based on error message content
func (eh *ErrorHandler) classifyByContent(err *ClassifiedError) {
	errMsg := err.OriginalError.Error()

	switch {
	case contains(errMsg, "timeout", "deadline exceeded", "context deadline exceeded"):
		err.Type = ErrorTypeTimeout
		err.StatusCode = http.StatusGatewayTimeout
		err.Retryable = true
		err.Message = "Request timeout"

	case contains(errMsg, "connection refused", "no such host", "network unreachable"):
		err.Type = ErrorTypeConnection
		err.StatusCode = http.StatusBadGateway
		err.Retryable = true
		err.Message = "Connection error"

	case contains(errMsg, "unauthorized", "authentication", "invalid credentials"):
		err.Type = ErrorTypeAuth
		err.StatusCode = http.StatusUnauthorized
		err.Retryable = false
		err.Message = "Authentication failed"

	case contains(errMsg, "rate limit", "too many requests"):
		err.Type = ErrorTypeRateLimit
		err.StatusCode = http.StatusTooManyRequests
		err.Retryable = true
		err.Message = "Rate limit exceeded"

	case contains(errMsg, "validation", "invalid input", "bad request"):
		err.Type = ErrorTypeValidation
		err.StatusCode = http.StatusBadRequest
		err.Retryable = false
		err.Message = "Validation error"

	case contains(errMsg, "script", "python", "execution"):
		err.Type = ErrorTypeScript
		err.StatusCode = http.StatusInternalServerError
		err.Retryable = false
		err.Message = "Script execution error"

	case contains(errMsg, "circuit breaker"):
		err.Type = ErrorTypeCircuit
		err.StatusCode = http.StatusServiceUnavailable
		err.Retryable = false
		err.Message = "Circuit breaker open"

	default:
		err.Type = ErrorTypeUnknown
		err.StatusCode = http.StatusInternalServerError
		err.Retryable = false
		err.Message = "Unknown error"
	}
}

// classifyByHTTPStatus classifies error based on HTTP status code from context
func (eh *ErrorHandler) classifyByHTTPStatus(err *ClassifiedError) {
	if statusCode, ok := err.Context["status_code"].(int); ok {
		err.StatusCode = statusCode

		switch {
		case statusCode >= 500 && statusCode < 600:
			err.Type = ErrorTypeTransient
			err.Retryable = true
			err.Message = fmt.Sprintf("Server error (HTTP %d)", statusCode)

		case statusCode == 429:
			err.Type = ErrorTypeRateLimit
			err.Retryable = true
			err.Message = "Rate limit exceeded"

		case statusCode == 408:
			err.Type = ErrorTypeTimeout
			err.Retryable = true
			err.Message = "Request timeout"

		case statusCode >= 400 && statusCode < 500:
			err.Type = ErrorTypeValidation
			err.Retryable = false
			err.Message = fmt.Sprintf("Client error (HTTP %d)", statusCode)
		}
	}
}

// classifyBySeverity determines error severity
func (eh *ErrorHandler) classifyBySeverity(err *ClassifiedError) {
	switch err.Type {
	case ErrorTypeAuth, ErrorTypeValidation:
		err.Severity = SeverityMedium
	case ErrorTypeTimeout, ErrorTypeRateLimit, ErrorTypeConnection:
		err.Severity = SeverityLow
	case ErrorTypeCircuit, ErrorTypeScript:
		err.Severity = SeverityHigh
	default:
		if err.StatusCode >= 500 {
			err.Severity = SeverityHigh
		} else {
			err.Severity = SeverityMedium
		}
	}

	// Escalate severity based on frequency or context
	if frequency, ok := err.Context["error_frequency"].(int); ok && frequency > 10 {
		if err.Severity == SeverityLow {
			err.Severity = SeverityMedium
		} else if err.Severity == SeverityMedium {
			err.Severity = SeverityHigh
		}
	}
}

// ExecuteWithRetry executes a function with retry logic
func (eh *ErrorHandler) ExecuteWithRetry(ctx context.Context, operation func() error, operationName string) error {
	var lastErr error

	for attempt := 0; attempt < eh.retryPolicy.MaxAttempts; attempt++ {
		err := operation()
		if err == nil {
			return nil
		}

		classified := eh.ClassifyError(err, map[string]interface{}{
			"operation": operationName,
			"attempt":   attempt + 1,
		})

		lastErr = classified

		// Check if error is retryable
		if !eh.isRetryable(classified) {
			eh.logger.WithError(classified).
				WithField("operation", operationName).
				Error("Non-retryable error encountered")
			return classified
		}

		// Don't retry on last attempt
		if attempt == eh.retryPolicy.MaxAttempts-1 {
			break
		}

		// Calculate delay with exponential backoff
		delay := eh.calculateDelay(attempt)

		eh.logger.WithError(classified).
			WithField("operation", operationName).
			WithField("attempt", attempt+1).
			WithField("delay_ms", delay.Milliseconds()).
			Warn("Operation failed, retrying")

		// Wait for delay or context cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
			continue
		}
	}

	eh.logger.WithError(lastErr).
		WithField("operation", operationName).
		WithField("max_attempts", eh.retryPolicy.MaxAttempts).
		Error("Operation failed after all retry attempts")

	return lastErr
}

// ExecuteWithCircuitBreaker executes a function with circuit breaker protection
func (eh *ErrorHandler) ExecuteWithCircuitBreaker(ctx context.Context, operation func() error, breakerName string) error {
	breaker := eh.getOrCreateCircuitBreaker(breakerName)

	return breaker.Execute(operation)
}

// ExecuteWithFullProtection executes a function with both retry and circuit breaker protection
func (eh *ErrorHandler) ExecuteWithFullProtection(ctx context.Context, operation func() error, operationName string) error {
	breakerName := fmt.Sprintf("%s_breaker", operationName)

	return eh.ExecuteWithCircuitBreaker(ctx, func() error {
		return eh.ExecuteWithRetry(ctx, operation, operationName)
	}, breakerName)
}

// HandleError processes an error through the complete error handling pipeline
func (eh *ErrorHandler) HandleError(ctx context.Context, err error, context map[string]interface{}) error {
	if err == nil {
		return nil
	}

	classified := eh.ClassifyError(err, context)

	// Log the error
	eh.logError(classified)

	// Send notifications
	eh.notifyError(classified)

	// Attempt recovery
	if recoveryErr := eh.attemptRecovery(ctx, classified); recoveryErr != nil {
		eh.logger.WithError(recoveryErr).
			WithField("original_error", classified.Error()).
			Error("Error recovery failed")
	}

	return classified
}

// Helper methods

func (eh *ErrorHandler) isRetryable(err *ClassifiedError) bool {
	if !err.Retryable {
		return false
	}

	for _, retryableType := range eh.retryPolicy.RetryableErrors {
		if err.Type == retryableType {
			return true
		}
	}

	return false
}

func (eh *ErrorHandler) calculateDelay(attempt int) time.Duration {
	delay := float64(eh.retryPolicy.InitialDelay)

	// Apply exponential backoff
	for i := 0; i < attempt; i++ {
		delay *= eh.retryPolicy.BackoffFactor
	}

	// Apply jitter if enabled
	if eh.retryPolicy.Jitter {
		jitterFactor := float64(time.Now().UnixNano()%100) / 100.0 // 0.0 to 0.99
		jitter := delay * 0.1 * (2*jitterFactor - 1)               // ±10% jitter
		delay += jitter
	}

	// Ensure delay doesn't exceed maximum
	if delay > float64(eh.retryPolicy.MaxDelay) {
		delay = float64(eh.retryPolicy.MaxDelay)
	}

	return time.Duration(delay)
}

func (eh *ErrorHandler) getOrCreateCircuitBreaker(name string) *ErrorCircuitBreaker {
	eh.mutex.RLock()
	breaker, exists := eh.circuitBreakers[name]
	eh.mutex.RUnlock()

	if exists {
		return breaker
	}

	eh.mutex.Lock()
	defer eh.mutex.Unlock()

	// Double-check after acquiring write lock
	if breaker, exists := eh.circuitBreakers[name]; exists {
		return breaker
	}

	// Create new circuit breaker
	breaker = NewErrorCircuitBreaker(name, 5, 30*time.Second, 60*time.Second)
	breaker.onStateChange = eh.onCircuitBreakerStateChange
	eh.circuitBreakers[name] = breaker

	return breaker
}

func (eh *ErrorHandler) onCircuitBreakerStateChange(name string, from, to ErrorCircuitBreakerState) {
	eh.logger.WithField("breaker_name", name).
		WithField("from_state", string(from)).
		WithField("to_state", string(to)).
		Info("Circuit breaker state changed")
}

func (eh *ErrorHandler) logError(err *ClassifiedError) {
	logEntry := eh.logger.WithError(err.OriginalError).
		WithField("error_type", string(err.Type)).
		WithField("severity", string(err.Severity)).
		WithField("status_code", err.StatusCode).
		WithField("retryable", err.Retryable)

	// Add context fields
	for key, value := range err.Context {
		logEntry = logEntry.WithField(key, value)
	}

	switch err.Severity {
	case SeverityLow:
		logEntry.Warn(err.Message)
	case SeverityMedium:
		logEntry.Error(err.Message)
	case SeverityHigh, SeverityCritical:
		logEntry.Error(err.Message)
	}
}

func (eh *ErrorHandler) notifyError(err *ClassifiedError) {
	for _, handler := range eh.notificationHandlers {
		go func(h func(*ClassifiedError)) {
			defer func() {
				if r := recover(); r != nil {
					eh.logger.WithField("panic", r).Error("Error notification handler panicked")
				}
			}()
			h(err)
		}(handler)
	}
}

func (eh *ErrorHandler) attemptRecovery(ctx context.Context, err *ClassifiedError) error {
	if handler, exists := eh.recoveryHandlers[err.Type]; exists {
		return handler(ctx, err)
	}
	return nil
}

func (eh *ErrorHandler) setupDefaultRecoveryHandlers() {
	// Rate limit recovery: wait and retry
	eh.recoveryHandlers[ErrorTypeRateLimit] = func(ctx context.Context, err *ClassifiedError) error {
		if retryAfter, ok := err.Context["retry_after"].(time.Duration); ok {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(retryAfter):
				return nil
			}
		}
		return nil
	}

	// Connection recovery: attempt reconnection
	eh.recoveryHandlers[ErrorTypeConnection] = func(ctx context.Context, err *ClassifiedError) error {
		eh.logger.Info("Attempting connection recovery")
		// This would implement connection recovery logic
		return nil
	}
}

// AddNotificationHandler adds an error notification handler
func (eh *ErrorHandler) AddNotificationHandler(handler func(*ClassifiedError)) {
	eh.notificationHandlers = append(eh.notificationHandlers, handler)
}

// AddRecoveryHandler adds a recovery handler for a specific error type
func (eh *ErrorHandler) AddRecoveryHandler(errorType ErrorType, handler func(context.Context, *ClassifiedError) error) {
	eh.recoveryHandlers[errorType] = handler
}

// GetCircuitBreakerStatus returns the status of all circuit breakers
func (eh *ErrorHandler) GetCircuitBreakerStatus() map[string]ErrorCircuitBreakerState {
	eh.mutex.RLock()
	defer eh.mutex.RUnlock()

	status := make(map[string]ErrorCircuitBreakerState)
	for name, breaker := range eh.circuitBreakers {
		status[name] = breaker.GetState()
	}

	return status
}

// SetRetryPolicy sets a custom retry policy
func (eh *ErrorHandler) SetRetryPolicy(policy *RetryPolicy) {
	eh.retryPolicy = policy
}

// Helper function to check if string contains any of the given substrings
func contains(s string, substrings ...string) bool {
	for _, substring := range substrings {
		if len(s) >= len(substring) {
			for i := 0; i <= len(s)-len(substring); i++ {
				if s[i:i+len(substring)] == substring {
					return true
				}
			}
		}
	}
	return false
}
