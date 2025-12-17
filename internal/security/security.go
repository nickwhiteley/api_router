package security

import (
	"context"
	"net/http"

	"api-translation-platform/internal/logger"
)

// SecurityManager manages all security-related functionality
type SecurityManager struct {
	inputValidator    *InputValidator
	middleware        *SecurityMiddleware
	auditor           *SecurityAuditor
	passwordValidator *PasswordValidator
	configValidator   *SecurityConfigValidator
	rateLimiter       *RateLimiter
	logger            *logger.Logger
}

// NewSecurityManager creates a new security manager
func NewSecurityManager(logger *logger.Logger, auditLogger AuditLogger) *SecurityManager {
	return &SecurityManager{
		inputValidator:    NewInputValidator(),
		middleware:        NewSecurityMiddleware(),
		auditor:           NewSecurityAuditor(auditLogger),
		passwordValidator: NewPasswordValidator(),
		configValidator:   NewSecurityConfigValidator(),
		rateLimiter:       NewRateLimiter(),
		logger:            logger,
	}
}

// GetSecurityMiddleware returns the security middleware stack
func (sm *SecurityManager) GetSecurityMiddleware() []func(http.Handler) http.Handler {
	return []func(http.Handler) http.Handler{
		sm.middleware.SecurityHeaders,
		sm.middleware.CORS,
		sm.middleware.HostValidation,
		sm.middleware.RateLimit,
		sm.middleware.InputValidation,
	}
}

// ValidateInput validates and sanitizes input
func (sm *SecurityManager) ValidateInput(input string) (string, error) {
	return sm.inputValidator.SanitizeInput(input)
}

// ValidatePassword validates password strength
func (sm *SecurityManager) ValidatePassword(password string) error {
	return sm.passwordValidator.ValidatePassword(password)
}

// LogSecurityEvent logs a security event
func (sm *SecurityManager) LogSecurityEvent(ctx context.Context, eventType SecurityEventType, userID, ipAddress, details string) error {
	switch eventType {
	case SecurityEventAuthFailure:
		return sm.auditor.LogAuthenticationFailure(ctx, userID, ipAddress, details)
	case SecurityEventAuthzViolation:
		return sm.auditor.LogAuthorizationViolation(ctx, userID, ipAddress, details)
	case SecurityEventSuspiciousActivity:
		return sm.auditor.LogSuspiciousActivity(ctx, userID, ipAddress, details)
	case SecurityEventRateLimit:
		return sm.auditor.LogRateLimitViolation(ctx, ipAddress, details)
	default:
		sm.logger.WithField("event_type", eventType).Warn("Unknown security event type")
		return nil
	}
}

// ValidateJWTConfig validates JWT configuration
func (sm *SecurityManager) ValidateJWTConfig(config JWTConfig) error {
	return sm.configValidator.ValidateJWTConfig(config)
}

// ValidateCORSConfig validates CORS configuration
func (sm *SecurityManager) ValidateCORSConfig(config CORSConfig) error {
	return sm.configValidator.ValidateCORSConfig(config)
}

// GetRateLimitStats returns rate limiting statistics
func (sm *SecurityManager) GetRateLimitStats() map[string]interface{} {
	return sm.rateLimiter.GetStats()
}

// DatabaseAuditLogger implements AuditLogger interface using database
type DatabaseAuditLogger struct {
	logger    *logger.Logger
	auditRepo AuditRepository
}

// AuditRepository interface for audit log storage
type AuditRepository interface {
	CreateSecurityEvent(ctx context.Context, event *SecurityEvent) error
	GetSecurityEvents(ctx context.Context, filters map[string]interface{}) ([]*SecurityEvent, error)
}

// NewDatabaseAuditLogger creates a new database audit logger
func NewDatabaseAuditLogger(logger *logger.Logger, auditRepo AuditRepository) *DatabaseAuditLogger {
	return &DatabaseAuditLogger{
		logger:    logger,
		auditRepo: auditRepo,
	}
}

// LogSecurityEvent logs a security event to the database
func (dal *DatabaseAuditLogger) LogSecurityEvent(ctx context.Context, event SecurityEvent) error {
	if err := dal.auditRepo.CreateSecurityEvent(ctx, &event); err != nil {
		dal.logger.WithError(err).Error("Failed to log security event to database")
		return err
	}

	// Also log to application logs for immediate visibility
	dal.logger.WithFields(map[string]interface{}{
		"event_id":    event.ID,
		"event_type":  event.Type,
		"severity":    event.Severity,
		"user_id":     event.UserID,
		"ip_address":  event.IPAddress,
		"resource_id": event.ResourceID,
		"action":      event.Action,
	}).Warn("Security event logged")

	return nil
}

// SecurityEventFilter represents filters for querying security events
type SecurityEventFilter struct {
	EventType  SecurityEventType `json:"event_type,omitempty"`
	Severity   SecuritySeverity  `json:"severity,omitempty"`
	UserID     string            `json:"user_id,omitempty"`
	IPAddress  string            `json:"ip_address,omitempty"`
	ResourceID string            `json:"resource_id,omitempty"`
	StartTime  string            `json:"start_time,omitempty"`
	EndTime    string            `json:"end_time,omitempty"`
	Limit      int               `json:"limit,omitempty"`
	Offset     int               `json:"offset,omitempty"`
}

// GetSecurityEvents retrieves security events based on filters
func (dal *DatabaseAuditLogger) GetSecurityEvents(ctx context.Context, filter SecurityEventFilter) ([]*SecurityEvent, error) {
	filters := make(map[string]interface{})

	if filter.EventType != "" {
		filters["event_type"] = filter.EventType
	}
	if filter.Severity != "" {
		filters["severity"] = filter.Severity
	}
	if filter.UserID != "" {
		filters["user_id"] = filter.UserID
	}
	if filter.IPAddress != "" {
		filters["ip_address"] = filter.IPAddress
	}
	if filter.ResourceID != "" {
		filters["resource_id"] = filter.ResourceID
	}
	if filter.StartTime != "" {
		filters["start_time"] = filter.StartTime
	}
	if filter.EndTime != "" {
		filters["end_time"] = filter.EndTime
	}
	if filter.Limit > 0 {
		filters["limit"] = filter.Limit
	}
	if filter.Offset > 0 {
		filters["offset"] = filter.Offset
	}

	return dal.auditRepo.GetSecurityEvents(ctx, filters)
}

// SecurityMetrics represents security-related metrics
type SecurityMetrics struct {
	AuthFailures         int64 `json:"auth_failures"`
	AuthzViolations      int64 `json:"authz_violations"`
	InputValidationFails int64 `json:"input_validation_fails"`
	RateLimitHits        int64 `json:"rate_limit_hits"`
	SuspiciousActivities int64 `json:"suspicious_activities"`
	TotalSecurityEvents  int64 `json:"total_security_events"`
}

// GetSecurityMetrics calculates security metrics
func (sm *SecurityManager) GetSecurityMetrics(ctx context.Context, auditLogger *DatabaseAuditLogger) (*SecurityMetrics, error) {
	metrics := &SecurityMetrics{}

	// Get counts for each event type
	eventTypes := []SecurityEventType{
		SecurityEventAuthFailure,
		SecurityEventAuthzViolation,
		SecurityEventInputValidation,
		SecurityEventRateLimit,
		SecurityEventSuspiciousActivity,
	}

	for _, eventType := range eventTypes {
		events, err := auditLogger.GetSecurityEvents(ctx, SecurityEventFilter{
			EventType: eventType,
			Limit:     1, // We just need the count
		})
		if err != nil {
			sm.logger.WithError(err).WithField("event_type", eventType).Error("Failed to get security events count")
			continue
		}

		count := int64(len(events))
		switch eventType {
		case SecurityEventAuthFailure:
			metrics.AuthFailures = count
		case SecurityEventAuthzViolation:
			metrics.AuthzViolations = count
		case SecurityEventInputValidation:
			metrics.InputValidationFails = count
		case SecurityEventRateLimit:
			metrics.RateLimitHits = count
		case SecurityEventSuspiciousActivity:
			metrics.SuspiciousActivities = count
		}

		metrics.TotalSecurityEvents += count
	}

	return metrics, nil
}
