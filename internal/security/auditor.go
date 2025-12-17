package security

import (
	"context"
	"time"
)

// SecurityEventType represents the type of security event
type SecurityEventType string

const (
	SecurityEventAuthFailure        SecurityEventType = "auth_failure"
	SecurityEventAuthzViolation     SecurityEventType = "authz_violation"
	SecurityEventInputValidation    SecurityEventType = "input_validation"
	SecurityEventSuspiciousActivity SecurityEventType = "suspicious_activity"
	SecurityEventRateLimit          SecurityEventType = "rate_limit"
	SecurityEventDataBreach         SecurityEventType = "data_breach"
)

// SecuritySeverity represents the severity of a security event
type SecuritySeverity string

const (
	SecuritySeverityLow      SecuritySeverity = "low"
	SecuritySeverityMedium   SecuritySeverity = "medium"
	SecuritySeverityHigh     SecuritySeverity = "high"
	SecuritySeverityCritical SecuritySeverity = "critical"
)

// SecurityEvent represents a security-related event
type SecurityEvent struct {
	ID         string            `json:"id"`
	Type       SecurityEventType `json:"type"`
	Severity   SecuritySeverity  `json:"severity"`
	Timestamp  time.Time         `json:"timestamp"`
	UserID     string            `json:"user_id,omitempty"`
	IPAddress  string            `json:"ip_address,omitempty"`
	UserAgent  string            `json:"user_agent,omitempty"`
	ResourceID string            `json:"resource_id,omitempty"`
	Action     string            `json:"action,omitempty"`
	Details    string            `json:"details"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

// AuditLogger interface for logging security events
type AuditLogger interface {
	LogSecurityEvent(ctx context.Context, event SecurityEvent) error
}

// SecurityAuditor handles security event auditing
type SecurityAuditor struct {
	logger AuditLogger
}

// NewSecurityAuditor creates a new security auditor
func NewSecurityAuditor(logger AuditLogger) *SecurityAuditor {
	return &SecurityAuditor{
		logger: logger,
	}
}

// LogAuthenticationFailure logs authentication failure events
func (a *SecurityAuditor) LogAuthenticationFailure(ctx context.Context, userID, ipAddress, details string) error {
	event := SecurityEvent{
		ID:        generateEventID(),
		Type:      SecurityEventAuthFailure,
		Severity:  SecuritySeverityMedium,
		Timestamp: time.Now().UTC(),
		UserID:    userID,
		IPAddress: ipAddress,
		Action:    "authentication_failed",
		Details:   details,
	}

	return a.logger.LogSecurityEvent(ctx, event)
}

// LogAuthorizationViolation logs authorization violation events
func (a *SecurityAuditor) LogAuthorizationViolation(ctx context.Context, userID, resourceID, details string) error {
	event := SecurityEvent{
		ID:         generateEventID(),
		Type:       SecurityEventAuthzViolation,
		Severity:   SecuritySeverityHigh,
		Timestamp:  time.Now().UTC(),
		UserID:     userID,
		ResourceID: resourceID,
		Action:     "authorization_violation",
		Details:    details,
	}

	return a.logger.LogSecurityEvent(ctx, event)
}

// LogInputValidationFailure logs input validation failure events
func (a *SecurityAuditor) LogInputValidationFailure(ctx context.Context, ipAddress, details, maliciousInput string) error {
	event := SecurityEvent{
		ID:        generateEventID(),
		Type:      SecurityEventInputValidation,
		Severity:  SecuritySeverityMedium,
		Timestamp: time.Now().UTC(),
		IPAddress: ipAddress,
		Action:    "input_validation_failed",
		Details:   details,
		Metadata: map[string]string{
			"malicious_input": maliciousInput,
		},
	}

	return a.logger.LogSecurityEvent(ctx, event)
}

// LogSuspiciousActivity logs suspicious activity events
func (a *SecurityAuditor) LogSuspiciousActivity(ctx context.Context, userID, ipAddress, details string) error {
	event := SecurityEvent{
		ID:        generateEventID(),
		Type:      SecurityEventSuspiciousActivity,
		Severity:  SecuritySeverityHigh,
		Timestamp: time.Now().UTC(),
		UserID:    userID,
		IPAddress: ipAddress,
		Action:    "suspicious_activity",
		Details:   details,
	}

	return a.logger.LogSecurityEvent(ctx, event)
}

// LogRateLimitViolation logs rate limit violation events
func (a *SecurityAuditor) LogRateLimitViolation(ctx context.Context, ipAddress, details string) error {
	event := SecurityEvent{
		ID:        generateEventID(),
		Type:      SecurityEventRateLimit,
		Severity:  SecuritySeverityLow,
		Timestamp: time.Now().UTC(),
		IPAddress: ipAddress,
		Action:    "rate_limit_exceeded",
		Details:   details,
	}

	return a.logger.LogSecurityEvent(ctx, event)
}

// LogDataBreachAttempt logs potential data breach attempts
func (a *SecurityAuditor) LogDataBreachAttempt(ctx context.Context, userID, ipAddress, resourceID, details string) error {
	event := SecurityEvent{
		ID:         generateEventID(),
		Type:       SecurityEventDataBreach,
		Severity:   SecuritySeverityCritical,
		Timestamp:  time.Now().UTC(),
		UserID:     userID,
		IPAddress:  ipAddress,
		ResourceID: resourceID,
		Action:     "data_breach_attempt",
		Details:    details,
	}

	return a.logger.LogSecurityEvent(ctx, event)
}

// generateEventID generates a unique event ID
func generateEventID() string {
	// In a real implementation, this would generate a proper UUID
	return time.Now().Format("20060102150405") + "-" + "security-event"
}
