package services

import (
	"context"
	"testing"
	"time"

	"api-translation-platform/internal/config"
	"api-translation-platform/internal/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func createTestLoggerForNotification() *logger.Logger {
	cfg := &config.Config{
		Logging: config.LoggingConfig{
			Level:  "info",
			Format: "text",
		},
	}
	return logger.NewLogger(cfg)
}

// Mock implementations for testing
type MockEmailSender struct {
	mock.Mock
}

func (m *MockEmailSender) SendEmail(ctx context.Context, to []string, subject, body string) error {
	args := m.Called(ctx, to, subject, body)
	return args.Error(0)
}

type MockSlackSender struct {
	mock.Mock
}

func (m *MockSlackSender) SendSlackMessage(ctx context.Context, channel, message string) error {
	args := m.Called(ctx, channel, message)
	return args.Error(0)
}

type MockWebhookSender struct {
	mock.Mock
}

func (m *MockWebhookSender) SendWebhook(ctx context.Context, url string, payload interface{}) error {
	args := m.Called(ctx, url, payload)
	return args.Error(0)
}

func TestNotificationRuleMatching(t *testing.T) {
	logger := createTestLoggerForNotification()
	ns := NewNotificationService(logger)

	// Add a test rule
	rule := &NotificationRule{
		ID:         "test_rule",
		Name:       "Test Rule",
		ErrorTypes: []ErrorType{ErrorTypeConnection, ErrorTypeTimeout},
		Severities: []ErrorSeverity{SeverityHigh},
		Channels:   []NotificationChannel{ChannelLog},
		Threshold:  1,
		TimeWindow: time.Minute,
		Cooldown:   time.Minute,
		Enabled:    true,
	}
	ns.AddRule(rule)

	tests := []struct {
		name        string
		error       *ClassifiedError
		orgID       string
		shouldMatch bool
	}{
		{
			name: "matching error type and severity",
			error: &ClassifiedError{
				Type:     ErrorTypeConnection,
				Severity: SeverityHigh,
			},
			shouldMatch: true,
		},
		{
			name: "matching error type, wrong severity",
			error: &ClassifiedError{
				Type:     ErrorTypeConnection,
				Severity: SeverityLow,
			},
			shouldMatch: false,
		},
		{
			name: "wrong error type, matching severity",
			error: &ClassifiedError{
				Type:     ErrorTypeAuth,
				Severity: SeverityHigh,
			},
			shouldMatch: false,
		},
		{
			name: "matching timeout error",
			error: &ClassifiedError{
				Type:     ErrorTypeTimeout,
				Severity: SeverityHigh,
			},
			shouldMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ns.shouldNotify(tt.error, rule, tt.orgID)
			assert.Equal(t, tt.shouldMatch, result)
		})
	}
}

func TestNotificationThreshold(t *testing.T) {
	logger := createTestLoggerForNotification()
	ns := NewNotificationService(logger)

	// Add a rule with threshold > 1
	rule := &NotificationRule{
		ID:         "threshold_rule",
		Name:       "Threshold Rule",
		ErrorTypes: []ErrorType{ErrorTypeConnection},
		Severities: []ErrorSeverity{SeverityMedium},
		Channels:   []NotificationChannel{ChannelLog},
		Threshold:  3, // Require 3 errors before notification
		TimeWindow: time.Minute,
		Cooldown:   time.Minute,
		Enabled:    true,
	}
	ns.AddRule(rule)

	err := &ClassifiedError{
		Type:     ErrorTypeConnection,
		Severity: SeverityMedium,
	}

	// First two errors should not trigger notification
	assert.False(t, ns.shouldNotify(err, rule, "org1"))
	assert.False(t, ns.shouldNotify(err, rule, "org1"))

	// Third error should trigger notification
	assert.True(t, ns.shouldNotify(err, rule, "org1"))

	// Fourth error should not trigger (counter reset after notification)
	assert.False(t, ns.shouldNotify(err, rule, "org1"))
}

func TestNotificationCooldown(t *testing.T) {
	logger := createTestLoggerForNotification()
	ns := NewNotificationService(logger)

	rule := &NotificationRule{
		ID:               "cooldown_rule",
		Name:             "Cooldown Rule",
		ErrorTypes:       []ErrorType{ErrorTypeConnection},
		Channels:         []NotificationChannel{ChannelLog},
		Threshold:        1,
		TimeWindow:       time.Minute,
		Cooldown:         100 * time.Millisecond,
		Enabled:          true,
		LastNotification: time.Now(), // Set recent notification
	}
	ns.AddRule(rule)

	err := &ClassifiedError{
		Type:     ErrorTypeConnection,
		Severity: SeverityMedium,
	}

	// Should not notify due to cooldown
	assert.False(t, ns.shouldNotify(err, rule, "org1"))

	// Wait for cooldown to expire
	time.Sleep(150 * time.Millisecond)

	// Should notify now
	assert.True(t, ns.shouldNotify(err, rule, "org1"))
}

func TestNotificationTimeWindow(t *testing.T) {
	logger := createTestLoggerForNotification()
	ns := NewNotificationService(logger)

	rule := &NotificationRule{
		ID:         "window_rule",
		Name:       "Window Rule",
		ErrorTypes: []ErrorType{ErrorTypeConnection},
		Channels:   []NotificationChannel{ChannelLog},
		Threshold:  2,
		TimeWindow: 50 * time.Millisecond, // Short window for testing
		Cooldown:   time.Millisecond,
		Enabled:    true,
	}
	ns.AddRule(rule)

	err := &ClassifiedError{
		Type:     ErrorTypeConnection,
		Severity: SeverityMedium,
	}

	// First error
	assert.False(t, ns.shouldNotify(err, rule, "org1"))

	// Wait for time window to expire
	time.Sleep(60 * time.Millisecond)

	// Second error after window - should reset counter
	assert.False(t, ns.shouldNotify(err, rule, "org1"))

	// Third error within new window
	assert.True(t, ns.shouldNotify(err, rule, "org1"))
}

func TestOrganisationScopedRules(t *testing.T) {
	logger := createTestLoggerForNotification()
	ns := NewNotificationService(logger)

	// Add organisation-specific rule
	rule := &NotificationRule{
		ID:             "org_rule",
		Name:           "Org Rule",
		ErrorTypes:     []ErrorType{ErrorTypeConnection},
		Channels:       []NotificationChannel{ChannelLog},
		Threshold:      1,
		TimeWindow:     time.Minute,
		Cooldown:       time.Millisecond,
		OrganisationID: "org1",
		Enabled:        true,
	}
	ns.AddRule(rule)

	err := &ClassifiedError{
		Type:     ErrorTypeConnection,
		Severity: SeverityMedium,
	}

	// Should match for org1
	assert.True(t, ns.shouldNotify(err, rule, "org1"))

	// Should not match for org2
	assert.False(t, ns.shouldNotify(err, rule, "org2"))

	// Should not match for empty org
	assert.False(t, ns.shouldNotify(err, rule, ""))
}

func TestNotificationMessageGeneration(t *testing.T) {
	logger := createTestLoggerForNotification()
	ns := NewNotificationService(logger)

	rule := &NotificationRule{
		ID:   "test_rule",
		Name: "Test Rule",
	}

	err := &ClassifiedError{
		Type:      ErrorTypeConnection,
		Severity:  SeverityHigh,
		Message:   "Connection failed",
		Timestamp: time.Now(),
		Context: map[string]interface{}{
			"organisation_id": "org1",
			"operation":       "rest_request",
		},
	}

	title := ns.generateTitle(err, rule)
	message := ns.generateMessage(err, rule)

	assert.Contains(t, title, "high")
	assert.Contains(t, title, "connection")
	assert.Contains(t, title, "Connection failed")

	assert.Contains(t, message, "Type: connection")
	assert.Contains(t, message, "Severity: high")
	assert.Contains(t, message, "Organisation: org1")
	assert.Contains(t, message, "Operation: rest_request")
}

func TestSeverityToLevelMapping(t *testing.T) {
	logger := createTestLoggerForNotification()
	ns := NewNotificationService(logger)

	tests := []struct {
		severity      ErrorSeverity
		expectedLevel NotificationLevel
	}{
		{SeverityLow, NotificationLevelInfo},
		{SeverityMedium, NotificationLevelWarning},
		{SeverityHigh, NotificationLevelError},
		{SeverityCritical, NotificationLevelCritical},
	}

	for _, tt := range tests {
		t.Run(string(tt.severity), func(t *testing.T) {
			level := ns.mapSeverityToLevel(tt.severity)
			assert.Equal(t, tt.expectedLevel, level)
		})
	}
}

func TestNotificationChannelSending(t *testing.T) {
	logger := createTestLoggerForNotification()
	ns := NewNotificationService(logger)

	// Set up mock senders
	mockEmail := &MockEmailSender{}
	mockSlack := &MockSlackSender{}
	mockWebhook := &MockWebhookSender{}

	ns.SetEmailSender(mockEmail)
	ns.SetSlackSender(mockSlack)
	ns.SetWebhookSender(mockWebhook)

	message := &NotificationMessage{
		ID:      "test_msg",
		Title:   "Test Alert",
		Message: "Test message body",
		Level:   NotificationLevelError,
	}

	ctx := context.Background()

	t.Run("email channel", func(t *testing.T) {
		mockEmail.On("SendEmail", ctx, []string{"admin@example.com"}, "Test Alert", "Test message body").Return(nil)

		err := ns.sendToChannel(ctx, message, ChannelEmail)
		assert.NoError(t, err)

		mockEmail.AssertExpectations(t)
	})

	t.Run("slack channel", func(t *testing.T) {
		expectedSlackMsg := "🚨 *Test Alert*\n```Test message body```"
		mockSlack.On("SendSlackMessage", ctx, "#alerts", expectedSlackMsg).Return(nil)

		err := ns.sendToChannel(ctx, message, ChannelSlack)
		assert.NoError(t, err)

		mockSlack.AssertExpectations(t)
	})

	t.Run("webhook channel", func(t *testing.T) {
		mockWebhook.On("SendWebhook", ctx, "https://example.com/webhook", message).Return(nil)

		err := ns.sendToChannel(ctx, message, ChannelWebhook)
		assert.NoError(t, err)

		mockWebhook.AssertExpectations(t)
	})

	t.Run("log channel", func(t *testing.T) {
		err := ns.sendToChannel(ctx, message, ChannelLog)
		assert.NoError(t, err)
	})

	t.Run("database channel", func(t *testing.T) {
		err := ns.sendToChannel(ctx, message, ChannelDatabase)
		assert.NoError(t, err)
	})

	t.Run("unsupported channel", func(t *testing.T) {
		err := ns.sendToChannel(ctx, message, NotificationChannel("unsupported"))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported notification channel")
	})
}

func TestNotificationProcessing(t *testing.T) {
	logger := createTestLoggerForNotification()
	ns := NewNotificationService(logger)

	// Add a rule that should trigger
	rule := &NotificationRule{
		ID:         "process_rule",
		Name:       "Process Rule",
		ErrorTypes: []ErrorType{ErrorTypeConnection},
		Channels:   []NotificationChannel{ChannelLog},
		Threshold:  1,
		TimeWindow: time.Minute,
		Cooldown:   time.Millisecond,
		Enabled:    true,
	}
	ns.AddRule(rule)

	err := &ClassifiedError{
		Type:     ErrorTypeConnection,
		Severity: SeverityMedium,
		Message:  "Test connection error",
		Context: map[string]interface{}{
			"organisation_id": "org1",
		},
	}

	// Process the error
	ns.ProcessError(context.Background(), err)

	// Give some time for async processing
	time.Sleep(100 * time.Millisecond)

	// Verify rule's last notification time was updated
	rules := ns.GetRules()
	updatedRule := rules["process_rule"]
	assert.True(t, time.Since(updatedRule.LastNotification) < time.Second)
}

func TestNotificationRuleManagement(t *testing.T) {
	logger := createTestLoggerForNotification()
	ns := NewNotificationService(logger)

	rule := &NotificationRule{
		ID:      "mgmt_rule",
		Name:    "Management Rule",
		Enabled: true,
	}

	// Add rule
	ns.AddRule(rule)
	rules := ns.GetRules()
	assert.Len(t, rules, 4) // 3 default + 1 added
	assert.Equal(t, "Management Rule", rules["mgmt_rule"].Name)

	// Remove rule
	ns.RemoveRule("mgmt_rule")
	rules = ns.GetRules()
	assert.Len(t, rules, 3) // Back to 3 default rules
	assert.NotContains(t, rules, "mgmt_rule")
}

func TestNotificationStats(t *testing.T) {
	logger := createTestLoggerForNotification()
	ns := NewNotificationService(logger)

	// Add some rules
	ns.AddRule(&NotificationRule{
		ID:      "stats_rule_1",
		Enabled: true,
	})
	ns.AddRule(&NotificationRule{
		ID:      "stats_rule_2",
		Enabled: false,
	})

	stats := ns.GetStats()

	assert.Equal(t, 5, stats["total_rules"])    // 3 default + 2 added
	assert.Equal(t, 4, stats["active_rules"])   // 3 default + 1 enabled
	assert.Equal(t, 0, stats["total_counters"]) // No errors processed yet
	assert.Equal(t, 0, stats["queue_size"])     // No messages queued
}

func TestDefaultNotificationRules(t *testing.T) {
	logger := createTestLoggerForNotification()
	ns := NewNotificationService(logger)

	rules := ns.GetRules()

	// Should have default rules
	assert.Contains(t, rules, "critical_errors")
	assert.Contains(t, rules, "high_severity_errors")
	assert.Contains(t, rules, "circuit_breaker_open")

	// Check critical errors rule
	criticalRule := rules["critical_errors"]
	assert.True(t, criticalRule.Enabled)
	assert.Contains(t, criticalRule.Severities, SeverityCritical)
	assert.Equal(t, 1, criticalRule.Threshold)

	// Check high severity rule
	highSevRule := rules["high_severity_errors"]
	assert.True(t, highSevRule.Enabled)
	assert.Contains(t, highSevRule.Severities, SeverityHigh)
	assert.Equal(t, 5, highSevRule.Threshold)

	// Check circuit breaker rule
	circuitRule := rules["circuit_breaker_open"]
	assert.True(t, circuitRule.Enabled)
	assert.Contains(t, circuitRule.ErrorTypes, ErrorTypeCircuit)
	assert.Equal(t, 1, circuitRule.Threshold)
}

// Benchmark tests
func BenchmarkNotificationRuleMatching(b *testing.B) {
	logger := createTestLoggerForNotification()
	ns := NewNotificationService(logger)

	rule := &NotificationRule{
		ID:         "bench_rule",
		ErrorTypes: []ErrorType{ErrorTypeConnection, ErrorTypeTimeout},
		Severities: []ErrorSeverity{SeverityHigh, SeverityMedium},
		Enabled:    true,
		Threshold:  1,
		Cooldown:   time.Millisecond,
	}

	err := &ClassifiedError{
		Type:     ErrorTypeConnection,
		Severity: SeverityHigh,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ns.shouldNotify(err, rule, "org1")
	}
}

func BenchmarkNotificationMessageGeneration(b *testing.B) {
	logger := createTestLoggerForNotification()
	ns := NewNotificationService(logger)

	rule := &NotificationRule{
		ID:   "bench_rule",
		Name: "Benchmark Rule",
	}

	err := &ClassifiedError{
		Type:      ErrorTypeConnection,
		Severity:  SeverityHigh,
		Message:   "Connection failed",
		Timestamp: time.Now(),
		Context: map[string]interface{}{
			"organisation_id": "org1",
			"operation":       "rest_request",
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ns.generateTitle(err, rule)
		ns.generateMessage(err, rule)
	}
}
