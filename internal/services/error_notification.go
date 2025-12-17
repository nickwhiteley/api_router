package services

import (
	"context"
	"fmt"
	"sync"
	"time"

	"api-translation-platform/internal/logger"
)

// NotificationLevel represents the level of notification
type NotificationLevel string

const (
	NotificationLevelInfo     NotificationLevel = "info"
	NotificationLevelWarning  NotificationLevel = "warning"
	NotificationLevelError    NotificationLevel = "error"
	NotificationLevelCritical NotificationLevel = "critical"
)

// NotificationChannel represents different notification channels
type NotificationChannel string

const (
	ChannelEmail    NotificationChannel = "email"
	ChannelSlack    NotificationChannel = "slack"
	ChannelWebhook  NotificationChannel = "webhook"
	ChannelDatabase NotificationChannel = "database"
	ChannelLog      NotificationChannel = "log"
)

// NotificationRule defines when and how to send notifications
type NotificationRule struct {
	ID               string                `json:"id"`
	Name             string                `json:"name"`
	ErrorTypes       []ErrorType           `json:"error_types"`
	Severities       []ErrorSeverity       `json:"severities"`
	Channels         []NotificationChannel `json:"channels"`
	Threshold        int                   `json:"threshold"`       // Number of errors before notification
	TimeWindow       time.Duration         `json:"time_window"`     // Time window for threshold
	Cooldown         time.Duration         `json:"cooldown"`        // Minimum time between notifications
	OrganisationID   string                `json:"organisation_id"` // Empty for global rules
	Enabled          bool                  `json:"enabled"`
	LastNotification time.Time             `json:"last_notification"`
}

// NotificationMessage represents a notification to be sent
type NotificationMessage struct {
	ID          string                 `json:"id"`
	Level       NotificationLevel      `json:"level"`
	Title       string                 `json:"title"`
	Message     string                 `json:"message"`
	Error       *ClassifiedError       `json:"error,omitempty"`
	Context     map[string]interface{} `json:"context"`
	Timestamp   time.Time              `json:"timestamp"`
	RuleID      string                 `json:"rule_id"`
	Channels    []NotificationChannel  `json:"channels"`
	Attempts    int                    `json:"attempts"`
	LastAttempt time.Time              `json:"last_attempt"`
	Status      string                 `json:"status"` // pending, sent, failed
}

// ErrorCounter tracks error occurrences for threshold-based notifications
type ErrorCounter struct {
	Count     int       `json:"count"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// NotificationService handles error notifications and escalation
type NotificationService struct {
	logger   *logger.Logger
	rules    map[string]*NotificationRule
	counters map[string]*ErrorCounter // key: ruleID_errorType_orgID
	mutex    sync.RWMutex

	// Notification channels
	emailSender   EmailSender
	slackSender   SlackSender
	webhookSender WebhookSender

	// Message queue for async processing
	messageQueue chan *NotificationMessage
	workers      int
	stopChan     chan struct{}
}

// EmailSender interface for email notifications
type EmailSender interface {
	SendEmail(ctx context.Context, to []string, subject, body string) error
}

// SlackSender interface for Slack notifications
type SlackSender interface {
	SendSlackMessage(ctx context.Context, channel, message string) error
}

// WebhookSender interface for webhook notifications
type WebhookSender interface {
	SendWebhook(ctx context.Context, url string, payload interface{}) error
}

// NewNotificationService creates a new notification service
func NewNotificationService(logger *logger.Logger) *NotificationService {
	ns := &NotificationService{
		logger:       logger,
		rules:        make(map[string]*NotificationRule),
		counters:     make(map[string]*ErrorCounter),
		messageQueue: make(chan *NotificationMessage, 1000),
		workers:      5,
		stopChan:     make(chan struct{}),
	}

	// Set up default notification rules
	ns.setupDefaultRules()

	// Start notification workers
	ns.startWorkers()

	return ns
}

// ProcessError processes an error and determines if notifications should be sent
func (ns *NotificationService) ProcessError(ctx context.Context, err *ClassifiedError) {
	ns.mutex.RLock()
	defer ns.mutex.RUnlock()

	orgID := ""
	if err.Context != nil {
		if id, ok := err.Context["organisation_id"].(string); ok {
			orgID = id
		}
	}

	for _, rule := range ns.rules {
		if ns.shouldNotify(err, rule, orgID) {
			ns.sendNotification(ctx, err, rule)
		}
	}
}

// shouldNotify determines if a notification should be sent based on the rule
func (ns *NotificationService) shouldNotify(err *ClassifiedError, rule *NotificationRule, orgID string) bool {
	if !rule.Enabled {
		return false
	}

	// Check organisation scope
	if rule.OrganisationID != "" && rule.OrganisationID != orgID {
		return false
	}

	// Check error type
	if len(rule.ErrorTypes) > 0 {
		found := false
		for _, errorType := range rule.ErrorTypes {
			if errorType == err.Type {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check severity
	if len(rule.Severities) > 0 {
		found := false
		for _, severity := range rule.Severities {
			if severity == err.Severity {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check cooldown period
	if time.Since(rule.LastNotification) < rule.Cooldown {
		return false
	}

	// Check threshold
	if rule.Threshold > 1 {
		counterKey := fmt.Sprintf("%s_%s_%s", rule.ID, err.Type, orgID)
		counter := ns.getOrCreateCounter(counterKey)

		// Reset counter if time window has passed
		if time.Since(counter.FirstSeen) > rule.TimeWindow {
			counter.Count = 0
			counter.FirstSeen = time.Now()
		}

		counter.Count++
		counter.LastSeen = time.Now()

		if counter.Count < rule.Threshold {
			return false
		}

		// Reset counter after notification
		counter.Count = 0
	}

	return true
}

// sendNotification creates and queues a notification message
func (ns *NotificationService) sendNotification(ctx context.Context, err *ClassifiedError, rule *NotificationRule) {
	level := ns.mapSeverityToLevel(err.Severity)

	message := &NotificationMessage{
		ID:        fmt.Sprintf("notif_%d", time.Now().UnixNano()),
		Level:     level,
		Title:     ns.generateTitle(err, rule),
		Message:   ns.generateMessage(err, rule),
		Error:     err,
		Context:   err.Context,
		Timestamp: time.Now(),
		RuleID:    rule.ID,
		Channels:  rule.Channels,
		Status:    "pending",
	}

	// Queue message for processing
	select {
	case ns.messageQueue <- message:
		ns.logger.WithField("notification_id", message.ID).
			WithField("rule_id", rule.ID).
			Info("Notification queued")
	default:
		ns.logger.WithField("rule_id", rule.ID).
			Error("Notification queue is full, dropping message")
	}

	// Update rule's last notification time
	rule.LastNotification = time.Now()
}

// generateTitle generates a notification title
func (ns *NotificationService) generateTitle(err *ClassifiedError, rule *NotificationRule) string {
	return fmt.Sprintf("[%s] %s Error: %s",
		string(err.Severity),
		string(err.Type),
		err.Message)
}

// generateMessage generates a detailed notification message
func (ns *NotificationService) generateMessage(err *ClassifiedError, rule *NotificationRule) string {
	msg := fmt.Sprintf("Error Details:\n")
	msg += fmt.Sprintf("Type: %s\n", err.Type)
	msg += fmt.Sprintf("Severity: %s\n", err.Severity)
	msg += fmt.Sprintf("Message: %s\n", err.Message)
	msg += fmt.Sprintf("Timestamp: %s\n", err.Timestamp.Format(time.RFC3339))

	if err.Context != nil {
		if orgID, ok := err.Context["organisation_id"].(string); ok {
			msg += fmt.Sprintf("Organisation: %s\n", orgID)
		}
		if operation, ok := err.Context["operation"].(string); ok {
			msg += fmt.Sprintf("Operation: %s\n", operation)
		}
	}

	if err.OriginalError != nil {
		msg += fmt.Sprintf("Original Error: %s\n", err.OriginalError.Error())
	}

	return msg
}

// mapSeverityToLevel maps error severity to notification level
func (ns *NotificationService) mapSeverityToLevel(severity ErrorSeverity) NotificationLevel {
	switch severity {
	case SeverityLow:
		return NotificationLevelInfo
	case SeverityMedium:
		return NotificationLevelWarning
	case SeverityHigh:
		return NotificationLevelError
	case SeverityCritical:
		return NotificationLevelCritical
	default:
		return NotificationLevelInfo
	}
}

// getOrCreateCounter gets or creates an error counter
func (ns *NotificationService) getOrCreateCounter(key string) *ErrorCounter {
	counter, exists := ns.counters[key]
	if !exists {
		counter = &ErrorCounter{
			Count:     0,
			FirstSeen: time.Now(),
			LastSeen:  time.Now(),
		}
		ns.counters[key] = counter
	}
	return counter
}

// startWorkers starts notification processing workers
func (ns *NotificationService) startWorkers() {
	for i := 0; i < ns.workers; i++ {
		go ns.worker()
	}
}

// worker processes notification messages
func (ns *NotificationService) worker() {
	for {
		select {
		case message := <-ns.messageQueue:
			ns.processMessage(message)
		case <-ns.stopChan:
			return
		}
	}
}

// processMessage processes a single notification message
func (ns *NotificationService) processMessage(message *NotificationMessage) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	message.Attempts++
	message.LastAttempt = time.Now()

	success := true
	for _, channel := range message.Channels {
		if err := ns.sendToChannel(ctx, message, channel); err != nil {
			ns.logger.WithError(err).
				WithField("notification_id", message.ID).
				WithField("channel", string(channel)).
				Error("Failed to send notification")
			success = false
		}
	}

	if success {
		message.Status = "sent"
		ns.logger.WithField("notification_id", message.ID).
			Info("Notification sent successfully")
	} else {
		message.Status = "failed"

		// Retry logic for failed notifications
		if message.Attempts < 3 {
			// Requeue with exponential backoff
			go func() {
				delay := time.Duration(message.Attempts*message.Attempts) * time.Second
				time.Sleep(delay)

				select {
				case ns.messageQueue <- message:
				default:
					ns.logger.WithField("notification_id", message.ID).
						Error("Failed to requeue notification")
				}
			}()
		}
	}
}

// sendToChannel sends a notification to a specific channel
func (ns *NotificationService) sendToChannel(ctx context.Context, message *NotificationMessage, channel NotificationChannel) error {
	switch channel {
	case ChannelEmail:
		return ns.sendEmailNotification(ctx, message)
	case ChannelSlack:
		return ns.sendSlackNotification(ctx, message)
	case ChannelWebhook:
		return ns.sendWebhookNotification(ctx, message)
	case ChannelDatabase:
		return ns.sendDatabaseNotification(ctx, message)
	case ChannelLog:
		return ns.sendLogNotification(ctx, message)
	default:
		return fmt.Errorf("unsupported notification channel: %s", channel)
	}
}

// sendEmailNotification sends an email notification
func (ns *NotificationService) sendEmailNotification(ctx context.Context, message *NotificationMessage) error {
	if ns.emailSender == nil {
		return fmt.Errorf("email sender not configured")
	}

	// This would be configured based on the rule or organisation settings
	recipients := []string{"admin@example.com"}

	return ns.emailSender.SendEmail(ctx, recipients, message.Title, message.Message)
}

// sendSlackNotification sends a Slack notification
func (ns *NotificationService) sendSlackNotification(ctx context.Context, message *NotificationMessage) error {
	if ns.slackSender == nil {
		return fmt.Errorf("slack sender not configured")
	}

	// Format message for Slack
	slackMessage := fmt.Sprintf("🚨 *%s*\n```%s```", message.Title, message.Message)

	return ns.slackSender.SendSlackMessage(ctx, "#alerts", slackMessage)
}

// sendWebhookNotification sends a webhook notification
func (ns *NotificationService) sendWebhookNotification(ctx context.Context, message *NotificationMessage) error {
	if ns.webhookSender == nil {
		return fmt.Errorf("webhook sender not configured")
	}

	// This would be configured based on the rule
	webhookURL := "https://example.com/webhook"

	return ns.webhookSender.SendWebhook(ctx, webhookURL, message)
}

// sendDatabaseNotification stores notification in database
func (ns *NotificationService) sendDatabaseNotification(ctx context.Context, message *NotificationMessage) error {
	// This would store the notification in a database table
	ns.logger.WithField("notification_id", message.ID).
		Info("Notification stored in database")
	return nil
}

// sendLogNotification logs the notification
func (ns *NotificationService) sendLogNotification(ctx context.Context, message *NotificationMessage) error {
	logEntry := ns.logger.WithField("notification_id", message.ID).
		WithField("level", string(message.Level)).
		WithField("rule_id", message.RuleID)

	switch message.Level {
	case NotificationLevelInfo:
		logEntry.Info(message.Message)
	case NotificationLevelWarning:
		logEntry.Warn(message.Message)
	case NotificationLevelError:
		logEntry.Error(message.Message)
	case NotificationLevelCritical:
		logEntry.Error(message.Message)
	}

	return nil
}

// setupDefaultRules sets up default notification rules
func (ns *NotificationService) setupDefaultRules() {
	// Critical errors - immediate notification
	ns.AddRule(&NotificationRule{
		ID:         "critical_errors",
		Name:       "Critical Errors",
		Severities: []ErrorSeverity{SeverityCritical},
		Channels:   []NotificationChannel{ChannelLog, ChannelDatabase},
		Threshold:  1,
		TimeWindow: time.Minute,
		Cooldown:   time.Minute,
		Enabled:    true,
	})

	// High severity errors - threshold-based
	ns.AddRule(&NotificationRule{
		ID:         "high_severity_errors",
		Name:       "High Severity Errors",
		Severities: []ErrorSeverity{SeverityHigh},
		Channels:   []NotificationChannel{ChannelLog, ChannelDatabase},
		Threshold:  5,
		TimeWindow: 5 * time.Minute,
		Cooldown:   10 * time.Minute,
		Enabled:    true,
	})

	// Circuit breaker notifications
	ns.AddRule(&NotificationRule{
		ID:         "circuit_breaker_open",
		Name:       "Circuit Breaker Open",
		ErrorTypes: []ErrorType{ErrorTypeCircuit},
		Channels:   []NotificationChannel{ChannelLog, ChannelDatabase},
		Threshold:  1,
		TimeWindow: time.Minute,
		Cooldown:   5 * time.Minute,
		Enabled:    true,
	})
}

// AddRule adds a new notification rule
func (ns *NotificationService) AddRule(rule *NotificationRule) {
	ns.mutex.Lock()
	defer ns.mutex.Unlock()

	ns.rules[rule.ID] = rule
}

// RemoveRule removes a notification rule
func (ns *NotificationService) RemoveRule(ruleID string) {
	ns.mutex.Lock()
	defer ns.mutex.Unlock()

	delete(ns.rules, ruleID)
}

// GetRules returns all notification rules
func (ns *NotificationService) GetRules() map[string]*NotificationRule {
	ns.mutex.RLock()
	defer ns.mutex.RUnlock()

	rules := make(map[string]*NotificationRule)
	for id, rule := range ns.rules {
		rules[id] = rule
	}

	return rules
}

// SetEmailSender sets the email sender
func (ns *NotificationService) SetEmailSender(sender EmailSender) {
	ns.emailSender = sender
}

// SetSlackSender sets the Slack sender
func (ns *NotificationService) SetSlackSender(sender SlackSender) {
	ns.slackSender = sender
}

// SetWebhookSender sets the webhook sender
func (ns *NotificationService) SetWebhookSender(sender WebhookSender) {
	ns.webhookSender = sender
}

// Stop stops the notification service
func (ns *NotificationService) Stop() {
	close(ns.stopChan)
}

// GetStats returns notification statistics
func (ns *NotificationService) GetStats() map[string]interface{} {
	ns.mutex.RLock()
	defer ns.mutex.RUnlock()

	stats := map[string]interface{}{
		"total_rules":    len(ns.rules),
		"active_rules":   0,
		"total_counters": len(ns.counters),
		"queue_size":     len(ns.messageQueue),
	}

	for _, rule := range ns.rules {
		if rule.Enabled {
			stats["active_rules"] = stats["active_rules"].(int) + 1
		}
	}

	return stats
}
