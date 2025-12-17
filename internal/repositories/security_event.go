package repositories

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"api-translation-platform/internal/logger"
	"api-translation-platform/internal/security"
)

// SecurityEventRepository handles security event data operations
type SecurityEventRepository struct {
	db     *sql.DB
	logger *logger.Logger
}

// NewSecurityEventRepository creates a new security event repository
func NewSecurityEventRepository(db *sql.DB, logger *logger.Logger) *SecurityEventRepository {
	return &SecurityEventRepository{
		db:     db,
		logger: logger,
	}
}

// CreateSecurityEvent creates a new security event record
func (r *SecurityEventRepository) CreateSecurityEvent(ctx context.Context, event *security.SecurityEvent) error {
	query := `
		INSERT INTO security_events (
			id, type, severity, timestamp, user_id, ip_address, user_agent,
			resource_id, action, details, metadata
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	// Convert metadata to JSON
	var metadataJSON []byte
	var err error
	if event.Metadata != nil {
		metadataJSON, err = json.Marshal(event.Metadata)
		if err != nil {
			r.logger.WithError(err).Error("Failed to marshal security event metadata")
			return fmt.Errorf("failed to marshal metadata: %w", err)
		}
	}

	_, err = r.db.ExecContext(ctx, query,
		event.ID,
		event.Type,
		event.Severity,
		event.Timestamp,
		event.UserID,
		event.IPAddress,
		event.UserAgent,
		event.ResourceID,
		event.Action,
		event.Details,
		metadataJSON,
	)

	if err != nil {
		r.logger.WithError(err).WithField("event_id", event.ID).Error("Failed to create security event")
		return fmt.Errorf("failed to create security event: %w", err)
	}

	r.logger.WithField("event_id", event.ID).
		WithField("event_type", event.Type).
		WithField("severity", event.Severity).
		Info("Security event created")

	return nil
}

// GetSecurityEvents retrieves security events based on filters
func (r *SecurityEventRepository) GetSecurityEvents(ctx context.Context, filters map[string]interface{}) ([]*security.SecurityEvent, error) {
	query := `
		SELECT id, type, severity, timestamp, user_id, ip_address, user_agent,
			   resource_id, action, details, metadata
		FROM security_events
	`

	var conditions []string
	var args []interface{}

	// Build WHERE clause based on filters
	if eventType, ok := filters["event_type"]; ok {
		conditions = append(conditions, "type = ?")
		args = append(args, eventType)
	}

	if severity, ok := filters["severity"]; ok {
		conditions = append(conditions, "severity = ?")
		args = append(args, severity)
	}

	if userID, ok := filters["user_id"]; ok {
		conditions = append(conditions, "user_id = ?")
		args = append(args, userID)
	}

	if ipAddress, ok := filters["ip_address"]; ok {
		conditions = append(conditions, "ip_address = ?")
		args = append(args, ipAddress)
	}

	if resourceID, ok := filters["resource_id"]; ok {
		conditions = append(conditions, "resource_id = ?")
		args = append(args, resourceID)
	}

	if startTime, ok := filters["start_time"]; ok {
		conditions = append(conditions, "timestamp >= ?")
		args = append(args, startTime)
	}

	if endTime, ok := filters["end_time"]; ok {
		conditions = append(conditions, "timestamp <= ?")
		args = append(args, endTime)
	}

	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}

	// Add ordering
	query += " ORDER BY timestamp DESC"

	// Add pagination
	if limit, ok := filters["limit"]; ok {
		query += " LIMIT ?"
		args = append(args, limit)
	}

	if offset, ok := filters["offset"]; ok {
		query += " OFFSET ?"
		args = append(args, offset)
	}

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		r.logger.WithError(err).Error("Failed to query security events")
		return nil, fmt.Errorf("failed to query security events: %w", err)
	}
	defer rows.Close()

	var events []*security.SecurityEvent
	for rows.Next() {
		event := &security.SecurityEvent{}
		var metadataJSON []byte

		err := rows.Scan(
			&event.ID,
			&event.Type,
			&event.Severity,
			&event.Timestamp,
			&event.UserID,
			&event.IPAddress,
			&event.UserAgent,
			&event.ResourceID,
			&event.Action,
			&event.Details,
			&metadataJSON,
		)

		if err != nil {
			r.logger.WithError(err).Error("Failed to scan security event row")
			continue
		}

		// Unmarshal metadata if present
		if len(metadataJSON) > 0 {
			if err := json.Unmarshal(metadataJSON, &event.Metadata); err != nil {
				r.logger.WithError(err).WithField("event_id", event.ID).
					Warn("Failed to unmarshal security event metadata")
			}
		}

		events = append(events, event)
	}

	if err := rows.Err(); err != nil {
		r.logger.WithError(err).Error("Error iterating security event rows")
		return nil, fmt.Errorf("error iterating rows: %w", err)
	}

	return events, nil
}

// GetSecurityEventsByTimeRange retrieves security events within a time range
func (r *SecurityEventRepository) GetSecurityEventsByTimeRange(ctx context.Context, startTime, endTime time.Time) ([]*security.SecurityEvent, error) {
	filters := map[string]interface{}{
		"start_time": startTime,
		"end_time":   endTime,
	}
	return r.GetSecurityEvents(ctx, filters)
}

// GetSecurityEventsByType retrieves security events of a specific type
func (r *SecurityEventRepository) GetSecurityEventsByType(ctx context.Context, eventType security.SecurityEventType) ([]*security.SecurityEvent, error) {
	filters := map[string]interface{}{
		"event_type": eventType,
	}
	return r.GetSecurityEvents(ctx, filters)
}

// GetSecurityEventsByUser retrieves security events for a specific user
func (r *SecurityEventRepository) GetSecurityEventsByUser(ctx context.Context, userID string) ([]*security.SecurityEvent, error) {
	filters := map[string]interface{}{
		"user_id": userID,
	}
	return r.GetSecurityEvents(ctx, filters)
}

// GetSecurityEventsByIPAddress retrieves security events for a specific IP address
func (r *SecurityEventRepository) GetSecurityEventsByIPAddress(ctx context.Context, ipAddress string) ([]*security.SecurityEvent, error) {
	filters := map[string]interface{}{
		"ip_address": ipAddress,
	}
	return r.GetSecurityEvents(ctx, filters)
}

// DeleteOldSecurityEvents deletes security events older than the specified duration
func (r *SecurityEventRepository) DeleteOldSecurityEvents(ctx context.Context, olderThan time.Duration) error {
	cutoffTime := time.Now().Add(-olderThan)

	query := "DELETE FROM security_events WHERE timestamp < ?"

	result, err := r.db.ExecContext(ctx, query, cutoffTime)
	if err != nil {
		r.logger.WithError(err).Error("Failed to delete old security events")
		return fmt.Errorf("failed to delete old security events: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	r.logger.WithField("rows_deleted", rowsAffected).
		WithField("cutoff_time", cutoffTime).
		Info("Deleted old security events")

	return nil
}

// GetSecurityEventStats returns statistics about security events
func (r *SecurityEventRepository) GetSecurityEventStats(ctx context.Context, timeRange time.Duration) (map[string]interface{}, error) {
	startTime := time.Now().Add(-timeRange)

	query := `
		SELECT 
			type,
			severity,
			COUNT(*) as count
		FROM security_events 
		WHERE timestamp >= ?
		GROUP BY type, severity
		ORDER BY count DESC
	`

	rows, err := r.db.QueryContext(ctx, query, startTime)
	if err != nil {
		r.logger.WithError(err).Error("Failed to get security event stats")
		return nil, fmt.Errorf("failed to get security event stats: %w", err)
	}
	defer rows.Close()

	stats := make(map[string]interface{})
	typeStats := make(map[string]int)
	severityStats := make(map[string]int)
	totalEvents := 0

	for rows.Next() {
		var eventType, severity string
		var count int

		if err := rows.Scan(&eventType, &severity, &count); err != nil {
			r.logger.WithError(err).Error("Failed to scan security event stats row")
			continue
		}

		typeStats[eventType] += count
		severityStats[severity] += count
		totalEvents += count
	}

	stats["by_type"] = typeStats
	stats["by_severity"] = severityStats
	stats["total_events"] = totalEvents
	stats["time_range_hours"] = int(timeRange.Hours())

	return stats, nil
}
