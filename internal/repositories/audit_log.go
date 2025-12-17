package repositories

import (
	"context"

	"api-translation-platform/internal/database"
	"api-translation-platform/internal/models"
)

// auditLogRepository implements AuditLogRepository
type auditLogRepository struct {
	db *database.Connection
}

// NewAuditLogRepository creates a new audit log repository
func NewAuditLogRepository(db *database.Connection) AuditLogRepository {
	return &auditLogRepository{db: db}
}

// Create creates a new audit log entry
func (r *auditLogRepository) Create(ctx context.Context, log *models.AuditLog) error {
	return r.db.WithContext(ctx).Create(log).Error
}

// GetByID retrieves an audit log by ID
func (r *auditLogRepository) GetByID(ctx context.Context, id string) (*models.AuditLog, error) {
	var log models.AuditLog
	err := r.db.WithContext(ctx).Preload("Organisation").Preload("User").First(&log, "id = ?", id).Error
	if err != nil {
		return nil, err
	}
	return &log, nil
}

// GetByOrganisation retrieves audit logs for an organisation with pagination
func (r *auditLogRepository) GetByOrganisation(ctx context.Context, orgID string, limit, offset int) ([]*models.AuditLog, error) {
	var logs []*models.AuditLog
	err := r.db.WithContext(ctx).
		Preload("User").
		Where("organisation_id = ?", orgID).
		Order("timestamp DESC").
		Limit(limit).
		Offset(offset).
		Find(&logs).Error
	return logs, err
}

// GetByResource retrieves audit logs for a specific resource with pagination
func (r *auditLogRepository) GetByResource(ctx context.Context, resourceType, resourceID string, limit, offset int) ([]*models.AuditLog, error) {
	var logs []*models.AuditLog
	err := r.db.WithContext(ctx).
		Preload("User").
		Where("resource_type = ? AND resource_id = ?", resourceType, resourceID).
		Order("timestamp DESC").
		Limit(limit).
		Offset(offset).
		Find(&logs).Error
	return logs, err
}

// GetByUser retrieves audit logs for a specific user with pagination
func (r *auditLogRepository) GetByUser(ctx context.Context, userID string, limit, offset int) ([]*models.AuditLog, error) {
	var logs []*models.AuditLog
	err := r.db.WithContext(ctx).
		Preload("Organisation").
		Where("user_id = ?", userID).
		Order("timestamp DESC").
		Limit(limit).
		Offset(offset).
		Find(&logs).Error
	return logs, err
}
