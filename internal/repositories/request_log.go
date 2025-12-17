package repositories

import (
	"context"

	"api-translation-platform/internal/database"
	"api-translation-platform/internal/models"
)

// requestLogRepository implements RequestLogRepository
type requestLogRepository struct {
	db *database.Connection
}

// NewRequestLogRepository creates a new request log repository
func NewRequestLogRepository(db *database.Connection) RequestLogRepository {
	return &requestLogRepository{db: db}
}

// Create creates a new request log
func (r *requestLogRepository) Create(ctx context.Context, log *models.RequestLog) error {
	return r.db.WithContext(ctx).Create(log).Error
}

// GetByID retrieves a request log by ID
func (r *requestLogRepository) GetByID(ctx context.Context, id string) (*models.RequestLog, error) {
	var log models.RequestLog
	err := r.db.WithContext(ctx).
		Preload("Organisation").
		Preload("Connector").
		First(&log, "id = ?", id).Error
	if err != nil {
		return nil, err
	}
	return &log, nil
}

// GetByOrganisation retrieves request logs for an organisation with pagination
func (r *requestLogRepository) GetByOrganisation(ctx context.Context, orgID string, limit, offset int) ([]*models.RequestLog, error) {
	var logs []*models.RequestLog
	err := r.db.WithContext(ctx).
		Preload("Connector").
		Where("organisation_id = ?", orgID).
		Order("timestamp DESC").
		Limit(limit).
		Offset(offset).
		Find(&logs).Error
	return logs, err
}

// GetByConnector retrieves request logs for a specific connector with pagination
func (r *requestLogRepository) GetByConnector(ctx context.Context, connectorID string, limit, offset int) ([]*models.RequestLog, error) {
	var logs []*models.RequestLog
	err := r.db.WithContext(ctx).
		Preload("Organisation").
		Preload("Connector").
		Where("connector_id = ?", connectorID).
		Order("timestamp DESC").
		Limit(limit).
		Offset(offset).
		Find(&logs).Error
	return logs, err
}

// GetErrorLogs retrieves error logs for an organisation with pagination
func (r *requestLogRepository) GetErrorLogs(ctx context.Context, orgID string, limit, offset int) ([]*models.RequestLog, error) {
	var logs []*models.RequestLog
	err := r.db.WithContext(ctx).
		Preload("Connector").
		Where("organisation_id = ? AND (status_code >= ? OR error_message != '')", orgID, 400).
		Order("timestamp DESC").
		Limit(limit).
		Offset(offset).
		Find(&logs).Error
	return logs, err
}

// Delete soft deletes a request log
func (r *requestLogRepository) Delete(ctx context.Context, id string) error {
	return r.db.WithContext(ctx).Delete(&models.RequestLog{}, "id = ?", id).Error
}

// GetAll retrieves all request logs with pagination (for global admins)
func (r *requestLogRepository) GetAll(ctx context.Context, limit, offset int) ([]*models.RequestLog, error) {
	var logs []*models.RequestLog

	query := r.db.WithContext(ctx).
		Order("created_at DESC").
		Limit(limit).
		Offset(offset)

	if err := query.Find(&logs).Error; err != nil {
		return nil, err
	}

	return logs, nil
}
