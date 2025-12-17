package repositories

import (
	"context"

	"api-translation-platform/internal/database"
	"api-translation-platform/internal/models"
)

// connectorRepository implements ConnectorRepository
type connectorRepository struct {
	db *database.Connection
}

// NewConnectorRepository creates a new connector repository
func NewConnectorRepository(db *database.Connection) ConnectorRepository {
	return &connectorRepository{db: db}
}

// Create creates a new connector
func (r *connectorRepository) Create(ctx context.Context, connector *models.Connector) error {
	return r.db.WithContext(ctx).Create(connector).Error
}

// GetByID retrieves a connector by ID
func (r *connectorRepository) GetByID(ctx context.Context, id string) (*models.Connector, error) {
	var connector models.Connector
	err := r.db.WithContext(ctx).
		Preload("Organisation").
		Preload("InboundAPI").
		Preload("OutboundAPI").
		First(&connector, "id = ?", id).Error
	if err != nil {
		return nil, err
	}
	return &connector, nil
}

// GetByOrganisation retrieves all connectors for an organisation
func (r *connectorRepository) GetByOrganisation(ctx context.Context, orgID string) ([]*models.Connector, error) {
	var connectors []*models.Connector
	err := r.db.WithContext(ctx).
		Preload("InboundAPI").
		Preload("OutboundAPI").
		Where("organisation_id = ?", orgID).
		Find(&connectors).Error
	return connectors, err
}

// GetByInboundAPI retrieves all connectors for a specific inbound API
func (r *connectorRepository) GetByInboundAPI(ctx context.Context, apiID string) ([]*models.Connector, error) {
	var connectors []*models.Connector
	err := r.db.WithContext(ctx).
		Preload("Organisation").
		Preload("InboundAPI").
		Preload("OutboundAPI").
		Where("inbound_api_id = ? AND is_active = ?", apiID, true).
		Find(&connectors).Error
	return connectors, err
}

// Update updates an existing connector
func (r *connectorRepository) Update(ctx context.Context, connector *models.Connector) error {
	return r.db.WithContext(ctx).Save(connector).Error
}

// Delete soft deletes a connector
func (r *connectorRepository) Delete(ctx context.Context, id string) error {
	return r.db.WithContext(ctx).Delete(&models.Connector{}, "id = ?", id).Error
}
