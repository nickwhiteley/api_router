package repositories

import (
	"context"

	"api-translation-platform/internal/database"
	"api-translation-platform/internal/models"
)

// apiConfigurationRepository implements APIConfigurationRepository
type apiConfigurationRepository struct {
	db *database.Connection
}

// NewAPIConfigurationRepository creates a new API configuration repository
func NewAPIConfigurationRepository(db *database.Connection) APIConfigurationRepository {
	return &apiConfigurationRepository{db: db}
}

// Create creates a new API configuration
func (r *apiConfigurationRepository) Create(ctx context.Context, config *models.APIConfiguration) error {
	return r.db.WithContext(ctx).Create(config).Error
}

// GetByID retrieves an API configuration by ID
func (r *apiConfigurationRepository) GetByID(ctx context.Context, id string) (*models.APIConfiguration, error) {
	var config models.APIConfiguration
	err := r.db.WithContext(ctx).Preload("Organisation").First(&config, "id = ?", id).Error
	if err != nil {
		return nil, err
	}
	return &config, nil
}

// GetByOrganisation retrieves all API configurations for an organisation
func (r *apiConfigurationRepository) GetByOrganisation(ctx context.Context, orgID string) ([]*models.APIConfiguration, error) {
	var configs []*models.APIConfiguration
	err := r.db.WithContext(ctx).Where("organisation_id = ?", orgID).Find(&configs).Error
	return configs, err
}

// GetInboundByOrganisation retrieves inbound API configurations for an organisation
func (r *apiConfigurationRepository) GetInboundByOrganisation(ctx context.Context, orgID string) ([]*models.APIConfiguration, error) {
	var configs []*models.APIConfiguration
	err := r.db.WithContext(ctx).Where("organisation_id = ? AND direction = ?", orgID, "inbound").Find(&configs).Error
	return configs, err
}

// GetOutboundByOrganisation retrieves outbound API configurations for an organisation
func (r *apiConfigurationRepository) GetOutboundByOrganisation(ctx context.Context, orgID string) ([]*models.APIConfiguration, error) {
	var configs []*models.APIConfiguration
	err := r.db.WithContext(ctx).Where("organisation_id = ? AND direction = ?", orgID, "outbound").Find(&configs).Error
	return configs, err
}

// Update updates an existing API configuration
func (r *apiConfigurationRepository) Update(ctx context.Context, config *models.APIConfiguration) error {
	return r.db.WithContext(ctx).Save(config).Error
}

// Delete soft deletes an API configuration
func (r *apiConfigurationRepository) Delete(ctx context.Context, id string) error {
	return r.db.WithContext(ctx).Delete(&models.APIConfiguration{}, "id = ?", id).Error
}
