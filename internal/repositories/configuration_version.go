package repositories

import (
	"context"

	"api-translation-platform/internal/database"
	"api-translation-platform/internal/models"
)

// configurationVersionRepository implements ConfigurationVersionRepository
type configurationVersionRepository struct {
	db *database.Connection
}

// NewConfigurationVersionRepository creates a new configuration version repository
func NewConfigurationVersionRepository(db *database.Connection) ConfigurationVersionRepository {
	return &configurationVersionRepository{db: db}
}

// Create creates a new configuration version
func (r *configurationVersionRepository) Create(ctx context.Context, version *models.ConfigurationVersion) error {
	return r.db.WithContext(ctx).Create(version).Error
}

// GetByID retrieves a configuration version by ID
func (r *configurationVersionRepository) GetByID(ctx context.Context, id string) (*models.ConfigurationVersion, error) {
	var version models.ConfigurationVersion
	err := r.db.WithContext(ctx).Preload("Organisation").Preload("Creator").First(&version, "id = ?", id).Error
	if err != nil {
		return nil, err
	}
	return &version, nil
}

// GetByResource retrieves all versions for a specific resource
func (r *configurationVersionRepository) GetByResource(ctx context.Context, resourceType, resourceID string) ([]*models.ConfigurationVersion, error) {
	var versions []*models.ConfigurationVersion
	err := r.db.WithContext(ctx).
		Preload("Creator").
		Where("resource_type = ? AND resource_id = ?", resourceType, resourceID).
		Order("version DESC").
		Find(&versions).Error
	return versions, err
}

// GetActiveVersion retrieves the currently active version for a resource
func (r *configurationVersionRepository) GetActiveVersion(ctx context.Context, resourceType, resourceID string) (*models.ConfigurationVersion, error) {
	var version models.ConfigurationVersion
	err := r.db.WithContext(ctx).
		Preload("Creator").
		Where("resource_type = ? AND resource_id = ? AND is_active = ?", resourceType, resourceID, true).
		First(&version).Error
	if err != nil {
		return nil, err
	}
	return &version, nil
}

// GetVersionByNumber retrieves a specific version number for a resource
func (r *configurationVersionRepository) GetVersionByNumber(ctx context.Context, resourceType, resourceID string, version int) (*models.ConfigurationVersion, error) {
	var configVersion models.ConfigurationVersion
	err := r.db.WithContext(ctx).
		Preload("Creator").
		Where("resource_type = ? AND resource_id = ? AND version = ?", resourceType, resourceID, version).
		First(&configVersion).Error
	if err != nil {
		return nil, err
	}
	return &configVersion, nil
}

// SetActiveVersion sets a specific version as active and deactivates others
func (r *configurationVersionRepository) SetActiveVersion(ctx context.Context, versionID string) error {
	// First get the version to activate
	var targetVersion models.ConfigurationVersion
	if err := r.db.WithContext(ctx).First(&targetVersion, "id = ?", versionID).Error; err != nil {
		return err
	}

	// Start transaction
	tx := r.db.WithContext(ctx).Begin()
	if tx.Error != nil {
		return tx.Error
	}
	defer tx.Rollback()

	// Deactivate all versions for this resource
	if err := tx.Model(&models.ConfigurationVersion{}).
		Where("resource_type = ? AND resource_id = ?", targetVersion.ResourceType, targetVersion.ResourceID).
		Update("is_active", false).Error; err != nil {
		return err
	}

	// Activate the target version
	if err := tx.Model(&targetVersion).Update("is_active", true).Error; err != nil {
		return err
	}

	return tx.Commit().Error
}

// GetLatestVersion retrieves the latest version (highest version number) for a resource
func (r *configurationVersionRepository) GetLatestVersion(ctx context.Context, resourceType, resourceID string) (*models.ConfigurationVersion, error) {
	var version models.ConfigurationVersion
	err := r.db.WithContext(ctx).
		Preload("Creator").
		Where("resource_type = ? AND resource_id = ?", resourceType, resourceID).
		Order("version DESC").
		First(&version).Error
	if err != nil {
		return nil, err
	}
	return &version, nil
}
