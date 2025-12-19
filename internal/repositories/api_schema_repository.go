package repositories

import (
	"context"
	"fmt"

	"api-translation-platform/internal/models"

	"gorm.io/gorm"
)

// APISchemaRepository defines the interface for API schema data operations
type APISchemaRepository interface {
	Create(ctx context.Context, schema *models.APISchema) (*models.APISchema, error)
	Update(ctx context.Context, schema *models.APISchema) (*models.APISchema, error)
	Delete(ctx context.Context, id string) error
	GetByID(ctx context.Context, id string) (*models.APISchema, error)
	GetByAPIConfigurationID(ctx context.Context, apiConfigID string) (*models.APISchema, error)
	List(ctx context.Context, limit, offset int) ([]*models.APISchema, error)
}

type apiSchemaRepository struct {
	db *gorm.DB
}

// NewAPISchemaRepository creates a new API schema repository
func NewAPISchemaRepository(db *gorm.DB) APISchemaRepository {
	return &apiSchemaRepository{db: db}
}

func (r *apiSchemaRepository) Create(ctx context.Context, schema *models.APISchema) (*models.APISchema, error) {
	if err := r.db.WithContext(ctx).Create(schema).Error; err != nil {
		return nil, fmt.Errorf("failed to create API schema: %w", err)
	}
	return schema, nil
}

func (r *apiSchemaRepository) Update(ctx context.Context, schema *models.APISchema) (*models.APISchema, error) {
	if err := r.db.WithContext(ctx).Save(schema).Error; err != nil {
		return nil, fmt.Errorf("failed to update API schema: %w", err)
	}
	return schema, nil
}

func (r *apiSchemaRepository) Delete(ctx context.Context, id string) error {
	result := r.db.WithContext(ctx).Delete(&models.APISchema{}, "id = ?", id)
	if result.Error != nil {
		return fmt.Errorf("failed to delete API schema: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("API schema not found")
	}
	return nil
}

func (r *apiSchemaRepository) GetByID(ctx context.Context, id string) (*models.APISchema, error) {
	var schema models.APISchema
	if err := r.db.WithContext(ctx).First(&schema, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("API schema not found")
		}
		return nil, fmt.Errorf("failed to get API schema: %w", err)
	}
	return &schema, nil
}

func (r *apiSchemaRepository) GetByAPIConfigurationID(ctx context.Context, apiConfigID string) (*models.APISchema, error) {
	var schema models.APISchema
	if err := r.db.WithContext(ctx).First(&schema, "api_configuration_id = ?", apiConfigID).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil // Return nil, nil when no schema exists (this is expected)
		}
		return nil, fmt.Errorf("failed to get API schema: %w", err)
	}
	return &schema, nil
}

func (r *apiSchemaRepository) List(ctx context.Context, limit, offset int) ([]*models.APISchema, error) {
	var schemas []*models.APISchema
	query := r.db.WithContext(ctx).Limit(limit).Offset(offset)

	if err := query.Find(&schemas).Error; err != nil {
		return nil, fmt.Errorf("failed to list API schemas: %w", err)
	}

	return schemas, nil
}
