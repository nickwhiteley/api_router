package repositories

import (
	"context"

	"api-translation-platform/internal/database"
	"api-translation-platform/internal/models"
)

// organisationRepository implements OrganisationRepository
type organisationRepository struct {
	db *database.Connection
}

// NewOrganisationRepository creates a new organisation repository
func NewOrganisationRepository(db *database.Connection) OrganisationRepository {
	return &organisationRepository{db: db}
}

// Create creates a new organisation
func (r *organisationRepository) Create(ctx context.Context, org *models.Organisation) error {
	return r.db.WithContext(ctx).Create(org).Error
}

// GetByID retrieves an organisation by ID
func (r *organisationRepository) GetByID(ctx context.Context, id string) (*models.Organisation, error) {
	var org models.Organisation
	err := r.db.WithContext(ctx).First(&org, "id = ?", id).Error
	if err != nil {
		return nil, err
	}
	return &org, nil
}

// GetAll retrieves all organisations
func (r *organisationRepository) GetAll(ctx context.Context) ([]*models.Organisation, error) {
	var orgs []*models.Organisation
	err := r.db.WithContext(ctx).Find(&orgs).Error
	return orgs, err
}

// Update updates an existing organisation
func (r *organisationRepository) Update(ctx context.Context, org *models.Organisation) error {
	return r.db.WithContext(ctx).Save(org).Error
}

// Delete soft deletes an organisation
func (r *organisationRepository) Delete(ctx context.Context, id string) error {
	return r.db.WithContext(ctx).Delete(&models.Organisation{}, "id = ?", id).Error
}
