package repositories

import (
	"context"

	"api-translation-platform/internal/database"
	"api-translation-platform/internal/models"
)

// userRepository implements UserRepository
type userRepository struct {
	db *database.Connection
}

// NewUserRepository creates a new user repository
func NewUserRepository(db *database.Connection) UserRepository {
	return &userRepository{db: db}
}

// Create creates a new user
func (r *userRepository) Create(ctx context.Context, user *models.User) error {
	return r.db.WithContext(ctx).Create(user).Error
}

// GetByID retrieves a user by ID
func (r *userRepository) GetByID(ctx context.Context, id string) (*models.User, error) {
	var user models.User
	err := r.db.WithContext(ctx).Preload("Organisation").First(&user, "id = ?", id).Error
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// GetByUsername retrieves a user by username
func (r *userRepository) GetByUsername(ctx context.Context, username string) (*models.User, error) {
	var user models.User
	err := r.db.WithContext(ctx).Preload("Organisation").First(&user, "username = ?", username).Error
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// GetByEmail retrieves a user by email
func (r *userRepository) GetByEmail(ctx context.Context, email string) (*models.User, error) {
	var user models.User
	err := r.db.WithContext(ctx).Preload("Organisation").First(&user, "email = ?", email).Error
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// GetByUsernameAndOrganisation retrieves a user by username within a specific organisation
func (r *userRepository) GetByUsernameAndOrganisation(ctx context.Context, username, orgID string) (*models.User, error) {
	var user models.User
	err := r.db.WithContext(ctx).Preload("Organisation").
		First(&user, "username = ? AND organisation_id = ?", username, orgID).Error
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// GetByOrganisation retrieves all users in an organisation
func (r *userRepository) GetByOrganisation(ctx context.Context, orgID string) ([]*models.User, error) {
	var users []*models.User
	err := r.db.WithContext(ctx).Where("organisation_id = ?", orgID).Find(&users).Error
	return users, err
}

// GetByOrganisationID retrieves all users in an organisation (alias for GetByOrganisation)
func (r *userRepository) GetByOrganisationID(ctx context.Context, orgID string) ([]*models.User, error) {
	return r.GetByOrganisation(ctx, orgID)
}

// Update updates an existing user
func (r *userRepository) Update(ctx context.Context, user *models.User) error {
	return r.db.WithContext(ctx).Save(user).Error
}

// Delete soft deletes a user
func (r *userRepository) Delete(ctx context.Context, id string) error {
	return r.db.WithContext(ctx).Delete(&models.User{}, "id = ?", id).Error
}

// GetAll retrieves all users in the system
func (r *userRepository) GetAll(ctx context.Context) ([]*models.User, error) {
	var users []*models.User
	err := r.db.WithContext(ctx).Preload("Organisation").Find(&users).Error
	return users, err
}
