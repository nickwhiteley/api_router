package services

import (
	"context"
	"errors"

	"golang.org/x/crypto/bcrypt"

	"api-translation-platform/internal/logger"
	"api-translation-platform/internal/models"
	"api-translation-platform/internal/repositories"
)

var (
	ErrUserAlreadyExists = errors.New("user already exists")
	ErrInvalidRole       = errors.New("invalid role")
)

// userManagementService implements UserManagementService
type userManagementService struct {
	logger   *logger.Logger
	userRepo repositories.UserRepository
	orgRepo  repositories.OrganisationRepository
	authSvc  AuthenticationService
}

// NewUserManagementService creates a new user management service
func NewUserManagementService(
	logger *logger.Logger,
	userRepo repositories.UserRepository,
	orgRepo repositories.OrganisationRepository,
	authSvc AuthenticationService,
) UserManagementService {
	return &userManagementService{
		logger:   logger,
		userRepo: userRepo,
		orgRepo:  orgRepo,
		authSvc:  authSvc,
	}
}

// CreateUser creates a new user with the specified password
func (s *userManagementService) CreateUser(ctx context.Context, user *models.User, password string) error {
	s.logger.WithField("username", user.Username).
		WithField("organisation_id", user.OrganisationID).
		Info("Creating new user")

	// Validate role
	if user.Role != "org_admin" && user.Role != "global_admin" {
		return ErrInvalidRole
	}

	// Check if organisation exists
	_, err := s.orgRepo.GetByID(ctx, user.OrganisationID)
	if err != nil {
		s.logger.WithField("organisation_id", user.OrganisationID).
			WithError(err).Error("Organisation not found")
		return err
	}

	// Check if user already exists by username
	existingUser, err := s.userRepo.GetByUsername(ctx, user.Username)
	if err == nil && existingUser != nil {
		return ErrUserAlreadyExists
	}

	// Check if user already exists by email
	existingUser, err = s.userRepo.GetByEmail(ctx, user.Email)
	if err == nil && existingUser != nil {
		return ErrUserAlreadyExists
	}

	// Hash password
	hashedPassword, err := s.authSvc.HashPassword(password)
	if err != nil {
		s.logger.WithError(err).Error("Failed to hash password")
		return err
	}

	user.PasswordHash = hashedPassword
	user.IsActive = true

	// Create user
	err = s.userRepo.Create(ctx, user)
	if err != nil {
		s.logger.WithError(err).Error("Failed to create user")
		return err
	}

	s.logger.WithField("user_id", user.ID).Info("User created successfully")
	return nil
}

// UpdateUser updates an existing user
func (s *userManagementService) UpdateUser(ctx context.Context, user *models.User) error {
	s.logger.WithField("user_id", user.ID).Info("Updating user")

	// Validate role
	if user.Role != "org_admin" && user.Role != "global_admin" {
		return ErrInvalidRole
	}

	// Check if organisation exists
	_, err := s.orgRepo.GetByID(ctx, user.OrganisationID)
	if err != nil {
		s.logger.WithField("organisation_id", user.OrganisationID).
			WithError(err).Error("Organisation not found")
		return err
	}

	err = s.userRepo.Update(ctx, user)
	if err != nil {
		s.logger.WithError(err).Error("Failed to update user")
		return err
	}

	s.logger.WithField("user_id", user.ID).Info("User updated successfully")
	return nil
}

// DeleteUser soft deletes a user
func (s *userManagementService) DeleteUser(ctx context.Context, userID string) error {
	s.logger.WithField("user_id", userID).Info("Deleting user")

	err := s.userRepo.Delete(ctx, userID)
	if err != nil {
		s.logger.WithError(err).Error("Failed to delete user")
		return err
	}

	s.logger.WithField("user_id", userID).Info("User deleted successfully")
	return nil
}

// GetUser retrieves a user by ID
func (s *userManagementService) GetUser(ctx context.Context, userID string) (*models.User, error) {
	return s.userRepo.GetByID(ctx, userID)
}

// GetUsersByOrganisation retrieves all users in an organisation
func (s *userManagementService) GetUsersByOrganisation(ctx context.Context, orgID string) ([]*models.User, error) {
	return s.userRepo.GetByOrganisation(ctx, orgID)
}

// AssignUserToOrganisation assigns a user to a different organisation
func (s *userManagementService) AssignUserToOrganisation(ctx context.Context, userID, orgID string) error {
	s.logger.WithField("user_id", userID).
		WithField("organisation_id", orgID).
		Info("Assigning user to organisation")

	// Check if organisation exists
	_, err := s.orgRepo.GetByID(ctx, orgID)
	if err != nil {
		s.logger.WithField("organisation_id", orgID).
			WithError(err).Error("Organisation not found")
		return err
	}

	// Get user
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return err
	}

	// Update organisation
	user.OrganisationID = orgID
	return s.userRepo.Update(ctx, user)
}

// ChangeUserRole changes a user's role
func (s *userManagementService) ChangeUserRole(ctx context.Context, userID, role string) error {
	s.logger.WithField("user_id", userID).
		WithField("role", role).
		Info("Changing user role")

	// Validate role
	if role != "org_admin" && role != "global_admin" {
		return ErrInvalidRole
	}

	// Get user
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return err
	}

	// Update role
	user.Role = role
	return s.userRepo.Update(ctx, user)
}

// ActivateUser activates a user account
func (s *userManagementService) ActivateUser(ctx context.Context, userID string) error {
	s.logger.WithField("user_id", userID).Info("Activating user")

	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return err
	}

	user.IsActive = true
	return s.userRepo.Update(ctx, user)
}

// DeactivateUser deactivates a user account
func (s *userManagementService) DeactivateUser(ctx context.Context, userID string) error {
	s.logger.WithField("user_id", userID).Info("Deactivating user")

	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return err
	}

	user.IsActive = false
	return s.userRepo.Update(ctx, user)
}

// ChangePassword changes a user's password
func (s *userManagementService) ChangePassword(ctx context.Context, userID, newPassword string) error {
	s.logger.WithField("user_id", userID).Info("Changing user password")

	// Hash new password
	hashedPassword, err := s.authSvc.HashPassword(newPassword)
	if err != nil {
		s.logger.WithError(err).Error("Failed to hash password")
		return err
	}

	// Get user
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return err
	}

	// Update password
	user.PasswordHash = hashedPassword
	return s.userRepo.Update(ctx, user)
}

// GetAllUsers retrieves all users in the system
func (s *userManagementService) GetAllUsers(ctx context.Context) ([]*models.User, error) {
	return s.userRepo.GetAll(ctx)
}

// GetUserByUsername retrieves a user by username
func (s *userManagementService) GetUserByUsername(ctx context.Context, username string) (*models.User, error) {
	return s.userRepo.GetByUsername(ctx, username)
}

// VerifyPassword verifies a password against a hash
func (s *userManagementService) VerifyPassword(hashedPassword, password string) error {
	// Use bcrypt to verify password
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}
