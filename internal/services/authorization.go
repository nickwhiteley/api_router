package services

import (
	"context"
	"reflect"

	"api-translation-platform/internal/logger"
	"api-translation-platform/internal/models"
	"api-translation-platform/internal/repositories"
)

// authorizationService implements AuthorizationService
type authorizationService struct {
	logger      *logger.Logger
	requestRepo repositories.RequestLogRepository
}

// NewAuthorizationService creates a new authorization service
func NewAuthorizationService(
	logger *logger.Logger,
	requestRepo repositories.RequestLogRepository,
) AuthorizationService {
	return &authorizationService{
		logger:      logger,
		requestRepo: requestRepo,
	}
}

// CanAccessResource checks if a user can access a resource based on organisation
func (s *authorizationService) CanAccessResource(ctx context.Context, user *models.User, resourceOrgID string) bool {
	if user == nil || !user.IsActive {
		return false
	}

	// Global admins can access all resources
	if user.IsGlobalAdmin() {
		return true
	}

	// Organisation admins can only access resources in their organisation
	if user.IsOrgAdmin() && user.OrganisationID == resourceOrgID {
		return true
	}

	return false
}

// CanManageOrganisation checks if a user can manage a specific organisation
func (s *authorizationService) CanManageOrganisation(ctx context.Context, user *models.User, orgID string) bool {
	if user == nil || !user.IsActive {
		return false
	}

	// Global admins can manage all organisations
	if user.IsGlobalAdmin() {
		return true
	}

	// Organisation admins can only manage their own organisation
	if user.IsOrgAdmin() && user.OrganisationID == orgID {
		return true
	}

	return false
}

// FilterByOrganisation filters data based on user's organisation access
func (s *authorizationService) FilterByOrganisation(ctx context.Context, user *models.User, data interface{}) interface{} {
	if user == nil || !user.IsActive {
		return nil
	}

	// Global admins see all data
	if user.IsGlobalAdmin() {
		return data
	}

	// Filter data based on organisation
	return s.filterDataByOrganisation(data, user.OrganisationID)
}

// filterDataByOrganisation filters a slice of data by organisation ID
func (s *authorizationService) filterDataByOrganisation(data interface{}, orgID string) interface{} {
	if data == nil {
		return nil
	}

	v := reflect.ValueOf(data)
	if v.Kind() != reflect.Slice {
		// For single items, check if they have OrganisationID field
		return s.filterSingleItem(data, orgID)
	}

	// For slices, filter each item
	var filtered []interface{}
	for i := 0; i < v.Len(); i++ {
		item := v.Index(i).Interface()
		if s.itemBelongsToOrganisation(item, orgID) {
			filtered = append(filtered, item)
		}
	}

	return filtered
}

// filterSingleItem checks if a single item belongs to the organisation
func (s *authorizationService) filterSingleItem(data interface{}, orgID string) interface{} {
	if s.itemBelongsToOrganisation(data, orgID) {
		return data
	}
	return nil
}

// itemBelongsToOrganisation checks if an item belongs to the specified organisation
func (s *authorizationService) itemBelongsToOrganisation(item interface{}, orgID string) bool {
	v := reflect.ValueOf(item)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}

	if v.Kind() != reflect.Struct {
		return false
	}

	// Look for OrganisationID field
	orgField := v.FieldByName("OrganisationID")
	if !orgField.IsValid() || orgField.Kind() != reflect.String {
		return false
	}

	return orgField.String() == orgID
}

// LogSecurityViolation logs a security violation attempt
func (s *authorizationService) LogSecurityViolation(ctx context.Context, user *models.User, action string, resourceID string) {
	userID := "anonymous"
	orgID := "unknown"

	if user != nil {
		userID = user.ID
		orgID = user.OrganisationID
	}

	s.logger.WithField("user_id", userID).
		WithField("organisation_id", orgID).
		WithField("action", action).
		WithField("resource_id", resourceID).
		Warn("Security violation detected")

	// Create audit log entry
	auditLog := &models.RequestLog{
		OrganisationID: orgID,
		RequestID:      "security-violation",
		Method:         "SECURITY",
		Path:           action,
		StatusCode:     403,
		ErrorMessage:   "Unauthorized access attempt to resource: " + resourceID,
	}

	// Log to database (ignore errors as this is audit logging)
	_ = s.requestRepo.Create(ctx, auditLog)
}
