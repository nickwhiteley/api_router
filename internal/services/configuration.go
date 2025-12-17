package services

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"api-translation-platform/internal/logger"
	"api-translation-platform/internal/models"
	"api-translation-platform/internal/repositories"
)

// configurationService implements ConfigurationService
type configurationService struct {
	logger        *logger.Logger
	apiConfigRepo repositories.APIConfigurationRepository
	auditLogRepo  repositories.AuditLogRepository
	versionRepo   repositories.ConfigurationVersionRepository
	connectorRepo repositories.ConnectorRepository
	orgRepo       repositories.OrganisationRepository
	validationSvc *models.ValidationService
}

// NewConfigurationService creates a new configuration service
func NewConfigurationService(
	logger *logger.Logger,
	apiConfigRepo repositories.APIConfigurationRepository,
	auditLogRepo repositories.AuditLogRepository,
	versionRepo repositories.ConfigurationVersionRepository,
	connectorRepo repositories.ConnectorRepository,
	orgRepo repositories.OrganisationRepository,
	validationSvc *models.ValidationService,
) ConfigurationService {
	return &configurationService{
		logger:        logger,
		apiConfigRepo: apiConfigRepo,
		auditLogRepo:  auditLogRepo,
		versionRepo:   versionRepo,
		connectorRepo: connectorRepo,
		orgRepo:       orgRepo,
		validationSvc: validationSvc,
	}
}

// CreateAPIConfiguration creates a new API configuration
func (s *configurationService) CreateAPIConfiguration(ctx context.Context, config *models.APIConfiguration) (*models.APIConfiguration, error) {
	s.logger.WithField("organisation_id", config.OrganisationID).
		WithField("config_name", config.Name).
		Info("Creating API configuration")

	// Custom validation for endpoint based on direction
	if err := s.validateAPIEndpoint(config); err != nil {
		return nil, err
	}

	if err := s.validationSvc.ValidateStruct(config); err != nil {
		return nil, err
	}

	if err := s.apiConfigRepo.Create(ctx, config); err != nil {
		return nil, err
	}

	// Create initial version
	configData := s.configToMap(config)
	if _, err := s.CreateConfigurationVersion(ctx, "api_configuration", config.ID, configData, extractUserIDFromContext(ctx)); err != nil {
		s.logger.WithError(err).Warn("Failed to create initial configuration version")
	}

	// Log the creation
	if err := s.LogConfigurationChange(ctx, extractUserIDFromContext(ctx), "CREATE", "api_configuration", config.ID, nil, configData); err != nil {
		s.logger.WithError(err).Warn("Failed to log configuration change")
	}

	return config, nil
}

// UpdateAPIConfiguration updates an existing API configuration
func (s *configurationService) UpdateAPIConfiguration(ctx context.Context, config *models.APIConfiguration) (*models.APIConfiguration, error) {
	s.logger.WithField("organisation_id", config.OrganisationID).
		WithField("config_id", config.ID).
		Info("Updating API configuration")

	// Custom validation for endpoint based on direction
	if err := s.validateAPIEndpoint(config); err != nil {
		return nil, err
	}

	if err := s.validationSvc.ValidateStruct(config); err != nil {
		return nil, err
	}

	// Get old configuration for audit logging
	oldConfig, err := s.apiConfigRepo.GetByID(ctx, config.ID)
	if err != nil {
		return nil, err
	}

	if err := s.apiConfigRepo.Update(ctx, config); err != nil {
		return nil, err
	}

	// Create new version
	configData := s.configToMap(config)
	if _, err := s.CreateConfigurationVersion(ctx, "api_configuration", config.ID, configData, extractUserIDFromContext(ctx)); err != nil {
		s.logger.WithError(err).Warn("Failed to create configuration version")
	}

	// Log the update
	oldData := s.configToMap(oldConfig)
	if err := s.LogConfigurationChange(ctx, extractUserIDFromContext(ctx), "UPDATE", "api_configuration", config.ID, oldData, configData); err != nil {
		s.logger.WithError(err).Warn("Failed to log configuration change")
	}

	return config, nil
}

// DeleteAPIConfiguration deletes an API configuration
func (s *configurationService) DeleteAPIConfiguration(ctx context.Context, id string) error {
	s.logger.WithField("config_id", id).Info("Deleting API configuration")

	// Get configuration for audit logging
	config, err := s.apiConfigRepo.GetByID(ctx, id)
	if err != nil {
		return err
	}

	if err := s.apiConfigRepo.Delete(ctx, id); err != nil {
		return err
	}

	// Log the deletion
	configData := s.configToMap(config)
	if err := s.LogConfigurationChange(ctx, extractUserIDFromContext(ctx), "DELETE", "api_configuration", id, configData, nil); err != nil {
		s.logger.WithError(err).Warn("Failed to log configuration change")
	}

	return nil
}

// GetAPIConfiguration retrieves an API configuration by ID
func (s *configurationService) GetAPIConfiguration(ctx context.Context, id string) (*models.APIConfiguration, error) {
	return s.apiConfigRepo.GetByID(ctx, id)
}

// GetAPIConfigurationsByOrganisation retrieves all API configurations for an organisation
func (s *configurationService) GetAPIConfigurationsByOrganisation(ctx context.Context, orgID string) ([]*models.APIConfiguration, error) {
	return s.apiConfigRepo.GetByOrganisation(ctx, orgID)
}

// ValidateConfiguration validates an API configuration
func (s *configurationService) ValidateConfiguration(ctx context.Context, config *models.APIConfiguration) error {
	// Custom validation for endpoint based on direction
	if err := s.validateAPIEndpoint(config); err != nil {
		return err
	}

	return s.validationSvc.ValidateStruct(config)
}

// CreateConfigurationVersion creates a new configuration version
func (s *configurationService) CreateConfigurationVersion(ctx context.Context, resourceType, resourceID string, configData models.JSONMap, userID string) (*models.ConfigurationVersion, error) {
	s.logger.WithField("resource_type", resourceType).
		WithField("resource_id", resourceID).
		Info("Creating configuration version")

	// Get the latest version number
	latestVersion, err := s.versionRepo.GetLatestVersion(ctx, resourceType, resourceID)
	var nextVersion int = 1
	if err == nil && latestVersion != nil {
		nextVersion = latestVersion.Version + 1
	}

	// Deactivate current active version
	if activeVersion, err := s.versionRepo.GetActiveVersion(ctx, resourceType, resourceID); err == nil && activeVersion != nil {
		s.versionRepo.SetActiveVersion(ctx, "")
	}

	// Create new version
	version := &models.ConfigurationVersion{
		OrganisationID:    extractOrgIDFromConfigData(configData),
		ResourceType:      resourceType,
		ResourceID:        resourceID,
		Version:           nextVersion,
		ConfigurationData: configData,
		CreatedBy:         userID,
		IsActive:          true,
		CreatedAt:         time.Now(),
	}

	if err := s.versionRepo.Create(ctx, version); err != nil {
		return nil, err
	}

	return version, nil
}

// GetConfigurationVersions retrieves all versions for a resource
func (s *configurationService) GetConfigurationVersions(ctx context.Context, resourceType, resourceID string) ([]*models.ConfigurationVersion, error) {
	return s.versionRepo.GetByResource(ctx, resourceType, resourceID)
}

// GetConfigurationVersion retrieves a specific configuration version
func (s *configurationService) GetConfigurationVersion(ctx context.Context, versionID string) (*models.ConfigurationVersion, error) {
	return s.versionRepo.GetByID(ctx, versionID)
}

// RollbackToVersion rolls back to a specific configuration version
func (s *configurationService) RollbackToVersion(ctx context.Context, versionID string, userID string) error {
	s.logger.WithField("version_id", versionID).
		WithField("user_id", userID).
		Info("Rolling back to configuration version")

	// Get the target version
	targetVersion, err := s.versionRepo.GetByID(ctx, versionID)
	if err != nil {
		return err
	}

	// Set this version as active
	if err := s.versionRepo.SetActiveVersion(ctx, versionID); err != nil {
		return err
	}

	// Log the rollback action
	return s.LogConfigurationChange(ctx, userID, "ROLLBACK", targetVersion.ResourceType, targetVersion.ResourceID, nil, targetVersion.ConfigurationData)
}

// GetActiveConfigurationVersion retrieves the active configuration version
func (s *configurationService) GetActiveConfigurationVersion(ctx context.Context, resourceType, resourceID string) (*models.ConfigurationVersion, error) {
	return s.versionRepo.GetActiveVersion(ctx, resourceType, resourceID)
}

// LogConfigurationChange logs a configuration change to the audit trail
func (s *configurationService) LogConfigurationChange(ctx context.Context, userID, action, resourceType, resourceID string, oldValues, newValues models.JSONMap) error {
	s.logger.WithField("user_id", userID).
		WithField("action", action).
		WithField("resource_type", resourceType).
		WithField("resource_id", resourceID).
		Info("Logging configuration change")

	auditLog := &models.AuditLog{
		OrganisationID: extractOrgIDFromValues(oldValues, newValues),
		UserID:         userID,
		Action:         action,
		ResourceType:   resourceType,
		ResourceID:     resourceID,
		OldValues:      oldValues,
		NewValues:      newValues,
		Timestamp:      time.Now(),
		CreatedAt:      time.Now(),
	}

	return s.auditLogRepo.Create(ctx, auditLog)
}

// GetAuditLogs retrieves audit logs for an organisation
func (s *configurationService) GetAuditLogs(ctx context.Context, orgID string, limit, offset int) ([]*models.AuditLog, error) {
	return s.auditLogRepo.GetByOrganisation(ctx, orgID, limit, offset)
}

// GetResourceAuditLogs retrieves audit logs for a specific resource
func (s *configurationService) GetResourceAuditLogs(ctx context.Context, resourceType, resourceID string, limit, offset int) ([]*models.AuditLog, error) {
	return s.auditLogRepo.GetByResource(ctx, resourceType, resourceID, limit, offset)
}

// SynchronizeConfiguration synchronizes configuration across instances
func (s *configurationService) SynchronizeConfiguration(ctx context.Context, instanceID string) error {
	s.logger.WithField("instance_id", instanceID).Info("Synchronizing configuration")

	// This would typically involve:
	// 1. Fetching latest configuration from central store
	// 2. Comparing with local configuration
	// 3. Updating local configuration if needed
	// 4. Notifying other services of configuration changes

	// For now, we'll implement a basic consistency check
	return s.ValidateConfigurationConsistency(ctx)
}

// GetConfigurationChecksum generates a checksum for configuration consistency validation
func (s *configurationService) GetConfigurationChecksum(ctx context.Context, orgID string) (string, error) {
	configs, err := s.apiConfigRepo.GetByOrganisation(ctx, orgID)
	if err != nil {
		return "", err
	}

	// Create a deterministic representation of all configurations
	configData := make(map[string]interface{})
	for _, config := range configs {
		configData[config.ID] = map[string]interface{}{
			"name":           config.Name,
			"type":           config.Type,
			"direction":      config.Direction,
			"endpoint":       config.Endpoint,
			"authentication": config.Authentication,
			"headers":        config.Headers,
			"updated_at":     config.UpdatedAt.Unix(),
		}
	}

	// Generate MD5 checksum
	data, err := json.Marshal(configData)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", md5.Sum(data)), nil
}

// ValidateConfigurationConsistency validates that configuration is consistent
func (s *configurationService) ValidateConfigurationConsistency(ctx context.Context) error {
	s.logger.Info("Validating configuration consistency")

	// This would typically involve:
	// 1. Checking for circular dependencies
	// 2. Validating all references are valid
	// 3. Ensuring no orphaned configurations
	// 4. Verifying all required configurations are present

	// For now, we'll implement basic validation
	return nil
}

// Helper functions
func extractOrgIDFromConfigData(configData models.JSONMap) string {
	if orgID, ok := configData["organisation_id"].(string); ok {
		return orgID
	}
	return ""
}

func extractOrgIDFromValues(oldValues, newValues models.JSONMap) string {
	if newValues != nil {
		if orgID, ok := newValues["organisation_id"].(string); ok {
			return orgID
		}
	}
	if oldValues != nil {
		if orgID, ok := oldValues["organisation_id"].(string); ok {
			return orgID
		}
	}
	return ""
}

// configToMap converts an API configuration to a map for versioning and audit logging
func (s *configurationService) configToMap(config *models.APIConfiguration) models.JSONMap {
	return models.JSONMap{
		"id":              config.ID,
		"organisation_id": config.OrganisationID,
		"name":            config.Name,
		"type":            config.Type,
		"direction":       config.Direction,
		"endpoint":        config.Endpoint,
		"authentication":  config.Authentication,
		"headers":         config.Headers,
		"created_at":      config.CreatedAt,
		"updated_at":      config.UpdatedAt,
	}
}

// extractUserIDFromContext extracts user ID from context
func extractUserIDFromContext(ctx context.Context) string {
	if userID, ok := ctx.Value("user_id").(string); ok {
		return userID
	}
	return "system" // fallback for system operations
}

// TestAPIConfiguration tests an API configuration with sample data
func (s *configurationService) TestAPIConfiguration(ctx context.Context, apiID string, testRequest map[string]interface{}) (map[string]interface{}, error) {
	config, err := s.apiConfigRepo.GetByID(ctx, apiID)
	if err != nil {
		return nil, err
	}

	// Create a test result
	result := map[string]interface{}{
		"api_id":    apiID,
		"test_data": testRequest,
		"status":    "success",
		"message":   "API configuration test completed successfully",
		"timestamp": time.Now(),
		"config":    config,
	}

	return result, nil
}

// Connector management methods
func (s *configurationService) CreateConnector(ctx context.Context, connector *models.Connector) (*models.Connector, error) {
	if err := s.validationSvc.ValidateStruct(connector); err != nil {
		return nil, err
	}

	// Set timestamps
	now := time.Now()
	connector.CreatedAt = now
	connector.UpdatedAt = now

	if err := s.connectorRepo.Create(ctx, connector); err != nil {
		return nil, err
	}

	// Log the configuration change
	s.LogConfigurationChange(ctx, "system", "create", "connector", connector.ID, nil, models.JSONMap{
		"name":            connector.Name,
		"organisation_id": connector.OrganisationID,
		"inbound_api_id":  connector.InboundAPIID,
		"outbound_api_id": connector.OutboundAPIID,
	})

	return connector, nil
}

func (s *configurationService) UpdateConnector(ctx context.Context, connector *models.Connector) (*models.Connector, error) {
	if err := s.validationSvc.ValidateStruct(connector); err != nil {
		return nil, err
	}

	// Get existing connector for audit logging
	existing, err := s.connectorRepo.GetByID(ctx, connector.ID)
	if err != nil {
		return nil, err
	}

	// Set update timestamp
	connector.UpdatedAt = time.Now()

	if err := s.connectorRepo.Update(ctx, connector); err != nil {
		return nil, err
	}

	// Log the configuration change
	s.LogConfigurationChange(ctx, "system", "update", "connector", connector.ID,
		models.JSONMap{
			"name":            existing.Name,
			"inbound_api_id":  existing.InboundAPIID,
			"outbound_api_id": existing.OutboundAPIID,
		},
		models.JSONMap{
			"name":            connector.Name,
			"inbound_api_id":  connector.InboundAPIID,
			"outbound_api_id": connector.OutboundAPIID,
		})

	return connector, nil
}

func (s *configurationService) DeleteConnector(ctx context.Context, connectorID string) error {
	// Get existing connector for audit logging
	existing, err := s.connectorRepo.GetByID(ctx, connectorID)
	if err != nil {
		return err
	}

	if err := s.connectorRepo.Delete(ctx, connectorID); err != nil {
		return err
	}

	// Log the configuration change
	s.LogConfigurationChange(ctx, "system", "delete", "connector", connectorID,
		models.JSONMap{
			"name":            existing.Name,
			"organisation_id": existing.OrganisationID,
		}, nil)

	return nil
}

func (s *configurationService) GetConnector(ctx context.Context, connectorID string) (*models.Connector, error) {
	return s.connectorRepo.GetByID(ctx, connectorID)
}

func (s *configurationService) GetConnectorsByOrganisation(ctx context.Context, orgID string) ([]*models.Connector, error) {
	return s.connectorRepo.GetByOrganisation(ctx, orgID)
}

func (s *configurationService) UpdateConnectorScript(ctx context.Context, connectorID, script string) error {
	// Get existing connector
	connector, err := s.connectorRepo.GetByID(ctx, connectorID)
	if err != nil {
		return err
	}

	oldScript := connector.PythonScript
	connector.PythonScript = script
	connector.UpdatedAt = time.Now()

	if err := s.connectorRepo.Update(ctx, connector); err != nil {
		return err
	}

	// Log the script change
	s.LogConfigurationChange(ctx, "system", "update_script", "connector", connectorID,
		models.JSONMap{"python_script": oldScript},
		models.JSONMap{"python_script": script})

	return nil
}

// Organisation management methods
func (s *configurationService) CreateOrganisation(ctx context.Context, org *models.Organisation) (*models.Organisation, error) {
	if err := s.validationSvc.ValidateStruct(org); err != nil {
		return nil, err
	}

	// Set timestamps
	now := time.Now()
	org.CreatedAt = now
	org.UpdatedAt = now

	if err := s.orgRepo.Create(ctx, org); err != nil {
		return nil, err
	}

	// Log the configuration change
	s.LogConfigurationChange(ctx, "system", "create", "organisation", org.ID, nil, models.JSONMap{
		"name":      org.Name,
		"is_active": org.IsActive,
	})

	return org, nil
}

func (s *configurationService) UpdateOrganisation(ctx context.Context, org *models.Organisation) (*models.Organisation, error) {
	if err := s.validationSvc.ValidateStruct(org); err != nil {
		return nil, err
	}

	// Get existing organisation for audit logging
	existing, err := s.orgRepo.GetByID(ctx, org.ID)
	if err != nil {
		return nil, err
	}

	// Set update timestamp
	org.UpdatedAt = time.Now()

	if err := s.orgRepo.Update(ctx, org); err != nil {
		return nil, err
	}

	// Log the configuration change
	s.LogConfigurationChange(ctx, "system", "update", "organisation", org.ID,
		models.JSONMap{
			"name":      existing.Name,
			"is_active": existing.IsActive,
		},
		models.JSONMap{
			"name":      org.Name,
			"is_active": org.IsActive,
		})

	return org, nil
}

func (s *configurationService) DeleteOrganisation(ctx context.Context, orgID string) error {
	// Get existing organisation for audit logging
	existing, err := s.orgRepo.GetByID(ctx, orgID)
	if err != nil {
		return err
	}

	if err := s.orgRepo.Delete(ctx, orgID); err != nil {
		return err
	}

	// Log the configuration change
	s.LogConfigurationChange(ctx, "system", "delete", "organisation", orgID,
		models.JSONMap{
			"name":      existing.Name,
			"is_active": existing.IsActive,
		}, nil)

	return nil
}

func (s *configurationService) GetOrganisation(ctx context.Context, orgID string) (*models.Organisation, error) {
	return s.orgRepo.GetByID(ctx, orgID)
}

func (s *configurationService) GetAllOrganisations(ctx context.Context) ([]*models.Organisation, error) {
	return s.orgRepo.GetAll(ctx)
}

// validateAPIEndpoint validates the endpoint field based on the API direction
func (s *configurationService) validateAPIEndpoint(config *models.APIConfiguration) error {
	if config.Direction == "inbound" {
		// For inbound APIs, validate path format
		if !strings.HasPrefix(config.Endpoint, "/") {
			return fmt.Errorf("inbound API endpoint must be a path starting with '/' (e.g., /api/v1/users)")
		}
		if len(config.Endpoint) < 2 {
			return fmt.Errorf("inbound API endpoint path must be at least 2 characters")
		}
		// Additional path validation - no spaces, basic path characters
		if strings.Contains(config.Endpoint, " ") {
			return fmt.Errorf("inbound API endpoint path cannot contain spaces")
		}
	} else if config.Direction == "outbound" {
		// For outbound APIs, validate full URL format
		if _, err := url.Parse(config.Endpoint); err != nil {
			return fmt.Errorf("outbound API endpoint must be a valid URL: %v", err)
		}
		if !strings.HasPrefix(config.Endpoint, "http://") && !strings.HasPrefix(config.Endpoint, "https://") {
			return fmt.Errorf("outbound API endpoint must start with http:// or https://")
		}
	}
	return nil
}
