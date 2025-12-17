package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"

	"api-translation-platform/internal/logger"
	"api-translation-platform/internal/models"
	"api-translation-platform/internal/services"
)

// ConfigurationHandler handles HTTP requests for configuration management
type ConfigurationHandler struct {
	logger    *logger.Logger
	configSvc services.ConfigurationService
}

// NewConfigurationHandler creates a new configuration handler
func NewConfigurationHandler(logger *logger.Logger, configSvc services.ConfigurationService) *ConfigurationHandler {
	return &ConfigurationHandler{
		logger:    logger,
		configSvc: configSvc,
	}
}

// RegisterRoutes registers all configuration management routes
func (h *ConfigurationHandler) RegisterRoutes(router *mux.Router) {
	// API Configuration routes
	router.HandleFunc("/api/v1/configurations", h.CreateAPIConfiguration).Methods("POST")
	router.HandleFunc("/api/v1/configurations/{id}", h.GetAPIConfiguration).Methods("GET")
	router.HandleFunc("/api/v1/configurations/{id}", h.UpdateAPIConfiguration).Methods("PUT")
	router.HandleFunc("/api/v1/configurations/{id}", h.DeleteAPIConfiguration).Methods("DELETE")
	router.HandleFunc("/api/v1/organisations/{orgId}/configurations", h.GetAPIConfigurationsByOrganisation).Methods("GET")

	// Configuration versioning routes
	router.HandleFunc("/api/v1/configurations/{id}/versions", h.GetConfigurationVersions).Methods("GET")
	router.HandleFunc("/api/v1/configurations/versions/{versionId}", h.GetConfigurationVersion).Methods("GET")
	router.HandleFunc("/api/v1/configurations/versions/{versionId}/rollback", h.RollbackToVersion).Methods("POST")
	router.HandleFunc("/api/v1/configurations/{id}/versions/active", h.GetActiveConfigurationVersion).Methods("GET")

	// Audit logging routes
	router.HandleFunc("/api/v1/organisations/{orgId}/audit-logs", h.GetAuditLogs).Methods("GET")
	router.HandleFunc("/api/v1/configurations/{id}/audit-logs", h.GetResourceAuditLogs).Methods("GET")

	// Configuration synchronization routes
	router.HandleFunc("/api/v1/configurations/sync/{instanceId}", h.SynchronizeConfiguration).Methods("POST")
	router.HandleFunc("/api/v1/organisations/{orgId}/configurations/checksum", h.GetConfigurationChecksum).Methods("GET")
	router.HandleFunc("/api/v1/configurations/validate-consistency", h.ValidateConfigurationConsistency).Methods("POST")
}

// CreateAPIConfiguration creates a new API configuration
func (h *ConfigurationHandler) CreateAPIConfiguration(w http.ResponseWriter, r *http.Request) {
	var config models.APIConfiguration
	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	ctx := r.Context()
	createdConfig, err := h.configSvc.CreateAPIConfiguration(ctx, &config)
	if err != nil {
		h.logger.WithError(err).Error("Failed to create API configuration")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to create configuration")
		return
	}

	h.writeJSONResponse(w, http.StatusCreated, createdConfig)
}

// GetAPIConfiguration retrieves an API configuration by ID
func (h *ConfigurationHandler) GetAPIConfiguration(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	ctx := r.Context()
	config, err := h.configSvc.GetAPIConfiguration(ctx, id)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get API configuration")
		h.writeErrorResponse(w, http.StatusNotFound, "Configuration not found")
		return
	}

	h.writeJSONResponse(w, http.StatusOK, config)
}

// UpdateAPIConfiguration updates an existing API configuration
func (h *ConfigurationHandler) UpdateAPIConfiguration(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	var config models.APIConfiguration
	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	config.ID = id
	ctx := r.Context()
	updatedConfig, err := h.configSvc.UpdateAPIConfiguration(ctx, &config)
	if err != nil {
		h.logger.WithError(err).Error("Failed to update API configuration")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to update configuration")
		return
	}

	h.writeJSONResponse(w, http.StatusOK, updatedConfig)
}

// DeleteAPIConfiguration deletes an API configuration
func (h *ConfigurationHandler) DeleteAPIConfiguration(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	ctx := r.Context()
	if err := h.configSvc.DeleteAPIConfiguration(ctx, id); err != nil {
		h.logger.WithError(err).Error("Failed to delete API configuration")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to delete configuration")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// GetAPIConfigurationsByOrganisation retrieves all API configurations for an organisation
func (h *ConfigurationHandler) GetAPIConfigurationsByOrganisation(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	orgID := vars["orgId"]

	ctx := r.Context()
	configs, err := h.configSvc.GetAPIConfigurationsByOrganisation(ctx, orgID)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get API configurations by organisation")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to get configurations")
		return
	}

	h.writeJSONResponse(w, http.StatusOK, configs)
}

// GetConfigurationVersions retrieves all versions for a configuration
func (h *ConfigurationHandler) GetConfigurationVersions(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	ctx := r.Context()
	versions, err := h.configSvc.GetConfigurationVersions(ctx, "api_configuration", id)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get configuration versions")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to get versions")
		return
	}

	h.writeJSONResponse(w, http.StatusOK, versions)
}

// GetConfigurationVersion retrieves a specific configuration version
func (h *ConfigurationHandler) GetConfigurationVersion(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	versionID := vars["versionId"]

	ctx := r.Context()
	version, err := h.configSvc.GetConfigurationVersion(ctx, versionID)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get configuration version")
		h.writeErrorResponse(w, http.StatusNotFound, "Version not found")
		return
	}

	h.writeJSONResponse(w, http.StatusOK, version)
}

// RollbackToVersion rolls back to a specific configuration version
func (h *ConfigurationHandler) RollbackToVersion(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	versionID := vars["versionId"]

	ctx := r.Context()
	userID := extractUserIDFromContext(ctx)

	if err := h.configSvc.RollbackToVersion(ctx, versionID, userID); err != nil {
		h.logger.WithError(err).Error("Failed to rollback to version")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to rollback")
		return
	}

	h.writeJSONResponse(w, http.StatusOK, map[string]string{"message": "Rollback successful"})
}

// GetActiveConfigurationVersion retrieves the active configuration version
func (h *ConfigurationHandler) GetActiveConfigurationVersion(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	ctx := r.Context()
	version, err := h.configSvc.GetActiveConfigurationVersion(ctx, "api_configuration", id)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get active configuration version")
		h.writeErrorResponse(w, http.StatusNotFound, "Active version not found")
		return
	}

	h.writeJSONResponse(w, http.StatusOK, version)
}

// GetAuditLogs retrieves audit logs for an organisation
func (h *ConfigurationHandler) GetAuditLogs(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	orgID := vars["orgId"]

	limit, offset := h.parsePaginationParams(r)

	ctx := r.Context()
	logs, err := h.configSvc.GetAuditLogs(ctx, orgID, limit, offset)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get audit logs")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to get audit logs")
		return
	}

	h.writeJSONResponse(w, http.StatusOK, logs)
}

// GetResourceAuditLogs retrieves audit logs for a specific resource
func (h *ConfigurationHandler) GetResourceAuditLogs(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	limit, offset := h.parsePaginationParams(r)

	ctx := r.Context()
	logs, err := h.configSvc.GetResourceAuditLogs(ctx, "api_configuration", id, limit, offset)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get resource audit logs")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to get audit logs")
		return
	}

	h.writeJSONResponse(w, http.StatusOK, logs)
}

// SynchronizeConfiguration synchronizes configuration across instances
func (h *ConfigurationHandler) SynchronizeConfiguration(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	instanceID := vars["instanceId"]

	ctx := r.Context()
	if err := h.configSvc.SynchronizeConfiguration(ctx, instanceID); err != nil {
		h.logger.WithError(err).Error("Failed to synchronize configuration")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to synchronize")
		return
	}

	h.writeJSONResponse(w, http.StatusOK, map[string]string{"message": "Synchronization successful"})
}

// GetConfigurationChecksum generates a checksum for configuration consistency validation
func (h *ConfigurationHandler) GetConfigurationChecksum(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	orgID := vars["orgId"]

	ctx := r.Context()
	checksum, err := h.configSvc.GetConfigurationChecksum(ctx, orgID)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get configuration checksum")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to get checksum")
		return
	}

	h.writeJSONResponse(w, http.StatusOK, map[string]string{"checksum": checksum})
}

// ValidateConfigurationConsistency validates that configuration is consistent
func (h *ConfigurationHandler) ValidateConfigurationConsistency(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := h.configSvc.ValidateConfigurationConsistency(ctx); err != nil {
		h.logger.WithError(err).Error("Configuration consistency validation failed")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Consistency validation failed")
		return
	}

	h.writeJSONResponse(w, http.StatusOK, map[string]string{"message": "Configuration is consistent"})
}

// Helper methods

func (h *ConfigurationHandler) writeJSONResponse(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(data)
}

func (h *ConfigurationHandler) writeErrorResponse(w http.ResponseWriter, statusCode int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

func (h *ConfigurationHandler) parsePaginationParams(r *http.Request) (limit, offset int) {
	limit = 50 // default limit
	offset = 0 // default offset

	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if parsedLimit, err := strconv.Atoi(limitStr); err == nil && parsedLimit > 0 && parsedLimit <= 100 {
			limit = parsedLimit
		}
	}

	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		if parsedOffset, err := strconv.Atoi(offsetStr); err == nil && parsedOffset >= 0 {
			offset = parsedOffset
		}
	}

	return limit, offset
}

func extractUserIDFromContext(ctx context.Context) string {
	if userID, ok := ctx.Value("user_id").(string); ok {
		return userID
	}
	return "system" // fallback for system operations
}
