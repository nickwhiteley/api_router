package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"api-translation-platform/internal/logger"
	"api-translation-platform/internal/models"
	"api-translation-platform/internal/services"

	"github.com/gorilla/mux"
)

// WebUIHandler handles web UI related requests
type WebUIHandler struct {
	logger         *logger.Logger
	authService    services.AuthenticationService
	authzService   services.AuthorizationService
	configService  services.ConfigurationService
	monitorService services.MonitoringService
}

// NewWebUIHandler creates a new web UI handler
func NewWebUIHandler(
	logger *logger.Logger,
	authService services.AuthenticationService,
	authzService services.AuthorizationService,
	configService services.ConfigurationService,
	monitorService services.MonitoringService,
) *WebUIHandler {
	return &WebUIHandler{
		logger:         logger,
		authService:    authService,
		authzService:   authzService,
		configService:  configService,
		monitorService: monitorService,
	}
}

// RegisterRoutes registers web UI routes
func (h *WebUIHandler) RegisterRoutes(router *mux.Router) {
	// Organisation-aware routing
	orgRouter := router.PathPrefix("/ui/{orgID}").Subrouter()
	orgRouter.Use(h.jwtAuthenticationMiddleware)
	orgRouter.Use(h.organisationMiddleware)

	// Dashboard routes
	orgRouter.HandleFunc("/dashboard", h.getDashboard).Methods("GET")
	orgRouter.HandleFunc("/dashboard/metrics", h.getDashboardMetrics).Methods("GET")

	// API configuration routes
	orgRouter.HandleFunc("/apis", h.getAPIConfigurations).Methods("GET")
	orgRouter.HandleFunc("/apis", h.createAPIConfiguration).Methods("POST")
	orgRouter.HandleFunc("/apis/{apiID}", h.getAPIConfiguration).Methods("GET")
	orgRouter.HandleFunc("/apis/{apiID}", h.updateAPIConfiguration).Methods("PUT")
	orgRouter.HandleFunc("/apis/{apiID}", h.deleteAPIConfiguration).Methods("DELETE")
	orgRouter.HandleFunc("/apis/{apiID}/test", h.testAPIConfiguration).Methods("POST")

	// Connector management routes
	orgRouter.HandleFunc("/connectors", h.getConnectors).Methods("GET")
	orgRouter.HandleFunc("/connectors", h.createConnector).Methods("POST")
	orgRouter.HandleFunc("/connectors/{connectorID}", h.getConnector).Methods("GET")
	orgRouter.HandleFunc("/connectors/{connectorID}", h.updateConnector).Methods("PUT")
	orgRouter.HandleFunc("/connectors/{connectorID}", h.deleteConnector).Methods("DELETE")
	orgRouter.HandleFunc("/connectors/{connectorID}/script", h.updateConnectorScript).Methods("PUT")

	// Monitoring routes
	orgRouter.HandleFunc("/logs", h.getLogs).Methods("GET")
	orgRouter.HandleFunc("/logs/errors", h.getErrorLogs).Methods("GET")
	orgRouter.HandleFunc("/metrics", h.getMetrics).Methods("GET")

	// Global admin routes (no organisation prefix)
	globalRouter := router.PathPrefix("/ui/admin").Subrouter()
	globalRouter.Use(h.jwtAuthenticationMiddleware)
	globalRouter.Use(h.globalAdminMiddleware)

	globalRouter.HandleFunc("/organisations", h.getOrganisations).Methods("GET")
	globalRouter.HandleFunc("/organisations", h.createOrganisation).Methods("POST")
	globalRouter.HandleFunc("/organisations/{orgID}", h.getOrganisation).Methods("GET")
	globalRouter.HandleFunc("/organisations/{orgID}", h.updateOrganisation).Methods("PUT")
	globalRouter.HandleFunc("/organisations/{orgID}", h.deleteOrganisation).Methods("DELETE")
	globalRouter.HandleFunc("/system/health", h.getSystemHealth).Methods("GET")
	globalRouter.HandleFunc("/system/metrics", h.getSystemMetrics).Methods("GET")
	globalRouter.HandleFunc("/system/logs", h.getSystemLogs).Methods("GET")
}

// organisationMiddleware ensures user has access to the organisation
func (h *WebUIHandler) organisationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := h.getUserFromContext(r)
		if user == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		vars := mux.Vars(r)
		orgID := vars["orgID"]

		if !h.authzService.CanAccessResource(r.Context(), user, orgID) {
			h.authzService.LogSecurityViolation(r.Context(), user, "unauthorized_org_access", orgID)
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// globalAdminMiddleware ensures user is a global admin
func (h *WebUIHandler) globalAdminMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := h.getUserFromContext(r)
		if user == nil || !user.IsGlobalAdmin() {
			if user != nil {
				h.authzService.LogSecurityViolation(r.Context(), user, "unauthorized_global_admin_access", "system")
			}
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// jwtAuthenticationMiddleware handles JWT authentication for web UI
func (h *WebUIHandler) jwtAuthenticationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract JWT token from Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Missing Authorization header", http.StatusUnauthorized)
			return
		}

		// Check for Bearer token format
		const bearerPrefix = "Bearer "
		if !strings.HasPrefix(authHeader, bearerPrefix) {
			http.Error(w, "Invalid Authorization header format", http.StatusUnauthorized)
			return
		}

		token := authHeader[len(bearerPrefix):]
		if token == "" {
			http.Error(w, "Missing JWT token", http.StatusUnauthorized)
			return
		}

		// Validate JWT token
		user, err := h.authService.ValidateJWT(r.Context(), token)
		if err != nil {
			h.logger.WithError(err).Warn("JWT validation failed")
			http.Error(w, "Invalid JWT token", http.StatusUnauthorized)
			return
		}

		// Add user to request context
		ctx := context.WithValue(r.Context(), "user", user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// getUserFromContext extracts user from request context
func (h *WebUIHandler) getUserFromContext(r *http.Request) *models.User {
	user, ok := r.Context().Value("user").(*models.User)
	if !ok {
		return nil
	}
	return user
}

// Dashboard handlers
func (h *WebUIHandler) getDashboard(w http.ResponseWriter, r *http.Request) {
	user := h.getUserFromContext(r)
	vars := mux.Vars(r)
	orgID := vars["orgID"]

	// Get dashboard data filtered by organisation
	dashboardData := map[string]interface{}{
		"organisation_id": orgID,
		"user_role":       user.Role,
		"apis":            h.getFilteredAPIConfigurations(r, orgID),
		"connectors":      h.getFilteredConnectors(r, orgID),
		"recent_logs":     h.getFilteredRecentLogs(r, orgID),
		"metrics":         h.getFilteredMetrics(r, orgID),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(dashboardData)
}

func (h *WebUIHandler) getDashboardMetrics(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	orgID := vars["orgID"]

	metrics, err := h.monitorService.GetOrganisationMetrics(r.Context(), orgID)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get dashboard metrics")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(metrics)
}

// API Configuration handlers
func (h *WebUIHandler) getAPIConfigurations(w http.ResponseWriter, r *http.Request) {
	user := h.getUserFromContext(r)
	vars := mux.Vars(r)
	orgID := vars["orgID"]

	configs, err := h.configService.GetAPIConfigurationsByOrganisation(r.Context(), orgID)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get API configurations")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Apply role-based filtering
	filteredConfigs := h.authzService.FilterByOrganisation(r.Context(), user, configs)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(filteredConfigs)
}

func (h *WebUIHandler) createAPIConfiguration(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	orgID := vars["orgID"]

	var config models.APIConfiguration
	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Ensure organisation ID matches route
	config.OrganisationID = orgID

	createdConfig, err := h.configService.CreateAPIConfiguration(r.Context(), &config)
	if err != nil {
		h.logger.WithError(err).Error("Failed to create API configuration")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(createdConfig)
}

func (h *WebUIHandler) getAPIConfiguration(w http.ResponseWriter, r *http.Request) {
	user := h.getUserFromContext(r)
	vars := mux.Vars(r)
	apiID := vars["apiID"]

	config, err := h.configService.GetAPIConfiguration(r.Context(), apiID)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get API configuration")
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	// Apply role-based filtering
	filteredConfig := h.authzService.FilterByOrganisation(r.Context(), user, config)
	if filteredConfig == nil {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(filteredConfig)
}

func (h *WebUIHandler) updateAPIConfiguration(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	apiID := vars["apiID"]
	orgID := vars["orgID"]

	var config models.APIConfiguration
	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Ensure IDs match route
	config.ID = apiID
	config.OrganisationID = orgID

	updatedConfig, err := h.configService.UpdateAPIConfiguration(r.Context(), &config)
	if err != nil {
		h.logger.WithError(err).Error("Failed to update API configuration")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(updatedConfig)
}

func (h *WebUIHandler) deleteAPIConfiguration(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	apiID := vars["apiID"]

	err := h.configService.DeleteAPIConfiguration(r.Context(), apiID)
	if err != nil {
		h.logger.WithError(err).Error("Failed to delete API configuration")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *WebUIHandler) testAPIConfiguration(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	apiID := vars["apiID"]

	var testRequest map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&testRequest); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Test the API configuration
	result, err := h.configService.TestAPIConfiguration(r.Context(), apiID, testRequest)
	if err != nil {
		h.logger.WithError(err).Error("Failed to test API configuration")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// Helper methods for filtered data
func (h *WebUIHandler) getFilteredAPIConfigurations(r *http.Request, orgID string) interface{} {
	user := h.getUserFromContext(r)
	configs, err := h.configService.GetAPIConfigurationsByOrganisation(r.Context(), orgID)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get API configurations for dashboard")
		return []interface{}{}
	}
	return h.authzService.FilterByOrganisation(r.Context(), user, configs)
}

func (h *WebUIHandler) getFilteredConnectors(r *http.Request, orgID string) interface{} {
	user := h.getUserFromContext(r)
	connectors, err := h.configService.GetConnectorsByOrganisation(r.Context(), orgID)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get connectors for dashboard")
		return []interface{}{}
	}
	return h.authzService.FilterByOrganisation(r.Context(), user, connectors)
}

func (h *WebUIHandler) getFilteredRecentLogs(r *http.Request, orgID string) interface{} {
	user := h.getUserFromContext(r)
	logs, err := h.monitorService.GetRecentLogs(r.Context(), orgID, 10)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get recent logs for dashboard")
		return []interface{}{}
	}
	return h.authzService.FilterByOrganisation(r.Context(), user, logs)
}

func (h *WebUIHandler) getFilteredMetrics(r *http.Request, orgID string) interface{} {
	metrics, err := h.monitorService.GetOrganisationMetrics(r.Context(), orgID)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get metrics for dashboard")
		return map[string]interface{}{}
	}
	return metrics
}

// Connector handlers (simplified for brevity)
func (h *WebUIHandler) getConnectors(w http.ResponseWriter, r *http.Request) {
	user := h.getUserFromContext(r)
	vars := mux.Vars(r)
	orgID := vars["orgID"]

	connectors, err := h.configService.GetConnectorsByOrganisation(r.Context(), orgID)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get connectors")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	filteredConnectors := h.authzService.FilterByOrganisation(r.Context(), user, connectors)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(filteredConnectors)
}

func (h *WebUIHandler) createConnector(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	orgID := vars["orgID"]

	var connector models.Connector
	if err := json.NewDecoder(r.Body).Decode(&connector); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	connector.OrganisationID = orgID

	createdConnector, err := h.configService.CreateConnector(r.Context(), &connector)
	if err != nil {
		h.logger.WithError(err).Error("Failed to create connector")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(createdConnector)
}

func (h *WebUIHandler) getConnector(w http.ResponseWriter, r *http.Request) {
	user := h.getUserFromContext(r)
	vars := mux.Vars(r)
	connectorID := vars["connectorID"]

	connector, err := h.configService.GetConnector(r.Context(), connectorID)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get connector")
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	filteredConnector := h.authzService.FilterByOrganisation(r.Context(), user, connector)
	if filteredConnector == nil {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(filteredConnector)
}

func (h *WebUIHandler) updateConnector(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	connectorID := vars["connectorID"]
	orgID := vars["orgID"]

	var connector models.Connector
	if err := json.NewDecoder(r.Body).Decode(&connector); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	connector.ID = connectorID
	connector.OrganisationID = orgID

	updatedConnector, err := h.configService.UpdateConnector(r.Context(), &connector)
	if err != nil {
		h.logger.WithError(err).Error("Failed to update connector")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(updatedConnector)
}

func (h *WebUIHandler) deleteConnector(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	connectorID := vars["connectorID"]

	err := h.configService.DeleteConnector(r.Context(), connectorID)
	if err != nil {
		h.logger.WithError(err).Error("Failed to delete connector")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *WebUIHandler) updateConnectorScript(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	connectorID := vars["connectorID"]

	var scriptUpdate struct {
		PythonScript string `json:"python_script"`
	}
	if err := json.NewDecoder(r.Body).Decode(&scriptUpdate); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	err := h.configService.UpdateConnectorScript(r.Context(), connectorID, scriptUpdate.PythonScript)
	if err != nil {
		h.logger.WithError(err).Error("Failed to update connector script")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// Monitoring handlers
func (h *WebUIHandler) getLogs(w http.ResponseWriter, r *http.Request) {
	user := h.getUserFromContext(r)
	vars := mux.Vars(r)
	orgID := vars["orgID"]

	// Parse query parameters
	limitStr := r.URL.Query().Get("limit")
	offsetStr := r.URL.Query().Get("offset")

	limit := 50 // default
	offset := 0 // default

	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	if offsetStr != "" {
		if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 {
			offset = o
		}
	}

	logs, err := h.monitorService.GetLogsByOrganisation(r.Context(), orgID, limit, offset)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get logs")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	filteredLogs := h.authzService.FilterByOrganisation(r.Context(), user, logs)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(filteredLogs)
}

func (h *WebUIHandler) getErrorLogs(w http.ResponseWriter, r *http.Request) {
	user := h.getUserFromContext(r)
	vars := mux.Vars(r)
	orgID := vars["orgID"]

	// Parse query parameters
	limitStr := r.URL.Query().Get("limit")
	offsetStr := r.URL.Query().Get("offset")

	limit := 50 // default
	offset := 0 // default

	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	if offsetStr != "" {
		if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 {
			offset = o
		}
	}

	errorLogs, err := h.monitorService.GetErrorLogs(r.Context(), orgID, limit, offset)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get error logs")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	filteredLogs := h.authzService.FilterByOrganisation(r.Context(), user, errorLogs)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(filteredLogs)
}

func (h *WebUIHandler) getMetrics(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	orgID := vars["orgID"]

	metrics, err := h.monitorService.GetOrganisationMetrics(r.Context(), orgID)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get metrics")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(metrics)
}

// Global admin handlers
func (h *WebUIHandler) getOrganisations(w http.ResponseWriter, r *http.Request) {
	organisations, err := h.configService.GetAllOrganisations(r.Context())
	if err != nil {
		h.logger.WithError(err).Error("Failed to get organisations")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(organisations)
}

func (h *WebUIHandler) createOrganisation(w http.ResponseWriter, r *http.Request) {
	var org models.Organisation
	if err := json.NewDecoder(r.Body).Decode(&org); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	createdOrg, err := h.configService.CreateOrganisation(r.Context(), &org)
	if err != nil {
		h.logger.WithError(err).Error("Failed to create organisation")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(createdOrg)
}

func (h *WebUIHandler) getOrganisation(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	orgID := vars["orgID"]

	org, err := h.configService.GetOrganisation(r.Context(), orgID)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get organisation")
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(org)
}

func (h *WebUIHandler) updateOrganisation(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	orgID := vars["orgID"]

	var org models.Organisation
	if err := json.NewDecoder(r.Body).Decode(&org); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	org.ID = orgID

	updatedOrg, err := h.configService.UpdateOrganisation(r.Context(), &org)
	if err != nil {
		h.logger.WithError(err).Error("Failed to update organisation")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(updatedOrg)
}

func (h *WebUIHandler) deleteOrganisation(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	orgID := vars["orgID"]

	err := h.configService.DeleteOrganisation(r.Context(), orgID)
	if err != nil {
		h.logger.WithError(err).Error("Failed to delete organisation")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *WebUIHandler) getSystemHealth(w http.ResponseWriter, r *http.Request) {
	health, err := h.monitorService.GetSystemHealth(r.Context())
	if err != nil {
		h.logger.WithError(err).Error("Failed to get system health")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(health)
}

func (h *WebUIHandler) getSystemMetrics(w http.ResponseWriter, r *http.Request) {
	metrics, err := h.monitorService.GetSystemMetrics(r.Context())
	if err != nil {
		h.logger.WithError(err).Error("Failed to get system metrics")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(metrics)
}

func (h *WebUIHandler) getSystemLogs(w http.ResponseWriter, r *http.Request) {
	// Parse query parameters
	limitStr := r.URL.Query().Get("limit")
	offsetStr := r.URL.Query().Get("offset")

	limit := 100 // default
	offset := 0  // default

	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	if offsetStr != "" {
		if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 {
			offset = o
		}
	}

	logs, err := h.monitorService.GetSystemLogs(r.Context(), limit, offset)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get system logs")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(logs)
}
