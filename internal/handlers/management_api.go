package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"api-translation-platform/internal/logger"
	"api-translation-platform/internal/models"
	"api-translation-platform/internal/services"
)

// ManagementAPIHandler handles comprehensive REST API operations
type ManagementAPIHandler struct {
	logger        *logger.Logger
	configSvc     services.ConfigurationService
	authSvc       services.AuthenticationService
	authzSvc      services.AuthorizationService
	userMgmtSvc   services.UserManagementService
	monitoringSvc services.MonitoringService

	// Rate limiting metrics
	rateLimitCounter prometheus.Counter
	apiUsageCounter  *prometheus.CounterVec
}

// NewManagementAPIHandler creates a new management API handler
func NewManagementAPIHandler(
	logger *logger.Logger,
	configSvc services.ConfigurationService,
	authSvc services.AuthenticationService,
	authzSvc services.AuthorizationService,
	userMgmtSvc services.UserManagementService,
	monitoringSvc services.MonitoringService,
) *ManagementAPIHandler {
	// Create a new registry for tests to avoid conflicts
	registry := prometheus.NewRegistry()
	factory := promauto.With(registry)

	return &ManagementAPIHandler{
		logger:        logger,
		configSvc:     configSvc,
		authSvc:       authSvc,
		authzSvc:      authzSvc,
		userMgmtSvc:   userMgmtSvc,
		monitoringSvc: monitoringSvc,
		rateLimitCounter: factory.NewCounter(prometheus.CounterOpts{
			Name: "management_api_rate_limit_exceeded_total",
			Help: "Total number of rate limit exceeded events",
		}),
		apiUsageCounter: factory.NewCounterVec(prometheus.CounterOpts{
			Name: "management_api_requests_total",
			Help: "Total number of management API requests",
		}, []string{"method", "endpoint", "status", "version"}),
	}
}

// RegisterRoutes registers all management API routes with versioning
func (h *ManagementAPIHandler) RegisterRoutes(router *mux.Router) {
	// API v1 routes
	v1 := router.PathPrefix("/api/v1").Subrouter()
	h.registerV1Routes(v1)

	// API v2 routes (for future backward compatibility)
	v2 := router.PathPrefix("/api/v2").Subrouter()
	h.registerV2Routes(v2)

	// Default to latest version
	router.PathPrefix("/api").Handler(http.StripPrefix("/api", v1))
}

// registerV1Routes registers version 1 API routes
func (h *ManagementAPIHandler) registerV1Routes(router *mux.Router) {
	// Apply middleware
	router.Use(h.rateLimitMiddleware)
	router.Use(h.usageAnalyticsMiddleware("v1"))
	router.Use(h.authenticationMiddleware)

	// Organisation management
	router.HandleFunc("/organisations", h.CreateOrganisation).Methods("POST")
	router.HandleFunc("/organisations", h.GetAllOrganisations).Methods("GET")
	router.HandleFunc("/organisations/{id}", h.GetOrganisation).Methods("GET")
	router.HandleFunc("/organisations/{id}", h.UpdateOrganisation).Methods("PUT")
	router.HandleFunc("/organisations/{id}", h.DeleteOrganisation).Methods("DELETE")

	// User management
	router.HandleFunc("/organisations/{orgId}/users", h.CreateUser).Methods("POST")
	router.HandleFunc("/organisations/{orgId}/users", h.GetUsersByOrganisation).Methods("GET")
	router.HandleFunc("/users/{id}", h.GetUser).Methods("GET")
	router.HandleFunc("/users/{id}", h.UpdateUser).Methods("PUT")
	router.HandleFunc("/users/{id}", h.DeleteUser).Methods("DELETE")
	router.HandleFunc("/users/{id}/role", h.ChangeUserRole).Methods("PUT")
	router.HandleFunc("/users/{id}/password", h.ChangeUserPassword).Methods("PUT")
	router.HandleFunc("/users/{id}/activate", h.ActivateUser).Methods("POST")
	router.HandleFunc("/users/{id}/deactivate", h.DeactivateUser).Methods("POST")

	// API Configuration management
	router.HandleFunc("/organisations/{orgId}/api-configurations", h.CreateAPIConfiguration).Methods("POST")
	router.HandleFunc("/organisations/{orgId}/api-configurations", h.GetAPIConfigurationsByOrganisation).Methods("GET")
	router.HandleFunc("/api-configurations/{id}", h.GetAPIConfiguration).Methods("GET")
	router.HandleFunc("/api-configurations/{id}", h.UpdateAPIConfiguration).Methods("PUT")
	router.HandleFunc("/api-configurations/{id}", h.DeleteAPIConfiguration).Methods("DELETE")
	router.HandleFunc("/api-configurations/{id}/test", h.TestAPIConfiguration).Methods("POST")

	// Connector management
	router.HandleFunc("/organisations/{orgId}/connectors", h.CreateConnector).Methods("POST")
	router.HandleFunc("/organisations/{orgId}/connectors", h.GetConnectorsByOrganisation).Methods("GET")
	router.HandleFunc("/connectors/{id}", h.GetConnector).Methods("GET")
	router.HandleFunc("/connectors/{id}", h.UpdateConnector).Methods("PUT")
	router.HandleFunc("/connectors/{id}", h.DeleteConnector).Methods("DELETE")
	router.HandleFunc("/connectors/{id}/script", h.UpdateConnectorScript).Methods("PUT")

	// Configuration versioning
	router.HandleFunc("/configurations/{id}/versions", h.GetConfigurationVersions).Methods("GET")
	router.HandleFunc("/configurations/versions/{versionId}", h.GetConfigurationVersion).Methods("GET")
	router.HandleFunc("/configurations/versions/{versionId}/rollback", h.RollbackToVersion).Methods("POST")

	// Monitoring and metrics
	router.HandleFunc("/organisations/{orgId}/metrics", h.GetOrganisationMetrics).Methods("GET")
	router.HandleFunc("/organisations/{orgId}/logs", h.GetOrganisationLogs).Methods("GET")
	router.HandleFunc("/organisations/{orgId}/errors", h.GetOrganisationErrors).Methods("GET")
	router.HandleFunc("/system/metrics", h.GetSystemMetrics).Methods("GET")
	router.HandleFunc("/system/health", h.GetSystemHealth).Methods("GET")
	router.HandleFunc("/system/logs", h.GetSystemLogs).Methods("GET")

	// Audit logs
	router.HandleFunc("/organisations/{orgId}/audit-logs", h.GetAuditLogs).Methods("GET")
	router.HandleFunc("/configurations/{id}/audit-logs", h.GetResourceAuditLogs).Methods("GET")

	// Configuration synchronization
	router.HandleFunc("/system/sync/{instanceId}", h.SynchronizeConfiguration).Methods("POST")
	router.HandleFunc("/organisations/{orgId}/checksum", h.GetConfigurationChecksum).Methods("GET")
	router.HandleFunc("/system/validate-consistency", h.ValidateConfigurationConsistency).Methods("POST")

	// API documentation
	router.HandleFunc("/docs/openapi.json", h.GetOpenAPISpec).Methods("GET")
	router.HandleFunc("/docs/swagger", h.GetSwaggerUI).Methods("GET")

	// API usage analytics
	router.HandleFunc("/analytics/usage", h.GetAPIUsageAnalytics).Methods("GET")
	router.HandleFunc("/analytics/rate-limits", h.GetRateLimitAnalytics).Methods("GET")
}

// registerV2Routes registers version 2 API routes (for future backward compatibility)
func (h *ManagementAPIHandler) registerV2Routes(router *mux.Router) {
	// Apply middleware
	router.Use(h.rateLimitMiddleware)
	router.Use(h.usageAnalyticsMiddleware("v2"))
	router.Use(h.authenticationMiddleware)

	// For now, v2 routes are identical to v1 (backward compatibility)
	// In the future, this would contain enhanced or modified endpoints
	h.registerV1Routes(router)
}

// Organisation Management Handlers

func (h *ManagementAPIHandler) CreateOrganisation(w http.ResponseWriter, r *http.Request) {
	var org models.Organisation
	if err := json.NewDecoder(r.Body).Decode(&org); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	ctx := r.Context()
	createdOrg, err := h.configSvc.CreateOrganisation(ctx, &org)
	if err != nil {
		h.logger.WithError(err).Error("Failed to create organisation")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to create organisation", err)
		return
	}

	h.writeJSONResponse(w, http.StatusCreated, createdOrg)
}

func (h *ManagementAPIHandler) GetAllOrganisations(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	user := h.getUserFromContext(ctx)

	orgs, err := h.configSvc.GetAllOrganisations(ctx)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get organisations")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to get organisations", err)
		return
	}

	// Filter based on user permissions
	filteredOrgs := h.authzSvc.FilterByOrganisation(ctx, user, orgs)
	h.writeJSONResponse(w, http.StatusOK, filteredOrgs)
}

func (h *ManagementAPIHandler) GetOrganisation(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	ctx := r.Context()
	user := h.getUserFromContext(ctx)

	if !h.authzSvc.CanAccessResource(ctx, user, id) {
		h.authzSvc.LogSecurityViolation(ctx, user, "unauthorized_organisation_access", id)
		h.writeErrorResponse(w, http.StatusForbidden, "Access denied", nil)
		return
	}

	org, err := h.configSvc.GetOrganisation(ctx, id)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get organisation")
		h.writeErrorResponse(w, http.StatusNotFound, "Organisation not found", err)
		return
	}

	h.writeJSONResponse(w, http.StatusOK, org)
}

func (h *ManagementAPIHandler) UpdateOrganisation(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	var org models.Organisation
	if err := json.NewDecoder(r.Body).Decode(&org); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	org.ID = id
	ctx := r.Context()
	user := h.getUserFromContext(ctx)

	if !h.authzSvc.CanManageOrganisation(ctx, user, id) {
		h.authzSvc.LogSecurityViolation(ctx, user, "unauthorized_organisation_update", id)
		h.writeErrorResponse(w, http.StatusForbidden, "Access denied", nil)
		return
	}

	updatedOrg, err := h.configSvc.UpdateOrganisation(ctx, &org)
	if err != nil {
		h.logger.WithError(err).Error("Failed to update organisation")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to update organisation", err)
		return
	}

	h.writeJSONResponse(w, http.StatusOK, updatedOrg)
}

func (h *ManagementAPIHandler) DeleteOrganisation(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	ctx := r.Context()
	user := h.getUserFromContext(ctx)

	if !h.authzSvc.CanManageOrganisation(ctx, user, id) {
		h.authzSvc.LogSecurityViolation(ctx, user, "unauthorized_organisation_delete", id)
		h.writeErrorResponse(w, http.StatusForbidden, "Access denied", nil)
		return
	}

	if err := h.configSvc.DeleteOrganisation(ctx, id); err != nil {
		h.logger.WithError(err).Error("Failed to delete organisation")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to delete organisation", err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// User Management Handlers

func (h *ManagementAPIHandler) CreateUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	orgID := vars["orgId"]

	var req struct {
		User     models.User `json:"user"`
		Password string      `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	req.User.OrganisationID = orgID
	ctx := r.Context()
	user := h.getUserFromContext(ctx)

	if !h.authzSvc.CanManageOrganisation(ctx, user, orgID) {
		h.authzSvc.LogSecurityViolation(ctx, user, "unauthorized_user_create", orgID)
		h.writeErrorResponse(w, http.StatusForbidden, "Access denied", nil)
		return
	}

	if err := h.userMgmtSvc.CreateUser(ctx, &req.User, req.Password); err != nil {
		h.logger.WithError(err).Error("Failed to create user")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to create user", err)
		return
	}

	h.writeJSONResponse(w, http.StatusCreated, req.User)
}

func (h *ManagementAPIHandler) GetUsersByOrganisation(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	orgID := vars["orgId"]

	ctx := r.Context()
	user := h.getUserFromContext(ctx)

	if !h.authzSvc.CanAccessResource(ctx, user, orgID) {
		h.authzSvc.LogSecurityViolation(ctx, user, "unauthorized_users_access", orgID)
		h.writeErrorResponse(w, http.StatusForbidden, "Access denied", nil)
		return
	}

	users, err := h.userMgmtSvc.GetUsersByOrganisation(ctx, orgID)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get users by organisation")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to get users", err)
		return
	}

	h.writeJSONResponse(w, http.StatusOK, users)
}

// API Configuration Handlers

func (h *ManagementAPIHandler) CreateAPIConfiguration(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	orgID := vars["orgId"]

	var config models.APIConfiguration
	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	config.OrganisationID = orgID
	ctx := r.Context()
	user := h.getUserFromContext(ctx)

	if !h.authzSvc.CanAccessResource(ctx, user, orgID) {
		h.authzSvc.LogSecurityViolation(ctx, user, "unauthorized_api_config_create", orgID)
		h.writeErrorResponse(w, http.StatusForbidden, "Access denied", nil)
		return
	}

	createdConfig, err := h.configSvc.CreateAPIConfiguration(ctx, &config)
	if err != nil {
		h.logger.WithError(err).Error("Failed to create API configuration")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to create API configuration", err)
		return
	}

	h.writeJSONResponse(w, http.StatusCreated, createdConfig)
}

func (h *ManagementAPIHandler) TestAPIConfiguration(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	var testRequest map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&testRequest); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	ctx := r.Context()
	result, err := h.configSvc.TestAPIConfiguration(ctx, id, testRequest)
	if err != nil {
		h.logger.WithError(err).Error("Failed to test API configuration")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to test API configuration", err)
		return
	}

	h.writeJSONResponse(w, http.StatusOK, result)
}

// Monitoring and Analytics Handlers

func (h *ManagementAPIHandler) GetOrganisationMetrics(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	orgID := vars["orgId"]

	ctx := r.Context()
	user := h.getUserFromContext(ctx)

	if !h.authzSvc.CanAccessResource(ctx, user, orgID) {
		h.authzSvc.LogSecurityViolation(ctx, user, "unauthorized_metrics_access", orgID)
		h.writeErrorResponse(w, http.StatusForbidden, "Access denied", nil)
		return
	}

	metrics, err := h.monitoringSvc.GetOrganisationMetrics(ctx, orgID)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get organisation metrics")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to get metrics", err)
		return
	}

	h.writeJSONResponse(w, http.StatusOK, metrics)
}

func (h *ManagementAPIHandler) GetSystemHealth(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	health, err := h.monitoringSvc.GetSystemHealth(ctx)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get system health")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to get system health", err)
		return
	}

	h.writeJSONResponse(w, http.StatusOK, health)
}

func (h *ManagementAPIHandler) GetAPIUsageAnalytics(w http.ResponseWriter, r *http.Request) {
	// Parse query parameters for time range
	startTime, endTime := h.parseTimeRange(r)

	ctx := r.Context()
	user := h.getUserFromContext(ctx)

	// Get usage analytics based on user permissions
	analytics := h.getUsageAnalytics(ctx, user, startTime, endTime)
	h.writeJSONResponse(w, http.StatusOK, analytics)
}

func (h *ManagementAPIHandler) GetRateLimitAnalytics(w http.ResponseWriter, r *http.Request) {
	startTime, endTime := h.parseTimeRange(r)

	ctx := r.Context()
	user := h.getUserFromContext(ctx)

	analytics := h.getRateLimitAnalytics(ctx, user, startTime, endTime)
	h.writeJSONResponse(w, http.StatusOK, analytics)
}

// API Documentation Handlers

func (h *ManagementAPIHandler) GetOpenAPISpec(w http.ResponseWriter, r *http.Request) {
	spec := h.generateOpenAPISpec()
	h.writeJSONResponse(w, http.StatusOK, spec)
}

func (h *ManagementAPIHandler) GetSwaggerUI(w http.ResponseWriter, r *http.Request) {
	swaggerHTML := h.generateSwaggerUI()
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(swaggerHTML))
}

// Middleware

func (h *ManagementAPIHandler) rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simple rate limiting implementation
		// In production, this would use Redis or similar
		if h.isRateLimited(r) {
			h.rateLimitCounter.Inc()
			h.writeErrorResponse(w, http.StatusTooManyRequests, "Rate limit exceeded", nil)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (h *ManagementAPIHandler) usageAnalyticsMiddleware(version string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// Wrap response writer to capture status code
			wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

			next.ServeHTTP(wrapped, r)

			// Record metrics
			h.apiUsageCounter.WithLabelValues(
				r.Method,
				r.URL.Path,
				strconv.Itoa(wrapped.statusCode),
				version,
			).Inc()

			// Log request details
			h.logger.WithFields(map[string]interface{}{
				"method":      r.Method,
				"path":        r.URL.Path,
				"status":      wrapped.statusCode,
				"duration_ms": time.Since(start).Milliseconds(),
				"version":     version,
			}).Info("Management API request")
		})
	}
}

func (h *ManagementAPIHandler) authenticationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip authentication for documentation endpoints
		if r.URL.Path == "/api/v1/docs/openapi.json" || r.URL.Path == "/api/v1/docs/swagger" {
			next.ServeHTTP(w, r)
			return
		}

		// Extract and validate JWT token
		token := h.extractToken(r)
		if token == "" {
			h.writeErrorResponse(w, http.StatusUnauthorized, "Missing authentication token", nil)
			return
		}

		user, err := h.authSvc.ValidateJWT(r.Context(), token)
		if err != nil {
			h.writeErrorResponse(w, http.StatusUnauthorized, "Invalid authentication token", err)
			return
		}

		// Add user to context
		ctx := context.WithValue(r.Context(), "user", user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Helper methods

func (h *ManagementAPIHandler) writeJSONResponse(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(data)
}

func (h *ManagementAPIHandler) writeErrorResponse(w http.ResponseWriter, statusCode int, message string, err error) {
	response := map[string]interface{}{
		"error":     message,
		"status":    statusCode,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}

	if err != nil {
		h.logger.WithError(err).Error(message)
		response["details"] = err.Error()
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(response)
}

func (h *ManagementAPIHandler) getUserFromContext(ctx context.Context) *models.User {
	if user, ok := ctx.Value("user").(*models.User); ok {
		return user
	}
	return nil
}

func (h *ManagementAPIHandler) extractToken(r *http.Request) string {
	// Try Authorization header first
	if auth := r.Header.Get("Authorization"); auth != "" {
		if len(auth) > 7 && auth[:7] == "Bearer " {
			return auth[7:]
		}
	}

	// Try query parameter
	return r.URL.Query().Get("token")
}

func (h *ManagementAPIHandler) isRateLimited(r *http.Request) bool {
	// Simple rate limiting logic
	// In production, this would use Redis with sliding window
	return false // Placeholder implementation
}

func (h *ManagementAPIHandler) parseTimeRange(r *http.Request) (time.Time, time.Time) {
	now := time.Now()
	startTime := now.Add(-24 * time.Hour) // Default to last 24 hours
	endTime := now

	if start := r.URL.Query().Get("start"); start != "" {
		if parsed, err := time.Parse(time.RFC3339, start); err == nil {
			startTime = parsed
		}
	}

	if end := r.URL.Query().Get("end"); end != "" {
		if parsed, err := time.Parse(time.RFC3339, end); err == nil {
			endTime = parsed
		}
	}

	return startTime, endTime
}

func (h *ManagementAPIHandler) getUsageAnalytics(ctx context.Context, user *models.User, startTime, endTime time.Time) map[string]interface{} {
	// Placeholder implementation
	return map[string]interface{}{
		"total_requests":    1000,
		"success_rate":      0.95,
		"avg_response_time": 150,
		"start_time":        startTime,
		"end_time":          endTime,
	}
}

func (h *ManagementAPIHandler) getRateLimitAnalytics(ctx context.Context, user *models.User, startTime, endTime time.Time) map[string]interface{} {
	// Placeholder implementation
	return map[string]interface{}{
		"rate_limit_hits":  50,
		"blocked_requests": 10,
		"start_time":       startTime,
		"end_time":         endTime,
	}
}

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// Additional handler methods for complete API coverage

func (h *ManagementAPIHandler) GetUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	ctx := r.Context()
	user, err := h.userMgmtSvc.GetUser(ctx, id)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get user")
		h.writeErrorResponse(w, http.StatusNotFound, "User not found", err)
		return
	}

	h.writeJSONResponse(w, http.StatusOK, user)
}

func (h *ManagementAPIHandler) UpdateUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	var user models.User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	user.ID = id
	ctx := r.Context()
	if err := h.userMgmtSvc.UpdateUser(ctx, &user); err != nil {
		h.logger.WithError(err).Error("Failed to update user")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to update user", err)
		return
	}

	h.writeJSONResponse(w, http.StatusOK, user)
}

func (h *ManagementAPIHandler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	ctx := r.Context()
	if err := h.userMgmtSvc.DeleteUser(ctx, id); err != nil {
		h.logger.WithError(err).Error("Failed to delete user")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to delete user", err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *ManagementAPIHandler) ChangeUserRole(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	var req struct {
		Role string `json:"role"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	ctx := r.Context()
	if err := h.userMgmtSvc.ChangeUserRole(ctx, id, req.Role); err != nil {
		h.logger.WithError(err).Error("Failed to change user role")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to change user role", err)
		return
	}

	h.writeJSONResponse(w, http.StatusOK, map[string]string{"message": "User role updated successfully"})
}

func (h *ManagementAPIHandler) ChangeUserPassword(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	var req struct {
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	ctx := r.Context()
	if err := h.userMgmtSvc.ChangePassword(ctx, id, req.Password); err != nil {
		h.logger.WithError(err).Error("Failed to change user password")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to change user password", err)
		return
	}

	h.writeJSONResponse(w, http.StatusOK, map[string]string{"message": "Password updated successfully"})
}

func (h *ManagementAPIHandler) ActivateUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	ctx := r.Context()
	if err := h.userMgmtSvc.ActivateUser(ctx, id); err != nil {
		h.logger.WithError(err).Error("Failed to activate user")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to activate user", err)
		return
	}

	h.writeJSONResponse(w, http.StatusOK, map[string]string{"message": "User activated successfully"})
}

func (h *ManagementAPIHandler) DeactivateUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	ctx := r.Context()
	if err := h.userMgmtSvc.DeactivateUser(ctx, id); err != nil {
		h.logger.WithError(err).Error("Failed to deactivate user")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to deactivate user", err)
		return
	}

	h.writeJSONResponse(w, http.StatusOK, map[string]string{"message": "User deactivated successfully"})
}

func (h *ManagementAPIHandler) GetAPIConfiguration(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	ctx := r.Context()
	config, err := h.configSvc.GetAPIConfiguration(ctx, id)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get API configuration")
		h.writeErrorResponse(w, http.StatusNotFound, "API configuration not found", err)
		return
	}

	h.writeJSONResponse(w, http.StatusOK, config)
}

func (h *ManagementAPIHandler) GetAPIConfigurationsByOrganisation(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	orgID := vars["orgId"]

	ctx := r.Context()
	user := h.getUserFromContext(ctx)

	if !h.authzSvc.CanAccessResource(ctx, user, orgID) {
		h.authzSvc.LogSecurityViolation(ctx, user, "unauthorized_api_configs_access", orgID)
		h.writeErrorResponse(w, http.StatusForbidden, "Access denied", nil)
		return
	}

	configs, err := h.configSvc.GetAPIConfigurationsByOrganisation(ctx, orgID)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get API configurations by organisation")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to get API configurations", err)
		return
	}

	h.writeJSONResponse(w, http.StatusOK, configs)
}

func (h *ManagementAPIHandler) UpdateAPIConfiguration(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	var config models.APIConfiguration
	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	config.ID = id
	ctx := r.Context()
	updatedConfig, err := h.configSvc.UpdateAPIConfiguration(ctx, &config)
	if err != nil {
		h.logger.WithError(err).Error("Failed to update API configuration")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to update API configuration", err)
		return
	}

	h.writeJSONResponse(w, http.StatusOK, updatedConfig)
}

func (h *ManagementAPIHandler) DeleteAPIConfiguration(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	ctx := r.Context()
	if err := h.configSvc.DeleteAPIConfiguration(ctx, id); err != nil {
		h.logger.WithError(err).Error("Failed to delete API configuration")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to delete API configuration", err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// Connector Management Handlers

func (h *ManagementAPIHandler) CreateConnector(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	orgID := vars["orgId"]

	var connector models.Connector
	if err := json.NewDecoder(r.Body).Decode(&connector); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	connector.OrganisationID = orgID
	ctx := r.Context()
	user := h.getUserFromContext(ctx)

	if !h.authzSvc.CanAccessResource(ctx, user, orgID) {
		h.authzSvc.LogSecurityViolation(ctx, user, "unauthorized_connector_create", orgID)
		h.writeErrorResponse(w, http.StatusForbidden, "Access denied", nil)
		return
	}

	createdConnector, err := h.configSvc.CreateConnector(ctx, &connector)
	if err != nil {
		h.logger.WithError(err).Error("Failed to create connector")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to create connector", err)
		return
	}

	h.writeJSONResponse(w, http.StatusCreated, createdConnector)
}

func (h *ManagementAPIHandler) GetConnectorsByOrganisation(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	orgID := vars["orgId"]

	ctx := r.Context()
	user := h.getUserFromContext(ctx)

	if !h.authzSvc.CanAccessResource(ctx, user, orgID) {
		h.authzSvc.LogSecurityViolation(ctx, user, "unauthorized_connectors_access", orgID)
		h.writeErrorResponse(w, http.StatusForbidden, "Access denied", nil)
		return
	}

	connectors, err := h.configSvc.GetConnectorsByOrganisation(ctx, orgID)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get connectors by organisation")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to get connectors", err)
		return
	}

	h.writeJSONResponse(w, http.StatusOK, connectors)
}

func (h *ManagementAPIHandler) GetConnector(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	ctx := r.Context()
	connector, err := h.configSvc.GetConnector(ctx, id)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get connector")
		h.writeErrorResponse(w, http.StatusNotFound, "Connector not found", err)
		return
	}

	h.writeJSONResponse(w, http.StatusOK, connector)
}

func (h *ManagementAPIHandler) UpdateConnector(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	var connector models.Connector
	if err := json.NewDecoder(r.Body).Decode(&connector); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	connector.ID = id
	ctx := r.Context()
	updatedConnector, err := h.configSvc.UpdateConnector(ctx, &connector)
	if err != nil {
		h.logger.WithError(err).Error("Failed to update connector")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to update connector", err)
		return
	}

	h.writeJSONResponse(w, http.StatusOK, updatedConnector)
}

func (h *ManagementAPIHandler) DeleteConnector(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	ctx := r.Context()
	if err := h.configSvc.DeleteConnector(ctx, id); err != nil {
		h.logger.WithError(err).Error("Failed to delete connector")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to delete connector", err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *ManagementAPIHandler) UpdateConnectorScript(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	var req struct {
		Script string `json:"script"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	ctx := r.Context()
	if err := h.configSvc.UpdateConnectorScript(ctx, id, req.Script); err != nil {
		h.logger.WithError(err).Error("Failed to update connector script")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to update connector script", err)
		return
	}

	h.writeJSONResponse(w, http.StatusOK, map[string]string{"message": "Connector script updated successfully"})
}

// Configuration Versioning Handlers

func (h *ManagementAPIHandler) GetConfigurationVersions(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	ctx := r.Context()
	versions, err := h.configSvc.GetConfigurationVersions(ctx, "api_configuration", id)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get configuration versions")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to get versions", err)
		return
	}

	h.writeJSONResponse(w, http.StatusOK, versions)
}

func (h *ManagementAPIHandler) GetConfigurationVersion(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	versionID := vars["versionId"]

	ctx := r.Context()
	version, err := h.configSvc.GetConfigurationVersion(ctx, versionID)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get configuration version")
		h.writeErrorResponse(w, http.StatusNotFound, "Version not found", err)
		return
	}

	h.writeJSONResponse(w, http.StatusOK, version)
}

func (h *ManagementAPIHandler) RollbackToVersion(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	versionID := vars["versionId"]

	ctx := r.Context()
	userID := h.extractUserIDFromContext(ctx)

	if err := h.configSvc.RollbackToVersion(ctx, versionID, userID); err != nil {
		h.logger.WithError(err).Error("Failed to rollback to version")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to rollback", err)
		return
	}

	h.writeJSONResponse(w, http.StatusOK, map[string]string{"message": "Rollback successful"})
}

// Monitoring and Logs Handlers

func (h *ManagementAPIHandler) GetOrganisationLogs(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	orgID := vars["orgId"]

	limit, offset := h.parsePaginationParams(r)

	ctx := r.Context()
	user := h.getUserFromContext(ctx)

	if !h.authzSvc.CanAccessResource(ctx, user, orgID) {
		h.authzSvc.LogSecurityViolation(ctx, user, "unauthorized_logs_access", orgID)
		h.writeErrorResponse(w, http.StatusForbidden, "Access denied", nil)
		return
	}

	logs, err := h.monitoringSvc.GetLogsByOrganisation(ctx, orgID, limit, offset)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get organisation logs")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to get logs", err)
		return
	}

	h.writeJSONResponse(w, http.StatusOK, logs)
}

func (h *ManagementAPIHandler) GetOrganisationErrors(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	orgID := vars["orgId"]

	limit, offset := h.parsePaginationParams(r)

	ctx := r.Context()
	user := h.getUserFromContext(ctx)

	if !h.authzSvc.CanAccessResource(ctx, user, orgID) {
		h.authzSvc.LogSecurityViolation(ctx, user, "unauthorized_errors_access", orgID)
		h.writeErrorResponse(w, http.StatusForbidden, "Access denied", nil)
		return
	}

	errors, err := h.monitoringSvc.GetErrorLogs(ctx, orgID, limit, offset)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get organisation errors")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to get errors", err)
		return
	}

	h.writeJSONResponse(w, http.StatusOK, errors)
}

func (h *ManagementAPIHandler) GetSystemMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	metrics, err := h.monitoringSvc.GetSystemMetrics(ctx)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get system metrics")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to get system metrics", err)
		return
	}

	h.writeJSONResponse(w, http.StatusOK, metrics)
}

func (h *ManagementAPIHandler) GetSystemLogs(w http.ResponseWriter, r *http.Request) {
	limit, offset := h.parsePaginationParams(r)

	ctx := r.Context()
	logs, err := h.monitoringSvc.GetSystemLogs(ctx, limit, offset)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get system logs")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to get system logs", err)
		return
	}

	h.writeJSONResponse(w, http.StatusOK, logs)
}

// Audit Log Handlers

func (h *ManagementAPIHandler) GetAuditLogs(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	orgID := vars["orgId"]

	limit, offset := h.parsePaginationParams(r)

	ctx := r.Context()
	user := h.getUserFromContext(ctx)

	if !h.authzSvc.CanAccessResource(ctx, user, orgID) {
		h.authzSvc.LogSecurityViolation(ctx, user, "unauthorized_audit_logs_access", orgID)
		h.writeErrorResponse(w, http.StatusForbidden, "Access denied", nil)
		return
	}

	logs, err := h.configSvc.GetAuditLogs(ctx, orgID, limit, offset)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get audit logs")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to get audit logs", err)
		return
	}

	h.writeJSONResponse(w, http.StatusOK, logs)
}

func (h *ManagementAPIHandler) GetResourceAuditLogs(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	limit, offset := h.parsePaginationParams(r)

	ctx := r.Context()
	logs, err := h.configSvc.GetResourceAuditLogs(ctx, "api_configuration", id, limit, offset)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get resource audit logs")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to get audit logs", err)
		return
	}

	h.writeJSONResponse(w, http.StatusOK, logs)
}

// Configuration Synchronization Handlers

func (h *ManagementAPIHandler) SynchronizeConfiguration(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	instanceID := vars["instanceId"]

	ctx := r.Context()
	if err := h.configSvc.SynchronizeConfiguration(ctx, instanceID); err != nil {
		h.logger.WithError(err).Error("Failed to synchronize configuration")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to synchronize", err)
		return
	}

	h.writeJSONResponse(w, http.StatusOK, map[string]string{"message": "Synchronization successful"})
}

func (h *ManagementAPIHandler) GetConfigurationChecksum(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	orgID := vars["orgId"]

	ctx := r.Context()
	user := h.getUserFromContext(ctx)

	if !h.authzSvc.CanAccessResource(ctx, user, orgID) {
		h.authzSvc.LogSecurityViolation(ctx, user, "unauthorized_checksum_access", orgID)
		h.writeErrorResponse(w, http.StatusForbidden, "Access denied", nil)
		return
	}

	checksum, err := h.configSvc.GetConfigurationChecksum(ctx, orgID)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get configuration checksum")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to get checksum", err)
		return
	}

	h.writeJSONResponse(w, http.StatusOK, map[string]string{"checksum": checksum})
}

func (h *ManagementAPIHandler) ValidateConfigurationConsistency(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := h.configSvc.ValidateConfigurationConsistency(ctx); err != nil {
		h.logger.WithError(err).Error("Configuration consistency validation failed")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Consistency validation failed", err)
		return
	}

	h.writeJSONResponse(w, http.StatusOK, map[string]string{"message": "Configuration is consistent"})
}

// Helper methods

func (h *ManagementAPIHandler) parsePaginationParams(r *http.Request) (limit, offset int) {
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

func (h *ManagementAPIHandler) extractUserIDFromContext(ctx context.Context) string {
	if user := h.getUserFromContext(ctx); user != nil {
		return user.ID
	}
	return "system" // fallback for system operations
}
