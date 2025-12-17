package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"

	"api-translation-platform/internal/logger"
	"api-translation-platform/internal/security"
)

// SecurityHandler handles security-related API endpoints
type SecurityHandler struct {
	logger          *logger.Logger
	securityManager *security.SecurityManager
	auditLogger     *security.DatabaseAuditLogger
}

// NewSecurityHandler creates a new security handler
func NewSecurityHandler(
	logger *logger.Logger,
	securityManager *security.SecurityManager,
	auditLogger *security.DatabaseAuditLogger,
) *SecurityHandler {
	return &SecurityHandler{
		logger:          logger,
		securityManager: securityManager,
		auditLogger:     auditLogger,
	}
}

// RegisterRoutes registers security-related routes
func (h *SecurityHandler) RegisterRoutes(router *mux.Router) {
	// Security events endpoints
	router.HandleFunc("/api/v1/security/events", h.GetSecurityEvents).Methods("GET")
	router.HandleFunc("/api/v1/security/events/stats", h.GetSecurityEventStats).Methods("GET")
	router.HandleFunc("/api/v1/security/metrics", h.GetSecurityMetrics).Methods("GET")
	router.HandleFunc("/api/v1/security/rate-limits", h.GetRateLimitStats).Methods("GET")

	// Security configuration endpoints
	router.HandleFunc("/api/v1/security/config/validate", h.ValidateSecurityConfig).Methods("POST")
}

// GetSecurityEvents retrieves security events with filtering
func (h *SecurityHandler) GetSecurityEvents(w http.ResponseWriter, r *http.Request) {
	// Parse query parameters for filtering
	filter := security.SecurityEventFilter{}

	if eventType := r.URL.Query().Get("type"); eventType != "" {
		filter.EventType = security.SecurityEventType(eventType)
	}

	if severity := r.URL.Query().Get("severity"); severity != "" {
		filter.Severity = security.SecuritySeverity(severity)
	}

	if userID := r.URL.Query().Get("user_id"); userID != "" {
		filter.UserID = userID
	}

	if ipAddress := r.URL.Query().Get("ip_address"); ipAddress != "" {
		filter.IPAddress = ipAddress
	}

	if resourceID := r.URL.Query().Get("resource_id"); resourceID != "" {
		filter.ResourceID = resourceID
	}

	if startTime := r.URL.Query().Get("start_time"); startTime != "" {
		filter.StartTime = startTime
	}

	if endTime := r.URL.Query().Get("end_time"); endTime != "" {
		filter.EndTime = endTime
	}

	// Parse pagination parameters
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if limit, err := strconv.Atoi(limitStr); err == nil && limit > 0 && limit <= 1000 {
			filter.Limit = limit
		} else {
			filter.Limit = 50 // default
		}
	} else {
		filter.Limit = 50
	}

	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		if offset, err := strconv.Atoi(offsetStr); err == nil && offset >= 0 {
			filter.Offset = offset
		}
	}

	// Get security events
	events, err := h.auditLogger.GetSecurityEvents(r.Context(), filter)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get security events")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to get security events", err)
		return
	}

	h.writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"events": events,
		"filter": filter,
		"count":  len(events),
	})
}

// GetSecurityEventStats retrieves security event statistics
func (h *SecurityHandler) GetSecurityEventStats(w http.ResponseWriter, r *http.Request) {
	// Parse time range parameter (default to last 24 hours)
	timeRange := 24 * time.Hour
	if rangeStr := r.URL.Query().Get("range_hours"); rangeStr != "" {
		if hours, err := strconv.Atoi(rangeStr); err == nil && hours > 0 && hours <= 168 { // max 1 week
			timeRange = time.Duration(hours) * time.Hour
		}
	}

	// Get security metrics
	metrics, err := h.securityManager.GetSecurityMetrics(r.Context(), h.auditLogger)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get security metrics")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to get security metrics", err)
		return
	}

	h.writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"metrics":    metrics,
		"time_range": timeRange.String(),
		"timestamp":  time.Now().UTC(),
	})
}

// GetSecurityMetrics retrieves comprehensive security metrics
func (h *SecurityHandler) GetSecurityMetrics(w http.ResponseWriter, r *http.Request) {
	metrics, err := h.securityManager.GetSecurityMetrics(r.Context(), h.auditLogger)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get security metrics")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to get security metrics", err)
		return
	}

	// Get rate limiting stats
	rateLimitStats := h.securityManager.GetRateLimitStats()

	response := map[string]interface{}{
		"security_events": metrics,
		"rate_limiting":   rateLimitStats,
		"timestamp":       time.Now().UTC(),
	}

	h.writeJSONResponse(w, http.StatusOK, response)
}

// GetRateLimitStats retrieves rate limiting statistics
func (h *SecurityHandler) GetRateLimitStats(w http.ResponseWriter, r *http.Request) {
	stats := h.securityManager.GetRateLimitStats()

	h.writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"rate_limit_stats": stats,
		"timestamp":        time.Now().UTC(),
	})
}

// ValidateSecurityConfig validates security configuration
func (h *SecurityHandler) ValidateSecurityConfig(w http.ResponseWriter, r *http.Request) {
	var config struct {
		JWT  *security.JWTConfig  `json:"jwt,omitempty"`
		CORS *security.CORSConfig `json:"cors,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	var validationErrors []string

	// Validate JWT config if provided
	if config.JWT != nil {
		if err := h.securityManager.ValidateJWTConfig(*config.JWT); err != nil {
			validationErrors = append(validationErrors, "JWT: "+err.Error())
		}
	}

	// Validate CORS config if provided
	if config.CORS != nil {
		if err := h.securityManager.ValidateCORSConfig(*config.CORS); err != nil {
			validationErrors = append(validationErrors, "CORS: "+err.Error())
		}
	}

	response := map[string]interface{}{
		"valid":  len(validationErrors) == 0,
		"errors": validationErrors,
	}

	statusCode := http.StatusOK
	if len(validationErrors) > 0 {
		statusCode = http.StatusBadRequest
	}

	h.writeJSONResponse(w, statusCode, response)
}

// Helper methods

func (h *SecurityHandler) writeJSONResponse(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(data)
}

func (h *SecurityHandler) writeErrorResponse(w http.ResponseWriter, statusCode int, message string, err error) {
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
