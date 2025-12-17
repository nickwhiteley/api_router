package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"api-translation-platform/internal/models"
	"api-translation-platform/internal/services"
)

// MetricsHandler handles metrics endpoints
type MetricsHandler struct {
	monitoringService services.MonitoringService
	authService       services.AuthorizationService
}

// NewMetricsHandler creates a new metrics handler
func NewMetricsHandler(monitoringService services.MonitoringService, authService services.AuthorizationService) *MetricsHandler {
	return &MetricsHandler{
		monitoringService: monitoringService,
		authService:       authService,
	}
}

// MetricsResponse represents the metrics response
type MetricsResponse struct {
	Metrics   []*models.Metric `json:"metrics"`
	StartTime time.Time        `json:"start_time"`
	EndTime   time.Time        `json:"end_time"`
	Count     int              `json:"count"`
}

// ThroughputResponse represents the throughput metrics response
type ThroughputResponse struct {
	*models.ThroughputMetrics
	RequestsPerSecond float64 `json:"requests_per_second"`
	SuccessRate       float64 `json:"success_rate"`
	ErrorRate         float64 `json:"error_rate"`
}

// HandleGetMetrics handles GET /metrics endpoint
func (h *MetricsHandler) HandleGetMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get user from context (set by authentication middleware)
	user, ok := ctx.Value("user").(*models.User)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Parse query parameters
	orgID := r.URL.Query().Get("organisation_id")
	metricName := r.URL.Query().Get("metric_name")
	startTimeStr := r.URL.Query().Get("start_time")
	endTimeStr := r.URL.Query().Get("end_time")

	// Validate organisation access
	if orgID != "" && !h.authService.CanAccessResource(ctx, user, orgID) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// If user is not global admin, filter by their organisation
	if user.Role != "global_admin" {
		orgID = user.OrganisationID
	}

	// Parse time range (default to last hour)
	endTime := time.Now()
	startTime := endTime.Add(-1 * time.Hour)

	if startTimeStr != "" {
		if parsed, err := time.Parse(time.RFC3339, startTimeStr); err == nil {
			startTime = parsed
		}
	}

	if endTimeStr != "" {
		if parsed, err := time.Parse(time.RFC3339, endTimeStr); err == nil {
			endTime = parsed
		}
	}

	// Get metrics
	metrics, err := h.monitoringService.GetMetrics(ctx, orgID, metricName, startTime, endTime)
	if err != nil {
		http.Error(w, "Failed to get metrics", http.StatusInternalServerError)
		return
	}

	response := MetricsResponse{
		Metrics:   metrics,
		StartTime: startTime,
		EndTime:   endTime,
		Count:     len(metrics),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// HandleGetThroughputMetrics handles GET /metrics/throughput endpoint
func (h *MetricsHandler) HandleGetThroughputMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get user from context
	user, ok := ctx.Value("user").(*models.User)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Parse query parameters
	orgID := r.URL.Query().Get("organisation_id")
	startTimeStr := r.URL.Query().Get("start_time")
	endTimeStr := r.URL.Query().Get("end_time")

	// Validate organisation access
	if orgID != "" && !h.authService.CanAccessResource(ctx, user, orgID) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// If user is not global admin, filter by their organisation
	if user.Role != "global_admin" {
		orgID = user.OrganisationID
	}

	// Parse time range (default to last hour)
	endTime := time.Now()
	startTime := endTime.Add(-1 * time.Hour)

	if startTimeStr != "" {
		if parsed, err := time.Parse(time.RFC3339, startTimeStr); err == nil {
			startTime = parsed
		}
	}

	if endTimeStr != "" {
		if parsed, err := time.Parse(time.RFC3339, endTimeStr); err == nil {
			endTime = parsed
		}
	}

	// Get throughput metrics
	throughputMetrics, err := h.monitoringService.GetThroughputMetrics(ctx, orgID, startTime, endTime)
	if err != nil {
		http.Error(w, "Failed to get throughput metrics", http.StatusInternalServerError)
		return
	}

	// Calculate additional metrics
	duration := endTime.Sub(startTime).Seconds()
	requestsPerSecond := float64(throughputMetrics.RequestCount) / duration

	var successRate, errorRate float64
	if throughputMetrics.RequestCount > 0 {
		successRate = float64(throughputMetrics.SuccessCount) / float64(throughputMetrics.RequestCount) * 100
		errorRate = float64(throughputMetrics.ErrorCount) / float64(throughputMetrics.RequestCount) * 100
	}

	response := ThroughputResponse{
		ThroughputMetrics: throughputMetrics,
		RequestsPerSecond: requestsPerSecond,
		SuccessRate:       successRate,
		ErrorRate:         errorRate,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// HandleGetSystemMetrics handles GET /metrics/system endpoint
func (h *MetricsHandler) HandleGetSystemMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get user from context
	user, ok := ctx.Value("user").(*models.User)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Only global admins can view system metrics
	if user.Role != "global_admin" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// Get system metrics
	systemMetrics, err := h.monitoringService.GetSystemMetrics(ctx)
	if err != nil {
		http.Error(w, "Failed to get system metrics", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(systemMetrics)
}

// HandlePostMetric handles POST /metrics endpoint for recording custom metrics
func (h *MetricsHandler) HandlePostMetric(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get user from context
	user, ok := ctx.Value("user").(*models.User)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Parse request body
	var request struct {
		Name   string            `json:"name"`
		Value  float64           `json:"value"`
		Labels map[string]string `json:"labels"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if request.Name == "" {
		http.Error(w, "Metric name is required", http.StatusBadRequest)
		return
	}

	// Record metric for user's organisation
	orgID := user.OrganisationID
	if user.Role == "global_admin" {
		// Global admins can specify organisation in labels
		if orgFromLabel, exists := request.Labels["organisation_id"]; exists {
			orgID = orgFromLabel
		}
	}

	err := h.monitoringService.RecordMetric(ctx, orgID, request.Name, request.Value, request.Labels)
	if err != nil {
		http.Error(w, "Failed to record metric", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"status": "metric recorded"})
}

// HandleGetAlerts handles GET /alerts endpoint
func (h *MetricsHandler) HandleGetAlerts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get user from context
	user, ok := ctx.Value("user").(*models.User)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Get organisation ID based on user role
	orgID := user.OrganisationID
	if user.Role == "global_admin" {
		if requestedOrgID := r.URL.Query().Get("organisation_id"); requestedOrgID != "" {
			orgID = requestedOrgID
		} else {
			orgID = "" // Global admin can see all alerts
		}
	}

	// Get active alerts
	alerts, err := h.monitoringService.GetActiveAlerts(ctx, orgID)
	if err != nil {
		http.Error(w, "Failed to get alerts", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"alerts": alerts,
		"count":  len(alerts),
	})
}

// HandleCreateAlert handles POST /alerts endpoint
func (h *MetricsHandler) HandleCreateAlert(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get user from context
	user, ok := ctx.Value("user").(*models.User)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Parse request body
	var alert models.Alert
	if err := json.NewDecoder(r.Body).Decode(&alert); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Set organisation ID based on user role
	if user.Role != "global_admin" {
		alert.OrganisationID = user.OrganisationID
	}

	// Validate required fields
	if alert.Name == "" || alert.Condition == "" {
		http.Error(w, "Name and condition are required", http.StatusBadRequest)
		return
	}

	// Create alert
	err := h.monitoringService.CreateAlert(ctx, &alert)
	if err != nil {
		http.Error(w, "Failed to create alert", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(alert)
}
