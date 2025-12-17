package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"api-translation-platform/internal/models"
	"api-translation-platform/internal/services"
)

// HealthHandler handles health check endpoints
type HealthHandler struct {
	monitoringService services.MonitoringService
}

// NewHealthHandler creates a new health handler
func NewHealthHandler(monitoringService services.MonitoringService) *HealthHandler {
	return &HealthHandler{
		monitoringService: monitoringService,
	}
}

// HealthResponse represents the health check response
type HealthResponse struct {
	Status     string                         `json:"status"`
	Timestamp  time.Time                      `json:"timestamp"`
	Components map[string]*models.HealthCheck `json:"components"`
	System     *models.SystemMetrics          `json:"system,omitempty"`
}

// HandleHealthCheck handles the main health check endpoint
func (h *HealthHandler) HandleHealthCheck(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get health status for all components
	components, err := h.monitoringService.GetHealthStatus(ctx)
	if err != nil {
		http.Error(w, "Failed to get health status", http.StatusInternalServerError)
		return
	}

	// Determine overall status
	overallStatus := "healthy"
	for _, component := range components {
		if !component.IsHealthy() {
			overallStatus = "unhealthy"
			break
		}
	}

	// Get system metrics if requested
	var systemMetrics *models.SystemMetrics
	if r.URL.Query().Get("include_system") == "true" {
		systemMetrics, _ = h.monitoringService.GetSystemMetrics(ctx)
	}

	response := HealthResponse{
		Status:     overallStatus,
		Timestamp:  time.Now(),
		Components: components,
		System:     systemMetrics,
	}

	w.Header().Set("Content-Type", "application/json")
	if overallStatus != "healthy" {
		w.WriteHeader(http.StatusServiceUnavailable)
	}

	json.NewEncoder(w).Encode(response)
}

// HandleLivenessProbe handles Kubernetes liveness probe
func (h *HealthHandler) HandleLivenessProbe(w http.ResponseWriter, r *http.Request) {
	// Simple liveness check - just return 200 if the service is running
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// HandleReadinessProbe handles Kubernetes readiness probe
func (h *HealthHandler) HandleReadinessProbe(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Check if critical components are healthy
	components, err := h.monitoringService.GetHealthStatus(ctx)
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("Service Unavailable"))
		return
	}

	// Check critical components (database, etc.)
	criticalComponents := []string{"database", "configuration"}
	for _, componentName := range criticalComponents {
		if component, exists := components[componentName]; exists {
			if !component.IsHealthy() {
				w.WriteHeader(http.StatusServiceUnavailable)
				w.Write([]byte("Service Unavailable"))
				return
			}
		}
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Ready"))
}

// HandleComponentHealth handles health check for a specific component
func (h *HealthHandler) HandleComponentHealth(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	component := r.URL.Query().Get("component")

	if component == "" {
		http.Error(w, "Component parameter is required", http.StatusBadRequest)
		return
	}

	healthCheck, err := h.monitoringService.PerformHealthCheck(ctx, component)
	if err != nil {
		http.Error(w, "Failed to perform health check", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if !healthCheck.IsHealthy() {
		w.WriteHeader(http.StatusServiceUnavailable)
	}

	json.NewEncoder(w).Encode(healthCheck)
}

// RegisterDefaultHealthChecks registers default health checks for common components
func (h *HealthHandler) RegisterDefaultHealthChecks() {
	// Database health check
	h.monitoringService.RegisterHealthCheck("database", func(ctx context.Context) (*models.HealthCheck, error) {
		// In a real implementation, this would test database connectivity
		return &models.HealthCheck{
			Component: "database",
			Status:    models.HealthStatusHealthy,
			Message:   "Database connection is healthy",
			Details: map[string]interface{}{
				"connection_pool_size": 10,
				"active_connections":   5,
			},
		}, nil
	})

	// Configuration service health check
	h.monitoringService.RegisterHealthCheck("configuration", func(ctx context.Context) (*models.HealthCheck, error) {
		return &models.HealthCheck{
			Component: "configuration",
			Status:    models.HealthStatusHealthy,
			Message:   "Configuration service is healthy",
		}, nil
	})

	// API Gateway health check
	h.monitoringService.RegisterHealthCheck("api_gateway", func(ctx context.Context) (*models.HealthCheck, error) {
		return &models.HealthCheck{
			Component: "api_gateway",
			Status:    models.HealthStatusHealthy,
			Message:   "API Gateway is healthy",
		}, nil
	})

	// Transformation engine health check
	h.monitoringService.RegisterHealthCheck("transformation_engine", func(ctx context.Context) (*models.HealthCheck, error) {
		return &models.HealthCheck{
			Component: "transformation_engine",
			Status:    models.HealthStatusHealthy,
			Message:   "Transformation engine is healthy",
		}, nil
	})
}
