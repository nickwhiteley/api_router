package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"api-translation-platform/internal/logger"
	"api-translation-platform/internal/services"

	"github.com/gorilla/mux"
)

// PerformanceHandler handles performance monitoring endpoints
type PerformanceHandler struct {
	logger             *logger.Logger
	performanceMonitor *services.PerformanceMonitor
	cacheService       *services.CacheService
	jobProcessor       *services.JobProcessor
}

// NewPerformanceHandler creates a new performance handler
func NewPerformanceHandler(
	logger *logger.Logger,
	performanceMonitor *services.PerformanceMonitor,
	cacheService *services.CacheService,
	jobProcessor *services.JobProcessor,
) *PerformanceHandler {
	return &PerformanceHandler{
		logger:             logger,
		performanceMonitor: performanceMonitor,
		cacheService:       cacheService,
		jobProcessor:       jobProcessor,
	}
}

// RegisterRoutes registers performance monitoring routes
func (h *PerformanceHandler) RegisterRoutes(router *mux.Router) {
	router.HandleFunc("/api/v1/performance/metrics", h.GetCurrentMetrics).Methods("GET")
	router.HandleFunc("/api/v1/performance/metrics/{metric}/history", h.GetMetricHistory).Methods("GET")
	router.HandleFunc("/api/v1/performance/cache/stats", h.GetCacheStats).Methods("GET")
	router.HandleFunc("/api/v1/performance/cache/clear", h.ClearCache).Methods("POST")
	router.HandleFunc("/api/v1/performance/cache/clear/{tag}", h.ClearCacheByTag).Methods("POST")
	router.HandleFunc("/api/v1/performance/jobs/stats", h.GetJobStats).Methods("GET")
	router.HandleFunc("/api/v1/performance/jobs/{jobId}/status", h.GetJobStatus).Methods("GET")
}

// GetCurrentMetrics returns current system performance metrics
func (h *PerformanceHandler) GetCurrentMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	metrics, err := h.performanceMonitor.GetCurrentMetrics(ctx)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get current metrics")
		http.Error(w, "Failed to get metrics", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
		"data":   metrics,
	})
}

// GetMetricHistory returns historical data for a specific metric
func (h *PerformanceHandler) GetMetricHistory(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	metricName := vars["metric"]

	// Parse duration parameter
	durationStr := r.URL.Query().Get("duration")
	if durationStr == "" {
		durationStr = "1h" // Default to 1 hour
	}

	duration, err := time.ParseDuration(durationStr)
	if err != nil {
		http.Error(w, "Invalid duration format", http.StatusBadRequest)
		return
	}

	metrics, err := h.performanceMonitor.GetMetricHistory(ctx, metricName, duration)
	if err != nil {
		h.logger.WithError(err).WithField("metric", metricName).Error("Failed to get metric history")
		http.Error(w, "Failed to get metric history", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
		"data": map[string]interface{}{
			"metric":   metricName,
			"duration": durationStr,
			"history":  metrics,
		},
	})
}

// GetCacheStats returns cache performance statistics
func (h *PerformanceHandler) GetCacheStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	stats, err := h.cacheService.GetStats(ctx)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get cache stats")
		http.Error(w, "Failed to get cache stats", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
		"data":   stats,
	})
}

// ClearCache clears all cached data
func (h *PerformanceHandler) ClearCache(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Clear all cache patterns
	patterns := []string{
		"config:*",
		"connector:*",
		"user:*",
		"org:*",
		"metrics:*",
	}

	for _, pattern := range patterns {
		if err := h.cacheService.DeletePattern(ctx, pattern); err != nil {
			h.logger.WithError(err).WithField("pattern", pattern).Error("Failed to clear cache pattern")
			http.Error(w, "Failed to clear cache", http.StatusInternalServerError)
			return
		}
	}

	h.logger.Info("Cache cleared successfully")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"message": "Cache cleared successfully",
	})
}

// ClearCacheByTag clears cached data by tag
func (h *PerformanceHandler) ClearCacheByTag(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	tag := vars["tag"]

	if err := h.cacheService.InvalidateByTag(ctx, tag); err != nil {
		h.logger.WithError(err).WithField("tag", tag).Error("Failed to clear cache by tag")
		http.Error(w, "Failed to clear cache by tag", http.StatusInternalServerError)
		return
	}

	h.logger.WithField("tag", tag).Info("Cache cleared by tag")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"message": "Cache cleared by tag: " + tag,
	})
}

// GetJobStats returns background job processing statistics
func (h *PerformanceHandler) GetJobStats(w http.ResponseWriter, r *http.Request) {
	// This would return job processing statistics
	// For now, return a placeholder response
	stats := map[string]interface{}{
		"total_jobs_processed":    0,
		"jobs_in_queue":           0,
		"failed_jobs":             0,
		"average_processing_time": "0ms",
		"worker_count":            4,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
		"data":   stats,
	})
}

// GetJobStatus returns the status of a specific job
func (h *PerformanceHandler) GetJobStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	jobID := vars["jobId"]

	job, err := h.jobProcessor.GetJobStatus(ctx, jobID)
	if err != nil {
		h.logger.WithError(err).WithField("job_id", jobID).Error("Failed to get job status")
		http.Error(w, "Job not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
		"data":   job,
	})
}

// PerformanceMiddleware records request performance metrics
func (h *PerformanceHandler) PerformanceMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Create a response writer wrapper to capture status code
		wrapper := &responseWriterWrapper{
			ResponseWriter: w,
			statusCode:     http.StatusOK,
		}

		// Process request
		next.ServeHTTP(wrapper, r)

		// Record metrics
		duration := time.Since(start)
		h.performanceMonitor.RecordRequestMetric(
			r.URL.Path,
			r.Method,
			wrapper.statusCode,
			duration,
		)
	})
}

// responseWriterWrapper wraps http.ResponseWriter to capture status code
type responseWriterWrapper struct {
	http.ResponseWriter
	statusCode int
}

func (w *responseWriterWrapper) WriteHeader(statusCode int) {
	w.statusCode = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

// CacheMiddleware provides caching for GET requests
func (h *PerformanceHandler) CacheMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only cache GET requests
		if r.Method != http.MethodGet {
			next.ServeHTTP(w, r)
			return
		}

		// Don't cache certain paths
		if !h.shouldCache(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		ctx := r.Context()
		cacheKey := h.buildCacheKey(r)

		// Try to get from cache
		start := time.Now()
		var cachedResponse CachedResponse
		err := h.cacheService.Get(ctx, cacheKey, &cachedResponse)

		if err == nil {
			// Cache hit
			h.performanceMonitor.RecordCacheMetric("get", true, time.Since(start))

			// Set headers and write cached response
			for key, value := range cachedResponse.Headers {
				w.Header().Set(key, value)
			}
			w.Header().Set("X-Cache", "HIT")
			w.WriteHeader(cachedResponse.StatusCode)
			w.Write(cachedResponse.Body)
			return
		}

		// Cache miss
		h.performanceMonitor.RecordCacheMetric("get", false, time.Since(start))

		// Create response recorder to capture response
		recorder := &responseRecorder{
			ResponseWriter: w,
			headers:        make(map[string]string),
		}

		// Process request
		next.ServeHTTP(recorder, r)

		// Cache successful responses
		if recorder.statusCode >= 200 && recorder.statusCode < 300 {
			cachedResponse := CachedResponse{
				StatusCode: recorder.statusCode,
				Headers:    recorder.headers,
				Body:       recorder.body,
			}

			// Cache for 5 minutes by default
			h.cacheService.Set(ctx, cacheKey, cachedResponse, 5*time.Minute)
		}

		w.Header().Set("X-Cache", "MISS")
	})
}

// CachedResponse represents a cached HTTP response
type CachedResponse struct {
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers"`
	Body       []byte            `json:"body"`
}

// responseRecorder records HTTP responses for caching
type responseRecorder struct {
	http.ResponseWriter
	statusCode int
	headers    map[string]string
	body       []byte
}

func (r *responseRecorder) WriteHeader(statusCode int) {
	r.statusCode = statusCode

	// Copy headers
	for key, values := range r.ResponseWriter.Header() {
		if len(values) > 0 {
			r.headers[key] = values[0]
		}
	}

	r.ResponseWriter.WriteHeader(statusCode)
}

func (r *responseRecorder) Write(data []byte) (int, error) {
	r.body = append(r.body, data...)
	return r.ResponseWriter.Write(data)
}

// shouldCache determines if a path should be cached
func (h *PerformanceHandler) shouldCache(path string) bool {
	// Cache API configuration and connector endpoints
	cacheable := []string{
		"/api/v1/configurations",
		"/api/v1/connectors",
		"/api/v1/organisations",
		"/api/v1/users",
	}

	for _, pattern := range cacheable {
		if path == pattern {
			return true
		}
	}

	return false
}

// buildCacheKey builds a cache key for the request
func (h *PerformanceHandler) buildCacheKey(r *http.Request) string {
	// Include organisation context if available
	orgID := r.Header.Get("X-Organisation-ID")
	if orgID == "" {
		orgID = "default"
	}

	return "http_cache:org:" + orgID + ":path:" + r.URL.Path + ":query:" + r.URL.RawQuery
}
