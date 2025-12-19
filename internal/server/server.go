package server

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"api-translation-platform/internal/config"
	"api-translation-platform/internal/handlers"
	"api-translation-platform/internal/logger"
	"api-translation-platform/internal/middleware"
	"api-translation-platform/internal/security"
	"api-translation-platform/internal/services"
)

// Server represents the HTTP server
type Server struct {
	config             *config.Config
	logger             *logger.Logger
	router             *mux.Router
	httpServer         *http.Server
	landingHandler     *handlers.LandingHandler
	authUIHandler      *handlers.AuthUIHandler
	managementHandler  *handlers.ManagementAPIHandler
	configHandler      *handlers.ConfigurationHandler
	healthHandler      *handlers.HealthHandler
	metricsHandler     *handlers.MetricsHandler
	webUIHandler       *handlers.WebUIHandler
	securityHandler    *handlers.SecurityHandler
	performanceHandler *handlers.PerformanceHandler
	authMiddleware     *middleware.AuthenticationMiddleware
	securityManager    *security.SecurityManager
	apiGatewayService  services.APIGatewayService
}

// NewServer creates a new HTTP server
func NewServer(
	config *config.Config,
	logger *logger.Logger,
	landingHandler *handlers.LandingHandler,
	authUIHandler *handlers.AuthUIHandler,
	managementHandler *handlers.ManagementAPIHandler,
	configHandler *handlers.ConfigurationHandler,
	healthHandler *handlers.HealthHandler,
	metricsHandler *handlers.MetricsHandler,
	webUIHandler *handlers.WebUIHandler,
	securityHandler *handlers.SecurityHandler,
	performanceHandler *handlers.PerformanceHandler,
	authMiddleware *middleware.AuthenticationMiddleware,
	securityManager *security.SecurityManager,
	apiGatewayService services.APIGatewayService,
) *Server {
	router := mux.NewRouter()

	server := &Server{
		config:             config,
		logger:             logger,
		router:             router,
		landingHandler:     landingHandler,
		authUIHandler:      authUIHandler,
		managementHandler:  managementHandler,
		configHandler:      configHandler,
		healthHandler:      healthHandler,
		metricsHandler:     metricsHandler,
		webUIHandler:       webUIHandler,
		securityHandler:    securityHandler,
		performanceHandler: performanceHandler,
		authMiddleware:     authMiddleware,
		securityManager:    securityManager,
		apiGatewayService:  apiGatewayService,
	}

	server.setupRoutes()
	server.setupHTTPServer()

	return server
}

// setupRoutes configures all HTTP routes
func (s *Server) setupRoutes() {
	// Landing page (no auth required)
	s.router.HandleFunc("/", s.landingHandler.HandleLandingPage).Methods("GET")

	// Health check endpoints (no auth required)
	s.router.HandleFunc("/health", s.healthHandler.HandleHealthCheck).Methods("GET")
	s.router.HandleFunc("/health/ready", s.healthHandler.HandleReadinessProbe).Methods("GET")
	s.router.HandleFunc("/health/live", s.healthHandler.HandleLivenessProbe).Methods("GET")

	// Metrics endpoint (no auth required for monitoring systems)
	s.router.Handle("/metrics", promhttp.Handler()).Methods("GET")

	// Authentication UI routes (login and management pages)
	s.authUIHandler.RegisterRoutes(s.router)

	// Management API routes (comprehensive REST API) - must be registered before API gateway
	s.managementHandler.RegisterRoutes(s.router)

	// Legacy configuration API routes (for backward compatibility)
	s.configHandler.RegisterRoutes(s.router)

	// Web UI routes
	s.webUIHandler.RegisterRoutes(s.router)

	// Security API routes
	s.securityHandler.RegisterRoutes(s.router)

	// Performance API routes
	s.performanceHandler.RegisterRoutes(s.router)

	// API Gateway routes - handle dynamic API endpoints (must be registered LAST to avoid conflicts)
	s.router.PathPrefix("/api/").Handler(http.HandlerFunc(s.handleAPIGatewayRequest))

	// Add security middleware first (order matters)
	securityMiddlewares := s.securityManager.GetSecurityMiddleware()
	for _, middleware := range securityMiddlewares {
		s.router.Use(middleware)
	}

	// Add performance monitoring middleware
	s.router.Use(s.performanceHandler.PerformanceMiddleware)

	// Add caching middleware for GET requests
	s.router.Use(s.performanceHandler.CacheMiddleware)

	// Add compression middleware
	s.router.Use(middleware.CompressionMiddleware)

	// Add static asset optimization middleware
	s.router.Use(middleware.StaticAssetMiddleware)

	// Add other global middleware
	s.router.Use(s.loggingMiddleware)
}

// setupHTTPServer configures the HTTP server
func (s *Server) setupHTTPServer() {
	s.httpServer = &http.Server{
		Addr:         fmt.Sprintf(":%s", s.config.Server.Port),
		Handler:      s.router,
		ReadTimeout:  time.Duration(s.config.Server.ReadTimeout) * time.Second,
		WriteTimeout: time.Duration(s.config.Server.WriteTimeout) * time.Second,
		IdleTimeout:  time.Duration(s.config.Server.IdleTimeout) * time.Second,
	}
}

// Start starts the HTTP server
func (s *Server) Start(ctx context.Context) error {
	s.logger.WithField("port", s.config.Server.Port).Info("Starting HTTP server")

	// Start server - this will block until the server is shut down
	if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		s.logger.WithError(err).Error("HTTP server error")
		return err
	}

	return nil
}

// Stop gracefully stops the HTTP server
func (s *Server) Stop() error {
	s.logger.Info("Shutting down HTTP server")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	return s.httpServer.Shutdown(ctx)
}

// Middleware

func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Wrap response writer to capture status code
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(wrapped, r)

		duration := time.Since(start)

		s.logger.WithFields(map[string]interface{}{
			"method":      r.Method,
			"path":        r.URL.Path,
			"status":      wrapped.statusCode,
			"duration_ms": duration.Milliseconds(),
			"remote_addr": r.RemoteAddr,
			"user_agent":  r.UserAgent(),
		}).Info("HTTP request")
	})
}

// Note: CORS and security headers are now handled by the SecurityManager middleware

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// handleAPIGatewayRequest handles dynamic API endpoint requests
func (s *Server) handleAPIGatewayRequest(w http.ResponseWriter, r *http.Request) {
	s.logger.WithField("path", r.URL.Path).Info("API Gateway request received")

	// Parse the request path to extract the API endpoint
	// Expected format: /api{endpoint} where {endpoint} is the API configuration endpoint
	apiPath := strings.TrimPrefix(r.URL.Path, "/api")
	if apiPath == "" {
		apiPath = "/"
	}

	// Look up API configuration by endpoint path
	// We need to get all API configurations and find the one that matches this endpoint
	ctx := r.Context()

	// For now, we'll need to get all API configurations and find a match
	// In a production system, you'd want to cache this or use a more efficient lookup

	// Since we don't have direct access to the configuration service here,
	// we'll delegate to the API gateway service which should handle the lookup
	resp, err := s.apiGatewayService.HandleInboundRequest(ctx, r, nil)
	if err != nil {
		s.logger.WithError(err).Error("API Gateway request processing failed")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error": "Internal server error", "message": "Request processing failed"}`))
		return
	}

	// If no API configuration found, return 404
	if resp == nil {
		s.logger.WithField("path", apiPath).Warn("No API configuration found for path")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error": "API not found", "path": "` + apiPath + `"}`))
		return
	}

	// Copy response headers
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	// Write status code
	w.WriteHeader(resp.StatusCode)

	// Copy response body
	if resp.Body != nil {
		defer resp.Body.Close()
		if _, err := io.Copy(w, resp.Body); err != nil {
			s.logger.WithError(err).Error("Failed to copy response body")
		}
	}
}
