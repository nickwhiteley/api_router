package services

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync"
	"time"

	"api-translation-platform/internal/logger"
	"api-translation-platform/internal/models"
	"api-translation-platform/internal/repositories"
)

// EndpointHandler represents a dynamic endpoint handler
type EndpointHandler struct {
	APIConfig *models.APIConfiguration
	Handler   http.HandlerFunc
}

// SOAPEnvelope represents a SOAP envelope structure
type SOAPEnvelope struct {
	XMLName xml.Name `xml:"soap:Envelope"`
	Xmlns   string   `xml:"xmlns:soap,attr"`
	Body    SOAPBody `xml:"soap:Body"`
}

// SOAPBody represents a SOAP body
type SOAPBody struct {
	Content interface{} `xml:",innerxml"`
}

// SOAPFault represents a SOAP fault
type SOAPFault struct {
	XMLName xml.Name `xml:"soap:Fault"`
	Code    string   `xml:"faultcode"`
	String  string   `xml:"faultstring"`
	Detail  string   `xml:"detail,omitempty"`
}

// apiGatewayService implements APIGatewayService
type apiGatewayService struct {
	logger           *logger.Logger
	connectorRepo    repositories.ConnectorRepository
	requestLogRepo   repositories.RequestLogRepository
	transformService TransformationService
	outboundService  OutboundClientService
	authService      AuthenticationService

	// Dynamic endpoint management
	endpoints map[string]*EndpointHandler
	mux       *http.ServeMux
	mutex     sync.RWMutex

	// Rate limiting
	rateLimiter map[string]*RateLimiter
	rateMutex   sync.RWMutex
}

// RateLimiter implements a simple token bucket rate limiter
type RateLimiter struct {
	tokens     int
	maxTokens  int
	refillRate time.Duration
	lastRefill time.Time
	mutex      sync.Mutex
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(maxTokens int, refillRate time.Duration) *RateLimiter {
	return &RateLimiter{
		tokens:     maxTokens,
		maxTokens:  maxTokens,
		refillRate: refillRate,
		lastRefill: time.Now(),
	}
}

// Allow checks if a request is allowed
func (rl *RateLimiter) Allow() bool {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	now := time.Now()
	elapsed := now.Sub(rl.lastRefill)
	tokensToAdd := int(elapsed / rl.refillRate)

	if tokensToAdd > 0 {
		rl.tokens = min(rl.maxTokens, rl.tokens+tokensToAdd)
		rl.lastRefill = now
	}

	if rl.tokens > 0 {
		rl.tokens--
		return true
	}

	return false
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// NewAPIGatewayService creates a new API gateway service
func NewAPIGatewayService(
	logger *logger.Logger,
	connectorRepo repositories.ConnectorRepository,
	requestLogRepo repositories.RequestLogRepository,
	transformService TransformationService,
	outboundService OutboundClientService,
	authService AuthenticationService,
) APIGatewayService {
	return &apiGatewayService{
		logger:           logger,
		connectorRepo:    connectorRepo,
		requestLogRepo:   requestLogRepo,
		transformService: transformService,
		outboundService:  outboundService,
		authService:      authService,
		endpoints:        make(map[string]*EndpointHandler),
		mux:              http.NewServeMux(),
		rateLimiter:      make(map[string]*RateLimiter),
	}
}

// HandleInboundRequest processes an inbound API request
func (s *apiGatewayService) HandleInboundRequest(ctx context.Context, req *http.Request, apiConfig *models.APIConfiguration) (*http.Response, error) {
	startTime := time.Now()
	requestID := req.Header.Get("X-Request-ID")
	if requestID == "" {
		requestID = fmt.Sprintf("req-%d", time.Now().UnixNano())
	}

	logEntry := s.logger.WithRequest(requestID).
		WithField("organisation_id", apiConfig.OrganisationID).
		WithField("api_config_id", apiConfig.ID).
		WithField("method", req.Method).
		WithField("path", req.URL.Path)

	logEntry.Info("Processing inbound request")

	// Rate limiting
	if !s.checkRateLimit(apiConfig.OrganisationID) {
		logEntry.Warn("Rate limit exceeded")
		return s.createErrorResponse(http.StatusTooManyRequests, "Rate limit exceeded"), nil
	}

	// Request validation
	if err := s.validateRequest(req, apiConfig); err != nil {
		logEntry.WithError(err).Error("Request validation failed")
		return s.createErrorResponse(http.StatusBadRequest, err.Error()), nil
	}

	// Find connector for this API
	connectors, err := s.connectorRepo.GetByInboundAPI(ctx, apiConfig.ID)
	if err != nil {
		logEntry.WithError(err).Error("Failed to get connectors")
		return s.createErrorResponse(http.StatusInternalServerError, "Internal server error"), nil
	}

	if len(connectors) == 0 {
		logEntry.Error("No active connector found for API")
		return s.createErrorResponse(http.StatusNotFound, "No connector configured"), nil
	}

	// Use the first active connector
	var activeConnector *models.Connector
	for _, connector := range connectors {
		if connector.IsActive {
			activeConnector = connector
			break
		}
	}

	if activeConnector == nil {
		logEntry.Error("No active connector found")
		return s.createErrorResponse(http.StatusServiceUnavailable, "No active connector"), nil
	}

	// Capture request data
	requestData, err := s.captureRequestData(req)
	if err != nil {
		logEntry.WithError(err).Error("Failed to capture request data")
		return s.createErrorResponse(http.StatusInternalServerError, "Failed to process request"), nil
	}

	// Process request through connector
	response, err := s.processRequest(ctx, requestData, activeConnector, apiConfig)
	if err != nil {
		logEntry.WithError(err).Error("Failed to process request")
		return s.createErrorResponse(http.StatusInternalServerError, "Request processing failed"), nil
	}

	// Log request completion
	processingTime := time.Since(startTime)
	s.logRequest(ctx, activeConnector, requestID, req, response, processingTime, "")

	logEntry.WithField("processing_time_ms", processingTime.Milliseconds()).
		WithField("status_code", response.StatusCode).
		Info("Request processed successfully")

	return response, nil
}

// CreateDynamicEndpoint creates a new dynamic API endpoint
func (s *apiGatewayService) CreateDynamicEndpoint(ctx context.Context, apiConfig *models.APIConfiguration) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	logEntry := s.logger.WithField("organisation_id", apiConfig.OrganisationID).
		WithField("api_config_id", apiConfig.ID).
		WithField("endpoint", apiConfig.Endpoint).
		WithField("type", apiConfig.Type)

	logEntry.Info("Creating dynamic endpoint")

	// Create endpoint path from configuration
	endpointPath := s.extractPathFromEndpoint(apiConfig.Endpoint)

	// Create handler based on API type
	var handler http.HandlerFunc
	if apiConfig.IsREST() {
		handler = s.createRESTHandler(apiConfig)
	} else if apiConfig.IsSOAP() {
		handler = s.createSOAPHandler(apiConfig)
	} else {
		return fmt.Errorf("unsupported API type: %s", apiConfig.Type)
	}

	// Store endpoint handler
	s.endpoints[apiConfig.ID] = &EndpointHandler{
		APIConfig: apiConfig,
		Handler:   handler,
	}

	// Register with HTTP mux
	s.mux.HandleFunc(endpointPath, handler)

	logEntry.WithField("path", endpointPath).Info("Dynamic endpoint created successfully")
	return nil
}

// RemoveEndpoint removes a dynamic API endpoint
func (s *apiGatewayService) RemoveEndpoint(ctx context.Context, apiConfigID string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	logEntry := s.logger.WithField("api_config_id", apiConfigID)
	logEntry.Info("Removing endpoint")

	// Remove from endpoints map
	delete(s.endpoints, apiConfigID)

	// Note: http.ServeMux doesn't support removing handlers, so we keep track
	// in our endpoints map and check there first in handlers

	logEntry.Info("Endpoint removed successfully")
	return nil
}

// Helper methods

func (s *apiGatewayService) checkRateLimit(orgID string) bool {
	s.rateMutex.Lock()
	defer s.rateMutex.Unlock()

	limiter, exists := s.rateLimiter[orgID]
	if !exists {
		// Create new rate limiter: 100 requests per minute
		limiter = NewRateLimiter(100, time.Minute/100)
		s.rateLimiter[orgID] = limiter
	}

	return limiter.Allow()
}

func (s *apiGatewayService) validateRequest(req *http.Request, apiConfig *models.APIConfiguration) error {
	// Basic validation
	if req.Method == "" {
		return fmt.Errorf("missing HTTP method")
	}

	// Content-Type validation for POST/PUT requests
	if req.Method == "POST" || req.Method == "PUT" {
		contentType := req.Header.Get("Content-Type")
		if contentType == "" {
			return fmt.Errorf("missing Content-Type header")
		}
	}

	// SOAP-specific validation
	if apiConfig.IsSOAP() {
		contentType := req.Header.Get("Content-Type")
		if !strings.Contains(contentType, "text/xml") && !strings.Contains(contentType, "application/soap+xml") {
			return fmt.Errorf("invalid Content-Type for SOAP request")
		}
	}

	return nil
}

func (s *apiGatewayService) captureRequestData(req *http.Request) (map[string]interface{}, error) {
	data := make(map[string]interface{})

	// Capture basic request info
	data["method"] = req.Method
	data["url"] = req.URL.String()
	data["headers"] = req.Header

	// Capture body if present
	if req.Body != nil {
		bodyBytes, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read request body: %w", err)
		}

		// Restore body for further processing
		req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

		data["body"] = string(bodyBytes)
	}

	// Capture query parameters
	data["query"] = req.URL.Query()

	return data, nil
}

func (s *apiGatewayService) processRequest(ctx context.Context, requestData map[string]interface{}, connector *models.Connector, apiConfig *models.APIConfiguration) (*http.Response, error) {
	// This would integrate with the transformation service and outbound client
	// For now, return a mock response

	response := &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(`{"status": "processed"}`)),
	}

	response.Header.Set("Content-Type", "application/json")
	return response, nil
}

func (s *apiGatewayService) createErrorResponse(statusCode int, message string) *http.Response {
	errorBody := map[string]interface{}{
		"error":   true,
		"message": message,
		"code":    statusCode,
	}

	bodyBytes, _ := json.Marshal(errorBody)

	response := &http.Response{
		StatusCode: statusCode,
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewReader(bodyBytes)),
	}

	response.Header.Set("Content-Type", "application/json")
	return response
}

func (s *apiGatewayService) logRequest(ctx context.Context, connector *models.Connector, requestID string, req *http.Request, resp *http.Response, processingTime time.Duration, errorMsg string) {
	if s.requestLogRepo == nil {
		return
	}

	// Capture request body
	var requestBody string
	if req.Body != nil {
		bodyBytes, _ := httputil.DumpRequest(req, true)
		requestBody = string(bodyBytes)
	}

	// Capture response body
	var responseBody string
	if resp.Body != nil {
		bodyBytes, _ := io.ReadAll(resp.Body)
		responseBody = string(bodyBytes)
		// Restore body
		resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}

	requestLog := &models.RequestLog{
		OrganisationID: connector.OrganisationID,
		ConnectorID:    connector.ID,
		RequestID:      requestID,
		Method:         req.Method,
		Path:           req.URL.Path,
		StatusCode:     resp.StatusCode,
		ProcessingTime: processingTime.Milliseconds(),
		ErrorMessage:   errorMsg,
		RequestBody:    requestBody,
		ResponseBody:   responseBody,
		Timestamp:      time.Now(),
	}

	if err := s.requestLogRepo.Create(ctx, requestLog); err != nil {
		s.logger.WithError(err).Error("Failed to log request")
	}
}

func (s *apiGatewayService) extractPathFromEndpoint(endpoint string) string {
	// Simple path extraction - in production this would be more sophisticated
	if strings.HasPrefix(endpoint, "http://") {
		endpoint = strings.TrimPrefix(endpoint, "http://")
	} else if strings.HasPrefix(endpoint, "https://") {
		endpoint = strings.TrimPrefix(endpoint, "https://")
	}

	// Find first slash after domain
	parts := strings.SplitN(endpoint, "/", 2)
	if len(parts) > 1 {
		return "/" + parts[1]
	}

	return "/api"
}

func (s *apiGatewayService) createRESTHandler(apiConfig *models.APIConfiguration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Check if endpoint still exists
		s.mutex.RLock()
		_, exists := s.endpoints[apiConfig.ID]
		s.mutex.RUnlock()

		if !exists {
			http.Error(w, "Endpoint not found", http.StatusNotFound)
			return
		}

		// Process the request
		resp, err := s.HandleInboundRequest(r.Context(), r, apiConfig)
		if err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Copy response
		for key, values := range resp.Header {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}

		w.WriteHeader(resp.StatusCode)

		if resp.Body != nil {
			io.Copy(w, resp.Body)
			resp.Body.Close()
		}
	}
}

func (s *apiGatewayService) createSOAPHandler(apiConfig *models.APIConfiguration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Check if endpoint still exists
		s.mutex.RLock()
		_, exists := s.endpoints[apiConfig.ID]
		s.mutex.RUnlock()

		if !exists {
			s.sendSOAPFault(w, "Server", "Endpoint not found")
			return
		}

		// SOAP requests must be POST
		if r.Method != "POST" {
			s.sendSOAPFault(w, "Client", "SOAP requests must use POST method")
			return
		}

		// Process the SOAP request
		resp, err := s.HandleInboundRequest(r.Context(), r, apiConfig)
		if err != nil {
			s.sendSOAPFault(w, "Server", "Internal server error")
			return
		}

		// Copy response
		for key, values := range resp.Header {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}

		w.WriteHeader(resp.StatusCode)

		if resp.Body != nil {
			io.Copy(w, resp.Body)
			resp.Body.Close()
		}
	}
}

func (s *apiGatewayService) sendSOAPFault(w http.ResponseWriter, code, message string) {
	fault := SOAPFault{
		Code:   code,
		String: message,
	}

	envelope := SOAPEnvelope{
		Xmlns: "http://schemas.xmlsoap.org/soap/envelope/",
		Body:  SOAPBody{Content: fault},
	}

	w.Header().Set("Content-Type", "text/xml; charset=utf-8")
	w.WriteHeader(http.StatusInternalServerError)

	xml.NewEncoder(w).Encode(envelope)
}
