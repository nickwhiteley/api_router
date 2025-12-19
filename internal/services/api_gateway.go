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
	configService    ConfigurationService

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
	configService ConfigurationService,
) APIGatewayService {
	return &apiGatewayService{
		logger:           logger,
		connectorRepo:    connectorRepo,
		requestLogRepo:   requestLogRepo,
		transformService: transformService,
		outboundService:  outboundService,
		authService:      authService,
		configService:    configService,
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

	// If no API configuration provided, look it up based on the request path
	if apiConfig == nil {
		var err error
		apiConfig, err = s.findAPIConfigByPath(ctx, req.URL.Path)
		if err != nil {
			s.logger.WithError(err).WithField("path", req.URL.Path).Error("Failed to find API configuration")
			response := s.createErrorResponse(http.StatusInternalServerError, "Failed to lookup API configuration")
			processingTime := time.Since(startTime)
			s.logFailedRequest(ctx, requestID, req, response, processingTime, "Failed to lookup API configuration", "")
			return response, err
		}
		if apiConfig == nil {
			s.logger.WithField("path", req.URL.Path).Warn("No API configuration found for path")
			response := s.createErrorResponse(http.StatusNotFound, "API endpoint not found")
			processingTime := time.Since(startTime)
			s.logFailedRequest(ctx, requestID, req, response, processingTime, "API endpoint not found", "")
			return response, nil
		}
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
		response := s.createErrorResponse(http.StatusTooManyRequests, "Rate limit exceeded")
		processingTime := time.Since(startTime)
		s.logFailedRequest(ctx, requestID, req, response, processingTime, "Rate limit exceeded", apiConfig.OrganisationID)
		return response, nil
	}

	// Request validation
	if err := s.validateRequest(req, apiConfig); err != nil {
		errorMsg := fmt.Sprintf("Request validation failed: %v", err)
		logEntry.WithError(err).Error("Request validation failed")
		response := s.createErrorResponse(http.StatusBadRequest, errorMsg)
		processingTime := time.Since(startTime)
		s.logFailedRequest(ctx, requestID, req, response, processingTime, err.Error(), apiConfig.OrganisationID)
		return response, nil
	}

	// Find connector for this API
	connectors, err := s.connectorRepo.GetByInboundAPI(ctx, apiConfig.ID)
	if err != nil {
		errorMsg := fmt.Sprintf("Failed to get connectors: %v", err)
		logEntry.WithError(err).Error("Failed to get connectors")
		response := s.createErrorResponse(http.StatusInternalServerError, errorMsg)
		processingTime := time.Since(startTime)
		s.logFailedRequest(ctx, requestID, req, response, processingTime, err.Error(), apiConfig.OrganisationID)
		return response, nil
	}

	if len(connectors) == 0 {
		logEntry.Error("No active connector found for API")
		response := s.createErrorResponse(http.StatusNotFound, "No connector configured")
		processingTime := time.Since(startTime)
		s.logFailedRequest(ctx, requestID, req, response, processingTime, "No connector configured", apiConfig.OrganisationID)
		return response, nil
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
		response := s.createErrorResponse(http.StatusServiceUnavailable, "No active connector")
		processingTime := time.Since(startTime)
		s.logFailedRequest(ctx, requestID, req, response, processingTime, "No active connector", apiConfig.OrganisationID)
		return response, nil
	}

	// Capture request data
	requestData, err := s.captureRequestData(req)
	if err != nil {
		errorMsg := fmt.Sprintf("Failed to capture request data: %v", err)
		logEntry.WithError(err).Error("Failed to capture request data")
		response := s.createErrorResponse(http.StatusInternalServerError, errorMsg)
		processingTime := time.Since(startTime)
		s.logRequest(ctx, activeConnector, requestID, req, response, processingTime, err.Error())
		return response, nil
	}

	// Process request through connector
	updatedCtx, response, err := s.processRequest(ctx, requestData, activeConnector, apiConfig)
	if err != nil {
		logEntry.WithError(err).Error("Failed to process request")
		// Use the detailed error response from processRequest instead of creating a generic one
		processingTime := time.Since(startTime)
		s.logRequest(updatedCtx, activeConnector, requestID, req, response, processingTime, err.Error())
		return response, nil
	}

	// Log request completion
	processingTime := time.Since(startTime)
	s.logRequest(updatedCtx, activeConnector, requestID, req, response, processingTime, "")

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

	// Header validation for inbound APIs
	if apiConfig.IsInbound() {
		missingHeaders := apiConfig.Headers.ValidateRequiredHeaders(req.Header)
		if len(missingHeaders) > 0 {
			return fmt.Errorf("missing required headers: %s", strings.Join(missingHeaders, ", "))
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

	// Check for sanitized body from security middleware first
	if sanitizedBody, hasSanitizedBody := req.Context().Value("sanitized_body").(map[string]interface{}); hasSanitizedBody {
		s.logger.WithField("sanitized_body", sanitizedBody).Info("Using sanitized body from security middleware")
		// Merge sanitized JSON fields into the top level for easier field mapping access
		for key, value := range sanitizedBody {
			data[key] = value
		}
		// Also store the raw sanitized body
		bodyBytes, _ := json.Marshal(sanitizedBody)
		data["body"] = string(bodyBytes)
	} else {
		// Fallback: try to read from request body if no sanitized body available
		if req.Body != nil {
			bodyBytes, err := io.ReadAll(req.Body)
			if err != nil {
				return nil, fmt.Errorf("failed to read request body: %w", err)
			}

			// Restore body for further processing
			req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

			// Store raw body as string
			data["body"] = string(bodyBytes)

			// Try to parse JSON body and merge fields into top level for easier field mapping
			if len(bodyBytes) > 0 {
				contentType := req.Header.Get("Content-Type")
				s.logger.WithField("content_type", contentType).WithField("body", string(bodyBytes)).Info("Processing request body from raw stream")
				if strings.Contains(contentType, "application/json") {
					var jsonBody map[string]interface{}
					if err := json.Unmarshal(bodyBytes, &jsonBody); err == nil {
						s.logger.WithField("parsed_json", jsonBody).Info("Successfully parsed JSON body")
						// Merge JSON fields into the top level for easier field mapping access
						for key, value := range jsonBody {
							data[key] = value
						}
					} else {
						s.logger.WithError(err).Error("Failed to parse JSON body")
					}
				}
			}
		}
	}

	// Capture query parameters
	data["query"] = req.URL.Query()

	return data, nil
}

func (s *apiGatewayService) processRequest(ctx context.Context, requestData map[string]interface{}, connector *models.Connector, apiConfig *models.APIConfiguration) (context.Context, *http.Response, error) {
	var transformedData interface{}
	var err error

	// Choose transformation method based on connector configuration
	if connector.PythonScript != "" {
		// Use Python script transformation
		transformedData, err = s.transformService.ExecuteScript(ctx, connector.PythonScript, requestData)
		if err != nil {
			// Prepare detailed error information for logging
			detailedErrorInfo := map[string]interface{}{
				"error_type":    "python_script_execution",
				"connector_id":  connector.ID,
				"script_length": len(connector.PythonScript),
				"error_message": err.Error(),
				"timestamp":     time.Now().UTC(),
			}

			// Add additional context if it's a ScriptExecutionError
			if scriptErr, ok := err.(*ScriptExecutionError); ok {
				detailedErrorInfo["exit_code"] = scriptErr.ExitCode
				detailedErrorInfo["stderr"] = scriptErr.Stderr
				detailedErrorInfo["script_path"] = scriptErr.ScriptPath

				if scriptErr.DetailedError != nil {
					detailedErrorInfo["python_error_details"] = scriptErr.DetailedError
					s.logger.WithField("has_python_error_details", true).
						WithField("python_error_type", func() string {
							if details, ok := scriptErr.DetailedError["error_type"].(string); ok {
								return details
							}
							return "unknown"
						}()).
						Info("Found detailed Python error information in ScriptExecutionError")
				} else {
					s.logger.WithField("has_python_error_details", false).
						Warn("ScriptExecutionError found but no detailed error information")
				}

				if scriptErr.InputData != "" {
					detailedErrorInfo["input_data"] = scriptErr.InputData
				}
			} else {
				s.logger.WithField("error_type", fmt.Sprintf("%T", err)).
					Warn("Error is not a ScriptExecutionError, detailed Python info may be lost")
			}

			// Add detailed error to context for logging
			ctx = context.WithValue(ctx, "detailed_error", detailedErrorInfo)

			// Log detailed error information
			logEntry := s.logger.WithError(err).
				WithField("connector_id", connector.ID).
				WithField("script_length", len(connector.PythonScript))

			if scriptErr, ok := err.(*ScriptExecutionError); ok {
				logEntry = logEntry.
					WithField("exit_code", scriptErr.ExitCode).
					WithField("stderr", scriptErr.Stderr).
					WithField("script_path", scriptErr.ScriptPath)

				if scriptErr.DetailedError != nil {
					logEntry = logEntry.WithField("detailed_error", scriptErr.DetailedError)
				}
			}

			logEntry.Error("Python script transformation failed with detailed error information")

			// Return a simple error message to the client, detailed info is in logs
			simpleErrorMsg := "Python script transformation failed"
			return ctx, s.createErrorResponse(http.StatusInternalServerError, simpleErrorMsg), fmt.Errorf("python script transformation failed")
		}
	} else if len(connector.FieldMappings) > 0 {
		// Use field mapping transformation
		transformedData, err = s.processFieldMappings(ctx, requestData, connector.FieldMappings)
		if err != nil {
			// Log detailed error information
			s.logger.WithError(err).
				WithField("connector_id", connector.ID).
				WithField("field_mappings_count", len(connector.FieldMappings)).
				Error("Field mapping transformation failed")

			// Return simple error message to client
			simpleErrorMsg := "Field mapping transformation failed"
			return ctx, s.createErrorResponse(http.StatusInternalServerError, simpleErrorMsg), fmt.Errorf("field mapping transformation failed")
		}
	} else {
		// No transformation configured - this should be caught by validation
		errorMsg := "No transformation configured - connector must have either Python script or field mappings"
		s.logger.Error("Connector has no transformation method configured")
		return ctx, s.createErrorResponse(http.StatusInternalServerError, errorMsg),
			fmt.Errorf("connector %s has no transformation method", connector.ID)
	}

	// Get outbound API configuration
	outboundAPI, err := s.configService.GetAPIConfiguration(ctx, connector.OutboundAPIID)
	if err != nil {
		// Log detailed error
		s.logger.WithError(err).
			WithField("outbound_api_id", connector.OutboundAPIID).
			Error("Failed to get outbound API configuration")

		// Return simple error message to client
		simpleErrorMsg := "Configuration error"
		return ctx, s.createErrorResponse(http.StatusInternalServerError, simpleErrorMsg), fmt.Errorf("configuration error")
	}

	// Send request to outbound API based on its type
	var response *http.Response
	if outboundAPI.IsREST() {
		// For REST APIs, use POST method with the transformed data
		response, err = s.outboundService.SendRESTRequest(ctx, outboundAPI, "POST", "", transformedData, nil)
	} else if outboundAPI.IsSOAP() {
		// For SOAP APIs, use the transformed data as the SOAP body
		response, err = s.outboundService.SendSOAPRequest(ctx, outboundAPI, "transform", transformedData)
	} else {
		err = fmt.Errorf("unsupported outbound API type: %s", outboundAPI.Type)
	}

	if err != nil {
		// Log detailed error
		s.logger.WithError(err).
			WithField("outbound_api_id", outboundAPI.ID).
			WithField("outbound_api_type", outboundAPI.Type).
			Error("Failed to send request to outbound API")

		// Return simple error message to client
		simpleErrorMsg := "Outbound API request failed"
		return ctx, s.createErrorResponse(http.StatusBadGateway, simpleErrorMsg), fmt.Errorf("outbound API request failed")
	}

	// Check if the outbound API returned an error status code
	if response.StatusCode >= 400 {
		// Read the response body to get error details
		var responseBody string
		if response.Body != nil {
			bodyBytes, readErr := io.ReadAll(response.Body)
			if readErr == nil {
				responseBody = string(bodyBytes)
				// Restore the body for logging
				response.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			}
		}

		// Log detailed error information
		s.logger.WithField("outbound_status", response.StatusCode).
			WithField("outbound_response", responseBody).
			WithField("outbound_api_id", outboundAPI.ID).
			Error("Outbound API returned error status")

		// Return simple error message to client
		simpleErrorMsg := fmt.Sprintf("Outbound API error (status %d)", response.StatusCode)
		return ctx, s.createErrorResponse(http.StatusBadGateway, simpleErrorMsg), fmt.Errorf("outbound API error: status %d", response.StatusCode)
	}

	return ctx, response, nil
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

	// Capture detailed error information from context if available
	var errorDetails string
	if errorDetailsData := ctx.Value("detailed_error"); errorDetailsData != nil {
		if detailsBytes, err := json.Marshal(errorDetailsData); err == nil {
			errorDetails = string(detailsBytes)
			s.logger.WithField("error_details_length", len(errorDetails)).
				WithField("has_error_details", true).
				WithField("error_details_preview", func() string {
					if len(errorDetails) > 200 {
						return errorDetails[:200] + "..."
					}
					return errorDetails
				}()).
				Info("Captured detailed error information for logging")
		} else {
			s.logger.WithError(err).Error("Failed to marshal detailed error information")
		}
	} else {
		s.logger.WithField("has_error_details", false).
			Info("No detailed error information found in context")
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
		ErrorDetails:   errorDetails,
		RequestBody:    requestBody,
		ResponseBody:   responseBody,
		Timestamp:      time.Now(),
	}

	if err := s.requestLogRepo.Create(ctx, requestLog); err != nil {
		s.logger.WithError(err).Error("Failed to log request")
	}
}

func (s *apiGatewayService) logFailedRequest(ctx context.Context, requestID string, req *http.Request, resp *http.Response, processingTime time.Duration, errorMsg string, orgID string) {
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

	// Capture detailed error information from context if available
	var errorDetails string
	if errorDetailsData := ctx.Value("detailed_error"); errorDetailsData != nil {
		if detailsBytes, err := json.Marshal(errorDetailsData); err == nil {
			errorDetails = string(detailsBytes)
		}
	}

	requestLog := &models.RequestLog{
		OrganisationID: orgID,
		ConnectorID:    "", // No connector for failed requests
		RequestID:      requestID,
		Method:         req.Method,
		Path:           req.URL.Path,
		StatusCode:     resp.StatusCode,
		ProcessingTime: processingTime.Milliseconds(),
		ErrorMessage:   errorMsg,
		ErrorDetails:   errorDetails,
		RequestBody:    requestBody,
		ResponseBody:   responseBody,
		Timestamp:      time.Now(),
	}

	if err := s.requestLogRepo.Create(ctx, requestLog); err != nil {
		s.logger.WithError(err).Error("Failed to log failed request")
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

// processFieldMappings transforms input data using field mappings
func (s *apiGatewayService) processFieldMappings(ctx context.Context, inputData map[string]interface{}, mappings []models.FieldMapping) (map[string]interface{}, error) {
	result := make(map[string]interface{})

	// Debug: log the input data structure
	s.logger.WithField("input_data_keys", getMapKeys(inputData)).Info("Processing field mappings with input data")

	for _, mapping := range mappings {
		if !mapping.IsActive {
			continue
		}

		// Extract value from input using field path
		value, err := s.extractFieldValue(inputData, mapping.InboundFieldPath)
		if err != nil {
			s.logger.WithError(err).WithField("field_path", mapping.InboundFieldPath).Warn("Failed to extract field value")
			continue // Skip missing fields rather than failing
		}

		// Apply transformation script if provided
		if mapping.TransformScript != "" {
			transformedValue, err := s.executeFieldTransform(ctx, mapping.TransformScript, value)
			if err != nil {
				s.logger.WithError(err).WithField("field_path", mapping.InboundFieldPath).Error("Field transformation failed")
				return nil, fmt.Errorf("transformation failed for field %s: %w", mapping.InboundFieldPath, err)
			}
			value = transformedValue
		}

		// Set value in output using field path
		err = s.setFieldValue(result, mapping.OutboundFieldPath, value)
		if err != nil {
			s.logger.WithError(err).WithField("field_path", mapping.OutboundFieldPath).Error("Failed to set field value")
			return nil, fmt.Errorf("failed to set field %s: %w", mapping.OutboundFieldPath, err)
		}
	}

	return result, nil
}

// getMapKeys returns the keys of a map for debugging
func getMapKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// findAPIConfigByPath finds an API configuration that matches the given request path
func (s *apiGatewayService) findAPIConfigByPath(ctx context.Context, requestPath string) (*models.APIConfiguration, error) {
	// Extract the API endpoint from the request path
	// Expected format: /api{endpoint} where {endpoint} is the API configuration endpoint
	apiPath := strings.TrimPrefix(requestPath, "/api")
	if apiPath == "" {
		apiPath = "/"
	}

	// Get all API configurations from all organizations
	// In a production system, you'd want to optimize this with indexing or caching
	allOrgs, err := s.configService.GetAllOrganisations(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get organisations: %w", err)
	}

	for _, org := range allOrgs {
		apis, err := s.configService.GetAPIConfigurationsByOrganisation(ctx, org.ID)
		if err != nil {
			s.logger.WithError(err).WithField("org_id", org.ID).Warn("Failed to get API configurations for organisation")
			continue
		}

		for _, api := range apis {
			// Check if this API configuration matches the request path
			if api.Direction == "inbound" && api.Endpoint == apiPath {
				s.logger.WithField("api_id", api.ID).WithField("endpoint", api.Endpoint).Info("Found matching API configuration")
				return api, nil
			}
		}
	}

	return nil, nil // No matching API configuration found
}

// extractFieldValue extracts a value from nested map using dot notation (e.g., "user.name")
func (s *apiGatewayService) extractFieldValue(data map[string]interface{}, fieldPath string) (interface{}, error) {
	parts := strings.Split(fieldPath, ".")
	current := data

	for i, part := range parts {
		if i == len(parts)-1 {
			// Last part - return the value
			if value, exists := current[part]; exists {
				return value, nil
			}
			return nil, fmt.Errorf("field %s not found", fieldPath)
		}

		// Navigate deeper into nested structure
		if next, exists := current[part]; exists {
			if nextMap, ok := next.(map[string]interface{}); ok {
				current = nextMap
			} else {
				return nil, fmt.Errorf("field %s is not a nested object", strings.Join(parts[:i+1], "."))
			}
		} else {
			return nil, fmt.Errorf("field %s not found", strings.Join(parts[:i+1], "."))
		}
	}

	return nil, fmt.Errorf("invalid field path: %s", fieldPath)
}

// setFieldValue sets a value in nested map using dot notation (e.g., "customer.name")
func (s *apiGatewayService) setFieldValue(data map[string]interface{}, fieldPath string, value interface{}) error {
	parts := strings.Split(fieldPath, ".")
	current := data

	for i, part := range parts {
		if i == len(parts)-1 {
			// Last part - set the value
			current[part] = value
			return nil
		}

		// Navigate or create nested structure
		if next, exists := current[part]; exists {
			if nextMap, ok := next.(map[string]interface{}); ok {
				current = nextMap
			} else {
				return fmt.Errorf("field %s exists but is not a nested object", strings.Join(parts[:i+1], "."))
			}
		} else {
			// Create new nested object
			newMap := make(map[string]interface{})
			current[part] = newMap
			current = newMap
		}
	}

	return nil
}

// executeFieldTransform executes a small Python snippet for field transformation
func (s *apiGatewayService) executeFieldTransform(ctx context.Context, script string, value interface{}) (interface{}, error) {
	// Create a simple Python script that transforms a single value
	fullScript := fmt.Sprintf(`
def transform_field(value):
    %s

# Execute transformation
import json
import sys

try:
    input_data = json.loads(sys.argv[1])
    result = transform_field(input_data)
    print(json.dumps(result))
except Exception as e:
    print(json.dumps({"error": str(e)}))
`, script)

	// Use the transformation service to execute the script
	inputData := map[string]interface{}{"value": value}
	result, err := s.transformService.ExecuteScript(ctx, fullScript, inputData)
	if err != nil {
		return nil, err
	}

	// Extract the transformed value
	if resultMap, ok := result.(map[string]interface{}); ok {
		if transformedValue, exists := resultMap["value"]; exists {
			return transformedValue, nil
		}
	}

	return result, nil
}
