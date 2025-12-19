package services

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"api-translation-platform/internal/logger"
	"api-translation-platform/internal/models"
)

// HTTPClientPool manages a pool of HTTP clients with connection pooling
type HTTPClientPool struct {
	clients map[string]*http.Client
	mutex   sync.RWMutex
}

// NewHTTPClientPool creates a new HTTP client pool
func NewHTTPClientPool() *HTTPClientPool {
	return &HTTPClientPool{
		clients: make(map[string]*http.Client),
	}
}

// GetClient returns an HTTP client for the given endpoint with connection pooling
func (p *HTTPClientPool) GetClient(endpoint string) *http.Client {
	p.mutex.RLock()
	client, exists := p.clients[endpoint]
	p.mutex.RUnlock()

	if exists {
		return client
	}

	p.mutex.Lock()
	defer p.mutex.Unlock()

	// Double-check after acquiring write lock
	if client, exists := p.clients[endpoint]; exists {
		return client
	}

	// Create new client with connection pooling
	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	}

	client = &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	p.clients[endpoint] = client
	return client
}

// RetryConfig holds retry configuration
type RetryConfig struct {
	MaxRetries      int
	InitialDelay    time.Duration
	MaxDelay        time.Duration
	BackoffFactor   float64
	RetryableErrors []int // HTTP status codes that should trigger retry
}

// DefaultRetryConfig returns default retry configuration
func DefaultRetryConfig() *RetryConfig {
	return &RetryConfig{
		MaxRetries:      3,
		InitialDelay:    100 * time.Millisecond,
		MaxDelay:        5 * time.Second,
		BackoffFactor:   2.0,
		RetryableErrors: []int{500, 502, 503, 504, 408, 429},
	}
}

// Note: SOAPEnvelope and SOAPFault are defined in api_gateway.go to avoid duplication

// outboundClientService implements OutboundClientService
type outboundClientService struct {
	logger       *logger.Logger
	clientPool   *HTTPClientPool
	retryConfig  *RetryConfig
	errorHandler *ErrorHandler
}

// NewOutboundClientService creates a new outbound client service
func NewOutboundClientService(logger *logger.Logger) OutboundClientService {
	return &outboundClientService{
		logger:       logger,
		clientPool:   NewHTTPClientPool(),
		retryConfig:  DefaultRetryConfig(),
		errorHandler: NewErrorHandler(logger),
	}
}

// SendRESTRequest sends a REST request to an outbound API with retry logic
func (s *outboundClientService) SendRESTRequest(ctx context.Context, apiConfig *models.APIConfiguration, method, path string, body interface{}, headers map[string]string) (*http.Response, error) {
	s.logger.WithField("organisation_id", apiConfig.OrganisationID).
		WithField("api_config_id", apiConfig.ID).
		WithField("method", method).
		WithField("path", path).
		Info("Sending REST request")

	// Construct full URL
	fullURL, err := s.buildURL(apiConfig.Endpoint, path)
	if err != nil {
		return nil, fmt.Errorf("failed to build URL: %w", err)
	}

	// Prepare request body
	var requestBody io.Reader
	if body != nil {
		bodyBytes, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		requestBody = bytes.NewReader(bodyBytes)
	}

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, method, fullURL, requestBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// Set headers
	s.setHeaders(req, apiConfig, headers)

	// Set authentication
	if err := s.setAuthentication(req, apiConfig); err != nil {
		return nil, fmt.Errorf("failed to set authentication: %w", err)
	}

	// Execute request with comprehensive error handling
	client := s.clientPool.GetClient(apiConfig.Endpoint)

	var response *http.Response
	err = s.errorHandler.ExecuteWithFullProtection(ctx, func() error {
		var execErr error
		response, execErr = client.Do(req)
		return execErr
	}, fmt.Sprintf("rest_request_%s", apiConfig.ID))

	if err != nil {
		return nil, s.errorHandler.HandleError(ctx, err, map[string]interface{}{
			"organisation_id": apiConfig.OrganisationID,
			"api_config_id":   apiConfig.ID,
			"method":          method,
			"path":            path,
			"operation":       "rest_request",
		})
	}

	return response, nil
}

// SendSOAPRequest sends a SOAP request to an outbound API
func (s *outboundClientService) SendSOAPRequest(ctx context.Context, apiConfig *models.APIConfiguration, action string, body interface{}) (*http.Response, error) {
	s.logger.WithField("organisation_id", apiConfig.OrganisationID).
		WithField("api_config_id", apiConfig.ID).
		WithField("action", action).
		Info("Sending SOAP request")

	// Convert body to XML-compatible format
	var bodyContent string
	switch v := body.(type) {
	case string:
		bodyContent = v
	case []byte:
		bodyContent = string(v)
	case map[string]string:
		// Convert map to simple XML elements
		var elements []string
		for key, value := range v {
			elements = append(elements, fmt.Sprintf("<%s>%s</%s>", key, value, key))
		}
		bodyContent = strings.Join(elements, "")
	default:
		// Try to marshal as JSON and wrap in CDATA
		jsonBytes, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal SOAP body: %w", err)
		}
		bodyContent = fmt.Sprintf("<![CDATA[%s]]>", string(jsonBytes))
	}

	// Create SOAP envelope with the body content
	envelope := SOAPEnvelope{
		Xmlns: "http://schemas.xmlsoap.org/soap/envelope/",
		Body:  SOAPBody{Content: bodyContent},
	}

	// Marshal SOAP envelope to XML
	soapBytes, err := xml.Marshal(envelope)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal SOAP envelope: %w", err)
	}

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "POST", apiConfig.Endpoint, bytes.NewReader(soapBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create SOAP request: %w", err)
	}

	// Set SOAP headers
	req.Header.Set("Content-Type", "text/xml; charset=utf-8")
	req.Header.Set("SOAPAction", action)

	// Set additional headers from configuration
	s.setHeaders(req, apiConfig, nil)

	// Set authentication
	if err := s.setAuthentication(req, apiConfig); err != nil {
		return nil, fmt.Errorf("failed to set authentication: %w", err)
	}

	// Execute request with comprehensive error handling
	client := s.clientPool.GetClient(apiConfig.Endpoint)

	var response *http.Response
	err = s.errorHandler.ExecuteWithFullProtection(ctx, func() error {
		var execErr error
		response, execErr = client.Do(req)
		return execErr
	}, fmt.Sprintf("soap_request_%s", apiConfig.ID))

	if err != nil {
		return nil, s.errorHandler.HandleError(ctx, err, map[string]interface{}{
			"organisation_id": apiConfig.OrganisationID,
			"api_config_id":   apiConfig.ID,
			"action":          action,
			"operation":       "soap_request",
		})
	}

	return response, nil
}

// TestConnection tests the connection to an outbound API
func (s *outboundClientService) TestConnection(ctx context.Context, apiConfig *models.APIConfiguration) error {
	s.logger.WithField("organisation_id", apiConfig.OrganisationID).
		WithField("api_config_id", apiConfig.ID).
		Info("Testing outbound connection")

	var req *http.Request
	var err error

	if apiConfig.IsREST() {
		// For REST APIs, send a HEAD request to test connectivity
		req, err = http.NewRequestWithContext(ctx, "HEAD", apiConfig.Endpoint, nil)
	} else if apiConfig.IsSOAP() {
		// For SOAP APIs, send a minimal SOAP request or OPTIONS request
		req, err = http.NewRequestWithContext(ctx, "OPTIONS", apiConfig.Endpoint, nil)
	} else {
		return fmt.Errorf("unsupported API type: %s", apiConfig.Type)
	}

	if err != nil {
		return fmt.Errorf("failed to create test request: %w", err)
	}

	// Set authentication for test request
	if err := s.setAuthentication(req, apiConfig); err != nil {
		return fmt.Errorf("failed to set authentication: %w", err)
	}

	// Execute test request
	client := s.clientPool.GetClient(apiConfig.Endpoint)
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("connection test failed: %w", err)
	}
	defer resp.Body.Close()

	// Check if response indicates successful connection
	if resp.StatusCode >= 400 && resp.StatusCode != 404 && resp.StatusCode != 405 {
		return fmt.Errorf("connection test failed with status: %d", resp.StatusCode)
	}

	s.logger.WithField("organisation_id", apiConfig.OrganisationID).
		WithField("api_config_id", apiConfig.ID).
		WithField("status_code", resp.StatusCode).
		Info("Connection test successful")

	return nil
}

// buildURL constructs a full URL from endpoint and path
func (s *outboundClientService) buildURL(endpoint, path string) (string, error) {
	baseURL, err := url.Parse(endpoint)
	if err != nil {
		return "", err
	}

	if path == "" {
		return baseURL.String(), nil
	}

	// Ensure path starts with /
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	pathURL, err := url.Parse(path)
	if err != nil {
		return "", err
	}

	return baseURL.ResolveReference(pathURL).String(), nil
}

// setHeaders sets HTTP headers on the request
func (s *outboundClientService) setHeaders(req *http.Request, apiConfig *models.APIConfiguration, additionalHeaders map[string]string) {
	// Set default headers
	if req.Header.Get("Content-Type") == "" && req.Body != nil {
		if apiConfig.IsREST() {
			req.Header.Set("Content-Type", "application/json")
		}
	}

	// Set headers from API configuration
	allHeaders := apiConfig.Headers.GetAllHeaders()
	for key, value := range allHeaders {
		req.Header.Set(key, value)
	}

	// Set additional headers
	for key, value := range additionalHeaders {
		req.Header.Set(key, value)
	}
}

// setAuthentication sets authentication headers based on configuration
func (s *outboundClientService) setAuthentication(req *http.Request, apiConfig *models.APIConfiguration) error {
	auth := apiConfig.Authentication

	switch auth.Type {
	case "api_key":
		headerName := auth.Parameters["header_name"]
		if headerName == "" {
			headerName = "X-API-Key"
		}
		apiKey := auth.Parameters["api_key"]
		if apiKey == "" {
			return fmt.Errorf("api_key parameter is required for api_key authentication")
		}
		req.Header.Set(headerName, apiKey)

	case "basic":
		username := auth.Parameters["username"]
		password := auth.Parameters["password"]
		if username == "" || password == "" {
			return fmt.Errorf("username and password parameters are required for basic authentication")
		}
		req.SetBasicAuth(username, password)

	case "oauth":
		token := auth.Parameters["token"]
		if token == "" {
			return fmt.Errorf("token parameter is required for oauth authentication")
		}
		req.Header.Set("Authorization", "Bearer "+token)

	case "none":
		// No authentication required
		break

	default:
		return fmt.Errorf("unsupported authentication type: %s", auth.Type)
	}

	return nil
}

// executeWithRetry executes an HTTP request with exponential backoff retry logic
func (s *outboundClientService) executeWithRetry(ctx context.Context, client *http.Client, req *http.Request) (*http.Response, error) {
	var lastErr error

	for attempt := 0; attempt <= s.retryConfig.MaxRetries; attempt++ {
		// Clone request for retry attempts
		reqClone := req.Clone(ctx)

		// Execute request
		resp, err := client.Do(reqClone)
		if err != nil {
			lastErr = err
			if attempt < s.retryConfig.MaxRetries {
				delay := s.calculateBackoffDelay(attempt)
				s.logger.WithField("attempt", attempt+1).
					WithField("delay", delay).
					WithField("error", err.Error()).
					Warn("Request failed, retrying")

				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-time.After(delay):
					continue
				}
			}
			continue
		}

		// Check if response status code indicates a retryable error
		if s.isRetryableStatusCode(resp.StatusCode) && attempt < s.retryConfig.MaxRetries {
			resp.Body.Close()
			delay := s.calculateBackoffDelay(attempt)
			s.logger.WithField("attempt", attempt+1).
				WithField("status_code", resp.StatusCode).
				WithField("delay", delay).
				Warn("Request returned retryable status code, retrying")

			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
				continue
			}
		}

		// Request successful or non-retryable error
		return resp, nil
	}

	return nil, fmt.Errorf("request failed after %d attempts: %w", s.retryConfig.MaxRetries+1, lastErr)
}

// calculateBackoffDelay calculates the delay for exponential backoff
func (s *outboundClientService) calculateBackoffDelay(attempt int) time.Duration {
	delay := float64(s.retryConfig.InitialDelay) * math.Pow(s.retryConfig.BackoffFactor, float64(attempt))
	if delay > float64(s.retryConfig.MaxDelay) {
		delay = float64(s.retryConfig.MaxDelay)
	}
	return time.Duration(delay)
}

// isRetryableStatusCode checks if a status code should trigger a retry
func (s *outboundClientService) isRetryableStatusCode(statusCode int) bool {
	for _, code := range s.retryConfig.RetryableErrors {
		if statusCode == code {
			return true
		}
	}
	return false
}
