// Package atp provides a Go client SDK for the API Translation Platform Management API
package atp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// Client represents the API Translation Platform client
type Client struct {
	baseURL    string
	httpClient *http.Client
	token      string
	version    string
}

// ClientOption represents a client configuration option
type ClientOption func(*Client)

// WithHTTPClient sets a custom HTTP client
func WithHTTPClient(client *http.Client) ClientOption {
	return func(c *Client) {
		c.httpClient = client
	}
}

// WithToken sets the authentication token
func WithToken(token string) ClientOption {
	return func(c *Client) {
		c.token = token
	}
}

// WithVersion sets the API version
func WithVersion(version string) ClientOption {
	return func(c *Client) {
		c.version = version
	}
}

// NewClient creates a new API Translation Platform client
func NewClient(baseURL string, options ...ClientOption) *Client {
	client := &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		version: "v1",
	}

	for _, option := range options {
		option(client)
	}

	return client
}

// Organisation represents an organisation in the system
type Organisation struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	IsActive  bool      `json:"is_active"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// OrganisationCreate represents the data needed to create an organisation
type OrganisationCreate struct {
	Name     string `json:"name"`
	IsActive bool   `json:"is_active"`
}

// APIConfiguration represents an API configuration
type APIConfiguration struct {
	ID             string               `json:"id"`
	OrganisationID string               `json:"organisation_id"`
	Name           string               `json:"name"`
	Type           string               `json:"type"`
	Direction      string               `json:"direction"`
	Endpoint       string               `json:"endpoint"`
	Authentication AuthenticationConfig `json:"authentication"`
	Headers        map[string]string    `json:"headers"`
	CreatedAt      time.Time            `json:"created_at"`
	UpdatedAt      time.Time            `json:"updated_at"`
}

// AuthenticationConfig represents authentication configuration
type AuthenticationConfig struct {
	Type       string            `json:"type"`
	Parameters map[string]string `json:"parameters"`
}

// Connector represents a connector configuration
type Connector struct {
	ID             string    `json:"id"`
	OrganisationID string    `json:"organisation_id"`
	Name           string    `json:"name"`
	InboundAPIID   string    `json:"inbound_api_id"`
	OutboundAPIID  string    `json:"outbound_api_id"`
	PythonScript   string    `json:"python_script"`
	IsActive       bool      `json:"is_active"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// User represents a user in the system
type User struct {
	ID             string    `json:"id"`
	OrganisationID string    `json:"organisation_id"`
	Username       string    `json:"username"`
	Email          string    `json:"email"`
	Role           string    `json:"role"`
	IsActive       bool      `json:"is_active"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// SystemHealth represents system health status
type SystemHealth struct {
	Status     string                     `json:"status"`
	Components map[string]ComponentHealth `json:"components"`
	Timestamp  time.Time                  `json:"timestamp"`
}

// ComponentHealth represents individual component health
type ComponentHealth struct {
	Status    string    `json:"status"`
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
}

// UsageAnalytics represents API usage analytics
type UsageAnalytics struct {
	TotalRequests   int       `json:"total_requests"`
	SuccessRate     float64   `json:"success_rate"`
	AvgResponseTime float64   `json:"avg_response_time"`
	StartTime       time.Time `json:"start_time"`
	EndTime         time.Time `json:"end_time"`
}

// Error represents an API error response
type Error struct {
	Message   string    `json:"error"`
	Status    int       `json:"status"`
	Timestamp time.Time `json:"timestamp"`
	Details   string    `json:"details,omitempty"`
}

func (e *Error) Error() string {
	return fmt.Sprintf("API error %d: %s", e.Status, e.Message)
}

// Organisation Management Methods

// CreateOrganisation creates a new organisation
func (c *Client) CreateOrganisation(ctx context.Context, org *OrganisationCreate) (*Organisation, error) {
	var result Organisation
	err := c.makeRequest(ctx, "POST", "/organisations", org, &result)
	return &result, err
}

// GetOrganisations retrieves all organisations
func (c *Client) GetOrganisations(ctx context.Context) ([]*Organisation, error) {
	var result []*Organisation
	err := c.makeRequest(ctx, "GET", "/organisations", nil, &result)
	return result, err
}

// GetOrganisation retrieves a specific organisation
func (c *Client) GetOrganisation(ctx context.Context, id string) (*Organisation, error) {
	var result Organisation
	path := fmt.Sprintf("/organisations/%s", id)
	err := c.makeRequest(ctx, "GET", path, nil, &result)
	return &result, err
}

// UpdateOrganisation updates an existing organisation
func (c *Client) UpdateOrganisation(ctx context.Context, id string, org *OrganisationCreate) (*Organisation, error) {
	var result Organisation
	path := fmt.Sprintf("/organisations/%s", id)
	err := c.makeRequest(ctx, "PUT", path, org, &result)
	return &result, err
}

// DeleteOrganisation deletes an organisation
func (c *Client) DeleteOrganisation(ctx context.Context, id string) error {
	path := fmt.Sprintf("/organisations/%s", id)
	return c.makeRequest(ctx, "DELETE", path, nil, nil)
}

// API Configuration Management Methods

// CreateAPIConfiguration creates a new API configuration
func (c *Client) CreateAPIConfiguration(ctx context.Context, orgID string, config *APIConfiguration) (*APIConfiguration, error) {
	var result APIConfiguration
	path := fmt.Sprintf("/organisations/%s/api-configurations", orgID)
	err := c.makeRequest(ctx, "POST", path, config, &result)
	return &result, err
}

// GetAPIConfigurations retrieves all API configurations for an organisation
func (c *Client) GetAPIConfigurations(ctx context.Context, orgID string) ([]*APIConfiguration, error) {
	var result []*APIConfiguration
	path := fmt.Sprintf("/organisations/%s/api-configurations", orgID)
	err := c.makeRequest(ctx, "GET", path, nil, &result)
	return result, err
}

// GetAPIConfiguration retrieves a specific API configuration
func (c *Client) GetAPIConfiguration(ctx context.Context, id string) (*APIConfiguration, error) {
	var result APIConfiguration
	path := fmt.Sprintf("/api-configurations/%s", id)
	err := c.makeRequest(ctx, "GET", path, nil, &result)
	return &result, err
}

// UpdateAPIConfiguration updates an existing API configuration
func (c *Client) UpdateAPIConfiguration(ctx context.Context, id string, config *APIConfiguration) (*APIConfiguration, error) {
	var result APIConfiguration
	path := fmt.Sprintf("/api-configurations/%s", id)
	err := c.makeRequest(ctx, "PUT", path, config, &result)
	return &result, err
}

// DeleteAPIConfiguration deletes an API configuration
func (c *Client) DeleteAPIConfiguration(ctx context.Context, id string) error {
	path := fmt.Sprintf("/api-configurations/%s", id)
	return c.makeRequest(ctx, "DELETE", path, nil, nil)
}

// TestAPIConfiguration tests an API configuration
func (c *Client) TestAPIConfiguration(ctx context.Context, id string, testData map[string]interface{}) (map[string]interface{}, error) {
	var result map[string]interface{}
	path := fmt.Sprintf("/api-configurations/%s/test", id)
	err := c.makeRequest(ctx, "POST", path, testData, &result)
	return result, err
}

// Connector Management Methods

// CreateConnector creates a new connector
func (c *Client) CreateConnector(ctx context.Context, orgID string, connector *Connector) (*Connector, error) {
	var result Connector
	path := fmt.Sprintf("/organisations/%s/connectors", orgID)
	err := c.makeRequest(ctx, "POST", path, connector, &result)
	return &result, err
}

// GetConnectors retrieves all connectors for an organisation
func (c *Client) GetConnectors(ctx context.Context, orgID string) ([]*Connector, error) {
	var result []*Connector
	path := fmt.Sprintf("/organisations/%s/connectors", orgID)
	err := c.makeRequest(ctx, "GET", path, nil, &result)
	return result, err
}

// GetConnector retrieves a specific connector
func (c *Client) GetConnector(ctx context.Context, id string) (*Connector, error) {
	var result Connector
	path := fmt.Sprintf("/connectors/%s", id)
	err := c.makeRequest(ctx, "GET", path, nil, &result)
	return &result, err
}

// UpdateConnector updates an existing connector
func (c *Client) UpdateConnector(ctx context.Context, id string, connector *Connector) (*Connector, error) {
	var result Connector
	path := fmt.Sprintf("/connectors/%s", id)
	err := c.makeRequest(ctx, "PUT", path, connector, &result)
	return &result, err
}

// DeleteConnector deletes a connector
func (c *Client) DeleteConnector(ctx context.Context, id string) error {
	path := fmt.Sprintf("/connectors/%s", id)
	return c.makeRequest(ctx, "DELETE", path, nil, nil)
}

// UpdateConnectorScript updates a connector's Python script
func (c *Client) UpdateConnectorScript(ctx context.Context, id, script string) error {
	path := fmt.Sprintf("/connectors/%s/script", id)
	payload := map[string]string{"script": script}
	return c.makeRequest(ctx, "PUT", path, payload, nil)
}

// Monitoring and Analytics Methods

// GetSystemHealth retrieves system health status
func (c *Client) GetSystemHealth(ctx context.Context) (*SystemHealth, error) {
	var result SystemHealth
	err := c.makeRequest(ctx, "GET", "/system/health", nil, &result)
	return &result, err
}

// GetOrganisationMetrics retrieves metrics for an organisation
func (c *Client) GetOrganisationMetrics(ctx context.Context, orgID string) (map[string]interface{}, error) {
	var result map[string]interface{}
	path := fmt.Sprintf("/organisations/%s/metrics", orgID)
	err := c.makeRequest(ctx, "GET", path, nil, &result)
	return result, err
}

// GetUsageAnalytics retrieves API usage analytics
func (c *Client) GetUsageAnalytics(ctx context.Context, startTime, endTime *time.Time) (*UsageAnalytics, error) {
	var result UsageAnalytics

	params := url.Values{}
	if startTime != nil {
		params.Set("start", startTime.Format(time.RFC3339))
	}
	if endTime != nil {
		params.Set("end", endTime.Format(time.RFC3339))
	}

	path := "/analytics/usage"
	if len(params) > 0 {
		path += "?" + params.Encode()
	}

	err := c.makeRequest(ctx, "GET", path, nil, &result)
	return &result, err
}

// GetRateLimitAnalytics retrieves rate limit analytics
func (c *Client) GetRateLimitAnalytics(ctx context.Context, startTime, endTime *time.Time) (map[string]interface{}, error) {
	var result map[string]interface{}

	params := url.Values{}
	if startTime != nil {
		params.Set("start", startTime.Format(time.RFC3339))
	}
	if endTime != nil {
		params.Set("end", endTime.Format(time.RFC3339))
	}

	path := "/analytics/rate-limits"
	if len(params) > 0 {
		path += "?" + params.Encode()
	}

	err := c.makeRequest(ctx, "GET", path, nil, &result)
	return result, err
}

// Pagination support

// ListOptions represents options for list operations
type ListOptions struct {
	Limit  int
	Offset int
}

// GetOrganisationLogs retrieves logs for an organisation with pagination
func (c *Client) GetOrganisationLogs(ctx context.Context, orgID string, opts *ListOptions) ([]map[string]interface{}, error) {
	var result []map[string]interface{}

	params := url.Values{}
	if opts != nil {
		if opts.Limit > 0 {
			params.Set("limit", strconv.Itoa(opts.Limit))
		}
		if opts.Offset > 0 {
			params.Set("offset", strconv.Itoa(opts.Offset))
		}
	}

	path := fmt.Sprintf("/organisations/%s/logs", orgID)
	if len(params) > 0 {
		path += "?" + params.Encode()
	}

	err := c.makeRequest(ctx, "GET", path, nil, &result)
	return result, err
}

// Private helper methods

func (c *Client) makeRequest(ctx context.Context, method, path string, body interface{}, result interface{}) error {
	url := fmt.Sprintf("%s/api/%s%s", c.baseURL, c.version, path)

	var reqBody io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("failed to marshal request body: %w", err)
		}
		reqBody = bytes.NewBuffer(jsonBody)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode >= 400 {
		var apiErr Error
		if err := json.Unmarshal(respBody, &apiErr); err != nil {
			return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
		}
		return &apiErr
	}

	if result != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, result); err != nil {
			return fmt.Errorf("failed to unmarshal response: %w", err)
		}
	}

	return nil
}
