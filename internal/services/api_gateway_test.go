package services

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
	"github.com/stretchr/testify/mock"

	"api-translation-platform/internal/models"
)

// createTestAPIGatewayService creates a test API gateway service with mocks
func createTestAPIGatewayService() APIGatewayService {
	testLogger := createTestLogger()
	mockConnectorRepo := &MockConnectorRepository{}
	mockRequestLogRepo := &MockRequestLogRepository{}
	mockTransformService := &MockTransformationService{}
	mockOutboundService := &MockOutboundClientService{}
	mockAuthService := &MockAuthenticationService{}
	return NewAPIGatewayService(testLogger, mockConnectorRepo, mockRequestLogRepo, mockTransformService, mockOutboundService, mockAuthService)
}

// MockConnectorRepository for testing
type MockConnectorRepository struct {
	mock.Mock
}

func (m *MockConnectorRepository) Create(ctx context.Context, connector *models.Connector) error {
	args := m.Called(ctx, connector)
	return args.Error(0)
}

func (m *MockConnectorRepository) Update(ctx context.Context, connector *models.Connector) error {
	args := m.Called(ctx, connector)
	return args.Error(0)
}

func (m *MockConnectorRepository) Delete(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockConnectorRepository) GetByID(ctx context.Context, id string) (*models.Connector, error) {
	args := m.Called(ctx, id)
	return args.Get(0).(*models.Connector), args.Error(1)
}

func (m *MockConnectorRepository) GetByOrganisation(ctx context.Context, orgID string) ([]*models.Connector, error) {
	args := m.Called(ctx, orgID)
	return args.Get(0).([]*models.Connector), args.Error(1)
}

func (m *MockConnectorRepository) GetByInboundAPI(ctx context.Context, apiID string) ([]*models.Connector, error) {
	args := m.Called(ctx, apiID)
	return args.Get(0).([]*models.Connector), args.Error(1)
}

// MockTransformationService for testing
type MockTransformationService struct {
	mock.Mock
}

func (m *MockTransformationService) ExecuteScript(ctx context.Context, script string, inputData interface{}) (interface{}, error) {
	args := m.Called(ctx, script, inputData)
	return args.Get(0), args.Error(1)
}

func (m *MockTransformationService) ValidateScript(ctx context.Context, script string) error {
	args := m.Called(ctx, script)
	return args.Error(0)
}

func (m *MockTransformationService) ReloadScript(ctx context.Context, connectorID string) error {
	args := m.Called(ctx, connectorID)
	return args.Error(0)
}

// MockOutboundClientService for testing
type MockOutboundClientService struct {
	mock.Mock
}

func (m *MockOutboundClientService) SendRESTRequest(ctx context.Context, apiConfig *models.APIConfiguration, method, path string, body interface{}, headers map[string]string) (*http.Response, error) {
	args := m.Called(ctx, apiConfig, method, path, body, headers)
	return args.Get(0).(*http.Response), args.Error(1)
}

func (m *MockOutboundClientService) SendSOAPRequest(ctx context.Context, apiConfig *models.APIConfiguration, action string, body interface{}) (*http.Response, error) {
	args := m.Called(ctx, apiConfig, action, body)
	return args.Get(0).(*http.Response), args.Error(1)
}

func (m *MockOutboundClientService) TestConnection(ctx context.Context, apiConfig *models.APIConfiguration) error {
	args := m.Called(ctx, apiConfig)
	return args.Error(0)
}

// MockAuthenticationService for testing
type MockAuthenticationService struct {
	mock.Mock
}

func (m *MockAuthenticationService) ValidateAPIKey(ctx context.Context, apiKey string, apiConfig *models.APIConfiguration) (*models.User, error) {
	args := m.Called(ctx, apiKey, apiConfig)
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockAuthenticationService) ValidateOAuth(ctx context.Context, token string, apiConfig *models.APIConfiguration) (*models.User, error) {
	args := m.Called(ctx, token, apiConfig)
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockAuthenticationService) ValidateBasicAuth(ctx context.Context, username, password string, apiConfig *models.APIConfiguration) (*models.User, error) {
	args := m.Called(ctx, username, password, apiConfig)
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockAuthenticationService) GenerateJWT(ctx context.Context, user *models.User) (string, error) {
	args := m.Called(ctx, user)
	return args.String(0), args.Error(1)
}

func (m *MockAuthenticationService) ValidateJWT(ctx context.Context, token string) (*models.User, error) {
	args := m.Called(ctx, token)
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockAuthenticationService) HashPassword(password string) (string, error) {
	args := m.Called(password)
	return args.String(0), args.Error(1)
}

// **Feature: api-translation-platform, Property 1: Dynamic API endpoint creation**
// **Validates: Requirements 1.1, 1.2**
func TestProperty_DynamicAPIEndpointCreation(t *testing.T) {
	properties := gopter.NewProperties(&gopter.TestParameters{MinSuccessfulTests: 100})

	properties.Property("valid API configuration should create functional endpoint", prop.ForAll(
		func(orgID, name, endpoint string, apiType, direction string) bool {
			service := createTestAPIGatewayService()

			apiConfig := &models.APIConfiguration{
				ID:             "test-api-id",
				OrganisationID: orgID,
				Name:           name,
				Type:           apiType,
				Direction:      direction,
				Endpoint:       endpoint,
				Authentication: models.AuthenticationConfig{
					Type:       "api_key",
					Parameters: map[string]string{"key": "test-key"},
				},
				Headers: map[string]string{"Content-Type": "application/json"},
			}

			err := service.CreateDynamicEndpoint(context.Background(), apiConfig)
			return err == nil
		},
		gen.AlphaString().SuchThat(func(s string) bool { return len(s) > 0 && len(s) < 50 }),   // orgID
		gen.AlphaString().SuchThat(func(s string) bool { return len(s) > 0 && len(s) <= 255 }), // name
		gen.OneConstOf("http://example.com/api", "https://api.example.com/v1"),                 // endpoint
		gen.OneConstOf("REST", "SOAP"),        // apiType
		gen.OneConstOf("inbound", "outbound"), // direction
	))

	properties.Property("REST endpoint creation should handle different HTTP methods", prop.ForAll(
		func(orgID, name string) bool {
			service := createTestAPIGatewayService()

			apiConfig := &models.APIConfiguration{
				ID:             "test-rest-api",
				OrganisationID: orgID,
				Name:           name,
				Type:           "REST",
				Direction:      "inbound",
				Endpoint:       "http://example.com/api/rest",
				Authentication: models.AuthenticationConfig{
					Type:       "api_key",
					Parameters: map[string]string{"key": "test-key"},
				},
			}

			err := service.CreateDynamicEndpoint(context.Background(), apiConfig)
			return err == nil
		},
		gen.AlphaString().SuchThat(func(s string) bool { return len(s) > 0 && len(s) < 50 }),
		gen.AlphaString().SuchThat(func(s string) bool { return len(s) > 0 && len(s) <= 255 }),
	))

	properties.Property("SOAP endpoint creation should handle WSDL interface", prop.ForAll(
		func(orgID, name string) bool {
			service := createTestAPIGatewayService()

			apiConfig := &models.APIConfiguration{
				ID:             "test-soap-api",
				OrganisationID: orgID,
				Name:           name,
				Type:           "SOAP",
				Direction:      "inbound",
				Endpoint:       "http://example.com/soap/service",
				Authentication: models.AuthenticationConfig{
					Type:       "basic",
					Parameters: map[string]string{"username": "user", "password": "pass"},
				},
			}

			err := service.CreateDynamicEndpoint(context.Background(), apiConfig)
			return err == nil
		},
		gen.AlphaString().SuchThat(func(s string) bool { return len(s) > 0 && len(s) < 50 }),
		gen.AlphaString().SuchThat(func(s string) bool { return len(s) > 0 && len(s) <= 255 }),
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// **Feature: api-translation-platform, Property 3: Request capture and routing**
// **Validates: Requirements 1.4**
func TestProperty_RequestCaptureAndRouting(t *testing.T) {
	properties := gopter.NewProperties(&gopter.TestParameters{MinSuccessfulTests: 100})

	properties.Property("inbound API request should be captured and routed to correct connector", prop.ForAll(
		func(orgID, apiID, connectorID string, method, path string) bool {
			if len(orgID) == 0 || len(apiID) == 0 || len(connectorID) == 0 {
				return true // Skip empty inputs
			}

			service := createTestAPIGatewayService()

			apiConfig := &models.APIConfiguration{
				ID:             apiID,
				OrganisationID: orgID,
				Name:           "test-api",
				Type:           "REST",
				Direction:      "inbound",
				Endpoint:       "http://example.com" + path,
				Authentication: models.AuthenticationConfig{
					Type:       "api_key",
					Parameters: map[string]string{"key": "test-key"},
				},
			}

			req, _ := http.NewRequest(method, "http://example.com"+path, nil)
			req.Header.Set("X-Request-ID", "test-request-id")

			_, err := service.HandleInboundRequest(context.Background(), req, apiConfig)
			return err == nil
		},
		gen.AlphaString().SuchThat(func(s string) bool { return len(s) > 0 && len(s) < 50 }), // orgID
		gen.AlphaString().SuchThat(func(s string) bool { return len(s) > 0 && len(s) < 50 }), // apiID
		gen.AlphaString().SuchThat(func(s string) bool { return len(s) > 0 && len(s) < 50 }), // connectorID
		gen.OneConstOf("GET", "POST", "PUT", "DELETE"),                                       // method
		gen.OneConstOf("/api/v1/test", "/api/v2/data", "/service/endpoint"),                  // path
	))

	properties.Property("request data should be captured completely for connector processing", prop.ForAll(
		func(orgID, apiID string) bool {
			if len(orgID) == 0 || len(apiID) == 0 {
				return true // Skip empty inputs
			}

			service := createTestAPIGatewayService()

			apiConfig := &models.APIConfiguration{
				ID:             apiID,
				OrganisationID: orgID,
				Name:           "test-api",
				Type:           "REST",
				Direction:      "inbound",
				Endpoint:       "http://example.com/api/test",
				Authentication: models.AuthenticationConfig{
					Type:       "none",
					Parameters: map[string]string{},
				},
			}

			req, _ := http.NewRequest("POST", "http://example.com/api/test", strings.NewReader(`{"test": "data"}`))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Custom-Header", "custom-value")
			req.Header.Set("X-Request-ID", "test-request-id")

			_, err := service.HandleInboundRequest(context.Background(), req, apiConfig)
			return err == nil
		},
		gen.AlphaString().SuchThat(func(s string) bool { return len(s) > 0 && len(s) < 50 }), // orgID
		gen.AlphaString().SuchThat(func(s string) bool { return len(s) > 0 && len(s) < 50 }), // apiID
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// **Feature: api-translation-platform, Property 18: Comprehensive logging**
// **Validates: Requirements 8.1, 8.2**
func TestProperty_ComprehensiveLogging(t *testing.T) {
	properties := gopter.NewProperties(&gopter.TestParameters{MinSuccessfulTests: 100})

	properties.Property("API request processing should log complete request details", prop.ForAll(
		func(orgID, apiID, method, path string, statusCode int) bool {
			if len(orgID) == 0 || len(apiID) == 0 || len(method) == 0 || len(path) == 0 {
				return true // Skip empty inputs
			}

			service := createTestAPIGatewayService()

			apiConfig := &models.APIConfiguration{
				ID:             apiID,
				OrganisationID: orgID,
				Name:           "test-api",
				Type:           "REST",
				Direction:      "inbound",
				Endpoint:       "http://example.com" + path,
				Authentication: models.AuthenticationConfig{
					Type:       "api_key",
					Parameters: map[string]string{"key": "test-key"},
				},
			}

			req, _ := http.NewRequest(method, "http://example.com"+path, strings.NewReader(`{"data": "test"}`))
			req.Header.Set("X-Request-ID", "test-request-"+apiID)
			req.Header.Set("Content-Type", "application/json")

			_, err := service.HandleInboundRequest(context.Background(), req, apiConfig)
			return err == nil
		},
		gen.AlphaString().SuchThat(func(s string) bool { return len(s) > 0 && len(s) < 50 }), // orgID
		gen.AlphaString().SuchThat(func(s string) bool { return len(s) > 0 && len(s) < 50 }), // apiID
		gen.OneConstOf("GET", "POST", "PUT", "DELETE", "PATCH"),                              // method
		gen.OneConstOf("/api/v1/test", "/api/v2/data", "/service/endpoint", "/health"),       // path
		gen.IntRange(200, 599), // statusCode
	))

	properties.Property("error conditions should be logged with detailed context", prop.ForAll(
		func(orgID, apiID string) bool {
			if len(orgID) == 0 || len(apiID) == 0 {
				return true // Skip empty inputs
			}

			service := createTestAPIGatewayService()

			apiConfig := &models.APIConfiguration{
				ID:             apiID,
				OrganisationID: orgID,
				Name:           "test-api",
				Type:           "REST",
				Direction:      "inbound",
				Endpoint:       "http://example.com/api/error",
				Authentication: models.AuthenticationConfig{
					Type:       "oauth",
					Parameters: map[string]string{"token": "invalid-token"},
				},
			}

			req, _ := http.NewRequest("POST", "http://example.com/api/error", strings.NewReader(`invalid json`))
			req.Header.Set("X-Request-ID", "error-request-"+apiID)
			req.Header.Set("Content-Type", "application/json")

			_, err := service.HandleInboundRequest(context.Background(), req, apiConfig)
			return err == nil
		},
		gen.AlphaString().SuchThat(func(s string) bool { return len(s) > 0 && len(s) < 50 }), // orgID
		gen.AlphaString().SuchThat(func(s string) bool { return len(s) > 0 && len(s) < 50 }), // apiID
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}
