package models

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidationService(t *testing.T) {
	validator := NewValidationService()

	t.Run("Organisation validation", func(t *testing.T) {
		// Valid organisation
		org := &Organisation{
			Name:     "Test Organisation",
			IsActive: true,
		}
		err := validator.ValidateStruct(org)
		assert.NoError(t, err)

		// Invalid organisation - missing name
		org.Name = ""
		err = validator.ValidateStruct(org)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "name")

		// Invalid organisation - name too long
		org.Name = string(make([]byte, 256)) // 256 characters
		err = validator.ValidateStruct(org)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "name")
	})

	t.Run("User validation", func(t *testing.T) {
		// Valid user
		user := &User{
			OrganisationID: "org-123",
			Username:       "testuser",
			Email:          "test@example.com",
			Role:           "org_admin",
			IsActive:       true,
		}
		err := validator.ValidateStruct(user)
		assert.NoError(t, err)

		// Invalid user - missing organisation ID
		user.OrganisationID = ""
		err = validator.ValidateStruct(user)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "organisation_id")

		// Invalid user - invalid email
		user.OrganisationID = "org-123"
		user.Email = "invalid-email"
		err = validator.ValidateStruct(user)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "email")

		// Invalid user - invalid role
		user.Email = "test@example.com"
		user.Role = "invalid_role"
		err = validator.ValidateStruct(user)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "role")

		// Invalid user - username too short
		user.Role = "org_admin"
		user.Username = "ab"
		err = validator.ValidateStruct(user)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "username")
	})

	t.Run("APIConfiguration validation", func(t *testing.T) {
		// Valid API configuration
		apiConfig := &APIConfiguration{
			OrganisationID: "org-123",
			Name:           "Test API",
			Type:           "REST",
			Direction:      "inbound",
			Endpoint:       "https://api.example.com",
			Authentication: AuthenticationConfig{
				Type:       "api_key",
				Parameters: map[string]string{"key": "test"},
			},
		}
		err := validator.ValidateStruct(apiConfig)
		assert.NoError(t, err)

		// Invalid API configuration - missing organisation ID
		apiConfig.OrganisationID = ""
		err = validator.ValidateStruct(apiConfig)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "organisation_id")

		// Invalid API configuration - invalid type
		apiConfig.OrganisationID = "org-123"
		apiConfig.Type = "INVALID"
		err = validator.ValidateStruct(apiConfig)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "type")

		// Invalid API configuration - invalid direction
		apiConfig.Type = "REST"
		apiConfig.Direction = "invalid"
		err = validator.ValidateStruct(apiConfig)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "direction")

		// Invalid API configuration - invalid URL
		apiConfig.Direction = "inbound"
		apiConfig.Endpoint = "not-a-url"
		err = validator.ValidateStruct(apiConfig)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "endpoint")
	})

	t.Run("Connector validation", func(t *testing.T) {
		// Valid connector with Python script
		connector := &Connector{
			OrganisationID: "org-123",
			Name:           "Test Connector",
			InboundAPIID:   "api-inbound",
			OutboundAPIID:  "api-outbound",
			PythonScript:   "print('hello world')",
			IsActive:       true,
		}
		err := validator.ValidateStruct(connector)
		assert.NoError(t, err)

		// Valid connector with field mappings (no Python script)
		connectorWithMappings := &Connector{
			OrganisationID: "org-123",
			Name:           "Test Connector with Mappings",
			InboundAPIID:   "api-inbound",
			OutboundAPIID:  "api-outbound",
			IsActive:       true,
			FieldMappings: []FieldMapping{
				{
					InboundFieldPath:  "user.name",
					OutboundFieldPath: "customer.fullName",
				},
			},
		}
		err = validator.ValidateStruct(connectorWithMappings)
		assert.NoError(t, err)
		err = connectorWithMappings.Validate()
		assert.NoError(t, err)

		// Invalid connector - missing organisation ID
		connector.OrganisationID = ""
		err = validator.ValidateStruct(connector)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "organisation_id")

		// Invalid connector - missing both Python script and field mappings
		connectorInvalid := &Connector{
			OrganisationID: "org-123",
			Name:           "Invalid Connector",
			InboundAPIID:   "api-inbound",
			OutboundAPIID:  "api-outbound",
			IsActive:       true,
		}
		err = connectorInvalid.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "python_script or field_mappings")
	})

	t.Run("RequestLog validation", func(t *testing.T) {
		// Valid request log
		requestLog := &RequestLog{
			OrganisationID: "org-123",
			ConnectorID:    "connector-123",
			RequestID:      "req-123",
			Method:         "POST",
			Path:           "/api/test",
			StatusCode:     200,
			ProcessingTime: 100,
		}
		err := validator.ValidateStruct(requestLog)
		assert.NoError(t, err)

		// Invalid request log - missing organisation ID
		requestLog.OrganisationID = ""
		err = validator.ValidateStruct(requestLog)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "organisation_id")

		// Invalid request log - missing method
		requestLog.OrganisationID = "org-123"
		requestLog.Method = ""
		err = validator.ValidateStruct(requestLog)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "method")
	})
}

func TestUserMethods(t *testing.T) {
	t.Run("IsGlobalAdmin", func(t *testing.T) {
		user := &User{Role: "global_admin"}
		assert.True(t, user.IsGlobalAdmin())

		user.Role = "org_admin"
		assert.False(t, user.IsGlobalAdmin())
	})

	t.Run("IsOrgAdmin", func(t *testing.T) {
		user := &User{Role: "org_admin"}
		assert.True(t, user.IsOrgAdmin())

		user.Role = "global_admin"
		assert.False(t, user.IsOrgAdmin())
	})
}

func TestAPIConfigurationMethods(t *testing.T) {
	t.Run("IsInbound", func(t *testing.T) {
		api := &APIConfiguration{Direction: "inbound"}
		assert.True(t, api.IsInbound())

		api.Direction = "outbound"
		assert.False(t, api.IsInbound())
	})

	t.Run("IsOutbound", func(t *testing.T) {
		api := &APIConfiguration{Direction: "outbound"}
		assert.True(t, api.IsOutbound())

		api.Direction = "inbound"
		assert.False(t, api.IsOutbound())
	})

	t.Run("IsREST", func(t *testing.T) {
		api := &APIConfiguration{Type: "REST"}
		assert.True(t, api.IsREST())

		api.Type = "SOAP"
		assert.False(t, api.IsREST())
	})

	t.Run("IsSOAP", func(t *testing.T) {
		api := &APIConfiguration{Type: "SOAP"}
		assert.True(t, api.IsSOAP())

		api.Type = "REST"
		assert.False(t, api.IsSOAP())
	})
}

func TestRequestLogMethods(t *testing.T) {
	t.Run("IsError", func(t *testing.T) {
		// Test with error status code
		log := &RequestLog{StatusCode: 400}
		assert.True(t, log.IsError())

		log.StatusCode = 500
		assert.True(t, log.IsError())

		// Test with error message
		log.StatusCode = 200
		log.ErrorMessage = "Something went wrong"
		assert.True(t, log.IsError())

		// Test success case
		log.ErrorMessage = ""
		assert.False(t, log.IsError())
	})

	t.Run("IsSuccess", func(t *testing.T) {
		// Test success case
		log := &RequestLog{StatusCode: 200}
		assert.True(t, log.IsSuccess())

		log.StatusCode = 201
		assert.True(t, log.IsSuccess())

		// Test error cases
		log.StatusCode = 400
		assert.False(t, log.IsSuccess())

		log.StatusCode = 200
		log.ErrorMessage = "Error occurred"
		assert.False(t, log.IsSuccess())
	})
}

func TestAuthenticationConfigSerialization(t *testing.T) {
	t.Run("JSON serialization/deserialization", func(t *testing.T) {
		original := AuthenticationConfig{
			Type: "api_key",
			Parameters: map[string]string{
				"key":    "test-key",
				"header": "X-API-Key",
			},
		}

		// Test JSON marshaling
		jsonData, err := json.Marshal(original)
		require.NoError(t, err)

		// Test JSON unmarshaling
		var deserialized AuthenticationConfig
		err = json.Unmarshal(jsonData, &deserialized)
		require.NoError(t, err)

		assert.Equal(t, original.Type, deserialized.Type)
		assert.Equal(t, original.Parameters, deserialized.Parameters)
	})

	t.Run("Database Value/Scan", func(t *testing.T) {
		auth := AuthenticationConfig{
			Type: "oauth",
			Parameters: map[string]string{
				"client_id":     "test-client",
				"client_secret": "test-secret",
			},
		}

		// Test Value method
		value, err := auth.Value()
		require.NoError(t, err)
		assert.NotNil(t, value)

		// Test Scan method
		var scanned AuthenticationConfig
		err = scanned.Scan(value)
		require.NoError(t, err)

		assert.Equal(t, auth.Type, scanned.Type)
		assert.Equal(t, auth.Parameters, scanned.Parameters)
	})

	t.Run("Scan with nil value", func(t *testing.T) {
		var auth AuthenticationConfig
		err := auth.Scan(nil)
		assert.NoError(t, err)
	})

	t.Run("Scan with invalid type", func(t *testing.T) {
		var auth AuthenticationConfig
		err := auth.Scan(123) // Invalid type
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cannot scan")
	})
}

func TestHeadersConfigSerialization(t *testing.T) {
	t.Run("JSON serialization/deserialization", func(t *testing.T) {
		original := HeadersConfig{
			Static: map[string]string{
				"Content-Type":    "application/json",
				"Authorization":   "Bearer token123",
				"X-Custom-Header": "custom-value",
			},
			Required: []string{"Authorization"},
			Dynamic:  map[string]string{},
		}

		// Test JSON marshaling
		jsonData, err := json.Marshal(original)
		require.NoError(t, err)

		// Test JSON unmarshaling
		var deserialized HeadersConfig
		err = json.Unmarshal(jsonData, &deserialized)
		require.NoError(t, err)

		assert.Equal(t, original, deserialized)
	})

	t.Run("Database Value/Scan", func(t *testing.T) {
		headers := HeadersConfig{
			Static: map[string]string{
				"Accept":        "application/json",
				"User-Agent":    "test-client/1.0",
				"Cache-Control": "no-cache",
			},
			Required: []string{"Accept"},
			Dynamic:  map[string]string{},
		}

		// Test Value method
		value, err := headers.Value()
		require.NoError(t, err)
		assert.NotNil(t, value)

		// Test Scan method
		var scanned HeadersConfig
		err = scanned.Scan(value)
		require.NoError(t, err)

		assert.Equal(t, headers, scanned)
	})

	t.Run("Scan with nil value", func(t *testing.T) {
		var headers HeadersConfig
		err := headers.Scan(nil)
		assert.NoError(t, err)
		assert.NotNil(t, headers)
		assert.Len(t, headers, 0)
	})

	t.Run("Scan with invalid type", func(t *testing.T) {
		var headers HeadersConfig
		err := headers.Scan(123) // Invalid type
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cannot scan")
	})

	t.Run("Value with empty HeadersConfig", func(t *testing.T) {
		var headers HeadersConfig
		value, err := headers.Value()
		assert.NoError(t, err)
		assert.NotNil(t, value)
	})
}

func TestModelTableNames(t *testing.T) {
	t.Run("Organisation table name", func(t *testing.T) {
		org := Organisation{}
		assert.Equal(t, "organisations", org.TableName())
	})

	t.Run("User table name", func(t *testing.T) {
		user := User{}
		assert.Equal(t, "users", user.TableName())
	})

	t.Run("APIConfiguration table name", func(t *testing.T) {
		api := APIConfiguration{}
		assert.Equal(t, "api_configurations", api.TableName())
	})

	t.Run("Connector table name", func(t *testing.T) {
		connector := Connector{}
		assert.Equal(t, "connectors", connector.TableName())
	})

	t.Run("RequestLog table name", func(t *testing.T) {
		log := RequestLog{}
		assert.Equal(t, "request_logs", log.TableName())
	})
}

func TestModelValidationConstraints(t *testing.T) {
	validator := NewValidationService()

	t.Run("Organisation name constraints", func(t *testing.T) {
		// Test minimum length
		org := &Organisation{Name: ""}
		err := validator.ValidateStruct(org)
		assert.Error(t, err)

		// Test maximum length (255 characters)
		longName := string(make([]byte, 256))
		for i := range longName {
			longName = longName[:i] + "a" + longName[i+1:]
		}
		org.Name = longName
		err = validator.ValidateStruct(org)
		assert.Error(t, err)

		// Test valid length
		org.Name = "Valid Organisation Name"
		err = validator.ValidateStruct(org)
		assert.NoError(t, err)
	})

	t.Run("User username constraints", func(t *testing.T) {
		user := &User{
			OrganisationID: "org-123",
			Email:          "test@example.com",
			Role:           "org_admin",
		}

		// Test minimum length (3 characters)
		user.Username = "ab"
		err := validator.ValidateStruct(user)
		assert.Error(t, err)

		// Test maximum length (50 characters)
		user.Username = string(make([]byte, 51))
		for i := range user.Username {
			user.Username = user.Username[:i] + "a" + user.Username[i+1:]
		}
		err = validator.ValidateStruct(user)
		assert.Error(t, err)

		// Test valid length
		user.Username = "validuser"
		err = validator.ValidateStruct(user)
		assert.NoError(t, err)
	})

	t.Run("Authentication type constraints", func(t *testing.T) {
		apiConfig := &APIConfiguration{
			OrganisationID: "org-123",
			Name:           "Test API",
			Type:           "REST",
			Direction:      "inbound",
			Endpoint:       "https://api.example.com",
		}

		// Test valid authentication types
		validTypes := []string{"api_key", "oauth", "basic", "none"}
		for _, authType := range validTypes {
			apiConfig.Authentication = AuthenticationConfig{
				Type:       authType,
				Parameters: map[string]string{},
			}
			err := validator.ValidateStruct(apiConfig)
			assert.NoError(t, err, "Authentication type %s should be valid", authType)
		}

		// Test invalid authentication type
		apiConfig.Authentication = AuthenticationConfig{
			Type:       "invalid_type",
			Parameters: map[string]string{},
		}
		err := validator.ValidateStruct(apiConfig)
		assert.Error(t, err)
	})
}
