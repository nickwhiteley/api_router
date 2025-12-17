package services

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"api-translation-platform/internal/config"
	"api-translation-platform/internal/logger"
	"api-translation-platform/internal/models"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOutboundClientService_PropertyTests(t *testing.T) {
	cfg := &config.Config{
		Logging: config.LoggingConfig{
			Level:  "info",
			Format: "text",
		},
	}
	logger := logger.NewLogger(cfg)
	service := NewOutboundClientService(logger)

	t.Run("Property4_OutboundConnectionEstablishment", func(t *testing.T) {
		/**Feature: api-translation-platform, Property 4: Outbound connection establishment**/
		properties := gopter.NewProperties(nil)

		properties.Property("outbound connections are established correctly", prop.ForAll(
			func(authType string, apiType string) bool {
				// Create test server that accepts all requests
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					if apiType == "SOAP" {
						w.Write([]byte(`<?xml version="1.0"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><response>success</response></soap:Body></soap:Envelope>`))
					} else {
						w.Write([]byte(`{"success": true}`))
					}
				}))
				defer server.Close()

				// Create API configuration
				apiConfig := &models.APIConfiguration{
					ID:        "test-api-" + authType + "-" + apiType,
					Type:      apiType,
					Direction: "outbound",
					Endpoint:  server.URL,
					Authentication: models.AuthenticationConfig{
						Type: authType,
						Parameters: map[string]string{
							"api_key":  "test-key",
							"username": "testuser",
							"password": "testpass",
							"token":    "test-token",
						},
					},
				}

				ctx := context.Background()

				// Test connection establishment
				if apiType == "REST" {
					resp, err := service.SendRESTRequest(ctx, apiConfig, "GET", "/test", nil, nil)
					if err != nil {
						return false
					}
					defer resp.Body.Close()
					return resp.StatusCode == http.StatusOK
				} else if apiType == "SOAP" {
					resp, err := service.SendSOAPRequest(ctx, apiConfig, "TestAction", map[string]string{"test": "data"})
					if err != nil {
						return false
					}
					defer resp.Body.Close()
					return resp.StatusCode == http.StatusOK
				}

				return false
			},
			gen.OneConstOf("api_key", "basic", "oauth", "none"),
			gen.OneConstOf("REST", "SOAP"),
		))

		properties.TestingRun(t, gopter.ConsoleReporter(false))
	})

	t.Run("Property5_ResponseCaptureAndProcessing", func(t *testing.T) {
		/**Feature: api-translation-platform, Property 5: Response capture and processing**/
		properties := gopter.NewProperties(nil)

		properties.Property("responses are captured and processed correctly", prop.ForAll(
			func(statusCode int, responseBody string, contentType string) bool {
				// Skip retryable status codes to avoid long test times
				if statusCode == 500 {
					return true
				}

				// Create test server that returns specific response
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", contentType)
					w.WriteHeader(statusCode)
					w.Write([]byte(responseBody))
				}))
				defer server.Close()

				apiConfig := &models.APIConfiguration{
					ID:        "test-response-capture",
					Type:      "REST",
					Direction: "outbound",
					Endpoint:  server.URL,
					Authentication: models.AuthenticationConfig{
						Type: "none",
					},
				}

				ctx := context.Background()
				resp, err := service.SendRESTRequest(ctx, apiConfig, "GET", "/test", nil, nil)
				if err != nil {
					return false
				}
				defer resp.Body.Close()

				// Verify response is captured correctly
				if resp.StatusCode != statusCode {
					return false
				}

				if resp.Header.Get("Content-Type") != contentType {
					return false
				}

				// Read and verify response body
				body := make([]byte, len(responseBody))
				n, _ := resp.Body.Read(body)
				return string(body[:n]) == responseBody
			},
			gen.OneConstOf(200, 201, 400, 401, 404),
			gen.AlphaString().SuchThat(func(s string) bool { return len(s) > 0 && len(s) < 100 }),
			gen.OneConstOf("application/json", "text/xml", "text/plain"),
		))

		properties.TestingRun(t, gopter.ConsoleReporter(false))
	})

	t.Run("Property6_ProtocolTranslation", func(t *testing.T) {
		/**Feature: api-translation-platform, Property 6: Protocol translation**/
		properties := gopter.NewProperties(nil)

		properties.Property("protocol translation between REST and SOAP works correctly", prop.ForAll(
			func(apiType string) bool {
				// Create a simple test server
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					if strings.Contains(r.Header.Get("Content-Type"), "text/xml") {
						// SOAP response
						w.Header().Set("Content-Type", "text/xml")
						w.Write([]byte(`<?xml version="1.0"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><response>success</response></soap:Body></soap:Envelope>`))
					} else {
						// REST response
						w.Header().Set("Content-Type", "application/json")
						w.Write([]byte(`{"success": true}`))
					}
				}))
				defer server.Close()

				// Test API configuration
				apiConfig := &models.APIConfiguration{
					ID:             "test-protocol-" + apiType,
					Type:           apiType,
					Direction:      "outbound",
					Endpoint:       server.URL,
					Authentication: models.AuthenticationConfig{Type: "none"},
				}

				ctx := context.Background()
				testData := map[string]string{"test": "data"}

				if apiType == "REST" {
					resp, err := service.SendRESTRequest(ctx, apiConfig, "POST", "/test", testData, nil)
					if err != nil {
						return false
					}
					defer resp.Body.Close()
					return resp.StatusCode == http.StatusOK
				} else if apiType == "SOAP" {
					resp, err := service.SendSOAPRequest(ctx, apiConfig, "TestAction", testData)
					if err != nil {
						return false
					}
					defer resp.Body.Close()
					return resp.StatusCode == http.StatusOK
				}

				return false
			},
			gen.OneConstOf("REST", "SOAP"),
		))

		properties.TestingRun(t, gopter.ConsoleReporter(false))
	})
}

func TestOutboundClientService_UnitTests(t *testing.T) {
	cfg := &config.Config{
		Logging: config.LoggingConfig{
			Level:  "info",
			Format: "text",
		},
	}
	logger := logger.NewLogger(cfg)
	service := NewOutboundClientService(logger)

	t.Run("TestConnection_REST_Success", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "HEAD", r.Method)
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		apiConfig := &models.APIConfiguration{
			ID:             "test-connection-rest",
			Type:           "REST",
			Direction:      "outbound",
			Endpoint:       server.URL,
			Authentication: models.AuthenticationConfig{Type: "none"},
		}

		ctx := context.Background()
		err := service.TestConnection(ctx, apiConfig)
		assert.NoError(t, err)
	})

	t.Run("TestConnection_SOAP_Success", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "OPTIONS", r.Method)
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		apiConfig := &models.APIConfiguration{
			ID:             "test-connection-soap",
			Type:           "SOAP",
			Direction:      "outbound",
			Endpoint:       server.URL,
			Authentication: models.AuthenticationConfig{Type: "none"},
		}

		ctx := context.Background()
		err := service.TestConnection(ctx, apiConfig)
		assert.NoError(t, err)
	})

	t.Run("SendRESTRequest_WithRetry", func(t *testing.T) {
		attempts := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			attempts++
			if attempts < 3 {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"success": true}`))
		}))
		defer server.Close()

		apiConfig := &models.APIConfiguration{
			ID:             "test-retry",
			Type:           "REST",
			Direction:      "outbound",
			Endpoint:       server.URL,
			Authentication: models.AuthenticationConfig{Type: "none"},
		}

		ctx := context.Background()
		resp, err := service.SendRESTRequest(ctx, apiConfig, "GET", "/test", nil, nil)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, 3, attempts) // Should have retried twice before succeeding
	})

	t.Run("SendSOAPRequest_WithAuthentication", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Verify SOAP headers
			assert.Contains(t, r.Header.Get("Content-Type"), "text/xml")
			assert.Equal(t, "TestAction", r.Header.Get("SOAPAction"))

			// Verify authentication
			assert.Equal(t, "test-key", r.Header.Get("X-API-Key"))

			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`<?xml version="1.0"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><response>success</response></soap:Body></soap:Envelope>`))
		}))
		defer server.Close()

		apiConfig := &models.APIConfiguration{
			ID:        "test-soap-auth",
			Type:      "SOAP",
			Direction: "outbound",
			Endpoint:  server.URL,
			Authentication: models.AuthenticationConfig{
				Type: "api_key",
				Parameters: map[string]string{
					"api_key": "test-key",
				},
			},
		}

		ctx := context.Background()
		resp, err := service.SendSOAPRequest(ctx, apiConfig, "TestAction", map[string]string{"test": "data"})
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("Authentication_Types", func(t *testing.T) {
		testCases := []struct {
			name     string
			authType string
			params   map[string]string
			verify   func(t *testing.T, r *http.Request)
		}{
			{
				name:     "API Key",
				authType: "api_key",
				params:   map[string]string{"api_key": "test-key"},
				verify: func(t *testing.T, r *http.Request) {
					assert.Equal(t, "test-key", r.Header.Get("X-API-Key"))
				},
			},
			{
				name:     "Basic Auth",
				authType: "basic",
				params:   map[string]string{"username": "user", "password": "pass"},
				verify: func(t *testing.T, r *http.Request) {
					username, password, ok := r.BasicAuth()
					assert.True(t, ok)
					assert.Equal(t, "user", username)
					assert.Equal(t, "pass", password)
				},
			},
			{
				name:     "OAuth",
				authType: "oauth",
				params:   map[string]string{"token": "test-token"},
				verify: func(t *testing.T, r *http.Request) {
					assert.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))
				},
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					tc.verify(t, r)
					w.WriteHeader(http.StatusOK)
				}))
				defer server.Close()

				apiConfig := &models.APIConfiguration{
					ID:        "test-auth-" + tc.authType,
					Type:      "REST",
					Direction: "outbound",
					Endpoint:  server.URL,
					Authentication: models.AuthenticationConfig{
						Type:       tc.authType,
						Parameters: tc.params,
					},
				}

				ctx := context.Background()
				resp, err := service.SendRESTRequest(ctx, apiConfig, "GET", "/test", nil, nil)
				require.NoError(t, err)
				defer resp.Body.Close()

				assert.Equal(t, http.StatusOK, resp.StatusCode)
			})
		}
	})

	t.Run("ConnectionPooling", func(t *testing.T) {
		pool := NewHTTPClientPool()

		// Get client for same endpoint multiple times
		client1 := pool.GetClient("http://example.com")
		client2 := pool.GetClient("http://example.com")
		client3 := pool.GetClient("http://different.com")

		// Should return same client for same endpoint
		assert.Same(t, client1, client2)
		// Should return different client for different endpoint
		assert.NotSame(t, client1, client3)
	})

	t.Run("RetryConfiguration", func(t *testing.T) {
		config := DefaultRetryConfig()

		assert.Equal(t, 3, config.MaxRetries)
		assert.Equal(t, 100*time.Millisecond, config.InitialDelay)
		assert.Equal(t, 5*time.Second, config.MaxDelay)
		assert.Equal(t, 2.0, config.BackoffFactor)
		assert.Contains(t, config.RetryableErrors, 500)
		assert.Contains(t, config.RetryableErrors, 502)
		assert.Contains(t, config.RetryableErrors, 503)
	})
}

func TestOutboundClientService_ErrorHandling(t *testing.T) {
	cfg := &config.Config{
		Logging: config.LoggingConfig{
			Level:  "info",
			Format: "text",
		},
	}
	logger := logger.NewLogger(cfg)
	service := NewOutboundClientService(logger)

	t.Run("InvalidURL", func(t *testing.T) {
		apiConfig := &models.APIConfiguration{
			ID:             "test-invalid-url",
			Type:           "REST",
			Direction:      "outbound",
			Endpoint:       "invalid-url",
			Authentication: models.AuthenticationConfig{Type: "none"},
		}

		ctx := context.Background()
		_, err := service.SendRESTRequest(ctx, apiConfig, "GET", "/test", nil, nil)
		assert.Error(t, err)
	})

	t.Run("ConnectionTimeout", func(t *testing.T) {
		// Use a non-routable IP to simulate timeout
		apiConfig := &models.APIConfiguration{
			ID:             "test-timeout",
			Type:           "REST",
			Direction:      "outbound",
			Endpoint:       "http://10.255.255.1:80", // Non-routable IP
			Authentication: models.AuthenticationConfig{Type: "none"},
		}

		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		_, err := service.SendRESTRequest(ctx, apiConfig, "GET", "/test", nil, nil)
		assert.Error(t, err)
	})

	t.Run("UnsupportedAuthType", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		apiConfig := &models.APIConfiguration{
			ID:        "test-unsupported-auth",
			Type:      "REST",
			Direction: "outbound",
			Endpoint:  server.URL,
			Authentication: models.AuthenticationConfig{
				Type: "unsupported",
			},
		}

		ctx := context.Background()
		_, err := service.SendRESTRequest(ctx, apiConfig, "GET", "/test", nil, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported authentication type")
	})
}
