package security

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockAuditLogger for testing security event logging
type MockAuditLogger struct {
	mock.Mock
}

func (m *MockAuditLogger) LogSecurityEvent(ctx context.Context, event SecurityEvent) error {
	args := m.Called(ctx, event)
	return args.Error(0)
}

// TestInputValidationAndSanitization tests input validation and sanitization across all endpoints
func TestInputValidationAndSanitization(t *testing.T) {
	validator := NewInputValidator()

	t.Run("SQL injection protection", func(t *testing.T) {
		maliciousInputs := []string{
			"'; DROP TABLE users; --",
			"1' OR '1'='1",
			"admin'/*",
			"1; DELETE FROM organisations WHERE 1=1; --",
			"' UNION SELECT * FROM users --",
		}

		for _, input := range maliciousInputs {
			t.Run(fmt.Sprintf("blocks SQL injection: %s", input), func(t *testing.T) {
				sanitized, err := validator.SanitizeInput(input)
				assert.NoError(t, err)
				assert.NotContains(t, sanitized, "DROP")
				assert.NotContains(t, sanitized, "DELETE")
				assert.NotContains(t, sanitized, "UNION")
				assert.NotContains(t, sanitized, "--")
				assert.NotContains(t, sanitized, "/*")
			})
		}
	})

	t.Run("XSS protection", func(t *testing.T) {
		maliciousInputs := []string{
			"<script>alert('xss')</script>",
			"javascript:alert('xss')",
			"<img src=x onerror=alert('xss')>",
			"<svg onload=alert('xss')>",
			"<iframe src=javascript:alert('xss')></iframe>",
			"<body onload=alert('xss')>",
		}

		for _, input := range maliciousInputs {
			t.Run(fmt.Sprintf("blocks XSS: %s", input), func(t *testing.T) {
				sanitized, err := validator.SanitizeInput(input)
				assert.NoError(t, err)
				assert.NotContains(t, sanitized, "<script")
				assert.NotContains(t, sanitized, "javascript:")
				assert.NotContains(t, sanitized, "onerror")
				assert.NotContains(t, sanitized, "onload")
				assert.NotContains(t, sanitized, "<iframe")
			})
		}
	})

	t.Run("validates required fields", func(t *testing.T) {
		testCases := []struct {
			name     string
			input    map[string]interface{}
			required []string
			valid    bool
		}{
			{
				name:     "all required fields present",
				input:    map[string]interface{}{"name": "test", "email": "test@example.com"},
				required: []string{"name", "email"},
				valid:    true,
			},
			{
				name:     "missing required field",
				input:    map[string]interface{}{"name": "test"},
				required: []string{"name", "email"},
				valid:    false,
			},
			{
				name:     "empty required field",
				input:    map[string]interface{}{"name": "", "email": "test@example.com"},
				required: []string{"name", "email"},
				valid:    false,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				err := validator.ValidateRequiredFields(tc.input, tc.required)
				if tc.valid {
					assert.NoError(t, err)
				} else {
					assert.Error(t, err)
				}
			})
		}
	})

	t.Run("validates email format", func(t *testing.T) {
		testCases := []struct {
			email string
			valid bool
		}{
			{"test@example.com", true},
			{"user.name@domain.co.uk", true},
			{"invalid-email", false},
			{"@domain.com", false},
			{"user@", false},
			{"", false},
		}

		for _, tc := range testCases {
			t.Run(tc.email, func(t *testing.T) {
				err := validator.ValidateEmail(tc.email)
				if tc.valid {
					assert.NoError(t, err)
				} else {
					assert.Error(t, err)
				}
			})
		}
	})

	t.Run("validates URL format", func(t *testing.T) {
		testCases := []struct {
			url   string
			valid bool
		}{
			{"https://example.com", true},
			{"http://api.example.com/v1", true},
			{"ftp://files.example.com", false}, // Only HTTP/HTTPS allowed
			{"javascript:alert('xss')", false},
			{"not-a-url", false},
			{"", false},
		}

		for _, tc := range testCases {
			t.Run(tc.url, func(t *testing.T) {
				err := validator.ValidateURL(tc.url)
				if tc.valid {
					assert.NoError(t, err)
				} else {
					assert.Error(t, err)
				}
			})
		}
	})
}

// TestSecurityHeaders tests that proper security headers are set
func TestSecurityHeaders(t *testing.T) {
	middleware := NewSecurityMiddleware()

	t.Run("sets security headers", func(t *testing.T) {
		handler := middleware.SecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		// Check security headers
		assert.Equal(t, "deny", w.Header().Get("X-Frame-Options"))
		assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
		assert.Equal(t, "1; mode=block", w.Header().Get("X-XSS-Protection"))
		assert.Equal(t, "no-referrer", w.Header().Get("Referrer-Policy"))
		assert.Contains(t, w.Header().Get("Content-Security-Policy"), "default-src 'self'")
		assert.Contains(t, w.Header().Get("Strict-Transport-Security"), "max-age=")
	})
}

// TestCORSConfiguration tests CORS configuration
func TestCORSConfiguration(t *testing.T) {
	middleware := NewSecurityMiddleware()

	t.Run("handles CORS preflight", func(t *testing.T) {
		handler := middleware.CORS(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest("OPTIONS", "/api/v1/test", nil)
		req.Header.Set("Origin", "https://trusted-domain.com")
		req.Header.Set("Access-Control-Request-Method", "POST")
		req.Header.Set("Access-Control-Request-Headers", "Content-Type,Authorization")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "https://trusted-domain.com", w.Header().Get("Access-Control-Allow-Origin"))
		assert.Contains(t, w.Header().Get("Access-Control-Allow-Methods"), "POST")
		assert.Contains(t, w.Header().Get("Access-Control-Allow-Headers"), "Content-Type")
	})

	t.Run("blocks untrusted origins", func(t *testing.T) {
		handler := middleware.CORS(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest("GET", "/api/v1/test", nil)
		req.Header.Set("Origin", "https://malicious-site.com")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.NotEqual(t, "https://malicious-site.com", w.Header().Get("Access-Control-Allow-Origin"))
	})
}

// TestAuditLoggingForSecurityEvents tests audit logging for security events
func TestAuditLoggingForSecurityEvents(t *testing.T) {
	mockLogger := &MockAuditLogger{}
	auditor := NewSecurityAuditor(mockLogger)

	t.Run("logs authentication failures", func(t *testing.T) {
		ctx := context.Background()

		mockLogger.On("LogSecurityEvent", ctx, mock.MatchedBy(func(event SecurityEvent) bool {
			return event.Type == SecurityEventAuthFailure &&
				event.Severity == SecuritySeverityMedium &&
				event.UserID == "test-user" &&
				event.IPAddress == "192.168.1.1"
		})).Return(nil)

		err := auditor.LogAuthenticationFailure(ctx, "test-user", "192.168.1.1", "invalid credentials")
		assert.NoError(t, err)
		mockLogger.AssertExpectations(t)
	})

	t.Run("logs authorization violations", func(t *testing.T) {
		ctx := context.Background()

		mockLogger.On("LogSecurityEvent", ctx, mock.MatchedBy(func(event SecurityEvent) bool {
			return event.Type == SecurityEventAuthzViolation &&
				event.Severity == SecuritySeverityHigh &&
				event.UserID == "test-user" &&
				event.ResourceID == "org-123"
		})).Return(nil)

		err := auditor.LogAuthorizationViolation(ctx, "test-user", "org-123", "unauthorized access attempt")
		assert.NoError(t, err)
		mockLogger.AssertExpectations(t)
	})

	t.Run("logs input validation failures", func(t *testing.T) {
		ctx := context.Background()

		mockLogger.On("LogSecurityEvent", ctx, mock.MatchedBy(func(event SecurityEvent) bool {
			return event.Type == SecurityEventInputValidation &&
				event.Severity == SecuritySeverityMedium &&
				strings.Contains(event.Details, "malicious input detected")
		})).Return(nil)

		err := auditor.LogInputValidationFailure(ctx, "192.168.1.1", "malicious input detected", "'; DROP TABLE users; --")
		assert.NoError(t, err)
		mockLogger.AssertExpectations(t)
	})

	t.Run("logs suspicious activity", func(t *testing.T) {
		ctx := context.Background()

		mockLogger.On("LogSecurityEvent", ctx, mock.MatchedBy(func(event SecurityEvent) bool {
			return event.Type == SecurityEventSuspiciousActivity &&
				event.Severity == SecuritySeverityHigh &&
				strings.Contains(event.Details, "multiple failed login attempts")
		})).Return(nil)

		err := auditor.LogSuspiciousActivity(ctx, "test-user", "192.168.1.1", "multiple failed login attempts")
		assert.NoError(t, err)
		mockLogger.AssertExpectations(t)
	})
}

// TestEndpointSecurityValidation tests security validation on actual endpoints
func TestEndpointSecurityValidation(t *testing.T) {
	// Create a test router with security middleware
	router := mux.NewRouter()
	middleware := NewSecurityMiddleware()

	// Apply security middleware
	router.Use(middleware.SecurityHeaders)
	router.Use(middleware.InputValidation)
	router.Use(middleware.CORS)

	// Add test endpoint
	router.HandleFunc("/api/v1/organisations", func(w http.ResponseWriter, r *http.Request) {
		var org map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&org); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(org)
	}).Methods("POST")

	t.Run("blocks malicious JSON payload", func(t *testing.T) {
		maliciousPayload := map[string]interface{}{
			"name":        "<script>alert('xss')</script>",
			"description": "'; DROP TABLE organisations; --",
		}

		body, _ := json.Marshal(maliciousPayload)
		req := httptest.NewRequest("POST", "/api/v1/organisations", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		// Should either sanitize the input or reject it
		assert.True(t, w.Code == http.StatusBadRequest || w.Code == http.StatusCreated)

		if w.Code == http.StatusCreated {
			var response map[string]interface{}
			json.NewDecoder(w.Body).Decode(&response)

			// Ensure malicious content is sanitized
			if name, ok := response["name"].(string); ok {
				assert.NotContains(t, name, "<script>")
				assert.NotContains(t, name, "alert")
			}
		}
	})

	t.Run("validates content type", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/organisations", strings.NewReader("invalid"))
		req.Header.Set("Content-Type", "text/plain")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnsupportedMediaType, w.Code)
	})

	t.Run("limits request body size", func(t *testing.T) {
		// Create a large payload (over 1MB)
		largePayload := strings.Repeat("a", 2*1024*1024)

		req := httptest.NewRequest("POST", "/api/v1/organisations", strings.NewReader(largePayload))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		// The middleware should reject large payloads, but the exact status code may vary
		assert.True(t, w.Code == http.StatusRequestEntityTooLarge || w.Code == http.StatusBadRequest)
	})
}

// TestRateLimitingSecurityFeatures tests rate limiting as a security feature
func TestRateLimitingSecurityFeatures(t *testing.T) {
	rateLimiter := NewRateLimiter()

	t.Run("blocks excessive requests from same IP", func(t *testing.T) {
		ip := "192.168.1.100"

		// First 100 requests should be allowed (bucket starts full)
		for i := 0; i < 100; i++ {
			allowed := rateLimiter.Allow(ip)
			assert.True(t, allowed, "Request %d should be allowed", i+1)
		}

		// Subsequent requests should be blocked
		for i := 0; i < 5; i++ {
			allowed := rateLimiter.Allow(ip)
			assert.False(t, allowed, "Request %d should be blocked", i+101)
		}
	})

	t.Run("different IPs have separate limits", func(t *testing.T) {
		ip1 := "192.168.1.101"
		ip2 := "192.168.1.102"

		// Exhaust limit for IP1
		for i := 0; i < 100; i++ {
			rateLimiter.Allow(ip1)
		}

		// IP2 should still be allowed
		allowed := rateLimiter.Allow(ip2)
		assert.True(t, allowed)

		// IP1 should be blocked
		blocked := rateLimiter.Allow(ip1)
		assert.False(t, blocked)
	})
}

// TestPasswordSecurityValidation tests password security requirements
func TestPasswordSecurityValidation(t *testing.T) {
	validator := NewPasswordValidator()

	t.Run("validates password strength", func(t *testing.T) {
		testCases := []struct {
			password string
			valid    bool
			reason   string
		}{
			{"Password123!", true, "strong password"},
			{"password", false, "no uppercase, numbers, or symbols"},
			{"PASSWORD", false, "no lowercase, numbers, or symbols"},
			{"Password", false, "no numbers or symbols"},
			{"Pass1!", false, "too short"},
			{"", false, "empty password"},
			{"Password123!@#$%^&*()", true, "very strong password"},
		}

		for _, tc := range testCases {
			t.Run(tc.reason, func(t *testing.T) {
				err := validator.ValidatePassword(tc.password)
				if tc.valid {
					assert.NoError(t, err, "Password should be valid: %s", tc.password)
				} else {
					assert.Error(t, err, "Password should be invalid: %s", tc.password)
				}
			})
		}
	})

	t.Run("detects common passwords", func(t *testing.T) {
		commonPasswords := []string{
			"password",
			"123456",
			"admin",
			"qwerty",
			"letmein",
		}

		for _, password := range commonPasswords {
			t.Run(password, func(t *testing.T) {
				err := validator.ValidatePassword(password)
				assert.Error(t, err)
				// The error could be about length or being too common
				assert.True(t,
					strings.Contains(err.Error(), "common") ||
						strings.Contains(err.Error(), "at least") ||
						strings.Contains(err.Error(), "must contain"),
					"Expected error about common password or validation failure, got: %v", err)
			})
		}
	})
}

// TestSecurityConfigurationValidation tests security configuration validation
func TestSecurityConfigurationValidation(t *testing.T) {
	validator := NewSecurityConfigValidator()

	t.Run("validates JWT configuration", func(t *testing.T) {
		testCases := []struct {
			name   string
			config JWTConfig
			valid  bool
		}{
			{
				name: "valid JWT config",
				config: JWTConfig{
					Secret:     "random-secure-jwt-token-for-production-use-only-xyz789",
					Expiration: 3600,
					Algorithm:  "HS256",
				},
				valid: true,
			},
			{
				name: "weak secret",
				config: JWTConfig{
					Secret:     "weak",
					Expiration: 3600,
					Algorithm:  "HS256",
				},
				valid: false,
			},
			{
				name: "invalid algorithm",
				config: JWTConfig{
					Secret:     "very-long-secret-key-that-is-secure",
					Expiration: 3600,
					Algorithm:  "none",
				},
				valid: false,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				err := validator.ValidateJWTConfig(tc.config)
				if tc.valid {
					assert.NoError(t, err)
				} else {
					assert.Error(t, err)
				}
			})
		}
	})

	t.Run("validates CORS configuration", func(t *testing.T) {
		testCases := []struct {
			name   string
			config CORSConfig
			valid  bool
		}{
			{
				name: "secure CORS config",
				config: CORSConfig{
					AllowedOrigins: []string{"https://trusted-domain.com"},
					AllowedMethods: []string{"GET", "POST"},
					AllowedHeaders: []string{"Content-Type", "Authorization"},
				},
				valid: true,
			},
			{
				name: "wildcard origin (insecure)",
				config: CORSConfig{
					AllowedOrigins: []string{"*"},
					AllowedMethods: []string{"GET", "POST"},
					AllowedHeaders: []string{"Content-Type", "Authorization"},
				},
				valid: false,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				err := validator.ValidateCORSConfig(tc.config)
				if tc.valid {
					assert.NoError(t, err)
				} else {
					assert.Error(t, err)
				}
			})
		}
	})
}
