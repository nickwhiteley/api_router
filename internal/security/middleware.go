package security

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// SecurityMiddleware provides security-related middleware
type SecurityMiddleware struct {
	validator    *InputValidator
	rateLimiter  *RateLimiter
	corsConfig   CORSConfig
	trustedHosts []string
}

// CORSConfig holds CORS configuration
type CORSConfig struct {
	AllowedOrigins []string
	AllowedMethods []string
	AllowedHeaders []string
	MaxAge         int
}

// NewSecurityMiddleware creates a new security middleware
func NewSecurityMiddleware() *SecurityMiddleware {
	return &SecurityMiddleware{
		validator:   NewInputValidator(),
		rateLimiter: NewRateLimiter(),
		corsConfig: CORSConfig{
			AllowedOrigins: []string{
				"https://trusted-domain.com",
				"https://app.api-translation-platform.com",
			},
			AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
			AllowedHeaders: []string{"Content-Type", "Authorization", "X-API-Key"},
			MaxAge:         86400, // 24 hours
		},
		trustedHosts: []string{
			"api-translation-platform.com",
			"app.api-translation-platform.com",
		},
	}
}

// SecurityHeaders adds security headers to responses
func (m *SecurityMiddleware) SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// X-Frame-Options: Prevent clickjacking
		w.Header().Set("X-Frame-Options", "deny")

		// X-Content-Type-Options: Prevent MIME type sniffing
		w.Header().Set("X-Content-Type-Options", "nosniff")

		// X-XSS-Protection: Enable XSS filtering
		w.Header().Set("X-XSS-Protection", "1; mode=block")

		// Referrer-Policy: Control referrer information
		w.Header().Set("Referrer-Policy", "no-referrer")

		// Content-Security-Policy: Apply different policies based on path
		csp := m.getCSPForPath(r.URL.Path)
		w.Header().Set("Content-Security-Policy", csp)

		// Strict-Transport-Security: Enforce HTTPS
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")

		// Remove server information
		w.Header().Set("Server", "")

		next.ServeHTTP(w, r)
	})
}

// getCSPForPath returns the appropriate CSP policy based on the request path
func (m *SecurityMiddleware) getCSPForPath(path string) string {
	// Relaxed CSP for Swagger UI documentation
	if strings.HasPrefix(path, "/api/v1/docs/swagger") || strings.HasPrefix(path, "/api/v2/docs/swagger") {
		return "default-src 'self'; " +
			"script-src 'self' 'unsafe-inline' 'unsafe-eval' https://unpkg.com; " +
			"style-src 'self' 'unsafe-inline' https://unpkg.com; " +
			"img-src 'self' data: https:; " +
			"font-src 'self' https://unpkg.com; " +
			"connect-src 'self'; " +
			"frame-ancestors 'none'"
	}

	// Relaxed CSP for management interface (allows inline styles for better UX)
	if strings.HasPrefix(path, "/manage/") || strings.HasPrefix(path, "/login") {
		return "default-src 'self'; " +
			"script-src 'self' 'unsafe-inline'; " +
			"style-src 'self' 'unsafe-inline'; " +
			"img-src 'self' data: https:; " +
			"font-src 'self'; " +
			"connect-src 'self'; " +
			"frame-ancestors 'none'"
	}

	// Strict CSP for API endpoints
	if strings.HasPrefix(path, "/api/") {
		return "default-src 'self'; " +
			"script-src 'self'; " +
			"style-src 'self'; " +
			"img-src 'self'; " +
			"font-src 'self'; " +
			"connect-src 'self'; " +
			"frame-ancestors 'none'"
	}

	// Default CSP for other endpoints
	return "default-src 'self'; " +
		"script-src 'self' 'unsafe-inline'; " +
		"style-src 'self' 'unsafe-inline'; " +
		"img-src 'self' data: https:; " +
		"font-src 'self'; " +
		"connect-src 'self'; " +
		"frame-ancestors 'none'"
}

// CORS handles Cross-Origin Resource Sharing
func (m *SecurityMiddleware) CORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")

		// Check if origin is allowed
		if m.isOriginAllowed(origin) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}

		// Handle preflight requests
		if r.Method == "OPTIONS" {
			w.Header().Set("Access-Control-Allow-Methods", strings.Join(m.corsConfig.AllowedMethods, ", "))
			w.Header().Set("Access-Control-Allow-Headers", strings.Join(m.corsConfig.AllowedHeaders, ", "))
			w.Header().Set("Access-Control-Max-Age", fmt.Sprintf("%d", m.corsConfig.MaxAge))
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// InputValidation validates and sanitizes input
func (m *SecurityMiddleware) InputValidation(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Limit request body size (1MB)
		r.Body = http.MaxBytesReader(w, r.Body, 1024*1024)

		// Validate content type for POST/PUT requests
		if r.Method == "POST" || r.Method == "PUT" {
			contentType := r.Header.Get("Content-Type")
			if !strings.HasPrefix(contentType, "application/json") &&
				!strings.HasPrefix(contentType, "application/x-www-form-urlencoded") &&
				!strings.HasPrefix(contentType, "multipart/form-data") {
				http.Error(w, "Unsupported Media Type", http.StatusUnsupportedMediaType)
				return
			}

			// For JSON requests, validate and sanitize the body
			if strings.HasPrefix(contentType, "application/json") {
				if err := m.validateJSONBody(r); err != nil {
					http.Error(w, fmt.Sprintf("Invalid input: %v", err), http.StatusBadRequest)
					return
				}
			}
		}

		// Validate query parameters
		for _, values := range r.URL.Query() {
			for _, value := range values {
				if m.validator.ContainsSQLInjection(value) || m.validator.ContainsXSS(value) {
					http.Error(w, "Malicious input detected in query parameters", http.StatusBadRequest)
					return
				}
			}
		}

		next.ServeHTTP(w, r)
	})
}

// RateLimit applies rate limiting
func (m *SecurityMiddleware) RateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientIP := m.getClientIP(r)

		if !m.rateLimiter.Allow(clientIP) {
			w.Header().Set("Retry-After", "60")
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// HostValidation validates the Host header
func (m *SecurityMiddleware) HostValidation(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host

		// Remove port if present
		if colonIndex := strings.Index(host, ":"); colonIndex != -1 {
			host = host[:colonIndex]
		}

		// Check if host is trusted
		if !m.isHostTrusted(host) {
			http.Error(w, "Invalid host", http.StatusBadRequest)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// validateJSONBody validates and sanitizes JSON request body
func (m *SecurityMiddleware) validateJSONBody(r *http.Request) error {
	var body map[string]interface{}

	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&body); err != nil {
		return fmt.Errorf("invalid JSON: %v", err)
	}

	// Validate and sanitize the JSON content
	sanitized, err := m.validator.ValidateJSONInput(body)
	if err != nil {
		return err
	}

	// Store sanitized body in context for handlers to use
	ctx := context.WithValue(r.Context(), "sanitized_body", sanitized)
	*r = *r.WithContext(ctx)

	return nil
}

// isOriginAllowed checks if the origin is in the allowed list
func (m *SecurityMiddleware) isOriginAllowed(origin string) bool {
	if origin == "" {
		return false
	}

	for _, allowed := range m.corsConfig.AllowedOrigins {
		if allowed == "*" || allowed == origin {
			return true
		}
	}

	return false
}

// isHostTrusted checks if the host is trusted
func (m *SecurityMiddleware) isHostTrusted(host string) bool {
	// Allow localhost for development
	if host == "localhost" || host == "127.0.0.1" {
		return true
	}

	for _, trusted := range m.trustedHosts {
		if trusted == host {
			return true
		}
	}

	return false
}

// getClientIP extracts the client IP address
func (m *SecurityMiddleware) getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header (from load balancers/proxies)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP in the chain
		if commaIndex := strings.Index(xff, ","); commaIndex != -1 {
			return strings.TrimSpace(xff[:commaIndex])
		}
		return strings.TrimSpace(xff)
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}

	// Fall back to RemoteAddr
	if colonIndex := strings.LastIndex(r.RemoteAddr, ":"); colonIndex != -1 {
		return r.RemoteAddr[:colonIndex]
	}

	return r.RemoteAddr
}

// GetSanitizedBody retrieves the sanitized body from request context
func GetSanitizedBody(r *http.Request) (map[string]interface{}, bool) {
	if body, ok := r.Context().Value("sanitized_body").(map[string]interface{}); ok {
		return body, true
	}
	return nil, false
}
