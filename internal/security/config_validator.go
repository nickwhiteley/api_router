package security

import (
	"fmt"
	"strings"
)

// JWTConfig holds JWT configuration
type JWTConfig struct {
	Secret     string `json:"secret"`
	Expiration int    `json:"expiration"` // in seconds
	Algorithm  string `json:"algorithm"`
}

// SecurityConfigValidator validates security configurations
type SecurityConfigValidator struct {
	allowedJWTAlgorithms []string
}

// NewSecurityConfigValidator creates a new security config validator
func NewSecurityConfigValidator() *SecurityConfigValidator {
	return &SecurityConfigValidator{
		allowedJWTAlgorithms: []string{"HS256", "HS384", "HS512", "RS256", "RS384", "RS512"},
	}
}

// ValidateJWTConfig validates JWT configuration for security
func (v *SecurityConfigValidator) ValidateJWTConfig(config JWTConfig) error {
	// Validate secret strength
	if len(config.Secret) < 32 {
		return fmt.Errorf("JWT secret must be at least 32 characters long")
	}

	// Check for weak secrets
	weakSecrets := []string{
		"secret",
		"your-secret-key",
		"change-this",
		"default",
		"password",
		"123456",
		"testing",
		"key",
	}

	lowerSecret := strings.ToLower(config.Secret)
	for _, weak := range weakSecrets {
		if strings.Contains(lowerSecret, weak) {
			return fmt.Errorf("JWT secret appears to contain weak or default values")
		}
	}

	// Validate algorithm
	if !v.isAlgorithmAllowed(config.Algorithm) {
		return fmt.Errorf("JWT algorithm '%s' is not allowed. Allowed algorithms: %s",
			config.Algorithm, strings.Join(v.allowedJWTAlgorithms, ", "))
	}

	// Validate expiration
	if config.Expiration <= 0 {
		return fmt.Errorf("JWT expiration must be greater than 0")
	}

	if config.Expiration > 86400*7 { // 7 days
		return fmt.Errorf("JWT expiration should not exceed 7 days for security reasons")
	}

	return nil
}

// ValidateCORSConfig validates CORS configuration for security
func (v *SecurityConfigValidator) ValidateCORSConfig(config CORSConfig) error {
	// Check for wildcard origins (security risk)
	for _, origin := range config.AllowedOrigins {
		if origin == "*" {
			return fmt.Errorf("wildcard origin '*' is not allowed for security reasons")
		}

		// Validate origin format
		if !strings.HasPrefix(origin, "http://") && !strings.HasPrefix(origin, "https://") {
			return fmt.Errorf("origin '%s' must include protocol (http:// or https://)", origin)
		}

		// Warn about HTTP origins (should use HTTPS in production)
		if strings.HasPrefix(origin, "http://") && !strings.Contains(origin, "localhost") {
			return fmt.Errorf("HTTP origins are not recommended for production. Use HTTPS instead: %s", origin)
		}
	}

	// Validate methods
	allowedMethods := map[string]bool{
		"GET": true, "POST": true, "PUT": true, "DELETE": true,
		"PATCH": true, "HEAD": true, "OPTIONS": true,
	}

	for _, method := range config.AllowedMethods {
		if !allowedMethods[strings.ToUpper(method)] {
			return fmt.Errorf("HTTP method '%s' is not allowed", method)
		}
	}

	// Validate headers
	for _, header := range config.AllowedHeaders {
		// Check for potentially dangerous headers
		dangerousHeaders := []string{
			"X-Forwarded-Host",
			"X-Forwarded-Server",
			"X-Rewrite-URL",
		}

		for _, dangerous := range dangerousHeaders {
			if strings.EqualFold(header, dangerous) {
				return fmt.Errorf("header '%s' is potentially dangerous and not allowed", header)
			}
		}
	}

	return nil
}

// ValidateRateLimitConfig validates rate limiting configuration
func (v *SecurityConfigValidator) ValidateRateLimitConfig(maxRequests int, windowSeconds int) error {
	if maxRequests <= 0 {
		return fmt.Errorf("max requests must be greater than 0")
	}

	if maxRequests > 10000 {
		return fmt.Errorf("max requests should not exceed 10000 for performance reasons")
	}

	if windowSeconds <= 0 {
		return fmt.Errorf("window seconds must be greater than 0")
	}

	if windowSeconds > 3600 { // 1 hour
		return fmt.Errorf("window should not exceed 1 hour")
	}

	// Calculate requests per second
	rps := float64(maxRequests) / float64(windowSeconds)
	if rps > 100 {
		return fmt.Errorf("rate limit allows %.2f requests per second, which may be too high", rps)
	}

	return nil
}

// ValidateSecurityHeaders validates security headers configuration
func (v *SecurityConfigValidator) ValidateSecurityHeaders(headers map[string]string) error {
	requiredHeaders := []string{
		"X-Frame-Options",
		"X-Content-Type-Options",
		"X-XSS-Protection",
		"Referrer-Policy",
		"Content-Security-Policy",
	}

	for _, required := range requiredHeaders {
		if _, exists := headers[required]; !exists {
			return fmt.Errorf("required security header '%s' is missing", required)
		}
	}

	// Validate specific header values
	if frameOptions, exists := headers["X-Frame-Options"]; exists {
		validFrameOptions := []string{"deny", "sameorigin"}
		if !contains(validFrameOptions, strings.ToLower(frameOptions)) {
			return fmt.Errorf("X-Frame-Options must be 'deny' or 'sameorigin'")
		}
	}

	if contentType, exists := headers["X-Content-Type-Options"]; exists {
		if strings.ToLower(contentType) != "nosniff" {
			return fmt.Errorf("X-Content-Type-Options must be 'nosniff'")
		}
	}

	if xss, exists := headers["X-XSS-Protection"]; exists {
		validXSSValues := []string{"1; mode=block", "0"}
		if !contains(validXSSValues, xss) {
			return fmt.Errorf("X-XSS-Protection must be '1; mode=block' or '0'")
		}
	}

	return nil
}

// ValidateEncryptionConfig validates encryption configuration
func (v *SecurityConfigValidator) ValidateEncryptionConfig(algorithm string, keySize int) error {
	allowedAlgorithms := map[string][]int{
		"AES": {128, 192, 256},
		"RSA": {2048, 3072, 4096},
	}

	allowedKeySizes, exists := allowedAlgorithms[strings.ToUpper(algorithm)]
	if !exists {
		return fmt.Errorf("encryption algorithm '%s' is not allowed", algorithm)
	}

	if !containsInt(allowedKeySizes, keySize) {
		return fmt.Errorf("key size %d is not allowed for algorithm %s. Allowed sizes: %v",
			keySize, algorithm, allowedKeySizes)
	}

	// Warn about weak key sizes
	if algorithm == "RSA" && keySize < 2048 {
		return fmt.Errorf("RSA key size %d is too weak. Minimum recommended size is 2048 bits", keySize)
	}

	if algorithm == "AES" && keySize < 128 {
		return fmt.Errorf("AES key size %d is too weak. Minimum recommended size is 128 bits", keySize)
	}

	return nil
}

// isAlgorithmAllowed checks if JWT algorithm is allowed
func (v *SecurityConfigValidator) isAlgorithmAllowed(algorithm string) bool {
	for _, allowed := range v.allowedJWTAlgorithms {
		if allowed == algorithm {
			return true
		}
	}
	return false
}

// contains checks if a slice contains a string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// containsInt checks if a slice contains an int
func containsInt(slice []int, item int) bool {
	for _, i := range slice {
		if i == item {
			return true
		}
	}
	return false
}
