package security

import (
	"fmt"
	"html"
	"net/url"
	"regexp"
	"strings"
)

// InputValidator provides input validation and sanitization
type InputValidator struct {
	sqlInjectionPatterns []string
	xssPatterns          []string
	emailRegex           *regexp.Regexp
	urlRegex             *regexp.Regexp
}

// NewInputValidator creates a new input validator
func NewInputValidator() *InputValidator {
	return &InputValidator{
		sqlInjectionPatterns: []string{
			`(?i)(union|select|insert|update|delete|drop|create|alter|exec|execute)`,
			`(?i)(--|#|/\*|\*/|;)`,
			`(?i)(\bor\b|\band\b)\s+\w+\s*=\s*\w+`,
			`(?i)'.*'`,
			`(?i)".*"`,
		},
		xssPatterns: []string{
			`(?i)<script[^>]*>.*?</script>`,
			`(?i)<iframe[^>]*>.*?</iframe>`,
			`(?i)javascript:`,
			`(?i)on\w+\s*=`,
			`(?i)<[^>]*\s+on\w+[^>]*>`,
		},
		emailRegex: regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`),
		urlRegex:   regexp.MustCompile(`^https?://[a-zA-Z0-9.-]+(?:\.[a-zA-Z]{2,})?(?:/.*)?$`),
	}
}

// SanitizeInput sanitizes input by removing or escaping malicious content
func (v *InputValidator) SanitizeInput(input string) (string, error) {
	if input == "" {
		return input, nil
	}

	// HTML escape to prevent XSS
	sanitized := html.EscapeString(input)

	// Remove SQL injection patterns
	for _, pattern := range v.sqlInjectionPatterns {
		re := regexp.MustCompile(pattern)
		sanitized = re.ReplaceAllString(sanitized, "")
	}

	// Remove XSS patterns
	for _, pattern := range v.xssPatterns {
		re := regexp.MustCompile(pattern)
		sanitized = re.ReplaceAllString(sanitized, "")
	}

	// Remove null bytes and control characters
	sanitized = strings.ReplaceAll(sanitized, "\x00", "")
	sanitized = regexp.MustCompile(`[\x00-\x1f\x7f]`).ReplaceAllString(sanitized, "")

	return strings.TrimSpace(sanitized), nil
}

// ValidatePythonScript performs basic validation on Python scripts without sanitization
func (v *InputValidator) ValidatePythonScript(script string) error {
	if script == "" {
		return nil // Empty script is allowed
	}

	// Check for obviously malicious patterns while preserving Python syntax
	maliciousPatterns := []string{
		`(?i)import\s+os.*system`, // os.system calls
		`(?i)import\s+subprocess`, // subprocess imports
		`(?i)exec\s*\(`,           // exec() calls
		`(?i)eval\s*\(`,           // eval() calls
		`(?i)__import__`,          // dynamic imports
		`(?i)open\s*\(.*['"]\s*/`, // file system access
	}

	for _, pattern := range maliciousPatterns {
		if matched, _ := regexp.MatchString(pattern, script); matched {
			return fmt.Errorf("potentially unsafe Python code detected")
		}
	}

	// Basic length check
	if len(script) > 50000 { // 50KB limit
		return fmt.Errorf("Python script too large (max 50KB)")
	}

	return nil
}

// ValidateRequiredFields validates that all required fields are present and non-empty
func (v *InputValidator) ValidateRequiredFields(input map[string]interface{}, required []string) error {
	for _, field := range required {
		value, exists := input[field]
		if !exists {
			return fmt.Errorf("required field '%s' is missing", field)
		}

		// Check if the value is empty
		if str, ok := value.(string); ok && strings.TrimSpace(str) == "" {
			return fmt.Errorf("required field '%s' cannot be empty", field)
		}
	}
	return nil
}

// ValidateEmail validates email format
func (v *InputValidator) ValidateEmail(email string) error {
	if email == "" {
		return fmt.Errorf("email cannot be empty")
	}

	if !v.emailRegex.MatchString(email) {
		return fmt.Errorf("invalid email format")
	}

	return nil
}

// ValidateURL validates URL format and ensures it's HTTP/HTTPS only
func (v *InputValidator) ValidateURL(urlStr string) error {
	if urlStr == "" {
		return fmt.Errorf("URL cannot be empty")
	}

	// Parse URL to validate format
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return fmt.Errorf("invalid URL format: %v", err)
	}

	// Only allow HTTP and HTTPS schemes
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return fmt.Errorf("only HTTP and HTTPS URLs are allowed")
	}

	// Additional validation using regex
	if !v.urlRegex.MatchString(urlStr) {
		return fmt.Errorf("invalid URL format")
	}

	return nil
}

// ContainsSQLInjection checks if input contains SQL injection patterns
func (v *InputValidator) ContainsSQLInjection(input string) bool {
	for _, pattern := range v.sqlInjectionPatterns {
		re := regexp.MustCompile(pattern)
		if re.MatchString(input) {
			return true
		}
	}
	return false
}

// ContainsXSS checks if input contains XSS patterns
func (v *InputValidator) ContainsXSS(input string) bool {
	for _, pattern := range v.xssPatterns {
		re := regexp.MustCompile(pattern)
		if re.MatchString(input) {
			return true
		}
	}
	return false
}

// ValidateJSONInput validates and sanitizes JSON input
func (v *InputValidator) ValidateJSONInput(input map[string]interface{}) (map[string]interface{}, error) {
	sanitized := make(map[string]interface{})

	for key, value := range input {
		// Sanitize the key
		sanitizedKey, err := v.SanitizeInput(key)
		if err != nil {
			return nil, fmt.Errorf("failed to sanitize key '%s': %v", key, err)
		}

		// Sanitize the value if it's a string
		if str, ok := value.(string); ok {
			// Skip sanitization for Python scripts to preserve formatting
			if key == "python_script" {
				// For Python scripts, only do basic validation without sanitization
				if err := v.ValidatePythonScript(str); err != nil {
					return nil, fmt.Errorf("invalid Python script: %v", err)
				}
				sanitized[sanitizedKey] = str // Keep original formatting
			} else {
				sanitizedValue, err := v.SanitizeInput(str)
				if err != nil {
					return nil, fmt.Errorf("failed to sanitize value for key '%s': %v", key, err)
				}
				sanitized[sanitizedKey] = sanitizedValue
			}
		} else {
			sanitized[sanitizedKey] = value
		}
	}

	return sanitized, nil
}
