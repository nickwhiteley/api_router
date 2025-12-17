package security

import (
	"fmt"
	"strings"
)

// PasswordValidator validates password strength and security
type PasswordValidator struct {
	minLength        int
	requireUppercase bool
	requireLowercase bool
	requireNumbers   bool
	requireSymbols   bool
	commonPasswords  map[string]bool
}

// NewPasswordValidator creates a new password validator
func NewPasswordValidator() *PasswordValidator {
	// Common passwords to reject
	commonPasswords := map[string]bool{
		"password":    true,
		"123456":      true,
		"123456789":   true,
		"qwerty":      true,
		"abc123":      true,
		"password123": true,
		"admin":       true,
		"letmein":     true,
		"welcome":     true,
		"monkey":      true,
		"dragon":      true,
		"master":      true,
		"shadow":      true,
		"superman":    true,
		"michael":     true,
		"football":    true,
		"baseball":    true,
		"trustno1":    true,
	}

	return &PasswordValidator{
		minLength:        8,
		requireUppercase: true,
		requireLowercase: true,
		requireNumbers:   true,
		requireSymbols:   true,
		commonPasswords:  commonPasswords,
	}
}

// ValidatePassword validates password strength and security requirements
func (v *PasswordValidator) ValidatePassword(password string) error {
	if len(password) < v.minLength {
		return fmt.Errorf("password must be at least %d characters long", v.minLength)
	}

	if len(password) > 128 {
		return fmt.Errorf("password must be no more than 128 characters long")
	}

	// Check for common passwords
	if v.isCommonPassword(password) {
		return fmt.Errorf("password is too common, please choose a more secure password")
	}

	// Check character requirements
	var hasUpper, hasLower, hasNumber, hasSymbol bool

	for _, char := range password {
		switch {
		case char >= 'A' && char <= 'Z':
			hasUpper = true
		case char >= 'a' && char <= 'z':
			hasLower = true
		case char >= '0' && char <= '9':
			hasNumber = true
		case isSymbol(char):
			hasSymbol = true
		}
	}

	var errors []string

	if v.requireUppercase && !hasUpper {
		errors = append(errors, "at least one uppercase letter")
	}

	if v.requireLowercase && !hasLower {
		errors = append(errors, "at least one lowercase letter")
	}

	if v.requireNumbers && !hasNumber {
		errors = append(errors, "at least one number")
	}

	if v.requireSymbols && !hasSymbol {
		errors = append(errors, "at least one symbol")
	}

	if len(errors) > 0 {
		return fmt.Errorf("password must contain %s", strings.Join(errors, ", "))
	}

	// Check for patterns that make passwords weak
	if err := v.checkWeakPatterns(password); err != nil {
		return err
	}

	return nil
}

// isCommonPassword checks if the password is in the common passwords list
func (v *PasswordValidator) isCommonPassword(password string) bool {
	// Check exact match (case insensitive)
	if v.commonPasswords[strings.ToLower(password)] {
		return true
	}

	// Check if password is just a common password with numbers appended
	for common := range v.commonPasswords {
		if strings.HasPrefix(strings.ToLower(password), common) {
			suffix := password[len(common):]
			if isAllNumbers(suffix) && len(suffix) <= 4 {
				return true
			}
		}
	}

	return false
}

// checkWeakPatterns checks for weak password patterns
func (v *PasswordValidator) checkWeakPatterns(password string) error {
	// Check for repeated characters (more than 3 in a row)
	if hasRepeatedChars(password, 4) {
		return fmt.Errorf("password cannot contain more than 3 repeated characters in a row")
	}

	// Check for sequential characters (like "1234" or "abcd")
	if hasSequentialChars(password, 4) {
		return fmt.Errorf("password cannot contain sequential characters (like '1234' or 'abcd')")
	}

	// Check for keyboard patterns (like "qwerty" or "asdf")
	keyboardPatterns := []string{
		"qwerty", "asdf", "zxcv", "1234", "4321",
		"qwertyuiop", "asdfghjkl", "zxcvbnm",
	}

	lowerPassword := strings.ToLower(password)
	for _, pattern := range keyboardPatterns {
		if strings.Contains(lowerPassword, pattern) {
			return fmt.Errorf("password cannot contain keyboard patterns")
		}
	}

	return nil
}

// isSymbol checks if a character is a symbol
func isSymbol(char rune) bool {
	symbols := "!@#$%^&*()_+-=[]{}|;:,.<>?"
	return strings.ContainsRune(symbols, char)
}

// isAllNumbers checks if a string contains only numbers
func isAllNumbers(s string) bool {
	for _, char := range s {
		if char < '0' || char > '9' {
			return false
		}
	}
	return len(s) > 0
}

// hasRepeatedChars checks for repeated characters in the password
func hasRepeatedChars(password string, maxRepeats int) bool {
	if len(password) < maxRepeats {
		return false
	}

	for i := 0; i <= len(password)-maxRepeats; i++ {
		char := password[i]
		count := 1

		for j := i + 1; j < len(password) && password[j] == char; j++ {
			count++
			if count >= maxRepeats {
				return true
			}
		}
	}

	return false
}

// hasSequentialChars checks for sequential characters in the password
func hasSequentialChars(password string, minLength int) bool {
	if len(password) < minLength {
		return false
	}

	for i := 0; i <= len(password)-minLength; i++ {
		// Check for ascending sequence
		isAscending := true
		for j := 1; j < minLength; j++ {
			if password[i+j] != password[i+j-1]+1 {
				isAscending = false
				break
			}
		}

		// Check for descending sequence
		isDescending := true
		for j := 1; j < minLength; j++ {
			if password[i+j] != password[i+j-1]-1 {
				isDescending = false
				break
			}
		}

		if isAscending || isDescending {
			return true
		}
	}

	return false
}

// GetPasswordStrengthScore returns a score from 0-100 indicating password strength
func (v *PasswordValidator) GetPasswordStrengthScore(password string) int {
	score := 0

	// Length score (up to 25 points)
	if len(password) >= 8 {
		score += 10
	}
	if len(password) >= 12 {
		score += 10
	}
	if len(password) >= 16 {
		score += 5
	}

	// Character variety (up to 40 points)
	var hasUpper, hasLower, hasNumber, hasSymbol bool
	for _, char := range password {
		switch {
		case char >= 'A' && char <= 'Z':
			hasUpper = true
		case char >= 'a' && char <= 'z':
			hasLower = true
		case char >= '0' && char <= '9':
			hasNumber = true
		case isSymbol(char):
			hasSymbol = true
		}
	}

	if hasUpper {
		score += 10
	}
	if hasLower {
		score += 10
	}
	if hasNumber {
		score += 10
	}
	if hasSymbol {
		score += 10
	}

	// Uniqueness (up to 35 points)
	if !v.isCommonPassword(password) {
		score += 15
	}
	if v.checkWeakPatterns(password) == nil {
		score += 20
	}

	if score > 100 {
		score = 100
	}

	return score
}
