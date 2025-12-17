package services

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"api-translation-platform/internal/logger"
	"api-translation-platform/internal/models"
	"api-translation-platform/internal/repositories"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserNotFound       = errors.New("user not found")
	ErrInvalidToken       = errors.New("invalid token")
	ErrTokenExpired       = errors.New("token expired")
	ErrUnauthorized       = errors.New("unauthorized access")
)

// JWTClaims represents the JWT token claims
type JWTClaims struct {
	UserID         string `json:"user_id"`
	OrganisationID string `json:"organisation_id"`
	Role           string `json:"role"`
	jwt.RegisteredClaims
}

// authenticationService implements AuthenticationService
type authenticationService struct {
	logger    *logger.Logger
	userRepo  repositories.UserRepository
	jwtSecret []byte
}

// NewAuthenticationService creates a new authentication service
func NewAuthenticationService(
	logger *logger.Logger,
	userRepo repositories.UserRepository,
) AuthenticationService {
	// In production, this should come from configuration
	jwtSecret := []byte("your-secret-key-change-this-in-production")

	return &authenticationService{
		logger:    logger,
		userRepo:  userRepo,
		jwtSecret: jwtSecret,
	}
}

// ValidateAPIKey validates an API key for authentication
func (s *authenticationService) ValidateAPIKey(ctx context.Context, apiKey string, apiConfig *models.APIConfiguration) (*models.User, error) {
	s.logger.WithField("organisation_id", apiConfig.OrganisationID).
		Info("Validating API key")

	if apiKey == "" {
		return nil, ErrInvalidCredentials
	}

	// Get the expected API key from configuration
	expectedKey, exists := apiConfig.Authentication.Parameters["key"]
	if !exists {
		s.logger.WithField("organisation_id", apiConfig.OrganisationID).
			Error("API key not configured")
		return nil, ErrInvalidCredentials
	}

	// Use constant-time comparison to prevent timing attacks
	if subtle.ConstantTimeCompare([]byte(apiKey), []byte(expectedKey)) != 1 {
		s.logger.WithField("organisation_id", apiConfig.OrganisationID).
			Warn("Invalid API key provided")
		return nil, ErrInvalidCredentials
	}

	// For API key authentication, we need to find a user associated with this organisation
	// In a real implementation, you might have API keys linked to specific users
	users, err := s.userRepo.GetByOrganisation(ctx, apiConfig.OrganisationID)
	if err != nil {
		s.logger.WithField("organisation_id", apiConfig.OrganisationID).
			WithError(err).Error("Failed to get users for organisation")
		return nil, err
	}

	if len(users) == 0 {
		return nil, ErrUserNotFound
	}

	// Return the first active user (in practice, you might want more sophisticated logic)
	for _, user := range users {
		if user.IsActive {
			return user, nil
		}
	}

	return nil, ErrUserNotFound
}

// ValidateOAuth validates an OAuth token for authentication
func (s *authenticationService) ValidateOAuth(ctx context.Context, token string, apiConfig *models.APIConfiguration) (*models.User, error) {
	s.logger.WithField("organisation_id", apiConfig.OrganisationID).
		Info("Validating OAuth token")

	if token == "" {
		return nil, ErrInvalidCredentials
	}

	// In a real implementation, you would validate the OAuth token with the OAuth provider
	// For now, we'll implement a simple token validation
	clientID, exists := apiConfig.Authentication.Parameters["client_id"]
	if !exists {
		return nil, ErrInvalidCredentials
	}

	// Simple validation - in practice, you'd call the OAuth provider's introspection endpoint
	if !strings.HasPrefix(token, clientID) {
		return nil, ErrInvalidCredentials
	}

	// Find a user for this organisation
	users, err := s.userRepo.GetByOrganisation(ctx, apiConfig.OrganisationID)
	if err != nil {
		return nil, err
	}

	if len(users) == 0 {
		return nil, ErrUserNotFound
	}

	for _, user := range users {
		if user.IsActive {
			return user, nil
		}
	}

	return nil, ErrUserNotFound
}

// ValidateBasicAuth validates basic authentication credentials
func (s *authenticationService) ValidateBasicAuth(ctx context.Context, username, password string, apiConfig *models.APIConfiguration) (*models.User, error) {
	s.logger.WithField("organisation_id", apiConfig.OrganisationID).
		WithField("username", username).
		Info("Validating basic auth")

	if username == "" || password == "" {
		return nil, ErrInvalidCredentials
	}

	// Find user by username and organisation
	user, err := s.userRepo.GetByUsernameAndOrganisation(ctx, username, apiConfig.OrganisationID)
	if err != nil {
		s.logger.WithField("username", username).
			WithField("organisation_id", apiConfig.OrganisationID).
			WithError(err).Warn("User not found for basic auth")
		return nil, ErrInvalidCredentials
	}

	if !user.IsActive {
		return nil, ErrInvalidCredentials
	}

	// Verify password
	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
	if err != nil {
		s.logger.WithField("username", username).
			Warn("Invalid password for basic auth")
		return nil, ErrInvalidCredentials
	}

	return user, nil
}

// GenerateJWT generates a JWT token for a user
func (s *authenticationService) GenerateJWT(ctx context.Context, user *models.User) (string, error) {
	s.logger.WithField("user_id", user.ID).
		WithField("organisation_id", user.OrganisationID).
		Info("Generating JWT token")

	// Create claims
	claims := JWTClaims{
		UserID:         user.ID,
		OrganisationID: user.OrganisationID,
		Role:           user.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "api-translation-platform",
			Subject:   user.ID,
		},
	}

	// Create token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(s.jwtSecret)
	if err != nil {
		s.logger.WithField("user_id", user.ID).
			WithError(err).Error("Failed to sign JWT token")
		return "", err
	}

	return tokenString, nil
}

// ValidateJWT validates a JWT token and returns the user
func (s *authenticationService) ValidateJWT(ctx context.Context, tokenString string) (*models.User, error) {
	s.logger.Info("Validating JWT token")

	if tokenString == "" {
		return nil, ErrInvalidToken
	}

	// Parse token
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.jwtSecret, nil
	})

	if err != nil {
		s.logger.WithError(err).Warn("Failed to parse JWT token")
		return nil, ErrInvalidToken
	}

	// Extract claims
	claims, ok := token.Claims.(*JWTClaims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}

	// Check if token is expired
	if claims.ExpiresAt != nil && claims.ExpiresAt.Before(time.Now()) {
		return nil, ErrTokenExpired
	}

	// Get user from database to ensure they still exist and are active
	user, err := s.userRepo.GetByID(ctx, claims.UserID)
	if err != nil {
		s.logger.WithField("user_id", claims.UserID).
			WithError(err).Warn("User not found for JWT token")
		return nil, ErrUserNotFound
	}

	if !user.IsActive {
		return nil, ErrUnauthorized
	}

	return user, nil
}

// HashPassword hashes a password using bcrypt
func (s *authenticationService) HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// ParseBasicAuth parses basic authentication header
func ParseBasicAuth(auth string) (username, password string, ok bool) {
	const prefix = "Basic "
	if len(auth) < len(prefix) || !strings.EqualFold(auth[:len(prefix)], prefix) {
		return "", "", false
	}

	c, err := base64.StdEncoding.DecodeString(auth[len(prefix):])
	if err != nil {
		return "", "", false
	}

	cs := string(c)
	username, password, ok = strings.Cut(cs, ":")
	if !ok {
		return "", "", false
	}

	return username, password, true
}
