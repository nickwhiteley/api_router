package middleware

import (
	"context"
	"net/http"
	"strings"

	"api-translation-platform/internal/logger"
	"api-translation-platform/internal/models"
	"api-translation-platform/internal/services"
)

// ContextKey is a type for context keys to avoid collisions
type ContextKey string

const (
	// UserContextKey is the context key for the authenticated user
	UserContextKey ContextKey = "user"
	// APIConfigContextKey is the context key for the API configuration
	APIConfigContextKey ContextKey = "api_config"
)

// AuthenticationMiddleware provides authentication middleware
type AuthenticationMiddleware struct {
	logger    *logger.Logger
	authSvc   services.AuthenticationService
	authzSvc  services.AuthorizationService
	configSvc services.ConfigurationService
}

// NewAuthenticationMiddleware creates a new authentication middleware
func NewAuthenticationMiddleware(
	logger *logger.Logger,
	authSvc services.AuthenticationService,
	authzSvc services.AuthorizationService,
	configSvc services.ConfigurationService,
) *AuthenticationMiddleware {
	return &AuthenticationMiddleware{
		logger:    logger,
		authSvc:   authSvc,
		authzSvc:  authzSvc,
		configSvc: configSvc,
	}
}

// RequireAuthentication middleware that requires authentication for API endpoints
func (m *AuthenticationMiddleware) RequireAuthentication(apiConfigID string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			// Get API configuration
			apiConfig, err := m.configSvc.GetAPIConfiguration(ctx, apiConfigID)
			if err != nil {
				m.logger.WithError(err).Error("Failed to get API configuration")
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}

			// Add API config to context
			ctx = context.WithValue(ctx, APIConfigContextKey, apiConfig)

			// Skip authentication if not required
			if apiConfig.Authentication.Type == "none" {
				r = r.WithContext(ctx)
				next.ServeHTTP(w, r)
				return
			}

			// Authenticate based on the configured method
			user, err := m.authenticateRequest(ctx, r, apiConfig)
			if err != nil {
				m.logger.WithError(err).Warn("Authentication failed")
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			// Add user to context
			ctx = context.WithValue(ctx, UserContextKey, user)
			r = r.WithContext(ctx)

			next.ServeHTTP(w, r)
		})
	}
}

// RequireJWT middleware that requires JWT authentication
func (m *AuthenticationMiddleware) RequireJWT() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			// Extract JWT token from Authorization header
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, "Authorization header required", http.StatusUnauthorized)
				return
			}

			// Check for Bearer token
			const bearerPrefix = "Bearer "
			if !strings.HasPrefix(authHeader, bearerPrefix) {
				http.Error(w, "Bearer token required", http.StatusUnauthorized)
				return
			}

			token := authHeader[len(bearerPrefix):]
			user, err := m.authSvc.ValidateJWT(ctx, token)
			if err != nil {
				m.logger.WithError(err).Warn("JWT validation failed")
				http.Error(w, "Invalid token", http.StatusUnauthorized)
				return
			}

			// Add user to context
			ctx = context.WithValue(ctx, UserContextKey, user)
			r = r.WithContext(ctx)

			next.ServeHTTP(w, r)
		})
	}
}

// RequireRole middleware that requires a specific role
func (m *AuthenticationMiddleware) RequireRole(role string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := GetUserFromContext(r.Context())
			if user == nil {
				http.Error(w, "Authentication required", http.StatusUnauthorized)
				return
			}

			if user.Role != role {
				m.authzSvc.LogSecurityViolation(r.Context(), user, "role_access_denied", role)
				http.Error(w, "Insufficient privileges", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireOrganisationAccess middleware that requires access to a specific organisation
func (m *AuthenticationMiddleware) RequireOrganisationAccess(orgID string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := GetUserFromContext(r.Context())
			if user == nil {
				http.Error(w, "Authentication required", http.StatusUnauthorized)
				return
			}

			if !m.authzSvc.CanAccessResource(r.Context(), user, orgID) {
				m.authzSvc.LogSecurityViolation(r.Context(), user, "organisation_access_denied", orgID)
				http.Error(w, "Access denied", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// authenticateRequest authenticates a request based on the API configuration
func (m *AuthenticationMiddleware) authenticateRequest(ctx context.Context, r *http.Request, apiConfig *models.APIConfiguration) (*models.User, error) {
	switch apiConfig.Authentication.Type {
	case "api_key":
		return m.authenticateAPIKey(ctx, r, apiConfig)
	case "oauth":
		return m.authenticateOAuth(ctx, r, apiConfig)
	case "basic":
		return m.authenticateBasicAuth(ctx, r, apiConfig)
	default:
		return nil, services.ErrInvalidCredentials
	}
}

// authenticateAPIKey authenticates using API key
func (m *AuthenticationMiddleware) authenticateAPIKey(ctx context.Context, r *http.Request, apiConfig *models.APIConfiguration) (*models.User, error) {
	// Try header first
	headerName := apiConfig.Authentication.Parameters["header"]
	if headerName == "" {
		headerName = "X-API-Key"
	}

	apiKey := r.Header.Get(headerName)
	if apiKey == "" {
		// Try query parameter
		apiKey = r.URL.Query().Get("api_key")
	}

	if apiKey == "" {
		return nil, services.ErrInvalidCredentials
	}

	return m.authSvc.ValidateAPIKey(ctx, apiKey, apiConfig)
}

// authenticateOAuth authenticates using OAuth token
func (m *AuthenticationMiddleware) authenticateOAuth(ctx context.Context, r *http.Request, apiConfig *models.APIConfiguration) (*models.User, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return nil, services.ErrInvalidCredentials
	}

	const bearerPrefix = "Bearer "
	if !strings.HasPrefix(authHeader, bearerPrefix) {
		return nil, services.ErrInvalidCredentials
	}

	token := authHeader[len(bearerPrefix):]
	return m.authSvc.ValidateOAuth(ctx, token, apiConfig)
}

// authenticateBasicAuth authenticates using basic authentication
func (m *AuthenticationMiddleware) authenticateBasicAuth(ctx context.Context, r *http.Request, apiConfig *models.APIConfiguration) (*models.User, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return nil, services.ErrInvalidCredentials
	}

	username, password, ok := services.ParseBasicAuth(authHeader)
	if !ok {
		return nil, services.ErrInvalidCredentials
	}

	return m.authSvc.ValidateBasicAuth(ctx, username, password, apiConfig)
}

// GetUserFromContext extracts the user from the request context
func GetUserFromContext(ctx context.Context) *models.User {
	user, ok := ctx.Value(UserContextKey).(*models.User)
	if !ok {
		return nil
	}
	return user
}

// GetAPIConfigFromContext extracts the API configuration from the request context
func GetAPIConfigFromContext(ctx context.Context) *models.APIConfiguration {
	config, ok := ctx.Value(APIConfigContextKey).(*models.APIConfiguration)
	if !ok {
		return nil
	}
	return config
}
