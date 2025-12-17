package services

import (
	"context"
	"testing"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"api-translation-platform/internal/logger"
	"api-translation-platform/internal/models"
)

// createTestLogger creates a logger for testing
func createTestLogger() *logger.Logger {
	return &logger.Logger{Logger: logrus.New()}
}

// MockUserRepository is a mock implementation of UserRepository for testing
type MockUserRepository struct {
	mock.Mock
}

func (m *MockUserRepository) Create(ctx context.Context, user *models.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockUserRepository) GetByID(ctx context.Context, id string) (*models.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserRepository) GetByUsername(ctx context.Context, username string) (*models.User, error) {
	args := m.Called(ctx, username)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserRepository) GetByEmail(ctx context.Context, email string) (*models.User, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserRepository) GetByUsernameAndOrganisation(ctx context.Context, username, orgID string) (*models.User, error) {
	args := m.Called(ctx, username, orgID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserRepository) GetByOrganisation(ctx context.Context, orgID string) ([]*models.User, error) {
	args := m.Called(ctx, orgID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.User), args.Error(1)
}

func (m *MockUserRepository) GetByOrganisationID(ctx context.Context, orgID string) ([]*models.User, error) {
	args := m.Called(ctx, orgID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.User), args.Error(1)
}

func (m *MockUserRepository) Update(ctx context.Context, user *models.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockUserRepository) Delete(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockUserRepository) GetAll(ctx context.Context) ([]*models.User, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.User), args.Error(1)
}

// **Feature: api-translation-platform, Property 2: Authentication validation consistency**
// **Validates: Requirements 1.3, 1.5**
func TestProperty_AuthenticationValidationConsistency(t *testing.T) {
	properties := gopter.NewProperties(&gopter.TestParameters{MinSuccessfulTests: 10})

	properties.Property("API key authentication should succeed with correct key and fail with incorrect key", prop.ForAll(
		func(apiKey string) bool {
			if len(apiKey) == 0 {
				return true // Skip empty inputs
			}

			ctx := context.Background()
			mockRepo := &MockUserRepository{}
			testLogger := createTestLogger()
			authSvc := NewAuthenticationService(testLogger, mockRepo)

			testUser := &models.User{
				ID:             "test-user-id",
				OrganisationID: "test-org-id",
				Username:       "testuser",
				Email:          "test@example.com",
				Role:           "org_admin",
				IsActive:       true,
			}

			apiConfig := &models.APIConfiguration{
				OrganisationID: "test-org-id",
				Authentication: models.AuthenticationConfig{
					Type: "api_key",
					Parameters: map[string]string{
						"key": apiKey,
					},
				},
			}

			mockRepo.On("GetByOrganisation", ctx, "test-org-id").Return([]*models.User{testUser}, nil)

			// Test with correct API key
			user, err := authSvc.ValidateAPIKey(ctx, apiKey, apiConfig)
			correctKeyResult := (err == nil && user != nil)

			// Test with incorrect API key
			user, err = authSvc.ValidateAPIKey(ctx, "wrong-"+apiKey, apiConfig)
			incorrectKeyResult := (err != nil && user == nil)

			return correctKeyResult && incorrectKeyResult
		},
		gen.AlphaString().SuchThat(func(s string) bool { return len(s) > 0 && len(s) < 50 }),
	))

	properties.Property("authentication methods should consistently validate credentials", prop.ForAll(
		func(validCredential string) bool {
			if len(validCredential) == 0 {
				return true // Skip empty inputs
			}

			ctx := context.Background()
			mockRepo := &MockUserRepository{}
			testLogger := createTestLogger()
			authSvc := NewAuthenticationService(testLogger, mockRepo)

			testUser := &models.User{
				ID:             "test-user-id",
				OrganisationID: "test-org-id",
				Username:       "testuser",
				Email:          "test@example.com",
				Role:           "org_admin",
				IsActive:       true,
			}

			// Test API key authentication
			apiKeyConfig := &models.APIConfiguration{
				OrganisationID: "test-org-id",
				Authentication: models.AuthenticationConfig{
					Type: "api_key",
					Parameters: map[string]string{
						"key": validCredential,
					},
				},
			}

			mockRepo.On("GetByOrganisation", ctx, "test-org-id").Return([]*models.User{testUser}, nil)

			// Valid credential should succeed
			user, err := authSvc.ValidateAPIKey(ctx, validCredential, apiKeyConfig)
			validResult := (err == nil && user != nil)

			// Invalid credential should fail
			user, err = authSvc.ValidateAPIKey(ctx, "invalid-"+validCredential, apiKeyConfig)
			invalidResult := (err != nil && user == nil)

			return validResult && invalidResult
		},
		gen.AlphaString().SuchThat(func(s string) bool { return len(s) > 0 && len(s) < 20 }),
	))

	properties.Property("empty credentials should always fail authentication", prop.ForAll(
		func(authType string) bool {
			if authType != "api_key" && authType != "oauth" && authType != "basic" {
				return true
			}

			ctx := context.Background()
			mockRepo := &MockUserRepository{}
			testLogger := createTestLogger()
			authSvc := NewAuthenticationService(testLogger, mockRepo)

			apiConfig := &models.APIConfiguration{
				OrganisationID: "test-org-id",
				Authentication: models.AuthenticationConfig{
					Type: authType,
					Parameters: map[string]string{
						"key":       "test-key",
						"client_id": "test-client",
					},
				},
			}

			switch authType {
			case "api_key":
				user, err := authSvc.ValidateAPIKey(ctx, "", apiConfig)
				return err != nil && user == nil

			case "oauth":
				user, err := authSvc.ValidateOAuth(ctx, "", apiConfig)
				return err != nil && user == nil

			case "basic":
				user, err := authSvc.ValidateBasicAuth(ctx, "", "", apiConfig)
				return err != nil && user == nil
			}

			return true
		},
		gen.OneConstOf("api_key", "oauth", "basic"),
	))

	properties.Property("JWT tokens should be valid after generation and invalid when tampered", prop.ForAll(
		func(userID string) bool {
			if len(userID) == 0 {
				return true
			}

			ctx := context.Background()
			mockRepo := &MockUserRepository{}
			testLogger := createTestLogger()
			authSvc := NewAuthenticationService(testLogger, mockRepo)

			testUser := &models.User{
				ID:             userID,
				OrganisationID: "test-org",
				Username:       "testuser",
				Email:          "test@example.com",
				Role:           "org_admin",
				IsActive:       true,
			}

			// Generate JWT (doesn't need mock)
			token, err := authSvc.GenerateJWT(ctx, testUser)
			if err != nil || token == "" {
				return false
			}

			// Set up mock for JWT validation - this will be called once for valid token
			mockRepo.On("GetByID", ctx, userID).Return(testUser, nil).Once()

			// Validate the generated token
			user, err := authSvc.ValidateJWT(ctx, token)
			validTokenResult := (err == nil && user != nil && user.ID == userID)

			// Test with tampered token - this should fail during JWT parsing, not reach the mock
			tamperedToken := token + "x"
			user, err = authSvc.ValidateJWT(ctx, tamperedToken)
			tamperedTokenResult := (err != nil && user == nil)

			return validTokenResult && tamperedTokenResult
		},
		gen.AlphaString().SuchThat(func(s string) bool { return len(s) > 0 && len(s) < 20 }),
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// Unit tests for specific authentication scenarios
func TestAuthenticationService_ValidateAPIKey(t *testing.T) {
	ctx := context.Background()
	mockRepo := &MockUserRepository{}
	testLogger := createTestLogger()
	authSvc := NewAuthenticationService(testLogger, mockRepo)

	testUser := &models.User{
		ID:             "test-user-id",
		OrganisationID: "test-org-id",
		Username:       "testuser",
		Email:          "test@example.com",
		Role:           "org_admin",
		IsActive:       true,
	}

	apiConfig := &models.APIConfiguration{
		OrganisationID: "test-org-id",
		Authentication: models.AuthenticationConfig{
			Type: "api_key",
			Parameters: map[string]string{
				"key": "valid-api-key",
			},
		},
	}

	t.Run("valid API key should authenticate successfully", func(t *testing.T) {
		mockRepo.On("GetByOrganisation", ctx, "test-org-id").Return([]*models.User{testUser}, nil)

		user, err := authSvc.ValidateAPIKey(ctx, "valid-api-key", apiConfig)
		assert.NoError(t, err)
		assert.NotNil(t, user)
		assert.Equal(t, testUser.ID, user.ID)
	})

	t.Run("invalid API key should fail authentication", func(t *testing.T) {
		user, err := authSvc.ValidateAPIKey(ctx, "invalid-api-key", apiConfig)
		assert.Error(t, err)
		assert.Nil(t, user)
		assert.Equal(t, ErrInvalidCredentials, err)
	})

	t.Run("empty API key should fail authentication", func(t *testing.T) {
		user, err := authSvc.ValidateAPIKey(ctx, "", apiConfig)
		assert.Error(t, err)
		assert.Nil(t, user)
		assert.Equal(t, ErrInvalidCredentials, err)
	})
}

func TestAuthenticationService_ValidateBasicAuth(t *testing.T) {
	ctx := context.Background()
	mockRepo := &MockUserRepository{}
	testLogger := createTestLogger()
	authSvc := NewAuthenticationService(testLogger, mockRepo)

	password := "testpassword123"
	hashedPassword, _ := authSvc.HashPassword(password)

	testUser := &models.User{
		ID:             "test-user-id",
		OrganisationID: "test-org-id",
		Username:       "testuser",
		Email:          "test@example.com",
		PasswordHash:   hashedPassword,
		Role:           "org_admin",
		IsActive:       true,
	}

	apiConfig := &models.APIConfiguration{
		OrganisationID: "test-org-id",
		Authentication: models.AuthenticationConfig{
			Type:       "basic",
			Parameters: map[string]string{},
		},
	}

	t.Run("valid credentials should authenticate successfully", func(t *testing.T) {
		mockRepo.On("GetByUsernameAndOrganisation", ctx, "testuser", "test-org-id").Return(testUser, nil)

		user, err := authSvc.ValidateBasicAuth(ctx, "testuser", password, apiConfig)
		assert.NoError(t, err)
		assert.NotNil(t, user)
		assert.Equal(t, testUser.ID, user.ID)
	})

	t.Run("invalid password should fail authentication", func(t *testing.T) {
		mockRepo.On("GetByUsernameAndOrganisation", ctx, "testuser", "test-org-id").Return(testUser, nil)

		user, err := authSvc.ValidateBasicAuth(ctx, "testuser", "wrongpassword", apiConfig)
		assert.Error(t, err)
		assert.Nil(t, user)
		assert.Equal(t, ErrInvalidCredentials, err)
	})

	t.Run("empty credentials should fail authentication", func(t *testing.T) {
		user, err := authSvc.ValidateBasicAuth(ctx, "", "", apiConfig)
		assert.Error(t, err)
		assert.Nil(t, user)
		assert.Equal(t, ErrInvalidCredentials, err)
	})
}

func TestAuthenticationService_JWTOperations(t *testing.T) {
	ctx := context.Background()
	mockRepo := &MockUserRepository{}
	testLogger := createTestLogger()
	authSvc := NewAuthenticationService(testLogger, mockRepo)

	testUser := &models.User{
		ID:             "test-user-id",
		OrganisationID: "test-org-id",
		Username:       "testuser",
		Email:          "test@example.com",
		Role:           "org_admin",
		IsActive:       true,
	}

	t.Run("JWT generation and validation should work correctly", func(t *testing.T) {
		// Generate JWT
		token, err := authSvc.GenerateJWT(ctx, testUser)
		assert.NoError(t, err)
		assert.NotEmpty(t, token)

		// Mock the GetByID call for validation
		mockRepo.On("GetByID", ctx, testUser.ID).Return(testUser, nil)

		// Validate JWT
		user, err := authSvc.ValidateJWT(ctx, token)
		assert.NoError(t, err)
		assert.NotNil(t, user)
		assert.Equal(t, testUser.ID, user.ID)
		assert.Equal(t, testUser.OrganisationID, user.OrganisationID)
		assert.Equal(t, testUser.Role, user.Role)
	})

	t.Run("invalid JWT should fail validation", func(t *testing.T) {
		user, err := authSvc.ValidateJWT(ctx, "invalid.jwt.token")
		assert.Error(t, err)
		assert.Nil(t, user)
	})

	t.Run("empty JWT should fail validation", func(t *testing.T) {
		user, err := authSvc.ValidateJWT(ctx, "")
		assert.Error(t, err)
		assert.Nil(t, user)
		assert.Equal(t, ErrInvalidToken, err)
	})
}

func TestParseBasicAuth(t *testing.T) {
	t.Run("valid basic auth header should parse correctly", func(t *testing.T) {
		// "testuser:testpass" in base64 is "dGVzdHVzZXI6dGVzdHBhc3M="
		authHeader := "Basic dGVzdHVzZXI6dGVzdHBhc3M="
		username, password, ok := ParseBasicAuth(authHeader)
		assert.True(t, ok)
		assert.Equal(t, "testuser", username)
		assert.Equal(t, "testpass", password)
	})

	t.Run("invalid basic auth header should fail parsing", func(t *testing.T) {
		username, password, ok := ParseBasicAuth("Bearer token")
		assert.False(t, ok)
		assert.Empty(t, username)
		assert.Empty(t, password)
	})

	t.Run("malformed basic auth should fail parsing", func(t *testing.T) {
		username, password, ok := ParseBasicAuth("Basic invalid-base64")
		assert.False(t, ok)
		assert.Empty(t, username)
		assert.Empty(t, password)
	})
}
