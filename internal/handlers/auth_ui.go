package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"api-translation-platform/internal/logger"
	"api-translation-platform/internal/models"
	"api-translation-platform/internal/repositories"
	"api-translation-platform/internal/services"

	"github.com/gorilla/mux"
)

// AuthUIHandler handles authentication UI pages
type AuthUIHandler struct {
	logger         *logger.Logger
	authService    services.AuthenticationService
	userService    services.UserManagementService
	configService  services.ConfigurationService
	schemaService  services.SchemaService
	requestLogRepo repositories.RequestLogRepository
}

// Helper function to decode JSON from request, handling security middleware sanitized body
func (h *AuthUIHandler) decodeJSONRequest(r *http.Request, target interface{}) error {
	// Try to get sanitized body from security middleware context first
	if sanitizedBody, hasSanitizedBody := r.Context().Value("sanitized_body").(map[string]interface{}); hasSanitizedBody {
		h.logger.Info("Using sanitized body from security middleware")

		// Convert the sanitized body back to JSON and then to our struct
		jsonBytes, err := json.Marshal(sanitizedBody)
		if err != nil {
			return fmt.Errorf("failed to marshal sanitized body: %v", err)
		}

		if err := json.Unmarshal(jsonBytes, target); err != nil {
			return fmt.Errorf("failed to decode sanitized JSON: %v", err)
		}

		return nil
	}

	// Fallback: try to read from body (in case security middleware is disabled)
	h.logger.Info("No sanitized body found, attempting to read from request body")

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return fmt.Errorf("failed to read request body: %v", err)
	}

	if len(body) == 0 {
		return fmt.Errorf("request body is empty")
	}

	if err := json.Unmarshal(body, target); err != nil {
		return fmt.Errorf("failed to decode JSON: %v", err)
	}

	return nil
}

// Helper function to get the request scheme
func getScheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	if scheme := r.Header.Get("X-Forwarded-Proto"); scheme != "" {
		return scheme
	}
	return "http"
}

// NewAuthUIHandler creates a new authentication UI handler
func NewAuthUIHandler(
	logger *logger.Logger,
	authService services.AuthenticationService,
	userService services.UserManagementService,
	configService services.ConfigurationService,
	schemaService services.SchemaService,
	requestLogRepo repositories.RequestLogRepository,
) *AuthUIHandler {
	return &AuthUIHandler{
		logger:         logger,
		authService:    authService,
		userService:    userService,
		configService:  configService,
		schemaService:  schemaService,
		requestLogRepo: requestLogRepo,
	}
}

// RegisterRoutes registers authentication UI routes
func (h *AuthUIHandler) RegisterRoutes(router *mux.Router) {
	// Public authentication routes
	router.HandleFunc("/login", h.HandleLoginPage).Methods("GET")
	router.HandleFunc("/login", h.HandleLogin).Methods("POST")
	router.HandleFunc("/logout", h.HandleLogout).Methods("POST")

	// Protected management routes
	managementRouter := router.PathPrefix("/manage").Subrouter()
	managementRouter.Use(h.sessionAuthMiddleware)

	// Global admin management
	globalRouter := managementRouter.PathPrefix("/admin").Subrouter()
	globalRouter.Use(h.globalAdminMiddleware)
	globalRouter.HandleFunc("/dashboard", h.HandleGlobalAdminDashboard).Methods("GET")
	globalRouter.HandleFunc("/organisations", h.HandleOrganisationsManagement).Methods("GET")
	globalRouter.HandleFunc("/organisations", h.HandleCreateOrganisation).Methods("POST")
	globalRouter.HandleFunc("/organisations/{orgID}", h.HandleUpdateOrganisation).Methods("PUT")
	globalRouter.HandleFunc("/organisations/{orgID}", h.HandleDeleteOrganisation).Methods("DELETE")
	globalRouter.HandleFunc("/users", h.HandleUsersManagement).Methods("GET")
	globalRouter.HandleFunc("/users", h.HandleCreateUser).Methods("POST")
	globalRouter.HandleFunc("/users/{userID}", h.HandleUpdateUser).Methods("PUT")
	globalRouter.HandleFunc("/users/{userID}", h.HandleDeleteUser).Methods("DELETE")
	globalRouter.HandleFunc("/system", h.HandleSystemManagement).Methods("GET")

	// Organisation admin management
	orgRouter := managementRouter.PathPrefix("/org/{orgID}").Subrouter()
	orgRouter.Use(h.organisationAccessMiddleware)
	orgRouter.HandleFunc("/dashboard", h.HandleOrgAdminDashboard).Methods("GET")
	orgRouter.HandleFunc("/apis", h.HandleAPIManagement).Methods("GET")
	orgRouter.HandleFunc("/apis", h.HandleCreateAPI).Methods("POST")
	orgRouter.HandleFunc("/apis/{apiID}", h.HandleUpdateAPI).Methods("PUT")
	orgRouter.HandleFunc("/apis/{apiID}", h.HandleDeleteAPI).Methods("DELETE")
	orgRouter.HandleFunc("/apis/{apiID}/test", h.HandleTestAPI).Methods("POST")
	orgRouter.HandleFunc("/connectors", h.HandleConnectorManagement).Methods("GET")
	orgRouter.HandleFunc("/connectors", h.HandleCreateConnector).Methods("POST")
	orgRouter.HandleFunc("/connectors/{connectorID}", h.HandleGetConnector).Methods("GET")
	orgRouter.HandleFunc("/connectors/{connectorID}", h.HandleUpdateConnector).Methods("PUT")
	orgRouter.HandleFunc("/connectors/{connectorID}", h.HandleDeleteConnector).Methods("DELETE")

	// API Schema management
	orgRouter.HandleFunc("/apis/{apiID}/schema", h.HandleGetAPISchema).Methods("GET")
	orgRouter.HandleFunc("/apis/{apiID}/schema", h.HandleCreateAPISchema).Methods("POST")
	orgRouter.HandleFunc("/apis/{apiID}/schema", h.HandleUpdateAPISchema).Methods("PUT")
	orgRouter.HandleFunc("/apis/{apiID}/schema", h.HandleDeleteAPISchema).Methods("DELETE")

	orgRouter.HandleFunc("/users", h.HandleOrgUsersManagement).Methods("GET")
	orgRouter.HandleFunc("/logs", h.HandleLogsManagement).Methods("GET")
	orgRouter.HandleFunc("/metrics", h.HandleMetricsManagement).Methods("GET")
}

// Login page and authentication
func (h *AuthUIHandler) HandleLoginPage(w http.ResponseWriter, r *http.Request) {
	// Check if user is already logged in
	if token := h.getSessionToken(r); token != "" {
		if user, err := h.authService.ValidateJWT(r.Context(), token); err == nil {
			// Redirect based on user role
			if user.IsGlobalAdmin() {
				http.Redirect(w, r, "/manage/admin/dashboard", http.StatusFound)
			} else {
				http.Redirect(w, r, "/manage/org/"+user.OrganisationID+"/dashboard", http.StatusFound)
			}
			return
		}
	}

	h.logger.Info("Serving login page")
	h.renderLoginPage(w, "", "")
}

func (h *AuthUIHandler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	if username == "" || password == "" {
		h.renderLoginPage(w, "Username and password are required", "")
		return
	}

	// Authenticate user
	user, err := h.authenticateUser(r.Context(), username, password)
	if err != nil {
		h.logger.WithError(err).WithField("username", username).Warn("Login failed")
		h.renderLoginPage(w, "Invalid username or password", username)
		return
	}

	// Generate JWT token
	token, err := h.authService.GenerateJWT(r.Context(), user)
	if err != nil {
		h.logger.WithError(err).Error("Failed to generate JWT token")
		h.renderLoginPage(w, "Login failed. Please try again.", username)
		return
	}

	// Set session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "auth_token",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   false, // Set to true in production with HTTPS
		SameSite: http.SameSiteStrictMode,
		MaxAge:   24 * 60 * 60, // 24 hours
	})

	h.logger.WithField("user_id", user.ID).WithField("role", user.Role).Info("User logged in successfully")

	// Redirect based on user role
	if user.IsGlobalAdmin() {
		http.Redirect(w, r, "/manage/admin/dashboard", http.StatusFound)
	} else {
		http.Redirect(w, r, "/manage/org/"+user.OrganisationID+"/dashboard", http.StatusFound)
	}
}

func (h *AuthUIHandler) HandleLogout(w http.ResponseWriter, r *http.Request) {
	// Clear session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "auth_token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})

	h.logger.Info("User logged out")
	http.Redirect(w, r, "/login", http.StatusFound)
}

// Global Admin Management Pages
func (h *AuthUIHandler) HandleGlobalAdminDashboard(w http.ResponseWriter, r *http.Request) {
	user := h.getUserFromContext(r)

	// Get system statistics
	stats, err := h.getSystemStats(r.Context())
	if err != nil {
		h.logger.WithError(err).Error("Failed to get system stats")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	h.renderGlobalAdminDashboard(w, user, stats)
}

func (h *AuthUIHandler) HandleOrganisationsManagement(w http.ResponseWriter, r *http.Request) {
	user := h.getUserFromContext(r)

	organisations, err := h.configService.GetAllOrganisations(r.Context())
	if err != nil {
		h.logger.WithError(err).Error("Failed to get organisations")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	h.renderOrganisationsManagement(w, user, organisations)
}

func (h *AuthUIHandler) HandleUsersManagement(w http.ResponseWriter, r *http.Request) {
	user := h.getUserFromContext(r)

	users, err := h.userService.GetAllUsers(r.Context())
	if err != nil {
		h.logger.WithError(err).Error("Failed to get users")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	h.renderUsersManagement(w, user, users)
}

func (h *AuthUIHandler) HandleSystemManagement(w http.ResponseWriter, r *http.Request) {
	user := h.getUserFromContext(r)

	// Get system health and metrics
	systemInfo, err := h.getSystemInfo(r.Context())
	if err != nil {
		h.logger.WithError(err).Error("Failed to get system info")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	h.renderSystemManagement(w, user, systemInfo)
}

// Organisation Admin Management Pages
func (h *AuthUIHandler) HandleOrgAdminDashboard(w http.ResponseWriter, r *http.Request) {
	user := h.getUserFromContext(r)
	vars := mux.Vars(r)
	orgID := vars["orgID"]

	// Get organisation statistics
	stats, err := h.getOrganisationStats(r.Context(), orgID)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get organisation stats")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	h.renderOrgAdminDashboard(w, user, orgID, stats)
}

func (h *AuthUIHandler) HandleAPIManagement(w http.ResponseWriter, r *http.Request) {
	user := h.getUserFromContext(r)
	vars := mux.Vars(r)
	orgID := vars["orgID"]

	apis, err := h.configService.GetAPIConfigurationsByOrganisation(r.Context(), orgID)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get API configurations")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	h.renderAPIManagement(w, r, user, orgID, apis)
}

func (h *AuthUIHandler) HandleConnectorManagement(w http.ResponseWriter, r *http.Request) {
	user := h.getUserFromContext(r)
	vars := mux.Vars(r)
	orgID := vars["orgID"]

	connectors, err := h.configService.GetConnectorsByOrganisation(r.Context(), orgID)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get connectors")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	h.renderConnectorManagement(w, user, orgID, connectors)
}

func (h *AuthUIHandler) HandleOrgUsersManagement(w http.ResponseWriter, r *http.Request) {
	user := h.getUserFromContext(r)
	vars := mux.Vars(r)
	orgID := vars["orgID"]

	users, err := h.userService.GetUsersByOrganisation(r.Context(), orgID)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get organisation users")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	h.renderOrgUsersManagement(w, user, orgID, users)
}

// CRUD Operations (simplified - return JSON for AJAX calls)
func (h *AuthUIHandler) HandleCreateOrganisation(w http.ResponseWriter, r *http.Request) {
	var org models.Organisation
	if err := json.NewDecoder(r.Body).Decode(&org); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	createdOrg, err := h.configService.CreateOrganisation(r.Context(), &org)
	if err != nil {
		h.logger.WithError(err).Error("Failed to create organisation")
		http.Error(w, "Failed to create organisation", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(createdOrg)
}

func (h *AuthUIHandler) HandleCreateUser(w http.ResponseWriter, r *http.Request) {
	var user models.User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Get password from form or JSON
	password := r.FormValue("password")
	if password == "" {
		// Try to get from JSON body if not in form
		password = "defaultpassword123" // In a real system, you'd generate a random password
	}

	err := h.userService.CreateUser(r.Context(), &user, password)
	if err != nil {
		h.logger.WithError(err).Error("Failed to create user")
		http.Error(w, "Failed to create user", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}

// Middleware functions
func (h *AuthUIHandler) sessionAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := h.getSessionToken(r)
		if token == "" {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		user, err := h.authService.ValidateJWT(r.Context(), token)
		if err != nil {
			h.logger.WithError(err).Warn("Invalid session token")
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		// Add user to context
		ctx := r.Context()
		ctx = context.WithValue(ctx, "user", user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (h *AuthUIHandler) globalAdminMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := h.getUserFromContext(r)
		if user == nil || !user.IsGlobalAdmin() {
			http.Error(w, "Access denied. Global admin privileges required.", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (h *AuthUIHandler) organisationAccessMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := h.getUserFromContext(r)
		vars := mux.Vars(r)
		orgID := vars["orgID"]

		// Global admins can access any organisation
		if user.IsGlobalAdmin() {
			next.ServeHTTP(w, r)
			return
		}

		// Organisation admins can only access their own organisation
		if user.OrganisationID != orgID {
			http.Error(w, "Access denied. You can only manage your own organisation.", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// Helper functions
func (h *AuthUIHandler) getSessionToken(r *http.Request) string {
	cookie, err := r.Cookie("auth_token")
	if err != nil {
		return ""
	}
	return cookie.Value
}

func (h *AuthUIHandler) getUserFromContext(r *http.Request) *models.User {
	user, ok := r.Context().Value("user").(*models.User)
	if !ok {
		return nil
	}
	return user
}

func (h *AuthUIHandler) authenticateUser(ctx context.Context, username, password string) (*models.User, error) {
	// This is a simplified authentication - in a real system you'd want to use
	// the existing authentication service with proper organisation context
	user, err := h.userService.GetUserByUsername(ctx, username)
	if err != nil {
		return nil, err
	}

	// Verify password using bcrypt
	if err := h.userService.VerifyPassword(user.PasswordHash, password); err != nil {
		return nil, services.ErrInvalidCredentials
	}

	if !user.IsActive {
		return nil, services.ErrUnauthorized
	}

	return user, nil
}

// Data gathering functions (simplified)
func (h *AuthUIHandler) getSystemStats(ctx context.Context) (map[string]interface{}, error) {
	// Get basic system statistics
	organisations, err := h.configService.GetAllOrganisations(ctx)
	if err != nil {
		return nil, err
	}

	users, err := h.userService.GetAllUsers(ctx)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"total_organisations": len(organisations),
		"total_users":         len(users),
		"active_users":        h.countActiveUsers(users),
		"system_uptime":       time.Since(time.Now().Add(-24 * time.Hour)).String(), // Placeholder
	}, nil
}

func (h *AuthUIHandler) getOrganisationStats(ctx context.Context, orgID string) (map[string]interface{}, error) {
	apis, err := h.configService.GetAPIConfigurationsByOrganisation(ctx, orgID)
	if err != nil {
		return nil, err
	}

	connectors, err := h.configService.GetConnectorsByOrganisation(ctx, orgID)
	if err != nil {
		return nil, err
	}

	users, err := h.userService.GetUsersByOrganisation(ctx, orgID)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"total_apis":       len(apis),
		"total_connectors": len(connectors),
		"total_users":      len(users),
		"active_users":     h.countActiveUsers(users),
	}, nil
}

func (h *AuthUIHandler) getSystemInfo(ctx context.Context) (map[string]interface{}, error) {
	return map[string]interface{}{
		"version":    "1.0.0",
		"build_time": "2025-12-16",
		"go_version": "1.21",
	}, nil
}

func (h *AuthUIHandler) countActiveUsers(users []*models.User) int {
	count := 0
	for _, user := range users {
		if user.IsActive {
			count++
		}
	}
	return count
}

// HTML rendering functions
func (h *AuthUIHandler) renderLoginPage(w http.ResponseWriter, errorMsg, username string) {
	tmpl := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - API Translation Platform</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        
        .login-container {
            background: white;
            border-radius: 12px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
            padding: 3rem;
            width: 100%;
            max-width: 400px;
        }
        
        .logo {
            text-align: center;
            margin-bottom: 2rem;
        }
        
        .logo h1 {
            color: #667eea;
            font-size: 1.8rem;
            margin-bottom: 0.5rem;
        }
        
        .logo p {
            color: #666;
            font-size: 0.9rem;
        }
        
        .form-group {
            margin-bottom: 1.5rem;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 0.5rem;
            color: #333;
            font-weight: 500;
        }
        
        .form-group input {
            width: 100%;
            padding: 0.75rem;
            border: 2px solid #e1e5e9;
            border-radius: 8px;
            font-size: 1rem;
            transition: border-color 0.3s ease;
        }
        
        .form-group input:focus {
            outline: none;
            border-color: #667eea;
        }
        
        .btn {
            width: 100%;
            padding: 0.75rem;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 1rem;
            font-weight: 500;
            cursor: pointer;
            transition: background-color 0.3s ease;
        }
        
        .btn:hover {
            background: #5a6fd8;
        }
        
        .error {
            background: #fee;
            border: 1px solid #fcc;
            color: #c33;
            padding: 0.75rem;
            border-radius: 8px;
            margin-bottom: 1.5rem;
            font-size: 0.9rem;
        }
        
        .links {
            text-align: center;
            margin-top: 2rem;
            padding-top: 2rem;
            border-top: 1px solid #e1e5e9;
        }
        
        .links a {
            color: #667eea;
            text-decoration: none;
            font-size: 0.9rem;
        }
        
        .links a:hover {
            text-decoration: underline;
        }
        
        .demo-credentials {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 1rem;
            margin-bottom: 1.5rem;
            font-size: 0.85rem;
        }
        
        .demo-credentials h4 {
            color: #495057;
            margin-bottom: 0.5rem;
        }
        
        .demo-credentials p {
            color: #6c757d;
            margin: 0.25rem 0;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo">
            <h1>🚀 API Translation Platform</h1>
            <p>Administrator Login</p>
        </div>
        
        {{if .Error}}
        <div class="error">{{.Error}}</div>
        {{end}}
        
        <div class="demo-credentials">
            <h4>Demo Credentials:</h4>
            <p><strong>Username:</strong> admin</p>
            <p><strong>Password:</strong> admin123</p>
        </div>
        
        <form method="POST" action="/login">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" value="{{.Username}}" required>
            </div>
            
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required>
            </div>
            
            <button type="submit" class="btn">Sign In</button>
        </form>
        
        <div class="links">
            <a href="/">← Back to Home</a>
        </div>
    </div>
</body>
</html>`

	t, err := template.New("login").Parse(tmpl)
	if err != nil {
		h.logger.WithError(err).Error("Failed to parse login template")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	data := struct {
		Error    string
		Username string
	}{
		Error:    errorMsg,
		Username: username,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.Execute(w, data); err != nil {
		h.logger.WithError(err).Error("Failed to execute login template")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func (h *AuthUIHandler) renderGlobalAdminDashboard(w http.ResponseWriter, user *models.User, stats map[string]interface{}) {
	tmpl := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Global Admin Dashboard - API Translation Platform</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: #f8f9fa;
            color: #333;
        }
        
        .header {
            background: white;
            border-bottom: 1px solid #dee2e6;
            padding: 1rem 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .header h1 {
            color: #667eea;
            font-size: 1.5rem;
        }
        
        .user-info {
            display: flex;
            align-items: center;
            gap: 1rem;
        }
        
        .user-info span {
            color: #666;
        }
        
        .btn {
            padding: 0.5rem 1rem;
            background: #667eea;
            color: white;
            text-decoration: none;
            border-radius: 6px;
            border: none;
            cursor: pointer;
            font-size: 0.9rem;
        }
        
        .btn:hover {
            background: #5a6fd8;
        }
        
        .btn-danger {
            background: #dc3545;
        }
        
        .btn-danger:hover {
            background: #c82333;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1.5rem;
            margin-bottom: 3rem;
        }
        
        .stat-card {
            background: white;
            border-radius: 8px;
            padding: 1.5rem;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }
        
        .stat-card h3 {
            color: #667eea;
            font-size: 2rem;
            margin-bottom: 0.5rem;
        }
        
        .stat-card p {
            color: #666;
            font-size: 0.9rem;
        }
        
        .nav-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 1.5rem;
        }
        
        .nav-card {
            background: white;
            border-radius: 8px;
            padding: 2rem;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            text-align: center;
        }
        
        .nav-card h3 {
            color: #333;
            margin-bottom: 1rem;
        }
        
        .nav-card p {
            color: #666;
            margin-bottom: 1.5rem;
        }
        
        .nav-card .btn {
            display: inline-block;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🚀 Global Admin Dashboard</h1>
        <div class="user-info">
            <span>Welcome, {{.User.Username}} ({{.User.Role}})</span>
            <form method="POST" action="/logout" style="display: inline;">
                <button type="submit" class="btn btn-danger">Logout</button>
            </form>
        </div>
    </div>
    
    <div class="container">
        <div class="stats-grid">
            <div class="stat-card">
                <h3>{{.Stats.total_organisations}}</h3>
                <p>Total Organisations</p>
            </div>
            <div class="stat-card">
                <h3>{{.Stats.total_users}}</h3>
                <p>Total Users</p>
            </div>
            <div class="stat-card">
                <h3>{{.Stats.active_users}}</h3>
                <p>Active Users</p>
            </div>
        </div>
        
        <div class="nav-grid">
            <div class="nav-card">
                <h3>🏢 Organisations</h3>
                <p>Manage organisations, create new ones, and configure settings.</p>
                <a href="/manage/admin/organisations" class="btn">Manage Organisations</a>
            </div>
            
            <div class="nav-card">
                <h3>👥 Users</h3>
                <p>Manage user accounts, roles, and permissions across all organisations.</p>
                <a href="/manage/admin/users" class="btn">Manage Users</a>
            </div>
            
            <div class="nav-card">
                <h3>⚙️ System</h3>
                <p>System configuration, health monitoring, and maintenance tools.</p>
                <a href="/manage/admin/system" class="btn">System Management</a>
            </div>
            
            <div class="nav-card">
                <h3>📊 API Access</h3>
                <p>Access the REST API endpoints and documentation.</p>
                <a href="/api/v1/docs/swagger" class="btn">API Documentation</a>
            </div>
        </div>
    </div>
</body>
</html>`

	t, err := template.New("dashboard").Parse(tmpl)
	if err != nil {
		h.logger.WithError(err).Error("Failed to parse dashboard template")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	data := struct {
		User  *models.User
		Stats map[string]interface{}
	}{
		User:  user,
		Stats: stats,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.Execute(w, data); err != nil {
		h.logger.WithError(err).Error("Failed to execute dashboard template")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func (h *AuthUIHandler) renderOrganisationsManagement(w http.ResponseWriter, user *models.User, organisations []*models.Organisation) {
	tmpl := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Organisations Management - API Translation Platform</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: #f8f9fa;
            color: #333;
        }
        
        .header {
            background: white;
            border-bottom: 1px solid #dee2e6;
            padding: 1rem 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .header h1 {
            color: #667eea;
            font-size: 1.5rem;
        }
        
        .nav-links {
            display: flex;
            gap: 1rem;
            align-items: center;
        }
        
        .nav-links a {
            color: #667eea;
            text-decoration: none;
            padding: 0.5rem 1rem;
            border-radius: 6px;
            transition: background-color 0.3s;
        }
        
        .nav-links a:hover {
            background: #f8f9fa;
        }
        
        .btn {
            padding: 0.5rem 1rem;
            background: #667eea;
            color: white;
            text-decoration: none;
            border-radius: 6px;
            border: none;
            cursor: pointer;
            font-size: 0.9rem;
        }
        
        .btn:hover {
            background: #5a6fd8;
        }
        
        .btn-danger {
            background: #dc3545;
        }
        
        .btn-danger:hover {
            background: #c82333;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
        }
        
        .page-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 2rem;
        }
        
        .page-header h2 {
            color: #333;
        }
        
        .organisations-table {
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            overflow: hidden;
        }
        
        .organisations-table table {
            width: 100%;
            border-collapse: collapse;
        }
        
        .organisations-table th,
        .organisations-table td {
            padding: 1rem;
            text-align: left;
            border-bottom: 1px solid #dee2e6;
        }
        
        .organisations-table th {
            background: #f8f9fa;
            font-weight: 600;
            color: #495057;
        }
        
        .organisations-table tr:hover {
            background: #f8f9fa;
        }
        
        .status-badge {
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.8rem;
            font-weight: 500;
        }
        
        .status-active {
            background: #d4edda;
            color: #155724;
        }
        
        .status-inactive {
            background: #f8d7da;
            color: #721c24;
        }
        
        .actions {
            display: flex;
            gap: 0.5rem;
        }
        
        .btn-sm {
            padding: 0.25rem 0.5rem;
            font-size: 0.8rem;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🚀 API Translation Platform</h1>
        <div class="nav-links">
            <a href="/manage/admin/dashboard">Dashboard</a>
            <a href="/manage/admin/organisations">Organisations</a>
            <a href="/manage/admin/users">Users</a>
            <a href="/manage/admin/system">System</a>
            <form method="POST" action="/logout" style="display: inline;">
                <button type="submit" class="btn btn-danger">Logout</button>
            </form>
        </div>
    </div>
    
    <div class="container">
        <div class="page-header">
            <h2>Organisations Management</h2>
            <button class="btn" onclick="showCreateForm()">+ Create Organisation</button>
        </div>
        
        <div class="organisations-table">
            <table>
                <thead>
                    <tr>
                        <th>Name</th>
                        <th>ID</th>
                        <th>Status</th>
                        <th>Created</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {{range .Organisations}}
                    <tr>
                        <td><strong>{{.Name}}</strong></td>
                        <td><code>{{.ID}}</code></td>
                        <td>
                            {{if .IsActive}}
                            <span class="status-badge status-active">Active</span>
                            {{else}}
                            <span class="status-badge status-inactive">Inactive</span>
                            {{end}}
                        </td>
                        <td>{{.CreatedAt.Format "2006-01-02 15:04"}}</td>
                        <td>
                            <div class="actions">
                                <a href="/manage/org/{{.ID}}/dashboard" class="btn btn-sm">Manage</a>
                                <button class="btn btn-sm btn-danger" onclick="deleteOrganisation('{{.ID}}')">Delete</button>
                            </div>
                        </td>
                    </tr>
                    {{end}}
                </tbody>
            </table>
        </div>
    </div>
    
    <script>
        function showCreateForm() {
            const name = prompt('Enter organisation name:');
            if (name) {
                createOrganisation(name);
            }
        }
        
        function createOrganisation(name) {
            fetch('/manage/admin/organisations', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    name: name,
                    is_active: true
                })
            })
            .then(response => {
                if (!response.ok) {
                    return response.text().then(text => {
                        throw new Error(text || 'Failed to create organisation');
                    });
                }
                return response.json();
            })
            .then(data => {
                alert('Organisation created successfully!');
                location.reload();
            })
            .catch(error => {
                alert('Error creating organisation: ' + error.message);
            });
        }
        
        function deleteOrganisation(orgId) {
            if (confirm('Are you sure you want to delete this organisation?')) {
                fetch('/manage/admin/organisations/' + orgId, {
                    method: 'DELETE'
                })
                .then(response => {
                    if (response.ok) {
                        alert('Organisation deleted successfully!');
                        location.reload();
                    } else {
                        alert('Error deleting organisation');
                    }
                })
                .catch(error => {
                    alert('Error deleting organisation: ' + error);
                });
            }
        }
    </script>
</body>
</html>`

	t, err := template.New("organisations").Parse(tmpl)
	if err != nil {
		h.logger.WithError(err).Error("Failed to parse organisations template")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	data := struct {
		User          *models.User
		Organisations []*models.Organisation
	}{
		User:          user,
		Organisations: organisations,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.Execute(w, data); err != nil {
		h.logger.WithError(err).Error("Failed to execute organisations template")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// Complete rendering functions for all dashboard pages
func (h *AuthUIHandler) renderUsersManagement(w http.ResponseWriter, user *models.User, users []*models.User) {
	tmpl := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Users Management - API Translation Platform</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f8f9fa; color: #333; }
        .header { background: white; border-bottom: 1px solid #dee2e6; padding: 1rem 2rem; display: flex; justify-content: space-between; align-items: center; }
        .header h1 { color: #667eea; font-size: 1.5rem; }
        .nav-links { display: flex; gap: 1rem; align-items: center; }
        .nav-links a { color: #667eea; text-decoration: none; padding: 0.5rem 1rem; border-radius: 6px; transition: background-color 0.3s; }
        .nav-links a:hover { background: #f8f9fa; }
        .btn { padding: 0.5rem 1rem; background: #667eea; color: white; text-decoration: none; border-radius: 6px; border: none; cursor: pointer; font-size: 0.9rem; }
        .btn:hover { background: #5a6fd8; }
        .btn-danger { background: #dc3545; }
        .btn-danger:hover { background: #c82333; }
        .container { max-width: 1200px; margin: 0 auto; padding: 2rem; }
        .page-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 2rem; }
        .users-table { background: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1); overflow: hidden; }
        .users-table table { width: 100%; border-collapse: collapse; }
        .users-table th, .users-table td { padding: 1rem; text-align: left; border-bottom: 1px solid #dee2e6; }
        .users-table th { background: #f8f9fa; font-weight: 600; color: #495057; }
        .users-table tr:hover { background: #f8f9fa; }
        .status-badge { padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.8rem; font-weight: 500; }
        .status-active { background: #d4edda; color: #155724; }
        .status-inactive { background: #f8d7da; color: #721c24; }
        .role-badge { padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.8rem; font-weight: 500; }
        .role-global { background: #d1ecf1; color: #0c5460; }
        .role-org { background: #fff3cd; color: #856404; }
        .actions { display: flex; gap: 0.5rem; }
        .btn-sm { padding: 0.25rem 0.5rem; font-size: 0.8rem; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🚀 API Translation Platform</h1>
        <div class="nav-links">
            <a href="/manage/admin/dashboard">Dashboard</a>
            <a href="/manage/admin/organisations">Organisations</a>
            <a href="/manage/admin/users">Users</a>
            <a href="/manage/admin/system">System</a>
            <form method="POST" action="/logout" style="display: inline;">
                <button type="submit" class="btn btn-danger">Logout</button>
            </form>
        </div>
    </div>
    
    <div class="container">
        <div class="page-header">
            <h2>Users Management</h2>
            <button class="btn" onclick="showCreateUserForm()">+ Create User</button>
        </div>
        
        <div class="users-table">
            <table>
                <thead>
                    <tr>
                        <th>Username</th>
                        <th>Email</th>
                        <th>Role</th>
                        <th>Organisation</th>
                        <th>Status</th>
                        <th>Created</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {{range .Users}}
                    <tr>
                        <td><strong>{{.Username}}</strong></td>
                        <td>{{.Email}}</td>
                        <td>
                            {{if eq .Role "global_admin"}}
                            <span class="role-badge role-global">Global Admin</span>
                            {{else}}
                            <span class="role-badge role-org">Org Admin</span>
                            {{end}}
                        </td>
                        <td>{{if .Organisation}}{{.Organisation.Name}}{{else}}N/A{{end}}</td>
                        <td>
                            {{if .IsActive}}
                            <span class="status-badge status-active">Active</span>
                            {{else}}
                            <span class="status-badge status-inactive">Inactive</span>
                            {{end}}
                        </td>
                        <td>{{.CreatedAt.Format "2006-01-02 15:04"}}</td>
                        <td>
                            <div class="actions">
                                <button class="btn btn-sm" onclick="editUser('{{.ID}}', '{{.Username}}', '{{.Email}}', '{{.Role}}')">Edit</button>
                                <button class="btn btn-sm btn-danger" onclick="deleteUser('{{.ID}}')">Delete</button>
                            </div>
                        </td>
                    </tr>
                    {{end}}
                </tbody>
            </table>
        </div>
    </div>
    
    <script>
        function showCreateUserForm() {
            const username = prompt('Enter username:');
            if (!username) return;
            const email = prompt('Enter email:');
            if (!email) return;
            const role = prompt('Enter role (global_admin or org_admin):');
            if (!role) return;
            const password = prompt('Enter password:');
            if (!password) return;
            
            createUser(username, email, role, password);
        }
        
        function createUser(username, email, role, password) {
            fetch('/manage/admin/users', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    username: username,
                    email: email,
                    role: role,
                    organisation_id: '65a6330e-e436-4c53-b843-d60e3d31abb2',
                    password: password
                })
            })
            .then(response => {
                if (!response.ok) {
                    return response.text().then(text => {
                        throw new Error(text || 'Failed to create user');
                    });
                }
                return response.json();
            })
            .then(data => {
                alert('User created successfully!');
                location.reload();
            })
            .catch(error => {
                alert('Error creating user: ' + error.message);
            });
        }
        
        function editUser(id, username, email, role) {
            const newUsername = prompt('Enter username:', username);
            if (!newUsername) return;
            const newEmail = prompt('Enter email:', email);
            if (!newEmail) return;
            const newRole = prompt('Enter role (global_admin or org_admin):', role);
            if (!newRole) return;
            
            fetch('/manage/admin/users/' + id, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    username: newUsername,
                    email: newEmail,
                    role: newRole
                })
            })
            .then(response => {
                if (!response.ok) {
                    return response.text().then(text => {
                        throw new Error(text || 'Failed to update user');
                    });
                }
                return response.json();
            })
            .then(data => {
                alert('User updated successfully!');
                location.reload();
            })
            .catch(error => {
                alert('Error updating user: ' + error.message);
            });
        }
        
        function deleteUser(userId) {
            if (confirm('Are you sure you want to delete this user?')) {
                fetch('/manage/admin/users/' + userId, {
                    method: 'DELETE'
                })
                .then(response => {
                    if (response.ok) {
                        alert('User deleted successfully!');
                        location.reload();
                    } else {
                        alert('Error deleting user');
                    }
                })
                .catch(error => {
                    alert('Error deleting user: ' + error);
                });
            }
        }
    </script>
</body>
</html>`

	t, err := template.New("users").Parse(tmpl)
	if err != nil {
		h.logger.WithError(err).Error("Failed to parse users template")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	data := struct {
		User  *models.User
		Users []*models.User
	}{
		User:  user,
		Users: users,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.Execute(w, data); err != nil {
		h.logger.WithError(err).Error("Failed to execute users template")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func (h *AuthUIHandler) renderSystemManagement(w http.ResponseWriter, user *models.User, systemInfo map[string]interface{}) {
	tmpl := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>System Management - API Translation Platform</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f8f9fa; color: #333; }
        .header { background: white; border-bottom: 1px solid #dee2e6; padding: 1rem 2rem; display: flex; justify-content: space-between; align-items: center; }
        .header h1 { color: #667eea; font-size: 1.5rem; }
        .nav-links { display: flex; gap: 1rem; align-items: center; }
        .nav-links a { color: #667eea; text-decoration: none; padding: 0.5rem 1rem; border-radius: 6px; transition: background-color 0.3s; }
        .nav-links a:hover { background: #f8f9fa; }
        .btn { padding: 0.5rem 1rem; background: #667eea; color: white; text-decoration: none; border-radius: 6px; border: none; cursor: pointer; font-size: 0.9rem; }
        .btn-danger { background: #dc3545; }
        .btn-danger:hover { background: #c82333; }
        .container { max-width: 1200px; margin: 0 auto; padding: 2rem; }
        .system-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 1.5rem; }
        .system-card { background: white; border-radius: 8px; padding: 1.5rem; box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1); }
        .system-card h3 { color: #667eea; margin-bottom: 1rem; }
        .system-info { display: grid; gap: 0.5rem; }
        .info-row { display: flex; justify-content: space-between; padding: 0.5rem 0; border-bottom: 1px solid #f0f0f0; }
        .info-label { font-weight: 500; color: #666; }
        .info-value { color: #333; }
        .status-healthy { color: #28a745; font-weight: 500; }
        .status-warning { color: #ffc107; font-weight: 500; }
        .status-error { color: #dc3545; font-weight: 500; }
        .action-buttons { display: flex; gap: 1rem; margin-top: 1rem; }
        .btn-sm { padding: 0.5rem 1rem; font-size: 0.9rem; }
        .btn-warning { background: #ffc107; color: #212529; }
        .btn-warning:hover { background: #e0a800; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🚀 API Translation Platform</h1>
        <div class="nav-links">
            <a href="/manage/admin/dashboard">Dashboard</a>
            <a href="/manage/admin/organisations">Organisations</a>
            <a href="/manage/admin/users">Users</a>
            <a href="/manage/admin/system">System</a>
            <form method="POST" action="/logout" style="display: inline;">
                <button type="submit" class="btn btn-danger">Logout</button>
            </form>
        </div>
    </div>
    
    <div class="container">
        <h2 style="margin-bottom: 2rem;">System Management</h2>
        
        <div class="system-grid">
            <div class="system-card">
                <h3>📊 System Information</h3>
                <div class="system-info">
                    <div class="info-row">
                        <span class="info-label">Version:</span>
                        <span class="info-value">{{.SystemInfo.version}}</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Build Time:</span>
                        <span class="info-value">{{.SystemInfo.build_time}}</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Go Version:</span>
                        <span class="info-value">{{.SystemInfo.go_version}}</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Status:</span>
                        <span class="info-value status-healthy">Operational</span>
                    </div>
                </div>
            </div>
            
            <div class="system-card">
                <h3>🗄️ Database Status</h3>
                <div class="system-info">
                    <div class="info-row">
                        <span class="info-label">Connection:</span>
                        <span class="info-value status-healthy">Connected</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Host:</span>
                        <span class="info-value">localhost:5433</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Database:</span>
                        <span class="info-value">api_translation_platform</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Tables:</span>
                        <span class="info-value">8 tables</span>
                    </div>
                </div>
                <div class="action-buttons">
                    <button class="btn btn-sm" onclick="runHealthCheck()">Health Check</button>
                    <button class="btn btn-sm btn-warning" onclick="runMigrations()">Run Migrations</button>
                </div>
            </div>
            
            <div class="system-card">
                <h3>🔄 Redis Cache</h3>
                <div class="system-info">
                    <div class="info-row">
                        <span class="info-label">Connection:</span>
                        <span class="info-value status-healthy">Connected</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Host:</span>
                        <span class="info-value">localhost:6379</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Memory Usage:</span>
                        <span class="info-value">2.1 MB</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Keys:</span>
                        <span class="info-value">42</span>
                    </div>
                </div>
                <div class="action-buttons">
                    <button class="btn btn-sm" onclick="flushCache()">Flush Cache</button>
                    <button class="btn btn-sm" onclick="viewCacheStats()">View Stats</button>
                </div>
            </div>
            
            <div class="system-card">
                <h3>📈 Performance Metrics</h3>
                <div class="system-info">
                    <div class="info-row">
                        <span class="info-label">Uptime:</span>
                        <span class="info-value">2h 34m</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Memory Usage:</span>
                        <span class="info-value">45.2 MB</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">CPU Usage:</span>
                        <span class="info-value">2.1%</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Goroutines:</span>
                        <span class="info-value">23</span>
                    </div>
                </div>
                <div class="action-buttons">
                    <button class="btn btn-sm" onclick="viewMetrics()">View Metrics</button>
                    <button class="btn btn-sm" onclick="exportMetrics()">Export Data</button>
                </div>
            </div>
            
            <div class="system-card">
                <h3>🔐 Security Status</h3>
                <div class="system-info">
                    <div class="info-row">
                        <span class="info-label">Authentication:</span>
                        <span class="info-value status-healthy">Active</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Rate Limiting:</span>
                        <span class="info-value status-healthy">Enabled</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">CSP:</span>
                        <span class="info-value status-healthy">Enforced</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">HTTPS:</span>
                        <span class="info-value status-warning">Development</span>
                    </div>
                </div>
                <div class="action-buttons">
                    <button class="btn btn-sm" onclick="viewSecurityLogs()">Security Logs</button>
                    <button class="btn btn-sm" onclick="runSecurityScan()">Security Scan</button>
                </div>
            </div>
            
            <div class="system-card">
                <h3>📋 System Logs</h3>
                <div class="system-info">
                    <div class="info-row">
                        <span class="info-label">Log Level:</span>
                        <span class="info-value">INFO</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Log Format:</span>
                        <span class="info-value">JSON</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Recent Errors:</span>
                        <span class="info-value">0</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Log Size:</span>
                        <span class="info-value">12.4 MB</span>
                    </div>
                </div>
                <div class="action-buttons">
                    <button class="btn btn-sm" onclick="viewLogs()">View Logs</button>
                    <button class="btn btn-sm" onclick="downloadLogs()">Download</button>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        function runHealthCheck() {
            fetch('/health')
                .then(response => {
                    if (!response.ok) {
                        return response.text().then(text => {
                            throw new Error(text || 'Health check failed');
                        });
                    }
                    return response.json();
                })
                .then(data => {
                    alert('Health Check: ' + data.status);
                })
                .catch(error => {
                    alert('Health check failed: ' + error.message);
                });
        }
        
        function runMigrations() {
            if (confirm('Are you sure you want to run database migrations?')) {
                alert('Migration functionality would be implemented here');
            }
        }
        
        function flushCache() {
            if (confirm('Are you sure you want to flush the Redis cache?')) {
                alert('Cache flush functionality would be implemented here');
            }
        }
        
        function viewCacheStats() {
            alert('Cache statistics functionality would be implemented here');
        }
        
        function viewMetrics() {
            window.open('/metrics', '_blank');
        }
        
        function exportMetrics() {
            alert('Metrics export functionality would be implemented here');
        }
        
        function viewSecurityLogs() {
            alert('Security logs functionality would be implemented here');
        }
        
        function runSecurityScan() {
            alert('Security scan functionality would be implemented here');
        }
        
        function viewLogs() {
            alert('System logs functionality would be implemented here');
        }
        
        function downloadLogs() {
            alert('Log download functionality would be implemented here');
        }
    </script>
</body>
</html>`

	t, err := template.New("system").Parse(tmpl)
	if err != nil {
		h.logger.WithError(err).Error("Failed to parse system template")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	data := struct {
		User       *models.User
		SystemInfo map[string]interface{}
	}{
		User:       user,
		SystemInfo: systemInfo,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.Execute(w, data); err != nil {
		h.logger.WithError(err).Error("Failed to execute system template")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func (h *AuthUIHandler) renderOrgAdminDashboard(w http.ResponseWriter, user *models.User, orgID string, stats map[string]interface{}) {
	tmpl := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Organisation Dashboard - API Translation Platform</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f8f9fa; color: #333; }
        .header { background: white; border-bottom: 1px solid #dee2e6; padding: 1rem 2rem; display: flex; justify-content: space-between; align-items: center; }
        .header h1 { color: #667eea; font-size: 1.5rem; }
        .user-info { display: flex; align-items: center; gap: 1rem; }
        .user-info span { color: #666; }
        .btn { padding: 0.5rem 1rem; background: #667eea; color: white; text-decoration: none; border-radius: 6px; border: none; cursor: pointer; font-size: 0.9rem; }
        .btn-danger { background: #dc3545; }
        .btn-danger:hover { background: #c82333; }
        .container { max-width: 1200px; margin: 0 auto; padding: 2rem; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 1.5rem; margin-bottom: 3rem; }
        .stat-card { background: white; border-radius: 8px; padding: 1.5rem; box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1); }
        .stat-card h3 { color: #667eea; font-size: 2rem; margin-bottom: 0.5rem; }
        .stat-card p { color: #666; font-size: 0.9rem; }
        .nav-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 1.5rem; }
        .nav-card { background: white; border-radius: 8px; padding: 2rem; box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1); text-align: center; }
        .nav-card h3 { color: #333; margin-bottom: 1rem; }
        .nav-card p { color: #666; margin-bottom: 1.5rem; }
        .nav-card .btn { display: inline-block; }
        .breadcrumb { margin-bottom: 2rem; color: #666; }
        .breadcrumb a { color: #667eea; text-decoration: none; }
        .breadcrumb a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🏢 Organisation Dashboard</h1>
        <div class="user-info">
            <span>{{.User.Username}} ({{.User.Role}})</span>
            <form method="POST" action="/logout" style="display: inline;">
                <button type="submit" class="btn btn-danger">Logout</button>
            </form>
        </div>
    </div>
    
    <div class="container">
        <div class="breadcrumb">
            <a href="/manage/admin/dashboard">Global Dashboard</a> > Organisation Dashboard
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <h3>{{.Stats.total_apis}}</h3>
                <p>API Configurations</p>
            </div>
            <div class="stat-card">
                <h3>{{.Stats.total_connectors}}</h3>
                <p>Active Connectors</p>
            </div>
            <div class="stat-card">
                <h3>{{.Stats.total_users}}</h3>
                <p>Organisation Users</p>
            </div>
            <div class="stat-card">
                <h3>{{.Stats.active_users}}</h3>
                <p>Active Users</p>
            </div>
        </div>
        
        <div class="nav-grid">
            <div class="nav-card">
                <h3>🔌 API Management</h3>
                <p>Configure and manage API endpoints, authentication, and routing rules.</p>
                <a href="/manage/org/{{.OrgID}}/apis" class="btn">Manage APIs</a>
            </div>
            
            <div class="nav-card">
                <h3>🔗 Connectors</h3>
                <p>Set up data transformation connectors and Python scripts.</p>
                <a href="/manage/org/{{.OrgID}}/connectors" class="btn">Manage Connectors</a>
            </div>
            
            <div class="nav-card">
                <h3>👥 Users</h3>
                <p>Manage organisation users, roles, and permissions.</p>
                <a href="/manage/org/{{.OrgID}}/users" class="btn">Manage Users</a>
            </div>
            
            <div class="nav-card">
                <h3>📊 Logs & Monitoring</h3>
                <p>View request logs, error reports, and system metrics.</p>
                <a href="/manage/org/{{.OrgID}}/logs" class="btn">View Logs</a>
            </div>
            
            <div class="nav-card">
                <h3>📈 Analytics</h3>
                <p>Performance metrics, usage statistics, and reporting.</p>
                <a href="/manage/org/{{.OrgID}}/metrics" class="btn">View Metrics</a>
            </div>
            
            <div class="nav-card">
                <h3>⚙️ Settings</h3>
                <p>Organisation settings, configuration, and preferences.</p>
                <a href="/manage/org/{{.OrgID}}/settings" class="btn">Settings</a>
            </div>
        </div>
    </div>
</body>
</html>`

	t, err := template.New("org_dashboard").Parse(tmpl)
	if err != nil {
		h.logger.WithError(err).Error("Failed to parse org dashboard template")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	data := struct {
		User  *models.User
		OrgID string
		Stats map[string]interface{}
	}{
		User:  user,
		OrgID: orgID,
		Stats: stats,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.Execute(w, data); err != nil {
		h.logger.WithError(err).Error("Failed to execute org dashboard template")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func (h *AuthUIHandler) renderAPIManagement(w http.ResponseWriter, r *http.Request, user *models.User, orgID string, apis []*models.APIConfiguration) {
	tmpl := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>API Management - API Translation Platform</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f8f9fa; color: #333; }
        .header { background: white; border-bottom: 1px solid #dee2e6; padding: 1rem 2rem; display: flex; justify-content: space-between; align-items: center; }
        .header h1 { color: #667eea; font-size: 1.5rem; }
        .nav-links { display: flex; gap: 1rem; align-items: center; }
        .nav-links a { color: #667eea; text-decoration: none; padding: 0.5rem 1rem; border-radius: 6px; transition: background-color 0.3s; }
        .nav-links a:hover { background: #f8f9fa; }
        .btn { padding: 0.5rem 1rem; background: #667eea; color: white; text-decoration: none; border-radius: 6px; border: none; cursor: pointer; font-size: 0.9rem; }
        .btn:hover { background: #5a6fd8; }
        .btn-danger { background: #dc3545; }
        .btn-danger:hover { background: #c82333; }
        .container { max-width: 1200px; margin: 0 auto; padding: 2rem; }
        .page-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 2rem; }
        .apis-table { background: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1); overflow: hidden; }
        .apis-table table { width: 100%; border-collapse: collapse; }
        .apis-table th, .apis-table td { padding: 1rem; text-align: left; border-bottom: 1px solid #dee2e6; }
        .apis-table th { background: #f8f9fa; font-weight: 600; color: #495057; }
        .apis-table tr:hover { background: #f8f9fa; }
        .type-badge { padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.8rem; font-weight: 500; }
        .type-rest { background: #d4edda; color: #155724; }
        .type-soap { background: #d1ecf1; color: #0c5460; }
        .direction-badge { padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.8rem; font-weight: 500; }
        .direction-inbound { background: #fff3cd; color: #856404; }
        .direction-outbound { background: #f8d7da; color: #721c24; }
        .actions { display: flex; gap: 0.5rem; }
        .btn-sm { padding: 0.25rem 0.5rem; font-size: 0.8rem; }
        .breadcrumb { margin-bottom: 2rem; color: #666; }
        .breadcrumb a { color: #667eea; text-decoration: none; }
        .breadcrumb a:hover { text-decoration: underline; }
        
        /* Schema Management Modal Styles */
        .schema-management-modal { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); display: flex; align-items: center; justify-content: center; z-index: 1000; }
        .schema-modal-content { background: white; border-radius: 8px; padding: 2rem; max-width: 700px; width: 90%; max-height: 80vh; overflow-y: auto; }
        .schema-modal-content h3 { margin-bottom: 1rem; color: #333; }
        .schema-status { margin-bottom: 1.5rem; padding: 1rem; border-radius: 6px; }
        .schema-exists { color: #155724; background: #d4edda; padding: 0.5rem; border-radius: 4px; margin: 0; }
        .no-schema { color: #721c24; background: #f8d7da; padding: 0.5rem; border-radius: 4px; margin: 0; }
        .existing-fields { margin-top: 1rem; }
        .existing-fields h4 { margin-bottom: 0.5rem; color: #555; }
        .field-list { max-height: 150px; overflow-y: auto; border: 1px solid #ddd; border-radius: 4px; padding: 0.5rem; }
        .field-item-display { display: flex; justify-content: space-between; padding: 0.25rem 0.5rem; margin: 0.25rem 0; background: #f8f9fa; border-radius: 3px; }
        .field-path { font-weight: 500; }
        .field-type { font-size: 0.8rem; color: #666; font-style: italic; }
        .schema-actions h4 { margin-bottom: 0.5rem; color: #555; }
        .schema-upload-options { margin-bottom: 1rem; }
        .schema-upload-options label { display: block; margin-bottom: 0.5rem; }
        .file-upload-area { border: 2px dashed #ccc; border-radius: 8px; padding: 2rem; text-align: center; margin-bottom: 1rem; transition: all 0.3s ease; cursor: pointer; }
        .file-upload-area:hover, .file-upload-area.drag-over { border-color: #667eea; background: #f8f9ff; }
        .upload-icon { font-size: 2rem; margin-bottom: 0.5rem; }
        .or-divider { text-align: center; margin: 1rem 0; color: #666; font-weight: 500; }
        #schemaTextInput { width: 100%; min-height: 150px; font-family: 'Courier New', monospace; }
        .schema-modal-actions { display: flex; gap: 1rem; margin-top: 1.5rem; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔌 API Management</h1>
        <div class="nav-links">
            <a href="/manage/org/{{.OrgID}}/dashboard">Dashboard</a>
            <a href="/manage/org/{{.OrgID}}/apis">APIs</a>
            <a href="/manage/org/{{.OrgID}}/connectors">Connectors</a>
            <form method="POST" action="/logout" style="display: inline;">
                <button type="submit" class="btn btn-danger">Logout</button>
            </form>
        </div>
    </div>
    
    <div class="container">
        <div class="breadcrumb">
            <a href="/manage/org/{{.OrgID}}/dashboard">Organisation Dashboard</a> > API Management
        </div>
        
        <div class="page-header">
            <h2>API Configurations</h2>
            <button class="btn" onclick="toggleCreateForm()">+ Create API</button>
        </div>
        
        <!-- API Creation Form -->
        <div id="createAPIForm" style="display: none; background: white; padding: 2rem; margin: 2rem 0; border-radius: 8px; box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);">
            <h3 style="margin-bottom: 1.5rem; color: #333;">Create New API Configuration</h3>
            <form id="apiForm">
                <div class="form-row" style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 1rem;">
                    <div class="form-group">
                        <label for="apiName" style="display: block; margin-bottom: 0.5rem; font-weight: 600; color: #555;">API Name *</label>
                        <input type="text" id="apiName" name="name" required 
                               style="width: 100%; padding: 0.75rem; border: 1px solid #ddd; border-radius: 4px; font-size: 1rem;"
                               placeholder="Enter API name">
                        <div class="error-message" id="nameError" style="color: #dc3545; font-size: 0.875rem; margin-top: 0.25rem; display: none;"></div>
                    </div>
                    <div class="form-group">
                        <label for="apiType" style="display: block; margin-bottom: 0.5rem; font-weight: 600; color: #555;">API Type *</label>
                        <select id="apiType" name="type" required 
                                style="width: 100%; padding: 0.75rem; border: 1px solid #ddd; border-radius: 4px; font-size: 1rem;">
                            <option value="">Select API Type</option>
                            <option value="REST">REST</option>
                            <option value="SOAP">SOAP</option>
                        </select>
                        <div class="error-message" id="typeError" style="color: #dc3545; font-size: 0.875rem; margin-top: 0.25rem; display: none;"></div>
                    </div>
                </div>
                
                <div class="form-row" style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 1rem;">
                    <div class="form-group">
                        <label for="apiDirection" style="display: block; margin-bottom: 0.5rem; font-weight: 600; color: #555;">Direction *</label>
                        <select id="apiDirection" name="direction" required onchange="updateEndpointField()"
                                style="width: 100%; padding: 0.75rem; border: 1px solid #ddd; border-radius: 4px; font-size: 1rem;">
                            <option value="">Select Direction</option>
                            <option value="inbound">Inbound (External to This Server)</option>
                            <option value="outbound">Outbound (This Server to External)</option>
                        </select>
                        <div class="error-message" id="directionError" style="color: #dc3545; font-size: 0.875rem; margin-top: 0.25rem; display: none;"></div>
                    </div>
                    <div class="form-group">
                        <label for="apiEndpoint" id="endpointLabel" style="display: block; margin-bottom: 0.5rem; font-weight: 600; color: #555;">Endpoint *</label>
                        <input type="text" id="apiEndpoint" name="endpoint" required 
                               style="width: 100%; padding: 0.75rem; border: 1px solid #ddd; border-radius: 4px; font-size: 1rem;"
                               placeholder="Select direction first">
                        <div class="help-text" id="endpointHelp" style="color: #666; font-size: 0.875rem; margin-top: 0.25rem; display: none;"></div>
                        <div class="error-message" id="endpointError" style="color: #dc3545; font-size: 0.875rem; margin-top: 0.25rem; display: none;"></div>
                    </div>
                </div>
                
                <!-- Full URL Display for Inbound APIs -->
                <div id="fullUrlDisplay" style="display: none; background: #e7f3ff; padding: 1rem; border-radius: 4px; margin-bottom: 1rem; border-left: 4px solid #007bff;">
                    <h4 style="margin: 0 0 0.5rem 0; color: #0056b3;">External Applications Will Connect To:</h4>
                    <div id="fullUrlText" style="font-family: monospace; font-size: 1.1rem; color: #0056b3; font-weight: 600;"></div>
                    <small style="color: #666; margin-top: 0.5rem; display: block;">This is the URL that external applications should use to connect to your API.</small>
                </div>
                
                <!-- Header Configuration -->
                <div style="background: #f8f9fa; padding: 1.5rem; border-radius: 4px; margin-bottom: 1rem;">
                    <h4 style="margin: 0 0 1rem 0; color: #333;">Header Configuration</h4>
                    
                    <!-- Static Headers -->
                    <div style="margin-bottom: 1.5rem;">
                        <label style="display: block; margin-bottom: 0.5rem; font-weight: 600; color: #555;">Static Headers</label>
                        <small style="color: #666; display: block; margin-bottom: 0.5rem;">Headers that are always sent with requests (outbound) or expected (inbound)</small>
                        <div id="staticHeadersList"></div>
                        <div style="display: flex; gap: 0.5rem; margin-top: 0.5rem;">
                            <input type="text" id="newStaticHeaderName" placeholder="Header name" style="flex: 1; padding: 0.5rem; border: 1px solid #ddd; border-radius: 4px;">
                            <input type="text" id="newStaticHeaderValue" placeholder="Header value" style="flex: 1; padding: 0.5rem; border: 1px solid #ddd; border-radius: 4px;">
                            <button type="button" onclick="addStaticHeader()" style="padding: 0.5rem 1rem; background: #28a745; color: white; border: none; border-radius: 4px; cursor: pointer;">Add</button>
                        </div>
                        <div style="margin-top: 0.5rem;">
                            <small style="color: #666;">Common headers:</small>
                            <button type="button" onclick="addCommonHeader('Authorization', 'Bearer YOUR_TOKEN')" style="margin: 0.25rem; padding: 0.25rem 0.5rem; background: #e9ecef; border: 1px solid #ddd; border-radius: 4px; cursor: pointer; font-size: 0.875rem;">Authorization</button>
                            <button type="button" onclick="addCommonHeader('X-API-Key', 'YOUR_API_KEY')" style="margin: 0.25rem; padding: 0.25rem 0.5rem; background: #e9ecef; border: 1px solid #ddd; border-radius: 4px; cursor: pointer; font-size: 0.875rem;">X-API-Key</button>
                            <button type="button" onclick="addCommonHeader('Content-Type', 'application/json')" style="margin: 0.25rem; padding: 0.25rem 0.5rem; background: #e9ecef; border: 1px solid #ddd; border-radius: 4px; cursor: pointer; font-size: 0.875rem;">Content-Type</button>
                            <button type="button" onclick="addCommonHeader('Accept', 'application/json')" style="margin: 0.25rem; padding: 0.25rem 0.5rem; background: #e9ecef; border: 1px solid #ddd; border-radius: 4px; cursor: pointer; font-size: 0.875rem;">Accept</button>
                        </div>
                    </div>
                    
                    <!-- Required Headers (Inbound Only) -->
                    <div id="requiredHeadersSection" style="display: none; margin-bottom: 1.5rem;">
                        <label style="display: block; margin-bottom: 0.5rem; font-weight: 600; color: #555;">Required Headers (Validation)</label>
                        <small style="color: #666; display: block; margin-bottom: 0.5rem;">Headers that must be present in incoming requests</small>
                        <div id="requiredHeadersList"></div>
                        <div style="display: flex; gap: 0.5rem; margin-top: 0.5rem;">
                            <input type="text" id="newRequiredHeader" placeholder="Header name (e.g., X-API-Key)" style="flex: 1; padding: 0.5rem; border: 1px solid #ddd; border-radius: 4px;">
                            <button type="button" onclick="addRequiredHeader()" style="padding: 0.5rem 1rem; background: #dc3545; color: white; border: none; border-radius: 4px; cursor: pointer;">Add Required</button>
                        </div>
                    </div>
                </div>
                
                <div class="form-actions" style="display: flex; gap: 1rem; margin-top: 2rem;">
                    <button type="submit" class="btn" style="background: #667eea; color: white; padding: 0.75rem 1.5rem; border: none; border-radius: 4px; cursor: pointer; font-size: 1rem;">
                        Create API
                    </button>
                    <button type="button" onclick="cancelCreateForm()" class="btn" style="background: #6c757d; color: white; padding: 0.75rem 1.5rem; border: none; border-radius: 4px; cursor: pointer; font-size: 1rem;">
                        Cancel
                    </button>
                </div>
            </form>
        </div>
        
        <div class="apis-table">
            <table>
                <thead>
                    <tr>
                        <th>Name</th>
                        <th>Type</th>
                        <th>Direction</th>
                        <th>Endpoint</th>
                        <th>Created</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {{range .APIs}}
                    <tr>
                        <td><strong>{{.Name}}</strong></td>
                        <td>
                            {{if eq .Type "REST"}}
                            <span class="type-badge type-rest">REST</span>
                            {{else}}
                            <span class="type-badge type-soap">SOAP</span>
                            {{end}}
                        </td>
                        <td>
                            {{if eq .Direction "inbound"}}
                            <span class="direction-badge direction-inbound">Inbound</span>
                            {{else}}
                            <span class="direction-badge direction-outbound">Outbound</span>
                            {{end}}
                        </td>
                        <td>
                            {{if eq .Direction "inbound"}}
                            <div>
                                <code style="color: #0056b3;">{{.Endpoint}}</code>
                                <br>
                                <small style="color: #666;">Full URL: <code>{{$.ServerURL}}/api{{.Endpoint}}</code></small>
                            </div>
                            {{else}}
                            <code>{{.Endpoint}}</code>
                            {{end}}
                        </td>
                        <td>{{.CreatedAt.Format "2006-01-02 15:04"}}</td>
                        <td>
                            <div class="actions">
                                <button class="btn btn-sm" onclick="manageSchema('{{.ID}}', '{{.Name}}')">Schema</button>
                                <button class="btn btn-sm" onclick="editAPI('{{.ID}}', '{{.Name}}', '{{.Type}}', '{{.Direction}}', '{{.Endpoint}}')">Edit</button>
                                <button class="btn btn-sm" onclick="testAPI('{{.ID}}')">Test</button>
                                <button class="btn btn-sm btn-danger" onclick="deleteAPI('{{.ID}}')">Delete</button>
                            </div>
                        </td>
                    </tr>
                    {{end}}
                </tbody>
            </table>
        </div>
    </div>
    
    <script>
        // Form management functions
        function toggleCreateForm() {
            const form = document.getElementById('createAPIForm');
            const isVisible = form.style.display !== 'none';
            
            if (isVisible) {
                form.style.display = 'none';
            } else {
                form.style.display = 'block';
                document.getElementById('apiName').focus();
            }
        }
        
        function updateEndpointField() {
            const direction = document.getElementById('apiDirection').value;
            const endpointField = document.getElementById('apiEndpoint');
            const endpointLabel = document.getElementById('endpointLabel');
            const endpointHelp = document.getElementById('endpointHelp');
            const fullUrlDisplay = document.getElementById('fullUrlDisplay');
            
            if (direction === 'inbound') {
                endpointLabel.textContent = 'API Path *';
                endpointField.type = 'text';
                endpointField.placeholder = '/api/v1/users';
                endpointHelp.textContent = 'Enter the path that external applications will use (e.g., /api/v1/users)';
                endpointHelp.style.display = 'block';
                fullUrlDisplay.style.display = 'block';
                updateFullUrl();
            } else if (direction === 'outbound') {
                endpointLabel.textContent = 'Target URL *';
                endpointField.type = 'url';
                endpointField.placeholder = 'https://api.example.com/endpoint';
                endpointHelp.textContent = 'Enter the full URL of the external API this server will connect to';
                endpointHelp.style.display = 'block';
                fullUrlDisplay.style.display = 'none';
            } else {
                endpointLabel.textContent = 'Endpoint *';
                endpointField.placeholder = 'Select direction first';
                endpointHelp.style.display = 'none';
                fullUrlDisplay.style.display = 'none';
            }
            
            // Clear any existing value when direction changes
            endpointField.value = '';
        }
        
        function updateFullUrl() {
            const path = document.getElementById('apiEndpoint').value;
            const fullUrlText = document.getElementById('fullUrlText');
            
            if (path) {
                // Get the current server URL (you might want to make this configurable)
                const serverUrl = window.location.protocol + '//' + window.location.host;
                const cleanPath = path.startsWith('/') ? path : '/' + path;
                fullUrlText.textContent = serverUrl + '/api' + cleanPath;
            } else {
                fullUrlText.textContent = 'Enter a path to see the full URL';
            }
        }
        
        // Add event listener for real-time URL updates
        document.addEventListener('DOMContentLoaded', function() {
            const endpointField = document.getElementById('apiEndpoint');
            if (endpointField) {
                endpointField.addEventListener('input', function() {
                    const direction = document.getElementById('apiDirection').value;
                    if (direction === 'inbound') {
                        updateFullUrl();
                    }
                });
            }
        });
        
        function cancelCreateForm() {
            document.getElementById('createAPIForm').style.display = 'none';
            clearFormErrors();
            document.getElementById('apiForm').reset();
            resetHeadersConfig();
        }
        
        function clearFormErrors() {
            const errorElements = document.querySelectorAll('.error-message');
            errorElements.forEach(el => {
                el.style.display = 'none';
                el.textContent = '';
            });
            
            const inputs = document.querySelectorAll('#apiForm input, #apiForm select');
            inputs.forEach(input => {
                input.style.borderColor = '#ddd';
            });
        }
        
        function showFieldError(fieldId, message) {
            const field = document.getElementById(fieldId);
            const errorEl = document.getElementById(fieldId + 'Error');
            
            field.style.borderColor = '#dc3545';
            errorEl.textContent = message;
            errorEl.style.display = 'block';
        }
        
        function validateForm() {
            clearFormErrors();
            let isValid = true;
            
            const name = document.getElementById('apiName').value.trim();
            const type = document.getElementById('apiType').value;
            const direction = document.getElementById('apiDirection').value;
            const endpoint = document.getElementById('apiEndpoint').value.trim();
            
            if (!name) {
                showFieldError('apiName', 'API name is required');
                isValid = false;
            } else if (name.length < 3) {
                showFieldError('apiName', 'API name must be at least 3 characters');
                isValid = false;
            }
            
            if (!type) {
                showFieldError('apiType', 'API type is required');
                isValid = false;
            }
            
            if (!direction) {
                showFieldError('apiDirection', 'Direction is required');
                isValid = false;
            }
            
            if (!endpoint) {
                if (direction === 'inbound') {
                    showFieldError('apiEndpoint', 'API path is required');
                } else {
                    showFieldError('apiEndpoint', 'Target URL is required');
                }
                isValid = false;
            } else {
                if (direction === 'inbound') {
                    // Validate path format for inbound APIs
                    if (!endpoint.startsWith('/')) {
                        showFieldError('apiEndpoint', 'Path must start with / (e.g., /api/v1/users)');
                        isValid = false;
                    } else if (endpoint.length < 2) {
                        showFieldError('apiEndpoint', 'Path must be at least 2 characters');
                        isValid = false;
                    }
                } else if (direction === 'outbound') {
                    // Validate full URL for outbound APIs
                    try {
                        new URL(endpoint);
                    } catch (e) {
                        showFieldError('apiEndpoint', 'Please enter a valid URL (e.g., https://api.example.com/endpoint)');
                        isValid = false;
                    }
                }
            }
            
            return isValid;
        }
        
        // Form submission handler
        document.getElementById('apiForm').addEventListener('submit', function(e) {
            e.preventDefault();
            
            if (!validateForm()) {
                return;
            }
            
            const name = document.getElementById('apiName').value.trim();
            const type = document.getElementById('apiType').value;
            const direction = document.getElementById('apiDirection').value;
            const endpoint = document.getElementById('apiEndpoint').value.trim();
            
            createAPI(name, type, direction, endpoint);
        });
        
        function createAPI(name, type, direction, endpoint) {
            const payload = {
                name: name,
                type: type,
                direction: direction,
                endpoint: endpoint,
                authentication: {
                    type: "none",
                    parameters: {}
                },
                headers: getHeadersConfig()
            };
            
            console.log('Creating API with payload:', payload);
            
            const jsonBody = JSON.stringify(payload);
            const url = '/manage/org/{{.OrgID}}/apis';
            
            // Disable form during submission
            const submitBtn = document.querySelector('#apiForm button[type="submit"]');
            const originalText = submitBtn.textContent;
            submitBtn.disabled = true;
            submitBtn.textContent = 'Creating...';
            
            fetch(url, {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json'
                },
                body: jsonBody
            })
            .then(response => {
                if (!response.ok) {
                    return response.text().then(text => {
                        throw new Error(text || 'Failed to create API');
                    });
                }
                return response.json();
            })
            .then(data => {
                alert('API created successfully!');
                cancelCreateForm();
                location.reload();
            })
            .catch(error => {
                console.error('API creation error:', error);
                alert('Error creating API: ' + error.message);
            })
            .finally(() => {
                submitBtn.disabled = false;
                submitBtn.textContent = originalText;
            });
        }
        
        function editAPI(id, name, type, direction, endpoint) {
            showEditAPIForm(id, name, type, direction, endpoint);
        }
        
        function showEditAPIForm(id, name, type, direction, endpoint) {
            // Hide create form if visible
            document.getElementById('createAPIForm').style.display = 'none';
            
            // Show edit form
            const editForm = document.getElementById('editAPIForm');
            if (!editForm) {
                createEditAPIForm();
            }
            
            // Populate form with current values
            document.getElementById('editApiId').value = id;
            document.getElementById('editApiName').value = name;
            document.getElementById('editApiType').value = type;
            document.getElementById('editApiDirection').value = direction;
            document.getElementById('editApiEndpoint').value = endpoint;
            
            // Update endpoint field based on direction
            updateEditEndpointField();
            
            document.getElementById('editAPIForm').style.display = 'block';
            document.getElementById('editApiName').focus();
        }
        
        function createEditAPIForm() {
            const formHTML = '<div id="editAPIForm" style="display: none; background: white; padding: 2rem; margin: 2rem 0; border-radius: 8px; box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);">' +
                '<h3 style="margin-bottom: 1.5rem; color: #333;">Edit API Configuration</h3>' +
                '<form id="editApiForm">' +
                '<input type="hidden" id="editApiId" name="id">' +
                '<div class="form-row" style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 1rem;">' +
                '<div class="form-group">' +
                '<label for="editApiName" style="display: block; margin-bottom: 0.5rem; font-weight: 600; color: #555;">API Name *</label>' +
                '<input type="text" id="editApiName" name="name" required style="width: 100%; padding: 0.75rem; border: 1px solid #ddd; border-radius: 4px; font-size: 1rem;" placeholder="Enter API name">' +
                '<div class="error-message" id="editNameError" style="color: #dc3545; font-size: 0.875rem; margin-top: 0.25rem; display: none;"></div>' +
                '</div>' +
                '<div class="form-group">' +
                '<label for="editApiType" style="display: block; margin-bottom: 0.5rem; font-weight: 600; color: #555;">API Type *</label>' +
                '<select id="editApiType" name="type" required style="width: 100%; padding: 0.75rem; border: 1px solid #ddd; border-radius: 4px; font-size: 1rem;">' +
                '<option value="">Select API Type</option>' +
                '<option value="REST">REST</option>' +
                '<option value="SOAP">SOAP</option>' +
                '</select>' +
                '<div class="error-message" id="editTypeError" style="color: #dc3545; font-size: 0.875rem; margin-top: 0.25rem; display: none;"></div>' +
                '</div>' +
                '</div>' +
                '<div class="form-row" style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 1rem;">' +
                '<div class="form-group">' +
                '<label for="editApiDirection" style="display: block; margin-bottom: 0.5rem; font-weight: 600; color: #555;">Direction *</label>' +
                '<select id="editApiDirection" name="direction" required onchange="updateEditEndpointField()" style="width: 100%; padding: 0.75rem; border: 1px solid #ddd; border-radius: 4px; font-size: 1rem;">' +
                '<option value="">Select Direction</option>' +
                '<option value="inbound">Inbound (External to This Server)</option>' +
                '<option value="outbound">Outbound (This Server to External)</option>' +
                '</select>' +
                '<div class="error-message" id="editDirectionError" style="color: #dc3545; font-size: 0.875rem; margin-top: 0.25rem; display: none;"></div>' +
                '</div>' +
                '<div class="form-group">' +
                '<label for="editApiEndpoint" id="editEndpointLabel" style="display: block; margin-bottom: 0.5rem; font-weight: 600; color: #555;">Endpoint *</label>' +
                '<input type="text" id="editApiEndpoint" name="endpoint" required style="width: 100%; padding: 0.75rem; border: 1px solid #ddd; border-radius: 4px; font-size: 1rem;" placeholder="Select direction first">' +
                '<div class="help-text" id="editEndpointHelp" style="color: #666; font-size: 0.875rem; margin-top: 0.25rem; display: none;"></div>' +
                '<div class="error-message" id="editEndpointError" style="color: #dc3545; font-size: 0.875rem; margin-top: 0.25rem; display: none;"></div>' +
                '</div>' +
                '</div>' +
                '<div id="editFullUrlDisplay" style="display: none; background: #e7f3ff; padding: 1rem; border-radius: 4px; margin-bottom: 1rem; border-left: 4px solid #007bff;">' +
                '<h4 style="margin: 0 0 0.5rem 0; color: #0056b3;">External Applications Will Connect To:</h4>' +
                '<div id="editFullUrlText" style="font-family: monospace; font-size: 1.1rem; color: #0056b3; font-weight: 600;"></div>' +
                '<small style="color: #666; margin-top: 0.5rem; display: block;">This is the URL that external applications should use to connect to your API.</small>' +
                '</div>' +
                '<div class="form-actions" style="display: flex; gap: 1rem; margin-top: 2rem;">' +
                '<button type="submit" class="btn" style="background: #667eea; color: white; padding: 0.75rem 1.5rem; border: none; border-radius: 4px; cursor: pointer; font-size: 1rem;">Update API</button>' +
                '<button type="button" onclick="cancelEditForm()" class="btn" style="background: #6c757d; color: white; padding: 0.75rem 1.5rem; border: none; border-radius: 4px; cursor: pointer; font-size: 1rem;">Cancel</button>' +
                '</div>' +
                '</form>' +
                '</div>';
            
            // Insert after create form
            const createForm = document.getElementById('createAPIForm');
            createForm.insertAdjacentHTML('afterend', formHTML);
            
            // Add event listeners
            document.getElementById('editApiForm').addEventListener('submit', function(e) {
                e.preventDefault();
                submitEditAPIForm();
            });
            
            document.getElementById('editApiEndpoint').addEventListener('input', function() {
                const direction = document.getElementById('editApiDirection').value;
                if (direction === 'inbound') {
                    updateEditFullUrl();
                }
            });
        }
        
        function updateEditEndpointField() {
            const direction = document.getElementById('editApiDirection').value;
            const endpointField = document.getElementById('editApiEndpoint');
            const endpointLabel = document.getElementById('editEndpointLabel');
            const endpointHelp = document.getElementById('editEndpointHelp');
            const fullUrlDisplay = document.getElementById('editFullUrlDisplay');
            
            if (direction === 'inbound') {
                endpointLabel.textContent = 'API Path *';
                endpointField.type = 'text';
                endpointField.placeholder = '/api/v1/users';
                endpointHelp.textContent = 'Enter the path that external applications will use (e.g., /api/v1/users)';
                endpointHelp.style.display = 'block';
                fullUrlDisplay.style.display = 'block';
                updateEditFullUrl();
            } else if (direction === 'outbound') {
                endpointLabel.textContent = 'Target URL *';
                endpointField.type = 'url';
                endpointField.placeholder = 'https://api.example.com/endpoint';
                endpointHelp.textContent = 'Enter the full URL of the external API this server will connect to';
                endpointHelp.style.display = 'block';
                fullUrlDisplay.style.display = 'none';
            } else {
                endpointLabel.textContent = 'Endpoint *';
                endpointField.placeholder = 'Select direction first';
                endpointHelp.style.display = 'none';
                fullUrlDisplay.style.display = 'none';
            }
        }
        
        function updateEditFullUrl() {
            const path = document.getElementById('editApiEndpoint').value;
            const fullUrlText = document.getElementById('editFullUrlText');
            
            if (path) {
                const serverUrl = window.location.protocol + '//' + window.location.host;
                const cleanPath = path.startsWith('/') ? path : '/' + path;
                fullUrlText.textContent = serverUrl + '/api' + cleanPath;
            } else {
                fullUrlText.textContent = 'Enter a path to see the full URL';
            }
        }
        
        function cancelEditForm() {
            document.getElementById('editAPIForm').style.display = 'none';
            clearEditFormErrors();
        }
        
        function clearEditFormErrors() {
            const errorElements = document.querySelectorAll('#editAPIForm .error-message');
            errorElements.forEach(el => {
                el.style.display = 'none';
                el.textContent = '';
            });
            
            const inputs = document.querySelectorAll('#editAPIForm input, #editAPIForm select');
            inputs.forEach(input => {
                input.style.borderColor = '#ddd';
            });
        }
        
        function submitEditAPIForm() {
            if (!validateEditForm()) {
                return;
            }
            
            const id = document.getElementById('editApiId').value;
            const name = document.getElementById('editApiName').value.trim();
            const type = document.getElementById('editApiType').value;
            const direction = document.getElementById('editApiDirection').value;
            const endpoint = document.getElementById('editApiEndpoint').value.trim();
            
            const payload = {
                name: name,
                type: type,
                direction: direction,
                endpoint: endpoint,
                authentication: {
                    type: "none",
                    parameters: {}
                },
                headers: {}
            };
            
            const submitBtn = document.querySelector('#editApiForm button[type="submit"]');
            const originalText = submitBtn.textContent;
            submitBtn.disabled = true;
            submitBtn.textContent = 'Updating...';
            
            fetch('/manage/org/{{.OrgID}}/apis/' + id, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            })
            .then(response => {
                if (!response.ok) {
                    return response.text().then(text => {
                        throw new Error(text || 'Failed to update API');
                    });
                }
                return response.json();
            })
            .then(data => {
                alert('API updated successfully!');
                cancelEditForm();
                location.reload();
            })
            .catch(error => {
                alert('Error updating API: ' + error.message);
            })
            .finally(() => {
                submitBtn.disabled = false;
                submitBtn.textContent = originalText;
            });
        }
        
        function validateEditForm() {
            clearEditFormErrors();
            let isValid = true;
            
            const name = document.getElementById('editApiName').value.trim();
            const type = document.getElementById('editApiType').value;
            const direction = document.getElementById('editApiDirection').value;
            const endpoint = document.getElementById('editApiEndpoint').value.trim();
            
            if (!name) {
                showEditFieldError('editApiName', 'API name is required');
                isValid = false;
            } else if (name.length < 3) {
                showEditFieldError('editApiName', 'API name must be at least 3 characters');
                isValid = false;
            }
            
            if (!type) {
                showEditFieldError('editApiType', 'API type is required');
                isValid = false;
            }
            
            if (!direction) {
                showEditFieldError('editApiDirection', 'Direction is required');
                isValid = false;
            }
            
            if (!endpoint) {
                if (direction === 'inbound') {
                    showEditFieldError('editApiEndpoint', 'API path is required');
                } else {
                    showEditFieldError('editApiEndpoint', 'Target URL is required');
                }
                isValid = false;
            } else {
                if (direction === 'inbound') {
                    if (!endpoint.startsWith('/')) {
                        showEditFieldError('editApiEndpoint', 'Path must start with / (e.g., /api/v1/users)');
                        isValid = false;
                    } else if (endpoint.length < 2) {
                        showEditFieldError('editApiEndpoint', 'Path must be at least 2 characters');
                        isValid = false;
                    }
                } else if (direction === 'outbound') {
                    try {
                        new URL(endpoint);
                    } catch (e) {
                        showEditFieldError('editApiEndpoint', 'Please enter a valid URL (e.g., https://api.example.com/endpoint)');
                        isValid = false;
                    }
                }
            }
            
            return isValid;
        }
        
        function showEditFieldError(fieldId, message) {
            const field = document.getElementById(fieldId);
            const errorEl = document.getElementById(fieldId.replace('editApi', 'edit') + 'Error');
            
            field.style.borderColor = '#dc3545';
            errorEl.textContent = message;
            errorEl.style.display = 'block';
        }
        
        function testAPI(apiId) {
            // Show test modal
            showTestModal(apiId);
        }
        
        function showTestModal(apiId) {
            // Create modal HTML
            const modalHTML = '<div id="testModal" style="position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); z-index: 1000; display: flex; align-items: center; justify-content: center;">' +
                '<div style="background: white; padding: 2rem; border-radius: 8px; max-width: 600px; width: 90%; max-height: 80%; overflow-y: auto;">' +
                '<h3 style="margin-bottom: 1rem;">Test API Configuration</h3>' +
                '<div style="margin-bottom: 1rem;">' +
                '<label style="display: block; margin-bottom: 0.5rem; font-weight: 600;">Test Method:</label>' +
                '<select id="testMethod" style="width: 100%; padding: 0.5rem; border: 1px solid #ddd; border-radius: 4px;">' +
                '<option value="GET">GET</option>' +
                '<option value="POST">POST</option>' +
                '<option value="PUT">PUT</option>' +
                '<option value="DELETE">DELETE</option>' +
                '</select>' +
                '</div>' +
                '<div style="margin-bottom: 1rem;">' +
                '<label style="display: block; margin-bottom: 0.5rem; font-weight: 600;">Test Path (optional):</label>' +
                '<input type="text" id="testPath" placeholder="/test-endpoint" style="width: 100%; padding: 0.5rem; border: 1px solid #ddd; border-radius: 4px;">' +
                '</div>' +
                '<div style="margin-bottom: 1rem;">' +
                '<label style="display: block; margin-bottom: 0.5rem; font-weight: 600;">Request Headers (JSON):</label>' +
                '<textarea id="testHeaders" rows="3" placeholder=\'{"Content-Type": "application/json"}\' style="width: 100%; padding: 0.5rem; border: 1px solid #ddd; border-radius: 4px; font-family: monospace;"></textarea>' +
                '</div>' +
                '<div style="margin-bottom: 1rem;">' +
                '<label style="display: block; margin-bottom: 0.5rem; font-weight: 600;">Request Body (for POST/PUT):</label>' +
                '<textarea id="testBody" rows="4" placeholder=\'{"key": "value"}\' style="width: 100%; padding: 0.5rem; border: 1px solid #ddd; border-radius: 4px; font-family: monospace;"></textarea>' +
                '</div>' +
                '<div id="testResults" style="margin-bottom: 1rem; display: none;">' +
                '<h4>Test Results:</h4>' +
                '<div id="testOutput" style="background: #f8f9fa; padding: 1rem; border-radius: 4px; font-family: monospace; white-space: pre-wrap; max-height: 200px; overflow-y: auto;"></div>' +
                '</div>' +
                '<div style="display: flex; gap: 1rem; justify-content: flex-end;">' +
                '<button onclick="executeAPITest(\'' + apiId + '\')" class="btn" style="background: #28a745; color: white; padding: 0.5rem 1rem; border: none; border-radius: 4px; cursor: pointer;">Run Test</button>' +
                '<button onclick="closeTestModal()" class="btn" style="background: #6c757d; color: white; padding: 0.5rem 1rem; border: none; border-radius: 4px; cursor: pointer;">Close</button>' +
                '</div>' +
                '</div>' +
                '</div>';
            
            // Add modal to page
            document.body.insertAdjacentHTML('beforeend', modalHTML);
        }
        
        function closeTestModal() {
            const modal = document.getElementById('testModal');
            if (modal) {
                modal.remove();
            }
        }
        
        function executeAPITest(apiId) {
            const method = document.getElementById('testMethod').value;
            const path = document.getElementById('testPath').value;
            const headersText = document.getElementById('testHeaders').value;
            const bodyText = document.getElementById('testBody').value;
            
            let headers = {};
            if (headersText.trim()) {
                try {
                    headers = JSON.parse(headersText);
                } catch (e) {
                    alert('Invalid JSON in headers field');
                    return;
                }
            }
            
            let body = null;
            if ((method === 'POST' || method === 'PUT') && bodyText.trim()) {
                try {
                    body = JSON.parse(bodyText);
                } catch (e) {
                    alert('Invalid JSON in body field');
                    return;
                }
            }
            
            const testPayload = {
                api_id: apiId,
                method: method,
                path: path || '',
                headers: headers,
                body: body
            };
            
            // Show loading state
            const testOutput = document.getElementById('testOutput');
            const testResults = document.getElementById('testResults');
            testResults.style.display = 'block';
            testOutput.textContent = 'Running test...';
            
            // Send test request to backend
            fetch('/manage/org/{{.OrgID}}/apis/' + apiId + '/test', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(testPayload)
            })
            .then(response => response.json())
            .then(data => {
                const output = 'Test Results:\n' +
                    'Status: ' + (data.status || 'Unknown') + '\n' +
                    'Response Time: ' + (data.response_time || 'N/A') + 'ms\n' +
                    'Response Headers: ' + JSON.stringify(data.response_headers || {}, null, 2) + '\n' +
                    'Response Body: ' + JSON.stringify(data.response_body || {}, null, 2) + '\n' +
                    (data.error ? 'Error: ' + data.error : '');
                testOutput.textContent = output;
            })
            .catch(error => {
                testOutput.textContent = 'Test failed: ' + error.message;
            });
        }
        
        function deleteAPI(apiId) {
            if (confirm('Are you sure you want to delete this API?')) {
                fetch('/manage/org/{{.OrgID}}/apis/' + apiId, {
                    method: 'DELETE'
                })
                .then(response => {
                    if (response.ok) {
                        alert('API deleted successfully!');
                        location.reload();
                    } else {
                        return response.text().then(text => {
                            throw new Error(text || 'Failed to delete API');
                        });
                    }
                })
                .catch(error => {
                    alert('Error deleting API: ' + error.message);
                });
            }
        }
        
        function toggleTestForm() {
            const form = document.getElementById('testForm');
            form.style.display = form.style.display === 'none' ? 'block' : 'none';
        }
        
        function submitTestForm() {
            const name = document.getElementById('testName').value;
            const type = document.getElementById('testType').value;
            const direction = document.getElementById('testDirection').value;
            const endpoint = document.getElementById('testEndpoint').value;
            
            console.log('Test form values:', { name, type, direction, endpoint });
            
            if (!name || !type || !direction || !endpoint) {
                alert('All fields are required');
                return;
            }
            
            // Use the same createAPI function
            createAPI(name, type, direction, endpoint);
        }

        // Schema Management Functions
        function manageSchema(apiId, apiName) {
            showSchemaManagementModal(apiId, apiName);
        }

        function showSchemaManagementModal(apiId, apiName) {
            // First, check if schema exists
            fetch('/manage/org/{{.OrgID}}/apis/' + apiId + '/schema')
                .then(response => response.json())
                .then(schema => {
                    const hasSchema = schema && schema.parsed_fields && schema.parsed_fields.length > 0;
                    showSchemaModal(apiId, apiName, hasSchema ? schema : null);
                })
                .catch(error => {
                    console.error('Error loading schema:', error);
                    showSchemaModal(apiId, apiName, null);
                });
        }

        function showSchemaModal(apiId, apiName, existingSchema) {
            const modal = document.createElement('div');
            modal.className = 'schema-management-modal';
            modal.innerHTML = '<div class="schema-modal-content">' +
                '<h3>Manage Schema for: ' + apiName + '</h3>' +
                '<div class="schema-status">' +
                    (existingSchema ? 
                        '<p class="schema-exists">✅ Schema is defined (' + existingSchema.parsed_fields.length + ' fields)</p>' +
                        '<div class="existing-fields">' +
                            '<h4>Current Fields:</h4>' +
                            '<div class="field-list">' +
                                existingSchema.parsed_fields.map(field => 
                                    '<div class="field-item-display">' +
                                        '<span class="field-path">' + field.path + '</span>' +
                                        '<span class="field-type">(' + field.type + ')</span>' +
                                    '</div>'
                                ).join('') +
                            '</div>' +
                        '</div>'
                        : '<p class="no-schema">❌ No schema defined</p>'
                    ) +
                '</div>' +
                '<div class="schema-actions">' +
                    '<h4>Schema Management Options:</h4>' +
                    '<div class="schema-upload-options">' +
                        '<label><input type="radio" name="schema_method" value="sample" checked> Upload Sample JSON Data</label>' +
                        '<label><input type="radio" name="schema_method" value="json_schema"> Upload JSON Schema</label>' +
                        '<label><input type="radio" name="schema_method" value="manual"> Define Fields Manually</label>' +
                    '</div>' +
                    '<div id="schemaUploadArea">' +
                        '<div class="file-upload-area" ondrop="dropSchemaFile(event)" ondragover="allowDrop(event)" ondragenter="dragEnter(event)" ondragleave="dragLeave(event)">' +
                            '<div class="upload-icon">📁</div>' +
                            '<p>Drag and drop a JSON file here, or</p>' +
                            '<input type="file" id="schemaFileInput" accept=".json" onchange="handleSchemaFile(event)" style="display: none;">' +
                            '<button type="button" onclick="document.getElementById(\'schemaFileInput\').click()" class="btn btn-secondary">Choose File</button>' +
                        '</div>' +
                        '<div class="or-divider">OR</div>' +
                        '<textarea id="schemaTextInput" placeholder="Paste JSON data or schema here..." rows="8"></textarea>' +
                    '</div>' +
                '</div>' +
                '<div class="schema-modal-actions">' +
                    '<button type="button" onclick="uploadSchemaForAPI(\'' + apiId + '\')" class="btn">Save Schema</button>' +
                    (existingSchema ? '<button type="button" onclick="deleteSchemaForAPI(\'' + apiId + '\')" class="btn btn-danger">Delete Schema</button>' : '') +
                    '<button type="button" onclick="closeSchemaManagementModal()" class="btn" style="background: #6c757d;">Cancel</button>' +
                '</div>' +
            '</div>';
            document.body.appendChild(modal);
        }

        function closeSchemaManagementModal() {
            const modal = document.querySelector('.schema-management-modal');
            if (modal) {
                modal.remove();
            }
        }

        function allowDrop(event) {
            event.preventDefault();
        }

        function dragEnter(event) {
            event.preventDefault();
            event.target.closest('.file-upload-area').classList.add('drag-over');
        }

        function dragLeave(event) {
            event.preventDefault();
            event.target.closest('.file-upload-area').classList.remove('drag-over');
        }

        function dropSchemaFile(event) {
            event.preventDefault();
            const uploadArea = event.target.closest('.file-upload-area');
            uploadArea.classList.remove('drag-over');
            
            const files = event.dataTransfer.files;
            if (files.length > 0) {
                handleSchemaFileUpload(files[0]);
            }
        }

        function handleSchemaFile(event) {
            const file = event.target.files[0];
            if (file) {
                handleSchemaFileUpload(file);
            }
        }

        function handleSchemaFileUpload(file) {
            if (!file.name.endsWith('.json')) {
                alert('Please select a JSON file');
                return;
            }

            const reader = new FileReader();
            reader.onload = function(e) {
                try {
                    const jsonContent = JSON.parse(e.target.result);
                    document.getElementById('schemaTextInput').value = JSON.stringify(jsonContent, null, 2);
                } catch (error) {
                    alert('Invalid JSON file: ' + error.message);
                }
            };
            reader.readAsText(file);
        }

        function uploadSchemaForAPI(apiId) {
            const method = document.querySelector('input[name="schema_method"]:checked').value;
            const schemaInput = document.getElementById('schemaTextInput').value.trim();
            
            if (!schemaInput) {
                alert('Please provide schema data');
                return;
            }

            let payload;
            try {
                const jsonData = JSON.parse(schemaInput);
                
                payload = {
                    schema_type: method === 'json_schema' ? 'json_schema' : 'custom',
                    schema_content: {
                        raw: method === 'json_schema' ? schemaInput : '',
                        sample_data: method === 'sample' ? jsonData : null,
                        description: 'Uploaded via Schema Management'
                    }
                };
            } catch (error) {
                alert('Invalid JSON: ' + error.message);
                return;
            }

            fetch('/manage/org/{{.OrgID}}/apis/' + apiId + '/schema', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(payload)
            })
            .then(response => {
                if (!response.ok) {
                    throw new Error('Failed to upload schema');
                }
                return response.json();
            })
            .then(data => {
                alert('Schema uploaded successfully! Found ' + data.parsed_fields.length + ' fields.');
                closeSchemaManagementModal();
                // Optionally refresh the page to show updated status
                // location.reload();
            })
            .catch(error => {
                console.error('Error uploading schema:', error);
                alert('Error uploading schema: ' + error.message);
            });
        }

        function deleteSchemaForAPI(apiId) {
            if (!confirm('Are you sure you want to delete this schema? This will affect field mappings that use these fields.')) {
                return;
            }

            fetch('/manage/org/{{.OrgID}}/apis/' + apiId + '/schema', {
                method: 'DELETE'
            })
            .then(response => {
                if (!response.ok) {
                    throw new Error('Failed to delete schema');
                }
                alert('Schema deleted successfully!');
                closeSchemaManagementModal();
            })
            .catch(error => {
                console.error('Error deleting schema:', error);
                alert('Error deleting schema: ' + error.message);
            });
        }
        
        // Header Management Functions
        let staticHeaders = {};
        let requiredHeaders = [];
        
        function updateHeaderVisibility() {
            const direction = document.getElementById('apiDirection').value;
            const requiredSection = document.getElementById('requiredHeadersSection');
            
            if (direction === 'inbound') {
                requiredSection.style.display = 'block';
            } else {
                requiredSection.style.display = 'none';
            }
        }
        
        // Add event listener for direction changes
        document.addEventListener('DOMContentLoaded', function() {
            const directionField = document.getElementById('apiDirection');
            if (directionField) {
                directionField.addEventListener('change', updateHeaderVisibility);
            }
        });
        
        function addStaticHeader() {
            const nameField = document.getElementById('newStaticHeaderName');
            const valueField = document.getElementById('newStaticHeaderValue');
            const name = nameField.value.trim();
            const value = valueField.value.trim();
            
            if (!name || !value) {
                alert('Please enter both header name and value');
                return;
            }
            
            staticHeaders[name] = value;
            nameField.value = '';
            valueField.value = '';
            renderStaticHeaders();
        }
        
        function addCommonHeader(name, value) {
            document.getElementById('newStaticHeaderName').value = name;
            document.getElementById('newStaticHeaderValue').value = value;
        }
        
        function removeStaticHeader(name) {
            delete staticHeaders[name];
            renderStaticHeaders();
        }
        
        function renderStaticHeaders() {
            const container = document.getElementById('staticHeadersList');
            container.innerHTML = '';
            
            Object.entries(staticHeaders).forEach(([name, value]) => {
                const headerDiv = document.createElement('div');
                headerDiv.style.cssText = 'display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.5rem; padding: 0.5rem; background: white; border: 1px solid #ddd; border-radius: 4px;';
                headerDiv.innerHTML = ` + "`" + `
                    <code style="flex: 1; color: #0056b3;">${name}: ${value}</code>
                    <button type="button" onclick="removeStaticHeader('${name}')" style="padding: 0.25rem 0.5rem; background: #dc3545; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 0.75rem;">Remove</button>
                ` + "`" + `;
                container.appendChild(headerDiv);
            });
        }
        
        function addRequiredHeader() {
            const field = document.getElementById('newRequiredHeader');
            const name = field.value.trim();
            
            if (!name) {
                alert('Please enter a header name');
                return;
            }
            
            if (requiredHeaders.includes(name)) {
                alert('Header already in required list');
                return;
            }
            
            requiredHeaders.push(name);
            field.value = '';
            renderRequiredHeaders();
        }
        
        function removeRequiredHeader(name) {
            requiredHeaders = requiredHeaders.filter(h => h !== name);
            renderRequiredHeaders();
        }
        
        function renderRequiredHeaders() {
            const container = document.getElementById('requiredHeadersList');
            container.innerHTML = '';
            
            requiredHeaders.forEach(name => {
                const headerDiv = document.createElement('div');
                headerDiv.style.cssText = 'display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.5rem; padding: 0.5rem; background: white; border: 1px solid #ddd; border-radius: 4px;';
                headerDiv.innerHTML = ` + "`" + `
                    <code style="flex: 1; color: #dc3545;">${name} (required)</code>
                    <button type="button" onclick="removeRequiredHeader('${name}')" style="padding: 0.25rem 0.5rem; background: #dc3545; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 0.75rem;">Remove</button>
                ` + "`" + `;
                container.appendChild(headerDiv);
            });
        }
        
        function getHeadersConfig() {
            return {
                static: staticHeaders,
                required: requiredHeaders,
                dynamic: {}
            };
        }
        
        function resetHeadersConfig() {
            staticHeaders = {};
            requiredHeaders = [];
            renderStaticHeaders();
            renderRequiredHeaders();
        }
    </script>
</body>
</html>`

	t, err := template.New("apis").Parse(tmpl)
	if err != nil {
		h.logger.WithError(err).Error("Failed to parse APIs template")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Get server URL for inbound API display
	serverURL := fmt.Sprintf("%s://%s", getScheme(r), r.Host)

	data := struct {
		User      *models.User
		OrgID     string
		APIs      []*models.APIConfiguration
		ServerURL string
	}{
		User:      user,
		OrgID:     orgID,
		APIs:      apis,
		ServerURL: serverURL,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.Execute(w, data); err != nil {
		h.logger.WithError(err).Error("Failed to execute APIs template")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func (h *AuthUIHandler) renderConnectorManagement(w http.ResponseWriter, user *models.User, orgID string, connectors []*models.Connector) {
	// Get APIs for the dropdowns
	apis, err := h.configService.GetAPIConfigurationsByOrganisation(context.Background(), orgID)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get APIs for connector management")
		apis = []*models.APIConfiguration{} // Empty slice as fallback
	}

	tmpl := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Connector Management - API Translation Platform</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f8f9fa; color: #333; }
        .header { background: white; border-bottom: 1px solid #dee2e6; padding: 1rem 2rem; display: flex; justify-content: space-between; align-items: center; }
        .header h1 { color: #667eea; font-size: 1.5rem; }
        .nav-links { display: flex; gap: 1rem; align-items: center; }
        .nav-links a { color: #667eea; text-decoration: none; padding: 0.5rem 1rem; border-radius: 6px; transition: background-color 0.3s; }
        .nav-links a:hover { background: #f8f9fa; }
        .btn { padding: 0.5rem 1rem; background: #667eea; color: white; text-decoration: none; border-radius: 6px; border: none; cursor: pointer; font-size: 0.9rem; }
        .btn:hover { background: #5a6fd8; }
        .btn-danger { background: #dc3545; }
        .btn-danger:hover { background: #c82333; }
        .container { max-width: 1200px; margin: 0 auto; padding: 2rem; }
        .page-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 2rem; }
        .connectors-table { background: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1); overflow: hidden; }
        .connectors-table table { width: 100%; border-collapse: collapse; }
        .connectors-table th, .connectors-table td { padding: 1rem; text-align: left; border-bottom: 1px solid #dee2e6; }
        .connectors-table th { background: #f8f9fa; font-weight: 600; color: #495057; }
        .connectors-table tr:hover { background: #f8f9fa; }
        .status-badge { padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.8rem; font-weight: 500; }
        .status-active { background: #d4edda; color: #155724; }
        .status-inactive { background: #f8d7da; color: #721c24; }
        .actions { display: flex; gap: 0.5rem; }
        .btn-sm { padding: 0.25rem 0.5rem; font-size: 0.8rem; }
        .breadcrumb { margin-bottom: 2rem; color: #666; }
        .breadcrumb a { color: #667eea; text-decoration: none; }
        .breadcrumb a:hover { text-decoration: underline; }
        .form-group { margin-bottom: 1rem; }
        .form-group label { display: block; margin-bottom: 0.5rem; font-weight: 600; color: #555; }
        .form-group input, .form-group select, .form-group textarea { width: 100%; padding: 0.75rem; border: 1px solid #ddd; border-radius: 4px; font-size: 1rem; }
        .form-group textarea { min-height: 120px; font-family: 'Courier New', monospace; }
        .form-row { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; }
        .error-message { color: #dc3545; font-size: 0.875rem; margin-top: 0.25rem; display: none; }
        .api-search { position: relative; }
        .api-dropdown { position: absolute; top: 100%; left: 0; right: 0; background: white; border: 1px solid #ddd; border-top: none; border-radius: 0 0 4px 4px; max-height: 200px; overflow-y: auto; z-index: 1000; display: none; }
        .api-option { padding: 0.75rem; cursor: pointer; border-bottom: 1px solid #eee; }
        .api-option:hover { background: #f8f9fa; }
        .api-option:last-child { border-bottom: none; }
        
        /* Field Mapping Styles */
        .radio-group { display: flex; gap: 1rem; }
        .radio-group label { display: flex; align-items: center; gap: 0.5rem; font-weight: normal; }
        .field-mapping-container { border: 1px solid #ddd; border-radius: 8px; padding: 1rem; background: #f9f9f9; }
        .mapping-columns { display: grid; grid-template-columns: 1fr 1fr; gap: 2rem; margin-bottom: 1rem; }
        .inbound-fields, .outbound-fields { background: white; border-radius: 6px; padding: 1rem; }
        .inbound-fields h4, .outbound-fields h4 { margin-bottom: 0.5rem; color: #555; font-size: 0.9rem; }
        .field-list { min-height: 150px; border: 1px dashed #ccc; border-radius: 4px; padding: 0.5rem; transition: background-color 0.3s; }
        .field-list.drag-over { background-color: #e3f2fd; border-color: #667eea; }
        .field-item { padding: 0.5rem; margin: 0.25rem 0; background: #e3f2fd; border-radius: 4px; cursor: grab; user-select: none; transition: all 0.3s; }
        .field-item:hover { background: #bbdefb; transform: translateX(2px); }
        .field-item:active { cursor: grabbing; }
        .field-item.dragging { opacity: 0.5; }
        .field-item.drop-target { background: #c8e6c9; border: 2px solid #4caf50; }
        .mappings-list { background: white; border-radius: 6px; padding: 1rem; }
        .mappings-container { min-height: 100px; border: 1px dashed #ccc; border-radius: 4px; padding: 0.5rem; margin-bottom: 1rem; }
        .mapping-item { display: flex; align-items: center; justify-content: space-between; padding: 0.5rem; margin: 0.25rem 0; background: #f0f8ff; border-radius: 4px; }
        .mapping-path { font-family: 'Courier New', monospace; font-size: 0.9rem; }
        .transform-script { font-size: 0.8rem; color: #666; font-style: italic; }
        .btn-remove { background: #dc3545; color: white; border: none; border-radius: 50%; width: 24px; height: 24px; cursor: pointer; font-size: 0.8rem; }
        .btn-remove:hover { background: #c82333; }
        .text-muted { color: #6c757d; font-style: italic; }
        
        /* Schema Modal Styles */
        .schema-modal { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); display: flex; align-items: center; justify-content: center; z-index: 1000; }
        .schema-modal-content { background: white; border-radius: 8px; padding: 2rem; max-width: 600px; width: 90%; max-height: 80vh; overflow-y: auto; }
        .schema-modal-content h3 { margin-bottom: 1rem; color: #333; }
        .schema-upload-options { margin-bottom: 1rem; }
        .schema-upload-options label { display: block; margin-bottom: 0.5rem; }
        .schema-modal-actions { display: flex; gap: 1rem; margin-top: 1rem; }
        #schemaInput { width: 100%; min-height: 200px; font-family: 'Courier New', monospace; }
        
        /* Enhanced Field Styles */
        .field-item { display: flex; justify-content: space-between; align-items: center; }
        .field-path { font-weight: 500; }
        .field-type { font-size: 0.8rem; color: #666; font-style: italic; }
        .no-schema-message { text-align: center; padding: 1rem; }
        .no-schema-message .btn { margin-top: 0.5rem; }
        .api-info { font-size: 0.875rem; color: #666; margin-top: 0.25rem; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔗 Connector Management</h1>
        <div class="nav-links">
            <a href="/manage/org/{{.OrgID}}/dashboard">Dashboard</a>
            <a href="/manage/org/{{.OrgID}}/apis">APIs</a>
            <a href="/manage/org/{{.OrgID}}/connectors">Connectors</a>
            <form method="POST" action="/logout" style="display: inline;">
                <button type="submit" class="btn btn-danger">Logout</button>
            </form>
        </div>
    </div>
    
    <div class="container">
        <div class="breadcrumb">
            <a href="/manage/org/{{.OrgID}}/dashboard">Organisation Dashboard</a> > Connector Management
        </div>
        
        <div class="page-header">
            <h2>Data Transformation Connectors</h2>
            <button class="btn" onclick="toggleCreateConnectorForm()">+ Create Connector</button>
        </div>
        
        <!-- Connector Creation Form -->
        <div id="createConnectorForm" style="display: none; background: white; padding: 2rem; margin: 2rem 0; border-radius: 8px; box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);">
            <h3 style="margin-bottom: 1.5rem; color: #333;">Create New Connector</h3>
            <form id="connectorForm">
                <div class="form-group">
                    <label for="connectorName">Connector Name *</label>
                    <input type="text" id="connectorName" name="name" required placeholder="Enter connector name">
                    <div class="error-message" id="nameError"></div>
                </div>
                
                <div class="form-row">
                    <div class="form-group">
                        <label for="inboundAPI">Inbound API *</label>
                        <div class="api-search">
                            <input type="text" id="inboundAPI" name="inbound_api" required placeholder="Search for inbound API..." autocomplete="off" onkeyup="filterAPIs('inbound')">
                            <input type="hidden" id="inboundAPIId" name="inbound_api_id">
                            <div class="api-dropdown" id="inboundDropdown"></div>
                        </div>
                        <div class="error-message" id="inboundError"></div>
                    </div>
                    <div class="form-group">
                        <label for="outboundAPI">Outbound API *</label>
                        <div class="api-search">
                            <input type="text" id="outboundAPI" name="outbound_api" required placeholder="Search for outbound API..." autocomplete="off" onkeyup="filterAPIs('outbound')">
                            <input type="hidden" id="outboundAPIId" name="outbound_api_id">
                            <div class="api-dropdown" id="outboundDropdown"></div>
                        </div>
                        <div class="error-message" id="outboundError"></div>
                    </div>
                </div>
                
                <div class="form-group">
                    <label>Transformation Method</label>
                    <div class="radio-group">
                        <label>
                            <input type="radio" name="transformation_method" value="script" checked onchange="toggleTransformationMethod()">
                            Python Script
                        </label>
                        <label>
                            <input type="radio" name="transformation_method" value="mappings" onchange="toggleTransformationMethod()">
                            Field Mappings (Drag & Drop)
                        </label>
                    </div>
                </div>

                <div id="scriptSection" class="form-group">
                    <label for="pythonScript">Python Transformation Script</label>
                    <textarea id="pythonScript" name="python_script" placeholder="# Enter your Python transformation script here
# Example:
def transform(input_data):
    # Transform the input data
    output_data = {
        'transformed': input_data
    }
    return output_data"></textarea>
                    <div class="error-message" id="scriptError"></div>
                </div>

                <div id="mappingsSection" class="form-group" style="display: none;">
                    <label>Field Mappings</label>
                    <div class="field-mapping-container">
                        <div class="mapping-columns">
                            <div class="inbound-fields">
                                <h4>Inbound API Fields</h4>
                                <div id="inboundFields" class="field-list">
                                    <p class="text-muted">Select an inbound API to see available fields</p>
                                </div>
                            </div>
                            <div class="outbound-fields">
                                <h4>Outbound API Fields</h4>
                                <div id="outboundFields" class="field-list" ondrop="drop(event)" ondragover="allowDrop(event)" ondragenter="allowDrop(event)">
                                    <p class="text-muted">Select an outbound API to see available fields</p>
                                </div>
                            </div>
                        </div>
                        <div class="mappings-list">
                            <h4>Field Mappings</h4>
                            <div id="fieldMappings" class="mappings-container">
                                <p class="text-muted">No mappings created yet. Drag fields from left to right to create mappings.</p>
                            </div>
                            <button type="button" onclick="addFieldMapping()" class="btn btn-secondary">Add Manual Mapping</button>
                        </div>
                    </div>
                    <div class="error-message" id="mappingsError"></div>
                </div>
                
                <div class="form-group">
                    <label>
                        <input type="checkbox" id="isActive" name="is_active" checked style="width: auto; margin-right: 0.5rem;">
                        Active (connector will process requests)
                    </label>
                </div>
                
                <div class="form-actions" style="display: flex; gap: 1rem; margin-top: 2rem;">
                    <button type="submit" class="btn" style="background: #667eea; color: white; padding: 0.75rem 1.5rem; border: none; border-radius: 4px; cursor: pointer; font-size: 1rem;">
                        Create Connector
                    </button>
                    <button type="button" onclick="cancelCreateConnectorForm()" class="btn" style="background: #6c757d; color: white; padding: 0.75rem 1.5rem; border: none; border-radius: 4px; cursor: pointer; font-size: 1rem;">
                        Cancel
                    </button>
                </div>
            </form>
        </div>
        
        <!-- Connector Edit Form -->
        <div id="editConnectorForm" style="display: none; background: white; padding: 2rem; margin: 2rem 0; border-radius: 8px; box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);">
            <h3 style="margin-bottom: 1.5rem; color: #333;">Edit Connector</h3>
            <form id="editConnectorFormElement">
                <input type="hidden" id="editConnectorId" name="id">
                
                <div class="form-group">
                    <label for="editConnectorName">Connector Name *</label>
                    <input type="text" id="editConnectorName" name="name" required placeholder="Enter connector name">
                    <div class="error-message" id="editNameError"></div>
                </div>
                
                <div class="form-row">
                    <div class="form-group">
                        <label for="editInboundAPI">Inbound API *</label>
                        <div class="api-search">
                            <input type="text" id="editInboundAPI" name="inbound_api" required placeholder="Search for inbound API..." autocomplete="off" onkeyup="filterAPIs('editInbound')">
                            <input type="hidden" id="editInboundAPIId" name="inbound_api_id">
                            <div class="api-dropdown" id="editInboundDropdown"></div>
                        </div>
                        <div class="error-message" id="editInboundError"></div>
                    </div>
                    <div class="form-group">
                        <label for="editOutboundAPI">Outbound API *</label>
                        <div class="api-search">
                            <input type="text" id="editOutboundAPI" name="outbound_api" required placeholder="Search for outbound API..." autocomplete="off" onkeyup="filterAPIs('editOutbound')">
                            <input type="hidden" id="editOutboundAPIId" name="outbound_api_id">
                            <div class="api-dropdown" id="editOutboundDropdown"></div>
                        </div>
                        <div class="error-message" id="editOutboundError"></div>
                    </div>
                </div>
                
                <div class="form-group">
                    <label>Transformation Method</label>
                    <div class="radio-group">
                        <label>
                            <input type="radio" name="edit_transformation_method" value="script" checked onchange="toggleEditTransformationMethod()">
                            Python Script
                        </label>
                        <label>
                            <input type="radio" name="edit_transformation_method" value="mappings" onchange="toggleEditTransformationMethod()">
                            Field Mappings (Drag & Drop)
                        </label>
                    </div>
                </div>

                <div id="editScriptSection" class="form-group">
                    <label for="editPythonScript">Python Transformation Script</label>
                    <textarea id="editPythonScript" name="python_script" placeholder="# Enter your Python transformation script here
# Example:
def transform(input_data):
    # Transform the input data
    output_data = {
        'transformed': input_data
    }
    return output_data"></textarea>
                    <div class="error-message" id="editScriptError"></div>
                </div>

                <div id="editMappingsSection" class="form-group" style="display: none;">
                    <label>Field Mappings</label>
                    <div class="field-mapping-container">
                        <div class="mapping-columns">
                            <div class="inbound-fields">
                                <h4>Inbound API Fields</h4>
                                <div id="editInboundFields" class="field-list">
                                    <p class="text-muted">Select an inbound API to see available fields</p>
                                </div>
                            </div>
                            <div class="outbound-fields">
                                <h4>Outbound API Fields</h4>
                                <div id="editOutboundFields" class="field-list" ondrop="editDrop(event)" ondragover="allowDrop(event)" ondragenter="allowDrop(event)">
                                    <p class="text-muted">Select an outbound API to see available fields</p>
                                </div>
                            </div>
                        </div>
                        <div class="mappings-list">
                            <h4>Field Mappings</h4>
                            <div id="editFieldMappings" class="mappings-container">
                                <p class="text-muted">No mappings created yet. Drag fields from left to right to create mappings.</p>
                            </div>
                            <button type="button" onclick="addEditFieldMapping()" class="btn btn-secondary">Add Manual Mapping</button>
                        </div>
                    </div>
                    <div class="error-message" id="editMappingsError"></div>
                </div>
                
                <div class="form-group">
                    <label>
                        <input type="checkbox" id="editIsActive" name="is_active" checked style="width: auto; margin-right: 0.5rem;">
                        Active (connector will process requests)
                    </label>
                </div>
                
                <div class="form-actions" style="display: flex; gap: 1rem; margin-top: 2rem;">
                    <button type="submit" class="btn" style="background: #667eea; color: white; padding: 0.75rem 1.5rem; border: none; border-radius: 4px; cursor: pointer; font-size: 1rem;">
                        Update Connector
                    </button>
                    <button type="button" onclick="cancelEditConnectorForm()" class="btn" style="background: #6c757d; color: white; padding: 0.75rem 1.5rem; border: none; border-radius: 4px; cursor: pointer; font-size: 1rem;">
                        Cancel
                    </button>
                </div>
            </form>
        </div>
        
        <div class="connectors-table">
            <table>
                <thead>
                    <tr>
                        <th>Name</th>
                        <th>Inbound API</th>
                        <th>Outbound API</th>
                        <th>Status</th>
                        <th>Created</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {{range .Connectors}}
                    <tr>
                        <td><strong>{{.Name}}</strong></td>
                        <td>
                            {{if .InboundAPI}}
                            <div>
                                <strong>{{.InboundAPI.Name}}</strong>
                                <div style="font-size: 0.875rem; color: #666;">{{.InboundAPI.Type}} - {{.InboundAPI.Direction}}</div>
                            </div>
                            {{else}}
                            <code>{{.InboundAPIID}}</code>
                            {{end}}
                        </td>
                        <td>
                            {{if .OutboundAPI}}
                            <div>
                                <strong>{{.OutboundAPI.Name}}</strong>
                                <div style="font-size: 0.875rem; color: #666;">{{.OutboundAPI.Type}} - {{.OutboundAPI.Direction}}</div>
                            </div>
                            {{else}}
                            <code>{{.OutboundAPIID}}</code>
                            {{end}}
                        </td>
                        <td>
                            {{if .IsActive}}
                            <span class="status-badge status-active">Active</span>
                            {{else}}
                            <span class="status-badge status-inactive">Inactive</span>
                            {{end}}
                        </td>
                        <td>{{.CreatedAt.Format "2006-01-02 15:04"}}</td>
                        <td>
                            <div class="actions">
                                <button class="btn btn-sm" onclick="editConnector('{{.ID}}', '{{.Name}}', '{{.InboundAPIID}}', '{{.OutboundAPIID}}', {{.IsActive}})">Edit</button>
                                <button class="btn btn-sm" onclick="editScript('{{.ID}}')">Script</button>
                                <button class="btn btn-sm" onclick="testConnector('{{.ID}}')">Test</button>
                                <button class="btn btn-sm btn-danger" onclick="deleteConnector('{{.ID}}')">Delete</button>
                            </div>
                        </td>
                    </tr>
                    {{end}}
                </tbody>
            </table>
        </div>
    </div>
    
    <script>
        // Store APIs data for searching
        const apisData = [
            {{range .APIs}}
            {
                id: '{{.ID}}',
                name: '{{.Name}}',
                type: '{{.Type}}',
                direction: '{{.Direction}}',
                endpoint: '{{.Endpoint}}'
            },
            {{end}}
        ];
        
        function toggleCreateConnectorForm() {
            const form = document.getElementById('createConnectorForm');
            const isVisible = form.style.display !== 'none';
            
            if (isVisible) {
                form.style.display = 'none';
            } else {
                form.style.display = 'block';
                document.getElementById('connectorName').focus();
            }
        }
        
        function cancelCreateConnectorForm() {
            document.getElementById('createConnectorForm').style.display = 'none';
            clearFormErrors();
            document.getElementById('connectorForm').reset();
            document.getElementById('inboundAPIId').value = '';
            document.getElementById('outboundAPIId').value = '';
        }
        
        function filterAPIs(type) {
            const input = document.getElementById(type + 'API');
            const dropdown = document.getElementById(type + 'Dropdown');
            const searchTerm = input.value.toLowerCase();
            
            if (searchTerm.length < 1) {
                dropdown.style.display = 'none';
                return;
            }
            
            const filteredAPIs = apisData.filter(api => 
                api.name.toLowerCase().includes(searchTerm) ||
                api.type.toLowerCase().includes(searchTerm) ||
                api.direction.toLowerCase().includes(searchTerm)
            );
            
            dropdown.innerHTML = '';
            
            if (filteredAPIs.length === 0) {
                dropdown.innerHTML = '<div class="api-option">No APIs found</div>';
            } else {
                filteredAPIs.forEach(api => {
                    const option = document.createElement('div');
                    option.className = 'api-option';
                    option.innerHTML = '<div><strong>' + api.name + '</strong></div>' +
                        '<div class="api-info">' + api.type + ' - ' + api.direction + ' - ' + api.endpoint + '</div>';
                    option.onclick = () => selectAPI(type, api);
                    dropdown.appendChild(option);
                });
            }
            
            dropdown.style.display = 'block';
        }
        
        function selectAPI(type, api) {
            document.getElementById(type + 'API').value = api.name;
            document.getElementById(type + 'APIId').value = api.id;
            document.getElementById(type + 'Dropdown').style.display = 'none';
            
            // Load fields if we're in mappings mode
            const isEdit = type.startsWith('edit');
            const transformationMethod = isEdit ? 
                document.querySelector('input[name="edit_transformation_method"]:checked')?.value :
                document.querySelector('input[name="transformation_method"]:checked')?.value;
                
            if (transformationMethod === 'mappings') {
                if (isEdit) {
                    loadEditAPIFields();
                } else {
                    loadAPIFields();
                }
            }
        }
        
        // Hide dropdowns when clicking outside
        document.addEventListener('click', function(e) {
            if (!e.target.closest('.api-search')) {
                document.querySelectorAll('.api-dropdown').forEach(dropdown => {
                    dropdown.style.display = 'none';
                });
            }
        });
        
        function clearFormErrors() {
            const errorElements = document.querySelectorAll('.error-message');
            errorElements.forEach(el => {
                el.style.display = 'none';
                el.textContent = '';
            });
            
            const inputs = document.querySelectorAll('#connectorForm input, #connectorForm select, #connectorForm textarea');
            inputs.forEach(input => {
                input.style.borderColor = '#ddd';
            });
        }
        
        function showFieldError(fieldId, message) {
            const field = document.getElementById(fieldId);
            const errorEl = document.getElementById(fieldId.replace(/API$/, '') + 'Error');
            
            if (field) field.style.borderColor = '#dc3545';
            if (errorEl) {
                errorEl.textContent = message;
                errorEl.style.display = 'block';
            }
        }
        
        function validateConnectorForm() {
            clearFormErrors();
            let isValid = true;
            
            const name = document.getElementById('connectorName').value.trim();
            const inboundAPIId = document.getElementById('inboundAPIId').value;
            const outboundAPIId = document.getElementById('outboundAPIId').value;
            const script = document.getElementById('pythonScript').value.trim();
            
            if (!name) {
                showFieldError('connectorName', 'Connector name is required');
                isValid = false;
            } else if (name.length < 3) {
                showFieldError('connectorName', 'Connector name must be at least 3 characters');
                isValid = false;
            }
            
            if (!inboundAPIId) {
                showFieldError('inboundAPI', 'Please select an inbound API');
                isValid = false;
            }
            
            if (!outboundAPIId) {
                showFieldError('outboundAPI', 'Please select an outbound API');
                isValid = false;
            }
            
            const transformationMethod = document.querySelector('input[name="transformation_method"]:checked').value;
            
            if (transformationMethod === 'script') {
                if (!script) {
                    showFieldError('pythonScript', 'Python script is required when using script transformation');
                    isValid = false;
                } else if (script.length < 10) {
                    showFieldError('pythonScript', 'Python script must be at least 10 characters');
                    isValid = false;
                }
            } else if (transformationMethod === 'mappings') {
                // Validate field mappings
                const mappings = getFieldMappings();
                if (mappings.length === 0) {
                    showFieldError('mappingsError', 'At least one field mapping is required');
                    isValid = false;
                }
            }
            
            return isValid;
        }
        
        // Form submission handler
        document.getElementById('connectorForm').addEventListener('submit', function(e) {
            e.preventDefault();
            
            if (!validateConnectorForm()) {
                return;
            }
            
            const name = document.getElementById('connectorName').value.trim();
            const inboundAPIId = document.getElementById('inboundAPIId').value;
            const outboundAPIId = document.getElementById('outboundAPIId').value;
            const script = document.getElementById('pythonScript').value.trim();
            const isActive = document.getElementById('isActive').checked;
            
            createConnector(name, inboundAPIId, outboundAPIId, script, isActive);
        });
        
        function createConnector(name, inboundAPIId, outboundAPIId, script, isActive) {
            const transformationMethod = document.querySelector('input[name="transformation_method"]:checked').value;
            
            const payload = {
                name: name,
                inbound_api_id: inboundAPIId,
                outbound_api_id: outboundAPIId,
                is_active: isActive
            };
            
            if (transformationMethod === 'script') {
                payload.python_script = script;
            } else if (transformationMethod === 'mappings') {
                payload.field_mappings = getFieldMappings();
            }
            
            const submitBtn = document.querySelector('#connectorForm button[type="submit"]');
            const originalText = submitBtn.textContent;
            submitBtn.disabled = true;
            submitBtn.textContent = 'Creating...';
            
            fetch('/manage/org/{{.OrgID}}/connectors', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            })
            .then(response => {
                if (!response.ok) {
                    return response.text().then(text => {
                        throw new Error(text || 'Failed to create connector');
                    });
                }
                return response.json();
            })
            .then(data => {
                alert('Connector created successfully!');
                cancelCreateConnectorForm();
                location.reload();
            })
            .catch(error => {
                alert('Error creating connector: ' + error.message);
            })
            .finally(() => {
                submitBtn.disabled = false;
                submitBtn.textContent = originalText;
            });
        }
        
        function editConnector(id, name, inboundAPIId, outboundAPIId, isActive) {
            // Hide create form if visible
            document.getElementById('createConnectorForm').style.display = 'none';
            
            // Show edit form
            const editForm = document.getElementById('editConnectorForm');
            editForm.style.display = 'block';
            
            // Populate form fields
            document.getElementById('editConnectorId').value = id;
            document.getElementById('editConnectorName').value = name;
            document.getElementById('editIsActive').checked = isActive;
            
            // Set API selections
            document.getElementById('editInboundAPIId').value = inboundAPIId;
            document.getElementById('editOutboundAPIId').value = outboundAPIId;
            
            // Find and set API names
            const inboundAPI = apisData.find(api => api.id === inboundAPIId);
            const outboundAPI = apisData.find(api => api.id === outboundAPIId);
            
            if (inboundAPI) {
                document.getElementById('editInboundAPI').value = inboundAPI.name;
            }
            if (outboundAPI) {
                document.getElementById('editOutboundAPI').value = outboundAPI.name;
            }
            
            // Load existing connector data to determine transformation method
            loadConnectorForEdit(id);
            
            // Scroll to form
            editForm.scrollIntoView({ behavior: 'smooth' });
        }
        
        function loadConnectorForEdit(connectorId) {
            // Fetch connector details to populate the form
            fetch('/manage/org/{{.OrgID}}/connectors/' + connectorId)
                .then(response => {
                    if (!response.ok) {
                        throw new Error('Failed to load connector details');
                    }
                    return response.json();
                })
                .then(connector => {
                    // Determine transformation method based on existing data
                    if (connector.field_mappings && connector.field_mappings.length > 0) {
                        // Has field mappings
                        document.querySelector('input[name="edit_transformation_method"][value="mappings"]').checked = true;
                        editFieldMappings = [...connector.field_mappings];
                        toggleEditTransformationMethod();
                        renderEditFieldMappings();
                    } else if (connector.python_script) {
                        // Has Python script
                        document.querySelector('input[name="edit_transformation_method"][value="script"]').checked = true;
                        // Debug: Log the original and unescaped script
                        console.log('Original script from API:', connector.python_script);
                        const unescapedScript = unescapePythonScript(connector.python_script);
                        console.log('Unescaped script:', unescapedScript);
                        document.getElementById('editPythonScript').value = unescapedScript;
                        toggleEditTransformationMethod();
                    } else {
                        // Default to script method
                        document.querySelector('input[name="edit_transformation_method"][value="script"]').checked = true;
                        toggleEditTransformationMethod();
                    }
                })
                .catch(error => {
                    console.error('Error loading connector details:', error);
                    // Default to script method if we can't load details
                    document.querySelector('input[name="edit_transformation_method"][value="script"]').checked = true;
                    toggleEditTransformationMethod();
                });
        }
        
        function cancelEditConnectorForm() {
            document.getElementById('editConnectorForm').style.display = 'none';
            clearEditFormErrors();
            document.getElementById('editConnectorFormElement').reset();
            document.getElementById('editInboundAPIId').value = '';
            document.getElementById('editOutboundAPIId').value = '';
            editFieldMappings = [];
        }
        
        function editScript(connectorId) {
            const script = prompt('Enter Python transformation script:');
            if (!script) return;
            
            alert('Script editing functionality would be implemented here for connector: ' + connectorId);
        }
        
        function testConnector(connectorId) {
            alert('Connector testing functionality would be implemented here for connector: ' + connectorId);
        }
        
        function deleteConnector(connectorId) {
            if (confirm('Are you sure you want to delete this connector?')) {
                fetch('/manage/org/{{.OrgID}}/connectors/' + connectorId, {
                    method: 'DELETE'
                })
                .then(response => {
                    if (response.ok) {
                        alert('Connector deleted successfully!');
                        location.reload();
                    } else {
                        return response.text().then(text => {
                            throw new Error(text || 'Failed to delete connector');
                        });
                    }
                })
                .catch(error => {
                    alert('Error deleting connector: ' + error.message);
                });
            }
        }

        // Field mapping functions
        function toggleTransformationMethod() {
            const method = document.querySelector('input[name="transformation_method"]:checked').value;
            const scriptSection = document.getElementById('scriptSection');
            const mappingsSection = document.getElementById('mappingsSection');
            
            if (method === 'script') {
                scriptSection.style.display = 'block';
                mappingsSection.style.display = 'none';
                document.getElementById('pythonScript').required = true;
            } else {
                scriptSection.style.display = 'none';
                mappingsSection.style.display = 'block';
                document.getElementById('pythonScript').required = false;
            }
            
            // Load API fields when switching to mappings
            if (method === 'mappings') {
                loadAPIFields();
            }
        }

        function loadAPIFields() {
            const inboundAPIId = document.getElementById('inboundAPIId').value;
            const outboundAPIId = document.getElementById('outboundAPIId').value;
            
            if (inboundAPIId) {
                loadFieldsForAPI(inboundAPIId, 'inboundFields');
            }
            if (outboundAPIId) {
                loadFieldsForAPI(outboundAPIId, 'outboundFields');
            }
        }

        function loadFieldsForAPI(apiId, containerId) {
            if (!apiId) return;
            
            const container = document.getElementById(containerId);
            container.innerHTML = '<p class="text-muted">Loading fields...</p>';
            
            // Fetch API schema fields
            fetch('/manage/org/{{.OrgID}}/apis/' + apiId + '/schema')
                .then(response => {
                    if (!response.ok) {
                        throw new Error('Failed to load API schema');
                    }
                    return response.json();
                })
                .then(schema => {
                    if (schema && schema.parsed_fields && schema.parsed_fields.length > 0) {
                        const isOutbound = containerId === 'outboundFields';
                        container.innerHTML = schema.parsed_fields.map(field => 
                            '<div class="field-item" draggable="true" ondragstart="dragStart(event)" data-field="' + field.path + '" title="' + (field.description || field.type) + '"' +
                            (isOutbound ? ' ondrop="dropOnField(event)" ondragover="allowDrop(event)"' : '') + '>' +
                                '<span class="field-path">' + field.path + '</span>' +
                                '<span class="field-type">(' + field.type + ')</span>' +
                            '</div>'
                        ).join('');
                        
                        // Add drop zone functionality to outbound container
                        if (isOutbound) {
                            container.setAttribute('ondrop', 'drop(event)');
                            container.setAttribute('ondragover', 'allowDrop(event)');
                            container.setAttribute('ondragenter', 'allowDrop(event)');
                        }
                    } else {
                        container.innerHTML = '<div class="no-schema-message">' +
                            '<p class="text-muted">No schema defined for this API.</p>' +
                            '<button type="button" onclick="showSchemaUpload(\'' + apiId + '\')" class="btn btn-sm">Define Schema</button>' +
                        '</div>';
                    }
                })
                .catch(error => {
                    console.error('Error loading API fields:', error);
                    container.innerHTML = '<div class="no-schema-message">' +
                        '<p class="text-muted">Error loading fields. <a href="#" onclick="loadFieldsForAPI(\'' + apiId + '\', \'' + containerId + '\')">Retry</a></p>' +
                        '<button type="button" onclick="showSchemaUpload(\'' + apiId + '\')" class="btn btn-sm">Define Schema</button>' +
                    '</div>';
                });
        }

        let fieldMappings = [];
        let editFieldMappings = [];

        function addFieldMapping() {
            const inboundField = prompt('Enter inbound field path (e.g., user.name):');
            if (!inboundField) return;
            
            const outboundField = prompt('Enter outbound field path (e.g., customer.fullName):');
            if (!outboundField) return;
            
            const transformScript = prompt('Enter optional Python transformation (leave empty for direct mapping):') || '';
            
            const mapping = {
                inbound_field_path: inboundField,
                outbound_field_path: outboundField,
                transform_script: transformScript
            };
            
            fieldMappings.push(mapping);
            renderFieldMappings();
        }

        function renderFieldMappings() {
            const container = document.getElementById('fieldMappings');
            if (fieldMappings.length === 0) {
                container.innerHTML = '<p class="text-muted">No mappings created yet. Drag fields from left to right to create mappings.</p>';
                return;
            }
            
            container.innerHTML = fieldMappings.map((mapping, index) => 
                '<div class="mapping-item">' +
                    '<span class="mapping-path">' + mapping.inbound_field_path + ' → ' + mapping.outbound_field_path + '</span>' +
                    (mapping.transform_script ? '<span class="transform-script">Transform: ' + mapping.transform_script + '</span>' : '') +
                    '<button type="button" onclick="removeFieldMapping(' + index + ')" class="btn-remove">×</button>' +
                '</div>'
            ).join('');
        }

        function removeFieldMapping(index) {
            fieldMappings.splice(index, 1);
            renderFieldMappings();
        }

        function getFieldMappings() {
            return fieldMappings;
        }

        // Drag and drop functionality
        function dragStart(event) {
            event.dataTransfer.setData('text/plain', event.target.dataset.field);
            event.target.style.opacity = '0.5';
        }

        function allowDrop(event) {
            event.preventDefault();
            event.currentTarget.style.backgroundColor = '#e3f2fd';
        }

        function dragLeave(event) {
            event.currentTarget.style.backgroundColor = '';
        }

        function drop(event) {
            event.preventDefault();
            event.currentTarget.style.backgroundColor = '';
            
            const inboundField = event.dataTransfer.getData('text/plain');
            if (!inboundField) return;
            
            const outboundField = prompt('Enter outbound field path for: ' + inboundField);
            
            if (outboundField) {
                const transformScript = prompt('Enter optional Python transformation (leave empty for direct mapping):') || '';
                
                const mapping = {
                    inbound_field_path: inboundField,
                    outbound_field_path: outboundField,
                    transform_script: transformScript
                };
                
                fieldMappings.push(mapping);
                renderFieldMappings();
            }
        }

        function dropOnField(event) {
            event.preventDefault();
            event.stopPropagation();
            event.currentTarget.style.backgroundColor = '';
            
            const inboundField = event.dataTransfer.getData('text/plain');
            const outboundField = event.currentTarget.dataset.field;
            
            if (!inboundField || !outboundField) return;
            
            // Check if mapping already exists
            const existingMapping = fieldMappings.find(m => 
                m.inbound_field_path === inboundField && m.outbound_field_path === outboundField
            );
            
            if (existingMapping) {
                alert('Mapping already exists: ' + inboundField + ' → ' + outboundField);
                return;
            }
            
            const transformScript = prompt('Enter optional Python transformation for ' + inboundField + ' → ' + outboundField + ' (leave empty for direct mapping):') || '';
            
            const mapping = {
                inbound_field_path: inboundField,
                outbound_field_path: outboundField,
                transform_script: transformScript
            };
            
            fieldMappings.push(mapping);
            renderFieldMappings();
            
            // Visual feedback
            event.currentTarget.style.backgroundColor = '#c8e6c9';
            setTimeout(() => {
                event.currentTarget.style.backgroundColor = '';
            }, 1000);
        }

        // Reset drag opacity on drag end
        document.addEventListener('dragend', function(event) {
            event.target.style.opacity = '';
        });

        // Schema upload functionality
        function showSchemaUpload(apiId) {
            const modal = document.createElement('div');
            modal.className = 'schema-modal';
            modal.innerHTML = '<div class="schema-modal-content">' +
                '<h3>Define API Schema</h3>' +
                '<div class="schema-upload-options">' +
                    '<label><input type="radio" name="schema_method" value="sample" checked> Upload Sample JSON Data</label>' +
                    '<label><input type="radio" name="schema_method" value="json_schema"> Upload JSON Schema</label>' +
                    '<label><input type="radio" name="schema_method" value="manual"> Define Fields Manually</label>' +
                '</div>' +
                '<div id="schemaUploadArea">' +
                    '<textarea id="schemaInput" placeholder="Paste sample JSON data here..." rows="10"></textarea>' +
                '</div>' +
                '<div class="schema-modal-actions">' +
                    '<button type="button" onclick="uploadSchema(\'' + apiId + '\')" class="btn">Upload Schema</button>' +
                    '<button type="button" onclick="closeSchemaModal()" class="btn" style="background: #6c757d;">Cancel</button>' +
                '</div>' +
            '</div>';
            document.body.appendChild(modal);
        }

        function closeSchemaModal() {
            const modal = document.querySelector('.schema-modal');
            if (modal) {
                modal.remove();
            }
        }

        function uploadSchema(apiId) {
            const method = document.querySelector('input[name="schema_method"]:checked').value;
            const schemaInput = document.getElementById('schemaInput').value.trim();
            
            if (!schemaInput) {
                alert('Please provide schema data');
                return;
            }

            const payload = {
                schema_type: method === 'json_schema' ? 'json_schema' : 'custom',
                schema_content: {
                    raw: method === 'json_schema' ? schemaInput : '',
                    sample_data: method === 'sample' ? JSON.parse(schemaInput) : null,
                    description: 'Uploaded via UI'
                }
            };

            fetch('/manage/org/{{.OrgID}}/apis/' + apiId + '/schema', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(payload)
            })
            .then(response => {
                if (!response.ok) {
                    throw new Error('Failed to upload schema');
                }
                return response.json();
            })
            .then(data => {
                alert('Schema uploaded successfully!');
                closeSchemaModal();
                loadAPIFields(); // Reload fields
            })
            .catch(error => {
                console.error('Error uploading schema:', error);
                alert('Error uploading schema: ' + error.message);
            });
        }

        // Edit form specific functions
        function toggleEditTransformationMethod() {
            const method = document.querySelector('input[name="edit_transformation_method"]:checked').value;
            const scriptSection = document.getElementById('editScriptSection');
            const mappingsSection = document.getElementById('editMappingsSection');
            
            if (method === 'script') {
                scriptSection.style.display = 'block';
                mappingsSection.style.display = 'none';
                document.getElementById('editPythonScript').required = true;
            } else {
                scriptSection.style.display = 'none';
                mappingsSection.style.display = 'block';
                document.getElementById('editPythonScript').required = false;
            }
            
            // Load API fields when switching to mappings
            if (method === 'mappings') {
                loadEditAPIFields();
            }
        }

        function loadEditAPIFields() {
            const inboundAPIId = document.getElementById('editInboundAPIId').value;
            const outboundAPIId = document.getElementById('editOutboundAPIId').value;
            
            if (inboundAPIId) {
                loadFieldsForAPI(inboundAPIId, 'editInboundFields');
            }
            if (outboundAPIId) {
                loadFieldsForAPI(outboundAPIId, 'editOutboundFields');
            }
        }

        function addEditFieldMapping() {
            const inboundField = prompt('Enter inbound field path (e.g., user.name):');
            if (!inboundField) return;
            
            const outboundField = prompt('Enter outbound field path (e.g., customer.fullName):');
            if (!outboundField) return;
            
            const transformScript = prompt('Enter optional Python transformation (leave empty for direct mapping):') || '';
            
            const mapping = {
                inbound_field_path: inboundField,
                outbound_field_path: outboundField,
                transform_script: transformScript
            };
            
            editFieldMappings.push(mapping);
            renderEditFieldMappings();
        }

        function renderEditFieldMappings() {
            const container = document.getElementById('editFieldMappings');
            if (editFieldMappings.length === 0) {
                container.innerHTML = '<p class="text-muted">No mappings created yet. Drag fields from left to right to create mappings.</p>';
                return;
            }
            
            container.innerHTML = editFieldMappings.map((mapping, index) => 
                '<div class="mapping-item">' +
                    '<span class="mapping-path">' + mapping.inbound_field_path + ' → ' + mapping.outbound_field_path + '</span>' +
                    (mapping.transform_script ? '<span class="transform-script">Transform: ' + mapping.transform_script + '</span>' : '') +
                    '<button type="button" onclick="removeEditFieldMapping(' + index + ')" class="btn-remove">×</button>' +
                '</div>'
            ).join('');
        }

        function removeEditFieldMapping(index) {
            editFieldMappings.splice(index, 1);
            renderEditFieldMappings();
        }

        function getEditFieldMappings() {
            return editFieldMappings;
        }

        function editDrop(event) {
            event.preventDefault();
            event.currentTarget.style.backgroundColor = '';
            
            const inboundField = event.dataTransfer.getData('text/plain');
            if (!inboundField) return;
            
            const outboundField = prompt('Enter outbound field path for: ' + inboundField);
            
            if (outboundField) {
                const transformScript = prompt('Enter optional Python transformation (leave empty for direct mapping):') || '';
                
                const mapping = {
                    inbound_field_path: inboundField,
                    outbound_field_path: outboundField,
                    transform_script: transformScript
                };
                
                editFieldMappings.push(mapping);
                renderEditFieldMappings();
            }
        }

        function clearEditFormErrors() {
            const errorElements = document.querySelectorAll('#editConnectorFormElement .error-message');
            errorElements.forEach(el => {
                el.style.display = 'none';
                el.textContent = '';
            });
            
            const inputs = document.querySelectorAll('#editConnectorFormElement input, #editConnectorFormElement select, #editConnectorFormElement textarea');
            inputs.forEach(input => {
                input.style.borderColor = '#ddd';
            });
        }

        function validateEditConnectorForm() {
            clearEditFormErrors();
            let isValid = true;
            
            const name = document.getElementById('editConnectorName').value.trim();
            const inboundAPIId = document.getElementById('editInboundAPIId').value;
            const outboundAPIId = document.getElementById('editOutboundAPIId').value;
            const script = document.getElementById('editPythonScript').value.trim();
            
            if (!name) {
                showEditFieldError('editConnectorName', 'Connector name is required');
                isValid = false;
            } else if (name.length < 3) {
                showEditFieldError('editConnectorName', 'Connector name must be at least 3 characters');
                isValid = false;
            }
            
            if (!inboundAPIId) {
                showEditFieldError('editInboundAPI', 'Please select an inbound API');
                isValid = false;
            }
            
            if (!outboundAPIId) {
                showEditFieldError('editOutboundAPI', 'Please select an outbound API');
                isValid = false;
            }
            
            const transformationMethod = document.querySelector('input[name="edit_transformation_method"]:checked').value;
            
            if (transformationMethod === 'script') {
                if (!script) {
                    showEditFieldError('editPythonScript', 'Python script is required when using script transformation');
                    isValid = false;
                } else if (script.length < 10) {
                    showEditFieldError('editPythonScript', 'Python script must be at least 10 characters');
                    isValid = false;
                }
            } else if (transformationMethod === 'mappings') {
                // Validate field mappings
                const mappings = getEditFieldMappings();
                if (mappings.length === 0) {
                    showEditFieldError('editMappingsError', 'At least one field mapping is required');
                    isValid = false;
                }
            }
            
            return isValid;
        }

        function showEditFieldError(fieldId, message) {
            const field = document.getElementById(fieldId);
            const errorEl = document.getElementById(fieldId.replace(/API$/, '') + 'Error');
            
            if (field) field.style.borderColor = '#dc3545';
            if (errorEl) {
                errorEl.textContent = message;
                errorEl.style.display = 'block';
            }
        }

        // Edit form submission handler
        document.addEventListener('DOMContentLoaded', function() {
            const editForm = document.getElementById('editConnectorFormElement');
            if (editForm) {
                editForm.addEventListener('submit', function(e) {
                    e.preventDefault();
                    
                    if (!validateEditConnectorForm()) {
                        return;
                    }
                    
                    const id = document.getElementById('editConnectorId').value;
                    const name = document.getElementById('editConnectorName').value.trim();
                    const inboundAPIId = document.getElementById('editInboundAPIId').value;
                    const outboundAPIId = document.getElementById('editOutboundAPIId').value;
                    const script = document.getElementById('editPythonScript').value.trim();
                    const isActive = document.getElementById('editIsActive').checked;
                    
                    updateConnector(id, name, inboundAPIId, outboundAPIId, script, isActive);
                });
            }
        });

        function updateConnector(id, name, inboundAPIId, outboundAPIId, script, isActive) {
            const transformationMethod = document.querySelector('input[name="edit_transformation_method"]:checked').value;
            
            const payload = {
                name: name,
                inbound_api_id: inboundAPIId,
                outbound_api_id: outboundAPIId,
                is_active: isActive
            };
            
            if (transformationMethod === 'script') {
                payload.python_script = script;
                payload.field_mappings = []; // Clear field mappings when using script
            } else if (transformationMethod === 'mappings') {
                payload.field_mappings = getEditFieldMappings();
                payload.python_script = ''; // Clear script when using mappings
            }
            
            const submitBtn = document.querySelector('#editConnectorFormElement button[type="submit"]');
            const originalText = submitBtn.textContent;
            submitBtn.disabled = true;
            submitBtn.textContent = 'Updating...';
            
            fetch('/manage/org/{{.OrgID}}/connectors/' + id, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            })
            .then(response => {
                if (!response.ok) {
                    return response.text().then(text => {
                        throw new Error(text || 'Failed to update connector');
                    });
                }
                return response.json();
            })
            .then(data => {
                alert('Connector updated successfully!');
                cancelEditConnectorForm();
                location.reload();
            })
            .catch(error => {
                alert('Error updating connector: ' + error.message);
            })
            .finally(() => {
                submitBtn.disabled = false;
                submitBtn.textContent = originalText;
            });
        }

        // Helper function to unescape Python script for display
        function unescapePythonScript(script) {
            if (!script) return '';
            
            // Unescape common JSON escape sequences
            return script
                .replace(/\\n/g, '\n')      // Newlines
                .replace(/\\r/g, '\r')      // Carriage returns
                .replace(/\\t/g, '\t')      // Tabs
                .replace(/\\"/g, '"')       // Double quotes
                .replace(/\\\\/g, '\\');    // Backslashes (must be last)
        }

        // Update API selection handlers
        document.addEventListener('DOMContentLoaded', function() {
            const inboundSelect = document.getElementById('inboundAPIId');
            const outboundSelect = document.getElementById('outboundAPIId');
            
            if (inboundSelect) {
                inboundSelect.addEventListener('change', loadAPIFields);
            }
            if (outboundSelect) {
                outboundSelect.addEventListener('change', loadAPIFields);
            }
        });
    </script>
</body>
</html>`

	t, err := template.New("connectors").Parse(tmpl)
	if err != nil {
		h.logger.WithError(err).Error("Failed to parse connectors template")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	data := struct {
		User       *models.User
		OrgID      string
		Connectors []*models.Connector
		APIs       []*models.APIConfiguration
	}{
		User:       user,
		OrgID:      orgID,
		Connectors: connectors,
		APIs:       apis,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.Execute(w, data); err != nil {
		h.logger.WithError(err).Error("Failed to execute connectors template")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func (h *AuthUIHandler) renderOrgUsersManagement(w http.ResponseWriter, user *models.User, orgID string, users []*models.User) {
	tmpl := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Organisation Users - API Translation Platform</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f8f9fa; color: #333; }
        .header { background: white; border-bottom: 1px solid #dee2e6; padding: 1rem 2rem; display: flex; justify-content: space-between; align-items: center; }
        .header h1 { color: #667eea; font-size: 1.5rem; }
        .nav-links { display: flex; gap: 1rem; align-items: center; }
        .nav-links a { color: #667eea; text-decoration: none; padding: 0.5rem 1rem; border-radius: 6px; transition: background-color 0.3s; }
        .nav-links a:hover { background: #f8f9fa; }
        .btn { padding: 0.5rem 1rem; background: #667eea; color: white; text-decoration: none; border-radius: 6px; border: none; cursor: pointer; font-size: 0.9rem; }
        .btn:hover { background: #5a6fd8; }
        .btn-danger { background: #dc3545; }
        .btn-danger:hover { background: #c82333; }
        .container { max-width: 1200px; margin: 0 auto; padding: 2rem; }
        .page-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 2rem; }
        .users-table { background: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1); overflow: hidden; }
        .users-table table { width: 100%; border-collapse: collapse; }
        .users-table th, .users-table td { padding: 1rem; text-align: left; border-bottom: 1px solid #dee2e6; }
        .users-table th { background: #f8f9fa; font-weight: 600; color: #495057; }
        .users-table tr:hover { background: #f8f9fa; }
        .status-badge { padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.8rem; font-weight: 500; }
        .status-active { background: #d4edda; color: #155724; }
        .status-inactive { background: #f8d7da; color: #721c24; }
        .role-badge { padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.8rem; font-weight: 500; }
        .role-org { background: #fff3cd; color: #856404; }
        .actions { display: flex; gap: 0.5rem; }
        .btn-sm { padding: 0.25rem 0.5rem; font-size: 0.8rem; }
        .breadcrumb { margin-bottom: 2rem; color: #666; }
        .breadcrumb a { color: #667eea; text-decoration: none; }
        .breadcrumb a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="header">
        <h1>👥 Organisation Users</h1>
        <div class="nav-links">
            <a href="/manage/org/{{.OrgID}}/dashboard">Dashboard</a>
            <a href="/manage/org/{{.OrgID}}/users">Users</a>
            <form method="POST" action="/logout" style="display: inline;">
                <button type="submit" class="btn btn-danger">Logout</button>
            </form>
        </div>
    </div>
    
    <div class="container">
        <div class="breadcrumb">
            <a href="/manage/org/{{.OrgID}}/dashboard">Organisation Dashboard</a> > Users Management
        </div>
        
        <div class="page-header">
            <h2>Organisation Users</h2>
            <button class="btn" onclick="showCreateUserForm()">+ Add User</button>
        </div>
        
        <div class="users-table">
            <table>
                <thead>
                    <tr>
                        <th>Username</th>
                        <th>Email</th>
                        <th>Role</th>
                        <th>Status</th>
                        <th>Created</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {{range .Users}}
                    <tr>
                        <td><strong>{{.Username}}</strong></td>
                        <td>{{.Email}}</td>
                        <td>
                            <span class="role-badge role-org">Org Admin</span>
                        </td>
                        <td>
                            {{if .IsActive}}
                            <span class="status-badge status-active">Active</span>
                            {{else}}
                            <span class="status-badge status-inactive">Inactive</span>
                            {{end}}
                        </td>
                        <td>{{.CreatedAt.Format "2006-01-02 15:04"}}</td>
                        <td>
                            <div class="actions">
                                <button class="btn btn-sm" onclick="editUser('{{.ID}}', '{{.Username}}', '{{.Email}}')">Edit</button>
                                <button class="btn btn-sm" onclick="resetPassword('{{.ID}}')">Reset Password</button>
                                <button class="btn btn-sm btn-danger" onclick="removeUser('{{.ID}}')">Remove</button>
                            </div>
                        </td>
                    </tr>
                    {{end}}
                </tbody>
            </table>
        </div>
    </div>
    
    <script>
        function showCreateUserForm() {
            const username = prompt('Enter username:');
            if (!username) return;
            const email = prompt('Enter email:');
            if (!email) return;
            const password = prompt('Enter password:');
            if (!password) return;
            
            createUser(username, email, password);
        }
        
        function createUser(username, email, password) {
            fetch('/manage/admin/users', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    username: username,
                    email: email,
                    role: 'org_admin',
                    organisation_id: '{{.OrgID}}',
                    password: password
                })
            })
            .then(response => {
                if (!response.ok) {
                    return response.text().then(text => {
                        throw new Error(text || 'Failed to create user');
                    });
                }
                return response.json();
            })
            .then(data => {
                alert('User created successfully!');
                location.reload();
            })
            .catch(error => {
                alert('Error creating user: ' + error.message);
            });
        }
        
        function editUser(id, username, email) {
            const newUsername = prompt('Enter username:', username);
            if (!newUsername) return;
            const newEmail = prompt('Enter email:', email);
            if (!newEmail) return;
            
            fetch('/manage/admin/users/' + id, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    username: newUsername,
                    email: newEmail,
                    role: 'org_admin'
                })
            })
            .then(response => {
                if (!response.ok) {
                    return response.text().then(text => {
                        throw new Error(text || 'Failed to update user');
                    });
                }
                return response.json();
            })
            .then(data => {
                alert('User updated successfully!');
                location.reload();
            })
            .catch(error => {
                alert('Error updating user: ' + error.message);
            });
        }
        
        function resetPassword(userId) {
            const newPassword = prompt('Enter new password:');
            if (!newPassword) return;
            
            alert('Password reset functionality would be implemented here for user: ' + userId);
        }
        
        function removeUser(userId) {
            if (confirm('Are you sure you want to remove this user from the organisation?')) {
                fetch('/manage/admin/users/' + userId, {
                    method: 'DELETE'
                })
                .then(response => {
                    if (response.ok) {
                        alert('User removed successfully!');
                        location.reload();
                    } else {
                        alert('Error removing user');
                    }
                })
                .catch(error => {
                    alert('Error removing user: ' + error);
                });
            }
        }
    </script>
</body>
</html>`

	t, err := template.New("org_users").Parse(tmpl)
	if err != nil {
		h.logger.WithError(err).Error("Failed to parse org users template")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	data := struct {
		User  *models.User
		OrgID string
		Users []*models.User
	}{
		User:  user,
		OrgID: orgID,
		Users: users,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.Execute(w, data); err != nil {
		h.logger.WithError(err).Error("Failed to execute org users template")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// Additional CRUD handlers
func (h *AuthUIHandler) HandleUpdateOrganisation(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	orgID := vars["orgID"]

	var org models.Organisation
	if err := json.NewDecoder(r.Body).Decode(&org); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	org.ID = orgID
	updatedOrg, err := h.configService.UpdateOrganisation(r.Context(), &org)
	if err != nil {
		h.logger.WithError(err).Error("Failed to update organisation")
		http.Error(w, "Failed to update organisation", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(updatedOrg)
}

func (h *AuthUIHandler) HandleDeleteOrganisation(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	orgID := vars["orgID"]

	err := h.configService.DeleteOrganisation(r.Context(), orgID)
	if err != nil {
		h.logger.WithError(err).Error("Failed to delete organisation")
		http.Error(w, "Failed to delete organisation", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *AuthUIHandler) HandleUpdateUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID := vars["userID"]

	var user models.User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	user.ID = userID
	err := h.userService.UpdateUser(r.Context(), &user)
	if err != nil {
		h.logger.WithError(err).Error("Failed to update user")
		http.Error(w, "Failed to update user", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}

func (h *AuthUIHandler) HandleDeleteUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID := vars["userID"]

	err := h.userService.DeleteUser(r.Context(), userID)
	if err != nil {
		h.logger.WithError(err).Error("Failed to delete user")
		http.Error(w, "Failed to delete user", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *AuthUIHandler) HandleCreateAPI(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	orgID := vars["orgID"]

	// Log request details for debugging
	h.logger.WithField("content_length", r.ContentLength).
		WithField("content_type", r.Header.Get("Content-Type")).
		WithField("method", r.Method).
		WithField("org_id", orgID).
		Info("Received API creation request")

	var api models.APIConfiguration
	if err := h.decodeJSONRequest(r, &api); err != nil {
		h.logger.WithError(err).Error("Failed to decode API configuration JSON")
		http.Error(w, fmt.Sprintf("Invalid JSON: %v", err), http.StatusBadRequest)
		return
	}

	// Basic validation
	if api.Name == "" {
		http.Error(w, "API name is required", http.StatusBadRequest)
		return
	}
	if api.Type == "" {
		http.Error(w, "API type is required", http.StatusBadRequest)
		return
	}
	if api.Direction == "" {
		http.Error(w, "API direction is required", http.StatusBadRequest)
		return
	}
	if api.Endpoint == "" {
		http.Error(w, "API endpoint is required", http.StatusBadRequest)
		return
	}

	// Process endpoint based on direction
	if api.Direction == "inbound" {
		// For inbound APIs, ensure the path starts with /
		if !strings.HasPrefix(api.Endpoint, "/") {
			api.Endpoint = "/" + api.Endpoint
		}
		// Store just the path for inbound APIs
		h.logger.WithField("inbound_path", api.Endpoint).Info("Processing inbound API path")
	} else if api.Direction == "outbound" {
		// For outbound APIs, validate it's a full URL
		if _, err := url.Parse(api.Endpoint); err != nil {
			http.Error(w, "Invalid URL format for outbound API", http.StatusBadRequest)
			return
		}
		h.logger.WithField("outbound_url", api.Endpoint).Info("Processing outbound API URL")
	}

	api.OrganisationID = orgID
	createdAPI, err := h.configService.CreateAPIConfiguration(r.Context(), &api)
	if err != nil {
		h.logger.WithError(err).Error("Failed to create API configuration")
		// Check if it's a validation error
		if err.Error() != "" {
			http.Error(w, fmt.Sprintf("Failed to create API configuration: %v", err), http.StatusBadRequest)
		} else {
			http.Error(w, "Failed to create API configuration", http.StatusInternalServerError)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(createdAPI)
}

func (h *AuthUIHandler) HandleUpdateAPI(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	apiID := vars["apiID"]
	orgID := vars["orgID"]

	var api models.APIConfiguration
	if err := json.NewDecoder(r.Body).Decode(&api); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	api.ID = apiID
	api.OrganisationID = orgID
	updatedAPI, err := h.configService.UpdateAPIConfiguration(r.Context(), &api)
	if err != nil {
		h.logger.WithError(err).Error("Failed to update API configuration")
		http.Error(w, "Failed to update API configuration", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(updatedAPI)
}

func (h *AuthUIHandler) HandleDeleteAPI(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	apiID := vars["apiID"]

	err := h.configService.DeleteAPIConfiguration(r.Context(), apiID)
	if err != nil {
		h.logger.WithError(err).Error("Failed to delete API configuration")
		http.Error(w, "Failed to delete API configuration", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *AuthUIHandler) HandleTestAPI(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	apiID := vars["apiID"]

	// Parse test request
	var testReq struct {
		APIID   string                 `json:"api_id"`
		Method  string                 `json:"method"`
		Path    string                 `json:"path"`
		Headers map[string]string      `json:"headers"`
		Body    map[string]interface{} `json:"body"`
	}

	if err := h.decodeJSONRequest(r, &testReq); err != nil {
		h.logger.WithError(err).Error("Failed to decode test request JSON")
		http.Error(w, fmt.Sprintf("Invalid JSON: %v", err), http.StatusBadRequest)
		return
	}

	// Get API configuration
	apiConfig, err := h.configService.GetAPIConfiguration(r.Context(), apiID)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get API configuration for test")
		http.Error(w, "API configuration not found", http.StatusNotFound)
		return
	}

	// Perform the test
	testResult := h.performAPITest(apiConfig, testReq.Method, testReq.Path, testReq.Headers, testReq.Body)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(testResult)
}

func (h *AuthUIHandler) performAPITest(apiConfig *models.APIConfiguration, method, path string, headers map[string]string, body map[string]interface{}) map[string]interface{} {
	startTime := time.Now()

	// Build test URL
	testURL := apiConfig.Endpoint

	// For inbound APIs, the endpoint is just a path, so we need to construct a full URL
	if apiConfig.Direction == "inbound" {
		// Construct full URL using the server's base URL
		// For inbound APIs, the actual endpoint is /api{endpoint}
		testURL = "http://localhost:8088/api" + apiConfig.Endpoint
	}

	if path != "" {
		if !strings.HasSuffix(testURL, "/") && !strings.HasPrefix(path, "/") {
			testURL += "/"
		}
		testURL += strings.TrimPrefix(path, "/")
	}

	// Prepare request body
	var reqBody io.Reader
	if body != nil && (method == "POST" || method == "PUT") {
		bodyBytes, err := json.Marshal(body)
		if err != nil {
			return map[string]interface{}{
				"status":        "error",
				"error":         "Failed to marshal request body: " + err.Error(),
				"response_time": time.Since(startTime).Milliseconds(),
			}
		}
		reqBody = bytes.NewReader(bodyBytes)
	}

	// Create HTTP request
	req, err := http.NewRequest(method, testURL, reqBody)
	if err != nil {
		return map[string]interface{}{
			"status":        "error",
			"error":         "Failed to create request: " + err.Error(),
			"response_time": time.Since(startTime).Milliseconds(),
		}
	}

	// Set headers from API config
	allHeaders := apiConfig.Headers.GetAllHeaders()
	for key, value := range allHeaders {
		req.Header.Set(key, value)
	}

	// Set additional test headers
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	// Set default Content-Type for POST/PUT if not specified
	if (method == "POST" || method == "PUT") && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}

	// Perform request with timeout
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	resp, err := client.Do(req)
	responseTime := time.Since(startTime).Milliseconds()

	if err != nil {
		return map[string]interface{}{
			"status":        "error",
			"error":         "Request failed: " + err.Error(),
			"response_time": responseTime,
		}
	}
	defer resp.Body.Close()

	// Read response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return map[string]interface{}{
			"status":        "error",
			"error":         "Failed to read response: " + err.Error(),
			"response_time": responseTime,
			"status_code":   resp.StatusCode,
		}
	}

	// Parse response headers
	respHeaders := make(map[string]string)
	for key, values := range resp.Header {
		if len(values) > 0 {
			respHeaders[key] = values[0]
		}
	}

	// Try to parse response body as JSON
	var respBodyParsed interface{}
	if err := json.Unmarshal(respBody, &respBodyParsed); err != nil {
		// If not JSON, return as string
		respBodyParsed = string(respBody)
	}

	return map[string]interface{}{
		"status":           "success",
		"status_code":      resp.StatusCode,
		"response_time":    responseTime,
		"response_headers": respHeaders,
		"response_body":    respBodyParsed,
	}
}

func (h *AuthUIHandler) HandleCreateConnector(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	orgID := vars["orgID"]

	var connector models.Connector
	if err := h.decodeJSONRequest(r, &connector); err != nil {
		h.logger.WithError(err).Error("Failed to decode connector JSON")
		http.Error(w, fmt.Sprintf("Invalid JSON: %v", err), http.StatusBadRequest)
		return
	}

	connector.OrganisationID = orgID
	createdConnector, err := h.configService.CreateConnector(r.Context(), &connector)
	if err != nil {
		h.logger.WithError(err).Error("Failed to create connector")
		http.Error(w, "Failed to create connector", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(createdConnector)
}

func (h *AuthUIHandler) HandleGetConnector(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	connectorID := vars["connectorID"]

	connector, err := h.configService.GetConnector(r.Context(), connectorID)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get connector")
		http.Error(w, "Failed to get connector", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(connector)
}

func (h *AuthUIHandler) HandleUpdateConnector(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	connectorID := vars["connectorID"]
	orgID := vars["orgID"]

	var connector models.Connector
	if err := h.decodeJSONRequest(r, &connector); err != nil {
		h.logger.WithError(err).Error("Failed to decode connector update request")
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	connector.ID = connectorID
	connector.OrganisationID = orgID
	updatedConnector, err := h.configService.UpdateConnector(r.Context(), &connector)
	if err != nil {
		h.logger.WithError(err).Error("Failed to update connector")
		http.Error(w, "Failed to update connector", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(updatedConnector)
}

func (h *AuthUIHandler) HandleDeleteConnector(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	connectorID := vars["connectorID"]

	err := h.configService.DeleteConnector(r.Context(), connectorID)
	if err != nil {
		h.logger.WithError(err).Error("Failed to delete connector")
		http.Error(w, "Failed to delete connector", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *AuthUIHandler) HandleLogsManagement(w http.ResponseWriter, r *http.Request) {
	user := h.getUserFromContext(r)
	vars := mux.Vars(r)
	orgID := vars["orgID"]

	// Get recent request logs for the organisation
	logs, err := h.getRecentRequestLogs(r.Context(), orgID)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get request logs")
		logs = []map[string]interface{}{} // Empty slice as fallback
	}

	h.renderLogsManagement(w, user, orgID, logs)
}

func (h *AuthUIHandler) HandleMetricsManagement(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte("<h1>Metrics Management</h1><p>Metrics management interface coming soon...</p>"))
}

// Helper function to get recent request logs
func (h *AuthUIHandler) getRecentRequestLogs(ctx context.Context, orgID string) ([]map[string]interface{}, error) {
	// Get recent request logs from the database
	requestLogs, err := h.requestLogRepo.GetByOrganisation(ctx, orgID, 50, 0) // Get last 50 logs
	if err != nil {
		h.logger.WithError(err).Error("Failed to get request logs from database")
		return []map[string]interface{}{}, err
	}

	// Convert to the format expected by the template
	logs := make([]map[string]interface{}, len(requestLogs))
	for i, log := range requestLogs {
		connectorID := ""
		if log.Connector != nil {
			connectorID = log.Connector.Name + " (" + log.ConnectorID[:8] + "...)"
		} else if log.ConnectorID != "" {
			connectorID = log.ConnectorID[:8] + "..."
		}

		message := "Request processed successfully"
		if log.ErrorMessage != "" {
			message = log.ErrorMessage
		} else if log.StatusCode >= 400 {
			message = fmt.Sprintf("HTTP %d error", log.StatusCode)
		}

		// Debug: log if we have error details
		if log.ErrorDetails != "" {
			h.logger.WithField("request_id", log.RequestID).
				WithField("error_details_length", len(log.ErrorDetails)).
				WithField("error_details_preview", func() string {
					if len(log.ErrorDetails) > 100 {
						return log.ErrorDetails[:100] + "..."
					}
					return log.ErrorDetails
				}()).
				Info("Found error details in database for request log")
		}

		logs[i] = map[string]interface{}{
			"timestamp":     log.Timestamp.Format("2006-01-02 15:04:05"),
			"method":        log.Method,
			"path":          log.Path,
			"status_code":   log.StatusCode,
			"response_time": fmt.Sprintf("%dms", log.ProcessingTime),
			"connector_id":  connectorID,
			"message":       message,
			"request_id":    log.RequestID,
			"request_body":  template.JSEscapeString(log.RequestBody),
			"response_body": template.JSEscapeString(log.ResponseBody),
			"error_details": log.ErrorDetails, // Don't escape - we want raw JSON for JavaScript parsing
		}
	}

	return logs, nil
}

func (h *AuthUIHandler) renderLogsManagement(w http.ResponseWriter, user *models.User, orgID string, logs []map[string]interface{}) {
	tmpl := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Logs Management - API Translation Platform</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f8f9fa; color: #333; }
        .header { background: white; border-bottom: 1px solid #dee2e6; padding: 1rem 2rem; display: flex; justify-content: space-between; align-items: center; }
        .header h1 { color: #667eea; font-size: 1.5rem; }
        .nav-links { display: flex; gap: 1rem; align-items: center; }
        .nav-links a { color: #667eea; text-decoration: none; padding: 0.5rem 1rem; border-radius: 6px; transition: background-color 0.3s; }
        .nav-links a:hover { background: #f8f9fa; }
        .btn { padding: 0.5rem 1rem; background: #667eea; color: white; text-decoration: none; border-radius: 6px; border: none; cursor: pointer; font-size: 0.9rem; }
        .btn:hover { background: #5a6fd8; }
        .btn-danger { background: #dc3545; }
        .btn-danger:hover { background: #c82333; }
        .container { max-width: 1200px; margin: 0 auto; padding: 2rem; }
        .page-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 2rem; }
        .logs-table { background: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1); overflow: hidden; }
        .logs-table table { width: 100%; border-collapse: collapse; }
        .logs-table th, .logs-table td { padding: 1rem; text-align: left; border-bottom: 1px solid #dee2e6; }
        .logs-table th { background: #f8f9fa; font-weight: 600; color: #495057; }
        .logs-table tr:hover { background: #f8f9fa; }
        .status-badge { padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.8rem; font-weight: 500; }
        .status-200 { background: #d4edda; color: #155724; }
        .status-404 { background: #fff3cd; color: #856404; }
        .status-500 { background: #f8d7da; color: #721c24; }
        .breadcrumb { margin-bottom: 2rem; color: #666; }
        .breadcrumb a { color: #667eea; text-decoration: none; }
        .breadcrumb a:hover { text-decoration: underline; }
        .method-badge { padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.8rem; font-weight: 500; }
        .method-get { background: #d1ecf1; color: #0c5460; }
        .method-post { background: #d4edda; color: #155724; }
        .method-put { background: #fff3cd; color: #856404; }
        .method-delete { background: #f8d7da; color: #721c24; }
        .refresh-btn { margin-left: 1rem; }
        .log-message { max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        
        /* Modal styles */
        .modal { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); display: none; align-items: center; justify-content: center; z-index: 1000; }
        .modal-content { background: white; border-radius: 8px; padding: 2rem; max-width: 80%; max-height: 80%; overflow-y: auto; }
        .modal-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem; border-bottom: 1px solid #dee2e6; padding-bottom: 1rem; }
        .modal-header h3 { margin: 0; color: #333; }
        .modal-close { background: none; border: none; font-size: 1.5rem; cursor: pointer; color: #666; }
        .modal-close:hover { color: #333; }
        .modal-section { margin-bottom: 1.5rem; }
        .modal-section h4 { margin-bottom: 0.5rem; color: #555; }
        .modal-body { background: #f8f9fa; border: 1px solid #dee2e6; border-radius: 4px; padding: 1rem; font-family: 'Courier New', monospace; font-size: 0.9rem; white-space: pre-wrap; word-wrap: break-word; max-height: 300px; overflow-y: auto; }
        .modal-info { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 1.5rem; }
        .modal-info-item { background: #f8f9fa; padding: 0.5rem; border-radius: 4px; }
        .modal-info-label { font-weight: 600; color: #555; font-size: 0.9rem; }
        .modal-info-value { color: #333; }
    </style>
</head>
<body>
    <div class="header">
        <h1>📊 Request Logs</h1>
        <div class="nav-links">
            <a href="/manage/org/{{.OrgID}}/dashboard">Dashboard</a>
            <a href="/manage/org/{{.OrgID}}/apis">APIs</a>
            <a href="/manage/org/{{.OrgID}}/connectors">Connectors</a>
            <a href="/manage/org/{{.OrgID}}/logs">Logs</a>
            <form method="POST" action="/logout" style="display: inline;">
                <button type="submit" class="btn btn-danger">Logout</button>
            </form>
        </div>
    </div>
    
    <div class="container">
        <div class="breadcrumb">
            <a href="/manage/org/{{.OrgID}}/dashboard">Organisation Dashboard</a> > Request Logs
        </div>
        
        <div class="page-header">
            <h2>Recent API Requests</h2>
            <button class="btn refresh-btn" onclick="location.reload()">🔄 Refresh</button>
        </div>
        
        <div class="logs-table">
            <table>
                <thead>
                    <tr>
                        <th>Timestamp</th>
                        <th>Method</th>
                        <th>Path</th>
                        <th>Status</th>
                        <th>Response Time</th>
                        <th>Connector</th>
                        <th>Message</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {{range .Logs}}
                    <tr>
                        <td>{{.timestamp}}</td>
                        <td>
                            <span class="method-badge method-{{.method | lower}}">{{.method}}</span>
                        </td>
                        <td><code>{{.path}}</code></td>
                        <td>
                            <span class="status-badge status-{{.status_code}}">{{.status_code}}</span>
                        </td>
                        <td>{{.response_time}}</td>
                        <td>
                            {{if .connector_id}}
                            <code>{{.connector_id}}</code>
                            {{else}}
                            <span style="color: #6c757d;">-</span>
                            {{end}}
                        </td>
                        <td>
                            <div class="log-message" title="{{.message}}">{{.message}}</div>
                        </td>
                        <td>
                            <button class="btn btn-sm" onclick="showRequestDetails('{{.request_id}}', '{{.method}}', '{{.path}}', '{{.status_code}}', '{{.timestamp}}', '{{.message}}', {{.request_body}}, {{.response_body}}, {{.error_details}})">Details</button>
                        </td>
                    </tr>
                    {{end}}
                </tbody>
            </table>
        </div>
        
        {{if not .Logs}}
        <div style="text-align: center; padding: 3rem; color: #6c757d;">
            <h3>No logs available</h3>
            <p>Request logs will appear here as API calls are processed.</p>
        </div>
        {{end}}
    </div>
    
    <!-- Request Details Modal -->
    <div id="requestModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3>Request Details</h3>
                <button class="modal-close" onclick="closeRequestModal()">&times;</button>
            </div>
            
            <div class="modal-info">
                <div class="modal-info-item">
                    <div class="modal-info-label">Request ID</div>
                    <div class="modal-info-value" id="modalRequestId"></div>
                </div>
                <div class="modal-info-item">
                    <div class="modal-info-label">Method</div>
                    <div class="modal-info-value" id="modalMethod"></div>
                </div>
                <div class="modal-info-item">
                    <div class="modal-info-label">Path</div>
                    <div class="modal-info-value" id="modalPath"></div>
                </div>
                <div class="modal-info-item">
                    <div class="modal-info-label">Status Code</div>
                    <div class="modal-info-value" id="modalStatusCode"></div>
                </div>
                <div class="modal-info-item">
                    <div class="modal-info-label">Timestamp</div>
                    <div class="modal-info-value" id="modalTimestamp"></div>
                </div>
                <div class="modal-info-item">
                    <div class="modal-info-label">Message</div>
                    <div class="modal-info-value" id="modalMessage"></div>
                </div>
            </div>
            
            <div class="modal-section">
                <h4>Request Body</h4>
                <div class="modal-body" id="modalRequestBody"></div>
            </div>
            
            <div class="modal-section">
                <h4>Response Body</h4>
                <div class="modal-body" id="modalResponseBody"></div>
            </div>
            
            <div class="modal-section" id="errorDetailsSection" style="display: none;">
                <h4>Detailed Error Information</h4>
                <div class="modal-body" id="modalErrorDetails"></div>
            </div>
        </div>
    </div>
    
    <script>
        function showRequestDetails(requestId, method, path, statusCode, timestamp, message, requestBody, responseBody, errorDetails) {
            document.getElementById('modalRequestId').textContent = requestId;
            document.getElementById('modalMethod').innerHTML = '<span class="method-badge method-' + method.toLowerCase() + '">' + method + '</span>';
            document.getElementById('modalPath').innerHTML = '<code>' + path + '</code>';
            document.getElementById('modalStatusCode').innerHTML = '<span class="status-badge status-' + statusCode + '">' + statusCode + '</span>';
            document.getElementById('modalTimestamp').textContent = timestamp;
            document.getElementById('modalMessage').textContent = message;
            
            // Format and display request body
            const reqBody = requestBody || 'No request body';
            document.getElementById('modalRequestBody').textContent = reqBody === 'No request body' ? reqBody : formatBody(reqBody);
            
            // Format and display response body
            const respBody = responseBody || 'No response body';
            document.getElementById('modalResponseBody').textContent = respBody === 'No response body' ? respBody : formatBody(respBody);
            
            // Handle detailed error information
            const errorDetailsSection = document.getElementById('errorDetailsSection');
            const modalErrorDetails = document.getElementById('modalErrorDetails');
            
            if (errorDetails && errorDetails.trim() !== '') {
                try {
                    const parsedErrorDetails = JSON.parse(errorDetails);
                    modalErrorDetails.textContent = formatErrorDetails(parsedErrorDetails);
                    errorDetailsSection.style.display = 'block';
                } catch (e) {
                    // If it's not valid JSON, display as plain text
                    modalErrorDetails.textContent = errorDetails;
                    errorDetailsSection.style.display = 'block';
                }
            } else {
                errorDetailsSection.style.display = 'none';
            }
            
            document.getElementById('requestModal').style.display = 'flex';
        }
        
        function closeRequestModal() {
            document.getElementById('requestModal').style.display = 'none';
        }
        
        function formatBody(body) {
            try {
                // Try to parse and format as JSON
                const parsed = JSON.parse(body);
                return JSON.stringify(parsed, null, 2);
            } catch (e) {
                // If not JSON, return as-is
                return body;
            }
        }
        
        function formatErrorDetails(errorDetails) {
            let formatted = '';
            
            // Add basic error information
            if (errorDetails.error_type) {
                formatted += '🔴 Error Type: ' + errorDetails.error_type + '\n';
            }
            if (errorDetails.error_message) {
                formatted += '💬 Error Message: ' + errorDetails.error_message + '\n';
            }
            if (errorDetails.timestamp) {
                formatted += '⏰ Timestamp: ' + new Date(errorDetails.timestamp).toLocaleString() + '\n';
            }
            
            // Add Python-specific error details
            if (errorDetails.python_error_details) {
                const pythonError = errorDetails.python_error_details;
                formatted += '\n🐍 === PYTHON ERROR DETAILS ===\n';
                
                // Handle nested detailed_error structure
                let actualError = pythonError;
                if (pythonError.detailed_error) {
                    actualError = pythonError.detailed_error;
                }
                
                if (actualError.error_type) {
                    formatted += '📛 Python Error Type: ' + actualError.error_type + '\n';
                }
                if (actualError.error_message) {
                    formatted += '📝 Python Error Message: ' + actualError.error_message + '\n';
                }
                
                // Add stack trace information
                if (actualError.stack_trace && Array.isArray(actualError.stack_trace)) {
                    formatted += '\n📍 STACK TRACE:\n';
                    actualError.stack_trace.forEach((frame, index) => {
                        formatted += '┌─ Frame ' + (index + 1) + ' ─────────────────────\n';
                        if (frame.function_name) {
                            formatted += '│ 🔧 Function: ' + frame.function_name + '()\n';
                        }
                        if (frame.line_number) {
                            formatted += '│ 📍 Line: ' + frame.line_number + '\n';
                        }
                        if (frame.line_content) {
                            formatted += '│ 💻 Code: ' + frame.line_content + '\n';
                        }
                        if (frame.local_variables && Object.keys(frame.local_variables).length > 0) {
                            formatted += '│ 🔍 Local Variables:\n';
                            Object.entries(frame.local_variables).forEach(([key, value]) => {
                                const formattedValue = typeof value === 'string' ? '"' + value + '"' : JSON.stringify(value);
                                formatted += '│   • ' + key + ' = ' + formattedValue + '\n';
                            });
                        }
                        formatted += '└─────────────────────────────\n\n';
                    });
                }
                
                // Add full traceback
                if (actualError.full_traceback && Array.isArray(actualError.full_traceback)) {
                    formatted += '📋 FULL PYTHON TRACEBACK:\n';
                    formatted += '┌─────────────────────────────\n';
                    actualError.full_traceback.forEach(line => {
                        formatted += '│ ' + line.replace(/\n$/, '') + '\n';
                    });
                    formatted += '└─────────────────────────────\n\n';
                }
            }
            
            // Add execution context
            if (errorDetails.exit_code !== undefined) {
                formatted += '🚪 Exit Code: ' + errorDetails.exit_code + '\n';
            }
            if (errorDetails.stderr) {
                formatted += '⚠️  Stderr Output:\n' + errorDetails.stderr + '\n';
            }
            if (errorDetails.input_data) {
                formatted += '📥 Input Data Preview:\n';
                try {
                    const inputData = JSON.parse(errorDetails.input_data);
                    formatted += JSON.stringify(inputData, null, 2) + '\n';
                } catch (e) {
                    formatted += errorDetails.input_data + '\n';
                }
            }
            
            // Add common error detection and suggestions
            if (errorDetails.python_error_details && errorDetails.python_error_details.common_error_detected) {
                const commonError = errorDetails.python_error_details.common_error_detected;
                formatted += '\n🎯 === COMMON ERROR DETECTED ===\n';
                
                if (commonError.common_error === 'json_loads_on_dict') {
                    formatted += '🚨 You are trying to call json.loads() on input_data!\n';
                    formatted += '💡 input_data is already a Python dictionary - no parsing needed.\n\n';
                }
                
                if (commonError.suggestion) {
                    formatted += '✅ SOLUTION:\n';
                    formatted += commonError.suggestion + '\n';
                }
                
                if (commonError.json_loads_calls && commonError.json_loads_calls.length > 0) {
                    formatted += '\n🔍 Found json.loads() calls in your code:\n';
                    commonError.json_loads_calls.forEach((call, index) => {
                        formatted += '  • Line ' + call.line_number + ': ' + call.line_content + '\n';
                    });
                }
                
                formatted += '\n📖 Remember: input_data is already parsed for you!\n';
                formatted += '═══════════════════════════════════════\n\n';
            }
            
            return formatted || JSON.stringify(errorDetails, null, 2);
        }
        
        // Close modal when clicking outside
        document.getElementById('requestModal').addEventListener('click', function(e) {
            if (e.target === this) {
                closeRequestModal();
            }
        });
        
        // Auto-refresh every 30 seconds
        setTimeout(function() {
            location.reload();
        }, 30000);
    </script>
</body>
</html>`

	t, err := template.New("logs").Funcs(template.FuncMap{
		"lower": strings.ToLower,
	}).Parse(tmpl)
	if err != nil {
		h.logger.WithError(err).Error("Failed to parse logs template")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	data := struct {
		User  *models.User
		OrgID string
		Logs  []map[string]interface{}
	}{
		User:  user,
		OrgID: orgID,
		Logs:  logs,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.Execute(w, data); err != nil {
		h.logger.WithError(err).Error("Failed to execute logs template")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// API Schema Management Handlers

func (h *AuthUIHandler) HandleGetAPISchema(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	apiID := vars["apiID"]

	// Get schema for the API
	schema, err := h.schemaService.GetSchemaByAPIID(r.Context(), apiID)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get API schema")
		http.Error(w, "Failed to get schema", http.StatusInternalServerError)
		return
	}

	// If no schema exists, return empty schema
	if schema == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"parsed_fields": []interface{}{},
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(schema)
}

func (h *AuthUIHandler) HandleCreateAPISchema(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	apiID := vars["apiID"]

	var schemaRequest struct {
		SchemaType    string                 `json:"schema_type"`
		SchemaContent map[string]interface{} `json:"schema_content"`
	}

	if err := h.decodeJSONRequest(r, &schemaRequest); err != nil {
		h.logger.WithError(err).Error("Failed to decode JSON request")
		http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Check if schema already exists
	existingSchema, err := h.schemaService.GetSchemaByAPIID(r.Context(), apiID)
	if err != nil {
		h.logger.WithError(err).Error("Failed to check existing schema")
		http.Error(w, "Failed to check existing schema", http.StatusInternalServerError)
		return
	}

	var schema *models.APISchema
	if existingSchema != nil {
		// Update existing schema
		schema = existingSchema
		schema.SchemaType = schemaRequest.SchemaType
		schema.SchemaContent = models.SchemaContent{
			Raw:         "",
			Parsed:      schemaRequest.SchemaContent,
			SampleData:  nil,
			Description: "Updated via UI",
		}
	} else {
		// Create new schema
		schema = &models.APISchema{
			APIConfigurationID: apiID,
			SchemaType:         schemaRequest.SchemaType,
			SchemaContent: models.SchemaContent{
				Raw:         "",
				Parsed:      schemaRequest.SchemaContent,
				SampleData:  nil,
				Description: "Uploaded via UI",
			},
		}
	}

	// Handle different schema types
	if schemaRequest.SchemaType == "json_schema" {
		if raw, ok := schemaRequest.SchemaContent["raw"].(string); ok {
			schema.SchemaContent.Raw = raw
			// Parse JSON schema to extract fields
			fields, err := h.schemaService.ParseJSONSchema(r.Context(), raw)
			if err != nil {
				h.logger.WithError(err).Error("Failed to parse JSON schema")
				http.Error(w, "Invalid JSON schema", http.StatusBadRequest)
				return
			}
			schema.ParsedFields = fields
		}
	} else if schemaRequest.SchemaType == "custom" {
		if sampleData, ok := schemaRequest.SchemaContent["sample_data"].(map[string]interface{}); ok {
			schema.SchemaContent.SampleData = sampleData
			// Parse sample data to extract fields
			fields, err := h.schemaService.ParseSampleData(r.Context(), sampleData)
			if err != nil {
				h.logger.WithError(err).Error("Failed to parse sample data")
				http.Error(w, "Invalid sample data", http.StatusBadRequest)
				return
			}
			schema.ParsedFields = fields
		}
	}

	// Create or update the schema
	var resultSchema *models.APISchema
	if existingSchema != nil {
		// Update existing schema
		resultSchema, err = h.schemaService.UpdateSchema(r.Context(), schema)
		if err != nil {
			h.logger.WithError(err).Error("Failed to update API schema")
			http.Error(w, "Failed to update schema", http.StatusInternalServerError)
			return
		}
	} else {
		// Create new schema
		resultSchema, err = h.schemaService.CreateSchema(r.Context(), schema)
		if err != nil {
			h.logger.WithError(err).Error("Failed to create API schema")
			http.Error(w, "Failed to create schema", http.StatusInternalServerError)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if existingSchema != nil {
		w.WriteHeader(http.StatusOK) // 200 for update
	} else {
		w.WriteHeader(http.StatusCreated) // 201 for create
	}
	json.NewEncoder(w).Encode(resultSchema)
}

func (h *AuthUIHandler) HandleUpdateAPISchema(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	apiID := vars["apiID"]

	// Get existing schema
	existingSchema, err := h.schemaService.GetSchemaByAPIID(r.Context(), apiID)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get existing schema")
		http.Error(w, "Failed to get schema", http.StatusInternalServerError)
		return
	}

	if existingSchema == nil {
		http.Error(w, "Schema not found", http.StatusNotFound)
		return
	}

	var schemaRequest struct {
		SchemaType    string                 `json:"schema_type"`
		SchemaContent map[string]interface{} `json:"schema_content"`
	}

	if err := json.NewDecoder(r.Body).Decode(&schemaRequest); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Update schema
	existingSchema.SchemaType = schemaRequest.SchemaType
	existingSchema.SchemaContent.Parsed = schemaRequest.SchemaContent

	// Handle different schema types
	if schemaRequest.SchemaType == "json_schema" {
		if raw, ok := schemaRequest.SchemaContent["raw"].(string); ok {
			existingSchema.SchemaContent.Raw = raw
			// Parse JSON schema to extract fields
			fields, err := h.schemaService.ParseJSONSchema(r.Context(), raw)
			if err != nil {
				h.logger.WithError(err).Error("Failed to parse JSON schema")
				http.Error(w, "Invalid JSON schema", http.StatusBadRequest)
				return
			}
			existingSchema.ParsedFields = fields
		}
	} else if schemaRequest.SchemaType == "custom" {
		if sampleData, ok := schemaRequest.SchemaContent["sample_data"].(map[string]interface{}); ok {
			existingSchema.SchemaContent.SampleData = sampleData
			// Parse sample data to extract fields
			fields, err := h.schemaService.ParseSampleData(r.Context(), sampleData)
			if err != nil {
				h.logger.WithError(err).Error("Failed to parse sample data")
				http.Error(w, "Invalid sample data", http.StatusBadRequest)
				return
			}
			existingSchema.ParsedFields = fields
		}
	}

	// Update the schema
	updatedSchema, err := h.schemaService.UpdateSchema(r.Context(), existingSchema)
	if err != nil {
		h.logger.WithError(err).Error("Failed to update API schema")
		http.Error(w, "Failed to update schema", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(updatedSchema)
}
func (h *AuthUIHandler) HandleDeleteAPISchema(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	apiID := vars["apiID"]

	// Get existing schema first
	existingSchema, err := h.schemaService.GetSchemaByAPIID(r.Context(), apiID)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get existing schema")
		http.Error(w, "Failed to get schema", http.StatusInternalServerError)
		return
	}

	if existingSchema == nil {
		http.Error(w, "Schema not found", http.StatusNotFound)
		return
	}

	// Delete the schema
	err = h.schemaService.DeleteSchema(r.Context(), existingSchema.ID)
	if err != nil {
		h.logger.WithError(err).Error("Failed to delete API schema")
		http.Error(w, "Failed to delete schema", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
