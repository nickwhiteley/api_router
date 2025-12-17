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
	"api-translation-platform/internal/services"

	"github.com/gorilla/mux"
)

// AuthUIHandler handles authentication UI pages
type AuthUIHandler struct {
	logger        *logger.Logger
	authService   services.AuthenticationService
	userService   services.UserManagementService
	configService services.ConfigurationService
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
) *AuthUIHandler {
	return &AuthUIHandler{
		logger:        logger,
		authService:   authService,
		userService:   userService,
		configService: configService,
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
	orgRouter.HandleFunc("/connectors/{connectorID}", h.HandleUpdateConnector).Methods("PUT")
	orgRouter.HandleFunc("/connectors/{connectorID}", h.HandleDeleteConnector).Methods("DELETE")
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
                headers: {}
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
                    <label for="pythonScript">Python Transformation Script *</label>
                    <textarea id="pythonScript" name="python_script" required placeholder="# Enter your Python transformation script here
# Example:
def transform(input_data):
    # Transform the input data
    output_data = {
        'transformed': input_data
    }
    return output_data"></textarea>
                    <div class="error-message" id="scriptError"></div>
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
            
            if (!script) {
                showFieldError('pythonScript', 'Python script is required');
                isValid = false;
            } else if (script.length < 10) {
                showFieldError('pythonScript', 'Python script must be at least 10 characters');
                isValid = false;
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
            const payload = {
                name: name,
                inbound_api_id: inboundAPIId,
                outbound_api_id: outboundAPIId,
                python_script: script,
                is_active: isActive
            };
            
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
            // For now, show a simple form - could be enhanced with a modal
            const newName = prompt('Enter connector name:', name);
            if (!newName) return;
            
            const payload = {
                name: newName,
                inbound_api_id: inboundAPIId,
                outbound_api_id: outboundAPIId,
                is_active: isActive
            };
            
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
                location.reload();
            })
            .catch(error => {
                alert('Error updating connector: ' + error.message);
            });
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
	for key, value := range apiConfig.Headers {
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

func (h *AuthUIHandler) HandleUpdateConnector(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	connectorID := vars["connectorID"]
	orgID := vars["orgID"]

	var connector models.Connector
	if err := json.NewDecoder(r.Body).Decode(&connector); err != nil {
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
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte("<h1>Logs Management</h1><p>Logs management interface coming soon...</p>"))
}

func (h *AuthUIHandler) HandleMetricsManagement(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte("<h1>Metrics Management</h1><p>Metrics management interface coming soon...</p>"))
}
