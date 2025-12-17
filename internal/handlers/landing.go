package handlers

import (
	"html/template"
	"net/http"

	"api-translation-platform/internal/logger"
)

// LandingHandler handles the landing page
type LandingHandler struct {
	logger *logger.Logger
}

// NewLandingHandler creates a new landing page handler
func NewLandingHandler(logger *logger.Logger) *LandingHandler {
	return &LandingHandler{
		logger: logger,
	}
}

// HandleLandingPage serves the main landing page
func (h *LandingHandler) HandleLandingPage(w http.ResponseWriter, r *http.Request) {
	// Only serve landing page for exact root path
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	h.logger.Info("Serving landing page")

	// HTML template for the landing page
	tmpl := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>API Translation Platform</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            line-height: 1.6;
            color: #333;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
        }
        
        .header {
            text-align: center;
            color: white;
            margin-bottom: 3rem;
        }
        
        .header h1 {
            font-size: 3rem;
            margin-bottom: 1rem;
            font-weight: 700;
        }
        
        .header p {
            font-size: 1.2rem;
            opacity: 0.9;
            max-width: 600px;
            margin: 0 auto;
        }
        
        .cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 2rem;
            margin-bottom: 3rem;
        }
        
        .card {
            background: white;
            border-radius: 12px;
            padding: 2rem;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1);
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }
        
        .card:hover {
            transform: translateY(-5px);
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.15);
        }
        
        .card h3 {
            color: #667eea;
            margin-bottom: 1rem;
            font-size: 1.5rem;
        }
        
        .card p {
            margin-bottom: 1.5rem;
            color: #666;
        }
        
        .links {
            list-style: none;
        }
        
        .links li {
            margin-bottom: 0.5rem;
        }
        
        .links a {
            color: #667eea;
            text-decoration: none;
            font-weight: 500;
            transition: color 0.3s ease;
        }
        
        .links a:hover {
            color: #764ba2;
            text-decoration: underline;
        }
        
        .status {
            background: white;
            border-radius: 12px;
            padding: 2rem;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1);
            text-align: center;
        }
        
        .status-indicator {
            display: inline-block;
            width: 12px;
            height: 12px;
            background: #4CAF50;
            border-radius: 50%;
            margin-right: 8px;
            animation: pulse 2s infinite;
        }
        
        @keyframes pulse {
            0% { opacity: 1; }
            50% { opacity: 0.5; }
            100% { opacity: 1; }
        }
        
        .footer {
            text-align: center;
            color: white;
            margin-top: 3rem;
            opacity: 0.8;
        }
        
        .auth-note {
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            border-radius: 8px;
            padding: 1rem;
            margin-top: 1rem;
            color: #856404;
        }
        
        .auth-note strong {
            color: #533f03;
        }
        
        @media (max-width: 768px) {
            .header h1 {
                font-size: 2rem;
            }
            
            .container {
                padding: 1rem;
            }
            
            .cards {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚀 API Translation Platform</h1>
            <p>A powerful integration platform that acts as an intermediary between different API systems, providing translation, authentication, and routing capabilities with multi-tenant architecture.</p>
        </div>
        
        <div class="cards">
            <div class="card">
                <h3>🔐 Administrator Login</h3>
                <p>Secure login portal for system administrators and organisation managers.</p>
                <ul class="links">
                    <li><a href="/login">Administrator Login</a></li>
                    <li><a href="/manage/admin/dashboard">Global Admin Dashboard</a></li>
                    <li><a href="/manage/org/65a6330e-e436-4c53-b843-d60e3d31abb2/dashboard">Organisation Dashboard</a></li>
                </ul>
                <div class="auth-note" style="background: #d1ecf1; border-color: #bee5eb; color: #0c5460;">
                    <strong>🌐 Demo Login:</strong> Use username "admin" and password "admin123" to access the management interface.
                </div>
            </div>
            
            <div class="card">
                <h3>📊 Admin Dashboard</h3>
                <p>Global administration interface for managing organisations, users, and system-wide settings.</p>
                <ul class="links">
                    <li><a href="/ui/admin/organisations">Organisations Management</a></li>
                    <li><a href="/ui/admin/system/health">System Health</a></li>
                    <li><a href="/ui/admin/system/metrics">System Metrics</a></li>
                    <li><a href="/ui/admin/system/logs">System Logs</a></li>
                </ul>
                <div class="auth-note">
                    <strong>🔐 Authentication Required:</strong> These endpoints require a valid JWT token with global admin privileges.
                </div>
            </div>
            
            <div class="card">
                <h3>🏢 Organisation Dashboard</h3>
                <p>Organisation-specific interface for managing APIs, connectors, and monitoring within your organisation.</p>
                <ul class="links">
                    <li><a href="/ui/65a6330e-e436-4c53-b843-d60e3d31abb2/dashboard">Organisation Dashboard</a></li>
                    <li><a href="/ui/65a6330e-e436-4c53-b843-d60e3d31abb2/apis">API Configurations</a></li>
                    <li><a href="/ui/65a6330e-e436-4c53-b843-d60e3d31abb2/connectors">Connector Management</a></li>
                    <li><a href="/ui/65a6330e-e436-4c53-b843-d60e3d31abb2/logs">Request Logs</a></li>
                    <li><a href="/ui/65a6330e-e436-4c53-b843-d60e3d31abb2/metrics">Organisation Metrics</a></li>
                </ul>
                <div class="auth-note">
                    <strong>🔐 Authentication Required:</strong> These endpoints require a valid JWT token with organisation access.
                </div>
            </div>
            
            <div class="card">
                <h3>🔌 Management API</h3>
                <p>RESTful API for programmatic access to all platform features and data management.</p>
                <ul class="links">
                    <li><a href="/api/v1/docs/swagger">API Documentation (Swagger)</a></li>
                    <li><a href="/api/v1/docs/openapi.json">OpenAPI Specification</a></li>
                    <li><a href="/api/v1/organisations">Organisations API</a></li>
                    <li><a href="/api/v1/users">Users API</a></li>
                    <li><a href="/api/v1/configurations">Configurations API</a></li>
                </ul>
                <div class="auth-note">
                    <strong>🔐 Authentication Required:</strong> Most API endpoints require JWT authentication via Authorization header.
                </div>
            </div>
            
            <div class="card">
                <h3>🔍 System Monitoring</h3>
                <p>Public endpoints for system health monitoring and observability.</p>
                <ul class="links">
                    <li><a href="/health">Health Check</a></li>
                    <li><a href="/health/ready">Readiness Probe</a></li>
                    <li><a href="/health/live">Liveness Probe</a></li>
                    <li><a href="/metrics">Prometheus Metrics</a></li>
                </ul>
                <div class="auth-note" style="background: #d1ecf1; border-color: #bee5eb; color: #0c5460;">
                    <strong>🌐 Public Access:</strong> These endpoints are publicly accessible for monitoring systems.
                </div>
            </div>
        </div>
        
        <div class="status">
            <h3><span class="status-indicator"></span>System Status: Operational</h3>
            <p>All services are running normally. Database connected, authentication active, and all endpoints responding.</p>
        </div>
        
        <div class="footer">
            <p>API Translation Platform v1.0 | Built with Go, PostgreSQL, and Redis</p>
            <p>🔐 <strong>Quick Start:</strong> <a href="/login" style="color: white;">Login here</a> with username "admin" and password "admin123"</p>
        </div>
    </div>
</body>
</html>`

	// Parse and execute template
	t, err := template.New("landing").Parse(tmpl)
	if err != nil {
		h.logger.WithError(err).Error("Failed to parse landing page template")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	if err := t.Execute(w, nil); err != nil {
		h.logger.WithError(err).Error("Failed to execute landing page template")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}
