package handlers

import (
	"fmt"
)

// OpenAPISpec represents the OpenAPI 3.0 specification
type OpenAPISpec struct {
	OpenAPI    string                 `json:"openapi"`
	Info       OpenAPIInfo            `json:"info"`
	Servers    []OpenAPIServer        `json:"servers"`
	Paths      map[string]interface{} `json:"paths"`
	Components OpenAPIComponents      `json:"components"`
}

type OpenAPIInfo struct {
	Title       string         `json:"title"`
	Description string         `json:"description"`
	Version     string         `json:"version"`
	Contact     OpenAPIContact `json:"contact"`
	License     OpenAPILicense `json:"license"`
}

type OpenAPIContact struct {
	Name  string `json:"name"`
	URL   string `json:"url"`
	Email string `json:"email"`
}

type OpenAPILicense struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

type OpenAPIServer struct {
	URL         string `json:"url"`
	Description string `json:"description"`
}

type OpenAPIComponents struct {
	Schemas         map[string]interface{} `json:"schemas"`
	SecuritySchemes map[string]interface{} `json:"securitySchemes"`
}

// generateOpenAPISpec generates the complete OpenAPI specification
func (h *ManagementAPIHandler) generateOpenAPISpec() OpenAPISpec {
	return OpenAPISpec{
		OpenAPI: "3.0.3",
		Info: OpenAPIInfo{
			Title:       "API Translation Platform Management API",
			Description: "Comprehensive REST API for managing the API Translation Platform",
			Version:     "1.0.0",
			Contact: OpenAPIContact{
				Name:  "API Translation Platform Team",
				URL:   "https://api-translation-platform.com",
				Email: "support@api-translation-platform.com",
			},
			License: OpenAPILicense{
				Name: "MIT",
				URL:  "https://opensource.org/licenses/MIT",
			},
		},
		Servers: []OpenAPIServer{
			{
				URL:         "/api/v1",
				Description: "Version 1 API",
			},
			{
				URL:         "/api/v2",
				Description: "Version 2 API (backward compatible)",
			},
		},
		Paths:      h.generatePaths(),
		Components: h.generateComponents(),
	}
}

// generatePaths generates all API paths
func (h *ManagementAPIHandler) generatePaths() map[string]interface{} {
	paths := make(map[string]interface{})

	// Organisation endpoints
	paths["/organisations"] = map[string]interface{}{
		"get": map[string]interface{}{
			"summary":     "Get all organisations",
			"description": "Retrieve all organisations accessible to the authenticated user",
			"tags":        []string{"Organisations"},
			"security":    []map[string][]string{{"bearerAuth": {}}},
			"responses": map[string]interface{}{
				"200": map[string]interface{}{
					"description": "List of organisations",
					"content": map[string]interface{}{
						"application/json": map[string]interface{}{
							"schema": map[string]interface{}{
								"type": "array",
								"items": map[string]interface{}{
									"$ref": "#/components/schemas/Organisation",
								},
							},
						},
					},
				},
				"401": map[string]interface{}{"$ref": "#/components/responses/Unauthorized"},
				"500": map[string]interface{}{"$ref": "#/components/responses/InternalError"},
			},
		},
		"post": map[string]interface{}{
			"summary":     "Create organisation",
			"description": "Create a new organisation",
			"tags":        []string{"Organisations"},
			"security":    []map[string][]string{{"bearerAuth": {}}},
			"requestBody": map[string]interface{}{
				"required": true,
				"content": map[string]interface{}{
					"application/json": map[string]interface{}{
						"schema": map[string]interface{}{
							"$ref": "#/components/schemas/OrganisationCreate",
						},
					},
				},
			},
			"responses": map[string]interface{}{
				"201": map[string]interface{}{
					"description": "Organisation created successfully",
					"content": map[string]interface{}{
						"application/json": map[string]interface{}{
							"schema": map[string]interface{}{
								"$ref": "#/components/schemas/Organisation",
							},
						},
					},
				},
				"400": map[string]interface{}{"$ref": "#/components/responses/BadRequest"},
				"401": map[string]interface{}{"$ref": "#/components/responses/Unauthorized"},
				"500": map[string]interface{}{"$ref": "#/components/responses/InternalError"},
			},
		},
	}

	paths["/organisations/{id}"] = map[string]interface{}{
		"get": map[string]interface{}{
			"summary":     "Get organisation",
			"description": "Retrieve a specific organisation by ID",
			"tags":        []string{"Organisations"},
			"security":    []map[string][]string{{"bearerAuth": {}}},
			"parameters": []map[string]interface{}{
				{
					"name":        "id",
					"in":          "path",
					"required":    true,
					"description": "Organisation ID",
					"schema":      map[string]interface{}{"type": "string", "format": "uuid"},
				},
			},
			"responses": map[string]interface{}{
				"200": map[string]interface{}{
					"description": "Organisation details",
					"content": map[string]interface{}{
						"application/json": map[string]interface{}{
							"schema": map[string]interface{}{
								"$ref": "#/components/schemas/Organisation",
							},
						},
					},
				},
				"401": map[string]interface{}{"$ref": "#/components/responses/Unauthorized"},
				"403": map[string]interface{}{"$ref": "#/components/responses/Forbidden"},
				"404": map[string]interface{}{"$ref": "#/components/responses/NotFound"},
				"500": map[string]interface{}{"$ref": "#/components/responses/InternalError"},
			},
		},
		"put": map[string]interface{}{
			"summary":     "Update organisation",
			"description": "Update an existing organisation",
			"tags":        []string{"Organisations"},
			"security":    []map[string][]string{{"bearerAuth": {}}},
			"parameters": []map[string]interface{}{
				{
					"name":        "id",
					"in":          "path",
					"required":    true,
					"description": "Organisation ID",
					"schema":      map[string]interface{}{"type": "string", "format": "uuid"},
				},
			},
			"requestBody": map[string]interface{}{
				"required": true,
				"content": map[string]interface{}{
					"application/json": map[string]interface{}{
						"schema": map[string]interface{}{
							"$ref": "#/components/schemas/OrganisationUpdate",
						},
					},
				},
			},
			"responses": map[string]interface{}{
				"200": map[string]interface{}{
					"description": "Organisation updated successfully",
					"content": map[string]interface{}{
						"application/json": map[string]interface{}{
							"schema": map[string]interface{}{
								"$ref": "#/components/schemas/Organisation",
							},
						},
					},
				},
				"400": map[string]interface{}{"$ref": "#/components/responses/BadRequest"},
				"401": map[string]interface{}{"$ref": "#/components/responses/Unauthorized"},
				"403": map[string]interface{}{"$ref": "#/components/responses/Forbidden"},
				"404": map[string]interface{}{"$ref": "#/components/responses/NotFound"},
				"500": map[string]interface{}{"$ref": "#/components/responses/InternalError"},
			},
		},
		"delete": map[string]interface{}{
			"summary":     "Delete organisation",
			"description": "Delete an organisation",
			"tags":        []string{"Organisations"},
			"security":    []map[string][]string{{"bearerAuth": {}}},
			"parameters": []map[string]interface{}{
				{
					"name":        "id",
					"in":          "path",
					"required":    true,
					"description": "Organisation ID",
					"schema":      map[string]interface{}{"type": "string", "format": "uuid"},
				},
			},
			"responses": map[string]interface{}{
				"204": map[string]interface{}{"description": "Organisation deleted successfully"},
				"401": map[string]interface{}{"$ref": "#/components/responses/Unauthorized"},
				"403": map[string]interface{}{"$ref": "#/components/responses/Forbidden"},
				"404": map[string]interface{}{"$ref": "#/components/responses/NotFound"},
				"500": map[string]interface{}{"$ref": "#/components/responses/InternalError"},
			},
		},
	}

	// API Configuration endpoints
	paths["/organisations/{orgId}/api-configurations"] = map[string]interface{}{
		"get": map[string]interface{}{
			"summary":     "Get API configurations",
			"description": "Retrieve all API configurations for an organisation",
			"tags":        []string{"API Configurations"},
			"security":    []map[string][]string{{"bearerAuth": {}}},
			"parameters": []map[string]interface{}{
				{
					"name":        "orgId",
					"in":          "path",
					"required":    true,
					"description": "Organisation ID",
					"schema":      map[string]interface{}{"type": "string", "format": "uuid"},
				},
			},
			"responses": map[string]interface{}{
				"200": map[string]interface{}{
					"description": "List of API configurations",
					"content": map[string]interface{}{
						"application/json": map[string]interface{}{
							"schema": map[string]interface{}{
								"type": "array",
								"items": map[string]interface{}{
									"$ref": "#/components/schemas/APIConfiguration",
								},
							},
						},
					},
				},
				"401": map[string]interface{}{"$ref": "#/components/responses/Unauthorized"},
				"403": map[string]interface{}{"$ref": "#/components/responses/Forbidden"},
				"500": map[string]interface{}{"$ref": "#/components/responses/InternalError"},
			},
		},
		"post": map[string]interface{}{
			"summary":     "Create API configuration",
			"description": "Create a new API configuration",
			"tags":        []string{"API Configurations"},
			"security":    []map[string][]string{{"bearerAuth": {}}},
			"parameters": []map[string]interface{}{
				{
					"name":        "orgId",
					"in":          "path",
					"required":    true,
					"description": "Organisation ID",
					"schema":      map[string]interface{}{"type": "string", "format": "uuid"},
				},
			},
			"requestBody": map[string]interface{}{
				"required": true,
				"content": map[string]interface{}{
					"application/json": map[string]interface{}{
						"schema": map[string]interface{}{
							"$ref": "#/components/schemas/APIConfigurationCreate",
						},
					},
				},
			},
			"responses": map[string]interface{}{
				"201": map[string]interface{}{
					"description": "API configuration created successfully",
					"content": map[string]interface{}{
						"application/json": map[string]interface{}{
							"schema": map[string]interface{}{
								"$ref": "#/components/schemas/APIConfiguration",
							},
						},
					},
				},
				"400": map[string]interface{}{"$ref": "#/components/responses/BadRequest"},
				"401": map[string]interface{}{"$ref": "#/components/responses/Unauthorized"},
				"403": map[string]interface{}{"$ref": "#/components/responses/Forbidden"},
				"500": map[string]interface{}{"$ref": "#/components/responses/InternalError"},
			},
		},
	}

	// System endpoints
	paths["/system/health"] = map[string]interface{}{
		"get": map[string]interface{}{
			"summary":     "Get system health",
			"description": "Retrieve system health status",
			"tags":        []string{"System"},
			"security":    []map[string][]string{{"bearerAuth": {}}},
			"responses": map[string]interface{}{
				"200": map[string]interface{}{
					"description": "System health status",
					"content": map[string]interface{}{
						"application/json": map[string]interface{}{
							"schema": map[string]interface{}{
								"$ref": "#/components/schemas/SystemHealth",
							},
						},
					},
				},
				"401": map[string]interface{}{"$ref": "#/components/responses/Unauthorized"},
				"500": map[string]interface{}{"$ref": "#/components/responses/InternalError"},
			},
		},
	}

	// Analytics endpoints
	paths["/analytics/usage"] = map[string]interface{}{
		"get": map[string]interface{}{
			"summary":     "Get API usage analytics",
			"description": "Retrieve API usage analytics and statistics",
			"tags":        []string{"Analytics"},
			"security":    []map[string][]string{{"bearerAuth": {}}},
			"parameters": []map[string]interface{}{
				{
					"name":        "start",
					"in":          "query",
					"description": "Start time (RFC3339 format)",
					"schema":      map[string]interface{}{"type": "string", "format": "date-time"},
				},
				{
					"name":        "end",
					"in":          "query",
					"description": "End time (RFC3339 format)",
					"schema":      map[string]interface{}{"type": "string", "format": "date-time"},
				},
			},
			"responses": map[string]interface{}{
				"200": map[string]interface{}{
					"description": "API usage analytics",
					"content": map[string]interface{}{
						"application/json": map[string]interface{}{
							"schema": map[string]interface{}{
								"$ref": "#/components/schemas/UsageAnalytics",
							},
						},
					},
				},
				"401": map[string]interface{}{"$ref": "#/components/responses/Unauthorized"},
				"500": map[string]interface{}{"$ref": "#/components/responses/InternalError"},
			},
		},
	}

	return paths
}

// generateComponents generates OpenAPI components (schemas, responses, etc.)
func (h *ManagementAPIHandler) generateComponents() OpenAPIComponents {
	return OpenAPIComponents{
		Schemas: map[string]interface{}{
			"Organisation": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"id": map[string]interface{}{
						"type":        "string",
						"format":      "uuid",
						"description": "Unique identifier for the organisation",
					},
					"name": map[string]interface{}{
						"type":        "string",
						"description": "Organisation name",
						"minLength":   1,
						"maxLength":   255,
					},
					"is_active": map[string]interface{}{
						"type":        "boolean",
						"description": "Whether the organisation is active",
					},
					"created_at": map[string]interface{}{
						"type":        "string",
						"format":      "date-time",
						"description": "Creation timestamp",
					},
					"updated_at": map[string]interface{}{
						"type":        "string",
						"format":      "date-time",
						"description": "Last update timestamp",
					},
				},
				"required": []string{"id", "name", "is_active", "created_at", "updated_at"},
			},
			"OrganisationCreate": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"name": map[string]interface{}{
						"type":        "string",
						"description": "Organisation name",
						"minLength":   1,
						"maxLength":   255,
					},
					"is_active": map[string]interface{}{
						"type":        "boolean",
						"description": "Whether the organisation is active",
						"default":     true,
					},
				},
				"required": []string{"name"},
			},
			"OrganisationUpdate": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"name": map[string]interface{}{
						"type":        "string",
						"description": "Organisation name",
						"minLength":   1,
						"maxLength":   255,
					},
					"is_active": map[string]interface{}{
						"type":        "boolean",
						"description": "Whether the organisation is active",
					},
				},
			},
			"APIConfiguration": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"id": map[string]interface{}{
						"type":        "string",
						"format":      "uuid",
						"description": "Unique identifier for the API configuration",
					},
					"organisation_id": map[string]interface{}{
						"type":        "string",
						"format":      "uuid",
						"description": "Organisation ID",
					},
					"name": map[string]interface{}{
						"type":        "string",
						"description": "API configuration name",
						"minLength":   1,
						"maxLength":   255,
					},
					"type": map[string]interface{}{
						"type":        "string",
						"enum":        []string{"REST", "SOAP"},
						"description": "API protocol type",
					},
					"direction": map[string]interface{}{
						"type":        "string",
						"enum":        []string{"inbound", "outbound"},
						"description": "API direction",
					},
					"endpoint": map[string]interface{}{
						"type":        "string",
						"format":      "uri",
						"description": "API endpoint URL",
					},
					"authentication": map[string]interface{}{
						"$ref": "#/components/schemas/AuthenticationConfig",
					},
					"headers": map[string]interface{}{
						"type": "object",
						"additionalProperties": map[string]interface{}{
							"type": "string",
						},
						"description": "HTTP headers",
					},
					"created_at": map[string]interface{}{
						"type":        "string",
						"format":      "date-time",
						"description": "Creation timestamp",
					},
					"updated_at": map[string]interface{}{
						"type":        "string",
						"format":      "date-time",
						"description": "Last update timestamp",
					},
				},
				"required": []string{"id", "organisation_id", "name", "type", "direction", "endpoint"},
			},
			"APIConfigurationCreate": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"name": map[string]interface{}{
						"type":        "string",
						"description": "API configuration name",
						"minLength":   1,
						"maxLength":   255,
					},
					"type": map[string]interface{}{
						"type":        "string",
						"enum":        []string{"REST", "SOAP"},
						"description": "API protocol type",
					},
					"direction": map[string]interface{}{
						"type":        "string",
						"enum":        []string{"inbound", "outbound"},
						"description": "API direction",
					},
					"endpoint": map[string]interface{}{
						"type":        "string",
						"format":      "uri",
						"description": "API endpoint URL",
					},
					"authentication": map[string]interface{}{
						"$ref": "#/components/schemas/AuthenticationConfig",
					},
					"headers": map[string]interface{}{
						"type": "object",
						"additionalProperties": map[string]interface{}{
							"type": "string",
						},
						"description": "HTTP headers",
					},
				},
				"required": []string{"name", "type", "direction", "endpoint"},
			},
			"AuthenticationConfig": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"type": map[string]interface{}{
						"type":        "string",
						"enum":        []string{"api_key", "oauth", "basic", "none"},
						"description": "Authentication type",
					},
					"parameters": map[string]interface{}{
						"type": "object",
						"additionalProperties": map[string]interface{}{
							"type": "string",
						},
						"description": "Authentication parameters",
					},
				},
				"required": []string{"type"},
			},
			"SystemHealth": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"status": map[string]interface{}{
						"type":        "string",
						"enum":        []string{"healthy", "degraded", "unhealthy"},
						"description": "Overall system health status",
					},
					"components": map[string]interface{}{
						"type": "object",
						"additionalProperties": map[string]interface{}{
							"type": "object",
							"properties": map[string]interface{}{
								"status": map[string]interface{}{
									"type": "string",
									"enum": []string{"healthy", "degraded", "unhealthy"},
								},
								"message": map[string]interface{}{
									"type": "string",
								},
								"timestamp": map[string]interface{}{
									"type":   "string",
									"format": "date-time",
								},
							},
						},
						"description": "Health status of individual components",
					},
					"timestamp": map[string]interface{}{
						"type":        "string",
						"format":      "date-time",
						"description": "Health check timestamp",
					},
				},
				"required": []string{"status", "components", "timestamp"},
			},
			"UsageAnalytics": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"total_requests": map[string]interface{}{
						"type":        "integer",
						"description": "Total number of requests",
					},
					"success_rate": map[string]interface{}{
						"type":        "number",
						"format":      "float",
						"minimum":     0,
						"maximum":     1,
						"description": "Success rate (0-1)",
					},
					"avg_response_time": map[string]interface{}{
						"type":        "number",
						"format":      "float",
						"description": "Average response time in milliseconds",
					},
					"start_time": map[string]interface{}{
						"type":        "string",
						"format":      "date-time",
						"description": "Analytics period start time",
					},
					"end_time": map[string]interface{}{
						"type":        "string",
						"format":      "date-time",
						"description": "Analytics period end time",
					},
				},
				"required": []string{"total_requests", "success_rate", "avg_response_time", "start_time", "end_time"},
			},
			"Error": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"error": map[string]interface{}{
						"type":        "string",
						"description": "Error message",
					},
					"status": map[string]interface{}{
						"type":        "integer",
						"description": "HTTP status code",
					},
					"timestamp": map[string]interface{}{
						"type":        "string",
						"format":      "date-time",
						"description": "Error timestamp",
					},
					"details": map[string]interface{}{
						"type":        "string",
						"description": "Additional error details",
					},
				},
				"required": []string{"error", "status", "timestamp"},
			},
		},
		SecuritySchemes: map[string]interface{}{
			"bearerAuth": map[string]interface{}{
				"type":         "http",
				"scheme":       "bearer",
				"bearerFormat": "JWT",
				"description":  "JWT token authentication",
			},
		},
	}
}

// generateSwaggerUI generates the Swagger UI HTML
func (h *ManagementAPIHandler) generateSwaggerUI() string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>API Translation Platform - Management API Documentation</title>
    <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@4.15.5/swagger-ui.css" />
    <style>
        html {
            box-sizing: border-box;
            overflow: -moz-scrollbars-vertical;
            overflow-y: scroll;
        }
        *, *:before, *:after {
            box-sizing: inherit;
        }
        body {
            margin:0;
            background: #fafafa;
        }
    </style>
</head>
<body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@4.15.5/swagger-ui-bundle.js"></script>
    <script src="https://unpkg.com/swagger-ui-dist@4.15.5/swagger-ui-standalone-preset.js"></script>
    <script>
        window.onload = function() {
            const ui = SwaggerUIBundle({
                url: '/api/v1/docs/openapi.json',
                dom_id: '#swagger-ui',
                deepLinking: true,
                presets: [
                    SwaggerUIBundle.presets.apis,
                    SwaggerUIStandalonePreset
                ],
                plugins: [
                    SwaggerUIBundle.plugins.DownloadUrl
                ],
                layout: "StandaloneLayout",
                validatorUrl: null,
                tryItOutEnabled: true,
                supportedSubmitMethods: ['get', 'post', 'put', 'delete', 'patch'],
                onComplete: function() {
                    console.log('Swagger UI loaded');
                },
                requestInterceptor: function(request) {
                    // Add authorization header if token is available
                    const token = localStorage.getItem('jwt_token');
                    if (token) {
                        request.headers['Authorization'] = 'Bearer ' + token;
                    }
                    return request;
                }
            });
        };
    </script>
</body>
</html>`)
}
