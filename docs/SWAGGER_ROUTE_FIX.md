# Swagger Route Fix

## Problem
The Swagger UI endpoint `/api/v1/docs/swagger` was returning 404 errors because the API Gateway's catch-all route was intercepting it before the Management API handler could process it.

## Root Cause
In the server route setup, the API Gateway was registered first with a `PathPrefix("/api/")` handler, which caught ALL requests starting with `/api/`, including:
- `/api/v1/docs/swagger` (Swagger UI)
- `/api/v1/docs/openapi.json` (OpenAPI spec)
- `/api/v1/organisations` (Management API endpoints)

This prevented the Management API handler from ever receiving these requests.

## Solution
Reordered the route registration in `internal/server/server.go`:

### Before (Broken)
```go
// API Gateway routes - registered first
s.router.PathPrefix("/api/").Handler(http.HandlerFunc(s.handleAPIGatewayRequest))

// Management API routes - registered second (never reached)
s.managementHandler.RegisterRoutes(s.router)
```

### After (Fixed)
```go
// Management API routes - registered first (specific routes)
s.managementHandler.RegisterRoutes(s.router)

// API Gateway routes - registered last (catch-all for dynamic endpoints)
s.router.PathPrefix("/api/").Handler(http.HandlerFunc(s.handleAPIGatewayRequest))
```

## How It Works Now
1. **Specific routes first**: Management API routes like `/api/v1/docs/swagger` are registered with specific handlers
2. **Catch-all last**: API Gateway's `PathPrefix("/api/")` only catches requests that don't match any specific routes
3. **Dynamic endpoints**: User-configured API endpoints (like `/api/webhook`) still work through the API Gateway

## Routes Now Working
- ✅ `/api/v1/docs/swagger` - Swagger UI
- ✅ `/api/v1/docs/openapi.json` - OpenAPI specification
- ✅ `/api/v1/organisations` - Management API endpoints
- ✅ `/api/webhook` - Dynamic user-configured endpoints (via API Gateway)

## Technical Details
The fix leverages Gorilla Mux's route matching priority:
- More specific routes (exact paths) are matched before less specific ones (path prefixes)
- Routes are evaluated in registration order when specificity is equal
- The API Gateway's `PathPrefix` acts as a fallback for unmatched `/api/` requests

## Files Modified
- `internal/server/server.go`: Reordered route registration

## Testing
After the fix:
1. Navigate to `http://localhost:8088/api/v1/docs/swagger`
2. Should see the Swagger UI interface
3. Dynamic API endpoints should continue working normally

This fix ensures that both the management API documentation and dynamic user-configured endpoints work correctly.