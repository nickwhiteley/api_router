# Logs Management Real Data Integration

## Issue
The "Recent API Requests" page was showing mock data and not displaying actual request logs, even when refreshing the page.

## Root Cause
The `getRecentRequestLogs` function in `auth_ui.go` was returning hardcoded mock data instead of querying the actual request logs from the database.

## Solution

### 1. Added RequestLogRepository Dependency
Updated the `AuthUIHandler` struct to include a `RequestLogRepository`:

```go
type AuthUIHandler struct {
    logger         *logger.Logger
    authService    services.AuthenticationService
    userService    services.UserManagementService
    configService  services.ConfigurationService
    schemaService  services.SchemaService
    requestLogRepo repositories.RequestLogRepository  // Added
}
```

### 2. Updated Constructor
Modified `NewAuthUIHandler` to accept and store the `RequestLogRepository`:

```go
func NewAuthUIHandler(
    logger *logger.Logger,
    authService services.AuthenticationService,
    userService services.UserManagementService,
    configService services.ConfigurationService,
    schemaService services.SchemaService,
    requestLogRepo repositories.RequestLogRepository,  // Added
) *AuthUIHandler
```

### 3. Implemented Real Data Retrieval
Replaced the mock data implementation with actual database queries:

```go
func (h *AuthUIHandler) getRecentRequestLogs(ctx context.Context, orgID string) ([]map[string]interface{}, error) {
    // Get recent request logs from the database
    requestLogs, err := h.requestLogRepo.GetByOrganisation(ctx, orgID, 50, 0)
    if err != nil {
        h.logger.WithError(err).Error("Failed to get request logs from database")
        return []map[string]interface{}{}, err
    }

    // Convert to template format
    logs := make([]map[string]interface{}, len(requestLogs))
    for i, log := range requestLogs {
        // Format connector ID
        connectorID := ""
        if log.Connector != nil {
            connectorID = log.Connector.Name + " (" + log.ConnectorID[:8] + "...)"
        } else if log.ConnectorID != "" {
            connectorID = log.ConnectorID[:8] + "..."
        }

        // Determine message
        message := "Request processed successfully"
        if log.ErrorMessage != "" {
            message = log.ErrorMessage
        } else if log.StatusCode >= 400 {
            message = fmt.Sprintf("HTTP %d error", log.StatusCode)
        }

        logs[i] = map[string]interface{}{
            "timestamp":     log.Timestamp.Format("2006-01-02 15:04:05"),
            "method":        log.Method,
            "path":          log.Path,
            "status_code":   log.StatusCode,
            "response_time": fmt.Sprintf("%dms", log.ProcessingTime),
            "connector_id":  connectorID,
            "message":       message,
        }
    }
    
    return logs, nil
}
```

### 4. Added Import
Added the repositories import to access the `RequestLogRepository` interface:

```go
import (
    // ... other imports
    "api-translation-platform/internal/repositories"
)
```

## How It Works

### Request Logging Flow
1. When an API request is processed through the API gateway
2. The `logRequest` function in `api_gateway.go` creates a `RequestLog` entry
3. The entry is saved to the database via `requestLogRepo.Create()`
4. The log includes:
   - Organisation ID
   - Connector ID
   - Request ID
   - HTTP method and path
   - Status code
   - Processing time
   - Error messages (if any)
   - Request and response bodies

### Logs Display Flow
1. User navigates to `/manage/org/{orgID}/logs`
2. `HandleLogsManagement` calls `getRecentRequestLogs`
3. `getRecentRequestLogs` queries the database for the last 50 logs
4. Logs are formatted for display with:
   - Formatted timestamps
   - Connector names (with truncated IDs)
   - Human-readable messages
   - Processing times in milliseconds
5. Template renders the logs in a table with color-coded status badges

## Features

### Real-Time Data
- Shows actual API requests as they're processed
- Displays last 50 requests per organisation
- Ordered by timestamp (most recent first)

### Rich Information
- **Timestamp**: When the request was processed
- **Method**: HTTP method (GET, POST, PUT, DELETE)
- **Path**: API endpoint path
- **Status Code**: HTTP status with color coding
  - 200-299: Green (success)
  - 400-499: Yellow (client error)
  - 500-599: Red (server error)
- **Response Time**: Processing time in milliseconds
- **Connector**: Name and ID of the connector used
- **Message**: Success message or error details

### Auto-Refresh
- Page automatically refreshes every 30 seconds
- Manual refresh button available

## Testing

### Verify Logs Are Being Created
1. Make an API request to an inbound endpoint
2. Check the database: `SELECT * FROM request_logs ORDER BY timestamp DESC LIMIT 10;`
3. Verify the log entry was created

### Verify Logs Page Shows Real Data
1. Navigate to the logs page: `http://localhost:8088/manage/org/{orgID}/logs`
2. Verify the table shows actual request data
3. Make a new API request
4. Refresh the logs page
5. Verify the new request appears in the table

## Files Modified
1. `internal/handlers/auth_ui.go` - Added RequestLogRepository dependency and implemented real data retrieval
2. No changes needed to `internal/container/container.go` - RequestLogRepository was already provided by fx

## Dependencies
- `internal/repositories.RequestLogRepository` - For querying request logs
- `internal/models.RequestLog` - Request log data model
- Database table `request_logs` - Stores request log entries

## Future Enhancements
- Add filtering by date range
- Add filtering by status code
- Add filtering by connector
- Add search functionality
- Add export to CSV/JSON
- Add pagination for large result sets
- Add real-time updates via WebSocket
- Add detailed view for individual requests
- Add request/response body inspection
