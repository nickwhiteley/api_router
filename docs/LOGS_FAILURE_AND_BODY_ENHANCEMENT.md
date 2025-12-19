# Logs Enhancement: Failure Logging and Request/Response Body Viewing

## Issues Addressed

### 1. Failures Not Being Logged
**Problem**: API request failures (404s, 500s, validation errors, etc.) were not being logged to the database, making it impossible to track and debug issues.

**Root Cause**: The `HandleInboundRequest` function in `api_gateway.go` was returning early on failures without calling the logging functions.

### 2. Unable to View Request/Response Bodies
**Problem**: The logs page showed basic request information but didn't provide access to the actual request and response bodies, making debugging difficult.

## Solutions Implemented

### 1. Enhanced Failure Logging

#### Added `logFailedRequest` Function
Created a new function specifically for logging failed requests that don't have an associated connector:

```go
func (s *apiGatewayService) logFailedRequest(ctx context.Context, requestID string, req *http.Request, resp *http.Response, processingTime time.Duration, errorMsg string, orgID string) {
    // Captures request/response bodies and logs to database
    // Uses empty ConnectorID for failed requests
}
```

#### Updated Error Handling
Modified all error return paths in `HandleInboundRequest` to log failures:

- **API Configuration Lookup Failures**: When API endpoint is not found
- **Rate Limiting**: When requests exceed rate limits
- **Request Validation**: When request format is invalid
- **Connector Lookup**: When no connectors are found
- **Connector Availability**: When no active connectors exist
- **Request Processing**: When transformation or outbound calls fail

#### Failure Categories Logged
- `404 Not Found`: API endpoint not configured
- `400 Bad Request`: Request validation failures
- `429 Too Many Requests`: Rate limit exceeded
- `500 Internal Server Error`: System errors
- `503 Service Unavailable`: No active connectors

### 2. Request/Response Body Viewing

#### Enhanced Data Structure
Updated the logs data structure to include:
- `request_id`: Unique identifier for each request
- `request_body`: Full HTTP request body (JSON escaped)
- `response_body`: Full HTTP response body (JSON escaped)

#### Modal Interface
Added a detailed modal popup that displays:

**Request Information**:
- Request ID
- HTTP Method (with color-coded badges)
- Path
- Status Code (with color-coded badges)
- Timestamp
- Error/Success Message

**Request Body**:
- Full HTTP request including headers
- JSON formatting for JSON payloads
- Raw text for other content types

**Response Body**:
- Complete response content
- Automatic JSON pretty-printing
- Error messages and stack traces

#### User Interface Enhancements
- **Details Button**: Added to each log row
- **Modal Popup**: Clean, scrollable interface for body content
- **Syntax Highlighting**: JSON content is automatically formatted
- **Responsive Design**: Modal adapts to different screen sizes
- **Click Outside to Close**: Intuitive modal interaction

## Technical Implementation

### API Gateway Changes
```go
// Before: Early return on failure
if apiConfig == nil {
    return s.createErrorResponse(http.StatusNotFound, "API endpoint not found"), nil
}

// After: Log failure before returning
if apiConfig == nil {
    response := s.createErrorResponse(http.StatusNotFound, "API endpoint not found")
    processingTime := time.Since(startTime)
    s.logFailedRequest(ctx, requestID, req, response, processingTime, "API endpoint not found", "")
    return response, nil
}
```

### Database Schema
The existing `request_logs` table already supported failure logging with:
- `status_code`: HTTP status codes including error codes
- `error_message`: Detailed error descriptions
- `request_body`: Full request content
- `response_body`: Full response content
- `connector_id`: Empty for failed requests without connectors

### Frontend JavaScript
```javascript
function showRequestDetails(requestId, method, path, statusCode, timestamp, message, requestBody, responseBody) {
    // Populate modal with request details
    // Format JSON bodies for better readability
    // Display in scrollable modal interface
}
```

## Features

### Comprehensive Failure Tracking
- **All Failures Logged**: Every failed request is now recorded
- **Detailed Error Messages**: Specific reasons for failures
- **Processing Time**: How long failed requests took
- **Request Context**: Full request details for debugging

### Request/Response Inspection
- **Full Body Content**: Complete request and response data
- **JSON Formatting**: Automatic pretty-printing for JSON
- **Header Information**: HTTP headers included in request body
- **Error Details**: Stack traces and error messages visible

### Enhanced Debugging
- **Failure Patterns**: Identify common failure points
- **Request Analysis**: See exactly what was sent
- **Response Analysis**: See exactly what was returned
- **Timeline View**: When failures occurred

## User Workflow

### Viewing Logs
1. Navigate to `/manage/org/{orgID}/logs`
2. See all requests (successful and failed) in chronological order
3. Failed requests show error status codes (400, 404, 500, etc.)

### Inspecting Request Details
1. Click "Details" button on any log entry
2. Modal opens showing:
   - Request metadata (method, path, status, timing)
   - Full request body with headers
   - Complete response body
   - Error messages if applicable
3. JSON content is automatically formatted for readability
4. Click outside modal or X button to close

### Debugging Failures
1. Filter visually by red status badges (500s) or yellow (400s)
2. Click Details to see exact error messages
3. Examine request body to verify correct format
4. Check response body for detailed error information

## Testing Scenarios

### Test Failure Logging
1. **404 Errors**: Request non-existent API endpoint
2. **400 Errors**: Send malformed JSON
3. **429 Errors**: Exceed rate limits
4. **500 Errors**: Trigger transformation failures
5. **503 Errors**: Disable all connectors

### Test Body Viewing
1. **JSON Requests**: Send JSON payload, verify formatting in modal
2. **XML/SOAP**: Send XML, verify raw display
3. **Large Bodies**: Test with large payloads
4. **Error Responses**: View error response bodies
5. **Empty Bodies**: Handle requests/responses with no body

## Files Modified

1. **`internal/services/api_gateway.go`**:
   - Added `logFailedRequest()` function
   - Updated all error paths to log failures
   - Enhanced request/response body capture

2. **`internal/handlers/auth_ui.go`**:
   - Added request_id and body fields to log data
   - Enhanced modal interface with detailed view
   - Added JavaScript for modal interaction and JSON formatting

## Performance Considerations

### Request Body Capture
- Bodies are captured using `httputil.DumpRequest()` for complete information
- Large bodies are stored as-is (consider size limits in production)
- Bodies are restored after reading to maintain request flow

### Database Storage
- Request/response bodies stored as TEXT fields
- Consider archiving old logs to manage database size
- Index on timestamp for efficient querying

### UI Performance
- Modal content is populated on-demand
- JSON formatting happens client-side
- Auto-refresh limited to 30 seconds to reduce server load

## Future Enhancements

### Advanced Filtering
- Filter by status code ranges
- Filter by error message content
- Filter by request/response body content
- Date range filtering

### Export Capabilities
- Export logs to CSV/JSON
- Export individual request/response pairs
- Bulk export for analysis

### Real-time Updates
- WebSocket integration for live log updates
- Push notifications for critical failures
- Real-time failure rate monitoring

### Body Analysis
- Syntax highlighting for different content types
- Request/response diff comparison
- Body size analysis and warnings