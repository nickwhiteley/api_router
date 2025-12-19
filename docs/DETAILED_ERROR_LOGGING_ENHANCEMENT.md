# Detailed Error Logging Enhancement

## Overview
Enhanced the API gateway error logging system to provide comprehensive error details including full Python stack traces, local variables, and detailed execution context, making it significantly easier to diagnose and troubleshoot issues.

## Implementation Details

### Enhanced Error Messages
Updated all error handling in `internal/services/api_gateway.go` and `internal/services/transformation.go` to include comprehensive error details:

1. **Python Script Errors**: Now include full stack traces, local variables, line-by-line execution context, and detailed error analysis
2. **Outbound API Errors**: Include HTTP status codes and complete response bodies
3. **Configuration Errors**: Provide specific details about what configuration is missing or invalid
4. **Validation Errors**: Include detailed validation failure reasons
5. **Transformation Errors**: Show specific field mapping or script execution failures with full context

### Key Changes

#### 1. Enhanced Python Script Error Handling
```go
// Before: Generic "script execution failed"
// After: Complete error analysis including:
// - Full Python stack trace with line numbers
// - Local variables at each stack frame
// - Actual code lines that caused errors
// - Input data context
// - Detailed error classification
```

#### 2. Comprehensive Error Data Structure
```json
{
  "error_type": "python_script_execution",
  "error_message": "ZeroDivisionError: division by zero",
  "python_error_details": {
    "error_type": "ZeroDivisionError",
    "error_message": "division by zero",
    "stack_trace": [
      {
        "filename": "/tmp/script_123.py",
        "line_number": 15,
        "function_name": "transform",
        "line_content": "calculation = user_age / 0",
        "local_variables": {
          "user_name": "john_doe",
          "user_age": 25,
          "user_data": {"name": "john_doe", "age": 25}
        }
      }
    ],
    "full_traceback": ["Traceback (most recent call last):", "..."]
  },
  "input_data": "{\"user\": \"john_doe\", \"age\": 25}",
  "timestamp": "2025-12-18T14:30:00Z"
}
```

#### 3. Database Schema Enhancement
Added `error_details` column to `request_logs` table to store comprehensive error information as JSON.

### Error Logging Functions

#### Enhanced `logFailedRequest()` Function
- Captures complete request and response data
- Includes detailed error messages
- Preserves HTTP status codes and response bodies

#### Enhanced `processRequest()` Function
- Returns detailed error responses instead of generic ones
- Includes underlying error details in response messages
- Maintains error context throughout the processing chain

### Logs Management UI Integration

The enhanced error logging integrates seamlessly with the existing logs management page:

- **Error Message Column**: Shows concise error descriptions
- **Request Details Modal**: Displays complete request/response data
- **Enhanced Error Details Section**: New modal section showing:
  - Full Python stack traces with line numbers
  - Local variables at each stack frame
  - Complete error context and execution flow
  - Input data that caused the error
  - Formatted and readable error presentation
- **Status Code Badges**: Color-coded status indicators
- **Real-time Updates**: Auto-refresh every 30 seconds

#### New Modal Features
- **Detailed Error Information**: Expandable section showing comprehensive error analysis
- **Stack Trace Visualization**: Frame-by-frame execution context
- **Local Variables Display**: Variable values at the time of error
- **Code Line Highlighting**: Exact lines that caused errors
- **Input Data Context**: Data that was being processed when error occurred

### Error Categories

#### 1. Authentication/Authorization Errors
- Rate limiting exceeded
- Invalid credentials
- Access denied

#### 2. Configuration Errors
- Missing API configuration
- Invalid connector setup
- Missing field mappings

#### 3. Transformation Errors
- Python script syntax errors
- Python script runtime errors
- Field mapping failures

#### 4. Outbound API Errors
- HTTP error status codes
- Network connectivity issues
- Response parsing failures

#### 5. Validation Errors
- Missing required fields
- Invalid data formats
- Security validation failures

## Benefits

### For Developers
- **Faster Debugging**: Specific error messages reduce troubleshooting time
- **Better Visibility**: Complete error context available in logs
- **Improved Monitoring**: Detailed error tracking and analysis

### For Operations
- **Proactive Issue Detection**: Detailed logs help identify problems early
- **Root Cause Analysis**: Complete error context enables faster resolution
- **Performance Monitoring**: Response times and error rates clearly visible

### For Users
- **Better Error Messages**: More informative error responses
- **Improved Reliability**: Faster issue resolution leads to better uptime
- **Enhanced Transparency**: Clear understanding of what went wrong

## Testing

The enhanced error logging has been tested with various failure scenarios:

1. **Python Script Errors**: Syntax errors, runtime exceptions, invalid transformations
2. **Outbound API Failures**: 404 errors, 500 errors, network timeouts
3. **Configuration Issues**: Missing APIs, invalid connectors, broken field mappings
4. **Validation Failures**: Invalid JSON, missing fields, security violations

## Files Modified

- `internal/services/transformation.go`: Complete Python error capture system with stack traces and local variables
- `internal/services/api_gateway.go`: Enhanced error handling and context preservation
- `internal/handlers/auth_ui.go`: Enhanced logs management UI with detailed error display
- `internal/models/request_log.go`: Added `error_details` field for comprehensive error storage
- `migrations/014_add_error_details_to_request_logs.sql`: Database schema update
- `test_enhanced_error_logging.py`: Comprehensive test cases for various error scenarios

## Usage

### Viewing Error Logs
1. Navigate to Organisation Dashboard
2. Click "Logs" in the navigation menu
3. View recent API requests with detailed error messages
4. Click "Details" button to see complete request/response data

### Error Message Format
Error messages now include comprehensive details with multiple levels of information:

#### Console/Log Format
```
Python ZeroDivisionError: division by zero

Stack Trace:
  Frame 1: transform() line 15
    Code: calculation = user_age / 0
    Local variables:
      user_name = "john_doe"
      user_age = 25
      user_data = {"name": "john_doe", "age": 25, "processed": true}

Full Python Traceback:
Traceback (most recent call last):
  File "/tmp/script_123.py", line 15, in transform
    calculation = user_age / 0
ZeroDivisionError: division by zero

Input Data Preview: {"user": "john_doe", "age": 25}
```

#### UI Modal Format
The logs management UI displays this information in a structured, readable format with:
- Collapsible sections for different error components
- Syntax highlighting for code snippets
- Formatted JSON for data structures
- Clear separation between error types and contexts

## Future Enhancements

1. **Error Categorization**: Group errors by type for better analysis
2. **Error Metrics**: Track error rates and patterns over time
3. **Alerting**: Automatic notifications for critical errors
4. **Error Recovery**: Automatic retry mechanisms for transient failures

## Conclusion

The detailed error logging enhancement significantly improves the platform's observability and debugging capabilities. Users can now quickly identify and resolve issues with specific, actionable error messages instead of generic failure notifications.