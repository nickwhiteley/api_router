# Error Details Display Fix

## Issue
The detailed error information was not being displayed in the Request Details panel of the Logs Management page, even though the error capture system was implemented.

## Root Cause
The problem was in the context flow between the `processRequest` function and the `logRequest` function:

1. **Context Modification**: The `processRequest` function was adding detailed error information to the context using `context.WithValue()`
2. **Context Loss**: However, the modified context was not being returned from `processRequest`
3. **Original Context Used**: The `HandleInboundRequest` function was still using the original context when calling `logRequest`
4. **Missing Error Details**: As a result, the detailed error information was lost and not stored in the database

## Solution

### 1. Modified Function Signature
Changed `processRequest` to return the updated context:

**Before:**
```go
func (s *apiGatewayService) processRequest(ctx context.Context, requestData map[string]interface{}, connector *models.Connector, apiConfig *models.APIConfiguration) (*http.Response, error)
```

**After:**
```go
func (s *apiGatewayService) processRequest(ctx context.Context, requestData map[string]interface{}, connector *models.Connector, apiConfig *models.APIConfiguration) (context.Context, *http.Response, error)
```

### 2. Updated Return Statements
Modified all return statements in `processRequest` to return the context:

**Before:**
```go
return s.createErrorResponse(http.StatusInternalServerError, simpleErrorMsg), fmt.Errorf("python script transformation failed")
```

**After:**
```go
return ctx, s.createErrorResponse(http.StatusInternalServerError, simpleErrorMsg), fmt.Errorf("python script transformation failed")
```

### 3. Updated Function Calls
Modified the call to `processRequest` in `HandleInboundRequest` to capture the updated context:

**Before:**
```go
response, err := s.processRequest(ctx, requestData, activeConnector, apiConfig)
// ...
s.logRequest(ctx, activeConnector, requestID, req, response, processingTime, err.Error())
```

**After:**
```go
updatedCtx, response, err := s.processRequest(ctx, requestData, activeConnector, apiConfig)
// ...
s.logRequest(updatedCtx, activeConnector, requestID, req, response, processingTime, err.Error())
```

### 4. Added Debugging
Added logging to track error details capture:

```go
if errorDetailsData := ctx.Value("detailed_error"); errorDetailsData != nil {
    if detailsBytes, err := json.Marshal(errorDetailsData); err == nil {
        errorDetails = string(detailsBytes)
        s.logger.WithField("error_details_length", len(errorDetails)).
            WithField("has_error_details", true).
            Info("Captured detailed error information for logging")
    }
} else {
    s.logger.WithField("has_error_details", false).
        Info("No detailed error information found in context")
}
```

## Error Details Flow

### Complete Flow (Fixed)
1. **Error Occurs**: Python script fails with detailed error information
2. **Error Capture**: `executePythonScript` captures full stack trace, local variables, etc.
3. **Context Addition**: `processRequest` adds detailed error info to context
4. **Context Return**: `processRequest` returns the updated context
5. **Context Usage**: `HandleInboundRequest` uses updated context for logging
6. **Database Storage**: `logRequest` extracts error details from context and stores in database
7. **UI Display**: Logs management page retrieves error details from database and displays in modal

### Data Structure Stored
The error details are stored as JSON in the `error_details` field:

```json
{
  "error_type": "python_script_execution",
  "connector_id": "uuid",
  "script_length": 150,
  "error_message": "ZeroDivisionError: division by zero...",
  "timestamp": "2025-12-18T14:30:00Z",
  "exit_code": 1,
  "stderr": "Python error output",
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
  }
}
```

## Testing the Fix

### 1. Create Test Connector
Use one of the test scripts from `test_error_details_capture.py`:

```python
def transform(input_data):
    # This will cause a ZeroDivisionError with local context
    user_name = input_data.get('name', 'unknown')
    user_age = input_data.get('age', 0)
    calculation = user_age / 0  # Error here
    return {"user": user_name, "calculation": calculation}
```

### 2. Send Test Request
Send a request to the connector endpoint to trigger the error.

### 3. Check Logs
1. Navigate to Organisation Dashboard → Logs
2. Find the failed request (red status badge)
3. Click "Details" button
4. Look for "Detailed Error Information" section
5. Verify it shows:
   - Error type and message
   - Stack trace with line numbers
   - Local variables at time of error
   - Full Python traceback

### 4. Verify Debugging Logs
Check server logs for messages like:
```
INFO Captured detailed error information for logging error_details_length=1234 has_error_details=true
```

## Files Modified

- `internal/services/api_gateway.go`: Fixed context flow and added debugging
- `test_error_details_capture.py`: Test scripts for verification

## Expected Results

After this fix:
- ✅ Detailed error information appears in Request Details modal
- ✅ Stack traces with line numbers are visible
- ✅ Local variables at time of error are shown
- ✅ Full Python traceback is displayed
- ✅ Error context is preserved throughout the request pipeline
- ✅ Debugging logs confirm error details capture

## Verification Checklist

- [ ] Python script errors show detailed stack traces
- [ ] Local variables are displayed in error details
- [ ] Full Python traceback is visible
- [ ] Error details section appears in modal
- [ ] JSON formatting is correct and readable
- [ ] Server logs show successful error details capture
- [ ] Database contains error_details JSON data

The fix ensures that the comprehensive error information captured during Python script execution is properly stored in the database and displayed in the user interface, providing developers with complete debugging context.