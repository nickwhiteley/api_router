# Error Details Capture Fix

## Issue
The full Python error details (like "TypeError: the JSON object must be str, bytes or bytearray") were visible in the terminal logs but not appearing in the Request Logs UI.

## Root Cause
The issue was in the transformation service error handling flow:

1. **Python Script Execution**: When a Python script failed, it returned detailed error information in a structured format
2. **Error Processing**: The transformation service was parsing this detailed error information correctly
3. **Error Return**: However, it was returning a generic `fmt.Errorf()` instead of a `ScriptExecutionError` with the detailed information
4. **Context Loss**: The API gateway was looking for `ScriptExecutionError.DetailedError` to populate the context, but since a generic error was returned, the detailed information was lost
5. **Database Storage**: Without the detailed error in the context, only generic error messages were stored in the database

## The Fix

### 1. Updated Error Return in Transformation Service
**Before:**
```go
// When Python script returned structured error
return nil, fmt.Errorf("%s", errorDetails.String())
```

**After:**
```go
// Create a ScriptExecutionError with detailed information
scriptError := &ScriptExecutionError{
    Message:       fmt.Sprintf("Python %s: %s", errorType, errorMessage),
    ScriptPath:    scriptPath,
    ExitCode:      0, // Script ran but returned error
    Stderr:        "", // No stderr since script executed successfully but returned error
    DetailedError: result, // Store the complete error result from Python
}

// Add input data if available
if inputPreview, ok := result["input_data_preview"].(string); ok {
    scriptError.InputData = inputPreview
}

return nil, scriptError
```

### 2. Enhanced Debugging
Added comprehensive logging to track error details flow:

**API Gateway Logging:**
```go
s.logger.WithField("error_details_length", len(errorDetails)).
    WithField("has_error_details", true).
    WithField("error_details_preview", errorDetails[:200]).
    Info("Captured detailed error information for logging")
```

**UI Handler Logging:**
```go
if log.ErrorDetails != "" {
    h.logger.WithField("request_id", log.RequestID).
        WithField("error_details_length", len(log.ErrorDetails)).
        Info("Found error details in database for request log")
}
```

## Error Details Flow (Fixed)

### Complete Flow
1. **Python Script Fails**: Script encounters error (e.g., TypeError)
2. **Detailed Capture**: Python wrapper captures full stack trace, local variables, error type, etc.
3. **Structured Return**: Python returns structured error with `success: false` and detailed error info
4. **Error Processing**: Transformation service parses the structured error
5. **ScriptExecutionError Creation**: Creates `ScriptExecutionError` with `DetailedError` field populated
6. **Context Population**: API gateway extracts `DetailedError` and adds to context
7. **Database Storage**: Complete error details stored as JSON in `error_details` column
8. **UI Display**: Logs management page retrieves and displays detailed error information

### Data Structure Stored
```json
{
  "error_type": "python_script_execution",
  "connector_id": "uuid",
  "script_length": 150,
  "error_message": "Python TypeError: the JSON object must be str, bytes or bytearray",
  "timestamp": "2025-12-18T15:30:00Z",
  "python_error_details": {
    "success": false,
    "error_type": "TypeError",
    "error_message": "the JSON object must be str, bytes or bytearray",
    "detailed_error": {
      "error_type": "TypeError",
      "error_message": "the JSON object must be str, bytes or bytearray",
      "stack_trace": [
        {
          "filename": "/tmp/script_123.py",
          "line_number": 8,
          "function_name": "transform",
          "line_content": "parsed_data = json.loads(invalid_json)",
          "local_variables": {
            "input_data": {"test": "data"},
            "invalid_json": {"key": "value"}
          }
        }
      ],
      "full_traceback": ["Traceback (most recent call last):", "..."]
    },
    "input_data_preview": "{\"test\": \"data\"}"
  }
}
```

## Testing the Fix

### 1. Create Test Connector
Use the TypeError test script:
```python
def transform(input_data):
    import json
    invalid_json = {"key": "value"}  # This is already a dict
    parsed_data = json.loads(invalid_json)  # This will fail with TypeError
    return {"result": parsed_data}
```

### 2. Send Test Request
Send a request to trigger the error.

### 3. Check Terminal Logs
You should see detailed logging:
```
INFO Captured detailed error information for logging error_details_length=1234 has_error_details=true
```

### 4. Check Request Logs UI
1. Navigate to Organisation Dashboard → Logs
2. Find the failed request
3. Click "Details" button
4. Look for "Detailed Error Information" section
5. Verify it shows:
   - Error type: TypeError
   - Error message: "the JSON object must be str, bytes or bytearray"
   - Stack trace with line numbers
   - Local variables showing the invalid_json dict
   - Full Python traceback

### 5. Verify Database Storage
The error details should now be stored in the `request_logs.error_details` column as JSON.

## Expected Results

After this fix:
- ✅ Full Python error messages appear in Request Logs UI
- ✅ TypeError details are captured and displayed
- ✅ Stack traces show exact line that caused the error
- ✅ Local variables reveal the problematic data
- ✅ Complete error context is preserved from terminal to UI
- ✅ Debugging logs confirm error details capture and storage

## Files Modified

- `internal/services/transformation.go`: Fixed error return to use ScriptExecutionError with detailed info
- `internal/services/api_gateway.go`: Enhanced debugging for error details capture
- `internal/handlers/auth_ui.go`: Added debugging for error details retrieval
- `test_type_error.py`: Test script to verify TypeError capture

## Verification Checklist

- [ ] TypeError appears in Request Logs UI with full message
- [ ] Stack trace shows the exact line with `json.loads(invalid_json)`
- [ ] Local variables show the `invalid_json` dict value
- [ ] Terminal logs show "Captured detailed error information for logging"
- [ ] UI logs show "Found error details in database for request log"
- [ ] Error details section is visible in the modal
- [ ] JSON formatting is correct and readable

The fix ensures that all Python error details visible in the terminal are now properly captured, stored in the database, and displayed in the Request Logs UI.