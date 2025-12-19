# Error Handler Bypass Fix

## Issue
The detailed Python error information was being captured correctly but was being processed by the error handler, which wrapped the original `ScriptExecutionError` with a generic `ClassifiedError`, losing all the detailed Python error information.

## Evidence from Request Logs
The Request Logs showed generic error handler information instead of detailed Python errors:
```json
{
  "connector_id": "2d2befda-b58e-49b8-9f0d-d1719e43f4e0",
  "error_message": "[script_execution:high] Script execution error",
  "error_type": "python_script_execution",
  "script_length": 159,
  "timestamp": "2025-12-18T19:55:01.44251795Z"
}
```

Instead of the expected detailed error information with:
- Actual Python error type (TypeError)
- Complete error message ("the JSON object must be str, bytes or bytearray, not dict")
- Stack trace with line numbers
- Local variables at time of error
- Full Python traceback

## Root Cause
The transformation service was using the error handler's `ExecuteWithFullProtection` method:

```go
err = s.errorHandler.ExecuteWithFullProtection(ctx, func() error {
    var execErr error
    result, execErr = s.executePythonScript(ctx, scriptPath, inputJSON)
    return execErr
}, "python_script_execution")
```

This caused the following flow:
1. **Python Script Fails**: `executePythonScript` returns `ScriptExecutionError` with detailed info
2. **Error Handler Wraps**: `ExecuteWithFullProtection` wraps it in a `ClassifiedError`
3. **Generic Error**: API gateway receives generic `[script_execution:high] Script execution error`
4. **Lost Details**: All Python-specific error details are lost

## The Fix

### 1. Bypass Error Handler for Python Execution
**Before:**
```go
err = s.errorHandler.ExecuteWithFullProtection(ctx, func() error {
    var execErr error
    result, execErr = s.executePythonScript(ctx, scriptPath, inputJSON)
    return execErr
}, "python_script_execution")

if err != nil {
    return nil, s.errorHandler.HandleError(ctx, err, map[string]interface{}{
        "operation":   "script_execution",
        "script_path": scriptPath,
    })
}
```

**After:**
```go
// Execute the Python script directly to preserve detailed error information
result, err := s.executePythonScript(ctx, scriptPath, inputJSON)
if err != nil {
    // Don't use error handler here as it would wrap the ScriptExecutionError
    // and lose the detailed Python error information
    s.logger.WithError(err).
        WithField("script_path", scriptPath).
        Error("Python script execution failed")
    return nil, err
}
```

### 2. Enhanced Debugging
Added debugging to confirm `ScriptExecutionError` with detailed info reaches the API gateway:

```go
if scriptErr, ok := err.(*ScriptExecutionError); ok {
    if scriptErr.DetailedError != nil {
        s.logger.WithField("has_python_error_details", true).
            WithField("python_error_type", scriptErr.DetailedError["error_type"]).
            Info("Found detailed Python error information in ScriptExecutionError")
    }
} else {
    s.logger.WithField("error_type", fmt.Sprintf("%T", err)).
        Warn("Error is not a ScriptExecutionError, detailed Python info may be lost")
}
```

## Expected Results After Fix

### Terminal Logs Should Show
```
INFO Found detailed Python error information in ScriptExecutionError has_python_error_details=true python_error_type=TypeError
INFO Captured detailed error information for logging error_details_length=2500 has_error_details=true
```

### Request Logs Should Show
```json
{
  "error_type": "python_script_execution",
  "connector_id": "uuid",
  "error_message": "Python TypeError: the JSON object must be str, bytes or bytearray, not dict",
  "python_error_details": {
    "success": false,
    "error_type": "TypeError",
    "error_message": "the JSON object must be str, bytes or bytearray, not dict",
    "detailed_error": {
      "stack_trace": [
        {
          "filename": "/tmp/script_123.py",
          "line_number": 8,
          "function_name": "transform",
          "line_content": "parsed_result = json.loads(invalid_json_data)",
          "local_variables": {
            "user_name": "test_user",
            "user_data": {"name": "test_user", "processed": true},
            "invalid_json_data": {"key": "value"}
          }
        }
      ],
      "full_traceback": ["Traceback (most recent call last):", "..."]
    }
  }
}
```

### Request Logs UI Should Display
- **Error Type**: TypeError
- **Error Message**: "the JSON object must be str, bytes or bytearray, not dict"
- **Stack Trace**: Frame-by-frame execution with line numbers
- **Local Variables**: All variable values at time of error
- **Code Context**: Exact line that caused the error
- **Full Traceback**: Complete Python traceback

## Why This Fix Works

### 1. Preserves Error Type
By bypassing the error handler, the original `ScriptExecutionError` with its `DetailedError` field intact reaches the API gateway.

### 2. Maintains Error Context
The API gateway can properly extract the detailed Python error information from `ScriptExecutionError.DetailedError`.

### 3. Complete Information Flow
The full error context flows from Python script → transformation service → API gateway → database → UI without being wrapped or modified.

### 4. Debugging Visibility
Enhanced logging confirms that detailed error information is being preserved at each step.

## Testing the Fix

### 1. Use Test Scripts
Use the provided test scripts in `tests/python_error_tests/test_error_handler_bypass.py`:
- JSON TypeError test
- ZeroDivisionError test

### 2. Check Terminal Logs
Look for these messages:
- `"Found detailed Python error information in ScriptExecutionError"`
- `"Captured detailed error information for logging"`

### 3. Verify Request Logs UI
1. Navigate to Request Logs
2. Find the failed request
3. Click "Details"
4. Check "Detailed Error Information" section
5. Verify complete Python error details are displayed

### 4. Confirm No Generic Messages
The error details should NOT show:
- `"[script_execution:high] Script execution error"`
- Generic error handler messages
- Wrapped or classified errors

## Files Modified

- `internal/services/transformation.go`: Bypassed error handler for Python execution
- `internal/services/api_gateway.go`: Enhanced debugging for ScriptExecutionError detection
- `tests/python_error_tests/test_error_handler_bypass.py`: Test scripts for verification

## Impact

This fix ensures that:
- ✅ Complete Python error details reach the Request Logs UI
- ✅ TypeError messages show the actual Python error
- ✅ Stack traces include line numbers and local variables
- ✅ Error context is preserved throughout the pipeline
- ✅ No information is lost to error handler wrapping
- ✅ Debugging logs confirm proper error flow

The detailed Python error information that you can see in the terminal should now appear in the Request Logs UI with complete context and debugging information.