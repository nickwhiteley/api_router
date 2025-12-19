# Error Message and Timeout Fixes

## Overview
Fixed two critical issues with the enhanced error logging system:
1. **Error Message Length**: Detailed error information was being returned to API clients instead of just being logged
2. **Timeout Issues**: Python script execution was timing out too quickly due to signal handling issues

## Issues Fixed

### 1. Error Message Length Issue

#### Problem
The comprehensive error details (including full stack traces, local variables, etc.) were being returned in the HTTP response to API clients, making responses very large and exposing internal implementation details.

#### Solution
- **Client Response**: Return simple, user-friendly error messages to API clients
- **Detailed Logging**: Keep comprehensive error details in server logs and database for debugging
- **Separation of Concerns**: Clear distinction between client-facing messages and internal debugging information

#### Changes Made

**Before:**
```json
{
  "error": "Python script transformation failed: ZeroDivisionError: division by zero\n\nStack Trace:\n  Frame 1: transform() line 15\n    Code: calculation = user_age / 0\n    Local variables:\n      user_name = \"john_doe\"\n      user_age = 25\n..."
}
```

**After:**
```json
{
  "error": "Python script transformation failed"
}
```

The detailed error information is still captured and available in:
- Server logs (with structured logging)
- Request logs database (in `error_details` field)
- Logs management UI (in detailed error modal)

### 2. Timeout Issues

#### Problem
Python scripts were timing out very quickly, possibly due to signal handling issues in containerized environments or process isolation problems.

#### Solution
- **Increased Timeout**: Extended timeout from 30 to 60 seconds
- **Improved Timeout Mechanism**: Replaced signal-based timeout with thread-based timeout for better compatibility
- **Context Timeout**: Extended Go context timeout to 65 seconds to allow Python timeout to trigger first

#### Changes Made

**Signal-based Timeout (Before):**
```python
import signal

def timeout_handler(signum, frame):
    raise TimeoutError("Script execution timeout")

signal.signal(signal.SIGALRM, timeout_handler)
signal.alarm(30)  # 30 second timeout
```

**Thread-based Timeout (After):**
```python
import threading
import time as time_module

def timeout_handler():
    time_module.sleep(60)  # 60 second timeout
    os._exit(124)  # Exit with timeout code

timeout_thread = threading.Thread(target=timeout_handler, daemon=True)
timeout_thread.start()
```

## Error Message Simplification

### Client-Facing Error Messages
All error messages returned to API clients are now simplified:

| Error Type | Client Message | Detailed Info Location |
|------------|----------------|------------------------|
| Python Script Error | "Python script transformation failed" | Logs + Database |
| Field Mapping Error | "Field mapping transformation failed" | Logs + Database |
| Configuration Error | "Configuration error" | Logs + Database |
| Outbound API Error | "Outbound API request failed" | Logs + Database |
| Outbound Status Error | "Outbound API error (status XXX)" | Logs + Database |

### Detailed Information Still Available
The comprehensive error details are still captured and available through:

1. **Server Logs**: Structured logging with all error context
2. **Database**: `request_logs.error_details` field contains full JSON error information
3. **Logs Management UI**: Detailed error modal shows complete stack traces and context
4. **Monitoring**: Error patterns and frequencies for operational insights

## Benefits

### For API Clients
- **Clean Responses**: Simple, consistent error messages
- **No Information Leakage**: Internal implementation details not exposed
- **Faster Responses**: Smaller response payloads
- **Better UX**: User-friendly error messages

### For Developers
- **Complete Debugging Info**: Full error context still available in logs
- **Structured Data**: Error details stored as structured JSON
- **Easy Access**: Logs management UI provides easy access to detailed errors
- **Performance**: Detailed error processing doesn't impact client response times

### For Operations
- **Security**: Internal details not exposed to clients
- **Monitoring**: Error patterns visible in logs and database
- **Debugging**: Complete error context available when needed
- **Compliance**: Sensitive information stays internal

## Implementation Details

### Error Context Flow
1. **Error Occurs**: Python script or other component fails
2. **Detailed Capture**: Complete error context captured (stack trace, variables, etc.)
3. **Context Storage**: Detailed error added to request context
4. **Simple Response**: Simple error message returned to client
5. **Detailed Logging**: Complete error context logged and stored in database
6. **UI Access**: Detailed error available in logs management interface

### Timeout Handling
1. **Thread-based Timeout**: More reliable than signal-based approach
2. **Graceful Exit**: Process exits cleanly on timeout
3. **Context Coordination**: Go context timeout slightly longer than Python timeout
4. **Error Classification**: Timeout errors properly classified and logged

## Testing

### Error Message Testing
- Verify client responses contain only simple error messages
- Confirm detailed error information is captured in logs
- Test logs management UI displays complete error details

### Timeout Testing
- Quick scripts (< 1 second) should execute normally
- Medium scripts (5-10 seconds) should complete successfully
- Long scripts (> 60 seconds) should timeout gracefully
- Timeout errors should be properly logged and classified

## Files Modified

- `internal/services/api_gateway.go`: Simplified client error messages, enhanced logging
- `internal/services/transformation.go`: Improved timeout handling mechanism
- `test_timeout_fix.py`: Test cases for timeout scenarios

## Conclusion

These fixes ensure that:
1. **API clients receive clean, simple error messages** without internal implementation details
2. **Developers have access to complete error context** through logs and database
3. **Python script timeouts are handled reliably** with appropriate timeout values
4. **System maintains security** by not exposing internal details to clients
5. **Debugging capabilities are preserved** while improving client experience

The system now provides the best of both worlds: clean client interfaces and comprehensive debugging capabilities.