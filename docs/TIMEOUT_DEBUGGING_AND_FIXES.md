# Timeout Debugging and Fixes

## Issue
User is experiencing a 500ms timeout when executing Python scripts, which is much shorter than the configured timeouts.

## Timeout Configurations

### Current Timeout Settings
1. **Python Script Timeout**: 60 seconds (in Python wrapper)
2. **Go Context Timeout**: 65 seconds (in transformation service)
3. **Server Read/Write Timeout**: 30 seconds (from config.yaml)
4. **Config Python Timeout**: 30 seconds (from config.yaml)

### 500ms Timeout Analysis
The 500ms timeout is extremely short and doesn't match any of our configured timeouts. This suggests the timeout is coming from:

1. **External Load Balancer/Proxy**: A reverse proxy or load balancer might have a short timeout
2. **Container/Orchestration Platform**: Docker, Kubernetes, or similar might have timeout limits
3. **Network Infrastructure**: Network equipment might be timing out connections
4. **Client-side Timeout**: The client making the request might have a short timeout
5. **OS-level Resource Limits**: System resource limits might be causing early termination

## Fixes Implemented

### 1. Increased Memory Limit
**Problem**: 128MB memory limit might be too restrictive
**Fix**: Increased to 512MB with error handling
```python
# Set memory limit (512MB) - increased to avoid memory issues
try:
    resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
except (ValueError, OSError) as e:
    # If setting memory limit fails, continue without it
    pass
```

### 2. Enhanced Python Command Detection
**Problem**: `python3` might not be available
**Fix**: Added fallback to `python`
```go
// Try python3 first, then python as fallback
pythonCmd := "python3"
if _, err := exec.LookPath("python3"); err != nil {
    s.logger.Warn("python3 not found, trying python")
    pythonCmd = "python"
}
```

### 3. Comprehensive Debugging
**Problem**: Limited visibility into execution failures
**Fix**: Added detailed logging throughout execution
```go
// Log execution start, duration, and results
s.logger.WithField("script_path", wrapperPath).
    WithField("python_cmd", pythonCmd).
    WithField("timeout_seconds", 65).
    Info("Starting Python script execution")

// Log execution completion with timing
s.logger.WithField("execution_time_ms", executionTime.Milliseconds()).
    WithField("stdout_length", stdout.Len()).
    WithField("stderr_length", stderr.Len()).
    WithField("has_error", err != nil).
    Info("Python script execution completed")
```

### 4. Enhanced Error Handling
**Problem**: Generic error messages don't help identify timeout source
**Fix**: Specific handling for different error types
```go
// Check for context timeout
if ctx.Err() == context.DeadlineExceeded {
    s.logger.WithField("execution_time_ms", executionTime.Milliseconds()).
        WithField("stderr", stderrStr).
        Error("Python script execution timed out")
    return nil, fmt.Errorf("python script execution timed out after %v", executionTime)
}
```

### 5. File Access Verification
**Problem**: Script file might not be accessible
**Fix**: Check file accessibility before execution
```go
// Check if the script file exists and is readable
if _, err := os.Stat(wrapperPath); err != nil {
    s.logger.WithError(err).WithField("script_path", wrapperPath).Error("Script file not accessible")
    return nil, fmt.Errorf("script file not accessible: %w", err)
}
```

## Debugging Steps

### 1. Check Server Logs
Look for these log messages to understand what's happening:
- `"Starting Python script execution"` - Script execution started
- `"Python script execution completed"` - Script finished (check execution_time_ms)
- `"Python script execution timed out"` - Context timeout occurred
- `"python3 not found, trying python"` - Python command fallback
- `"Script file not accessible"` - File permission issues

### 2. Verify Python Installation
```bash
python3 --version
python3 -c "import json; print(json.dumps({'test': 'success'}))"
```

### 3. Test Simple Script
Use the provided test scripts:
- `test_simple_python.py` - Basic functionality test
- `test_python_execution.py` - Transform function test
- `test_timeout_fix.py` - Timeout scenario tests

### 4. Check System Resources
```bash
# Check memory limits
ulimit -a

# Check available memory
free -h

# Check disk space
df -h

# Check Python process limits
python3 -c "import resource; print('Memory limit:', resource.getrlimit(resource.RLIMIT_AS))"
```

### 5. Monitor Request Flow
Check logs for the complete request flow:
1. Request received by API gateway
2. Connector processing started
3. Python script execution started
4. Python script execution completed/failed
5. Response returned to client

## Potential External Causes

### 1. Load Balancer/Proxy Timeout
If using nginx, Apache, or cloud load balancer:
```nginx
# nginx example
proxy_read_timeout 300s;
proxy_connect_timeout 300s;
proxy_send_timeout 300s;
```

### 2. Container Platform Limits
If using Docker/Kubernetes:
```yaml
# Kubernetes example
resources:
  limits:
    memory: "1Gi"
    cpu: "1000m"
  requests:
    memory: "512Mi"
    cpu: "500m"
```

### 3. Cloud Platform Timeouts
- **AWS Lambda**: 15-minute maximum
- **Google Cloud Functions**: 9-minute maximum
- **Azure Functions**: 10-minute maximum
- **Heroku**: 30-second request timeout

### 4. Client-side Timeouts
Check if the client (browser, API client, etc.) has a short timeout configured.

## Testing the Fixes

### 1. Simple Test
Create a connector with this Python script:
```python
def transform(input_data):
    import time
    time.sleep(2)  # 2-second delay
    return {"status": "success", "input": input_data}
```

### 2. Monitor Logs
Watch the server logs during execution:
```bash
tail -f /path/to/logs | grep -E "(Starting Python|Python script execution|timed out)"
```

### 3. Check Execution Time
Look for `execution_time_ms` in the logs to see actual execution duration.

## Expected Results After Fixes

1. **Detailed Logging**: Clear visibility into execution flow and timing
2. **Better Error Messages**: Specific error types and causes
3. **Increased Reliability**: Higher memory limits and better error handling
4. **Timeout Identification**: Clear indication if timeout is from our system or external

## Next Steps if Issue Persists

1. **Check External Infrastructure**: Load balancers, proxies, cloud platform limits
2. **Monitor System Resources**: Memory, CPU, disk usage during execution
3. **Test with Minimal Script**: Use simplest possible Python script
4. **Check Client Timeout**: Verify client-side timeout configuration
5. **Network Analysis**: Check for network-level timeouts or interruptions

## Files Modified

- `internal/services/transformation.go`: Enhanced timeout handling and debugging
- `test_simple_python.py`: Simple test script
- `test_python_execution.py`: Transform function test
- `test_timeout_fix.py`: Timeout scenario tests

The enhanced debugging should help identify exactly where the 500ms timeout is coming from and provide the information needed to resolve it.