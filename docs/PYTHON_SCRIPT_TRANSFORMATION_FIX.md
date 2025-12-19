# Python Script Transformation Fix

## Issue
Python script transformations were failing with the error:
```
"script error: invalid decimal literal (<string>, line 1)"
```

This error occurred when the transformation service tried to execute user-provided Python scripts for data transformation.

## Root Cause
The issue was in the `executePythonScript` function in `internal/services/transformation.go`. The function was creating a wrapper Python script that embedded JSON input data directly into Python code using string formatting:

```go
wrapperScript := fmt.Sprintf(`
...
    # Provide input data
    input_data = %s  // <-- PROBLEM: Direct JSON insertion
...
`, string(inputData), scriptPath)
```

When the `inputData` contained JSON like `{"key": "value", "number": 123}`, it would be inserted directly into the Python code as:

```python
input_data = {"key": "value", "number": 123}
```

However, this approach had several problems:
1. **JSON vs Python syntax differences**: JSON uses `null`, `true`, `false` while Python uses `None`, `True`, `False`
2. **String escaping issues**: JSON strings with special characters could break Python syntax
3. **Number format issues**: JSON numbers might not be valid Python literals
4. **Complex structures**: Nested objects and arrays could cause syntax errors

## Solution

### 1. Proper JSON Escaping
Instead of embedding JSON directly as Python code, the fix properly escapes the JSON string and parses it within Python:

```go
// Properly escape the JSON data for Python
escapedInputData := fmt.Sprintf("%q", string(inputData))

wrapperScript := fmt.Sprintf(`
...
try:
    # Provide input data - parse from JSON string
    input_data_json = %s  // <-- Escaped JSON string
    input_data = json.loads(input_data_json)  // <-- Parse in Python
    
    # Execute the user script
    exec(open('%s').read())
...
`, escapedInputData, scriptPath)
```

### 2. Enhanced Error Messages
Added more user-friendly error messages for common Python script issues:

```go
// Provide more user-friendly error messages
if errorMsg == "Script must define a 'transform' function" {
    return nil, fmt.Errorf("Python script must define a 'transform(input_data)' function that returns the transformed data")
}

// Better error categorization
if strings.Contains(stderrStr, "SyntaxError") {
    return nil, fmt.Errorf("Python syntax error in script: %s", stderrStr)
}
if strings.Contains(stderrStr, "NameError") {
    return nil, fmt.Errorf("Python name error (undefined variable/function): %s", stderrStr)
}
if strings.Contains(stderrStr, "IndentationError") {
    return nil, fmt.Errorf("Python indentation error: %s", stderrStr)
}
```

## How It Works Now

### 1. Input Data Processing
1. Input data is marshaled to JSON: `{"key": "value", "number": 123}`
2. JSON string is properly escaped for Python: `"{\"key\": \"value\", \"number\": 123}"`
3. Python wrapper script receives the escaped string
4. Python parses the JSON using `json.loads()` to get proper Python objects

### 2. Script Execution Flow
1. **Wrapper Creation**: Creates a secure Python wrapper with resource limits and timeouts
2. **Data Injection**: Safely injects input data as an escaped JSON string
3. **Script Execution**: Executes user script with `exec()`
4. **Function Call**: Calls the user's `transform()` function with parsed input data
5. **Result Capture**: Captures and returns the transformed result as JSON

### 3. Error Handling
- **Syntax Errors**: Clear messages about Python syntax issues
- **Runtime Errors**: Detailed error messages with context
- **Missing Function**: Helpful message about required `transform()` function
- **Timeout Protection**: 30-second execution limit
- **Memory Protection**: 128MB memory limit

## Python Script Requirements

For Python scripts to work correctly, they must:

### 1. Define a `transform` Function
```python
def transform(input_data):
    # Transform the input data
    result = {
        "transformed": input_data
    }
    return result
```

### 2. Handle Input Data Structure
The `input_data` parameter contains the request data as a Python dictionary:
```python
def transform(input_data):
    # Access request fields
    user_name = input_data.get('user', {}).get('name', '')
    
    # Transform data
    result = {
        "customer_name": user_name.upper(),
        "processed_at": "2025-12-18T12:00:00Z"
    }
    return result
```

### 3. Return Valid JSON-Serializable Data
The return value must be serializable to JSON:
```python
def transform(input_data):
    # Valid return types: dict, list, str, int, float, bool, None
    return {
        "status": "success",
        "data": input_data,
        "count": len(input_data) if isinstance(input_data, dict) else 1
    }
```

## Example Usage

### Input Data
```json
{
    "user": {
        "firstName": "John",
        "lastName": "Doe",
        "email": "john.doe@example.com"
    },
    "order": {
        "id": 12345,
        "amount": 99.99
    }
}
```

### Python Script
```python
def transform(input_data):
    user = input_data.get('user', {})
    order = input_data.get('order', {})
    
    # Transform to different structure
    result = {
        "customer": {
            "fullName": f"{user.get('firstName', '')} {user.get('lastName', '')}".strip(),
            "contactEmail": user.get('email', '')
        },
        "purchase": {
            "orderId": order.get('id'),
            "totalAmount": order.get('amount'),
            "currency": "USD"
        },
        "processedAt": "2025-12-18T12:00:00Z"
    }
    
    return result
```

### Output
```json
{
    "customer": {
        "fullName": "John Doe",
        "contactEmail": "john.doe@example.com"
    },
    "purchase": {
        "orderId": 12345,
        "totalAmount": 99.99,
        "currency": "USD"
    },
    "processedAt": "2025-12-18T12:00:00Z"
}
```

## Security Features

### Resource Limits
- **Memory Limit**: 128MB maximum memory usage
- **Execution Timeout**: 30-second maximum execution time
- **Signal Handling**: Proper timeout handling with SIGALRM

### Sandboxing
- **Temporary Files**: Scripts run in isolated temporary files
- **No Network Access**: Scripts cannot make external network calls
- **Limited System Access**: Restricted access to system resources

### Error Isolation
- **Exception Handling**: All script errors are caught and reported
- **Clean Cleanup**: Temporary files are always removed
- **Safe Execution**: Script failures don't crash the main application

## Testing

### Test Valid Script
```python
def transform(input_data):
    return {"result": "success", "input": input_data}
```

### Test Error Scenarios
1. **Missing Function**: Script without `transform()` function
2. **Syntax Error**: Script with invalid Python syntax
3. **Runtime Error**: Script that throws exceptions
4. **Invalid Return**: Script that returns non-serializable data

## Files Modified
- `internal/services/transformation.go`: Fixed JSON data injection and enhanced error handling

## Dependencies
- **Python 3**: Required for script execution
- **JSON Module**: Used for data parsing and serialization
- **Resource Module**: Used for memory and execution limits
- **Signal Module**: Used for timeout handling