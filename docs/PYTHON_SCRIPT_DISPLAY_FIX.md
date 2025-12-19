# Python Script Display Fix

## Issue
When viewing Python scripts in the connector edit form, they appear as escaped single-line strings instead of properly formatted multi-line code. For example:

**Problem Display:**
```
def transform(input_data):\n    return {\"result\": input_data}\n
```

**Expected Display:**
```python
def transform(input_data):
    return {"result": input_data}
```

## Root Cause
When connector data is retrieved via the API endpoint `/manage/org/{orgID}/connectors/{connectorID}`, the Python script is JSON-encoded as part of the response. JSON encoding converts:
- Newlines (`\n`) to `\\n`
- Quotes (`"`) to `\"`
- Backslashes (`\`) to `\\`

When this JSON is parsed in JavaScript, the escape sequences remain as literal strings instead of being converted back to their original characters.

## Solution
Added a JavaScript function `unescapePythonScript()` that properly converts JSON escape sequences back to their original characters before displaying the script in the textarea.

### JavaScript Function Added
```javascript
function unescapePythonScript(script) {
    if (!script) return '';
    
    // Unescape common JSON escape sequences
    return script
        .replace(/\\n/g, '\n')      // Newlines
        .replace(/\\r/g, '\r')      // Carriage returns
        .replace(/\\t/g, '\t')      // Tabs
        .replace(/\\"/g, '"')       // Double quotes
        .replace(/\\\\/g, '\\');    // Backslashes (must be last)
}
```

### Updated Script Loading
```javascript
} else if (connector.python_script) {
    // Has Python script
    document.querySelector('input[name="edit_transformation_method"][value="script"]').checked = true;
    // Properly unescape the Python script for display
    document.getElementById('editPythonScript').value = unescapePythonScript(connector.python_script);
    toggleEditTransformationMethod();
}
```

## How It Works

### 1. Data Flow
1. **Database Storage**: Python script stored as TEXT with proper formatting
2. **API Response**: Script JSON-encoded with escape sequences (`\n`, `\"`, etc.)
3. **JavaScript Parsing**: JSON parsed but escape sequences remain as strings
4. **Unescaping**: `unescapePythonScript()` converts escape sequences back to actual characters
5. **Display**: Properly formatted script shown in textarea

### 2. Escape Sequence Handling
| Original | JSON Encoded | After Unescaping |
|----------|--------------|------------------|
| `\n` (newline) | `\\n` | `\n` (actual newline) |
| `\t` (tab) | `\\t` | `\t` (actual tab) |
| `"` (quote) | `\"` | `"` (actual quote) |
| `\` (backslash) | `\\` | `\` (actual backslash) |

### 3. Order of Operations
The replacement order is important:
1. **Newlines first**: `\n` → actual newlines
2. **Carriage returns**: `\r` → actual carriage returns  
3. **Tabs**: `\t` → actual tabs
4. **Quotes**: `\"` → actual quotes
5. **Backslashes last**: `\\` → actual backslashes (must be last to avoid double-processing)

## Testing

### Test Cases
1. **Simple Script**:
   ```python
   def transform(input_data):
       return input_data
   ```

2. **Script with Quotes**:
   ```python
   def transform(input_data):
       return {"message": "Hello \"World\""}
   ```

3. **Script with Complex Formatting**:
   ```python
   def transform(input_data):
       # Process user data
       user = input_data.get('user', {})
       
       return {
           "name": user.get('name', ''),
           "email": user.get('email', ''),
           "processed": True
       }
   ```

### Verification Steps
1. Create a connector with a multi-line Python script
2. Save the connector
3. Edit the connector
4. Verify the script displays with proper formatting (newlines, indentation, quotes)
5. Verify the script can be edited and saved again

## Alternative Solutions Considered

### 1. Server-Side Unescaping
- **Approach**: Modify the API response to send unescaped strings
- **Issue**: Would break JSON format and cause parsing errors
- **Verdict**: Not viable

### 2. Base64 Encoding
- **Approach**: Encode Python scripts as Base64 in API responses
- **Issue**: Adds complexity and makes debugging harder
- **Verdict**: Overkill for this issue

### 3. Separate Endpoint for Scripts
- **Approach**: Create dedicated endpoint for retrieving Python scripts as plain text
- **Issue**: Requires additional API calls and complexity
- **Verdict**: Unnecessary when JavaScript solution works

## Files Modified
- `internal/handlers/auth_ui.go`: Added `unescapePythonScript()` function and updated script loading logic

## Browser Compatibility
The solution uses standard JavaScript string methods that are supported in all modern browsers:
- `String.replace()` with regular expressions
- Basic string manipulation
- No external dependencies required

## Future Enhancements

### 1. Syntax Highlighting
Could add syntax highlighting for Python code in the textarea:
```javascript
// Example with a syntax highlighting library
function applySyntaxHighlighting(textarea) {
    // Apply Python syntax highlighting
}
```

### 2. Code Validation
Could add client-side Python syntax validation:
```javascript
function validatePythonSyntax(script) {
    // Basic syntax validation
    // Check for common issues like mismatched brackets, indentation
}
```

### 3. Code Formatting
Could add automatic code formatting:
```javascript
function formatPythonCode(script) {
    // Apply consistent indentation and formatting
}
```

## Security Considerations
The unescaping function only handles standard JSON escape sequences and doesn't execute any code, making it safe from XSS attacks. The function:
- Only processes string replacements
- Doesn't use `eval()` or similar dangerous functions
- Doesn't execute the Python code
- Only affects display formatting

## Performance Impact
The unescaping function has minimal performance impact:
- Only runs when loading connector edit forms
- Processes strings using efficient regex replacements
- No network requests or heavy computations
- Negligible memory usage