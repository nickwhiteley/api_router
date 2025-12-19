# Python Script Usage Guide

## 🚨 MOST COMMON ERROR: "the JSON object must be str, bytes or bytearray, not dict"

**This error occurs when you try to call `json.loads()` on `input_data`.**

### ⚡ Quick Fix
```python
# ❌ WRONG - This causes the error
import json
def transform(input_data):
    data = json.loads(input_data)  # ERROR!
    return data

# ✅ CORRECT - input_data is already parsed
def transform(input_data):
    user_name = input_data.get('name', 'Unknown')  # Works!
    return {'greeting': f'Hello, {user_name}!'}
```

**Remember: `input_data` is already a Python dictionary - no parsing needed!**

## Understanding Input Data

### How Input Data is Provided
When your Python transformation script is executed, the `input_data` parameter is **already a parsed Python dictionary**. You do not need to (and should not) call `json.loads()` on it.

```python
# ✅ CORRECT: input_data is already a dict
def transform(input_data):
    user_name = input_data['name']  # Direct access
    return {'greeting': f'Hello, {user_name}!'}

# ❌ INCORRECT: This will cause TypeError
def transform(input_data):
    import json
    parsed = json.loads(input_data)  # ERROR: input_data is already a dict!
    return parsed
```

## Common Mistakes and Solutions

### 1. Trying to Parse Input Data
**❌ Wrong:**
```python
def transform(input_data):
    import json
    # This causes: TypeError: the JSON object must be str, bytes or bytearray, not dict
    data = json.loads(input_data)
    return data
```

**✅ Correct:**
```python
def transform(input_data):
    # input_data is already parsed - use it directly
    return {
        'user': input_data.get('name', 'Unknown'),
        'processed': True
    }
```

### 2. Double-Parsing Nested Data
**❌ Wrong:**
```python
def transform(input_data):
    import json
    # If 'user_data' is already a dict, this will fail
    user = json.loads(input_data['user_data'])
    return user
```

**✅ Correct:**
```python
def transform(input_data):
    # Access nested data directly
    user_data = input_data.get('user_data', {})
    return {
        'user_id': user_data.get('id'),
        'user_name': user_data.get('name')
    }
```

### 3. Handling Mixed String/Dict Data
If you have fields that might be JSON strings OR already-parsed dictionaries, use the provided helper:

**✅ Correct:**
```python
def transform(input_data):
    # Use the provided helper function
    user_data = json_loads_safe(input_data.get('user_data'))
    return {
        'user_id': user_data.get('id'),
        'processed': True
    }
```

## Input Data Structure

Your input data comes from HTTP requests and is structured like this:

```python
input_data = {
    'method': 'POST',
    'url': 'https://api.example.com/webhook',
    'headers': {'Content-Type': 'application/json'},
    'body': '{"user": "john", "action": "login"}',  # Raw request body as string
    'query': {'param1': 'value1'},
    
    # If the request body was JSON, it's also parsed and merged:
    'user': 'john',      # From parsed JSON body
    'action': 'login'    # From parsed JSON body
}
```

## Correct Usage Patterns

### 1. Basic Field Access
```python
def transform(input_data):
    return {
        'user_name': input_data.get('user', 'Unknown'),
        'action': input_data.get('action', 'none'),
        'timestamp': '2025-12-18T20:00:00Z'
    }
```

### 2. Field Mapping
```python
def transform(input_data):
    result = {}
    
    # Map input fields to output fields
    if 'customer_name' in input_data:
        result['name'] = input_data['customer_name']
    
    if 'customer_email' in input_data:
        result['email'] = input_data['customer_email'].lower()
    
    return result
```

### 3. Processing Raw Body
```python
def transform(input_data):
    import json
    
    # The raw request body is available as a string
    raw_body = input_data.get('body', '{}')
    
    # Parse the raw body if needed (this is a string, so json.loads is correct)
    if raw_body and isinstance(raw_body, str):
        body_data = json.loads(raw_body)
    else:
        body_data = {}
    
    return {
        'parsed_body': body_data,
        'method': input_data.get('method')
    }
```

### 4. Complex Transformations
```python
def transform(input_data):
    # Process multiple fields
    user_info = {
        'id': input_data.get('user_id'),
        'name': input_data.get('user_name', '').title(),
        'email': input_data.get('email', '').lower()
    }
    
    # Calculate derived values
    order_items = input_data.get('items', [])
    total_items = len(order_items) if isinstance(order_items, list) else 0
    
    return {
        'user': user_info,
        'order_summary': {
            'item_count': total_items,
            'processed_at': '2025-12-18T20:00:00Z'
        }
    }
```

## Helper Functions Available

### json_loads_safe(data)
Safely parses JSON data, handling both strings and already-parsed objects:

```python
def transform(input_data):
    # This works whether user_data is a string or already a dict
    user_data = json_loads_safe(input_data.get('user_data', {}))
    
    return {
        'user_id': user_data.get('id'),
        'user_name': user_data.get('name')
    }
```

## Debugging Tips

### 1. Check Input Data Type
```python
def transform(input_data):
    # Debug: see what type input_data is
    print(f"Input data type: {type(input_data)}")
    print(f"Input data: {input_data}")
    
    # It should be <class 'dict'>
    return {'debug': True}
```

### 2. Inspect Available Fields
```python
def transform(input_data):
    # See what fields are available
    available_fields = list(input_data.keys())
    
    return {
        'available_fields': available_fields,
        'field_count': len(available_fields)
    }
```

### 3. Handle Missing Fields Gracefully
```python
def transform(input_data):
    result = {}
    
    # Use .get() with defaults to avoid KeyError
    result['user'] = input_data.get('user', 'Unknown')
    result['action'] = input_data.get('action', 'none')
    
    # Check if field exists before processing
    if 'items' in input_data and isinstance(input_data['items'], list):
        result['item_count'] = len(input_data['items'])
    else:
        result['item_count'] = 0
    
    return result
```

## Error Prevention Checklist

- [ ] ✅ Do NOT call `json.loads(input_data)`
- [ ] ✅ Access fields directly: `input_data['field_name']`
- [ ] ✅ Use `.get()` for optional fields: `input_data.get('field', default)`
- [ ] ✅ Check types before processing: `isinstance(data, dict)`
- [ ] ✅ Use `json_loads_safe()` for mixed string/dict data
- [ ] ✅ Only use `json.loads()` on actual JSON string fields
- [ ] ✅ Handle missing fields gracefully with defaults

## Summary

The key point is: **input_data is already a Python dictionary**. Treat it like any other Python dict and access its fields directly. The "JSON object must be str, bytes or bytearray, not dict" error happens when you try to parse something that's already parsed.