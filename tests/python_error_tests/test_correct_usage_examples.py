#!/usr/bin/env python3
"""
Examples of correct Python transformation script usage.
These examples show how to properly handle input data without causing JSON parsing errors.
"""

def correct_basic_transform():
    """Correct: input_data is already a parsed Python dictionary"""
    return """
def transform(input_data):
    # input_data is already a Python dict - no need to parse JSON
    user_name = input_data.get('name', 'Unknown')
    user_age = input_data.get('age', 0)
    
    return {
        'greeting': f'Hello, {user_name}!',
        'age_in_months': user_age * 12,
        'processed': True
    }
"""

def correct_field_mapping():
    """Correct: Direct field access and transformation"""
    return """
def transform(input_data):
    # Access fields directly from the input dictionary
    result = {}
    
    # Map input fields to output fields
    if 'customer_name' in input_data:
        result['name'] = input_data['customer_name']
    
    if 'customer_email' in input_data:
        result['email'] = input_data['customer_email'].lower()
    
    if 'order_items' in input_data:
        result['item_count'] = len(input_data['order_items'])
    
    return result
"""

def correct_with_helper_function():
    """Correct: Using the provided json_loads_safe helper for mixed data"""
    return """
def transform(input_data):
    # Use the provided helper function for safe JSON parsing
    # This handles both dict and string inputs safely
    
    # If you have a field that might be a JSON string or already parsed
    user_data = json_loads_safe(input_data.get('user_data', {}))
    
    return {
        'user_id': user_data.get('id'),
        'user_name': user_data.get('name'),
        'processed_at': 'now'
    }
"""

def incorrect_json_loads():
    """INCORRECT: This will cause the TypeError"""
    return """
def transform(input_data):
    import json
    
    # ❌ WRONG: input_data is already a dict, not a JSON string
    # This will cause: TypeError: the JSON object must be str, bytes or bytearray, not dict
    parsed_data = json.loads(input_data)
    
    return parsed_data
"""

def incorrect_double_parsing():
    """INCORRECT: This will also cause issues"""
    return """
def transform(input_data):
    import json
    
    # ❌ WRONG: Trying to parse already-parsed data
    user_info = json.loads(input_data['user'])  # If 'user' is already a dict
    
    return user_info
"""

def correct_json_string_handling():
    """Correct: How to handle actual JSON strings in input data"""
    return """
def transform(input_data):
    import json
    
    # ✅ CORRECT: If you have a field that contains a JSON string
    if 'json_payload' in input_data and isinstance(input_data['json_payload'], str):
        # Only parse if it's actually a string
        parsed_payload = json.loads(input_data['json_payload'])
    else:
        # If it's already parsed, use it directly
        parsed_payload = input_data.get('json_payload', {})
    
    return {
        'payload_data': parsed_payload,
        'original_input': input_data
    }
"""

if __name__ == "__main__":
    print("Python Transformation Script Usage Guide")
    print("========================================")
    print()
    
    examples = [
        ("✅ Correct Basic Transform", correct_basic_transform()),
        ("✅ Correct Field Mapping", correct_field_mapping()),
        ("✅ Correct with Helper Function", correct_with_helper_function()),
        ("✅ Correct JSON String Handling", correct_json_string_handling()),
        ("❌ Incorrect json.loads() Usage", incorrect_json_loads()),
        ("❌ Incorrect Double Parsing", incorrect_double_parsing()),
    ]
    
    for title, script in examples:
        print(f"{title}:")
        print("-" * len(title))
        print(script)
        print()
    
    print("Key Points:")
    print("===========")
    print("1. input_data is already a parsed Python dictionary")
    print("2. Do NOT call json.loads() on input_data")
    print("3. Access fields directly: input_data['field_name']")
    print("4. Use json_loads_safe() helper for mixed string/dict data")
    print("5. Only use json.loads() on actual JSON string fields")
    print()
    print("Common Error:")
    print("TypeError: the JSON object must be str, bytes or bytearray, not dict")
    print("This happens when you call json.loads() on input_data (which is already a dict)")