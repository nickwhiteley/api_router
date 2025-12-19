#!/usr/bin/env python3
"""
Test script to verify that error details are displayed in a readable format
with proper unescaping and formatting.
"""

def test_readable_error_display():
    """Test script that generates a rich error with multiple local variables"""
    return """
def transform(input_data):
    import json
    
    # Set up rich local context for better error display testing
    user_info = {
        'name': input_data.get('name', 'John Doe'),
        'age': input_data.get('age', 25),
        'email': input_data.get('email', 'john@example.com')
    }
    
    processing_config = {
        'validate_input': True,
        'format_output': 'json',
        'include_metadata': True
    }
    
    calculation_data = [1, 2, 3, 4, 5]
    result_buffer = []
    
    # This will cause a TypeError with rich local context
    invalid_json_object = {'key': 'value', 'nested': {'data': 123}}
    parsed_data = json.loads(invalid_json_object)  # TypeError here
    
    return {
        'user': user_info,
        'config': processing_config,
        'data': parsed_data
    }
"""

if __name__ == "__main__":
    print("Readable Error Formatting Test")
    print("==============================")
    print("This script will generate a TypeError with rich local context.")
    print("The error details should now display with:")
    print("- 🔴 Clear error type and message")
    print("- 🐍 Python-specific error section")
    print("- 📍 Stack trace with emojis and formatting")
    print("- 🔍 Local variables with proper formatting")
    print("- 📋 Full Python traceback in a box")
    print("- 📥 Input data preview formatted as JSON")
    print("\nScript:")
    print(test_readable_error_display())