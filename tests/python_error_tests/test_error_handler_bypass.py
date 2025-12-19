#!/usr/bin/env python3
"""
Test script to verify that detailed Python error information bypasses the error handler
and makes it to the Request Logs UI.
"""

def test_json_type_error():
    """Test script that causes a specific TypeError with JSON parsing"""
    return """
def transform(input_data):
    import json
    
    # Set up some context variables
    user_name = input_data.get('name', 'test_user')
    user_data = {'name': user_name, 'processed': True}
    
    # This will cause the specific TypeError you mentioned:
    # "the JSON object must be str, bytes or bytearray, not dict"
    invalid_json_data = {"key": "value"}  # This is already a dict
    parsed_result = json.loads(invalid_json_data)  # This will fail
    
    return {
        "user": user_data,
        "parsed": parsed_result
    }
"""

def test_zero_division_error():
    """Test script that causes a ZeroDivisionError with local context"""
    return """
def transform(input_data):
    # Set up local variables for context
    user_age = input_data.get('age', 0)
    user_name = input_data.get('name', 'unknown')
    calculation_factor = 100
    
    # This will cause a ZeroDivisionError
    result = calculation_factor / user_age
    
    return {
        "user": user_name,
        "age_factor": result
    }
"""

if __name__ == "__main__":
    print("Error Handler Bypass Test Scripts")
    print("=================================")
    print("\nThese scripts should now show detailed error information in Request Logs:")
    print("\n1. JSON TypeError Test:")
    print(test_json_type_error())
    print("\n2. ZeroDivisionError Test:")
    print(test_zero_division_error())
    print("\nExpected in Request Logs:")
    print("- Full error type and message")
    print("- Stack trace with line numbers")
    print("- Local variables (user_name, user_data, etc.)")
    print("- Complete Python traceback")
    print("- Input data context")