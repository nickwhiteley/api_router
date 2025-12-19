#!/usr/bin/env python3
"""
Test script to verify that the enhanced Python wrapper detects and provides
helpful suggestions for the common json.loads() error.
"""

def test_json_loads_error():
    """Test script that will trigger the json.loads() error"""
    return """
import json

def transform(input_data):
    # This should trigger the enhanced error message
    parsed_data = json.loads(input_data)
    return parsed_data
"""

def test_correct_usage():
    """Test script showing correct usage"""
    return """
def transform(input_data):
    # Correct: access input_data directly
    user_name = input_data.get('name', 'Unknown')
    return {
        'greeting': f'Hello, {user_name}!',
        'processed': True
    }
"""

if __name__ == "__main__":
    print("Testing JSON loads error detection...")
    print("====================================")
    print()
    
    print("❌ Script that will trigger error:")
    print(test_json_loads_error())
    print()
    
    print("✅ Correct script:")
    print(test_correct_usage())