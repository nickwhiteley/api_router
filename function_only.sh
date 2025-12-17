
# Mock functions for testing
print_status() { echo "STATUS: $1"; }
print_success() { echo "SUCCESS: $1"; }
execute_sql() { echo "SQL: $6"; }

# Test the function
echo "Testing create_default_admin function..."
if declare -f create_default_admin > /dev/null; then
    echo "✓ Function is defined correctly"
else
    echo "✗ Function is not defined"
    exit 1
fi
