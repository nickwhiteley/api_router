#!/bin/bash

# API Translation Platform - Database Status Check Script
# This script checks the status of the database and displays connection information

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default configuration
DEFAULT_DB_HOST="localhost"
DEFAULT_DB_PORT="5432"
DEFAULT_DB_NAME="api_translation_platform"
DEFAULT_DB_USER="atp_user"

# Configuration from environment or defaults
DB_HOST="${DB_HOST:-$DEFAULT_DB_HOST}"
DB_PORT="${DB_PORT:-$DEFAULT_DB_PORT}"
DB_NAME="${DB_NAME:-$DEFAULT_DB_NAME}"
DB_USER="${DB_USER:-$DEFAULT_DB_USER}"
DB_PASSWORD="${DB_PASSWORD:-}"

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to show usage
show_usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Check the status of the API Translation Platform database.

OPTIONS:
    -h, --help              Show this help message

ENVIRONMENT VARIABLES:
    DB_HOST                 Database host (default: $DEFAULT_DB_HOST)
    DB_PORT                 Database port (default: $DEFAULT_DB_PORT)
    DB_NAME                 Database name (default: $DEFAULT_DB_NAME)
    DB_USER                 Database user (default: $DEFAULT_DB_USER)
    DB_PASSWORD             Database password (required)

EXAMPLES:
    # Basic status check
    DB_PASSWORD=mypass $0
EOF
}

# Function to test database connection
test_connection() {
    if [[ -z "$DB_PASSWORD" ]]; then
        print_error "DB_PASSWORD environment variable is required"
        return 1
    fi

    PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c "SELECT 1;" >/dev/null 2>&1
}

# Function to get table information
get_table_info() {
    PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -tAc \
        "SELECT schemaname, tablename, tableowner FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename;"
}

# Function to get database size
get_database_size() {
    PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -tAc \
        "SELECT pg_size_pretty(pg_database_size('$DB_NAME'));"
}

# Function to get record counts
get_record_counts() {
    local tables=("organisations" "users" "api_configurations" "connectors" "request_logs" "audit_logs" "configuration_versions" "security_events")
    
    echo "Record Counts:"
    for table in "${tables[@]}"; do
        local count
        count=$(PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -tAc \
            "SELECT COUNT(*) FROM $table;" 2>/dev/null || echo "N/A")
        printf "  %-20s: %s\n" "$table" "$count"
    done
}

# Function to check database version
get_database_version() {
    PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -tAc \
        "SELECT version();"
}

# Main function
main() {
    if [[ $# -gt 0 && ("$1" == "-h" || "$1" == "--help") ]]; then
        show_usage
        exit 0
    fi

    echo "API Translation Platform - Database Status Check"
    echo "==============================================="
    echo

    print_status "Checking database connection..."

    if test_connection; then
        print_success "Database connection successful"
    else
        print_error "Failed to connect to database"
        echo "Connection details:"
        echo "  Host: $DB_HOST"
        echo "  Port: $DB_PORT"
        echo "  Database: $DB_NAME"
        echo "  User: $DB_USER"
        exit 1
    fi

    echo
    echo "Database Information:"
    echo "  Host: $DB_HOST:$DB_PORT"
    echo "  Database: $DB_NAME"
    echo "  User: $DB_USER"
    
    local db_size
    db_size=$(get_database_size)
    echo "  Size: $db_size"
    
    echo
    echo "PostgreSQL Version:"
    get_database_version | head -1
    
    echo
    echo "Tables:"
    get_table_info | while IFS='|' read -r schema table owner; do
        printf "  %-25s (owner: %s)\n" "$table" "$owner"
    done
    
    echo
    get_record_counts
    
    echo
    print_success "Database status check completed"
}

# Run main function with all arguments
main "$@"