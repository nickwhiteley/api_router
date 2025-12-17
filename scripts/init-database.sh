#!/bin/bash

# API Translation Platform - Database Initialization Script
# This script initializes the PostgreSQL database and runs migrations

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
DEFAULT_ADMIN_DB="postgres"
DEFAULT_ADMIN_USER="postgres"

# Configuration from environment or defaults
DB_HOST="${DB_HOST:-$DEFAULT_DB_HOST}"
DB_PORT="${DB_PORT:-$DEFAULT_DB_PORT}"
DB_NAME="${DB_NAME:-$DEFAULT_DB_NAME}"
DB_USER="${DB_USER:-$DEFAULT_DB_USER}"
DB_PASSWORD="${DB_PASSWORD:-}"
ADMIN_DB="${ADMIN_DB:-$DEFAULT_ADMIN_DB}"
ADMIN_USER="${ADMIN_USER:-$DEFAULT_ADMIN_USER}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-}"

# Script options
FORCE_RECREATE=false
SKIP_USER_CREATION=false
SKIP_MIGRATIONS=false
SEED_DATA=false
VERBOSE=false

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

Initialize the API Translation Platform database.
This script will automatically create a default admin user (username: admin, password: admin123).

OPTIONS:
    -h, --help              Show this help message
    -f, --force             Force recreate database (WARNING: destroys existing data)
    -s, --skip-user         Skip database user creation
    -m, --skip-migrations   Skip running migrations
    -d, --seed-data         Insert seed data after initialization
    -v, --verbose           Enable verbose output

ENVIRONMENT VARIABLES:
    DB_HOST                 Database host (default: $DEFAULT_DB_HOST)
    DB_PORT                 Database port (default: $DEFAULT_DB_PORT)
    DB_NAME                 Database name (default: $DEFAULT_DB_NAME)
    DB_USER                 Database user (default: $DEFAULT_DB_USER)
    DB_PASSWORD             Database password (required)
    ADMIN_DB                Admin database (default: $DEFAULT_ADMIN_DB)
    ADMIN_USER              Admin user (default: $DEFAULT_ADMIN_USER)
    ADMIN_PASSWORD          Admin password (required)

EXAMPLES:
    # Basic initialization
    DB_PASSWORD=mypass ADMIN_PASSWORD=adminpass $0

    # Force recreate with seed data
    DB_PASSWORD=mypass ADMIN_PASSWORD=adminpass $0 --force --seed-data

    # Skip user creation (user already exists)
    DB_PASSWORD=mypass ADMIN_PASSWORD=adminpass $0 --skip-user
EOF
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_usage
                exit 0
                ;;
            -f|--force)
                FORCE_RECREATE=true
                shift
                ;;
            -s|--skip-user)
                SKIP_USER_CREATION=true
                shift
                ;;
            -m|--skip-migrations)
                SKIP_MIGRATIONS=true
                shift
                ;;
            -d|--seed-data)
                SEED_DATA=true
                shift
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            *)
                print_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check prerequisites
check_prerequisites() {
    print_status "Checking prerequisites..."

    if ! command_exists psql; then
        print_error "PostgreSQL client (psql) is not installed"
        exit 1
    fi

    if ! command_exists go; then
        print_error "Go is not installed"
        exit 1
    fi

    if [[ -z "$DB_PASSWORD" ]]; then
        print_error "DB_PASSWORD environment variable is required"
        exit 1
    fi

    if [[ -z "$ADMIN_PASSWORD" ]]; then
        print_error "ADMIN_PASSWORD environment variable is required"
        exit 1
    fi

    print_success "Prerequisites check passed"
}

# Function to test database connection
test_connection() {
    local host=$1
    local port=$2
    local database=$3
    local user=$4
    local password=$5

    if [[ "$VERBOSE" == "true" ]]; then
        print_status "Testing connection to $user@$host:$port/$database"
    fi

    PGPASSWORD="$password" psql -h "$host" -p "$port" -U "$user" -d "$database" -c "SELECT 1;" >/dev/null 2>&1
}

# Function to execute SQL command
execute_sql() {
    local host=$1
    local port=$2
    local database=$3
    local user=$4
    local password=$5
    local sql=$6

    if [[ "$VERBOSE" == "true" ]]; then
        print_status "Executing SQL: $sql"
    fi

    PGPASSWORD="$password" psql -h "$host" -p "$port" -U "$user" -d "$database" -c "$sql"
}

# Function to check if database exists
database_exists() {
    local host=$1
    local port=$2
    local database=$3
    local admin_user=$4
    local admin_password=$5
    local target_db=$6

    PGPASSWORD="$admin_password" psql -h "$host" -p "$port" -U "$admin_user" -d "$database" -tAc "SELECT 1 FROM pg_database WHERE datname='$target_db';" | grep -q 1
}

# Function to check if user exists
user_exists() {
    local host=$1
    local port=$2
    local database=$3
    local admin_user=$4
    local admin_password=$5
    local target_user=$6

    PGPASSWORD="$admin_password" psql -h "$host" -p "$port" -U "$admin_user" -d "$database" -tAc "SELECT 1 FROM pg_user WHERE usename='$target_user';" | grep -q 1
}

# Function to create database user
create_user() {
    if [[ "$SKIP_USER_CREATION" == "true" ]]; then
        print_status "Skipping user creation"
        return 0
    fi

    print_status "Creating database user: $DB_USER"

    if user_exists "$DB_HOST" "$DB_PORT" "$ADMIN_DB" "$ADMIN_USER" "$ADMIN_PASSWORD" "$DB_USER"; then
        print_warning "User $DB_USER already exists"
    else
        execute_sql "$DB_HOST" "$DB_PORT" "$ADMIN_DB" "$ADMIN_USER" "$ADMIN_PASSWORD" \
            "CREATE USER $DB_USER WITH PASSWORD '$DB_PASSWORD';"
        print_success "User $DB_USER created"
    fi
}

# Function to create database
create_database() {
    print_status "Creating database: $DB_NAME"

    if database_exists "$DB_HOST" "$DB_PORT" "$ADMIN_DB" "$ADMIN_USER" "$ADMIN_PASSWORD" "$DB_NAME"; then
        if [[ "$FORCE_RECREATE" == "true" ]]; then
            print_warning "Dropping existing database $DB_NAME"
            execute_sql "$DB_HOST" "$DB_PORT" "$ADMIN_DB" "$ADMIN_USER" "$ADMIN_PASSWORD" \
                "DROP DATABASE IF EXISTS $DB_NAME;"
        else
            print_warning "Database $DB_NAME already exists (use --force to recreate)"
            return 0
        fi
    fi

    execute_sql "$DB_HOST" "$DB_PORT" "$ADMIN_DB" "$ADMIN_USER" "$ADMIN_PASSWORD" \
        "CREATE DATABASE $DB_NAME OWNER $DB_USER;"
    
    print_success "Database $DB_NAME created"
}

# Function to grant permissions
grant_permissions() {
    print_status "Granting permissions to user: $DB_USER"

    execute_sql "$DB_HOST" "$DB_PORT" "$ADMIN_DB" "$ADMIN_USER" "$ADMIN_PASSWORD" \
        "GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;"
    
    # Connect to the target database and grant schema permissions
    execute_sql "$DB_HOST" "$DB_PORT" "$DB_NAME" "$ADMIN_USER" "$ADMIN_PASSWORD" \
        "GRANT ALL ON SCHEMA public TO $DB_USER;"
    
    execute_sql "$DB_HOST" "$DB_PORT" "$DB_NAME" "$ADMIN_USER" "$ADMIN_PASSWORD" \
        "GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO $DB_USER;"
    
    execute_sql "$DB_HOST" "$DB_PORT" "$DB_NAME" "$ADMIN_USER" "$ADMIN_PASSWORD" \
        "GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO $DB_USER;"
    
    execute_sql "$DB_HOST" "$DB_PORT" "$DB_NAME" "$ADMIN_USER" "$ADMIN_PASSWORD" \
        "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO $DB_USER;"
    
    execute_sql "$DB_HOST" "$DB_PORT" "$DB_NAME" "$ADMIN_USER" "$ADMIN_PASSWORD" \
        "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO $DB_USER;"

    print_success "Permissions granted"
}

# Function to enable required extensions
enable_extensions() {
    print_status "Enabling PostgreSQL extensions"

    # Enable UUID extension for generating UUIDs
    execute_sql "$DB_HOST" "$DB_PORT" "$DB_NAME" "$ADMIN_USER" "$ADMIN_PASSWORD" \
        "CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\";"
    
    # Enable pgcrypto for password hashing
    execute_sql "$DB_HOST" "$DB_PORT" "$DB_NAME" "$ADMIN_USER" "$ADMIN_PASSWORD" \
        "CREATE EXTENSION IF NOT EXISTS pgcrypto;"

    print_success "Extensions enabled"
}

# Function to run migrations
run_migrations() {
    if [[ "$SKIP_MIGRATIONS" == "true" ]]; then
        print_status "Skipping migrations"
        return 0
    fi

    print_status "Running database migrations"

    # Set environment variables for the Go application
    export DB_HOST DB_PORT DB_NAME DB_USER DB_PASSWORD

    # Check if we're in the project root
    if [[ ! -f "go.mod" ]]; then
        print_error "go.mod not found. Please run this script from the project root directory."
        exit 1
    fi

    # Build and run migration command
    if go run cmd/migrate/main.go up 2>/dev/null; then
        print_success "Migrations completed successfully"
    else
        print_warning "Migration command not found, using GORM auto-migrate"
        
        # Create a temporary migration program
        cat > /tmp/migrate.go << 'EOF'
package main

import (
    "fmt"
    "log"
    "os"

    "api-translation-platform/internal/config"
    "api-translation-platform/internal/database"
)

func main() {
    cfg, err := config.LoadConfig()
    if err != nil {
        log.Fatalf("Failed to load config: %v", err)
    }

    db, err := database.NewConnection(cfg)
    if err != nil {
        log.Fatalf("Failed to connect to database: %v", err)
    }

    migrator := database.NewMigrator(db)
    if err := migrator.Up(); err != nil {
        log.Fatalf("Failed to run migrations: %v", err)
    }

    fmt.Println("Migrations completed successfully")
}
EOF

        if go run /tmp/migrate.go; then
            print_success "GORM auto-migrate completed successfully"
            rm -f /tmp/migrate.go
        else
            print_error "Failed to run migrations"
            rm -f /tmp/migrate.go
            exit 1
        fi
    fi
}

# Function to create default admin user (always runs)
create_default_admin() {
    print_status "Creating default admin user"

    # Create admin user SQL
    cat > /tmp/admin_user.sql << EOF
-- Insert default organisation if it doesn't exist
INSERT INTO organisations (id, name, is_active, created_at, updated_at) 
VALUES (
    gen_random_uuid(),
    'System Administration',
    true,
    NOW(),
    NOW()
) ON CONFLICT (name) DO NOTHING;

-- Insert default admin user
INSERT INTO users (id, organisation_id, username, email, password_hash, role, is_active, created_at, updated_at)
VALUES (
    gen_random_uuid(),
    (SELECT id FROM organisations WHERE name = 'System Administration' LIMIT 1),
    'admin',
    'admin@system.local',
    crypt('admin123', gen_salt('bf')),
    'global_admin',
    true,
    NOW(),
    NOW()
) ON CONFLICT (username) DO UPDATE SET
    password_hash = crypt('admin123', gen_salt('bf')),
    updated_at = NOW();
EOF

    execute_sql "$DB_HOST" "$DB_PORT" "$DB_NAME" "$DB_USER" "$DB_PASSWORD" \
        "$(cat /tmp/admin_user.sql)"
    
    rm -f /tmp/admin_user.sql
    print_success "Default admin user created/updated (username: admin, password: admin123)"
}

# Function to insert seed data
insert_seed_data() {
    if [[ "$SEED_DATA" != "true" ]]; then
        return 0
    fi

    print_status "Inserting seed data"

    # Create seed data SQL
    cat > /tmp/seed_data.sql << EOF
-- Insert default organisation
INSERT INTO organisations (id, name, is_active, created_at, updated_at) 
VALUES (
    gen_random_uuid(),
    'Default Organisation',
    true,
    NOW(),
    NOW()
) ON CONFLICT (name) DO NOTHING;

-- Insert default admin user
INSERT INTO users (id, organisation_id, username, email, password_hash, role, is_active, created_at, updated_at)
VALUES (
    gen_random_uuid(),
    (SELECT id FROM organisations WHERE name = 'Default Organisation' LIMIT 1),
    'admin',
    'admin@example.com',
    crypt('admin123', gen_salt('bf')),
    'global_admin',
    true,
    NOW(),
    NOW()
) ON CONFLICT (username) DO NOTHING;

-- Insert sample API configuration
INSERT INTO api_configurations (id, organisation_id, name, type, direction, endpoint, authentication, headers, created_at, updated_at)
VALUES (
    gen_random_uuid(),
    (SELECT id FROM organisations WHERE name = 'Default Organisation' LIMIT 1),
    'Sample REST API',
    'REST',
    'inbound',
    '/api/v1/sample',
    '{"type": "api_key", "parameters": {"header": "X-API-Key"}}',
    '{"Content-Type": "application/json"}',
    NOW(),
    NOW()
) ON CONFLICT DO NOTHING;
EOF

    execute_sql "$DB_HOST" "$DB_PORT" "$DB_NAME" "$DB_USER" "$DB_PASSWORD" \
        "$(cat /tmp/seed_data.sql)"
    
    rm -f /tmp/seed_data.sql
    print_success "Seed data inserted"
}

# Function to verify installation
verify_installation() {
    print_status "Verifying database installation"

    if ! test_connection "$DB_HOST" "$DB_PORT" "$DB_NAME" "$DB_USER" "$DB_PASSWORD"; then
        print_error "Failed to connect to database with application user"
        exit 1
    fi

    # Check if tables exist
    local table_count
    table_count=$(PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -tAc \
        "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public' AND table_type = 'BASE TABLE';")

    if [[ "$table_count" -gt 0 ]]; then
        print_success "Database verification passed ($table_count tables found)"
    else
        print_error "No tables found in database"
        exit 1
    fi
}

# Function to display connection info
display_connection_info() {
    print_success "Database initialization completed!"
    echo
    echo "Connection Information:"
    echo "  Host: $DB_HOST"
    echo "  Port: $DB_PORT"
    echo "  Database: $DB_NAME"
    echo "  User: $DB_USER"
    echo
    echo "Connection String:"
    echo "  postgresql://$DB_USER:$DB_PASSWORD@$DB_HOST:$DB_PORT/$DB_NAME?sslmode=prefer"
    echo
    if [[ "$SEED_DATA" == "true" ]]; then
        echo "Default Admin Credentials:"
        echo "  Username: admin"
        echo "  Password: admin123"
        echo "  Email: admin@example.com"
        echo
    fi
}

# Main function
main() {
    echo "API Translation Platform - Database Initialization"
    echo "=================================================="
    echo

    parse_args "$@"
    check_prerequisites

    print_status "Starting database initialization with the following configuration:"
    echo "  Host: $DB_HOST:$DB_PORT"
    echo "  Database: $DB_NAME"
    echo "  User: $DB_USER"
    echo "  Force recreate: $FORCE_RECREATE"
    echo "  Skip user creation: $SKIP_USER_CREATION"
    echo "  Skip migrations: $SKIP_MIGRATIONS"
    echo "  Seed data: $SEED_DATA"
    echo

    # Test admin connection
    if ! test_connection "$DB_HOST" "$DB_PORT" "$ADMIN_DB" "$ADMIN_USER" "$ADMIN_PASSWORD"; then
        print_error "Failed to connect to PostgreSQL with admin credentials"
        exit 1
    fi

    create_user
    create_database
    grant_permissions
    enable_extensions
    run_migrations
    create_default_admin
    insert_seed_data
    verify_installation
    display_connection_info
}

# Run main function with all arguments
main "$@"