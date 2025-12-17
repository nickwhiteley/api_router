# API Translation Platform

A Go-based integration platform that acts as an intermediary between different API systems, providing translation, authentication, and routing capabilities with multi-tenant architecture.

## Project Structure

```
api-translation-platform/
├── cmd/
│   └── server/                 # Main application entry point
├── internal/
│   ├── config/                 # Configuration management
│   ├── container/              # Dependency injection setup
│   ├── database/               # Database connection and migrations
│   ├── logger/                 # Structured logging
│   ├── models/                 # Data models and validation
│   ├── repositories/           # Data access layer
│   └── services/               # Business logic layer
├── config.yaml                 # Configuration file
├── go.mod                      # Go module definition
└── README.md                   # This file
```

## Features

- **Landing Page**: User-friendly web interface with links to all platform areas
- **Multi-tenant Architecture**: Organisation-level data isolation
- **API Gateway**: Dynamic REST and SOAP endpoint creation
- **Python Transformation Engine**: Scriptable data transformation
- **Authentication**: Support for API key, OAuth, and basic auth
- **Monitoring**: Comprehensive logging and metrics
- **Horizontal Scaling**: API-driven configuration for multi-instance deployment

## Getting Started

### Prerequisites

- Go 1.21 or later
- PostgreSQL 12 or later
- Redis (optional, for caching)

### Database Setup

#### Option 1: Using Docker (Recommended for Development)

Start the development database with Docker Compose:

```bash
# Start PostgreSQL and Redis for development
docker-compose -f docker-compose.dev.yml up -d

# The database will be automatically initialized with:
# - Database: api_translation_platform
# - User: atp_user
# - Password: atp_password

# Run migrations
DB_HOST=localhost DB_USER=atp_user DB_PASSWORD=atp_password go run cmd/migrate/main.go up
```

#### Option 2: Manual Database Setup

Initialize the database using the provided script:

```bash
# Set required environment variables
export DB_PASSWORD="your_db_password"
export ADMIN_PASSWORD="your_postgres_password"

# Initialize database with default settings
./scripts/init-database.sh

# Or with custom options
DB_HOST=localhost DB_NAME=my_atp_db ./scripts/init-database.sh --seed-data
```

The initialization script will:
- Create the database user and database
- Set up proper permissions
- Enable required PostgreSQL extensions (uuid-ossp, pgcrypto)
- **Create a default admin user** (username: `admin`, password: `admin123`)

### Default Admin User

The system automatically creates a default admin user during database initialization:

- **Username**: `admin`
- **Password**: `admin123`
- **Role**: `global_admin`

**⚠️ IMPORTANT**: Change the default password immediately after first login!

For detailed information about the admin user, see [ADMIN_USER.md](ADMIN_USER.md).
- Run all database migrations
- Optionally insert seed data

#### Database Script Options

```bash
./scripts/init-database.sh [OPTIONS]

OPTIONS:
    -h, --help              Show help message
    -f, --force             Force recreate database (destroys existing data)
    -s, --skip-user         Skip database user creation
    -m, --skip-migrations   Skip running migrations
    -d, --seed-data         Insert seed data after initialization
    -v, --verbose           Enable verbose output
```

#### Manual Migration

You can also run migrations manually:

```bash
# Run migrations
go run cmd/migrate/main.go up

# Check migration status
go run cmd/migrate/main.go status

# Rollback migrations (for development)
go run cmd/migrate/main.go down
```

#### Database Status Check

Check your database status anytime:

```bash
DB_PASSWORD=your_password ./scripts/check-database.sh
```

### Configuration

Copy and modify the `config.yaml` file to match your environment:

```yaml
server:
  host: "0.0.0.0"
  port: "8080"

database:
  host: "localhost"
  port: 5432
  user: "atp_user"
  password: "your_db_password"
  dbname: "api_translation_platform"
  sslmode: "prefer"
```

### Building

```bash
go mod tidy
go build ./cmd/server
```

### Running Tests

```bash
go test ./...
```

### Running the Application

```bash
./server
```

Once the server is running, visit the landing page at `http://localhost:8080/` for a comprehensive overview of all available endpoints and features.

### Authentication and Admin Access

The application uses JWT-based authentication for both the Management API and Web UI.

#### Creating Admin Tokens

Generate a JWT token for the admin user:

```bash
# Generate token for admin user
DB_HOST=localhost DB_PORT=5433 DB_USER=atp_user DB_PASSWORD=atp_password go run cmd/admin-token/main.go admin
```

This will output a JWT token that you can use for authentication.

#### Available Endpoints

**Public Endpoints (no authentication required):**
- `GET /` - Landing page with links to all platform areas
- `GET /login` - Administrator login page
- `GET /health` - System health check
- `GET /api/v1/docs/openapi.json` - OpenAPI specification
- `GET /api/v1/docs/swagger` - Swagger UI

**Management API (requires JWT token):**
- `GET /api/v1/organisations` - List organisations
- `GET /api/v1/organisations/{id}` - Get organisation details
- `POST /api/v1/organisations` - Create organisation
- And more...

**Management Interface (session-based authentication):**

*Global Admin Routes:*
- `GET /manage/admin/dashboard` - Global admin dashboard
- `GET /manage/admin/organisations` - Organisations management
- `GET /manage/admin/users` - Users management
- `GET /manage/admin/system` - System management

*Organisation Admin Routes:*
- `GET /manage/org/{orgID}/dashboard` - Organisation dashboard
- `GET /manage/org/{orgID}/apis` - API configurations management
- `GET /manage/org/{orgID}/connectors` - Connector management
- `GET /manage/org/{orgID}/users` - Organisation users management

**Legacy Web UI Endpoints (requires JWT token):**

*Global Admin Routes:*
- `GET /ui/admin/organisations` - Admin organisation management
- `GET /ui/admin/system/health` - System health dashboard
- `GET /ui/admin/system/metrics` - System metrics dashboard

*Organisation-Specific Routes:*
- `GET /ui/{orgID}/dashboard` - Organisation dashboard
- `GET /ui/{orgID}/apis` - API configurations
- `GET /ui/{orgID}/connectors` - Connector management
- `GET /ui/{orgID}/logs` - Request logs
- `GET /ui/{orgID}/metrics` - Organisation metrics

#### Web-Based Management Interface

Access the management interface through your browser:

1. **Login**: Visit `http://localhost:8080/login`
2. **Credentials**: Username `admin`, Password `admin123`
3. **Dashboard**: Automatically redirected to appropriate dashboard based on role

#### Using JWT Tokens (for API access)

Include the JWT token in the Authorization header:

```bash
curl -H "Authorization: Bearer YOUR_JWT_TOKEN" http://localhost:8080/api/v1/organisations
```

#### Default Credentials

The system comes with a default admin account:
- **Username:** `admin`
- **Email:** `admin@example.com`
- **Role:** `global_admin`
- **Organisation ID:** `65a6330e-e436-4c53-b843-d60e3d31abb2`

## Architecture

The application follows a clean architecture pattern with:

- **Models**: Data structures and validation
- **Repositories**: Data access interfaces and implementations
- **Services**: Business logic and orchestration
- **Container**: Dependency injection using Uber FX

## Testing

The project uses both unit tests and property-based tests:

- **Unit Tests**: Test specific functionality and edge cases
- **Property-Based Tests**: Test universal properties using gopter
- **Integration Tests**: Test component interactions

Property-based tests validate correctness properties defined in the design specification.