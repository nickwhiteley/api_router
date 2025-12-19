# Project Structure

This document describes the organization of the API Translation Platform project.

## Directory Structure

```
api-translation-platform/
├── .git/                           # Git repository data
├── .github/                        # GitHub workflows and templates
├── .kiro/                          # Kiro IDE configuration
├── .vscode/                        # VS Code configuration
├── bin/                            # Build artifacts (gitignored)
│   └── api-router                  # Main application binary
├── cmd/                            # Application entry points
│   ├── admin-token/                # Admin token generation utility
│   ├── migrate/                    # Database migration utility
│   └── server/                     # Main server application
├── deployments/                    # Deployment configurations
│   ├── config/                     # Deployment-specific configs
│   ├── kubernetes/                 # Kubernetes manifests
│   ├── monitoring/                 # Monitoring configurations
│   ├── nginx/                      # Nginx configurations
│   └── tests/                      # Deployment tests
├── docs/                           # Documentation (NEW)
│   ├── deployment/                 # Deployment-specific documentation
│   │   ├── PRODUCTION_CHECKLIST.md
│   │   └── README.md
│   ├── ADMIN_USER.md
│   ├── API_SCHEMA_IMPLEMENTATION.md
│   ├── CONNECTOR_CHANGES_SUMMARY.md
│   ├── DEPLOYMENT_STATUS.md
│   ├── FIELD_MAPPING.md
│   ├── IMPLEMENTATION_SUMMARY.md
│   ├── PROJECT_STRUCTURE.md        # This file
│   ├── README.md                   # Documentation index
│   └── SCHEMA_MANAGEMENT_GUIDE.md
├── internal/                       # Internal application code
│   ├── config/                     # Configuration management
│   ├── container/                  # Dependency injection
│   ├── database/                   # Database connections and migrations
│   ├── handlers/                   # HTTP handlers
│   ├── logger/                     # Logging utilities
│   ├── middleware/                 # HTTP middleware
│   ├── models/                     # Data models
│   ├── repositories/               # Data access layer
│   ├── security/                   # Security utilities
│   ├── server/                     # HTTP server setup
│   └── services/                   # Business logic
├── migrations/                     # Database migration files
├── python_test_server/             # Python test server for development
├── scripts/                        # Build and deployment scripts
├── sdk/                            # Client SDKs
├── tmp/                            # Temporary files (gitignored)
│   ├── cookies.txt
│   ├── function_only.sh
│   └── test-schema.json
├── .gitignore                      # Git ignore rules
├── config.yaml                     # Application configuration
├── docker-compose.dev.yml          # Development Docker Compose
├── docker-compose.yml              # Production Docker Compose
├── Dockerfile                      # Docker image definition
├── go.mod                          # Go module definition
├── go.sum                          # Go module checksums
├── makefile                        # Build automation
├── README.md                       # Project overview
├── test_horizontal_scaling.sh      # Horizontal scaling tests
└── test_scaling_basic.sh           # Basic scaling tests
```

## Key Organizational Principles

### Build Artifacts
- All build outputs go to `bin/` directory
- Build artifacts are gitignored
- Use `make build` to build to the correct location

### Temporary Files
- All temporary files go to `tmp/` directory
- Temporary files are gitignored
- Clean up with `make clean`

### Documentation
- All documentation is organized in `docs/` directory
- Deployment-specific docs are in `docs/deployment/`
- Main documentation index is at `docs/README.md`
- Project README.md links to documentation

### Code Organization
- Application entry points in `cmd/`
- Internal application code in `internal/`
- External SDKs in `sdk/`
- Database migrations in `migrations/`
- Deployment configurations in `deployments/`

## Build Commands

```bash
# Standard build (with formatting and vetting)
make build

# Quick build (development)
make quick-build

# Build all binaries
make build-all

# Clean build artifacts and temporary files
make clean

# Check documentation structure
make docs-check
```

## File Naming Conventions

- **Documentation**: Use descriptive names in UPPER_CASE.md format
- **Configuration**: Use lowercase with hyphens (docker-compose.yml)
- **Scripts**: Use lowercase with underscores (test_scaling_basic.sh)
- **Go files**: Use lowercase with underscores following Go conventions