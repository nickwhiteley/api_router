# API Translation Platform Documentation

This directory contains all documentation for the API Translation Platform.

## Table of Contents

### Getting Started
- [Main README](../README.md) - Project overview and quick start guide

### Implementation Guides
- [API Schema Implementation](API_SCHEMA_IMPLEMENTATION.md) - Guide for implementing API schema management
- [Field Mapping](FIELD_MAPPING.md) - Documentation on field mapping functionality
- [Schema Management Guide](SCHEMA_MANAGEMENT_GUIDE.md) - Comprehensive guide for managing API schemas

### Development Documentation
- [Project Structure](PROJECT_STRUCTURE.md) - Complete project organization guide
- [Implementation Summary](IMPLEMENTATION_SUMMARY.md) - Summary of key implementation details
- [Connector Changes Summary](CONNECTOR_CHANGES_SUMMARY.md) - Summary of connector-related changes

### Administration
- [Admin User Guide](ADMIN_USER.md) - Guide for administrative users

### Deployment
- [Production Checklist](deployment/PRODUCTION_CHECKLIST.md) - Pre-deployment checklist
- [Deployment README](deployment/README.md) - Deployment-specific documentation

### Status Reports
- [Deployment Status](DEPLOYMENT_STATUS.md) - Current deployment status and notes

## Documentation Structure

```
docs/
├── README.md                           # This file
├── PROJECT_STRUCTURE.md                # Complete project organization guide
├── API_SCHEMA_IMPLEMENTATION.md        # API schema implementation guide
├── FIELD_MAPPING.md                    # Field mapping documentation
├── SCHEMA_MANAGEMENT_GUIDE.md          # Schema management guide
├── IMPLEMENTATION_SUMMARY.md           # Implementation summary
├── CONNECTOR_CHANGES_SUMMARY.md        # Connector changes summary
├── ADMIN_USER.md                       # Admin user guide
├── DEPLOYMENT_STATUS.md                # Deployment status
└── deployment/                         # Deployment-specific docs
    ├── PRODUCTION_CHECKLIST.md         # Production checklist
    └── README.md                       # Deployment README
```

## Contributing to Documentation

When adding new documentation:

1. Place general documentation files in the `docs/` root directory
2. Place deployment-specific documentation in `docs/deployment/`
3. Update this README.md file to include links to new documentation
4. Use clear, descriptive filenames
5. Follow the existing documentation style and structure