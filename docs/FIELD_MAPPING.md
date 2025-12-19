# Field Mapping Feature

## Overview

The API Translation Platform now supports **optional Python scripts** for connectors. Instead of requiring Python code for every transformation, you can use a **drag-and-drop field mapping interface** to visually link inbound API fields to outbound API fields.

## How It Works

### Three Transformation Options

1. **Python Script Only** - Traditional approach with full Python transformation logic
2. **Field Mappings Only** - Visual drag-and-drop mappings without any code
3. **Hybrid Approach** - Field mappings with optional Python snippets for individual field transformations

### Field Mapping Structure

Each field mapping consists of:

- **Inbound Field Path**: JSON path to the source field (e.g., `request.user.firstName`)
- **Outbound Field Path**: JSON path to the destination field (e.g., `customer.name`)
- **Transform Script** (optional): Small Python snippet to transform the value (e.g., `value.upper()`)

## Data Model

### Connector Model (Updated)

```go
type Connector struct {
    ID             string
    OrganisationID string
    Name           string
    InboundAPIID   string
    OutboundAPIID  string
    PythonScript   string         // Now optional
    IsActive       bool
    FieldMappings  []FieldMapping // New relationship
}
```

### Field Mapping Model (New)

```go
type FieldMapping struct {
    ID                string
    ConnectorID       string
    InboundFieldPath  string  // e.g., "user.email"
    OutboundFieldPath string  // e.g., "customer.emailAddress"
    TransformScript   string  // Optional Python snippet
    IsActive          bool
}
```

## Validation Rules

A connector is valid if it has **either**:
- A Python script, OR
- One or more field mappings

A connector with neither will fail validation.

## Example Use Cases

### Simple Field Mapping (No Code)

```json
{
  "connector_id": "conn-123",
  "field_mappings": [
    {
      "inbound_field_path": "user.name",
      "outbound_field_path": "customer.fullName"
    },
    {
      "inbound_field_path": "user.email",
      "outbound_field_path": "customer.emailAddress"
    }
  ]
}
```

### Field Mapping with Transformation

```json
{
  "connector_id": "conn-123",
  "field_mappings": [
    {
      "inbound_field_path": "user.firstName",
      "outbound_field_path": "customer.name",
      "transform_script": "value.upper()"
    },
    {
      "inbound_field_path": "user.birthDate",
      "outbound_field_path": "customer.dob",
      "transform_script": "datetime.strptime(value, '%Y-%m-%d').strftime('%d/%m/%Y')"
    }
  ]
}
```

### Complex Transformation (Python Script)

For complex logic that can't be expressed as simple field mappings:

```json
{
  "connector_id": "conn-123",
  "python_script": "def transform(data):\n    # Complex business logic\n    return transformed_data"
}
```

## Database Schema

### Field Mappings Table

```sql
CREATE TABLE field_mappings (
    id UUID PRIMARY KEY,
    connector_id UUID NOT NULL REFERENCES connectors(id),
    inbound_field_path VARCHAR(500) NOT NULL,
    outbound_field_path VARCHAR(500) NOT NULL,
    transform_script TEXT,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP,
    updated_at TIMESTAMP,
    deleted_at TIMESTAMP
);
```

## Migration Path

### For Existing Connectors

Existing connectors with Python scripts will continue to work without changes. The `python_script` field is now optional but still fully supported.

### For New Connectors

New connectors can be created with:
1. Field mappings only (no Python required)
2. Python script only (traditional approach)
3. Both field mappings and Python script (hybrid)

## UI Implementation Notes

The drag-and-drop interface should:

1. **Display API Schemas**: Show inbound and outbound API field structures side-by-side
2. **Visual Linking**: Allow users to drag from inbound fields to outbound fields
3. **Transform Snippets**: Provide an optional text input for Python transformation code per mapping
4. **Validation**: Ensure field paths are valid and transformations are syntactically correct
5. **Persistence**: Save mappings to the `field_mappings` table via REST API

## API Endpoints (To Be Implemented)

```
POST   /api/v1/connectors/{id}/field-mappings
GET    /api/v1/connectors/{id}/field-mappings
PUT    /api/v1/connectors/{id}/field-mappings/{mapping_id}
DELETE /api/v1/connectors/{id}/field-mappings/{mapping_id}
```

## Next Steps

1. Implement transformation engine logic to process field mappings
2. Create REST API endpoints for field mapping CRUD operations
3. Build the drag-and-drop UI interface
4. Add integration tests for field mapping transformations
5. Update documentation and user guides
