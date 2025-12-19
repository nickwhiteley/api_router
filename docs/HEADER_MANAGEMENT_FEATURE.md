# Header Management Feature

## Overview
The header management feature allows you to configure HTTP headers for both inbound and outbound APIs with different types of header configurations.

## Header Types

### 1. Static Headers
- **Purpose**: Headers that are always sent with outbound requests or expected in inbound requests
- **Use Cases**: 
  - API keys for outbound services
  - Content-Type specifications
  - Custom application headers
- **Example**: `Authorization: Bearer token123`

### 2. Required Headers (Inbound Only)
- **Purpose**: Headers that must be present in incoming requests for validation
- **Use Cases**:
  - API key validation
  - Authentication tokens
  - Required metadata headers
- **Example**: Requiring `X-API-Key` header for all inbound requests

### 3. Dynamic Headers
- **Purpose**: Headers that can be set per request (future enhancement)
- **Use Cases**: Request-specific metadata, correlation IDs

## Configuration

### API Management UI
When creating or editing an API configuration, you'll see a "Header Configuration" section with:

1. **Static Headers**
   - Add header name/value pairs
   - Common header suggestions (Authorization, X-API-Key, Content-Type, Accept)
   - Remove individual headers

2. **Required Headers** (Inbound APIs only)
   - Specify header names that must be present
   - Validation occurs before request processing

### Common Header Suggestions
The UI provides quick-add buttons for common headers:
- **Authorization**: `Bearer YOUR_TOKEN`
- **X-API-Key**: `YOUR_API_KEY`
- **Content-Type**: `application/json`
- **Accept**: `application/json`

## Technical Implementation

### Data Structure
```go
type HeadersConfig struct {
    Static   map[string]string `json:"static"`   // Always sent/expected
    Required []string          `json:"required"` // Must be present (inbound)
    Dynamic  map[string]string `json:"dynamic"`  // Per-request headers
}
```

### Database Storage
Headers are stored as JSONB in the `api_configurations.headers` column:
```json
{
  "static": {
    "Authorization": "Bearer token123",
    "Content-Type": "application/json"
  },
  "required": ["X-API-Key", "Authorization"],
  "dynamic": {}
}
```

### Validation (Inbound APIs)
Required headers are validated in the `validateRequest` function:
- Missing required headers result in HTTP 400 Bad Request
- Error message lists all missing headers

### Header Application (Outbound APIs)
Static and dynamic headers are automatically applied to outbound requests:
- Static headers are always included
- Dynamic headers can override static headers
- Authentication headers are applied separately

## Usage Examples

### Inbound API with Required Headers
```json
{
  "name": "Webhook API",
  "type": "REST",
  "direction": "inbound",
  "endpoint": "/webhook",
  "headers": {
    "static": {},
    "required": ["X-API-Key", "X-Signature"],
    "dynamic": {}
  }
}
```

### Outbound API with Static Headers
```json
{
  "name": "External Service",
  "type": "REST", 
  "direction": "outbound",
  "endpoint": "https://api.external.com",
  "headers": {
    "static": {
      "Authorization": "Bearer abc123",
      "Content-Type": "application/json",
      "User-Agent": "MyApp/1.0"
    },
    "required": [],
    "dynamic": {}
  }
}
```

## Error Handling

### Missing Required Headers
When required headers are missing from inbound requests:
```
HTTP 400 Bad Request
{
  "error": "Request validation failed: missing required headers: X-API-Key, Authorization"
}
```

### Invalid Header Values
Header values are validated for:
- Non-empty strings
- Valid header name format
- Reasonable length limits

## Migration
Existing header configurations are automatically migrated from the old `map[string]string` format to the new `HeadersConfig` structure:
- Old headers become "static" headers
- Required and dynamic arrays are initialized as empty

## Files Modified
- `internal/models/api_configuration.go`: Enhanced HeadersConfig structure
- `internal/services/api_gateway.go`: Added header validation
- `internal/services/outbound_client.go`: Updated header application
- `internal/handlers/auth_ui.go`: Added header management UI
- `migrations/015_update_headers_config_structure.sql`: Database migration

## Benefits
1. **Security**: Required header validation prevents unauthorized access
2. **Flexibility**: Different header types for different use cases
3. **Usability**: Common header suggestions and intuitive UI
4. **Maintainability**: Centralized header configuration
5. **Backward Compatibility**: Automatic migration of existing configurations

## Future Enhancements
- Dynamic header templates with variable substitution
- Header transformation rules
- Conditional headers based on request content
- Header encryption for sensitive values