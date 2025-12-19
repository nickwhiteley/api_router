-- +goose Up
CREATE TABLE api_schemas (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    api_configuration_id UUID NOT NULL REFERENCES api_configurations(id) ON DELETE CASCADE,
    schema_type VARCHAR(50) NOT NULL CHECK (schema_type IN ('json_schema', 'openapi_v3', 'wsdl', 'custom')),
    schema_content JSONB NOT NULL DEFAULT '{}',
    parsed_fields JSONB NOT NULL DEFAULT '[]',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP NULL,
    
    UNIQUE(api_configuration_id)
);

CREATE INDEX idx_api_schemas_api_configuration_id ON api_schemas(api_configuration_id);
CREATE INDEX idx_api_schemas_schema_type ON api_schemas(schema_type);
CREATE INDEX idx_api_schemas_deleted_at ON api_schemas(deleted_at);

-- +goose Down
DROP TABLE api_schemas;