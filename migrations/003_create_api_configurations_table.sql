-- +goose Up
CREATE TABLE api_configurations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organisation_id UUID NOT NULL REFERENCES organisations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    type VARCHAR(50) NOT NULL CHECK (type IN ('REST', 'SOAP')),
    direction VARCHAR(50) NOT NULL CHECK (direction IN ('inbound', 'outbound')),
    endpoint TEXT NOT NULL,
    authentication JSONB NOT NULL DEFAULT '{}',
    headers JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP NULL,
    
    UNIQUE(organisation_id, name)
);

CREATE INDEX idx_api_configurations_organisation_id ON api_configurations(organisation_id);
CREATE INDEX idx_api_configurations_type ON api_configurations(type);
CREATE INDEX idx_api_configurations_direction ON api_configurations(direction);
CREATE INDEX idx_api_configurations_name ON api_configurations(name);
CREATE INDEX idx_api_configurations_deleted_at ON api_configurations(deleted_at);

-- +goose Down
DROP TABLE api_configurations;