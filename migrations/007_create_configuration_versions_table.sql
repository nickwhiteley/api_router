-- +goose Up
CREATE TABLE configuration_versions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    resource_type VARCHAR(100) NOT NULL,
    resource_id VARCHAR(255) NOT NULL,
    version_number INTEGER NOT NULL,
    config_data JSONB NOT NULL,
    is_active BOOLEAN DEFAULT false,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    UNIQUE(resource_type, resource_id, version_number)
);

CREATE INDEX idx_configuration_versions_resource ON configuration_versions(resource_type, resource_id);
CREATE INDEX idx_configuration_versions_version ON configuration_versions(version_number);
CREATE INDEX idx_configuration_versions_active ON configuration_versions(is_active);
CREATE INDEX idx_configuration_versions_created_by ON configuration_versions(created_by);
CREATE INDEX idx_configuration_versions_created_at ON configuration_versions(created_at);

-- +goose Down
DROP TABLE configuration_versions;