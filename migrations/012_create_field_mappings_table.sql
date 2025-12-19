-- +goose Up
CREATE TABLE field_mappings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    connector_id UUID NOT NULL REFERENCES connectors(id) ON DELETE CASCADE,
    inbound_field_path VARCHAR(500) NOT NULL,
    outbound_field_path VARCHAR(500) NOT NULL,
    transform_script TEXT,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP NULL
);

CREATE INDEX idx_field_mappings_connector_id ON field_mappings(connector_id);
CREATE INDEX idx_field_mappings_active ON field_mappings(is_active);
CREATE INDEX idx_field_mappings_deleted_at ON field_mappings(deleted_at);

-- +goose Down
DROP TABLE field_mappings;
