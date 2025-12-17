-- +goose Up
CREATE TABLE connectors (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organisation_id UUID NOT NULL REFERENCES organisations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    inbound_api_id UUID NOT NULL REFERENCES api_configurations(id) ON DELETE CASCADE,
    outbound_api_id UUID NOT NULL REFERENCES api_configurations(id) ON DELETE CASCADE,
    python_script TEXT NOT NULL,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP NULL,
    
    UNIQUE(organisation_id, name)
);

CREATE INDEX idx_connectors_organisation_id ON connectors(organisation_id);
CREATE INDEX idx_connectors_inbound_api_id ON connectors(inbound_api_id);
CREATE INDEX idx_connectors_outbound_api_id ON connectors(outbound_api_id);
CREATE INDEX idx_connectors_name ON connectors(name);
CREATE INDEX idx_connectors_active ON connectors(is_active);
CREATE INDEX idx_connectors_deleted_at ON connectors(deleted_at);

-- +goose Down
DROP TABLE connectors;