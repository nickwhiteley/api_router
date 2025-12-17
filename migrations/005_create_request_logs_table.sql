-- +goose Up
CREATE TABLE request_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organisation_id UUID NOT NULL REFERENCES organisations(id) ON DELETE CASCADE,
    connector_id UUID REFERENCES connectors(id) ON DELETE SET NULL,
    request_id VARCHAR(255) NOT NULL,
    method VARCHAR(10) NOT NULL,
    path TEXT NOT NULL,
    status_code INTEGER NOT NULL,
    processing_time_ms INTEGER NOT NULL DEFAULT 0,
    error_message TEXT,
    request_headers JSONB DEFAULT '{}',
    request_body TEXT,
    response_headers JSONB DEFAULT '{}',
    response_body TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_request_logs_organisation_id ON request_logs(organisation_id);
CREATE INDEX idx_request_logs_connector_id ON request_logs(connector_id);
CREATE INDEX idx_request_logs_request_id ON request_logs(request_id);
CREATE INDEX idx_request_logs_method ON request_logs(method);
CREATE INDEX idx_request_logs_status_code ON request_logs(status_code);
CREATE INDEX idx_request_logs_timestamp ON request_logs(timestamp);
CREATE INDEX idx_request_logs_processing_time ON request_logs(processing_time_ms);

-- +goose Down
DROP TABLE request_logs;