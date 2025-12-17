-- +goose Up
CREATE TABLE security_events (
    id VARCHAR(255) PRIMARY KEY,
    type VARCHAR(50) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    user_id VARCHAR(255),
    ip_address VARCHAR(45),
    user_agent TEXT,
    resource_id VARCHAR(255),
    action VARCHAR(100),
    details TEXT,
    metadata JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_security_events_type (type),
    INDEX idx_security_events_severity (severity),
    INDEX idx_security_events_timestamp (timestamp),
    INDEX idx_security_events_user_id (user_id),
    INDEX idx_security_events_ip_address (ip_address),
    INDEX idx_security_events_resource_id (resource_id)
);

-- +goose Down
DROP TABLE security_events;