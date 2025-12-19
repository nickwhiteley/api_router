-- Add error_details column to request_logs table for storing detailed error information
-- +goose Up
ALTER TABLE request_logs ADD COLUMN error_details TEXT;

-- +goose Down
ALTER TABLE request_logs DROP COLUMN error_details;