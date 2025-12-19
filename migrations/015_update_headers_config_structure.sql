-- Migration to update headers configuration structure
-- This migration updates existing headers from map[string]string to the new HeadersConfig structure

-- Update existing headers to new structure
UPDATE api_configurations 
SET headers = jsonb_build_object(
    'static', COALESCE(headers, '{}'::jsonb),
    'required', '[]'::jsonb,
    'dynamic', '{}'::jsonb
)
WHERE headers IS NOT NULL;

-- Set default structure for NULL headers
UPDATE api_configurations 
SET headers = jsonb_build_object(
    'static', '{}'::jsonb,
    'required', '[]'::jsonb,
    'dynamic', '{}'::jsonb
)
WHERE headers IS NULL;

-- Add comment to document the new structure
COMMENT ON COLUMN api_configurations.headers IS 'Headers configuration with static (always sent), required (validation only), and dynamic (per-request) headers';