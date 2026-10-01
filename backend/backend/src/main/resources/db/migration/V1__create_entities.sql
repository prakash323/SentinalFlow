CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE TABLE entities (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  entity_id VARCHAR(128) NOT NULL UNIQUE,
  entity_type VARCHAR(64) NOT NULL,
  display_name VARCHAR(255),
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_entities_type ON entities(entity_type);
