CREATE TABLE model_versions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  model_name VARCHAR(128) NOT NULL,
  version VARCHAR(64) NOT NULL,
  artifact_uri TEXT,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  active BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(model_name, version)
);
CREATE INDEX idx_model_versions_active ON model_versions(model_name, active);
