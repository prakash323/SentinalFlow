CREATE TABLE incidents (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  incident_key VARCHAR(128) NOT NULL UNIQUE,
  entity_id UUID REFERENCES entities(id),
  status VARCHAR(32) NOT NULL DEFAULT 'OPEN',
  summary TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  closed_at TIMESTAMPTZ
);
CREATE INDEX idx_incidents_entity_status ON incidents(entity_id, status);
