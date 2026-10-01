CREATE TABLE events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  event_id VARCHAR(128) NOT NULL UNIQUE,
  entity_id UUID NOT NULL REFERENCES entities(id),
  event_type VARCHAR(128) NOT NULL,
  event_version VARCHAR(32) NOT NULL,
  occurred_at TIMESTAMPTZ NOT NULL,
  source VARCHAR(128),
  payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_events_entity_occurred ON events(entity_id, occurred_at DESC);
CREATE INDEX idx_events_type_occurred ON events(event_type, occurred_at DESC);
