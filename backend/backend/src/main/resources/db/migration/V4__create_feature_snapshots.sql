CREATE TABLE feature_snapshots (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  event_id UUID NOT NULL REFERENCES events(id),
  entity_id UUID NOT NULL REFERENCES entities(id),
  feature_version VARCHAR(64) NOT NULL,
  features JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_feature_snapshots_entity_created ON feature_snapshots(entity_id, created_at DESC);
CREATE INDEX idx_feature_snapshots_event ON feature_snapshots(event_id);
