CREATE TABLE predictions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  event_id UUID NOT NULL REFERENCES events(id),
  entity_id UUID NOT NULL REFERENCES entities(id),
  model_name VARCHAR(128) NOT NULL,
  model_version VARCHAR(64) NOT NULL,
  anomaly_score NUMERIC(6,5) NOT NULL CHECK (anomaly_score >= 0 AND anomaly_score <= 1),
  confidence NUMERIC(6,5) CHECK (confidence IS NULL OR (confidence >= 0 AND confidence <= 1)),
  fused_score NUMERIC(6,5) CHECK (fused_score IS NULL OR (fused_score >= 0 AND fused_score <= 1)),
  decision VARCHAR(64) NOT NULL,
  features JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_predictions_entity_created ON predictions(entity_id, created_at DESC);
CREATE INDEX idx_predictions_event ON predictions(event_id);
