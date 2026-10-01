CREATE TABLE alert_factors (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  alert_id UUID NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
  factor VARCHAR(128) NOT NULL,
  rank INTEGER NOT NULL CHECK (rank > 0),
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(alert_id, rank)
);
CREATE INDEX idx_alert_factors_alert_rank ON alert_factors(alert_id, rank);
