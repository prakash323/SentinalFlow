CREATE TABLE alerts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  event_id UUID REFERENCES events(id),
  entity_id UUID NOT NULL REFERENCES entities(id),
  prediction_id UUID REFERENCES predictions(id),
  incident_id UUID REFERENCES incidents(id),
  decision VARCHAR(64) NOT NULL,
  severity VARCHAR(32) NOT NULL,
  status VARCHAR(32) NOT NULL DEFAULT 'OPEN',
  anomaly_score NUMERIC(6,5) CHECK (anomaly_score IS NULL OR (anomaly_score >= 0 AND anomaly_score <= 1)),
  confidence NUMERIC(6,5) CHECK (confidence IS NULL OR (confidence >= 0 AND confidence <= 1)),
  fused_score NUMERIC(6,5) CHECK (fused_score IS NULL OR (fused_score >= 0 AND fused_score <= 1)),
  policy_version VARCHAR(64) NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  acknowledged_at TIMESTAMPTZ,
  resolved_at TIMESTAMPTZ
);
CREATE INDEX idx_alerts_status_created ON alerts(status, created_at DESC);
CREATE INDEX idx_alerts_severity_status ON alerts(severity, status);
CREATE INDEX idx_alerts_entity_created ON alerts(entity_id, created_at DESC);
CREATE INDEX idx_alerts_incident ON alerts(incident_id);
