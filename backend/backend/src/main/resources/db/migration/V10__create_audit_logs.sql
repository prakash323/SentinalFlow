CREATE TABLE audit_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  actor VARCHAR(128),
  action VARCHAR(128) NOT NULL,
  resource_type VARCHAR(64) NOT NULL,
  resource_id UUID,
  correlation_id VARCHAR(128),
  details JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_audit_logs_resource_created ON audit_logs(resource_type, resource_id, created_at DESC);
CREATE INDEX idx_audit_logs_correlation ON audit_logs(correlation_id);
