-- Independent deterministic detection (P1): lets an Alert be raised by a
-- platform rule instead of an ML prediction. Both columns are nullable and
-- purely additive - every existing alert row is untouched (rule_id/rule_name
-- simply stay NULL, which the application layer reads as "ML-driven alert").
ALTER TABLE alerts ADD COLUMN rule_id VARCHAR(64);
ALTER TABLE alerts ADD COLUMN rule_name VARCHAR(200);

CREATE INDEX idx_alerts_rule_id ON alerts(rule_id);
