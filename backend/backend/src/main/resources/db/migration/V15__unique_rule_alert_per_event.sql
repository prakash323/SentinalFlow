-- At most one alert per (triggering event, deterministic rule).
--
-- A rule alert's business identity is (event_id, rule_id): both rules check
-- existsByEvent_IdAndRuleId before raising one, and a new alert for the same
-- rule on the same entity is only legitimate for a different triggering
-- event. ML alerts (rule_id IS NULL) are not affected.
--
-- DeterministicRuleService row-locks the event so concurrent evaluations
-- (Kafka consumer + admin replay) never race; this index is the database
-- guarantee behind that. Before applying, this must return no rows:
--   SELECT event_id, rule_id, count(*) FROM alerts
--   WHERE rule_id IS NOT NULL GROUP BY 1, 2 HAVING count(*) > 1;
CREATE UNIQUE INDEX uk_alerts_event_rule
    ON alerts (event_id, rule_id)
    WHERE rule_id IS NOT NULL;
