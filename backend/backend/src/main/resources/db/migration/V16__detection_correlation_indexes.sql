-- Detection Engine 2.0: indexes for the correlation queries.
--
-- The correlation state for every deterministic rule IS the events table (see
-- CorrelationWindowService) - there is no in-memory window and no second copy of
-- anything to keep consistent. That choice is only affordable if the queries
-- behind it are indexed, which is what this migration adds.
--
-- Purely additive: no column, constraint or row is changed, so every existing
-- query, entity mapping and test behaves exactly as before. Indexes can be
-- dropped without affecting correctness, only speed.

-- Source-correlated rules (PASSWORD_SPRAY, ACCOUNT_ENUMERATION) ask
-- "what else did THIS SOURCE ADDRESS do, across entities, recently?".
-- That is EventRepository.findByPayloadStringFieldAndType, which filters on
-- payload->>'ip' together with event_type and an occurred_at window.
--
-- A B-tree on the extracted expression (not a GIN index on the whole document)
-- is the right shape here: the predicate is an equality test on one scalar key,
-- and the index can also serve the ORDER BY occurred_at DESC that follows.
CREATE INDEX IF NOT EXISTS idx_events_payload_ip_type_time
    ON events ((payload ->> 'ip'), event_type, occurred_at DESC)
    WHERE payload ? 'ip';

-- Entity-scoped rules (AUTH_BURST, NEW_PROCESS_EXTERNAL_CONNECTION,
-- BRUTE_FORCE_SUCCESS, IMPOSSIBLE_TRAVEL, PRIVILEGE_ESCALATION_CHAIN,
-- PROCESS_NETWORK_BURST, NETWORK_CONNECTION_BURST, MULTI_STAGE_ATTACK_CHAIN) all
-- ask "what else did THIS ENTITY do, of THIS TYPE, recently?" - the query shape
-- the original two rules already used, now on a far hotter path because eight
-- more rules share it.
--
-- The existing indexes cover (entity_id) and (event_type) separately; this
-- composite one matches the whole predicate plus the newest-first ordering, so a
-- rule evaluation is an index range scan rather than a filter over an entity's
-- entire history.
CREATE INDEX IF NOT EXISTS idx_events_entity_type_time
    ON events (entity_id, event_type, occurred_at DESC);

-- Suppression lookups for the source-correlated rules
-- (AlertRepository.findByRuleIdAndStatusIn) scan active alerts for one rule
-- ACROSS entities, because their finding is about a source address rather than
-- the entity an alert happens to be filed against. The existing
-- idx_alerts_rule_id covers rule_id alone; adding status and created_at lets the
-- capped, newest-first scan be served entirely from the index.
CREATE INDEX IF NOT EXISTS idx_alerts_rule_status_created
    ON alerts (rule_id, status, created_at DESC)
    WHERE rule_id IS NOT NULL;
