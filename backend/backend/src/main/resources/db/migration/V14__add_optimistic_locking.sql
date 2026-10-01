-- Concurrency hardening: optimistic locking for Alert/Incident lifecycle
-- mutations. Confirmed live (not hypothetical) before this migration was
-- written: two concurrent PATCH /alerts/{id}/status requests on the same
-- alert both returned 200 with their own requested status, the DB ended up
-- with only one of them, and the audit log permanently recorded BOTH
-- transitions as if each had taken effect. version defaults to 0 for every
-- existing row - purely additive, no existing data changes meaning.
ALTER TABLE alerts ADD COLUMN version BIGINT NOT NULL DEFAULT 0;
ALTER TABLE incidents ADD COLUMN version BIGINT NOT NULL DEFAULT 0;
