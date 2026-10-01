ALTER TABLE events
    ADD COLUMN processing_status VARCHAR(32) NOT NULL DEFAULT 'PENDING',
    ADD COLUMN processing_attempts INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN last_processing_error TEXT,
    ADD COLUMN processed_at TIMESTAMPTZ;

CREATE INDEX idx_events_processing_status ON events(processing_status);
