ALTER TABLE scans
    ADD COLUMN IF NOT EXISTS retry_count INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS max_retry_count INTEGER NOT NULL DEFAULT 3,
    ADD COLUMN IF NOT EXISTS failure_category TEXT,
    ADD COLUMN IF NOT EXISTS next_retry_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS dead_lettered BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS dead_lettered_at TIMESTAMPTZ;

ALTER TABLE scans
    DROP CONSTRAINT IF EXISTS scans_retry_count_non_negative,
    DROP CONSTRAINT IF EXISTS scans_max_retry_count_non_negative;

ALTER TABLE scans
    ADD CONSTRAINT scans_retry_count_non_negative
        CHECK (retry_count >= 0) NOT VALID,
    ADD CONSTRAINT scans_max_retry_count_non_negative
        CHECK (max_retry_count >= 0) NOT VALID;

ALTER TABLE scans VALIDATE CONSTRAINT scans_retry_count_non_negative;
ALTER TABLE scans VALIDATE CONSTRAINT scans_max_retry_count_non_negative;

CREATE INDEX IF NOT EXISTS idx_scans_retry_queue
    ON scans (provider, started_at ASC, next_retry_at ASC)
    WHERE status = 'queued' AND dead_lettered = FALSE;

CREATE INDEX IF NOT EXISTS idx_scans_dead_lettered_started_at
    ON scans (started_at DESC)
    WHERE dead_lettered = TRUE;
