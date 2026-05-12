DROP INDEX IF EXISTS idx_scans_dead_lettered_started_at;
DROP INDEX IF EXISTS idx_scans_retry_queue;

ALTER TABLE scans
    DROP CONSTRAINT IF EXISTS scans_max_retry_count_non_negative,
    DROP CONSTRAINT IF EXISTS scans_retry_count_non_negative;

ALTER TABLE scans
    DROP COLUMN IF EXISTS dead_lettered_at,
    DROP COLUMN IF EXISTS dead_lettered,
    DROP COLUMN IF EXISTS next_retry_at,
    DROP COLUMN IF EXISTS failure_category,
    DROP COLUMN IF EXISTS max_retry_count,
    DROP COLUMN IF EXISTS retry_count;
