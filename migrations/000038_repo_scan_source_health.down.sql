DROP INDEX IF EXISTS idx_repo_scans_source_health;

ALTER TABLE repo_scans
    DROP CONSTRAINT IF EXISTS repo_scans_source_health_valid;

ALTER TABLE repo_scans
    DROP COLUMN IF EXISTS source_health_details,
    DROP COLUMN IF EXISTS source_health;
