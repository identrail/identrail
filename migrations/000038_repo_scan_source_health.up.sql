ALTER TABLE repo_scans
    ADD COLUMN source_health TEXT NOT NULL DEFAULT 'unknown',
    ADD COLUMN source_health_details JSONB NOT NULL DEFAULT '[]'::jsonb;

ALTER TABLE repo_scans
    ADD CONSTRAINT repo_scans_source_health_valid
    CHECK (source_health IN ('complete', 'partial', 'permission_limited', 'rate_limited', 'unavailable', 'unknown'));

ALTER TABLE repo_scans
    ADD CONSTRAINT repo_scans_source_health_details_is_array
    CHECK (jsonb_typeof(source_health_details) = 'array');

CREATE INDEX IF NOT EXISTS idx_repo_scans_source_health
    ON repo_scans (tenant_id, workspace_id, source_health, started_at DESC);
