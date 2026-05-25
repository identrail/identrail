ALTER TABLE scans
    ADD COLUMN IF NOT EXISTS source_project_id TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS source_connector_id TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_scans_source_scope_status_started
    ON scans (tenant_id, workspace_id, source_project_id, source_connector_id, provider, status, started_at DESC);
