ALTER TABLE repo_scans
    ADD COLUMN IF NOT EXISTS source_provider TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS source_project_id TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS source_connector_id TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS source_installation_id BIGINT NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_repo_scans_scope_source_started_at
    ON repo_scans (tenant_id, workspace_id, source_provider, source_project_id, started_at DESC);
