ALTER TABLE repo_scans
    ADD COLUMN IF NOT EXISTS scan_mode TEXT NOT NULL DEFAULT 'deep',
    ADD COLUMN IF NOT EXISTS base_revision TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS head_revision TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS cursor_before TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS cursor_after TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS changed_paths JSONB NOT NULL DEFAULT '[]'::jsonb;

ALTER TABLE repo_scans
    DROP CONSTRAINT IF EXISTS repo_scans_scan_mode_valid;

ALTER TABLE repo_scans
    ADD CONSTRAINT repo_scans_scan_mode_valid
        CHECK (scan_mode IN ('quick', 'delta', 'deep')) NOT VALID;

ALTER TABLE repo_scans VALIDATE CONSTRAINT repo_scans_scan_mode_valid;

CREATE INDEX IF NOT EXISTS idx_repo_scans_scope_mode_started_at
    ON repo_scans (tenant_id, workspace_id, scan_mode, started_at DESC);

CREATE INDEX IF NOT EXISTS idx_repo_scans_scope_repository_head_revision
    ON repo_scans (tenant_id, workspace_id, repository, head_revision);

CREATE TABLE IF NOT EXISTS repo_scan_cursors (
    tenant_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    repository TEXT NOT NULL,
    source_provider TEXT NOT NULL DEFAULT '',
    source_project_id TEXT NOT NULL DEFAULT '',
    source_connector_id TEXT NOT NULL DEFAULT '',
    source_installation_id BIGINT NOT NULL DEFAULT 0,
    last_scanned_revision TEXT NOT NULL,
    last_deep_scanned_at TIMESTAMPTZ,
    last_scan_id UUID,
    last_scan_mode TEXT NOT NULL DEFAULT 'deep',
    last_scan_completed_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT repo_scan_cursors_last_scanned_revision_non_empty
        CHECK (LENGTH(TRIM(last_scanned_revision)) > 0),
    CONSTRAINT repo_scan_cursors_last_scan_mode_valid
        CHECK (last_scan_mode IN ('quick', 'delta', 'deep'))
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_repo_scan_cursors_scope_repository_source
    ON repo_scan_cursors (
        tenant_id,
        workspace_id,
        (lower(repository)),
        source_provider,
        source_project_id,
        source_connector_id,
        source_installation_id
    );

CREATE INDEX IF NOT EXISTS idx_repo_scan_cursors_scope_updated_at
    ON repo_scan_cursors (tenant_id, workspace_id, updated_at DESC);

ALTER TABLE repo_scan_cursors ENABLE ROW LEVEL SECURITY;
ALTER TABLE repo_scan_cursors FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS repo_scan_cursors_scope_isolation ON repo_scan_cursors;
CREATE POLICY repo_scan_cursors_scope_isolation ON repo_scan_cursors
USING (identrail_rls_scope_matches(tenant_id, workspace_id))
WITH CHECK (identrail_rls_scope_matches(tenant_id, workspace_id));
