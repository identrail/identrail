DROP POLICY IF EXISTS repo_scan_cursors_scope_isolation ON repo_scan_cursors;
ALTER TABLE IF EXISTS repo_scan_cursors NO FORCE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS repo_scan_cursors DISABLE ROW LEVEL SECURITY;

DROP INDEX IF EXISTS idx_repo_scan_cursors_scope_updated_at;
DROP INDEX IF EXISTS idx_repo_scan_cursors_scope_repository_source;
DROP TABLE IF EXISTS repo_scan_cursors;

DROP INDEX IF EXISTS idx_repo_scans_scope_repository_head_revision;
DROP INDEX IF EXISTS idx_repo_scans_scope_mode_started_at;

ALTER TABLE repo_scans
    DROP CONSTRAINT IF EXISTS repo_scans_scan_mode_valid;

ALTER TABLE repo_scans
    DROP COLUMN IF EXISTS changed_paths,
    DROP COLUMN IF EXISTS cursor_after,
    DROP COLUMN IF EXISTS cursor_before,
    DROP COLUMN IF EXISTS head_revision,
    DROP COLUMN IF EXISTS base_revision,
    DROP COLUMN IF EXISTS scan_mode;
