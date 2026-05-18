DROP INDEX IF EXISTS idx_repo_scans_scope_source_started_at;

ALTER TABLE repo_scans
    DROP COLUMN IF EXISTS source_installation_id,
    DROP COLUMN IF EXISTS source_connector_id,
    DROP COLUMN IF EXISTS source_project_id,
    DROP COLUMN IF EXISTS source_provider;
