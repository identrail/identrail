DROP INDEX IF EXISTS idx_scans_source_scope_status_started;

ALTER TABLE scans
    DROP COLUMN IF EXISTS source_connector_id,
    DROP COLUMN IF EXISTS source_project_id;
