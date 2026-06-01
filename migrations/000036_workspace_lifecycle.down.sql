DROP INDEX IF EXISTS idx_tenancy_workspaces_status_deleted_at;

ALTER TABLE tenancy_workspaces
    DROP CONSTRAINT IF EXISTS tenancy_workspaces_status_check;

ALTER TABLE tenancy_workspaces
    DROP COLUMN IF EXISTS deleted_at,
    DROP COLUMN IF EXISTS suspended_at,
    DROP COLUMN IF EXISTS status;
