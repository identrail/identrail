DROP INDEX IF EXISTS idx_sessions_context;
DROP INDEX IF EXISTS idx_sessions_absolute_expires_at;
DROP INDEX IF EXISTS idx_sessions_user_id;
DROP TABLE IF EXISTS sessions;

DROP INDEX IF EXISTS idx_tenancy_members_scope_user_uuid;
ALTER TABLE tenancy_workspace_members
    DROP COLUMN IF EXISTS user_uuid;

DROP TABLE IF EXISTS user_identities;
DROP TABLE IF EXISTS users;
