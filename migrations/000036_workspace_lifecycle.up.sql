-- Workspace lifecycle: suspend/delete with a 30-day grace window.
-- Mirrors the user-account lifecycle pattern from migration 000018 (users.status
-- + users.deleted_at). A workspace flips through active → suspended (reversible
-- with no purge timer) or active → deleted (soft, 30-day reversible window),
-- with a separate worker pass authoritative for the post-grace hard delete.

ALTER TABLE tenancy_workspaces
    ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active',
    ADD COLUMN IF NOT EXISTS suspended_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;

-- Scope the existence check to tenancy_workspaces. A bare conname-only check
-- would skip creating the constraint here if any other table in any schema
-- already had a constraint by the same name, leaving status validation off.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint c
        JOIN pg_class t ON t.oid = c.conrelid
        WHERE c.conname = 'tenancy_workspaces_status_check'
          AND t.relname = 'tenancy_workspaces'
    ) THEN
        ALTER TABLE tenancy_workspaces
            ADD CONSTRAINT tenancy_workspaces_status_check
            CHECK (status IN ('active', 'suspended', 'deleted'));
    END IF;
END$$;

CREATE INDEX IF NOT EXISTS idx_tenancy_workspaces_status_deleted_at
    ON tenancy_workspaces (status, deleted_at)
    WHERE status = 'deleted';
