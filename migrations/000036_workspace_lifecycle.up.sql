-- Workspace lifecycle: suspend/delete with a 30-day grace window.
-- Mirrors the user-account lifecycle pattern from migration 000018 (users.status
-- + users.deleted_at). A workspace flips through active → suspended (reversible
-- with no purge timer) or active → deleted (soft, 30-day reversible window),
-- with a separate worker pass authoritative for the post-grace hard delete.

ALTER TABLE tenancy_workspaces
    ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active',
    ADD COLUMN IF NOT EXISTS suspended_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;

-- Scope the existence check to the exact target table by OID. Matching on
-- conname plus relname could still false-positive if another schema in the
-- same database carries a `tenancy_workspaces` table with a same-named
-- constraint; the `::regclass` cast resolves against the current
-- search_path so we compare to the exact OID of the table this migration
-- targets, leaving the constraint missing on the wrong row impossible.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint c
        WHERE c.conname = 'tenancy_workspaces_status_check'
          AND c.conrelid = 'tenancy_workspaces'::regclass
    ) THEN
        ALTER TABLE tenancy_workspaces
            ADD CONSTRAINT tenancy_workspaces_status_check
            CHECK (status IN ('active', 'suspended', 'deleted'));
    END IF;
END$$;

CREATE INDEX IF NOT EXISTS idx_tenancy_workspaces_status_deleted_at
    ON tenancy_workspaces (status, deleted_at)
    WHERE status = 'deleted';
