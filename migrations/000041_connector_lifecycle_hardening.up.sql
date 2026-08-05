-- Connector lifecycle hardening for issue #1789.
--
-- `disabled` is an explicit operator gate, while lifecycle_generation is an
-- optimistic fence for late callbacks and workers. Keeping both on the
-- authoritative connector row prevents health observations from being
-- mistaken for authorization to resume work.

ALTER TABLE tenancy_connectors
    ADD COLUMN IF NOT EXISTS disabled BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS lifecycle_generation BIGINT NOT NULL DEFAULT 0;

ALTER TABLE tenancy_connectors
    DROP CONSTRAINT IF EXISTS tenancy_connectors_lifecycle_generation_nonnegative;

ALTER TABLE tenancy_connectors
    ADD CONSTRAINT tenancy_connectors_lifecycle_generation_nonnegative
    CHECK (lifecycle_generation >= 0);

CREATE INDEX IF NOT EXISTS idx_tenancy_connectors_lifecycle_gate
    ON tenancy_connectors (tenant_id, workspace_id, project_id, disabled, status, updated_at DESC);
