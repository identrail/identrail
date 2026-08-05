DROP INDEX IF EXISTS idx_tenancy_connectors_lifecycle_gate;
ALTER TABLE tenancy_connectors
    DROP CONSTRAINT IF EXISTS tenancy_connectors_lifecycle_generation_nonnegative;
ALTER TABLE tenancy_connectors
    DROP COLUMN IF EXISTS lifecycle_generation,
    DROP COLUMN IF EXISTS disabled;
