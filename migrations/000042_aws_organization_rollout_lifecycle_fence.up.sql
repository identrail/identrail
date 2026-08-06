-- Bind organization rollout envelopes to the lifecycle generation of the
-- controlling connector that approved them. A pause or disconnect advances
-- that generation, making old callbacks and worker passes stale.

ALTER TABLE aws_organization_rollouts
    ADD COLUMN IF NOT EXISTS controlling_connector_lifecycle_generation BIGINT NOT NULL DEFAULT 0;

ALTER TABLE aws_organization_rollouts
    DROP CONSTRAINT IF EXISTS aws_organization_rollouts_lifecycle_generation_nonnegative;

ALTER TABLE aws_organization_rollouts
    ADD CONSTRAINT aws_organization_rollouts_lifecycle_generation_nonnegative
    CHECK (controlling_connector_lifecycle_generation >= 0);
