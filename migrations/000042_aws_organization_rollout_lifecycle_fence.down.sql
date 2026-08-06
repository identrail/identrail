ALTER TABLE aws_organization_rollouts
    DROP CONSTRAINT IF EXISTS aws_organization_rollouts_lifecycle_generation_nonnegative;

ALTER TABLE aws_organization_rollouts
    DROP COLUMN IF EXISTS controlling_connector_lifecycle_generation;
