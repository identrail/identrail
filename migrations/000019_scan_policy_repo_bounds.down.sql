DROP INDEX IF EXISTS idx_tenancy_scan_policies_scope_limits;

ALTER TABLE tenancy_scan_policies
    DROP CONSTRAINT IF EXISTS tenancy_scan_policies_max_findings_positive,
    DROP CONSTRAINT IF EXISTS tenancy_scan_policies_history_limit_positive;

ALTER TABLE tenancy_scan_policies
    DROP COLUMN IF EXISTS max_findings,
    DROP COLUMN IF EXISTS history_limit;
