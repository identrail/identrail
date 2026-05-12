ALTER TABLE tenancy_scan_policies
    ADD COLUMN IF NOT EXISTS history_limit INTEGER NOT NULL DEFAULT 500,
    ADD COLUMN IF NOT EXISTS max_findings INTEGER NOT NULL DEFAULT 200;

ALTER TABLE tenancy_scan_policies
    DROP CONSTRAINT IF EXISTS tenancy_scan_policies_history_limit_positive,
    DROP CONSTRAINT IF EXISTS tenancy_scan_policies_max_findings_positive;

ALTER TABLE tenancy_scan_policies
    ADD CONSTRAINT tenancy_scan_policies_history_limit_positive CHECK (history_limit > 0),
    ADD CONSTRAINT tenancy_scan_policies_max_findings_positive CHECK (max_findings > 0);

CREATE INDEX IF NOT EXISTS idx_tenancy_scan_policies_scope_limits
    ON tenancy_scan_policies (tenant_id, workspace_id, project_id, history_limit, max_findings);
