CREATE TABLE IF NOT EXISTS aws_account_region_coverages (
    tenant_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    connector_id TEXT NOT NULL,
    account_id TEXT NOT NULL,
    account_alias TEXT,
    organization_id TEXT,
    ou_path TEXT,
    partition TEXT NOT NULL DEFAULT 'aws',
    region TEXT NOT NULL,
    role_arn TEXT,
    coverage_status TEXT NOT NULL DEFAULT 'unknown',
    last_successful_scan_at TIMESTAMPTZ,
    last_observed_error_code TEXT,
    last_observed_error_message TEXT,
    scan_cursor JSONB NOT NULL DEFAULT '{}'::jsonb,
    suspended BOOLEAN NOT NULL DEFAULT FALSE,
    disabled BOOLEAN NOT NULL DEFAULT FALSE,
    unreachable BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, workspace_id, project_id, connector_id, account_id, region),
    FOREIGN KEY (tenant_id, workspace_id, project_id, connector_id)
        REFERENCES tenancy_connectors(tenant_id, workspace_id, project_id, connector_id)
        ON DELETE CASCADE,
    CHECK (account_id ~ '^[0-9]{12}$'),
    CHECK (LENGTH(TRIM(partition)) > 0),
    CHECK (LENGTH(TRIM(region)) > 0),
    CHECK (coverage_status IN ('unknown', 'pending', 'covered', 'gap', 'error', 'suspended', 'disabled', 'unreachable')),
    CHECK (jsonb_typeof(scan_cursor) = 'object')
);

CREATE INDEX IF NOT EXISTS idx_aws_account_region_coverages_scope_status
    ON aws_account_region_coverages (tenant_id, workspace_id, project_id, connector_id, coverage_status, updated_at DESC);

CREATE INDEX IF NOT EXISTS idx_aws_account_region_coverages_account_region
    ON aws_account_region_coverages (tenant_id, workspace_id, account_id, region);

ALTER TABLE aws_account_region_coverages ENABLE ROW LEVEL SECURITY;
ALTER TABLE aws_account_region_coverages FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS aws_account_region_coverages_scope_isolation ON aws_account_region_coverages;
CREATE POLICY aws_account_region_coverages_scope_isolation ON aws_account_region_coverages
USING (identrail_rls_scope_matches(tenant_id, workspace_id))
WITH CHECK (identrail_rls_scope_matches(tenant_id, workspace_id));
