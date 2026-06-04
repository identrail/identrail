CREATE TABLE IF NOT EXISTS aws_platform_baseline_results (
    tenant_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    connector_id TEXT NOT NULL DEFAULT '',
    git_sha TEXT NOT NULL DEFAULT '',
    source_mode TEXT NOT NULL DEFAULT '',
    fixture_only BOOLEAN NOT NULL DEFAULT FALSE,
    connector_profile_version TEXT NOT NULL DEFAULT '',
    graph_contract_version TEXT NOT NULL DEFAULT '',
    account_id TEXT NOT NULL DEFAULT '',
    region TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL,
    confidence DOUBLE PRECISION NOT NULL DEFAULT 0,
    required_checks_passed BOOLEAN NOT NULL DEFAULT FALSE,
    failure_reasons JSONB NOT NULL DEFAULT '[]'::jsonb,
    evidence_links JSONB NOT NULL DEFAULT '[]'::jsonb,
    checks JSONB NOT NULL DEFAULT '[]'::jsonb,
    verified_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, workspace_id, project_id, connector_id),
    FOREIGN KEY (tenant_id, workspace_id, project_id)
        REFERENCES tenancy_projects(tenant_id, workspace_id, project_id)
        ON DELETE CASCADE,
    CHECK (status IN ('not_run', 'ready', 'degraded', 'blocked')),
    CHECK (confidence >= 0 AND confidence <= 1),
    CHECK (account_id = '' OR account_id ~ '^[0-9]{12}$'),
    CHECK (jsonb_typeof(failure_reasons) = 'array'),
    CHECK (jsonb_typeof(evidence_links) = 'array'),
    CHECK (jsonb_typeof(checks) = 'array')
);

CREATE INDEX IF NOT EXISTS idx_aws_platform_baseline_results_scope_status
    ON aws_platform_baseline_results (tenant_id, workspace_id, project_id, connector_id, status, updated_at DESC);

ALTER TABLE aws_platform_baseline_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE aws_platform_baseline_results FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS aws_platform_baseline_results_scope_isolation ON aws_platform_baseline_results;
CREATE POLICY aws_platform_baseline_results_scope_isolation ON aws_platform_baseline_results
USING (identrail_rls_scope_matches(tenant_id, workspace_id))
WITH CHECK (identrail_rls_scope_matches(tenant_id, workspace_id));
