CREATE TABLE IF NOT EXISTS onboarding_state (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    current_step TEXT NOT NULL DEFAULT 'org',
    org_id TEXT,
    workspace_id TEXT,
    project_id TEXT,
    connector_id TEXT,
    connector_type TEXT,
    connector_skipped BOOLEAN NOT NULL DEFAULT FALSE,
    scan_skipped BOOLEAN NOT NULL DEFAULT FALSE,
    dashboard_tour_dismissed_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (current_step IN ('org', 'workspace', 'connect', 'scan', 'invite', 'complete')),
    CHECK (connector_type IS NULL OR connector_type IN ('aws', 'github', 'kubernetes')),
    CHECK (org_id IS NOT NULL OR workspace_id IS NULL),
    CHECK (workspace_id IS NOT NULL OR project_id IS NULL),
    CHECK (completed_at IS NULL OR current_step = 'complete'),
    FOREIGN KEY (org_id, workspace_id, project_id)
        REFERENCES tenancy_projects(tenant_id, workspace_id, project_id)
        ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_onboarding_state_step_updated
    ON onboarding_state (current_step, updated_at DESC);

CREATE INDEX IF NOT EXISTS idx_onboarding_state_scope
    ON onboarding_state (org_id, workspace_id, project_id)
    WHERE org_id IS NOT NULL;
