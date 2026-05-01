CREATE TABLE IF NOT EXISTS tenancy_connectors (
    tenant_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    connector_id TEXT NOT NULL,
    type TEXT NOT NULL,
    display_name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    secret_provider TEXT,
    secret_ref_id TEXT,
    secret_ref_version TEXT,
    secret_last_rotated_at TIMESTAMPTZ,
    config_checksum TEXT,
    last_sync_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, workspace_id, project_id, connector_id),
    UNIQUE (tenant_id, workspace_id, project_id, type, display_name),
    FOREIGN KEY (tenant_id, workspace_id, project_id)
        REFERENCES tenancy_projects(tenant_id, workspace_id, project_id)
        ON DELETE CASCADE,
    CHECK (LENGTH(TRIM(connector_id)) > 0),
    CHECK (LENGTH(TRIM(display_name)) > 0),
    CHECK (type IN ('github', 'aws', 'kubernetes')),
    CHECK (status IN ('pending', 'active', 'degraded', 'disconnected')),
    CHECK (secret_provider IS NULL OR LENGTH(TRIM(secret_provider)) > 0),
    CHECK (secret_ref_id IS NULL OR LENGTH(TRIM(secret_ref_id)) > 0),
    CHECK (
        (secret_provider IS NULL) = (secret_ref_id IS NULL)
    )
);

CREATE TABLE IF NOT EXISTS tenancy_connector_states (
    tenant_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    connector_id TEXT NOT NULL,
    health_status TEXT NOT NULL DEFAULT 'unknown',
    sync_cursor TEXT,
    last_successful_sync_at TIMESTAMPTZ,
    last_error_code TEXT,
    last_error_message TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    observed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, workspace_id, project_id, connector_id),
    FOREIGN KEY (tenant_id, workspace_id, project_id, connector_id)
        REFERENCES tenancy_connectors(tenant_id, workspace_id, project_id, connector_id)
        ON DELETE CASCADE,
    CHECK (health_status IN ('unknown', 'healthy', 'warning', 'error')),
    CHECK (jsonb_typeof(metadata) = 'object')
);

CREATE TABLE IF NOT EXISTS tenancy_scan_policies (
    tenant_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    policy_id TEXT NOT NULL,
    name TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    trigger_mode TEXT NOT NULL DEFAULT 'manual',
    cron TEXT,
    max_concurrent_scans INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, workspace_id, project_id, policy_id),
    UNIQUE (tenant_id, workspace_id, project_id, name),
    FOREIGN KEY (tenant_id, workspace_id, project_id)
        REFERENCES tenancy_projects(tenant_id, workspace_id, project_id)
        ON DELETE CASCADE,
    CHECK (LENGTH(TRIM(policy_id)) > 0),
    CHECK (LENGTH(TRIM(name)) > 0),
    CHECK (trigger_mode IN ('manual', 'scheduled', 'event', 'hybrid')),
    CHECK (max_concurrent_scans > 0),
    CHECK (
        trigger_mode NOT IN ('scheduled', 'hybrid')
        OR (cron IS NOT NULL AND LENGTH(TRIM(cron)) > 0)
    )
);

CREATE INDEX IF NOT EXISTS idx_tenancy_connectors_scope_status
    ON tenancy_connectors (tenant_id, workspace_id, status, updated_at DESC);

CREATE INDEX IF NOT EXISTS idx_tenancy_connectors_scope_sync
    ON tenancy_connectors (tenant_id, workspace_id, project_id, last_sync_at DESC);

CREATE INDEX IF NOT EXISTS idx_tenancy_connector_states_scope_health
    ON tenancy_connector_states (tenant_id, workspace_id, project_id, health_status, observed_at DESC);

CREATE INDEX IF NOT EXISTS idx_tenancy_scan_policies_scope_mode_enabled
    ON tenancy_scan_policies (tenant_id, workspace_id, project_id, trigger_mode, enabled);

CREATE INDEX IF NOT EXISTS idx_tenancy_scan_policies_scope_updated
    ON tenancy_scan_policies (tenant_id, workspace_id, project_id, updated_at DESC);
