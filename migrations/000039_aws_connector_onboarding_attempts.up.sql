CREATE TABLE IF NOT EXISTS aws_connector_onboarding_attempts (
    attempt_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    connector_id TEXT NOT NULL,
    status TEXT NOT NULL,
    token_hash BYTEA NOT NULL,
    token_key_version TEXT NOT NULL,
    provider_topic_arn TEXT NOT NULL,
    template_version TEXT NOT NULL,
    template_checksum TEXT NOT NULL,
    deployment_region TEXT NOT NULL,
    stack_id TEXT,
    aws_account_id TEXT,
    aws_partition TEXT,
    role_arn TEXT,
    bootstrap_request_id TEXT,
    register_request_id TEXT,
    failure_code TEXT,
    failure_message TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    registered_at TIMESTAMPTZ,
    validated_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    version BIGINT NOT NULL DEFAULT 1,
    FOREIGN KEY (tenant_id, workspace_id, project_id, connector_id)
        REFERENCES tenancy_connectors(tenant_id, workspace_id, project_id, connector_id)
        ON DELETE CASCADE,
    CHECK (LENGTH(TRIM(attempt_id)) > 0),
    CHECK (LENGTH(token_hash) = 32),
    CHECK (LENGTH(TRIM(token_key_version)) > 0),
    CHECK (LENGTH(TRIM(provider_topic_arn)) > 0),
    CHECK (LENGTH(TRIM(template_version)) > 0),
    CHECK (LENGTH(TRIM(template_checksum)) > 0),
    CHECK (LENGTH(TRIM(deployment_region)) > 0),
    CHECK (version > 0),
    CHECK (status IN (
        'waiting_for_aws',
        'registering',
        'validating',
        'connected',
        'needs_fix',
        'expired',
        'failed'
    ))
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_aws_connector_onboarding_one_active
    ON aws_connector_onboarding_attempts (tenant_id, workspace_id, project_id, connector_id)
    WHERE status IN ('waiting_for_aws', 'registering', 'validating');

CREATE INDEX IF NOT EXISTS idx_aws_connector_onboarding_scope_connector
    ON aws_connector_onboarding_attempts (
        tenant_id,
        workspace_id,
        project_id,
        connector_id,
        created_at DESC
    );

CREATE INDEX IF NOT EXISTS idx_aws_connector_onboarding_expiry
    ON aws_connector_onboarding_attempts (status, expires_at)
    WHERE status IN ('waiting_for_aws', 'registering', 'validating');

ALTER TABLE aws_connector_onboarding_attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE aws_connector_onboarding_attempts FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS aws_connector_onboarding_attempts_scope_isolation ON aws_connector_onboarding_attempts;
CREATE POLICY aws_connector_onboarding_attempts_scope_isolation ON aws_connector_onboarding_attempts
USING (identrail_rls_scope_matches(tenant_id, workspace_id))
WITH CHECK (identrail_rls_scope_matches(tenant_id, workspace_id));
