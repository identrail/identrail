-- AWS Organization rollout envelopes and per-target state.
--
-- One rollout row represents a single approved StackSet rollout (organization,
-- selected OUs / accounts, exclusions, regions) launched from a validated
-- controlling account. Its registration_secret_hash is the only persisted form
-- of the one-time secret that every member-account stack instance presents in
-- its registration event. Targets are the (account, region) pairs the rollout
-- expects to cover; each carries its own honest state and is upserted
-- idempotently as AWS-authenticated events arrive.

CREATE TABLE IF NOT EXISTS aws_organization_rollouts (
    rollout_id                       TEXT PRIMARY KEY,
    tenant_id                        TEXT NOT NULL,
    workspace_id                     TEXT NOT NULL,
    project_id                       TEXT NOT NULL,
    controlling_connector_id         TEXT NOT NULL,
    controlling_role                 TEXT NOT NULL,
    organization_id                  TEXT NOT NULL,
    management_account_id            TEXT NOT NULL,
    partition                        TEXT NOT NULL,
    deployment_mode                  TEXT NOT NULL,
    stack_set_name                   TEXT NOT NULL,
    expected_role_name               TEXT NOT NULL,
    template_version                 TEXT NOT NULL,
    template_checksum                TEXT NOT NULL,
    registration_secret_hash         BYTEA NOT NULL,
    registration_secret_key_version  TEXT NOT NULL,
    selected_ou_ids                  JSONB NOT NULL DEFAULT '[]'::jsonb,
    selected_account_ids             JSONB NOT NULL DEFAULT '[]'::jsonb,
    excluded_account_ids             JSONB NOT NULL DEFAULT '[]'::jsonb,
    target_regions                   JSONB NOT NULL DEFAULT '[]'::jsonb,
    auto_deploy_new_accounts         BOOLEAN NOT NULL DEFAULT FALSE,
    status                           TEXT NOT NULL,
    failure_code                     TEXT,
    failure_message                  TEXT,
    expires_at                       TIMESTAMPTZ NOT NULL,
    created_at                       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at                       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    version                          BIGINT NOT NULL DEFAULT 1,
    FOREIGN KEY (tenant_id, workspace_id, project_id, controlling_connector_id)
        REFERENCES tenancy_connectors(tenant_id, workspace_id, project_id, connector_id)
        ON DELETE CASCADE,
    CHECK (LENGTH(TRIM(rollout_id)) > 0),
    CHECK (LENGTH(TRIM(organization_id)) > 0),
    CHECK (LENGTH(TRIM(management_account_id)) = 12),
    CHECK (LENGTH(TRIM(partition)) > 0),
    CHECK (LENGTH(TRIM(stack_set_name)) > 0),
    CHECK (LENGTH(TRIM(expected_role_name)) > 0),
    CHECK (LENGTH(TRIM(template_version)) > 0),
    CHECK (LENGTH(TRIM(template_checksum)) > 0),
    CHECK (LENGTH(registration_secret_hash) = 32),
    CHECK (LENGTH(TRIM(registration_secret_key_version)) > 0),
    CHECK (version > 0),
    CHECK (controlling_role IN ('management', 'delegated_admin')),
    CHECK (deployment_mode IN ('service_managed', 'self_managed')),
    CHECK (management_account_id ~ '^[0-9]{12}$'),
    -- Every scope list is JSONB but must be a JSON array so the target
    -- seeder, StackSet launch URL builder, and scope validators never see
    -- an object, scalar, or JSON `null` where they expect a list.
    CHECK (jsonb_typeof(selected_ou_ids) = 'array'),
    CHECK (jsonb_typeof(selected_account_ids) = 'array'),
    CHECK (jsonb_typeof(excluded_account_ids) = 'array'),
    CHECK (jsonb_typeof(target_regions) = 'array'),
    CHECK (status IN (
        'created',
        'launching',
        'in_progress',
        'reconciling',
        'completed',
        'partial',
        'failed',
        'expired',
        'canceled'
    )),
    -- The composite scope key is what the target FK below references so
    -- (rollout_id, tenant_id, workspace_id, project_id) cannot diverge from
    -- the parent envelope. Without this, a target row could persist under an
    -- unrelated project/workspace even with a valid rollout_id.
    CONSTRAINT aws_organization_rollouts_scope_uniq
        UNIQUE (rollout_id, tenant_id, workspace_id, project_id)
);

CREATE INDEX IF NOT EXISTS idx_aws_organization_rollouts_scope
    ON aws_organization_rollouts (
        tenant_id, workspace_id, project_id, controlling_connector_id, created_at DESC
    );

CREATE UNIQUE INDEX IF NOT EXISTS idx_aws_organization_rollouts_one_active
    ON aws_organization_rollouts (
        tenant_id, workspace_id, project_id, controlling_connector_id
    )
    WHERE status IN ('created', 'launching', 'in_progress', 'reconciling');

CREATE INDEX IF NOT EXISTS idx_aws_organization_rollouts_expiry
    ON aws_organization_rollouts (status, expires_at)
    WHERE status IN ('created', 'launching', 'in_progress', 'reconciling');

ALTER TABLE aws_organization_rollouts ENABLE ROW LEVEL SECURITY;
ALTER TABLE aws_organization_rollouts FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS aws_organization_rollouts_scope_isolation ON aws_organization_rollouts;
CREATE POLICY aws_organization_rollouts_scope_isolation ON aws_organization_rollouts
USING (identrail_rls_scope_matches(tenant_id, workspace_id))
WITH CHECK (identrail_rls_scope_matches(tenant_id, workspace_id));

CREATE TABLE IF NOT EXISTS aws_organization_rollout_targets (
    rollout_id            TEXT NOT NULL,
    account_id            TEXT NOT NULL,
    region                TEXT NOT NULL,
    tenant_id             TEXT NOT NULL,
    workspace_id          TEXT NOT NULL,
    project_id            TEXT NOT NULL,
    account_name          TEXT,
    ou_path               TEXT,
    is_management         BOOLEAN NOT NULL DEFAULT FALSE,
    state                 TEXT NOT NULL,
    stack_instance_id     TEXT,
    stack_id              TEXT,
    role_arn              TEXT,
    failure_code          TEXT,
    failure_message       TEXT,
    retryable             BOOLEAN NOT NULL DEFAULT FALSE,
    evidence_ref          TEXT,
    register_request_id   TEXT,
    last_transition_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_validation_at    TIMESTAMPTZ,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    version               BIGINT NOT NULL DEFAULT 1,
    PRIMARY KEY (rollout_id, account_id, region),
    -- The composite FK binds every target row to its parent's complete scope
    -- (rollout_id + tenant + workspace + project). Without this an insert
    -- with a valid rollout_id but the wrong scope would silently succeed and
    -- desynchronize scoped status queries from persisted state.
    FOREIGN KEY (rollout_id, tenant_id, workspace_id, project_id)
        REFERENCES aws_organization_rollouts(rollout_id, tenant_id, workspace_id, project_id)
        ON DELETE CASCADE,
    CHECK (account_id ~ '^[0-9]{12}$'),
    CHECK (LENGTH(TRIM(region)) > 0),
    CHECK (version > 0),
    CHECK (state IN (
        'pending',
        'deploying',
        'registering',
        'validating',
        'connected',
        'partial',
        'failed',
        'excluded',
        'suspended',
        'removed'
    ))
);

CREATE INDEX IF NOT EXISTS idx_aws_organization_rollout_targets_scope
    ON aws_organization_rollout_targets (tenant_id, workspace_id, project_id, rollout_id);

CREATE INDEX IF NOT EXISTS idx_aws_organization_rollout_targets_state
    ON aws_organization_rollout_targets (rollout_id, state);

ALTER TABLE aws_organization_rollout_targets ENABLE ROW LEVEL SECURITY;
ALTER TABLE aws_organization_rollout_targets FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS aws_organization_rollout_targets_scope_isolation ON aws_organization_rollout_targets;
CREATE POLICY aws_organization_rollout_targets_scope_isolation ON aws_organization_rollout_targets
USING (identrail_rls_scope_matches(tenant_id, workspace_id))
WITH CHECK (identrail_rls_scope_matches(tenant_id, workspace_id));
