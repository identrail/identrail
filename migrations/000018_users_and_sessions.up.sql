CREATE EXTENSION IF NOT EXISTS citext;

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY,
    primary_email CITEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL DEFAULT '',
    avatar_url TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ,
    CHECK (LENGTH(TRIM(primary_email::TEXT)) > 0),
    CHECK (status IN ('active', 'deactivated', 'deleted'))
);

CREATE TABLE IF NOT EXISTS user_identities (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    subject TEXT NOT NULL,
    email CITEXT,
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    raw_claims JSONB NOT NULL DEFAULT '{}'::jsonb,
    last_authenticated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (provider, subject),
    CHECK (LENGTH(TRIM(provider)) > 0),
    CHECK (LENGTH(TRIM(subject)) > 0)
);

ALTER TABLE tenancy_workspace_members
    ADD COLUMN IF NOT EXISTS user_uuid UUID REFERENCES users(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_tenancy_members_scope_user_uuid
    ON tenancy_workspace_members (tenant_id, workspace_id, user_uuid)
    WHERE user_uuid IS NOT NULL;

CREATE TABLE IF NOT EXISTS sessions (
    id BYTEA PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    current_org_id TEXT,
    current_workspace_id TEXT,
    current_project_id TEXT,
    auth_method TEXT NOT NULL,
    ip INET,
    user_agent TEXT,
    idle_expires_at TIMESTAMPTZ NOT NULL,
    absolute_expires_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (LENGTH(id) = 32),
    CHECK (auth_method IN ('workos', 'oidc', 'manual')),
    CHECK (idle_expires_at <= absolute_expires_at),
    CHECK (
        (current_org_id IS NULL AND current_workspace_id IS NULL AND current_project_id IS NULL)
        OR (current_org_id IS NOT NULL AND current_workspace_id IS NOT NULL)
    ),
    FOREIGN KEY (current_org_id, current_workspace_id, current_project_id)
        REFERENCES tenancy_projects(tenant_id, workspace_id, project_id)
        ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_user_id
    ON sessions (user_id)
    WHERE revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_sessions_absolute_expires_at
    ON sessions (absolute_expires_at);

CREATE INDEX IF NOT EXISTS idx_sessions_context
    ON sessions (current_org_id, current_workspace_id, current_project_id)
    WHERE current_org_id IS NOT NULL;
