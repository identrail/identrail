CREATE TABLE IF NOT EXISTS invitations (
    id UUID PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES tenancy_organizations(tenant_id) ON DELETE CASCADE,
    email CITEXT NOT NULL,
    role TEXT NOT NULL,
    invited_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    token_hash BYTEA NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    accepted_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (LENGTH(TRIM(email::TEXT)) > 0),
    CHECK (role IN ('owner', 'admin', 'analyst', 'viewer')),
    CHECK (LENGTH(token_hash) = 32),
    CHECK (expires_at > created_at),
    CHECK (accepted_at IS NULL OR revoked_at IS NULL)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_invitations_org_email_pending
    ON invitations (org_id, email)
    WHERE accepted_at IS NULL AND revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_invitations_org_created
    ON invitations (org_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_invitations_org_expires
    ON invitations (org_id, expires_at);

CREATE TABLE IF NOT EXISTS verified_domains (
    id UUID PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES tenancy_organizations(tenant_id) ON DELETE CASCADE,
    domain CITEXT NOT NULL,
    verification_token TEXT NOT NULL,
    verification_method TEXT NOT NULL DEFAULT 'dns_txt',
    verified_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, domain),
    CHECK (LENGTH(TRIM(domain::TEXT)) > 0),
    CHECK (LENGTH(TRIM(verification_token)) > 0),
    CHECK (verification_method IN ('dns_txt', 'manual'))
);

CREATE INDEX IF NOT EXISTS idx_verified_domains_org_verified
    ON verified_domains (org_id, verified_at DESC);

CREATE TABLE IF NOT EXISTS identity_connections (
    id UUID PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES tenancy_organizations(tenant_id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    type TEXT NOT NULL,
    workos_connection_id TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    group_role_map JSONB NOT NULL DEFAULT '{}'::jsonb,
    sso_required BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, provider, type),
    UNIQUE (workos_connection_id),
    CHECK (provider IN ('workos', 'oidc', 'saml')),
    CHECK (type IN ('sso', 'directory_sync')),
    CHECK (status IN ('pending', 'active', 'disabled')),
    CHECK (jsonb_typeof(group_role_map) = 'object'),
    CHECK (workos_connection_id IS NULL OR LENGTH(TRIM(workos_connection_id)) > 0)
);

CREATE INDEX IF NOT EXISTS idx_identity_connections_org_status
    ON identity_connections (org_id, status, updated_at DESC);

ALTER TABLE invitations ENABLE ROW LEVEL SECURITY;
ALTER TABLE invitations FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS invitations_scope_isolation ON invitations;
CREATE POLICY invitations_scope_isolation ON invitations
USING (identrail_rls_tenant_matches(org_id))
WITH CHECK (identrail_rls_tenant_matches(org_id));

ALTER TABLE verified_domains ENABLE ROW LEVEL SECURITY;
ALTER TABLE verified_domains FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS verified_domains_scope_isolation ON verified_domains;
CREATE POLICY verified_domains_scope_isolation ON verified_domains
USING (identrail_rls_tenant_matches(org_id))
WITH CHECK (identrail_rls_tenant_matches(org_id));

ALTER TABLE identity_connections ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity_connections FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS identity_connections_scope_isolation ON identity_connections;
CREATE POLICY identity_connections_scope_isolation ON identity_connections
USING (identrail_rls_tenant_matches(org_id))
WITH CHECK (identrail_rls_tenant_matches(org_id));
