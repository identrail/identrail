-- 000024_native_sso_scim_scaffold.up.sql
--
-- Adds the schema scaffolding for native SAML SSO and SCIM 2.0 provisioning
-- alongside the existing WorkOS-managed path. Purely additive: existing
-- WorkOS-SAML rows continue to validate; all new columns are nullable or
-- defaulted; no existing reads or writes change.
--
-- Forward-safe; all column adds, table creates, indexes, and constraints use
-- IF NOT EXISTS / DO blocks.

------------------------------------------------------------------------------
-- identity_connections: native SAML + SCIM bearer token columns
------------------------------------------------------------------------------

ALTER TABLE identity_connections
    ADD COLUMN IF NOT EXISTS entity_id TEXT,
    ADD COLUMN IF NOT EXISTS sso_url TEXT,
    ADD COLUMN IF NOT EXISTS certificate_pem TEXT,
    ADD COLUMN IF NOT EXISTS attribute_mapping JSONB NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN IF NOT EXISTS jit_provisioning_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS scim_bearer_token_hash TEXT;

-- Constrain SAML rows to be either WorkOS-backed or native-complete. WorkOS
-- rows continue to satisfy the legacy contract (workos_connection_id set,
-- native columns NULL). Native rows require entity_id, certificate_pem, and
-- an https sso_url. Non-saml providers (workos, oidc) are unaffected.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'identity_connections_saml_completeness'
    ) THEN
        ALTER TABLE identity_connections
            ADD CONSTRAINT identity_connections_saml_completeness CHECK (
                provider <> 'saml'
                OR workos_connection_id IS NOT NULL
                OR (
                    entity_id IS NOT NULL AND LENGTH(TRIM(entity_id)) > 0
                    AND certificate_pem IS NOT NULL AND LENGTH(TRIM(certificate_pem)) > 0
                    AND sso_url IS NOT NULL AND sso_url ~* '^https://'
                )
            );
    END IF;
END;
$$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'identity_connections_attribute_mapping_object'
    ) THEN
        ALTER TABLE identity_connections
            ADD CONSTRAINT identity_connections_attribute_mapping_object CHECK (
                jsonb_typeof(attribute_mapping) = 'object'
            );
    END IF;
END;
$$;

------------------------------------------------------------------------------
-- users.scim_external_id: stable foreign id from the IdP (Okta/Azure user id)
------------------------------------------------------------------------------

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS scim_external_id TEXT;

-- Unique only when populated; one IdP-assigned id per Identrail user.
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_scim_external_id
    ON users (scim_external_id)
    WHERE scim_external_id IS NOT NULL;

------------------------------------------------------------------------------
-- scim_provisioning_events: append-only audit of every SCIM op
------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS scim_provisioning_events (
    id UUID PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES tenancy_organizations(tenant_id) ON DELETE CASCADE,
    connection_id UUID NOT NULL REFERENCES identity_connections(id) ON DELETE CASCADE,
    op TEXT NOT NULL,
    external_id TEXT,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (op IN ('create', 'update', 'deactivate', 'delete')),
    CHECK (jsonb_typeof(payload) = 'object')
);

CREATE INDEX IF NOT EXISTS idx_scim_provisioning_events_connection_time
    ON scim_provisioning_events (connection_id, occurred_at DESC);

CREATE INDEX IF NOT EXISTS idx_scim_provisioning_events_external_id
    ON scim_provisioning_events (external_id)
    WHERE external_id IS NOT NULL;

ALTER TABLE scim_provisioning_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE scim_provisioning_events FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS scim_provisioning_events_scope_isolation ON scim_provisioning_events;
CREATE POLICY scim_provisioning_events_scope_isolation ON scim_provisioning_events
USING (identrail_rls_tenant_matches(org_id))
WITH CHECK (identrail_rls_tenant_matches(org_id));
