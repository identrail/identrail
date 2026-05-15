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
-- The constraint is added NOT VALID so the migration is forward-safe against
-- databases that already contain bare provider='saml' scaffold rows created
-- under the pre-#1138 schema (status='pending', no workos_connection_id, no
-- native fields). Those legacy rows are grandfathered: they remain in place,
-- but any subsequent INSERT or UPDATE on identity_connections must satisfy
-- the constraint. Operators can run
--   ALTER TABLE identity_connections VALIDATE CONSTRAINT identity_connections_saml_completeness;
-- once they have backfilled or removed any leftover bare-pending SAML rows.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'identity_connections_saml_completeness'
    ) THEN
        ALTER TABLE identity_connections
            ADD CONSTRAINT identity_connections_saml_completeness CHECK (
                provider <> 'saml'
                OR (
                    -- WorkOS-backed: workos_connection_id set, native fields empty.
                    workos_connection_id IS NOT NULL
                    AND entity_id IS NULL
                    AND certificate_pem IS NULL
                    AND sso_url IS NULL
                )
                OR (
                    -- Native: entity_id + certificate_pem + https sso_url all set,
                    -- workos_connection_id empty.
                    workos_connection_id IS NULL
                    AND entity_id IS NOT NULL AND LENGTH(TRIM(entity_id)) > 0
                    AND certificate_pem IS NOT NULL AND LENGTH(TRIM(certificate_pem)) > 0
                    AND sso_url IS NOT NULL AND sso_url ~* '^https://'
                )
            ) NOT VALID;
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

-- A composite (org_id, id) unique index lets scim_provisioning_events install
-- a composite foreign key that enforces tenant scope, not just "the connection
-- uuid exists". Without it, a tenant could insert an event referencing a
-- connection owned by a different tenant — and the RLS policy on the events
-- table would then expose that cross-tenant row.
CREATE UNIQUE INDEX IF NOT EXISTS uq_identity_connections_org_id
    ON identity_connections (org_id, id);

-- Note: the SCIM-assigned external id is a per-connection identifier — two
-- IdPs (or two tenants on the same IdP) can legitimately emit the same value
-- without conflict. Identrail therefore stores SCIM identities in the existing
-- user_identities table with provider = 'scim:<connection_uuid>', reusing its
-- UNIQUE (provider, subject) contract instead of carrying a per-user column
-- on users that would either force global uniqueness or violate it.

------------------------------------------------------------------------------
-- scim_provisioning_events: append-only audit of every SCIM op
------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS scim_provisioning_events (
    id UUID PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES tenancy_organizations(tenant_id) ON DELETE CASCADE,
    connection_id UUID NOT NULL,
    op TEXT NOT NULL,
    external_id TEXT,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (op IN ('create', 'update', 'deactivate', 'delete')),
    CHECK (jsonb_typeof(payload) = 'object'),
    -- Composite foreign key forces (org_id, connection_id) to identify a row
    -- in identity_connections that belongs to the same tenant. Without this,
    -- an attacker (or buggy caller) with a valid connection uuid from tenant B
    -- could insert an event under tenant A; the table's RLS scopes by org_id,
    -- so that cross-tenant row would then be visible to tenant A.
    CONSTRAINT scim_provisioning_events_connection_in_org
        FOREIGN KEY (org_id, connection_id)
        REFERENCES identity_connections (org_id, id)
        ON DELETE CASCADE
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
