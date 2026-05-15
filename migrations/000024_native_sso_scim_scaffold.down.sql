-- 000024_native_sso_scim_scaffold.down.sql

DROP POLICY IF EXISTS scim_provisioning_events_scope_isolation ON scim_provisioning_events;
DROP INDEX IF EXISTS idx_scim_provisioning_events_external_id;
DROP INDEX IF EXISTS idx_scim_provisioning_events_connection_time;
DROP TABLE IF EXISTS scim_provisioning_events;

DROP INDEX IF EXISTS uq_identity_connections_org_id;

ALTER TABLE identity_connections
    DROP CONSTRAINT IF EXISTS identity_connections_attribute_mapping_object,
    DROP CONSTRAINT IF EXISTS identity_connections_saml_completeness,
    DROP COLUMN IF EXISTS scim_bearer_token_hash,
    DROP COLUMN IF EXISTS jit_provisioning_enabled,
    DROP COLUMN IF EXISTS attribute_mapping,
    DROP COLUMN IF EXISTS certificate_pem,
    DROP COLUMN IF EXISTS sso_url,
    DROP COLUMN IF EXISTS entity_id;
