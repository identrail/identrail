CREATE OR REPLACE FUNCTION identrail_rls_tenant_matches(row_tenant TEXT)
RETURNS BOOLEAN
LANGUAGE SQL
STABLE
AS $$
    SELECT
        COALESCE(current_setting('identrail.rls_enforce', true), 'off') <> 'on'
        OR (
            NULLIF(current_setting('identrail.tenant_id', true), '') IS NOT NULL
            AND row_tenant = current_setting('identrail.tenant_id', true)
        );
$$;

ALTER TABLE tenancy_organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenancy_organizations FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenancy_organizations_scope_isolation ON tenancy_organizations;
CREATE POLICY tenancy_organizations_scope_isolation ON tenancy_organizations
USING (identrail_rls_tenant_matches(tenant_id))
WITH CHECK (identrail_rls_tenant_matches(tenant_id));

ALTER TABLE tenancy_workspaces ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenancy_workspaces FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenancy_workspaces_scope_isolation ON tenancy_workspaces;
CREATE POLICY tenancy_workspaces_scope_isolation ON tenancy_workspaces
USING (identrail_rls_scope_matches(tenant_id, workspace_id))
WITH CHECK (identrail_rls_scope_matches(tenant_id, workspace_id));

ALTER TABLE tenancy_workspace_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenancy_workspace_members FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenancy_workspace_members_scope_isolation ON tenancy_workspace_members;
CREATE POLICY tenancy_workspace_members_scope_isolation ON tenancy_workspace_members
USING (identrail_rls_scope_matches(tenant_id, workspace_id))
WITH CHECK (identrail_rls_scope_matches(tenant_id, workspace_id));

ALTER TABLE tenancy_projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenancy_projects FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenancy_projects_scope_isolation ON tenancy_projects;
CREATE POLICY tenancy_projects_scope_isolation ON tenancy_projects
USING (identrail_rls_scope_matches(tenant_id, workspace_id))
WITH CHECK (identrail_rls_scope_matches(tenant_id, workspace_id));

ALTER TABLE tenancy_connectors ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenancy_connectors FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenancy_connectors_scope_isolation ON tenancy_connectors;
CREATE POLICY tenancy_connectors_scope_isolation ON tenancy_connectors
USING (identrail_rls_scope_matches(tenant_id, workspace_id))
WITH CHECK (identrail_rls_scope_matches(tenant_id, workspace_id));

ALTER TABLE tenancy_connector_states ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenancy_connector_states FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenancy_connector_states_scope_isolation ON tenancy_connector_states;
CREATE POLICY tenancy_connector_states_scope_isolation ON tenancy_connector_states
USING (identrail_rls_scope_matches(tenant_id, workspace_id))
WITH CHECK (identrail_rls_scope_matches(tenant_id, workspace_id));

ALTER TABLE tenancy_scan_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenancy_scan_policies FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenancy_scan_policies_scope_isolation ON tenancy_scan_policies;
CREATE POLICY tenancy_scan_policies_scope_isolation ON tenancy_scan_policies
USING (identrail_rls_scope_matches(tenant_id, workspace_id))
WITH CHECK (identrail_rls_scope_matches(tenant_id, workspace_id));

ALTER TABLE tenancy_connector_secret_envelopes ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenancy_connector_secret_envelopes FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenancy_connector_secret_envelopes_scope_isolation ON tenancy_connector_secret_envelopes;
CREATE POLICY tenancy_connector_secret_envelopes_scope_isolation ON tenancy_connector_secret_envelopes
USING (identrail_rls_scope_matches(tenant_id, workspace_id))
WITH CHECK (identrail_rls_scope_matches(tenant_id, workspace_id));
