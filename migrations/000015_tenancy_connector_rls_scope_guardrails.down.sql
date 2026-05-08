DROP POLICY IF EXISTS tenancy_connector_secret_envelopes_scope_isolation ON tenancy_connector_secret_envelopes;
ALTER TABLE tenancy_connector_secret_envelopes NO FORCE ROW LEVEL SECURITY;
ALTER TABLE tenancy_connector_secret_envelopes DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenancy_scan_policies_scope_isolation ON tenancy_scan_policies;
ALTER TABLE tenancy_scan_policies NO FORCE ROW LEVEL SECURITY;
ALTER TABLE tenancy_scan_policies DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenancy_connector_states_scope_isolation ON tenancy_connector_states;
ALTER TABLE tenancy_connector_states NO FORCE ROW LEVEL SECURITY;
ALTER TABLE tenancy_connector_states DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenancy_connectors_scope_isolation ON tenancy_connectors;
ALTER TABLE tenancy_connectors NO FORCE ROW LEVEL SECURITY;
ALTER TABLE tenancy_connectors DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenancy_projects_scope_isolation ON tenancy_projects;
ALTER TABLE tenancy_projects NO FORCE ROW LEVEL SECURITY;
ALTER TABLE tenancy_projects DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenancy_workspace_members_scope_isolation ON tenancy_workspace_members;
ALTER TABLE tenancy_workspace_members NO FORCE ROW LEVEL SECURITY;
ALTER TABLE tenancy_workspace_members DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenancy_workspaces_scope_isolation ON tenancy_workspaces;
ALTER TABLE tenancy_workspaces NO FORCE ROW LEVEL SECURITY;
ALTER TABLE tenancy_workspaces DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenancy_organizations_scope_isolation ON tenancy_organizations;
ALTER TABLE tenancy_organizations NO FORCE ROW LEVEL SECURITY;
ALTER TABLE tenancy_organizations DISABLE ROW LEVEL SECURITY;

DROP FUNCTION IF EXISTS identrail_rls_tenant_matches(TEXT);
