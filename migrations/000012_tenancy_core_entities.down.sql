DROP INDEX IF EXISTS idx_tenancy_projects_scope_archived;
DROP INDEX IF EXISTS idx_tenancy_projects_scope_created;
DROP INDEX IF EXISTS idx_tenancy_members_scope_joined;
DROP INDEX IF EXISTS idx_tenancy_members_scope_role_status;
DROP INDEX IF EXISTS idx_tenancy_workspaces_scope_created;

DROP TABLE IF EXISTS tenancy_projects;
DROP TABLE IF EXISTS tenancy_workspace_members;
DROP TABLE IF EXISTS tenancy_workspaces;
DROP TABLE IF EXISTS tenancy_organizations;
