CREATE TABLE IF NOT EXISTS tenancy_organizations (
    tenant_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (LENGTH(TRIM(tenant_id)) > 0),
    CHECK (LENGTH(TRIM(display_name)) > 0),
    CHECK (LENGTH(TRIM(slug)) > 0)
);

CREATE TABLE IF NOT EXISTS tenancy_workspaces (
    tenant_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    display_name TEXT NOT NULL,
    slug TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, workspace_id),
    UNIQUE (tenant_id, slug),
    FOREIGN KEY (tenant_id) REFERENCES tenancy_organizations(tenant_id) ON DELETE CASCADE,
    CHECK (LENGTH(TRIM(workspace_id)) > 0),
    CHECK (LENGTH(TRIM(display_name)) > 0),
    CHECK (LENGTH(TRIM(slug)) > 0)
);

CREATE TABLE IF NOT EXISTS tenancy_workspace_members (
    tenant_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    member_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    email TEXT,
    role TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'invited',
    joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, workspace_id, member_id),
    UNIQUE (tenant_id, workspace_id, user_id),
    FOREIGN KEY (tenant_id, workspace_id) REFERENCES tenancy_workspaces(tenant_id, workspace_id) ON DELETE CASCADE,
    CHECK (LENGTH(TRIM(member_id)) > 0),
    CHECK (LENGTH(TRIM(user_id)) > 0),
    CHECK (role IN ('owner', 'admin', 'analyst', 'viewer')),
    CHECK (status IN ('invited', 'active', 'suspended', 'removed'))
);

CREATE TABLE IF NOT EXISTS tenancy_projects (
    tenant_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    name TEXT NOT NULL,
    slug TEXT NOT NULL,
    description TEXT,
    archived_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, workspace_id, project_id),
    UNIQUE (tenant_id, workspace_id, slug),
    FOREIGN KEY (tenant_id, workspace_id) REFERENCES tenancy_workspaces(tenant_id, workspace_id) ON DELETE CASCADE,
    CHECK (LENGTH(TRIM(project_id)) > 0),
    CHECK (LENGTH(TRIM(name)) > 0),
    CHECK (LENGTH(TRIM(slug)) > 0)
);

CREATE INDEX IF NOT EXISTS idx_tenancy_workspaces_scope_created
    ON tenancy_workspaces (tenant_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_tenancy_members_scope_role_status
    ON tenancy_workspace_members (tenant_id, workspace_id, role, status);

CREATE INDEX IF NOT EXISTS idx_tenancy_members_scope_joined
    ON tenancy_workspace_members (tenant_id, workspace_id, joined_at);

CREATE INDEX IF NOT EXISTS idx_tenancy_projects_scope_created
    ON tenancy_projects (tenant_id, workspace_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_tenancy_projects_scope_archived
    ON tenancy_projects (tenant_id, workspace_id, archived_at);
