package db

import (
	"context"
	"sort"
	"strings"
)

// UpsertOrganization persists or updates one tenant organization record.
func (m *MemoryStore) UpsertOrganization(ctx context.Context, organization TenancyOrganization) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return err
	}
	organization.TenantID = scope.TenantID
	normalized, err := NormalizeTenancyOrganizationForWrite(organization)
	if err != nil {
		return err
	}
	m.organizations[normalized.TenantID] = normalized
	return nil
}

// GetOrganization returns the active scoped tenant organization.
func (m *MemoryStore) GetOrganization(ctx context.Context) (TenancyOrganization, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return TenancyOrganization{}, err
	}
	organization, exists := m.organizations[scope.TenantID]
	if !exists {
		return TenancyOrganization{}, ErrNotFound
	}
	return organization, nil
}

// DeleteOrganization removes the active scoped tenant organization record.
func (m *MemoryStore) DeleteOrganization(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return err
	}
	if _, exists := m.organizations[scope.TenantID]; !exists {
		return ErrNotFound
	}
	delete(m.organizations, scope.TenantID)
	for key, workspace := range m.workspaces {
		if workspace.TenantID == scope.TenantID {
			delete(m.workspaces, key)
		}
	}
	for key, member := range m.members {
		if member.TenantID == scope.TenantID {
			delete(m.members, key)
		}
	}
	for key, project := range m.projects {
		if project.TenantID == scope.TenantID {
			delete(m.projects, key)
		}
	}
	return nil
}

// UpsertWorkspace persists or updates one scoped workspace record.
func (m *MemoryStore) UpsertWorkspace(ctx context.Context, workspace TenancyWorkspace) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return err
	}
	workspace.TenantID = scope.TenantID
	if workspace.WorkspaceID == "" {
		workspace.WorkspaceID = scope.WorkspaceID
	}
	normalized, err := NormalizeTenancyWorkspaceForWrite(workspace)
	if err != nil {
		return err
	}
	if _, exists := m.organizations[normalized.TenantID]; !exists {
		return ErrNotFound
	}
	m.workspaces[tenancyWorkspaceKey(normalized.TenantID, normalized.WorkspaceID)] = normalized
	return nil
}

// GetWorkspace returns one workspace by id in active tenant scope.
func (m *MemoryStore) GetWorkspace(ctx context.Context, workspaceID string) (TenancyWorkspace, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return TenancyWorkspace{}, err
	}
	key := tenancyWorkspaceKey(scope.TenantID, workspaceID)
	workspace, exists := m.workspaces[key]
	if !exists {
		return TenancyWorkspace{}, ErrNotFound
	}
	return workspace, nil
}

// ListWorkspaces returns scoped workspaces ordered by created_at descending.
func (m *MemoryStore) ListWorkspaces(ctx context.Context, limit int) ([]TenancyWorkspace, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 20
	}
	workspaces := make([]TenancyWorkspace, 0, limit)
	for _, workspace := range m.workspaces {
		if workspace.TenantID != scope.TenantID {
			continue
		}
		workspaces = append(workspaces, workspace)
	}
	sort.Slice(workspaces, func(i, j int) bool { return workspaces[i].CreatedAt.After(workspaces[j].CreatedAt) })
	if len(workspaces) > limit {
		workspaces = workspaces[:limit]
	}
	return workspaces, nil
}

// DeleteWorkspace removes one scoped workspace and all child records.
func (m *MemoryStore) DeleteWorkspace(ctx context.Context, workspaceID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return err
	}
	normalizedWorkspaceID := strings.TrimSpace(workspaceID)
	key := tenancyWorkspaceKey(scope.TenantID, normalizedWorkspaceID)
	if _, exists := m.workspaces[key]; !exists {
		return ErrNotFound
	}
	delete(m.workspaces, key)
	for memberKey, member := range m.members {
		if member.TenantID == scope.TenantID && member.WorkspaceID == normalizedWorkspaceID {
			delete(m.members, memberKey)
		}
	}
	for projectKey, project := range m.projects {
		if project.TenantID == scope.TenantID && project.WorkspaceID == normalizedWorkspaceID {
			delete(m.projects, projectKey)
		}
	}
	return nil
}

// UpsertWorkspaceMember persists one workspace member assignment.
func (m *MemoryStore) UpsertWorkspaceMember(ctx context.Context, member TenancyWorkspaceMember) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return err
	}
	member.TenantID = scope.TenantID
	if member.WorkspaceID == "" {
		member.WorkspaceID = scope.WorkspaceID
	}
	normalized, err := NormalizeTenancyWorkspaceMemberForWrite(member)
	if err != nil {
		return err
	}
	if _, exists := m.workspaces[tenancyWorkspaceKey(normalized.TenantID, normalized.WorkspaceID)]; !exists {
		return ErrNotFound
	}
	m.members[tenancyMemberKey(normalized.TenantID, normalized.WorkspaceID, normalized.MemberID)] = normalized
	return nil
}

// GetWorkspaceMember returns one scoped workspace member by member id.
func (m *MemoryStore) GetWorkspaceMember(ctx context.Context, workspaceID string, memberID string) (TenancyWorkspaceMember, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return TenancyWorkspaceMember{}, err
	}
	member, exists := m.members[tenancyMemberKey(scope.TenantID, workspaceID, memberID)]
	if !exists {
		return TenancyWorkspaceMember{}, ErrNotFound
	}
	return member, nil
}

// ListWorkspaceMembers returns members for one scoped workspace.
func (m *MemoryStore) ListWorkspaceMembers(ctx context.Context, workspaceID string, limit int) ([]TenancyWorkspaceMember, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 100
	}
	normalizedWorkspaceID := strings.TrimSpace(workspaceID)
	members := make([]TenancyWorkspaceMember, 0, limit)
	for _, member := range m.members {
		if member.TenantID != scope.TenantID || member.WorkspaceID != normalizedWorkspaceID {
			continue
		}
		members = append(members, member)
	}
	sort.Slice(members, func(i, j int) bool { return members[i].JoinedAt.Before(members[j].JoinedAt) })
	if len(members) > limit {
		members = members[:limit]
	}
	return members, nil
}

// DeleteWorkspaceMember removes one scoped workspace member.
func (m *MemoryStore) DeleteWorkspaceMember(ctx context.Context, workspaceID string, memberID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return err
	}
	key := tenancyMemberKey(scope.TenantID, workspaceID, memberID)
	if _, exists := m.members[key]; !exists {
		return ErrNotFound
	}
	delete(m.members, key)
	return nil
}

// UpsertProject persists one scoped project record.
func (m *MemoryStore) UpsertProject(ctx context.Context, project TenancyProject) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return err
	}
	project.TenantID = scope.TenantID
	if project.WorkspaceID == "" {
		project.WorkspaceID = scope.WorkspaceID
	}
	normalized, err := NormalizeTenancyProjectForWrite(project)
	if err != nil {
		return err
	}
	if _, exists := m.workspaces[tenancyWorkspaceKey(normalized.TenantID, normalized.WorkspaceID)]; !exists {
		return ErrNotFound
	}
	m.projects[tenancyProjectKey(normalized.TenantID, normalized.WorkspaceID, normalized.ProjectID)] = normalized
	return nil
}

// GetProject returns one scoped project by id.
func (m *MemoryStore) GetProject(ctx context.Context, workspaceID string, projectID string) (TenancyProject, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return TenancyProject{}, err
	}
	project, exists := m.projects[tenancyProjectKey(scope.TenantID, workspaceID, projectID)]
	if !exists {
		return TenancyProject{}, ErrNotFound
	}
	return project, nil
}

// ListProjects returns projects for one scoped workspace.
func (m *MemoryStore) ListProjects(ctx context.Context, workspaceID string, includeArchived bool, limit int) ([]TenancyProject, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 100
	}
	normalizedWorkspaceID := strings.TrimSpace(workspaceID)
	projects := make([]TenancyProject, 0, limit)
	for _, project := range m.projects {
		if project.TenantID != scope.TenantID || project.WorkspaceID != normalizedWorkspaceID {
			continue
		}
		if !includeArchived && project.ArchivedAt != nil {
			continue
		}
		projects = append(projects, project)
	}
	sort.Slice(projects, func(i, j int) bool { return projects[i].CreatedAt.After(projects[j].CreatedAt) })
	if len(projects) > limit {
		projects = projects[:limit]
	}
	return projects, nil
}

// DeleteProject removes one scoped project.
func (m *MemoryStore) DeleteProject(ctx context.Context, workspaceID string, projectID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return err
	}
	key := tenancyProjectKey(scope.TenantID, workspaceID, projectID)
	if _, exists := m.projects[key]; !exists {
		return ErrNotFound
	}
	delete(m.projects, key)
	return nil
}

func tenancyWorkspaceKey(tenantID string, workspaceID string) string {
	return strings.TrimSpace(tenantID) + "|" + strings.TrimSpace(workspaceID)
}

func tenancyMemberKey(tenantID string, workspaceID string, memberID string) string {
	return tenancyWorkspaceKey(tenantID, workspaceID) + "|" + strings.TrimSpace(memberID)
}

func tenancyProjectKey(tenantID string, workspaceID string, projectID string) string {
	return tenancyWorkspaceKey(tenantID, workspaceID) + "|" + strings.TrimSpace(projectID)
}
