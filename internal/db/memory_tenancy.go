package db

import (
	"context"
	"sort"
	"strconv"
	"strings"

	"github.com/identrail/identrail/internal/audit"
	"github.com/identrail/identrail/internal/domain"
)

// UpsertOrganization persists or updates one tenant organization record.
func (m *MemoryStore) UpsertOrganization(ctx context.Context, organization TenancyOrganization) error {
	m.mu.Lock()

	scope, err := RequireScope(ctx)
	if err != nil {
		m.mu.Unlock()
		return err
	}
	organization.TenantID = scope.TenantID
	normalized, err := NormalizeTenancyOrganizationForWrite(organization)
	if err != nil {
		m.mu.Unlock()
		return err
	}
	m.organizations[normalized.TenantID] = normalized
	m.mu.Unlock()

	audit.WriteAction(ctx, audit.AuditEvent{
		Action:       "tenancy.organization.upsert",
		TenantID:     normalized.TenantID,
		ResourceType: "tenancy_organization",
		ResourceID:   normalized.TenantID,
		Outcome:      "success",
	})
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

	scope, err := RequireScope(ctx)
	if err != nil {
		m.mu.Unlock()
		return err
	}
	if _, exists := m.organizations[scope.TenantID]; !exists {
		m.mu.Unlock()
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
	for key, connector := range m.connectors {
		if connector.TenantID == scope.TenantID {
			delete(m.connectors, key)
			delete(m.connStates, key)
		}
	}
	for secretKey, secret := range m.connSecrets {
		if secret.TenantID == scope.TenantID {
			delete(m.connSecrets, secretKey)
		}
	}
	m.mu.Unlock()

	audit.WriteAction(ctx, audit.AuditEvent{
		Action:       "tenancy.organization.delete",
		TenantID:     scope.TenantID,
		ResourceType: "tenancy_organization",
		ResourceID:   scope.TenantID,
		Outcome:      "success",
	})
	return nil
}

// UpsertWorkspace persists or updates one scoped workspace record.
func (m *MemoryStore) UpsertWorkspace(ctx context.Context, workspace TenancyWorkspace) error {
	m.mu.Lock()

	scope, err := RequireScope(ctx)
	if err != nil {
		m.mu.Unlock()
		return err
	}
	workspace.TenantID = scope.TenantID
	resolvedWorkspaceID, err := ResolveScopedWorkspaceID(scope, workspace.WorkspaceID)
	if err != nil {
		m.mu.Unlock()
		return err
	}
	workspace.WorkspaceID = resolvedWorkspaceID
	normalized, err := NormalizeTenancyWorkspaceForWrite(workspace)
	if err != nil {
		m.mu.Unlock()
		return err
	}
	if _, exists := m.organizations[normalized.TenantID]; !exists {
		m.mu.Unlock()
		return ErrNotFound
	}
	m.workspaces[tenancyWorkspaceKey(normalized.TenantID, normalized.WorkspaceID)] = normalized
	m.mu.Unlock()

	audit.WriteAction(ctx, audit.AuditEvent{
		Action:       "tenancy.workspace.upsert",
		TenantID:     normalized.TenantID,
		WorkspaceID:  normalized.WorkspaceID,
		ResourceType: "tenancy_workspace",
		ResourceID:   normalized.WorkspaceID,
		Outcome:      "success",
	})
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
	resolvedWorkspaceID, err := ResolveScopedWorkspaceID(scope, workspaceID)
	if err != nil {
		return TenancyWorkspace{}, err
	}
	key := tenancyWorkspaceKey(scope.TenantID, resolvedWorkspaceID)
	workspace, exists := m.workspaces[key]
	if !exists {
		return TenancyWorkspace{}, ErrNotFound
	}
	return workspace, nil
}

// ListWorkspaces returns tenant-scoped workspaces ordered by created_at descending.
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

	scope, err := RequireScope(ctx)
	if err != nil {
		m.mu.Unlock()
		return err
	}
	normalizedWorkspaceID, err := ResolveScopedWorkspaceID(scope, workspaceID)
	if err != nil {
		m.mu.Unlock()
		return err
	}
	key := tenancyWorkspaceKey(scope.TenantID, normalizedWorkspaceID)
	if _, exists := m.workspaces[key]; !exists {
		m.mu.Unlock()
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
	for connectorKey, connector := range m.connectors {
		if connector.TenantID == scope.TenantID && connector.WorkspaceID == normalizedWorkspaceID {
			delete(m.connectors, connectorKey)
			delete(m.connStates, connectorKey)
		}
	}
	for secretKey, secret := range m.connSecrets {
		if secret.TenantID == scope.TenantID && secret.WorkspaceID == normalizedWorkspaceID {
			delete(m.connSecrets, secretKey)
		}
	}
	m.mu.Unlock()

	audit.WriteAction(ctx, audit.AuditEvent{
		Action:       "tenancy.workspace.delete",
		TenantID:     scope.TenantID,
		WorkspaceID:  normalizedWorkspaceID,
		ResourceType: "tenancy_workspace",
		ResourceID:   normalizedWorkspaceID,
		Outcome:      "success",
	})
	return nil
}

// UpsertWorkspaceMember persists one workspace member assignment.
func (m *MemoryStore) UpsertWorkspaceMember(ctx context.Context, member TenancyWorkspaceMember) error {
	m.mu.Lock()

	scope, err := RequireScope(ctx)
	if err != nil {
		m.mu.Unlock()
		return err
	}
	member.TenantID = scope.TenantID
	resolvedWorkspaceID, err := ResolveScopedWorkspaceID(scope, member.WorkspaceID)
	if err != nil {
		m.mu.Unlock()
		return err
	}
	member.WorkspaceID = resolvedWorkspaceID
	normalized, err := NormalizeTenancyWorkspaceMemberForWrite(member)
	if err != nil {
		m.mu.Unlock()
		return err
	}
	if _, exists := m.workspaces[tenancyWorkspaceKey(normalized.TenantID, normalized.WorkspaceID)]; !exists {
		m.mu.Unlock()
		return ErrNotFound
	}
	m.members[tenancyMemberKey(normalized.TenantID, normalized.WorkspaceID, normalized.MemberID)] = normalized
	m.mu.Unlock()

	audit.WriteAction(ctx, audit.AuditEvent{
		Action:       "tenancy.workspace_member.upsert",
		TenantID:     normalized.TenantID,
		WorkspaceID:  normalized.WorkspaceID,
		ResourceType: "tenancy_workspace_member",
		ResourceID:   normalized.MemberID,
		Outcome:      "success",
	})
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
	resolvedWorkspaceID, err := ResolveScopedWorkspaceID(scope, workspaceID)
	if err != nil {
		return TenancyWorkspaceMember{}, err
	}
	member, exists := m.members[tenancyMemberKey(scope.TenantID, resolvedWorkspaceID, memberID)]
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
	normalizedWorkspaceID, err := ResolveScopedWorkspaceID(scope, workspaceID)
	if err != nil {
		return nil, err
	}
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

	scope, err := RequireScope(ctx)
	if err != nil {
		m.mu.Unlock()
		return err
	}
	resolvedWorkspaceID, err := ResolveScopedWorkspaceID(scope, workspaceID)
	if err != nil {
		m.mu.Unlock()
		return err
	}
	key := tenancyMemberKey(scope.TenantID, resolvedWorkspaceID, memberID)
	if _, exists := m.members[key]; !exists {
		m.mu.Unlock()
		return ErrNotFound
	}
	delete(m.members, key)
	m.mu.Unlock()

	audit.WriteAction(ctx, audit.AuditEvent{
		Action:       "tenancy.workspace_member.delete",
		TenantID:     scope.TenantID,
		WorkspaceID:  resolvedWorkspaceID,
		ResourceType: "tenancy_workspace_member",
		ResourceID:   memberID,
		Outcome:      "success",
	})
	return nil
}

// UpsertProject persists one scoped project record.
func (m *MemoryStore) UpsertProject(ctx context.Context, project TenancyProject) error {
	m.mu.Lock()

	scope, err := RequireScope(ctx)
	if err != nil {
		m.mu.Unlock()
		return err
	}
	project.TenantID = scope.TenantID
	resolvedWorkspaceID, err := ResolveScopedWorkspaceID(scope, project.WorkspaceID)
	if err != nil {
		m.mu.Unlock()
		return err
	}
	project.WorkspaceID = resolvedWorkspaceID
	normalized, err := NormalizeTenancyProjectForWrite(project)
	if err != nil {
		m.mu.Unlock()
		return err
	}
	if _, exists := m.workspaces[tenancyWorkspaceKey(normalized.TenantID, normalized.WorkspaceID)]; !exists {
		m.mu.Unlock()
		return ErrNotFound
	}
	m.projects[tenancyProjectKey(normalized.TenantID, normalized.WorkspaceID, normalized.ProjectID)] = normalized
	m.mu.Unlock()

	audit.WriteAction(ctx, audit.AuditEvent{
		Action:       "tenancy.project.upsert",
		TenantID:     normalized.TenantID,
		WorkspaceID:  normalized.WorkspaceID,
		ResourceType: "tenancy_project",
		ResourceID:   normalized.ProjectID,
		Outcome:      "success",
	})
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
	resolvedWorkspaceID, err := ResolveScopedWorkspaceID(scope, workspaceID)
	if err != nil {
		return TenancyProject{}, err
	}
	project, exists := m.projects[tenancyProjectKey(scope.TenantID, resolvedWorkspaceID, projectID)]
	if !exists {
		return TenancyProject{}, ErrNotFound
	}
	if project.ArchivedAt != nil {
		archived := project.ArchivedAt.UTC()
		project.ArchivedAt = &archived
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
	normalizedWorkspaceID, err := ResolveScopedWorkspaceID(scope, workspaceID)
	if err != nil {
		return nil, err
	}
	projects := make([]TenancyProject, 0, limit)
	for _, project := range m.projects {
		if project.TenantID != scope.TenantID || project.WorkspaceID != normalizedWorkspaceID {
			continue
		}
		if !includeArchived && project.ArchivedAt != nil {
			continue
		}
		if project.ArchivedAt != nil {
			archived := project.ArchivedAt.UTC()
			project.ArchivedAt = &archived
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

	scope, err := RequireScope(ctx)
	if err != nil {
		m.mu.Unlock()
		return err
	}
	resolvedWorkspaceID, err := ResolveScopedWorkspaceID(scope, workspaceID)
	if err != nil {
		m.mu.Unlock()
		return err
	}
	key := tenancyProjectKey(scope.TenantID, resolvedWorkspaceID, projectID)
	if _, exists := m.projects[key]; !exists {
		m.mu.Unlock()
		return ErrNotFound
	}
	delete(m.projects, key)
	for connectorKey, connector := range m.connectors {
		if connector.TenantID == scope.TenantID && connector.WorkspaceID == resolvedWorkspaceID && connector.ProjectID == projectID {
			delete(m.connectors, connectorKey)
			delete(m.connStates, connectorKey)
		}
	}
	for secretKey, secret := range m.connSecrets {
		if secret.TenantID == scope.TenantID && secret.WorkspaceID == resolvedWorkspaceID && secret.ProjectID == projectID {
			delete(m.connSecrets, secretKey)
		}
	}
	m.mu.Unlock()

	audit.WriteAction(ctx, audit.AuditEvent{
		Action:       "tenancy.project.delete",
		TenantID:     scope.TenantID,
		WorkspaceID:  resolvedWorkspaceID,
		ResourceType: "tenancy_project",
		ResourceID:   projectID,
		Outcome:      "success",
	})
	return nil
}

func tenancyWorkspaceKey(tenantID string, workspaceID string) string {
	return tenancyCompositeKey(strings.TrimSpace(tenantID), strings.TrimSpace(workspaceID))
}

func tenancyMemberKey(tenantID string, workspaceID string, memberID string) string {
	return tenancyCompositeKey(strings.TrimSpace(tenantID), strings.TrimSpace(workspaceID), strings.TrimSpace(memberID))
}

func tenancyProjectKey(tenantID string, workspaceID string, projectID string) string {
	return tenancyCompositeKey(strings.TrimSpace(tenantID), strings.TrimSpace(workspaceID), strings.TrimSpace(projectID))
}

// UpsertTenancyConnector persists one connector and its latest state atomically.
func (m *MemoryStore) UpsertTenancyConnector(ctx context.Context, connector TenancyConnector, state TenancyConnectorState) error {
	m.mu.Lock()

	scope, err := RequireScope(ctx)
	if err != nil {
		m.mu.Unlock()
		return err
	}
	connector.TenantID = scope.TenantID
	resolvedWorkspaceID, err := ResolveScopedWorkspaceID(scope, connector.WorkspaceID)
	if err != nil {
		m.mu.Unlock()
		return err
	}
	connector.WorkspaceID = resolvedWorkspaceID
	state.TenantID = scope.TenantID
	state.WorkspaceID = resolvedWorkspaceID
	state.ProjectID = connector.ProjectID
	state.ConnectorID = connector.ConnectorID
	createdAtWasZero := connector.CreatedAt.IsZero()
	normalizedConnector, err := NormalizeTenancyConnectorForWrite(connector)
	if err != nil {
		m.mu.Unlock()
		return err
	}
	normalizedState, err := NormalizeTenancyConnectorStateForWrite(state)
	if err != nil {
		m.mu.Unlock()
		return err
	}
	if _, exists := m.projects[tenancyProjectKey(normalizedConnector.TenantID, normalizedConnector.WorkspaceID, normalizedConnector.ProjectID)]; !exists {
		m.mu.Unlock()
		return ErrNotFound
	}
	key := tenancyConnectorKey(normalizedConnector.TenantID, normalizedConnector.WorkspaceID, normalizedConnector.ProjectID, normalizedConnector.ConnectorID)
	if existing, exists := m.connectors[key]; exists && createdAtWasZero {
		normalizedConnector.CreatedAt = existing.CreatedAt
	}
	m.connectors[key] = normalizedConnector
	m.connStates[key] = normalizedState
	m.mu.Unlock()

	audit.WriteAction(ctx, audit.AuditEvent{
		Action:       "tenancy.connector.upsert",
		TenantID:     normalizedConnector.TenantID,
		WorkspaceID:  normalizedConnector.WorkspaceID,
		ResourceType: "tenancy_connector",
		ResourceID:   normalizedConnector.ConnectorID,
		Outcome:      "success",
	})
	return nil
}

// GetTenancyConnector returns one connector and its latest state.
func (m *MemoryStore) GetTenancyConnector(ctx context.Context, workspaceID string, projectID string, connectorID string) (TenancyConnectorWithState, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return TenancyConnectorWithState{}, err
	}
	resolvedWorkspaceID, err := ResolveScopedWorkspaceID(scope, workspaceID)
	if err != nil {
		return TenancyConnectorWithState{}, err
	}
	key := tenancyConnectorKey(scope.TenantID, resolvedWorkspaceID, strings.TrimSpace(projectID), strings.TrimSpace(connectorID))
	connector, exists := m.connectors[key]
	if !exists {
		return TenancyConnectorWithState{}, ErrNotFound
	}
	state := m.connStates[key]
	state.Metadata = cloneMetadataMap(state.Metadata)
	return TenancyConnectorWithState{Connector: connector, State: state}, nil
}

// ListTenancyConnectors returns scoped connectors ordered by most recent update.
func (m *MemoryStore) ListTenancyConnectors(ctx context.Context, workspaceID string, projectID string, connectorType domain.ConnectorType, limit int) ([]TenancyConnectorWithState, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return nil, err
	}
	resolvedWorkspaceID, err := ResolveScopedWorkspaceID(scope, workspaceID)
	if err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 100
	}
	normalizedProjectID := strings.TrimSpace(projectID)
	normalizedType := domain.ConnectorType(strings.ToLower(strings.TrimSpace(string(connectorType))))
	connectors := make([]TenancyConnectorWithState, 0, limit)
	for key, connector := range m.connectors {
		if connector.TenantID != scope.TenantID || connector.WorkspaceID != resolvedWorkspaceID {
			continue
		}
		if normalizedProjectID != "" && connector.ProjectID != normalizedProjectID {
			continue
		}
		if normalizedType != "" && connector.Type != normalizedType {
			continue
		}
		state := m.connStates[key]
		state.Metadata = cloneMetadataMap(state.Metadata)
		connectors = append(connectors, TenancyConnectorWithState{Connector: connector, State: state})
	}
	sort.Slice(connectors, func(i, j int) bool {
		return connectors[i].Connector.UpdatedAt.After(connectors[j].Connector.UpdatedAt)
	})
	if len(connectors) > limit {
		connectors = connectors[:limit]
	}
	return connectors, nil
}

// ListTenancyConnectorsUnscoped returns connectors across all scopes for internal webhook dispatch.
func (m *MemoryStore) ListTenancyConnectorsUnscoped(_ context.Context, connectorType domain.ConnectorType, limit int) ([]TenancyConnectorWithState, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	normalizedType := domain.ConnectorType(strings.ToLower(strings.TrimSpace(string(connectorType))))
	capacity := len(m.connectors)
	if limit > 0 && limit < capacity {
		capacity = limit
	}
	connectors := make([]TenancyConnectorWithState, 0, capacity)
	for key, connector := range m.connectors {
		if normalizedType != "" && connector.Type != normalizedType {
			continue
		}
		state := m.connStates[key]
		state.Metadata = cloneMetadataMap(state.Metadata)
		connectors = append(connectors, TenancyConnectorWithState{Connector: connector, State: state})
	}
	sort.Slice(connectors, func(i, j int) bool {
		return connectors[i].Connector.UpdatedAt.After(connectors[j].Connector.UpdatedAt)
	})
	if limit > 0 && len(connectors) > limit {
		connectors = connectors[:limit]
	}
	return connectors, nil
}

// ListAllTenancyConnectorsByType returns connectors across all scopes for internal runtime matching.
func (m *MemoryStore) ListAllTenancyConnectorsByType(ctx context.Context, connectorType domain.ConnectorType, limit int) ([]TenancyConnectorWithState, error) {
	return m.ListTenancyConnectorsUnscoped(ctx, connectorType, limit)
}

// UpsertTenancyConnectorSecretEnvelope persists one encrypted connector secret envelope.
func (m *MemoryStore) UpsertTenancyConnectorSecretEnvelope(ctx context.Context, envelope TenancyConnectorSecretEnvelope) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return err
	}
	envelope.TenantID = scope.TenantID
	resolvedWorkspaceID, err := ResolveScopedWorkspaceID(scope, envelope.WorkspaceID)
	if err != nil {
		return err
	}
	envelope.WorkspaceID = resolvedWorkspaceID
	normalized, err := NormalizeTenancyConnectorSecretEnvelopeForWrite(envelope)
	if err != nil {
		return err
	}
	connectorKey := tenancyConnectorKey(
		normalized.TenantID,
		normalized.WorkspaceID,
		normalized.ProjectID,
		normalized.ConnectorID,
	)
	if _, exists := m.connectors[connectorKey]; !exists {
		return ErrNotFound
	}
	secretKey := tenancyConnectorSecretKey(
		normalized.TenantID,
		normalized.WorkspaceID,
		normalized.ProjectID,
		normalized.ConnectorID,
		normalized.SecretName,
	)
	if existing, exists := m.connSecrets[secretKey]; exists {
		normalized.CreatedAt = existing.CreatedAt
	}
	m.connSecrets[secretKey] = normalized
	return nil
}

// GetTenancyConnectorSecretEnvelope loads one encrypted connector secret envelope.
func (m *MemoryStore) GetTenancyConnectorSecretEnvelope(ctx context.Context, workspaceID string, projectID string, connectorID string, secretName string) (TenancyConnectorSecretEnvelope, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return TenancyConnectorSecretEnvelope{}, err
	}
	resolvedWorkspaceID, err := ResolveScopedWorkspaceID(scope, workspaceID)
	if err != nil {
		return TenancyConnectorSecretEnvelope{}, err
	}
	key := tenancyConnectorSecretKey(scope.TenantID, resolvedWorkspaceID, strings.TrimSpace(projectID), strings.TrimSpace(connectorID), strings.TrimSpace(secretName))
	secret, exists := m.connSecrets[key]
	if !exists {
		return TenancyConnectorSecretEnvelope{}, ErrNotFound
	}
	secret.Envelope.Nonce = append([]byte(nil), secret.Envelope.Nonce...)
	secret.Envelope.Ciphertext = append([]byte(nil), secret.Envelope.Ciphertext...)
	return secret, nil
}

func tenancyConnectorKey(tenantID string, workspaceID string, projectID string, connectorID string) string {
	return tenancyCompositeKey(
		strings.TrimSpace(tenantID),
		strings.TrimSpace(workspaceID),
		strings.TrimSpace(projectID),
		strings.TrimSpace(connectorID),
	)
}

func tenancyConnectorSecretKey(tenantID string, workspaceID string, projectID string, connectorID string, secretName string) string {
	return tenancyCompositeKey(
		strings.TrimSpace(tenantID),
		strings.TrimSpace(workspaceID),
		strings.TrimSpace(projectID),
		strings.TrimSpace(connectorID),
		strings.TrimSpace(secretName),
	)
}

func tenancyCompositeKey(parts ...string) string {
	var builder strings.Builder
	for _, part := range parts {
		builder.WriteString(strconv.Itoa(len(part)))
		builder.WriteByte(':')
		builder.WriteString(part)
		builder.WriteByte('|')
	}
	return builder.String()
}
