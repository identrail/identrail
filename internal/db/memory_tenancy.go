package db

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

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
	for key, policy := range m.scanPolicies {
		if policy.TenantID == scope.TenantID {
			delete(m.scanPolicies, key)
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
	for coverageKey, coverage := range m.awsCoverages {
		if coverage.TenantID == scope.TenantID {
			delete(m.awsCoverages, coverageKey)
		}
	}
	m.deleteAWSPlatformBaselineResultsLocked(scope.TenantID, "", "")
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
	// Preserve lifecycle fields on upsert so a casual rename of an existing
	// workspace cannot revive a deleted or suspended row. Lifecycle writes
	// go through the dedicated Suspend/Reactivate/SoftDelete/Cancel methods.
	key := tenancyWorkspaceKey(normalized.TenantID, normalized.WorkspaceID)
	if existing, exists := m.workspaces[key]; exists {
		normalized.Status = existing.Status
		normalized.SuspendedAt = existing.SuspendedAt
		normalized.DeletedAt = existing.DeletedAt
		normalized.CreatedAt = existing.CreatedAt
	}
	m.workspaces[key] = normalized
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

// SuspendWorkspace flips the workspace status to suspended and stamps
// suspended_at. Idempotent on an already-suspended workspace: the stored
// suspended_at is preserved.
func (m *MemoryStore) SuspendWorkspace(ctx context.Context, workspaceID string, now time.Time) (TenancyWorkspace, error) {
	m.mu.Lock()

	scope, err := RequireScope(ctx)
	if err != nil {
		m.mu.Unlock()
		return TenancyWorkspace{}, err
	}
	resolvedWorkspaceID, err := ResolveScopedWorkspaceID(scope, workspaceID)
	if err != nil {
		m.mu.Unlock()
		return TenancyWorkspace{}, err
	}
	key := tenancyWorkspaceKey(scope.TenantID, resolvedWorkspaceID)
	workspace, exists := m.workspaces[key]
	if !exists {
		m.mu.Unlock()
		return TenancyWorkspace{}, ErrNotFound
	}
	if workspace.Status == WorkspaceStatusDeleted || workspace.DeletedAt != nil {
		m.mu.Unlock()
		return TenancyWorkspace{}, ErrConflict
	}
	whenUTC := now.UTC()
	workspace.Status = WorkspaceStatusSuspended
	if workspace.SuspendedAt == nil {
		t := whenUTC
		workspace.SuspendedAt = &t
	}
	workspace.UpdatedAt = whenUTC
	m.workspaces[key] = workspace
	m.mu.Unlock()

	audit.WriteAction(ctx, audit.AuditEvent{
		Action:       "tenancy.workspace.suspend",
		TenantID:     scope.TenantID,
		WorkspaceID:  resolvedWorkspaceID,
		ResourceType: "tenancy_workspace",
		ResourceID:   resolvedWorkspaceID,
		Outcome:      "success",
	})
	return workspace, nil
}

// ReactivateWorkspace flips a suspended workspace back to active and clears
// suspended_at. Callers that want active-workspace idempotency should check
// before issuing the store transition.
func (m *MemoryStore) ReactivateWorkspace(ctx context.Context, workspaceID string, now time.Time) (TenancyWorkspace, error) {
	m.mu.Lock()

	scope, err := RequireScope(ctx)
	if err != nil {
		m.mu.Unlock()
		return TenancyWorkspace{}, err
	}
	resolvedWorkspaceID, err := ResolveScopedWorkspaceID(scope, workspaceID)
	if err != nil {
		m.mu.Unlock()
		return TenancyWorkspace{}, err
	}
	key := tenancyWorkspaceKey(scope.TenantID, resolvedWorkspaceID)
	workspace, exists := m.workspaces[key]
	if !exists {
		m.mu.Unlock()
		return TenancyWorkspace{}, ErrNotFound
	}
	if workspace.Status != WorkspaceStatusSuspended || workspace.DeletedAt != nil {
		m.mu.Unlock()
		return TenancyWorkspace{}, ErrConflict
	}
	whenUTC := now.UTC()
	workspace.Status = WorkspaceStatusActive
	workspace.SuspendedAt = nil
	workspace.UpdatedAt = whenUTC
	m.workspaces[key] = workspace
	m.mu.Unlock()

	audit.WriteAction(ctx, audit.AuditEvent{
		Action:       "tenancy.workspace.reactivate",
		TenantID:     scope.TenantID,
		WorkspaceID:  resolvedWorkspaceID,
		ResourceType: "tenancy_workspace",
		ResourceID:   resolvedWorkspaceID,
		Outcome:      "success",
	})
	return workspace, nil
}

// SoftDeleteWorkspace flips the workspace to status=deleted and stamps
// deleted_at to open the reversible grace window. Idempotent: an existing
// deleted_at is preserved so repeat calls cannot extend the grace deadline.
func (m *MemoryStore) SoftDeleteWorkspace(ctx context.Context, workspaceID string, now time.Time) (TenancyWorkspace, error) {
	m.mu.Lock()

	scope, err := RequireScope(ctx)
	if err != nil {
		m.mu.Unlock()
		return TenancyWorkspace{}, err
	}
	resolvedWorkspaceID, err := ResolveScopedWorkspaceID(scope, workspaceID)
	if err != nil {
		m.mu.Unlock()
		return TenancyWorkspace{}, err
	}
	key := tenancyWorkspaceKey(scope.TenantID, resolvedWorkspaceID)
	workspace, exists := m.workspaces[key]
	if !exists {
		m.mu.Unlock()
		return TenancyWorkspace{}, ErrNotFound
	}
	whenUTC := now.UTC()
	workspace.Status = WorkspaceStatusDeleted
	if workspace.DeletedAt == nil {
		t := whenUTC
		workspace.DeletedAt = &t
	}
	workspace.UpdatedAt = whenUTC
	m.workspaces[key] = workspace
	m.mu.Unlock()

	audit.WriteAction(ctx, audit.AuditEvent{
		Action:       "tenancy.workspace.delete",
		TenantID:     scope.TenantID,
		WorkspaceID:  resolvedWorkspaceID,
		ResourceType: "tenancy_workspace",
		ResourceID:   resolvedWorkspaceID,
		Outcome:      "success",
	})
	return workspace, nil
}

// CancelWorkspaceDeletion reverses a soft delete during the grace window:
// clears deleted_at and returns the workspace to status=active.
func (m *MemoryStore) CancelWorkspaceDeletion(ctx context.Context, workspaceID string, now time.Time) (TenancyWorkspace, error) {
	m.mu.Lock()

	scope, err := RequireScope(ctx)
	if err != nil {
		m.mu.Unlock()
		return TenancyWorkspace{}, err
	}
	resolvedWorkspaceID, err := ResolveScopedWorkspaceID(scope, workspaceID)
	if err != nil {
		m.mu.Unlock()
		return TenancyWorkspace{}, err
	}
	key := tenancyWorkspaceKey(scope.TenantID, resolvedWorkspaceID)
	workspace, exists := m.workspaces[key]
	if !exists {
		m.mu.Unlock()
		return TenancyWorkspace{}, ErrNotFound
	}
	whenUTC := now.UTC()
	workspace.Status = WorkspaceStatusActive
	workspace.DeletedAt = nil
	// Cancel-deletion restores to fully active — clear any stale
	// suspended_at too so the row does not surface as "active with
	// suspension metadata" in the UI after restoration.
	workspace.SuspendedAt = nil
	workspace.UpdatedAt = whenUTC
	m.workspaces[key] = workspace
	m.mu.Unlock()

	audit.WriteAction(ctx, audit.AuditEvent{
		Action:       "tenancy.workspace.delete.cancel",
		TenantID:     scope.TenantID,
		WorkspaceID:  resolvedWorkspaceID,
		ResourceType: "tenancy_workspace",
		ResourceID:   resolvedWorkspaceID,
		Outcome:      "success",
	})
	return workspace, nil
}

// ListWorkspaceStrandedActiveMembers returns the other active members in the
// workspace iff the caller is the sole active owner. Empty slice means no
// stranding would occur — either the caller has co-owners, or there are no
// other active members to strand.
func (m *MemoryStore) ListWorkspaceStrandedActiveMembers(ctx context.Context, workspaceID string, userUUID string) ([]TenancyWorkspaceMember, error) {
	normalizedUserUUID := strings.TrimSpace(userUUID)
	if normalizedUserUUID == "" {
		return []TenancyWorkspaceMember{}, nil
	}
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
	if _, exists := m.workspaces[tenancyWorkspaceKey(scope.TenantID, resolvedWorkspaceID)]; !exists {
		return nil, ErrNotFound
	}
	callerIsOwner := false
	otherLiveOwners := 0
	otherActive := make([]TenancyWorkspaceMember, 0)
	for _, member := range m.members {
		if member.TenantID != scope.TenantID || member.WorkspaceID != resolvedWorkspaceID {
			continue
		}
		if member.Status != "active" {
			continue
		}
		if member.UserUUID == normalizedUserUUID {
			if member.Role == "owner" {
				callerIsOwner = true
			}
			continue
		}
		if member.Role == "owner" {
			if owner, ok := m.users[member.UserUUID]; ok && owner.Status == "deleted" {
				continue
			}
			otherLiveOwners++
		}
		otherActive = append(otherActive, member)
	}
	if !callerIsOwner || otherLiveOwners > 0 || len(otherActive) == 0 {
		return []TenancyWorkspaceMember{}, nil
	}
	sort.Slice(otherActive, func(i, j int) bool { return otherActive[i].MemberID < otherActive[j].MemberID })
	return otherActive, nil
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
	for policyKey, policy := range m.scanPolicies {
		if policy.TenantID == scope.TenantID && policy.WorkspaceID == normalizedWorkspaceID {
			delete(m.scanPolicies, policyKey)
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
	for coverageKey, coverage := range m.awsCoverages {
		if coverage.TenantID == scope.TenantID && coverage.WorkspaceID == normalizedWorkspaceID {
			delete(m.awsCoverages, coverageKey)
		}
	}
	m.deleteAWSPlatformBaselineResultsLocked(scope.TenantID, normalizedWorkspaceID, "")
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

// ListWorkspacesPendingHardDelete returns soft-deleted workspaces whose
// grace window closed. Bypasses scope so the worker can enumerate across
// all tenants in a single pass. Results are stable-sorted by deleted_at
// then workspace_id to make worker progress deterministic.
func (m *MemoryStore) ListWorkspacesPendingHardDelete(ctx context.Context, deletedBefore time.Time, limit int) ([]TenancyWorkspace, error) {
	cutoff := deletedBefore.UTC()
	if limit <= 0 {
		limit = 100
	}
	m.mu.RLock()
	pending := make([]TenancyWorkspace, 0)
	for _, workspace := range m.workspaces {
		if workspace.Status != WorkspaceStatusDeleted || workspace.DeletedAt == nil {
			continue
		}
		if !workspace.DeletedAt.UTC().Before(cutoff) {
			continue
		}
		pending = append(pending, workspace)
	}
	m.mu.RUnlock()
	sort.Slice(pending, func(i, j int) bool {
		if pending[i].DeletedAt.Equal(*pending[j].DeletedAt) {
			return pending[i].WorkspaceID < pending[j].WorkspaceID
		}
		return pending[i].DeletedAt.Before(*pending[j].DeletedAt)
	})
	if len(pending) > limit {
		pending = pending[:limit]
	}
	return pending, nil
}

// HardDeleteWorkspace permanently removes a soft-deleted workspace and all
// of its child rows. Refuses the purge unless the workspace is genuinely
// past grace (status='deleted', deleted_at matches the value the worker
// observed when it listed the row) so:
//   - workspace_id alone is not globally unique; requiring tenant_id
//     locks the purge to the correct row.
//   - a cancel-deletion + re-delete race between the worker's list and
//     its purge call advances deleted_at to a fresh value; matching
//     against the listed deleted_at refuses that case and lets the new
//     30-day window run.
func (m *MemoryStore) HardDeleteWorkspace(ctx context.Context, tenantID, workspaceID string, expectedDeletedAt time.Time, now time.Time) (TenancyWorkspace, error) {
	tenant := strings.TrimSpace(tenantID)
	id := strings.TrimSpace(workspaceID)
	expected := expectedDeletedAt.UTC()
	when := now.UTC()
	m.mu.Lock()
	key := tenancyWorkspaceKey(tenant, id)
	workspace, exists := m.workspaces[key]
	if !exists {
		m.mu.Unlock()
		return TenancyWorkspace{}, ErrNotFound
	}
	if workspace.Status != WorkspaceStatusDeleted || workspace.DeletedAt == nil {
		m.mu.Unlock()
		return TenancyWorkspace{}, fmt.Errorf("hard delete: workspace %s/%s is not pending deletion (status=%q)", tenant, id, workspace.Status)
	}
	if !workspace.DeletedAt.UTC().Equal(expected) {
		m.mu.Unlock()
		return TenancyWorkspace{}, fmt.Errorf("hard delete: workspace %s/%s deleted_at drifted (worker saw %s, row now %s); the row was likely re-deleted within grace", tenant, id, expected, workspace.DeletedAt.UTC())
	}
	delete(m.workspaces, key)
	for memberKey, member := range m.members {
		if member.TenantID == tenant && member.WorkspaceID == id {
			delete(m.members, memberKey)
		}
	}
	for projectKey, project := range m.projects {
		if project.TenantID == tenant && project.WorkspaceID == id {
			delete(m.projects, projectKey)
		}
	}
	for policyKey, policy := range m.scanPolicies {
		if policy.TenantID == tenant && policy.WorkspaceID == id {
			delete(m.scanPolicies, policyKey)
		}
	}
	for connectorKey, connector := range m.connectors {
		if connector.TenantID == tenant && connector.WorkspaceID == id {
			delete(m.connectors, connectorKey)
			delete(m.connStates, connectorKey)
		}
	}
	for secretKey, secret := range m.connSecrets {
		if secret.TenantID == tenant && secret.WorkspaceID == id {
			delete(m.connSecrets, secretKey)
		}
	}
	for coverageKey, coverage := range m.awsCoverages {
		if coverage.TenantID == tenant && coverage.WorkspaceID == id {
			delete(m.awsCoverages, coverageKey)
		}
	}
	m.deleteAWSPlatformBaselineResultsLocked(tenant, id, "")
	// Collect scan + repo-scan IDs first so the second pass can drain
	// their child artifact maps. The postgres backend gets this "for
	// free" via FK ON DELETE CASCADE on scans/repo_scans; the memory
	// store has no such cascade so we must replicate it explicitly
	// (codex round-4 P2 on #1450). Without this the memory backend
	// retained workspace-scoped findings, raw assets, identities,
	// policies, relationships, permissions, scan events, and repo
	// findings after a hard delete — diverging from postgres and
	// leaking dev/test fixtures across purges.
	scanIDs := make([]string, 0)
	for scanID, record := range m.scans {
		if record.TenantID == tenant && record.WorkspaceID == id {
			scanIDs = append(scanIDs, scanID)
			delete(m.scans, scanID)
		}
	}
	repoScanIDs := make([]string, 0)
	for scanID, record := range m.repoScans {
		if record.TenantID == tenant && record.WorkspaceID == id {
			repoScanIDs = append(repoScanIDs, scanID)
			delete(m.repoScans, scanID)
		}
	}
	// Per-scan child artifacts. Each map uses a composite key whose
	// first `|`-separated segment is the scan id (see
	// UpsertScanArtifacts in memory.go), so a HasPrefix match drains
	// every entry tied to a purged scan id in one pass.
	for _, scanID := range scanIDs {
		prefix := scanID + "|"
		for key := range m.rawAssets {
			if strings.HasPrefix(key, prefix) {
				delete(m.rawAssets, key)
			}
		}
		for key := range m.identities {
			if strings.HasPrefix(key, prefix) {
				delete(m.identities, key)
			}
		}
		for key := range m.policies {
			if strings.HasPrefix(key, prefix) {
				delete(m.policies, key)
			}
		}
		for key := range m.relationships {
			if strings.HasPrefix(key, prefix) {
				delete(m.relationships, key)
			}
		}
		for key := range m.permissions {
			if strings.HasPrefix(key, prefix) {
				delete(m.permissions, key)
			}
		}
		// scanFindings indexes finding keys; drop those finding rows
		// first then the index entry.
		for _, findingKey := range m.scanFindings[scanID] {
			delete(m.findings, findingKey)
		}
		delete(m.scanFindings, scanID)
		delete(m.events, scanID)
	}
	for _, repoScanID := range repoScanIDs {
		for _, findingKey := range m.repoFindingIDs[repoScanID] {
			delete(m.repoFindings, findingKey)
		}
		delete(m.repoFindingIDs, repoScanID)
	}
	// repo_scan_cursors hold tenant/workspace-scoped incremental scan
	// state with no FK back to tenancy_workspaces; codex round-2 P2 on
	// #1450 flagged that leaving these rows behind violates the
	// "every workspace-scoped row is purged" contract.
	for cursorKey, cursor := range m.repoCursors {
		if cursor.TenantID == tenant && cursor.WorkspaceID == id {
			delete(m.repoCursors, cursorKey)
		}
	}
	// Authz + triage state lives in dedicated maps keyed by
	// scope-derived strings. Codex round-3 P2 on #1450 flagged that
	// the postgres path purges those tables but the memory store left
	// them behind — divergent behaviour between backends, and the
	// memory store's scoped API would continue returning rows for a
	// workspace that has just been hard-deleted. Iterate each map and
	// drop every entry whose TenantID/WorkspaceID matches.
	for key, attrs := range m.authzAttrs {
		if attrs.TenantID == tenant && attrs.WorkspaceID == id {
			delete(m.authzAttrs, key)
		}
	}
	for key, rel := range m.authzRels {
		if rel.TenantID == tenant && rel.WorkspaceID == id {
			delete(m.authzRels, key)
		}
	}
	for key, set := range m.authzSets {
		if set.TenantID == tenant && set.WorkspaceID == id {
			delete(m.authzSets, key)
		}
	}
	for key, version := range m.authzVersions {
		if version.TenantID == tenant && version.WorkspaceID == id {
			delete(m.authzVersions, key)
		}
	}
	for key, rollout := range m.authzRollouts {
		if rollout.TenantID == tenant && rollout.WorkspaceID == id {
			delete(m.authzRollouts, key)
		}
	}
	for key, events := range m.authzEvents {
		// authzEvents is map[string][]AuthzPolicyEvent — every event
		// in a single slot shares the same scope (the key is derived
		// from it), so checking the first entry is sufficient.
		if len(events) > 0 && events[0].TenantID == tenant && events[0].WorkspaceID == id {
			for _, event := range events {
				delete(m.authzEventIDs, event.ID)
			}
			delete(m.authzEvents, key)
		}
	}
	for sessionKey, session := range m.sessions {
		if session.CurrentOrgID == tenant && session.CurrentWorkspaceID == id {
			session.CurrentOrgID = ""
			session.CurrentWorkspaceID = ""
			session.CurrentProjectID = ""
			m.sessions[sessionKey] = session
		}
	}
	for userID, state := range m.onboardingStates {
		if state.OrgID == tenant && state.WorkspaceID == id {
			state.OrgID = ""
			state.WorkspaceID = ""
			state.ProjectID = ""
			m.onboardingStates[userID] = state
		}
	}
	// FindingTriageState/Event don't carry TenantID/WorkspaceID on
	// the value itself — the map key embeds the scope as
	// `tenant|workspace|finding_id` (see findingScopeKey). Prefix
	// match on the scope segments to purge every triage row tied to
	// the workspace.
	triagePrefix := tenant + "|" + id + "|"
	for key := range m.triageStates {
		if strings.HasPrefix(key, triagePrefix) {
			delete(m.triageStates, key)
		}
	}
	for key := range m.triageEvents {
		if strings.HasPrefix(key, triagePrefix) {
			delete(m.triageEvents, key)
		}
	}
	workspace.UpdatedAt = when
	m.mu.Unlock()

	audit.WriteAction(ctx, audit.AuditEvent{
		Action:       "tenancy.workspace.hard_delete",
		TenantID:     tenant,
		WorkspaceID:  HardDeletedWorkspaceMarker(id),
		ResourceType: "tenancy_workspace",
		ResourceID:   HardDeletedWorkspaceMarker(id),
		Outcome:      "success",
	})
	return workspace, nil
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

// GetWorkspaceMemberByUserUUID returns one scoped workspace member by auth user UUID.
func (m *MemoryStore) GetWorkspaceMemberByUserUUID(ctx context.Context, workspaceID string, userUUID string) (TenancyWorkspaceMember, error) {
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
	normalizedUserUUID := strings.TrimSpace(userUUID)
	for _, member := range m.members {
		if member.TenantID == scope.TenantID &&
			member.WorkspaceID == resolvedWorkspaceID &&
			member.UserUUID == normalizedUserUUID {
			return member, nil
		}
	}
	return TenancyWorkspaceMember{}, ErrNotFound
}

// FindFirstWorkspaceMemberByUserUUID returns the newest active workspace membership for one auth user.
func (m *MemoryStore) FindFirstWorkspaceMemberByUserUUID(ctx context.Context, userUUID string) (TenancyWorkspaceMember, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	normalizedUserUUID := strings.TrimSpace(userUUID)
	var selected TenancyWorkspaceMember
	for _, member := range m.members {
		if member.UserUUID != normalizedUserUUID || member.Status != "active" {
			continue
		}
		if selected.UserUUID == "" || member.JoinedAt.After(selected.JoinedAt) {
			selected = member
		}
	}
	if selected.UserUUID == "" {
		return TenancyWorkspaceMember{}, ErrNotFound
	}
	return selected, nil
}

// FindFirstWorkspaceMemberByUserUUIDAndTenantID returns the newest active workspace membership for one auth user in one tenant.
func (m *MemoryStore) FindFirstWorkspaceMemberByUserUUIDAndTenantID(ctx context.Context, userUUID string, tenantID string) (TenancyWorkspaceMember, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	normalizedUserUUID := strings.TrimSpace(userUUID)
	normalizedTenantID := strings.TrimSpace(tenantID)
	var selected TenancyWorkspaceMember
	for _, member := range m.members {
		if member.UserUUID != normalizedUserUUID || member.TenantID != normalizedTenantID || member.Status != "active" {
			continue
		}
		if selected.UserUUID == "" || member.JoinedAt.After(selected.JoinedAt) {
			selected = member
		}
	}
	if selected.UserUUID == "" {
		return TenancyWorkspaceMember{}, ErrNotFound
	}
	return selected, nil
}

// ListWorkspaceMembershipsByUserUUIDAndTenantID returns every active workspace
// membership the user holds within one tenant. It is the authorization basis
// for organization-wide reads: a caller may only aggregate data from the
// workspaces they actually belong to.
func (m *MemoryStore) ListWorkspaceMembershipsByUserUUIDAndTenantID(ctx context.Context, userUUID string, tenantID string) ([]TenancyWorkspaceMember, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	normalizedUserUUID := strings.TrimSpace(userUUID)
	normalizedTenantID := strings.TrimSpace(tenantID)
	if normalizedUserUUID == "" || normalizedTenantID == "" {
		return []TenancyWorkspaceMember{}, nil
	}
	memberships := make([]TenancyWorkspaceMember, 0)
	for _, member := range m.members {
		if member.UserUUID != normalizedUserUUID || member.TenantID != normalizedTenantID || member.Status != "active" {
			continue
		}
		memberships = append(memberships, member)
	}
	sort.Slice(memberships, func(i, j int) bool {
		return memberships[i].WorkspaceID < memberships[j].WorkspaceID
	})
	return memberships, nil
}

// ListWorkspaceMembershipsByUserUUID returns every active workspace membership
// the user holds across all tenants.
func (m *MemoryStore) ListWorkspaceMembershipsByUserUUID(ctx context.Context, userUUID string) ([]TenancyWorkspaceMember, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	normalizedUserUUID := strings.TrimSpace(userUUID)
	if normalizedUserUUID == "" {
		return []TenancyWorkspaceMember{}, nil
	}
	memberships := make([]TenancyWorkspaceMember, 0)
	for _, member := range m.members {
		if member.UserUUID != normalizedUserUUID || member.Status != "active" {
			continue
		}
		memberships = append(memberships, member)
	}
	sort.Slice(memberships, func(i, j int) bool {
		if memberships[i].TenantID != memberships[j].TenantID {
			return memberships[i].TenantID < memberships[j].TenantID
		}
		return memberships[i].WorkspaceID < memberships[j].WorkspaceID
	})
	return memberships, nil
}

// ListSoleOwnerWorkspaces returns every workspace, across all tenants, in which
// the user is the only active owner.
func (m *MemoryStore) ListSoleOwnerWorkspaces(ctx context.Context, userUUID string) ([]TenancyWorkspace, error) {
	normalizedUserUUID := strings.TrimSpace(userUUID)
	if normalizedUserUUID == "" {
		return []TenancyWorkspace{}, nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	// A workspace is sole-owned by the caller iff (a) the caller holds an
	// active owner membership and (b) no OTHER user holds an active owner
	// membership backed by a non-deleted user. Soft-deleted owners cannot
	// transfer ownership; counting them would let the caller delete their
	// account and leave the workspace with no live owner.
	otherLiveOwners := map[string]int{}
	userOwns := map[string]struct{}{}
	for _, member := range m.members {
		if member.Status != "active" || member.Role != "owner" {
			continue
		}
		key := tenancyWorkspaceKey(member.TenantID, member.WorkspaceID)
		if member.UserUUID == normalizedUserUUID {
			userOwns[key] = struct{}{}
			continue
		}
		if owner, ok := m.users[member.UserUUID]; ok && owner.Status == "deleted" {
			continue
		}
		otherLiveOwners[key]++
	}
	workspaces := make([]TenancyWorkspace, 0)
	for key := range userOwns {
		if otherLiveOwners[key] > 0 {
			continue
		}
		if workspace, exists := m.workspaces[key]; exists {
			if workspace.Status == WorkspaceStatusDeleted || workspace.DeletedAt != nil {
				continue
			}
			workspaces = append(workspaces, workspace)
		}
	}
	sort.Slice(workspaces, func(i, j int) bool {
		return workspaces[i].WorkspaceID < workspaces[j].WorkspaceID
	})
	return workspaces, nil
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
	for policyKey, policy := range m.scanPolicies {
		if policy.TenantID == scope.TenantID && policy.WorkspaceID == resolvedWorkspaceID && policy.ProjectID == projectID {
			delete(m.scanPolicies, policyKey)
		}
	}
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
	for coverageKey, coverage := range m.awsCoverages {
		if coverage.TenantID == scope.TenantID && coverage.WorkspaceID == resolvedWorkspaceID && coverage.ProjectID == projectID {
			delete(m.awsCoverages, coverageKey)
		}
	}
	m.deleteAWSPlatformBaselineResultsLocked(scope.TenantID, resolvedWorkspaceID, projectID)
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

// UpsertTenancyScanPolicy persists one scan policy for a scoped project.
func (m *MemoryStore) UpsertTenancyScanPolicy(ctx context.Context, policy TenancyScanPolicy) error {
	m.mu.Lock()

	scope, err := RequireScope(ctx)
	if err != nil {
		m.mu.Unlock()
		return err
	}
	policy.TenantID = scope.TenantID
	resolvedWorkspaceID, err := ResolveScopedWorkspaceID(scope, policy.WorkspaceID)
	if err != nil {
		m.mu.Unlock()
		return err
	}
	policy.WorkspaceID = resolvedWorkspaceID
	normalized, err := NormalizeTenancyScanPolicyForWrite(policy)
	if err != nil {
		m.mu.Unlock()
		return err
	}
	if _, exists := m.projects[tenancyProjectKey(normalized.TenantID, normalized.WorkspaceID, normalized.ProjectID)]; !exists {
		m.mu.Unlock()
		return ErrNotFound
	}
	for existingKey, existing := range m.scanPolicies {
		if existingKey == tenancyScanPolicyKey(normalized.TenantID, normalized.WorkspaceID, normalized.ProjectID, normalized.PolicyID) {
			continue
		}
		if existing.TenantID == normalized.TenantID &&
			existing.WorkspaceID == normalized.WorkspaceID &&
			existing.ProjectID == normalized.ProjectID &&
			strings.EqualFold(existing.Name, normalized.Name) {
			m.mu.Unlock()
			return ErrConflict
		}
	}
	key := tenancyScanPolicyKey(normalized.TenantID, normalized.WorkspaceID, normalized.ProjectID, normalized.PolicyID)
	if existing, exists := m.scanPolicies[key]; exists {
		normalized.CreatedAt = existing.CreatedAt
		normalized.LastScheduledAt = existing.LastScheduledAt
	}
	m.scanPolicies[key] = normalized
	m.mu.Unlock()

	audit.WriteAction(ctx, audit.AuditEvent{
		Action:       "tenancy.scan_policy.upsert",
		TenantID:     normalized.TenantID,
		WorkspaceID:  normalized.WorkspaceID,
		ResourceType: "tenancy_scan_policy",
		ResourceID:   normalized.PolicyID,
		Outcome:      "success",
	})
	return nil
}

// GetTenancyScanPolicy returns one scoped scan policy by id.
func (m *MemoryStore) GetTenancyScanPolicy(ctx context.Context, workspaceID string, projectID string, policyID string) (TenancyScanPolicy, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return TenancyScanPolicy{}, err
	}
	resolvedWorkspaceID, err := ResolveScopedWorkspaceID(scope, workspaceID)
	if err != nil {
		return TenancyScanPolicy{}, err
	}
	key := tenancyScanPolicyKey(scope.TenantID, resolvedWorkspaceID, strings.TrimSpace(projectID), strings.TrimSpace(policyID))
	policy, exists := m.scanPolicies[key]
	if !exists {
		return TenancyScanPolicy{}, ErrNotFound
	}
	return policy, nil
}

// ListTenancyScanPolicies returns scoped policies ordered before limiting.
func (m *MemoryStore) ListTenancyScanPolicies(ctx context.Context, workspaceID string, projectID string, triggerMode domain.ScanTriggerMode, enabled *bool, sortBy string, sortDesc bool, limit int) ([]TenancyScanPolicy, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 100
	}
	resolvedWorkspaceID, err := ResolveScopedWorkspaceID(scope, workspaceID)
	if err != nil {
		return nil, err
	}
	normalizedProjectID := strings.TrimSpace(projectID)
	normalizedTriggerMode := domain.ScanTriggerMode(strings.ToLower(strings.TrimSpace(string(triggerMode))))
	policies := make([]TenancyScanPolicy, 0, limit)
	for _, policy := range m.scanPolicies {
		if policy.TenantID != scope.TenantID || policy.WorkspaceID != resolvedWorkspaceID || policy.ProjectID != normalizedProjectID {
			continue
		}
		if normalizedTriggerMode != "" && policy.TriggerMode != normalizedTriggerMode {
			continue
		}
		if enabled != nil && policy.Enabled != *enabled {
			continue
		}
		policies = append(policies, policy)
	}
	sort.SliceStable(policies, func(i, j int) bool {
		left := policies[i]
		right := policies[j]
		var cmp int
		switch sortBy {
		case "policy_id":
			cmp = compareMemoryString(left.PolicyID, right.PolicyID)
		case "name":
			cmp = compareMemoryString(left.Name, right.Name)
		case "trigger_mode":
			cmp = compareMemoryString(string(left.TriggerMode), string(right.TriggerMode))
		case "updated_at":
			cmp = left.UpdatedAt.Compare(right.UpdatedAt)
		default:
			cmp = left.CreatedAt.Compare(right.CreatedAt)
		}
		if cmp == 0 {
			return compareMemoryString(left.PolicyID, right.PolicyID) < 0
		}
		if sortDesc {
			return cmp > 0
		}
		return cmp < 0
	})
	if len(policies) > limit {
		policies = policies[:limit]
	}
	return policies, nil
}

// ListScheduledTenancyScanPolicies returns all enabled scheduled policies for worker execution.
func (m *MemoryStore) ListScheduledTenancyScanPolicies(ctx context.Context, limit int, offset int) ([]TenancyScanPolicy, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if limit <= 0 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	policies := make([]TenancyScanPolicy, 0, limit)
	for _, policy := range m.scanPolicies {
		if !policy.Enabled {
			continue
		}
		if policy.TriggerMode != domain.ScanTriggerModeScheduled && policy.TriggerMode != domain.ScanTriggerModeHybrid {
			continue
		}
		workspace, exists := m.workspaces[tenancyWorkspaceKey(policy.TenantID, policy.WorkspaceID)]
		if !exists || workspace.Status != WorkspaceStatusActive || workspace.DeletedAt != nil {
			continue
		}
		policies = append(policies, policy)
	}
	sort.SliceStable(policies, func(i, j int) bool {
		left := policies[i]
		right := policies[j]
		if cmp := left.CreatedAt.Compare(right.CreatedAt); cmp != 0 {
			return cmp < 0
		}
		if cmp := compareMemoryString(left.TenantID, right.TenantID); cmp != 0 {
			return cmp < 0
		}
		if cmp := compareMemoryString(left.WorkspaceID, right.WorkspaceID); cmp != 0 {
			return cmp < 0
		}
		if cmp := compareMemoryString(left.ProjectID, right.ProjectID); cmp != 0 {
			return cmp < 0
		}
		return compareMemoryString(left.PolicyID, right.PolicyID) < 0
	})
	if offset >= len(policies) {
		return []TenancyScanPolicy{}, nil
	}
	end := offset + limit
	if end > len(policies) {
		end = len(policies)
	}
	return policies[offset:end], nil
}

// ClaimTenancyScanPolicySchedule atomically records the scheduled tick claimed by a worker.
func (m *MemoryStore) ClaimTenancyScanPolicySchedule(ctx context.Context, workspaceID string, projectID string, policyID string, scheduledAt time.Time, now time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return false, err
	}
	resolvedWorkspaceID, err := ResolveScopedWorkspaceID(scope, workspaceID)
	if err != nil {
		return false, err
	}
	key := tenancyScanPolicyKey(scope.TenantID, resolvedWorkspaceID, strings.TrimSpace(projectID), strings.TrimSpace(policyID))
	policy, exists := m.scanPolicies[key]
	if !exists {
		return false, ErrNotFound
	}
	if !policy.Enabled || (policy.TriggerMode != domain.ScanTriggerModeScheduled && policy.TriggerMode != domain.ScanTriggerModeHybrid) {
		return false, nil
	}
	workspace, exists := m.workspaces[tenancyWorkspaceKey(scope.TenantID, resolvedWorkspaceID)]
	if !exists || workspace.Status != WorkspaceStatusActive || workspace.DeletedAt != nil {
		return false, nil
	}
	scheduledAt = scheduledAt.UTC().Truncate(time.Minute)
	if policy.LastScheduledAt != nil && !policy.LastScheduledAt.Before(scheduledAt) {
		return false, nil
	}
	now = now.UTC()
	policy.LastScheduledAt = &scheduledAt
	policy.UpdatedAt = now
	m.scanPolicies[key] = policy
	return true, nil
}

// DeleteTenancyScanPolicy removes one scoped scan policy.
func (m *MemoryStore) DeleteTenancyScanPolicy(ctx context.Context, workspaceID string, projectID string, policyID string) error {
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
	key := tenancyScanPolicyKey(scope.TenantID, resolvedWorkspaceID, strings.TrimSpace(projectID), strings.TrimSpace(policyID))
	if _, exists := m.scanPolicies[key]; !exists {
		m.mu.Unlock()
		return ErrNotFound
	}
	delete(m.scanPolicies, key)
	m.mu.Unlock()

	audit.WriteAction(ctx, audit.AuditEvent{
		Action:       "tenancy.scan_policy.delete",
		TenantID:     scope.TenantID,
		WorkspaceID:  resolvedWorkspaceID,
		ResourceType: "tenancy_scan_policy",
		ResourceID:   strings.TrimSpace(policyID),
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

func tenancyScanPolicyKey(tenantID string, workspaceID string, projectID string, policyID string) string {
	return tenancyCompositeKey(strings.TrimSpace(tenantID), strings.TrimSpace(workspaceID), strings.TrimSpace(projectID), strings.TrimSpace(policyID))
}

func awsAccountRegionCoverageKey(tenantID string, workspaceID string, projectID string, connectorID string, accountID string, region string) string {
	return tenancyCompositeKey(strings.TrimSpace(tenantID), strings.TrimSpace(workspaceID), strings.TrimSpace(projectID), strings.TrimSpace(connectorID), strings.TrimSpace(accountID), strings.ToLower(strings.TrimSpace(region)))
}

func awsPlatformBaselineKey(tenantID string, workspaceID string, projectID string, connectorID string) string {
	return tenancyCompositeKey(strings.TrimSpace(tenantID), strings.TrimSpace(workspaceID), strings.TrimSpace(projectID), strings.TrimSpace(connectorID))
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

// ClaimKubernetesEnrollmentToken marks a single connector enrollment token as consumed.
func (m *MemoryStore) ClaimKubernetesEnrollmentToken(ctx context.Context, workspaceID string, projectID string, connectorID string, expectedEnrollmentTokenHash string, updatedMetadata map[string]any, status domain.ConnectorStatus, health string, lastErrorCode string, lastErrorMessage string, observedAt time.Time, updatedAt time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return false, err
	}
	resolvedWorkspaceID, err := ResolveScopedWorkspaceID(scope, workspaceID)
	if err != nil {
		return false, err
	}
	key := tenancyConnectorKey(scope.TenantID, resolvedWorkspaceID, strings.TrimSpace(projectID), strings.TrimSpace(connectorID))
	state, exists := m.connStates[key]
	if !exists {
		return false, ErrNotFound
	}
	currentHash, ok := state.Metadata["enrollment_token_sha256"].(string)
	if !ok || strings.TrimSpace(currentHash) != strings.TrimSpace(expectedEnrollmentTokenHash) {
		return false, nil
	}
	if _, wasUsed := state.Metadata["enrollment_token_used_at"]; wasUsed {
		return false, nil
	}

	conn, exists := m.connectors[key]
	if !exists {
		return false, ErrNotFound
	}

	state.Metadata = cloneMetadataMap(updatedMetadata)
	state.HealthStatus = strings.TrimSpace(health)
	state.LastErrorCode = strings.TrimSpace(lastErrorCode)
	state.LastErrorMessage = strings.TrimSpace(lastErrorMessage)
	state.ObservedAt = observedAt.UTC()
	state.UpdatedAt = updatedAt.UTC()
	conn.Status = status
	conn.UpdatedAt = updatedAt.UTC()
	m.connectors[key] = conn
	m.connStates[key] = state
	return true, nil
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

// UpsertAWSAccountRegionCoverage persists one account/region coverage row for a scoped AWS connector.
func (m *MemoryStore) UpsertAWSAccountRegionCoverage(ctx context.Context, coverage AWSAccountRegionCoverage) (AWSAccountRegionCoverage, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return AWSAccountRegionCoverage{}, err
	}
	coverage.TenantID = scope.TenantID
	resolvedWorkspaceID, err := ResolveScopedWorkspaceID(scope, coverage.WorkspaceID)
	if err != nil {
		return AWSAccountRegionCoverage{}, err
	}
	coverage.WorkspaceID = resolvedWorkspaceID
	normalized, err := NormalizeAWSAccountRegionCoverageForWrite(coverage)
	if err != nil {
		return AWSAccountRegionCoverage{}, err
	}
	connectorKey := tenancyConnectorKey(normalized.TenantID, normalized.WorkspaceID, normalized.ProjectID, normalized.ConnectorID)
	if connector, exists := m.connectors[connectorKey]; !exists || connector.Type != domain.ConnectorTypeAWS {
		return AWSAccountRegionCoverage{}, ErrNotFound
	}
	key := awsAccountRegionCoverageKey(normalized.TenantID, normalized.WorkspaceID, normalized.ProjectID, normalized.ConnectorID, normalized.AccountID, normalized.Region)
	if existing, exists := m.awsCoverages[key]; exists {
		normalized.CreatedAt = existing.CreatedAt
	}
	m.awsCoverages[key] = normalized
	return cloneAWSAccountRegionCoverage(normalized), nil
}

// ListAWSAccountRegionCoverages returns deterministic scoped AWS account/region coverage rows.
func (m *MemoryStore) ListAWSAccountRegionCoverages(ctx context.Context, filter AWSAccountRegionCoverageFilter) ([]AWSAccountRegionCoverage, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return nil, err
	}
	resolvedWorkspaceID, err := ResolveScopedWorkspaceID(scope, filter.WorkspaceID)
	if err != nil {
		return nil, err
	}
	projectID := strings.TrimSpace(filter.ProjectID)
	if projectID == "" {
		return nil, fmt.Errorf("project id is required")
	}
	limit := filter.Limit
	if limit <= 0 {
		limit = 100
	}
	connectorID := strings.TrimSpace(filter.ConnectorID)
	accountID := strings.TrimSpace(filter.AccountID)
	region := strings.ToLower(strings.TrimSpace(filter.Region))
	results := make([]AWSAccountRegionCoverage, 0, limit)
	for _, coverage := range m.awsCoverages {
		if coverage.TenantID != scope.TenantID || coverage.WorkspaceID != resolvedWorkspaceID || coverage.ProjectID != projectID {
			continue
		}
		if connectorID != "" && coverage.ConnectorID != connectorID {
			continue
		}
		if accountID != "" && coverage.AccountID != accountID {
			continue
		}
		if region != "" && coverage.Region != region {
			continue
		}
		results = append(results, cloneAWSAccountRegionCoverage(coverage))
	}
	sort.Slice(results, func(i, j int) bool {
		if results[i].ConnectorID != results[j].ConnectorID {
			return results[i].ConnectorID < results[j].ConnectorID
		}
		if results[i].AccountID != results[j].AccountID {
			return results[i].AccountID < results[j].AccountID
		}
		return results[i].Region < results[j].Region
	})
	if len(results) > limit {
		results = results[:limit]
	}
	return results, nil
}

func cloneAWSAccountRegionCoverage(coverage AWSAccountRegionCoverage) AWSAccountRegionCoverage {
	cloned := coverage
	cloned.ScanCursor = cloneMetadataMap(coverage.ScanCursor)
	if coverage.LastSuccessfulScanAt != nil {
		scanned := coverage.LastSuccessfulScanAt.UTC()
		cloned.LastSuccessfulScanAt = &scanned
	}
	return cloned
}

// UpsertAWSPlatformBaselineResult persists one project-scoped AWS baseline gate result.
func (m *MemoryStore) UpsertAWSPlatformBaselineResult(ctx context.Context, result AWSPlatformBaselineResult) (AWSPlatformBaselineResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return AWSPlatformBaselineResult{}, err
	}
	result.TenantID = scope.TenantID
	resolvedWorkspaceID, err := ResolveScopedWorkspaceID(scope, result.WorkspaceID)
	if err != nil {
		return AWSPlatformBaselineResult{}, err
	}
	result.WorkspaceID = resolvedWorkspaceID
	normalized, err := NormalizeAWSPlatformBaselineResultForWrite(result)
	if err != nil {
		return AWSPlatformBaselineResult{}, err
	}
	if _, exists := m.projects[tenancyProjectKey(normalized.TenantID, normalized.WorkspaceID, normalized.ProjectID)]; !exists {
		return AWSPlatformBaselineResult{}, ErrNotFound
	}
	if normalized.ConnectorID != "" {
		connectorKey := tenancyConnectorKey(normalized.TenantID, normalized.WorkspaceID, normalized.ProjectID, normalized.ConnectorID)
		if connector, exists := m.connectors[connectorKey]; !exists || connector.Type != domain.ConnectorTypeAWS {
			return AWSPlatformBaselineResult{}, ErrNotFound
		}
	}
	key := awsPlatformBaselineKey(normalized.TenantID, normalized.WorkspaceID, normalized.ProjectID, normalized.ConnectorID)
	if existing, exists := m.awsBaselines[key]; exists {
		normalized.CreatedAt = existing.CreatedAt
	}
	m.awsBaselines[key] = normalized
	return cloneAWSPlatformBaselineResult(normalized), nil
}

// GetAWSPlatformBaselineResult returns the latest scoped AWS baseline gate result.
func (m *MemoryStore) GetAWSPlatformBaselineResult(ctx context.Context, filter AWSPlatformBaselineFilter) (AWSPlatformBaselineResult, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return AWSPlatformBaselineResult{}, err
	}
	resolvedWorkspaceID, err := ResolveScopedWorkspaceID(scope, filter.WorkspaceID)
	if err != nil {
		return AWSPlatformBaselineResult{}, err
	}
	projectID := strings.TrimSpace(filter.ProjectID)
	if projectID == "" {
		return AWSPlatformBaselineResult{}, fmt.Errorf("project id is required")
	}
	key := awsPlatformBaselineKey(scope.TenantID, resolvedWorkspaceID, projectID, filter.ConnectorID)
	result, exists := m.awsBaselines[key]
	if !exists {
		return AWSPlatformBaselineResult{}, ErrNotFound
	}
	return cloneAWSPlatformBaselineResult(result), nil
}

func (m *MemoryStore) deleteAWSPlatformBaselineResultsLocked(tenantID string, workspaceID string, projectID string) {
	for key, baseline := range m.awsBaselines {
		if tenantID != "" && baseline.TenantID != tenantID {
			continue
		}
		if workspaceID != "" && baseline.WorkspaceID != workspaceID {
			continue
		}
		if projectID != "" && baseline.ProjectID != projectID {
			continue
		}
		delete(m.awsBaselines, key)
	}
}

func cloneAWSPlatformBaselineResult(result AWSPlatformBaselineResult) AWSPlatformBaselineResult {
	cloned := result
	cloned.FailureReasons = append([]string(nil), result.FailureReasons...)
	cloned.EvidenceLinks = append([]string(nil), result.EvidenceLinks...)
	cloned.Checks = make([]AWSPlatformBaselineCheck, len(result.Checks))
	for idx, check := range result.Checks {
		cloned.Checks[idx] = check
		cloned.Checks[idx].Evidence = cloneMetadataMap(check.Evidence)
	}
	return cloned
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

// DeleteTenancyConnectorSecretEnvelope removes one encrypted connector secret envelope.
func (m *MemoryStore) DeleteTenancyConnectorSecretEnvelope(ctx context.Context, workspaceID string, projectID string, connectorID string, secretName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return err
	}
	resolvedWorkspaceID, err := ResolveScopedWorkspaceID(scope, workspaceID)
	if err != nil {
		return err
	}
	key := tenancyConnectorSecretKey(scope.TenantID, resolvedWorkspaceID, strings.TrimSpace(projectID), strings.TrimSpace(connectorID), strings.TrimSpace(secretName))
	if _, exists := m.connSecrets[key]; !exists {
		return ErrNotFound
	}
	delete(m.connSecrets, key)
	return nil
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
