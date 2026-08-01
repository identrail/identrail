package db

import (
	"context"
	"crypto/sha256"
	"regexp"
	"sort"
	"strings"
	"time"
)

func (m *MemoryStore) CreateAWSOrganizationRollout(ctx context.Context, rollout AWSOrganizationRollout) (AWSOrganizationRollout, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	normalized, err := normalizeAWSOrganizationRollout(ctx, rollout)
	if err != nil {
		return AWSOrganizationRollout{}, err
	}
	if _, exists := m.awsOrgRollouts[normalized.RolloutID]; exists {
		return AWSOrganizationRollout{}, ErrConflict
	}
	connectorKey := tenancyConnectorKey(normalized.TenantID, normalized.WorkspaceID, normalized.ProjectID, normalized.ControllingConnectorID)
	if _, exists := m.connectors[connectorKey]; !exists {
		return AWSOrganizationRollout{}, ErrNotFound
	}
	for _, existing := range m.awsOrgRollouts {
		if existing.TenantID == normalized.TenantID &&
			existing.WorkspaceID == normalized.WorkspaceID &&
			existing.ProjectID == normalized.ProjectID &&
			existing.ControllingConnectorID == normalized.ControllingConnectorID &&
			awsOrganizationRolloutActive(existing.Status) {
			return AWSOrganizationRollout{}, ErrConflict
		}
	}
	m.awsOrgRollouts[normalized.RolloutID] = cloneAWSOrganizationRollout(normalized)
	return cloneAWSOrganizationRollout(normalized), nil
}

func (m *MemoryStore) GetAWSOrganizationRollout(ctx context.Context, workspaceID string, projectID string, rolloutID string) (AWSOrganizationRollout, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return AWSOrganizationRollout{}, err
	}
	resolvedWorkspaceID, err := ResolveScopedWorkspaceID(scope, workspaceID)
	if err != nil {
		return AWSOrganizationRollout{}, err
	}
	rollout, ok := m.awsOrgRollouts[strings.TrimSpace(rolloutID)]
	if !ok || rollout.TenantID != scope.TenantID || rollout.WorkspaceID != resolvedWorkspaceID || rollout.ProjectID != strings.TrimSpace(projectID) {
		return AWSOrganizationRollout{}, ErrNotFound
	}
	return cloneAWSOrganizationRollout(rollout), nil
}

func (m *MemoryStore) GetAWSOrganizationRolloutAnyScope(_ context.Context, rolloutID string) (AWSOrganizationRollout, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	rollout, ok := m.awsOrgRollouts[strings.TrimSpace(rolloutID)]
	if !ok {
		return AWSOrganizationRollout{}, ErrNotFound
	}
	return cloneAWSOrganizationRollout(rollout), nil
}

func (m *MemoryStore) ListAWSOrganizationRollouts(ctx context.Context, workspaceID string, projectID string, connectorID string, limit int) ([]AWSOrganizationRollout, error) {
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
	trimmedProject := strings.TrimSpace(projectID)
	trimmedConnector := strings.TrimSpace(connectorID)
	out := make([]AWSOrganizationRollout, 0)
	for _, rollout := range m.awsOrgRollouts {
		if rollout.TenantID != scope.TenantID || rollout.WorkspaceID != resolvedWorkspaceID || rollout.ProjectID != trimmedProject {
			continue
		}
		if trimmedConnector != "" && rollout.ControllingConnectorID != trimmedConnector {
			continue
		}
		out = append(out, cloneAWSOrganizationRollout(rollout))
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	// Mirror the Postgres store's default (50) and cap (200) so tests written
	// against the memory adapter cannot pass under a limit that will be
	// silently truncated by Postgres in production.
	effectiveLimit := limit
	if effectiveLimit <= 0 || effectiveLimit > 200 {
		effectiveLimit = 50
	}
	if len(out) > effectiveLimit {
		out = out[:effectiveLimit]
	}
	return out, nil
}

func (m *MemoryStore) UpdateAWSOrganizationRollout(ctx context.Context, rollout AWSOrganizationRollout, expectedVersion int64) (AWSOrganizationRollout, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	normalized, err := normalizeAWSOrganizationRollout(ctx, rollout)
	if err != nil {
		return AWSOrganizationRollout{}, err
	}
	existing, ok := m.awsOrgRollouts[normalized.RolloutID]
	if !ok {
		return AWSOrganizationRollout{}, ErrNotFound
	}
	if existing.TenantID != normalized.TenantID ||
		existing.WorkspaceID != normalized.WorkspaceID ||
		existing.ProjectID != normalized.ProjectID ||
		existing.ControllingConnectorID != normalized.ControllingConnectorID {
		return AWSOrganizationRollout{}, ErrNotFound
	}
	if existing.Version != expectedVersion {
		return AWSOrganizationRollout{}, ErrConflict
	}
	if awsOrganizationRolloutActive(normalized.Status) {
		for id, other := range m.awsOrgRollouts {
			if id == normalized.RolloutID {
				continue
			}
			if other.TenantID == normalized.TenantID &&
				other.WorkspaceID == normalized.WorkspaceID &&
				other.ProjectID == normalized.ProjectID &&
				other.ControllingConnectorID == normalized.ControllingConnectorID &&
				awsOrganizationRolloutActive(other.Status) {
				return AWSOrganizationRollout{}, ErrConflict
			}
		}
	}
	normalized.CreatedAt = existing.CreatedAt
	normalized.Version = existing.Version + 1
	m.awsOrgRollouts[normalized.RolloutID] = cloneAWSOrganizationRollout(normalized)
	return cloneAWSOrganizationRollout(normalized), nil
}

func (m *MemoryStore) UpsertAWSOrganizationRolloutTarget(ctx context.Context, target AWSOrganizationRolloutTarget) (AWSOrganizationRolloutTarget, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	normalized, err := normalizeAWSOrganizationRolloutTarget(ctx, target)
	if err != nil {
		return AWSOrganizationRolloutTarget{}, err
	}
	parent, ok := m.awsOrgRollouts[normalized.RolloutID]
	if !ok {
		return AWSOrganizationRolloutTarget{}, ErrNotFound
	}
	if parent.TenantID != normalized.TenantID ||
		parent.WorkspaceID != normalized.WorkspaceID ||
		parent.ProjectID != normalized.ProjectID {
		return AWSOrganizationRolloutTarget{}, ErrNotFound
	}
	key := awsOrganizationRolloutTargetKey(normalized.RolloutID, normalized.AccountID, normalized.Region)
	now := time.Now().UTC()
	if existing, ok := m.awsOrgRolloutTargets[key]; ok {
		normalized.CreatedAt = existing.CreatedAt
		normalized.Version = existing.Version + 1
		// Guard against a state downgrade. A late redelivery, an SQS
		// duplicate, or a stack Update for a member that has already been
		// reconciled to a terminal state (connected/failed/partial/
		// suspended/removed/excluded) must not demote the target back to a
		// non-terminal state. When the incoming state would downgrade, keep
		// the existing state and its transition timestamp; other evidence
		// fields (stack IDs, role ARN) are still refreshed.
		if !awsOrganizationRolloutTargetStateAdvances(existing.State, normalized.State) {
			normalized.State = existing.State
			normalized.LastTransitionAt = existing.LastTransitionAt
		} else if normalized.State != existing.State {
			// Preserve a caller-supplied transition time so reconciliation
			// and tests can pin the exact event timestamp. Postgres has
			// always accepted the supplied value; the memory adapter used
			// to overwrite it with now(), causing behavior drift.
			if normalized.LastTransitionAt.IsZero() {
				normalized.LastTransitionAt = now
			}
		} else if normalized.LastTransitionAt.IsZero() {
			normalized.LastTransitionAt = existing.LastTransitionAt
		}
		// Mirror the Postgres upsert's COALESCE behavior: a caller updating
		// state without re-supplying every optional field must not erase
		// prior evidence (account name, OU path, stack IDs, role ARN,
		// evidence ref, last validation timestamp). A registration event and
		// a later reconciliation update carry different fields, and both
		// paths need to converge to a durable, cumulative view.
		if normalized.AccountName == "" {
			normalized.AccountName = existing.AccountName
		}
		if normalized.OUPath == "" {
			normalized.OUPath = existing.OUPath
		}
		if normalized.StackInstanceID == "" {
			normalized.StackInstanceID = existing.StackInstanceID
		}
		if normalized.StackID == "" {
			normalized.StackID = existing.StackID
		}
		if normalized.RoleARN == "" {
			normalized.RoleARN = existing.RoleARN
		}
		if normalized.EvidenceRef == "" {
			normalized.EvidenceRef = existing.EvidenceRef
		}
		if normalized.RegisterRequestID == "" {
			normalized.RegisterRequestID = existing.RegisterRequestID
		}
		if normalized.LastValidationAt == nil {
			normalized.LastValidationAt = existing.LastValidationAt
		}
	} else {
		if normalized.CreatedAt.IsZero() {
			normalized.CreatedAt = now
		}
		normalized.Version = 1
		if normalized.LastTransitionAt.IsZero() {
			normalized.LastTransitionAt = now
		}
	}
	normalized.UpdatedAt = now
	m.awsOrgRolloutTargets[key] = cloneAWSOrganizationRolloutTarget(normalized)
	return cloneAWSOrganizationRolloutTarget(normalized), nil
}

func (m *MemoryStore) GetAWSOrganizationRolloutTarget(_ context.Context, rolloutID string, accountID string, region string) (AWSOrganizationRolloutTarget, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	target, ok := m.awsOrgRolloutTargets[awsOrganizationRolloutTargetKey(strings.TrimSpace(rolloutID), strings.TrimSpace(accountID), strings.ToLower(strings.TrimSpace(region)))]
	if !ok {
		return AWSOrganizationRolloutTarget{}, ErrNotFound
	}
	return cloneAWSOrganizationRolloutTarget(target), nil
}

func (m *MemoryStore) ListAWSOrganizationRolloutTargets(ctx context.Context, workspaceID string, projectID string, rolloutID string) ([]AWSOrganizationRolloutTarget, error) {
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
	rollout, ok := m.awsOrgRollouts[strings.TrimSpace(rolloutID)]
	if !ok || rollout.TenantID != scope.TenantID || rollout.WorkspaceID != resolvedWorkspaceID || rollout.ProjectID != strings.TrimSpace(projectID) {
		return nil, ErrNotFound
	}
	out := make([]AWSOrganizationRolloutTarget, 0)
	for _, target := range m.awsOrgRolloutTargets {
		if target.RolloutID != rollout.RolloutID {
			continue
		}
		out = append(out, cloneAWSOrganizationRolloutTarget(target))
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].AccountID == out[j].AccountID {
			return out[i].Region < out[j].Region
		}
		return out[i].AccountID < out[j].AccountID
	})
	return out, nil
}

func normalizeAWSOrganizationRollout(ctx context.Context, rollout AWSOrganizationRollout) (AWSOrganizationRollout, error) {
	scope, err := RequireScope(ctx)
	if err != nil {
		return AWSOrganizationRollout{}, err
	}
	rollout.TenantID = scope.TenantID
	workspaceID, err := ResolveScopedWorkspaceID(scope, rollout.WorkspaceID)
	if err != nil {
		return AWSOrganizationRollout{}, err
	}
	rollout.WorkspaceID = workspaceID
	rollout.RolloutID = strings.TrimSpace(rollout.RolloutID)
	rollout.ProjectID = strings.TrimSpace(rollout.ProjectID)
	rollout.ControllingConnectorID = strings.TrimSpace(rollout.ControllingConnectorID)
	rollout.OrganizationID = strings.TrimSpace(rollout.OrganizationID)
	rollout.ManagementAccountID = strings.TrimSpace(rollout.ManagementAccountID)
	rollout.Partition = strings.TrimSpace(rollout.Partition)
	rollout.DeploymentMode = strings.TrimSpace(rollout.DeploymentMode)
	rollout.StackSetName = strings.TrimSpace(rollout.StackSetName)
	rollout.ExpectedRoleName = strings.TrimSpace(rollout.ExpectedRoleName)
	rollout.TemplateVersion = strings.TrimSpace(rollout.TemplateVersion)
	rollout.TemplateChecksum = strings.TrimSpace(rollout.TemplateChecksum)
	rollout.RegistrationSecretKeyVersion = strings.TrimSpace(rollout.RegistrationSecretKeyVersion)
	rollout.ControllingRole = strings.TrimSpace(rollout.ControllingRole)
	rollout.Status = strings.TrimSpace(rollout.Status)
	rollout.SelectedOUIDs = trimAndDedupeStringSlice(rollout.SelectedOUIDs)
	rollout.SelectedAccountIDs = trimAndDedupeStringSlice(rollout.SelectedAccountIDs)
	rollout.ExcludedAccountIDs = trimAndDedupeStringSlice(rollout.ExcludedAccountIDs)
	rollout.TargetRegions = trimAndLowerDedupeStringSlice(rollout.TargetRegions)
	if rollout.RolloutID == "" || rollout.ProjectID == "" || rollout.ControllingConnectorID == "" ||
		rollout.OrganizationID == "" || !awsAccountIDPattern.MatchString(rollout.ManagementAccountID) ||
		rollout.Partition == "" || rollout.StackSetName == "" || rollout.ExpectedRoleName == "" ||
		rollout.TemplateVersion == "" || rollout.TemplateChecksum == "" ||
		len(rollout.RegistrationSecretHash) != sha256.Size ||
		rollout.RegistrationSecretKeyVersion == "" ||
		!awsOrganizationRolloutControllingRoleValid(rollout.ControllingRole) ||
		!awsOrganizationRolloutDeploymentModeValid(rollout.DeploymentMode) ||
		!awsOrganizationRolloutStatusValid(rollout.Status) ||
		rollout.ExpiresAt.IsZero() ||
		len(rollout.TargetRegions) == 0 {
		return AWSOrganizationRollout{}, ErrInvalidAWSOrganizationRollout
	}
	now := time.Now().UTC()
	if rollout.CreatedAt.IsZero() {
		rollout.CreatedAt = now
	}
	if rollout.UpdatedAt.IsZero() {
		rollout.UpdatedAt = rollout.CreatedAt
	}
	if rollout.Version <= 0 {
		rollout.Version = 1
	}
	return rollout, nil
}

func normalizeAWSOrganizationRolloutTarget(ctx context.Context, target AWSOrganizationRolloutTarget) (AWSOrganizationRolloutTarget, error) {
	scope, err := RequireScope(ctx)
	if err != nil {
		return AWSOrganizationRolloutTarget{}, err
	}
	target.TenantID = scope.TenantID
	workspaceID, err := ResolveScopedWorkspaceID(scope, target.WorkspaceID)
	if err != nil {
		return AWSOrganizationRolloutTarget{}, err
	}
	target.WorkspaceID = workspaceID
	target.RolloutID = strings.TrimSpace(target.RolloutID)
	target.ProjectID = strings.TrimSpace(target.ProjectID)
	target.AccountID = strings.TrimSpace(target.AccountID)
	target.Region = strings.ToLower(strings.TrimSpace(target.Region))
	target.State = strings.TrimSpace(target.State)
	if target.RolloutID == "" || target.ProjectID == "" ||
		!awsAccountIDPattern.MatchString(target.AccountID) || target.Region == "" ||
		!awsOrganizationRolloutTargetStateValid(target.State) {
		return AWSOrganizationRolloutTarget{}, ErrInvalidAWSOrganizationRolloutTarget
	}
	return target, nil
}

// awsAccountIDPattern mirrors the CHECK (~ '^[0-9]{12}$') on the parent and
// target tables so the memory adapter rejects the same inputs Postgres would.
// A length-only check let alphabetic 12-char IDs (like "abcd12345678") through
// the memory path even though production Postgres would reject them at
// commit, so adapter tests could pass under invariants the real store does
// not preserve.
var awsAccountIDPattern = regexp.MustCompile(`^[0-9]{12}$`)

func awsOrganizationRolloutControllingRoleValid(role string) bool {
	switch role {
	case AWSOrganizationRolloutControllingManagement, AWSOrganizationRolloutControllingDelegatedAdmin:
		return true
	default:
		return false
	}
}

func awsOrganizationRolloutDeploymentModeValid(mode string) bool {
	switch mode {
	case AWSOrganizationRolloutDeploymentServiceManaged, AWSOrganizationRolloutDeploymentSelfManaged:
		return true
	default:
		return false
	}
}

func awsOrganizationRolloutStatusValid(status string) bool {
	switch status {
	case AWSOrganizationRolloutStatusCreated,
		AWSOrganizationRolloutStatusLaunching,
		AWSOrganizationRolloutStatusInProgress,
		AWSOrganizationRolloutStatusReconciling,
		AWSOrganizationRolloutStatusCompleted,
		AWSOrganizationRolloutStatusPartial,
		AWSOrganizationRolloutStatusFailed,
		AWSOrganizationRolloutStatusExpired,
		AWSOrganizationRolloutStatusCanceled:
		return true
	default:
		return false
	}
}

func awsOrganizationRolloutActive(status string) bool {
	switch status {
	case AWSOrganizationRolloutStatusCreated,
		AWSOrganizationRolloutStatusLaunching,
		AWSOrganizationRolloutStatusInProgress,
		AWSOrganizationRolloutStatusReconciling:
		return true
	default:
		return false
	}
}

// awsOrganizationRolloutTargetStateTerminal returns true for target states
// that reconciliation considers durable outcomes. A terminal target may only
// be transitioned by another terminal event (e.g., connected → failed if
// validation regresses); a late in-flight callback cannot demote it back.
func awsOrganizationRolloutTargetStateTerminal(state string) bool {
	switch state {
	case AWSOrganizationRolloutTargetConnected,
		AWSOrganizationRolloutTargetFailed,
		AWSOrganizationRolloutTargetPartial,
		AWSOrganizationRolloutTargetSuspended,
		AWSOrganizationRolloutTargetRemoved,
		AWSOrganizationRolloutTargetExcluded:
		return true
	default:
		return false
	}
}

// awsOrganizationRolloutTargetStateAdvances returns true when transitioning
// from `from` to `to` is a valid forward move under the promote-only rule.
// Identical states advance; non-terminal → anything advances; a terminal
// origin only accepts another terminal destination.
func awsOrganizationRolloutTargetStateAdvances(from string, to string) bool {
	if from == to {
		return true
	}
	if !awsOrganizationRolloutTargetStateTerminal(from) {
		return true
	}
	return awsOrganizationRolloutTargetStateTerminal(to)
}

func awsOrganizationRolloutTargetStateValid(state string) bool {
	switch state {
	case AWSOrganizationRolloutTargetPending,
		AWSOrganizationRolloutTargetDeploying,
		AWSOrganizationRolloutTargetRegistering,
		AWSOrganizationRolloutTargetValidating,
		AWSOrganizationRolloutTargetConnected,
		AWSOrganizationRolloutTargetPartial,
		AWSOrganizationRolloutTargetFailed,
		AWSOrganizationRolloutTargetExcluded,
		AWSOrganizationRolloutTargetSuspended,
		AWSOrganizationRolloutTargetRemoved:
		return true
	default:
		return false
	}
}

func awsOrganizationRolloutTargetKey(rolloutID string, accountID string, region string) string {
	return rolloutID + "\x00" + accountID + "\x00" + region
}

func cloneAWSOrganizationRollout(rollout AWSOrganizationRollout) AWSOrganizationRollout {
	rollout.RegistrationSecretHash = append([]byte(nil), rollout.RegistrationSecretHash...)
	rollout.SelectedOUIDs = append([]string{}, rollout.SelectedOUIDs...)
	rollout.SelectedAccountIDs = append([]string{}, rollout.SelectedAccountIDs...)
	rollout.ExcludedAccountIDs = append([]string{}, rollout.ExcludedAccountIDs...)
	rollout.TargetRegions = append([]string{}, rollout.TargetRegions...)
	rollout.TargetRegions = append([]string(nil), rollout.TargetRegions...)
	return rollout
}

func cloneAWSOrganizationRolloutTarget(target AWSOrganizationRolloutTarget) AWSOrganizationRolloutTarget {
	if target.LastValidationAt != nil {
		copied := *target.LastValidationAt
		target.LastValidationAt = &copied
	}
	return target
}

func trimAndDedupeStringSlice(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, v := range values {
		trimmed := strings.TrimSpace(v)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	return out
}

func trimAndLowerDedupeStringSlice(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, v := range values {
		trimmed := strings.ToLower(strings.TrimSpace(v))
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	return out
}
