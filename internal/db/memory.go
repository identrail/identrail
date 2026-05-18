package db

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/identrail/identrail/internal/domain"
	"github.com/identrail/identrail/internal/providers"
)

// MemoryStore is a concurrency-safe in-memory persistence adapter.
type MemoryStore struct {
	mu             sync.RWMutex
	scans          map[string]ScanRecord
	scanIDs        []string
	findings       map[string]domain.Finding
	scanFindings   map[string][]string
	triageStates   map[string]FindingTriageState
	triageEvents   map[string][]FindingTriageEvent
	events         map[string][]ScanEvent
	repoScans      map[string]RepoScanRecord
	repoScanIDs    []string
	repoFindings   map[string]domain.Finding
	repoFindingIDs map[string][]string

	rawAssets                     map[string]providers.RawAsset
	authzAttrs                    map[string]AuthzEntityAttributes
	authzRels                     map[string]AuthzRelationship
	authzSets                     map[string]AuthzPolicySet
	authzVersions                 map[string]AuthzPolicyVersion
	authzRollouts                 map[string]AuthzPolicyRollout
	authzEvents                   map[string][]AuthzPolicyEvent
	authzEventIDs                 map[string]struct{}
	organizations                 map[string]TenancyOrganization
	workspaces                    map[string]TenancyWorkspace
	members                       map[string]TenancyWorkspaceMember
	projects                      map[string]TenancyProject
	scanPolicies                  map[string]TenancyScanPolicy
	connectors                    map[string]TenancyConnector
	connStates                    map[string]TenancyConnectorState
	connSecrets                   map[string]TenancyConnectorSecretEnvelope
	users                         map[string]User
	userIdentityByID              map[string]UserIdentity
	userIdentityByProviderSubject map[string]string
	sessions                      map[string]Session
	onboardingStates              map[string]OnboardingState
	invitations                   map[string]Invitation
	verifiedDomains               map[string]VerifiedDomain
	identityConnections           map[string]IdentityConnection
	samlRelayStates               map[string]SAMLRelayState
	oauthTransactions             map[string]OAuthTransaction
	webhookEvents                 map[string]webhookEventRecord
	scimEvents                    map[string]SCIMProvisioningEventRecord
	identities                    map[string]domain.Identity
	policies                      map[string]domain.Policy
	relationships                 map[string]domain.Relationship
	permissions                   map[string]providers.PermissionTuple
}

// NewMemoryStore initializes an empty in-memory store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		scans:          map[string]ScanRecord{},
		scanIDs:        []string{},
		findings:       map[string]domain.Finding{},
		scanFindings:   map[string][]string{},
		triageStates:   map[string]FindingTriageState{},
		triageEvents:   map[string][]FindingTriageEvent{},
		events:         map[string][]ScanEvent{},
		repoScans:      map[string]RepoScanRecord{},
		repoScanIDs:    []string{},
		repoFindings:   map[string]domain.Finding{},
		repoFindingIDs: map[string][]string{},

		rawAssets:                     map[string]providers.RawAsset{},
		authzAttrs:                    map[string]AuthzEntityAttributes{},
		authzRels:                     map[string]AuthzRelationship{},
		authzSets:                     map[string]AuthzPolicySet{},
		authzVersions:                 map[string]AuthzPolicyVersion{},
		authzRollouts:                 map[string]AuthzPolicyRollout{},
		authzEvents:                   map[string][]AuthzPolicyEvent{},
		authzEventIDs:                 map[string]struct{}{},
		organizations:                 map[string]TenancyOrganization{},
		workspaces:                    map[string]TenancyWorkspace{},
		members:                       map[string]TenancyWorkspaceMember{},
		projects:                      map[string]TenancyProject{},
		scanPolicies:                  map[string]TenancyScanPolicy{},
		connectors:                    map[string]TenancyConnector{},
		connStates:                    map[string]TenancyConnectorState{},
		connSecrets:                   map[string]TenancyConnectorSecretEnvelope{},
		users:                         map[string]User{},
		userIdentityByID:              map[string]UserIdentity{},
		userIdentityByProviderSubject: map[string]string{},
		sessions:                      map[string]Session{},
		onboardingStates:              map[string]OnboardingState{},
		invitations:                   map[string]Invitation{},
		verifiedDomains:               map[string]VerifiedDomain{},
		identityConnections:           map[string]IdentityConnection{},
		samlRelayStates:               map[string]SAMLRelayState{},
		oauthTransactions:             map[string]OAuthTransaction{},
		webhookEvents:                 map[string]webhookEventRecord{},
		scimEvents:                    map[string]SCIMProvisioningEventRecord{},
		identities:                    map[string]domain.Identity{},
		policies:                      map[string]domain.Policy{},
		relationships:                 map[string]domain.Relationship{},
		permissions:                   map[string]providers.PermissionTuple{},
	}
}

func appendUniqueID(items []string, id string) []string {
	for _, existing := range items {
		if existing == id {
			return items
		}
	}
	return append(items, id)
}

func sortFindingsForQuery(items []domain.Finding, sortBy string, desc bool) {
	sort.SliceStable(items, func(i, j int) bool {
		left := items[i]
		right := items[j]
		var cmp int
		switch strings.ToLower(strings.TrimSpace(sortBy)) {
		case "severity":
			cmp = compareMemoryInt(severityRank(left.Severity), severityRank(right.Severity))
		case "type":
			cmp = compareMemoryString(string(left.Type), string(right.Type))
		case "title":
			cmp = compareMemoryString(left.Title, right.Title)
		default:
			cmp = compareMemoryTime(left.CreatedAt, right.CreatedAt)
		}
		if cmp == 0 {
			cmp = compareMemoryString(left.ID, right.ID)
		}
		if desc {
			return cmp > 0
		}
		return cmp < 0
	})
}

func compareMemoryTime(left time.Time, right time.Time) int {
	switch {
	case left.Before(right):
		return -1
	case left.After(right):
		return 1
	default:
		return 0
	}
}

func compareMemoryString(left string, right string) int {
	switch {
	case left < right:
		return -1
	case left > right:
		return 1
	default:
		return 0
	}
}

func compareMemoryInt(left int, right int) int {
	switch {
	case left < right:
		return -1
	case left > right:
		return 1
	default:
		return 0
	}
}

func severityRank(severity domain.FindingSeverity) int {
	switch severity {
	case domain.SeverityCritical:
		return 5
	case domain.SeverityHigh:
		return 4
	case domain.SeverityMedium:
		return 3
	case domain.SeverityLow:
		return 2
	case domain.SeverityInfo:
		return 1
	default:
		return 0
	}
}

// CreateScan persists a scan start event.
func (m *MemoryStore) CreateScan(ctx context.Context, provider string, startedAt time.Time) (ScanRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return ScanRecord{}, err
	}
	return m.createScanLocked(scope, provider, "running", startedAt), nil
}

// CreateQueuedScan persists one queued scan request.
func (m *MemoryStore) CreateQueuedScan(ctx context.Context, provider string, queuedAt time.Time) (ScanRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return ScanRecord{}, err
	}
	record := m.createScanLocked(scope, provider, "queued", queuedAt)
	record.TraceParent, record.TraceState = QueueTraceContextFromContext(ctx)
	m.scans[record.ID] = record
	return record, nil
}

// CreateQueuedScanWithinLimit persists one queued scan request only when pending capacity remains.
func (m *MemoryStore) CreateQueuedScanWithinLimit(ctx context.Context, provider string, queuedAt time.Time, maxPending int) (ScanRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return ScanRecord{}, err
	}
	if maxPending <= 0 {
		maxPending = 1
	}
	normalizedProvider := strings.TrimSpace(provider)
	queued := 0
	for _, record := range m.scans {
		if !MatchScope(scope, record.TenantID, record.WorkspaceID) {
			continue
		}
		if record.Status != "queued" || record.DeadLettered {
			continue
		}
		if normalizedProvider != "" && strings.TrimSpace(record.Provider) != normalizedProvider {
			continue
		}
		queued++
	}
	if queued >= maxPending {
		return ScanRecord{}, ErrQueueLimitReached
	}
	record := m.createScanLocked(scope, provider, "queued", queuedAt)
	record.TraceParent, record.TraceState = QueueTraceContextFromContext(ctx)
	m.scans[record.ID] = record
	return record, nil
}

// CreateQueuedScanIfNoPending persists one queued scan only when no queued/running scan exists.
func (m *MemoryStore) CreateQueuedScanIfNoPending(ctx context.Context, provider string, queuedAt time.Time) (ScanRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return ScanRecord{}, err
	}
	normalizedProvider := strings.TrimSpace(provider)
	for _, record := range m.scans {
		if !MatchScope(scope, record.TenantID, record.WorkspaceID) {
			continue
		}
		if normalizedProvider != "" && strings.TrimSpace(record.Provider) != normalizedProvider {
			continue
		}
		if record.DeadLettered {
			continue
		}
		if record.Status == "queued" || record.Status == "running" {
			return ScanRecord{}, ErrPendingScanExists
		}
	}
	record := m.createScanLocked(scope, provider, "queued", queuedAt)
	record.TraceParent, record.TraceState = QueueTraceContextFromContext(ctx)
	m.scans[record.ID] = record
	return record, nil
}

// ClaimNextQueuedScan moves one queued scan to running for execution.
func (m *MemoryStore) ClaimNextQueuedScan(ctx context.Context, provider string) (ScanRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return ScanRecord{}, err
	}
	return m.claimNextQueuedScanLocked(&scope, provider)
}

// ClaimNextQueuedScanAnyScope moves one queued scan to running across all tenant/workspace scopes.
func (m *MemoryStore) ClaimNextQueuedScanAnyScope(_ context.Context, provider string) (ScanRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.claimNextQueuedScanLocked(nil, provider)
}

func (m *MemoryStore) claimNextQueuedScanLocked(scope *Scope, provider string) (ScanRecord, error) {
	normalizedProvider := strings.TrimSpace(provider)
	found := false
	var bestRecord ScanRecord
	for _, scanID := range m.scanIDs {
		record := m.scans[scanID]
		if scope != nil && !MatchScope(*scope, record.TenantID, record.WorkspaceID) {
			continue
		}
		if record.Status != "queued" || record.DeadLettered {
			continue
		}
		if normalizedProvider != "" && strings.TrimSpace(record.Provider) != normalizedProvider {
			continue
		}
		if record.NextRetryAt != nil && record.NextRetryAt.After(time.Now().UTC()) {
			continue
		}
		if !found || record.StartedAt.Before(bestRecord.StartedAt) {
			bestRecord = record
			found = true
		}
	}
	if !found {
		return ScanRecord{}, ErrNotFound
	}
	bestRecord.Status = "running"
	bestRecord.FinishedAt = nil
	bestRecord.ErrorMessage = ""
	bestRecord.FailureCategory = ""
	bestRecord.NextRetryAt = nil
	m.scans[bestRecord.ID] = bestRecord
	return bestRecord, nil
}

// CountQueuedScans returns the queued scan count for one provider.
func (m *MemoryStore) CountQueuedScans(ctx context.Context, provider string) (int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return 0, err
	}
	normalizedProvider := strings.TrimSpace(provider)
	count := 0
	for _, record := range m.scans {
		if !MatchScope(scope, record.TenantID, record.WorkspaceID) {
			continue
		}
		if record.Status != "queued" || record.DeadLettered {
			continue
		}
		if normalizedProvider != "" && strings.TrimSpace(record.Provider) != normalizedProvider {
			continue
		}
		count++
	}
	return count, nil
}

// CountQueuedScansAnyScope returns queued scan count across all scopes for one provider.
func (m *MemoryStore) CountQueuedScansAnyScope(_ context.Context, provider string) (int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	normalizedProvider := strings.TrimSpace(provider)
	count := 0
	for _, record := range m.scans {
		if record.Status != "queued" || record.DeadLettered {
			continue
		}
		if normalizedProvider != "" && strings.TrimSpace(record.Provider) != normalizedProvider {
			continue
		}
		count++
	}
	return count, nil
}

func (m *MemoryStore) createScanLocked(scope Scope, provider string, status string, startedAt time.Time) ScanRecord {
	normalizedScope := scope.Normalize()
	record := ScanRecord{
		ID:            uuid.NewString(),
		TenantID:      normalizedScope.TenantID,
		WorkspaceID:   normalizedScope.WorkspaceID,
		Provider:      strings.TrimSpace(provider),
		Status:        strings.TrimSpace(status),
		StartedAt:     startedAt.UTC(),
		MaxRetryCount: DefaultScanMaxRetryCount,
	}
	m.scans[record.ID] = record
	m.scanIDs = append(m.scanIDs, record.ID)
	return record
}

// GetScan returns one persisted scan by id.
func (m *MemoryStore) GetScan(ctx context.Context, scanID string) (ScanRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return ScanRecord{}, err
	}
	record, exists := m.scans[scanID]
	if !exists || !MatchScope(scope, record.TenantID, record.WorkspaceID) {
		return ScanRecord{}, ErrNotFound
	}
	return record, nil
}

// CompleteScan finalizes persisted scan metadata.
func (m *MemoryStore) CompleteScan(ctx context.Context, scanID string, status string, finishedAt time.Time, assetCount int, findingCount int, errorMessage string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return err
	}
	record, exists := m.scans[scanID]
	if !exists || !MatchScope(scope, record.TenantID, record.WorkspaceID) {
		return ErrNotFound
	}
	finished := finishedAt.UTC()
	record.Status = status
	record.FinishedAt = &finished
	record.AssetCount = assetCount
	record.FindingCount = findingCount
	record.ErrorMessage = errorMessage
	record.FailureCategory = ""
	record.NextRetryAt = nil
	record.DeadLettered = false
	record.DeadLetteredAt = nil
	m.scans[scanID] = record
	return nil
}

// ScheduleScanRetry moves a failed scan attempt back to queued state with backoff metadata.
func (m *MemoryStore) ScheduleScanRetry(ctx context.Context, scanID string, queuedAt time.Time, retryCount int, maxRetryCount int, failureCategory string, errorMessage string, nextRetryAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return err
	}
	record, exists := m.scans[scanID]
	if !exists || !MatchScope(scope, record.TenantID, record.WorkspaceID) {
		return ErrNotFound
	}
	record.Status = "queued"
	record.StartedAt = queuedAt.UTC()
	record.FinishedAt = nil
	record.ErrorMessage = errorMessage
	record.RetryCount = retryCount
	record.MaxRetryCount = maxRetryCount
	record.FailureCategory = strings.TrimSpace(failureCategory)
	retryAt := nextRetryAt.UTC()
	record.NextRetryAt = &retryAt
	record.DeadLettered = false
	record.DeadLetteredAt = nil
	m.scans[scanID] = record
	return nil
}

// DeadLetterScan marks a failed queued scan as operator-replayable.
func (m *MemoryStore) DeadLetterScan(ctx context.Context, scanID string, finishedAt time.Time, retryCount int, maxRetryCount int, assetCount int, findingCount int, failureCategory string, errorMessage string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return err
	}
	record, exists := m.scans[scanID]
	if !exists || !MatchScope(scope, record.TenantID, record.WorkspaceID) {
		return ErrNotFound
	}
	finished := finishedAt.UTC()
	record.Status = "failed"
	record.FinishedAt = &finished
	record.ErrorMessage = errorMessage
	record.RetryCount = retryCount
	record.MaxRetryCount = maxRetryCount
	record.AssetCount = assetCount
	record.FindingCount = findingCount
	record.FailureCategory = strings.TrimSpace(failureCategory)
	record.NextRetryAt = nil
	record.DeadLettered = true
	record.DeadLetteredAt = &finished
	m.scans[scanID] = record
	return nil
}

// UpsertFindings persists findings idempotently by scan_id + finding_id.
func (m *MemoryStore) UpsertFindings(ctx context.Context, scanID string, findings []domain.Finding) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return err
	}
	scan, exists := m.scans[scanID]
	if !exists || !MatchScope(scope, scan.TenantID, scan.WorkspaceID) {
		return ErrNotFound
	}

	for _, finding := range findings {
		finding.ScanID = scanID
		key := scanID + "|" + finding.ID
		m.findings[key] = finding
		m.scanFindings[scanID] = appendUniqueID(m.scanFindings[scanID], key)
	}
	return nil
}

// GetFindingTriageState returns triage workflow state for one finding id.
func (m *MemoryStore) GetFindingTriageState(ctx context.Context, findingID string) (FindingTriageState, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return FindingTriageState{}, err
	}
	state, exists := m.triageStates[findingScopeKey(scope, findingID)]
	if !exists {
		return FindingTriageState{}, ErrNotFound
	}
	return state, nil
}

// ListFindingTriageStates returns triage states for provided finding ids.
func (m *MemoryStore) ListFindingTriageStates(ctx context.Context, findingIDs []string) ([]FindingTriageState, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	result := make([]FindingTriageState, 0, len(findingIDs))
	for _, findingID := range findingIDs {
		normalized := strings.TrimSpace(findingID)
		if normalized == "" {
			continue
		}
		if _, exists := seen[normalized]; exists {
			continue
		}
		seen[normalized] = struct{}{}
		state, exists := m.triageStates[findingScopeKey(scope, normalized)]
		if !exists {
			continue
		}
		result = append(result, state)
	}
	return result, nil
}

// UpsertFindingTriageState creates or updates mutable triage metadata.
func (m *MemoryStore) UpsertFindingTriageState(ctx context.Context, state FindingTriageState) error {
	normalized, err := normalizeFindingTriageStateForWrite(state)
	if err != nil {
		return err
	}
	scope, err := RequireScope(ctx)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.triageStates[findingScopeKey(scope, normalized.FindingID)] = normalized
	return nil
}

// AppendFindingTriageEvent records one immutable triage action.
func (m *MemoryStore) AppendFindingTriageEvent(ctx context.Context, event FindingTriageEvent) error {
	normalized, err := normalizeFindingTriageEventForWrite(event)
	if err != nil {
		return err
	}
	scope, err := RequireScope(ctx)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	key := findingScopeKey(scope, normalized.FindingID)
	m.triageEvents[key] = append(m.triageEvents[key], normalized)
	return nil
}

// ApplyFindingTriageTransition persists state and audit history atomically.
func (m *MemoryStore) ApplyFindingTriageTransition(ctx context.Context, state FindingTriageState, event FindingTriageEvent) error {
	normalizedState, err := normalizeFindingTriageStateForWrite(state)
	if err != nil {
		return err
	}
	normalizedEvent, err := normalizeFindingTriageEventForWrite(event)
	if err != nil {
		return err
	}
	if normalizedState.FindingID != normalizedEvent.FindingID {
		return fmt.Errorf("finding id mismatch between state and event")
	}
	scope, err := RequireScope(ctx)
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	key := findingScopeKey(scope, normalizedState.FindingID)
	m.triageStates[key] = normalizedState
	m.triageEvents[key] = append(m.triageEvents[key], normalizedEvent)
	return nil
}

// ListFindingTriageEvents returns triage actions newest-first for one finding id.
func (m *MemoryStore) ListFindingTriageEvents(ctx context.Context, findingID string, limit int) ([]FindingTriageEvent, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return nil, err
	}
	normalizedID := strings.TrimSpace(findingID)
	if normalizedID == "" {
		return nil, ErrNotFound
	}
	events := append([]FindingTriageEvent(nil), m.triageEvents[findingScopeKey(scope, normalizedID)]...)
	sort.Slice(events, func(i, j int) bool {
		return events[i].CreatedAt.After(events[j].CreatedAt)
	})
	if limit > 0 && len(events) > limit {
		events = events[:limit]
	}
	return events, nil
}

// UpsertArtifacts persists raw and normalized scan artifacts idempotently.
func (m *MemoryStore) UpsertArtifacts(ctx context.Context, scanID string, artifacts ScanArtifacts) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return err
	}
	scan, exists := m.scans[scanID]
	if !exists || !MatchScope(scope, scan.TenantID, scan.WorkspaceID) {
		return ErrNotFound
	}

	for _, asset := range artifacts.RawAssets {
		key := scanID + "|" + asset.SourceID + "|" + asset.Kind
		m.rawAssets[key] = asset
	}
	for _, identity := range artifacts.Bundle.Identities {
		key := scanID + "|" + identity.ID
		m.identities[key] = identity
	}
	for _, policy := range artifacts.Bundle.Policies {
		key := scanID + "|" + policy.ID
		m.policies[key] = policy
	}
	for _, relationship := range artifacts.Relationships {
		key := scanID + "|" + relationship.ID
		m.relationships[key] = relationship
	}
	for _, permission := range artifacts.Permissions {
		key := scanID + "|" + permission.IdentityID + "|" + permission.Action + "|" + permission.Resource + "|" + permission.Effect
		m.permissions[key] = permission
	}
	return nil
}

// ListScans returns latest scans first.
func (m *MemoryStore) ListScans(ctx context.Context, limit int) ([]ScanRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if limit <= 0 {
		limit = 100
	}
	scope, err := RequireScope(ctx)
	if err != nil {
		return nil, err
	}
	records := make([]ScanRecord, 0, len(m.scanIDs))
	for _, scanID := range m.scanIDs {
		record := m.scans[scanID]
		if !MatchScope(scope, record.TenantID, record.WorkspaceID) {
			continue
		}
		records = append(records, record)
	}
	sort.Slice(records, func(i, j int) bool {
		return records[i].StartedAt.After(records[j].StartedAt)
	})
	if len(records) > limit {
		records = records[:limit]
	}
	return records, nil
}

// ListFindings returns latest findings first.
func (m *MemoryStore) ListFindings(ctx context.Context, limit int) ([]domain.Finding, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if limit <= 0 {
		limit = 100
	}
	scope, err := RequireScope(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]domain.Finding, 0, len(m.findings))
	for _, finding := range m.findings {
		scan, exists := m.scans[finding.ScanID]
		if !exists || !MatchScope(scope, scan.TenantID, scan.WorkspaceID) {
			continue
		}
		result = append(result, finding)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].CreatedAt.After(result[j].CreatedAt)
	})
	if len(result) > limit {
		result = result[:limit]
	}
	return result, nil
}

// ListFindingsFiltered returns findings after applying persistence-level filters and stable ordering.
func (m *MemoryStore) ListFindingsFiltered(ctx context.Context, filter FindingListFilter) ([]domain.Finding, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return nil, err
	}
	normalized := NormalizeFindingListFilter(filter)
	if normalized.ScanID != "" {
		scan, exists := m.scans[normalized.ScanID]
		if !exists || !MatchScope(scope, scan.TenantID, scan.WorkspaceID) {
			return nil, ErrNotFound
		}
	}
	now := normalized.Now
	result := make([]domain.Finding, 0, len(m.findings))
	for _, finding := range m.findings {
		scan, exists := m.scans[finding.ScanID]
		if !exists || !MatchScope(scope, scan.TenantID, scan.WorkspaceID) {
			continue
		}
		if normalized.ScanID != "" && finding.ScanID != normalized.ScanID {
			continue
		}
		if normalized.FindingID != "" && finding.ID != normalized.FindingID {
			continue
		}
		if normalized.Severity != "" && strings.ToLower(string(finding.Severity)) != normalized.Severity {
			continue
		}
		if normalized.Type != "" && strings.ToLower(string(finding.Type)) != normalized.Type {
			continue
		}
		finding.Triage = m.findingTriageForScopeLocked(scope, finding.ID, now)
		if normalized.LifecycleStatus != "" && strings.ToLower(string(finding.Triage.Status)) != normalized.LifecycleStatus {
			continue
		}
		if normalized.Assignee != "" && strings.ToLower(strings.TrimSpace(finding.Triage.Assignee)) != normalized.Assignee {
			continue
		}
		result = append(result, finding)
	}
	sortFilteredFindings(result, normalized.SortBy, normalized.SortDesc)
	if normalized.Offset >= len(result) {
		return []domain.Finding{}, nil
	}
	end := normalized.Offset + normalized.Limit + 1
	if end > len(result) {
		end = len(result)
	}
	return append([]domain.Finding(nil), result[normalized.Offset:end]...), nil
}

// ListFindingsAll returns all findings for current scope ordered by recency.
func (m *MemoryStore) ListFindingsAll(ctx context.Context) ([]domain.Finding, error) {
	return m.ListFindings(ctx, 0)
}

// SummarizeFindings returns aggregate counters for current scope without materializing router-facing copies.
func (m *MemoryStore) SummarizeFindings(ctx context.Context) (FindingSummaryCounts, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return FindingSummaryCounts{}, err
	}
	summary := FindingSummaryCounts{
		BySeverity: map[string]int{},
		ByType:     map[string]int{},
	}
	for _, finding := range m.findings {
		record, exists := m.scans[finding.ScanID]
		if !exists || !MatchScope(scope, record.TenantID, record.WorkspaceID) {
			continue
		}
		summary.Total++
		summary.BySeverity[string(finding.Severity)]++
		summary.ByType[string(finding.Type)]++
	}
	return summary, nil
}

// ListFindingsByScan returns latest findings first for one scan.
func (m *MemoryStore) ListFindingsByScan(ctx context.Context, scanID string, limit int) ([]domain.Finding, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if limit <= 0 {
		limit = 100
	}
	scope, err := RequireScope(ctx)
	if err != nil {
		return nil, err
	}
	scan, exists := m.scans[scanID]
	if !exists || !MatchScope(scope, scan.TenantID, scan.WorkspaceID) {
		return nil, ErrNotFound
	}

	keys := m.scanFindings[scanID]
	result := make([]domain.Finding, 0, len(keys))
	for _, key := range keys {
		finding, exists := m.findings[key]
		if !exists {
			continue
		}
		result = append(result, finding)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].CreatedAt.After(result[j].CreatedAt)
	})
	if len(result) > limit {
		result = result[:limit]
	}
	return result, nil
}

func (m *MemoryStore) findingTriageForScopeLocked(scope Scope, findingID string, now time.Time) domain.FindingTriage {
	triage := domain.DefaultFindingTriage()
	state, exists := m.triageStates[findingScopeKey(scope, strings.TrimSpace(findingID))]
	if !exists {
		return triage
	}
	updatedAt := state.UpdatedAt.UTC()
	triage = domain.FindingTriage{
		Status:               state.Status,
		Assignee:             state.Assignee,
		SuppressionExpiresAt: state.SuppressionExpiresAt,
		ResolvedAt:           state.ResolvedAt,
		UpdatedAt:            &updatedAt,
		UpdatedBy:            state.UpdatedBy,
	}
	return NormalizeFindingTriage(triage, now)
}

func sortFilteredFindings(items []domain.Finding, sortBy string, desc bool) {
	sort.SliceStable(items, func(i, j int) bool {
		left := items[i]
		right := items[j]
		var cmp int
		switch sortBy {
		case "severity":
			cmp = compareFindingInts(findingSeverityOrder(left.Severity), findingSeverityOrder(right.Severity))
		case "type":
			cmp = compareFindingStrings(strings.ToLower(string(left.Type)), strings.ToLower(string(right.Type)))
		case "title":
			cmp = compareFindingStrings(strings.ToLower(left.Title), strings.ToLower(right.Title))
		default:
			cmp = compareFindingTimes(left.CreatedAt, right.CreatedAt)
		}
		if cmp == 0 {
			cmp = compareFindingStrings(left.ScanID, right.ScanID)
		}
		if cmp == 0 {
			cmp = compareFindingStrings(left.ID, right.ID)
		}
		if desc {
			return cmp > 0
		}
		return cmp < 0
	})
}

func findingSeverityOrder(severity domain.FindingSeverity) int {
	switch severity {
	case domain.SeverityCritical:
		return 5
	case domain.SeverityHigh:
		return 4
	case domain.SeverityMedium:
		return 3
	case domain.SeverityLow:
		return 2
	case domain.SeverityInfo:
		return 1
	default:
		return 0
	}
}

func compareFindingStrings(left string, right string) int {
	switch {
	case left < right:
		return -1
	case left > right:
		return 1
	default:
		return 0
	}
}

func compareFindingInts(left int, right int) int {
	switch {
	case left < right:
		return -1
	case left > right:
		return 1
	default:
		return 0
	}
}

func compareFindingTimes(left time.Time, right time.Time) int {
	switch {
	case left.Before(right):
		return -1
	case left.After(right):
		return 1
	default:
		return 0
	}
}

// GetFinding returns one finding by id, optionally scoped to one scan id.
func (m *MemoryStore) GetFinding(ctx context.Context, findingID string, scanID string) (domain.Finding, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return domain.Finding{}, err
	}
	id := strings.TrimSpace(findingID)
	if id == "" {
		return domain.Finding{}, ErrNotFound
	}
	scanFilter := strings.TrimSpace(scanID)
	var latest domain.Finding
	found := false
	for _, scanKey := range m.scanIDs {
		record := m.scans[scanKey]
		if !MatchScope(scope, record.TenantID, record.WorkspaceID) {
			continue
		}
		if scanFilter != "" && scanKey != scanFilter {
			continue
		}
		findingKey := scanKey + "|" + id
		finding, exists := m.findings[findingKey]
		if !exists {
			continue
		}
		if scanFilter != "" {
			return finding, nil
		}
		if !found || finding.CreatedAt.After(latest.CreatedAt) {
			latest = finding
			found = true
		}
	}
	if found {
		return latest, nil
	}
	return domain.Finding{}, ErrNotFound
}

// ListFindingMetasByScan returns lightweight finding metadata for one scan.
func (m *MemoryStore) ListFindingMetasByScan(ctx context.Context, scanID string) ([]FindingMeta, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return nil, err
	}
	scan, exists := m.scans[scanID]
	if !exists || !MatchScope(scope, scan.TenantID, scan.WorkspaceID) {
		return nil, ErrNotFound
	}
	keys := m.scanFindings[scanID]
	metas := make([]FindingMeta, 0, len(keys))
	for _, key := range keys {
		finding, exists := m.findings[key]
		if !exists {
			continue
		}
		metas = append(metas, FindingMeta{
			ID:        finding.ID,
			ScanID:    finding.ScanID,
			Severity:  string(finding.Severity),
			Type:      string(finding.Type),
			CreatedAt: finding.CreatedAt,
		})
	}
	return metas, nil
}

// ListFindingsByScanAndIDs returns detailed findings for one scan and ID set.
func (m *MemoryStore) ListFindingsByScanAndIDs(ctx context.Context, scanID string, findingIDs []string) ([]domain.Finding, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return nil, err
	}
	scan, exists := m.scans[scanID]
	if !exists || !MatchScope(scope, scan.TenantID, scan.WorkspaceID) {
		return nil, ErrNotFound
	}
	result := make([]domain.Finding, 0, len(findingIDs))
	seen := map[string]struct{}{}
	for _, findingID := range findingIDs {
		normalizedID := strings.TrimSpace(findingID)
		if normalizedID == "" {
			continue
		}
		if _, exists := seen[normalizedID]; exists {
			continue
		}
		seen[normalizedID] = struct{}{}
		finding, exists := m.findings[scanID+"|"+normalizedID]
		if !exists {
			continue
		}
		result = append(result, finding)
	}
	return result, nil
}

// ListFindingTrendCounts aggregates findings by scan and severity.
func (m *MemoryStore) ListFindingTrendCounts(ctx context.Context, scanIDs []string, severity string, findingType string) ([]FindingTrendCount, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return nil, err
	}
	normalizedSeverity := strings.ToLower(strings.TrimSpace(severity))
	normalizedType := strings.ToLower(strings.TrimSpace(findingType))
	result := make([]FindingTrendCount, 0, len(scanIDs))
	for _, scanID := range scanIDs {
		scan, exists := m.scans[scanID]
		if !exists || !MatchScope(scope, scan.TenantID, scan.WorkspaceID) {
			continue
		}
		counts := map[string]int{}
		for _, key := range m.scanFindings[scanID] {
			finding, exists := m.findings[key]
			if !exists {
				continue
			}
			if normalizedSeverity != "" && strings.ToLower(string(finding.Severity)) != normalizedSeverity {
				continue
			}
			if normalizedType != "" && strings.ToLower(string(finding.Type)) != normalizedType {
				continue
			}
			counts[string(finding.Severity)]++
		}
		if len(counts) == 0 {
			result = append(result, FindingTrendCount{ScanID: scanID, StartedAt: scan.StartedAt})
			continue
		}
		for severityKey, count := range counts {
			result = append(result, FindingTrendCount{
				ScanID:     scanID,
				StartedAt:  scan.StartedAt,
				Severity:   severityKey,
				TotalCount: count,
			})
		}
	}
	return result, nil
}

// ListRepoFindingTrendCounts aggregates repository finding totals by repo scan and severity.
func (m *MemoryStore) ListRepoFindingTrendCounts(ctx context.Context, repoScanIDs []string, severity string, findingType string) ([]FindingTrendCount, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return nil, err
	}
	normalizedSeverity := strings.ToLower(strings.TrimSpace(severity))
	normalizedType := strings.ToLower(strings.TrimSpace(findingType))

	unique := make([]string, 0, len(repoScanIDs))
	seen := map[string]struct{}{}
	for _, repoScanID := range repoScanIDs {
		normalized := strings.TrimSpace(repoScanID)
		if normalized == "" {
			continue
		}
		if _, exists := seen[normalized]; exists {
			continue
		}
		seen[normalized] = struct{}{}
		repoScan, exists := m.repoScans[normalized]
		if !exists || !MatchScope(scope, repoScan.TenantID, repoScan.WorkspaceID) {
			continue
		}
		unique = append(unique, normalized)
	}

	result := make([]FindingTrendCount, 0, len(unique))
	for _, repoScanID := range unique {
		repoScan, exists := m.repoScans[repoScanID]
		if !exists {
			continue
		}
		counts := map[string]int{}
		for _, key := range m.repoFindingIDs[repoScanID] {
			finding, exists := m.repoFindings[key]
			if !exists {
				continue
			}
			if normalizedSeverity != "" && strings.ToLower(string(finding.Severity)) != normalizedSeverity {
				continue
			}
			if normalizedType != "" && strings.ToLower(string(finding.Type)) != normalizedType {
				continue
			}
			counts[string(finding.Severity)]++
		}
		if len(counts) == 0 {
			result = append(result, FindingTrendCount{ScanID: repoScanID, StartedAt: repoScan.StartedAt})
			continue
		}
		for severityKey, count := range counts {
			result = append(result, FindingTrendCount{
				ScanID:     repoScanID,
				StartedAt:  repoScan.StartedAt,
				Severity:   severityKey,
				TotalCount: count,
			})
		}
	}

	return result, nil
}

// UpsertAuthzEntityAttributes creates or updates trusted authorization attributes.
func (m *MemoryStore) UpsertAuthzEntityAttributes(ctx context.Context, attributes AuthzEntityAttributes) error {
	normalized, err := NormalizeAuthzEntityAttributesForWrite(attributes)
	if err != nil {
		return err
	}
	scope, err := RequireScope(ctx)
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	scoped := scope.Normalize()
	normalized.TenantID = scoped.TenantID
	normalized.WorkspaceID = scoped.WorkspaceID
	m.authzAttrs[authzEntityScopeKey(scoped, normalized.EntityKind, normalized.EntityType, normalized.EntityID)] = normalized
	return nil
}

// GetAuthzEntityAttributes returns trusted authorization attributes for one entity.
func (m *MemoryStore) GetAuthzEntityAttributes(ctx context.Context, entityKind string, entityType string, entityID string) (AuthzEntityAttributes, error) {
	scope, err := RequireScope(ctx)
	if err != nil {
		return AuthzEntityAttributes{}, err
	}
	lookup, err := NormalizeAuthzEntityAttributesForWrite(AuthzEntityAttributes{
		EntityKind: entityKind,
		EntityType: entityType,
		EntityID:   entityID,
	})
	if err != nil {
		return AuthzEntityAttributes{}, err
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	scoped := scope.Normalize()
	record, exists := m.authzAttrs[authzEntityScopeKey(scoped, lookup.EntityKind, lookup.EntityType, lookup.EntityID)]
	if !exists {
		return AuthzEntityAttributes{}, ErrNotFound
	}
	return record, nil
}

// UpsertAuthzRelationship creates or updates one scoped ReBAC tuple.
func (m *MemoryStore) UpsertAuthzRelationship(ctx context.Context, relationship AuthzRelationship) error {
	normalized, err := NormalizeAuthzRelationshipForWrite(relationship)
	if err != nil {
		return err
	}
	scope, err := RequireScope(ctx)
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	scoped := scope.Normalize()
	normalized.TenantID = scoped.TenantID
	normalized.WorkspaceID = scoped.WorkspaceID
	key := authzRelationshipScopeKey(scoped, normalized.SubjectType, normalized.SubjectID, normalized.Relation, normalized.ObjectType, normalized.ObjectID)
	if existing, exists := m.authzRels[key]; exists {
		normalized.CreatedAt = existing.CreatedAt
	}
	m.authzRels[key] = normalized
	return nil
}

// DeleteAuthzRelationship removes one scoped ReBAC tuple.
func (m *MemoryStore) DeleteAuthzRelationship(ctx context.Context, relationship AuthzRelationship) error {
	normalized, err := NormalizeAuthzRelationshipForWrite(relationship)
	if err != nil {
		return err
	}
	scope, err := RequireScope(ctx)
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	scoped := scope.Normalize()
	key := authzRelationshipScopeKey(scoped, normalized.SubjectType, normalized.SubjectID, normalized.Relation, normalized.ObjectType, normalized.ObjectID)
	if _, exists := m.authzRels[key]; !exists {
		return ErrNotFound
	}
	delete(m.authzRels, key)
	return nil
}

// ListAuthzRelationships returns filtered scoped ReBAC tuples.
func (m *MemoryStore) ListAuthzRelationships(ctx context.Context, filter AuthzRelationshipFilter, limit int) ([]AuthzRelationship, error) {
	scope, err := RequireScope(ctx)
	if err != nil {
		return nil, err
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	normalizedScope := scope.Normalize()
	subjectType := strings.ToLower(strings.TrimSpace(filter.SubjectType))
	subjectID := strings.TrimSpace(filter.SubjectID)
	relation := strings.ToLower(strings.TrimSpace(filter.Relation))
	if relation != "" {
		if _, ok := validAuthzRelationships[relation]; !ok {
			return nil, fmt.Errorf("invalid relation value")
		}
	}
	objectType := strings.ToLower(strings.TrimSpace(filter.ObjectType))
	objectID := strings.TrimSpace(filter.ObjectID)
	now := time.Now().UTC()

	records := make([]AuthzRelationship, 0, len(m.authzRels))
	for _, relationship := range m.authzRels {
		if !MatchScope(normalizedScope, relationship.TenantID, relationship.WorkspaceID) {
			continue
		}
		if subjectType != "" && relationship.SubjectType != subjectType {
			continue
		}
		if subjectID != "" && relationship.SubjectID != subjectID {
			continue
		}
		if relation != "" && relationship.Relation != relation {
			continue
		}
		if objectType != "" && relationship.ObjectType != objectType {
			continue
		}
		if objectID != "" && relationship.ObjectID != objectID {
			continue
		}
		if !filter.IncludeExpired && relationship.ExpiresAt != nil && !relationship.ExpiresAt.After(now) {
			continue
		}
		records = append(records, relationship)
	}

	sort.Slice(records, func(i, j int) bool {
		left := records[i]
		right := records[j]
		if left.SubjectType != right.SubjectType {
			return left.SubjectType < right.SubjectType
		}
		if left.SubjectID != right.SubjectID {
			return left.SubjectID < right.SubjectID
		}
		if left.Relation != right.Relation {
			return left.Relation < right.Relation
		}
		if left.ObjectType != right.ObjectType {
			return left.ObjectType < right.ObjectType
		}
		if left.ObjectID != right.ObjectID {
			return left.ObjectID < right.ObjectID
		}
		return left.UpdatedAt.After(right.UpdatedAt)
	})
	if limit > 0 && len(records) > limit {
		records = records[:limit]
	}
	return records, nil
}

// UpsertAuthzPolicySet creates or updates one scoped policy set metadata record.
func (m *MemoryStore) UpsertAuthzPolicySet(ctx context.Context, policySet AuthzPolicySet) error {
	normalized, err := NormalizeAuthzPolicySetForWrite(policySet)
	if err != nil {
		return err
	}
	scope, err := RequireScope(ctx)
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	scoped := scope.Normalize()
	normalized.TenantID = scoped.TenantID
	normalized.WorkspaceID = scoped.WorkspaceID
	key := authzPolicySetScopeKey(scoped, normalized.PolicySetID)
	if existing, exists := m.authzSets[key]; exists {
		normalized.CreatedAt = existing.CreatedAt
		normalized.CreatedBy = existing.CreatedBy
	}
	m.authzSets[key] = normalized
	return nil
}

// GetAuthzPolicySet returns one scoped policy set metadata record.
func (m *MemoryStore) GetAuthzPolicySet(ctx context.Context, policySetID string) (AuthzPolicySet, error) {
	scope, err := RequireScope(ctx)
	if err != nil {
		return AuthzPolicySet{}, err
	}
	normalizedPolicySetID, err := normalizeAuthzPolicySetID(policySetID)
	if err != nil {
		return AuthzPolicySet{}, err
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	scoped := scope.Normalize()
	record, exists := m.authzSets[authzPolicySetScopeKey(scoped, normalizedPolicySetID)]
	if !exists {
		return AuthzPolicySet{}, ErrNotFound
	}
	return record, nil
}

// CreateAuthzPolicyVersion persists one immutable policy bundle version.
func (m *MemoryStore) CreateAuthzPolicyVersion(ctx context.Context, version AuthzPolicyVersion) (AuthzPolicyVersion, error) {
	scope, err := RequireScope(ctx)
	if err != nil {
		return AuthzPolicyVersion{}, err
	}
	scoped := scope.Normalize()
	policySetID, err := normalizeAuthzPolicySetID(version.PolicySetID)
	if err != nil {
		return AuthzPolicyVersion{}, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.authzSets[authzPolicySetScopeKey(scoped, policySetID)]; !exists {
		return AuthzPolicyVersion{}, ErrNotFound
	}
	if version.Version <= 0 {
		nextVersion := 1
		for _, candidate := range m.authzVersions {
			if !MatchScope(scoped, candidate.TenantID, candidate.WorkspaceID) {
				continue
			}
			if candidate.PolicySetID != policySetID {
				continue
			}
			if candidate.Version >= nextVersion {
				nextVersion = candidate.Version + 1
			}
		}
		version.Version = nextVersion
	}

	normalized, err := NormalizeAuthzPolicyVersionForWrite(version)
	if err != nil {
		return AuthzPolicyVersion{}, err
	}
	normalized.TenantID = scoped.TenantID
	normalized.WorkspaceID = scoped.WorkspaceID

	key := authzPolicyVersionScopeKey(scoped, normalized.PolicySetID, normalized.Version)
	if _, exists := m.authzVersions[key]; exists {
		return AuthzPolicyVersion{}, fmt.Errorf("authz policy version already exists")
	}
	m.authzVersions[key] = normalized
	return normalized, nil
}

// GetAuthzPolicyVersion returns one scoped immutable policy bundle version.
func (m *MemoryStore) GetAuthzPolicyVersion(ctx context.Context, policySetID string, version int) (AuthzPolicyVersion, error) {
	scope, err := RequireScope(ctx)
	if err != nil {
		return AuthzPolicyVersion{}, err
	}
	normalizedPolicySetID, err := normalizeAuthzPolicySetID(policySetID)
	if err != nil {
		return AuthzPolicyVersion{}, err
	}
	if version <= 0 {
		return AuthzPolicyVersion{}, fmt.Errorf("version must be greater than zero")
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	scoped := scope.Normalize()
	record, exists := m.authzVersions[authzPolicyVersionScopeKey(scoped, normalizedPolicySetID, version)]
	if !exists {
		return AuthzPolicyVersion{}, ErrNotFound
	}
	return record, nil
}

// ListAuthzPolicyVersions returns policy bundle versions for one policy set (newest first).
func (m *MemoryStore) ListAuthzPolicyVersions(ctx context.Context, policySetID string, limit int) ([]AuthzPolicyVersion, error) {
	scope, err := RequireScope(ctx)
	if err != nil {
		return nil, err
	}
	normalizedPolicySetID, err := normalizeAuthzPolicySetID(policySetID)
	if err != nil {
		return nil, err
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	scoped := scope.Normalize()
	records := make([]AuthzPolicyVersion, 0)
	for _, version := range m.authzVersions {
		if !MatchScope(scoped, version.TenantID, version.WorkspaceID) {
			continue
		}
		if version.PolicySetID != normalizedPolicySetID {
			continue
		}
		records = append(records, version)
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].Version != records[j].Version {
			return records[i].Version > records[j].Version
		}
		return records[i].CreatedAt.After(records[j].CreatedAt)
	})
	if limit > 0 && len(records) > limit {
		records = records[:limit]
	}
	return records, nil
}

// UpsertAuthzPolicyRollout creates or updates one scoped rollout pointer row.
func (m *MemoryStore) UpsertAuthzPolicyRollout(ctx context.Context, rollout AuthzPolicyRollout) error {
	normalized, err := NormalizeAuthzPolicyRolloutForWrite(rollout)
	if err != nil {
		return err
	}
	scope, err := RequireScope(ctx)
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	scoped := scope.Normalize()
	if _, exists := m.authzSets[authzPolicySetScopeKey(scoped, normalized.PolicySetID)]; !exists {
		return ErrNotFound
	}
	if normalized.ActiveVersion != nil {
		if _, exists := m.authzVersions[authzPolicyVersionScopeKey(scoped, normalized.PolicySetID, *normalized.ActiveVersion)]; !exists {
			return ErrNotFound
		}
	}
	if normalized.CandidateVersion != nil {
		if _, exists := m.authzVersions[authzPolicyVersionScopeKey(scoped, normalized.PolicySetID, *normalized.CandidateVersion)]; !exists {
			return ErrNotFound
		}
	}

	normalized.TenantID = scoped.TenantID
	normalized.WorkspaceID = scoped.WorkspaceID
	normalized.TenantAllowlist = append([]string(nil), normalized.TenantAllowlist...)
	normalized.WorkspaceAllowlist = append([]string(nil), normalized.WorkspaceAllowlist...)
	normalized.ValidatedVersions = append([]int(nil), normalized.ValidatedVersions...)
	m.authzRollouts[authzPolicySetScopeKey(scoped, normalized.PolicySetID)] = normalized
	return nil
}

// GetAuthzPolicyRollout returns one scoped rollout pointer row.
func (m *MemoryStore) GetAuthzPolicyRollout(ctx context.Context, policySetID string) (AuthzPolicyRollout, error) {
	scope, err := RequireScope(ctx)
	if err != nil {
		return AuthzPolicyRollout{}, err
	}
	normalizedPolicySetID, err := normalizeAuthzPolicySetID(policySetID)
	if err != nil {
		return AuthzPolicyRollout{}, err
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	scoped := scope.Normalize()
	record, exists := m.authzRollouts[authzPolicySetScopeKey(scoped, normalizedPolicySetID)]
	if !exists {
		return AuthzPolicyRollout{}, ErrNotFound
	}
	record.TenantAllowlist = append([]string(nil), record.TenantAllowlist...)
	record.WorkspaceAllowlist = append([]string(nil), record.WorkspaceAllowlist...)
	record.ValidatedVersions = append([]int(nil), record.ValidatedVersions...)
	return record, nil
}

// AppendAuthzPolicyEvent records one immutable policy lifecycle event.
func (m *MemoryStore) AppendAuthzPolicyEvent(ctx context.Context, event AuthzPolicyEvent) error {
	normalized, err := NormalizeAuthzPolicyEventForWrite(event)
	if err != nil {
		return err
	}
	scope, err := RequireScope(ctx)
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	scoped := scope.Normalize()
	if _, exists := m.authzSets[authzPolicySetScopeKey(scoped, normalized.PolicySetID)]; !exists {
		return ErrNotFound
	}
	if normalized.ID == "" {
		normalized.ID = uuid.NewString()
	}
	if _, exists := m.authzEventIDs[normalized.ID]; exists {
		return fmt.Errorf("authz policy event already exists")
	}

	normalized.TenantID = scoped.TenantID
	normalized.WorkspaceID = scoped.WorkspaceID
	key := authzPolicyEventsScopeKey(scoped, normalized.PolicySetID)
	m.authzEvents[key] = append(m.authzEvents[key], normalized)
	m.authzEventIDs[normalized.ID] = struct{}{}
	return nil
}

// ListAuthzPolicyEvents returns immutable lifecycle events for one policy set (newest first).
func (m *MemoryStore) ListAuthzPolicyEvents(ctx context.Context, policySetID string, limit int) ([]AuthzPolicyEvent, error) {
	scope, err := RequireScope(ctx)
	if err != nil {
		return nil, err
	}
	normalizedPolicySetID, err := normalizeAuthzPolicySetID(policySetID)
	if err != nil {
		return nil, err
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	scoped := scope.Normalize()
	events := append([]AuthzPolicyEvent(nil), m.authzEvents[authzPolicyEventsScopeKey(scoped, normalizedPolicySetID)]...)
	sort.Slice(events, func(i, j int) bool {
		return events[i].CreatedAt.After(events[j].CreatedAt)
	})
	if limit > 0 && len(events) > limit {
		events = events[:limit]
	}
	return events, nil
}

// ListIdentities returns identities filtered by scan/provider/type/name.
func (m *MemoryStore) ListIdentities(ctx context.Context, filter IdentityFilter, limit int) ([]domain.Identity, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return nil, err
	}
	filteredScanID := strings.TrimSpace(filter.ScanID)
	if filteredScanID != "" {
		scan, exists := m.scans[filteredScanID]
		if !exists || !MatchScope(scope, scan.TenantID, scan.WorkspaceID) {
			return nil, ErrNotFound
		}
	}

	namePrefix := strings.ToLower(strings.TrimSpace(filter.NamePrefix))
	provider := strings.ToLower(strings.TrimSpace(filter.Provider))
	identityType := strings.ToLower(strings.TrimSpace(filter.Type))
	result := []domain.Identity{}
	for key, identity := range m.identities {
		scanID := scanKeyPrefix(key)
		scan, exists := m.scans[scanID]
		if !exists || !MatchScope(scope, scan.TenantID, scan.WorkspaceID) {
			continue
		}
		if filteredScanID != "" && scanID != filteredScanID {
			continue
		}
		if provider != "" && strings.ToLower(string(identity.Provider)) != provider {
			continue
		}
		if identityType != "" && strings.ToLower(string(identity.Type)) != identityType {
			continue
		}
		if namePrefix != "" && !strings.HasPrefix(strings.ToLower(identity.Name), namePrefix) {
			continue
		}
		result = append(result, identity)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	if limit > 0 && len(result) > limit {
		result = result[:limit]
	}
	return result, nil
}

// ListRelationships returns relationships filtered by scan/type/from/to.
func (m *MemoryStore) ListRelationships(ctx context.Context, filter RelationshipFilter, limit int) ([]domain.Relationship, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return nil, err
	}
	filteredScanID := strings.TrimSpace(filter.ScanID)
	if filteredScanID != "" {
		scan, exists := m.scans[filteredScanID]
		if !exists || !MatchScope(scope, scan.TenantID, scan.WorkspaceID) {
			return nil, ErrNotFound
		}
	}
	relType := strings.ToLower(strings.TrimSpace(filter.Type))
	fromNode := strings.TrimSpace(filter.FromNodeID)
	toNode := strings.TrimSpace(filter.ToNodeID)

	result := []domain.Relationship{}
	for key, relationship := range m.relationships {
		scanID := scanKeyPrefix(key)
		scan, exists := m.scans[scanID]
		if !exists || !MatchScope(scope, scan.TenantID, scan.WorkspaceID) {
			continue
		}
		if filteredScanID != "" && scanID != filteredScanID {
			continue
		}
		if relType != "" && strings.ToLower(string(relationship.Type)) != relType {
			continue
		}
		if fromNode != "" && relationship.FromNodeID != fromNode {
			continue
		}
		if toNode != "" && relationship.ToNodeID != toNode {
			continue
		}
		result = append(result, relationship)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].DiscoveredAt.After(result[j].DiscoveredAt) })
	if limit > 0 && len(result) > limit {
		result = result[:limit]
	}
	return result, nil
}

// AppendScanEvent appends one scan event entry.
func (m *MemoryStore) AppendScanEvent(ctx context.Context, scanID string, level string, message string, metadata map[string]any) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return err
	}
	scan, exists := m.scans[scanID]
	if !exists || !MatchScope(scope, scan.TenantID, scan.WorkspaceID) {
		return ErrNotFound
	}
	normalizedLevel, err := NormalizeScanEventLevel(strings.ToLower(strings.TrimSpace(level)))
	if err != nil {
		return err
	}
	m.events[scanID] = append(m.events[scanID], ScanEvent{
		ID:        uuid.NewString(),
		ScanID:    scanID,
		Level:     normalizedLevel,
		Message:   message,
		Metadata:  metadata,
		CreatedAt: time.Now().UTC(),
	})
	return nil
}

// ListScanEvents returns most recent scan events first.
func (m *MemoryStore) ListScanEvents(ctx context.Context, scanID string, limit int) ([]ScanEvent, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return nil, err
	}
	scan, exists := m.scans[scanID]
	if !exists || !MatchScope(scope, scan.TenantID, scan.WorkspaceID) {
		return nil, ErrNotFound
	}
	events := append([]ScanEvent(nil), m.events[scanID]...)
	sort.Slice(events, func(i, j int) bool {
		return events[i].CreatedAt.After(events[j].CreatedAt)
	})
	if limit > 0 && len(events) > limit {
		events = events[:limit]
	}
	return events, nil
}

func scanKeyPrefix(key string) string {
	parts := strings.SplitN(key, "|", 2)
	if len(parts) != 2 {
		return ""
	}
	return parts[0]
}

func findingScopeKey(scope Scope, findingID string) string {
	normalized := scope.Normalize()
	return normalized.TenantID + "|" + normalized.WorkspaceID + "|" + strings.TrimSpace(findingID)
}

func authzEntityScopeKey(scope Scope, entityKind string, entityType string, entityID string) string {
	normalized := scope.Normalize()
	return normalized.TenantID + "|" + normalized.WorkspaceID + "|" + strings.ToLower(strings.TrimSpace(entityKind)) + "|" + strings.ToLower(strings.TrimSpace(entityType)) + "|" + strings.TrimSpace(entityID)
}

func authzRelationshipScopeKey(scope Scope, subjectType string, subjectID string, relation string, objectType string, objectID string) string {
	normalized := scope.Normalize()
	return normalized.TenantID + "|" + normalized.WorkspaceID + "|" + strings.ToLower(strings.TrimSpace(subjectType)) + "|" + strings.TrimSpace(subjectID) + "|" + strings.ToLower(strings.TrimSpace(relation)) + "|" + strings.ToLower(strings.TrimSpace(objectType)) + "|" + strings.TrimSpace(objectID)
}

func authzPolicySetScopeKey(scope Scope, policySetID string) string {
	normalized := scope.Normalize()
	return normalized.TenantID + "|" + normalized.WorkspaceID + "|" + strings.ToLower(strings.TrimSpace(policySetID))
}

func authzPolicyVersionScopeKey(scope Scope, policySetID string, version int) string {
	return fmt.Sprintf("%s|%d", authzPolicySetScopeKey(scope, policySetID), version)
}

func authzPolicyEventsScopeKey(scope Scope, policySetID string) string {
	return authzPolicySetScopeKey(scope, policySetID)
}

func normalizeFindingTriageStateForWrite(state FindingTriageState) (FindingTriageState, error) {
	normalizedID := strings.TrimSpace(state.FindingID)
	if normalizedID == "" {
		return FindingTriageState{}, fmt.Errorf("finding id is required")
	}
	state.FindingID = normalizedID
	state.Assignee = strings.TrimSpace(state.Assignee)
	state.UpdatedBy = strings.TrimSpace(state.UpdatedBy)
	state.ResolvedAt = resolvedAtForStatus(state.Status, state.ResolvedAt)
	if state.UpdatedAt.IsZero() {
		state.UpdatedAt = time.Now().UTC()
	} else {
		state.UpdatedAt = state.UpdatedAt.UTC()
	}
	return state, nil
}

func normalizeFindingTriageEventForWrite(event FindingTriageEvent) (FindingTriageEvent, error) {
	normalizedID := strings.TrimSpace(event.FindingID)
	if normalizedID == "" {
		return FindingTriageEvent{}, fmt.Errorf("finding id is required")
	}
	if strings.TrimSpace(event.ID) == "" {
		event.ID = uuid.NewString()
	}
	event.FindingID = normalizedID
	event.Action = strings.TrimSpace(event.Action)
	event.Assignee = strings.TrimSpace(event.Assignee)
	event.Comment = strings.TrimSpace(event.Comment)
	event.Actor = strings.TrimSpace(event.Actor)
	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now().UTC()
	} else {
		event.CreatedAt = event.CreatedAt.UTC()
	}
	return event, nil
}

// CreateRepoScan persists one repository exposure scan start event.
func (m *MemoryStore) CreateRepoScan(ctx context.Context, repository string, source RepoScanSource, startedAt time.Time) (RepoScanRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return RepoScanRecord{}, err
	}
	return m.createRepoScanLocked(scope, strings.TrimSpace(repository), source, "running", 0, 0, startedAt), nil
}

// CreateQueuedRepoScan persists one queued repository exposure scan request.
func (m *MemoryStore) CreateQueuedRepoScan(ctx context.Context, repository string, source RepoScanSource, historyLimit int, maxFindings int, queuedAt time.Time) (RepoScanRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return RepoScanRecord{}, err
	}
	record := m.createRepoScanLocked(scope, strings.TrimSpace(repository), source, "queued", historyLimit, maxFindings, queuedAt)
	record.TraceParent, record.TraceState = QueueTraceContextFromContext(ctx)
	m.repoScans[record.ID] = record
	return record, nil
}

// CreateQueuedRepoScanWithinLimit persists one queued repository scan only when the target is idle and queue capacity remains.
func (m *MemoryStore) CreateQueuedRepoScanWithinLimit(ctx context.Context, repository string, source RepoScanSource, historyLimit int, maxFindings int, queuedAt time.Time, maxPending int) (RepoScanRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return RepoScanRecord{}, err
	}
	if maxPending <= 0 {
		maxPending = 1
	}
	normalizedRepository := strings.TrimSpace(repository)
	queued := 0
	for _, record := range m.repoScans {
		if !MatchScope(scope, record.TenantID, record.WorkspaceID) {
			continue
		}
		if strings.EqualFold(record.Repository, normalizedRepository) && (record.Status == "queued" || record.Status == "running") {
			return RepoScanRecord{}, ErrPendingRepoScanExists
		}
		if record.Status == "queued" {
			queued++
		}
	}
	if queued >= maxPending {
		return RepoScanRecord{}, ErrQueueLimitReached
	}
	record := m.createRepoScanLocked(scope, normalizedRepository, source, "queued", historyLimit, maxFindings, queuedAt)
	record.TraceParent, record.TraceState = QueueTraceContextFromContext(ctx)
	m.repoScans[record.ID] = record
	return record, nil
}

// ClaimNextQueuedRepoScan moves one queued repository scan to running for execution.
func (m *MemoryStore) ClaimNextQueuedRepoScan(ctx context.Context) (RepoScanRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return RepoScanRecord{}, err
	}
	return m.claimNextQueuedRepoScanLocked(&scope)
}

// ClaimNextQueuedRepoScanAnyScope moves one queued repository scan to running across all tenant/workspace scopes.
func (m *MemoryStore) ClaimNextQueuedRepoScanAnyScope(_ context.Context) (RepoScanRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.claimNextQueuedRepoScanLocked(nil)
}

func (m *MemoryStore) claimNextQueuedRepoScanLocked(scope *Scope) (RepoScanRecord, error) {
	var claimed RepoScanRecord
	found := false
	for _, scanID := range m.repoScanIDs {
		record := m.repoScans[scanID]
		if scope != nil && !MatchScope(*scope, record.TenantID, record.WorkspaceID) {
			continue
		}
		if record.Status != "queued" {
			continue
		}
		if !found || record.StartedAt.Before(claimed.StartedAt) {
			claimed = record
			found = true
		}
	}
	if !found {
		return RepoScanRecord{}, ErrNotFound
	}
	queuedAt := claimed.StartedAt
	claimed.Status = "running"
	claimed.StartedAt = time.Now().UTC()
	claimed.FinishedAt = nil
	claimed.ErrorMessage = ""
	m.repoScans[claimed.ID] = claimed
	claimed.StartedAt = queuedAt
	return claimed, nil
}

// CountQueuedRepoScans returns queued repository scan count.
func (m *MemoryStore) CountQueuedRepoScans(ctx context.Context) (int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, record := range m.repoScans {
		if !MatchScope(scope, record.TenantID, record.WorkspaceID) {
			continue
		}
		if record.Status == "queued" {
			count++
		}
	}
	return count, nil
}

// CountQueuedRepoScansAnyScope returns queued repository scan count across all scopes.
func (m *MemoryStore) CountQueuedRepoScansAnyScope(_ context.Context) (int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	count := 0
	for _, record := range m.repoScans {
		if record.Status == "queued" {
			count++
		}
	}
	return count, nil
}

// CountPendingRepoScansByRepository returns queued/running scan count for one repository.
func (m *MemoryStore) CountPendingRepoScansByRepository(ctx context.Context, repository string) (int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return 0, err
	}
	normalizedRepository := strings.TrimSpace(repository)
	if normalizedRepository == "" {
		return 0, nil
	}
	count := 0
	for _, record := range m.repoScans {
		if !MatchScope(scope, record.TenantID, record.WorkspaceID) {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(record.Repository), normalizedRepository) {
			continue
		}
		if record.Status == "queued" || record.Status == "running" {
			count++
		}
	}
	return count, nil
}

// RequeueRepoScan moves a running repository scan back to queued state.
func (m *MemoryStore) RequeueRepoScan(ctx context.Context, repoScanID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return err
	}
	record, exists := m.repoScans[repoScanID]
	if !exists || !MatchScope(scope, record.TenantID, record.WorkspaceID) {
		return ErrNotFound
	}
	if record.Status != "running" {
		return ErrNotFound
	}
	record.Status = "queued"
	record.StartedAt = time.Now().UTC()
	record.FinishedAt = nil
	record.ErrorMessage = ""
	m.repoScans[repoScanID] = record
	return nil
}

// RequeueStaleRepoScansAnyScope moves stale running repository scans back to queued state across all scopes.
func (m *MemoryStore) RequeueStaleRepoScansAnyScope(_ context.Context, staleBefore time.Time, limit int) (int, error) {
	if limit <= 0 {
		return 0, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	cutoff := staleBefore.UTC()
	candidates := make([]RepoScanRecord, 0)
	for _, scanID := range m.repoScanIDs {
		record := m.repoScans[scanID]
		if record.Status != "running" || !record.StartedAt.Before(cutoff) {
			continue
		}
		candidates = append(candidates, record)
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		return candidates[i].StartedAt.Before(candidates[j].StartedAt)
	})
	if len(candidates) > limit {
		candidates = candidates[:limit]
	}
	now := time.Now().UTC()
	for _, record := range candidates {
		record.Status = "queued"
		record.StartedAt = now
		record.FinishedAt = nil
		record.ErrorMessage = ""
		m.repoScans[record.ID] = record
	}
	return len(candidates), nil
}

func (m *MemoryStore) createRepoScanLocked(scope Scope, repository string, source RepoScanSource, status string, historyLimit int, maxFindings int, startedAt time.Time) RepoScanRecord {
	normalizedScope := scope.Normalize()
	record := RepoScanRecord{
		ID:           uuid.NewString(),
		TenantID:     normalizedScope.TenantID,
		WorkspaceID:  normalizedScope.WorkspaceID,
		Repository:   strings.TrimSpace(repository),
		Status:       strings.TrimSpace(status),
		StartedAt:    startedAt.UTC(),
		HistoryLimit: historyLimit,
		MaxFindings:  maxFindings,
		Source:       source.Normalize(),
	}
	m.repoScans[record.ID] = record
	m.repoScanIDs = append(m.repoScanIDs, record.ID)
	return record
}

// GetRepoScan returns one persisted repo scan by id.
func (m *MemoryStore) GetRepoScan(ctx context.Context, repoScanID string) (RepoScanRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return RepoScanRecord{}, err
	}
	record, exists := m.repoScans[repoScanID]
	if !exists || !MatchScope(scope, record.TenantID, record.WorkspaceID) {
		return RepoScanRecord{}, ErrNotFound
	}
	return record, nil
}

// CompleteRepoScan finalizes repo scan metadata.
func (m *MemoryStore) CompleteRepoScan(ctx context.Context, repoScanID string, status string, finishedAt time.Time, commitsScanned int, filesScanned int, findingCount int, truncated bool, errorMessage string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return err
	}
	record, exists := m.repoScans[repoScanID]
	if !exists || !MatchScope(scope, record.TenantID, record.WorkspaceID) {
		return ErrNotFound
	}
	finished := finishedAt.UTC()
	record.Status = strings.TrimSpace(status)
	record.FinishedAt = &finished
	record.CommitsScanned = commitsScanned
	record.FilesScanned = filesScanned
	record.FindingCount = findingCount
	record.Truncated = truncated
	record.ErrorMessage = strings.TrimSpace(errorMessage)
	m.repoScans[repoScanID] = record
	return nil
}

// UpsertRepoFindings persists repository findings idempotently by repo_scan_id + finding_id.
func (m *MemoryStore) UpsertRepoFindings(ctx context.Context, repoScanID string, findings []domain.Finding) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return err
	}
	repoScan, exists := m.repoScans[repoScanID]
	if !exists || !MatchScope(scope, repoScan.TenantID, repoScan.WorkspaceID) {
		return ErrNotFound
	}
	for _, finding := range findings {
		finding.ScanID = repoScanID
		domain.NormalizeRepoFindingMetadata(&finding)
		key := repoScanID + "|" + finding.ID
		m.repoFindings[key] = finding
		m.repoFindingIDs[repoScanID] = appendUniqueID(m.repoFindingIDs[repoScanID], key)
	}
	return nil
}

// ListRepoScans returns latest repo scans first.
func (m *MemoryStore) ListRepoScans(ctx context.Context, limit int) ([]RepoScanRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]RepoScanRecord, 0, len(m.repoScanIDs))
	for _, scanID := range m.repoScanIDs {
		record := m.repoScans[scanID]
		if !MatchScope(scope, record.TenantID, record.WorkspaceID) {
			continue
		}
		result = append(result, record)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].StartedAt.After(result[j].StartedAt)
	})
	if limit > 0 && len(result) > limit {
		result = result[:limit]
	}
	return result, nil
}

// ListRepoFindings returns repository findings using optional filters.
func (m *MemoryStore) ListRepoFindings(ctx context.Context, filter RepoFindingFilter, limit int) ([]domain.Finding, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return nil, err
	}
	normalized := NormalizeRepoFindingFilter(filter)
	repoScanID := normalized.RepoScanID
	findingID := normalized.FindingID
	repoScanRepository := ""
	if repoScanID != "" {
		record, exists := m.repoScans[repoScanID]
		if !exists || !MatchScope(scope, record.TenantID, record.WorkspaceID) {
			return nil, ErrNotFound
		}
		repoScanRepository = strings.TrimSpace(record.Repository)
	}

	result := make([]domain.Finding, 0, len(m.repoFindings))
	if repoScanID != "" {
		for _, key := range m.repoFindingIDs[repoScanID] {
			finding, exists := m.repoFindings[key]
			if !exists {
				continue
			}
			if findingID != "" && finding.ID != findingID {
				continue
			}
			if normalized.Severity != "" && strings.ToLower(string(finding.Severity)) != normalized.Severity {
				continue
			}
			if normalized.Type != "" && strings.ToLower(string(finding.Type)) != normalized.Type {
				continue
			}
			if finding.Repository == "" {
				finding.Repository = repoScanRepository
			}
			domain.NormalizeRepoFindingMetadata(&finding)
			result = append(result, finding)
		}
	} else {
		for _, finding := range m.repoFindings {
			record, exists := m.repoScans[finding.ScanID]
			if !exists || !MatchScope(scope, record.TenantID, record.WorkspaceID) {
				continue
			}
			if findingID != "" && finding.ID != findingID {
				continue
			}
			if normalized.Severity != "" && strings.ToLower(string(finding.Severity)) != normalized.Severity {
				continue
			}
			if normalized.Type != "" && strings.ToLower(string(finding.Type)) != normalized.Type {
				continue
			}
			if finding.Repository == "" {
				finding.Repository = strings.TrimSpace(record.Repository)
			}
			domain.NormalizeRepoFindingMetadata(&finding)
			result = append(result, finding)
		}
	}
	sortFindingsForQuery(result, normalized.SortBy, normalized.SortDesc)
	if limit > 0 && len(result) > limit {
		result = result[:limit]
	}
	return result, nil
}

// ListRepoFindingClusters returns repository finding clusters using store-backed pagination semantics.
func (m *MemoryStore) ListRepoFindingClusters(ctx context.Context, filter RepoFindingClusterListFilter) ([]domain.RepoFindingCluster, error) {
	findings, err := m.ListRepoFindings(ctx, RepoFindingFilter{
		RepoScanID: filter.RepoScanID,
		Severity:   filter.Severity,
		Type:       filter.Type,
	}, 0)
	if err != nil {
		return nil, err
	}
	normalized := NormalizeRepoFindingClusterListFilter(filter)
	clusters := domain.BuildRepoFindingClusters(findings)
	domain.SortRepoFindingClusters(clusters, normalized.SortBy, normalized.SortDesc)
	if normalized.Offset >= len(clusters) {
		return []domain.RepoFindingCluster{}, nil
	}
	end := normalized.Offset + normalized.Limit + 1
	if end > len(clusters) {
		end = len(clusters)
	}
	return append([]domain.RepoFindingCluster(nil), clusters[normalized.Offset:end]...), nil
}

// Close closes store resources.
func (m *MemoryStore) Close() error {
	return nil
}
