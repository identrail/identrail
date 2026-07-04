package db

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/identrail/identrail/internal/domain"
	"github.com/identrail/identrail/internal/providers"
	"github.com/identrail/identrail/internal/secretstore"
)

// ErrNotFound indicates the requested record does not exist.
var ErrNotFound = errors.New("record not found")

// ErrScopeRequired indicates tenant/workspace scope must be provided in context.
var ErrScopeRequired = errors.New("scope is required")

// ErrConflict indicates the requested write conflicts with an existing record.
var ErrConflict = errors.New("record conflict")

// FindingSummaryCounts captures aggregate finding counters for one scoped workspace.
type FindingSummaryCounts struct {
	Total      int
	BySeverity map[string]int
	ByType     map[string]int
}

// ErrQueueLimitReached indicates a bounded queue has no remaining capacity.
var ErrQueueLimitReached = errors.New("queue limit reached")

// ErrPendingScanExists indicates one queued or running scan already exists for the provider scope.
var ErrPendingScanExists = errors.New("pending scan already exists")

// ErrPendingRepoScanExists indicates the target repository already has a queued or running scan.
var ErrPendingRepoScanExists = errors.New("pending repo scan exists")
var authzOwnerTeamPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
var tenancySlugPattern = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

// SessionIdleTimeout is the sliding browser-session renewal window.
const SessionIdleTimeout = 24 * time.Hour

const (
	ScanEventLevelDebug = "debug"
	ScanEventLevelInfo  = "info"
	ScanEventLevelWarn  = "warn"
	ScanEventLevelError = "error"

	RepoScanModeDeep  = "deep"
	RepoScanModeDelta = "delta"
	RepoScanModeQuick = "quick"

	FindingTriageActionAcknowledged = "acknowledged"
	FindingTriageActionSuppressed   = "suppressed"
	FindingTriageActionResolved     = "resolved"
	FindingTriageActionReopened     = "reopened"
	FindingTriageActionAssigned     = "assignee_updated"
	FindingTriageActionSuppression  = "suppression_updated"
	FindingTriageActionCommented    = "commented"

	AuthzEntityKindSubject  = "subject"
	AuthzEntityKindResource = "resource"

	AuthzAttributeEnvProd    = "prod"
	AuthzAttributeEnvStaging = "staging"
	AuthzAttributeEnvDev     = "dev"
	AuthzAttributeEnvTest    = "test"
	AuthzAttributeEnvSandbox = "sandbox"

	AuthzAttributeRiskTierLow      = "low"
	AuthzAttributeRiskTierMedium   = "medium"
	AuthzAttributeRiskTierHigh     = "high"
	AuthzAttributeRiskTierCritical = "critical"

	AuthzAttributeClassificationPublic       = "public"
	AuthzAttributeClassificationInternal     = "internal"
	AuthzAttributeClassificationConfidential = "confidential"
	AuthzAttributeClassificationRestricted   = "restricted"

	AuthzRelationshipOwns           = "owns"
	AuthzRelationshipManages        = "manages"
	AuthzRelationshipDelegatedAdmin = "delegated_admin"
	AuthzRelationshipMemberOf       = "member_of"

	AuthzPolicyRolloutModeDisabled = "disabled"
	AuthzPolicyRolloutModeShadow   = "shadow"
	AuthzPolicyRolloutModeEnforce  = "enforce"

	defaultTenancyScanPolicyHistoryLimit = 500
	defaultTenancyScanPolicyMaxFindings  = 200
)

var validAuthzEntityKinds = map[string]struct{}{
	AuthzEntityKindSubject:  {},
	AuthzEntityKindResource: {},
}

var validAuthzEnvironments = map[string]struct{}{
	AuthzAttributeEnvProd:    {},
	AuthzAttributeEnvStaging: {},
	AuthzAttributeEnvDev:     {},
	AuthzAttributeEnvTest:    {},
	AuthzAttributeEnvSandbox: {},
}

var validAuthzRiskTiers = map[string]struct{}{
	AuthzAttributeRiskTierLow:      {},
	AuthzAttributeRiskTierMedium:   {},
	AuthzAttributeRiskTierHigh:     {},
	AuthzAttributeRiskTierCritical: {},
}

var validAuthzClassifications = map[string]struct{}{
	AuthzAttributeClassificationPublic:       {},
	AuthzAttributeClassificationInternal:     {},
	AuthzAttributeClassificationConfidential: {},
	AuthzAttributeClassificationRestricted:   {},
}

var validAuthzRelationships = map[string]struct{}{
	AuthzRelationshipOwns:           {},
	AuthzRelationshipManages:        {},
	AuthzRelationshipDelegatedAdmin: {},
	AuthzRelationshipMemberOf:       {},
}

var validAuthzPolicyRolloutModes = map[string]struct{}{
	AuthzPolicyRolloutModeDisabled: {},
	AuthzPolicyRolloutModeShadow:   {},
	AuthzPolicyRolloutModeEnforce:  {},
}

var validTenancyMemberRoles = map[string]struct{}{
	"owner":   {},
	"admin":   {},
	"analyst": {},
	"viewer":  {},
}

var validTenancyMemberStatuses = map[string]struct{}{
	"invited":   {},
	"active":    {},
	"suspended": {},
	"removed":   {},
}

var validUserStatuses = map[string]struct{}{
	"active":      {},
	"deactivated": {},
	"deleted":     {},
}

// UserDeletionGracePeriod is the window between the soft-delete request and the
// hard-delete worker pass during which the user can cancel deletion. It is a
// const so the API and worker agree on the same number — drifting between them
// would mean the cancel-deletion endpoint advertises a date the worker does not
// honor.
const UserDeletionGracePeriod = 30 * 24 * time.Hour

// Self-serve data-export lifecycle constants (#1421). Held here so the API,
// worker, and store agree on the same TTLs without drifting if any one of them
// is changed in isolation.
const (
	// UserDataExportDownloadTTL is how long a completed bundle's signed
	// download URL stays valid after the job finishes.
	UserDataExportDownloadTTL = 24 * time.Hour
	// UserDataExportRetention is how long a completed bundle is kept on
	// disk before the GC pass deletes the file and marks the row purged.
	UserDataExportRetention = 7 * 24 * time.Hour
)

// User-data-export job lifecycle status values.
const (
	UserDataExportStatusQueued  = "queued"
	UserDataExportStatusRunning = "running"
	UserDataExportStatusReady   = "ready"
	UserDataExportStatusFailed  = "failed"
	UserDataExportStatusExpired = "expired"
)

var validUserDataExportStatuses = map[string]struct{}{
	UserDataExportStatusQueued:  {},
	UserDataExportStatusRunning: {},
	UserDataExportStatusReady:   {},
	UserDataExportStatusFailed:  {},
	UserDataExportStatusExpired: {},
}

// WorkspaceDeletionGracePeriod mirrors UserDeletionGracePeriod for workspace
// lifecycle. The window between a workspace soft-delete and the worker hard
// purge. See migration 000036_workspace_lifecycle.
const WorkspaceDeletionGracePeriod = 30 * 24 * time.Hour

// Workspace lifecycle statuses persisted on tenancy_workspaces.status.
const (
	WorkspaceStatusActive    = "active"
	WorkspaceStatusSuspended = "suspended"
	WorkspaceStatusDeleted   = "deleted"
)

// hardDeletedWorkspaceMarkerPrefix brackets the synthetic identifier emitted
// on audit events for hard-deleted workspaces (#1420 PR 2). The marker keeps
// the audit log human-readable while ensuring no live workspace ID can
// collide with it — `:` is not legal in tenancy identifiers (validated by
// validateAppModeIdentifier), so any field starting with this prefix is
// unambiguously a tombstone reference rather than an active workspace.
const hardDeletedWorkspaceMarkerPrefix = "deleted-workspace:"

// HardDeletedWorkspaceMarker returns the synthetic workspace identifier the
// workspace hard-delete worker emits on its audit event so downstream
// consumers can recognize references to purged workspaces without needing a
// live row to dereference.
func HardDeletedWorkspaceMarker(workspaceID string) string {
	return hardDeletedWorkspaceMarkerPrefix + strings.TrimSpace(workspaceID)
}

// IsHardDeletedWorkspaceMarker reports whether the supplied identifier is a
// hard-delete marker emitted by the workspace purge worker.
func IsHardDeletedWorkspaceMarker(identifier string) bool {
	return strings.HasPrefix(strings.TrimSpace(identifier), hardDeletedWorkspaceMarkerPrefix)
}

// hardDeletedEmailPrefix and hardDeletedEmailSuffix bracket the synthetic
// primary_email a user row carries after PII purge. They keep the NOT NULL /
// UNIQUE / length constraints on the column satisfied while guaranteeing the
// value holds no real address, and let the pending-hard-delete query skip rows
// that were already purged so the daily worker pass is idempotent rather than
// perpetual. The suffix is part of the match so a real user whose email
// legitimately starts with "deleted-user+" (the local part can be anything in
// RFC 5321) is not misclassified as already tombstoned.
const (
	hardDeletedEmailPrefix = "deleted-user+"
	hardDeletedEmailSuffix = "@accounts.invalid"
)

// HardDeletedTombstoneEmail returns the deterministic, PII-free placeholder
// address assigned to a user row when its account is hard-deleted.
func HardDeletedTombstoneEmail(userID string) string {
	return hardDeletedEmailPrefix + strings.ToLower(strings.TrimSpace(userID)) + hardDeletedEmailSuffix
}

// IsHardDeletedTombstoneEmailForUser reports whether `email` is exactly the
// deterministic tombstone for `userID`. Exact per-user matching avoids the
// false positives a generic prefix+suffix scan would invite — a malicious
// signup with the right shape could otherwise convince the worker that an
// active account had already been purged and exclude it from future runs.
func IsHardDeletedTombstoneEmailForUser(email string, userID string) bool {
	return strings.EqualFold(strings.TrimSpace(email), HardDeletedTombstoneEmail(userID))
}

var validSessionAuthMethods = map[string]struct{}{
	"workos": {},
	"oidc":   {},
	"manual": {},
	"saml":   {},
}

var validIdentityConnectionProviders = map[string]struct{}{
	"workos": {},
	"oidc":   {},
	"saml":   {},
}

var validIdentityConnectionTypes = map[string]struct{}{
	"sso":            {},
	"directory_sync": {},
}

const DefaultScanMaxRetryCount = 3

var validIdentityConnectionStatuses = map[string]struct{}{
	"pending":  {},
	"active":   {},
	"disabled": {},
}

var validRepoScanModes = map[string]struct{}{
	RepoScanModeDeep:  {},
	RepoScanModeDelta: {},
	RepoScanModeQuick: {},
}

// ScanRecord tracks persisted scan execution metadata.
type ScanRecord struct {
	ID              string     `json:"id"`
	TenantID        string     `json:"-"`
	WorkspaceID     string     `json:"-"`
	ProjectID       string     `json:"project_id,omitempty"`
	ConnectorID     string     `json:"connector_id,omitempty"`
	Provider        string     `json:"provider"`
	Status          string     `json:"status"`
	StartedAt       time.Time  `json:"started_at"`
	FinishedAt      *time.Time `json:"finished_at,omitempty"`
	AssetCount      int        `json:"asset_count"`
	FindingCount    int        `json:"finding_count"`
	ErrorMessage    string     `json:"error_message,omitempty"`
	RetryCount      int        `json:"retry_count"`
	MaxRetryCount   int        `json:"max_retry_count"`
	FailureCategory string     `json:"failure_category,omitempty"`
	NextRetryAt     *time.Time `json:"next_retry_at,omitempty"`
	DeadLettered    bool       `json:"dead_lettered"`
	DeadLetteredAt  *time.Time `json:"dead_lettered_at,omitempty"`
	TraceParent     string     `json:"-"`
	TraceState      string     `json:"-"`
}

// ScanSource carries non-secret project/connector context for cloud scans.
type ScanSource struct {
	ProjectID   string
	ConnectorID string
}

// Normalize returns a stable source key.
func (s ScanSource) Normalize() ScanSource {
	return ScanSource{
		ProjectID:   strings.TrimSpace(s.ProjectID),
		ConnectorID: strings.TrimSpace(s.ConnectorID),
	}
}

// Empty reports whether a scan has no explicit project/connector binding.
func (s ScanSource) Empty() bool {
	normalized := s.Normalize()
	return normalized.ProjectID == "" && normalized.ConnectorID == ""
}

// RepoScanRecord tracks persisted repository exposure scan metadata.
type RepoScanRecord struct {
	ID             string         `json:"id"`
	TenantID       string         `json:"-"`
	WorkspaceID    string         `json:"-"`
	Repository     string         `json:"repository"`
	Status         string         `json:"status"`
	StartedAt      time.Time      `json:"started_at"`
	FinishedAt     *time.Time     `json:"finished_at,omitempty"`
	CommitsScanned int            `json:"commits_scanned"`
	FilesScanned   int            `json:"files_scanned"`
	FindingCount   int            `json:"finding_count"`
	Truncated      bool           `json:"truncated"`
	ScanMode       string         `json:"scan_mode"`
	BaseRevision   string         `json:"base_revision,omitempty"`
	HeadRevision   string         `json:"head_revision,omitempty"`
	CursorBefore   string         `json:"cursor_before,omitempty"`
	CursorAfter    string         `json:"cursor_after,omitempty"`
	ChangedPaths   []string       `json:"changed_paths,omitempty"`
	ErrorMessage   string         `json:"error_message,omitempty"`
	HistoryLimit   int            `json:"-"`
	MaxFindings    int            `json:"-"`
	Source         RepoScanSource `json:"-"`
	TraceParent    string         `json:"-"`
	TraceState     string         `json:"-"`
}

// RepoScanContext captures incremental execution metadata for one scan.
type RepoScanContext struct {
	ScanMode         string
	BaseRevision     string
	HeadRevision     string
	CursorBefore     string
	CursorAfter      string
	ChangedPaths     []string
	PartialSourceRun bool
}

// NormalizeRepoScanContext returns stable scan-mode and revision metadata.
func NormalizeRepoScanContext(scanContext RepoScanContext) RepoScanContext {
	mode := strings.ToLower(strings.TrimSpace(scanContext.ScanMode))
	if _, ok := validRepoScanModes[mode]; !ok {
		mode = RepoScanModeDeep
	}
	normalized := RepoScanContext{
		ScanMode:         mode,
		BaseRevision:     strings.TrimSpace(scanContext.BaseRevision),
		HeadRevision:     strings.TrimSpace(scanContext.HeadRevision),
		CursorBefore:     strings.TrimSpace(scanContext.CursorBefore),
		CursorAfter:      strings.TrimSpace(scanContext.CursorAfter),
		ChangedPaths:     normalizeRepoScanChangedPaths(scanContext.ChangedPaths),
		PartialSourceRun: scanContext.PartialSourceRun,
	}
	return normalized
}

// RepoScanCursor stores the latest scanned revision for one scoped repository source.
type RepoScanCursor struct {
	TenantID            string         `json:"-"`
	WorkspaceID         string         `json:"-"`
	Repository          string         `json:"repository"`
	Source              RepoScanSource `json:"-"`
	LastScannedRevision string         `json:"last_scanned_revision,omitempty"`
	LastDeepScannedAt   *time.Time     `json:"last_deep_scanned_at,omitempty"`
	LastScanID          string         `json:"last_scan_id,omitempty"`
	LastScanMode        string         `json:"last_scan_mode,omitempty"`
	LastScanCompletedAt time.Time      `json:"last_scan_completed_at"`
	UpdatedAt           time.Time      `json:"updated_at"`
}

// Normalize returns a stable cursor key and payload.
func (c RepoScanCursor) Normalize() RepoScanCursor {
	normalized := RepoScanCursor{
		TenantID:            strings.TrimSpace(c.TenantID),
		WorkspaceID:         strings.TrimSpace(c.WorkspaceID),
		Repository:          strings.TrimSpace(c.Repository),
		Source:              c.Source.Normalize(),
		LastScannedRevision: strings.TrimSpace(c.LastScannedRevision),
		LastScanID:          strings.TrimSpace(c.LastScanID),
		LastScanMode:        strings.ToLower(strings.TrimSpace(c.LastScanMode)),
		LastScanCompletedAt: c.LastScanCompletedAt.UTC(),
		UpdatedAt:           c.UpdatedAt.UTC(),
	}
	if _, ok := validRepoScanModes[normalized.LastScanMode]; !ok {
		normalized.LastScanMode = RepoScanModeDeep
	}
	if c.LastDeepScannedAt != nil {
		converted := c.LastDeepScannedAt.UTC()
		normalized.LastDeepScannedAt = &converted
	}
	if normalized.LastScanCompletedAt.IsZero() {
		normalized.LastScanCompletedAt = normalized.UpdatedAt
	}
	if normalized.UpdatedAt.IsZero() {
		normalized.UpdatedAt = normalized.LastScanCompletedAt
	}
	return normalized
}

// RepoScanSource carries non-secret connector context for repository scans.
// It lets workers resolve short-lived credentials at execution time without
// persisting raw tokens in the queue.
type RepoScanSource struct {
	Provider       string
	ProjectID      string
	ConnectorID    string
	InstallationID int64
}

// Normalize returns a copy with stable whitespace/casing.
func (s RepoScanSource) Normalize() RepoScanSource {
	return RepoScanSource{
		Provider:       strings.ToLower(strings.TrimSpace(s.Provider)),
		ProjectID:      strings.TrimSpace(s.ProjectID),
		ConnectorID:    strings.TrimSpace(s.ConnectorID),
		InstallationID: s.InstallationID,
	}
}

// Empty reports whether the scan has no connector-backed source.
func (s RepoScanSource) Empty() bool {
	normalized := s.Normalize()
	return normalized.Provider == "" &&
		normalized.ProjectID == "" &&
		normalized.ConnectorID == "" &&
		normalized.InstallationID == 0
}

func normalizeRepoScanChangedPaths(paths []string) []string {
	if len(paths) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	normalized := make([]string, 0, len(paths))
	for _, path := range paths {
		item := strings.TrimSpace(strings.ReplaceAll(path, "\\", "/"))
		item = strings.TrimPrefix(item, "/")
		item = strings.TrimPrefix(item, "./")
		if item == "" || strings.Contains(item, "\x00") || strings.HasPrefix(item, "../") || strings.Contains(item, "/../") {
			continue
		}
		if _, exists := seen[item]; exists {
			continue
		}
		seen[item] = struct{}{}
		normalized = append(normalized, item)
	}
	sort.Strings(normalized)
	return normalized
}

// ScanArtifacts contains raw and normalized scan outputs to persist idempotently.
type ScanArtifacts struct {
	RawAssets     []providers.RawAsset
	Bundle        providers.NormalizedBundle
	Permissions   []providers.PermissionTuple
	Relationships []domain.Relationship
}

// ScanEvent tracks important state transitions for scan observability.
type ScanEvent struct {
	ID        string         `json:"id"`
	ScanID    string         `json:"scan_id"`
	Level     string         `json:"level"`
	Message   string         `json:"message"`
	Metadata  map[string]any `json:"metadata,omitempty"`
	CreatedAt time.Time      `json:"created_at"`
}

// FindingTriageState stores mutable workflow metadata for one finding id.
type FindingTriageState struct {
	FindingID            string                        `json:"finding_id"`
	Status               domain.FindingLifecycleStatus `json:"status"`
	Assignee             string                        `json:"assignee,omitempty"`
	SuppressionExpiresAt *time.Time                    `json:"suppression_expires_at,omitempty"`
	// ResolvedAt is non-nil only while Status is resolved; it captures the
	// resolution time so the executive report can compute accurate MTTR.
	ResolvedAt *time.Time `json:"resolved_at,omitempty"`
	UpdatedAt  time.Time  `json:"updated_at"`
	UpdatedBy  string     `json:"updated_by,omitempty"`
}

// resolvedAtForStatus enforces the resolved_at invariant shared by every store
// backend: a finding only carries a resolution time while it is resolved, so a
// reopened (or otherwise non-resolved) finding never reports a stale value.
func resolvedAtForStatus(status domain.FindingLifecycleStatus, resolvedAt *time.Time) *time.Time {
	if status != domain.FindingLifecycleResolved || resolvedAt == nil {
		return nil
	}
	value := resolvedAt.UTC()
	return &value
}

// FindingTriageEvent records one immutable workflow action.
type FindingTriageEvent struct {
	ID                   string                        `json:"id"`
	FindingID            string                        `json:"finding_id"`
	Action               string                        `json:"action"`
	FromStatus           domain.FindingLifecycleStatus `json:"from_status"`
	ToStatus             domain.FindingLifecycleStatus `json:"to_status"`
	Assignee             string                        `json:"assignee,omitempty"`
	SuppressionExpiresAt *time.Time                    `json:"suppression_expires_at,omitempty"`
	Comment              string                        `json:"comment,omitempty"`
	Actor                string                        `json:"actor,omitempty"`
	CreatedAt            time.Time                     `json:"created_at"`
}

// AuthzEntityAttributes stores trusted policy attributes for one subject or resource.
type AuthzEntityAttributes struct {
	TenantID       string    `json:"-"`
	WorkspaceID    string    `json:"-"`
	EntityKind     string    `json:"entity_kind"`
	EntityType     string    `json:"entity_type"`
	EntityID       string    `json:"entity_id"`
	OwnerTeam      string    `json:"owner_team,omitempty"`
	Environment    string    `json:"env,omitempty"`
	RiskTier       string    `json:"risk_tier,omitempty"`
	Classification string    `json:"classification,omitempty"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// AuthzRelationship stores one directional relation tuple used by ReBAC checks.
type AuthzRelationship struct {
	TenantID    string     `json:"-"`
	WorkspaceID string     `json:"-"`
	SubjectType string     `json:"subject_type"`
	SubjectID   string     `json:"subject_id"`
	Relation    string     `json:"relation"`
	ObjectType  string     `json:"object_type"`
	ObjectID    string     `json:"object_id"`
	Source      string     `json:"source,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

// AuthzRelationshipFilter controls scoped ReBAC tuple listing.
type AuthzRelationshipFilter struct {
	SubjectType    string
	SubjectID      string
	Relation       string
	ObjectType     string
	ObjectID       string
	IncludeExpired bool
}

// AuthzPolicySet stores one scoped policy namespace and metadata.
type AuthzPolicySet struct {
	TenantID    string    `json:"-"`
	WorkspaceID string    `json:"-"`
	PolicySetID string    `json:"policy_set_id"`
	DisplayName string    `json:"display_name"`
	Description string    `json:"description,omitempty"`
	CreatedBy   string    `json:"created_by,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// AuthzPolicyVersion stores one immutable compiled policy bundle.
type AuthzPolicyVersion struct {
	TenantID    string    `json:"-"`
	WorkspaceID string    `json:"-"`
	PolicySetID string    `json:"policy_set_id"`
	Version     int       `json:"version"`
	Bundle      string    `json:"bundle"`
	Checksum    string    `json:"checksum"`
	CreatedBy   string    `json:"created_by,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

// AuthzPolicyRollout stores one scoped rollout pointer for active/candidate versions.
type AuthzPolicyRollout struct {
	TenantID           string    `json:"-"`
	WorkspaceID        string    `json:"-"`
	PolicySetID        string    `json:"policy_set_id"`
	ActiveVersion      *int      `json:"active_version,omitempty"`
	CandidateVersion   *int      `json:"candidate_version,omitempty"`
	Mode               string    `json:"mode"`
	TenantAllowlist    []string  `json:"tenant_allowlist,omitempty"`
	WorkspaceAllowlist []string  `json:"workspace_allowlist,omitempty"`
	CanaryPercentage   int       `json:"canary_percentage"`
	ValidatedVersions  []int     `json:"validated_versions,omitempty"`
	UpdatedBy          string    `json:"updated_by,omitempty"`
	UpdatedAt          time.Time `json:"updated_at"`
}

// AuthzPolicyEvent records one immutable policy lifecycle action.
type AuthzPolicyEvent struct {
	ID          string         `json:"id"`
	TenantID    string         `json:"-"`
	WorkspaceID string         `json:"-"`
	PolicySetID string         `json:"policy_set_id"`
	EventType   string         `json:"event_type"`
	FromVersion *int           `json:"from_version,omitempty"`
	ToVersion   *int           `json:"to_version,omitempty"`
	Actor       string         `json:"actor,omitempty"`
	Message     string         `json:"message,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
	CreatedAt   time.Time      `json:"created_at"`
}

// TenancyOrganization stores one tenant root metadata record.
type TenancyOrganization struct {
	TenantID    string    `json:"tenant_id"`
	DisplayName string    `json:"display_name"`
	Slug        string    `json:"slug"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// TenancyWorkspace stores one workspace metadata record.
type TenancyWorkspace struct {
	TenantID    string     `json:"tenant_id"`
	WorkspaceID string     `json:"workspace_id"`
	DisplayName string     `json:"display_name"`
	Slug        string     `json:"slug"`
	Status      string     `json:"status,omitempty"`
	SuspendedAt *time.Time `json:"suspended_at,omitempty"`
	DeletedAt   *time.Time `json:"deleted_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

// TenancyWorkspaceMember stores one workspace member assignment.
type TenancyWorkspaceMember struct {
	TenantID    string    `json:"tenant_id"`
	WorkspaceID string    `json:"workspace_id"`
	MemberID    string    `json:"member_id"`
	UserID      string    `json:"user_id"`
	UserUUID    string    `json:"user_uuid,omitempty"`
	Email       string    `json:"email,omitempty"`
	Role        string    `json:"role"`
	Status      string    `json:"status"`
	JoinedAt    time.Time `json:"joined_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// User stores one human account independent of provider identities.
type User struct {
	ID           string     `json:"id"`
	PrimaryEmail string     `json:"primary_email"`
	DisplayName  string     `json:"display_name,omitempty"`
	AvatarURL    string     `json:"avatar_url,omitempty"`
	Status       string     `json:"status"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
	DeletedAt    *time.Time `json:"deleted_at,omitempty"`
}

// UserIdentity links one external identity provider subject to a user.
type UserIdentity struct {
	ID                  string          `json:"id"`
	UserID              string          `json:"user_id"`
	Provider            string          `json:"provider"`
	Subject             string          `json:"subject"`
	Email               string          `json:"email,omitempty"`
	EmailVerified       bool            `json:"email_verified"`
	RawClaims           json.RawMessage `json:"raw_claims,omitempty"`
	LastAuthenticatedAt time.Time       `json:"last_authenticated_at"`
	CreatedAt           time.Time       `json:"created_at"`
}

// UserDataExport tracks one self-serve "Download my data" job for #1421.
// Bundles live on disk / object storage at BundlePath; the row holds the
// metadata and lifecycle timestamps. The signed-download URL the API issues
// is HMAC-signed by the server's session key, so no token material is
// persisted on the row.
type UserDataExport struct {
	ID                string     `json:"id"`
	UserID            string     `json:"user_id"`
	Status            string     `json:"status"`
	BundlePath        string     `json:"bundle_path,omitempty"`
	BundleSizeBytes   int64      `json:"bundle_size_bytes,omitempty"`
	BundleSHA256      string     `json:"bundle_sha256,omitempty"`
	ErrorMessage      string     `json:"error_message,omitempty"`
	RequestedAt       time.Time  `json:"requested_at"`
	StartedAt         *time.Time `json:"started_at,omitempty"`
	CompletedAt       *time.Time `json:"completed_at,omitempty"`
	DownloadExpiresAt *time.Time `json:"download_expires_at,omitempty"`
	PurgeAfter        *time.Time `json:"purge_after,omitempty"`
	PurgedAt          *time.Time `json:"purged_at,omitempty"`
}

// Session stores one opaque server-side browser session.
type Session struct {
	ID                 []byte     `json:"-"`
	UserID             string     `json:"user_id"`
	CurrentOrgID       string     `json:"current_org_id,omitempty"`
	CurrentWorkspaceID string     `json:"current_workspace_id,omitempty"`
	CurrentProjectID   string     `json:"current_project_id,omitempty"`
	AuthMethod         string     `json:"auth_method"`
	IP                 string     `json:"ip,omitempty"`
	UserAgent          string     `json:"user_agent,omitempty"`
	IdleExpiresAt      time.Time  `json:"idle_expires_at"`
	AbsoluteExpiresAt  time.Time  `json:"absolute_expires_at"`
	LastSeenAt         time.Time  `json:"last_seen_at"`
	RevokedAt          *time.Time `json:"revoked_at,omitempty"`
	CreatedAt          time.Time  `json:"created_at"`
	User               *User      `json:"user,omitempty"`
}

// OnboardingState stores the server-driven account setup progress for one user.
type OnboardingState struct {
	UserID                   string     `json:"user_id"`
	CurrentStep              string     `json:"current_step"`
	OrgID                    string     `json:"org_id,omitempty"`
	WorkspaceID              string     `json:"workspace_id,omitempty"`
	ProjectID                string     `json:"project_id,omitempty"`
	ConnectorID              string     `json:"connector_id,omitempty"`
	ConnectorType            string     `json:"connector_type,omitempty"`
	ConnectorSkipped         bool       `json:"connector_skipped"`
	ScanSkipped              bool       `json:"scan_skipped"`
	DashboardTourDismissedAt *time.Time `json:"dashboard_tour_dismissed_at,omitempty"`
	CompletedAt              *time.Time `json:"completed_at,omitempty"`
	StartedAt                time.Time  `json:"started_at"`
	UpdatedAt                time.Time  `json:"updated_at"`
}

// Invitation stores one organization invitation scaffold for later invite flows.
type Invitation struct {
	ID              string     `json:"id"`
	OrgID           string     `json:"org_id"`
	Email           string     `json:"email"`
	Role            string     `json:"role"`
	InvitedByUserID string     `json:"invited_by_user_id"`
	TokenHash       []byte     `json:"-"`
	ExpiresAt       time.Time  `json:"expires_at"`
	AcceptedAt      *time.Time `json:"accepted_at,omitempty"`
	RevokedAt       *time.Time `json:"revoked_at,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
}

// VerifiedDomain stores one organization domain-verification scaffold.
type VerifiedDomain struct {
	ID                 string     `json:"id"`
	OrgID              string     `json:"org_id"`
	Domain             string     `json:"domain"`
	VerificationToken  string     `json:"verification_token"`
	VerificationMethod string     `json:"verification_method"`
	VerifiedAt         *time.Time `json:"verified_at,omitempty"`
	CreatedAt          time.Time  `json:"created_at"`
}

// IdentityConnection stores one enterprise SSO or directory-sync connection.
//
// A row with Provider == "saml" must be either WorkOS-backed (the legacy path,
// WorkOSConnectionID populated and native fields zero) or native (EntityID,
// SSOURL, and CertificatePEM all populated; SSOURL must use https). The two
// modes are mutually exclusive at write time so callers cannot end up with a
// half-configured connection.
type IdentityConnection struct {
	ID                     string            `json:"id"`
	OrgID                  string            `json:"org_id"`
	Provider               string            `json:"provider"`
	Type                   string            `json:"type"`
	WorkOSConnectionID     string            `json:"workos_connection_id,omitempty"`
	Status                 string            `json:"status"`
	GroupRoleMap           map[string]string `json:"group_role_map"`
	SSORequired            bool              `json:"sso_required"`
	JITProvisioningEnabled bool              `json:"jit_provisioning_enabled"`
	EntityID               string            `json:"entity_id,omitempty"`
	SSOURL                 string            `json:"sso_url,omitempty"`
	CertificatePEM         string            `json:"certificate_pem,omitempty"`
	AttributeMapping       map[string]string `json:"attribute_mapping,omitempty"`
	SCIMBearerTokenHash    string            `json:"scim_bearer_token_hash,omitempty"`
	CreatedAt              time.Time         `json:"created_at"`
	UpdatedAt              time.Time         `json:"updated_at"`
}

// IsNativeSAML reports whether this connection drives native SAML directly
// (as opposed to delegating to WorkOS). Only meaningful when Provider=="saml".
func (c IdentityConnection) IsNativeSAML() bool {
	return strings.ToLower(strings.TrimSpace(c.Provider)) == "saml" &&
		strings.TrimSpace(c.WorkOSConnectionID) == "" &&
		strings.TrimSpace(c.EntityID) != ""
}

// SAMLRelayState is the persisted SP-side context for one in-flight SAML
// SP-initiated AuthnRequest. The handle is the short opaque token that
// travels through the IdP as RelayState; the row is one-shot consumed by
// the ACS handler.
type SAMLRelayState struct {
	Handle        string     `json:"handle"`
	ConnectionID  string     `json:"connection_id"`
	SAMLRequestID string     `json:"saml_request_id"`
	ReturnTo      string     `json:"return_to,omitempty"`
	Intent        string     `json:"intent"`
	ExpiresAt     time.Time  `json:"expires_at"`
	CreatedAt     time.Time  `json:"created_at"`
	ConsumedAt    *time.Time `json:"consumed_at,omitempty"`
}

// OAuthTransaction is the persisted server-side record for one in-flight
// WorkOS OAuth login. The signed `state` token carries Nonce; the matching
// callback must present both the signed state (Nonce) and the browser-bound
// CookieToken set when the redirect was issued. The row is one-shot consumed
// by the callback handler so a captured state cannot be replayed — including
// against a different API instance that shares this database.
type OAuthTransaction struct {
	Nonce             string     `json:"nonce"`
	CookieToken       string     `json:"cookie_token"`
	Intent            string     `json:"intent"`
	ReturnTo          string     `json:"return_to,omitempty"`
	ExpectedUserID    string     `json:"expected_user_id,omitempty"`
	ExpectedSessionID string     `json:"expected_session_id,omitempty"`
	ExpiresAt         time.Time  `json:"expires_at"`
	CreatedAt         time.Time  `json:"created_at"`
	ConsumedAt        *time.Time `json:"consumed_at,omitempty"`
}

// WebhookEvent is the persisted idempotency record for one provider-issued
// webhook delivery. (Provider, EventID) is unique. The row carries a status
// so concurrent deliveries of the same event are handled correctly: the
// first delivery claims the row ("processing") and applies side effects;
// only once it finishes ("processed") does a duplicate get a no-op success.
// A duplicate that arrives while the first is still in flight must be told
// to retry, never acknowledged — otherwise the provider could stop retrying
// before the side effects are durably applied. The row is recorded only
// after signature validation so an attacker cannot poison the table.
type WebhookEvent struct {
	Provider   string    `json:"provider"`
	EventID    string    `json:"event_id"`
	EventType  string    `json:"event_type,omitempty"`
	ReceivedAt time.Time `json:"received_at"`
}

// WebhookEventStatus is the result of BeginWebhookEvent. Claimed/Processing
// are transient outcomes for the caller; only Processed authorizes a no-op
// acknowledgement of a duplicate.
type WebhookEventStatus string

const (
	// WebhookEventClaimed means this delivery won the insert (or reclaimed a
	// stale in-flight row) and must apply the side effects, then call
	// CompleteWebhookEvent.
	WebhookEventClaimed WebhookEventStatus = "claimed"
	// WebhookEventProcessing means another delivery of the same event is
	// still in flight. The caller must NOT acknowledge success; it should
	// return a retryable response so the provider redelivers later.
	WebhookEventProcessing WebhookEventStatus = "processing"
	// WebhookEventProcessed means the event was already fully handled. The
	// caller returns a successful no-op without reapplying side effects.
	WebhookEventProcessed WebhookEventStatus = "processed"
)

// WebhookProcessingReclaimAfter bounds how long a "processing" row may sit
// before another delivery may reclaim it. It protects against an instance
// that crashed mid-processing wedging an event forever; it is far longer
// than the webhook handler's own processing time.
const WebhookProcessingReclaimAfter = 5 * time.Minute

// WebhookEventRetention bounds how long a webhook idempotency row is kept.
// It must comfortably exceed any provider's retry/replay window (WorkOS
// retries over days) while keeping the ledger from growing unbounded; rows
// older than this are opportunistically pruned on the claim path.
const WebhookEventRetention = 30 * 24 * time.Hour

// SCIMProvisioningEventRecord is the persisted form of one SCIM op recorded
// for tenant-visible governance audit. Append-only.
type SCIMProvisioningEventRecord struct {
	ID           string         `json:"id"`
	OrgID        string         `json:"org_id"`
	ConnectionID string         `json:"connection_id"`
	Op           string         `json:"op"`
	ExternalID   string         `json:"external_id,omitempty"`
	UserID       string         `json:"user_id,omitempty"`
	Payload      map[string]any `json:"payload,omitempty"`
	OccurredAt   time.Time      `json:"occurred_at"`
}

// TenancyProject stores one project metadata record.
type TenancyProject struct {
	TenantID    string     `json:"tenant_id"`
	WorkspaceID string     `json:"workspace_id"`
	ProjectID   string     `json:"project_id"`
	Name        string     `json:"name"`
	Slug        string     `json:"slug"`
	Description string     `json:"description,omitempty"`
	ArchivedAt  *time.Time `json:"archived_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

// TenancyScanPolicy stores one project-scoped automation policy record.
type TenancyScanPolicy struct {
	TenantID           string                 `json:"tenant_id"`
	WorkspaceID        string                 `json:"workspace_id"`
	ProjectID          string                 `json:"project_id"`
	PolicyID           string                 `json:"policy_id"`
	Name               string                 `json:"name"`
	Enabled            bool                   `json:"enabled"`
	TriggerMode        domain.ScanTriggerMode `json:"trigger_mode"`
	Cron               string                 `json:"cron,omitempty"`
	MaxConcurrentScans int                    `json:"max_concurrent_scans"`
	HistoryLimit       int                    `json:"history_limit"`
	MaxFindings        int                    `json:"max_findings"`
	LastScheduledAt    *time.Time             `json:"last_scheduled_at,omitempty"`
	CreatedAt          time.Time              `json:"created_at"`
	UpdatedAt          time.Time              `json:"updated_at"`
}

// TenancyConnector stores one project-scoped source connector record.
type TenancyConnector struct {
	TenantID            string                 `json:"tenant_id"`
	WorkspaceID         string                 `json:"workspace_id"`
	ProjectID           string                 `json:"project_id"`
	ConnectorID         string                 `json:"connector_id"`
	Type                domain.ConnectorType   `json:"type"`
	DisplayName         string                 `json:"display_name"`
	Status              domain.ConnectorStatus `json:"status"`
	SecretProvider      string                 `json:"secret_provider,omitempty"`
	SecretRefID         string                 `json:"secret_ref_id,omitempty"`
	SecretRefVersion    string                 `json:"secret_ref_version,omitempty"`
	SecretLastRotatedAt *time.Time             `json:"secret_last_rotated_at,omitempty"`
	ConfigChecksum      string                 `json:"config_checksum,omitempty"`
	LastSyncAt          *time.Time             `json:"last_sync_at,omitempty"`
	CreatedAt           time.Time              `json:"created_at"`
	UpdatedAt           time.Time              `json:"updated_at"`
}

// TenancyConnectorState stores observed health and provider metadata for a connector.
type TenancyConnectorState struct {
	TenantID             string         `json:"tenant_id"`
	WorkspaceID          string         `json:"workspace_id"`
	ProjectID            string         `json:"project_id"`
	ConnectorID          string         `json:"connector_id"`
	HealthStatus         string         `json:"health_status"`
	SyncCursor           string         `json:"sync_cursor,omitempty"`
	LastSuccessfulSyncAt *time.Time     `json:"last_successful_sync_at,omitempty"`
	LastErrorCode        string         `json:"last_error_code,omitempty"`
	LastErrorMessage     string         `json:"last_error_message,omitempty"`
	Metadata             map[string]any `json:"metadata"`
	ObservedAt           time.Time      `json:"observed_at"`
	UpdatedAt            time.Time      `json:"updated_at"`
}

// TenancyConnectorWithState returns a connector with its latest persisted state.
type TenancyConnectorWithState struct {
	Connector TenancyConnector      `json:"connector"`
	State     TenancyConnectorState `json:"state"`
}

const (
	AWSAccountRegionCoverageUnknown     = "unknown"
	AWSAccountRegionCoveragePending     = "pending"
	AWSAccountRegionCoverageCovered     = "covered"
	AWSAccountRegionCoverageGap         = "gap"
	AWSAccountRegionCoverageError       = "error"
	AWSAccountRegionCoverageSuspended   = "suspended"
	AWSAccountRegionCoverageDisabled    = "disabled"
	AWSAccountRegionCoverageUnreachable = "unreachable"
)

const (
	AWSPlatformBaselineStatusNotRun   = "not_run"
	AWSPlatformBaselineStatusReady    = "ready"
	AWSPlatformBaselineStatusDegraded = "degraded"
	AWSPlatformBaselineStatusBlocked  = "blocked"

	AWSPlatformBaselineCheckPassed           = "passed"
	AWSPlatformBaselineCheckFailed           = "failed"
	AWSPlatformBaselineCheckDegraded         = "degraded"
	AWSPlatformBaselineCheckPermissionDenied = "permission_denied"
	AWSPlatformBaselineCheckUnknown          = "unknown"
	AWSPlatformBaselineCheckSkipped          = "skipped"
)

// AWSAccountRegionCoverage stores account/region inventory and scan readiness
// for one project-scoped AWS connector. Connector health describes whether
// Identrail can use the connector role; coverage describes each target account
// and region reachable through that connector.
type AWSAccountRegionCoverage struct {
	TenantID                 string         `json:"tenant_id"`
	WorkspaceID              string         `json:"workspace_id"`
	ProjectID                string         `json:"project_id"`
	ConnectorID              string         `json:"connector_id"`
	AccountID                string         `json:"account_id"`
	AccountAlias             string         `json:"account_alias,omitempty"`
	OrganizationID           string         `json:"organization_id,omitempty"`
	OUPath                   string         `json:"ou_path,omitempty"`
	Partition                string         `json:"partition"`
	Region                   string         `json:"region"`
	RoleARN                  string         `json:"role_arn,omitempty"`
	CoverageStatus           string         `json:"coverage_status"`
	LastSuccessfulScanAt     *time.Time     `json:"last_successful_scan_at,omitempty"`
	LastObservedErrorCode    string         `json:"last_observed_error_code,omitempty"`
	LastObservedErrorMessage string         `json:"last_observed_error_message,omitempty"`
	ScanCursor               map[string]any `json:"scan_cursor"`
	Suspended                bool           `json:"suspended"`
	Disabled                 bool           `json:"disabled"`
	Unreachable              bool           `json:"unreachable"`
	CreatedAt                time.Time      `json:"created_at"`
	UpdatedAt                time.Time      `json:"updated_at"`
}

// AWSAccountRegionCoverageFilter constrains account/region coverage reads to a
// scoped project and optionally one connector, account, or region.
type AWSAccountRegionCoverageFilter struct {
	WorkspaceID string
	ProjectID   string
	ConnectorID string
	AccountID   string
	Region      string
	Limit       int
	Offset      int
}

// AWSPlatformBaselineCheck records one operator-visible readiness check for the
// AWS baseline gate. Evidence must never contain secret values.
type AWSPlatformBaselineCheck struct {
	Name          string         `json:"name"`
	Category      string         `json:"category"`
	Required      bool           `json:"required"`
	Status        string         `json:"status"`
	Message       string         `json:"message"`
	FailureReason string         `json:"failure_reason,omitempty"`
	Remediation   string         `json:"remediation,omitempty"`
	EvidenceURL   string         `json:"evidence_url,omitempty"`
	Confidence    float64        `json:"confidence"`
	Evidence      map[string]any `json:"evidence,omitempty"`
	CheckedAt     time.Time      `json:"checked_at"`
}

// AWSPlatformBaselineResult is the persisted project-scoped readiness gate
// result used before AWS scans or later remediation/governance jobs can start.
type AWSPlatformBaselineResult struct {
	TenantID                string                     `json:"tenant_id"`
	WorkspaceID             string                     `json:"workspace_id"`
	ProjectID               string                     `json:"project_id"`
	ConnectorID             string                     `json:"connector_id,omitempty"`
	GitSHA                  string                     `json:"git_sha"`
	SourceMode              string                     `json:"source_mode"`
	FixtureOnly             bool                       `json:"fixture_only"`
	ConnectorProfileVersion string                     `json:"connector_profile_version"`
	GraphContractVersion    string                     `json:"graph_contract_version"`
	AccountID               string                     `json:"account_id,omitempty"`
	Region                  string                     `json:"region,omitempty"`
	Status                  string                     `json:"status"`
	Confidence              float64                    `json:"confidence"`
	RequiredChecksPassed    bool                       `json:"required_checks_passed"`
	FailureReasons          []string                   `json:"failure_reasons"`
	EvidenceLinks           []string                   `json:"evidence_links"`
	Checks                  []AWSPlatformBaselineCheck `json:"checks"`
	VerifiedAt              time.Time                  `json:"verified_at"`
	CreatedAt               time.Time                  `json:"created_at"`
	UpdatedAt               time.Time                  `json:"updated_at"`
}

// AWSPlatformBaselineFilter identifies one scoped AWS baseline result. An empty
// connector id returns the project-level result when no specific connector was
// requested.
type AWSPlatformBaselineFilter struct {
	WorkspaceID string
	ProjectID   string
	ConnectorID string
}

// TenancyConnectorSecretEnvelope stores one encrypted connector secret envelope.
type TenancyConnectorSecretEnvelope struct {
	TenantID        string               `json:"tenant_id"`
	WorkspaceID     string               `json:"workspace_id"`
	ProjectID       string               `json:"project_id"`
	ConnectorID     string               `json:"connector_id"`
	SecretName      string               `json:"secret_name"`
	EnvelopeVersion int                  `json:"envelope_version"`
	Envelope        secretstore.Envelope `json:"envelope"`
	SecretRefID     string               `json:"secret_ref_id,omitempty"`
	RotatedAt       time.Time            `json:"rotated_at"`
	RotationDueAt   *time.Time           `json:"rotation_due_at,omitempty"`
	CreatedAt       time.Time            `json:"created_at"`
	UpdatedAt       time.Time            `json:"updated_at"`
}

// NormalizeScanEventLevel validates and normalizes event levels.
func NormalizeScanEventLevel(level string) (string, error) {
	switch level {
	case ScanEventLevelDebug, ScanEventLevelInfo, ScanEventLevelWarn, ScanEventLevelError:
		return level, nil
	default:
		return "", errors.New("invalid scan event level")
	}
}

// NormalizeAuthzEntityAttributesForWrite validates and canonicalizes trusted authz attributes.
func NormalizeAuthzEntityAttributesForWrite(attrs AuthzEntityAttributes) (AuthzEntityAttributes, error) {
	normalized := attrs
	normalized.EntityKind = strings.ToLower(strings.TrimSpace(attrs.EntityKind))
	if _, ok := validAuthzEntityKinds[normalized.EntityKind]; !ok {
		return AuthzEntityAttributes{}, fmt.Errorf("invalid authz entity kind")
	}
	normalized.EntityType = strings.ToLower(strings.TrimSpace(attrs.EntityType))
	if normalized.EntityType == "" {
		return AuthzEntityAttributes{}, fmt.Errorf("entity type is required")
	}
	normalized.EntityID = strings.TrimSpace(attrs.EntityID)
	if normalized.EntityID == "" {
		return AuthzEntityAttributes{}, fmt.Errorf("entity id is required")
	}
	normalized.OwnerTeam = strings.ToLower(strings.TrimSpace(attrs.OwnerTeam))
	if normalized.OwnerTeam != "" && !authzOwnerTeamPattern.MatchString(normalized.OwnerTeam) {
		return AuthzEntityAttributes{}, fmt.Errorf("invalid owner_team format")
	}
	normalized.Environment = strings.ToLower(strings.TrimSpace(attrs.Environment))
	if normalized.Environment != "" {
		if _, ok := validAuthzEnvironments[normalized.Environment]; !ok {
			return AuthzEntityAttributes{}, fmt.Errorf("invalid env value")
		}
	}
	normalized.RiskTier = strings.ToLower(strings.TrimSpace(attrs.RiskTier))
	if normalized.RiskTier != "" {
		if _, ok := validAuthzRiskTiers[normalized.RiskTier]; !ok {
			return AuthzEntityAttributes{}, fmt.Errorf("invalid risk_tier value")
		}
	}
	normalized.Classification = strings.ToLower(strings.TrimSpace(attrs.Classification))
	if normalized.Classification != "" {
		if _, ok := validAuthzClassifications[normalized.Classification]; !ok {
			return AuthzEntityAttributes{}, fmt.Errorf("invalid classification value")
		}
	}
	if normalized.UpdatedAt.IsZero() {
		normalized.UpdatedAt = time.Now().UTC()
	} else {
		normalized.UpdatedAt = normalized.UpdatedAt.UTC()
	}
	return normalized, nil
}

// NormalizeAuthzRelationshipForWrite validates and canonicalizes relationship tuples.
func NormalizeAuthzRelationshipForWrite(relationship AuthzRelationship) (AuthzRelationship, error) {
	normalized := relationship
	normalized.SubjectType = strings.ToLower(strings.TrimSpace(relationship.SubjectType))
	if normalized.SubjectType == "" {
		return AuthzRelationship{}, fmt.Errorf("subject type is required")
	}
	normalized.SubjectID = strings.TrimSpace(relationship.SubjectID)
	if normalized.SubjectID == "" {
		return AuthzRelationship{}, fmt.Errorf("subject id is required")
	}
	normalized.Relation = strings.ToLower(strings.TrimSpace(relationship.Relation))
	if _, ok := validAuthzRelationships[normalized.Relation]; !ok {
		return AuthzRelationship{}, fmt.Errorf("invalid relation value")
	}
	normalized.ObjectType = strings.ToLower(strings.TrimSpace(relationship.ObjectType))
	if normalized.ObjectType == "" {
		return AuthzRelationship{}, fmt.Errorf("object type is required")
	}
	normalized.ObjectID = strings.TrimSpace(relationship.ObjectID)
	if normalized.ObjectID == "" {
		return AuthzRelationship{}, fmt.Errorf("object id is required")
	}
	normalized.Source = strings.ToLower(strings.TrimSpace(relationship.Source))
	if normalized.Source == "" {
		normalized.Source = "manual"
	}
	if normalized.ExpiresAt != nil {
		utc := normalized.ExpiresAt.UTC()
		normalized.ExpiresAt = &utc
	}
	if normalized.CreatedAt.IsZero() {
		normalized.CreatedAt = time.Now().UTC()
	} else {
		normalized.CreatedAt = normalized.CreatedAt.UTC()
	}
	if normalized.UpdatedAt.IsZero() {
		normalized.UpdatedAt = normalized.CreatedAt
	} else {
		normalized.UpdatedAt = normalized.UpdatedAt.UTC()
	}
	return normalized, nil
}

// NormalizeAuthzPolicySetForWrite validates and canonicalizes one policy-set metadata row.
func NormalizeAuthzPolicySetForWrite(policySet AuthzPolicySet) (AuthzPolicySet, error) {
	normalized := policySet
	policySetID, err := normalizeAuthzPolicySetID(policySet.PolicySetID)
	if err != nil {
		return AuthzPolicySet{}, err
	}
	normalized.PolicySetID = policySetID
	normalized.DisplayName = strings.TrimSpace(policySet.DisplayName)
	if normalized.DisplayName == "" {
		return AuthzPolicySet{}, fmt.Errorf("display name is required")
	}
	normalized.Description = strings.TrimSpace(policySet.Description)
	normalized.CreatedBy = strings.TrimSpace(policySet.CreatedBy)
	if normalized.CreatedAt.IsZero() {
		normalized.CreatedAt = time.Now().UTC()
	} else {
		normalized.CreatedAt = normalized.CreatedAt.UTC()
	}
	if normalized.UpdatedAt.IsZero() {
		normalized.UpdatedAt = normalized.CreatedAt
	} else {
		normalized.UpdatedAt = normalized.UpdatedAt.UTC()
	}
	return normalized, nil
}

// NormalizeAuthzPolicyVersionForWrite validates and canonicalizes one immutable policy bundle version.
func NormalizeAuthzPolicyVersionForWrite(version AuthzPolicyVersion) (AuthzPolicyVersion, error) {
	normalized := version
	policySetID, err := normalizeAuthzPolicySetID(version.PolicySetID)
	if err != nil {
		return AuthzPolicyVersion{}, err
	}
	normalized.PolicySetID = policySetID
	if normalized.Version <= 0 {
		return AuthzPolicyVersion{}, fmt.Errorf("version must be greater than zero")
	}
	normalized.Bundle = strings.TrimSpace(version.Bundle)
	if normalized.Bundle == "" {
		return AuthzPolicyVersion{}, fmt.Errorf("policy bundle is required")
	}
	if !json.Valid([]byte(normalized.Bundle)) {
		return AuthzPolicyVersion{}, fmt.Errorf("policy bundle must be valid json")
	}
	normalized.Checksum = strings.ToLower(strings.TrimSpace(version.Checksum))
	if normalized.Checksum == "" {
		digest := sha256.Sum256([]byte(normalized.Bundle))
		normalized.Checksum = hex.EncodeToString(digest[:])
	}
	normalized.CreatedBy = strings.TrimSpace(version.CreatedBy)
	if normalized.CreatedAt.IsZero() {
		normalized.CreatedAt = time.Now().UTC()
	} else {
		normalized.CreatedAt = normalized.CreatedAt.UTC()
	}
	return normalized, nil
}

// NormalizeAuthzPolicyRolloutForWrite validates and canonicalizes one rollout pointer row.
func NormalizeAuthzPolicyRolloutForWrite(rollout AuthzPolicyRollout) (AuthzPolicyRollout, error) {
	normalized := rollout
	policySetID, err := normalizeAuthzPolicySetID(rollout.PolicySetID)
	if err != nil {
		return AuthzPolicyRollout{}, err
	}
	normalized.PolicySetID = policySetID
	if normalized.ActiveVersion != nil && *normalized.ActiveVersion <= 0 {
		return AuthzPolicyRollout{}, fmt.Errorf("active version must be greater than zero")
	}
	if normalized.CandidateVersion != nil && *normalized.CandidateVersion <= 0 {
		return AuthzPolicyRollout{}, fmt.Errorf("candidate version must be greater than zero")
	}
	normalized.Mode = strings.ToLower(strings.TrimSpace(rollout.Mode))
	if normalized.Mode == "" {
		normalized.Mode = AuthzPolicyRolloutModeDisabled
	}
	if _, ok := validAuthzPolicyRolloutModes[normalized.Mode]; !ok {
		return AuthzPolicyRollout{}, fmt.Errorf("invalid rollout mode")
	}
	normalized.TenantAllowlist = normalizeAuthzRolloutAllowlist(rollout.TenantAllowlist)
	normalized.WorkspaceAllowlist = normalizeAuthzRolloutAllowlist(rollout.WorkspaceAllowlist)
	normalized.CanaryPercentage = rollout.CanaryPercentage
	if normalized.CanaryPercentage == 0 {
		normalized.CanaryPercentage = 100
	}
	if normalized.CanaryPercentage < 0 || normalized.CanaryPercentage > 100 {
		return AuthzPolicyRollout{}, fmt.Errorf("canary percentage must be between 0 and 100")
	}
	normalized.ValidatedVersions, err = normalizeAuthzRolloutValidatedVersions(rollout.ValidatedVersions)
	if err != nil {
		return AuthzPolicyRollout{}, err
	}
	if normalized.Mode == AuthzPolicyRolloutModeEnforce {
		if normalized.ActiveVersion != nil && !containsInt(normalized.ValidatedVersions, *normalized.ActiveVersion) {
			return AuthzPolicyRollout{}, fmt.Errorf("active version must exist in validated_versions when mode is enforce")
		}
		if normalized.CandidateVersion != nil && !containsInt(normalized.ValidatedVersions, *normalized.CandidateVersion) {
			return AuthzPolicyRollout{}, fmt.Errorf("candidate version must exist in validated_versions when mode is enforce")
		}
	}
	normalized.UpdatedBy = strings.TrimSpace(rollout.UpdatedBy)
	if normalized.UpdatedAt.IsZero() {
		normalized.UpdatedAt = time.Now().UTC()
	} else {
		normalized.UpdatedAt = normalized.UpdatedAt.UTC()
	}
	return normalized, nil
}

func normalizeAuthzRolloutAllowlist(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		item := strings.TrimSpace(value)
		if item == "" {
			continue
		}
		if _, exists := seen[item]; exists {
			continue
		}
		seen[item] = struct{}{}
		normalized = append(normalized, item)
	}
	sort.Strings(normalized)
	if len(normalized) == 0 {
		return nil
	}
	return normalized
}

func normalizeAuthzRolloutValidatedVersions(versions []int) ([]int, error) {
	if len(versions) == 0 {
		return nil, nil
	}
	seen := map[int]struct{}{}
	normalized := make([]int, 0, len(versions))
	for _, version := range versions {
		if version <= 0 {
			return nil, fmt.Errorf("validated versions must be greater than zero")
		}
		if _, exists := seen[version]; exists {
			continue
		}
		seen[version] = struct{}{}
		normalized = append(normalized, version)
	}
	sort.Ints(normalized)
	return normalized, nil
}

func containsInt(values []int, value int) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func validateTenancySlug(value, field string) error {
	if len(value) > 63 {
		return fmt.Errorf("%s must be 63 characters or fewer", field)
	}
	if !tenancySlugPattern.MatchString(value) {
		return fmt.Errorf("%s must match %s", field, tenancySlugPattern.String())
	}
	return nil
}

// NormalizeTenancyOrganizationForWrite validates and canonicalizes organization metadata.
func NormalizeTenancyOrganizationForWrite(organization TenancyOrganization) (TenancyOrganization, error) {
	normalized := organization
	normalized.TenantID = strings.TrimSpace(organization.TenantID)
	if normalized.TenantID == "" {
		return TenancyOrganization{}, fmt.Errorf("tenant id is required")
	}
	normalized.DisplayName = strings.TrimSpace(organization.DisplayName)
	if normalized.DisplayName == "" {
		return TenancyOrganization{}, fmt.Errorf("display name is required")
	}
	normalized.Slug = strings.ToLower(strings.TrimSpace(organization.Slug))
	if normalized.Slug == "" {
		return TenancyOrganization{}, fmt.Errorf("slug is required")
	}
	if err := validateTenancySlug(normalized.Slug, "slug"); err != nil {
		return TenancyOrganization{}, err
	}
	if normalized.CreatedAt.IsZero() {
		normalized.CreatedAt = time.Now().UTC()
	} else {
		normalized.CreatedAt = normalized.CreatedAt.UTC()
	}
	if normalized.UpdatedAt.IsZero() {
		normalized.UpdatedAt = normalized.CreatedAt
	} else {
		normalized.UpdatedAt = normalized.UpdatedAt.UTC()
	}
	return normalized, nil
}

// NormalizeTenancyWorkspaceForWrite validates and canonicalizes workspace metadata.
func NormalizeTenancyWorkspaceForWrite(workspace TenancyWorkspace) (TenancyWorkspace, error) {
	normalized := workspace
	normalized.TenantID = strings.TrimSpace(workspace.TenantID)
	if normalized.TenantID == "" {
		return TenancyWorkspace{}, fmt.Errorf("tenant id is required")
	}
	normalized.WorkspaceID = strings.TrimSpace(workspace.WorkspaceID)
	if normalized.WorkspaceID == "" {
		return TenancyWorkspace{}, fmt.Errorf("workspace id is required")
	}
	normalized.DisplayName = strings.TrimSpace(workspace.DisplayName)
	if normalized.DisplayName == "" {
		return TenancyWorkspace{}, fmt.Errorf("display name is required")
	}
	normalized.Slug = strings.ToLower(strings.TrimSpace(workspace.Slug))
	if normalized.Slug == "" {
		return TenancyWorkspace{}, fmt.Errorf("slug is required")
	}
	if err := validateTenancySlug(normalized.Slug, "slug"); err != nil {
		return TenancyWorkspace{}, err
	}
	normalized.Status = strings.TrimSpace(workspace.Status)
	if normalized.Status == "" {
		normalized.Status = WorkspaceStatusActive
	}
	switch normalized.Status {
	case WorkspaceStatusActive, WorkspaceStatusSuspended, WorkspaceStatusDeleted:
	default:
		return TenancyWorkspace{}, fmt.Errorf("workspace status %q is invalid", normalized.Status)
	}
	if normalized.SuspendedAt != nil {
		t := normalized.SuspendedAt.UTC()
		normalized.SuspendedAt = &t
	}
	if normalized.DeletedAt != nil {
		t := normalized.DeletedAt.UTC()
		normalized.DeletedAt = &t
	}
	if normalized.CreatedAt.IsZero() {
		normalized.CreatedAt = time.Now().UTC()
	} else {
		normalized.CreatedAt = normalized.CreatedAt.UTC()
	}
	if normalized.UpdatedAt.IsZero() {
		normalized.UpdatedAt = normalized.CreatedAt
	} else {
		normalized.UpdatedAt = normalized.UpdatedAt.UTC()
	}
	return normalized, nil
}

// NormalizeTenancyWorkspaceMemberForWrite validates and canonicalizes workspace members.
func NormalizeTenancyWorkspaceMemberForWrite(member TenancyWorkspaceMember) (TenancyWorkspaceMember, error) {
	normalized := member
	normalized.TenantID = strings.TrimSpace(member.TenantID)
	if normalized.TenantID == "" {
		return TenancyWorkspaceMember{}, fmt.Errorf("tenant id is required")
	}
	normalized.WorkspaceID = strings.TrimSpace(member.WorkspaceID)
	if normalized.WorkspaceID == "" {
		return TenancyWorkspaceMember{}, fmt.Errorf("workspace id is required")
	}
	normalized.MemberID = strings.TrimSpace(member.MemberID)
	if normalized.MemberID == "" {
		return TenancyWorkspaceMember{}, fmt.Errorf("member id is required")
	}
	normalized.UserID = strings.TrimSpace(member.UserID)
	if normalized.UserID == "" {
		return TenancyWorkspaceMember{}, fmt.Errorf("user id is required")
	}
	normalized.UserUUID = strings.TrimSpace(member.UserUUID)
	normalized.Email = strings.TrimSpace(member.Email)
	normalized.Role = strings.ToLower(strings.TrimSpace(member.Role))
	if _, ok := validTenancyMemberRoles[normalized.Role]; !ok {
		return TenancyWorkspaceMember{}, fmt.Errorf("invalid member role")
	}
	normalized.Status = strings.ToLower(strings.TrimSpace(member.Status))
	if normalized.Status == "" {
		normalized.Status = "invited"
	}
	if _, ok := validTenancyMemberStatuses[normalized.Status]; !ok {
		return TenancyWorkspaceMember{}, fmt.Errorf("invalid member status")
	}
	if normalized.JoinedAt.IsZero() {
		normalized.JoinedAt = time.Now().UTC()
	} else {
		normalized.JoinedAt = normalized.JoinedAt.UTC()
	}
	if normalized.UpdatedAt.IsZero() {
		normalized.UpdatedAt = normalized.JoinedAt
	} else {
		normalized.UpdatedAt = normalized.UpdatedAt.UTC()
	}
	return normalized, nil
}

// NormalizeUserForWrite validates and canonicalizes one account row.
func NormalizeUserForWrite(user User) (User, error) {
	normalized := user
	normalized.ID = strings.TrimSpace(user.ID)
	if normalized.ID == "" {
		normalized.ID = uuid.NewString()
	} else if _, err := uuid.Parse(normalized.ID); err != nil {
		return User{}, fmt.Errorf("invalid user id")
	}
	normalized.PrimaryEmail = strings.ToLower(strings.TrimSpace(user.PrimaryEmail))
	if normalized.PrimaryEmail == "" {
		return User{}, fmt.Errorf("primary email is required")
	}
	normalized.DisplayName = strings.TrimSpace(user.DisplayName)
	normalized.AvatarURL = strings.TrimSpace(user.AvatarURL)
	normalized.Status = strings.ToLower(strings.TrimSpace(user.Status))
	if normalized.Status == "" {
		normalized.Status = "active"
	}
	if _, ok := validUserStatuses[normalized.Status]; !ok {
		return User{}, fmt.Errorf("invalid user status")
	}
	if normalized.CreatedAt.IsZero() {
		normalized.CreatedAt = time.Now().UTC()
	} else {
		normalized.CreatedAt = normalized.CreatedAt.UTC()
	}
	if normalized.UpdatedAt.IsZero() {
		normalized.UpdatedAt = normalized.CreatedAt
	} else {
		normalized.UpdatedAt = normalized.UpdatedAt.UTC()
	}
	if normalized.DeletedAt != nil {
		deletedAt := normalized.DeletedAt.UTC()
		normalized.DeletedAt = &deletedAt
	}
	return normalized, nil
}

// NormalizeUserIdentityForWrite validates and canonicalizes one provider identity row.
func NormalizeUserIdentityForWrite(identity UserIdentity) (UserIdentity, error) {
	normalized := identity
	normalized.ID = strings.TrimSpace(identity.ID)
	if normalized.ID == "" {
		normalized.ID = uuid.NewString()
	} else if _, err := uuid.Parse(normalized.ID); err != nil {
		return UserIdentity{}, fmt.Errorf("invalid user identity id")
	}
	normalized.UserID = strings.TrimSpace(identity.UserID)
	if _, err := uuid.Parse(normalized.UserID); err != nil {
		return UserIdentity{}, fmt.Errorf("invalid user id")
	}
	normalized.Provider = strings.ToLower(strings.TrimSpace(identity.Provider))
	if normalized.Provider == "" {
		return UserIdentity{}, fmt.Errorf("provider is required")
	}
	normalized.Subject = strings.TrimSpace(identity.Subject)
	if normalized.Subject == "" {
		return UserIdentity{}, fmt.Errorf("subject is required")
	}
	normalized.Email = strings.ToLower(strings.TrimSpace(identity.Email))
	if len(normalized.RawClaims) == 0 {
		normalized.RawClaims = json.RawMessage(`{}`)
	}
	if !json.Valid(normalized.RawClaims) {
		return UserIdentity{}, fmt.Errorf("raw claims must be valid json")
	}
	if normalized.LastAuthenticatedAt.IsZero() {
		normalized.LastAuthenticatedAt = time.Now().UTC()
	} else {
		normalized.LastAuthenticatedAt = normalized.LastAuthenticatedAt.UTC()
	}
	if normalized.CreatedAt.IsZero() {
		normalized.CreatedAt = normalized.LastAuthenticatedAt
	} else {
		normalized.CreatedAt = normalized.CreatedAt.UTC()
	}
	return normalized, nil
}

// NormalizeSessionForWrite validates and canonicalizes one session row.
func NormalizeSessionForWrite(session Session) (Session, error) {
	normalized := session
	if len(normalized.ID) != sha256.Size {
		return Session{}, fmt.Errorf("session id hash must be %d bytes", sha256.Size)
	}
	normalized.ID = append([]byte(nil), normalized.ID...)
	normalized.UserID = strings.TrimSpace(session.UserID)
	if _, err := uuid.Parse(normalized.UserID); err != nil {
		return Session{}, fmt.Errorf("invalid user id")
	}
	normalized.CurrentOrgID = strings.TrimSpace(session.CurrentOrgID)
	normalized.CurrentWorkspaceID = strings.TrimSpace(session.CurrentWorkspaceID)
	normalized.CurrentProjectID = strings.TrimSpace(session.CurrentProjectID)
	normalized.AuthMethod = strings.ToLower(strings.TrimSpace(session.AuthMethod))
	if _, ok := validSessionAuthMethods[normalized.AuthMethod]; !ok {
		return Session{}, fmt.Errorf("invalid auth method")
	}
	normalized.IP = strings.TrimSpace(session.IP)
	normalized.UserAgent = strings.TrimSpace(session.UserAgent)
	if normalized.CreatedAt.IsZero() {
		normalized.CreatedAt = time.Now().UTC()
	} else {
		normalized.CreatedAt = normalized.CreatedAt.UTC()
	}
	if normalized.IdleExpiresAt.IsZero() {
		return Session{}, fmt.Errorf("idle expiry is required")
	}
	normalized.IdleExpiresAt = normalized.IdleExpiresAt.UTC()
	if normalized.AbsoluteExpiresAt.IsZero() {
		return Session{}, fmt.Errorf("absolute expiry is required")
	}
	normalized.AbsoluteExpiresAt = normalized.AbsoluteExpiresAt.UTC()
	if normalized.LastSeenAt.IsZero() {
		normalized.LastSeenAt = normalized.CreatedAt
	} else {
		normalized.LastSeenAt = normalized.LastSeenAt.UTC()
	}
	if normalized.RevokedAt != nil {
		revokedAt := normalized.RevokedAt.UTC()
		normalized.RevokedAt = &revokedAt
	}
	if normalized.User != nil {
		user := *normalized.User
		normalized.User = &user
	}
	return normalized, nil
}

var validOnboardingSteps = map[string]struct{}{
	"org":       {},
	"workspace": {},
	"connect":   {},
	"scan":      {},
	"invite":    {},
	"complete":  {},
}

// NormalizeOnboardingStateForWrite validates and canonicalizes one onboarding state row.
func NormalizeOnboardingStateForWrite(state OnboardingState) (OnboardingState, error) {
	normalized := state
	normalized.UserID = strings.TrimSpace(state.UserID)
	if normalized.UserID == "" {
		return OnboardingState{}, fmt.Errorf("user id is required")
	}
	if _, err := uuid.Parse(normalized.UserID); err != nil {
		return OnboardingState{}, fmt.Errorf("invalid user id")
	}
	normalized.CurrentStep = strings.ToLower(strings.TrimSpace(state.CurrentStep))
	if normalized.CurrentStep == "" {
		normalized.CurrentStep = "org"
	}
	if _, ok := validOnboardingSteps[normalized.CurrentStep]; !ok {
		return OnboardingState{}, fmt.Errorf("onboarding step is invalid")
	}
	normalized.OrgID = strings.TrimSpace(state.OrgID)
	normalized.WorkspaceID = strings.TrimSpace(state.WorkspaceID)
	normalized.ProjectID = strings.TrimSpace(state.ProjectID)
	normalized.ConnectorID = strings.TrimSpace(state.ConnectorID)
	normalized.ConnectorType = strings.ToLower(strings.TrimSpace(state.ConnectorType))
	if normalized.DashboardTourDismissedAt != nil {
		dismissedAt := normalized.DashboardTourDismissedAt.UTC()
		normalized.DashboardTourDismissedAt = &dismissedAt
	}
	if normalized.CompletedAt != nil {
		completedAt := normalized.CompletedAt.UTC()
		normalized.CompletedAt = &completedAt
		normalized.CurrentStep = "complete"
	}
	if normalized.StartedAt.IsZero() {
		normalized.StartedAt = time.Now().UTC()
	} else {
		normalized.StartedAt = normalized.StartedAt.UTC()
	}
	if normalized.UpdatedAt.IsZero() {
		normalized.UpdatedAt = normalized.StartedAt
	} else {
		normalized.UpdatedAt = normalized.UpdatedAt.UTC()
	}
	return normalized, nil
}

// NormalizeInvitationForWrite validates and canonicalizes one organization invite scaffold.
func NormalizeInvitationForWrite(invitation Invitation) (Invitation, error) {
	normalized := invitation
	normalized.ID = strings.TrimSpace(invitation.ID)
	if normalized.ID == "" {
		normalized.ID = uuid.NewString()
	} else if _, err := uuid.Parse(normalized.ID); err != nil {
		return Invitation{}, fmt.Errorf("invalid invitation id")
	}
	normalized.OrgID = strings.TrimSpace(invitation.OrgID)
	if normalized.OrgID == "" {
		return Invitation{}, fmt.Errorf("org id is required")
	}
	normalized.Email = strings.ToLower(strings.TrimSpace(invitation.Email))
	if normalized.Email == "" || !strings.Contains(normalized.Email, "@") {
		return Invitation{}, fmt.Errorf("email is required")
	}
	normalized.Role = strings.ToLower(strings.TrimSpace(invitation.Role))
	if _, ok := validTenancyMemberRoles[normalized.Role]; !ok {
		return Invitation{}, fmt.Errorf("invalid invitation role")
	}
	normalized.InvitedByUserID = strings.TrimSpace(invitation.InvitedByUserID)
	if normalized.InvitedByUserID != "" {
		if _, err := uuid.Parse(normalized.InvitedByUserID); err != nil {
			return Invitation{}, fmt.Errorf("invalid inviter user id")
		}
	}
	if len(normalized.TokenHash) != sha256.Size {
		return Invitation{}, fmt.Errorf("token hash must be %d bytes", sha256.Size)
	}
	normalized.TokenHash = append([]byte(nil), normalized.TokenHash...)
	if normalized.CreatedAt.IsZero() {
		normalized.CreatedAt = time.Now().UTC()
	} else {
		normalized.CreatedAt = normalized.CreatedAt.UTC()
	}
	if normalized.ExpiresAt.IsZero() {
		return Invitation{}, fmt.Errorf("expires_at is required")
	}
	normalized.ExpiresAt = normalized.ExpiresAt.UTC()
	if !normalized.ExpiresAt.After(normalized.CreatedAt) {
		return Invitation{}, fmt.Errorf("expires_at must be after created_at")
	}
	if normalized.AcceptedAt != nil {
		acceptedAt := normalized.AcceptedAt.UTC()
		normalized.AcceptedAt = &acceptedAt
	}
	if normalized.RevokedAt != nil {
		revokedAt := normalized.RevokedAt.UTC()
		normalized.RevokedAt = &revokedAt
	}
	if normalized.AcceptedAt != nil && normalized.RevokedAt != nil {
		return Invitation{}, fmt.Errorf("invitation cannot be both accepted and revoked")
	}
	return normalized, nil
}

// NormalizeVerifiedDomainForWrite validates and canonicalizes one domain-verification scaffold.
func NormalizeVerifiedDomainForWrite(domain VerifiedDomain) (VerifiedDomain, error) {
	normalized := domain
	normalized.ID = strings.TrimSpace(domain.ID)
	if normalized.ID == "" {
		normalized.ID = uuid.NewString()
	} else if _, err := uuid.Parse(normalized.ID); err != nil {
		return VerifiedDomain{}, fmt.Errorf("invalid verified domain id")
	}
	normalized.OrgID = strings.TrimSpace(domain.OrgID)
	if normalized.OrgID == "" {
		return VerifiedDomain{}, fmt.Errorf("org id is required")
	}
	normalized.Domain = strings.ToLower(strings.Trim(strings.TrimSpace(domain.Domain), "."))
	if normalized.Domain == "" || strings.ContainsAny(normalized.Domain, "/:@") {
		return VerifiedDomain{}, fmt.Errorf("invalid domain")
	}
	normalized.VerificationToken = strings.TrimSpace(domain.VerificationToken)
	if normalized.VerificationToken == "" {
		return VerifiedDomain{}, fmt.Errorf("verification token is required")
	}
	normalized.VerificationMethod = strings.ToLower(strings.TrimSpace(domain.VerificationMethod))
	if normalized.VerificationMethod == "" {
		normalized.VerificationMethod = "dns_txt"
	}
	if normalized.VerificationMethod != "dns_txt" && normalized.VerificationMethod != "manual" {
		return VerifiedDomain{}, fmt.Errorf("invalid verification method")
	}
	if normalized.VerifiedAt != nil {
		verifiedAt := normalized.VerifiedAt.UTC()
		normalized.VerifiedAt = &verifiedAt
	}
	if normalized.CreatedAt.IsZero() {
		normalized.CreatedAt = time.Now().UTC()
	} else {
		normalized.CreatedAt = normalized.CreatedAt.UTC()
	}
	return normalized, nil
}

// NormalizeIdentityConnectionForWrite validates and canonicalizes one enterprise identity connection scaffold.
func NormalizeIdentityConnectionForWrite(connection IdentityConnection) (IdentityConnection, error) {
	normalized := connection
	normalized.ID = strings.TrimSpace(connection.ID)
	if normalized.ID == "" {
		normalized.ID = uuid.NewString()
	} else if _, err := uuid.Parse(normalized.ID); err != nil {
		return IdentityConnection{}, fmt.Errorf("invalid identity connection id")
	}
	normalized.OrgID = strings.TrimSpace(connection.OrgID)
	if normalized.OrgID == "" {
		return IdentityConnection{}, fmt.Errorf("org id is required")
	}
	normalized.Provider = strings.ToLower(strings.TrimSpace(connection.Provider))
	if _, ok := validIdentityConnectionProviders[normalized.Provider]; !ok {
		return IdentityConnection{}, fmt.Errorf("invalid identity provider")
	}
	normalized.Type = strings.ToLower(strings.TrimSpace(connection.Type))
	if _, ok := validIdentityConnectionTypes[normalized.Type]; !ok {
		return IdentityConnection{}, fmt.Errorf("invalid identity connection type")
	}
	normalized.WorkOSConnectionID = strings.TrimSpace(connection.WorkOSConnectionID)
	normalized.Status = strings.ToLower(strings.TrimSpace(connection.Status))
	if normalized.Status == "" {
		normalized.Status = "pending"
	}
	if _, ok := validIdentityConnectionStatuses[normalized.Status]; !ok {
		return IdentityConnection{}, fmt.Errorf("invalid identity connection status")
	}
	normalized.GroupRoleMap = normalizeGroupRoleMap(connection.GroupRoleMap)
	normalized.EntityID = strings.TrimSpace(connection.EntityID)
	normalized.SSOURL = strings.TrimSpace(connection.SSOURL)
	normalized.CertificatePEM = strings.TrimSpace(connection.CertificatePEM)
	normalized.SCIMBearerTokenHash = strings.TrimSpace(connection.SCIMBearerTokenHash)
	normalized.AttributeMapping = normalizeAttributeMapping(connection.AttributeMapping)

	if err := validateSAMLCompleteness(normalized); err != nil {
		return IdentityConnection{}, err
	}

	if normalized.CreatedAt.IsZero() {
		normalized.CreatedAt = time.Now().UTC()
	} else {
		normalized.CreatedAt = normalized.CreatedAt.UTC()
	}
	if normalized.UpdatedAt.IsZero() {
		normalized.UpdatedAt = normalized.CreatedAt
	} else {
		normalized.UpdatedAt = normalized.UpdatedAt.UTC()
	}
	return normalized, nil
}

// validateSAMLCompleteness mirrors the identity_connections_saml_completeness
// CHECK constraint at the Go layer so memory-mode CRUD enforces the same
// contract as Postgres. A SAML row must be exactly one of:
//   - WorkOS-backed: workos_connection_id set, native fields empty
//   - Native: entity_id + certificate_pem + https sso_url all set,
//     workos_connection_id empty
//
// Mixed-mode rows are rejected so the runtime cannot end up confused about
// which protocol path owns the connection.
func validateSAMLCompleteness(c IdentityConnection) error {
	if c.Provider != "saml" {
		return nil
	}
	if c.WorkOSConnectionID != "" {
		if c.EntityID != "" || c.CertificatePEM != "" || c.SSOURL != "" {
			return fmt.Errorf("workos-backed saml connection cannot set native fields (entity_id, certificate_pem, sso_url)")
		}
		return nil
	}
	missing := []string{}
	if c.EntityID == "" {
		missing = append(missing, "entity_id")
	}
	if c.CertificatePEM == "" {
		missing = append(missing, "certificate_pem")
	}
	if c.SSOURL == "" {
		missing = append(missing, "sso_url")
	} else if err := validateNativeSSOURL(c.SSOURL); err != nil {
		return err
	}
	if len(missing) > 0 {
		return fmt.Errorf("native saml connection is missing required fields: %s", strings.Join(missing, ", "))
	}
	return nil
}

// validateNativeSSOURL enforces that the persisted SSO URL is not just a
// string starting with https:// but a parseable absolute URL with an actual
// hostname. Without this, payloads like "https://", "https://%zz",
// "https:///path", or port-only authorities like "https://:443/path" would
// pass the SQL CHECK and the prefix check yet fail the first time the SAML
// ACS handler tries to redirect the user to the IdP.
//
// Hostname() is used over Host so a "https://:443" port-only authority is
// correctly rejected — Host returns ":443" (non-empty) but Hostname returns
// the empty string.
func validateNativeSSOURL(raw string) error {
	if !strings.HasPrefix(strings.ToLower(raw), "https://") {
		return fmt.Errorf("saml sso_url must use https://")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("saml sso_url is not a valid URL: %w", err)
	}
	if parsed.Hostname() == "" {
		return fmt.Errorf("saml sso_url must include a host")
	}
	return nil
}

func normalizeAttributeMapping(values map[string]string) map[string]string {
	if len(values) == 0 {
		return map[string]string{}
	}
	out := make(map[string]string, len(values))
	for k, v := range values {
		key := strings.TrimSpace(k)
		val := strings.TrimSpace(v)
		if key == "" || val == "" {
			continue
		}
		out[key] = val
	}
	return out
}

var validSCIMProvisioningOps = map[string]struct{}{
	"create":     {},
	"update":     {},
	"deactivate": {},
	"delete":     {},
}

// NormalizeSCIMProvisioningEventForWrite validates and canonicalizes one
// persisted SCIM provisioning event prior to insert.
func NormalizeSCIMProvisioningEventForWrite(event SCIMProvisioningEventRecord) (SCIMProvisioningEventRecord, error) {
	normalized := event
	normalized.ID = strings.TrimSpace(event.ID)
	if normalized.ID == "" {
		normalized.ID = uuid.NewString()
	} else if _, err := uuid.Parse(normalized.ID); err != nil {
		return SCIMProvisioningEventRecord{}, fmt.Errorf("invalid scim provisioning event id")
	}
	normalized.OrgID = strings.TrimSpace(event.OrgID)
	if normalized.OrgID == "" {
		return SCIMProvisioningEventRecord{}, fmt.Errorf("org id is required")
	}
	normalized.ConnectionID = strings.TrimSpace(event.ConnectionID)
	if normalized.ConnectionID == "" {
		return SCIMProvisioningEventRecord{}, fmt.Errorf("connection id is required")
	}
	if _, err := uuid.Parse(normalized.ConnectionID); err != nil {
		return SCIMProvisioningEventRecord{}, fmt.Errorf("invalid connection id")
	}
	normalized.Op = strings.ToLower(strings.TrimSpace(event.Op))
	if _, ok := validSCIMProvisioningOps[normalized.Op]; !ok {
		return SCIMProvisioningEventRecord{}, fmt.Errorf("invalid scim provisioning op %q", event.Op)
	}
	normalized.ExternalID = strings.TrimSpace(event.ExternalID)
	normalized.UserID = strings.TrimSpace(event.UserID)
	if normalized.UserID != "" {
		if _, err := uuid.Parse(normalized.UserID); err != nil {
			return SCIMProvisioningEventRecord{}, fmt.Errorf("invalid user id")
		}
	}
	if normalized.Payload == nil {
		normalized.Payload = map[string]any{}
	}
	if normalized.OccurredAt.IsZero() {
		normalized.OccurredAt = time.Now().UTC()
	} else {
		normalized.OccurredAt = normalized.OccurredAt.UTC()
	}
	return normalized, nil
}

func normalizeGroupRoleMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return map[string]string{}
	}
	normalized := make(map[string]string, len(values))
	for group, role := range values {
		group = strings.TrimSpace(group)
		role = strings.ToLower(strings.TrimSpace(role))
		if group == "" {
			continue
		}
		if _, ok := validTenancyMemberRoles[role]; !ok {
			continue
		}
		normalized[group] = role
	}
	return normalized
}

// NormalizeTenancyProjectForWrite validates and canonicalizes project metadata.
func NormalizeTenancyProjectForWrite(project TenancyProject) (TenancyProject, error) {
	normalized := project
	normalized.TenantID = strings.TrimSpace(project.TenantID)
	if normalized.TenantID == "" {
		return TenancyProject{}, fmt.Errorf("tenant id is required")
	}
	normalized.WorkspaceID = strings.TrimSpace(project.WorkspaceID)
	if normalized.WorkspaceID == "" {
		return TenancyProject{}, fmt.Errorf("workspace id is required")
	}
	normalized.ProjectID = strings.TrimSpace(project.ProjectID)
	if normalized.ProjectID == "" {
		return TenancyProject{}, fmt.Errorf("project id is required")
	}
	normalized.Name = strings.TrimSpace(project.Name)
	if normalized.Name == "" {
		return TenancyProject{}, fmt.Errorf("project name is required")
	}
	normalized.Slug = strings.ToLower(strings.TrimSpace(project.Slug))
	if normalized.Slug == "" {
		return TenancyProject{}, fmt.Errorf("project slug is required")
	}
	if err := validateTenancySlug(normalized.Slug, "project slug"); err != nil {
		return TenancyProject{}, err
	}
	normalized.Description = strings.TrimSpace(project.Description)
	if normalized.ArchivedAt != nil {
		archived := normalized.ArchivedAt.UTC()
		normalized.ArchivedAt = &archived
	}
	if normalized.CreatedAt.IsZero() {
		normalized.CreatedAt = time.Now().UTC()
	} else {
		normalized.CreatedAt = normalized.CreatedAt.UTC()
	}
	if normalized.UpdatedAt.IsZero() {
		normalized.UpdatedAt = normalized.CreatedAt
	} else {
		normalized.UpdatedAt = normalized.UpdatedAt.UTC()
	}
	return normalized, nil
}

// NormalizeTenancyScanPolicyForWrite validates and canonicalizes project scan policies.
func NormalizeTenancyScanPolicyForWrite(policy TenancyScanPolicy) (TenancyScanPolicy, error) {
	normalized := policy
	normalized.TenantID = strings.TrimSpace(policy.TenantID)
	if normalized.TenantID == "" {
		return TenancyScanPolicy{}, fmt.Errorf("tenant id is required")
	}
	normalized.WorkspaceID = strings.TrimSpace(policy.WorkspaceID)
	if normalized.WorkspaceID == "" {
		return TenancyScanPolicy{}, fmt.Errorf("workspace id is required")
	}
	normalized.ProjectID = strings.TrimSpace(policy.ProjectID)
	if normalized.ProjectID == "" {
		return TenancyScanPolicy{}, fmt.Errorf("project id is required")
	}
	normalized.PolicyID = strings.TrimSpace(policy.PolicyID)
	if normalized.PolicyID == "" {
		return TenancyScanPolicy{}, fmt.Errorf("policy id is required")
	}
	normalized.Name = strings.TrimSpace(policy.Name)
	if normalized.Name == "" {
		return TenancyScanPolicy{}, fmt.Errorf("scan policy name is required")
	}
	normalized.TriggerMode = domain.ScanTriggerMode(strings.ToLower(strings.TrimSpace(string(policy.TriggerMode))))
	if normalized.TriggerMode == "" {
		normalized.TriggerMode = domain.ScanTriggerModeManual
	}
	switch normalized.TriggerMode {
	case domain.ScanTriggerModeManual, domain.ScanTriggerModeScheduled, domain.ScanTriggerModeEvent, domain.ScanTriggerModeHybrid:
	default:
		return TenancyScanPolicy{}, fmt.Errorf("invalid scan policy trigger mode")
	}
	normalized.Cron = strings.TrimSpace(policy.Cron)
	if normalized.TriggerMode == domain.ScanTriggerModeScheduled || normalized.TriggerMode == domain.ScanTriggerModeHybrid {
		if normalized.Cron == "" {
			return TenancyScanPolicy{}, fmt.Errorf("scan policy cron is required for scheduled or hybrid trigger mode")
		}
	} else {
		normalized.Cron = ""
	}
	if normalized.MaxConcurrentScans <= 0 {
		normalized.MaxConcurrentScans = 1
	}
	if normalized.HistoryLimit <= 0 {
		normalized.HistoryLimit = defaultTenancyScanPolicyHistoryLimit
	}
	if normalized.MaxFindings <= 0 {
		normalized.MaxFindings = defaultTenancyScanPolicyMaxFindings
	}
	if normalized.LastScheduledAt != nil {
		lastScheduledAt := normalized.LastScheduledAt.UTC()
		normalized.LastScheduledAt = &lastScheduledAt
	}
	if normalized.CreatedAt.IsZero() {
		normalized.CreatedAt = time.Now().UTC()
	} else {
		normalized.CreatedAt = normalized.CreatedAt.UTC()
	}
	if normalized.UpdatedAt.IsZero() {
		normalized.UpdatedAt = normalized.CreatedAt
	} else {
		normalized.UpdatedAt = normalized.UpdatedAt.UTC()
	}
	return normalized, nil
}

// NormalizeTenancyConnectorForWrite validates and canonicalizes source connector metadata.
func NormalizeTenancyConnectorForWrite(connector TenancyConnector) (TenancyConnector, error) {
	normalized := connector
	normalized.TenantID = strings.TrimSpace(connector.TenantID)
	if normalized.TenantID == "" {
		return TenancyConnector{}, fmt.Errorf("tenant id is required")
	}
	normalized.WorkspaceID = strings.TrimSpace(connector.WorkspaceID)
	if normalized.WorkspaceID == "" {
		return TenancyConnector{}, fmt.Errorf("workspace id is required")
	}
	normalized.ProjectID = strings.TrimSpace(connector.ProjectID)
	if normalized.ProjectID == "" {
		return TenancyConnector{}, fmt.Errorf("project id is required")
	}
	normalized.ConnectorID = strings.TrimSpace(connector.ConnectorID)
	if normalized.ConnectorID == "" {
		return TenancyConnector{}, fmt.Errorf("connector id is required")
	}
	normalized.Type = domain.ConnectorType(strings.ToLower(strings.TrimSpace(string(connector.Type))))
	switch normalized.Type {
	case domain.ConnectorTypeGitHub, domain.ConnectorTypeAWS, domain.ConnectorTypeKubernetes:
	default:
		return TenancyConnector{}, fmt.Errorf("invalid connector type")
	}
	normalized.DisplayName = strings.TrimSpace(connector.DisplayName)
	if normalized.DisplayName == "" {
		return TenancyConnector{}, fmt.Errorf("connector display name is required")
	}
	normalized.Status = domain.ConnectorStatus(strings.ToLower(strings.TrimSpace(string(connector.Status))))
	if normalized.Status == "" {
		normalized.Status = domain.ConnectorStatusPending
	}
	switch normalized.Status {
	case domain.ConnectorStatusPending, domain.ConnectorStatusActive, domain.ConnectorStatusDegraded, domain.ConnectorStatusDisconnected:
	default:
		return TenancyConnector{}, fmt.Errorf("invalid connector status")
	}
	normalized.SecretProvider = strings.TrimSpace(connector.SecretProvider)
	normalized.SecretRefID = strings.TrimSpace(connector.SecretRefID)
	normalized.SecretRefVersion = strings.TrimSpace(connector.SecretRefVersion)
	if (normalized.SecretProvider == "") != (normalized.SecretRefID == "") {
		return TenancyConnector{}, fmt.Errorf("secret provider and secret ref id must be set together")
	}
	if normalized.SecretLastRotatedAt != nil {
		rotated := normalized.SecretLastRotatedAt.UTC()
		normalized.SecretLastRotatedAt = &rotated
	}
	normalized.ConfigChecksum = strings.TrimSpace(connector.ConfigChecksum)
	if normalized.LastSyncAt != nil {
		synced := normalized.LastSyncAt.UTC()
		normalized.LastSyncAt = &synced
	}
	if normalized.CreatedAt.IsZero() {
		normalized.CreatedAt = time.Now().UTC()
	} else {
		normalized.CreatedAt = normalized.CreatedAt.UTC()
	}
	if normalized.UpdatedAt.IsZero() {
		normalized.UpdatedAt = normalized.CreatedAt
	} else {
		normalized.UpdatedAt = normalized.UpdatedAt.UTC()
	}
	return normalized, nil
}

// NormalizeTenancyConnectorStateForWrite validates and canonicalizes connector health state.
func NormalizeTenancyConnectorStateForWrite(state TenancyConnectorState) (TenancyConnectorState, error) {
	normalized := state
	normalized.TenantID = strings.TrimSpace(state.TenantID)
	if normalized.TenantID == "" {
		return TenancyConnectorState{}, fmt.Errorf("tenant id is required")
	}
	normalized.WorkspaceID = strings.TrimSpace(state.WorkspaceID)
	if normalized.WorkspaceID == "" {
		return TenancyConnectorState{}, fmt.Errorf("workspace id is required")
	}
	normalized.ProjectID = strings.TrimSpace(state.ProjectID)
	if normalized.ProjectID == "" {
		return TenancyConnectorState{}, fmt.Errorf("project id is required")
	}
	normalized.ConnectorID = strings.TrimSpace(state.ConnectorID)
	if normalized.ConnectorID == "" {
		return TenancyConnectorState{}, fmt.Errorf("connector id is required")
	}
	normalized.HealthStatus = strings.ToLower(strings.TrimSpace(state.HealthStatus))
	if normalized.HealthStatus == "" {
		normalized.HealthStatus = "unknown"
	}
	switch normalized.HealthStatus {
	case "unknown", "healthy", "warning", "error":
	default:
		return TenancyConnectorState{}, fmt.Errorf("invalid connector health status")
	}
	normalized.SyncCursor = strings.TrimSpace(state.SyncCursor)
	if normalized.LastSuccessfulSyncAt != nil {
		synced := normalized.LastSuccessfulSyncAt.UTC()
		normalized.LastSuccessfulSyncAt = &synced
	}
	normalized.LastErrorCode = strings.TrimSpace(state.LastErrorCode)
	normalized.LastErrorMessage = strings.TrimSpace(state.LastErrorMessage)
	if normalized.Metadata == nil {
		normalized.Metadata = map[string]any{}
	} else {
		normalized.Metadata = cloneMetadataMap(normalized.Metadata)
	}
	if normalized.ObservedAt.IsZero() {
		normalized.ObservedAt = time.Now().UTC()
	} else {
		normalized.ObservedAt = normalized.ObservedAt.UTC()
	}
	if normalized.UpdatedAt.IsZero() {
		normalized.UpdatedAt = normalized.ObservedAt
	} else {
		normalized.UpdatedAt = normalized.UpdatedAt.UTC()
	}
	return normalized, nil
}

// NormalizeAWSAccountRegionCoverageForWrite validates and canonicalizes one AWS
// account/region coverage record before persistence.
func NormalizeAWSAccountRegionCoverageForWrite(coverage AWSAccountRegionCoverage) (AWSAccountRegionCoverage, error) {
	normalized := coverage
	normalized.TenantID = strings.TrimSpace(coverage.TenantID)
	if normalized.TenantID == "" {
		return AWSAccountRegionCoverage{}, fmt.Errorf("tenant id is required")
	}
	normalized.WorkspaceID = strings.TrimSpace(coverage.WorkspaceID)
	if normalized.WorkspaceID == "" {
		return AWSAccountRegionCoverage{}, fmt.Errorf("workspace id is required")
	}
	normalized.ProjectID = strings.TrimSpace(coverage.ProjectID)
	if normalized.ProjectID == "" {
		return AWSAccountRegionCoverage{}, fmt.Errorf("project id is required")
	}
	normalized.ConnectorID = strings.TrimSpace(coverage.ConnectorID)
	if normalized.ConnectorID == "" {
		return AWSAccountRegionCoverage{}, fmt.Errorf("connector id is required")
	}
	normalized.AccountID = strings.TrimSpace(coverage.AccountID)
	if !validAWSAccountID(normalized.AccountID) {
		return AWSAccountRegionCoverage{}, fmt.Errorf("aws account id must be 12 digits")
	}
	normalized.AccountAlias = strings.TrimSpace(coverage.AccountAlias)
	normalized.OrganizationID = strings.TrimSpace(coverage.OrganizationID)
	normalized.OUPath = strings.TrimSpace(coverage.OUPath)
	normalized.Partition = strings.ToLower(strings.TrimSpace(coverage.Partition))
	if normalized.Partition == "" {
		normalized.Partition = "aws"
	}
	normalized.Region = strings.ToLower(strings.TrimSpace(coverage.Region))
	if normalized.Region == "" {
		return AWSAccountRegionCoverage{}, fmt.Errorf("region is required")
	}
	normalized.RoleARN = strings.TrimSpace(coverage.RoleARN)
	normalized.CoverageStatus = strings.ToLower(strings.TrimSpace(coverage.CoverageStatus))
	if normalized.CoverageStatus == "" {
		switch {
		case normalized.Suspended:
			normalized.CoverageStatus = AWSAccountRegionCoverageSuspended
		case normalized.Disabled:
			normalized.CoverageStatus = AWSAccountRegionCoverageDisabled
		case normalized.Unreachable:
			normalized.CoverageStatus = AWSAccountRegionCoverageUnreachable
		case strings.TrimSpace(coverage.LastObservedErrorCode) != "" || strings.TrimSpace(coverage.LastObservedErrorMessage) != "":
			normalized.CoverageStatus = AWSAccountRegionCoverageError
		default:
			normalized.CoverageStatus = AWSAccountRegionCoverageUnknown
		}
	}
	switch normalized.CoverageStatus {
	case AWSAccountRegionCoverageUnknown,
		AWSAccountRegionCoveragePending,
		AWSAccountRegionCoverageCovered,
		AWSAccountRegionCoverageGap,
		AWSAccountRegionCoverageError,
		AWSAccountRegionCoverageSuspended,
		AWSAccountRegionCoverageDisabled,
		AWSAccountRegionCoverageUnreachable:
	default:
		return AWSAccountRegionCoverage{}, fmt.Errorf("invalid aws coverage status")
	}
	switch normalized.CoverageStatus {
	case AWSAccountRegionCoverageSuspended:
		if !normalized.Suspended || normalized.Disabled || normalized.Unreachable {
			return AWSAccountRegionCoverage{}, fmt.Errorf("aws coverage status %q requires only the suspended flag", normalized.CoverageStatus)
		}
	case AWSAccountRegionCoverageDisabled:
		if !normalized.Disabled || normalized.Suspended || normalized.Unreachable {
			return AWSAccountRegionCoverage{}, fmt.Errorf("aws coverage status %q requires only the disabled flag", normalized.CoverageStatus)
		}
	case AWSAccountRegionCoverageUnreachable:
		if !normalized.Unreachable || normalized.Suspended || normalized.Disabled {
			return AWSAccountRegionCoverage{}, fmt.Errorf("aws coverage status %q requires only the unreachable flag", normalized.CoverageStatus)
		}
	default:
		if normalized.Suspended || normalized.Disabled || normalized.Unreachable {
			return AWSAccountRegionCoverage{}, fmt.Errorf("aws coverage status %q must not set blocked-state flags", normalized.CoverageStatus)
		}
	}
	if normalized.LastSuccessfulScanAt != nil {
		scanned := normalized.LastSuccessfulScanAt.UTC()
		normalized.LastSuccessfulScanAt = &scanned
	}
	normalized.LastObservedErrorCode = strings.TrimSpace(coverage.LastObservedErrorCode)
	normalized.LastObservedErrorMessage = strings.TrimSpace(coverage.LastObservedErrorMessage)
	if normalized.ScanCursor == nil {
		normalized.ScanCursor = map[string]any{}
	} else {
		normalized.ScanCursor = cloneMetadataMap(normalized.ScanCursor)
	}
	if normalized.CreatedAt.IsZero() {
		normalized.CreatedAt = time.Now().UTC()
	} else {
		normalized.CreatedAt = normalized.CreatedAt.UTC()
	}
	if normalized.UpdatedAt.IsZero() {
		normalized.UpdatedAt = normalized.CreatedAt
	} else {
		normalized.UpdatedAt = normalized.UpdatedAt.UTC()
	}
	return normalized, nil
}

// NormalizeAWSPlatformBaselineResultForWrite validates and canonicalizes one AWS
// platform baseline gate result before persistence.
func NormalizeAWSPlatformBaselineResultForWrite(result AWSPlatformBaselineResult) (AWSPlatformBaselineResult, error) {
	normalized := result
	normalized.TenantID = strings.TrimSpace(result.TenantID)
	if normalized.TenantID == "" {
		return AWSPlatformBaselineResult{}, fmt.Errorf("tenant id is required")
	}
	normalized.WorkspaceID = strings.TrimSpace(result.WorkspaceID)
	if normalized.WorkspaceID == "" {
		return AWSPlatformBaselineResult{}, fmt.Errorf("workspace id is required")
	}
	normalized.ProjectID = strings.TrimSpace(result.ProjectID)
	if normalized.ProjectID == "" {
		return AWSPlatformBaselineResult{}, fmt.Errorf("project id is required")
	}
	normalized.ConnectorID = strings.TrimSpace(result.ConnectorID)
	normalized.GitSHA = strings.TrimSpace(result.GitSHA)
	normalized.SourceMode = strings.ToLower(strings.TrimSpace(result.SourceMode))
	normalized.ConnectorProfileVersion = strings.TrimSpace(result.ConnectorProfileVersion)
	normalized.GraphContractVersion = strings.TrimSpace(result.GraphContractVersion)
	normalized.AccountID = strings.TrimSpace(result.AccountID)
	if normalized.AccountID != "" && !validAWSAccountID(normalized.AccountID) {
		return AWSPlatformBaselineResult{}, fmt.Errorf("aws account id must be 12 digits")
	}
	normalized.Region = strings.ToLower(strings.TrimSpace(result.Region))
	normalized.Status = strings.ToLower(strings.TrimSpace(result.Status))
	if normalized.Status == "" {
		normalized.Status = AWSPlatformBaselineStatusNotRun
	}
	switch normalized.Status {
	case AWSPlatformBaselineStatusNotRun,
		AWSPlatformBaselineStatusReady,
		AWSPlatformBaselineStatusDegraded,
		AWSPlatformBaselineStatusBlocked:
	default:
		return AWSPlatformBaselineResult{}, fmt.Errorf("invalid aws platform baseline status")
	}
	normalized.Confidence = clampConfidence(result.Confidence)
	normalized.FailureReasons = normalizeStringList(result.FailureReasons)
	normalized.EvidenceLinks = normalizeStringList(result.EvidenceLinks)
	normalized.Checks = normalizeAWSPlatformBaselineChecks(result.Checks)
	if normalized.FailureReasons == nil {
		normalized.FailureReasons = []string{}
	}
	if normalized.EvidenceLinks == nil {
		normalized.EvidenceLinks = []string{}
	}
	if normalized.Checks == nil {
		normalized.Checks = []AWSPlatformBaselineCheck{}
	}
	if normalized.VerifiedAt.IsZero() {
		normalized.VerifiedAt = time.Now().UTC()
	} else {
		normalized.VerifiedAt = normalized.VerifiedAt.UTC()
	}
	if normalized.CreatedAt.IsZero() {
		normalized.CreatedAt = normalized.VerifiedAt
	} else {
		normalized.CreatedAt = normalized.CreatedAt.UTC()
	}
	if normalized.UpdatedAt.IsZero() {
		normalized.UpdatedAt = normalized.VerifiedAt
	} else {
		normalized.UpdatedAt = normalized.UpdatedAt.UTC()
	}
	return normalized, nil
}

func normalizeAWSPlatformBaselineChecks(checks []AWSPlatformBaselineCheck) []AWSPlatformBaselineCheck {
	if len(checks) == 0 {
		return []AWSPlatformBaselineCheck{}
	}
	normalized := make([]AWSPlatformBaselineCheck, 0, len(checks))
	for _, check := range checks {
		item := check
		item.Name = strings.TrimSpace(check.Name)
		if item.Name == "" {
			continue
		}
		item.Category = strings.TrimSpace(check.Category)
		item.Status = strings.ToLower(strings.TrimSpace(check.Status))
		switch item.Status {
		case AWSPlatformBaselineCheckPassed,
			AWSPlatformBaselineCheckFailed,
			AWSPlatformBaselineCheckDegraded,
			AWSPlatformBaselineCheckPermissionDenied,
			AWSPlatformBaselineCheckUnknown,
			AWSPlatformBaselineCheckSkipped:
		default:
			item.Status = AWSPlatformBaselineCheckUnknown
		}
		item.Message = strings.TrimSpace(check.Message)
		item.FailureReason = strings.TrimSpace(check.FailureReason)
		item.Remediation = strings.TrimSpace(check.Remediation)
		item.EvidenceURL = strings.TrimSpace(check.EvidenceURL)
		item.Confidence = clampConfidence(check.Confidence)
		if item.Evidence == nil {
			item.Evidence = map[string]any{}
		} else {
			item.Evidence = cloneMetadataMap(item.Evidence)
		}
		if item.CheckedAt.IsZero() {
			item.CheckedAt = time.Now().UTC()
		} else {
			item.CheckedAt = item.CheckedAt.UTC()
		}
		normalized = append(normalized, item)
	}
	return normalized
}

func normalizeStringList(items []string) []string {
	if len(items) == 0 {
		return []string{}
	}
	normalized := make([]string, 0, len(items))
	seen := map[string]struct{}{}
	for _, item := range items {
		value := strings.TrimSpace(item)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		normalized = append(normalized, value)
	}
	return normalized
}

func clampConfidence(confidence float64) float64 {
	switch {
	case confidence < 0:
		return 0
	case confidence > 1:
		return 1
	default:
		return confidence
	}
}

func validAWSAccountID(accountID string) bool {
	if len(accountID) != 12 {
		return false
	}
	for _, char := range accountID {
		if char < '0' || char > '9' {
			return false
		}
	}
	return true
}

// NormalizeTenancyConnectorSecretEnvelopeForWrite validates one connector secret envelope record.
func NormalizeTenancyConnectorSecretEnvelopeForWrite(secret TenancyConnectorSecretEnvelope) (TenancyConnectorSecretEnvelope, error) {
	normalized := secret
	normalized.TenantID = strings.TrimSpace(secret.TenantID)
	if normalized.TenantID == "" {
		return TenancyConnectorSecretEnvelope{}, fmt.Errorf("tenant id is required")
	}
	normalized.WorkspaceID = strings.TrimSpace(secret.WorkspaceID)
	if normalized.WorkspaceID == "" {
		return TenancyConnectorSecretEnvelope{}, fmt.Errorf("workspace id is required")
	}
	normalized.ProjectID = strings.TrimSpace(secret.ProjectID)
	if normalized.ProjectID == "" {
		return TenancyConnectorSecretEnvelope{}, fmt.Errorf("project id is required")
	}
	normalized.ConnectorID = strings.TrimSpace(secret.ConnectorID)
	if normalized.ConnectorID == "" {
		return TenancyConnectorSecretEnvelope{}, fmt.Errorf("connector id is required")
	}
	normalized.SecretName = strings.TrimSpace(secret.SecretName)
	if normalized.SecretName == "" {
		return TenancyConnectorSecretEnvelope{}, fmt.Errorf("secret name is required")
	}
	if normalized.EnvelopeVersion <= 0 {
		normalized.EnvelopeVersion = 1
	}
	normalized.Envelope.Version = normalized.EnvelopeVersion
	normalized.Envelope.Algorithm = strings.TrimSpace(secret.Envelope.Algorithm)
	normalized.Envelope.KeyVersion = strings.TrimSpace(secret.Envelope.KeyVersion)
	normalized.Envelope.Nonce = append([]byte(nil), secret.Envelope.Nonce...)
	normalized.Envelope.Ciphertext = append([]byte(nil), secret.Envelope.Ciphertext...)
	if normalized.Envelope.Algorithm != secretstore.AlgorithmAES256GCM {
		return TenancyConnectorSecretEnvelope{}, fmt.Errorf("invalid connector secret envelope algorithm")
	}
	if normalized.Envelope.KeyVersion == "" {
		return TenancyConnectorSecretEnvelope{}, fmt.Errorf("connector secret envelope key version is required")
	}
	if len(normalized.Envelope.Nonce) != 12 {
		return TenancyConnectorSecretEnvelope{}, fmt.Errorf("connector secret envelope nonce is invalid")
	}
	if len(normalized.Envelope.Ciphertext) == 0 {
		return TenancyConnectorSecretEnvelope{}, fmt.Errorf("connector secret envelope ciphertext is required")
	}
	normalized.SecretRefID = strings.TrimSpace(secret.SecretRefID)
	if normalized.RotationDueAt != nil {
		due := normalized.RotationDueAt.UTC()
		normalized.RotationDueAt = &due
	}
	if normalized.RotatedAt.IsZero() {
		normalized.RotatedAt = time.Now().UTC()
	} else {
		normalized.RotatedAt = normalized.RotatedAt.UTC()
	}
	if normalized.CreatedAt.IsZero() {
		normalized.CreatedAt = normalized.RotatedAt
	} else {
		normalized.CreatedAt = normalized.CreatedAt.UTC()
	}
	if normalized.UpdatedAt.IsZero() {
		normalized.UpdatedAt = normalized.RotatedAt
	} else {
		normalized.UpdatedAt = normalized.UpdatedAt.UTC()
	}
	return normalized, nil
}

func cloneMetadataMap(metadata map[string]any) map[string]any {
	if len(metadata) == 0 {
		return map[string]any{}
	}
	cloned := make(map[string]any, len(metadata))
	for key, value := range metadata {
		cloned[key] = value
	}
	return cloned
}

// NormalizeAuthzPolicyEventForWrite validates and canonicalizes one immutable policy event.
func NormalizeAuthzPolicyEventForWrite(event AuthzPolicyEvent) (AuthzPolicyEvent, error) {
	normalized := event
	normalized.ID = strings.TrimSpace(event.ID)
	policySetID, err := normalizeAuthzPolicySetID(event.PolicySetID)
	if err != nil {
		return AuthzPolicyEvent{}, err
	}
	normalized.PolicySetID = policySetID
	normalized.EventType = strings.ToLower(strings.TrimSpace(event.EventType))
	if normalized.EventType == "" {
		return AuthzPolicyEvent{}, fmt.Errorf("event type is required")
	}
	if normalized.FromVersion != nil && *normalized.FromVersion <= 0 {
		return AuthzPolicyEvent{}, fmt.Errorf("from version must be greater than zero")
	}
	if normalized.ToVersion != nil && *normalized.ToVersion <= 0 {
		return AuthzPolicyEvent{}, fmt.Errorf("to version must be greater than zero")
	}
	normalized.Actor = strings.TrimSpace(event.Actor)
	normalized.Message = strings.TrimSpace(event.Message)
	if normalized.CreatedAt.IsZero() {
		normalized.CreatedAt = time.Now().UTC()
	} else {
		normalized.CreatedAt = normalized.CreatedAt.UTC()
	}
	return normalized, nil
}

func normalizeAuthzPolicySetID(value string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if normalized == "" {
		return "", fmt.Errorf("policy set id is required")
	}
	if !authzOwnerTeamPattern.MatchString(normalized) {
		return "", fmt.Errorf("invalid policy set id format")
	}
	return normalized, nil
}

// IdentityFilter controls identity list query shape.
type IdentityFilter struct {
	ScanID     string
	Provider   string
	Type       string
	NamePrefix string
}

// RelationshipFilter controls relationship list query shape.
type RelationshipFilter struct {
	ScanID     string
	Type       string
	FromNodeID string
	ToNodeID   string
}

// RepoFindingFilter controls repository finding list queries.
type RepoFindingFilter struct {
	RepoScanID        string
	FindingID         string
	Repository        string
	Severity          string
	Type              string
	Status            string
	Detector          string
	Owner             string
	Source            string
	MinConfidence     float64
	MinAgeDays        int
	LifecycleStatus   string
	Assignee          string
	SortBy            string
	SortDesc          bool
	Now               time.Time
	IncludeHistorical bool
}

// RepoFindingClusterListFilter controls repository finding cluster list queries.
type RepoFindingClusterListFilter struct {
	RepoScanID string
	Severity   string
	Type       string
	SortBy     string
	SortDesc   bool
	Limit      int
	Offset     int
}

// FindingListFilter controls filtered finding list queries.
type FindingListFilter struct {
	ScanID          string
	FindingID       string
	Severity        string
	Type            string
	LifecycleStatus string
	Assignee        string
	SortBy          string
	SortDesc        bool
	Limit           int
	Offset          int
	Now             time.Time
}

// NormalizeFindingListFilter trims inputs and applies stable defaults.
func NormalizeFindingListFilter(filter FindingListFilter) FindingListFilter {
	normalized := FindingListFilter{
		ScanID:          strings.TrimSpace(filter.ScanID),
		FindingID:       strings.TrimSpace(filter.FindingID),
		Severity:        strings.ToLower(strings.TrimSpace(filter.Severity)),
		Type:            strings.ToLower(strings.TrimSpace(filter.Type)),
		LifecycleStatus: strings.ToLower(strings.TrimSpace(filter.LifecycleStatus)),
		Assignee:        strings.ToLower(strings.TrimSpace(filter.Assignee)),
		SortDesc:        filter.SortDesc,
		Limit:           filter.Limit,
		Offset:          filter.Offset,
		Now:             filter.Now.UTC(),
	}
	switch strings.ToLower(strings.TrimSpace(filter.SortBy)) {
	case "severity", "type", "title":
		normalized.SortBy = strings.ToLower(strings.TrimSpace(filter.SortBy))
	default:
		normalized.SortBy = "created_at"
	}
	if normalized.Limit <= 0 {
		normalized.Limit = 100
	}
	if normalized.Offset < 0 {
		normalized.Offset = 0
	}
	if normalized.Now.IsZero() {
		normalized.Now = time.Now().UTC()
	}
	return normalized
}

// NormalizeRepoFindingClusterListFilter trims inputs and applies stable defaults.
func NormalizeRepoFindingClusterListFilter(filter RepoFindingClusterListFilter) RepoFindingClusterListFilter {
	normalized := RepoFindingClusterListFilter{
		RepoScanID: strings.TrimSpace(filter.RepoScanID),
		Severity:   strings.ToLower(strings.TrimSpace(filter.Severity)),
		Type:       strings.ToLower(strings.TrimSpace(filter.Type)),
		SortDesc:   filter.SortDesc,
		Limit:      filter.Limit,
		Offset:     filter.Offset,
	}
	switch strings.ToLower(strings.TrimSpace(filter.SortBy)) {
	case "count", "severity", "repository", "detector", "first_seen_at":
		normalized.SortBy = strings.ToLower(strings.TrimSpace(filter.SortBy))
	default:
		normalized.SortBy = "last_seen_at"
	}
	if normalized.Limit <= 0 {
		normalized.Limit = 100
	}
	if normalized.Offset < 0 {
		normalized.Offset = 0
	}
	return normalized
}

// NormalizeRepoFindingFilter trims optional filters for repository findings.
func NormalizeRepoFindingFilter(filter RepoFindingFilter) RepoFindingFilter {
	rawSortBy := strings.ToLower(strings.TrimSpace(filter.SortBy))
	sortBy := rawSortBy
	sortDesc := filter.SortDesc
	switch sortBy {
	case "severity", "type", "title", "created_at", "first_seen_at", "last_seen_at", "status", "owner":
	default:
		sortBy = "created_at"
		if rawSortBy == "" {
			sortDesc = true
		}
	}
	now := filter.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	minConfidence := filter.MinConfidence
	if minConfidence < 0 {
		minConfidence = 0
	}
	if minConfidence > 1 {
		minConfidence = 1
	}

	normalized := RepoFindingFilter{
		RepoScanID:        strings.TrimSpace(filter.RepoScanID),
		FindingID:         strings.TrimSpace(filter.FindingID),
		Repository:        strings.TrimSpace(filter.Repository),
		Severity:          strings.ToLower(strings.TrimSpace(filter.Severity)),
		Type:              strings.ToLower(strings.TrimSpace(filter.Type)),
		Status:            strings.ToLower(strings.TrimSpace(filter.Status)),
		Detector:          strings.ToLower(strings.TrimSpace(filter.Detector)),
		Owner:             strings.ToLower(strings.TrimSpace(filter.Owner)),
		Source:            strings.ToLower(strings.TrimSpace(filter.Source)),
		MinConfidence:     minConfidence,
		MinAgeDays:        filter.MinAgeDays,
		LifecycleStatus:   strings.ToLower(strings.TrimSpace(filter.LifecycleStatus)),
		Assignee:          strings.ToLower(strings.TrimSpace(filter.Assignee)),
		SortBy:            sortBy,
		SortDesc:          sortDesc,
		Now:               now,
		IncludeHistorical: filter.IncludeHistorical,
	}
	if normalized.MinAgeDays < 0 {
		normalized.MinAgeDays = 0
	}
	return normalized
}

func shouldCloseMissingRepoFindings(status string, truncated bool, scanContext RepoScanContext) bool {
	normalizedStatus := strings.ToLower(strings.TrimSpace(status))
	if normalizedStatus != "succeeded" && normalizedStatus != "completed" {
		return false
	}
	if truncated {
		return false
	}
	normalizedContext := NormalizeRepoScanContext(scanContext)
	if normalizedContext.PartialSourceRun {
		return false
	}
	return normalizedContext.ScanMode == "deep" && len(normalizedContext.ChangedPaths) == 0
}

// NormalizeFindingTriage returns a stable, API-shaped finding triage state.
func NormalizeFindingTriage(triage domain.FindingTriage, now time.Time) domain.FindingTriage {
	normalized := triage
	if normalized.Status == "" {
		normalized.Status = domain.FindingLifecycleOpen
	}
	switch normalized.Status {
	case domain.FindingLifecycleOpen, domain.FindingLifecycleAck, domain.FindingLifecycleSuppressed, domain.FindingLifecycleResolved:
	default:
		normalized.Status = domain.FindingLifecycleOpen
	}
	if normalized.Status == domain.FindingLifecycleSuppressed &&
		normalized.SuppressionExpiresAt != nil &&
		!normalized.SuppressionExpiresAt.After(now) {
		normalized.Status = domain.FindingLifecycleOpen
		normalized.SuppressionExpiresAt = nil
	}
	if normalized.Status != domain.FindingLifecycleSuppressed {
		normalized.SuppressionExpiresAt = nil
	}
	if normalized.Status != domain.FindingLifecycleResolved {
		normalized.ResolvedAt = nil
	}
	return normalized
}

func applyRepoFindingLifecycleSnapshot(finding *domain.Finding, snapshot domain.Finding, observedAt time.Time) domain.RepoFindingLifecycleStatus {
	if finding == nil {
		return domain.RepoFindingLifecycleOpen
	}
	switch snapshot.LifecycleStatus {
	case domain.RepoFindingLifecycleFixed:
		reopenedAt := observedAt.UTC()
		finding.ReopenedAt = &reopenedAt
		return domain.RepoFindingLifecycleReopened
	case domain.RepoFindingLifecycleSuppressed, domain.RepoFindingLifecycleRiskAccepted, domain.RepoFindingLifecycleFalsePositive:
		if repoFindingDismissalExpired(snapshot, observedAt) {
			reopenedAt := observedAt.UTC()
			finding.ReopenedAt = &reopenedAt
			finding.DismissedAt = nil
			finding.SuppressionExpiresAt = nil
			return domain.RepoFindingLifecycleReopened
		}
		finding.DismissedAt = cloneTimePointer(snapshot.DismissedAt)
		finding.SuppressionExpiresAt = cloneTimePointer(snapshot.SuppressionExpiresAt)
		return snapshot.LifecycleStatus
	case domain.RepoFindingLifecycleReopened:
		finding.ReopenedAt = cloneTimePointer(snapshot.ReopenedAt)
		return domain.RepoFindingLifecycleReopened
	default:
		return domain.RepoFindingLifecycleOpen
	}
}

func repoFindingDismissalExpired(snapshot domain.Finding, observedAt time.Time) bool {
	if snapshot.SuppressionExpiresAt == nil || snapshot.SuppressionExpiresAt.IsZero() {
		return false
	}
	evaluationTime := observedAt.UTC()
	if evaluationTime.IsZero() {
		evaluationTime = time.Now().UTC()
	}
	return !snapshot.SuppressionExpiresAt.After(evaluationTime)
}

// FindingMeta is the lightweight shape used for trend/diff set operations.
type FindingMeta struct {
	ID        string
	ScanID    string
	Severity  string
	Type      string
	CreatedAt time.Time
}

// FindingTrendCount aggregates finding totals for one scan and severity bucket.
type FindingTrendCount struct {
	ScanID     string
	StartedAt  time.Time
	Severity   string
	TotalCount int
}

// Store defines persistence operations required by API and scheduler orchestration.
type Store interface {
	CreateScan(ctx context.Context, provider string, startedAt time.Time) (ScanRecord, error)
	CreateQueuedScan(ctx context.Context, provider string, queuedAt time.Time) (ScanRecord, error)
	CreateQueuedScanWithSource(ctx context.Context, provider string, source ScanSource, queuedAt time.Time) (ScanRecord, error)
	CreateQueuedScanWithinLimit(ctx context.Context, provider string, queuedAt time.Time, maxPending int) (ScanRecord, error)
	CreateQueuedScanWithinLimitWithSource(ctx context.Context, provider string, source ScanSource, queuedAt time.Time, maxPending int) (ScanRecord, error)
	CreateQueuedScanIfNoPending(ctx context.Context, provider string, queuedAt time.Time) (ScanRecord, error)
	CreateQueuedScanIfNoPendingWithSource(ctx context.Context, provider string, source ScanSource, queuedAt time.Time) (ScanRecord, error)
	ClaimNextQueuedScan(ctx context.Context, provider string) (ScanRecord, error)
	ClaimNextQueuedScanAnyScope(ctx context.Context, provider string) (ScanRecord, error)
	CountQueuedScans(ctx context.Context, provider string) (int, error)
	CountQueuedScansWithSource(ctx context.Context, provider string, source ScanSource) (int, error)
	CountPendingScansWithSource(ctx context.Context, provider string, source ScanSource) (int, error)
	GetScan(ctx context.Context, scanID string) (ScanRecord, error)
	CompleteScan(ctx context.Context, scanID string, status string, finishedAt time.Time, assetCount int, findingCount int, errorMessage string) error
	ScheduleScanRetry(ctx context.Context, scanID string, queuedAt time.Time, retryCount int, maxRetryCount int, failureCategory string, errorMessage string, nextRetryAt time.Time) error
	DeadLetterScan(ctx context.Context, scanID string, finishedAt time.Time, retryCount int, maxRetryCount int, assetCount int, findingCount int, failureCategory string, errorMessage string) error
	UpsertArtifacts(ctx context.Context, scanID string, artifacts ScanArtifacts) error
	UpsertFindings(ctx context.Context, scanID string, findings []domain.Finding) error
	GetFindingTriageState(ctx context.Context, findingID string) (FindingTriageState, error)
	ListFindingTriageStates(ctx context.Context, findingIDs []string) ([]FindingTriageState, error)
	UpsertFindingTriageState(ctx context.Context, state FindingTriageState) error
	AppendFindingTriageEvent(ctx context.Context, event FindingTriageEvent) error
	ApplyFindingTriageTransition(ctx context.Context, state FindingTriageState, event FindingTriageEvent) error
	ListFindingTriageEvents(ctx context.Context, findingID string, limit int) ([]FindingTriageEvent, error)
	ListScans(ctx context.Context, limit int) ([]ScanRecord, error)
	ListFindings(ctx context.Context, limit int) ([]domain.Finding, error)
	ListFindingsFiltered(ctx context.Context, filter FindingListFilter) ([]domain.Finding, error)
	ListFindingsAll(ctx context.Context) ([]domain.Finding, error)
	ListFindingsByScan(ctx context.Context, scanID string, limit int) ([]domain.Finding, error)
	GetFinding(ctx context.Context, findingID string, scanID string) (domain.Finding, error)
	ListFindingMetasByScan(ctx context.Context, scanID string) ([]FindingMeta, error)
	ListFindingsByScanAndIDs(ctx context.Context, scanID string, findingIDs []string) ([]domain.Finding, error)
	ListFindingTrendCounts(ctx context.Context, scanIDs []string, severity string, findingType string) ([]FindingTrendCount, error)
	ListRepoFindingTrendCounts(ctx context.Context, repoScanIDs []string, severity string, findingType string) ([]FindingTrendCount, error)
	UpsertAuthzEntityAttributes(ctx context.Context, attributes AuthzEntityAttributes) error
	GetAuthzEntityAttributes(ctx context.Context, entityKind string, entityType string, entityID string) (AuthzEntityAttributes, error)
	UpsertAuthzRelationship(ctx context.Context, relationship AuthzRelationship) error
	DeleteAuthzRelationship(ctx context.Context, relationship AuthzRelationship) error
	ListAuthzRelationships(ctx context.Context, filter AuthzRelationshipFilter, limit int) ([]AuthzRelationship, error)
	UpsertAuthzPolicySet(ctx context.Context, policySet AuthzPolicySet) error
	GetAuthzPolicySet(ctx context.Context, policySetID string) (AuthzPolicySet, error)
	CreateAuthzPolicyVersion(ctx context.Context, version AuthzPolicyVersion) (AuthzPolicyVersion, error)
	GetAuthzPolicyVersion(ctx context.Context, policySetID string, version int) (AuthzPolicyVersion, error)
	ListAuthzPolicyVersions(ctx context.Context, policySetID string, limit int) ([]AuthzPolicyVersion, error)
	UpsertAuthzPolicyRollout(ctx context.Context, rollout AuthzPolicyRollout) error
	GetAuthzPolicyRollout(ctx context.Context, policySetID string) (AuthzPolicyRollout, error)
	AppendAuthzPolicyEvent(ctx context.Context, event AuthzPolicyEvent) error
	ListAuthzPolicyEvents(ctx context.Context, policySetID string, limit int) ([]AuthzPolicyEvent, error)
	UpsertOrganization(ctx context.Context, organization TenancyOrganization) error
	GetOrganization(ctx context.Context) (TenancyOrganization, error)
	DeleteOrganization(ctx context.Context) error
	UpsertWorkspace(ctx context.Context, workspace TenancyWorkspace) error
	GetWorkspace(ctx context.Context, workspaceID string) (TenancyWorkspace, error)
	ListWorkspaces(ctx context.Context, limit int) ([]TenancyWorkspace, error)
	DeleteWorkspace(ctx context.Context, workspaceID string) error
	// SuspendWorkspace flips the workspace to status=suspended and stamps
	// suspended_at. Idempotent: a repeat call preserves the original
	// suspended_at so an over-eager UI cannot drift the timestamp.
	SuspendWorkspace(ctx context.Context, workspaceID string, now time.Time) (TenancyWorkspace, error)
	// ReactivateWorkspace flips a suspended workspace back to active and
	// clears suspended_at. A no-op on an already-active workspace.
	ReactivateWorkspace(ctx context.Context, workspaceID string, now time.Time) (TenancyWorkspace, error)
	// SoftDeleteWorkspace flips the workspace to status=deleted and stamps
	// deleted_at to start the reversible grace window. Idempotent: a repeat
	// call preserves the original deleted_at so the purge deadline cannot
	// be pushed back.
	SoftDeleteWorkspace(ctx context.Context, workspaceID string, now time.Time) (TenancyWorkspace, error)
	// CancelWorkspaceDeletion reverses a soft delete during the grace
	// window: clears deleted_at and returns the workspace to status=active.
	CancelWorkspaceDeletion(ctx context.Context, workspaceID string, now time.Time) (TenancyWorkspace, error)
	// ListWorkspaceStrandedActiveMembers returns the OTHER active members
	// in the workspace iff the caller is the sole active owner. An empty
	// slice means no stranding would occur — either there are co-owners,
	// or the caller is the only member. Used to gate suspend/delete with
	// the structured `sole_owner_requires_transfer` 409 from #1420.
	ListWorkspaceStrandedActiveMembers(ctx context.Context, workspaceID string, userUUID string) ([]TenancyWorkspaceMember, error)
	// ListWorkspacesPendingHardDelete returns soft-deleted workspaces
	// whose grace window closed (deleted_at < deletedBefore), so the
	// workspace hard-delete worker can purge them. Bypasses scope so
	// the worker enumerates across tenants.
	ListWorkspacesPendingHardDelete(ctx context.Context, deletedBefore time.Time, limit int) ([]TenancyWorkspace, error)
	// HardDeleteWorkspace permanently removes a workspace whose
	// soft-delete grace window has elapsed. The (tenantID, workspaceID)
	// pair is the composite identity — workspace_id alone is not
	// globally unique (defaults like "default" repeat across tenants),
	// so a tenant-less lookup risks destroying a different tenant's
	// data. expectedDeletedAt is the deleted_at the worker observed
	// when it listed this row; the destructive SQL requires the
	// current row's deleted_at to still match, so a cancel-deletion +
	// re-delete race between the worker's list and its purge refreshes
	// the row to a new fresh-grace deleted_at and is correctly refused.
	//
	// Implementations refuse the purge unless the row is genuinely past
	// grace (status='deleted', deleted_at = expectedDeletedAt). Cascades
	// to every child table with an FK on tenancy_workspaces (members,
	// projects, connectors, secret envelopes, scan policies) and
	// explicitly purges every workspace-scoped non-FK table the
	// migrations have introduced (scans, repo_scans, AWS coverage,
	// authz tables, finding triage). Returns the deleted workspace row
	// for audit metadata.
	HardDeleteWorkspace(ctx context.Context, tenantID, workspaceID string, expectedDeletedAt time.Time, now time.Time) (TenancyWorkspace, error)
	UpsertWorkspaceMember(ctx context.Context, member TenancyWorkspaceMember) error
	GetWorkspaceMember(ctx context.Context, workspaceID string, memberID string) (TenancyWorkspaceMember, error)
	GetWorkspaceMemberByUserUUID(ctx context.Context, workspaceID string, userUUID string) (TenancyWorkspaceMember, error)
	ListWorkspaceMembers(ctx context.Context, workspaceID string, limit int) ([]TenancyWorkspaceMember, error)
	DeleteWorkspaceMember(ctx context.Context, workspaceID string, memberID string) error
	UpsertProject(ctx context.Context, project TenancyProject) error
	GetProject(ctx context.Context, workspaceID string, projectID string) (TenancyProject, error)
	ListProjects(ctx context.Context, workspaceID string, includeArchived bool, limit int) ([]TenancyProject, error)
	DeleteProject(ctx context.Context, workspaceID string, projectID string) error
	UpsertTenancyConnector(ctx context.Context, connector TenancyConnector, state TenancyConnectorState) error
	GetTenancyConnector(ctx context.Context, workspaceID string, projectID string, connectorID string) (TenancyConnectorWithState, error)
	ListTenancyConnectors(ctx context.Context, workspaceID string, projectID string, connectorType domain.ConnectorType, limit int) ([]TenancyConnectorWithState, error)
	ListTenancyConnectorsUnscoped(ctx context.Context, connectorType domain.ConnectorType, limit int) ([]TenancyConnectorWithState, error)
	UpsertAWSAccountRegionCoverage(ctx context.Context, coverage AWSAccountRegionCoverage) (AWSAccountRegionCoverage, error)
	ListAWSAccountRegionCoverages(ctx context.Context, filter AWSAccountRegionCoverageFilter) ([]AWSAccountRegionCoverage, error)
	UpsertAWSPlatformBaselineResult(ctx context.Context, result AWSPlatformBaselineResult) (AWSPlatformBaselineResult, error)
	GetAWSPlatformBaselineResult(ctx context.Context, filter AWSPlatformBaselineFilter) (AWSPlatformBaselineResult, error)
	ClaimKubernetesEnrollmentToken(ctx context.Context, workspaceID string, projectID string, connectorID string, expectedEnrollmentTokenHash string, updatedMetadata map[string]any, status domain.ConnectorStatus, health string, lastErrorCode string, lastErrorMessage string, observedAt time.Time, updatedAt time.Time) (bool, error)
	UpsertTenancyScanPolicy(ctx context.Context, policy TenancyScanPolicy) error
	GetTenancyScanPolicy(ctx context.Context, workspaceID string, projectID string, policyID string) (TenancyScanPolicy, error)
	ListTenancyScanPolicies(ctx context.Context, workspaceID string, projectID string, triggerMode domain.ScanTriggerMode, enabled *bool, sortBy string, sortDesc bool, limit int) ([]TenancyScanPolicy, error)
	ListScheduledTenancyScanPolicies(ctx context.Context, limit int, offset int) ([]TenancyScanPolicy, error)
	ClaimTenancyScanPolicySchedule(ctx context.Context, workspaceID string, projectID string, policyID string, scheduledAt time.Time, now time.Time) (bool, error)
	DeleteTenancyScanPolicy(ctx context.Context, workspaceID string, projectID string, policyID string) error
	UpsertTenancyConnectorSecretEnvelope(ctx context.Context, envelope TenancyConnectorSecretEnvelope) error
	GetTenancyConnectorSecretEnvelope(ctx context.Context, workspaceID string, projectID string, connectorID string, secretName string) (TenancyConnectorSecretEnvelope, error)
	DeleteTenancyConnectorSecretEnvelope(ctx context.Context, workspaceID string, projectID string, connectorID string, secretName string) error
	UpsertUser(ctx context.Context, user User) (User, error)
	UpdateUserProfile(ctx context.Context, user User) (User, error)
	UpdateCurrentUserProfile(ctx context.Context, userID string, displayName *string, avatarURL *string, updatedAt time.Time) (User, error)
	GetUser(ctx context.Context, userID string) (User, error)
	GetUserByPrimaryEmail(ctx context.Context, email string) (User, error)
	SetUserStatus(ctx context.Context, userID string, status string, now time.Time) (User, error)
	// SoftDeleteUser flips the account to status=deleted and stamps deleted_at
	// to start the reversible grace window. Idempotent: an already-deleted row
	// keeps its original deleted_at so repeat calls cannot extend the deadline.
	SoftDeleteUser(ctx context.Context, userID string, now time.Time) (User, error)
	// CancelUserDeletion reverses a soft delete during the grace window: it
	// clears deleted_at and returns the account to status=active.
	CancelUserDeletion(ctx context.Context, userID string, now time.Time) (User, error)
	// ListUsersPendingHardDelete returns soft-deleted accounts whose grace
	// window closed (deleted_at < deletedBefore) and whose PII has not already
	// been purged, so the worker can hard-delete them.
	ListUsersPendingHardDelete(ctx context.Context, deletedBefore time.Time, limit int) ([]User, error)
	// HardDeleteUser purges PII from a soft-deleted account (email tombstoned,
	// display name and avatar cleared) and deletes its provider identities and
	// sessions, while keeping the users row so audit references by UUID stay
	// intact. Idempotent and safely re-runnable.
	HardDeleteUser(ctx context.Context, userID string, now time.Time) (User, error)
	UpsertUserIdentity(ctx context.Context, identity UserIdentity) (UserIdentity, error)
	GetUserIdentity(ctx context.Context, provider string, subject string) (UserIdentity, error)
	GetUserIdentityByProviderUserID(ctx context.Context, provider string, userID string) (UserIdentity, error)
	ListUserIdentitiesByProvider(ctx context.Context, provider string, limit int) ([]UserIdentity, error)
	DeleteUserIdentity(ctx context.Context, provider string, subject string) error
	CreateSession(ctx context.Context, session Session) (Session, error)
	TouchSession(ctx context.Context, sessionIDHash []byte, now time.Time) (Session, error)
	// TouchSessionAllowingPendingDeletion is TouchSession with the lifecycle
	// gate relaxed so cookies pointing to a soft-deleted-within-grace user
	// resolve to their session. It is the single-purpose authentication path
	// for `/v1/me/cancel-deletion` — every other route uses TouchSession and
	// continues to refuse deleted users.
	TouchSessionAllowingPendingDeletion(ctx context.Context, sessionIDHash []byte, now time.Time) (Session, error)
	UpdateSessionContext(ctx context.Context, userID string, sessionIDHash []byte, orgID string, workspaceID string, projectID string, now time.Time) (Session, error)
	ListUserSessions(ctx context.Context, userID string, now time.Time, limit int) ([]Session, error)
	ListUserSessionHistory(ctx context.Context, userID string, limit int) ([]Session, error)
	RevokeUserSession(ctx context.Context, userID string, sessionIDHash []byte, revokedAt time.Time) (Session, error)
	RevokeOtherUserSessions(ctx context.Context, userID string, currentSessionIDHash []byte, revokedAt time.Time) (int, error)
	RevokeAllUserSessions(ctx context.Context, userID string, revokedAt time.Time) (int, error)
	// CreateUserDataExport enqueues a new "Download my data" export job for
	// the caller. The store generates an ID if one is not supplied.
	CreateUserDataExport(ctx context.Context, export UserDataExport) (UserDataExport, error)
	// GetUserDataExport returns one export job, scoped to its owner. Returns
	// ErrNotFound if the row does not exist OR belongs to a different user so
	// scoping cannot be bypassed by guessing job ids.
	GetUserDataExport(ctx context.Context, userID string, jobID string) (UserDataExport, error)
	// GetUserDataExportByID returns one export job by id without scoping to a
	// caller. Used by the signed-download route, which authorizes via the
	// HMAC token rather than a session cookie.
	GetUserDataExportByID(ctx context.Context, jobID string) (UserDataExport, error)
	// ListUserDataExports returns the user's export jobs, newest first.
	ListUserDataExports(ctx context.Context, userID string, limit int) ([]UserDataExport, error)
	// ClaimNextQueuedUserDataExport atomically transitions one queued job to
	// running and returns it. Returns ErrNotFound when nothing is queued.
	ClaimNextQueuedUserDataExport(ctx context.Context, now time.Time) (UserDataExport, error)
	// ClaimQueuedUserDataExport atomically transitions the named queued job to
	// running and returns it. Returns ErrNotFound if the job is already claimed
	// or terminal.
	ClaimQueuedUserDataExport(ctx context.Context, jobID string, now time.Time) (UserDataExport, error)
	// CompleteUserDataExport marks a running job ready and records the
	// finished bundle's metadata and TTLs.
	CompleteUserDataExport(ctx context.Context, jobID string, bundlePath string, sizeBytes int64, sha256Hex string, completedAt time.Time, downloadExpiresAt time.Time, purgeAfter time.Time) (UserDataExport, error)
	// FailUserDataExport marks a job failed and records the error message.
	FailUserDataExport(ctx context.Context, jobID string, errMsg string, failedAt time.Time) (UserDataExport, error)
	// FailStaleRunningUserDataExports marks running jobs as failed when they
	// have been running since before startedBefore and returns the jobs that were
	// transitioned. Workers use this after restarts so interrupted jobs do not
	// remain running forever.
	FailStaleRunningUserDataExports(ctx context.Context, startedBefore time.Time, failedAt time.Time, limit int, errMsg string) ([]UserDataExport, error)
	// ListUserDataExportsPendingPurge returns ready jobs whose retention
	// window has elapsed and whose bundle file has not yet been removed.
	ListUserDataExportsPendingPurge(ctx context.Context, now time.Time, limit int) ([]UserDataExport, error)
	// MarkUserDataExportPurged transitions a job to expired and stamps
	// purged_at after the worker has removed the bundle from storage.
	MarkUserDataExportPurged(ctx context.Context, jobID string, now time.Time) (UserDataExport, error)
	UpsertOnboardingState(ctx context.Context, state OnboardingState) (OnboardingState, error)
	GetOnboardingState(ctx context.Context, userID string) (OnboardingState, error)
	FindFirstWorkspaceMemberByUserUUID(ctx context.Context, userUUID string) (TenancyWorkspaceMember, error)
	FindFirstWorkspaceMemberByUserUUIDAndTenantID(ctx context.Context, userUUID string, tenantID string) (TenancyWorkspaceMember, error)
	ListWorkspaceMembershipsByUserUUID(ctx context.Context, userUUID string) ([]TenancyWorkspaceMember, error)
	ListWorkspaceMembershipsByUserUUIDAndTenantID(ctx context.Context, userUUID string, tenantID string) ([]TenancyWorkspaceMember, error)
	// ListSoleOwnerWorkspaces returns every workspace, across all tenants, in
	// which the user is the only active owner. Account deletion uses this to
	// refuse with a structured 409 until ownership is transferred.
	ListSoleOwnerWorkspaces(ctx context.Context, userUUID string) ([]TenancyWorkspace, error)
	CreateInvitation(ctx context.Context, invitation Invitation) (Invitation, error)
	GetInvitation(ctx context.Context, orgID string, invitationID string) (Invitation, error)
	ListInvitations(ctx context.Context, orgID string, limit int) ([]Invitation, error)
	RevokeInvitation(ctx context.Context, orgID string, invitationID string, revokedAt time.Time) (Invitation, error)
	CreateVerifiedDomain(ctx context.Context, domain VerifiedDomain) (VerifiedDomain, error)
	GetVerifiedDomain(ctx context.Context, orgID string, domainID string) (VerifiedDomain, error)
	ListVerifiedDomains(ctx context.Context, orgID string, limit int) ([]VerifiedDomain, error)
	CreateIdentityConnection(ctx context.Context, connection IdentityConnection) (IdentityConnection, error)
	GetIdentityConnection(ctx context.Context, orgID string, connectionID string) (IdentityConnection, error)
	// GetIdentityConnectionByID looks up a connection by its globally unique
	// UUID without requiring the caller to know the owning org id. Needed
	// for unauthenticated entry points like /auth/saml/login/:connection_id
	// where the org context is determined by the connection itself.
	GetIdentityConnectionByID(ctx context.Context, connectionID string) (IdentityConnection, error)
	GetIdentityConnectionBySCIMBearerTokenHash(ctx context.Context, tokenHash string) (IdentityConnection, error)
	// CreateSAMLRelayState persists one in-flight SAML SP-initiated request
	// so the matching ACS POST (potentially handled by a different API
	// instance) can look the AuthnRequest id, connection scope, and
	// return_to back up by the opaque handle.
	CreateSAMLRelayState(ctx context.Context, state SAMLRelayState) (SAMLRelayState, error)
	// ConsumeSAMLRelayState marks the row consumed and returns the persisted
	// state. A subsequent call with the same handle returns ErrNotFound so
	// the relay value cannot be replayed.
	ConsumeSAMLRelayState(ctx context.Context, handle string, now time.Time) (SAMLRelayState, error)
	// CreateOAuthTransaction persists one in-flight WorkOS OAuth login so the
	// callback (potentially handled by a different API instance) can match
	// the signed state nonce and browser-bound cookie token against a
	// single-use, short-TTL row.
	CreateOAuthTransaction(ctx context.Context, txn OAuthTransaction) (OAuthTransaction, error)
	// ConsumeOAuthTransaction atomically consumes the row matching nonce and
	// cookieToken when it is unexpired and unconsumed, returning the stored
	// transaction. Any later, expired, missing, or cookie-mismatched call
	// returns ErrNotFound so the OAuth state cannot be replayed.
	ConsumeOAuthTransaction(ctx context.Context, nonce string, cookieToken string, now time.Time) (OAuthTransaction, error)
	// BeginWebhookEvent atomically claims a provider webhook event for
	// processing. It returns WebhookEventClaimed when this delivery inserted
	// the row (or reclaimed a stale in-flight row older than
	// WebhookProcessingReclaimAfter) and must apply the side effects;
	// WebhookEventProcessing when another delivery of the same event is
	// still in flight (the caller must return a retryable response, never a
	// success acknowledgement); and WebhookEventProcessed when the event was
	// already fully handled (the caller returns a no-op success). Atomic at
	// the database, so it holds across restarts and concurrent API
	// instances.
	// When the status is WebhookEventClaimed the returned claim token
	// identifies this specific claim; it must be passed back to
	// CompleteWebhookEvent / DeleteWebhookEvent so a handler whose claim was
	// reclaimed (because it ran past WebhookProcessingReclaimAfter and a
	// retry took over) cannot complete or erase the successor's claim. The
	// token is empty for the non-claimed statuses.
	BeginWebhookEvent(ctx context.Context, event WebhookEvent, now time.Time) (WebhookEventStatus, string, error)
	// CompleteWebhookEvent marks a claimed event as fully processed so later
	// duplicate deliveries become no-op successes. Called after side effects
	// are durably applied, or for a deterministic terminal outcome (bad
	// payload, identity conflict) that an identical retry would not resolve.
	// It only acts on the row if claimToken still matches the active claim,
	// so a superseded stale handler cannot mark the successor's in-flight
	// claim processed.
	CompleteWebhookEvent(ctx context.Context, provider string, eventID string, claimToken string, now time.Time) error
	// DeleteWebhookEvent rolls back a claimed webhook row when a transient
	// (server-side) failure prevented the side effects from being applied,
	// so a provider retry can reprocess it. It only deletes the row if
	// claimToken still matches the active claim, so a superseded stale
	// handler cannot erase the successor's claim.
	DeleteWebhookEvent(ctx context.Context, provider string, eventID string, claimToken string) error
	ListIdentityConnections(ctx context.Context, orgID string, limit int) ([]IdentityConnection, error)
	UpdateIdentityConnection(ctx context.Context, connection IdentityConnection) (IdentityConnection, error)
	DeleteIdentityConnection(ctx context.Context, orgID string, connectionID string) error
	CreateSCIMProvisioningEvent(ctx context.Context, event SCIMProvisioningEventRecord) (SCIMProvisioningEventRecord, error)
	ListSCIMProvisioningEvents(ctx context.Context, orgID string, connectionID string, limit int) ([]SCIMProvisioningEventRecord, error)
	ListIdentities(ctx context.Context, filter IdentityFilter, limit int) ([]domain.Identity, error)
	ListRelationships(ctx context.Context, filter RelationshipFilter, limit int) ([]domain.Relationship, error)
	AppendScanEvent(ctx context.Context, scanID string, level string, message string, metadata map[string]any) error
	ListScanEvents(ctx context.Context, scanID string, limit int) ([]ScanEvent, error)
	SummarizeFindings(ctx context.Context) (FindingSummaryCounts, error)
	CreateRepoScan(ctx context.Context, repository string, source RepoScanSource, scanContext RepoScanContext, startedAt time.Time) (RepoScanRecord, error)
	CreateQueuedRepoScan(ctx context.Context, repository string, source RepoScanSource, scanContext RepoScanContext, historyLimit int, maxFindings int, queuedAt time.Time) (RepoScanRecord, error)
	CreateQueuedRepoScanWithinLimit(ctx context.Context, repository string, source RepoScanSource, scanContext RepoScanContext, historyLimit int, maxFindings int, queuedAt time.Time, maxPending int) (RepoScanRecord, error)
	ClaimNextQueuedRepoScan(ctx context.Context) (RepoScanRecord, error)
	ClaimNextQueuedRepoScanAnyScope(ctx context.Context) (RepoScanRecord, error)
	CountQueuedRepoScans(ctx context.Context) (int, error)
	CountPendingRepoScansByRepository(ctx context.Context, repository string) (int, error)
	RequeueRepoScan(ctx context.Context, repoScanID string) error
	FailStaleRepoScansAnyScope(ctx context.Context, staleBefore time.Time, limit int, errorMessage string) (int, error)
	GetRepoScan(ctx context.Context, repoScanID string) (RepoScanRecord, error)
	CancelRepoScan(ctx context.Context, repoScanID string, finishedAt time.Time, errorMessage string) (RepoScanRecord, error)
	CompleteRepoScan(ctx context.Context, repoScanID string, status string, finishedAt time.Time, commitsScanned int, filesScanned int, findingCount int, truncated bool, scanContext RepoScanContext, errorMessage string) error
	GetRepoScanCursor(ctx context.Context, repository string, source RepoScanSource) (RepoScanCursor, error)
	UpsertRepoScanCursor(ctx context.Context, cursor RepoScanCursor) error
	UpsertRepoFindings(ctx context.Context, repoScanID string, findings []domain.Finding) error
	DeleteRepoFindings(ctx context.Context, repoScanID string) error
	ListRepoScans(ctx context.Context, limit int) ([]RepoScanRecord, error)
	ListRepoFindings(ctx context.Context, filter RepoFindingFilter, limit int) ([]domain.Finding, error)
	ListRepoFindingClusters(ctx context.Context, filter RepoFindingClusterListFilter) ([]domain.RepoFindingCluster, error)
	Close() error
}
