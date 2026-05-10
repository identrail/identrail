package db

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/identrail/identrail/internal/domain"
	"github.com/identrail/identrail/internal/providers"
	"github.com/identrail/identrail/internal/secretstore"
)

// ErrNotFound indicates the requested record does not exist.
var ErrNotFound = errors.New("record not found")

// ErrScopeRequired indicates tenant/workspace scope must be provided in context.
var ErrScopeRequired = errors.New("scope is required")

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

const (
	ScanEventLevelDebug = "debug"
	ScanEventLevelInfo  = "info"
	ScanEventLevelWarn  = "warn"
	ScanEventLevelError = "error"

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

// ScanRecord tracks persisted scan execution metadata.
type ScanRecord struct {
	ID           string     `json:"id"`
	TenantID     string     `json:"-"`
	WorkspaceID  string     `json:"-"`
	Provider     string     `json:"provider"`
	Status       string     `json:"status"`
	StartedAt    time.Time  `json:"started_at"`
	FinishedAt   *time.Time `json:"finished_at,omitempty"`
	AssetCount   int        `json:"asset_count"`
	FindingCount int        `json:"finding_count"`
	ErrorMessage string     `json:"error_message,omitempty"`
	TraceParent  string     `json:"-"`
	TraceState   string     `json:"-"`
}

// RepoScanRecord tracks persisted repository exposure scan metadata.
type RepoScanRecord struct {
	ID             string     `json:"id"`
	TenantID       string     `json:"-"`
	WorkspaceID    string     `json:"-"`
	Repository     string     `json:"repository"`
	Status         string     `json:"status"`
	StartedAt      time.Time  `json:"started_at"`
	FinishedAt     *time.Time `json:"finished_at,omitempty"`
	CommitsScanned int        `json:"commits_scanned"`
	FilesScanned   int        `json:"files_scanned"`
	FindingCount   int        `json:"finding_count"`
	Truncated      bool       `json:"truncated"`
	ErrorMessage   string     `json:"error_message,omitempty"`
	HistoryLimit   int        `json:"-"`
	MaxFindings    int        `json:"-"`
	TraceParent    string     `json:"-"`
	TraceState     string     `json:"-"`
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
	UpdatedAt            time.Time                     `json:"updated_at"`
	UpdatedBy            string                        `json:"updated_by,omitempty"`
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
	TenantID    string    `json:"tenant_id"`
	WorkspaceID string    `json:"workspace_id"`
	DisplayName string    `json:"display_name"`
	Slug        string    `json:"slug"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// TenancyWorkspaceMember stores one workspace member assignment.
type TenancyWorkspaceMember struct {
	TenantID    string    `json:"tenant_id"`
	WorkspaceID string    `json:"workspace_id"`
	MemberID    string    `json:"member_id"`
	UserID      string    `json:"user_id"`
	Email       string    `json:"email,omitempty"`
	Role        string    `json:"role"`
	Status      string    `json:"status"`
	JoinedAt    time.Time `json:"joined_at"`
	UpdatedAt   time.Time `json:"updated_at"`
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
	RepoScanID string
	Severity   string
	Type       string
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
	return normalized
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
	CreateQueuedScanWithinLimit(ctx context.Context, provider string, queuedAt time.Time, maxPending int) (ScanRecord, error)
	CreateQueuedScanIfNoPending(ctx context.Context, provider string, queuedAt time.Time) (ScanRecord, error)
	ClaimNextQueuedScan(ctx context.Context, provider string) (ScanRecord, error)
	ClaimNextQueuedScanAnyScope(ctx context.Context, provider string) (ScanRecord, error)
	CountQueuedScans(ctx context.Context, provider string) (int, error)
	GetScan(ctx context.Context, scanID string) (ScanRecord, error)
	CompleteScan(ctx context.Context, scanID string, status string, finishedAt time.Time, assetCount int, findingCount int, errorMessage string) error
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
	UpsertWorkspaceMember(ctx context.Context, member TenancyWorkspaceMember) error
	GetWorkspaceMember(ctx context.Context, workspaceID string, memberID string) (TenancyWorkspaceMember, error)
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
	UpsertTenancyConnectorSecretEnvelope(ctx context.Context, envelope TenancyConnectorSecretEnvelope) error
	GetTenancyConnectorSecretEnvelope(ctx context.Context, workspaceID string, projectID string, connectorID string, secretName string) (TenancyConnectorSecretEnvelope, error)
	ListIdentities(ctx context.Context, filter IdentityFilter, limit int) ([]domain.Identity, error)
	ListRelationships(ctx context.Context, filter RelationshipFilter, limit int) ([]domain.Relationship, error)
	AppendScanEvent(ctx context.Context, scanID string, level string, message string, metadata map[string]any) error
	ListScanEvents(ctx context.Context, scanID string, limit int) ([]ScanEvent, error)
	SummarizeFindings(ctx context.Context) (FindingSummaryCounts, error)
	CreateRepoScan(ctx context.Context, repository string, startedAt time.Time) (RepoScanRecord, error)
	CreateQueuedRepoScan(ctx context.Context, repository string, historyLimit int, maxFindings int, queuedAt time.Time) (RepoScanRecord, error)
	CreateQueuedRepoScanWithinLimit(ctx context.Context, repository string, historyLimit int, maxFindings int, queuedAt time.Time, maxPending int) (RepoScanRecord, error)
	ClaimNextQueuedRepoScan(ctx context.Context) (RepoScanRecord, error)
	ClaimNextQueuedRepoScanAnyScope(ctx context.Context) (RepoScanRecord, error)
	CountQueuedRepoScans(ctx context.Context) (int, error)
	CountPendingRepoScansByRepository(ctx context.Context, repository string) (int, error)
	RequeueRepoScan(ctx context.Context, repoScanID string) error
	GetRepoScan(ctx context.Context, repoScanID string) (RepoScanRecord, error)
	CompleteRepoScan(ctx context.Context, repoScanID string, status string, finishedAt time.Time, commitsScanned int, filesScanned int, findingCount int, truncated bool, errorMessage string) error
	UpsertRepoFindings(ctx context.Context, repoScanID string, findings []domain.Finding) error
	ListRepoScans(ctx context.Context, limit int) ([]RepoScanRecord, error)
	ListRepoFindings(ctx context.Context, filter RepoFindingFilter, limit int) ([]domain.Finding, error)
	Close() error
}
