package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/url"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/identrail/identrail/internal/app"
	"github.com/identrail/identrail/internal/audit"
	awsconnector "github.com/identrail/identrail/internal/connectors/aws"
	githubconnector "github.com/identrail/identrail/internal/connectors/github"
	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/domain"
	emailer "github.com/identrail/identrail/internal/email"
	"github.com/identrail/identrail/internal/findings/standards"
	"github.com/identrail/identrail/internal/providers"
	"github.com/identrail/identrail/internal/remediation/fixpr"
	"github.com/identrail/identrail/internal/repoallowlist"
	"github.com/identrail/identrail/internal/repoexposure"
	"github.com/identrail/identrail/internal/scheduler"
	"github.com/identrail/identrail/internal/secretstore"
	"github.com/identrail/identrail/internal/telemetry"
	"github.com/identrail/identrail/internal/workflow"
	"go.opentelemetry.io/otel/propagation"
)

const (
	defaultRepoScanHistoryLimit      = 500
	defaultRepoScanMaxFindings       = 200
	defaultRepoScanHistoryMax        = 5000
	defaultRepoScanFindingsMax       = 1000
	defaultScanQueueMaxPending       = 25
	defaultScanRetryBaseDelay        = 30 * time.Second
	defaultScanRetryMaxDelay         = 15 * time.Minute
	defaultRepoQueueMaxPending       = 100
	defaultRepoScanRunningStaleAfter = 35 * time.Minute
	defaultRepoScanStaleFailureLimit = 100
	staleRepoScanFailureMessage      = "repository scan exceeded worker timeout before reporting a terminal result"
	userCanceledRepoScanMessage      = "repository scan canceled by user"
	defaultGitHubWebhookReplayWindow = 24 * time.Hour
	defaultGitHubWebhookBurstWindow  = 30 * time.Second
	maxSourceErrorsInEvent           = 25
	repoFindingsTriageFilterStep     = maxCursorFetchLimit
	repoFindingsTriageFilterCap      = maxCursorFetchLimit * 4
	repoFindingSLAHighCritical       = 7 * 24 * time.Hour
	maxRepoFindingBulkDeleteItems    = 5000
	gitHubRepoFindingConfidenceFloor = 0.90
)

const (
	scanLifecycleQueued    = "queued"
	scanLifecycleRunning   = "running"
	scanLifecyclePartial   = "partial"
	scanLifecycleSucceeded = "succeeded"
	scanLifecycleFailed    = "failed"
)

const (
	scanFailureStageConnectorSetup  = "connector_setup"
	scanFailureStageExecution       = "execution"
	scanFailureStageArtifactsStore  = "artifacts_persist"
	scanFailureStageFindingsStore   = "findings_persist"
	scanFailureStageFinalize        = "finalize"
	scanFailureCategoryConnector    = "connector_setup"
	scanFailureCategoryProviderAuth = "provider_auth"
	scanFailureCategoryThrottle     = "provider_throttle"
	scanFailureCategoryTransient    = "provider_transient"
	scanFailureCategoryConfig       = "provider_configuration"
	scanFailureCategoryExecution    = "provider_execution"
	scanFailureCategoryPersistence  = "persistence"
	scanFailureCategoryFinalize     = "finalization"
)

var queueTracePropagator = propagation.TraceContext{}

// ScannerRunner is the scan execution dependency required by API service.
type ScannerRunner interface {
	Run(ctx context.Context) (app.ScanResult, error)
}

// RepoScanExecutor defines repository exposure scanning behavior.
type RepoScanExecutor interface {
	ScanRepository(ctx context.Context, target string) (repoexposure.ScanResult, error)
}

// RepoScanExecutorWithOptions supports incremental repository scan execution.
type RepoScanExecutorWithOptions interface {
	ScanRepositoryWithOptions(ctx context.Context, target string, options repoexposure.ScanOptions) (repoexposure.ScanResult, error)
}

// RepoScannerFactory creates a repository scanner with bounded scan parameters.
type RepoScannerFactory func(historyLimit int, maxFindings int) RepoScanExecutor

// AuthenticatedRepoScannerFactory creates a repository scanner with a short-lived clone credential.
type AuthenticatedRepoScannerFactory func(historyLimit int, maxFindings int, credential repoexposure.HTTPSCloneCredential) RepoScanExecutor

// GitHubInstallationTokenMinter mints short-lived GitHub App installation tokens.
type GitHubInstallationTokenMinter interface {
	Mint(ctx context.Context, installationID int64) (githubconnector.InstallationToken, error)
}

// GitHubCodeScanningAlertCollector lists code-scanning alerts visible to one GitHub App installation.
type GitHubCodeScanningAlertCollector interface {
	ListCodeScanningAlerts(ctx context.Context, installationID int64, repository string) ([]githubconnector.CodeScanningAlert, error)
}

// RepoRemediationPublisher publishes operator-approved repository remediation PRs.
type RepoRemediationPublisher interface {
	PublishRepoExposureRemediation(ctx context.Context, finding domain.Finding, opts fixpr.RepoExposurePublishOptions) (fixpr.PublishResult, standards.RepoExposureRemediation, error)
}

// GitHubSecretScanningAlertCollector lists secret-scanning alerts visible to one GitHub App installation.
type GitHubSecretScanningAlertCollector interface {
	ListSecretScanningAlerts(ctx context.Context, installationID int64, repository string) ([]githubconnector.SecretScanningAlert, error)
}

// GitHubDependabotAlertCollector lists Dependabot alerts visible to one GitHub App installation.
type GitHubDependabotAlertCollector interface {
	ListDependabotAlerts(ctx context.Context, installationID int64, repository string) ([]githubconnector.DependabotAlert, error)
}

// AWSScannerFactory creates a scanner bound to one persisted AWS connector.
type AWSScannerFactory func(ctx context.Context, connection AWSConnectionStatus) (ScannerRunner, error)

// AWSCloudTrailLookupEventsFactory builds a runtime-event ingester
// bound to one persisted AWS connector. The API runtime-events handler
// calls the factory only when a live connector is healthy; if the
// factory is nil, the handler falls back to the fixture path so unit
// tests and offline demos keep working without AWS credentials.
type AWSCloudTrailLookupEventsFactory func(ctx context.Context, connection AWSConnectionStatus) (AWSCloudTrailRuntimeEventIngester, error)

// AWSCloudTrailRuntimeEventIngester is the narrow seam the API layer
// uses to drive one bounded CloudTrail LookupEvents ingestion run.
// internal/runtime/cloudtrail.Ingester implements it; tests can
// implement a fake.
type AWSCloudTrailRuntimeEventIngester interface {
	Ingest(ctx context.Context, request AWSCloudTrailIngestRequest) (AWSCloudTrailIngestResult, error)
}

// AWSCloudTrailDeliverySource selects which CloudTrail delivery
// channel (S3 trail logs or EventBridge/SQS) the delivery factory
// should bind to.
type AWSCloudTrailDeliverySource string

const (
	// AWSCloudTrailDeliverySourceS3 selects the S3 trail log ingester.
	AWSCloudTrailDeliverySourceS3 AWSCloudTrailDeliverySource = "s3"
	// AWSCloudTrailDeliverySourceEventBridge selects the EventBridge
	// (SQS-backed) ingester.
	AWSCloudTrailDeliverySourceEventBridge AWSCloudTrailDeliverySource = "eventbridge"
)

// AWSCloudTrailDeliveryIngesterFactory builds a delivery-channel
// ingester (S3 trail logs or EventBridge/SQS) bound to one persisted
// AWS connector. The factory returns nil for sources the deployment
// does not configure (e.g. no S3 bucket recorded on the connector);
// the runtime-events handler then skips that source for the request.
type AWSCloudTrailDeliveryIngesterFactory func(ctx context.Context, connection AWSConnectionStatus, source AWSCloudTrailDeliverySource) (AWSCloudTrailRuntimeEventIngester, error)

// AWSRuntimeSignalFactory builds an IAM last-used / Access Analyzer
// ingester bound to one persisted AWS connector.
type AWSRuntimeSignalFactory func(ctx context.Context, connection AWSConnectionStatus) (AWSRuntimeSignalIngester, error)

type queuedScanDepthCounter interface {
	CountQueuedScansAnyScope(ctx context.Context, provider string) (int, error)
}

type queuedRepoScanDepthCounter interface {
	CountQueuedRepoScansAnyScope(ctx context.Context) (int, error)
}

// Service orchestrates scan execution and persistence.
type Service struct {
	Store                db.Store
	Scanner              ScannerRunner
	Provider             string
	DefaultScope         db.Scope
	Now                  func() time.Time
	Locker               scheduler.Locker
	LockNamespace        string
	Alerter              FindingAlerter
	OnAlertError         func(error)
	EmailSender          emailer.Sender
	EmailFromAddress     string
	EmailReplyToAddress  string
	EmailAppBaseURL      string
	OnEmailError         func(error)
	OnRepoScanQueueEvent func(RepoScanQueueEvent)
	ReadinessCheck       func(context.Context) error
	Metrics              *telemetry.Metrics
	// Repo scan controls are intentionally separate from cloud identity scan flow.
	RepoScanEnabled                    bool
	RepoScanDefaultHistoryLimit        int
	RepoScanDefaultMaxFindings         int
	RepoScanMaxHistoryLimit            int
	RepoScanMaxFindingsLimit           int
	RepoScanAllowedTargets             []string
	ScanQueueMaxPending                int
	RepoQueueMaxPending                int
	RepoScannerFactory                 RepoScannerFactory
	AuthenticatedRepoScannerFactory    AuthenticatedRepoScannerFactory
	RepoRemediationPublisher           RepoRemediationPublisher
	ConnectorSecretManager             *secretstore.Manager
	KubernetesPreflightFactory         KubernetesConnectorPreflightFactory
	AWSConnectorValidator              AWSConnectorValidator
	AWSScannerFactory                  AWSScannerFactory
	AWSCloudTrailLookupEventsFactory   AWSCloudTrailLookupEventsFactory
	AWSCloudTrailDeliveryFactory       AWSCloudTrailDeliveryIngesterFactory
	AWSRuntimeSignalFactory            AWSRuntimeSignalFactory
	AWSCloudFormationTemplateURL       string
	AWSCloudFormationTemplateSHA       string
	AWSAccountID                       string
	AWSRegistrationTopicARNs           map[string]string
	AWSCloudFormationResponder         AWSCloudFormationResponder
	AWSBaselineGitSHA                  string
	AWSBaselineSourceMode              string
	AWSBaselineFixturePaths            []string
	AWSBaselineConnectorProfileVersion string
	AWSBaselineGraphContractVersion    string
	AWSConnectorCapabilityPolicy       awsconnector.CapabilityPolicy
	WorkflowRouter                     *workflow.Router
	GitHubAppID                        int64
	GitHubAppName                      string
	GitHubAppPrivateKey                string
	GitHubAppWebhookSecret             string
	GitHubPATValidator                 GitHubPATValidator
	GitHubRepositoryLister             GitHubRepositoryLister
	GitHubRepositoryPostureCollector   GitHubRepositoryPostureCollector
	GitHubInstallationTokenMinter      GitHubInstallationTokenMinter
	GitHubInstallationVerifier         GitHubInstallationVerifier
	GitHubCodeScanningAlertCollector   GitHubCodeScanningAlertCollector
	GitHubSecretScanningAlertCollector GitHubSecretScanningAlertCollector
	GitHubDependabotAlertCollector     GitHubDependabotAlertCollector
	GitHubWebhookReplayWindow          time.Duration
	GitHubWebhookBurstWindow           time.Duration
	githubConnectMu                    sync.RWMutex
	githubConnections                  map[string]githubProjectConnection
	githubConnectStates                map[string]githubConnectState
	githubWebhookSeen                  map[string]time.Time
	githubWebhookLastQueued            map[string]time.Time
	kubernetesConnectMu                sync.RWMutex
	kubernetesConnections              map[string]kubernetesProjectConnection
	// UserExportStorage is the bundle backend used by the self-serve
	// "Download my data" endpoints (#1421). nil disables the feature so dev
	// deployments without a configured bundle path return 503 rather than
	// silently failing.
	UserExportStorage UserExportStorage
	// UserExportTokenSecret is the HMAC key used to sign download URLs.
	// Reusing the session signing key keeps deployment configuration
	// minimal — operators do not need to manage a second secret.
	UserExportTokenSecret []byte
}

// UserExportStorage is a minimal interface, matching internal/userexport.Storage,
// that the data-export handlers depend on. Local here so Service tests don't
// have to import the userexport package.
type UserExportStorage interface {
	Put(ctx context.Context, key string, r io.Reader) (string, error)
	Open(ctx context.Context, key string) (io.ReadCloser, error)
	Delete(ctx context.Context, key string) error
}

// RepoScanQueueEvent reports visible lifecycle transitions for repository scans
// drained by the worker API queue.
type RepoScanQueueEvent struct {
	Kind       string
	RepoScanID string
	Repository string
	Status     string
	Reason     string
	Count      int
}

// CheckReadiness validates critical runtime dependencies for readiness checks.
func (s *Service) CheckReadiness(ctx context.Context) error {
	if s == nil {
		return errors.New("service is not initialized")
	}
	if s.Store == nil {
		return errors.New("store is not initialized")
	}
	if s.Scanner == nil {
		return errors.New("scanner is not initialized")
	}
	if s.ReadinessCheck != nil {
		if err := s.ReadinessCheck(ctx); err != nil {
			return err
		}
	}
	return nil
}

// RunScanResult is returned after a scan API trigger.
type RunScanResult struct {
	Scan             db.ScanRecord `json:"scan"`
	Assets           int           `json:"assets"`
	FindingCount     int           `json:"finding_count"`
	PartialSourceRun bool          `json:"partial_source_run"`
}

// RunRepoScanResult is returned after repo scan API trigger.
type RunRepoScanResult struct {
	RepoScan db.RepoScanRecord       `json:"repo_scan"`
	Result   repoexposure.ScanResult `json:"result"`
}

// RepoScanRequest captures one repository exposure scan request.
type RepoScanRequest struct {
	Repository   string   `json:"repository"`
	ProjectID    string   `json:"project_id,omitempty"`
	ConnectorID  string   `json:"connector_id,omitempty"`
	ScanMode     string   `json:"scan_mode,omitempty"`
	BaseRevision string   `json:"base_revision,omitempty"`
	HeadRevision string   `json:"head_revision,omitempty"`
	ChangedPaths []string `json:"changed_paths,omitempty"`
	HistoryLimit int      `json:"history_limit"`
	MaxFindings  int      `json:"max_findings"`
}

// OrganizationUpsertRequest captures one tenancy organization write payload.
type OrganizationUpsertRequest struct {
	DisplayName string `json:"display_name"`
	Slug        string `json:"slug"`
}

// WorkspaceUpsertRequest captures one workspace write payload.
type WorkspaceUpsertRequest struct {
	WorkspaceID string `json:"workspace_id"`
	DisplayName string `json:"display_name"`
	Slug        string `json:"slug"`
}

// WorkspaceMemberUpsertRequest captures one workspace member write payload.
type WorkspaceMemberUpsertRequest struct {
	MemberID string `json:"member_id"`
	UserID   string `json:"user_id"`
	Email    string `json:"email,omitempty"`
	Role     string `json:"role"`
	Status   string `json:"status"`
}

// ProjectUpsertRequest captures one workspace project write payload.
type ProjectUpsertRequest struct {
	ProjectID   string  `json:"project_id"`
	Name        string  `json:"name"`
	Slug        string  `json:"slug"`
	Description string  `json:"description,omitempty"`
	ArchivedAt  *string `json:"archived_at,omitempty"`
}

// WorkspaceContext captures one workspace plus caller membership context.
type WorkspaceContext struct {
	Workspace db.TenancyWorkspace        `json:"workspace"`
	Member    *db.TenancyWorkspaceMember `json:"member,omitempty"`
	IsActive  bool                       `json:"is_active"`
}

// WhoAmIContext captures identity-adjacent tenancy context for frontend bootstrapping.
type WhoAmIContext struct {
	Scope           db.Scope           `json:"scope"`
	ActiveWorkspace *WorkspaceContext  `json:"active_workspace,omitempty"`
	Workspaces      []WorkspaceContext `json:"workspaces"`
}

// FindingsFilter narrows findings list queries without changing API response schema.
type FindingsFilter struct {
	FindingID       string
	ScanID          string
	Severity        string
	Type            string
	LifecycleStatus string
	Assignee        string
	SortBy          string
	SortDesc        bool
	Offset          int
}

// RepoFindingClusterFilter narrows repository finding cluster list queries.
type RepoFindingClusterFilter struct {
	RepoScanID string
	Severity   string
	Type       string
	SortBy     string
	SortDesc   bool
	Offset     int
}

// RepoRiskGraphFilter narrows the repository findings used to build a risk graph.
type RepoRiskGraphFilter struct {
	RepoScanID    string
	Repository    string
	Severity      string
	Type          string
	MinConfidence float64
	DefaultBranch string
}

// RepoFindingRemediationPreviewRequest captures a request to preview safe
// remediation for one repository finding. SourceContent is optional; when
// present and the detector has a deterministic patch, the response also
// includes the exact fix-PR plan.
type RepoFindingRemediationPreviewRequest struct {
	RepoScanID     string `json:"repo_scan_id,omitempty"`
	SourceContent  string `json:"source_content,omitempty"`
	BaseBranch     string `json:"base_branch,omitempty"`
	BranchPrefix   string `json:"branch_prefix,omitempty"`
	FindingURL     string `json:"finding_url,omitempty"`
	RequireFixPlan bool   `json:"require_fix_plan,omitempty"`
}

// RepoFindingRemediationPreview is the API-facing preview for one repo finding
// remediation workflow.
type RepoFindingRemediationPreview struct {
	Finding     domain.Finding                    `json:"finding"`
	Remediation standards.RepoExposureRemediation `json:"remediation"`
	FixPRPlan   *fixpr.FixPRPlan                  `json:"fix_pr_plan,omitempty"`
}

// RepoFindingRemediationPublishRequest captures the explicit approval and
// short-lived write credential needed to publish a deterministic remediation PR.
type RepoFindingRemediationPublishRequest struct {
	RepoScanID                 string `json:"repo_scan_id,omitempty"`
	SourceContent              string `json:"source_content,omitempty"`
	BaseBranch                 string `json:"base_branch,omitempty"`
	BranchPrefix               string `json:"branch_prefix,omitempty"`
	FindingURL                 string `json:"finding_url,omitempty"`
	OperatorApproved           bool   `json:"operator_approved"`
	WritePermissionsConfigured bool   `json:"write_permissions_configured"`
	GitHubToken                string `json:"github_token,omitempty"`
}

// RepoFindingRemediationPublishResponse returns the GitHub pull request opened
// for one approved repository remediation. It never echoes write credentials.
type RepoFindingRemediationPublishResponse struct {
	Finding     domain.Finding                    `json:"finding"`
	Remediation standards.RepoExposureRemediation `json:"remediation"`
	Publish     fixpr.PublishResult               `json:"publish"`
}

// FindingsPage captures one paginated findings response.
type FindingsPage struct {
	Items      []domain.Finding
	NextCursor string
}

// FindingTriageRequest captures one triage mutation request for a finding.
type FindingTriageRequest struct {
	Status               *string `json:"status,omitempty"`
	Assignee             *string `json:"assignee,omitempty"`
	SuppressionExpiresAt *string `json:"suppression_expires_at,omitempty"`
	Comment              string  `json:"comment,omitempty"`
}

// FindingsSummary returns quick aggregation counters for dashboards/alerts.
type FindingsSummary struct {
	Total      int            `json:"total"`
	BySeverity map[string]int `json:"by_severity"`
	ByType     map[string]int `json:"by_type"`
}

// RepoFindingsSummary exposes lifecycle intelligence for repository findings.
type RepoFindingsSummary struct {
	TotalOpen                int            `json:"total_open"`
	FixedCount               int            `json:"fixed_count"`
	ReopenedCount            int            `json:"reopened_count"`
	SuppressedCount          int            `json:"suppressed_count"`
	SLAAgedCount             int            `json:"sla_aged_count"`
	MTTRReadyResolvedCount   int            `json:"mttr_ready_resolved_count"`
	MeanTimeToResolveSeconds *float64       `json:"mean_time_to_resolve_seconds,omitempty"`
	OldestOpenFirstSeenAt    *time.Time     `json:"oldest_open_first_seen_at,omitempty"`
	ByOwner                  map[string]int `json:"by_owner"`
	ByDetector               map[string]int `json:"by_detector"`
	BySeverity               map[string]int `json:"by_severity"`
}

// RepoFindingDeleteTarget identifies one repository finding inside one scan.
type RepoFindingDeleteTarget struct {
	FindingID  string `json:"finding_id"`
	RepoScanID string `json:"repo_scan_id"`
}

// RepoFindingsBulkDeleteRequest captures selected repository findings to remove.
type RepoFindingsBulkDeleteRequest struct {
	Items []RepoFindingDeleteTarget `json:"items"`
}

// RepoFindingDeleteFailure records a selected finding that could not be removed.
type RepoFindingDeleteFailure struct {
	RepoFindingDeleteTarget
	Error string `json:"error"`
}

// RepoFindingsBulkDeleteResponse reports which selected findings were removed.
type RepoFindingsBulkDeleteResponse struct {
	Deleted []RepoFindingDeleteTarget  `json:"deleted"`
	Failed  []RepoFindingDeleteFailure `json:"failed,omitempty"`
}

// ScanDiff captures delta between one scan and its previous scan for same provider.
type ScanDiff struct {
	ScanID          string           `json:"scan_id"`
	PreviousScanID  string           `json:"previous_scan_id,omitempty"`
	AddedCount      int              `json:"added_count"`
	ResolvedCount   int              `json:"resolved_count"`
	PersistingCount int              `json:"persisting_count"`
	Added           []domain.Finding `json:"added"`
	Resolved        []domain.Finding `json:"resolved"`
	Persisting      []domain.Finding `json:"persisting"`
}

// TrendPoint gives one scan-level snapshot used by dashboard trend charts.
type TrendPoint struct {
	ScanID     string         `json:"scan_id"`
	StartedAt  time.Time      `json:"started_at"`
	Total      int            `json:"total"`
	BySeverity map[string]int `json:"by_severity"`
}

// FindingExports returns standards-aligned payloads for one finding.
type FindingExports struct {
	OCSF map[string]any `json:"ocsf"`
	ASFF map[string]any `json:"asff"`
}

// OwnershipFilter narrows ownership-signal query scope.
type OwnershipFilter struct {
	ScanID string
}

// ScanRequest narrows an AWS scan to one project and optional connector.
type ScanRequest struct {
	ProjectID   string `json:"project_id,omitempty"`
	ConnectorID string `json:"connector_id,omitempty"`
}

// ErrScanInProgress is returned when a scan for the same provider is already running.
var ErrScanInProgress = errors.New("scan already in progress")

// ErrInvalidScanRequest indicates invalid cloud scan request input.
var ErrInvalidScanRequest = errors.New("invalid scan request")

// ErrScanQueueFull is returned when queued scan requests exceed configured capacity.
var ErrScanQueueFull = errors.New("scan queue is full")

// ErrScanReplayUnavailable is returned when a scan cannot be replayed into the queue.
var ErrScanReplayUnavailable = errors.New("scan replay is unavailable")

// ErrInvalidScanDiffBaseline is returned when previous_scan_id is incompatible.
var ErrInvalidScanDiffBaseline = errors.New("invalid scan diff baseline")

// ErrRepoScanDisabled is returned when repository exposure scanning is disabled.
var ErrRepoScanDisabled = errors.New("repo scan is disabled")

// ErrRepoTargetNotAllowed is returned when repository target is outside configured allowlist.
var ErrRepoTargetNotAllowed = errors.New("repo target is not allowed")

// ErrInvalidRepoScanRequest indicates invalid repository scan request input.
var ErrInvalidRepoScanRequest = errors.New("invalid repo scan request")

// ErrRepoScanAlreadyCurrent indicates a delta scan target already matches the stored cursor.
var ErrRepoScanAlreadyCurrent = errors.New("repo scan already current")

// ErrRepoScanInProgress is returned when the same repository scan target is already running.
var ErrRepoScanInProgress = errors.New("repo scan already in progress")

// ErrRepoScanCancelUnavailable is returned when a repository scan is already terminal.
var ErrRepoScanCancelUnavailable = errors.New("repo scan cancel is unavailable")

// ErrRepoScanDeleteUnavailable is returned when a repository scan should remain auditable.
var ErrRepoScanDeleteUnavailable = errors.New("repo scan delete is unavailable")

var errRepoScanTerminalStateChanged = errors.New("repo scan terminal state changed")

// ErrInvalidFindingTriageRequest indicates invalid triage payload or state transition.
var ErrInvalidFindingTriageRequest = errors.New("invalid finding triage request")

// ErrUnsupportedRepoRemediation indicates no safe remediation workflow is registered.
var ErrUnsupportedRepoRemediation = errors.New("unsupported repo remediation")

// ErrInvalidRepoRemediationRequest indicates stale source content or invalid preview inputs.
var ErrInvalidRepoRemediationRequest = errors.New("invalid repo remediation request")

// ErrRepoRemediationCredentialRejected indicates GitHub rejected the supplied
// write credential during publish (HTTP 401/403). It is client-actionable
// (rotate or re-scope the token), not an internal server error.
var ErrRepoRemediationCredentialRejected = errors.New("repo remediation github credential rejected")

// ErrRepoScanQueueFull is returned when queued repo scan requests exceed configured capacity.
var ErrRepoScanQueueFull = errors.New("repo scan queue is full")

// ErrInvalidTenancyRequest indicates invalid tenancy write payload.
var ErrInvalidTenancyRequest = errors.New("invalid tenancy request")

// ErrWorkspaceAccessDenied indicates the caller cannot switch to target workspace.
var ErrWorkspaceAccessDenied = errors.New("workspace access denied")

// ErrWorkspaceSoleOwnerRequiresTransfer indicates a workspace suspend or
// delete was refused because the caller is the only active owner of a
// workspace that still has other active members. The structured 409 surfaced
// to the caller carries the affected-member list so the UI can deep-link to
// the member-management screen for ownership transfer.
var ErrWorkspaceSoleOwnerRequiresTransfer = errors.New("workspace sole owner requires transfer")

// ErrWorkspaceDeletionGraceExpired indicates a cancel-deletion request
// arrived after the grace window closed. The hard-delete worker is
// authoritative past the deadline.
var ErrWorkspaceDeletionGraceExpired = errors.New("workspace deletion grace period has expired")

// ErrWorkspaceOwnerRequired indicates a caller tried to flip a workspace's
// lifecycle without holding an active owner membership. The authz route table
// grants the action to "owner"-role memberships, but this service-level check
// is the authoritative gate so role claims alone cannot bypass membership.
var ErrWorkspaceOwnerRequired = errors.New("workspace owner role required")

// ErrWorkspaceNotReactivatable indicates a reactivate request hit a
// workspace that is not in the suspended state. Soft-deleted workspaces
// must go through cancel-deletion (which enforces the grace window)
// rather than reactivate, otherwise the worker's purge deadline could be
// silently dodged.
var ErrWorkspaceNotReactivatable = errors.New("workspace is not suspended")

// ErrWorkspaceNotSuspendable indicates a suspend request hit a workspace
// that is already soft-deleted. Without this guard a delete→suspend→
// reactivate sequence could transition the row back to active while the
// hard-delete worker still considers it pending purge (because deleted_at
// is preserved across non-cancel transitions), creating a hidden tombstone
// that survives in an "active" workspace.
var ErrWorkspaceNotSuspendable = errors.New("workspace is not suspendable")

// ErrWorkspaceDeletionNotPending indicates cancel-deletion was called for a
// workspace that is not pending deletion.
var ErrWorkspaceDeletionNotPending = errors.New("workspace deletion is not pending")

// NewService creates an API service with defaults.
func NewService(store db.Store, scanner ScannerRunner, provider string) *Service {
	svc := &Service{
		Store:                       store,
		Scanner:                     scanner,
		Provider:                    provider,
		DefaultScope:                db.Scope{}.Normalize(),
		Now:                         time.Now,
		Locker:                      scheduler.NewInMemoryLocker(),
		LockNamespace:               "identrail",
		Alerter:                     NopFindingAlerter{},
		RepoScanEnabled:             true,
		RepoScanDefaultHistoryLimit: defaultRepoScanHistoryLimit,
		RepoScanDefaultMaxFindings:  defaultRepoScanMaxFindings,
		RepoScanMaxHistoryLimit:     defaultRepoScanHistoryMax,
		RepoScanMaxFindingsLimit:    defaultRepoScanFindingsMax,
		ScanQueueMaxPending:         defaultScanQueueMaxPending,
		RepoQueueMaxPending:         defaultRepoQueueMaxPending,
		GitHubWebhookReplayWindow:   defaultGitHubWebhookReplayWindow,
		GitHubWebhookBurstWindow:    defaultGitHubWebhookBurstWindow,
		ConnectorSecretManager:      secretstore.NewEphemeralManager(),
		githubConnections:           make(map[string]githubProjectConnection),
		githubConnectStates:         make(map[string]githubConnectState),
		githubWebhookSeen:           make(map[string]time.Time),
		githubWebhookLastQueued:     make(map[string]time.Time),
		kubernetesConnections:       make(map[string]kubernetesProjectConnection),
		RepoScannerFactory: func(historyLimit int, maxFindings int) RepoScanExecutor {
			return repoexposure.NewScanner(
				nil,
				repoexposure.WithHistoryLimit(historyLimit),
				repoexposure.WithMaxFindings(maxFindings),
			)
		},
		AuthenticatedRepoScannerFactory: func(historyLimit int, maxFindings int, credential repoexposure.HTTPSCloneCredential) RepoScanExecutor {
			return repoexposure.NewScanner(
				nil,
				repoexposure.WithHistoryLimit(historyLimit),
				repoexposure.WithMaxFindings(maxFindings),
				repoexposure.WithHTTPSCloneCredential(credential),
			)
		},
	}
	svc.hydrateGitHubConnections(context.Background())
	return svc
}

// EnqueueScan stores one queued scan request for asynchronous worker execution.
func (s *Service) EnqueueScan(ctx context.Context, requests ...ScanRequest) (db.ScanRecord, error) {
	ctx = s.scopeContext(ctx)
	ctx = withQueueTraceContext(ctx)
	request := ScanRequest{}
	if len(requests) > 0 {
		request = requests[0]
	}
	source, err := s.resolveScanSource(ctx, request)
	if err != nil {
		return db.ScanRecord{}, err
	}
	if err := s.ensureAWSPlatformBaselineReadyForScan(ctx, s.Provider, source); err != nil {
		return db.ScanRecord{}, err
	}
	maxPending := s.ScanQueueMaxPending
	if maxPending <= 0 {
		maxPending = 1
	}

	var (
		record db.ScanRecord
	)
	if maxPending == 1 {
		record, err = s.Store.CreateQueuedScanIfNoPendingWithSource(ctx, s.Provider, source, s.Now().UTC())
		if errors.Is(err, db.ErrPendingScanExists) {
			return db.ScanRecord{}, ErrScanInProgress
		}
	} else {
		record, err = s.Store.CreateQueuedScanWithinLimitWithSource(ctx, s.Provider, source, s.Now().UTC(), maxPending)
		if errors.Is(err, db.ErrQueueLimitReached) {
			return db.ScanRecord{}, ErrScanQueueFull
		}
	}
	if err != nil {
		return db.ScanRecord{}, fmt.Errorf("enqueue scan: %w", err)
	}
	queuedCount := s.countQueuedScansForDepth(ctx, s.Provider)
	s.appendScanLifecycleEvent(ctx, record.ID, scanLifecycleQueued, map[string]any{
		"provider":     s.Provider,
		"project_id":   record.ProjectID,
		"connector_id": record.ConnectorID,
	})
	s.recordQueueDepth("scan", queuedCount)
	s.appendScanEvent(ctx, record.ID, db.ScanEventLevelInfo, "scan queued for worker execution", map[string]any{
		"provider":     s.Provider,
		"project_id":   record.ProjectID,
		"connector_id": record.ConnectorID,
		"queue_depth":  queuedCount,
		"queue_limit":  maxPending,
	})
	return record, nil
}

func (s *Service) resolveScanSource(ctx context.Context, request ScanRequest) (db.ScanSource, error) {
	source := db.ScanSource{
		ProjectID:   request.ProjectID,
		ConnectorID: request.ConnectorID,
	}.Normalize()
	if source.Empty() {
		return db.ScanSource{}, nil
	}
	// Source scoping is AWS-only. For other providers, ignore any project/connector
	// hints so pending-scan guards keep their single-queue semantics rather than
	// partitioning by project.
	if strings.ToLower(strings.TrimSpace(s.Provider)) != string(domain.ConnectorTypeAWS) {
		return db.ScanSource{}, nil
	}
	if source.ProjectID == "" {
		return db.ScanSource{}, ErrInvalidScanRequest
	}
	project, _, err := s.requireScopedProject(ctx, "", source.ProjectID)
	if err != nil {
		if errors.Is(err, ErrInvalidGitHubConnectionRequest) || errors.Is(err, db.ErrNotFound) {
			return db.ScanSource{}, ErrInvalidScanRequest
		}
		return db.ScanSource{}, err
	}
	source.ProjectID = project.ProjectID
	if source.ConnectorID == "" {
		return source, nil
	}
	stored, err := s.Store.GetTenancyConnector(ctx, project.WorkspaceID, project.ProjectID, source.ConnectorID)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			return db.ScanSource{}, ErrInvalidScanRequest
		}
		return db.ScanSource{}, err
	}
	if stored.Connector.Type != domain.ConnectorTypeAWS {
		return db.ScanSource{}, ErrInvalidScanRequest
	}
	return source, nil
}

// ReplayScan re-enqueues one failed or dead-lettered scan as a fresh queued scan.
func (s *Service) ReplayScan(ctx context.Context, scanID string) (db.ScanRecord, error) {
	ctx = s.scopeContext(ctx)
	source, err := s.Store.GetScan(ctx, scanID)
	if err != nil {
		return db.ScanRecord{}, err
	}
	if !source.DeadLettered && source.Status != scanLifecycleFailed {
		return db.ScanRecord{}, ErrScanReplayUnavailable
	}

	maxPending := s.ScanQueueMaxPending
	if maxPending <= 0 {
		maxPending = 1
	}

	var replay db.ScanRecord
	sourceContext := db.ScanSource{
		ProjectID:   source.ProjectID,
		ConnectorID: source.ConnectorID,
	}
	if err := s.ensureAWSPlatformBaselineReadyForScan(ctx, source.Provider, sourceContext); err != nil {
		return db.ScanRecord{}, err
	}
	if maxPending == 1 {
		replay, err = s.Store.CreateQueuedScanIfNoPendingWithSource(ctx, source.Provider, sourceContext, s.Now().UTC())
		if errors.Is(err, db.ErrPendingScanExists) {
			return db.ScanRecord{}, ErrScanInProgress
		}
	} else {
		replay, err = s.Store.CreateQueuedScanWithinLimitWithSource(ctx, source.Provider, sourceContext, s.Now().UTC(), maxPending)
		if errors.Is(err, db.ErrQueueLimitReached) {
			return db.ScanRecord{}, ErrScanQueueFull
		}
	}
	if err != nil {
		return db.ScanRecord{}, fmt.Errorf("replay scan: %w", err)
	}

	queuedCount := s.countQueuedScansForDepth(ctx, source.Provider)
	s.appendScanEvent(ctx, source.ID, db.ScanEventLevelInfo, "scan replay queued", map[string]any{
		"replay_scan_id": replay.ID,
		"provider":       source.Provider,
	})
	s.appendScanLifecycleEvent(ctx, replay.ID, scanLifecycleQueued, map[string]any{
		"provider":           replay.Provider,
		"replayed_from_scan": source.ID,
		"source_dead_letter": source.DeadLettered,
		"source_status":      source.Status,
		"failure_category":   source.FailureCategory,
	})
	s.appendScanEvent(ctx, replay.ID, db.ScanEventLevelInfo, "scan replay queued from failed scan", map[string]any{
		"source_scan_id":   source.ID,
		"source_status":    source.Status,
		"failure_category": source.FailureCategory,
		"queue_depth":      queuedCount,
		"queue_limit":      maxPending,
	})
	s.recordQueueDepth("scan", queuedCount)
	return replay, nil
}

// ProcessNextQueuedScan claims and executes one queued scan. It returns false when no job is available.
func (s *Service) ProcessNextQueuedScan(ctx context.Context) (bool, error) {
	ctx = s.scopeContext(ctx)
	if s.Locker != nil {
		release, ok := s.Locker.TryAcquire(ctx, s.lockKey("scan:"+s.Provider))
		if !ok {
			return false, nil
		}
		defer release(context.Background())
	}
	record, err := s.Store.ClaimNextQueuedScanAnyScope(ctx, s.Provider)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			s.recordQueueDepth("scan", 0)
			return false, nil
		}
		s.recordWorkerJob("scan", "failure")
		return false, fmt.Errorf("claim queued scan: %w", err)
	}
	recordScopeCtx := db.WithScope(ctx, db.Scope{
		TenantID:    record.TenantID,
		WorkspaceID: record.WorkspaceID,
	})
	// Workspace lifecycle gate — a scan queued before the workspace was
	// suspended/soft-deleted will still surface through
	// ClaimNextQueuedScanAnyScope (the claim SQL filters only on scan
	// status), so without this check the worker would execute scans
	// against an inactive workspace and contradict the lifecycle pause
	// contract. Refuse the claimed record by marking it terminal with a
	// clear error so it does not retry forever; the workspace owner can
	// requeue after reactivate/cancel-deletion.
	if skipped, skipErr := s.skipScanIfWorkspaceInactive(recordScopeCtx, record); skipErr != nil {
		s.recordWorkerJob("scan", "failure")
		return true, skipErr
	} else if skipped {
		s.recordWorkerJob("scan", "skipped_workspace_inactive")
		return true, nil
	}
	s.recordAutomationLag("api_queue", "scan", s.Now().UTC().Sub(record.StartedAt.UTC()))
	recordScopeCtx = continueQueueTraceContext(recordScopeCtx, record.TraceParent, record.TraceState)
	s.appendScanLifecycleEvent(recordScopeCtx, record.ID, scanLifecycleRunning, map[string]any{"provider": record.Provider})
	s.appendScanEvent(recordScopeCtx, record.ID, db.ScanEventLevelInfo, "queued scan started", map[string]any{"provider": record.Provider})
	runResult, runErr := s.runScanWithRecord(recordScopeCtx, record, true)
	if runErr != nil {
		s.recordAutomationRun("api_queue", record.Provider, "failed")
		s.recordWorkerJob("scan", "failure")
		return true, runErr
	}
	outcome := "succeeded"
	if runResult.PartialSourceRun {
		outcome = "partial"
	}
	s.recordAutomationRun("api_queue", record.Provider, outcome)
	s.recordWorkerJob("scan", "success")
	return true, nil
}

// RunScan executes one scan and persists metadata + findings.
func (s *Service) RunScan(ctx context.Context) (RunScanResult, error) {
	ctx = s.scopeContext(ctx)
	if s.Locker != nil {
		release, ok := s.Locker.TryAcquire(ctx, s.lockKey("scan:"+s.Provider))
		if !ok {
			return RunScanResult{}, ErrScanInProgress
		}
		defer release(context.Background())
	}
	record, err := s.Store.CreateScan(ctx, s.Provider, s.Now().UTC())
	if err != nil {
		return RunScanResult{}, err
	}
	s.appendScanLifecycleEvent(ctx, record.ID, scanLifecycleQueued, map[string]any{"provider": s.Provider})
	s.appendScanLifecycleEvent(ctx, record.ID, scanLifecycleRunning, map[string]any{"provider": s.Provider})
	s.appendScanEvent(ctx, record.ID, db.ScanEventLevelInfo, "scan started", map[string]any{"provider": s.Provider})
	return s.runScanWithRecord(ctx, record, false)
}

func (s *Service) runScanWithRecord(ctx context.Context, record db.ScanRecord, allowRetry bool) (RunScanResult, error) {
	ctx = s.scopeContext(ctx)
	scanStarted := time.Now()
	if s.Metrics != nil {
		s.Metrics.ScanRunsTotal.Inc()
		s.Metrics.ScanInFlight.Inc()
		defer s.Metrics.ScanInFlight.Dec()
		defer func() {
			s.Metrics.ScanDurationMS.Observe(float64(time.Since(scanStarted).Milliseconds()))
		}()
	}
	scanner, err := s.scannerForScan(ctx, record)
	if err != nil {
		if handleErr := s.handleScanFailure(ctx, record, allowRetry, scanFailureStageConnectorSetup, 0, 0, err, "scan failed while preparing provider connector"); handleErr != nil {
			return RunScanResult{}, handleErr
		}
		if allowRetry {
			return RunScanResult{}, nil
		}
		return RunScanResult{}, err
	}
	result, err := scanner.Run(ctx)
	if err != nil {
		if handleErr := s.handleScanFailure(ctx, record, allowRetry, scanFailureStageExecution, 0, 0, err, "scan failed during collection/analysis"); handleErr != nil {
			return RunScanResult{}, handleErr
		}
		if allowRetry {
			return RunScanResult{}, nil
		}
		return RunScanResult{}, err
	}
	result.Findings = enrichFindings(result.Findings)
	if len(result.SourceErrors) > 0 {
		if s.Metrics != nil {
			s.Metrics.ScanPartialTotal.Inc()
		}
		s.appendScanEvent(ctx, record.ID, db.ScanEventLevelWarn, "scan completed with partial source errors", map[string]any{
			"source_error_count": len(result.SourceErrors),
			"source_errors":      truncateSourceErrors(result.SourceErrors, maxSourceErrorsInEvent),
		})
		s.appendScanLifecycleEvent(ctx, record.ID, scanLifecyclePartial, map[string]any{"source_error_count": len(result.SourceErrors)})
	}

	if err := s.Store.UpsertArtifacts(ctx, record.ID, db.ScanArtifacts{
		RawAssets:     result.RawAssets,
		Bundle:        result.Bundle,
		Permissions:   result.Permissions,
		Relationships: result.Relationships,
	}); err != nil {
		if handleErr := s.handleScanFailure(ctx, record, allowRetry, scanFailureStageArtifactsStore, result.Assets, 0, err, "scan failed while persisting artifacts"); handleErr != nil {
			return RunScanResult{}, handleErr
		}
		if allowRetry {
			return RunScanResult{}, nil
		}
		return RunScanResult{}, fmt.Errorf("persist artifacts: %w", err)
	}
	s.appendScanEvent(ctx, record.ID, db.ScanEventLevelInfo, "artifacts persisted", map[string]any{"raw_assets": len(result.RawAssets), "identities": len(result.Bundle.Identities)})

	if err := s.Store.UpsertFindings(ctx, record.ID, result.Findings); err != nil {
		if handleErr := s.handleScanFailure(ctx, record, allowRetry, scanFailureStageFindingsStore, result.Assets, 0, err, "scan failed while persisting findings"); handleErr != nil {
			return RunScanResult{}, handleErr
		}
		if allowRetry {
			return RunScanResult{}, nil
		}
		return RunScanResult{}, fmt.Errorf("persist findings: %w", err)
	}
	s.appendScanEvent(ctx, record.ID, db.ScanEventLevelInfo, "findings persisted", map[string]any{"findings": len(result.Findings)})

	if err := s.completeScanTerminal(ctx, record.ID, "succeeded", s.Now().UTC(), result.Assets, len(result.Findings), ""); err != nil {
		if handleErr := s.handleScanFailure(ctx, record, allowRetry, scanFailureStageFinalize, result.Assets, len(result.Findings), err, "scan failed while finalizing scan record"); handleErr != nil {
			return RunScanResult{}, handleErr
		}
		if allowRetry {
			return RunScanResult{}, nil
		}
		return RunScanResult{}, fmt.Errorf("complete scan record: %w", err)
	}

	record.Status = "succeeded"
	finished := s.Now().UTC()
	record.FinishedAt = &finished
	record.AssetCount = result.Assets
	record.FindingCount = len(result.Findings)
	if s.Metrics != nil {
		s.Metrics.ScanSuccessTotal.Inc()
		s.Metrics.FindingsGenerated.Add(float64(len(result.Findings)))
	}
	s.appendScanLifecycleEvent(ctx, record.ID, scanLifecycleSucceeded, map[string]any{
		"assets":             result.Assets,
		"findings":           len(result.Findings),
		"partial_source_run": len(result.SourceErrors) > 0,
	})
	s.appendScanEvent(ctx, record.ID, db.ScanEventLevelInfo, "scan completed", map[string]any{"assets": result.Assets, "findings": len(result.Findings)})
	provider := strings.TrimSpace(record.Provider)
	if provider == "" {
		provider = s.Provider
	}
	if s.Alerter != nil {
		if alertErr := s.Alerter.NotifyScan(ctx, provider, record, result.Findings); alertErr != nil && s.OnAlertError != nil {
			s.OnAlertError(alertErr)
		}
	}

	return RunScanResult{
		Scan:             record,
		Assets:           result.Assets,
		FindingCount:     len(result.Findings),
		PartialSourceRun: len(result.SourceErrors) > 0,
	}, nil
}

func (s *Service) handleScanFailure(
	ctx context.Context,
	record db.ScanRecord,
	allowRetry bool,
	stage string,
	assetCount int,
	findingCount int,
	failure error,
	eventMessage string,
) error {
	now := s.Now().UTC()
	policy := classifyScanFailure(stage, failure)
	metadata := map[string]any{
		"error":            failure.Error(),
		"failure_category": policy.Category,
		"failure_stage":    stage,
		"retryable":        allowRetry && policy.Retryable,
		"retry_count":      record.RetryCount,
		"max_retry_count":  effectiveScanRetryLimit(record),
		"dead_lettered":    false,
		"asset_count":      assetCount,
		"finding_count":    findingCount,
	}

	s.recordScanExecutionFailure()
	s.appendScanLifecycleEvent(ctx, record.ID, scanLifecycleFailed, metadata)

	if !allowRetry {
		s.appendScanEvent(ctx, record.ID, db.ScanEventLevelError, eventMessage, metadata)
		return s.completeScanTerminal(ctx, record.ID, scanLifecycleFailed, now, assetCount, findingCount, failure.Error())
	}

	maxRetryCount := effectiveScanRetryLimit(record)
	if policy.Retryable && record.RetryCount < maxRetryCount {
		nextRetryCount := record.RetryCount + 1
		nextRetryAt := now.Add(scanRetryBackoff(nextRetryCount))
		metadata["retry_count"] = nextRetryCount
		metadata["next_retry_at"] = nextRetryAt.Format(time.RFC3339Nano)
		s.appendScanEvent(ctx, record.ID, db.ScanEventLevelWarn, eventMessage, metadata)
		if err := s.scheduleScanRetry(ctx, record.ID, now, nextRetryCount, maxRetryCount, policy.Category, failure.Error(), nextRetryAt); err != nil {
			return err
		}
		s.appendScanLifecycleEvent(ctx, record.ID, scanLifecycleQueued, map[string]any{
			"provider":           record.Provider,
			"retry_count":        nextRetryCount,
			"max_retry_count":    maxRetryCount,
			"next_retry_at":      nextRetryAt.Format(time.RFC3339Nano),
			"failure_category":   policy.Category,
			"requeued_for_retry": true,
		})
		s.appendScanEvent(ctx, record.ID, db.ScanEventLevelInfo, "scan requeued with backoff", map[string]any{
			"retry_count":      nextRetryCount,
			"max_retry_count":  maxRetryCount,
			"next_retry_at":    nextRetryAt.Format(time.RFC3339Nano),
			"failure_category": policy.Category,
		})
		s.recordWorkerRequeue("scan")
		return nil
	}

	metadata["dead_lettered"] = true
	metadata["retryable"] = false
	s.appendScanEvent(ctx, record.ID, db.ScanEventLevelError, eventMessage, metadata)
	if err := s.deadLetterQueuedScan(ctx, record.ID, now, record.RetryCount, maxRetryCount, assetCount, findingCount, policy.Category, failure.Error()); err != nil {
		return err
	}
	s.appendScanEvent(ctx, record.ID, db.ScanEventLevelError, "scan moved to dead-letter queue", map[string]any{
		"retry_count":      record.RetryCount,
		"max_retry_count":  maxRetryCount,
		"failure_category": policy.Category,
		"dead_lettered":    true,
	})
	s.recordWorkerDeadLetter("scan")
	return nil
}

func (s *Service) recordScanExecutionFailure() {
	if s.Metrics != nil {
		s.Metrics.ScanFailureTotal.Inc()
	}
}

type scanFailurePolicy struct {
	Category  string
	Retryable bool
}

func classifyScanFailure(stage string, failure error) scanFailurePolicy {
	if failure == nil {
		return scanFailurePolicy{Category: scanFailureCategoryExecution}
	}
	message := strings.ToLower(strings.TrimSpace(failure.Error()))
	switch stage {
	case scanFailureStageArtifactsStore, scanFailureStageFindingsStore:
		return scanFailurePolicy{Category: scanFailureCategoryPersistence}
	case scanFailureStageFinalize:
		return scanFailurePolicy{Category: scanFailureCategoryFinalize}
	}
	if containsFailureToken(message, "rate limit", "too many requests", "throttle", "throttl") {
		return scanFailurePolicy{Category: scanFailureCategoryThrottle, Retryable: true}
	}
	if containsFailureToken(message, "access denied", "forbidden", "unauthorized", "expired token", "invalid credentials", "assume role", "permission denied") {
		return scanFailurePolicy{Category: scanFailureCategoryProviderAuth}
	}
	if containsFailureToken(message, "timeout", "deadline exceeded", "temporary", "temporarily", "connection reset", "connection refused", "i/o timeout", "eof", "service unavailable", "unavailable") {
		return scanFailurePolicy{Category: scanFailureCategoryTransient, Retryable: true}
	}
	if containsFailureToken(message, "invalid", "malformed", "unsupported", "not configured", "missing", "not found", "nil scanner") {
		return scanFailurePolicy{Category: scanFailureCategoryConfig}
	}
	if stage == scanFailureStageConnectorSetup {
		return scanFailurePolicy{Category: scanFailureCategoryConnector}
	}
	return scanFailurePolicy{Category: scanFailureCategoryExecution, Retryable: true}
}

func containsFailureToken(message string, values ...string) bool {
	for _, value := range values {
		if strings.Contains(message, strings.ToLower(strings.TrimSpace(value))) {
			return true
		}
	}
	return false
}

func effectiveScanRetryLimit(record db.ScanRecord) int {
	if record.MaxRetryCount < 0 {
		return 0
	}
	if record.MaxRetryCount == 0 {
		return db.DefaultScanMaxRetryCount
	}
	return record.MaxRetryCount
}

func scanRetryBackoff(retryCount int) time.Duration {
	if retryCount <= 0 {
		return defaultScanRetryBaseDelay
	}
	backoff := defaultScanRetryBaseDelay
	for attempt := 1; attempt < retryCount; attempt++ {
		backoff *= 2
		if backoff >= defaultScanRetryMaxDelay {
			return defaultScanRetryMaxDelay
		}
	}
	if backoff > defaultScanRetryMaxDelay {
		return defaultScanRetryMaxDelay
	}
	return backoff
}

func (s *Service) scannerForScan(ctx context.Context, record db.ScanRecord) (ScannerRunner, error) {
	provider := strings.ToLower(strings.TrimSpace(record.Provider))
	if provider == "" {
		provider = strings.ToLower(strings.TrimSpace(s.Provider))
	}
	if provider != "aws" || s.AWSScannerFactory == nil {
		return s.Scanner, nil
	}
	connection, ok, err := s.activeAWSConnectionForScan(ctx, record)
	if err != nil {
		return nil, err
	}
	if !ok {
		return s.Scanner, nil
	}
	scanner, err := s.AWSScannerFactory(ctx, connection)
	if err != nil {
		return nil, fmt.Errorf("initialize aws connector scanner: %w", err)
	}
	if scanner == nil {
		return nil, errors.New("aws connector scanner factory returned nil scanner")
	}
	return scanner, nil
}

func (s *Service) recordServiceAuthzDenial(ctx context.Context, action string, resourceType string, resourceID string) {
	if s.Metrics != nil {
		s.Metrics.ServiceAuthzDenialsTotal.WithLabelValues(action, resourceType).Inc()
	}
	audit.WriteAction(ctx, audit.AuditEvent{
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Outcome:      "denied",
	})
}

func (s *Service) activeAWSConnectionForScan(ctx context.Context, record db.ScanRecord) (AWSConnectionStatus, bool, error) {
	source := db.ScanSource{
		ProjectID:   record.ProjectID,
		ConnectorID: record.ConnectorID,
	}.Normalize()
	if source.ProjectID != "" {
		project, _, err := s.requireScopedProject(ctx, "", source.ProjectID)
		if err != nil {
			if errors.Is(err, ErrInvalidGitHubConnectionRequest) || errors.Is(err, db.ErrNotFound) {
				return AWSConnectionStatus{}, false, ErrInvalidScanRequest
			}
			return AWSConnectionStatus{}, false, err
		}
		if source.ConnectorID != "" {
			stored, err := s.Store.GetTenancyConnector(ctx, project.WorkspaceID, project.ProjectID, source.ConnectorID)
			if err != nil {
				if errors.Is(err, db.ErrNotFound) {
					return AWSConnectionStatus{}, false, ErrInvalidScanRequest
				}
				return AWSConnectionStatus{}, false, err
			}
			if stored.Connector.Type != domain.ConnectorTypeAWS {
				return AWSConnectionStatus{}, false, ErrInvalidScanRequest
			}
			status := s.awsConnectionStatusFromStored(ctx, stored)
			if !status.Connected {
				return AWSConnectionStatus{}, false, fmt.Errorf("aws connector %q is not active in project %q", source.ConnectorID, project.ProjectID)
			}
			return status, true, nil
		}
		items, err := s.Store.ListTenancyConnectors(ctx, project.WorkspaceID, project.ProjectID, domain.ConnectorTypeAWS, 25)
		if err != nil {
			return AWSConnectionStatus{}, false, fmt.Errorf("list scoped aws connectors: %w", err)
		}
		return s.firstActiveAWSConnection(ctx, items)
	}
	items, err := s.Store.ListTenancyConnectors(ctx, "", "", domain.ConnectorTypeAWS, 25)
	if err != nil {
		return AWSConnectionStatus{}, false, fmt.Errorf("list aws connectors: %w", err)
	}
	return s.firstActiveAWSConnection(ctx, items)
}

func (s *Service) firstActiveAWSConnection(ctx context.Context, items []db.TenancyConnectorWithState) (AWSConnectionStatus, bool, error) {
	sort.SliceStable(items, func(i, j int) bool {
		left := items[i].Connector
		right := items[j].Connector
		if left.UpdatedAt.Equal(right.UpdatedAt) {
			return left.ConnectorID < right.ConnectorID
		}
		return left.UpdatedAt.After(right.UpdatedAt)
	})
	for _, item := range items {
		status := s.awsConnectionStatusFromStored(ctx, item)
		if status.Connected {
			return status, true, nil
		}
	}
	return AWSConnectionStatus{}, false, nil
}

func (s *Service) recordQueueDepth(queue string, depth int) {
	if s.Metrics != nil {
		s.Metrics.QueueDepth.WithLabelValues(queue).Set(float64(depth))
	}
}

func (s *Service) countQueuedScansForDepth(ctx context.Context, provider string) int {
	if counter, ok := s.Store.(queuedScanDepthCounter); ok {
		count, err := counter.CountQueuedScansAnyScope(ctx, provider)
		if err != nil {
			return 0
		}
		return count
	}
	count, err := s.Store.CountQueuedScans(ctx, provider)
	if err != nil {
		return 0
	}
	return count
}

func (s *Service) countQueuedRepoScansForDepth(ctx context.Context) int {
	if counter, ok := s.Store.(queuedRepoScanDepthCounter); ok {
		count, err := counter.CountQueuedRepoScansAnyScope(ctx)
		if err != nil {
			return 0
		}
		return count
	}
	count, err := s.Store.CountQueuedRepoScans(ctx)
	if err != nil {
		return 0
	}
	return count
}

func (s *Service) recordWorkerJob(queue string, outcome string) {
	if s.Metrics != nil {
		s.Metrics.WorkerJobsTotal.WithLabelValues(queue, outcome).Inc()
	}
}

func (s *Service) recordWorkerRequeue(queue string) {
	if s.Metrics != nil {
		s.Metrics.WorkerRequeuesTotal.WithLabelValues(queue).Inc()
	}
}

func (s *Service) recordWorkerDeadLetter(runner string) {
	if s.Metrics != nil {
		s.Metrics.WorkerDeadLettersTotal.WithLabelValues(runner).Inc()
	}
}

func (s *Service) recordRepoScanModeRun(mode string, outcome string) {
	if s.Metrics != nil {
		s.Metrics.RepoScanModeRunsTotal.WithLabelValues(repoScanModeLabel(mode), automationOutcomeLabel(outcome)).Inc()
	}
}

func (s *Service) recordRepoScanSkipped(mode string, reason string) {
	if s.Metrics != nil {
		s.Metrics.RepoScanSkippedTotal.WithLabelValues(repoScanModeLabel(mode), repoScanSkipReasonLabel(reason)).Inc()
	}
}

func (s *Service) recordAutomationRun(source string, connector string, outcome string) {
	s.recordAutomationRuns(source, connector, outcome, 1)
}

func (s *Service) recordAutomationRuns(source string, connector string, outcome string, count int) {
	if s.Metrics == nil || count <= 0 {
		return
	}
	s.Metrics.AutomationRunsTotal.WithLabelValues(
		automationSourceLabel(source),
		automationConnectorLabel(connector),
		automationOutcomeLabel(outcome),
	).Add(float64(count))
}

func (s *Service) recordAutomationLag(source string, queue string, lag time.Duration) {
	if s.Metrics == nil {
		return
	}
	if lag < 0 {
		lag = 0
	}
	s.Metrics.AutomationLagMS.WithLabelValues(
		automationSourceLabel(source),
		automationQueueLabel(queue),
	).Observe(float64(lag.Milliseconds()))
}

func automationSourceLabel(source string) string {
	switch strings.ToLower(strings.TrimSpace(source)) {
	case "scheduled":
		return "scheduled"
	case "event":
		return "event"
	case "api_queue":
		return "api_queue"
	default:
		return "other"
	}
}

func automationConnectorLabel(connector string) string {
	switch strings.ToLower(strings.TrimSpace(connector)) {
	case "aws":
		return "aws"
	case "github":
		return "github"
	case "kubernetes":
		return "kubernetes"
	case "repo_scan":
		return "repo_scan"
	case "scan_policy":
		return "scan_policy"
	default:
		return "other"
	}
}

func automationOutcomeLabel(outcome string) string {
	switch strings.ToLower(strings.TrimSpace(outcome)) {
	case "queued":
		return "queued"
	case "succeeded", "success":
		return "succeeded"
	case "failed", "failure":
		return "failed"
	case "partial":
		return "partial"
	case "skipped":
		return "skipped"
	case "requeued":
		return "requeued"
	default:
		return "other"
	}
}

func automationQueueLabel(queue string) string {
	switch strings.ToLower(strings.TrimSpace(queue)) {
	case "scan":
		return "scan"
	case "repo_scan":
		return "repo_scan"
	default:
		return "other"
	}
}

func repoScanModeLabel(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case db.RepoScanModeQuick:
		return db.RepoScanModeQuick
	case db.RepoScanModeDelta:
		return db.RepoScanModeDelta
	case db.RepoScanModeDeep:
		return db.RepoScanModeDeep
	default:
		return db.RepoScanModeDeep
	}
}

func repoScanSkipReasonLabel(reason string) string {
	switch strings.ToLower(strings.TrimSpace(reason)) {
	case "cursor_current":
		return "cursor_current"
	case "queue_full":
		return "queue_full"
	case "in_progress":
		return "in_progress"
	case "invalid_delta":
		return "invalid_delta"
	case "disabled":
		return "disabled"
	case "target_not_allowed":
		return "target_not_allowed"
	case "throttled":
		return "throttled"
	case "replay":
		return "replay"
	default:
		return "other"
	}
}

// ListFindings returns persisted findings.
func (s *Service) ListFindings(ctx context.Context, limit int) ([]domain.Finding, error) {
	ctx = s.scopeContext(ctx)
	items, err := s.Store.ListFindings(ctx, limit)
	if err != nil {
		return nil, err
	}
	enriched := enrichFindings(items)
	return s.applyFindingTriageStates(ctx, enriched)
}

// RunRepoScan performs one repository exposure scan with configured guardrails.
func (s *Service) RunRepoScan(ctx context.Context, request RepoScanRequest) (repoexposure.ScanResult, error) {
	runResult, err := s.RunRepoScanPersisted(ctx, request)
	if err != nil {
		return repoexposure.ScanResult{}, err
	}
	return runResult.Result, nil
}

// EnqueueRepoScan stores one queued repository scan request for asynchronous worker execution.
func (s *Service) EnqueueRepoScan(ctx context.Context, request RepoScanRequest) (db.RepoScanRecord, error) {
	ctx = s.scopeContext(ctx)
	ctx = withQueueTraceContext(ctx)
	target, source, scanContext, historyLimit, maxFindings, err := s.validateRepoScanRequest(ctx, request)
	if err != nil {
		return db.RepoScanRecord{}, err
	}
	cursor, hasCursor, err := s.repoScanCursor(ctx, target, source)
	if err != nil {
		return db.RepoScanRecord{}, err
	}
	if hasCursor && scanContext.CursorBefore == "" {
		scanContext.CursorBefore = cursor.LastScannedRevision
	}
	if repoScanCursorAlreadyCoversRequest(scanContext, cursor, hasCursor) {
		s.recordRepoScanSkipped(scanContext.ScanMode, "cursor_current")
		return db.RepoScanRecord{}, ErrRepoScanAlreadyCurrent
	}
	maxPending := s.RepoQueueMaxPending
	if maxPending <= 0 {
		maxPending = defaultRepoQueueMaxPending
	}
	record, err := s.Store.CreateQueuedRepoScanWithinLimit(ctx, target, source, scanContext, historyLimit, maxFindings, s.Now().UTC(), maxPending)
	if err != nil {
		switch {
		case errors.Is(err, db.ErrPendingRepoScanExists):
			return db.RepoScanRecord{}, ErrRepoScanInProgress
		case errors.Is(err, db.ErrQueueLimitReached):
			return db.RepoScanRecord{}, ErrRepoScanQueueFull
		default:
			return db.RepoScanRecord{}, fmt.Errorf("enqueue repo scan: %w", err)
		}
	}
	queuedCount := s.countQueuedRepoScansForDepth(ctx)
	s.recordQueueDepth("repo_scan", queuedCount)
	return record, nil
}

// CancelRepoScan marks an active repository scan terminal so the target can be retried.
func (s *Service) CancelRepoScan(ctx context.Context, repoScanID string) (db.RepoScanRecord, error) {
	ctx = s.scopeContext(ctx)
	record, err := s.Store.CancelRepoScan(ctx, repoScanID, s.Now().UTC(), userCanceledRepoScanMessage)
	if err != nil {
		if errors.Is(err, db.ErrConflict) {
			return db.RepoScanRecord{}, ErrRepoScanCancelUnavailable
		}
		return db.RepoScanRecord{}, err
	}
	s.recordAutomationRun("api_queue", "repo_scan", "canceled")
	s.emitRepoScanQueueEvent(RepoScanQueueEvent{
		Kind:       "canceled",
		RepoScanID: record.ID,
		Repository: record.Repository,
		Status:     "failed",
		Reason:     "user_canceled",
	})
	return record, nil
}

// ProcessNextQueuedRepoScan claims and executes one queued repository scan. It returns false when no job is available.
func (s *Service) ProcessNextQueuedRepoScan(ctx context.Context) (bool, error) {
	ctx = s.scopeContext(ctx)
	failedStale, err := s.Store.FailStaleRepoScansAnyScope(
		ctx,
		s.Now().UTC().Add(-defaultRepoScanRunningStaleAfter),
		defaultRepoScanStaleFailureLimit,
		staleRepoScanFailureMessage,
	)
	if err != nil {
		s.recordWorkerJob("repo_scan", "failure")
		return false, fmt.Errorf("fail stale repo scans: %w", err)
	}
	if failedStale > 0 {
		for i := 0; i < failedStale; i++ {
			s.recordWorkerJob("repo_scan", "failure")
			s.recordWorkerDeadLetter("repo_scan")
		}
		s.recordAutomationRun("api_queue", "repo_scan", "failed")
		s.emitRepoScanQueueEvent(RepoScanQueueEvent{Kind: "stale_failed", Status: "failed", Reason: "stale_running", Count: failedStale})
		return true, nil
	}
	queuedCount := s.countQueuedRepoScansForDepth(ctx)
	s.recordQueueDepth("repo_scan", queuedCount)
	if queuedCount > 0 {
		s.emitRepoScanQueueEvent(RepoScanQueueEvent{Kind: "claim_attempt", Status: "pending", Count: queuedCount})
	}
	record, err := s.Store.ClaimNextQueuedRepoScanAnyScope(ctx)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			s.recordQueueDepth("repo_scan", 0)
			return false, nil
		}
		s.recordWorkerJob("repo_scan", "failure")
		return false, fmt.Errorf("claim queued repo scan: %w", err)
	}
	s.emitRepoScanQueueEvent(RepoScanQueueEvent{
		Kind:       "claimed",
		RepoScanID: record.ID,
		Repository: record.Repository,
		Status:     "running",
	})
	recordScopeCtx := db.WithScope(ctx, db.Scope{
		TenantID:    record.TenantID,
		WorkspaceID: record.WorkspaceID,
	})
	// Workspace lifecycle gate — a repo scan queued before the workspace
	// was suspended/soft-deleted still surfaces through
	// ClaimNextQueuedRepoScanAnyScope (the claim SQL filters only on
	// repo_scans.status='queued'). Mirror the regular-scan gate added
	// in ProcessNextQueuedScan so a paused workspace genuinely stops
	// every scan execution path — including this codex round-8 gap.
	if skipped, skipErr := s.skipRepoScanIfWorkspaceInactive(recordScopeCtx, record); skipErr != nil {
		s.recordWorkerJob("repo_scan", "failure")
		return true, skipErr
	} else if skipped {
		s.recordWorkerJob("repo_scan", "skipped_workspace_inactive")
		s.emitRepoScanQueueEvent(RepoScanQueueEvent{
			Kind:       "failed",
			RepoScanID: record.ID,
			Repository: record.Repository,
			Status:     "failed",
			Reason:     "workspace_inactive",
		})
		return true, nil
	}
	s.recordAutomationLag("api_queue", "repo_scan", s.Now().UTC().Sub(record.StartedAt.UTC()))
	recordScopeCtx = continueQueueTraceContext(recordScopeCtx, record.TraceParent, record.TraceState)
	requeue := false
	if s.Locker != nil {
		release, ok := s.Locker.TryAcquire(ctx, s.lockKey("repo-scan:"+strings.ToLower(record.Repository)))
		if !ok {
			requeue = true
		} else {
			defer release(context.Background())
		}
	}
	if requeue {
		if requeueErr := s.Store.RequeueRepoScan(recordScopeCtx, record.ID); requeueErr != nil && !errors.Is(requeueErr, db.ErrNotFound) {
			s.recordWorkerJob("repo_scan", "failure")
			return false, fmt.Errorf("requeue repo scan: %w", requeueErr)
		}
		s.recordAutomationRun("api_queue", "repo_scan", "requeued")
		s.recordWorkerJob("repo_scan", "requeued")
		s.recordWorkerRequeue("repo_scan")
		s.emitRepoScanQueueEvent(RepoScanQueueEvent{
			Kind:       "requeued",
			RepoScanID: record.ID,
			Repository: record.Repository,
			Status:     "queued",
			Reason:     "execution_lock_held",
		})
		// A queued item was handled (requeued) even if this target is currently locked.
		// Returning true lets the worker keep draining other queued targets in the same tick.
		return true, nil
	}
	s.emitRepoScanQueueEvent(RepoScanQueueEvent{
		Kind:       "scan_started",
		RepoScanID: record.ID,
		Repository: record.Repository,
		Status:     "running",
	})
	_, runErr := s.runRepoScanWithRecord(recordScopeCtx, record, record.HistoryLimit, record.MaxFindings)
	if runErr != nil {
		if errors.Is(runErr, errRepoScanTerminalStateChanged) {
			return true, nil
		}
		s.recordAutomationRun("api_queue", "repo_scan", "failed")
		s.recordWorkerJob("repo_scan", "failure")
		s.recordWorkerDeadLetter("repo_scan")
		s.emitRepoScanQueueEvent(RepoScanQueueEvent{
			Kind:       "failed",
			RepoScanID: record.ID,
			Repository: record.Repository,
			Status:     "failed",
		})
		return true, runErr
	}
	s.recordAutomationRun("api_queue", "repo_scan", "succeeded")
	s.recordWorkerJob("repo_scan", "success")
	s.emitRepoScanQueueEvent(RepoScanQueueEvent{
		Kind:       "succeeded",
		RepoScanID: record.ID,
		Repository: record.Repository,
		Status:     "succeeded",
	})
	return true, nil
}

func (s *Service) emitRepoScanQueueEvent(event RepoScanQueueEvent) {
	if s != nil && s.OnRepoScanQueueEvent != nil {
		s.OnRepoScanQueueEvent(event)
	}
}

// RunRepoScanPersisted runs one repository scan and persists repo scan metadata + findings.
func (s *Service) RunRepoScanPersisted(ctx context.Context, request RepoScanRequest) (RunRepoScanResult, error) {
	ctx = s.scopeContext(ctx)
	target, source, scanContext, historyLimit, maxFindings, err := s.validateRepoScanRequest(ctx, request)
	if err != nil {
		return RunRepoScanResult{}, err
	}
	cursor, hasCursor, err := s.repoScanCursor(ctx, target, source)
	if err != nil {
		return RunRepoScanResult{}, err
	}
	if hasCursor && scanContext.CursorBefore == "" {
		scanContext.CursorBefore = cursor.LastScannedRevision
	}
	if repoScanCursorAlreadyCoversRequest(scanContext, cursor, hasCursor) {
		s.recordRepoScanSkipped(scanContext.ScanMode, "cursor_current")
		return RunRepoScanResult{}, ErrRepoScanAlreadyCurrent
	}
	if s.Locker != nil {
		release, ok := s.Locker.TryAcquire(ctx, s.lockKey("repo-scan:"+strings.ToLower(target)))
		if !ok {
			return RunRepoScanResult{}, ErrRepoScanInProgress
		}
		defer release(context.Background())
	}
	record, err := s.Store.CreateRepoScan(ctx, target, source, scanContext, s.Now().UTC())
	if err != nil {
		return RunRepoScanResult{}, fmt.Errorf("create repo scan: %w", err)
	}
	return s.runRepoScanWithRecord(ctx, record, historyLimit, maxFindings)
}

func (s *Service) validateRepoScanRequest(ctx context.Context, request RepoScanRequest) (string, db.RepoScanSource, db.RepoScanContext, int, int, error) {
	if !s.RepoScanEnabled {
		return "", db.RepoScanSource{}, db.RepoScanContext{}, 0, 0, ErrRepoScanDisabled
	}
	target := strings.TrimSpace(request.Repository)
	if target == "" {
		return "", db.RepoScanSource{}, db.RepoScanContext{}, 0, 0, ErrInvalidRepoScanRequest
	}
	if repoTargetContainsURLCredentials(target) {
		return "", db.RepoScanSource{}, db.RepoScanContext{}, 0, 0, repoScanRequestValidationError{"repository target must not include credentials in URL userinfo"}
	}
	if repoexposure.IsLocalRepositoryTarget(target) {
		s.recordServiceAuthzDenial(ctx, "repo_scans.run", "repo_scan_target", target)
		return "", db.RepoScanSource{}, db.RepoScanContext{}, 0, 0, ErrRepoTargetNotAllowed
	}
	historyLimit, err := sanitizeRepoScanLimit(request.HistoryLimit, s.RepoScanDefaultHistoryLimit, s.RepoScanMaxHistoryLimit)
	if err != nil {
		return "", db.RepoScanSource{}, db.RepoScanContext{}, 0, 0, ErrInvalidRepoScanRequest
	}
	maxFindings, err := sanitizeRepoScanLimit(request.MaxFindings, s.RepoScanDefaultMaxFindings, s.RepoScanMaxFindingsLimit)
	if err != nil {
		return "", db.RepoScanSource{}, db.RepoScanContext{}, 0, 0, ErrInvalidRepoScanRequest
	}
	scanContext := db.NormalizeRepoScanContext(db.RepoScanContext{
		ScanMode:     request.ScanMode,
		BaseRevision: request.BaseRevision,
		HeadRevision: request.HeadRevision,
		ChangedPaths: request.ChangedPaths,
	})
	if scanContext.ScanMode == db.RepoScanModeDelta && scanContext.HeadRevision == "" {
		return "", db.RepoScanSource{}, db.RepoScanContext{}, 0, 0, ErrInvalidRepoScanRequest
	}

	if repoScanRequestUsesConnector(request) {
		normalizedTarget := normalizeGitHubRepositoryPath(target)
		if normalizedTarget == "" {
			return "", db.RepoScanSource{}, db.RepoScanContext{}, 0, 0, ErrInvalidRepoScanRequest
		}
		target = normalizeGitHubRepository(normalizedTarget)

		source, err := s.resolveRepoScanSource(ctx, target, request)
		if err != nil {
			return "", db.RepoScanSource{}, db.RepoScanContext{}, 0, 0, err
		}

		return target, source, scanContext, historyLimit, maxFindings, nil
	}
	if !repoTargetAllowed(target, s.RepoScanAllowedTargets) {
		s.recordServiceAuthzDenial(ctx, "repo_scans.run", "repo_scan_target", target)
		return "", db.RepoScanSource{}, db.RepoScanContext{}, 0, 0, ErrRepoTargetNotAllowed
	}
	return target, db.RepoScanSource{}, scanContext, historyLimit, maxFindings, nil
}

func repoScanRequestUsesConnector(request RepoScanRequest) bool {
	return strings.TrimSpace(request.ProjectID) != "" || strings.TrimSpace(request.ConnectorID) != ""
}

func (s *Service) resolveRepoScanSource(ctx context.Context, target string, request RepoScanRequest) (db.RepoScanSource, error) {
	projectID := strings.TrimSpace(request.ProjectID)
	connectorID := strings.TrimSpace(request.ConnectorID)
	if projectID == "" && connectorID == "" {
		return db.RepoScanSource{}, nil
	}
	if projectID == "" {
		return db.RepoScanSource{}, ErrInvalidRepoScanRequest
	}

	project, _, err := s.requireScopedProject(ctx, "", projectID)
	if err != nil {
		if errors.Is(err, ErrInvalidGitHubConnectionRequest) {
			return db.RepoScanSource{}, ErrInvalidRepoScanRequest
		}
		if errors.Is(err, db.ErrNotFound) {
			return db.RepoScanSource{}, ErrInvalidRepoScanRequest
		}
		return db.RepoScanSource{}, err
	}
	status, err := s.GetGitHubConnection(ctx, project.WorkspaceID, project.ProjectID)
	if err != nil {
		if errors.Is(err, ErrInvalidGitHubConnectionRequest) || errors.Is(err, ErrGitHubConnectionNotFound) || errors.Is(err, db.ErrNotFound) {
			return db.RepoScanSource{}, ErrRepoTargetNotAllowed
		}
		return db.RepoScanSource{}, err
	}
	effectiveConnectorID := firstNonEmptyString(status.ConnectorID, githubConnectorID)
	if connectorID != "" && connectorID != effectiveConnectorID {
		return db.RepoScanSource{}, ErrInvalidRepoScanRequest
	}
	if !status.Connected || !strings.EqualFold(status.Provider, "github_app") || status.InstallationID <= 0 {
		return db.RepoScanSource{}, ErrRepoTargetNotAllowed
	}
	if !repositorySelected(status.SelectedRepositories, target) {
		s.recordServiceAuthzDenial(ctx, "repo_scans.run", "repo_scan_target", target)
		return db.RepoScanSource{}, ErrRepoTargetNotAllowed
	}
	return db.RepoScanSource{
		Provider:       "github_app",
		ProjectID:      project.ProjectID,
		ConnectorID:    effectiveConnectorID,
		InstallationID: status.InstallationID,
	}.Normalize(), nil
}

// repoScanRequestValidationError keeps the user-facing message while preserving
// ErrInvalidRepoScanRequest compatibility for routing checks.
type repoScanRequestValidationError struct {
	message string
}

func (e repoScanRequestValidationError) Error() string {
	return e.message
}

func (e repoScanRequestValidationError) Is(target error) bool {
	return target == ErrInvalidRepoScanRequest
}

func repoTargetContainsURLCredentials(target string) bool {
	parsed, err := url.Parse(target)
	if err != nil || parsed == nil || parsed.Scheme == "" {
		return false
	}
	if parsed.User == nil {
		return false
	}
	if strings.EqualFold(parsed.Scheme, "ssh") {
		if _, hasPassword := parsed.User.Password(); hasPassword {
			return true
		}
		return strings.TrimSpace(parsed.User.Username()) == ""
	}
	return true
}

func (s *Service) runRepoScanWithRecord(ctx context.Context, record db.RepoScanRecord, historyLimit int, maxFindings int) (RunRepoScanResult, error) {
	ctx = s.scopeContext(ctx)
	scanStarted := time.Now()
	if s.Metrics != nil {
		s.Metrics.RepoScanRunsTotal.Inc()
		defer func() {
			s.Metrics.RepoScanDurationMS.Observe(float64(time.Since(scanStarted).Milliseconds()))
		}()
	}
	target := strings.TrimSpace(record.Repository)
	if target == "" {
		s.recordRepoScanExecutionFailure()
		return RunRepoScanResult{}, ErrInvalidRepoScanRequest
	}
	record.ScanMode = db.NormalizeRepoScanContext(db.RepoScanContext{ScanMode: record.ScanMode}).ScanMode
	normalizedHistory, err := sanitizeRepoScanLimit(historyLimit, s.RepoScanDefaultHistoryLimit, s.RepoScanMaxHistoryLimit)
	if err != nil {
		s.recordRepoScanExecutionFailure()
		s.recordRepoScanModeRun(record.ScanMode, "failure")
		_ = s.completeRepoScanTerminal(ctx, record.ID, "failed", s.Now().UTC(), 0, 0, 0, false, db.RepoScanContext{}, ErrInvalidRepoScanRequest.Error())
		return RunRepoScanResult{}, ErrInvalidRepoScanRequest
	}
	normalizedMaxFindings, err := sanitizeRepoScanLimit(maxFindings, s.RepoScanDefaultMaxFindings, s.RepoScanMaxFindingsLimit)
	if err != nil {
		s.recordRepoScanExecutionFailure()
		s.recordRepoScanModeRun(record.ScanMode, "failure")
		_ = s.completeRepoScanTerminal(ctx, record.ID, "failed", s.Now().UTC(), 0, 0, 0, false, db.RepoScanContext{}, ErrInvalidRepoScanRequest.Error())
		return RunRepoScanResult{}, ErrInvalidRepoScanRequest
	}
	executor, scanSecrets, err := s.repoScanExecutorForRecord(ctx, record, normalizedHistory, normalizedMaxFindings)
	if err != nil {
		s.recordRepoScanExecutionFailure()
		s.recordRepoScanModeRun(record.ScanMode, "failure")
		_ = s.completeRepoScanTerminal(ctx, record.ID, "failed", s.Now().UTC(), 0, 0, 0, false, db.RepoScanContext{}, err.Error())
		return RunRepoScanResult{}, err
	}
	scanContext := db.NormalizeRepoScanContext(db.RepoScanContext{
		ScanMode:     record.ScanMode,
		BaseRevision: record.BaseRevision,
		HeadRevision: record.HeadRevision,
		ChangedPaths: record.ChangedPaths,
	})
	result, err := runRepoScanExecutor(ctx, executor, target, scanContext)
	if err != nil {
		safeErr := sanitizeRepoScanError(err, scanSecrets...)
		s.recordRepoScanExecutionFailure()
		s.recordRepoScanModeRun(record.ScanMode, "failure")
		_ = s.completeRepoScanTerminal(ctx, record.ID, "failed", s.Now().UTC(), 0, 0, 0, false, db.RepoScanContext{}, safeErr.Error())
		return RunRepoScanResult{}, safeErr
	}
	result = applyRepoScanContextToResult(result, target, scanContext)
	sourceErrors := []providers.SourceError{}
	inconclusiveLifecycleKeys := []string{}
	if !result.Truncated {
		externalEvidence, externalErr := s.repoScanExternalFindings(ctx, record, s.Now().UTC())
		externalFindings := externalEvidence.Findings
		sourceErrors = append(sourceErrors, externalEvidence.SourceErrors...)
		inconclusiveLifecycleKeys = append(inconclusiveLifecycleKeys, externalEvidence.InconclusiveLifecycleKeys...)
		if len(sourceErrors) > 0 {
			s.appendScanEvent(ctx, record.ID, db.ScanEventLevelWarn, "repo scan completed with partial source errors", map[string]any{
				"source_error_count": len(sourceErrors),
				"source_errors":      truncateSourceErrors(sourceErrors, maxSourceErrorsInEvent),
			})
			s.appendScanLifecycleEvent(ctx, record.ID, scanLifecyclePartial, map[string]any{"source_error_count": len(sourceErrors)})
		}
		if externalErr != nil {
			if errors.Is(externalErr, context.Canceled) || errors.Is(externalErr, context.DeadlineExceeded) {
				s.recordRepoScanExecutionFailure()
				s.recordRepoScanModeRun(record.ScanMode, "failure")
				_ = s.completeRepoScanTerminal(ctx, record.ID, "failed", s.Now().UTC(), result.CommitsScanned, result.FilesScanned, len(result.Findings), result.Truncated, db.RepoScanContext{}, externalErr.Error())
				return RunRepoScanResult{}, externalErr
			}
		} else if len(externalFindings) > 0 {
			var externalTruncated bool
			result.Findings, externalTruncated = repoexposure.MergeExternalFindings(result.Findings, externalFindings, normalizedMaxFindings)
			result.Truncated = result.Truncated || externalTruncated
		}
	}
	sourceHealthDetails := s.repoScanSourceHealthDetails(record, result.Truncated, sourceErrors)
	sourceHealth, _ := db.NormalizeRepoScanSourceHealth("", sourceHealthDetails)
	partialSourceRun := sourceHealth != db.RepoScanSourceHealthComplete
	result.Findings = enrichFindingsWithRepoContext(result.Findings, result.Repository, record.Repository)
	if repoScanUsesGitHubAppSource(record) {
		result.Findings = filterReportableRepoFindings(result.Findings)
	}
	if err := s.Store.UpsertRepoFindings(ctx, record.ID, result.Findings); err != nil {
		if errors.Is(err, db.ErrConflict) {
			if cleanupErr := s.clearRepoScanFindingsAfterTerminalChange(ctx, record.ID); cleanupErr != nil {
				return RunRepoScanResult{}, cleanupErr
			}
			return RunRepoScanResult{}, fmt.Errorf("%w: %w", errRepoScanTerminalStateChanged, err)
		}
		s.recordRepoScanExecutionFailure()
		s.recordRepoScanModeRun(record.ScanMode, "failure")
		_ = s.completeRepoScanTerminal(ctx, record.ID, "failed", s.Now().UTC(), result.CommitsScanned, result.FilesScanned, 0, result.Truncated, db.RepoScanContext{}, err.Error())
		return RunRepoScanResult{}, fmt.Errorf("persist repo findings: %w", err)
	}
	cursorAfter := firstNonEmptyString(result.HeadRevision, record.HeadRevision)
	completionContext := db.RepoScanContext{
		ScanMode:                  result.ScanMode,
		BaseRevision:              result.BaseRevision,
		HeadRevision:              result.HeadRevision,
		ChangedPaths:              append([]string(nil), result.ChangedPaths...),
		InconclusiveLifecycleKeys: inconclusiveLifecycleKeys,
		PartialSourceRun:          partialSourceRun,
		SourceHealth:              sourceHealth,
		SourceDetails:             sourceHealthDetails,
	}
	if !result.Truncated && !partialSourceRun {
		completionContext.CursorAfter = cursorAfter
	}
	if err := s.completeRepoScanTerminal(
		ctx,
		record.ID,
		"succeeded",
		s.Now().UTC(),
		result.CommitsScanned,
		result.FilesScanned,
		len(result.Findings),
		result.Truncated,
		completionContext,
		"",
	); err != nil {
		if errors.Is(err, db.ErrConflict) {
			if cleanupErr := s.clearRepoScanFindingsAfterTerminalChange(ctx, record.ID); cleanupErr != nil {
				return RunRepoScanResult{}, cleanupErr
			}
			return RunRepoScanResult{}, fmt.Errorf("%w: %w", errRepoScanTerminalStateChanged, err)
		}
		s.recordRepoScanExecutionFailure()
		s.recordRepoScanModeRun(record.ScanMode, "failure")
		return RunRepoScanResult{}, fmt.Errorf("complete repo scan: %w", err)
	}
	if cursorAfter != "" && !result.Truncated && !partialSourceRun {
		completedAt := s.Now().UTC()
		record.CursorAfter = cursorAfter
		record.HeadRevision = firstNonEmptyString(record.HeadRevision, result.HeadRevision)
		// The scan row is already terminal-success; cursor persistence must not turn it into a failed worker run.
		_ = s.Store.UpsertRepoScanCursor(ctx, db.RepoScanCursor{
			Repository:          record.Repository,
			Source:              record.Source,
			LastScannedRevision: cursorAfter,
			LastDeepScannedAt:   repoScanLastDeepScannedAt(record.ScanMode, completedAt),
			LastScanID:          record.ID,
			LastScanMode:        record.ScanMode,
			LastScanCompletedAt: completedAt,
			UpdatedAt:           completedAt,
		})
	}
	s.recordRepoScanModeRun(record.ScanMode, "succeeded")
	record.Status = "succeeded"
	finished := s.Now().UTC()
	record.FinishedAt = &finished
	record.CommitsScanned = result.CommitsScanned
	record.FilesScanned = result.FilesScanned
	record.FindingCount = len(result.Findings)
	record.Truncated = result.Truncated
	record.SourceHealth = sourceHealth
	record.SourceHealthDetails = sourceHealthDetails
	record.ScanMode = result.ScanMode
	record.BaseRevision = result.BaseRevision
	record.HeadRevision = result.HeadRevision
	record.ChangedPaths = append([]string(nil), result.ChangedPaths...)
	record.HistoryLimit = normalizedHistory
	record.MaxFindings = normalizedMaxFindings
	if s.Metrics != nil {
		s.Metrics.RepoScanSuccessTotal.Inc()
		s.Metrics.RepoFindingsGenerated.Add(float64(len(result.Findings)))
		if result.Truncated {
			s.Metrics.RepoScanTruncatedTotal.Inc()
		}
	}
	return RunRepoScanResult{RepoScan: record, Result: result}, nil
}

func (s *Service) clearRepoScanFindingsAfterTerminalChange(ctx context.Context, repoScanID string) error {
	if err := s.Store.DeleteRepoFindings(ctx, repoScanID); err != nil && !errors.Is(err, db.ErrNotFound) {
		return fmt.Errorf("clear terminal repo scan findings: %w", err)
	}
	return nil
}

func repoScanCursorAlreadyCoversRequest(scanContext db.RepoScanContext, cursor db.RepoScanCursor, hasCursor bool) bool {
	return scanContext.ScanMode == db.RepoScanModeDelta &&
		scanContext.HeadRevision != "" &&
		hasCursor &&
		strings.EqualFold(cursor.LastScannedRevision, scanContext.HeadRevision) &&
		repoScanCursorCoversDeltaHistory(cursor)
}

func repoScanCursorCoversDeltaHistory(cursor db.RepoScanCursor) bool {
	switch strings.ToLower(strings.TrimSpace(cursor.LastScanMode)) {
	case "", db.RepoScanModeDeep, db.RepoScanModeDelta:
		return true
	default:
		return false
	}
}

func (s *Service) repoScanExecutorForRecord(ctx context.Context, record db.RepoScanRecord, historyLimit int, maxFindings int) (RepoScanExecutor, []string, error) {
	source := record.Source.Normalize()
	if source.Empty() {
		if s.RepoScannerFactory == nil {
			return nil, nil, fmt.Errorf("repo scanner factory is not configured")
		}
		return s.RepoScannerFactory(historyLimit, maxFindings), nil, nil
	}
	switch source.Provider {
	case "github_app":
		if s.AuthenticatedRepoScannerFactory == nil {
			return nil, nil, fmt.Errorf("authenticated repo scanner factory is not configured")
		}
		credential, err := s.githubAppRepoScanCredential(ctx, record)
		if err != nil {
			return nil, nil, err
		}
		return s.AuthenticatedRepoScannerFactory(historyLimit, maxFindings, credential), []string{credential.Password}, nil
	default:
		return nil, nil, ErrInvalidRepoScanRequest
	}
}

func runRepoScanExecutor(ctx context.Context, executor RepoScanExecutor, target string, scanContext db.RepoScanContext) (repoexposure.ScanResult, error) {
	options := repoexposure.ScanOptions{
		Mode:         scanContext.ScanMode,
		BaseRevision: scanContext.BaseRevision,
		HeadRevision: scanContext.HeadRevision,
		ChangedPaths: append([]string(nil), scanContext.ChangedPaths...),
	}
	if withOptions, ok := executor.(RepoScanExecutorWithOptions); ok {
		return withOptions.ScanRepositoryWithOptions(ctx, target, options)
	}
	return executor.ScanRepository(ctx, target)
}

func applyRepoScanContextToResult(result repoexposure.ScanResult, target string, scanContext db.RepoScanContext) repoexposure.ScanResult {
	normalized := db.NormalizeRepoScanContext(scanContext)
	if strings.TrimSpace(result.Repository) == "" {
		result.Repository = strings.TrimSpace(target)
	}
	if strings.TrimSpace(result.ScanMode) == "" {
		result.ScanMode = normalized.ScanMode
	}
	if strings.TrimSpace(result.BaseRevision) == "" {
		result.BaseRevision = normalized.BaseRevision
	}
	if strings.TrimSpace(result.HeadRevision) == "" {
		result.HeadRevision = normalized.HeadRevision
	}
	if len(result.ChangedPaths) == 0 {
		result.ChangedPaths = append([]string(nil), normalized.ChangedPaths...)
	}
	return result
}

func (s *Service) repoScanCursor(ctx context.Context, repository string, source db.RepoScanSource) (db.RepoScanCursor, bool, error) {
	cursor, err := s.Store.GetRepoScanCursor(ctx, repository, source)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			return db.RepoScanCursor{}, false, nil
		}
		return db.RepoScanCursor{}, false, fmt.Errorf("get repo scan cursor: %w", err)
	}
	return cursor, true, nil
}

func repoScanLastDeepScannedAt(mode string, completedAt time.Time) *time.Time {
	if !strings.EqualFold(strings.TrimSpace(mode), db.RepoScanModeDeep) {
		return nil
	}
	converted := completedAt.UTC()
	return &converted
}

// repoScanExternalEvidence is the outcome of enriching one repo scan with
// GitHub-native sources.
type repoScanExternalEvidence struct {
	Findings     []domain.Finding
	SourceErrors []providers.SourceError
	// InconclusiveLifecycleKeys are lifecycle keys whose control this scan could
	// not evaluate. They must not be closed at completion even though they are
	// absent from Findings.
	InconclusiveLifecycleKeys []string
}

func (s *Service) repoScanExternalFindings(ctx context.Context, record db.RepoScanRecord, detectedAt time.Time) (repoScanExternalEvidence, error) {
	source := record.Source.Normalize()
	if source.Provider != "github_app" || source.InstallationID <= 0 {
		return repoScanExternalEvidence{}, nil
	}
	inconclusiveLifecycleKeys := []string{}
	sourceErrors := make([]providers.SourceError, 0)
	recordSourceError := func(collector, code, message string) {
		sourceErrors = append(sourceErrors, providers.SourceError{
			Collector: collector,
			Code:      code,
			Message:   message,
		})
	}
	recordSourceErr := func(collector string, operation string, err error) {
		if err == nil {
			return
		}
		recordSourceError(collector, operation, err.Error())
	}
	findings := []domain.Finding{}
	// Each GitHub-native alert source is an enrichment source. Permission-limited,
	// unavailable, or rate-limited endpoints must not fail the native repo scan;
	// they simply contribute no imported findings for that run. Only context
	// cancellation/deadline aborts the collection.
	if s.GitHubCodeScanningAlertCollector != nil {
		alerts, err := s.GitHubCodeScanningAlertCollector.ListCodeScanningAlerts(ctx, source.InstallationID, record.Repository)
		if err != nil {
			if ctx.Err() != nil {
				return repoScanExternalEvidence{}, ctx.Err()
			}
			recordSourceErr("github_code_scanning", "alert_list_error", err)
		} else {
			imported, normErr := repoexposure.NormalizeGitHubCodeScanningAlerts(ctx, record.Repository, "", githubCodeScanningAlertsToRepoExposure(alerts), detectedAt)
			if normErr != nil {
				if ctx.Err() != nil {
					return repoScanExternalEvidence{}, ctx.Err()
				}
				recordSourceErr("github_code_scanning", "normalize_error", normErr)
			} else {
				findings = append(findings, imported...)
			}
		}
	}
	if s.GitHubSecretScanningAlertCollector != nil {
		alerts, err := s.GitHubSecretScanningAlertCollector.ListSecretScanningAlerts(ctx, source.InstallationID, record.Repository)
		if err != nil {
			if ctx.Err() != nil {
				return repoScanExternalEvidence{}, ctx.Err()
			}
			recordSourceErr("github_secret_scanning", "alert_list_error", err)
		} else {
			imported, normErr := repoexposure.NormalizeGitHubSecretScanningAlerts(ctx, record.Repository, "", githubSecretScanningAlertsToRepoExposure(alerts), detectedAt)
			if normErr != nil {
				if ctx.Err() != nil {
					return repoScanExternalEvidence{}, ctx.Err()
				}
				recordSourceErr("github_secret_scanning", "normalize_error", normErr)
			} else {
				findings = append(findings, imported...)
			}
		}
	}
	if s.GitHubDependabotAlertCollector != nil {
		alerts, err := s.GitHubDependabotAlertCollector.ListDependabotAlerts(ctx, source.InstallationID, record.Repository)
		if err != nil {
			if ctx.Err() != nil {
				return repoScanExternalEvidence{}, ctx.Err()
			}
			recordSourceErr("github_dependabot", "alert_list_error", err)
		} else {
			imported, normErr := repoexposure.NormalizeGitHubDependabotAlerts(ctx, record.Repository, "", githubDependabotAlertsToRepoExposure(alerts), detectedAt)
			if normErr != nil {
				if ctx.Err() != nil {
					return repoScanExternalEvidence{}, ctx.Err()
				}
				recordSourceErr("github_dependabot", "normalize_error", normErr)
			} else {
				findings = append(findings, imported...)
			}
		}
	}
	if s.GitHubRepositoryPostureCollector != nil {
		posture, err := s.GitHubRepositoryPostureCollector.CollectRepositoryPosture(ctx, source.InstallationID, record.Repository)
		if err != nil {
			if ctx.Err() != nil {
				return repoScanExternalEvidence{}, ctx.Err()
			}
			recordSourceErr("github_repository_posture", "posture_collect_error", err)
		} else {
			findings = append(findings, githubconnector.RepositoryPostureFindings(posture, detectedAt)...)
			inconclusiveLifecycleKeys = append(inconclusiveLifecycleKeys, githubconnector.RepositoryPostureInconclusiveLifecycleKeys(posture)...)
		}
		if owner, _, ok := strings.Cut(record.Repository, "/"); ok && strings.TrimSpace(owner) != "" {
			orgPosture, orgErr := s.GitHubRepositoryPostureCollector.CollectOrganizationPosture(ctx, source.InstallationID, owner, record.Repository)
			if orgErr != nil {
				if ctx.Err() != nil {
					return repoScanExternalEvidence{}, ctx.Err()
				}
				recordSourceErr("github_organization_posture", "posture_collect_error", orgErr)
			} else {
				// Checks GitHub could not evaluate are collected even when the
				// organization posture is otherwise skipped, so an organization
				// control that stops being exposed never reads as a fix.
				inconclusiveLifecycleKeys = append(inconclusiveLifecycleKeys, githubconnector.OrganizationPostureInconclusiveLifecycleKeys(orgPosture, record.Repository)...)
				if githubOrganizationPostureAvailable(orgPosture) {
					findings = append(findings, githubconnector.OrganizationPostureFindings(orgPosture, record.Repository, detectedAt)...)
				}
			}
		}
	}
	return repoScanExternalEvidence{
		Findings:                  findings,
		SourceErrors:              sourceErrors,
		InconclusiveLifecycleKeys: inconclusiveLifecycleKeys,
	}, nil
}

func repoScanUsesGitHubAppSource(record db.RepoScanRecord) bool {
	source := record.Source.Normalize()
	return source.Provider == "github_app"
}

func filterReportableRepoFindings(findings []domain.Finding) []domain.Finding {
	filtered := findings[:0]
	for _, finding := range findings {
		if finding.ConfidenceScore < gitHubRepoFindingConfidenceFloor {
			continue
		}
		if !isHighImpactRepoFinding(finding) {
			continue
		}
		filtered = append(filtered, finding)
	}
	return filtered
}

func isHighImpactRepoFinding(finding domain.Finding) bool {
	switch finding.Severity {
	case domain.SeverityCritical, domain.SeverityHigh:
		return true
	default:
		return false
	}
}

func (s *Service) repoScanSourceHealthDetails(record db.RepoScanRecord, truncated bool, sourceErrors []providers.SourceError) []db.RepoScanSourceHealth {
	details := []db.RepoScanSourceHealth{{
		Source: "identrail_repo_scanner",
		Status: db.RepoScanSourceHealthComplete,
	}}
	skipCode := ""
	skipMessage := ""
	if truncated {
		details[0].Status = db.RepoScanSourceHealthPartial
		details[0].Code = "repo_scan_truncated"
		details[0].Message = "repository scan reached the configured finding limit"
		skipCode = "scan_truncated"
		skipMessage = "source collection skipped because repository scan was truncated"
	}

	source := record.Source.Normalize()
	if source.Provider != "github_app" || source.InstallationID <= 0 {
		return details
	}

	errorsByCollector := map[string][]providers.SourceError{}
	for _, sourceError := range sourceErrors {
		collector := strings.ToLower(strings.TrimSpace(sourceError.Collector))
		if collector == "" {
			collector = "unknown"
		}
		errorsByCollector[collector] = append(errorsByCollector[collector], sourceError)
	}

	githubSources := []struct {
		name      string
		available bool
		code      string
		message   string
	}{
		{name: "github_code_scanning", available: s.GitHubCodeScanningAlertCollector != nil, code: "collector_unavailable", message: "GitHub code scanning collector is unavailable"},
		{name: "github_secret_scanning", available: s.GitHubSecretScanningAlertCollector != nil, code: "collector_unavailable", message: "GitHub secret scanning collector is unavailable"},
		{name: "github_dependabot", available: s.GitHubDependabotAlertCollector != nil, code: "collector_unavailable", message: "GitHub Dependabot collector is unavailable"},
		{name: "github_repository_posture", available: s.GitHubRepositoryPostureCollector != nil, code: "collector_unavailable", message: "GitHub repository posture collector is unavailable"},
		{name: "github_organization_posture", available: s.GitHubRepositoryPostureCollector != nil && repoScanRepositoryOwner(record.Repository) != "", code: "collector_unavailable", message: "GitHub organization posture collector is unavailable"},
	}
	for _, githubSource := range githubSources {
		if sourceErrors, exists := errorsByCollector[githubSource.name]; exists {
			for _, sourceError := range sourceErrors {
				details = append(details, repoScanSourceHealthFromSourceError(githubSource.name, sourceError))
			}
			continue
		}
		if truncated {
			details = append(details, db.RepoScanSourceHealth{
				Source:  githubSource.name,
				Status:  db.RepoScanSourceHealthPartial,
				Code:    skipCode,
				Message: skipMessage,
			})
			continue
		}
		if !githubSource.available {
			if githubSource.name == "github_organization_posture" && s.GitHubRepositoryPostureCollector != nil {
				githubSource.code = "invalid_repository"
				githubSource.message = "repository target does not include an owner for organization posture collection"
			}
			details = append(details, db.RepoScanSourceHealth{
				Source:  githubSource.name,
				Status:  db.RepoScanSourceHealthUnavailable,
				Code:    githubSource.code,
				Message: githubSource.message,
			})
			continue
		}
		details = append(details, db.RepoScanSourceHealth{
			Source: githubSource.name,
			Status: db.RepoScanSourceHealthComplete,
		})
	}
	for collector, collectorErrors := range errorsByCollector {
		if repoScanKnownGitHubCollector(collector) {
			continue
		}
		for _, sourceError := range collectorErrors {
			details = append(details, repoScanSourceHealthFromSourceError(collector, sourceError))
		}
	}
	return details
}

func repoScanSourceHealthFromSourceError(source string, sourceError providers.SourceError) db.RepoScanSourceHealth {
	status := classifyRepoScanSourceHealth(sourceError.Code, sourceError.Message)
	return db.RepoScanSourceHealth{
		Source:    source,
		Status:    status,
		Code:      sourceError.Code,
		Message:   sourceError.Message,
		Retryable: sourceError.Retryable || status == db.RepoScanSourceHealthRateLimited || status == db.RepoScanSourceHealthUnavailable,
	}
}

func classifyRepoScanSourceHealth(code string, message string) string {
	needle := strings.ToLower(strings.TrimSpace(code + " " + message))
	switch {
	case strings.Contains(needle, "rate limit") ||
		strings.Contains(needle, "secondary rate") ||
		strings.Contains(needle, "abuse detection") ||
		strings.Contains(needle, "throttl") ||
		strings.Contains(needle, "429") ||
		(strings.Contains(needle, "403") && strings.Contains(needle, "rate")):
		return db.RepoScanSourceHealthRateLimited
	case strings.Contains(needle, "permission") ||
		strings.Contains(needle, "forbidden") ||
		strings.Contains(needle, "unauthor") ||
		strings.Contains(needle, "access denied") ||
		strings.Contains(needle, "accessdenied") ||
		strings.Contains(needle, "requires authentication") ||
		strings.Contains(needle, "bad credentials") ||
		strings.Contains(needle, "403"):
		return db.RepoScanSourceHealthPermissionLimited
	case strings.Contains(needle, "timeout") ||
		strings.Contains(needle, "timed out") ||
		strings.Contains(needle, "unavailable") ||
		strings.Contains(needle, "temporarily") ||
		strings.Contains(needle, "network") ||
		strings.Contains(needle, "connection") ||
		strings.Contains(needle, "502") ||
		strings.Contains(needle, "503") ||
		strings.Contains(needle, "504"):
		return db.RepoScanSourceHealthUnavailable
	case strings.Contains(needle, "partial") ||
		strings.Contains(needle, "normalize"):
		return db.RepoScanSourceHealthPartial
	default:
		return db.RepoScanSourceHealthUnknown
	}
}

func repoScanRepositoryOwner(repository string) string {
	owner, _, ok := strings.Cut(strings.TrimSpace(repository), "/")
	if !ok {
		return ""
	}
	return strings.TrimSpace(owner)
}

func repoScanKnownGitHubCollector(collector string) bool {
	switch strings.ToLower(strings.TrimSpace(collector)) {
	case "github_code_scanning", "github_secret_scanning", "github_dependabot", "github_repository_posture", "github_organization_posture":
		return true
	default:
		return false
	}
}

func githubCodeScanningAlertsToRepoExposure(alerts []githubconnector.CodeScanningAlert) []repoexposure.GitHubCodeScanningAlert {
	converted := make([]repoexposure.GitHubCodeScanningAlert, 0, len(alerts))
	for _, alert := range alerts {
		converted = append(converted, repoexposure.GitHubCodeScanningAlert{
			Number: alert.Number,
			State:  alert.State,
			Rule: repoexposure.GitHubCodeScanningRule{
				ID:                    alert.Rule.ID,
				Name:                  alert.Rule.Name,
				Severity:              alert.Rule.Severity,
				Description:           alert.Rule.Description,
				SecuritySeverityLevel: alert.Rule.SecuritySeverityLevel,
				Tags:                  append([]string(nil), alert.Rule.Tags...),
			},
			Tool: repoexposure.GitHubCodeScanningTool{
				Name:    alert.Tool.Name,
				Version: alert.Tool.Version,
			},
			MostRecentInstance: repoexposure.GitHubCodeScanningAlertInstance{
				Ref:         alert.MostRecentInstance.Ref,
				AnalysisKey: alert.MostRecentInstance.AnalysisKey,
				Category:    alert.MostRecentInstance.Category,
				State:       alert.MostRecentInstance.State,
				CommitSHA:   alert.MostRecentInstance.CommitSHA,
				Message: repoexposure.GitHubCodeScanningMessage{
					Text: alert.MostRecentInstance.Message.Text,
				},
				Location: repoexposure.GitHubCodeScanningLocation{
					Path:        alert.MostRecentInstance.Location.Path,
					StartLine:   alert.MostRecentInstance.Location.StartLine,
					EndLine:     alert.MostRecentInstance.Location.EndLine,
					StartColumn: alert.MostRecentInstance.Location.StartColumn,
					EndColumn:   alert.MostRecentInstance.Location.EndColumn,
				},
			},
			HTMLURL: alert.HTMLURL,
		})
	}
	return converted
}

func githubSecretScanningAlertsToRepoExposure(alerts []githubconnector.SecretScanningAlert) []repoexposure.GitHubSecretScanningAlert {
	converted := make([]repoexposure.GitHubSecretScanningAlert, 0, len(alerts))
	for _, alert := range alerts {
		converted = append(converted, repoexposure.GitHubSecretScanningAlert{
			Number:                alert.Number,
			State:                 alert.State,
			SecretType:            alert.SecretType,
			SecretTypeDisplayName: alert.SecretTypeDisplayName,
			Validity:              alert.Validity,
			Resolution:            alert.Resolution,
			PushProtectionBypass:  alert.PushProtectionBypass,
			HTMLURL:               alert.HTMLURL,
		})
	}
	return converted
}

func githubDependabotAlertsToRepoExposure(alerts []githubconnector.DependabotAlert) []repoexposure.GitHubDependabotAlert {
	converted := make([]repoexposure.GitHubDependabotAlert, 0, len(alerts))
	for _, alert := range alerts {
		identifiers := make([]repoexposure.GitHubDependabotAdvisoryIdentity, 0, len(alert.SecurityAdvisory.Identifiers))
		for _, identifier := range alert.SecurityAdvisory.Identifiers {
			identifiers = append(identifiers, repoexposure.GitHubDependabotAdvisoryIdentity{
				Type:  identifier.Type,
				Value: identifier.Value,
			})
		}
		converted = append(converted, repoexposure.GitHubDependabotAlert{
			Number: alert.Number,
			State:  alert.State,
			Dependency: repoexposure.GitHubDependabotDependency{
				Package: repoexposure.GitHubDependabotPackage{
					Ecosystem: alert.Dependency.Package.Ecosystem,
					Name:      alert.Dependency.Package.Name,
				},
				ManifestPath: alert.Dependency.ManifestPath,
				Scope:        alert.Dependency.Scope,
			},
			SecurityAdvisory: repoexposure.GitHubDependabotAdvisory{
				GHSAID:      alert.SecurityAdvisory.GHSAID,
				CVEID:       alert.SecurityAdvisory.CVEID,
				Summary:     alert.SecurityAdvisory.Summary,
				Severity:    alert.SecurityAdvisory.Severity,
				Identifiers: identifiers,
			},
			SecurityVulnerability: repoexposure.GitHubDependabotVulnerable{
				Package: repoexposure.GitHubDependabotPackage{
					Ecosystem: alert.SecurityVulnerability.Package.Ecosystem,
					Name:      alert.SecurityVulnerability.Package.Name,
				},
				Severity:               alert.SecurityVulnerability.Severity,
				VulnerableVersionRange: alert.SecurityVulnerability.VulnerableVersionRange,
				FirstPatchedVersion: repoexposure.GitHubDependabotPatch{
					Identifier: alert.SecurityVulnerability.FirstPatchedVersion.Identifier,
				},
			},
			HTMLURL: alert.HTMLURL,
		})
	}
	return converted
}

func (s *Service) githubAppRepoScanCredential(ctx context.Context, record db.RepoScanRecord) (repoexposure.HTTPSCloneCredential, error) {
	source := record.Source.Normalize()
	if source.ProjectID == "" || source.InstallationID <= 0 {
		return repoexposure.HTTPSCloneCredential{}, ErrInvalidRepoScanRequest
	}
	// Workers run in a separate process from the API that completed the install
	// flow. Reload persisted connector state so repository selection changes are
	// honored before minting a short-lived installation token.
	status, err := s.refreshGitHubConnection(ctx, record.WorkspaceID, source.ProjectID)
	if err != nil {
		if errors.Is(err, ErrInvalidGitHubConnectionRequest) || errors.Is(err, ErrGitHubConnectionNotFound) || errors.Is(err, db.ErrNotFound) {
			return repoexposure.HTTPSCloneCredential{}, ErrRepoTargetNotAllowed
		}
		return repoexposure.HTTPSCloneCredential{}, err
	}
	effectiveConnectorID := firstNonEmptyString(status.ConnectorID, githubConnectorID)
	if source.ConnectorID != "" && source.ConnectorID != effectiveConnectorID {
		return repoexposure.HTTPSCloneCredential{}, ErrRepoTargetNotAllowed
	}
	if !status.Connected || !strings.EqualFold(status.Provider, "github_app") || status.InstallationID != source.InstallationID {
		return repoexposure.HTTPSCloneCredential{}, ErrRepoTargetNotAllowed
	}
	if !repositorySelected(status.SelectedRepositories, record.Repository) {
		return repoexposure.HTTPSCloneCredential{}, ErrRepoTargetNotAllowed
	}
	if s.GitHubInstallationTokenMinter == nil {
		return repoexposure.HTTPSCloneCredential{}, fmt.Errorf("github installation token minter is not configured")
	}
	token, err := s.GitHubInstallationTokenMinter.Mint(ctx, source.InstallationID)
	if err != nil {
		return repoexposure.HTTPSCloneCredential{}, fmt.Errorf("mint github installation token: %w", err)
	}
	tokenValue := strings.TrimSpace(token.Token)
	if tokenValue == "" {
		return repoexposure.HTTPSCloneCredential{}, fmt.Errorf("github installation token is empty")
	}
	return repoexposure.HTTPSCloneCredential{
		Host:     "github.com",
		Username: "x-access-token",
		Password: tokenValue,
	}, nil
}

func sanitizeRepoScanError(err error, secrets ...string) error {
	if err == nil {
		return nil
	}
	message := err.Error()
	redacted := false
	for _, secret := range secrets {
		secret = strings.TrimSpace(secret)
		if secret == "" {
			continue
		}
		if strings.Contains(message, secret) {
			redacted = true
		}
		message = strings.ReplaceAll(message, secret, "[redacted]")
	}
	if !redacted {
		return err
	}
	return errors.New(message)
}

func (s *Service) recordRepoScanExecutionFailure() {
	if s.Metrics != nil {
		s.Metrics.RepoScanFailureTotal.Inc()
	}
}

// ListRepoScans returns persisted repository scans.
func (s *Service) ListRepoScans(ctx context.Context, limit int) ([]db.RepoScanRecord, error) {
	ctx = s.scopeContext(ctx)
	return s.Store.ListRepoScans(ctx, limit)
}

// GetRepoScan returns one repository scan by id.
func (s *Service) GetRepoScan(ctx context.Context, repoScanID string) (db.RepoScanRecord, error) {
	ctx = s.scopeContext(ctx)
	id := strings.TrimSpace(repoScanID)
	if id == "" {
		return db.RepoScanRecord{}, db.ErrNotFound
	}
	return s.Store.GetRepoScan(ctx, id)
}

// DeleteRepoScan removes a failed repository scan record.
func (s *Service) DeleteRepoScan(ctx context.Context, repoScanID string) error {
	ctx = s.scopeContext(ctx)
	id := strings.TrimSpace(repoScanID)
	if id == "" {
		return db.ErrNotFound
	}
	record, err := s.Store.GetRepoScan(ctx, id)
	if err != nil {
		return err
	}
	if !isFailedRepoScanRecord(record) {
		return ErrRepoScanDeleteUnavailable
	}
	return s.Store.DeleteRepoScan(ctx, id)
}

func isFailedRepoScanRecord(record db.RepoScanRecord) bool {
	return strings.EqualFold(strings.TrimSpace(record.Status), scanLifecycleFailed)
}

// ListRepoFindings returns repository findings using optional filters.
func (s *Service) ListRepoFindings(ctx context.Context, limit int, filter db.RepoFindingFilter) ([]domain.Finding, error) {
	ctx = s.scopeContext(ctx)
	normalized := db.NormalizeRepoFindingFilter(filter)
	storeFilter := normalized
	storeFilter.Status = ""
	hasPostTriageFilter := normalized.Status != "" || normalized.LifecycleStatus != "" || normalized.Assignee != ""
	requestLimit := limit
	if requestLimit <= 0 {
		requestLimit = defaultFindingsLimit
	}
	repoLimit := requestLimit
	if hasPostTriageFilter && repoLimit < repoFindingsTriageFilterStep {
		repoLimit = repoFindingsTriageFilterStep
	}

	if hasPostTriageFilter {
		return s.listRepoFindingsWithPostTriageFilter(ctx, repoLimit, requestLimit, storeFilter, normalized)
	}

	findings, err := s.Store.ListRepoFindings(ctx, storeFilter, repoLimit)
	if err != nil {
		return nil, err
	}
	findings = enrichFindingsWithRepoContext(findings)
	withTriage, err := s.applyRepoFindingTriageStates(ctx, findings)
	if err != nil {
		return nil, err
	}
	return withTriage, nil
}

// GetRepoFindingsSummary returns lifecycle and ownership rollups for the
// repository finding list using the same filters as the list endpoint.
func (s *Service) GetRepoFindingsSummary(ctx context.Context, filter db.RepoFindingFilter) (RepoFindingsSummary, error) {
	ctx = s.scopeContext(ctx)
	normalized := db.NormalizeRepoFindingFilter(filter)
	storeFilter := normalized
	storeFilter.Status = ""
	findings, err := s.Store.ListRepoFindings(ctx, storeFilter, 0)
	if err != nil {
		return RepoFindingsSummary{}, err
	}
	findings = enrichFindingsWithRepoContext(findings)
	withTriage, err := s.applyRepoFindingTriageStates(ctx, findings)
	if err != nil {
		return RepoFindingsSummary{}, err
	}
	if normalized.Status != "" || normalized.LifecycleStatus != "" || normalized.Assignee != "" {
		withTriage = filterRepoFindingsByLifecycleAndTriage(withTriage, normalized.Status, normalized.LifecycleStatus, normalized.Assignee)
	}
	return summarizeRepoFindings(withTriage, s.Now().UTC()), nil
}

// DeleteRepoFinding permanently removes one repository finding from one scan.
func (s *Service) DeleteRepoFinding(ctx context.Context, findingID string, repoScanID string) error {
	ctx = s.scopeContext(ctx)
	findingID = strings.TrimSpace(findingID)
	repoScanID = strings.TrimSpace(repoScanID)
	if findingID == "" || repoScanID == "" {
		return ErrInvalidRepoRemediationRequest
	}
	return s.Store.DeleteRepoFinding(ctx, repoScanID, findingID)
}

// ExpandRepoFindingDeleteTargets returns the concrete repository finding rows a delete request can remove.
func (s *Service) ExpandRepoFindingDeleteTargets(ctx context.Context, targets []RepoFindingDeleteTarget) ([]RepoFindingDeleteTarget, error) {
	ctx = s.scopeContext(ctx)
	normalized, err := normalizeRepoFindingDeleteTargets(targets)
	if err != nil {
		return nil, err
	}
	storeTargets := make([]db.RepoFindingDeleteTarget, 0, len(normalized))
	for _, target := range normalized {
		storeTargets = append(storeTargets, db.RepoFindingDeleteTarget{
			RepoScanID: target.RepoScanID,
			FindingID:  target.FindingID,
		})
	}
	expandedTargets, err := s.Store.ExpandRepoFindingDeleteTargets(ctx, storeTargets)
	if err != nil {
		return nil, err
	}
	return repoFindingDeleteTargetsFromStore(expandedTargets), nil
}

// DeleteRepoFindings permanently removes selected repository findings.
func (s *Service) DeleteRepoFindings(ctx context.Context, targets []RepoFindingDeleteTarget, deleteTargetsOverride ...[]RepoFindingDeleteTarget) (RepoFindingsBulkDeleteResponse, error) {
	ctx = s.scopeContext(ctx)
	normalized, err := normalizeRepoFindingDeleteTargets(targets)
	if err != nil {
		return RepoFindingsBulkDeleteResponse{}, err
	}
	normalizedDeleteTargets := normalized
	if len(deleteTargetsOverride) > 0 {
		normalizedDeleteTargets, err = normalizeRepoFindingDeleteTargetsAllowEmpty(deleteTargetsOverride[0])
		if err != nil {
			return RepoFindingsBulkDeleteResponse{}, err
		}
	}
	deletedTargets := []db.RepoFindingDeleteTarget{}
	if len(normalizedDeleteTargets) > 0 {
		storeTargets := repoFindingDeleteTargetsToStore(normalizedDeleteTargets)
		deletedTargets, err = s.Store.DeleteRepoFindingTargets(ctx, storeTargets)
		if err != nil {
			return RepoFindingsBulkDeleteResponse{}, err
		}
	}
	deletedSet := make(map[string]struct{}, len(deletedTargets))
	for _, target := range deletedTargets {
		deletedSet[repoFindingDeleteTargetKey(target.RepoScanID, target.FindingID)] = struct{}{}
	}
	response := RepoFindingsBulkDeleteResponse{
		Deleted: []RepoFindingDeleteTarget{},
		Failed:  []RepoFindingDeleteFailure{},
	}
	for _, target := range normalized {
		if _, ok := deletedSet[repoFindingDeleteTargetKey(target.RepoScanID, target.FindingID)]; ok {
			response.Deleted = append(response.Deleted, target)
			continue
		}
		response.Failed = append(response.Failed, RepoFindingDeleteFailure{
			RepoFindingDeleteTarget: target,
			Error:                   "repo finding not found",
		})
	}
	return response, nil
}

func repoFindingDeleteTargetsToStore(targets []RepoFindingDeleteTarget) []db.RepoFindingDeleteTarget {
	storeTargets := make([]db.RepoFindingDeleteTarget, 0, len(targets))
	for _, target := range targets {
		storeTargets = append(storeTargets, db.RepoFindingDeleteTarget{
			RepoScanID: target.RepoScanID,
			FindingID:  target.FindingID,
		})
	}
	return storeTargets
}

func repoFindingDeleteTargetsFromStore(targets []db.RepoFindingDeleteTarget) []RepoFindingDeleteTarget {
	apiTargets := make([]RepoFindingDeleteTarget, 0, len(targets))
	seen := make(map[string]struct{}, len(targets))
	for _, target := range targets {
		repoScanID := strings.TrimSpace(target.RepoScanID)
		findingID := strings.TrimSpace(target.FindingID)
		if repoScanID == "" || findingID == "" {
			continue
		}
		key := repoFindingDeleteTargetKey(repoScanID, findingID)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		apiTargets = append(apiTargets, RepoFindingDeleteTarget{
			FindingID:  findingID,
			RepoScanID: repoScanID,
		})
	}
	return apiTargets
}

func mergeRepoFindingDeleteTargets(groups ...[]RepoFindingDeleteTarget) []RepoFindingDeleteTarget {
	merged := []RepoFindingDeleteTarget{}
	seen := map[string]struct{}{}
	for _, targets := range groups {
		for _, target := range targets {
			repoScanID := strings.TrimSpace(target.RepoScanID)
			findingID := strings.TrimSpace(target.FindingID)
			if repoScanID == "" || findingID == "" {
				continue
			}
			key := repoFindingDeleteTargetKey(repoScanID, findingID)
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			merged = append(merged, RepoFindingDeleteTarget{
				FindingID:  findingID,
				RepoScanID: repoScanID,
			})
		}
	}
	return merged
}

func repoFindingDeleteTargetKey(repoScanID string, findingID string) string {
	return strings.TrimSpace(repoScanID) + "::" + strings.TrimSpace(findingID)
}

func normalizeRepoFindingDeleteTargets(targets []RepoFindingDeleteTarget) ([]RepoFindingDeleteTarget, error) {
	if len(targets) == 0 || len(targets) > maxRepoFindingBulkDeleteItems {
		return nil, ErrInvalidRepoRemediationRequest
	}
	normalized := make([]RepoFindingDeleteTarget, 0, len(targets))
	seen := make(map[string]struct{}, len(targets))
	for _, target := range targets {
		findingID := strings.TrimSpace(target.FindingID)
		repoScanID := strings.TrimSpace(target.RepoScanID)
		if findingID == "" || repoScanID == "" {
			return nil, ErrInvalidRepoRemediationRequest
		}
		key := repoScanID + "::" + findingID
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		normalized = append(normalized, RepoFindingDeleteTarget{
			FindingID:  findingID,
			RepoScanID: repoScanID,
		})
	}
	if len(normalized) == 0 {
		return nil, ErrInvalidRepoRemediationRequest
	}
	return normalized, nil
}

func normalizeRepoFindingDeleteTargetsAllowEmpty(targets []RepoFindingDeleteTarget) ([]RepoFindingDeleteTarget, error) {
	if len(targets) == 0 {
		return []RepoFindingDeleteTarget{}, nil
	}
	normalized := make([]RepoFindingDeleteTarget, 0, len(targets))
	seen := make(map[string]struct{}, len(targets))
	for _, target := range targets {
		findingID := strings.TrimSpace(target.FindingID)
		repoScanID := strings.TrimSpace(target.RepoScanID)
		if findingID == "" || repoScanID == "" {
			return nil, ErrInvalidRepoRemediationRequest
		}
		key := repoScanID + "::" + findingID
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		normalized = append(normalized, RepoFindingDeleteTarget{
			FindingID:  findingID,
			RepoScanID: repoScanID,
		})
	}
	return normalized, nil
}

func (s *Service) listRepoFindingsWithPostTriageFilter(
	ctx context.Context,
	repoLimit int,
	requestLimit int,
	storeFilter db.RepoFindingFilter,
	postFilter db.RepoFindingFilter,
) ([]domain.Finding, error) {
	for {
		findings, err := s.Store.ListRepoFindings(ctx, storeFilter, repoLimit)
		if err != nil {
			return nil, err
		}

		findings = enrichFindingsWithRepoContext(findings)
		withTriage, err := s.applyRepoFindingTriageStates(ctx, findings)
		if err != nil {
			return nil, err
		}
		filtered := filterRepoFindingsByLifecycleAndTriage(withTriage, postFilter.Status, postFilter.LifecycleStatus, postFilter.Assignee)
		if len(filtered) > requestLimit {
			filtered = filtered[:requestLimit]
		}

		// Keep bounded reads while scanning until we find enough triaged rows for
		// the caller's requested window or we hit the safety cap.
		if len(filtered) >= requestLimit || len(findings) < repoLimit {
			return filtered, nil
		}
		if repoLimit >= repoFindingsTriageFilterCap {
			return filtered, nil
		}
		repoLimit *= 2
		if repoLimit > repoFindingsTriageFilterCap {
			repoLimit = repoFindingsTriageFilterCap
		}
	}
}

// ListRepoFindingClusters returns duplicate-aware repository finding clusters.
func (s *Service) ListRepoFindingClusters(ctx context.Context, limit int, filter RepoFindingClusterFilter) ([]domain.RepoFindingCluster, error) {
	ctx = s.scopeContext(ctx)
	sortBy := strings.TrimSpace(filter.SortBy)
	sortDesc := filter.SortDesc
	if sortBy == "" {
		sortDesc = true
	}
	items, err := s.Store.ListRepoFindingClusters(ctx, db.RepoFindingClusterListFilter{
		RepoScanID: filter.RepoScanID,
		Severity:   filter.Severity,
		Type:       filter.Type,
		SortBy:     sortBy,
		SortDesc:   sortDesc,
		Limit:      limit,
		Offset:     filter.Offset,
	})
	if err != nil {
		return nil, err
	}
	return enrichRepoFindingClusters(items), nil
}

// GetRepoRiskGraph returns the graph-backed machine-identity blast radius for repository findings.
func (s *Service) GetRepoRiskGraph(ctx context.Context, filter RepoRiskGraphFilter) (domain.RepoRiskGraph, error) {
	ctx = s.scopeContext(ctx)
	repository := strings.TrimSpace(filter.Repository)
	if repoScanID := strings.TrimSpace(filter.RepoScanID); repoScanID != "" {
		record, err := s.Store.GetRepoScan(ctx, repoScanID)
		if err != nil {
			return domain.RepoRiskGraph{}, err
		}
		if repository == "" {
			repository = strings.TrimSpace(record.Repository)
		}
	}

	findings, err := s.Store.ListRepoFindings(ctx, db.RepoFindingFilter{
		RepoScanID:    strings.TrimSpace(filter.RepoScanID),
		Repository:    repository,
		Severity:      strings.TrimSpace(filter.Severity),
		Type:          strings.TrimSpace(filter.Type),
		MinConfidence: filter.MinConfidence,
		SortBy:        "created_at",
		SortDesc:      true,
	}, 0)
	if err != nil {
		return domain.RepoRiskGraph{}, err
	}
	return domain.BuildRepoRiskGraph(enrichFindingsWithRepoContext(findings), domain.RepoRiskGraphOptions{
		Repository:    repository,
		DefaultBranch: strings.TrimSpace(filter.DefaultBranch),
		Now:           s.Now().UTC(),
	}), nil
}

// PreviewRepoFindingRemediation returns rule-specific remediation guidance for
// one repository finding. When source content is provided for a deterministic
// patchable detector, the response includes the exact fix-PR plan without
// publishing anything.
func (s *Service) PreviewRepoFindingRemediation(ctx context.Context, findingID string, request RepoFindingRemediationPreviewRequest) (RepoFindingRemediationPreview, error) {
	id := strings.TrimSpace(findingID)
	if id == "" {
		return RepoFindingRemediationPreview{}, db.ErrNotFound
	}
	request.RepoScanID = strings.TrimSpace(request.RepoScanID)
	finding, err := s.getRepoFindingForRemediation(ctx, id, request.RepoScanID)
	if err != nil {
		return RepoFindingRemediationPreview{}, err
	}
	domain.NormalizeRepoFindingMetadata(&finding)
	remediation, ok := standards.SuggestRepoExposureRemediation(finding)
	if !ok {
		return RepoFindingRemediationPreview{}, ErrUnsupportedRepoRemediation
	}

	responseFinding := finding
	if responseFinding.Type == domain.FindingSecretExposure {
		responseFinding.LineSnippet = ""
		redacted := true
		responseFinding.LineSnippetRedacted = &redacted
		if len(responseFinding.Evidence) > 0 {
			evidence := maps.Clone(responseFinding.Evidence)
			delete(evidence, "line_snippet")
			delete(evidence, "redacted_line_snip")
			delete(evidence, "match_snippet")
			evidence["line_snippet_redacted"] = true
			responseFinding.Evidence = evidence
		}
	}
	response := RepoFindingRemediationPreview{
		Finding:     responseFinding,
		Remediation: remediation,
	}

	sourceContentProvided := request.SourceContent != ""
	if !sourceContentProvided {
		if request.RequireFixPlan {
			return RepoFindingRemediationPreview{}, ErrInvalidRepoRemediationRequest
		}
		return response, nil
	}
	plan, _, err := fixpr.BuildRepoExposureFixPRPlan(finding, request.SourceContent, fixpr.PlanOptions{
		BaseBranch:   request.BaseBranch,
		BranchPrefix: request.BranchPrefix,
		FindingURL:   request.FindingURL,
	})
	if err != nil {
		if errors.Is(err, fixpr.ErrRepoExposureRemediationUnsupported) {
			return RepoFindingRemediationPreview{}, ErrUnsupportedRepoRemediation
		}
		if errors.Is(err, fixpr.ErrRepoExposureRemediationUnsafe) && !request.RequireFixPlan {
			return response, nil
		}
		return RepoFindingRemediationPreview{}, ErrInvalidRepoRemediationRequest
	}
	response.FixPRPlan = &plan
	return response, nil
}

// PublishRepoFindingRemediation publishes one deterministic repository
// remediation PR after explicit operator approval and write-credential
// confirmation. It reuses the same fix-plan builder as preview mode so stale
// source content, unsafe paths, placeholder patches, and secret findings fail
// closed before GitHub write APIs are called.
func (s *Service) PublishRepoFindingRemediation(ctx context.Context, findingID string, request RepoFindingRemediationPublishRequest) (RepoFindingRemediationPublishResponse, error) {
	id := strings.TrimSpace(findingID)
	if id == "" {
		return RepoFindingRemediationPublishResponse{}, db.ErrNotFound
	}
	request.RepoScanID = strings.TrimSpace(request.RepoScanID)
	finding, err := s.getRepoFindingForRemediation(ctx, id, request.RepoScanID)
	if err != nil {
		return RepoFindingRemediationPublishResponse{}, err
	}
	domain.NormalizeRepoFindingMetadata(&finding)
	owner, repo, ok := splitRepositoryOwnerName(finding.Repository)
	if !ok {
		return RepoFindingRemediationPublishResponse{}, ErrInvalidRepoRemediationRequest
	}

	publisher := s.RepoRemediationPublisher
	if publisher == nil {
		publisher = fixpr.GitHubPublisher{}
	}
	result, remediation, err := publisher.PublishRepoExposureRemediation(ctx, finding, fixpr.RepoExposurePublishOptions{
		Owner:         owner,
		Repo:          repo,
		Token:         request.GitHubToken,
		SourceContent: request.SourceContent,
		PlanOptions: fixpr.PlanOptions{
			BaseBranch:   request.BaseBranch,
			BranchPrefix: request.BranchPrefix,
			FindingURL:   request.FindingURL,
		},
		OperatorApproved:           request.OperatorApproved,
		WritePermissionsConfigured: request.WritePermissionsConfigured,
	})
	if err != nil {
		switch {
		case errors.Is(err, fixpr.ErrRepoExposureRemediationUnsupported):
			return RepoFindingRemediationPublishResponse{}, ErrUnsupportedRepoRemediation
		case errors.Is(err, fixpr.ErrRepoExposurePublishCredentialRejected):
			return RepoFindingRemediationPublishResponse{}, ErrRepoRemediationCredentialRejected
		case errors.Is(err, fixpr.ErrRepoExposurePublishApprovalRequired),
			errors.Is(err, fixpr.ErrRepoExposurePublishCredentialsMissing),
			errors.Is(err, fixpr.ErrRepoExposureSourceRequired),
			errors.Is(err, fixpr.ErrRepoExposurePatchApplyFailed),
			errors.Is(err, fixpr.ErrRepoExposureRemediationUnsafe):
			return RepoFindingRemediationPublishResponse{}, ErrInvalidRepoRemediationRequest
		default:
			return RepoFindingRemediationPublishResponse{}, err
		}
	}
	return RepoFindingRemediationPublishResponse{
		Finding:     finding,
		Remediation: remediation,
		Publish:     result,
	}, nil
}

func splitRepositoryOwnerName(repository string) (string, string, bool) {
	owner, name, ok := strings.Cut(strings.TrimSpace(repository), "/")
	owner = strings.TrimSpace(owner)
	name = strings.TrimSpace(name)
	return owner, name, ok && owner != "" && name != ""
}

func (s *Service) getRepoFindingForRemediation(ctx context.Context, findingID string, repoScanID string) (domain.Finding, error) {
	findings, err := s.ListRepoFindings(ctx, 1, db.RepoFindingFilter{
		FindingID:  strings.TrimSpace(findingID),
		RepoScanID: strings.TrimSpace(repoScanID),
	})
	if err != nil {
		return domain.Finding{}, err
	}
	if len(findings) == 0 {
		return domain.Finding{}, db.ErrNotFound
	}
	return findings[0], nil
}

// GetOrganization returns the current scoped organization record.
func (s *Service) GetOrganization(ctx context.Context) (db.TenancyOrganization, error) {
	ctx = s.scopeContext(ctx)
	return s.Store.GetOrganization(ctx)
}

// UpsertOrganization creates or updates the current scoped organization.
func (s *Service) UpsertOrganization(ctx context.Context, request OrganizationUpsertRequest) (db.TenancyOrganization, error) {
	ctx = s.scopeContext(ctx)
	scope, err := db.RequireScope(ctx)
	if err != nil {
		return db.TenancyOrganization{}, err
	}
	normalized, err := db.NormalizeTenancyOrganizationForWrite(db.TenancyOrganization{
		TenantID:    scope.TenantID,
		DisplayName: request.DisplayName,
		Slug:        request.Slug,
	})
	if err != nil {
		return db.TenancyOrganization{}, ErrInvalidTenancyRequest
	}
	if err := s.Store.UpsertOrganization(ctx, normalized); err != nil {
		return db.TenancyOrganization{}, err
	}
	return s.Store.GetOrganization(ctx)
}

// ListWorkspaces returns tenant-scoped workspaces.
func (s *Service) ListWorkspaces(ctx context.Context, limit int) ([]db.TenancyWorkspace, error) {
	ctx = s.scopeContext(ctx)
	return s.Store.ListWorkspaces(ctx, limit)
}

// UpsertWorkspace creates or updates one scoped workspace.
func (s *Service) UpsertWorkspace(ctx context.Context, request WorkspaceUpsertRequest) (db.TenancyWorkspace, error) {
	ctx = s.scopeContext(ctx)
	scope, err := db.RequireScope(ctx)
	if err != nil {
		return db.TenancyWorkspace{}, err
	}
	normalizedWorkspaceID, err := db.ResolveScopedWorkspaceID(scope, request.WorkspaceID)
	if err != nil {
		return db.TenancyWorkspace{}, err
	}
	normalized, err := db.NormalizeTenancyWorkspaceForWrite(db.TenancyWorkspace{
		TenantID:    scope.TenantID,
		WorkspaceID: normalizedWorkspaceID,
		DisplayName: request.DisplayName,
		Slug:        request.Slug,
	})
	if err != nil {
		return db.TenancyWorkspace{}, ErrInvalidTenancyRequest
	}
	if err := s.Store.UpsertWorkspace(ctx, normalized); err != nil {
		return db.TenancyWorkspace{}, err
	}
	return s.Store.GetWorkspace(ctx, normalized.WorkspaceID)
}

// GetWorkspace returns one workspace by id.
func (s *Service) GetWorkspace(ctx context.Context, workspaceID string) (db.TenancyWorkspace, error) {
	ctx = s.scopeContext(ctx)
	return s.Store.GetWorkspace(ctx, strings.TrimSpace(workspaceID))
}

// DeleteWorkspace removes one workspace.
func (s *Service) DeleteWorkspace(ctx context.Context, workspaceID string) error {
	ctx = s.scopeContext(ctx)
	return s.Store.DeleteWorkspace(ctx, strings.TrimSpace(workspaceID))
}

// WorkspaceSoleOwnerStranding is the structured result of the sole-owner
// guard. When StrandedMembers is non-empty the caller is the only active
// owner and there are other active members who would lose their access if
// the workspace were suspended or deleted.
type WorkspaceSoleOwnerStranding struct {
	Workspace       db.TenancyWorkspace
	StrandedMembers []db.TenancyWorkspaceMember
}

// SuspendWorkspace flips an active workspace into the suspended state.
// Refuses with ErrWorkspaceNotSuspendable when the workspace is already
// soft-deleted: otherwise a deleted→suspended→reactivated sequence could
// sneak past the cancel-deletion grace check and leave the row "active"
// with a non-NULL deleted_at scheduled for hard purge.
//
// callerUserUUID gates both the owner-role check and the sole-owner guard.
// Empty callers are refused: route-level owner claims are not enough for
// lifecycle writes without a verifiable workspace membership row.
func (s *Service) SuspendWorkspace(ctx context.Context, workspaceID string, callerUserUUID string) (WorkspaceSoleOwnerStranding, db.TenancyWorkspace, error) {
	ctx = s.scopeContext(ctx)
	normalizedWorkspaceID := strings.TrimSpace(workspaceID)
	if normalizedWorkspaceID == "" {
		return WorkspaceSoleOwnerStranding{}, db.TenancyWorkspace{}, ErrInvalidTenancyRequest
	}
	if err := s.requireWorkspaceOwner(ctx, normalizedWorkspaceID, callerUserUUID); err != nil {
		return WorkspaceSoleOwnerStranding{}, db.TenancyWorkspace{}, err
	}
	workspace, err := s.Store.GetWorkspace(ctx, normalizedWorkspaceID)
	if err != nil {
		return WorkspaceSoleOwnerStranding{}, db.TenancyWorkspace{}, err
	}
	if workspace.Status == db.WorkspaceStatusDeleted || workspace.DeletedAt != nil {
		return WorkspaceSoleOwnerStranding{}, db.TenancyWorkspace{}, ErrWorkspaceNotSuspendable
	}
	stranding, err := s.checkWorkspaceSoleOwnerStranding(ctx, normalizedWorkspaceID, callerUserUUID)
	if err != nil {
		return WorkspaceSoleOwnerStranding{}, db.TenancyWorkspace{}, err
	}
	if len(stranding.StrandedMembers) > 0 {
		return stranding, db.TenancyWorkspace{}, ErrWorkspaceSoleOwnerRequiresTransfer
	}
	saved, err := s.Store.SuspendWorkspace(ctx, normalizedWorkspaceID, s.now())
	if err != nil {
		if errors.Is(err, db.ErrConflict) {
			return WorkspaceSoleOwnerStranding{}, db.TenancyWorkspace{}, ErrWorkspaceNotSuspendable
		}
		return WorkspaceSoleOwnerStranding{}, db.TenancyWorkspace{}, err
	}
	return WorkspaceSoleOwnerStranding{}, saved, nil
}

// ReactivateWorkspace reverses a suspend. Refuses if the workspace is in
// the `deleted` state — that path must go through cancel-deletion so the
// 30-day grace window stays authoritative. An already-active workspace is
// a no-op (idempotent) success.
func (s *Service) ReactivateWorkspace(ctx context.Context, workspaceID string, callerUserUUID string) (db.TenancyWorkspace, error) {
	ctx = s.scopeContext(ctx)
	normalizedWorkspaceID := strings.TrimSpace(workspaceID)
	if normalizedWorkspaceID == "" {
		return db.TenancyWorkspace{}, ErrInvalidTenancyRequest
	}
	if err := s.requireWorkspaceOwner(ctx, normalizedWorkspaceID, callerUserUUID); err != nil {
		return db.TenancyWorkspace{}, err
	}
	workspace, err := s.Store.GetWorkspace(ctx, normalizedWorkspaceID)
	if err != nil {
		return db.TenancyWorkspace{}, err
	}
	switch workspace.Status {
	case db.WorkspaceStatusActive:
		return workspace, nil
	case db.WorkspaceStatusSuspended:
		// Fall through to the store transition below.
	default:
		// Deleted (or any unknown future status) cannot be reactivated;
		// the cancel-deletion route is the only legal revival path.
		return db.TenancyWorkspace{}, ErrWorkspaceNotReactivatable
	}
	saved, err := s.Store.ReactivateWorkspace(ctx, normalizedWorkspaceID, s.now())
	if err != nil {
		if errors.Is(err, db.ErrConflict) {
			return db.TenancyWorkspace{}, ErrWorkspaceNotReactivatable
		}
		return db.TenancyWorkspace{}, err
	}
	return saved, nil
}

// SoftDeleteWorkspace flips the workspace into the deleted state with a
// reversible grace window. Same sole-owner guard semantics as Suspend.
func (s *Service) SoftDeleteWorkspace(ctx context.Context, workspaceID string, callerUserUUID string) (WorkspaceSoleOwnerStranding, db.TenancyWorkspace, error) {
	ctx = s.scopeContext(ctx)
	normalizedWorkspaceID := strings.TrimSpace(workspaceID)
	if normalizedWorkspaceID == "" {
		return WorkspaceSoleOwnerStranding{}, db.TenancyWorkspace{}, ErrInvalidTenancyRequest
	}
	if err := s.requireWorkspaceOwner(ctx, normalizedWorkspaceID, callerUserUUID); err != nil {
		return WorkspaceSoleOwnerStranding{}, db.TenancyWorkspace{}, err
	}
	stranding, err := s.checkWorkspaceSoleOwnerStranding(ctx, normalizedWorkspaceID, callerUserUUID)
	if err != nil {
		return WorkspaceSoleOwnerStranding{}, db.TenancyWorkspace{}, err
	}
	if len(stranding.StrandedMembers) > 0 {
		return stranding, db.TenancyWorkspace{}, ErrWorkspaceSoleOwnerRequiresTransfer
	}
	saved, err := s.Store.SoftDeleteWorkspace(ctx, normalizedWorkspaceID, s.now())
	if err != nil {
		return WorkspaceSoleOwnerStranding{}, db.TenancyWorkspace{}, err
	}
	return WorkspaceSoleOwnerStranding{}, saved, nil
}

// CancelWorkspaceDeletion reverses a soft delete inside the grace window.
// Refuses with ErrWorkspaceDeletionGraceExpired once the worker is
// authoritative for the purge so a stale UI cannot resurrect a workspace
// the caller has already lost the option to keep.
func (s *Service) CancelWorkspaceDeletion(ctx context.Context, workspaceID string, callerUserUUID string) (db.TenancyWorkspace, error) {
	ctx = s.scopeContext(ctx)
	normalizedWorkspaceID := strings.TrimSpace(workspaceID)
	if normalizedWorkspaceID == "" {
		return db.TenancyWorkspace{}, ErrInvalidTenancyRequest
	}
	if err := s.requireWorkspaceOwner(ctx, normalizedWorkspaceID, callerUserUUID); err != nil {
		return db.TenancyWorkspace{}, err
	}
	workspace, err := s.Store.GetWorkspace(ctx, normalizedWorkspaceID)
	if err != nil {
		return db.TenancyWorkspace{}, err
	}
	if workspace.DeletedAt != nil && s.now().UTC().Sub(workspace.DeletedAt.UTC()) > db.WorkspaceDeletionGracePeriod {
		return db.TenancyWorkspace{}, ErrWorkspaceDeletionGraceExpired
	}
	if workspace.Status == db.WorkspaceStatusActive && workspace.DeletedAt == nil {
		return workspace, nil
	}
	if workspace.Status != db.WorkspaceStatusDeleted && workspace.DeletedAt == nil {
		return db.TenancyWorkspace{}, ErrWorkspaceDeletionNotPending
	}
	return s.Store.CancelWorkspaceDeletion(ctx, normalizedWorkspaceID, s.now())
}

// WorkspaceDeletionGraceDeadline returns the wall-clock deadline by which the
// hard-delete worker will purge the workspace. Returns the zero time when the
// workspace is not pending deletion.
func WorkspaceDeletionGraceDeadline(workspace db.TenancyWorkspace) time.Time {
	if workspace.DeletedAt == nil {
		return time.Time{}
	}
	return workspace.DeletedAt.UTC().Add(db.WorkspaceDeletionGracePeriod)
}

// requireWorkspaceOwner is the authoritative owner-only gate for workspace
// lifecycle endpoints. The authz route table restricts tenancy.owner to the
// role string "owner", but that string alone is forgeable by non-session
// principals carrying an owner claim. This service-level check is the
// authoritative gate: every caller must present a verifiable user UUID that
// resolves to an active owner membership row for the target workspace.
//
// Order is important — GetWorkspace runs first so a missing id returns
// ErrNotFound (404) rather than masquerading as an authorization failure,
// which would otherwise leak "you don't own this" for a workspace that
// does not exist.
func (s *Service) requireWorkspaceOwner(ctx context.Context, workspaceID string, callerUserUUID string) error {
	if _, err := s.Store.GetWorkspace(ctx, workspaceID); err != nil {
		return err
	}
	normalizedUUID := strings.TrimSpace(callerUserUUID)
	if normalizedUUID == "" {
		return ErrWorkspaceOwnerRequired
	}
	member, err := s.Store.GetWorkspaceMemberByUserUUID(ctx, workspaceID, normalizedUUID)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			return ErrWorkspaceOwnerRequired
		}
		return err
	}
	if member.Status != "active" || member.Role != "owner" {
		return ErrWorkspaceOwnerRequired
	}
	return nil
}

func (s *Service) checkWorkspaceSoleOwnerStranding(ctx context.Context, workspaceID string, callerUserUUID string) (WorkspaceSoleOwnerStranding, error) {
	workspace, err := s.Store.GetWorkspace(ctx, workspaceID)
	if err != nil {
		return WorkspaceSoleOwnerStranding{}, err
	}
	if strings.TrimSpace(callerUserUUID) == "" {
		return WorkspaceSoleOwnerStranding{Workspace: workspace}, nil
	}
	stranded, err := s.Store.ListWorkspaceStrandedActiveMembers(ctx, workspaceID, callerUserUUID)
	if err != nil {
		return WorkspaceSoleOwnerStranding{}, err
	}
	return WorkspaceSoleOwnerStranding{Workspace: workspace, StrandedMembers: stranded}, nil
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

// ListWorkspaceMembers returns members for one scoped workspace with optional role/status filters.
func (s *Service) ListWorkspaceMembers(
	ctx context.Context,
	workspaceID string,
	role string,
	status string,
	limit int,
) ([]db.TenancyWorkspaceMember, error) {
	ctx = s.scopeContext(ctx)
	loadLimit := limit
	if loadLimit <= 0 {
		loadLimit = 100
	}
	hasFilter := strings.TrimSpace(role) != "" || strings.TrimSpace(status) != ""
	if hasFilter && loadLimit < 5000 {
		loadLimit = 5000
	}
	items, err := s.Store.ListWorkspaceMembers(ctx, strings.TrimSpace(workspaceID), loadLimit)
	if err != nil {
		return nil, err
	}
	normalizedRole := strings.ToLower(strings.TrimSpace(role))
	normalizedStatus := strings.ToLower(strings.TrimSpace(status))
	filtered := make([]db.TenancyWorkspaceMember, 0, len(items))
	for _, item := range items {
		if normalizedRole != "" && strings.ToLower(strings.TrimSpace(item.Role)) != normalizedRole {
			continue
		}
		if normalizedStatus != "" && strings.ToLower(strings.TrimSpace(item.Status)) != normalizedStatus {
			continue
		}
		filtered = append(filtered, item)
		if limit > 0 && len(filtered) >= limit {
			break
		}
	}
	return filtered, nil
}

// UpsertWorkspaceMember creates or updates one scoped workspace member.
func (s *Service) UpsertWorkspaceMember(
	ctx context.Context,
	workspaceID string,
	request WorkspaceMemberUpsertRequest,
) (db.TenancyWorkspaceMember, error) {
	ctx = s.scopeContext(ctx)
	scope, err := db.RequireScope(ctx)
	if err != nil {
		return db.TenancyWorkspaceMember{}, err
	}
	normalizedWorkspaceID, err := db.ResolveScopedWorkspaceID(scope, workspaceID)
	if err != nil {
		return db.TenancyWorkspaceMember{}, err
	}
	normalized, err := db.NormalizeTenancyWorkspaceMemberForWrite(db.TenancyWorkspaceMember{
		TenantID:    scope.TenantID,
		WorkspaceID: normalizedWorkspaceID,
		MemberID:    request.MemberID,
		UserID:      request.UserID,
		Email:       request.Email,
		Role:        request.Role,
		Status:      request.Status,
	})
	if err != nil {
		return db.TenancyWorkspaceMember{}, ErrInvalidTenancyRequest
	}
	if err := s.Store.UpsertWorkspaceMember(ctx, normalized); err != nil {
		return db.TenancyWorkspaceMember{}, err
	}
	return s.Store.GetWorkspaceMember(ctx, normalized.WorkspaceID, normalized.MemberID)
}

// GetWorkspaceMember returns one scoped workspace member.
func (s *Service) GetWorkspaceMember(ctx context.Context, workspaceID string, memberID string) (db.TenancyWorkspaceMember, error) {
	ctx = s.scopeContext(ctx)
	return s.Store.GetWorkspaceMember(ctx, strings.TrimSpace(workspaceID), strings.TrimSpace(memberID))
}

// DeleteWorkspaceMember removes one scoped workspace member.
func (s *Service) DeleteWorkspaceMember(ctx context.Context, workspaceID string, memberID string) error {
	ctx = s.scopeContext(ctx)
	return s.Store.DeleteWorkspaceMember(ctx, strings.TrimSpace(workspaceID), strings.TrimSpace(memberID))
}

// ListProjects returns projects for one scoped workspace.
func (s *Service) ListProjects(ctx context.Context, workspaceID string, includeArchived bool, limit int) ([]db.TenancyProject, error) {
	ctx = s.scopeContext(ctx)
	return s.Store.ListProjects(ctx, strings.TrimSpace(workspaceID), includeArchived, limit)
}

// UpsertProject creates or updates one scoped project.
func (s *Service) UpsertProject(ctx context.Context, workspaceID string, request ProjectUpsertRequest) (db.TenancyProject, error) {
	ctx = s.scopeContext(ctx)
	scope, err := db.RequireScope(ctx)
	if err != nil {
		return db.TenancyProject{}, err
	}
	normalizedWorkspaceID, err := db.ResolveScopedWorkspaceID(scope, workspaceID)
	if err != nil {
		return db.TenancyProject{}, err
	}
	archivedAt, err := parseTenancyArchivedAt(request.ArchivedAt)
	if err != nil {
		return db.TenancyProject{}, err
	}
	normalized, err := db.NormalizeTenancyProjectForWrite(db.TenancyProject{
		TenantID:    scope.TenantID,
		WorkspaceID: normalizedWorkspaceID,
		ProjectID:   request.ProjectID,
		Name:        request.Name,
		Slug:        request.Slug,
		Description: request.Description,
		ArchivedAt:  archivedAt,
	})
	if err != nil {
		return db.TenancyProject{}, ErrInvalidTenancyRequest
	}
	if err := s.Store.UpsertProject(ctx, normalized); err != nil {
		return db.TenancyProject{}, err
	}
	return s.Store.GetProject(ctx, normalized.WorkspaceID, normalized.ProjectID)
}

// GetProject returns one scoped project by id.
func (s *Service) GetProject(ctx context.Context, workspaceID string, projectID string) (db.TenancyProject, error) {
	ctx = s.scopeContext(ctx)
	return s.Store.GetProject(ctx, strings.TrimSpace(workspaceID), strings.TrimSpace(projectID))
}

// DeleteProject removes one scoped project.
func (s *Service) DeleteProject(ctx context.Context, workspaceID string, projectID string) error {
	ctx = s.scopeContext(ctx)
	return s.Store.DeleteProject(ctx, strings.TrimSpace(workspaceID), strings.TrimSpace(projectID))
}

// ResolveWhoAmIContext returns scoped workspace context and caller membership details.
func (s *Service) ResolveWhoAmIContext(ctx context.Context, subject string) (WhoAmIContext, error) {
	ctx = s.scopeContext(ctx)
	scope, err := db.RequireScope(ctx)
	if err != nil {
		return WhoAmIContext{}, err
	}
	workspaces, err := s.Store.ListWorkspaces(ctx, maxCursorFetchLimit)
	if err != nil {
		return WhoAmIContext{}, err
	}
	normalizedSubject := strings.TrimSpace(subject)
	contexts := make([]WorkspaceContext, 0, len(workspaces))
	var activeWorkspace *WorkspaceContext
	for _, workspace := range workspaces {
		workspaceScope := db.WithScope(ctx, db.Scope{
			TenantID:    scope.TenantID,
			WorkspaceID: workspace.WorkspaceID,
		})
		member, memberFound, err := s.lookupWorkspaceMemberBySubject(workspaceScope, workspace.WorkspaceID, normalizedSubject)
		if err != nil {
			return WhoAmIContext{}, err
		}
		workspaceContext := WorkspaceContext{
			Workspace: workspace,
			IsActive:  workspace.WorkspaceID == scope.WorkspaceID,
		}
		if memberFound {
			workspaceContext.Member = &member
		}
		contexts = append(contexts, workspaceContext)
		if workspaceContext.IsActive {
			current := workspaceContext
			activeWorkspace = &current
		}
	}
	return WhoAmIContext{
		Scope:           scope,
		ActiveWorkspace: activeWorkspace,
		Workspaces:      contexts,
	}, nil
}

// ResolveActiveWorkspace validates access and returns the requested active workspace context.
func (s *Service) ResolveActiveWorkspace(ctx context.Context, subject string, workspaceID string) (WorkspaceContext, error) {
	ctx = s.scopeContext(ctx)
	scope, err := db.RequireScope(ctx)
	if err != nil {
		return WorkspaceContext{}, err
	}
	normalizedWorkspaceID := strings.TrimSpace(workspaceID)
	if normalizedWorkspaceID == "" {
		return WorkspaceContext{}, ErrInvalidTenancyRequest
	}
	workspaceScope := db.WithScope(ctx, db.Scope{
		TenantID:    scope.TenantID,
		WorkspaceID: normalizedWorkspaceID,
	})
	workspace, err := s.Store.GetWorkspace(workspaceScope, normalizedWorkspaceID)
	if err != nil {
		return WorkspaceContext{}, err
	}
	contextItem := WorkspaceContext{
		Workspace: workspace,
		IsActive:  true,
	}
	normalizedSubject := strings.TrimSpace(subject)
	if normalizedSubject == "" {
		return contextItem, nil
	}
	member, memberFound, err := s.lookupWorkspaceMemberBySubject(workspaceScope, normalizedWorkspaceID, normalizedSubject)
	if err != nil {
		return WorkspaceContext{}, err
	}
	if !memberFound {
		s.recordServiceAuthzDenial(ctx, "workspaces.active.switch", "workspace", normalizedWorkspaceID)
		return WorkspaceContext{}, ErrWorkspaceAccessDenied
	}
	if strings.ToLower(strings.TrimSpace(member.Status)) != "active" {
		s.recordServiceAuthzDenial(ctx, "workspaces.active.switch", "workspace", normalizedWorkspaceID)
		return WorkspaceContext{}, ErrWorkspaceAccessDenied
	}
	contextItem.Member = &member
	return contextItem, nil
}

// ListFindingsFiltered returns findings with optional scan/type/severity filters.
func (s *Service) ListFindingsFiltered(ctx context.Context, limit int, filter FindingsFilter) ([]domain.Finding, error) {
	ctx = s.scopeContext(ctx)
	sortBy := strings.TrimSpace(filter.SortBy)
	sortDesc := filter.SortDesc
	if sortBy == "" {
		sortDesc = true
	}
	items, err := s.Store.ListFindingsFiltered(ctx, db.FindingListFilter{
		ScanID:          filter.ScanID,
		FindingID:       filter.FindingID,
		Severity:        filter.Severity,
		Type:            filter.Type,
		LifecycleStatus: filter.LifecycleStatus,
		Assignee:        filter.Assignee,
		SortBy:          sortBy,
		SortDesc:        sortDesc,
		Limit:           limit,
		Offset:          filter.Offset,
		Now:             s.Now().UTC(),
	})
	if err != nil {
		return nil, err
	}
	if limit > 0 && len(items) > limit {
		items = items[:limit]
	}
	return enrichFindings(items), nil
}

// GetFinding returns one finding by id, optionally scoped to one scan.
func (s *Service) GetFinding(ctx context.Context, findingID string, scanID string) (domain.Finding, error) {
	ctx = s.scopeContext(ctx)
	id := strings.TrimSpace(findingID)
	if id == "" {
		return domain.Finding{}, db.ErrNotFound
	}
	item, err := s.Store.GetFinding(ctx, id, strings.TrimSpace(scanID))
	if err != nil {
		if !errors.Is(err, db.ErrNotFound) {
			return domain.Finding{}, err
		}
		fallback, fallbackErr := s.ListRepoFindings(ctx, maxCursorFetchLimit, db.RepoFindingFilter{
			FindingID:  id,
			RepoScanID: strings.TrimSpace(scanID),
		})
		if fallbackErr != nil {
			return domain.Finding{}, fallbackErr
		}
		if len(fallback) == 0 {
			return domain.Finding{}, db.ErrNotFound
		}
		return fallback[0], nil
	}
	enriched := enrichFindings([]domain.Finding{item})
	withTriage, err := s.applyFindingTriageStates(ctx, enriched)
	if err != nil {
		return domain.Finding{}, err
	}
	if len(withTriage) == 0 {
		return domain.Finding{}, db.ErrNotFound
	}
	return withTriage[0], nil
}

func filterRepoFindingsByLifecycleAndTriage(
	findings []domain.Finding,
	rawRepoStatus string,
	rawTriageStatus string,
	rawAssignee string,
) []domain.Finding {
	repoStatusFilter := domain.NormalizeRepoFindingLifecycleStatus(rawRepoStatus)
	triageStatusFilter := domain.FindingLifecycleStatus(strings.ToLower(strings.TrimSpace(rawTriageStatus)))
	assigneeFilter := strings.ToLower(strings.TrimSpace(rawAssignee))
	if repoStatusFilter == "" && triageStatusFilter == "" && assigneeFilter == "" {
		return findings
	}
	if strings.TrimSpace(rawRepoStatus) != "" && repoStatusFilter == "" {
		return nil
	}
	if triageStatusFilter != "" && !isValidFindingLifecycleStatus(triageStatusFilter) {
		return nil
	}
	filtered := make([]domain.Finding, 0, len(findings))
	for _, finding := range findings {
		repoStatus := finding.LifecycleStatus
		if repoStatus == "" {
			repoStatus = domain.RepoFindingLifecycleOpen
		}
		if repoStatusFilter != "" && repoStatus != repoStatusFilter {
			continue
		}
		triage := finding.Triage
		status := triage.Status
		if !isValidFindingLifecycleStatus(status) {
			status = domain.FindingLifecycleOpen
		}
		if triageStatusFilter != "" && status != triageStatusFilter {
			continue
		}
		if assigneeFilter != "" && strings.ToLower(strings.TrimSpace(triage.Assignee)) != assigneeFilter {
			continue
		}
		filtered = append(filtered, finding)
	}
	return filtered
}

func summarizeRepoFindings(findings []domain.Finding, now time.Time) RepoFindingsSummary {
	summary := RepoFindingsSummary{
		ByOwner:    map[string]int{},
		ByDetector: map[string]int{},
		BySeverity: map[string]int{},
	}
	var totalResolveSeconds float64
	for _, finding := range findings {
		status := finding.LifecycleStatus
		if status == "" {
			status = domain.RepoFindingLifecycleOpen
		}
		switch status {
		case domain.RepoFindingLifecycleFixed:
			summary.FixedCount++
			if finding.FirstSeenAt != nil && finding.FixedAt != nil && finding.FixedAt.After(*finding.FirstSeenAt) {
				totalResolveSeconds += finding.FixedAt.Sub(*finding.FirstSeenAt).Seconds()
				summary.MTTRReadyResolvedCount++
			}
		case domain.RepoFindingLifecycleReopened:
			summary.ReopenedCount++
			summary.TotalOpen++
		case domain.RepoFindingLifecycleSuppressed, domain.RepoFindingLifecycleRiskAccepted, domain.RepoFindingLifecycleFalsePositive:
			summary.SuppressedCount++
		default:
			summary.TotalOpen++
		}
		if status == domain.RepoFindingLifecycleOpen || status == domain.RepoFindingLifecycleReopened {
			firstSeen := finding.CreatedAt
			if finding.FirstSeenAt != nil {
				firstSeen = finding.FirstSeenAt.UTC()
			}
			if summary.OldestOpenFirstSeenAt == nil || firstSeen.Before(*summary.OldestOpenFirstSeenAt) {
				value := firstSeen.UTC()
				summary.OldestOpenFirstSeenAt = &value
			}
			if (finding.Severity == domain.SeverityHigh || finding.Severity == domain.SeverityCritical) &&
				!firstSeen.IsZero() &&
				now.Sub(firstSeen) >= repoFindingSLAHighCritical {
				summary.SLAAgedCount++
			}
		}
		owner := strings.TrimSpace(finding.Owner)
		if owner == "" {
			owner = "unassigned"
		}
		summary.ByOwner[owner]++
		detector := strings.TrimSpace(finding.Detector)
		if detector == "" {
			detector = "unknown"
		}
		summary.ByDetector[detector]++
		severity := strings.TrimSpace(string(finding.Severity))
		if severity == "" {
			severity = "unknown"
		}
		summary.BySeverity[severity]++
	}
	if summary.MTTRReadyResolvedCount > 0 {
		mean := totalResolveSeconds / float64(summary.MTTRReadyResolvedCount)
		summary.MeanTimeToResolveSeconds = &mean
	}
	return summary
}

// TriageFinding applies one workflow mutation and records audit history.
func (s *Service) TriageFinding(ctx context.Context, findingID string, scanID string, request FindingTriageRequest, actor string) (domain.Finding, error) {
	id := strings.TrimSpace(findingID)
	if id == "" {
		return domain.Finding{}, db.ErrNotFound
	}
	finding, err := s.GetFinding(ctx, id, scanID)
	if err != nil {
		return domain.Finding{}, err
	}
	if request.Status == nil && request.Assignee == nil && request.SuppressionExpiresAt == nil && strings.TrimSpace(request.Comment) == "" {
		return domain.Finding{}, ErrInvalidFindingTriageRequest
	}

	now := s.Now().UTC()
	stateKey := findingTriageStateKey(finding)
	currentState, err := s.Store.GetFindingTriageState(ctx, stateKey)
	if err != nil && !errors.Is(err, db.ErrNotFound) {
		return domain.Finding{}, err
	}
	if errors.Is(err, db.ErrNotFound) {
		currentState = db.FindingTriageState{
			FindingID: stateKey,
			Status:    domain.FindingLifecycleOpen,
		}
	}
	currentState = normalizeFindingTriageState(currentState, now)
	nextState := currentState
	changed := false

	if request.Status != nil {
		parsedStatus, parseErr := parseFindingLifecycleStatus(*request.Status)
		if parseErr != nil {
			return domain.Finding{}, parseErr
		}
		if nextState.Status != parsedStatus {
			changed = true
		}
		nextState.Status = parsedStatus
	}
	if request.Assignee != nil {
		nextAssignee := strings.TrimSpace(*request.Assignee)
		if nextState.Assignee != nextAssignee {
			changed = true
		}
		nextState.Assignee = nextAssignee
	}
	if request.SuppressionExpiresAt != nil {
		parsedExpiry, parseErr := parseSuppressionExpiry(*request.SuppressionExpiresAt, now)
		if parseErr != nil {
			return domain.Finding{}, parseErr
		}
		if !timePointersEqual(nextState.SuppressionExpiresAt, parsedExpiry) {
			changed = true
		}
		nextState.SuppressionExpiresAt = parsedExpiry
	}
	if nextState.Status != domain.FindingLifecycleSuppressed && nextState.SuppressionExpiresAt != nil {
		nextState.SuppressionExpiresAt = nil
		changed = true
	}
	comment := strings.TrimSpace(request.Comment)
	suppressionRequested := request.Status != nil && nextState.Status == domain.FindingLifecycleSuppressed
	enteringSuppression := currentState.Status != domain.FindingLifecycleSuppressed && nextState.Status == domain.FindingLifecycleSuppressed
	if (suppressionRequested || enteringSuppression) && comment == "" {
		return domain.Finding{}, ErrInvalidFindingTriageRequest
	}
	if nextState.Status == domain.FindingLifecycleSuppressed && nextState.SuppressionExpiresAt != nil && !nextState.SuppressionExpiresAt.After(now) {
		return domain.Finding{}, ErrInvalidFindingTriageRequest
	}
	if !changed && comment == "" {
		return domain.Finding{}, ErrInvalidFindingTriageRequest
	}

	nextState.FindingID = stateKey
	nextState.UpdatedAt = now
	nextState.UpdatedBy = normalizeActor(actor)
	if nextState.Status == "" {
		nextState.Status = domain.FindingLifecycleOpen
	}
	nextState.ResolvedAt = resolveResolvedAt(currentState, nextState, now)

	action := deriveFindingTriageAction(currentState, nextState, comment)
	if err := s.Store.ApplyFindingTriageTransition(ctx, nextState, db.FindingTriageEvent{
		FindingID:            stateKey,
		Action:               action,
		FromStatus:           currentState.Status,
		ToStatus:             nextState.Status,
		Assignee:             nextState.Assignee,
		SuppressionExpiresAt: nextState.SuppressionExpiresAt,
		Comment:              comment,
		Actor:                nextState.UpdatedBy,
		CreatedAt:            now,
	}); err != nil {
		return domain.Finding{}, err
	}

	return s.GetFinding(ctx, id, scanID)
}

// ListFindingTriageHistory returns triage actions newest-first for one finding.
func (s *Service) ListFindingTriageHistory(ctx context.Context, findingID string, scanID string, limit int) ([]db.FindingTriageEvent, error) {
	id := strings.TrimSpace(findingID)
	if id == "" {
		return nil, db.ErrNotFound
	}
	finding, err := s.GetFinding(ctx, id, scanID)
	if err != nil {
		return nil, err
	}
	return s.Store.ListFindingTriageEvents(ctx, findingTriageStateKey(finding), limit)
}

// GetFindingExports returns OCSF-aligned and ASFF payloads for one finding.
func (s *Service) GetFindingExports(ctx context.Context, findingID string, scanID string) (FindingExports, error) {
	finding, err := s.GetFinding(ctx, findingID, scanID)
	if err != nil {
		return FindingExports{}, err
	}
	return FindingExports{
		OCSF: standards.BuildOCSFAlignedExport(finding),
		ASFF: standards.BuildASFFExport(finding, "", "", ""),
	}, nil
}

// ListScans returns persisted scans.
func (s *Service) ListScans(ctx context.Context, limit int) ([]db.ScanRecord, error) {
	ctx = s.scopeContext(ctx)
	return s.Store.ListScans(ctx, limit)
}

// GetFindingsSummary returns grouped counts by severity and type.
func (s *Service) GetFindingsSummary(ctx context.Context, limit int) (FindingsSummary, error) {
	ctx = s.scopeContext(ctx)
	counts, err := s.Store.SummarizeFindings(ctx)
	if err != nil {
		return FindingsSummary{}, err
	}
	return FindingsSummary{
		Total:      counts.Total,
		BySeverity: counts.BySeverity,
		ByType:     counts.ByType,
	}, nil
}

// ListScanEvents returns recent scan events for one scan id.
func (s *Service) ListScanEvents(ctx context.Context, scanID string, limit int) ([]db.ScanEvent, error) {
	return s.ListScanEventsFiltered(ctx, scanID, "", limit)
}

// ListScanEventsFiltered returns recent scan events with optional level filtering.
func (s *Service) ListScanEventsFiltered(ctx context.Context, scanID string, level string, limit int) ([]db.ScanEvent, error) {
	ctx = s.scopeContext(ctx)
	events, err := s.Store.ListScanEvents(ctx, scanID, limit)
	if err != nil {
		return nil, err
	}
	normalizedLevel := strings.ToLower(strings.TrimSpace(level))
	if normalizedLevel == "" {
		return events, nil
	}
	result := make([]db.ScanEvent, 0, len(events))
	for _, event := range events {
		if strings.ToLower(strings.TrimSpace(event.Level)) != normalizedLevel {
			continue
		}
		result = append(result, event)
	}
	return result, nil
}

// ListIdentities returns identities for given filters, defaulting scan_id to latest scan.
func (s *Service) ListIdentities(ctx context.Context, scanID string, provider string, identityType string, namePrefix string, limit int) ([]domain.Identity, error) {
	ctx = s.scopeContext(ctx)
	normalizedScanID := scanID
	if normalizedScanID == "" {
		latest, err := s.latestScanID(ctx)
		if err != nil {
			return nil, err
		}
		normalizedScanID = latest
	}
	return s.Store.ListIdentities(ctx, db.IdentityFilter{
		ScanID:     normalizedScanID,
		Provider:   provider,
		Type:       identityType,
		NamePrefix: namePrefix,
	}, limit)
}

// ListRelationships returns relationships for given filters, defaulting scan_id to latest scan.
func (s *Service) ListRelationships(ctx context.Context, scanID string, relationshipType string, fromNodeID string, toNodeID string, limit int) ([]domain.Relationship, error) {
	ctx = s.scopeContext(ctx)
	normalizedScanID := scanID
	if normalizedScanID == "" {
		latest, err := s.latestScanID(ctx)
		if err != nil {
			return nil, err
		}
		normalizedScanID = latest
	}
	return s.Store.ListRelationships(ctx, db.RelationshipFilter{
		ScanID:     normalizedScanID,
		Type:       relationshipType,
		FromNodeID: fromNodeID,
		ToNodeID:   toNodeID,
	}, limit)
}

// GetFindingsTrend returns findings totals by severity across recent scans.
func (s *Service) GetFindingsTrend(ctx context.Context, points int) ([]TrendPoint, error) {
	return s.GetFindingsTrendFiltered(ctx, points, "", "")
}

// GetFindingsTrendFiltered returns findings trend with optional severity/type filters.
func (s *Service) GetFindingsTrendFiltered(ctx context.Context, points int, severity string, findingType string) ([]TrendPoint, error) {
	ctx = s.scopeContext(ctx)
	if points <= 0 {
		points = 10
	}
	scans, err := s.Store.ListScans(ctx, points)
	if err != nil {
		return nil, err
	}
	// Return oldest->newest for chart consumers.
	sort.Slice(scans, func(i, j int) bool { return scans[i].StartedAt.Before(scans[j].StartedAt) })
	scanIDs := make([]string, 0, len(scans))
	index := make(map[string]*TrendPoint, len(scans))
	result := make([]TrendPoint, 0, len(scans))
	for _, scan := range scans {
		scanIDs = append(scanIDs, scan.ID)
		result = append(result, TrendPoint{
			ScanID:     scan.ID,
			StartedAt:  scan.StartedAt,
			BySeverity: map[string]int{},
		})
		index[scan.ID] = &result[len(result)-1]
	}
	counts, err := s.Store.ListFindingTrendCounts(ctx, scanIDs, severity, findingType)
	if err != nil {
		return nil, err
	}
	for _, count := range counts {
		point := index[count.ScanID]
		if point == nil {
			continue
		}
		if strings.TrimSpace(count.Severity) != "" {
			point.BySeverity[count.Severity] += count.TotalCount
		}
		point.Total += count.TotalCount
	}
	return result, nil
}

// GetRepoFindingsTrend returns repository finding trend totals by repo scan.
func (s *Service) GetRepoFindingsTrend(ctx context.Context, points int) ([]TrendPoint, error) {
	return s.GetRepoFindingsTrendFiltered(ctx, points, "", "", 0)
}

// GetRepoFindingsTrendFiltered returns repository finding trend with optional severity/type filters.
func (s *Service) GetRepoFindingsTrendFiltered(ctx context.Context, points int, severity string, findingType string, minConfidence float64) ([]TrendPoint, error) {
	ctx = s.scopeContext(ctx)
	if points <= 0 {
		points = 10
	}

	repoScans, err := s.Store.ListRepoScans(ctx, points)
	if err != nil {
		return nil, err
	}

	sort.Slice(repoScans, func(i, j int) bool {
		return repoScans[i].StartedAt.Before(repoScans[j].StartedAt)
	})
	repoScanIDs := make([]string, 0, len(repoScans))
	index := make(map[string]*TrendPoint, len(repoScans))
	result := make([]TrendPoint, 0, len(repoScans))
	for _, scan := range repoScans {
		repoScanIDs = append(repoScanIDs, scan.ID)
		result = append(result, TrendPoint{
			ScanID:     scan.ID,
			StartedAt:  scan.StartedAt,
			BySeverity: map[string]int{},
		})
		index[scan.ID] = &result[len(result)-1]
	}

	counts, err := s.Store.ListRepoFindingTrendCounts(ctx, repoScanIDs, severity, findingType, minConfidence)
	if err != nil {
		return nil, err
	}
	for _, count := range counts {
		point := index[count.ScanID]
		if point == nil {
			continue
		}
		if strings.TrimSpace(count.Severity) != "" {
			point.BySeverity[count.Severity] += count.TotalCount
		}
		point.Total += count.TotalCount
	}

	return result, nil
}

// ListOwnershipSignals returns inferred ownership hints for identities in one scan.
func (s *Service) ListOwnershipSignals(ctx context.Context, limit int, filter OwnershipFilter) ([]domain.OwnershipSignal, error) {
	ctx = s.scopeContext(ctx)
	normalizedScanID := strings.TrimSpace(filter.ScanID)
	if normalizedScanID == "" {
		latest, err := s.latestScanID(ctx)
		if err != nil {
			return nil, err
		}
		normalizedScanID = latest
	}
	loadLimit := limit
	if loadLimit <= 0 {
		loadLimit = 100
	}
	if loadLimit > 5000 {
		loadLimit = 5000
	}
	identities, err := s.Store.ListIdentities(ctx, db.IdentityFilter{ScanID: normalizedScanID}, loadLimit)
	if err != nil {
		return nil, err
	}
	signals := make([]domain.OwnershipSignal, 0, len(identities))
	for _, identity := range identities {
		signal, ok := inferOwnershipSignal(identity)
		if !ok {
			continue
		}
		signals = append(signals, signal)
	}
	sort.Slice(signals, func(i, j int) bool {
		if signals[i].Confidence == signals[j].Confidence {
			return signals[i].IdentityID < signals[j].IdentityID
		}
		return signals[i].Confidence > signals[j].Confidence
	})
	if limit > 0 && len(signals) > limit {
		signals = signals[:limit]
	}
	return signals, nil
}

// GetScanDiff compares findings between this scan and previous scan of same provider.
func (s *Service) GetScanDiff(ctx context.Context, scanID string, limit int) (ScanDiff, error) {
	return s.GetScanDiffAgainst(ctx, scanID, "", limit)
}

// GetScanDiffAgainst compares findings between one scan and an optional baseline scan.
func (s *Service) GetScanDiffAgainst(ctx context.Context, scanID string, previousScanID string, limit int) (ScanDiff, error) {
	ctx = s.scopeContext(ctx)
	currentScan, err := s.Store.GetScan(ctx, scanID)
	if err != nil {
		return ScanDiff{}, err
	}

	currentMetas, err := s.Store.ListFindingMetasByScan(ctx, scanID)
	if err != nil {
		return ScanDiff{}, err
	}
	normalizedPreviousScanID := strings.TrimSpace(previousScanID)
	if normalizedPreviousScanID != "" {
		if normalizedPreviousScanID == currentScan.ID {
			return ScanDiff{}, ErrInvalidScanDiffBaseline
		}
		baselineScan, err := s.Store.GetScan(ctx, normalizedPreviousScanID)
		if err != nil {
			return ScanDiff{}, err
		}
		if baselineScan.Provider != currentScan.Provider {
			return ScanDiff{}, ErrInvalidScanDiffBaseline
		}
		if !baselineScan.StartedAt.Before(currentScan.StartedAt) {
			return ScanDiff{}, ErrInvalidScanDiffBaseline
		}
	} else {
		scans, err := s.Store.ListScans(ctx, 500)
		if err != nil {
			return ScanDiff{}, err
		}
		for _, scan := range scans {
			if scan.ID == currentScan.ID || scan.Provider != currentScan.Provider {
				continue
			}
			if scan.StartedAt.Before(currentScan.StartedAt) {
				normalizedPreviousScanID = scan.ID
				break
			}
		}
	}

	diff := ScanDiff{ScanID: scanID, PreviousScanID: normalizedPreviousScanID}
	currentByID := map[string]db.FindingMeta{}
	for _, finding := range currentMetas {
		currentByID[finding.ID] = finding
	}
	if normalizedPreviousScanID == "" {
		diff.AddedCount = len(currentMetas)
		addedIDs := limitFindingIDsByMeta(currentMetas, limit)
		diff.Added, err = s.findingsForDiffIDs(ctx, scanID, addedIDs)
		if err != nil {
			return ScanDiff{}, err
		}
		diff.applyLimit(limit)
		return diff, nil
	}

	previousMetas, err := s.Store.ListFindingMetasByScan(ctx, normalizedPreviousScanID)
	if err != nil {
		return ScanDiff{}, err
	}
	previousByID := map[string]db.FindingMeta{}
	for _, finding := range previousMetas {
		previousByID[finding.ID] = finding
	}

	added := make([]db.FindingMeta, 0)
	persisting := make([]db.FindingMeta, 0)
	resolved := make([]db.FindingMeta, 0)
	for id, finding := range currentByID {
		if _, exists := previousByID[id]; exists {
			persisting = append(persisting, finding)
			continue
		}
		added = append(added, finding)
	}
	for id, finding := range previousByID {
		if _, exists := currentByID[id]; exists {
			continue
		}
		resolved = append(resolved, finding)
	}
	sortFindingMetas(added)
	sortFindingMetas(resolved)
	sortFindingMetas(persisting)
	diff.AddedCount = len(added)
	diff.ResolvedCount = len(resolved)
	diff.PersistingCount = len(persisting)
	diff.Added, err = s.findingsForDiffIDs(ctx, scanID, limitFindingIDsByMeta(added, limit))
	if err != nil {
		return ScanDiff{}, err
	}
	diff.Resolved, err = s.findingsForDiffIDs(ctx, normalizedPreviousScanID, limitFindingIDsByMeta(resolved, limit))
	if err != nil {
		return ScanDiff{}, err
	}
	diff.Persisting, err = s.findingsForDiffIDs(ctx, scanID, limitFindingIDsByMeta(persisting, limit))
	if err != nil {
		return ScanDiff{}, err
	}
	diff.applyLimit(limit)
	return diff, nil
}

func sortFindingMetas(items []db.FindingMeta) {
	sort.Slice(items, func(i, j int) bool {
		if items[i].CreatedAt.Equal(items[j].CreatedAt) {
			return items[i].ID < items[j].ID
		}
		return items[i].CreatedAt.After(items[j].CreatedAt)
	})
}

func limitFindingIDsByMeta(items []db.FindingMeta, limit int) []string {
	if limit > 0 && len(items) > limit {
		items = items[:limit]
	}
	ids := make([]string, 0, len(items))
	for _, item := range items {
		ids = append(ids, item.ID)
	}
	return ids
}

func (s *Service) findingsForDiffIDs(ctx context.Context, scanID string, findingIDs []string) ([]domain.Finding, error) {
	if len(findingIDs) == 0 {
		return []domain.Finding{}, nil
	}
	items, err := s.Store.ListFindingsByScanAndIDs(s.scopeContext(ctx), scanID, findingIDs)
	if err != nil {
		return nil, err
	}
	enriched := enrichFindings(items)
	withTriage, err := s.applyFindingTriageStates(ctx, enriched)
	if err != nil {
		return nil, err
	}
	byID := make(map[string]domain.Finding, len(withTriage))
	for _, item := range withTriage {
		byID[item.ID] = item
	}
	ordered := make([]domain.Finding, 0, len(findingIDs))
	for _, findingID := range findingIDs {
		item, exists := byID[findingID]
		if !exists {
			continue
		}
		ordered = append(ordered, item)
	}
	return ordered, nil
}

func (s *Service) appendScanEvent(ctx context.Context, scanID string, level string, message string, metadata map[string]any) {
	ctx = s.scopeContext(ctx)
	_ = s.Store.AppendScanEvent(ctx, scanID, level, message, metadata)
}

func (s *Service) appendScanLifecycleEvent(ctx context.Context, scanID string, state string, metadata map[string]any) {
	payload := map[string]any{"state": state}
	for key, value := range metadata {
		payload[key] = value
	}
	s.appendScanEvent(ctx, scanID, db.ScanEventLevelInfo, "scan lifecycle transition", payload)
}

func (d *ScanDiff) applyLimit(limit int) {
	if limit <= 0 {
		return
	}
	if len(d.Added) > limit {
		d.Added = d.Added[:limit]
	}
	if len(d.Resolved) > limit {
		d.Resolved = d.Resolved[:limit]
	}
	if len(d.Persisting) > limit {
		d.Persisting = d.Persisting[:limit]
	}
}

func (s *Service) latestScanID(ctx context.Context) (string, error) {
	ctx = s.scopeContext(ctx)
	scans, err := s.Store.ListScans(ctx, 1)
	if err != nil {
		return "", err
	}
	if len(scans) == 0 {
		return "", db.ErrNotFound
	}
	return scans[0].ID, nil
}

func sanitizeRepoScanLimit(candidate int, fallback int, maxAllowed int) (int, error) {
	if fallback <= 0 {
		fallback = 1
	}
	if maxAllowed <= 0 {
		maxAllowed = fallback
	}
	if candidate < 0 {
		return 0, ErrInvalidRepoScanRequest
	}
	if candidate == 0 {
		candidate = fallback
	}
	if candidate > maxAllowed {
		return 0, ErrInvalidRepoScanRequest
	}
	return candidate, nil
}

func enrichFindings(findings []domain.Finding) []domain.Finding {
	return enrichFindingsWithRepoContext(findings)
}

func enrichFindingsWithRepoContext(findings []domain.Finding, repositoryHints ...string) []domain.Finding {
	if len(findings) == 0 {
		return findings
	}
	defaultRepository := ""
	for _, hint := range repositoryHints {
		if trimmed := strings.TrimSpace(hint); trimmed != "" {
			defaultRepository = trimmed
			break
		}
	}
	enriched := make([]domain.Finding, 0, len(findings))
	for _, finding := range findings {
		if finding.Repository == "" && defaultRepository != "" {
			finding.Repository = defaultRepository
		}
		domain.NormalizeRepoFindingMetadata(&finding)
		if finding.SourceURL == "" {
			finding.SourceURL = repoFindingSourceURL(finding.Repository, finding.Commit, finding.FilePath, finding.LineNumber)
		}
		finding.ConfidenceScore = scoreFindingConfidence(finding)
		enriched = append(enriched, standards.EnrichFinding(finding))
	}
	return enriched
}

func enrichRepoFindingClusters(clusters []domain.RepoFindingCluster) []domain.RepoFindingCluster {
	if len(clusters) == 0 {
		return clusters
	}
	enriched := make([]domain.RepoFindingCluster, 0, len(clusters))
	for _, cluster := range clusters {
		copyCluster := cluster
		if len(cluster.Members) > 0 {
			copyCluster.Members = make([]domain.RepoFindingClusterMember, 0, len(cluster.Members))
			for _, member := range cluster.Members {
				copyMember := member
				if copyMember.SourceURL == "" {
					copyMember.SourceURL = repoFindingSourceURL(copyMember.Repository, copyMember.Commit, copyMember.FilePath, copyMember.LineNumber)
				}
				copyCluster.Members = append(copyCluster.Members, copyMember)
			}
		}
		enriched = append(enriched, copyCluster)
	}
	return enriched
}

func repoFindingSourceURL(repository string, commit string, filePath string, lineNumber int) string {
	if lineNumber < 1 {
		return ""
	}
	normalizedRepository := normalizeGitHubRepositoryPath(repository)
	normalizedCommit := strings.TrimSpace(commit)
	normalizedFilePath := strings.Trim(strings.TrimSpace(filePath), "/")
	if normalizedRepository == "" || normalizedCommit == "" || normalizedFilePath == "" {
		return ""
	}
	blobURL := url.URL{
		Scheme: "https",
		Host:   "github.com",
		Path:   "/" + path.Join(normalizedRepository, "blob", normalizedCommit, normalizedFilePath),
	}
	return fmt.Sprintf("%s#L%d", blobURL.String(), lineNumber)
}

func normalizeGitHubRepositoryPath(repository string) string {
	trimmed := strings.TrimSpace(repository)
	if trimmed == "" {
		return ""
	}
	if strings.Count(trimmed, "/") == 1 &&
		!strings.HasPrefix(trimmed, "/") &&
		!strings.HasPrefix(trimmed, ".") &&
		!strings.HasPrefix(trimmed, "~") &&
		!strings.Contains(trimmed, "\\") &&
		!strings.Contains(trimmed, "://") &&
		!strings.HasPrefix(strings.ToLower(trimmed), "git@") {
		return canonicalGitHubRepositoryPath(trimmed)
	}

	if strings.HasPrefix(strings.ToLower(trimmed), "git@") {
		parts := strings.SplitN(trimmed, ":", 2)
		if len(parts) != 2 {
			return ""
		}
		host := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(parts[0])), "git@")
		if host != "github.com" && host != "www.github.com" {
			return ""
		}
		return canonicalGitHubRepositoryPath(parts[1])
	}

	parsed, err := url.Parse(trimmed)
	if err != nil {
		return ""
	}
	host := strings.ToLower(parsed.Hostname())
	if host != "github.com" && host != "www.github.com" {
		return ""
	}
	return canonicalGitHubRepositoryPath(parsed.Path)
}

func canonicalGitHubRepositoryPath(raw string) string {
	normalized := strings.Trim(strings.TrimSpace(raw), "/")
	normalized = strings.TrimSuffix(normalized, ".git")
	parts := strings.Split(normalized, "/")
	if len(parts) != 2 {
		return ""
	}
	if strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
		return ""
	}
	return strings.TrimSpace(parts[0]) + "/" + strings.TrimSpace(parts[1])
}

func (s *Service) applyFindingTriageStates(ctx context.Context, findings []domain.Finding) ([]domain.Finding, error) {
	if len(findings) == 0 {
		return findings, nil
	}
	ids := make([]string, 0, len(findings))
	seen := map[string]struct{}{}
	for _, finding := range findings {
		id := findingTriageStateKey(finding)
		if id == "" {
			continue
		}
		if _, exists := seen[id]; exists {
			continue
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	states, err := s.Store.ListFindingTriageStates(ctx, ids)
	if err != nil {
		return nil, err
	}
	byID := map[string]db.FindingTriageState{}
	now := s.Now().UTC()
	for _, state := range states {
		normalized := normalizeFindingTriageState(state, now)
		byID[normalized.FindingID] = normalized
	}
	result := make([]domain.Finding, 0, len(findings))
	for _, finding := range findings {
		triage := domain.DefaultFindingTriage()
		if state, exists := byID[findingTriageStateKey(finding)]; exists {
			updatedAt := state.UpdatedAt.UTC()
			triage = domain.FindingTriage{
				Status:               state.Status,
				Assignee:             state.Assignee,
				SuppressionExpiresAt: state.SuppressionExpiresAt,
				ResolvedAt:           state.ResolvedAt,
				UpdatedAt:            &updatedAt,
				UpdatedBy:            state.UpdatedBy,
			}
		}
		finding.Triage = triage
		result = append(result, finding)
	}
	return result, nil
}

func (s *Service) applyRepoFindingTriageStates(ctx context.Context, findings []domain.Finding) ([]domain.Finding, error) {
	withTriage, err := s.applyFindingTriageStates(ctx, findings)
	if err != nil {
		return nil, err
	}
	for i := range withTriage {
		domain.ApplyRepoFindingTriageToLifecycle(&withTriage[i])
	}
	return withTriage, nil
}

const repoFindingTriageStatePrefix = "repo-finding-triage"

func findingTriageStateKey(finding domain.Finding) string {
	id := strings.TrimSpace(finding.ID)
	if id == "" {
		return ""
	}
	if !isRepoFinding(finding) {
		return id
	}
	scanID := strings.TrimSpace(finding.ScanID)
	if scanID == "" {
		return id
	}
	return repoFindingTriageStatePrefix + "|" + scanID + "|" + id
}

func isRepoFinding(finding domain.Finding) bool {
	return strings.TrimSpace(finding.Repository) != "" ||
		strings.TrimSpace(finding.Commit) != "" ||
		strings.TrimSpace(finding.FilePath) != "" ||
		strings.TrimSpace(finding.SourceURL) != ""
}

func normalizeFindingTriageState(state db.FindingTriageState, now time.Time) db.FindingTriageState {
	if state.Status == "" {
		state.Status = domain.FindingLifecycleOpen
	}
	if !isValidFindingLifecycleStatus(state.Status) {
		state.Status = domain.FindingLifecycleOpen
	}
	if state.Status == domain.FindingLifecycleSuppressed && state.SuppressionExpiresAt != nil && !state.SuppressionExpiresAt.After(now) {
		state.Status = domain.FindingLifecycleOpen
		state.SuppressionExpiresAt = nil
	}
	if state.Status != domain.FindingLifecycleSuppressed {
		state.SuppressionExpiresAt = nil
	}
	if state.Status != domain.FindingLifecycleResolved {
		state.ResolvedAt = nil
	}
	return state
}

// resolveResolvedAt computes the resolution timestamp for the next triage
// state. It is set only when a finding transitions into the resolved state;
// while a finding stays resolved (e.g. an assignee or comment edit) the
// original resolution time is preserved, and any non-resolved state clears it
// so reopened findings never report a stale MTTR source.
func resolveResolvedAt(current, next db.FindingTriageState, now time.Time) *time.Time {
	if next.Status != domain.FindingLifecycleResolved {
		return nil
	}
	if current.Status == domain.FindingLifecycleResolved && current.ResolvedAt != nil {
		preserved := current.ResolvedAt.UTC()
		return &preserved
	}
	resolved := now.UTC()
	return &resolved
}

func parseFindingLifecycleStatus(raw string) (domain.FindingLifecycleStatus, error) {
	status := domain.FindingLifecycleStatus(strings.ToLower(strings.TrimSpace(raw)))
	if !isValidFindingLifecycleStatus(status) {
		return "", ErrInvalidFindingTriageRequest
	}
	return status, nil
}

func isValidFindingLifecycleStatus(status domain.FindingLifecycleStatus) bool {
	switch status {
	case domain.FindingLifecycleOpen, domain.FindingLifecycleAck, domain.FindingLifecycleSuppressed, domain.FindingLifecycleResolved:
		return true
	default:
		return false
	}
}

func parseSuppressionExpiry(raw string, now time.Time) (*time.Time, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return nil, nil
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return nil, ErrInvalidFindingTriageRequest
	}
	normalized := parsed.UTC()
	if !normalized.After(now) {
		return nil, ErrInvalidFindingTriageRequest
	}
	return &normalized, nil
}

func parseTenancyArchivedAt(raw *string) (*time.Time, error) {
	if raw == nil {
		return nil, nil
	}
	value := strings.TrimSpace(*raw)
	if value == "" {
		return nil, nil
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return nil, ErrInvalidTenancyRequest
	}
	normalized := parsed.UTC()
	return &normalized, nil
}

func timePointersEqual(a *time.Time, b *time.Time) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return a.UTC().Equal(b.UTC())
}

func normalizeActor(actor string) string {
	normalized := strings.TrimSpace(actor)
	if normalized == "" {
		return "unknown"
	}
	return normalized
}

func deriveFindingTriageAction(current db.FindingTriageState, next db.FindingTriageState, comment string) string {
	if current.Status != next.Status {
		switch next.Status {
		case domain.FindingLifecycleAck:
			return db.FindingTriageActionAcknowledged
		case domain.FindingLifecycleSuppressed:
			return db.FindingTriageActionSuppressed
		case domain.FindingLifecycleResolved:
			return db.FindingTriageActionResolved
		case domain.FindingLifecycleOpen:
			return db.FindingTriageActionReopened
		}
	}
	if current.Assignee != next.Assignee {
		return db.FindingTriageActionAssigned
	}
	if !timePointersEqual(current.SuppressionExpiresAt, next.SuppressionExpiresAt) {
		return db.FindingTriageActionSuppression
	}
	if strings.TrimSpace(comment) != "" {
		return db.FindingTriageActionCommented
	}
	return db.FindingTriageActionCommented
}

func truncateSourceErrors(errors []providers.SourceError, max int) []providers.SourceError {
	if len(errors) == 0 {
		return nil
	}
	if max <= 0 || len(errors) <= max {
		return append([]providers.SourceError(nil), errors...)
	}
	return append([]providers.SourceError(nil), errors[:max]...)
}

func repoTargetAllowed(target string, allowlist []string) bool {
	return repoallowlist.TargetAllowed(target, allowlist, false)
}

func inferOwnershipSignal(identity domain.Identity) (domain.OwnershipSignal, bool) {
	ownerHint := strings.TrimSpace(identity.OwnerHint)
	if ownerHint != "" {
		return domain.OwnershipSignal{
			ID:         "ownership:" + identity.ID,
			IdentityID: identity.ID,
			Team:       ownerHint,
			Source:     "owner_hint",
			Confidence: 0.9,
		}, true
	}

	tags := identity.Tags
	team := firstNonEmptyTag(tags, "team", "owner", "team_name")
	repository := firstNonEmptyTag(tags, "repository", "repo", "service_repo")
	if team == "" && repository == "" {
		return domain.OwnershipSignal{}, false
	}
	confidence := 0.65
	source := "tags"
	if team != "" {
		confidence = 0.8
		source = "tags.team"
	}
	if team != "" && repository != "" {
		confidence = 0.85
		source = "tags.team+repository"
	}
	if team == "" && repository != "" {
		confidence = 0.75
		source = "tags.repository"
	}
	return domain.OwnershipSignal{
		ID:         "ownership:" + identity.ID,
		IdentityID: identity.ID,
		Team:       team,
		Repository: repository,
		Source:     source,
		Confidence: confidence,
	}, true
}

func (s *Service) lookupWorkspaceMemberBySubject(
	ctx context.Context,
	workspaceID string,
	subject string,
) (db.TenancyWorkspaceMember, bool, error) {
	normalizedSubject := strings.TrimSpace(subject)
	if normalizedSubject == "" {
		return db.TenancyWorkspaceMember{}, false, nil
	}
	if _, err := uuid.Parse(normalizedSubject); err == nil {
		member, err := s.Store.GetWorkspaceMemberByUserUUID(ctx, workspaceID, normalizedSubject)
		if err != nil && !errors.Is(err, db.ErrNotFound) {
			return db.TenancyWorkspaceMember{}, false, err
		}
		if err == nil {
			if strings.ToLower(strings.TrimSpace(member.Status)) == "active" {
				return member, true, nil
			}
			return member, true, nil
		}
	}
	members, err := s.ListWorkspaceMembers(ctx, workspaceID, "", "", maxCursorFetchLimit)
	if err != nil {
		return db.TenancyWorkspaceMember{}, false, err
	}
	var fallback db.TenancyWorkspaceMember
	fallbackSet := false
	for _, member := range members {
		if strings.TrimSpace(member.UserID) != normalizedSubject {
			continue
		}
		if strings.ToLower(strings.TrimSpace(member.Status)) == "active" {
			return member, true, nil
		}
		if !fallbackSet {
			fallback = member
			fallbackSet = true
		}
	}
	if fallbackSet {
		return fallback, true, nil
	}
	return db.TenancyWorkspaceMember{}, false, nil
}

func firstNonEmptyTag(tags map[string]string, keys ...string) string {
	for _, key := range keys {
		value := strings.TrimSpace(tags[key])
		if value != "" {
			return value
		}
	}
	return ""
}

func (s *Service) lockKey(key string) string {
	normalizedKey := strings.TrimSpace(key)
	namespace := strings.TrimSpace(s.LockNamespace)
	if namespace == "" {
		return normalizedKey
	}
	if normalizedKey == "" {
		return namespace
	}
	return namespace + ":" + normalizedKey
}

func (s *Service) scopeContext(ctx context.Context) context.Context {
	return db.WithDefaultScope(ctx, s.DefaultScope)
}

func withQueueTraceContext(ctx context.Context) context.Context {
	carrier := propagation.MapCarrier{}
	queueTracePropagator.Inject(ctx, carrier)
	traceParent := strings.TrimSpace(carrier.Get("traceparent"))
	traceState := strings.TrimSpace(carrier.Get("tracestate"))
	if traceParent == "" && traceState == "" {
		return ctx
	}
	return db.WithQueueTraceContext(ctx, traceParent, traceState)
}

func continueQueueTraceContext(ctx context.Context, traceParent string, traceState string) context.Context {
	traceParent = strings.TrimSpace(traceParent)
	traceState = strings.TrimSpace(traceState)
	if traceParent == "" && traceState == "" {
		return ctx
	}
	carrier := propagation.MapCarrier{}
	if traceParent != "" {
		carrier.Set("traceparent", traceParent)
	}
	if traceState != "" {
		carrier.Set("tracestate", traceState)
	}
	return queueTracePropagator.Extract(ctx, carrier)
}

func (s *Service) terminalWriteContext(ctx context.Context) context.Context {
	return db.WithScope(context.Background(), db.ScopeFromContext(s.scopeContext(ctx)))
}

// skipScanIfWorkspaceInactive enforces the workspace lifecycle pause on
// scans claimed from the queue. The scheduler already filters out
// inactive workspaces when enqueuing new scheduled scans, and the route
// table refuses ad-hoc POST /v1/scans for inactive workspaces, but a
// scan that was queued BEFORE the suspend/soft-delete will still surface
// here because ClaimNextQueuedScanAnyScope filters only on scan status.
// Mark it terminal with a clear error so it does not retry forever; the
// workspace owner can requeue after reactivate/cancel-deletion.
//
// Returns (true, nil) when the scan was skipped, (false, nil) when the
// workspace is active and the scan should proceed.
func (s *Service) skipScanIfWorkspaceInactive(ctx context.Context, record db.ScanRecord) (bool, error) {
	workspaceID := strings.TrimSpace(record.WorkspaceID)
	tenantID := strings.TrimSpace(record.TenantID)
	if workspaceID == "" || tenantID == "" {
		return false, nil
	}
	workspace, err := s.Store.GetWorkspace(ctx, workspaceID)
	if err != nil {
		// A missing workspace is a different failure mode — let the
		// regular scan executor surface it rather than silently
		// skipping a record whose tenant scope might be misconfigured.
		if errors.Is(err, db.ErrNotFound) {
			return false, nil
		}
		return false, fmt.Errorf("workspace lifecycle gate: %w", err)
	}
	if workspace.Status == db.WorkspaceStatusActive && workspace.DeletedAt == nil {
		return false, nil
	}
	reason := fmt.Sprintf("workspace lifecycle is %s; scan refused (see #1420)", workspace.Status)
	s.appendScanLifecycleEvent(ctx, record.ID, scanLifecycleFailed, map[string]any{
		"provider":         record.Provider,
		"reason":           "workspace_inactive",
		"workspace_status": workspace.Status,
	})
	s.appendScanEvent(ctx, record.ID, db.ScanEventLevelWarn, reason, map[string]any{
		"workspace_status": workspace.Status,
	})
	if err := s.completeScanTerminal(ctx, record.ID, scanLifecycleFailed, s.Now().UTC(), 0, 0, reason); err != nil {
		return false, fmt.Errorf("mark scan failed for inactive workspace: %w", err)
	}
	return true, nil
}

// skipRepoScanIfWorkspaceInactive mirrors skipScanIfWorkspaceInactive
// for the repo-scan queue. ClaimNextQueuedRepoScanAnyScope filters only
// on repo_scans.status='queued', so a record queued before the
// workspace was suspended/soft-deleted will still surface to the
// worker; without this gate runRepoScanWithRecord would execute that
// scan against an inactive workspace, contradicting the lifecycle
// pause contract (codex round 8 on PR #1445).
//
// Marks the claimed record terminal-failed with a workspace_lifecycle
// reason so it does not retry forever; the workspace owner can requeue
// after reactivate/cancel-deletion.
func (s *Service) skipRepoScanIfWorkspaceInactive(ctx context.Context, record db.RepoScanRecord) (bool, error) {
	workspaceID := strings.TrimSpace(record.WorkspaceID)
	tenantID := strings.TrimSpace(record.TenantID)
	if workspaceID == "" || tenantID == "" {
		return false, nil
	}
	workspace, err := s.Store.GetWorkspace(ctx, workspaceID)
	if err != nil {
		// A missing workspace is a different failure mode — let the
		// regular repo-scan executor surface it rather than silently
		// skipping a record whose tenant scope might be misconfigured.
		if errors.Is(err, db.ErrNotFound) {
			return false, nil
		}
		return false, fmt.Errorf("repo scan workspace lifecycle gate: %w", err)
	}
	if workspace.Status == db.WorkspaceStatusActive && workspace.DeletedAt == nil {
		return false, nil
	}
	reason := fmt.Sprintf("workspace lifecycle is %s; repo scan refused (see #1420)", workspace.Status)
	if err := s.completeRepoScanTerminal(ctx, record.ID, "failed", s.Now().UTC(), 0, 0, 0, false, db.RepoScanContext{}, reason); err != nil {
		return false, fmt.Errorf("mark repo scan failed for inactive workspace: %w", err)
	}
	return true, nil
}

func (s *Service) completeScanTerminal(
	ctx context.Context,
	scanID string,
	status string,
	finishedAt time.Time,
	assetCount int,
	findingCount int,
	errorMessage string,
) error {
	writeCtx := ctx
	if shouldRetryTerminalWrite(ctx.Err()) {
		writeCtx = s.terminalWriteContext(ctx)
	}
	err := s.Store.CompleteScan(writeCtx, scanID, status, finishedAt, assetCount, findingCount, errorMessage)
	if !shouldRetryTerminalWrite(err) {
		return err
	}
	return s.Store.CompleteScan(s.terminalWriteContext(ctx), scanID, status, finishedAt, assetCount, findingCount, errorMessage)
}

func (s *Service) scheduleScanRetry(
	ctx context.Context,
	scanID string,
	queuedAt time.Time,
	retryCount int,
	maxRetryCount int,
	failureCategory string,
	errorMessage string,
	nextRetryAt time.Time,
) error {
	writeCtx := ctx
	if shouldRetryTerminalWrite(ctx.Err()) {
		writeCtx = s.terminalWriteContext(ctx)
	}
	err := s.Store.ScheduleScanRetry(writeCtx, scanID, queuedAt, retryCount, maxRetryCount, failureCategory, errorMessage, nextRetryAt)
	if !shouldRetryTerminalWrite(err) {
		return err
	}
	return s.Store.ScheduleScanRetry(s.terminalWriteContext(ctx), scanID, queuedAt, retryCount, maxRetryCount, failureCategory, errorMessage, nextRetryAt)
}

func (s *Service) deadLetterQueuedScan(
	ctx context.Context,
	scanID string,
	finishedAt time.Time,
	retryCount int,
	maxRetryCount int,
	assetCount int,
	findingCount int,
	failureCategory string,
	errorMessage string,
) error {
	writeCtx := ctx
	if shouldRetryTerminalWrite(ctx.Err()) {
		writeCtx = s.terminalWriteContext(ctx)
	}
	err := s.Store.DeadLetterScan(writeCtx, scanID, finishedAt, retryCount, maxRetryCount, assetCount, findingCount, failureCategory, errorMessage)
	if !shouldRetryTerminalWrite(err) {
		return err
	}
	return s.Store.DeadLetterScan(s.terminalWriteContext(ctx), scanID, finishedAt, retryCount, maxRetryCount, assetCount, findingCount, failureCategory, errorMessage)
}

func (s *Service) completeRepoScanTerminal(
	ctx context.Context,
	repoScanID string,
	status string,
	finishedAt time.Time,
	commitsScanned int,
	filesScanned int,
	findingCount int,
	truncated bool,
	scanContext db.RepoScanContext,
	errorMessage string,
) error {
	writeCtx := ctx
	if shouldRetryTerminalWrite(ctx.Err()) {
		writeCtx = s.terminalWriteContext(ctx)
	}
	err := s.Store.CompleteRepoScan(
		writeCtx,
		repoScanID,
		status,
		finishedAt,
		commitsScanned,
		filesScanned,
		findingCount,
		truncated,
		scanContext,
		errorMessage,
	)
	if errors.Is(err, db.ErrConflict) {
		return err
	}
	if !shouldRetryTerminalWrite(err) {
		return err
	}
	err = s.Store.CompleteRepoScan(
		s.terminalWriteContext(ctx),
		repoScanID,
		status,
		finishedAt,
		commitsScanned,
		filesScanned,
		findingCount,
		truncated,
		scanContext,
		errorMessage,
	)
	if errors.Is(err, db.ErrConflict) {
		return err
	}
	return err
}

func shouldRetryTerminalWrite(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}
