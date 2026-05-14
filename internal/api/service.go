package api

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/identrail/identrail/internal/app"
	"github.com/identrail/identrail/internal/audit"
	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/domain"
	"github.com/identrail/identrail/internal/findings/standards"
	"github.com/identrail/identrail/internal/providers"
	"github.com/identrail/identrail/internal/repoallowlist"
	"github.com/identrail/identrail/internal/repoexposure"
	"github.com/identrail/identrail/internal/scheduler"
	"github.com/identrail/identrail/internal/secretstore"
	"github.com/identrail/identrail/internal/telemetry"
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
	defaultGitHubWebhookReplayWindow = 24 * time.Hour
	defaultGitHubWebhookBurstWindow  = 30 * time.Second
	maxSourceErrorsInEvent           = 25
	repoFindingsTriageFilterStep     = maxCursorFetchLimit
	repoFindingsTriageFilterCap      = maxCursorFetchLimit * 4
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

// RepoScannerFactory creates a repository scanner with bounded scan parameters.
type RepoScannerFactory func(historyLimit int, maxFindings int) RepoScanExecutor

// AWSScannerFactory creates a scanner bound to one persisted AWS connector.
type AWSScannerFactory func(ctx context.Context, connection AWSConnectionStatus) (ScannerRunner, error)

type queuedScanDepthCounter interface {
	CountQueuedScansAnyScope(ctx context.Context, provider string) (int, error)
}

type queuedRepoScanDepthCounter interface {
	CountQueuedRepoScansAnyScope(ctx context.Context) (int, error)
}

// Service orchestrates scan execution and persistence.
type Service struct {
	Store          db.Store
	Scanner        ScannerRunner
	Provider       string
	DefaultScope   db.Scope
	Now            func() time.Time
	Locker         scheduler.Locker
	LockNamespace  string
	Alerter        FindingAlerter
	OnAlertError   func(error)
	ReadinessCheck func(context.Context) error
	Metrics        *telemetry.Metrics
	// Repo scan controls are intentionally separate from cloud identity scan flow.
	RepoScanEnabled              bool
	RepoScanDefaultHistoryLimit  int
	RepoScanDefaultMaxFindings   int
	RepoScanMaxHistoryLimit      int
	RepoScanMaxFindingsLimit     int
	RepoScanAllowedTargets       []string
	ScanQueueMaxPending          int
	RepoQueueMaxPending          int
	RepoScannerFactory           RepoScannerFactory
	ConnectorSecretManager       *secretstore.Manager
	KubernetesPreflightFactory   KubernetesConnectorPreflightFactory
	AWSConnectorValidator        AWSConnectorValidator
	AWSScannerFactory            AWSScannerFactory
	AWSCloudFormationTemplateURL string
	AWSAccountID                 string
	GitHubAppID                  int64
	GitHubAppName                string
	GitHubAppPrivateKey          string
	GitHubAppWebhookSecret       string
	GitHubPATValidator           GitHubPATValidator
	GitHubRepositoryLister       GitHubRepositoryLister
	GitHubWebhookReplayWindow    time.Duration
	GitHubWebhookBurstWindow     time.Duration
	githubConnectMu              sync.RWMutex
	githubConnections            map[string]githubProjectConnection
	githubConnectStates          map[string]githubConnectState
	githubWebhookSeen            map[string]time.Time
	githubWebhookLastQueued      map[string]time.Time
	kubernetesConnectMu          sync.RWMutex
	kubernetesConnections        map[string]kubernetesProjectConnection
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
	Repository   string `json:"repository"`
	HistoryLimit int    `json:"history_limit"`
	MaxFindings  int    `json:"max_findings"`
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

// ErrScanInProgress is returned when a scan for the same provider is already running.
var ErrScanInProgress = errors.New("scan already in progress")

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

// ErrRepoScanInProgress is returned when the same repository scan target is already running.
var ErrRepoScanInProgress = errors.New("repo scan already in progress")

// ErrInvalidFindingTriageRequest indicates invalid triage payload or state transition.
var ErrInvalidFindingTriageRequest = errors.New("invalid finding triage request")

// ErrRepoScanQueueFull is returned when queued repo scan requests exceed configured capacity.
var ErrRepoScanQueueFull = errors.New("repo scan queue is full")

// ErrInvalidTenancyRequest indicates invalid tenancy write payload.
var ErrInvalidTenancyRequest = errors.New("invalid tenancy request")

// ErrWorkspaceAccessDenied indicates the caller cannot switch to target workspace.
var ErrWorkspaceAccessDenied = errors.New("workspace access denied")

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
	}
	svc.hydrateGitHubConnections(context.Background())
	return svc
}

// EnqueueScan stores one queued scan request for asynchronous worker execution.
func (s *Service) EnqueueScan(ctx context.Context) (db.ScanRecord, error) {
	ctx = s.scopeContext(ctx)
	ctx = withQueueTraceContext(ctx)
	maxPending := s.ScanQueueMaxPending
	if maxPending <= 0 {
		maxPending = 1
	}

	var (
		record db.ScanRecord
		err    error
	)
	if maxPending == 1 {
		record, err = s.Store.CreateQueuedScanIfNoPending(ctx, s.Provider, s.Now().UTC())
		if errors.Is(err, db.ErrPendingScanExists) {
			return db.ScanRecord{}, ErrScanInProgress
		}
	} else {
		record, err = s.Store.CreateQueuedScanWithinLimit(ctx, s.Provider, s.Now().UTC(), maxPending)
		if errors.Is(err, db.ErrQueueLimitReached) {
			return db.ScanRecord{}, ErrScanQueueFull
		}
	}
	if err != nil {
		return db.ScanRecord{}, fmt.Errorf("enqueue scan: %w", err)
	}
	queuedCount := s.countQueuedScansForDepth(ctx, s.Provider)
	s.appendScanLifecycleEvent(ctx, record.ID, scanLifecycleQueued, map[string]any{"provider": s.Provider})
	s.recordQueueDepth("scan", queuedCount)
	s.appendScanEvent(ctx, record.ID, db.ScanEventLevelInfo, "scan queued for worker execution", map[string]any{
		"provider":    s.Provider,
		"queue_depth": queuedCount,
		"queue_limit": maxPending,
	})
	return record, nil
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
	if maxPending == 1 {
		replay, err = s.Store.CreateQueuedScanIfNoPending(ctx, source.Provider, s.Now().UTC())
		if errors.Is(err, db.ErrPendingScanExists) {
			return db.ScanRecord{}, ErrScanInProgress
		}
	} else {
		replay, err = s.Store.CreateQueuedScanWithinLimit(ctx, source.Provider, s.Now().UTC(), maxPending)
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
	connection, ok, err := s.activeAWSConnectionForScan(ctx)
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

func (s *Service) activeAWSConnectionForScan(ctx context.Context) (AWSConnectionStatus, bool, error) {
	items, err := s.Store.ListTenancyConnectors(ctx, "", "", domain.ConnectorTypeAWS, 25)
	if err != nil {
		return AWSConnectionStatus{}, false, fmt.Errorf("list aws connectors: %w", err)
	}
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
	case "succeeded":
		return "succeeded"
	case "failed":
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
	target, historyLimit, maxFindings, err := s.validateRepoScanRequest(ctx, request)
	if err != nil {
		return db.RepoScanRecord{}, err
	}
	maxPending := s.RepoQueueMaxPending
	if maxPending <= 0 {
		maxPending = defaultRepoQueueMaxPending
	}
	record, err := s.Store.CreateQueuedRepoScanWithinLimit(ctx, target, historyLimit, maxFindings, s.Now().UTC(), maxPending)
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

// ProcessNextQueuedRepoScan claims and executes one queued repository scan. It returns false when no job is available.
func (s *Service) ProcessNextQueuedRepoScan(ctx context.Context) (bool, error) {
	ctx = s.scopeContext(ctx)
	record, err := s.Store.ClaimNextQueuedRepoScanAnyScope(ctx)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			s.recordQueueDepth("repo_scan", 0)
			return false, nil
		}
		s.recordWorkerJob("repo_scan", "failure")
		return false, fmt.Errorf("claim queued repo scan: %w", err)
	}
	recordScopeCtx := db.WithScope(ctx, db.Scope{
		TenantID:    record.TenantID,
		WorkspaceID: record.WorkspaceID,
	})
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
		// A queued item was handled (requeued) even if this target is currently locked.
		// Returning true lets the worker keep draining other queued targets in the same tick.
		return true, nil
	}
	_, runErr := s.runRepoScanWithRecord(recordScopeCtx, record, record.HistoryLimit, record.MaxFindings)
	if runErr != nil {
		s.recordAutomationRun("api_queue", "repo_scan", "failed")
		s.recordWorkerJob("repo_scan", "failure")
		s.recordWorkerDeadLetter("repo_scan")
		return true, runErr
	}
	s.recordAutomationRun("api_queue", "repo_scan", "succeeded")
	s.recordWorkerJob("repo_scan", "success")
	return true, nil
}

// RunRepoScanPersisted runs one repository scan and persists repo scan metadata + findings.
func (s *Service) RunRepoScanPersisted(ctx context.Context, request RepoScanRequest) (RunRepoScanResult, error) {
	ctx = s.scopeContext(ctx)
	target, historyLimit, maxFindings, err := s.validateRepoScanRequest(ctx, request)
	if err != nil {
		return RunRepoScanResult{}, err
	}
	if s.Locker != nil {
		release, ok := s.Locker.TryAcquire(ctx, s.lockKey("repo-scan:"+strings.ToLower(target)))
		if !ok {
			return RunRepoScanResult{}, ErrRepoScanInProgress
		}
		defer release(context.Background())
	}
	record, err := s.Store.CreateRepoScan(ctx, target, s.Now().UTC())
	if err != nil {
		return RunRepoScanResult{}, fmt.Errorf("create repo scan: %w", err)
	}
	return s.runRepoScanWithRecord(ctx, record, historyLimit, maxFindings)
}

func (s *Service) validateRepoScanRequest(ctx context.Context, request RepoScanRequest) (string, int, int, error) {
	if !s.RepoScanEnabled {
		return "", 0, 0, ErrRepoScanDisabled
	}
	target := strings.TrimSpace(request.Repository)
	if target == "" {
		return "", 0, 0, ErrInvalidRepoScanRequest
	}
	if repoTargetContainsURLCredentials(target) {
		return "", 0, 0, repoScanRequestValidationError{"repository target must not include credentials in URL userinfo"}
	}
	if repoexposure.IsLocalRepositoryTarget(target) {
		s.recordServiceAuthzDenial(ctx, "repo_scans.run", "repo_scan_target", target)
		return "", 0, 0, ErrRepoTargetNotAllowed
	}
	if !repoTargetAllowed(target, s.RepoScanAllowedTargets) {
		s.recordServiceAuthzDenial(ctx, "repo_scans.run", "repo_scan_target", target)
		return "", 0, 0, ErrRepoTargetNotAllowed
	}
	historyLimit, err := sanitizeRepoScanLimit(request.HistoryLimit, s.RepoScanDefaultHistoryLimit, s.RepoScanMaxHistoryLimit)
	if err != nil {
		return "", 0, 0, ErrInvalidRepoScanRequest
	}
	maxFindings, err := sanitizeRepoScanLimit(request.MaxFindings, s.RepoScanDefaultMaxFindings, s.RepoScanMaxFindingsLimit)
	if err != nil {
		return "", 0, 0, ErrInvalidRepoScanRequest
	}
	return target, historyLimit, maxFindings, nil
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
	normalizedHistory, err := sanitizeRepoScanLimit(historyLimit, s.RepoScanDefaultHistoryLimit, s.RepoScanMaxHistoryLimit)
	if err != nil {
		s.recordRepoScanExecutionFailure()
		_ = s.completeRepoScanTerminal(ctx, record.ID, "failed", s.Now().UTC(), 0, 0, 0, false, ErrInvalidRepoScanRequest.Error())
		return RunRepoScanResult{}, ErrInvalidRepoScanRequest
	}
	normalizedMaxFindings, err := sanitizeRepoScanLimit(maxFindings, s.RepoScanDefaultMaxFindings, s.RepoScanMaxFindingsLimit)
	if err != nil {
		s.recordRepoScanExecutionFailure()
		_ = s.completeRepoScanTerminal(ctx, record.ID, "failed", s.Now().UTC(), 0, 0, 0, false, ErrInvalidRepoScanRequest.Error())
		return RunRepoScanResult{}, ErrInvalidRepoScanRequest
	}
	if s.RepoScannerFactory == nil {
		s.recordRepoScanExecutionFailure()
		return RunRepoScanResult{}, fmt.Errorf("repo scanner factory is not configured")
	}
	result, err := s.RepoScannerFactory(normalizedHistory, normalizedMaxFindings).ScanRepository(ctx, target)
	if err != nil {
		s.recordRepoScanExecutionFailure()
		_ = s.completeRepoScanTerminal(ctx, record.ID, "failed", s.Now().UTC(), 0, 0, 0, false, err.Error())
		return RunRepoScanResult{}, err
	}
	result.Findings = enrichFindingsWithRepoContext(result.Findings, result.Repository, record.Repository)
	if err := s.Store.UpsertRepoFindings(ctx, record.ID, result.Findings); err != nil {
		s.recordRepoScanExecutionFailure()
		_ = s.completeRepoScanTerminal(ctx, record.ID, "failed", s.Now().UTC(), result.CommitsScanned, result.FilesScanned, 0, result.Truncated, err.Error())
		return RunRepoScanResult{}, fmt.Errorf("persist repo findings: %w", err)
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
		"",
	); err != nil {
		s.recordRepoScanExecutionFailure()
		return RunRepoScanResult{}, fmt.Errorf("complete repo scan: %w", err)
	}
	record.Status = "succeeded"
	finished := s.Now().UTC()
	record.FinishedAt = &finished
	record.CommitsScanned = result.CommitsScanned
	record.FilesScanned = result.FilesScanned
	record.FindingCount = len(result.Findings)
	record.Truncated = result.Truncated
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

// ListRepoFindings returns repository findings using optional filters.
func (s *Service) ListRepoFindings(ctx context.Context, limit int, filter db.RepoFindingFilter) ([]domain.Finding, error) {
	ctx = s.scopeContext(ctx)
	normalized := db.NormalizeRepoFindingFilter(filter)
	hasTriageFilter := normalized.LifecycleStatus != "" || normalized.Assignee != ""
	requestLimit := limit
	if requestLimit <= 0 {
		requestLimit = defaultFindingsLimit
	}
	repoLimit := requestLimit
	if hasTriageFilter && repoLimit < repoFindingsTriageFilterStep {
		repoLimit = repoFindingsTriageFilterStep
	}

	if hasTriageFilter {
		return s.listRepoFindingsWithTriageFilter(ctx, repoLimit, requestLimit, normalized)
	}

	findings, err := s.Store.ListRepoFindings(ctx, normalized, repoLimit)
	if err != nil {
		return nil, err
	}
	findings = enrichFindingsWithRepoContext(findings)
	withTriage, err := s.applyFindingTriageStates(ctx, findings)
	if err != nil {
		return nil, err
	}
	if normalized.LifecycleStatus == "" && normalized.Assignee == "" {
		return withTriage, nil
	}
	filtered := filterRepoFindingsByTriage(withTriage, normalized.LifecycleStatus, normalized.Assignee)
	if len(filtered) > requestLimit {
		filtered = filtered[:requestLimit]
	}
	return filtered, nil
}

func (s *Service) listRepoFindingsWithTriageFilter(
	ctx context.Context,
	repoLimit int,
	requestLimit int,
	filter db.RepoFindingFilter,
) ([]domain.Finding, error) {
	for {
		findings, err := s.Store.ListRepoFindings(ctx, filter, repoLimit)
		if err != nil {
			return nil, err
		}

		findings = enrichFindingsWithRepoContext(findings)
		withTriage, err := s.applyFindingTriageStates(ctx, findings)
		if err != nil {
			return nil, err
		}
		filtered := filterRepoFindingsByTriage(withTriage, filter.LifecycleStatus, filter.Assignee)
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

func filterRepoFindingsByTriage(
	findings []domain.Finding,
	rawStatus string,
	rawAssignee string,
) []domain.Finding {
	statusFilter := domain.FindingLifecycleStatus(strings.ToLower(strings.TrimSpace(rawStatus)))
	assigneeFilter := strings.ToLower(strings.TrimSpace(rawAssignee))
	if statusFilter == "" && assigneeFilter == "" {
		return findings
	}
	if statusFilter != "" && !isValidFindingLifecycleStatus(statusFilter) {
		return nil
	}
	filtered := make([]domain.Finding, 0, len(findings))
	for _, finding := range findings {
		triage := finding.Triage
		status := triage.Status
		if !isValidFindingLifecycleStatus(status) {
			status = domain.FindingLifecycleOpen
		}
		if statusFilter != "" && status != statusFilter {
			continue
		}
		if assigneeFilter != "" && strings.ToLower(strings.TrimSpace(triage.Assignee)) != assigneeFilter {
			continue
		}
		filtered = append(filtered, finding)
	}
	return filtered
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
	if nextState.Status == domain.FindingLifecycleSuppressed && nextState.SuppressionExpiresAt == nil {
		return domain.Finding{}, ErrInvalidFindingTriageRequest
	}
	if nextState.Status == domain.FindingLifecycleSuppressed && nextState.SuppressionExpiresAt != nil && !nextState.SuppressionExpiresAt.After(now) {
		return domain.Finding{}, ErrInvalidFindingTriageRequest
	}
	comment := strings.TrimSpace(request.Comment)
	if !changed && comment == "" {
		return domain.Finding{}, ErrInvalidFindingTriageRequest
	}

	nextState.FindingID = stateKey
	nextState.UpdatedAt = now
	nextState.UpdatedBy = normalizeActor(actor)
	if nextState.Status == "" {
		nextState.Status = domain.FindingLifecycleOpen
	}

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
	return s.GetRepoFindingsTrendFiltered(ctx, points, "", "")
}

// GetRepoFindingsTrendFiltered returns repository finding trend with optional severity/type filters.
func (s *Service) GetRepoFindingsTrendFiltered(ctx context.Context, points int, severity string, findingType string) ([]TrendPoint, error) {
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

	counts, err := s.Store.ListRepoFindingTrendCounts(ctx, repoScanIDs, severity, findingType)
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
				UpdatedAt:            &updatedAt,
				UpdatedBy:            state.UpdatedBy,
			}
		}
		finding.Triage = triage
		result = append(result, finding)
	}
	return result, nil
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
	return state
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
		errorMessage,
	)
	if !shouldRetryTerminalWrite(err) {
		return err
	}
	return s.Store.CompleteRepoScan(
		s.terminalWriteContext(ctx),
		repoScanID,
		status,
		finishedAt,
		commitsScanned,
		filesScanned,
		findingCount,
		truncated,
		errorMessage,
	)
}

func shouldRetryTerminalWrite(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}
