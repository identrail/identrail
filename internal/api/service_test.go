package api

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/app"
	githubconnector "github.com/identrail/identrail/internal/connectors/github"
	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/domain"
	"github.com/identrail/identrail/internal/findings/standards"
	"github.com/identrail/identrail/internal/providers"
	"github.com/identrail/identrail/internal/remediation/fixpr"
	"github.com/identrail/identrail/internal/repoexposure"
	"github.com/identrail/identrail/internal/scheduler"
	"go.opentelemetry.io/otel/trace"
)

type fakeScanner struct {
	result app.ScanResult
	err    error
}

func (f fakeScanner) Run(context.Context) (app.ScanResult, error) {
	if f.err != nil {
		return app.ScanResult{}, f.err
	}
	return f.result, nil
}

type fakeAlerter struct {
	calls int
	err   error
}

func (a *fakeAlerter) NotifyScan(context.Context, string, db.ScanRecord, []domain.Finding) error {
	a.calls++
	return a.err
}

type fakeRepoExecutor struct {
	result       repoexposure.ScanResult
	err          error
	target       string
	runCtx       context.Context
	options      repoexposure.ScanOptions
	beforeReturn func(context.Context, string)
	calls        int
}

func (f *fakeRepoExecutor) ScanRepository(ctx context.Context, target string) (repoexposure.ScanResult, error) {
	f.calls++
	f.target = target
	f.runCtx = ctx
	if f.beforeReturn != nil {
		f.beforeReturn(ctx, target)
	}
	if f.err != nil {
		return repoexposure.ScanResult{}, f.err
	}
	return f.result, nil
}

func (f *fakeRepoExecutor) ScanRepositoryWithOptions(ctx context.Context, target string, options repoexposure.ScanOptions) (repoexposure.ScanResult, error) {
	f.options = options
	return f.ScanRepository(ctx, target)
}

type fakeGitHubInstallationTokenMinter struct {
	token          githubconnector.InstallationToken
	err            error
	installationID int64
	calls          int
}

func (f *fakeGitHubInstallationTokenMinter) Mint(ctx context.Context, installationID int64) (githubconnector.InstallationToken, error) {
	f.calls++
	f.installationID = installationID
	if f.err != nil {
		return githubconnector.InstallationToken{}, f.err
	}
	return f.token, nil
}

type fakeGitHubCodeScanningAlertCollector struct {
	alerts         []githubconnector.CodeScanningAlert
	err            error
	installationID int64
	repository     string
	calls          int
}

func (f *fakeGitHubCodeScanningAlertCollector) ListCodeScanningAlerts(ctx context.Context, installationID int64, repository string) ([]githubconnector.CodeScanningAlert, error) {
	f.calls++
	f.installationID = installationID
	f.repository = repository
	if f.err != nil {
		return nil, f.err
	}
	return f.alerts, nil
}

type fakeRepoRemediationPublisher struct {
	result  fixpr.PublishResult
	err     error
	finding domain.Finding
	opts    fixpr.RepoExposurePublishOptions
	calls   int
}

func (f *fakeRepoRemediationPublisher) PublishRepoExposureRemediation(ctx context.Context, finding domain.Finding, opts fixpr.RepoExposurePublishOptions) (fixpr.PublishResult, standards.RepoExposureRemediation, error) {
	f.calls++
	f.finding = finding
	f.opts = opts
	remediation, _ := standards.SuggestRepoExposureRemediation(finding)
	if f.err != nil {
		return fixpr.PublishResult{}, remediation, f.err
	}
	return f.result, remediation, nil
}

type fakeGitHubSecretScanningAlertCollector struct {
	alerts         []githubconnector.SecretScanningAlert
	err            error
	installationID int64
	repository     string
	calls          int
}

func (f *fakeGitHubSecretScanningAlertCollector) ListSecretScanningAlerts(ctx context.Context, installationID int64, repository string) ([]githubconnector.SecretScanningAlert, error) {
	f.calls++
	f.installationID = installationID
	f.repository = repository
	if f.err != nil {
		return nil, f.err
	}
	return f.alerts, nil
}

type fakeGitHubDependabotAlertCollector struct {
	alerts         []githubconnector.DependabotAlert
	err            error
	installationID int64
	repository     string
	calls          int
}

func (f *fakeGitHubDependabotAlertCollector) ListDependabotAlerts(ctx context.Context, installationID int64, repository string) ([]githubconnector.DependabotAlert, error) {
	f.calls++
	f.installationID = installationID
	f.repository = repository
	if f.err != nil {
		return nil, f.err
	}
	return f.alerts, nil
}

type traceCapturingScanner struct {
	result app.ScanResult
	err    error
	runCtx context.Context
}

func (s *traceCapturingScanner) Run(ctx context.Context) (app.ScanResult, error) {
	s.runCtx = ctx
	if s.err != nil {
		return app.ScanResult{}, s.err
	}
	return s.result, nil
}

type completionContextStore struct {
	*db.MemoryStore
	lastScanCompletionCtxErr     error
	lastRepoScanCompletionCtxErr error
}

type cancelOnCompleteRepoScanStore struct {
	*db.MemoryStore
	now time.Time
}

type failingCompleteScanStore struct {
	*db.MemoryStore
}

func (s *failingCompleteScanStore) CompleteScan(
	context.Context,
	string,
	string,
	time.Time,
	int,
	int,
	string,
) error {
	return errors.New("finalize failed")
}

type failingRepoScanCursorStore struct {
	*db.MemoryStore
}

func (s *failingRepoScanCursorStore) UpsertRepoScanCursor(context.Context, db.RepoScanCursor) error {
	return errors.New("cursor update failed")
}

type failingAnyScopeDepthStore struct {
	*db.MemoryStore
}

type repoFindingClusterFilterCaptureStore struct {
	*db.MemoryStore
	lastRepoFindingClusterFilter db.RepoFindingClusterListFilter
}

func (s *failingAnyScopeDepthStore) CountQueuedScansAnyScope(context.Context, string) (int, error) {
	return 0, errors.New("count queued scans any scope failed")
}

func (s *failingAnyScopeDepthStore) CountQueuedRepoScansAnyScope(context.Context) (int, error) {
	return 0, errors.New("count queued repo scans any scope failed")
}

func (s *repoFindingClusterFilterCaptureStore) ListRepoFindingClusters(ctx context.Context, filter db.RepoFindingClusterListFilter) ([]domain.RepoFindingCluster, error) {
	s.lastRepoFindingClusterFilter = filter
	return s.MemoryStore.ListRepoFindingClusters(ctx, filter)
}

func (s *completionContextStore) CompleteScan(
	ctx context.Context,
	scanID string,
	status string,
	finishedAt time.Time,
	assetCount int,
	findingCount int,
	errorMessage string,
) error {
	s.lastScanCompletionCtxErr = ctx.Err()
	return s.MemoryStore.CompleteScan(ctx, scanID, status, finishedAt, assetCount, findingCount, errorMessage)
}

func (s *completionContextStore) CompleteRepoScan(
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
	s.lastRepoScanCompletionCtxErr = ctx.Err()
	return s.MemoryStore.CompleteRepoScan(
		ctx,
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
}

func (s *cancelOnCompleteRepoScanStore) CompleteRepoScan(
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
	cancelAt := s.now
	if cancelAt.IsZero() {
		cancelAt = finishedAt
	}
	_, _ = s.MemoryStore.CancelRepoScan(ctx, repoScanID, cancelAt, userCanceledRepoScanMessage)
	return s.MemoryStore.CompleteRepoScan(
		ctx,
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
}

func TestServiceCheckReadiness(t *testing.T) {
	svc := NewService(db.NewMemoryStore(), fakeScanner{}, "aws")
	if err := svc.CheckReadiness(context.Background()); err != nil {
		t.Fatalf("expected readiness check to pass, got %v", err)
	}
}

func TestServiceCheckReadinessDependencyFailure(t *testing.T) {
	svc := NewService(db.NewMemoryStore(), fakeScanner{}, "aws")
	svc.ReadinessCheck = func(context.Context) error {
		return errors.New("dependency unavailable")
	}
	if err := svc.CheckReadiness(context.Background()); err == nil {
		t.Fatal("expected readiness check failure")
	}
}

func TestServiceRunScanSuccess(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC)

	svc := NewService(store, fakeScanner{result: app.ScanResult{
		Assets: 1,
		Findings: []domain.Finding{{
			ID:           "f1",
			Type:         domain.FindingRiskyTrustPolicy,
			Severity:     domain.SeverityHigh,
			Title:        "Risky",
			HumanSummary: "summary",
			CreatedAt:    now,
		}},
	}}, "aws")
	svc.Now = func() time.Time { return now }

	result, err := svc.RunScan(defaultScopeContext())
	if err != nil {
		t.Fatalf("run scan failed: %v", err)
	}
	if result.Scan.Status != "succeeded" || result.FindingCount != 1 {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestServiceRunScanUsesPersistedAWSConnector(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	seedDefaultProject(t, store, ctx, "project-1")
	now := time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC)
	if err := store.UpsertTenancyConnector(ctx, db.TenancyConnector{
		WorkspaceID: "default",
		ProjectID:   "project-1",
		ConnectorID: "aws-123456789012",
		Type:        domain.ConnectorTypeAWS,
		DisplayName: "Production AWS",
		Status:      domain.ConnectorStatusActive,
		CreatedAt:   now,
		UpdatedAt:   now,
	}, db.TenancyConnectorState{
		WorkspaceID:  "default",
		ProjectID:    "project-1",
		ConnectorID:  "aws-123456789012",
		HealthStatus: "healthy",
		Metadata: map[string]any{
			"role_arn":               "arn:aws:iam::123456789012:role/IdentrailReadOnly",
			"external_id":            "tenant-external-id",
			"external_id_configured": true,
			"region":                 "us-west-2",
			"permission_checks": []AWSConnectionPermissionCheck{{
				Name:    "sts:AssumeRole",
				Passed:  true,
				Message: "Role assumption succeeded.",
			}},
			"diagnostics":       []AWSConnectionDiagnostic{},
			"last_validated_at": now.Format(time.RFC3339Nano),
		},
		ObservedAt: now,
		UpdatedAt:  now,
	}); err != nil {
		t.Fatalf("seed aws connector: %v", err)
	}

	factoryCalled := false
	svc := NewService(store, fakeScanner{err: errors.New("default scanner should not run")}, "aws")
	svc.Now = func() time.Time { return now }
	svc.AWSScannerFactory = func(_ context.Context, connection AWSConnectionStatus) (ScannerRunner, error) {
		factoryCalled = true
		if connection.RoleARN != "arn:aws:iam::123456789012:role/IdentrailReadOnly" ||
			connection.ExternalID != "tenant-external-id" ||
			connection.Region != "us-west-2" {
			t.Fatalf("factory received wrong connection: %+v", connection)
		}
		return fakeScanner{result: app.ScanResult{Assets: 1}}, nil
	}

	result, err := svc.RunScan(ctx)
	if err != nil {
		t.Fatalf("run scan failed: %v", err)
	}
	if !factoryCalled {
		t.Fatal("expected scan to use persisted aws connector scanner factory")
	}
	if result.Scan.Status != "succeeded" || result.Assets != 1 {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestServiceRunScanFailure(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC)

	svc := NewService(store, fakeScanner{err: errors.New("scanner failed")}, "aws")
	svc.Now = func() time.Time { return now }

	_, err := svc.RunScan(defaultScopeContext())
	if err == nil {
		t.Fatal("expected error")
	}

	scans, listErr := store.ListScans(defaultScopeContext(), 1)
	if listErr != nil {
		t.Fatalf("list scans failed: %v", listErr)
	}
	if len(scans) != 1 || scans[0].Status != "failed" {
		t.Fatalf("expected failed scan record, got %+v", scans)
	}
}

func TestServiceRunScanFailureUsesFreshContextForTerminalWrite(t *testing.T) {
	store := &completionContextStore{MemoryStore: db.NewMemoryStore()}
	svc := NewService(store, fakeScanner{err: context.Canceled}, "aws")

	canceledCtx, cancel := context.WithCancel(defaultScopeContext())
	cancel()

	if _, err := svc.RunScan(canceledCtx); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled error, got %v", err)
	}
	if store.lastScanCompletionCtxErr != nil {
		t.Fatalf("expected terminal scan completion to use non-canceled context, got %v", store.lastScanCompletionCtxErr)
	}
	scans, err := store.ListScans(defaultScopeContext(), 10)
	if err != nil {
		t.Fatalf("list scans: %v", err)
	}
	if len(scans) != 1 || scans[0].Status != "failed" {
		t.Fatalf("expected failed scan record, got %+v", scans)
	}
}

func TestServiceRunScanSuccessUsesFreshContextForTerminalWrite(t *testing.T) {
	store := &completionContextStore{MemoryStore: db.NewMemoryStore()}
	svc := NewService(store, fakeScanner{result: app.ScanResult{
		Assets: 3,
		Findings: []domain.Finding{{
			ID:           "finding-success",
			Type:         domain.FindingRiskyTrustPolicy,
			Severity:     domain.SeverityLow,
			Title:        "No issue",
			HumanSummary: "summary",
		}},
	}}, "aws")

	canceledCtx, cancel := context.WithCancel(defaultScopeContext())
	cancel()

	result, err := svc.RunScan(canceledCtx)
	if err != nil {
		t.Fatalf("run scan failed: %v", err)
	}
	if result.Scan.Status != "succeeded" {
		t.Fatalf("expected succeeded scan status, got %q", result.Scan.Status)
	}
	scans, err := store.ListScans(defaultScopeContext(), 10)
	if err != nil {
		t.Fatalf("list scans: %v", err)
	}
	if len(scans) != 1 || scans[0].Status != "succeeded" {
		t.Fatalf("expected succeeded scan record, got %+v", scans)
	}
	if store.lastScanCompletionCtxErr != nil {
		t.Fatalf("expected terminal scan completion to use non-canceled context, got %v", store.lastScanCompletionCtxErr)
	}
}

func seedDefaultProject(t *testing.T, store db.Store, ctx context.Context, projectID string) {
	t.Helper()
	scope, err := db.RequireScope(ctx)
	if err != nil {
		t.Fatalf("resolve scope: %v", err)
	}
	if err := store.UpsertOrganization(ctx, db.TenancyOrganization{
		DisplayName: "Tenant " + scope.TenantID,
		Slug:        scope.TenantID,
	}); err != nil {
		t.Fatalf("seed organization: %v", err)
	}
	if err := store.UpsertWorkspace(ctx, db.TenancyWorkspace{
		WorkspaceID: scope.WorkspaceID,
		DisplayName: "Workspace " + scope.WorkspaceID,
		Slug:        scope.WorkspaceID,
	}); err != nil {
		t.Fatalf("seed workspace: %v", err)
	}
	if err := store.UpsertProject(ctx, db.TenancyProject{
		WorkspaceID: scope.WorkspaceID,
		ProjectID:   projectID,
		Name:        "Project " + projectID,
		Slug:        projectID,
	}); err != nil {
		t.Fatalf("seed project: %v", err)
	}
}

func seedGitHubAppConnection(t *testing.T, svc *Service, ctx context.Context, projectID string, installationID int64, repositories []string) {
	t.Helper()
	scope, err := db.RequireScope(ctx)
	if err != nil {
		t.Fatalf("resolve scope: %v", err)
	}
	now := time.Now().UTC()
	envelope, err := svc.encryptGitHubWebhookSecret(scope, projectID, "test-github-webhook-secret")
	if err != nil {
		t.Fatalf("encrypt github webhook secret: %v", err)
	}
	connection := githubProjectConnection{
		TenantID:               scope.TenantID,
		WorkspaceID:            scope.WorkspaceID,
		ProjectID:              projectID,
		ConnectorID:            githubConnectorID,
		DisplayName:            githubConnectorDisplayName,
		Status:                 domain.ConnectorStatusActive,
		HealthStatus:           "healthy",
		Provider:               "github_app",
		InstallationID:         installationID,
		TokenReference:         fmt.Sprintf("github-app-installation:%d", installationID),
		WebhookSecretReference: "github-app:webhook",
		WebhookSecretEnvelope:  envelope,
		WebhookSecretRotatedAt: now,
		SelectedRepositories:   repositories,
		CreatedAt:              now,
		UpdatedAt:              now,
	}
	svc.githubConnections[githubConnectionKey(scope.TenantID, scope.WorkspaceID, projectID)] = connection
	if err := svc.persistGitHubConnection(ctx, connection); err != nil {
		t.Fatalf("persist github connection: %v", err)
	}
}

func TestServiceScanPolicyCRUDAndDefaults(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	seedDefaultProject(t, store, ctx, "project-1")
	svc := NewService(store, fakeScanner{}, "aws")

	enabled := false
	policy, err := svc.UpsertScanPolicy(ctx, "default", "project-1", ScanPolicyUpsertRequest{
		PolicyID:           "default",
		Name:               "Default policy",
		Enabled:            &enabled,
		TriggerMode:        "event",
		MaxConcurrentScans: 2,
	})
	if err != nil {
		t.Fatalf("upsert scan policy: %v", err)
	}
	if policy.Enabled || policy.TriggerMode != domain.ScanTriggerModeEvent {
		t.Fatalf("unexpected scan policy state: %+v", policy)
	}
	if policy.HistoryLimit != defaultRepoScanHistoryLimit || policy.MaxFindings != defaultRepoScanMaxFindings {
		t.Fatalf("expected default scan bounds, got history=%d findings=%d", policy.HistoryLimit, policy.MaxFindings)
	}

	reloaded, err := svc.GetScanPolicy(ctx, "default", "project-1", "default")
	if err != nil {
		t.Fatalf("get scan policy: %v", err)
	}
	if reloaded.PolicyID != "default" {
		t.Fatalf("unexpected reloaded policy: %+v", reloaded)
	}

	disabled := false
	filtered, err := svc.ListScanPolicies(ctx, "default", "project-1", ScanPolicyListFilter{
		TriggerMode: "event",
		Enabled:     &disabled,
		Limit:       10,
	})
	if err != nil {
		t.Fatalf("list scan policies: %v", err)
	}
	if len(filtered) != 1 || filtered[0].PolicyID != "default" {
		t.Fatalf("unexpected filtered policies: %+v", filtered)
	}

	if err := svc.DeleteScanPolicy(ctx, "default", "project-1", "default"); err != nil {
		t.Fatalf("delete scan policy: %v", err)
	}
	if _, err := svc.GetScanPolicy(ctx, "default", "project-1", "default"); !errors.Is(err, db.ErrNotFound) {
		t.Fatalf("expected deleted policy to return ErrNotFound, got %v", err)
	}
}

func TestServiceScanPolicyUsesDefaultScopeForStoreCalls(t *testing.T) {
	store := db.NewMemoryStore()
	scopedCtx := defaultScopeContext()
	seedDefaultProject(t, store, scopedCtx, "project-1")
	svc := NewService(store, fakeScanner{}, "aws")

	policy, err := svc.UpsertScanPolicy(context.Background(), "default", "project-1", ScanPolicyUpsertRequest{
		PolicyID:    "default",
		Name:        "Default policy",
		TriggerMode: "manual",
	})
	if err != nil {
		t.Fatalf("upsert scan policy with default service scope: %v", err)
	}
	if policy.PolicyID != "default" {
		t.Fatalf("unexpected policy from default scope upsert: %+v", policy)
	}

	if _, err := svc.GetScanPolicy(context.Background(), "default", "project-1", "default"); err != nil {
		t.Fatalf("get scan policy with default service scope: %v", err)
	}
	policies, err := svc.ListScanPolicies(context.Background(), "default", "project-1", ScanPolicyListFilter{Limit: 10})
	if err != nil {
		t.Fatalf("list scan policies with default service scope: %v", err)
	}
	if len(policies) != 1 {
		t.Fatalf("expected one scan policy with default service scope, got %+v", policies)
	}
	if err := svc.DeleteScanPolicy(context.Background(), "default", "project-1", "default"); err != nil {
		t.Fatalf("delete scan policy with default service scope: %v", err)
	}
}

func TestServiceScanPolicyDuplicateNameConflicts(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	seedDefaultProject(t, store, ctx, "project-1")
	svc := NewService(store, fakeScanner{}, "aws")

	if _, err := svc.UpsertScanPolicy(ctx, "default", "project-1", ScanPolicyUpsertRequest{
		PolicyID:    "default",
		Name:        "Default policy",
		TriggerMode: "manual",
	}); err != nil {
		t.Fatalf("upsert first scan policy: %v", err)
	}
	if _, err := svc.UpsertScanPolicy(ctx, "default", "project-1", ScanPolicyUpsertRequest{
		PolicyID:    "secondary",
		Name:        "Default policy",
		TriggerMode: "event",
	}); !errors.Is(err, db.ErrConflict) {
		t.Fatalf("expected duplicate scan policy name conflict, got %v", err)
	}
}

func TestServiceScanPolicyValidation(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	seedDefaultProject(t, store, ctx, "project-1")
	svc := NewService(store, fakeScanner{}, "aws")
	svc.RepoScanMaxHistoryLimit = 100
	svc.RepoScanMaxFindingsLimit = 50

	cases := []struct {
		name    string
		request ScanPolicyUpsertRequest
	}{
		{
			name: "scheduled policy requires cron",
			request: ScanPolicyUpsertRequest{
				PolicyID:    "scheduled",
				Name:        "Scheduled",
				TriggerMode: "scheduled",
			},
		},
		{
			name: "invalid trigger mode",
			request: ScanPolicyUpsertRequest{
				PolicyID:    "invalid-mode",
				Name:        "Invalid mode",
				TriggerMode: "always",
			},
		},
		{
			name: "history limit above configured maximum",
			request: ScanPolicyUpsertRequest{
				PolicyID:     "too-deep",
				Name:         "Too deep",
				TriggerMode:  "manual",
				HistoryLimit: 101,
			},
		},
		{
			name: "max findings above configured maximum",
			request: ScanPolicyUpsertRequest{
				PolicyID:    "too-many-findings",
				Name:        "Too many findings",
				TriggerMode: "manual",
				MaxFindings: 51,
			},
		},
		{
			name: "negative max concurrent scans",
			request: ScanPolicyUpsertRequest{
				PolicyID:           "negative-concurrency",
				Name:               "Negative concurrency",
				TriggerMode:        "manual",
				MaxConcurrentScans: -1,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := svc.UpsertScanPolicy(ctx, "default", "project-1", tc.request); !errors.Is(err, ErrInvalidScanPolicyRequest) {
				t.Fatalf("expected ErrInvalidScanPolicyRequest, got %v", err)
			}
		})
	}
}

func TestServiceRunScanLocked(t *testing.T) {
	store := db.NewMemoryStore()
	locker := scheduler.NewInMemoryLocker()
	release, ok := locker.TryAcquire(context.Background(), "identrail:scan:aws")
	if !ok {
		t.Fatal("expected lock acquire")
	}
	defer release(context.Background())

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Locker = locker

	_, err := svc.RunScan(defaultScopeContext())
	if !errors.Is(err, ErrScanInProgress) {
		t.Fatalf("expected ErrScanInProgress, got %v", err)
	}
}

func TestServiceRunScanAlertHookCalled(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC)
	alerter := &fakeAlerter{}
	svc := NewService(store, fakeScanner{result: app.ScanResult{
		Assets:   1,
		Findings: []domain.Finding{{ID: "f1", Severity: domain.SeverityHigh}},
	}}, "aws")
	svc.Now = func() time.Time { return now }
	svc.Alerter = alerter

	if _, err := svc.RunScan(defaultScopeContext()); err != nil {
		t.Fatalf("run scan: %v", err)
	}
	if alerter.calls != 1 {
		t.Fatalf("expected 1 alert call, got %d", alerter.calls)
	}
}

func TestServiceRunScanAlertFailureIsNonBlocking(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC)
	alerter := &fakeAlerter{err: errors.New("webhook down")}
	svc := NewService(store, fakeScanner{result: app.ScanResult{
		Assets:   1,
		Findings: []domain.Finding{{ID: "f1", Severity: domain.SeverityHigh}},
	}}, "aws")
	svc.Now = func() time.Time { return now }
	svc.Alerter = alerter

	errorCalls := 0
	svc.OnAlertError = func(err error) {
		if err != nil {
			errorCalls++
		}
	}

	result, err := svc.RunScan(defaultScopeContext())
	if err != nil {
		t.Fatalf("expected scan success despite alert error, got %v", err)
	}
	if result.Scan.Status != "succeeded" {
		t.Fatalf("expected succeeded status, got %q", result.Scan.Status)
	}
	if errorCalls != 1 {
		t.Fatalf("expected alert error callback once, got %d", errorCalls)
	}
}

func TestServiceGetFindingsSummary(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC)
	scan, err := store.CreateScan(defaultScopeContext(), "aws", now)
	if err != nil {
		t.Fatalf("create scan: %v", err)
	}
	if err := store.UpsertFindings(defaultScopeContext(), scan.ID, []domain.Finding{
		{ID: "f1", Type: domain.FindingOwnerless, Severity: domain.SeverityHigh, CreatedAt: now},
		{ID: "f2", Type: domain.FindingOwnerless, Severity: domain.SeverityMedium, CreatedAt: now},
		{ID: "f3", Type: domain.FindingStaleIdentity, Severity: domain.SeverityHigh, CreatedAt: now},
	}); err != nil {
		t.Fatalf("upsert findings: %v", err)
	}

	svc := NewService(store, fakeScanner{}, "aws")
	summary, err := svc.GetFindingsSummary(defaultScopeContext(), 100)
	if err != nil {
		t.Fatalf("get summary: %v", err)
	}
	if summary.Total != 3 {
		t.Fatalf("expected total 3, got %d", summary.Total)
	}
	if summary.BySeverity["high"] != 2 {
		t.Fatalf("unexpected severity summary: %+v", summary.BySeverity)
	}
	if summary.ByType["ownerless_identity"] != 2 {
		t.Fatalf("unexpected type summary: %+v", summary.ByType)
	}
}

func TestServiceGetFindingsSummaryIgnoresListLimitForTotals(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC)
	scan, _ := store.CreateScan(defaultScopeContext(), "aws", now)

	findings := make([]domain.Finding, 0, 120)
	for i := 0; i < 120; i++ {
		findings = append(findings, domain.Finding{
			ID:        fmt.Sprintf("finding-%03d", i),
			Type:      domain.FindingOwnerless,
			Severity:  domain.SeverityHigh,
			CreatedAt: now.Add(time.Duration(i) * time.Second),
		})
	}
	if err := store.UpsertFindings(defaultScopeContext(), scan.ID, findings); err != nil {
		t.Fatalf("upsert findings: %v", err)
	}

	svc := NewService(store, fakeScanner{}, "aws")
	summary, err := svc.GetFindingsSummary(defaultScopeContext(), 10)
	if err != nil {
		t.Fatalf("get summary: %v", err)
	}
	if summary.Total != 120 {
		t.Fatalf("expected total 120, got %d", summary.Total)
	}
	if summary.BySeverity["high"] != 120 {
		t.Fatalf("unexpected severity summary: %+v", summary.BySeverity)
	}
}

func TestServiceListFindingsFiltered(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC)
	scanA, _ := store.CreateScan(defaultScopeContext(), "aws", now)
	scanB, _ := store.CreateScan(defaultScopeContext(), "aws", now.Add(1*time.Minute))
	_ = store.UpsertFindings(defaultScopeContext(), scanA.ID, []domain.Finding{
		{ID: "f1", Type: domain.FindingOwnerless, Severity: domain.SeverityHigh, CreatedAt: now},
	})
	_ = store.UpsertFindings(defaultScopeContext(), scanB.ID, []domain.Finding{
		{ID: "f2", Type: domain.FindingEscalationPath, Severity: domain.SeverityCritical, CreatedAt: now.Add(1 * time.Minute)},
		{ID: "f3", Type: domain.FindingOwnerless, Severity: domain.SeverityLow, CreatedAt: now.Add(1 * time.Minute)},
	})

	svc := NewService(store, fakeScanner{}, "aws")

	highOnly, err := svc.ListFindingsFiltered(defaultScopeContext(), 10, FindingsFilter{Severity: "critical"})
	if err != nil {
		t.Fatalf("list findings filtered by severity: %v", err)
	}
	if len(highOnly) != 1 || highOnly[0].ID != "f2" {
		t.Fatalf("unexpected critical findings: %+v", highOnly)
	}

	scanOnly, err := svc.ListFindingsFiltered(defaultScopeContext(), 10, FindingsFilter{ScanID: scanA.ID, Type: "ownerless_identity"})
	if err != nil {
		t.Fatalf("list findings filtered by scan/type: %v", err)
	}
	if len(scanOnly) != 1 || scanOnly[0].ID != "f1" {
		t.Fatalf("unexpected findings for scan/type: %+v", scanOnly)
	}

	limited, err := svc.ListFindingsFiltered(defaultScopeContext(), 1, FindingsFilter{SortBy: "created_at", SortDesc: true})
	if err != nil {
		t.Fatalf("list findings with limit: %v", err)
	}
	if len(limited) != 1 || limited[0].ID != "f3" {
		t.Fatalf("expected service to enforce limit and keep newest first, got %+v", limited)
	}

	defaultOrdered, err := svc.ListFindingsFiltered(defaultScopeContext(), 1, FindingsFilter{})
	if err != nil {
		t.Fatalf("list findings with default sort: %v", err)
	}
	if len(defaultOrdered) != 1 || defaultOrdered[0].ID != "f3" {
		t.Fatalf("expected default filtered order to remain newest-first, got %+v", defaultOrdered)
	}

	offsetWindow, err := svc.ListFindingsFiltered(defaultScopeContext(), 2, FindingsFilter{
		SortBy:   "created_at",
		SortDesc: true,
		Offset:   1,
	})
	if err != nil {
		t.Fatalf("list findings with offset: %v", err)
	}
	if len(offsetWindow) == 0 || offsetWindow[0].ID != "f2" {
		t.Fatalf("expected offset to be applied before paging window, got %+v", offsetWindow)
	}
}

func TestServiceListFindingsFilteredByAssigneeOnly(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 3, 17, 8, 0, 0, 0, time.UTC)
	scan, _ := store.CreateScan(defaultScopeContext(), "aws", now)
	_ = store.UpsertFindings(defaultScopeContext(), scan.ID, []domain.Finding{
		{ID: "finding-platform", Type: domain.FindingOwnerless, Severity: domain.SeverityHigh, CreatedAt: now},
		{ID: "finding-operations", Type: domain.FindingOwnerless, Severity: domain.SeverityMedium, CreatedAt: now.Add(1 * time.Minute)},
		{ID: "finding-empty", Type: domain.FindingOwnerless, Severity: domain.SeverityLow, CreatedAt: now.Add(2 * time.Minute)},
	})

	svc := NewService(store, fakeScanner{}, "aws")
	ack := string(domain.FindingLifecycleAck)
	open := string(domain.FindingLifecycleOpen)
	platform := "platform"
	operations := "ops"
	_, err := svc.TriageFinding(
		defaultScopeContext(),
		"finding-platform",
		scan.ID,
		FindingTriageRequest{Assignee: &platform, Status: &ack},
		"subject:user-1",
	)
	if err != nil {
		t.Fatalf("triage platform finding: %v", err)
	}

	_, err = svc.TriageFinding(
		defaultScopeContext(),
		"finding-operations",
		scan.ID,
		FindingTriageRequest{Assignee: &operations, Status: &open},
		"subject:user-1",
	)
	if err != nil {
		t.Fatalf("triage operations finding: %v", err)
	}

	platformOnly, err := svc.ListFindingsFiltered(defaultScopeContext(), 10, FindingsFilter{Assignee: "platform"})
	if err != nil {
		t.Fatalf("list findings by assignee only: %v", err)
	}
	if len(platformOnly) != 1 || platformOnly[0].ID != "finding-platform" {
		t.Fatalf("expected only finding-platform for assignee filter, got %+v", platformOnly)
	}

	operationsOnly, err := svc.ListFindingsFiltered(defaultScopeContext(), 10, FindingsFilter{Assignee: "OPS"})
	if err != nil {
		t.Fatalf("list findings by uppercase assignee: %v", err)
	}
	if len(operationsOnly) != 1 || operationsOnly[0].ID != "finding-operations" {
		t.Fatalf("expected case-insensitive assignee matching, got %+v", operationsOnly)
	}
}

func TestServiceListFindingsFilteredMatchesOlderRowsBeyondLegacyWindow(t *testing.T) {
	store := db.NewMemoryStore()
	base := time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 5001; i++ {
		scan, err := store.CreateScan(defaultScopeContext(), "aws", base.Add(time.Duration(i)*time.Minute))
		if err != nil {
			t.Fatalf("create scan %d: %v", i, err)
		}
		severity := domain.SeverityLow
		if i == 0 {
			severity = domain.SeverityCritical
		}
		if err := store.UpsertFindings(defaultScopeContext(), scan.ID, []domain.Finding{{
			ID:        fmt.Sprintf("finding-%04d", i),
			Type:      domain.FindingOwnerless,
			Severity:  severity,
			CreatedAt: base.Add(time.Duration(i) * time.Minute),
		}}); err != nil {
			t.Fatalf("upsert finding %d: %v", i, err)
		}
	}

	svc := NewService(store, fakeScanner{}, "aws")
	items, err := svc.ListFindingsFiltered(defaultScopeContext(), 10, FindingsFilter{Severity: "critical"})
	if err != nil {
		t.Fatalf("list critical findings: %v", err)
	}
	if len(items) != 1 || items[0].ID != "finding-0000" {
		t.Fatalf("expected oldest critical finding to be returned, got %+v", items)
	}
}

func TestServiceListRepoFindingsFilterTriagedResultsBeyondLegacyWindow(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC)
	repoScan, _ := store.CreateRepoScan(defaultScopeContext(), "owner/repo", db.RepoScanSource{}, db.RepoScanContext{}, now)

	repoFindings := make([]domain.Finding, 0, 5001)
	for i := 0; i < 5001; i++ {
		id := fmt.Sprintf("repo-finding-%04d", i)
		repoFindings = append(repoFindings, domain.Finding{
			ID:        id,
			Type:      domain.FindingSecretExposure,
			Severity:  domain.SeverityHigh,
			CreatedAt: now.Add(time.Duration(i) * time.Minute),
		})
	}
	if err := store.UpsertRepoFindings(defaultScopeContext(), repoScan.ID, repoFindings); err != nil {
		t.Fatalf("upsert repo findings: %v", err)
	}

	svc := NewService(store, fakeScanner{}, "aws")
	ack := string(domain.FindingLifecycleAck)
	_, err := svc.TriageFinding(
		defaultScopeContext(),
		"repo-finding-0000",
		repoScan.ID,
		FindingTriageRequest{Status: &ack},
		"subject:user-1",
	)
	if err != nil {
		t.Fatalf("triage oldest repo finding: %v", err)
	}

	filtered, err := svc.ListRepoFindings(
		defaultScopeContext(),
		maxCursorFetchLimit,
		db.RepoFindingFilter{
			RepoScanID:      repoScan.ID,
			LifecycleStatus: string(domain.FindingLifecycleAck),
		},
	)
	if err != nil {
		t.Fatalf("list repo findings by lifecycle status: %v", err)
	}
	if len(filtered) != 1 || filtered[0].ID != "repo-finding-0000" {
		t.Fatalf("expected oldest triaged repo finding to be returned, got %+v", filtered)
	}
}

func TestServiceListRepoFindingsSortBySeverityHonorsLimitBeyondLegacyWindow(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC)
	repoScan, _ := store.CreateRepoScan(defaultScopeContext(), "owner/repo", db.RepoScanSource{}, db.RepoScanContext{}, now)

	repoFindings := make([]domain.Finding, 0, 5001)
	for i := 0; i < 5001; i++ {
		severity := domain.SeverityLow
		if i == 0 {
			severity = domain.SeverityCritical
		}
		repoFindings = append(repoFindings, domain.Finding{
			ID:        fmt.Sprintf("repo-finding-%04d", i),
			Type:      domain.FindingSecretExposure,
			Severity:  severity,
			CreatedAt: now.Add(time.Duration(i) * time.Minute),
		})
	}
	if err := store.UpsertRepoFindings(defaultScopeContext(), repoScan.ID, repoFindings); err != nil {
		t.Fatalf("upsert repo findings: %v", err)
	}

	svc := NewService(store, fakeScanner{}, "aws")
	sorted, err := svc.ListRepoFindings(
		defaultScopeContext(),
		2,
		db.RepoFindingFilter{
			RepoScanID: repoScan.ID,
			SortBy:     "severity",
			SortDesc:   true,
		},
	)
	if err != nil {
		t.Fatalf("list repo findings by severity: %v", err)
	}
	if len(sorted) != 2 {
		t.Fatalf("expected prioritized sorting to honor the requested limit, got %d items", len(sorted))
	}
	if sorted[0].ID != "repo-finding-0000" || sorted[0].Severity != domain.SeverityCritical {
		t.Fatalf("expected oldest critical repo finding to lead prioritized results, got %+v", sorted[0])
	}
}

func TestServiceRepoFindingTriageScopesStateToRepoScan(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC)
	firstScan, _ := store.CreateRepoScan(defaultScopeContext(), "owner/repo", db.RepoScanSource{}, db.RepoScanContext{}, now)
	secondScan, _ := store.CreateRepoScan(defaultScopeContext(), "owner/repo", db.RepoScanSource{}, db.RepoScanContext{}, now.Add(time.Hour))

	if err := store.UpsertRepoFindings(defaultScopeContext(), firstScan.ID, []domain.Finding{{
		ID:        "shared-id",
		Type:      domain.FindingSecretExposure,
		Severity:  domain.SeverityHigh,
		CreatedAt: now,
	}}); err != nil {
		t.Fatalf("upsert first repo findings: %v", err)
	}
	if err := store.UpsertRepoFindings(defaultScopeContext(), secondScan.ID, []domain.Finding{{
		ID:        "shared-id",
		Type:      domain.FindingSecretExposure,
		Severity:  domain.SeverityMedium,
		CreatedAt: now.Add(time.Hour),
	}}); err != nil {
		t.Fatalf("upsert second repo findings: %v", err)
	}

	svc := NewService(store, fakeScanner{}, "aws")
	ack := string(domain.FindingLifecycleAck)
	firstAssignee := "platform-a"
	if _, err := svc.TriageFinding(
		defaultScopeContext(),
		"shared-id",
		firstScan.ID,
		FindingTriageRequest{Status: &ack, Assignee: &firstAssignee},
		"subject:user-1",
	); err != nil {
		t.Fatalf("triage first repo finding: %v", err)
	}

	resolved := string(domain.FindingLifecycleResolved)
	secondAssignee := "platform-b"
	if _, err := svc.TriageFinding(
		defaultScopeContext(),
		"shared-id",
		secondScan.ID,
		FindingTriageRequest{Status: &resolved, Assignee: &secondAssignee},
		"subject:user-2",
	); err != nil {
		t.Fatalf("triage second repo finding: %v", err)
	}

	firstFindings, err := svc.ListRepoFindings(defaultScopeContext(), 10, db.RepoFindingFilter{RepoScanID: firstScan.ID})
	if err != nil {
		t.Fatalf("list first repo findings: %v", err)
	}
	secondFindings, err := svc.ListRepoFindings(defaultScopeContext(), 10, db.RepoFindingFilter{RepoScanID: secondScan.ID})
	if err != nil {
		t.Fatalf("list second repo findings: %v", err)
	}
	if len(firstFindings) != 1 {
		t.Fatalf("expected one row for first scan filter, got %+v", firstFindings)
	}
	if len(secondFindings) != 1 {
		t.Fatalf("expected one row for second scan filter, got %+v", secondFindings)
	}
	findings := append(firstFindings, secondFindings...)

	triageByScan := map[string]domain.FindingTriage{}
	for _, finding := range findings {
		triageByScan[finding.ScanID] = finding.Triage
	}
	if triageByScan[firstScan.ID].Status != domain.FindingLifecycleAck || triageByScan[firstScan.ID].Assignee != firstAssignee {
		t.Fatalf("expected first scan triage to stay isolated, got %+v", triageByScan[firstScan.ID])
	}
	if triageByScan[secondScan.ID].Status != domain.FindingLifecycleResolved || triageByScan[secondScan.ID].Assignee != secondAssignee {
		t.Fatalf("expected second scan triage to stay isolated, got %+v", triageByScan[secondScan.ID])
	}

	filtered, err := svc.ListRepoFindings(
		defaultScopeContext(),
		10,
		db.RepoFindingFilter{
			RepoScanID:      firstScan.ID,
			LifecycleStatus: string(domain.FindingLifecycleAck),
		},
	)
	if err != nil {
		t.Fatalf("list repo findings by lifecycle status: %v", err)
	}
	if len(filtered) != 1 || filtered[0].ScanID != firstScan.ID {
		t.Fatalf("expected ack filter to return only first scan row, got %+v", filtered)
	}

	fixedByRepoStatus, err := svc.ListRepoFindings(
		defaultScopeContext(),
		10,
		db.RepoFindingFilter{
			RepoScanID: secondScan.ID,
			Status:     string(domain.RepoFindingLifecycleFixed),
		},
	)
	if err != nil {
		t.Fatalf("list repo findings by repo lifecycle status: %v", err)
	}
	if len(fixedByRepoStatus) != 1 || fixedByRepoStatus[0].ScanID != secondScan.ID || fixedByRepoStatus[0].LifecycleStatus != domain.RepoFindingLifecycleFixed {
		t.Fatalf("expected resolved triage to satisfy fixed repo lifecycle filter, got %+v", fixedByRepoStatus)
	}

	staleOpenByRepoStatus, err := svc.ListRepoFindings(
		defaultScopeContext(),
		10,
		db.RepoFindingFilter{
			RepoScanID: secondScan.ID,
			Status:     string(domain.RepoFindingLifecycleOpen),
		},
	)
	if err != nil {
		t.Fatalf("list open repo findings by repo lifecycle status: %v", err)
	}
	if len(staleOpenByRepoStatus) != 0 {
		t.Fatalf("expected resolved triage to be excluded from open repo lifecycle filter, got %+v", staleOpenByRepoStatus)
	}

	history, err := svc.ListFindingTriageHistory(defaultScopeContext(), "shared-id", secondScan.ID, 10)
	if err != nil {
		t.Fatalf("list repo triage history: %v", err)
	}
	if len(history) != 1 || history[0].ToStatus != domain.FindingLifecycleResolved || history[0].Assignee != secondAssignee {
		t.Fatalf("expected second scan history to stay isolated, got %+v", history)
	}
}

func TestServiceRepoFindingLifecycleTracksFixedAndReopenedAcrossScans(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 5, 20, 9, 0, 0, 0, time.UTC)

	firstScan, err := store.CreateRepoScan(ctx, "owner/repo", db.RepoScanSource{}, db.RepoScanContext{ScanMode: "deep"}, now)
	if err != nil {
		t.Fatalf("create first repo scan: %v", err)
	}
	firstFinding := domain.Finding{
		ID:              "finding:first-commit",
		Type:            domain.FindingSecretExposure,
		Severity:        domain.SeverityHigh,
		ConfidenceScore: 0.92,
		Title:           "GitHub token exposed",
		HumanSummary:    "A token-like value was committed.",
		Repository:      "owner/repo",
		Commit:          "abc123",
		FilePath:        "config/app.env",
		LineNumber:      7,
		Detector:        "github_token",
		Owner:           "platform",
		Evidence: map[string]any{
			"repository":         "owner/repo",
			"detector":           "github_token",
			"file_path":          "config/app.env",
			"line_number":        7,
			"secret_fingerprint": "fp-token",
			"confidence_score":   0.92,
			"owner":              "platform",
		},
		CreatedAt: now,
	}
	if err := store.UpsertRepoFindings(ctx, firstScan.ID, []domain.Finding{firstFinding}); err != nil {
		t.Fatalf("upsert first repo finding: %v", err)
	}
	if err := store.CompleteRepoScan(ctx, firstScan.ID, "succeeded", now.Add(time.Minute), 10, 8, 1, false, db.RepoScanContext{ScanMode: "deep"}, ""); err != nil {
		t.Fatalf("complete first repo scan: %v", err)
	}

	secondScan, err := store.CreateRepoScan(ctx, "owner/repo", db.RepoScanSource{}, db.RepoScanContext{ScanMode: "deep"}, now.Add(24*time.Hour))
	if err != nil {
		t.Fatalf("create second repo scan: %v", err)
	}
	if err := store.CompleteRepoScan(ctx, secondScan.ID, "succeeded", now.Add(24*time.Hour+time.Minute), 10, 8, 0, false, db.RepoScanContext{ScanMode: "deep"}, ""); err != nil {
		t.Fatalf("complete second repo scan: %v", err)
	}

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now.Add(48 * time.Hour) }
	fixed, err := svc.ListRepoFindings(ctx, 10, db.RepoFindingFilter{Status: string(domain.RepoFindingLifecycleFixed)})
	if err != nil {
		t.Fatalf("list fixed repo findings: %v", err)
	}
	if len(fixed) != 1 || fixed[0].LifecycleStatus != domain.RepoFindingLifecycleFixed || fixed[0].FixedAt == nil {
		t.Fatalf("expected one fixed lifecycle row, got %+v", fixed)
	}
	openAfterFixed, err := svc.ListRepoFindings(ctx, 10, db.RepoFindingFilter{Status: string(domain.RepoFindingLifecycleOpen)})
	if err != nil {
		t.Fatalf("list open repo findings after fixed lifecycle: %v", err)
	}
	if len(openAfterFixed) != 0 {
		t.Fatalf("expected stale open lifecycle rows to be hidden, got %+v", openAfterFixed)
	}

	thirdScan, err := store.CreateRepoScan(ctx, "owner/repo", db.RepoScanSource{}, db.RepoScanContext{ScanMode: "deep"}, now.Add(48*time.Hour))
	if err != nil {
		t.Fatalf("create third repo scan: %v", err)
	}
	reopenedFinding := firstFinding
	reopenedFinding.ID = "finding:second-commit"
	reopenedFinding.Commit = "def456"
	reopenedFinding.CreatedAt = now.Add(48 * time.Hour)
	reopenedFinding.Evidence["commit"] = "def456"
	if err := store.UpsertRepoFindings(ctx, thirdScan.ID, []domain.Finding{reopenedFinding}); err != nil {
		t.Fatalf("upsert reopened repo finding: %v", err)
	}
	if err := store.CompleteRepoScan(ctx, thirdScan.ID, "succeeded", now.Add(48*time.Hour+time.Minute), 10, 8, 1, false, db.RepoScanContext{ScanMode: "deep"}, ""); err != nil {
		t.Fatalf("complete third repo scan: %v", err)
	}

	reopened, err := svc.ListRepoFindings(ctx, 10, db.RepoFindingFilter{
		Status:        string(domain.RepoFindingLifecycleReopened),
		Repository:    "owner/repo",
		Detector:      "github_token",
		Owner:         "platform",
		MinConfidence: 0.9,
		MinAgeDays:    1,
		Now:           now.Add(49 * time.Hour),
	})
	if err != nil {
		t.Fatalf("list reopened repo findings: %v", err)
	}
	if len(reopened) != 1 || reopened[0].ID != "finding:second-commit" {
		t.Fatalf("expected latest reopened finding only, got %+v", reopened)
	}
	if reopened[0].FirstSeenAt == nil || !reopened[0].FirstSeenAt.Equal(now) {
		t.Fatalf("expected first_seen_at to be preserved from first scan, got %+v", reopened[0].FirstSeenAt)
	}
	if reopened[0].LastSeenAt == nil || !reopened[0].LastSeenAt.Equal(now.Add(48*time.Hour)) {
		t.Fatalf("expected last_seen_at from reopened scan, got %+v", reopened[0].LastSeenAt)
	}
	if reopened[0].ReopenedAt == nil {
		t.Fatalf("expected reopened_at to be populated, got %+v", reopened[0])
	}

	svc.Now = func() time.Time { return now.Add(10 * 24 * time.Hour) }
	summary, err := svc.GetRepoFindingsSummary(ctx, db.RepoFindingFilter{Repository: "owner/repo"})
	if err != nil {
		t.Fatalf("summarize repo findings: %v", err)
	}
	if summary.TotalOpen != 1 || summary.ReopenedCount != 1 || summary.FixedCount != 0 || summary.SLAAgedCount != 1 {
		t.Fatalf("unexpected repo finding summary: %+v", summary)
	}
}

func TestServiceGetFinding(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC)
	scan, _ := store.CreateScan(defaultScopeContext(), "aws", now)
	_ = store.UpsertFindings(defaultScopeContext(), scan.ID, []domain.Finding{
		{ID: "finding-1", Type: domain.FindingOwnerless, Severity: domain.SeverityHigh, CreatedAt: now},
	})

	svc := NewService(store, fakeScanner{}, "aws")
	found, err := svc.GetFinding(defaultScopeContext(), "finding-1", scan.ID)
	if err != nil {
		t.Fatalf("get finding: %v", err)
	}
	if found.ID != "finding-1" {
		t.Fatalf("unexpected finding id: %q", found.ID)
	}

	if _, err := svc.GetFinding(defaultScopeContext(), "missing", scan.ID); !errors.Is(err, db.ErrNotFound) {
		t.Fatalf("expected not found for missing finding, got %v", err)
	}
}

func TestServiceGetFindingBeyondListWindow(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC)
	scan, _ := store.CreateScan(defaultScopeContext(), "aws", now)

	findings := make([]domain.Finding, 0, 6001)
	for i := 0; i < 6001; i++ {
		id := fmt.Sprintf("finding-%04d", i)
		findings = append(findings, domain.Finding{
			ID:        id,
			Type:      domain.FindingOwnerless,
			Severity:  domain.SeverityHigh,
			CreatedAt: now.Add(time.Duration(i) * time.Second),
		})
	}
	if err := store.UpsertFindings(defaultScopeContext(), scan.ID, findings); err != nil {
		t.Fatalf("upsert findings: %v", err)
	}

	svc := NewService(store, fakeScanner{}, "aws")
	found, err := svc.GetFinding(defaultScopeContext(), "finding-0000", scan.ID)
	if err != nil {
		t.Fatalf("get finding beyond previous list window: %v", err)
	}
	if found.ID != "finding-0000" {
		t.Fatalf("unexpected finding id: %q", found.ID)
	}
}

func TestServiceFindingTriageLifecycleAndHistory(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 3, 22, 9, 0, 0, 0, time.UTC)
	scan, err := store.CreateScan(defaultScopeContext(), "aws", now)
	if err != nil {
		t.Fatalf("create scan: %v", err)
	}
	if err := store.UpsertFindings(defaultScopeContext(), scan.ID, []domain.Finding{
		{ID: "finding-1", Type: domain.FindingOwnerless, Severity: domain.SeverityHigh, CreatedAt: now},
	}); err != nil {
		t.Fatalf("upsert findings: %v", err)
	}

	clock := now
	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return clock }

	initial, err := svc.GetFinding(defaultScopeContext(), "finding-1", scan.ID)
	if err != nil {
		t.Fatalf("get initial finding: %v", err)
	}
	if initial.Triage.Status != domain.FindingLifecycleOpen {
		t.Fatalf("expected default open status, got %q", initial.Triage.Status)
	}

	suppressed := string(domain.FindingLifecycleSuppressed)
	assignee := "secops"
	suppressionExpiry := clock.Add(2 * time.Hour).Format(time.RFC3339)
	updated, err := svc.TriageFinding(
		defaultScopeContext(),
		"finding-1",
		scan.ID,
		FindingTriageRequest{
			Status:               &suppressed,
			Assignee:             &assignee,
			SuppressionExpiresAt: &suppressionExpiry,
			Comment:              "accepted risk until patch lands",
		},
		"subject:user-1",
	)
	if err != nil {
		t.Fatalf("triage finding: %v", err)
	}
	if updated.Triage.Status != domain.FindingLifecycleSuppressed {
		t.Fatalf("expected suppressed status, got %q", updated.Triage.Status)
	}
	if updated.Triage.Assignee != "secops" {
		t.Fatalf("expected assignee secops, got %q", updated.Triage.Assignee)
	}
	if updated.Triage.SuppressionExpiresAt == nil {
		t.Fatal("expected suppression expiry to be set")
	}
	if updated.Triage.UpdatedBy != "subject:user-1" {
		t.Fatalf("expected triage actor to be persisted, got %q", updated.Triage.UpdatedBy)
	}

	history, err := svc.ListFindingTriageHistory(defaultScopeContext(), "finding-1", scan.ID, 10)
	if err != nil {
		t.Fatalf("list triage history: %v", err)
	}
	if len(history) != 1 {
		t.Fatalf("expected one triage event, got %d", len(history))
	}
	if history[0].Action != db.FindingTriageActionSuppressed {
		t.Fatalf("expected suppressed action, got %q", history[0].Action)
	}
	if history[0].FromStatus != domain.FindingLifecycleOpen || history[0].ToStatus != domain.FindingLifecycleSuppressed {
		t.Fatalf("unexpected status transition: %+v", history[0])
	}

	suppressedItems, err := svc.ListFindingsFiltered(defaultScopeContext(), 10, FindingsFilter{
		LifecycleStatus: "suppressed",
		Assignee:        "SECOPS",
	})
	if err != nil {
		t.Fatalf("list suppressed findings: %v", err)
	}
	if len(suppressedItems) != 1 || suppressedItems[0].ID != "finding-1" {
		t.Fatalf("unexpected suppressed filter result: %+v", suppressedItems)
	}

	clock = clock.Add(3 * time.Hour)
	reopened, err := svc.GetFinding(defaultScopeContext(), "finding-1", scan.ID)
	if err != nil {
		t.Fatalf("get finding after suppression expiry: %v", err)
	}
	if reopened.Triage.Status != domain.FindingLifecycleOpen {
		t.Fatalf("expected suppression expiry to reopen finding, got %q", reopened.Triage.Status)
	}
	if reopened.Triage.SuppressionExpiresAt != nil {
		t.Fatalf("expected suppression expiry cleared after expiration, got %v", reopened.Triage.SuppressionExpiresAt)
	}
}

func TestServiceFindingTriageResolvedAtLifecycle(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 4, 1, 8, 0, 0, 0, time.UTC)
	scan, err := store.CreateScan(defaultScopeContext(), "aws", now)
	if err != nil {
		t.Fatalf("create scan: %v", err)
	}
	if err := store.UpsertFindings(defaultScopeContext(), scan.ID, []domain.Finding{
		{ID: "finding-1", Type: domain.FindingOwnerless, Severity: domain.SeverityHigh, CreatedAt: now},
	}); err != nil {
		t.Fatalf("upsert findings: %v", err)
	}

	clock := now
	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return clock }

	resolved := string(domain.FindingLifecycleResolved)
	open := string(domain.FindingLifecycleOpen)

	// Transition into resolved records the actual resolution time.
	resolvedTime := clock
	got, err := svc.TriageFinding(defaultScopeContext(), "finding-1", scan.ID,
		FindingTriageRequest{Status: &resolved, Comment: "patched"}, "subject:user-1")
	if err != nil {
		t.Fatalf("resolve finding: %v", err)
	}
	if got.Triage.ResolvedAt == nil || !got.Triage.ResolvedAt.Equal(resolvedTime) {
		t.Fatalf("expected resolved_at %v, got %v", resolvedTime, got.Triage.ResolvedAt)
	}

	// The primary filtered findings list must also expose resolved_at.
	listed, err := svc.ListFindingsFiltered(defaultScopeContext(), 10, FindingsFilter{LifecycleStatus: "resolved"})
	if err != nil {
		t.Fatalf("list filtered findings: %v", err)
	}
	if len(listed) != 1 || listed[0].Triage.ResolvedAt == nil || !listed[0].Triage.ResolvedAt.Equal(resolvedTime) {
		t.Fatalf("expected filtered list to expose resolved_at %v, got %+v", resolvedTime, listed)
	}

	// A comment while still resolved preserves the original resolution time.
	clock = clock.Add(2 * time.Hour)
	got, err = svc.TriageFinding(defaultScopeContext(), "finding-1", scan.ID,
		FindingTriageRequest{Comment: "still resolved"}, "subject:user-1")
	if err != nil {
		t.Fatalf("comment while resolved: %v", err)
	}
	if got.Triage.ResolvedAt == nil || !got.Triage.ResolvedAt.Equal(resolvedTime) {
		t.Fatalf("expected resolved_at preserved at %v, got %v", resolvedTime, got.Triage.ResolvedAt)
	}

	// Reopening must not keep a stale resolution time.
	clock = clock.Add(time.Hour)
	got, err = svc.TriageFinding(defaultScopeContext(), "finding-1", scan.ID,
		FindingTriageRequest{Status: &open, Comment: "regressed"}, "subject:user-1")
	if err != nil {
		t.Fatalf("reopen finding: %v", err)
	}
	if got.Triage.ResolvedAt != nil {
		t.Fatalf("expected resolved_at cleared after reopen, got %v", got.Triage.ResolvedAt)
	}
	openListed, err := svc.ListFindingsFiltered(defaultScopeContext(), 10, FindingsFilter{LifecycleStatus: "open"})
	if err != nil {
		t.Fatalf("list filtered findings after reopen: %v", err)
	}
	if len(openListed) != 1 || openListed[0].Triage.ResolvedAt != nil {
		t.Fatalf("expected filtered list to drop resolved_at after reopen, got %+v", openListed)
	}

	// Re-resolving records a fresh resolution time, not the prior one.
	clock = clock.Add(4 * time.Hour)
	reResolvedTime := clock
	got, err = svc.TriageFinding(defaultScopeContext(), "finding-1", scan.ID,
		FindingTriageRequest{Status: &resolved, Comment: "patched again"}, "subject:user-1")
	if err != nil {
		t.Fatalf("re-resolve finding: %v", err)
	}
	if got.Triage.ResolvedAt == nil || !got.Triage.ResolvedAt.Equal(reResolvedTime) {
		t.Fatalf("expected fresh resolved_at %v, got %v", reResolvedTime, got.Triage.ResolvedAt)
	}
	if got.Triage.ResolvedAt.Equal(resolvedTime) {
		t.Fatal("re-resolve must not reuse the original resolution time")
	}
}

func TestServiceTriageFindingRejectsInvalidRequest(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 3, 22, 9, 0, 0, 0, time.UTC)
	scan, err := store.CreateScan(defaultScopeContext(), "aws", now)
	if err != nil {
		t.Fatalf("create scan: %v", err)
	}
	if err := store.UpsertFindings(defaultScopeContext(), scan.ID, []domain.Finding{
		{ID: "finding-1", Type: domain.FindingOwnerless, Severity: domain.SeverityHigh, CreatedAt: now},
	}); err != nil {
		t.Fatalf("upsert findings: %v", err)
	}

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }

	if _, err := svc.TriageFinding(defaultScopeContext(), "finding-1", scan.ID, FindingTriageRequest{}, "subject:user-1"); !errors.Is(err, ErrInvalidFindingTriageRequest) {
		t.Fatalf("expected invalid triage request error for empty payload, got %v", err)
	}

	suppressed := string(domain.FindingLifecycleSuppressed)
	if _, err := svc.TriageFinding(
		defaultScopeContext(),
		"finding-1",
		scan.ID,
		FindingTriageRequest{
			Status: &suppressed,
		},
		"subject:user-1",
	); !errors.Is(err, ErrInvalidFindingTriageRequest) {
		t.Fatalf("expected invalid triage request error for missing suppression reason, got %v", err)
	}

	pastExpiry := now.Add(-1 * time.Hour).Format(time.RFC3339)
	if _, err := svc.TriageFinding(
		defaultScopeContext(),
		"finding-1",
		scan.ID,
		FindingTriageRequest{
			Status:               &suppressed,
			SuppressionExpiresAt: &pastExpiry,
			Comment:              "past exception window",
		},
		"subject:user-1",
	); !errors.Is(err, ErrInvalidFindingTriageRequest) {
		t.Fatalf("expected invalid triage request error for past suppression expiry, got %v", err)
	}

	reason := "accepted test fixture"
	suppressedFinding, err := svc.TriageFinding(
		defaultScopeContext(),
		"finding-1",
		scan.ID,
		FindingTriageRequest{
			Status:  &suppressed,
			Comment: reason,
		},
		"subject:user-1",
	)
	if err != nil {
		t.Fatalf("expected suppression with reason and no expiry to pass: %v", err)
	}
	if suppressedFinding.Triage.Status != domain.FindingLifecycleSuppressed || suppressedFinding.Triage.SuppressionExpiresAt != nil {
		t.Fatalf("expected suppressed finding without expiry, got %+v", suppressedFinding.Triage)
	}

	nextAssignee := "platform"
	updatedSuppressed, err := svc.TriageFinding(
		defaultScopeContext(),
		"finding-1",
		scan.ID,
		FindingTriageRequest{
			Assignee: &nextAssignee,
		},
		"subject:user-1",
	)
	if err != nil {
		t.Fatalf("expected suppressed finding assignee update without new comment to pass: %v", err)
	}
	if updatedSuppressed.Triage.Status != domain.FindingLifecycleSuppressed || updatedSuppressed.Triage.Assignee != nextAssignee {
		t.Fatalf("expected suppressed finding assignee update, got %+v", updatedSuppressed.Triage)
	}

	if _, err := svc.TriageFinding(
		defaultScopeContext(),
		"finding-1",
		scan.ID,
		FindingTriageRequest{
			Status: &suppressed,
		},
		"subject:user-1",
	); !errors.Is(err, ErrInvalidFindingTriageRequest) {
		t.Fatalf("expected explicit suppression request without reason to fail, got %v", err)
	}
}

func TestServiceExportAndImportFindingBaseline(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 3, 23, 11, 0, 0, 0, time.UTC)
	sourceScan, err := store.CreateScan(defaultScopeContext(), "aws", now)
	if err != nil {
		t.Fatalf("create source scan: %v", err)
	}
	targetScan, err := store.CreateScan(defaultScopeContext(), "aws", now.Add(2*time.Hour))
	if err != nil {
		t.Fatalf("create target scan: %v", err)
	}

	sourceFinding := domain.Finding{
		ID:           "finding-1",
		Type:         domain.FindingOwnerless,
		Severity:     domain.SeverityHigh,
		Title:        "Ownerless identity: payments-role",
		HumanSummary: "No ownership metadata is attached to this identity.",
		Path:         []string{"identity:payments-role"},
		Evidence:     map[string]any{"identity_id": "identity:payments-role"},
		CreatedAt:    now,
	}
	targetFinding := sourceFinding
	targetFinding.ID = "finding-2"
	targetFinding.CreatedAt = now.Add(2 * time.Hour)

	if err := store.UpsertFindings(defaultScopeContext(), sourceScan.ID, []domain.Finding{sourceFinding}); err != nil {
		t.Fatalf("upsert source findings: %v", err)
	}
	if err := store.UpsertFindings(defaultScopeContext(), targetScan.ID, []domain.Finding{targetFinding}); err != nil {
		t.Fatalf("upsert target findings: %v", err)
	}

	clock := now
	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return clock }

	suppressed := string(domain.FindingLifecycleSuppressed)
	expiry := clock.Add(24 * time.Hour).Format(time.RFC3339)
	updated, err := svc.TriageFinding(defaultScopeContext(), sourceFinding.ID, sourceScan.ID, FindingTriageRequest{
		Status:               &suppressed,
		SuppressionExpiresAt: &expiry,
		Comment:              "known false positive",
	}, "subject:owner")
	if err != nil {
		t.Fatalf("triage source finding: %v", err)
	}
	if updated.ConfidenceScore <= 0 {
		t.Fatalf("expected exported finding confidence score, got %+v", updated)
	}

	baseline, err := svc.ExportFindingBaseline(defaultScopeContext(), sourceScan.ID, 10)
	if err != nil {
		t.Fatalf("export baseline: %v", err)
	}
	if baseline.SchemaVersion != findingBaselineSchemaVersion || baseline.MatchMode != "exact_fingerprint_v1" {
		t.Fatalf("unexpected baseline metadata: %+v", baseline)
	}
	if len(baseline.Items) != 1 {
		t.Fatalf("expected one baseline item, got %+v", baseline.Items)
	}
	if baseline.Items[0].ConfidenceScore <= 0 || baseline.Items[0].SuppressionExpiresAt == nil {
		t.Fatalf("expected baseline confidence and expiry, got %+v", baseline.Items[0])
	}

	imported, err := svc.ImportFindingBaseline(defaultScopeContext(), FindingBaselineImportRequest{
		ScanID:   targetScan.ID,
		Baseline: baseline,
		Comment:  "carry forward false positive",
	}, "subject:owner")
	if err != nil {
		t.Fatalf("import baseline: %v", err)
	}
	if imported.AppliedCount != 1 || imported.SkippedCount != 0 {
		t.Fatalf("unexpected import counts: %+v", imported)
	}
	if len(imported.Items) != 1 || imported.Items[0].Status != "applied" || imported.Items[0].MatchConfidenceScore < findingBaselineImportMatchThreshold {
		t.Fatalf("unexpected import items: %+v", imported.Items)
	}

	applied, err := svc.GetFinding(defaultScopeContext(), targetFinding.ID, targetScan.ID)
	if err != nil {
		t.Fatalf("get imported finding: %v", err)
	}
	if applied.Triage.Status != domain.FindingLifecycleSuppressed || applied.Triage.SuppressionExpiresAt == nil {
		t.Fatalf("expected imported suppression to apply, got %+v", applied.Triage)
	}
}

func TestServiceImportFindingBaselineSkipsChangedVariants(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 3, 23, 11, 0, 0, 0, time.UTC)
	sourceScan, _ := store.CreateScan(defaultScopeContext(), "aws", now)
	targetScan, _ := store.CreateScan(defaultScopeContext(), "aws", now.Add(2*time.Hour))

	sourceFinding := domain.Finding{
		ID:           "finding-1",
		Type:         domain.FindingOwnerless,
		Severity:     domain.SeverityHigh,
		Title:        "Ownerless identity: payments-role",
		HumanSummary: "No ownership metadata is attached to this identity.",
		Path:         []string{"identity:payments-role"},
		Evidence:     map[string]any{"identity_id": "identity:payments-role"},
		CreatedAt:    now,
	}
	changedVariant := sourceFinding
	changedVariant.ID = "finding-2"
	changedVariant.HumanSummary = "Ownership metadata is still missing after the latest scan."
	changedVariant.CreatedAt = now.Add(2 * time.Hour)

	if err := store.UpsertFindings(defaultScopeContext(), sourceScan.ID, []domain.Finding{sourceFinding}); err != nil {
		t.Fatalf("upsert source findings: %v", err)
	}
	if err := store.UpsertFindings(defaultScopeContext(), targetScan.ID, []domain.Finding{changedVariant}); err != nil {
		t.Fatalf("upsert target findings: %v", err)
	}

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	suppressed := string(domain.FindingLifecycleSuppressed)
	expiry := now.Add(24 * time.Hour).Format(time.RFC3339)
	if _, err := svc.TriageFinding(defaultScopeContext(), sourceFinding.ID, sourceScan.ID, FindingTriageRequest{
		Status:               &suppressed,
		SuppressionExpiresAt: &expiry,
		Comment:              "known false positive",
	}, "subject:owner"); err != nil {
		t.Fatalf("triage source finding: %v", err)
	}

	baseline, err := svc.ExportFindingBaseline(defaultScopeContext(), sourceScan.ID, 10)
	if err != nil {
		t.Fatalf("export baseline: %v", err)
	}

	imported, err := svc.ImportFindingBaseline(defaultScopeContext(), FindingBaselineImportRequest{
		ScanID:   targetScan.ID,
		Baseline: baseline,
	}, "subject:owner")
	if err != nil {
		t.Fatalf("import baseline: %v", err)
	}
	if imported.AppliedCount != 0 || imported.SkippedCount != 1 {
		t.Fatalf("unexpected import counts: %+v", imported)
	}
	if imported.Items[0].Status != "skipped" || imported.Items[0].MatchConfidenceScore >= findingBaselineImportMatchThreshold {
		t.Fatalf("expected changed variant to be skipped, got %+v", imported.Items[0])
	}

	targetState, err := svc.GetFinding(defaultScopeContext(), changedVariant.ID, targetScan.ID)
	if err != nil {
		t.Fatalf("get changed variant: %v", err)
	}
	if targetState.Triage.Status != domain.FindingLifecycleOpen {
		t.Fatalf("expected changed variant to remain open, got %+v", targetState.Triage)
	}
}

func TestServiceImportFindingBaselinePagesLargeScansForFingerprintFallback(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 3, 23, 11, 0, 0, 0, time.UTC)
	sourceScan, _ := store.CreateScan(defaultScopeContext(), "aws", now)
	targetScan, _ := store.CreateScan(defaultScopeContext(), "aws", now.Add(2*time.Hour))

	sourceFinding := domain.Finding{
		ID:           "finding-source",
		Type:         domain.FindingOwnerless,
		Severity:     domain.SeverityHigh,
		Title:        "Ownerless identity: payments-role",
		HumanSummary: "No ownership metadata is attached to this identity.",
		Path:         []string{"identity:payments-role"},
		Evidence:     map[string]any{"identity_id": "identity:payments-role"},
		CreatedAt:    now,
	}
	targetFinding := sourceFinding
	targetFinding.ID = "finding-target"
	targetFinding.CreatedAt = now

	if err := store.UpsertFindings(defaultScopeContext(), sourceScan.ID, []domain.Finding{sourceFinding}); err != nil {
		t.Fatalf("upsert source findings: %v", err)
	}

	targetFindings := make([]domain.Finding, 0, 5201)
	for i := 0; i < 5200; i++ {
		targetFindings = append(targetFindings, domain.Finding{
			ID:           fmt.Sprintf("noise-%04d", i),
			Type:         domain.FindingOwnerless,
			Severity:     domain.SeverityLow,
			Title:        fmt.Sprintf("Noise finding %04d", i),
			HumanSummary: "Synthetic filler finding",
			Path:         []string{fmt.Sprintf("identity:noise-%04d", i)},
			Evidence:     map[string]any{"identity_id": fmt.Sprintf("identity:noise-%04d", i)},
			CreatedAt:    now.Add(time.Duration(i+1) * time.Second),
		})
	}
	targetFindings = append(targetFindings, targetFinding)
	if err := store.UpsertFindings(defaultScopeContext(), targetScan.ID, targetFindings); err != nil {
		t.Fatalf("upsert target findings: %v", err)
	}

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	suppressed := string(domain.FindingLifecycleSuppressed)
	expiry := now.Add(24 * time.Hour).Format(time.RFC3339)
	if _, err := svc.TriageFinding(defaultScopeContext(), sourceFinding.ID, sourceScan.ID, FindingTriageRequest{
		Status:               &suppressed,
		SuppressionExpiresAt: &expiry,
		Comment:              "known false positive",
	}, "subject:owner"); err != nil {
		t.Fatalf("triage source finding: %v", err)
	}

	baseline, err := svc.ExportFindingBaseline(defaultScopeContext(), sourceScan.ID, 10)
	if err != nil {
		t.Fatalf("export baseline: %v", err)
	}

	imported, err := svc.ImportFindingBaseline(defaultScopeContext(), FindingBaselineImportRequest{
		ScanID:   targetScan.ID,
		Baseline: baseline,
	}, "subject:owner")
	if err != nil {
		t.Fatalf("import baseline: %v", err)
	}
	if imported.AppliedCount != 1 || imported.SkippedCount != 0 {
		t.Fatalf("unexpected import counts for paged scan: %+v", imported)
	}
	if imported.Items[0].FindingID != targetFinding.ID || imported.Items[0].Status != "applied" {
		t.Fatalf("expected paged fallback to apply to target finding, got %+v", imported.Items[0])
	}

	applied, err := svc.GetFinding(defaultScopeContext(), targetFinding.ID, targetScan.ID)
	if err != nil {
		t.Fatalf("get paged target finding: %v", err)
	}
	if applied.Triage.Status != domain.FindingLifecycleSuppressed || applied.Triage.SuppressionExpiresAt == nil {
		t.Fatalf("expected paged target finding to be suppressed, got %+v", applied.Triage)
	}
}

func TestServiceGetFindingExports(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC)
	scan, _ := store.CreateScan(defaultScopeContext(), "aws", now)
	_ = store.UpsertFindings(defaultScopeContext(), scan.ID, []domain.Finding{
		{
			ID:        "finding-1",
			Type:      domain.FindingOverPrivileged,
			Severity:  domain.SeverityHigh,
			Title:     "Overprivileged role",
			CreatedAt: now,
		},
	})

	svc := NewService(store, fakeScanner{}, "aws")
	exports, err := svc.GetFindingExports(defaultScopeContext(), "finding-1", scan.ID)
	if err != nil {
		t.Fatalf("get finding exports: %v", err)
	}
	findingInfo, ok := exports.OCSF["finding_info"].(map[string]any)
	if !ok {
		t.Fatalf("expected finding_info object, got %+v", exports.OCSF)
	}
	if findingInfo["uid"] != "finding-1" {
		t.Fatalf("expected OCSF payload, got %+v", exports.OCSF)
	}
	if exports.ASFF["SchemaVersion"] != "2018-10-08" {
		t.Fatalf("expected ASFF schema version, got %+v", exports.ASFF)
	}
}

func TestServiceGetScanDiff(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC)

	first, err := store.CreateScan(defaultScopeContext(), "aws", now)
	if err != nil {
		t.Fatalf("create first scan: %v", err)
	}
	if err := store.UpsertFindings(defaultScopeContext(), first.ID, []domain.Finding{
		{ID: "persist", Type: domain.FindingOwnerless, Severity: domain.SeverityHigh, CreatedAt: now.Add(1 * time.Second)},
		{ID: "resolved", Type: domain.FindingStaleIdentity, Severity: domain.SeverityMedium, CreatedAt: now.Add(2 * time.Second)},
	}); err != nil {
		t.Fatalf("seed first findings: %v", err)
	}

	second, err := store.CreateScan(defaultScopeContext(), "aws", now.Add(10*time.Minute))
	if err != nil {
		t.Fatalf("create second scan: %v", err)
	}
	if err := store.UpsertFindings(defaultScopeContext(), second.ID, []domain.Finding{
		{ID: "persist", Type: domain.FindingOwnerless, Severity: domain.SeverityHigh, CreatedAt: now.Add(11 * time.Minute)},
		{ID: "added", Type: domain.FindingEscalationPath, Severity: domain.SeverityCritical, CreatedAt: now.Add(12 * time.Minute)},
	}); err != nil {
		t.Fatalf("seed second findings: %v", err)
	}

	svc := NewService(store, fakeScanner{}, "aws")
	diff, err := svc.GetScanDiff(defaultScopeContext(), second.ID, 10)
	if err != nil {
		t.Fatalf("get scan diff: %v", err)
	}
	if diff.PreviousScanID != first.ID {
		t.Fatalf("expected previous scan %q, got %q", first.ID, diff.PreviousScanID)
	}
	if diff.AddedCount != 1 || diff.ResolvedCount != 1 || diff.PersistingCount != 1 {
		t.Fatalf("unexpected diff counts: %+v", diff)
	}
}

func TestServiceGetScanDiffAgainst(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC)

	first, _ := store.CreateScan(defaultScopeContext(), "aws", now)
	_ = store.UpsertFindings(defaultScopeContext(), first.ID, []domain.Finding{
		{ID: "persist", Severity: domain.SeverityHigh, CreatedAt: now.Add(1 * time.Second)},
		{ID: "resolved", Severity: domain.SeverityMedium, CreatedAt: now.Add(2 * time.Second)},
	})
	second, _ := store.CreateScan(defaultScopeContext(), "aws", now.Add(5*time.Minute))
	_ = store.UpsertFindings(defaultScopeContext(), second.ID, []domain.Finding{
		{ID: "persist", Severity: domain.SeverityHigh, CreatedAt: now.Add(5 * time.Minute)},
		{ID: "added", Severity: domain.SeverityCritical, CreatedAt: now.Add(6 * time.Minute)},
	})

	svc := NewService(store, fakeScanner{}, "aws")
	diff, err := svc.GetScanDiffAgainst(defaultScopeContext(), second.ID, first.ID, 10)
	if err != nil {
		t.Fatalf("get scan diff against baseline: %v", err)
	}
	if diff.PreviousScanID != first.ID || diff.AddedCount != 1 || diff.ResolvedCount != 1 {
		t.Fatalf("unexpected diff against baseline: %+v", diff)
	}
}

func TestServiceGetScanDiffAgainstRejectsInvalidBaseline(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC)

	current, _ := store.CreateScan(defaultScopeContext(), "aws", now)
	previous, _ := store.CreateScan(defaultScopeContext(), "aws", now.Add(-5*time.Minute))
	wrongProvider, _ := store.CreateScan(defaultScopeContext(), "azure", now.Add(-10*time.Minute))
	newerBaseline, _ := store.CreateScan(defaultScopeContext(), "aws", now.Add(10*time.Minute))

	svc := NewService(store, fakeScanner{}, "aws")

	if _, err := svc.GetScanDiffAgainst(defaultScopeContext(), current.ID, current.ID, 10); !errors.Is(err, ErrInvalidScanDiffBaseline) {
		t.Fatalf("expected invalid baseline when baseline==current, got %v", err)
	}
	if _, err := svc.GetScanDiffAgainst(defaultScopeContext(), current.ID, wrongProvider.ID, 10); !errors.Is(err, ErrInvalidScanDiffBaseline) {
		t.Fatalf("expected invalid baseline provider error, got %v", err)
	}
	if _, err := svc.GetScanDiffAgainst(defaultScopeContext(), current.ID, newerBaseline.ID, 10); !errors.Is(err, ErrInvalidScanDiffBaseline) {
		t.Fatalf("expected invalid baseline time ordering error, got %v", err)
	}
	if _, err := svc.GetScanDiffAgainst(defaultScopeContext(), current.ID, previous.ID, 10); err != nil {
		t.Fatalf("expected valid older baseline, got %v", err)
	}
}

func TestServiceListScanEvents(t *testing.T) {
	store := db.NewMemoryStore()
	svc := NewService(store, fakeScanner{result: app.ScanResult{}}, "aws")
	svc.Now = func() time.Time { return time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC) }

	result, err := svc.RunScan(defaultScopeContext())
	if err != nil {
		t.Fatalf("run scan: %v", err)
	}
	events, err := svc.ListScanEvents(defaultScopeContext(), result.Scan.ID, 10)
	if err != nil {
		t.Fatalf("list scan events: %v", err)
	}
	if len(events) == 0 {
		t.Fatal("expected scan events")
	}

	if err := store.AppendScanEvent(defaultScopeContext(), result.Scan.ID, db.ScanEventLevelError, "forced error", nil); err != nil {
		t.Fatalf("append error event: %v", err)
	}
	errorEvents, err := svc.ListScanEventsFiltered(defaultScopeContext(), result.Scan.ID, db.ScanEventLevelError, 20)
	if err != nil {
		t.Fatalf("list filtered scan events: %v", err)
	}
	if len(errorEvents) == 0 {
		t.Fatal("expected at least one error-level event")
	}
}

func TestServiceRunScanPartialLifecycleEvents(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 3, 19, 10, 0, 0, 0, time.UTC)
	svc := NewService(store, fakeScanner{result: app.ScanResult{
		Assets: 1,
		Bundle: providers.NormalizedBundle{
			Identities: []domain.Identity{{
				ID:       "aws:identity:arn:aws:iam::123456789012:role/demo",
				Provider: domain.ProviderAWS,
				Type:     domain.IdentityTypeRole,
				Name:     "demo",
			}},
		},
		SourceErrors: []providers.SourceError{{
			Collector: "aws_iam_collector",
			Code:      "missing_role_arn",
			Message:   "skipped IAM role record without ARN",
		}},
	}}, "aws")
	svc.Now = func() time.Time { return now }

	result, err := svc.RunScan(defaultScopeContext())
	if err != nil {
		t.Fatalf("run scan: %v", err)
	}
	if result.Scan.Status != "succeeded" {
		t.Fatalf("expected succeeded scan status, got %q", result.Scan.Status)
	}

	events, err := svc.ListScanEvents(defaultScopeContext(), result.Scan.ID, 50)
	if err != nil {
		t.Fatalf("list scan events: %v", err)
	}
	states := map[string]bool{}
	for _, event := range events {
		state, _ := event.Metadata["state"].(string)
		if state != "" {
			states[state] = true
		}
	}
	for _, expected := range []string{scanLifecycleQueued, scanLifecycleRunning, scanLifecyclePartial, scanLifecycleSucceeded} {
		if !states[expected] {
			t.Fatalf("expected lifecycle state %q in events, got %+v", expected, states)
		}
	}
}

func TestServiceRunScanPersistsRawAndNormalizedArtifactsConsistently(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 3, 20, 11, 0, 0, 0, time.UTC)
	identityID := "aws:identity:arn:aws:iam::123456789012:role/demo"
	policyID := "aws:policy:demo"
	relationshipID := "rel-attached-policy"

	svc := NewService(store, fakeScanner{result: app.ScanResult{
		Assets: 1,
		RawAssets: []providers.RawAsset{
			{
				Kind:      "aws_iam_role",
				SourceID:  "arn:aws:iam::123456789012:role/demo",
				Payload:   []byte(`{"RoleName":"demo"}`),
				Collected: now.Format(time.RFC3339Nano),
			},
		},
		Bundle: providers.NormalizedBundle{
			Identities: []domain.Identity{
				{
					ID:       identityID,
					Provider: domain.ProviderAWS,
					Type:     domain.IdentityTypeRole,
					Name:     "demo",
					ARN:      "arn:aws:iam::123456789012:role/demo",
					RawRef:   "aws_iam_role:arn:aws:iam::123456789012:role/demo",
				},
			},
			Policies: []domain.Policy{
				{
					ID:       policyID,
					Provider: domain.ProviderAWS,
					Name:     "demo-inline",
					RawRef:   "aws_iam_policy:demo-inline",
					Normalized: map[string]any{
						"policy_type": "permission",
						"identity_id": identityID,
						"statements": []map[string]any{
							{"effect": "Allow", "actions": []string{"s3:GetObject"}, "resources": []string{"*"}},
						},
					},
				},
			},
		},
		Permissions: []providers.PermissionTuple{
			{
				IdentityID: identityID,
				Action:     "s3:GetObject",
				Resource:   "*",
				Effect:     "Allow",
			},
		},
		Relationships: []domain.Relationship{
			{
				ID:           relationshipID,
				Type:         domain.RelationshipAttachedPolicy,
				FromNodeID:   identityID,
				ToNodeID:     policyID,
				DiscoveredAt: now,
			},
		},
		Findings: []domain.Finding{
			{
				ID:           "finding-ownerless",
				Type:         domain.FindingOwnerless,
				Severity:     domain.SeverityMedium,
				Title:        "Ownerless identity",
				HumanSummary: "Identity has no owner hint",
				Remediation:  "Assign team owner",
				CreatedAt:    now,
			},
		},
	}}, "aws")
	svc.Now = func() time.Time { return now }

	result, err := svc.RunScan(defaultScopeContext())
	if err != nil {
		t.Fatalf("run scan: %v", err)
	}
	if result.Assets != 1 || result.FindingCount != 1 {
		t.Fatalf("unexpected run result: %+v", result)
	}

	identities, err := svc.ListIdentities(defaultScopeContext(), result.Scan.ID, "aws", "role", "", 10)
	if err != nil {
		t.Fatalf("list identities: %v", err)
	}
	if len(identities) != 1 || identities[0].ID != identityID {
		t.Fatalf("unexpected identities: %+v", identities)
	}

	relationships, err := svc.ListRelationships(defaultScopeContext(), result.Scan.ID, string(domain.RelationshipAttachedPolicy), "", "", 10)
	if err != nil {
		t.Fatalf("list relationships: %v", err)
	}
	if len(relationships) != 1 || relationships[0].ID != relationshipID {
		t.Fatalf("unexpected relationships: %+v", relationships)
	}

	findings, err := svc.ListFindingsFiltered(defaultScopeContext(), 10, FindingsFilter{ScanID: result.Scan.ID})
	if err != nil {
		t.Fatalf("list findings filtered: %v", err)
	}
	if len(findings) != 1 || findings[0].ID != "finding-ownerless" {
		t.Fatalf("unexpected findings: %+v", findings)
	}
}

func TestServiceListIdentitiesAndRelationshipsDefaultsToLatestScan(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC)

	scanA, err := store.CreateScan(defaultScopeContext(), "aws", now)
	if err != nil {
		t.Fatalf("create scan A: %v", err)
	}
	if err := store.UpsertArtifacts(defaultScopeContext(), scanA.ID, db.ScanArtifacts{
		Bundle: providers.NormalizedBundle{
			Identities: []domain.Identity{{ID: "id-1", Provider: domain.ProviderAWS, Type: domain.IdentityTypeRole, Name: "app-a", RawRef: "raw-a"}},
		},
		Relationships: []domain.Relationship{{ID: "rel-1", Type: domain.RelationshipCanAssume, FromNodeID: "id-1", ToNodeID: "id-2", DiscoveredAt: now}},
	}); err != nil {
		t.Fatalf("seed artifacts A: %v", err)
	}

	scanB, err := store.CreateScan(defaultScopeContext(), "aws", now.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("create scan B: %v", err)
	}
	if err := store.UpsertArtifacts(defaultScopeContext(), scanB.ID, db.ScanArtifacts{
		Bundle: providers.NormalizedBundle{
			Identities: []domain.Identity{{ID: "id-2", Provider: domain.ProviderAWS, Type: domain.IdentityTypeRole, Name: "app-b", RawRef: "raw-b"}},
		},
		Relationships: []domain.Relationship{{ID: "rel-2", Type: domain.RelationshipCanAccess, FromNodeID: "id-2", ToNodeID: "bucket-1", DiscoveredAt: now.Add(1 * time.Minute)}},
	}); err != nil {
		t.Fatalf("seed artifacts B: %v", err)
	}

	svc := NewService(store, fakeScanner{}, "aws")
	identities, err := svc.ListIdentities(defaultScopeContext(), "", "aws", "role", "app", 10)
	if err != nil {
		t.Fatalf("list identities: %v", err)
	}
	if len(identities) != 1 || identities[0].ID != "id-2" {
		t.Fatalf("unexpected identities from latest scan: %+v", identities)
	}

	relationships, err := svc.ListRelationships(defaultScopeContext(), "", "can_access", "", "", 10)
	if err != nil {
		t.Fatalf("list relationships: %v", err)
	}
	if len(relationships) != 1 || relationships[0].ID != "rel-2" {
		t.Fatalf("unexpected relationships from latest scan: %+v", relationships)
	}
}

func TestServiceListOwnershipSignals(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 3, 17, 18, 0, 0, 0, time.UTC)
	scan, err := store.CreateScan(defaultScopeContext(), "aws", now)
	if err != nil {
		t.Fatalf("create scan: %v", err)
	}
	if err := store.UpsertArtifacts(defaultScopeContext(), scan.ID, db.ScanArtifacts{
		Bundle: providers.NormalizedBundle{
			Identities: []domain.Identity{
				{
					ID:        "id-owner-hint",
					Provider:  domain.ProviderAWS,
					Type:      domain.IdentityTypeRole,
					Name:      "app-a",
					OwnerHint: "platform",
					RawRef:    "raw-a",
				},
				{
					ID:       "id-tags",
					Provider: domain.ProviderAWS,
					Type:     domain.IdentityTypeRole,
					Name:     "app-b",
					Tags: map[string]string{
						"team":       "payments",
						"repository": "github.com/acme/payments",
					},
					RawRef: "raw-b",
				},
			},
		},
	}); err != nil {
		t.Fatalf("upsert artifacts: %v", err)
	}

	svc := NewService(store, fakeScanner{}, "aws")
	signals, err := svc.ListOwnershipSignals(defaultScopeContext(), 10, OwnershipFilter{ScanID: scan.ID})
	if err != nil {
		t.Fatalf("list ownership signals: %v", err)
	}
	if len(signals) != 2 {
		t.Fatalf("expected 2 ownership signals, got %d", len(signals))
	}
	if signals[0].IdentityID != "id-owner-hint" || signals[0].Source != "owner_hint" {
		t.Fatalf("unexpected top signal %+v", signals[0])
	}
}

func TestServiceGetFindingsTrend(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC)

	scanA, _ := store.CreateScan(defaultScopeContext(), "aws", now)
	_ = store.UpsertFindings(defaultScopeContext(), scanA.ID, []domain.Finding{
		{ID: "f1", Severity: domain.SeverityHigh, CreatedAt: now},
	})
	scanB, _ := store.CreateScan(defaultScopeContext(), "aws", now.Add(3*time.Minute))
	_ = store.UpsertFindings(defaultScopeContext(), scanB.ID, []domain.Finding{
		{ID: "f2", Severity: domain.SeverityCritical, CreatedAt: now.Add(3 * time.Minute)},
		{ID: "f3", Severity: domain.SeverityMedium, CreatedAt: now.Add(3 * time.Minute)},
	})

	svc := NewService(store, fakeScanner{}, "aws")
	points, err := svc.GetFindingsTrend(defaultScopeContext(), 10)
	if err != nil {
		t.Fatalf("get findings trend: %v", err)
	}
	if len(points) != 2 {
		t.Fatalf("expected 2 trend points, got %d", len(points))
	}
	if points[0].ScanID != scanA.ID || points[1].ScanID != scanB.ID {
		t.Fatalf("unexpected trend order: %+v", points)
	}
	if points[1].BySeverity["critical"] != 1 {
		t.Fatalf("unexpected severity bucket: %+v", points[1].BySeverity)
	}
}

func TestServiceGetFindingsTrendFiltered(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC)
	scan, _ := store.CreateScan(defaultScopeContext(), "aws", now)
	_ = store.UpsertFindings(defaultScopeContext(), scan.ID, []domain.Finding{
		{ID: "f1", Severity: domain.SeverityCritical, Type: domain.FindingEscalationPath, CreatedAt: now},
		{ID: "f2", Severity: domain.SeverityHigh, Type: domain.FindingOwnerless, CreatedAt: now},
	})

	svc := NewService(store, fakeScanner{}, "aws")
	points, err := svc.GetFindingsTrendFiltered(defaultScopeContext(), 10, "critical", "escalation_path")
	if err != nil {
		t.Fatalf("trend filtered: %v", err)
	}
	if len(points) != 1 || points[0].Total != 1 {
		t.Fatalf("unexpected filtered points: %+v", points)
	}
}

func TestServiceGetRepoFindingsTrend(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC)
	ctx := defaultScopeContext()

	scanA, err := store.CreateRepoScan(ctx, "owner/repo-a", db.RepoScanSource{}, db.RepoScanContext{}, now)
	if err != nil {
		t.Fatalf("create repo scan A: %v", err)
	}
	if err := store.UpsertRepoFindings(ctx, scanA.ID, []domain.Finding{
		{ID: "f1", Severity: domain.SeverityHigh, Type: domain.FindingOwnerless, CreatedAt: now},
	}); err != nil {
		t.Fatalf("upsert repo findings for scan A: %v", err)
	}

	scanB, err := store.CreateRepoScan(ctx, "owner/repo-b", db.RepoScanSource{}, db.RepoScanContext{}, now.Add(3*time.Minute))
	if err != nil {
		t.Fatalf("create repo scan B: %v", err)
	}
	if err := store.UpsertRepoFindings(ctx, scanB.ID, []domain.Finding{
		{ID: "f2", Severity: domain.SeverityCritical, Type: domain.FindingEscalationPath, CreatedAt: now.Add(3 * time.Minute)},
	}); err != nil {
		t.Fatalf("upsert repo findings for scan B: %v", err)
	}

	svc := NewService(store, fakeScanner{}, "aws")
	points, err := svc.GetRepoFindingsTrend(ctx, 10)
	if err != nil {
		t.Fatalf("get repo findings trend: %v", err)
	}
	if len(points) != 2 {
		t.Fatalf("expected 2 repo trend points, got %d", len(points))
	}
	if points[0].ScanID != scanA.ID || points[1].ScanID != scanB.ID {
		t.Fatalf("unexpected repo trend order: %+v", points)
	}
	if points[1].BySeverity["critical"] != 1 {
		t.Fatalf("unexpected critical total in latest repo trend point: %+v", points[1])
	}
}

func TestServiceGetRepoFindingsTrendFiltered(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC)
	ctx := defaultScopeContext()

	scanA, err := store.CreateRepoScan(ctx, "owner/repo-a", db.RepoScanSource{}, db.RepoScanContext{}, now)
	if err != nil {
		t.Fatalf("create repo scan A: %v", err)
	}
	if err := store.UpsertRepoFindings(ctx, scanA.ID, []domain.Finding{
		{ID: "f1", Severity: domain.SeverityCritical, Type: domain.FindingEscalationPath, ConfidenceScore: 0.92, CreatedAt: now},
		{ID: "f2", Severity: domain.SeverityHigh, Type: domain.FindingOwnerless, ConfidenceScore: 0.88, CreatedAt: now},
	}); err != nil {
		t.Fatalf("upsert repo findings for scan A: %v", err)
	}

	scanB, err := store.CreateRepoScan(ctx, "owner/repo-b", db.RepoScanSource{}, db.RepoScanContext{}, now.Add(3*time.Minute))
	if err != nil {
		t.Fatalf("create repo scan B: %v", err)
	}
	if err := store.UpsertRepoFindings(ctx, scanB.ID, []domain.Finding{
		{ID: "f3", Severity: domain.SeverityLow, Type: domain.FindingOwnerless, ConfidenceScore: 0.95, CreatedAt: now.Add(3 * time.Minute)},
	}); err != nil {
		t.Fatalf("upsert repo findings for scan B: %v", err)
	}

	svc := NewService(store, fakeScanner{}, "aws")
	points, err := svc.GetRepoFindingsTrendFiltered(ctx, 10, "critical", "escalation_path", 0)
	if err != nil {
		t.Fatalf("get filtered repo findings trend: %v", err)
	}
	if len(points) != 2 || points[0].Total != 1 || points[1].Total != 0 {
		t.Fatalf("unexpected filtered repo trend points: %+v", points)
	}

	confidencePoints, err := svc.GetRepoFindingsTrendFiltered(ctx, 10, "", "", 0.9)
	if err != nil {
		t.Fatalf("get confidence-filtered repo findings trend: %v", err)
	}
	if len(confidencePoints) != 2 || confidencePoints[0].Total != 1 || confidencePoints[1].Total != 1 {
		t.Fatalf("unexpected confidence-filtered repo trend points: %+v", confidencePoints)
	}
}

func TestServiceRunRepoScanSuccess(t *testing.T) {
	store := db.NewMemoryStore()
	svc := NewService(store, fakeScanner{}, "aws")
	svc.RepoScanAllowedTargets = []string{"owner/repo"}
	executor := &fakeRepoExecutor{
		result: repoexposure.ScanResult{
			Repository:     "owner/repo",
			CommitsScanned: 10,
			FilesScanned:   4,
			Findings: []domain.Finding{
				{ID: "f1", Type: domain.FindingSecretExposure, Severity: domain.SeverityHigh},
			},
		},
	}
	var gotHistory, gotMax int
	svc.RepoScannerFactory = func(historyLimit int, maxFindings int) RepoScanExecutor {
		gotHistory, gotMax = historyLimit, maxFindings
		return executor
	}

	result, err := svc.RunRepoScan(defaultScopeContext(), RepoScanRequest{
		Repository:   "owner/repo",
		HistoryLimit: 800,
		MaxFindings:  300,
	})
	if err != nil {
		t.Fatalf("run repo scan: %v", err)
	}
	if result.Repository != "owner/repo" || len(result.Findings) != 1 {
		t.Fatalf("unexpected result: %+v", result)
	}
	if executor.target != "owner/repo" {
		t.Fatalf("unexpected scan target: %q", executor.target)
	}
	if gotHistory != 800 || gotMax != 300 {
		t.Fatalf("unexpected scanner args history=%d max=%d", gotHistory, gotMax)
	}
}

func TestServiceRunRepoScanFiltersLowSignalFindings(t *testing.T) {
	findings := []domain.Finding{
		{ID: "high-confidence-secret", Type: domain.FindingSecretExposure, Severity: domain.SeverityHigh, ConfidenceScore: 0.95},
		{ID: "lower-confidence-policy", Type: domain.FindingOverPrivileged, Severity: domain.SeverityHigh, ConfidenceScore: 0.78},
		{ID: "high-confidence-medium", Type: domain.FindingRepoMisconfig, Severity: domain.SeverityMedium, ConfidenceScore: 0.95},
	}

	filtered := filterReportableRepoFindings(findings)
	if len(filtered) != 1 || filtered[0].ID != "high-confidence-secret" {
		t.Fatalf("expected only high-confidence finding to remain, got %+v", filtered)
	}
	if filtered[0].ConfidenceScore < gitHubRepoFindingConfidenceFloor {
		t.Fatalf("expected remaining finding to meet confidence floor, got %.2f", filtered[0].ConfidenceScore)
	}
	if !isHighImpactRepoFinding(filtered[0]) {
		t.Fatalf("expected remaining finding to meet severity floor, got %q", filtered[0].Severity)
	}
}

func TestServiceRunRepoScanKeepsLowSignalFindingsForManualScans(t *testing.T) {
	store := db.NewMemoryStore()
	svc := NewService(store, fakeScanner{}, "aws")
	svc.RepoScanAllowedTargets = []string{"owner/repo"}
	svc.RepoScannerFactory = func(int, int) RepoScanExecutor {
		return &fakeRepoExecutor{
			result: repoexposure.ScanResult{
				Repository:     "owner/repo",
				CommitsScanned: 1,
				FilesScanned:   2,
				Findings: []domain.Finding{
					{ID: "high-confidence-secret", Type: domain.FindingSecretExposure, Severity: domain.SeverityHigh},
					{ID: "lower-confidence-policy", Type: domain.FindingOverPrivileged, Severity: domain.SeverityHigh},
					{ID: "high-confidence-medium", Type: domain.FindingRepoMisconfig, Severity: domain.SeverityMedium, ConfidenceScore: 0.95},
				},
			},
		}
	}

	result, err := svc.RunRepoScan(defaultScopeContext(), RepoScanRequest{Repository: "owner/repo"})
	if err != nil {
		t.Fatalf("run repo scan: %v", err)
	}
	if len(result.Findings) != 3 {
		t.Fatalf("expected manual scan findings to remain unfiltered, got %+v", result.Findings)
	}
}

func TestServiceRunRepoScanPersistedStoresRecords(t *testing.T) {
	store := db.NewMemoryStore()
	svc := NewService(store, fakeScanner{}, "aws")
	svc.RepoScanAllowedTargets = []string{"owner/repo"}
	svc.Now = func() time.Time { return time.Date(2026, 3, 17, 15, 0, 0, 0, time.UTC) }
	svc.RepoScannerFactory = func(historyLimit int, maxFindings int) RepoScanExecutor {
		redacted := true
		return &fakeRepoExecutor{
			result: repoexposure.ScanResult{
				Repository:     "owner/repo",
				CommitsScanned: historyLimit,
				FilesScanned:   5,
				HeadRevision:   "3333333333333333333333333333333333333333",
				Findings: []domain.Finding{
					{
						ID:                  "rf-1",
						Type:                domain.FindingSecretExposure,
						Severity:            domain.SeverityHigh,
						Commit:              "abc123",
						FilePath:            "config/app.env",
						LineNumber:          7,
						Detector:            "aws-access-key",
						LineSnippet:         "AWS_ACCESS_KEY_ID=AKIA****",
						LineSnippetRedacted: &redacted,
						CreatedAt:           time.Now().UTC(),
					},
				},
				Truncated: false,
			},
		}
	}
	run, err := svc.RunRepoScanPersisted(defaultScopeContext(), RepoScanRequest{
		Repository:   "owner/repo",
		HistoryLimit: 10,
		MaxFindings:  20,
	})
	if err != nil {
		t.Fatalf("run repo scan persisted: %v", err)
	}
	if run.RepoScan.ID == "" || run.RepoScan.Status != "succeeded" || run.RepoScan.FindingCount != 1 {
		t.Fatalf("unexpected repo scan run result: %+v", run)
	}

	stored, err := svc.GetRepoScan(defaultScopeContext(), run.RepoScan.ID)
	if err != nil {
		t.Fatalf("get repo scan: %v", err)
	}
	if stored.ID != run.RepoScan.ID || stored.CommitsScanned != 10 {
		t.Fatalf("unexpected persisted repo scan: %+v", stored)
	}
	if stored.HeadRevision != "3333333333333333333333333333333333333333" {
		t.Fatalf("expected completed scan head revision to be persisted, got %+v", stored)
	}

	findings, err := svc.ListRepoFindings(defaultScopeContext(), 10, db.RepoFindingFilter{RepoScanID: run.RepoScan.ID})
	if err != nil {
		t.Fatalf("list repo findings: %v", err)
	}
	if len(findings) != 1 || findings[0].ID != "rf-1" {
		t.Fatalf("unexpected persisted repo findings: %+v", findings)
	}
	if findings[0].Repository != "owner/repo" {
		t.Fatalf("expected repository metadata, got %+v", findings[0])
	}
	if findings[0].Commit != "abc123" || findings[0].FilePath != "config/app.env" || findings[0].LineNumber != 7 || findings[0].Detector != "aws-access-key" {
		t.Fatalf("expected persisted repo metadata, got %+v", findings[0])
	}
	if findings[0].LineSnippet != "AWS_ACCESS_KEY_ID=AKIA****" || findings[0].LineSnippetRedacted == nil || !*findings[0].LineSnippetRedacted {
		t.Fatalf("expected persisted snippet metadata, got %+v", findings[0])
	}
	if findings[0].SourceURL != "https://github.com/owner/repo/blob/abc123/config/app.env#L7" {
		t.Fatalf("expected GitHub source URL, got %+v", findings[0].SourceURL)
	}
}

func TestServiceRunRepoScanPersistedPersistsComputedDeltaMetadata(t *testing.T) {
	store := db.NewMemoryStore()
	svc := NewService(store, fakeScanner{}, "aws")
	svc.RepoScanAllowedTargets = []string{"owner/repo"}
	request := RepoScanRequest{
		Repository:   "owner/repo",
		ScanMode:     db.RepoScanModeDelta,
		BaseRevision: "1111111111111111111111111111111111111111",
		HeadRevision: "2222222222222222222222222222222222222222",
	}
	svc.RepoScannerFactory = func(int, int) RepoScanExecutor {
		return &fakeRepoExecutor{
			result: repoexposure.ScanResult{
				Repository:     "owner/repo",
				CommitsScanned: 1,
				FilesScanned:   1,
				ScanMode:       db.RepoScanModeDelta,
				BaseRevision:   request.BaseRevision,
				HeadRevision:   request.HeadRevision,
				ChangedPaths:   []string{"app.env", ".github/workflows/build.yml"},
			},
		}
	}

	run, err := svc.RunRepoScanPersisted(defaultScopeContext(), request)
	if err != nil {
		t.Fatalf("run delta repo scan persisted: %v", err)
	}
	stored, err := svc.GetRepoScan(defaultScopeContext(), run.RepoScan.ID)
	if err != nil {
		t.Fatalf("get repo scan: %v", err)
	}
	if stored.HeadRevision != request.HeadRevision || len(stored.ChangedPaths) != 2 {
		t.Fatalf("expected completed delta metadata to be persisted, got %+v", stored)
	}
}

func TestServiceRunRepoScanPersistedUpdatesCursorAndSkipsCurrentDelta(t *testing.T) {
	store := db.NewMemoryStore()
	svc := NewService(store, fakeScanner{}, "aws")
	svc.RepoScanAllowedTargets = []string{"owner/repo"}
	now := time.Date(2026, 5, 20, 9, 30, 0, 0, time.UTC)
	svc.Now = func() time.Time { return now }
	executor := &fakeRepoExecutor{
		result: repoexposure.ScanResult{
			Repository:     "owner/repo",
			CommitsScanned: 1,
			FilesScanned:   1,
		},
	}
	svc.RepoScannerFactory = func(int, int) RepoScanExecutor {
		return executor
	}

	request := RepoScanRequest{
		Repository:   "owner/repo",
		ScanMode:     db.RepoScanModeDelta,
		BaseRevision: "1111111111111111111111111111111111111111",
		HeadRevision: "2222222222222222222222222222222222222222",
		ChangedPaths: []string{"app.env", "app.env", ".github/workflows/build.yml"},
	}
	run, err := svc.RunRepoScanPersisted(defaultScopeContext(), request)
	if err != nil {
		t.Fatalf("run delta repo scan persisted: %v", err)
	}
	if run.RepoScan.ScanMode != db.RepoScanModeDelta || run.RepoScan.HeadRevision != request.HeadRevision {
		t.Fatalf("expected delta scan metadata, got %+v", run.RepoScan)
	}
	if executor.options.Mode != db.RepoScanModeDelta || executor.options.BaseRevision != request.BaseRevision || executor.options.HeadRevision != request.HeadRevision {
		t.Fatalf("expected executor delta options, got %+v", executor.options)
	}
	if len(executor.options.ChangedPaths) != 2 {
		t.Fatalf("expected normalized changed paths, got %+v", executor.options.ChangedPaths)
	}

	cursor, err := store.GetRepoScanCursor(defaultScopeContext(), "owner/repo", db.RepoScanSource{})
	if err != nil {
		t.Fatalf("get repo scan cursor: %v", err)
	}
	if cursor.LastScannedRevision != request.HeadRevision || cursor.LastScanMode != db.RepoScanModeDelta || cursor.LastScanID != run.RepoScan.ID {
		t.Fatalf("unexpected cursor after delta scan: %+v", cursor)
	}

	if _, err := svc.EnqueueRepoScan(defaultScopeContext(), request); !errors.Is(err, ErrRepoScanAlreadyCurrent) {
		t.Fatalf("expected current delta enqueue to be skipped, got %v", err)
	}
	if executor.calls != 1 {
		t.Fatalf("expected current delta skip to avoid executor, got %d calls", executor.calls)
	}
}

func TestServiceEnqueueRepoScanDoesNotSkipDeltaAfterQuickCursor(t *testing.T) {
	store := db.NewMemoryStore()
	svc := NewService(store, fakeScanner{}, "aws")
	svc.RepoScanAllowedTargets = []string{"owner/repo"}
	now := time.Date(2026, 5, 20, 10, 0, 0, 0, time.UTC)
	svc.Now = func() time.Time { return now }

	head := "2222222222222222222222222222222222222222"
	if err := store.UpsertRepoScanCursor(defaultScopeContext(), db.RepoScanCursor{
		Repository:          "owner/repo",
		LastScannedRevision: head,
		LastScanMode:        db.RepoScanModeQuick,
		LastScanCompletedAt: now.Add(-time.Minute),
		UpdatedAt:           now.Add(-time.Minute),
	}); err != nil {
		t.Fatalf("seed quick cursor: %v", err)
	}

	record, err := svc.EnqueueRepoScan(defaultScopeContext(), RepoScanRequest{
		Repository:   "owner/repo",
		ScanMode:     db.RepoScanModeDelta,
		BaseRevision: "1111111111111111111111111111111111111111",
		HeadRevision: head,
		ChangedPaths: []string{"app.env"},
	})
	if err != nil {
		t.Fatalf("expected delta enqueue after quick cursor, got %v", err)
	}
	if record.ScanMode != db.RepoScanModeDelta || record.HeadRevision != head || record.CursorBefore != head {
		t.Fatalf("expected queued delta to keep quick cursor as cursor_before without skipping, got %+v", record)
	}
}

func TestServiceRunRepoScanPersistedDoesNotSkipDeltaAfterQuickCursor(t *testing.T) {
	store := db.NewMemoryStore()
	svc := NewService(store, fakeScanner{}, "aws")
	svc.RepoScanAllowedTargets = []string{"owner/repo"}
	now := time.Date(2026, 5, 20, 10, 30, 0, 0, time.UTC)
	svc.Now = func() time.Time { return now }

	head := "2222222222222222222222222222222222222222"
	if err := store.UpsertRepoScanCursor(defaultScopeContext(), db.RepoScanCursor{
		Repository:          "owner/repo",
		LastScannedRevision: head,
		LastScanMode:        db.RepoScanModeQuick,
		LastScanCompletedAt: now.Add(-time.Minute),
		UpdatedAt:           now.Add(-time.Minute),
	}); err != nil {
		t.Fatalf("seed quick cursor: %v", err)
	}
	executor := &fakeRepoExecutor{
		result: repoexposure.ScanResult{
			Repository:     "owner/repo",
			CommitsScanned: 2,
			FilesScanned:   1,
			ScanMode:       db.RepoScanModeDelta,
			HeadRevision:   head,
		},
	}
	svc.RepoScannerFactory = func(int, int) RepoScanExecutor {
		return executor
	}

	run, err := svc.RunRepoScanPersisted(defaultScopeContext(), RepoScanRequest{
		Repository:   "owner/repo",
		ScanMode:     db.RepoScanModeDelta,
		BaseRevision: "1111111111111111111111111111111111111111",
		HeadRevision: head,
		ChangedPaths: []string{"app.env"},
	})
	if err != nil {
		t.Fatalf("expected delta run after quick cursor, got %v", err)
	}
	if executor.calls != 1 {
		t.Fatalf("expected delta executor to run after quick cursor, got %d calls", executor.calls)
	}
	if run.RepoScan.CursorBefore != head || run.RepoScan.CursorAfter != head {
		t.Fatalf("expected run to carry quick cursor before and completed delta cursor after, got %+v", run.RepoScan)
	}
	cursor, err := store.GetRepoScanCursor(defaultScopeContext(), "owner/repo", db.RepoScanSource{})
	if err != nil {
		t.Fatalf("get repo scan cursor: %v", err)
	}
	if cursor.LastScannedRevision != head || cursor.LastScanMode != db.RepoScanModeDelta || cursor.LastScanID != run.RepoScan.ID {
		t.Fatalf("expected delta run to replace quick cursor, got %+v", cursor)
	}
}

func TestServiceRunRepoScanPersistedDoesNotAdvanceCursorAfterTruncatedScan(t *testing.T) {
	store := db.NewMemoryStore()
	svc := NewService(store, fakeScanner{}, "aws")
	svc.RepoScanAllowedTargets = []string{"owner/repo"}
	now := time.Date(2026, 5, 20, 11, 0, 0, 0, time.UTC)
	svc.Now = func() time.Time { return now }

	oldHead := "1111111111111111111111111111111111111111"
	newHead := "2222222222222222222222222222222222222222"
	if err := store.UpsertRepoScanCursor(defaultScopeContext(), db.RepoScanCursor{
		Repository:          "owner/repo",
		LastScannedRevision: oldHead,
		LastScanID:          "old-scan-id",
		LastScanMode:        db.RepoScanModeDelta,
		LastScanCompletedAt: now.Add(-time.Hour),
		UpdatedAt:           now.Add(-time.Hour),
	}); err != nil {
		t.Fatalf("seed existing cursor: %v", err)
	}
	executor := &fakeRepoExecutor{
		result: repoexposure.ScanResult{
			Repository:     "owner/repo",
			CommitsScanned: 5,
			FilesScanned:   3,
			ScanMode:       db.RepoScanModeDelta,
			BaseRevision:   oldHead,
			HeadRevision:   newHead,
			Truncated:      true,
		},
	}
	svc.RepoScannerFactory = func(int, int) RepoScanExecutor {
		return executor
	}

	run, err := svc.RunRepoScanPersisted(defaultScopeContext(), RepoScanRequest{
		Repository:   "owner/repo",
		ScanMode:     db.RepoScanModeDelta,
		BaseRevision: oldHead,
		HeadRevision: newHead,
		ChangedPaths: []string{"app.env"},
	})
	if err != nil {
		t.Fatalf("run truncated delta repo scan: %v", err)
	}
	if !run.RepoScan.Truncated || run.RepoScan.HeadRevision != newHead {
		t.Fatalf("expected truncated run to persist head metadata, got %+v", run.RepoScan)
	}
	if run.RepoScan.CursorAfter != "" {
		t.Fatalf("truncated run must not advance cursor_after, got %+v", run.RepoScan)
	}
	stored, err := svc.GetRepoScan(defaultScopeContext(), run.RepoScan.ID)
	if err != nil {
		t.Fatalf("get repo scan: %v", err)
	}
	if stored.CursorAfter != "" || !stored.Truncated || stored.HeadRevision != newHead {
		t.Fatalf("stored truncated scan should retain audit metadata without cursor_after, got %+v", stored)
	}
	cursor, err := store.GetRepoScanCursor(defaultScopeContext(), "owner/repo", db.RepoScanSource{})
	if err != nil {
		t.Fatalf("get repo scan cursor: %v", err)
	}
	if cursor.LastScannedRevision != oldHead || cursor.LastScanID != "old-scan-id" || cursor.LastScanMode != db.RepoScanModeDelta {
		t.Fatalf("truncated scan must not overwrite existing cursor, got %+v", cursor)
	}
}

func TestServiceRunRepoScanPersistedDoesNotAdvanceCursorAfterPartialSourceRun(t *testing.T) {
	store := db.NewMemoryStore()
	svc := NewService(store, fakeScanner{}, "aws")
	svc.RepoScanAllowedTargets = []string{"owner/private"}
	ctx := defaultScopeContext()
	seedDefaultProject(t, store, ctx, "project-1")
	seedGitHubAppConnection(t, svc, ctx, "project-1", 101, []string{"owner/private"})

	now := time.Date(2026, 7, 4, 10, 0, 0, 0, time.UTC)
	svc.Now = func() time.Time { return now }

	oldHead := "1111111111111111111111111111111111111111"
	newHead := "2222222222222222222222222222222222222222"
	if err := store.UpsertRepoScanCursor(defaultScopeContext(), db.RepoScanCursor{
		Repository:          "owner/private",
		LastScannedRevision: oldHead,
		LastScanID:          "old-scan-id",
		LastScanMode:        db.RepoScanModeDelta,
		LastScanCompletedAt: now.Add(-time.Hour),
		UpdatedAt:           now.Add(-time.Hour),
	}); err != nil {
		t.Fatalf("seed existing cursor: %v", err)
	}

	svc.GitHubInstallationTokenMinter = &fakeGitHubInstallationTokenMinter{
		token: githubconnector.InstallationToken{Token: "ghs_token", ExpiresAt: now.Add(time.Hour)},
	}
	collector := &fakeGitHubRepositoryPostureCollector{
		err: errors.New("github posture source unavailable"),
	}
	svc.GitHubRepositoryPostureCollector = collector
	svc.AuthenticatedRepoScannerFactory = func(historyLimit int, maxFindings int, credential repoexposure.HTTPSCloneCredential) RepoScanExecutor {
		return &fakeRepoExecutor{
			result: repoexposure.ScanResult{
				Repository:     "owner/private",
				CommitsScanned: 1,
				FilesScanned:   2,
				ScanMode:       db.RepoScanModeDelta,
				BaseRevision:   oldHead,
				HeadRevision:   newHead,
			},
		}
	}

	run, err := svc.RunRepoScanPersisted(defaultScopeContext(), RepoScanRequest{
		Repository:   "owner/private",
		ProjectID:    "project-1",
		ScanMode:     db.RepoScanModeDelta,
		BaseRevision: oldHead,
		HeadRevision: newHead,
	})
	if err != nil {
		t.Fatalf("run persisted delta repo scan: %v", err)
	}
	if collector.seenRepository != "owner/private" {
		t.Fatalf("expected repository posture collector to run for owner/private, got %+v", collector.seenRepository)
	}
	if run.RepoScan.CursorAfter != "" {
		t.Fatalf("partial source run must not advance cursor_after, got %+v", run.RepoScan)
	}
	if run.RepoScan.SourceHealth != db.RepoScanSourceHealthPartial {
		t.Fatalf("expected returned repo scan source health to be partial, got %+v", run.RepoScan)
	}
	postureHealth := repoScanSourceHealthBySource(run.RepoScan.SourceHealthDetails, "github_repository_posture")
	if postureHealth == nil || postureHealth.Status != db.RepoScanSourceHealthUnavailable {
		t.Fatalf("expected posture source to be unavailable from returned source health details, got %+v", run.RepoScan.SourceHealthDetails)
	}

	cursor, err := store.GetRepoScanCursor(defaultScopeContext(), "owner/private", db.RepoScanSource{})
	if err != nil {
		t.Fatalf("get repo scan cursor: %v", err)
	}
	if cursor.LastScannedRevision != oldHead || cursor.LastScanID != "old-scan-id" || cursor.LastScanMode != db.RepoScanModeDelta {
		t.Fatalf("partial source run must not overwrite existing cursor, got %+v", cursor)
	}
}

func TestServiceRunRepoScanPersistedDoesNotFailAfterSuccessfulCursorUpdateMiss(t *testing.T) {
	store := &failingRepoScanCursorStore{MemoryStore: db.NewMemoryStore()}
	svc := NewService(store, fakeScanner{}, "aws")
	svc.RepoScanAllowedTargets = []string{"owner/repo"}
	svc.RepoScannerFactory = func(int, int) RepoScanExecutor {
		return &fakeRepoExecutor{
			result: repoexposure.ScanResult{
				Repository:     "owner/repo",
				CommitsScanned: 1,
				FilesScanned:   1,
				HeadRevision:   "2222222222222222222222222222222222222222",
			},
		}
	}

	run, err := svc.RunRepoScanPersisted(defaultScopeContext(), RepoScanRequest{Repository: "owner/repo"})
	if err != nil {
		t.Fatalf("expected successful repo scan despite cursor update failure, got %v", err)
	}
	if run.RepoScan.Status != "succeeded" {
		t.Fatalf("expected successful repo scan result, got %+v", run.RepoScan)
	}
	stored, err := svc.GetRepoScan(defaultScopeContext(), run.RepoScan.ID)
	if err != nil {
		t.Fatalf("get repo scan: %v", err)
	}
	if stored.Status != "succeeded" {
		t.Fatalf("expected persisted success despite cursor update failure, got %+v", stored)
	}
}

func TestServiceGetRepoRiskGraphUsesServiceClock(t *testing.T) {
	store := db.NewMemoryStore()
	svc := NewService(store, fakeScanner{}, "aws")
	now := time.Date(2030, 1, 2, 12, 0, 0, 0, time.UTC)
	svc.Now = func() time.Time { return now }

	repoScan, err := store.CreateRepoScan(defaultScopeContext(), "owner/repo", db.RepoScanSource{}, db.RepoScanContext{}, now.Add(-time.Hour))
	if err != nil {
		t.Fatalf("create repo scan: %v", err)
	}
	if err := store.UpsertRepoFindings(defaultScopeContext(), repoScan.ID, []domain.Finding{{
		ID:        "fresh-finding",
		Type:      domain.FindingRepoMisconfig,
		Severity:  domain.SeverityMedium,
		CreatedAt: now.Add(-2 * time.Hour),
	}}); err != nil {
		t.Fatalf("upsert repo findings: %v", err)
	}

	graph, err := svc.GetRepoRiskGraph(defaultScopeContext(), RepoRiskGraphFilter{RepoScanID: repoScan.ID})
	if err != nil {
		t.Fatalf("get repo risk graph: %v", err)
	}
	if len(graph.Scores) != 1 {
		t.Fatalf("expected one graph score, got %+v", graph)
	}
	if graph.Scores[0].Factors.Freshness != 100 {
		t.Fatalf("expected service clock to drive freshness score, got %+v", graph.Scores[0])
	}
}

func TestServicePreviewRepoFindingRemediationReturnsGuidanceAndFixPlan(t *testing.T) {
	store := db.NewMemoryStore()
	svc := NewService(store, fakeScanner{}, "aws")
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	repoScan, err := store.CreateRepoScan(defaultScopeContext(), "owner/repo", db.RepoScanSource{}, db.RepoScanContext{}, now)
	if err != nil {
		t.Fatalf("create repo scan: %v", err)
	}
	finding := domain.Finding{
		ID:           "repo-finding-remediate",
		ScanID:       repoScan.ID,
		Type:         domain.FindingRepoMisconfig,
		Severity:     domain.SeverityHigh,
		Title:        "Workflow grants broad token permissions",
		HumanSummary: "Workflow permissions are set to write-all.",
		Repository:   "owner/repo",
		Commit:       "abc123",
		FilePath:     ".github/workflows/ci.yml",
		LineNumber:   2,
		Detector:     "workflow_write_all_permissions",
		LineSnippet:  "permissions: write-all",
		Remediation:  "Restrict workflow permissions.",
		CreatedAt:    now,
	}
	if err := store.UpsertRepoFindings(defaultScopeContext(), repoScan.ID, []domain.Finding{finding}); err != nil {
		t.Fatalf("upsert repo findings: %v", err)
	}

	preview, err := svc.PreviewRepoFindingRemediation(defaultScopeContext(), finding.ID, RepoFindingRemediationPreviewRequest{
		RepoScanID:    repoScan.ID,
		SourceContent: "name: ci\npermissions: write-all\n",
		BaseBranch:    "dev",
		FindingURL:    "https://app.example.com/findings/repo-finding-remediate",
	})
	if err != nil {
		t.Fatalf("preview remediation: %v", err)
	}
	if preview.Remediation.Detector != "workflow_write_all_permissions" || !preview.Remediation.Publishable {
		t.Fatalf("unexpected remediation preview: %+v", preview.Remediation)
	}
	if preview.FixPRPlan == nil {
		t.Fatal("expected fix PR plan when source content is supplied")
	}
	if len(preview.FixPRPlan.Files) != 1 || preview.FixPRPlan.Files[0].Path != ".github/workflows/ci.yml" {
		t.Fatalf("expected affected workflow-only plan, got %+v", preview.FixPRPlan.Files)
	}
	if !strings.Contains(preview.FixPRPlan.Files[0].Content, "permissions:\n  contents: read\n") {
		t.Fatalf("expected patched permissions, got:\n%s", preview.FixPRPlan.Files[0].Content)
	}
}

func TestServicePublishRepoFindingRemediationRequiresApprovalAndPublishes(t *testing.T) {
	store := db.NewMemoryStore()
	publisher := &fakeRepoRemediationPublisher{
		result: fixpr.PublishResult{
			PRNumber:   42,
			PRURL:      "https://github.com/owner/repo/pull/42",
			BranchName: "identrail/fix/repo-finding-remediate",
			CommitSHA:  "abc123",
		},
	}
	svc := NewService(store, fakeScanner{}, "aws")
	svc.RepoRemediationPublisher = publisher
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	repoScan, err := store.CreateRepoScan(defaultScopeContext(), "owner/repo", db.RepoScanSource{}, db.RepoScanContext{}, now)
	if err != nil {
		t.Fatalf("create repo scan: %v", err)
	}
	finding := domain.Finding{
		ID:          "repo-finding-remediate",
		ScanID:      repoScan.ID,
		Type:        domain.FindingRepoMisconfig,
		Severity:    domain.SeverityHigh,
		Repository:  "owner/repo",
		FilePath:    ".github/workflows/ci.yml",
		LineNumber:  2,
		Detector:    "workflow_write_all_permissions",
		LineSnippet: "permissions: write-all",
		CreatedAt:   now,
	}
	if err := store.UpsertRepoFindings(defaultScopeContext(), repoScan.ID, []domain.Finding{finding}); err != nil {
		t.Fatalf("upsert repo findings: %v", err)
	}

	response, err := svc.PublishRepoFindingRemediation(defaultScopeContext(), finding.ID, RepoFindingRemediationPublishRequest{
		RepoScanID:                 repoScan.ID,
		SourceContent:              "name: ci\npermissions: write-all\n",
		BaseBranch:                 "dev",
		BranchPrefix:               "identrail/fix",
		FindingURL:                 "https://app.example.com/findings/repo-finding-remediate",
		OperatorApproved:           true,
		WritePermissionsConfigured: true,
		GitHubToken:                "ghs_write_token",
	})
	if err != nil {
		t.Fatalf("publish remediation: %v", err)
	}
	if publisher.calls != 1 {
		t.Fatalf("expected publisher call, got %d", publisher.calls)
	}
	if publisher.opts.Owner != "owner" || publisher.opts.Repo != "repo" || publisher.opts.Token != "ghs_write_token" {
		t.Fatalf("unexpected publisher options: %+v", publisher.opts)
	}
	if !publisher.opts.OperatorApproved || !publisher.opts.WritePermissionsConfigured {
		t.Fatalf("expected explicit approval and write credential gate, got %+v", publisher.opts)
	}
	if response.Publish.PRNumber != 42 || response.Publish.PRURL == "" {
		t.Fatalf("unexpected publish response: %+v", response.Publish)
	}
}

func TestServicePublishRepoFindingRemediationRejectsMissingApproval(t *testing.T) {
	store := db.NewMemoryStore()
	svc := NewService(store, fakeScanner{}, "aws")
	svc.RepoRemediationPublisher = &fakeRepoRemediationPublisher{err: fixpr.ErrRepoExposurePublishApprovalRequired}
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	repoScan, err := store.CreateRepoScan(defaultScopeContext(), "owner/repo", db.RepoScanSource{}, db.RepoScanContext{}, now)
	if err != nil {
		t.Fatalf("create repo scan: %v", err)
	}
	finding := domain.Finding{
		ID:          "repo-finding-remediate",
		ScanID:      repoScan.ID,
		Type:        domain.FindingRepoMisconfig,
		Repository:  "owner/repo",
		Detector:    "workflow_write_all_permissions",
		LineSnippet: "permissions: write-all",
		CreatedAt:   now,
	}
	if err := store.UpsertRepoFindings(defaultScopeContext(), repoScan.ID, []domain.Finding{finding}); err != nil {
		t.Fatalf("upsert repo findings: %v", err)
	}

	_, err = svc.PublishRepoFindingRemediation(defaultScopeContext(), finding.ID, RepoFindingRemediationPublishRequest{
		RepoScanID:    repoScan.ID,
		SourceContent: "name: ci\npermissions: write-all\n",
		GitHubToken:   "ghs_write_token",
	})
	if !errors.Is(err, ErrInvalidRepoRemediationRequest) {
		t.Fatalf("expected invalid remediation request for missing approval, got %v", err)
	}
}

func TestServicePublishRepoFindingRemediationMapsCredentialRejection(t *testing.T) {
	store := db.NewMemoryStore()
	svc := NewService(store, fakeScanner{}, "aws")
	// Simulate GitHub rejecting the supplied write token (HTTP 401/403), wrapped
	// the same way the real publisher surfaces it through the call chain.
	svc.RepoRemediationPublisher = &fakeRepoRemediationPublisher{
		err: fmt.Errorf("create branch: %w", fixpr.ErrRepoExposurePublishCredentialRejected),
	}
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	repoScan, err := store.CreateRepoScan(defaultScopeContext(), "owner/repo", db.RepoScanSource{}, db.RepoScanContext{}, now)
	if err != nil {
		t.Fatalf("create repo scan: %v", err)
	}
	finding := domain.Finding{
		ID:          "repo-finding-remediate",
		ScanID:      repoScan.ID,
		Type:        domain.FindingRepoMisconfig,
		Repository:  "owner/repo",
		Detector:    "workflow_write_all_permissions",
		LineSnippet: "permissions: write-all",
		CreatedAt:   now,
	}
	if err := store.UpsertRepoFindings(defaultScopeContext(), repoScan.ID, []domain.Finding{finding}); err != nil {
		t.Fatalf("upsert repo findings: %v", err)
	}

	_, err = svc.PublishRepoFindingRemediation(defaultScopeContext(), finding.ID, RepoFindingRemediationPublishRequest{
		RepoScanID:                 repoScan.ID,
		SourceContent:              "name: ci\npermissions: write-all\n",
		GitHubToken:                "ghs_expired_token",
		OperatorApproved:           true,
		WritePermissionsConfigured: true,
	})
	if !errors.Is(err, ErrRepoRemediationCredentialRejected) {
		t.Fatalf("expected credential rejection error, got %v", err)
	}
}

func TestServicePreviewRepoFindingRemediationUsesRepoFindingOnly(t *testing.T) {
	store := db.NewMemoryStore()
	svc := NewService(store, fakeScanner{}, "aws")
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	regularScan, err := store.CreateScan(defaultScopeContext(), "aws", now.Add(5*time.Minute))
	if err != nil {
		t.Fatalf("create regular scan: %v", err)
	}
	if err := store.UpsertFindings(defaultScopeContext(), regularScan.ID, []domain.Finding{{
		ID:           "shared-finding-id",
		ScanID:       regularScan.ID,
		Type:         domain.FindingOverPrivileged,
		Severity:     domain.SeverityHigh,
		Title:        "Cloud finding with same id",
		HumanSummary: "This non-repo finding must not be used by repo remediation previews.",
		CreatedAt:    now.Add(5 * time.Minute),
	}}); err != nil {
		t.Fatalf("upsert regular finding: %v", err)
	}
	repoScan, err := store.CreateRepoScan(defaultScopeContext(), "owner/repo", db.RepoScanSource{}, db.RepoScanContext{}, now)
	if err != nil {
		t.Fatalf("create repo scan: %v", err)
	}
	repoFinding := domain.Finding{
		ID:           "shared-finding-id",
		ScanID:       repoScan.ID,
		Type:         domain.FindingRepoMisconfig,
		Severity:     domain.SeverityHigh,
		Title:        "Repository misconfiguration",
		HumanSummary: "Workflow permissions are set to write-all.",
		Repository:   "owner/repo",
		FilePath:     ".github/workflows/ci.yml",
		LineNumber:   1,
		Detector:     "workflow_write_all_permissions",
		LineSnippet:  "permissions: write-all",
		CreatedAt:    now,
	}
	if err := store.UpsertRepoFindings(defaultScopeContext(), repoScan.ID, []domain.Finding{repoFinding}); err != nil {
		t.Fatalf("upsert repo finding: %v", err)
	}

	preview, err := svc.PreviewRepoFindingRemediation(defaultScopeContext(), repoFinding.ID, RepoFindingRemediationPreviewRequest{
		SourceContent: "permissions: write-all\n",
	})
	if err != nil {
		t.Fatalf("preview remediation: %v", err)
	}
	if preview.Finding.Type != domain.FindingRepoMisconfig || preview.Finding.ScanID != repoScan.ID {
		t.Fatalf("expected repo finding preview, got %+v", preview.Finding)
	}
	if preview.Remediation.Detector != "workflow_write_all_permissions" {
		t.Fatalf("expected repo remediation detector, got %+v", preview.Remediation)
	}
}

func TestServicePreviewRepoFindingRemediationKeepsSecretRotationOnly(t *testing.T) {
	store := db.NewMemoryStore()
	svc := NewService(store, fakeScanner{}, "aws")
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	repoScan, err := store.CreateRepoScan(defaultScopeContext(), "owner/repo", db.RepoScanSource{}, db.RepoScanContext{}, now)
	if err != nil {
		t.Fatalf("create repo scan: %v", err)
	}
	secretRedacted := false
	finding := domain.Finding{
		ID:                  "repo-secret-remediate",
		ScanID:              repoScan.ID,
		Type:                domain.FindingSecretExposure,
		Severity:            domain.SeverityCritical,
		Title:               "Repository contains a secret",
		HumanSummary:        "A credential-like value was committed.",
		Repository:          "owner/repo",
		Commit:              "abc123",
		FilePath:            "app.env",
		LineNumber:          1,
		Detector:            "github_token",
		LineSnippet:         "GITHUB_TOKEN=ghp_exampleSecretValue",
		LineSnippetRedacted: &secretRedacted,
		Remediation:         "Rotate the token.",
		CreatedAt:           now,
	}
	if err := store.UpsertRepoFindings(defaultScopeContext(), repoScan.ID, []domain.Finding{finding}); err != nil {
		t.Fatalf("upsert repo findings: %v", err)
	}

	preview, err := svc.PreviewRepoFindingRemediation(defaultScopeContext(), finding.ID, RepoFindingRemediationPreviewRequest{
		RepoScanID:    repoScan.ID,
		SourceContent: "GITHUB_TOKEN=ghp_exampleSecretValue\n",
	})
	if err != nil {
		t.Fatalf("preview remediation: %v", err)
	}
	if !preview.Remediation.SecretRotation || preview.Remediation.Patch != nil || preview.Remediation.Publishable {
		t.Fatalf("expected rotation-only secret remediation, got %+v", preview.Remediation)
	}
	if preview.FixPRPlan != nil {
		t.Fatalf("secret remediation must not include fix PR plan, got %+v", preview.FixPRPlan)
	}
	if preview.Finding.LineSnippet != "" || preview.Remediation.Evidence.LineSnippet != "" {
		t.Fatalf("secret preview must not echo raw snippet, got finding=%q evidence=%q", preview.Finding.LineSnippet, preview.Remediation.Evidence.LineSnippet)
	}
	for _, key := range []string{"line_snippet", "redacted_line_snip", "match_snippet"} {
		if value, exists := preview.Finding.Evidence[key]; exists {
			t.Fatalf("secret preview must not echo evidence key %s=%v", key, value)
		}
	}
	if preview.Finding.Evidence["line_snippet_redacted"] != true {
		t.Fatalf("expected secret preview evidence to remain explicitly redacted, got %+v", preview.Finding.Evidence)
	}
}

func TestServicePreviewRepoFindingRemediationRequireFixPlanRejectsGuidanceOnly(t *testing.T) {
	store := db.NewMemoryStore()
	svc := NewService(store, fakeScanner{}, "aws")
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	repoScan, err := store.CreateRepoScan(defaultScopeContext(), "owner/repo", db.RepoScanSource{}, db.RepoScanContext{}, now)
	if err != nil {
		t.Fatalf("create repo scan: %v", err)
	}
	finding := domain.Finding{
		ID:         "repo-finding-guidance",
		ScanID:     repoScan.ID,
		Type:       domain.FindingRepoMisconfig,
		Severity:   domain.SeverityMedium,
		Repository: "owner/repo",
		FilePath:   "Dockerfile",
		LineNumber: 1,
		Detector:   "docker_latest_tag",
		CreatedAt:  now,
	}
	if err := store.UpsertRepoFindings(defaultScopeContext(), repoScan.ID, []domain.Finding{finding}); err != nil {
		t.Fatalf("upsert repo findings: %v", err)
	}

	_, err = svc.PreviewRepoFindingRemediation(defaultScopeContext(), finding.ID, RepoFindingRemediationPreviewRequest{
		RepoScanID:     repoScan.ID,
		SourceContent:  "FROM golang:latest\n",
		RequireFixPlan: true,
	})
	if !errors.Is(err, ErrInvalidRepoRemediationRequest) {
		t.Fatalf("expected invalid request for required placeholder fix plan, got %v", err)
	}
}

func TestServiceListRepoFindingClusters(t *testing.T) {
	store := db.NewMemoryStore()
	svc := NewService(store, fakeScanner{}, "aws")

	firstScan, err := store.CreateRepoScan(defaultScopeContext(), "owner/repo", db.RepoScanSource{}, db.RepoScanContext{}, time.Date(2026, 4, 29, 9, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("create first repo scan: %v", err)
	}
	secondScan, err := store.CreateRepoScan(defaultScopeContext(), "owner/repo", db.RepoScanSource{}, db.RepoScanContext{}, time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("create second repo scan: %v", err)
	}

	if err := store.UpsertRepoFindings(defaultScopeContext(), firstScan.ID, []domain.Finding{
		{
			ID:           "rf-1",
			Type:         domain.FindingRepoMisconfig,
			Severity:     domain.SeverityMedium,
			Title:        "GitHub workflow uses pull_request_target trigger",
			HumanSummary: "pull_request_target can execute with elevated token context if not strictly controlled.",
			Repository:   "owner/repo",
			Commit:       "abc123",
			FilePath:     ".github/workflows/build.yml",
			LineNumber:   7,
			Detector:     "workflow_pull_request_target",
			LineSnippet:  "pull_request_target:",
			CreatedAt:    time.Date(2026, 4, 29, 9, 0, 0, 0, time.UTC),
		},
		{
			ID:           "rf-2",
			Type:         domain.FindingSecretExposure,
			Severity:     domain.SeverityHigh,
			Title:        "Potential AWS access key exposed in commit history",
			HumanSummary: "A line added in commit history appears to contain an AWS access key identifier.",
			Repository:   "owner/repo",
			Commit:       "deadbeef",
			FilePath:     "config/app.env",
			LineNumber:   3,
			Detector:     "aws_access_key_id",
			LineSnippet:  "AWS_ACCESS_KEY_ID=AKIA****",
			Evidence:     map[string]any{"secret_fingerprint": "fp-a"},
			CreatedAt:    time.Date(2026, 4, 29, 10, 0, 0, 0, time.UTC),
		},
	}); err != nil {
		t.Fatalf("upsert first repo findings: %v", err)
	}

	if err := store.UpsertRepoFindings(defaultScopeContext(), secondScan.ID, []domain.Finding{
		{
			ID:           "rf-3",
			Type:         domain.FindingRepoMisconfig,
			Severity:     domain.SeverityMedium,
			Title:        "GitHub workflow uses pull_request_target trigger",
			HumanSummary: "pull_request_target can execute with elevated token context if not strictly controlled.",
			Repository:   "owner/repo",
			Commit:       "def456",
			FilePath:     ".github/workflows/release.yml",
			LineNumber:   11,
			Detector:     "workflow_pull_request_target",
			LineSnippet:  "pull_request_target:",
			CreatedAt:    time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC),
		},
		{
			ID:           "rf-4",
			Type:         domain.FindingSecretExposure,
			Severity:     domain.SeverityHigh,
			Title:        "Potential AWS access key exposed in commit history",
			HumanSummary: "A line added in commit history appears to contain an AWS access key identifier.",
			Repository:   "owner/repo",
			Commit:       "cafe1234",
			FilePath:     "config/app.env",
			LineNumber:   3,
			Detector:     "aws_access_key_id",
			LineSnippet:  "AWS_ACCESS_KEY_ID=AKIA****",
			Evidence:     map[string]any{"secret_fingerprint": "fp-a"},
			CreatedAt:    time.Date(2026, 5, 1, 12, 5, 0, 0, time.UTC),
		},
	}); err != nil {
		t.Fatalf("upsert second repo findings: %v", err)
	}

	clusters, err := svc.ListRepoFindingClusters(defaultScopeContext(), 100, RepoFindingClusterFilter{})
	if err != nil {
		t.Fatalf("list repo finding clusters: %v", err)
	}
	if len(clusters) != 2 {
		t.Fatalf("expected two clusters, got %+v", clusters)
	}
	if clusters[0].Detector != "aws_access_key_id" || clusters[0].Count != 2 {
		t.Fatalf("expected secret cluster rollup first, got %+v", clusters[0])
	}
	if clusters[0].Spread.Commits != 2 || clusters[0].Spread.RepoScans != 2 || len(clusters[0].Members) != 2 {
		t.Fatalf("expected secret spread metadata, got %+v", clusters[0])
	}
	if clusters[1].Detector != "workflow_pull_request_target" || clusters[1].Count != 2 {
		t.Fatalf("expected misconfig cluster rollup second, got %+v", clusters[1])
	}
	if clusters[1].Spread.Paths != 2 || clusters[1].Members[0].SourceURL != "https://github.com/owner/repo/blob/def456/.github/workflows/release.yml#L11" {
		t.Fatalf("expected member source URLs and path spread, got %+v", clusters[1])
	}
}

func TestServiceListRepoFindingClustersUsesBoundedPageFilter(t *testing.T) {
	store := &repoFindingClusterFilterCaptureStore{MemoryStore: db.NewMemoryStore()}
	svc := NewService(store, fakeScanner{}, "aws")

	repoScan, err := store.CreateRepoScan(defaultScopeContext(), "owner/repo", db.RepoScanSource{}, db.RepoScanContext{}, time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("create repo scan: %v", err)
	}
	if err := store.UpsertRepoFindings(defaultScopeContext(), repoScan.ID, []domain.Finding{{
		ID:         "rf-1",
		Type:       domain.FindingRepoMisconfig,
		Severity:   domain.SeverityMedium,
		Repository: "owner/repo",
		Detector:   "workflow_pull_request_target",
		CreatedAt:  time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC),
	}}); err != nil {
		t.Fatalf("upsert repo finding: %v", err)
	}

	if _, err := svc.ListRepoFindingClusters(defaultScopeContext(), 25, RepoFindingClusterFilter{
		SortBy: "count",
		Offset: 10,
	}); err != nil {
		t.Fatalf("list repo finding clusters: %v", err)
	}
	if store.lastRepoFindingClusterFilter.Limit != 25 || store.lastRepoFindingClusterFilter.Offset != 10 {
		t.Fatalf("expected bounded repo finding cluster page filter, got %+v", store.lastRepoFindingClusterFilter)
	}
	if store.lastRepoFindingClusterFilter.SortBy != "count" || store.lastRepoFindingClusterFilter.SortDesc {
		t.Fatalf("expected explicit count sort to pass through unchanged, got %+v", store.lastRepoFindingClusterFilter)
	}
}

func TestServiceListRepoFindingClustersBackfillsLegacyRepositoryContext(t *testing.T) {
	store := db.NewMemoryStore()
	svc := NewService(store, fakeScanner{}, "aws")

	firstScan, err := store.CreateRepoScan(defaultScopeContext(), "owner/repo-a", db.RepoScanSource{}, db.RepoScanContext{}, time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("create first repo scan: %v", err)
	}
	secondScan, err := store.CreateRepoScan(defaultScopeContext(), "owner/repo-b", db.RepoScanSource{}, db.RepoScanContext{}, time.Date(2026, 5, 2, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("create second repo scan: %v", err)
	}

	for _, candidate := range []struct {
		scanID    string
		findingID string
		createdAt time.Time
	}{
		{scanID: firstScan.ID, findingID: "rf-1", createdAt: time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)},
		{scanID: secondScan.ID, findingID: "rf-2", createdAt: time.Date(2026, 5, 2, 12, 0, 0, 0, time.UTC)},
	} {
		if err := store.UpsertRepoFindings(defaultScopeContext(), candidate.scanID, []domain.Finding{{
			ID:           candidate.findingID,
			Type:         domain.FindingRepoMisconfig,
			Severity:     domain.SeverityMedium,
			Title:        "GitHub workflow uses pull_request_target trigger",
			HumanSummary: "pull_request_target can execute with elevated token context if not strictly controlled.",
			Detector:     "workflow_pull_request_target",
			FilePath:     ".github/workflows/release.yml",
			LineNumber:   18,
			CreatedAt:    candidate.createdAt,
		}}); err != nil {
			t.Fatalf("upsert repo finding for %s: %v", candidate.scanID, err)
		}
	}

	clusters, err := svc.ListRepoFindingClusters(defaultScopeContext(), 100, RepoFindingClusterFilter{})
	if err != nil {
		t.Fatalf("list repo finding clusters: %v", err)
	}
	if len(clusters) != 2 {
		t.Fatalf("expected distinct clusters per repository, got %+v", clusters)
	}
	if clusters[0].Repository != "owner/repo-b" || clusters[1].Repository != "owner/repo-a" {
		t.Fatalf("expected repository backfill to separate clusters, got %+v", clusters)
	}
}

func TestRepoFindingSourceURLSupportsGitHubRepositoryForms(t *testing.T) {
	testCases := []struct {
		name       string
		repository string
		want       string
	}{
		{
			name:       "owner slash repo",
			repository: "owner/repo",
			want:       "https://github.com/owner/repo/blob/abc123/.github/workflows/release.yml#L18",
		},
		{
			name:       "https clone url",
			repository: "https://github.com/owner/repo.git",
			want:       "https://github.com/owner/repo/blob/abc123/.github/workflows/release.yml#L18",
		},
		{
			name:       "ssh clone url",
			repository: "ssh://git@github.com/owner/repo.git",
			want:       "https://github.com/owner/repo/blob/abc123/.github/workflows/release.yml#L18",
		},
		{
			name:       "scp style",
			repository: "git@github.com:owner/repo.git",
			want:       "https://github.com/owner/repo/blob/abc123/.github/workflows/release.yml#L18",
		},
		{
			name:       "legacy head ref",
			repository: "owner/repo",
			want:       "https://github.com/owner/repo/blob/HEAD/.github/workflows/release.yml#L18",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			commit := "abc123"
			if tc.name == "legacy head ref" {
				commit = "HEAD"
			}
			if got := repoFindingSourceURL(tc.repository, commit, ".github/workflows/release.yml", 18); got != tc.want {
				t.Fatalf("unexpected source url %q", got)
			}
		})
	}

	if got := repoFindingSourceURL("https://gitlab.com/owner/repo.git", "abc123", "main.tf", 9); got != "" {
		t.Fatalf("expected non-GitHub repositories to skip source URLs, got %q", got)
	}
}

func TestServiceRunRepoScanGuards(t *testing.T) {
	svc := NewService(db.NewMemoryStore(), fakeScanner{}, "aws")
	svc.RepoScanEnabled = false
	if _, err := svc.RunRepoScan(defaultScopeContext(), RepoScanRequest{Repository: "owner/repo"}); !errors.Is(err, ErrRepoScanDisabled) {
		t.Fatalf("expected disabled error, got %v", err)
	}

	svc.RepoScanEnabled = true
	svc.RepoScanAllowedTargets = []string{"trusted/*"}
	if _, err := svc.RunRepoScan(defaultScopeContext(), RepoScanRequest{Repository: "owner/repo"}); !errors.Is(err, ErrRepoTargetNotAllowed) {
		t.Fatalf("expected target not allowed error, got %v", err)
	}

	svc.RepoScanAllowedTargets = nil
	if _, err := svc.RunRepoScan(defaultScopeContext(), RepoScanRequest{Repository: "", HistoryLimit: 10, MaxFindings: 10}); !errors.Is(err, ErrInvalidRepoScanRequest) {
		t.Fatalf("expected invalid request error for missing repo, got %v", err)
	}

	svc.RepoScanAllowedTargets = []string{"owner/repo"}
	if _, err := svc.RunRepoScan(defaultScopeContext(), RepoScanRequest{Repository: "owner/repo", HistoryLimit: -1, MaxFindings: 10}); !errors.Is(err, ErrInvalidRepoScanRequest) {
		t.Fatalf("expected invalid request error for negative history, got %v", err)
	}
}

func TestServiceRunRepoScanLocked(t *testing.T) {
	store := db.NewMemoryStore()
	svc := NewService(store, fakeScanner{}, "aws")
	svc.RepoScanAllowedTargets = []string{"owner/repo"}
	locker := scheduler.NewInMemoryLocker()
	release, ok := locker.TryAcquire(context.Background(), "identrail:repo-scan:owner/repo")
	if !ok {
		t.Fatal("expected repo lock acquire")
	}
	defer release(context.Background())
	svc.Locker = locker

	if _, err := svc.RunRepoScanPersisted(defaultScopeContext(), RepoScanRequest{Repository: "owner/repo"}); !errors.Is(err, ErrRepoScanInProgress) {
		t.Fatalf("expected repo scan in progress error, got %v", err)
	}
}

func TestServiceResolveWhoAmIContextAndActiveWorkspace(t *testing.T) {
	store := db.NewMemoryStore()
	svc := NewService(store, fakeScanner{}, "aws")
	scopeCtx := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	userUUID := "00000000-0000-0000-0000-0000000000a1"

	if err := store.UpsertOrganization(scopeCtx, db.TenancyOrganization{
		TenantID:    "tenant-a",
		DisplayName: "Tenant A",
		Slug:        "tenant-a",
	}); err != nil {
		t.Fatalf("seed organization: %v", err)
	}
	if err := store.UpsertWorkspace(scopeCtx, db.TenancyWorkspace{
		TenantID:    "tenant-a",
		WorkspaceID: "workspace-a",
		DisplayName: "Workspace A",
		Slug:        "workspace-a",
	}); err != nil {
		t.Fatalf("seed workspace-a: %v", err)
	}
	workspaceBCtx := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-b"})
	if err := store.UpsertWorkspace(workspaceBCtx, db.TenancyWorkspace{
		TenantID:    "tenant-a",
		WorkspaceID: "workspace-b",
		DisplayName: "Workspace B",
		Slug:        "workspace-b",
	}); err != nil {
		t.Fatalf("seed workspace-b: %v", err)
	}
	workspaceACtx := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	if err := store.UpsertWorkspaceMember(workspaceACtx, db.TenancyWorkspaceMember{
		TenantID:    "tenant-a",
		WorkspaceID: "workspace-a",
		MemberID:    "member-a",
		UserID:      "user-1",
		UserUUID:    userUUID,
		Role:        "admin",
		Status:      "active",
	}); err != nil {
		t.Fatalf("seed workspace-a member: %v", err)
	}
	if err := store.UpsertWorkspaceMember(workspaceBCtx, db.TenancyWorkspaceMember{
		TenantID:    "tenant-a",
		WorkspaceID: "workspace-b",
		MemberID:    "member-b",
		UserID:      "user-1",
		UserUUID:    userUUID,
		Role:        "viewer",
		Status:      "active",
	}); err != nil {
		t.Fatalf("seed workspace-b member: %v", err)
	}

	contextSnapshot, err := svc.ResolveWhoAmIContext(scopeCtx, "user-1")
	if err != nil {
		t.Fatalf("resolve whoami context: %v", err)
	}
	if contextSnapshot.Scope.TenantID != "tenant-a" || contextSnapshot.Scope.WorkspaceID != "workspace-a" {
		t.Fatalf("unexpected scope: %+v", contextSnapshot.Scope)
	}
	if contextSnapshot.ActiveWorkspace == nil || contextSnapshot.ActiveWorkspace.Workspace.WorkspaceID != "workspace-a" {
		t.Fatalf("unexpected active workspace: %+v", contextSnapshot.ActiveWorkspace)
	}
	if contextSnapshot.ActiveWorkspace.Member == nil || contextSnapshot.ActiveWorkspace.Member.Role != "admin" {
		t.Fatalf("unexpected active workspace member: %+v", contextSnapshot.ActiveWorkspace.Member)
	}
	if len(contextSnapshot.Workspaces) != 2 {
		t.Fatalf("expected 2 workspace contexts, got %d", len(contextSnapshot.Workspaces))
	}

	switched, err := svc.ResolveActiveWorkspace(scopeCtx, "user-1", "workspace-b")
	if err != nil {
		t.Fatalf("resolve active workspace: %v", err)
	}
	if switched.Workspace.WorkspaceID != "workspace-b" {
		t.Fatalf("unexpected switched workspace: %+v", switched.Workspace)
	}
	if switched.Member == nil || switched.Member.Role != "viewer" {
		t.Fatalf("unexpected switched member role: %+v", switched.Member)
	}

	switchedByUUID, err := svc.ResolveActiveWorkspace(scopeCtx, userUUID, "workspace-b")
	if err != nil {
		t.Fatalf("resolve active workspace by user uuid: %v", err)
	}
	if switchedByUUID.Member == nil || switchedByUUID.Member.MemberID != "member-b" {
		t.Fatalf("unexpected uuid switched member: %+v", switchedByUUID.Member)
	}
}

func TestServiceResolveActiveWorkspaceGuards(t *testing.T) {
	store := db.NewMemoryStore()
	svc := NewService(store, fakeScanner{}, "aws")
	scopeCtx := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	if err := store.UpsertOrganization(scopeCtx, db.TenancyOrganization{
		TenantID:    "tenant-a",
		DisplayName: "Tenant A",
		Slug:        "tenant-a",
	}); err != nil {
		t.Fatalf("seed organization: %v", err)
	}

	if _, err := svc.ResolveActiveWorkspace(scopeCtx, "user-1", ""); !errors.Is(err, ErrInvalidTenancyRequest) {
		t.Fatalf("expected invalid tenancy request, got %v", err)
	}
	if _, err := svc.ResolveActiveWorkspace(scopeCtx, "user-1", "workspace-missing"); !errors.Is(err, db.ErrNotFound) {
		t.Fatalf("expected workspace not found, got %v", err)
	}
	workspaceBCtx := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-b"})
	if err := store.UpsertWorkspace(workspaceBCtx, db.TenancyWorkspace{
		TenantID:    "tenant-a",
		WorkspaceID: "workspace-b",
		DisplayName: "Workspace B",
		Slug:        "workspace-b",
	}); err != nil {
		t.Fatalf("seed workspace-b: %v", err)
	}
	if _, err := svc.ResolveActiveWorkspace(scopeCtx, "user-1", "workspace-b"); !errors.Is(err, ErrWorkspaceAccessDenied) {
		t.Fatalf("expected workspace access denied, got %v", err)
	}
}

func TestServiceListFindingsWrapperAndRepoScanDetailGuard(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 3, 17, 15, 10, 0, 0, time.UTC)
	scan, err := store.CreateScan(defaultScopeContext(), "aws", now)
	if err != nil {
		t.Fatalf("create scan: %v", err)
	}
	if err := store.UpsertFindings(defaultScopeContext(), scan.ID, []domain.Finding{
		{ID: "f1", Type: domain.FindingOwnerless, Severity: domain.SeverityHigh, CreatedAt: now},
	}); err != nil {
		t.Fatalf("upsert findings: %v", err)
	}
	svc := NewService(store, fakeScanner{}, "aws")
	items, err := svc.ListFindings(defaultScopeContext(), 10)
	if err != nil {
		t.Fatalf("list findings wrapper: %v", err)
	}
	if len(items) != 1 || items[0].ID != "f1" {
		t.Fatalf("unexpected list findings result %+v", items)
	}
	if _, err := svc.GetRepoScan(defaultScopeContext(), " "); !errors.Is(err, db.ErrNotFound) {
		t.Fatalf("expected not found for empty repo scan id, got %v", err)
	}
}

func TestServiceRunRepoScanPersistedScannerError(t *testing.T) {
	store := db.NewMemoryStore()
	svc := NewService(store, fakeScanner{}, "aws")
	svc.RepoScanAllowedTargets = []string{"owner/repo"}
	svc.RepoScannerFactory = func(int, int) RepoScanExecutor {
		return &fakeRepoExecutor{err: errors.New("scanner failed")}
	}
	if _, err := svc.RunRepoScanPersisted(defaultScopeContext(), RepoScanRequest{
		Repository: "owner/repo",
	}); err == nil {
		t.Fatal("expected scanner error")
	}
	repoScans, err := svc.ListRepoScans(defaultScopeContext(), 10)
	if err != nil {
		t.Fatalf("list repo scans: %v", err)
	}
	if len(repoScans) != 1 || repoScans[0].Status != "failed" {
		t.Fatalf("expected failed repo scan record, got %+v", repoScans)
	}
}

func TestServiceRunRepoScanPersistedFailureUsesFreshContextForTerminalWrite(t *testing.T) {
	store := &completionContextStore{MemoryStore: db.NewMemoryStore()}
	svc := NewService(store, fakeScanner{}, "aws")
	svc.RepoScanAllowedTargets = []string{"owner/repo"}
	svc.RepoScannerFactory = func(int, int) RepoScanExecutor {
		return &fakeRepoExecutor{err: context.Canceled}
	}

	canceledCtx, cancel := context.WithCancel(defaultScopeContext())
	cancel()

	if _, err := svc.RunRepoScanPersisted(canceledCtx, RepoScanRequest{Repository: "owner/repo"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled error, got %v", err)
	}
	if store.lastRepoScanCompletionCtxErr != nil {
		t.Fatalf("expected terminal repo completion to use non-canceled context, got %v", store.lastRepoScanCompletionCtxErr)
	}
	repoScans, err := svc.ListRepoScans(defaultScopeContext(), 10)
	if err != nil {
		t.Fatalf("list repo scans: %v", err)
	}
	if len(repoScans) != 1 || repoScans[0].Status != "failed" {
		t.Fatalf("expected failed repo scan record, got %+v", repoScans)
	}
}

func remoteTraceContext(ctx context.Context) (context.Context, trace.TraceID) {
	traceID, _ := trace.TraceIDFromHex("4bf92f3577b34da6a3ce929d0e0e4736")
	spanID, _ := trace.SpanIDFromHex("00f067aa0ba902b7")
	spanContext := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    traceID,
		SpanID:     spanID,
		TraceFlags: trace.FlagsSampled,
		Remote:     true,
	})
	return trace.ContextWithRemoteSpanContext(ctx, spanContext), traceID
}

func TestServiceEnqueueScanAndProcessQueue(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 3, 20, 8, 0, 0, 0, time.UTC)
	svc := NewService(store, fakeScanner{result: app.ScanResult{
		Assets:   2,
		Findings: []domain.Finding{{ID: "f-1", Type: domain.FindingOwnerless, Severity: domain.SeverityHigh, CreatedAt: now}},
	}}, "aws")
	svc.Now = func() time.Time { return now }

	record, err := svc.EnqueueScan(defaultScopeContext())
	if err != nil {
		t.Fatalf("enqueue scan: %v", err)
	}
	if record.Status != "queued" {
		t.Fatalf("expected queued status, got %q", record.Status)
	}
	processed, err := svc.ProcessNextQueuedScan(defaultScopeContext())
	if err != nil {
		t.Fatalf("process queued scan: %v", err)
	}
	if !processed {
		t.Fatal("expected one queued scan to be processed")
	}
	scan, err := store.GetScan(defaultScopeContext(), record.ID)
	if err != nil {
		t.Fatalf("get scan: %v", err)
	}
	if scan.Status != "succeeded" || scan.FindingCount != 1 {
		t.Fatalf("unexpected processed scan record: %+v", scan)
	}
	processed, err = svc.ProcessNextQueuedScan(defaultScopeContext())
	if err != nil {
		t.Fatalf("process queued scan again: %v", err)
	}
	if processed {
		t.Fatal("expected no more queued scans")
	}
}

func TestServiceProcessNextQueuedScanContinuesEnqueuedTraceContext(t *testing.T) {
	store := db.NewMemoryStore()
	scanner := &traceCapturingScanner{result: app.ScanResult{Assets: 1}}
	svc := NewService(store, scanner, "aws")
	enqueueCtx, expectedTraceID := remoteTraceContext(defaultScopeContext())

	record, err := svc.EnqueueScan(enqueueCtx)
	if err != nil {
		t.Fatalf("enqueue scan: %v", err)
	}
	if record.TraceParent == "" {
		t.Fatal("expected queued scan record to persist traceparent")
	}

	processed, err := svc.ProcessNextQueuedScan(defaultScopeContext())
	if err != nil {
		t.Fatalf("process queued scan: %v", err)
	}
	if !processed {
		t.Fatal("expected queued scan to be processed")
	}
	if scanner.runCtx == nil {
		t.Fatal("expected scanner context capture")
	}
	spanContext := trace.SpanContextFromContext(scanner.runCtx)
	if !spanContext.IsValid() {
		t.Fatal("expected valid span context in scanner run context")
	}
	if spanContext.TraceID() != expectedTraceID {
		t.Fatalf("expected trace id %s, got %s", expectedTraceID.String(), spanContext.TraceID().String())
	}
}

func TestServiceCountQueuedScansForDepthReturnsZeroWhenAnyScopeCountFails(t *testing.T) {
	store := &failingAnyScopeDepthStore{MemoryStore: db.NewMemoryStore()}
	svc := NewService(store, fakeScanner{}, "aws")
	scopedCtx := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	now := time.Date(2026, 5, 10, 11, 30, 0, 0, time.UTC)

	if _, err := store.CreateQueuedScanWithinLimit(scopedCtx, "aws", now, 5); err != nil {
		t.Fatalf("create queued scan: %v", err)
	}
	scopedCount, err := store.CountQueuedScans(scopedCtx, "aws")
	if err != nil {
		t.Fatalf("count queued scans in scope: %v", err)
	}
	if scopedCount != 1 {
		t.Fatalf("expected one scoped queued scan, got %d", scopedCount)
	}

	queuedCount := svc.countQueuedScansForDepth(scopedCtx, "aws")
	if queuedCount != 0 {
		t.Fatalf("expected depth 0 when any-scope count fails, got %d", queuedCount)
	}
}

func TestServiceProcessNextQueuedScanFinalizesFailure(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 3, 20, 9, 0, 0, 0, time.UTC)
	svc := NewService(store, fakeScanner{err: errors.New("invalid credentials for provider connector")}, "aws")
	svc.Now = func() time.Time { return now }

	record, err := svc.EnqueueScan(defaultScopeContext())
	if err != nil {
		t.Fatalf("enqueue scan: %v", err)
	}

	processed, err := svc.ProcessNextQueuedScan(defaultScopeContext())
	if !processed {
		t.Fatal("expected queued scan to be processed")
	}
	if err != nil {
		t.Fatalf("expected queued scan failure to be handled without worker error, got %v", err)
	}

	scan, err := store.GetScan(defaultScopeContext(), record.ID)
	if err != nil {
		t.Fatalf("get scan: %v", err)
	}
	if scan.Status != "failed" {
		t.Fatalf("expected failed status, got %q", scan.Status)
	}
	if !scan.DeadLettered {
		t.Fatal("expected failed scan to be marked dead-lettered")
	}
	if scan.ErrorMessage == "" {
		t.Fatal("expected persisted scan error message")
	}

	events, err := svc.ListScanEvents(defaultScopeContext(), record.ID, 20)
	if err != nil {
		t.Fatalf("list scan events: %v", err)
	}
	foundFailureEvent := false
	foundDeadLetterEvent := false
	for _, event := range events {
		if event.Level == db.ScanEventLevelError && strings.Contains(event.Message, "scan failed during collection/analysis") {
			foundFailureEvent = true
		}
		if event.Level == db.ScanEventLevelError && strings.Contains(event.Message, "scan moved to dead-letter queue") {
			foundDeadLetterEvent = true
		}
	}
	if !foundFailureEvent {
		t.Fatalf("expected failure scan event, got %+v", events)
	}
	if !foundDeadLetterEvent {
		t.Fatalf("expected dead-letter scan event, got %+v", events)
	}

	processed, err = svc.ProcessNextQueuedScan(defaultScopeContext())
	if err != nil {
		t.Fatalf("second queue process: %v", err)
	}
	if processed {
		t.Fatal("expected failed scan to not be retried from queue")
	}
}

func TestServiceProcessNextQueuedScanDeadLettersFinalizeFailurePreservingCounts(t *testing.T) {
	store := &failingCompleteScanStore{MemoryStore: db.NewMemoryStore()}
	now := time.Date(2026, 3, 20, 9, 30, 0, 0, time.UTC)
	svc := NewService(store, fakeScanner{result: app.ScanResult{
		Assets: 4,
		Findings: []domain.Finding{{
			ID:           "finding-1",
			Type:         domain.FindingRiskyTrustPolicy,
			Severity:     domain.SeverityHigh,
			Title:        "Risky trust",
			HumanSummary: "summary",
			CreatedAt:    now,
		}},
	}}, "aws")
	svc.Now = func() time.Time { return now }

	record, err := svc.EnqueueScan(defaultScopeContext())
	if err != nil {
		t.Fatalf("enqueue scan: %v", err)
	}

	processed, err := svc.ProcessNextQueuedScan(defaultScopeContext())
	if err != nil {
		t.Fatalf("expected finalize failure to be dead-lettered without worker error, got %v", err)
	}
	if !processed {
		t.Fatal("expected queued scan to be processed")
	}

	scan, err := store.GetScan(defaultScopeContext(), record.ID)
	if err != nil {
		t.Fatalf("get scan: %v", err)
	}
	if scan.Status != "failed" || !scan.DeadLettered {
		t.Fatalf("expected dead-lettered failed scan, got %+v", scan)
	}
	if scan.AssetCount != 4 || scan.FindingCount != 1 {
		t.Fatalf("expected dead-lettered scan counts to be preserved, got assets=%d findings=%d", scan.AssetCount, scan.FindingCount)
	}
	if scan.FailureCategory != scanFailureCategoryFinalize {
		t.Fatalf("expected finalization failure category, got %q", scan.FailureCategory)
	}
}

func TestServiceProcessNextQueuedScanRetriesTransientFailure(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Now().UTC()
	svc := NewService(store, fakeScanner{err: errors.New("temporary timeout talking to provider")}, "aws")
	svc.Now = func() time.Time { return now }

	record, err := svc.EnqueueScan(defaultScopeContext())
	if err != nil {
		t.Fatalf("enqueue scan: %v", err)
	}

	processed, err := svc.ProcessNextQueuedScan(defaultScopeContext())
	if err != nil {
		t.Fatalf("expected transient failure to be requeued without worker error, got %v", err)
	}
	if !processed {
		t.Fatal("expected queued scan to be processed")
	}

	scan, err := store.GetScan(defaultScopeContext(), record.ID)
	if err != nil {
		t.Fatalf("get scan: %v", err)
	}
	if scan.Status != "queued" {
		t.Fatalf("expected scan to be requeued, got status %q", scan.Status)
	}
	if scan.RetryCount != 1 {
		t.Fatalf("expected retry_count=1, got %d", scan.RetryCount)
	}
	if scan.NextRetryAt == nil {
		t.Fatal("expected next_retry_at to be set")
	}
	if scan.DeadLettered {
		t.Fatal("did not expect dead-lettered retryable scan")
	}

	processed, err = svc.ProcessNextQueuedScan(defaultScopeContext())
	if err != nil {
		t.Fatalf("second queue process: %v", err)
	}
	if processed {
		t.Fatal("expected backoff-delayed retry to stay out of the queue until due")
	}
}

func TestServiceReplayScanQueuesFreshRecordFromDeadLetter(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 3, 20, 9, 0, 0, 0, time.UTC)
	svc := NewService(store, fakeScanner{err: errors.New("invalid credentials for provider connector")}, "aws")
	svc.Now = func() time.Time { return now }

	record, err := svc.EnqueueScan(defaultScopeContext())
	if err != nil {
		t.Fatalf("enqueue scan: %v", err)
	}

	processed, err := svc.ProcessNextQueuedScan(defaultScopeContext())
	if err != nil {
		t.Fatalf("dead-letter source scan: %v", err)
	}
	if !processed {
		t.Fatal("expected source scan to be processed")
	}

	source, err := store.GetScan(defaultScopeContext(), record.ID)
	if err != nil {
		t.Fatalf("get source scan: %v", err)
	}
	if !source.DeadLettered {
		t.Fatal("expected source scan to be dead-lettered before replay")
	}

	replay, err := svc.ReplayScan(defaultScopeContext(), record.ID)
	if err != nil {
		t.Fatalf("replay scan: %v", err)
	}
	if replay.ID == record.ID {
		t.Fatal("expected replay to create a fresh scan record")
	}
	if replay.Provider != record.Provider {
		t.Fatalf("expected replay provider %q, got %q", record.Provider, replay.Provider)
	}
	if replay.Status != "queued" {
		t.Fatalf("expected replay status queued, got %q", replay.Status)
	}
	if replay.DeadLettered {
		t.Fatal("did not expect replay scan to be dead-lettered")
	}
	if replay.RetryCount != 0 {
		t.Fatalf("expected replay retry_count=0, got %d", replay.RetryCount)
	}

	sourceEvents, err := svc.ListScanEvents(defaultScopeContext(), record.ID, 20)
	if err != nil {
		t.Fatalf("list source scan events: %v", err)
	}
	foundSourceReplayEvent := false
	for _, event := range sourceEvents {
		if event.Level == db.ScanEventLevelInfo && strings.Contains(event.Message, "scan replay queued") {
			foundSourceReplayEvent = true
			break
		}
	}
	if !foundSourceReplayEvent {
		t.Fatalf("expected replay event on source scan, got %+v", sourceEvents)
	}

	replayEvents, err := svc.ListScanEvents(defaultScopeContext(), replay.ID, 20)
	if err != nil {
		t.Fatalf("list replay scan events: %v", err)
	}
	foundReplayQueuedEvent := false
	for _, event := range replayEvents {
		if event.Level == db.ScanEventLevelInfo && strings.Contains(event.Message, "scan replay queued from failed scan") {
			foundReplayQueuedEvent = true
			break
		}
	}
	if !foundReplayQueuedEvent {
		t.Fatalf("expected replay queue event on replay scan, got %+v", replayEvents)
	}
}

func TestServiceReplayScanRejectsSucceededScan(t *testing.T) {
	svc := NewService(db.NewMemoryStore(), fakeScanner{result: app.ScanResult{}}, "aws")

	result, err := svc.RunScan(defaultScopeContext())
	if err != nil {
		t.Fatalf("run scan: %v", err)
	}

	if _, err := svc.ReplayScan(defaultScopeContext(), result.Scan.ID); !errors.Is(err, ErrScanReplayUnavailable) {
		t.Fatalf("expected replay unavailable error, got %v", err)
	}
}

func TestServiceReplayScanRejectsFullQueue(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 3, 20, 10, 0, 0, 0, time.UTC)
	svc := NewService(store, fakeScanner{err: errors.New("invalid credentials for provider connector")}, "aws")
	svc.Now = func() time.Time { return now }
	svc.ScanQueueMaxPending = 2

	source, err := svc.EnqueueScan(defaultScopeContext())
	if err != nil {
		t.Fatalf("enqueue source scan: %v", err)
	}
	processed, err := svc.ProcessNextQueuedScan(defaultScopeContext())
	if err != nil {
		t.Fatalf("dead-letter source scan: %v", err)
	}
	if !processed {
		t.Fatal("expected source scan to be processed")
	}
	for i := 0; i < 2; i++ {
		if _, err := svc.EnqueueScan(defaultScopeContext()); err != nil {
			t.Fatalf("enqueue pending scan %d: %v", i, err)
		}
	}

	if _, err := svc.ReplayScan(defaultScopeContext(), source.ID); !errors.Is(err, ErrScanQueueFull) {
		t.Fatalf("expected replay queue full error, got %v", err)
	}
}

func TestScanRetryPolicyHelpers(t *testing.T) {
	tests := []struct {
		name          string
		stage         string
		err           error
		wantCategory  string
		wantRetryable bool
	}{
		{
			name:          "nil failure defaults to execution",
			stage:         scanFailureStageExecution,
			wantCategory:  scanFailureCategoryExecution,
			wantRetryable: false,
		},
		{
			name:          "artifacts persistence failure is non-retryable",
			stage:         scanFailureStageArtifactsStore,
			err:           errors.New("write failed"),
			wantCategory:  scanFailureCategoryPersistence,
			wantRetryable: false,
		},
		{
			name:          "finalize failure is non-retryable",
			stage:         scanFailureStageFinalize,
			err:           errors.New("commit failed"),
			wantCategory:  scanFailureCategoryFinalize,
			wantRetryable: false,
		},
		{
			name:          "rate limit failure is retryable",
			stage:         scanFailureStageExecution,
			err:           errors.New("provider rate limit exceeded"),
			wantCategory:  scanFailureCategoryThrottle,
			wantRetryable: true,
		},
		{
			name:          "auth failure is non-retryable",
			stage:         scanFailureStageExecution,
			err:           errors.New("invalid credentials for provider connector"),
			wantCategory:  scanFailureCategoryProviderAuth,
			wantRetryable: false,
		},
		{
			name:          "temporary failure is retryable",
			stage:         scanFailureStageExecution,
			err:           errors.New("temporary connection refused"),
			wantCategory:  scanFailureCategoryTransient,
			wantRetryable: true,
		},
		{
			name:          "config failure is non-retryable",
			stage:         scanFailureStageExecution,
			err:           errors.New("missing region configuration"),
			wantCategory:  scanFailureCategoryConfig,
			wantRetryable: false,
		},
		{
			name:          "connector setup fallback uses connector category",
			stage:         scanFailureStageConnectorSetup,
			err:           errors.New("provider bootstrap failed"),
			wantCategory:  scanFailureCategoryConnector,
			wantRetryable: false,
		},
		{
			name:          "unknown execution failure defaults to retryable execution",
			stage:         scanFailureStageExecution,
			err:           errors.New("unexpected downstream crash"),
			wantCategory:  scanFailureCategoryExecution,
			wantRetryable: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := classifyScanFailure(tt.stage, tt.err)
			if policy.Category != tt.wantCategory {
				t.Fatalf("expected category %q, got %q", tt.wantCategory, policy.Category)
			}
			if policy.Retryable != tt.wantRetryable {
				t.Fatalf("expected retryable=%t, got %t", tt.wantRetryable, policy.Retryable)
			}
		})
	}

	if got := effectiveScanRetryLimit(db.ScanRecord{MaxRetryCount: -1}); got != 0 {
		t.Fatalf("expected negative retry limit to clamp to 0, got %d", got)
	}
	if got := effectiveScanRetryLimit(db.ScanRecord{}); got != db.DefaultScanMaxRetryCount {
		t.Fatalf("expected default retry limit %d, got %d", db.DefaultScanMaxRetryCount, got)
	}
	if got := effectiveScanRetryLimit(db.ScanRecord{MaxRetryCount: 7}); got != 7 {
		t.Fatalf("expected explicit retry limit 7, got %d", got)
	}

	if got := scanRetryBackoff(0); got != defaultScanRetryBaseDelay {
		t.Fatalf("expected base backoff %s, got %s", defaultScanRetryBaseDelay, got)
	}
	if got := scanRetryBackoff(2); got != defaultScanRetryBaseDelay*2 {
		t.Fatalf("expected doubled backoff %s, got %s", defaultScanRetryBaseDelay*2, got)
	}
	if got := scanRetryBackoff(20); got != defaultScanRetryMaxDelay {
		t.Fatalf("expected capped backoff %s, got %s", defaultScanRetryMaxDelay, got)
	}
}

func TestServiceEnqueueScanRejectsDuplicatePendingScan(t *testing.T) {
	svc := NewService(db.NewMemoryStore(), fakeScanner{}, "aws")
	svc.ScanQueueMaxPending = 1
	if _, err := svc.EnqueueScan(defaultScopeContext()); err != nil {
		t.Fatalf("enqueue first scan: %v", err)
	}
	if _, err := svc.EnqueueScan(defaultScopeContext()); !errors.Is(err, ErrScanInProgress) {
		t.Fatalf("expected scan in-progress error, got %v", err)
	}
}

func TestServiceEnqueueScanConcurrentRespectsDuplicateGuard(t *testing.T) {
	svc := NewService(db.NewMemoryStore(), fakeScanner{}, "aws")
	svc.ScanQueueMaxPending = 1

	const workers = 12
	start := make(chan struct{})
	var wg sync.WaitGroup
	var successCount int32
	var inProgressCount int32
	var unexpectedErrCount int32

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := svc.EnqueueScan(defaultScopeContext())
			switch {
			case err == nil:
				atomic.AddInt32(&successCount, 1)
			case errors.Is(err, ErrScanInProgress):
				atomic.AddInt32(&inProgressCount, 1)
			default:
				atomic.AddInt32(&unexpectedErrCount, 1)
			}
		}()
	}

	close(start)
	wg.Wait()

	if unexpectedErrCount != 0 {
		t.Fatalf("expected no unexpected enqueue errors, got %d", unexpectedErrCount)
	}
	if successCount != 1 {
		t.Fatalf("expected exactly one successful enqueue, got %d", successCount)
	}
	if inProgressCount != workers-1 {
		t.Fatalf("expected %d in-progress responses, got %d", workers-1, inProgressCount)
	}
}

func TestServiceEnqueueScanConcurrentRespectsQueueLimit(t *testing.T) {
	svc := NewService(db.NewMemoryStore(), fakeScanner{}, "aws")
	svc.ScanQueueMaxPending = 3

	const workers = 12
	start := make(chan struct{})
	var wg sync.WaitGroup
	var successCount int32
	var queueFullCount int32
	var unexpectedErrCount int32

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := svc.EnqueueScan(defaultScopeContext())
			switch {
			case err == nil:
				atomic.AddInt32(&successCount, 1)
			case errors.Is(err, ErrScanQueueFull):
				atomic.AddInt32(&queueFullCount, 1)
			default:
				atomic.AddInt32(&unexpectedErrCount, 1)
			}
		}()
	}

	close(start)
	wg.Wait()

	if unexpectedErrCount != 0 {
		t.Fatalf("expected no unexpected enqueue errors, got %d", unexpectedErrCount)
	}
	if successCount != 3 {
		t.Fatalf("expected exactly three successful enqueues, got %d", successCount)
	}
	if queueFullCount != workers-3 {
		t.Fatalf("expected %d queue-full responses, got %d", workers-3, queueFullCount)
	}
}

func TestServiceProcessQueuedScanAcrossScopes(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 3, 20, 10, 15, 0, 0, time.UTC)
	svc := NewService(store, fakeScanner{result: app.ScanResult{
		Assets:   1,
		Findings: []domain.Finding{{ID: "f-cross-scope", Type: domain.FindingOwnerless, Severity: domain.SeverityHigh, CreatedAt: now}},
	}}, "aws")
	svc.Now = func() time.Time { return now }

	tenantScopeCtx := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	record, err := svc.EnqueueScan(tenantScopeCtx)
	if err != nil {
		t.Fatalf("enqueue scoped scan: %v", err)
	}

	processed, err := svc.ProcessNextQueuedScan(defaultScopeContext())
	if err != nil {
		t.Fatalf("process queued scan from default scope context: %v", err)
	}
	if !processed {
		t.Fatal("expected queued scoped scan to be processed")
	}

	scan, err := store.GetScan(tenantScopeCtx, record.ID)
	if err != nil {
		t.Fatalf("get scoped scan: %v", err)
	}
	if scan.Status != "succeeded" {
		t.Fatalf("expected succeeded scan status, got %q", scan.Status)
	}
	if scan.FindingCount != 1 {
		t.Fatalf("expected finding_count=1, got %d", scan.FindingCount)
	}
	if scan.TenantID != "tenant-a" || scan.WorkspaceID != "workspace-a" {
		t.Fatalf("unexpected scan scope: tenant=%q workspace=%q", scan.TenantID, scan.WorkspaceID)
	}
}

func TestServiceQueuedScanBurstProcessing(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 3, 20, 8, 15, 0, 0, time.UTC)
	svc := NewService(store, fakeScanner{result: app.ScanResult{
		Assets:   1,
		Findings: []domain.Finding{{ID: "f-burst", Type: domain.FindingOwnerless, Severity: domain.SeverityLow, CreatedAt: now}},
	}}, "aws")
	svc.Now = func() time.Time { return now }

	const queued = 40
	for i := 0; i < queued; i++ {
		if _, err := svc.EnqueueScan(defaultScopeContext()); err != nil {
			t.Fatalf("enqueue burst scan %d: %v", i, err)
		}
		processed, err := svc.ProcessNextQueuedScan(defaultScopeContext())
		if err != nil {
			t.Fatalf("process burst queue: %v", err)
		}
		if !processed {
			t.Fatalf("expected queued burst scan %d to be processed", i)
		}
	}
	processed, err := svc.ProcessNextQueuedScan(defaultScopeContext())
	if err != nil {
		t.Fatalf("process drained queue: %v", err)
	}
	if processed {
		t.Fatal("expected no queued scan after sequential burst processing")
	}
	scans, err := store.ListScans(defaultScopeContext(), 1000)
	if err != nil {
		t.Fatalf("list scans: %v", err)
	}
	if len(scans) != queued {
		t.Fatalf("expected %d persisted scans, got %d", queued, len(scans))
	}
	for _, scan := range scans {
		if scan.Status != "succeeded" {
			t.Fatalf("expected succeeded scan status, got %q", scan.Status)
		}
	}
}

func TestServiceEnqueueRepoScanAndProcessQueue(t *testing.T) {
	store := db.NewMemoryStore()
	svc := NewService(store, fakeScanner{}, "aws")
	svc.RepoScanAllowedTargets = []string{"owner/*"}
	svc.RepoQueueMaxPending = 2
	events := []RepoScanQueueEvent{}
	svc.OnRepoScanQueueEvent = func(event RepoScanQueueEvent) {
		events = append(events, event)
	}
	svc.RepoScannerFactory = func(historyLimit int, maxFindings int) RepoScanExecutor {
		return &fakeRepoExecutor{
			result: repoexposure.ScanResult{
				Repository:     "owner/repo",
				CommitsScanned: historyLimit,
				FilesScanned:   6,
				Findings: []domain.Finding{
					{ID: "rf-queued", Type: domain.FindingSecretExposure, Severity: domain.SeverityHigh, CreatedAt: time.Now().UTC()},
				},
				Truncated: false,
			},
		}
	}
	record, err := svc.EnqueueRepoScan(defaultScopeContext(), RepoScanRequest{
		Repository:   "owner/repo",
		HistoryLimit: 25,
		MaxFindings:  30,
	})
	if err != nil {
		t.Fatalf("enqueue repo scan: %v", err)
	}
	if record.Status != "queued" {
		t.Fatalf("expected queued repo scan status, got %q", record.Status)
	}
	processed, err := svc.ProcessNextQueuedRepoScan(defaultScopeContext())
	if err != nil {
		t.Fatalf("process queued repo scan: %v", err)
	}
	if !processed {
		t.Fatal("expected queued repo scan to be processed")
	}
	stored, err := svc.GetRepoScan(defaultScopeContext(), record.ID)
	if err != nil {
		t.Fatalf("get repo scan: %v", err)
	}
	if stored.Status != "succeeded" || stored.CommitsScanned != 25 {
		t.Fatalf("unexpected processed repo scan record: %+v", stored)
	}
	if len(events) != 4 {
		t.Fatalf("expected claim attempt, claimed, scan started, and succeeded queue events, got %+v", events)
	}
	if events[0].Kind != "claim_attempt" || events[0].Status != "pending" || events[0].Count != 1 {
		t.Fatalf("unexpected claim attempt queue event: %+v", events[0])
	}
	if events[1].Kind != "claimed" || events[1].RepoScanID != record.ID || events[1].Repository != "owner/repo" || events[1].Status != "running" {
		t.Fatalf("unexpected claimed queue event: %+v", events[1])
	}
	if events[2].Kind != "scan_started" || events[2].RepoScanID != record.ID || events[2].Repository != "owner/repo" || events[2].Status != "running" {
		t.Fatalf("unexpected scan started queue event: %+v", events[2])
	}
	if events[3].Kind != "succeeded" || events[3].RepoScanID != record.ID || events[3].Repository != "owner/repo" || events[3].Status != "succeeded" {
		t.Fatalf("unexpected succeeded queue event: %+v", events[3])
	}
}

func TestServiceEnqueueRepoScanWithGitHubAppSourceStoresConnectorContext(t *testing.T) {
	store := db.NewMemoryStore()
	svc := NewService(store, fakeScanner{}, "aws")
	ctx := defaultScopeContext()
	seedDefaultProject(t, store, ctx, "project-1")
	seedGitHubAppConnection(t, svc, ctx, "project-1", 101, []string{"owner/private"})
	svc.RepoScanAllowedTargets = []string{"owner/*"}

	record, err := svc.EnqueueRepoScan(ctx, RepoScanRequest{
		Repository: "owner/private",
		ProjectID:  "project-1",
	})
	if err != nil {
		t.Fatalf("enqueue connector-backed repo scan: %v", err)
	}
	if record.Source.Provider != "github_app" || record.Source.ProjectID != "project-1" || record.Source.InstallationID != 101 {
		t.Fatalf("expected connector source metadata, got %+v", record.Source)
	}

	stored, err := svc.GetRepoScan(ctx, record.ID)
	if err != nil {
		t.Fatalf("get queued repo scan: %v", err)
	}
	if stored.Source.Provider != "github_app" || stored.Source.ProjectID != "project-1" || stored.Source.InstallationID != 101 {
		t.Fatalf("expected stored connector source metadata, got %+v", stored.Source)
	}
}

func TestServiceEnqueueRepoScanWithGitHubAppSourceCanonicalizesGitHubTarget(t *testing.T) {
	store := db.NewMemoryStore()
	svc := NewService(store, fakeScanner{}, "aws")
	ctx := defaultScopeContext()
	seedDefaultProject(t, store, ctx, "project-1")
	seedGitHubAppConnection(t, svc, ctx, "project-1", 101, []string{"owner/private"})
	svc.RepoScanAllowedTargets = []string{"owner/*"}

	record, err := svc.EnqueueRepoScan(ctx, RepoScanRequest{
		Repository: "git@github.com:Owner/Private.git",
		ProjectID:  "project-1",
	})
	if err != nil {
		t.Fatalf("enqueue connector-backed repo scan: %v", err)
	}
	if record.Repository != "owner/private" {
		t.Fatalf("expected canonical github repository target, got %q", record.Repository)
	}
}

func TestServiceEnqueueRepoScanWithGitHubAppSourceUsesSelectedRepositoriesAsTargetGuard(t *testing.T) {
	store := db.NewMemoryStore()
	svc := NewService(store, fakeScanner{}, "aws")
	ctx := defaultScopeContext()
	seedDefaultProject(t, store, ctx, "project-1")
	seedGitHubAppConnection(t, svc, ctx, "project-1", 101, []string{"Oluwatobi-Mustapha/iam-fuzzer"})

	record, err := svc.EnqueueRepoScan(ctx, RepoScanRequest{
		Repository: "oluwatobi-mustapha/iam-fuzzer",
		ProjectID:  "project-1",
	})
	if err != nil {
		t.Fatalf("expected selected GitHub App repository to queue without global repo scan allowlist: %v", err)
	}
	if record.Repository != "oluwatobi-mustapha/iam-fuzzer" || record.Source.Provider != "github_app" {
		t.Fatalf("expected connector-backed scan for selected repository, got %+v", record)
	}

	_, err = svc.EnqueueRepoScan(ctx, RepoScanRequest{
		Repository: "oluwatobi-mustapha/other",
		ProjectID:  "project-1",
	})
	if !errors.Is(err, ErrRepoTargetNotAllowed) {
		t.Fatalf("expected unselected GitHub App repository to remain denied, got %v", err)
	}
}

func TestServiceEnqueueRepoScanUnknownProjectIDIsInvalidRequest(t *testing.T) {
	store := db.NewMemoryStore()
	svc := NewService(store, fakeScanner{}, "aws")
	ctx := defaultScopeContext()
	seedDefaultProject(t, store, ctx, "project-1")

	_, err := svc.EnqueueRepoScan(ctx, RepoScanRequest{
		Repository: "owner/repo",
		ProjectID:  "project-missing",
	})
	if err == nil || !errors.Is(err, ErrInvalidRepoScanRequest) {
		t.Fatalf("expected invalid repo scan request for missing project, got %v", err)
	}
}

func TestServiceProcessQueuedGitHubAppRepoScanUsesInstallationToken(t *testing.T) {
	store := db.NewMemoryStore()
	svc := NewService(store, fakeScanner{}, "aws")
	ctx := defaultScopeContext()
	seedDefaultProject(t, store, ctx, "project-1")
	seedGitHubAppConnection(t, svc, ctx, "project-1", 101, []string{"owner/private"})
	svc.RepoScanAllowedTargets = []string{"owner/*"}
	svc.GitHubInstallationTokenMinter = &fakeGitHubInstallationTokenMinter{
		token: githubconnector.InstallationToken{Token: "ghs_installation_token", ExpiresAt: time.Now().Add(time.Hour)},
	}

	var gotCredential repoexposure.HTTPSCloneCredential
	var gotHistory, gotMax int
	svc.AuthenticatedRepoScannerFactory = func(historyLimit int, maxFindings int, credential repoexposure.HTTPSCloneCredential) RepoScanExecutor {
		gotHistory, gotMax = historyLimit, maxFindings
		gotCredential = credential
		return &fakeRepoExecutor{
			result: repoexposure.ScanResult{
				Repository:     "owner/private",
				CommitsScanned: historyLimit,
				FilesScanned:   2,
			},
		}
	}

	if _, err := svc.EnqueueRepoScan(ctx, RepoScanRequest{
		Repository:   "owner/private",
		ProjectID:    "project-1",
		HistoryLimit: 25,
		MaxFindings:  30,
	}); err != nil {
		t.Fatalf("enqueue connector-backed repo scan: %v", err)
	}
	processed, err := svc.ProcessNextQueuedRepoScan(ctx)
	if err != nil {
		t.Fatalf("process connector-backed repo scan: %v", err)
	}
	if !processed {
		t.Fatal("expected queued connector-backed repo scan to be processed")
	}
	minter := svc.GitHubInstallationTokenMinter.(*fakeGitHubInstallationTokenMinter)
	if minter.calls != 1 || minter.installationID != 101 {
		t.Fatalf("expected one token mint for installation 101, got calls=%d installation=%d", minter.calls, minter.installationID)
	}
	if gotHistory != 25 || gotMax != 30 {
		t.Fatalf("unexpected scanner limits history=%d max=%d", gotHistory, gotMax)
	}
	if gotCredential.Host != "github.com" || gotCredential.Username != "x-access-token" || gotCredential.Password != "ghs_installation_token" {
		t.Fatalf("unexpected clone credential %+v", gotCredential)
	}
}

func TestServiceProcessQueuedGitHubAppRepoScanRefreshesStaleWorkerConnection(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	seedDefaultProject(t, store, ctx, "project-1")

	apiSvc := NewService(store, fakeScanner{}, "aws")
	workerSvc := NewService(store, fakeScanner{}, "aws")
	seedGitHubAppConnection(t, workerSvc, ctx, "project-1", 101, []string{"owner/old-private"})
	seedGitHubAppConnection(t, apiSvc, ctx, "project-1", 101, []string{"owner/new-private"})
	workerSvc.GitHubInstallationTokenMinter = &fakeGitHubInstallationTokenMinter{
		token: githubconnector.InstallationToken{Token: "ghs_installation_token", ExpiresAt: time.Now().Add(time.Hour)},
	}
	workerSvc.AuthenticatedRepoScannerFactory = func(historyLimit int, maxFindings int, credential repoexposure.HTTPSCloneCredential) RepoScanExecutor {
		return &fakeRepoExecutor{
			result: repoexposure.ScanResult{
				Repository:     "owner/new-private",
				CommitsScanned: 1,
				FilesScanned:   1,
			},
		}
	}

	if _, err := apiSvc.EnqueueRepoScan(ctx, RepoScanRequest{
		Repository: "owner/new-private",
		ProjectID:  "project-1",
	}); err != nil {
		t.Fatalf("enqueue connector-backed repo scan: %v", err)
	}
	processed, err := workerSvc.ProcessNextQueuedRepoScan(ctx)
	if err != nil {
		t.Fatalf("process connector-backed repo scan with stale worker cache: %v", err)
	}
	if !processed {
		t.Fatal("expected queued connector-backed repo scan to be processed")
	}
	minter := workerSvc.GitHubInstallationTokenMinter.(*fakeGitHubInstallationTokenMinter)
	if minter.calls != 1 || minter.installationID != 101 {
		t.Fatalf("expected one token mint for refreshed installation 101, got calls=%d installation=%d", minter.calls, minter.installationID)
	}
	records, err := store.ListRepoScans(ctx, 10)
	if err != nil {
		t.Fatalf("list repo scans: %v", err)
	}
	if len(records) != 1 || records[0].Status != "succeeded" {
		t.Fatalf("expected refreshed worker connection to complete scan, got %+v", records)
	}
}

func TestServiceProcessQueuedGitHubAppRepoScanImportsCodeScanningAlerts(t *testing.T) {
	store := db.NewMemoryStore()
	svc := NewService(store, fakeScanner{}, "aws")
	ctx := defaultScopeContext()
	seedDefaultProject(t, store, ctx, "project-1")
	seedGitHubAppConnection(t, svc, ctx, "project-1", 101, []string{"owner/private"})
	svc.RepoScanAllowedTargets = []string{"owner/*"}
	svc.GitHubInstallationTokenMinter = &fakeGitHubInstallationTokenMinter{
		token: githubconnector.InstallationToken{Token: "ghs_installation_token", ExpiresAt: time.Now().Add(time.Hour)},
	}
	svc.GitHubCodeScanningAlertCollector = &fakeGitHubCodeScanningAlertCollector{
		alerts: []githubconnector.CodeScanningAlert{
			{
				Number: 12,
				State:  "open",
				Rule: githubconnector.CodeScanningRule{
					ID:                    "js/sql-injection",
					Name:                  "SQL query built from user-controlled sources",
					Severity:              "warning",
					SecuritySeverityLevel: "high",
					Tags:                  []string{"security"},
				},
				Tool: githubconnector.CodeScanningTool{Name: "CodeQL", Version: "2.17.0"},
				MostRecentInstance: githubconnector.CodeScanningAlertInstance{
					State:     "open",
					CommitSHA: "def456",
					Message:   githubconnector.CodeScanningMessage{Text: "Query string includes user input."},
					Location:  githubconnector.CodeScanningLocation{Path: "src/db.ts", StartLine: 88, StartColumn: 11},
				},
				HTMLURL: "https://github.com/owner/private/security/code-scanning/12",
			},
		},
	}
	svc.AuthenticatedRepoScannerFactory = func(historyLimit int, maxFindings int, credential repoexposure.HTTPSCloneCredential) RepoScanExecutor {
		return &fakeRepoExecutor{
			result: repoexposure.ScanResult{
				Repository:     "owner/private",
				CommitsScanned: 1,
				FilesScanned:   1,
			},
		}
	}

	record, err := svc.EnqueueRepoScan(ctx, RepoScanRequest{
		Repository: "owner/private",
		ProjectID:  "project-1",
	})
	if err != nil {
		t.Fatalf("enqueue connector-backed repo scan: %v", err)
	}
	processed, err := svc.ProcessNextQueuedRepoScan(ctx)
	if err != nil {
		t.Fatalf("process connector-backed repo scan: %v", err)
	}
	if !processed {
		t.Fatal("expected queued connector-backed repo scan to be processed")
	}
	collector := svc.GitHubCodeScanningAlertCollector.(*fakeGitHubCodeScanningAlertCollector)
	if collector.calls != 1 || collector.installationID != 101 || collector.repository != "owner/private" {
		t.Fatalf("unexpected code scanning collector call: calls=%d installation=%d repository=%q", collector.calls, collector.installationID, collector.repository)
	}
	stored, err := svc.GetRepoScan(ctx, record.ID)
	if err != nil {
		t.Fatalf("get repo scan: %v", err)
	}
	if stored.FindingCount != 1 {
		t.Fatalf("expected one imported code-scanning finding, got %+v", stored)
	}
	findings, err := svc.ListRepoFindings(ctx, 10, db.RepoFindingFilter{RepoScanID: record.ID})
	if err != nil {
		t.Fatalf("list repo findings: %v", err)
	}
	if len(findings) != 1 || findings[0].Detector != "github_code_scanning:codeql:js_sql-injection" || findings[0].SourceURL == "" {
		t.Fatalf("unexpected imported finding: %+v", findings)
	}
}

func TestServiceProcessQueuedGitHubAppRepoScanImportsSecretAndDependabotAlerts(t *testing.T) {
	store := db.NewMemoryStore()
	svc := NewService(store, fakeScanner{}, "aws")
	ctx := defaultScopeContext()
	seedDefaultProject(t, store, ctx, "project-1")
	seedGitHubAppConnection(t, svc, ctx, "project-1", 101, []string{"owner/private"})
	svc.RepoScanAllowedTargets = []string{"owner/*"}
	svc.GitHubInstallationTokenMinter = &fakeGitHubInstallationTokenMinter{
		token: githubconnector.InstallationToken{Token: "ghs_installation_token", ExpiresAt: time.Now().Add(time.Hour)},
	}
	// Code scanning is permission-limited for this installation; the native scan
	// and the other GitHub-native imports must still complete.
	svc.GitHubCodeScanningAlertCollector = &fakeGitHubCodeScanningAlertCollector{
		err: errors.New("github api /repos/owner/private/code-scanning/alerts: status 403: permission denied"),
	}
	svc.GitHubSecretScanningAlertCollector = &fakeGitHubSecretScanningAlertCollector{
		alerts: []githubconnector.SecretScanningAlert{
			{
				Number:                3,
				State:                 "open",
				SecretType:            "github_personal_access_token",
				SecretTypeDisplayName: "GitHub Personal Access Token",
				Validity:              "active",
				HTMLURL:               "https://github.com/owner/private/security/secret-scanning/3",
			},
		},
	}
	svc.GitHubDependabotAlertCollector = &fakeGitHubDependabotAlertCollector{
		alerts: []githubconnector.DependabotAlert{
			{
				Number: 7,
				State:  "open",
				Dependency: githubconnector.DependabotDependency{
					Package:      githubconnector.DependabotPackage{Ecosystem: "pip", Name: "django"},
					ManifestPath: "requirements.txt",
				},
				SecurityAdvisory: githubconnector.DependabotSecurityAdvisory{
					GHSAID:   "GHSA-xxxx-yyyy-zzzz",
					CVEID:    "CVE-2024-0001",
					Summary:  "SQL injection in django",
					Severity: "high",
				},
				SecurityVulnerability: githubconnector.DependabotVulnerability{
					Severity:               "high",
					VulnerableVersionRange: "< 4.2.1",
					FirstPatchedVersion:    githubconnector.DependabotPatchVersion{Identifier: "4.2.1"},
				},
				HTMLURL: "https://github.com/owner/private/security/dependabot/7",
			},
		},
	}
	svc.AuthenticatedRepoScannerFactory = func(historyLimit int, maxFindings int, credential repoexposure.HTTPSCloneCredential) RepoScanExecutor {
		return &fakeRepoExecutor{
			result: repoexposure.ScanResult{
				Repository:     "owner/private",
				CommitsScanned: 1,
				FilesScanned:   1,
			},
		}
	}

	record, err := svc.EnqueueRepoScan(ctx, RepoScanRequest{
		Repository: "owner/private",
		ProjectID:  "project-1",
	})
	if err != nil {
		t.Fatalf("enqueue connector-backed repo scan: %v", err)
	}
	processed, err := svc.ProcessNextQueuedRepoScan(ctx)
	if err != nil {
		t.Fatalf("process connector-backed repo scan: %v", err)
	}
	if !processed {
		t.Fatal("expected queued connector-backed repo scan to be processed")
	}
	secretCollector := svc.GitHubSecretScanningAlertCollector.(*fakeGitHubSecretScanningAlertCollector)
	if secretCollector.calls != 1 || secretCollector.installationID != 101 || secretCollector.repository != "owner/private" {
		t.Fatalf("unexpected secret scanning collector call: calls=%d installation=%d repository=%q", secretCollector.calls, secretCollector.installationID, secretCollector.repository)
	}
	if secretCollector.err != nil {
		t.Fatalf("secret collector unexpectedly failed: %v", secretCollector.err)
	}
	dependabotCollector := svc.GitHubDependabotAlertCollector.(*fakeGitHubDependabotAlertCollector)
	if dependabotCollector.calls != 1 || dependabotCollector.installationID != 101 || dependabotCollector.repository != "owner/private" {
		t.Fatalf("unexpected dependabot collector call: calls=%d installation=%d repository=%q", dependabotCollector.calls, dependabotCollector.installationID, dependabotCollector.repository)
	}
	stored, err := svc.GetRepoScan(ctx, record.ID)
	if err != nil {
		t.Fatalf("get repo scan: %v", err)
	}
	if stored.FindingCount != 2 {
		t.Fatalf("expected two imported alert findings, got %+v", stored)
	}
	findings, err := svc.ListRepoFindings(ctx, 10, db.RepoFindingFilter{RepoScanID: record.ID})
	if err != nil {
		t.Fatalf("list repo findings: %v", err)
	}
	var secretFinding, dependabotFinding *domain.Finding
	for i := range findings {
		switch findings[i].Type {
		case domain.FindingSecretExposure:
			secretFinding = &findings[i]
		case domain.FindingRepoMisconfig:
			dependabotFinding = &findings[i]
		}
	}
	if secretFinding == nil {
		t.Fatalf("expected an imported secret-exposure finding, got %+v", findings)
	}
	if secretFinding.Severity != domain.SeverityCritical || secretFinding.LineSnippetRedacted == nil || !*secretFinding.LineSnippetRedacted {
		t.Fatalf("unexpected secret finding: %+v", secretFinding)
	}
	if got, _ := secretFinding.Evidence["raw_secret_stored"].(bool); got {
		t.Fatalf("secret finding must not store raw secret: %+v", secretFinding.Evidence)
	}
	if dependabotFinding == nil {
		t.Fatalf("expected an imported dependabot finding, got %+v", findings)
	}
	if dependabotFinding.Evidence["adapter_advisory_ghsa"] != "GHSA-xxxx-yyyy-zzzz" || dependabotFinding.Evidence["adapter_package"] != "django" {
		t.Fatalf("unexpected dependabot finding evidence: %+v", dependabotFinding.Evidence)
	}
}

func TestServiceProcessQueuedGitHubAppRepoScanImportsPostureFindings(t *testing.T) {
	store := db.NewMemoryStore()
	svc := NewService(store, fakeScanner{}, "aws")
	ctx := defaultScopeContext()
	seedDefaultProject(t, store, ctx, "project-1")
	seedGitHubAppConnection(t, svc, ctx, "project-1", 101, []string{"owner/private"})
	svc.RepoScanAllowedTargets = []string{"owner/*"}
	svc.GitHubInstallationTokenMinter = &fakeGitHubInstallationTokenMinter{
		token: githubconnector.InstallationToken{Token: "ghs_installation_token", ExpiresAt: time.Now().Add(time.Hour)},
	}
	collectedAt := time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC)
	svc.GitHubRepositoryPostureCollector = &fakeGitHubRepositoryPostureCollector{
		posture: githubconnector.RepositoryPosture{
			Repository:     "owner/private",
			InstallationID: 101,
			CollectedAt:    collectedAt,
			Checks: []githubconnector.RepositoryPostureCheck{
				{
					ID:       "default_branch_protection",
					Category: "branch_protection",
					State:    githubconnector.RepositoryPostureStateInsecure,
					Reason:   "weak_protection",
					Summary:  "Default branch protection is weak.",
				},
				{
					ID:       "deploy_keys",
					Category: "access",
					State:    githubconnector.RepositoryPostureStateSecure,
					Reason:   "no_writable_deploy_keys",
					Summary:  "No writable deploy keys were returned.",
				},
			},
		},
		organizationPosture: githubconnector.OrganizationPosture{
			Organization:   "owner",
			InstallationID: 101,
			CollectedAt:    collectedAt,
			Checks: []githubconnector.RepositoryPostureCheck{
				{
					ID:       "org_workflow_permissions",
					Category: "actions",
					State:    githubconnector.RepositoryPostureStateInsecure,
					Reason:   "write_token_or_pr_approval",
					Summary:  "Organization grants write-scoped default workflow tokens.",
				},
			},
		},
	}
	svc.AuthenticatedRepoScannerFactory = func(historyLimit int, maxFindings int, credential repoexposure.HTTPSCloneCredential) RepoScanExecutor {
		return &fakeRepoExecutor{
			result: repoexposure.ScanResult{
				Repository:     "owner/private",
				CommitsScanned: 1,
				FilesScanned:   1,
			},
		}
	}

	record, err := svc.EnqueueRepoScan(ctx, RepoScanRequest{
		Repository: "owner/private",
		ProjectID:  "project-1",
	})
	if err != nil {
		t.Fatalf("enqueue connector-backed repo scan: %v", err)
	}
	processed, err := svc.ProcessNextQueuedRepoScan(ctx)
	if err != nil {
		t.Fatalf("process connector-backed repo scan: %v", err)
	}
	if !processed {
		t.Fatal("expected queued connector-backed repo scan to be processed")
	}
	collector := svc.GitHubRepositoryPostureCollector.(*fakeGitHubRepositoryPostureCollector)
	if collector.seenInstallationID != 101 || collector.seenRepository != "owner/private" || collector.seenOrganization != "owner" || collector.seenOrganizationRepo != "owner/private" {
		t.Fatalf("unexpected posture collector calls: %+v", collector)
	}
	stored, err := svc.GetRepoScan(ctx, record.ID)
	if err != nil {
		t.Fatalf("get repo scan: %v", err)
	}
	if stored.FindingCount != 2 {
		t.Fatalf("expected two imported posture findings, got %+v", stored)
	}
	findings, err := svc.ListRepoFindings(ctx, 10, db.RepoFindingFilter{RepoScanID: record.ID})
	if err != nil {
		t.Fatalf("list repo findings: %v", err)
	}
	branchFinding := repoFindingByDetector(findings, "github_default_branch_unprotected")
	if branchFinding == nil {
		t.Fatalf("expected branch posture finding, got %+v", findings)
	}
	if branchFinding.Repository != "owner/private" || branchFinding.LifecycleKey == "" || branchFinding.Evidence["github_posture_check_id"] != "default_branch_protection" {
		t.Fatalf("unexpected branch posture finding: %+v", branchFinding)
	}
	orgFinding := repoFindingByDetector(findings, "github_workflow_permissions_write_default")
	if orgFinding == nil {
		t.Fatalf("expected org workflow posture finding, got %+v", findings)
	}
	if orgFinding.AdapterSource != "github_org_posture" || orgFinding.Evidence["organization"] != "owner" || orgFinding.Evidence["raw_secret_stored"] != false {
		t.Fatalf("unexpected org posture finding: %+v", orgFinding)
	}
}

func TestServiceProcessQueuedGitHubAppRepoScanPreservesPostureFindingsWhenPostureSourceFails(t *testing.T) {
	store := db.NewMemoryStore()
	svc := NewService(store, fakeScanner{}, "aws")
	ctx := defaultScopeContext()
	seedDefaultProject(t, store, ctx, "project-1")
	seedGitHubAppConnection(t, svc, ctx, "project-1", 101, []string{"owner/private"})
	now := time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC)

	previousScan, err := store.CreateRepoScan(ctx, "owner/private", db.RepoScanSource{}, db.RepoScanContext{ScanMode: db.RepoScanModeDeep}, now)
	if err != nil {
		t.Fatalf("create previous repo scan: %v", err)
	}
	previousFindings := githubconnector.RepositoryPostureFindings(githubconnector.RepositoryPosture{
		Repository:     "owner/private",
		InstallationID: 101,
		CollectedAt:    now,
		Checks: []githubconnector.RepositoryPostureCheck{
			{
				ID:       "default_branch_protection",
				Category: "branch_protection",
				State:    githubconnector.RepositoryPostureStateInsecure,
				Reason:   "weak_protection",
				Summary:  "Default branch protection is weak.",
			},
		},
	}, now)
	if len(previousFindings) != 1 {
		t.Fatalf("expected one previous posture finding, got %+v", previousFindings)
	}
	if err := store.UpsertRepoFindings(ctx, previousScan.ID, previousFindings); err != nil {
		t.Fatalf("upsert previous posture finding: %v", err)
	}
	if err := store.CompleteRepoScan(ctx, previousScan.ID, "succeeded", now.Add(time.Minute), 1, 1, len(previousFindings), false, db.RepoScanContext{ScanMode: db.RepoScanModeDeep}, ""); err != nil {
		t.Fatalf("complete previous repo scan: %v", err)
	}

	svc.GitHubInstallationTokenMinter = &fakeGitHubInstallationTokenMinter{
		token: githubconnector.InstallationToken{Token: "ghs_installation_token", ExpiresAt: now.Add(time.Hour)},
	}
	svc.GitHubRepositoryPostureCollector = &fakeGitHubRepositoryPostureCollector{
		err: errors.New("github posture source unavailable"),
	}
	svc.AuthenticatedRepoScannerFactory = func(historyLimit int, maxFindings int, credential repoexposure.HTTPSCloneCredential) RepoScanExecutor {
		return &fakeRepoExecutor{
			result: repoexposure.ScanResult{
				Repository:     "owner/private",
				CommitsScanned: 1,
				FilesScanned:   1,
			},
		}
	}

	record, err := svc.EnqueueRepoScan(ctx, RepoScanRequest{
		Repository: "owner/private",
		ProjectID:  "project-1",
	})
	if err != nil {
		t.Fatalf("enqueue connector-backed repo scan: %v", err)
	}
	processed, err := svc.ProcessNextQueuedRepoScan(ctx)
	if err != nil {
		t.Fatalf("process connector-backed repo scan: %v", err)
	}
	if !processed {
		t.Fatal("expected queued connector-backed repo scan to be processed")
	}
	currentScan, err := svc.GetRepoScan(ctx, record.ID)
	if err != nil {
		t.Fatalf("get current repo scan: %v", err)
	}
	if currentScan.Status != "succeeded" || currentScan.FindingCount != 0 {
		t.Fatalf("expected partial source scan to succeed without imported posture findings, got %+v", currentScan)
	}
	if currentScan.SourceHealth != db.RepoScanSourceHealthPartial {
		t.Fatalf("expected partial source health, got %+v", currentScan)
	}
	postureHealth := repoScanSourceHealthBySource(currentScan.SourceHealthDetails, "github_repository_posture")
	if postureHealth == nil || postureHealth.Status != db.RepoScanSourceHealthUnavailable {
		t.Fatalf("expected unavailable repository posture health, got %+v", currentScan.SourceHealthDetails)
	}

	openFindings, err := svc.ListRepoFindings(ctx, 10, db.RepoFindingFilter{
		Repository: "owner/private",
		Status:     string(domain.RepoFindingLifecycleOpen),
	})
	if err != nil {
		t.Fatalf("list open repo findings: %v", err)
	}
	if len(openFindings) != 1 || openFindings[0].LifecycleKey != previousFindings[0].LifecycleKey {
		t.Fatalf("expected previous posture finding to remain open after source failure, got %+v", openFindings)
	}
	fixedFindings, err := svc.ListRepoFindings(ctx, 10, db.RepoFindingFilter{
		Repository: "owner/private",
		Status:     string(domain.RepoFindingLifecycleFixed),
	})
	if err != nil {
		t.Fatalf("list fixed repo findings: %v", err)
	}
	if len(fixedFindings) != 0 {
		t.Fatalf("expected posture source failure not to mark findings fixed, got %+v", fixedFindings)
	}
}

func TestServiceGitHubAppRepoScanClosesAndReopensPostureFindingsAcrossCompleteScans(t *testing.T) {
	store := db.NewMemoryStore()
	svc := NewService(store, fakeScanner{}, "aws")
	ctx := defaultScopeContext()
	seedDefaultProject(t, store, ctx, "project-1")
	seedGitHubAppConnection(t, svc, ctx, "project-1", 101, []string{"owner/private"})
	svc.RepoScanAllowedTargets = []string{"owner/*"}
	svc.GitHubInstallationTokenMinter = &fakeGitHubInstallationTokenMinter{
		token: githubconnector.InstallationToken{Token: "ghs_installation_token", ExpiresAt: time.Now().Add(24 * time.Hour)},
	}
	svc.AuthenticatedRepoScannerFactory = func(historyLimit int, maxFindings int, credential repoexposure.HTTPSCloneCredential) RepoScanExecutor {
		return &fakeRepoExecutor{
			result: repoexposure.ScanResult{
				Repository:     "owner/private",
				CommitsScanned: 1,
				FilesScanned:   1,
			},
		}
	}
	current := time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC)
	svc.Now = func() time.Time { return current }
	insecureCheck := githubconnector.RepositoryPostureCheck{
		ID:       "default_branch_protection",
		Category: "branch_protection",
		State:    githubconnector.RepositoryPostureStateInsecure,
		Reason:   "weak_protection",
		Summary:  "Default branch protection is weak.",
	}
	secureCheck := insecureCheck
	secureCheck.State = githubconnector.RepositoryPostureStateSecure
	secureCheck.Reason = "protected"
	secureCheck.Summary = "Default branch protection is enforced."
	postureWithCheck := func(check githubconnector.RepositoryPostureCheck) *fakeGitHubRepositoryPostureCollector {
		return &fakeGitHubRepositoryPostureCollector{
			posture: githubconnector.RepositoryPosture{
				Repository:     "owner/private",
				InstallationID: 101,
				CollectedAt:    current,
				Checks:         []githubconnector.RepositoryPostureCheck{check},
			},
			organizationPosture: githubconnector.OrganizationPosture{
				Organization:   "owner",
				InstallationID: 101,
				CollectedAt:    current,
				Checks: []githubconnector.RepositoryPostureCheck{{
					ID:       "org_workflow_permissions",
					Category: "actions",
					State:    githubconnector.RepositoryPostureStateSecure,
					Reason:   "read_only_default",
					Summary:  "Organization defaults workflow tokens to read-only.",
				}},
			},
		}
	}
	runScan := func(label string) {
		t.Helper()
		if _, err := svc.EnqueueRepoScan(ctx, RepoScanRequest{Repository: "owner/private", ProjectID: "project-1"}); err != nil {
			t.Fatalf("enqueue %s repo scan: %v", label, err)
		}
		processed, err := svc.ProcessNextQueuedRepoScan(ctx)
		if err != nil {
			t.Fatalf("process %s repo scan: %v", label, err)
		}
		if !processed {
			t.Fatalf("expected %s repo scan to be processed", label)
		}
	}

	// Scan 1: the posture gap is promoted into an open durable finding.
	svc.GitHubRepositoryPostureCollector = postureWithCheck(insecureCheck)
	runScan("first")
	openFindings, err := svc.ListRepoFindings(ctx, 10, db.RepoFindingFilter{
		Repository: "owner/private",
		Status:     string(domain.RepoFindingLifecycleOpen),
	})
	if err != nil {
		t.Fatalf("list open findings after first scan: %v", err)
	}
	if len(openFindings) != 1 || openFindings[0].Detector != "github_default_branch_unprotected" {
		t.Fatalf("expected one open posture finding, got %+v", openFindings)
	}
	lifecycleKey := openFindings[0].LifecycleKey
	firstScanID := openFindings[0].ScanID
	if lifecycleKey == "" {
		t.Fatalf("expected stable posture lifecycle key, got %+v", openFindings[0])
	}
	firstSeenAt := openFindings[0].FirstSeenAt
	if firstSeenAt == nil {
		t.Fatalf("expected first seen timestamp, got %+v", openFindings[0])
	}

	// Scan 2: the check is secure again, posture collection is complete, so the
	// missing posture finding closes.
	current = current.Add(24 * time.Hour)
	svc.GitHubRepositoryPostureCollector = postureWithCheck(secureCheck)
	runScan("second")
	fixedFindings, err := svc.ListRepoFindings(ctx, 10, db.RepoFindingFilter{
		Repository: "owner/private",
		Status:     string(domain.RepoFindingLifecycleFixed),
	})
	if err != nil {
		t.Fatalf("list fixed findings after second scan: %v", err)
	}
	if len(fixedFindings) != 1 || fixedFindings[0].LifecycleKey != lifecycleKey || fixedFindings[0].FixedAt == nil {
		t.Fatalf("expected the posture finding to close after a complete secure scan, got %+v", fixedFindings)
	}

	// Scan 3: the gap reappears, so the same lifecycle key transitions to
	// reopened on a new scan row while keeping its first-seen age.
	current = current.Add(24 * time.Hour)
	svc.GitHubRepositoryPostureCollector = postureWithCheck(insecureCheck)
	runScan("third")
	reopenedFindings, err := svc.ListRepoFindings(ctx, 10, db.RepoFindingFilter{
		Repository: "owner/private",
		Status:     string(domain.RepoFindingLifecycleReopened),
	})
	if err != nil {
		t.Fatalf("list reopened findings after third scan: %v", err)
	}
	if len(reopenedFindings) != 1 || reopenedFindings[0].LifecycleKey != lifecycleKey || reopenedFindings[0].ReopenedAt == nil {
		t.Fatalf("expected the reappearing posture gap to reopen, got %+v", reopenedFindings)
	}
	if reopenedFindings[0].ScanID == firstScanID {
		t.Fatalf("expected the reopened row to come from a new scan, got %+v", reopenedFindings[0])
	}
	if reopenedFindings[0].FirstSeenAt == nil || !reopenedFindings[0].FirstSeenAt.Equal(*firstSeenAt) {
		t.Fatalf("expected reopened posture finding to keep first seen %v, got %+v", firstSeenAt, reopenedFindings[0].FirstSeenAt)
	}

	// The lifecycle summary, clusters, and trends all include the posture
	// finding with its detector/source metadata.
	summary, err := svc.GetRepoFindingsSummary(ctx, db.RepoFindingFilter{Repository: "owner/private"})
	if err != nil {
		t.Fatalf("summarize repo findings: %v", err)
	}
	if summary.ReopenedCount != 1 || summary.ByDetector["github_default_branch_unprotected"] == 0 {
		t.Fatalf("expected reopened posture finding in summary, got %+v", summary)
	}

	// Operator drill-down filters resolve posture findings by their promotion
	// source and detector.
	bySource, err := svc.ListRepoFindings(ctx, 10, db.RepoFindingFilter{
		Repository: "owner/private",
		Source:     "github_posture",
	})
	if err != nil {
		t.Fatalf("filter repo findings by source: %v", err)
	}
	if len(bySource) != 1 || bySource[0].LifecycleKey != lifecycleKey {
		t.Fatalf("expected source filter to select the posture finding, got %+v", bySource)
	}
	byDetector, err := svc.ListRepoFindings(ctx, 10, db.RepoFindingFilter{
		Repository: "owner/private",
		Detector:   "github_default_branch_unprotected",
	})
	if err != nil {
		t.Fatalf("filter repo findings by detector: %v", err)
	}
	if len(byDetector) != 1 || byDetector[0].LifecycleKey != lifecycleKey {
		t.Fatalf("expected detector filter to select the posture finding, got %+v", byDetector)
	}
	clusters, err := svc.ListRepoFindingClusters(ctx, 10, RepoFindingClusterFilter{})
	if err != nil {
		t.Fatalf("list repo finding clusters: %v", err)
	}
	var postureCluster *domain.RepoFindingCluster
	for i := range clusters {
		if clusters[i].Detector == "github_default_branch_unprotected" {
			postureCluster = &clusters[i]
			break
		}
	}
	if postureCluster == nil || postureCluster.Count != 2 || postureCluster.Spread.RepoScans != 2 {
		t.Fatalf("expected posture findings to cluster across repeated scans, got %+v", clusters)
	}
	trend, err := svc.GetRepoFindingsTrendFiltered(ctx, 10, "", string(domain.FindingRepoMisconfig), 0)
	if err != nil {
		t.Fatalf("repo findings trend: %v", err)
	}
	trendTotal := 0
	for _, point := range trend {
		trendTotal += point.Total
	}
	if trendTotal != 2 {
		t.Fatalf("expected posture findings in trend buckets across scans, got %+v", trend)
	}
}

func TestServiceGitHubAppRepoScanKeepsPostureFindingsOpenWhenCheckIsNotConclusive(t *testing.T) {
	// A posture check that GitHub could not evaluate still promotes a finding
	// under the same lifecycle key, but at a confidence/severity the reportable
	// filter drops. The durable gap must stay open rather than read as fixed,
	// because the control was never re-checked.
	states := []struct {
		name   string
		state  githubconnector.RepositoryPostureState
		reason string
	}{
		{name: "permission_limited", state: githubconnector.RepositoryPostureStatePermissionLimited},
		{name: "unavailable", state: githubconnector.RepositoryPostureStateUnavailable},
		{name: "unknown", state: githubconnector.RepositoryPostureStateUnknown},
		{name: "unsupported_plan_change", state: githubconnector.RepositoryPostureStateUnsupported, reason: "plan_unavailable"},
	}
	for _, tc := range states {
		t.Run(tc.name, func(t *testing.T) {
			store := db.NewMemoryStore()
			svc := NewService(store, fakeScanner{}, "aws")
			ctx := defaultScopeContext()
			seedDefaultProject(t, store, ctx, "project-1")
			seedGitHubAppConnection(t, svc, ctx, "project-1", 101, []string{"owner/private"})
			svc.RepoScanAllowedTargets = []string{"owner/*"}
			svc.GitHubInstallationTokenMinter = &fakeGitHubInstallationTokenMinter{
				token: githubconnector.InstallationToken{Token: "ghs_installation_token", ExpiresAt: time.Now().Add(24 * time.Hour)},
			}
			svc.AuthenticatedRepoScannerFactory = func(historyLimit int, maxFindings int, credential repoexposure.HTTPSCloneCredential) RepoScanExecutor {
				return &fakeRepoExecutor{result: repoexposure.ScanResult{Repository: "owner/private", CommitsScanned: 1, FilesScanned: 1}}
			}
			current := time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC)
			svc.Now = func() time.Time { return current }
			postureWith := func(check githubconnector.RepositoryPostureCheck) *fakeGitHubRepositoryPostureCollector {
				return &fakeGitHubRepositoryPostureCollector{
					posture: githubconnector.RepositoryPosture{
						Repository:     "owner/private",
						InstallationID: 101,
						CollectedAt:    current,
						Checks:         []githubconnector.RepositoryPostureCheck{check},
					},
					organizationPosture: githubconnector.OrganizationPosture{
						Organization:   "owner",
						InstallationID: 101,
						CollectedAt:    current,
						Checks: []githubconnector.RepositoryPostureCheck{{
							ID:    "org_workflow_permissions",
							State: githubconnector.RepositoryPostureStateSecure,
						}},
					},
				}
			}
			runScan := func(label string) {
				t.Helper()
				if _, err := svc.EnqueueRepoScan(ctx, RepoScanRequest{Repository: "owner/private", ProjectID: "project-1"}); err != nil {
					t.Fatalf("enqueue %s repo scan: %v", label, err)
				}
				processed, err := svc.ProcessNextQueuedRepoScan(ctx)
				if err != nil {
					t.Fatalf("process %s repo scan: %v", label, err)
				}
				if !processed {
					t.Fatalf("expected %s repo scan to be processed", label)
				}
			}

			svc.GitHubRepositoryPostureCollector = postureWith(githubconnector.RepositoryPostureCheck{
				ID:       "default_branch_protection",
				Category: "branch_protection",
				State:    githubconnector.RepositoryPostureStateInsecure,
				Reason:   "weak_protection",
			})
			runScan("first")
			openFindings, err := svc.ListRepoFindings(ctx, 10, db.RepoFindingFilter{
				Repository: "owner/private",
				Status:     string(domain.RepoFindingLifecycleOpen),
			})
			if err != nil {
				t.Fatalf("list open findings: %v", err)
			}
			if len(openFindings) != 1 {
				t.Fatalf("expected the posture gap to be open, got %+v", openFindings)
			}
			lifecycleKey := openFindings[0].LifecycleKey

			// The same control now reports an inconclusive state.
			current = current.Add(24 * time.Hour)
			svc.GitHubRepositoryPostureCollector = postureWith(githubconnector.RepositoryPostureCheck{
				ID:       "default_branch_protection",
				Category: "branch_protection",
				State:    tc.state,
				Reason:   tc.reason,
			})
			runScan("second")

			fixedFindings, err := svc.ListRepoFindings(ctx, 10, db.RepoFindingFilter{
				Repository: "owner/private",
				Status:     string(domain.RepoFindingLifecycleFixed),
			})
			if err != nil {
				t.Fatalf("list fixed findings: %v", err)
			}
			if len(fixedFindings) != 0 {
				t.Fatalf("expected an unverified posture check not to close the gap, got %+v", fixedFindings)
			}
			stillOpen, err := svc.ListRepoFindings(ctx, 10, db.RepoFindingFilter{
				Repository: "owner/private",
				Status:     string(domain.RepoFindingLifecycleOpen),
			})
			if err != nil {
				t.Fatalf("list open findings after inconclusive scan: %v", err)
			}
			if len(stillOpen) != 1 || stillOpen[0].LifecycleKey != lifecycleKey {
				t.Fatalf("expected the posture gap to stay open, got %+v", stillOpen)
			}
		})
	}
}

func TestServiceGitHubAppRepoScanClosesPostureFindingWhenOrganizationNoLongerApplies(t *testing.T) {
	// A repository owned by a user account genuinely has no organization policy,
	// so an organization posture gap no longer applies and must close rather than
	// linger forever.
	store := db.NewMemoryStore()
	svc := NewService(store, fakeScanner{}, "aws")
	ctx := defaultScopeContext()
	seedDefaultProject(t, store, ctx, "project-1")
	seedGitHubAppConnection(t, svc, ctx, "project-1", 101, []string{"owner/private"})
	svc.RepoScanAllowedTargets = []string{"owner/*"}
	svc.GitHubInstallationTokenMinter = &fakeGitHubInstallationTokenMinter{
		token: githubconnector.InstallationToken{Token: "ghs_installation_token", ExpiresAt: time.Now().Add(24 * time.Hour)},
	}
	svc.AuthenticatedRepoScannerFactory = func(historyLimit int, maxFindings int, credential repoexposure.HTTPSCloneCredential) RepoScanExecutor {
		return &fakeRepoExecutor{result: repoexposure.ScanResult{Repository: "owner/private", CommitsScanned: 1, FilesScanned: 1}}
	}
	current := time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC)
	svc.Now = func() time.Time { return current }
	collectorWith := func(orgChecks []githubconnector.RepositoryPostureCheck) *fakeGitHubRepositoryPostureCollector {
		return &fakeGitHubRepositoryPostureCollector{
			posture: githubconnector.RepositoryPosture{
				Repository:     "owner/private",
				InstallationID: 101,
				CollectedAt:    current,
				Checks: []githubconnector.RepositoryPostureCheck{{
					ID:    "default_branch_protection",
					State: githubconnector.RepositoryPostureStateSecure,
				}},
			},
			organizationPosture: githubconnector.OrganizationPosture{
				Organization:   "owner",
				InstallationID: 101,
				CollectedAt:    current,
				Checks:         orgChecks,
			},
		}
	}
	runScan := func(label string) {
		t.Helper()
		if _, err := svc.EnqueueRepoScan(ctx, RepoScanRequest{Repository: "owner/private", ProjectID: "project-1"}); err != nil {
			t.Fatalf("enqueue %s repo scan: %v", label, err)
		}
		processed, err := svc.ProcessNextQueuedRepoScan(ctx)
		if err != nil {
			t.Fatalf("process %s repo scan: %v", label, err)
		}
		if !processed {
			t.Fatalf("expected %s repo scan to be processed", label)
		}
	}

	svc.GitHubRepositoryPostureCollector = collectorWith([]githubconnector.RepositoryPostureCheck{{
		ID:     "org_workflow_permissions",
		State:  githubconnector.RepositoryPostureStateInsecure,
		Reason: "write_token_or_pr_approval",
	}})
	runScan("first")
	openFindings, err := svc.ListRepoFindings(ctx, 10, db.RepoFindingFilter{
		Repository: "owner/private",
		Status:     string(domain.RepoFindingLifecycleOpen),
	})
	if err != nil {
		t.Fatalf("list open findings: %v", err)
	}
	if len(openFindings) != 1 || openFindings[0].AdapterSource != "github_org_posture" {
		t.Fatalf("expected an open org posture gap, got %+v", openFindings)
	}

	current = current.Add(24 * time.Hour)
	svc.GitHubRepositoryPostureCollector = collectorWith([]githubconnector.RepositoryPostureCheck{{
		ID:     "org_workflow_permissions",
		State:  githubconnector.RepositoryPostureStateUnsupported,
		Reason: "not_an_organization",
	}})
	runScan("second")
	fixedFindings, err := svc.ListRepoFindings(ctx, 10, db.RepoFindingFilter{
		Repository: "owner/private",
		Status:     string(domain.RepoFindingLifecycleFixed),
	})
	if err != nil {
		t.Fatalf("list fixed findings: %v", err)
	}
	if len(fixedFindings) != 1 || fixedFindings[0].AdapterSource != "github_org_posture" {
		t.Fatalf("expected the org posture gap to close once it no longer applies, got %+v", fixedFindings)
	}
}

func TestServiceRepoScanWithoutPostureCollectionPreservesPostureFindings(t *testing.T) {
	store := db.NewMemoryStore()
	svc := NewService(store, fakeScanner{}, "aws")
	ctx := defaultScopeContext()
	now := time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC)

	firstScan, err := store.CreateRepoScan(ctx, "owner/private", db.RepoScanSource{}, db.RepoScanContext{ScanMode: db.RepoScanModeDeep}, now)
	if err != nil {
		t.Fatalf("create first repo scan: %v", err)
	}
	postureFindings := githubconnector.RepositoryPostureFindings(githubconnector.RepositoryPosture{
		Repository:     "owner/private",
		InstallationID: 101,
		CollectedAt:    now,
		Checks: []githubconnector.RepositoryPostureCheck{{
			ID:       "default_branch_protection",
			Category: "branch_protection",
			State:    githubconnector.RepositoryPostureStateInsecure,
			Reason:   "weak_protection",
			Summary:  "Default branch protection is weak.",
		}},
	}, now)
	if len(postureFindings) != 1 {
		t.Fatalf("expected one posture finding, got %+v", postureFindings)
	}
	nativeFinding := domain.Finding{
		ID:              "finding:native-secret",
		Type:            domain.FindingSecretExposure,
		Severity:        domain.SeverityHigh,
		ConfidenceScore: 0.95,
		Title:           "GitHub token exposed",
		HumanSummary:    "A token-like value was committed.",
		Repository:      "owner/private",
		Commit:          "abc123",
		FilePath:        "config/app.env",
		LineNumber:      7,
		Detector:        "github_token",
		Evidence: map[string]any{
			"repository":         "owner/private",
			"detector":           "github_token",
			"file_path":          "config/app.env",
			"line_number":        7,
			"secret_fingerprint": "fp-token",
		},
		CreatedAt: now,
	}
	if err := store.UpsertRepoFindings(ctx, firstScan.ID, append(postureFindings, nativeFinding)); err != nil {
		t.Fatalf("upsert first scan findings: %v", err)
	}
	if err := store.CompleteRepoScan(ctx, firstScan.ID, "succeeded", now.Add(time.Minute), 1, 1, 2, false, db.RepoScanContext{ScanMode: db.RepoScanModeDeep}, ""); err != nil {
		t.Fatalf("complete first repo scan: %v", err)
	}

	// A complete plain scan never runs GitHub posture collection: it may close
	// the missing native finding but must leave the posture finding open.
	secondScan, err := store.CreateRepoScan(ctx, "owner/private", db.RepoScanSource{}, db.RepoScanContext{ScanMode: db.RepoScanModeDeep}, now.Add(24*time.Hour))
	if err != nil {
		t.Fatalf("create second repo scan: %v", err)
	}
	if err := store.CompleteRepoScan(ctx, secondScan.ID, "succeeded", now.Add(24*time.Hour+time.Minute), 1, 1, 0, false, db.RepoScanContext{
		ScanMode: db.RepoScanModeDeep,
		SourceDetails: []db.RepoScanSourceHealth{
			{Source: "identrail_repo_scanner", Status: db.RepoScanSourceHealthComplete},
		},
	}, ""); err != nil {
		t.Fatalf("complete second repo scan: %v", err)
	}
	openFindings, err := svc.ListRepoFindings(ctx, 10, db.RepoFindingFilter{
		Repository: "owner/private",
		Status:     string(domain.RepoFindingLifecycleOpen),
	})
	if err != nil {
		t.Fatalf("list open findings after plain scan: %v", err)
	}
	if len(openFindings) != 1 || openFindings[0].LifecycleKey != postureFindings[0].LifecycleKey {
		t.Fatalf("expected the posture finding to stay open after a plain scan, got %+v", openFindings)
	}
	fixedFindings, err := svc.ListRepoFindings(ctx, 10, db.RepoFindingFilter{
		Repository: "owner/private",
		Status:     string(domain.RepoFindingLifecycleFixed),
	})
	if err != nil {
		t.Fatalf("list fixed findings after plain scan: %v", err)
	}
	if len(fixedFindings) != 1 || fixedFindings[0].Detector != "github_token" {
		t.Fatalf("expected only the native finding to close after a plain scan, got %+v", fixedFindings)
	}

	// A complete scan that collected the repository posture source closes the
	// still-missing posture finding.
	thirdScan, err := store.CreateRepoScan(ctx, "owner/private", db.RepoScanSource{}, db.RepoScanContext{ScanMode: db.RepoScanModeDeep}, now.Add(48*time.Hour))
	if err != nil {
		t.Fatalf("create third repo scan: %v", err)
	}
	if err := store.CompleteRepoScan(ctx, thirdScan.ID, "succeeded", now.Add(48*time.Hour+time.Minute), 1, 1, 0, false, db.RepoScanContext{
		ScanMode: db.RepoScanModeDeep,
		SourceDetails: []db.RepoScanSourceHealth{
			{Source: "identrail_repo_scanner", Status: db.RepoScanSourceHealthComplete},
			{Source: "github_repository_posture", Status: db.RepoScanSourceHealthComplete},
			{Source: "github_organization_posture", Status: db.RepoScanSourceHealthComplete},
		},
	}, ""); err != nil {
		t.Fatalf("complete third repo scan: %v", err)
	}
	openAfterPosture, err := svc.ListRepoFindings(ctx, 10, db.RepoFindingFilter{
		Repository: "owner/private",
		Status:     string(domain.RepoFindingLifecycleOpen),
	})
	if err != nil {
		t.Fatalf("list open findings after posture scan: %v", err)
	}
	if len(openAfterPosture) != 0 {
		t.Fatalf("expected posture finding to close after posture collection, got %+v", openAfterPosture)
	}
}

func TestRepoScanSourceHealthClassification(t *testing.T) {
	tests := []struct {
		name    string
		code    string
		message string
		want    string
	}{
		{name: "permission limited", code: "alert_list_error", message: "403 resource not accessible by integration", want: db.RepoScanSourceHealthPermissionLimited},
		{name: "rate limited", code: "alert_list_error", message: "secondary rate limit exceeded", want: db.RepoScanSourceHealthRateLimited},
		{name: "rate limited with 403", code: "alert_list_error", message: "HTTP 403: Secondary rate limit hit", want: db.RepoScanSourceHealthRateLimited},
		{name: "unavailable", code: "posture_collect_error", message: "GitHub API unavailable: 503", want: db.RepoScanSourceHealthUnavailable},
		{name: "partial normalization", code: "normalize_error", message: "could not normalize one alert", want: db.RepoScanSourceHealthPartial},
		{name: "unknown", code: "alert_list_error", message: "unexpected response", want: db.RepoScanSourceHealthUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyRepoScanSourceHealth(tt.code, tt.message); got != tt.want {
				t.Fatalf("expected %s, got %s", tt.want, got)
			}
		})
	}
}

func TestRepoScanSourceHealthDetailsMixedGitHubSources(t *testing.T) {
	svc := NewService(db.NewMemoryStore(), fakeScanner{}, "aws")
	svc.GitHubCodeScanningAlertCollector = &fakeGitHubCodeScanningAlertCollector{}
	svc.GitHubSecretScanningAlertCollector = &fakeGitHubSecretScanningAlertCollector{}
	svc.GitHubDependabotAlertCollector = &fakeGitHubDependabotAlertCollector{}
	svc.GitHubRepositoryPostureCollector = &fakeGitHubRepositoryPostureCollector{}
	details := svc.repoScanSourceHealthDetails(db.RepoScanRecord{
		Repository: "owner/repo",
		Source: db.RepoScanSource{
			Provider:       "github_app",
			InstallationID: 101,
		},
	}, false, []providers.SourceError{
		{Collector: "github_secret_scanning", Code: "alert_list_error", Message: "403 resource not accessible by integration"},
		{Collector: "github_dependabot", Code: "alert_list_error", Message: "secondary rate limit exceeded"},
	})
	overall, normalized := db.NormalizeRepoScanSourceHealth("", details)
	if overall != db.RepoScanSourceHealthPartial {
		t.Fatalf("expected mixed source health to be partial, got %s with %+v", overall, normalized)
	}
	if health := repoScanSourceHealthBySource(normalized, "github_code_scanning"); health == nil || health.Status != db.RepoScanSourceHealthComplete {
		t.Fatalf("expected complete code scanning source, got %+v", normalized)
	}
	if health := repoScanSourceHealthBySource(normalized, "github_secret_scanning"); health == nil || health.Status != db.RepoScanSourceHealthPermissionLimited {
		t.Fatalf("expected permission-limited secret scanning source, got %+v", normalized)
	}
	if health := repoScanSourceHealthBySource(normalized, "github_dependabot"); health == nil || health.Status != db.RepoScanSourceHealthRateLimited {
		t.Fatalf("expected rate-limited dependabot source, got %+v", normalized)
	}
}

func TestRepoScanSourceHealthDetailsMarksGitHubSourcesSkippedWhenTruncated(t *testing.T) {
	svc := NewService(db.NewMemoryStore(), fakeScanner{}, "aws")
	svc.GitHubCodeScanningAlertCollector = &fakeGitHubCodeScanningAlertCollector{}
	svc.GitHubSecretScanningAlertCollector = &fakeGitHubSecretScanningAlertCollector{}
	svc.GitHubDependabotAlertCollector = &fakeGitHubDependabotAlertCollector{}
	svc.GitHubRepositoryPostureCollector = &fakeGitHubRepositoryPostureCollector{}

	details := svc.repoScanSourceHealthDetails(db.RepoScanRecord{
		Repository: "owner/private",
		Source: db.RepoScanSource{
			Provider:       "github_app",
			InstallationID: 101,
		},
	}, true, nil)
	overall, normalized := db.NormalizeRepoScanSourceHealth("", details)
	if overall != db.RepoScanSourceHealthPartial {
		t.Fatalf("expected truncated source collection to be partial, got %s with %+v", overall, normalized)
	}
	truncatedSources := []string{
		"github_code_scanning",
		"github_secret_scanning",
		"github_dependabot",
		"github_repository_posture",
		"github_organization_posture",
	}
	for _, source := range truncatedSources {
		health := repoScanSourceHealthBySource(normalized, source)
		if health == nil || health.Status != db.RepoScanSourceHealthPartial {
			t.Fatalf("expected truncated source %s to be partial, got %+v", source, normalized)
		}
		if health.Code != "scan_truncated" {
			t.Fatalf("expected truncated source %s to have scan_truncated code, got %+v", source, health)
		}
		if !strings.Contains(strings.ToLower(health.Message), "truncated") {
			t.Fatalf("expected truncated source %s to include truncated message, got %+v", source, health)
		}
	}
}

func repoScanSourceHealthBySource(details []db.RepoScanSourceHealth, source string) *db.RepoScanSourceHealth {
	for i := range details {
		if details[i].Source == source {
			return &details[i]
		}
	}
	return nil
}

func repoFindingByDetector(findings []domain.Finding, detector string) *domain.Finding {
	for i := range findings {
		if findings[i].Detector == detector {
			return &findings[i]
		}
	}
	return nil
}

func TestServiceProcessQueuedGitHubAppRepoScanRedactsInstallationTokenErrors(t *testing.T) {
	store := db.NewMemoryStore()
	svc := NewService(store, fakeScanner{}, "aws")
	ctx := defaultScopeContext()
	seedDefaultProject(t, store, ctx, "project-1")
	seedGitHubAppConnection(t, svc, ctx, "project-1", 101, []string{"owner/private"})
	svc.RepoScanAllowedTargets = []string{"owner/*"}
	svc.GitHubInstallationTokenMinter = &fakeGitHubInstallationTokenMinter{
		token: githubconnector.InstallationToken{Token: "ghs_secret_token", ExpiresAt: time.Now().Add(time.Hour)},
	}
	svc.AuthenticatedRepoScannerFactory = func(historyLimit int, maxFindings int, credential repoexposure.HTTPSCloneCredential) RepoScanExecutor {
		return &fakeRepoExecutor{err: errors.New("clone failed with token ghs_secret_token")}
	}

	record, err := svc.EnqueueRepoScan(ctx, RepoScanRequest{
		Repository: "owner/private",
		ProjectID:  "project-1",
	})
	if err != nil {
		t.Fatalf("enqueue connector-backed repo scan: %v", err)
	}
	processed, err := svc.ProcessNextQueuedRepoScan(ctx)
	if err == nil {
		t.Fatal("expected connector-backed repo scan to fail")
	}
	if !processed {
		t.Fatal("expected queued connector-backed repo scan to be claimed")
	}
	if strings.Contains(err.Error(), "ghs_secret_token") || !strings.Contains(err.Error(), "[redacted]") {
		t.Fatalf("expected returned error to redact token, got %v", err)
	}
	stored, getErr := svc.GetRepoScan(ctx, record.ID)
	if getErr != nil {
		t.Fatalf("get failed repo scan: %v", getErr)
	}
	if strings.Contains(stored.ErrorMessage, "ghs_secret_token") || !strings.Contains(stored.ErrorMessage, "[redacted]") {
		t.Fatalf("expected persisted error to redact token, got %q", stored.ErrorMessage)
	}
}

func TestServiceProcessNextQueuedRepoScanContinuesEnqueuedTraceContext(t *testing.T) {
	store := db.NewMemoryStore()
	repoExecutor := &fakeRepoExecutor{
		result: repoexposure.ScanResult{
			Repository:     "owner/repo",
			CommitsScanned: 5,
			FilesScanned:   1,
		},
	}
	svc := NewService(store, fakeScanner{}, "aws")
	svc.RepoScanAllowedTargets = []string{"owner/*"}
	svc.RepoScannerFactory = func(historyLimit int, maxFindings int) RepoScanExecutor {
		return repoExecutor
	}

	enqueueCtx, expectedTraceID := remoteTraceContext(defaultScopeContext())
	record, err := svc.EnqueueRepoScan(enqueueCtx, RepoScanRequest{Repository: "owner/repo"})
	if err != nil {
		t.Fatalf("enqueue repo scan: %v", err)
	}
	if record.TraceParent == "" {
		t.Fatal("expected queued repo scan record to persist traceparent")
	}

	processed, err := svc.ProcessNextQueuedRepoScan(defaultScopeContext())
	if err != nil {
		t.Fatalf("process queued repo scan: %v", err)
	}
	if !processed {
		t.Fatal("expected queued repo scan to be processed")
	}
	if repoExecutor.runCtx == nil {
		t.Fatal("expected repo executor context capture")
	}
	spanContext := trace.SpanContextFromContext(repoExecutor.runCtx)
	if !spanContext.IsValid() {
		t.Fatal("expected valid span context in repo executor run context")
	}
	if spanContext.TraceID() != expectedTraceID {
		t.Fatalf("expected trace id %s, got %s", expectedTraceID.String(), spanContext.TraceID().String())
	}
}

func TestServiceCountQueuedRepoScansForDepthReturnsZeroWhenAnyScopeCountFails(t *testing.T) {
	store := &failingAnyScopeDepthStore{MemoryStore: db.NewMemoryStore()}
	svc := NewService(store, fakeScanner{}, "aws")
	scopedCtx := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	now := time.Date(2026, 5, 10, 11, 45, 0, 0, time.UTC)

	if _, err := store.CreateQueuedRepoScanWithinLimit(scopedCtx, "owner/repo", db.RepoScanSource{}, db.RepoScanContext{}, 50, 200, now, 5); err != nil {
		t.Fatalf("create queued repo scan: %v", err)
	}
	scopedCount, err := store.CountQueuedRepoScans(scopedCtx)
	if err != nil {
		t.Fatalf("count queued repo scans in scope: %v", err)
	}
	if scopedCount != 1 {
		t.Fatalf("expected one scoped queued repo scan, got %d", scopedCount)
	}

	queuedCount := svc.countQueuedRepoScansForDepth(scopedCtx)
	if queuedCount != 0 {
		t.Fatalf("expected depth 0 when any-scope repo count fails, got %d", queuedCount)
	}
}

func TestServiceEnqueueRepoScanGuards(t *testing.T) {
	svc := NewService(db.NewMemoryStore(), fakeScanner{}, "aws")
	svc.RepoScanAllowedTargets = []string{"owner/*"}
	svc.RepoQueueMaxPending = 1

	if _, err := svc.EnqueueRepoScan(defaultScopeContext(), RepoScanRequest{Repository: "owner/repo"}); err != nil {
		t.Fatalf("enqueue first repo scan: %v", err)
	}
	if _, err := svc.EnqueueRepoScan(defaultScopeContext(), RepoScanRequest{Repository: "owner/repo"}); !errors.Is(err, ErrRepoScanInProgress) {
		t.Fatalf("expected repo in-progress error for duplicate target, got %v", err)
	}
	if _, err := svc.EnqueueRepoScan(defaultScopeContext(), RepoScanRequest{Repository: "Owner/Repo"}); !errors.Is(err, ErrRepoScanInProgress) {
		t.Fatalf("expected repo in-progress error for case-variant duplicate target, got %v", err)
	}
	if _, err := svc.EnqueueRepoScan(defaultScopeContext(), RepoScanRequest{Repository: "owner/another"}); !errors.Is(err, ErrRepoScanQueueFull) {
		t.Fatalf("expected repo queue full error, got %v", err)
	}
}

func TestServiceCancelRepoScanReleasesTarget(t *testing.T) {
	store := db.NewMemoryStore()
	svc := NewService(store, fakeScanner{}, "aws")
	svc.RepoScanAllowedTargets = []string{"owner/*"}
	svc.RepoQueueMaxPending = 1
	svc.Now = func() time.Time { return time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC) }

	queued, err := svc.EnqueueRepoScan(defaultScopeContext(), RepoScanRequest{Repository: "owner/repo"})
	if err != nil {
		t.Fatalf("enqueue repo scan: %v", err)
	}
	canceled, err := svc.CancelRepoScan(defaultScopeContext(), queued.ID)
	if err != nil {
		t.Fatalf("cancel repo scan: %v", err)
	}
	if canceled.Status != "failed" || canceled.ErrorMessage != userCanceledRepoScanMessage {
		t.Fatalf("unexpected canceled repo scan: %+v", canceled)
	}
	if err := svc.completeRepoScanTerminal(defaultScopeContext(), queued.ID, "completed", svc.Now().Add(time.Minute), 3, 2, 1, false, db.RepoScanContext{}, ""); !errors.Is(err, db.ErrConflict) {
		t.Fatalf("expected stale terminal completion after cancel to conflict, got %v", err)
	}
	afterCompletion, err := store.GetRepoScan(defaultScopeContext(), queued.ID)
	if err != nil {
		t.Fatalf("get canceled repo scan: %v", err)
	}
	if afterCompletion.Status != "failed" || afterCompletion.ErrorMessage != userCanceledRepoScanMessage {
		t.Fatalf("expected stale completion not to overwrite cancel, got %+v", afterCompletion)
	}
	if _, err := svc.EnqueueRepoScan(defaultScopeContext(), RepoScanRequest{Repository: "owner/repo"}); err != nil {
		t.Fatalf("enqueue repo scan after cancel: %v", err)
	}
	if _, err := svc.CancelRepoScan(defaultScopeContext(), queued.ID); !errors.Is(err, ErrRepoScanCancelUnavailable) {
		t.Fatalf("expected cancel unavailable for terminal scan, got %v", err)
	}
}

func TestServiceProcessQueuedRepoScanDoesNotAdvanceCursorAfterCancelDuringRun(t *testing.T) {
	store := db.NewMemoryStore()
	svc := NewService(store, fakeScanner{}, "aws")
	svc.RepoScanAllowedTargets = []string{"owner/*"}
	now := time.Date(2026, 5, 20, 12, 30, 0, 0, time.UTC)
	svc.Now = func() time.Time { return now }
	scopeCtx := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	head := "2222222222222222222222222222222222222222"
	var queued db.RepoScanRecord
	var events []RepoScanQueueEvent
	svc.OnRepoScanQueueEvent = func(event RepoScanQueueEvent) {
		events = append(events, event)
	}
	svc.RepoScannerFactory = func(int, int) RepoScanExecutor {
		return &fakeRepoExecutor{
			beforeReturn: func(context.Context, string) {
				if _, err := svc.CancelRepoScan(scopeCtx, queued.ID); err != nil {
					t.Errorf("cancel repo scan during run: %v", err)
				}
			},
			result: repoexposure.ScanResult{
				Repository:     "owner/repo",
				CommitsScanned: 1,
				FilesScanned:   1,
				Findings: []domain.Finding{{
					ID:        "rf-canceled-before-upsert",
					Type:      domain.FindingSecretExposure,
					Severity:  domain.SeverityHigh,
					CreatedAt: now,
				}},
				ScanMode:     db.RepoScanModeDelta,
				HeadRevision: head,
			},
		}
	}

	var err error
	queued, err = svc.EnqueueRepoScan(scopeCtx, RepoScanRequest{
		Repository:   "owner/repo",
		ScanMode:     db.RepoScanModeDelta,
		HeadRevision: head,
	})
	if err != nil {
		t.Fatalf("enqueue repo scan: %v", err)
	}

	processed, err := svc.ProcessNextQueuedRepoScan(defaultScopeContext())
	if err != nil {
		t.Fatalf("process canceled repo scan: %v", err)
	}
	if !processed {
		t.Fatal("expected canceled repo scan to count as processed")
	}
	stored, err := store.GetRepoScan(scopeCtx, queued.ID)
	if err != nil {
		t.Fatalf("get canceled repo scan: %v", err)
	}
	if stored.Status != "failed" || stored.ErrorMessage != userCanceledRepoScanMessage || stored.CursorAfter != "" {
		t.Fatalf("expected canceled scan to stay failed without cursor_after, got %+v", stored)
	}
	if _, err := store.GetRepoScanCursor(scopeCtx, "owner/repo", db.RepoScanSource{}); !errors.Is(err, db.ErrNotFound) {
		t.Fatalf("expected canceled scan not to advance cursor, got %v", err)
	}
	findings, err := svc.ListRepoFindings(scopeCtx, 10, db.RepoFindingFilter{RepoScanID: queued.ID})
	if err != nil {
		t.Fatalf("list canceled scan findings: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected canceled scan not to persist findings, got %+v", findings)
	}
	for _, event := range events {
		if event.Kind == "succeeded" {
			t.Fatalf("canceled scan must not emit success event, got events %+v", events)
		}
	}
}

func TestServiceProcessQueuedRepoScanClearsFindingsWhenCancelWinsCompletion(t *testing.T) {
	now := time.Date(2026, 5, 20, 12, 45, 0, 0, time.UTC)
	store := &cancelOnCompleteRepoScanStore{
		MemoryStore: db.NewMemoryStore(),
		now:         now.Add(2 * time.Minute),
	}
	svc := NewService(store, fakeScanner{}, "aws")
	svc.RepoScanAllowedTargets = []string{"owner/*"}
	svc.Now = func() time.Time { return now }
	scopeCtx := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	svc.RepoScannerFactory = func(int, int) RepoScanExecutor {
		return &fakeRepoExecutor{
			result: repoexposure.ScanResult{
				Repository:     "owner/repo",
				CommitsScanned: 1,
				FilesScanned:   1,
				Findings: []domain.Finding{{
					ID:        "rf-canceled-after-upsert",
					Type:      domain.FindingSecretExposure,
					Severity:  domain.SeverityHigh,
					CreatedAt: now,
				}},
			},
		}
	}

	queued, err := svc.EnqueueRepoScan(scopeCtx, RepoScanRequest{Repository: "owner/repo"})
	if err != nil {
		t.Fatalf("enqueue repo scan: %v", err)
	}

	processed, err := svc.ProcessNextQueuedRepoScan(defaultScopeContext())
	if err != nil {
		t.Fatalf("process canceled repo scan: %v", err)
	}
	if !processed {
		t.Fatal("expected canceled repo scan to count as processed")
	}
	stored, err := store.GetRepoScan(scopeCtx, queued.ID)
	if err != nil {
		t.Fatalf("get canceled repo scan: %v", err)
	}
	if stored.Status != "failed" || stored.ErrorMessage != userCanceledRepoScanMessage {
		t.Fatalf("expected canceled scan to stay failed, got %+v", stored)
	}
	findings, err := svc.ListRepoFindings(scopeCtx, 10, db.RepoFindingFilter{RepoScanID: queued.ID})
	if err != nil {
		t.Fatalf("list canceled scan findings: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected terminal conflict cleanup to remove repo findings, got %+v", findings)
	}
}

func TestServiceProcessQueuedRepoScanAcrossScopes(t *testing.T) {
	store := db.NewMemoryStore()
	svc := NewService(store, fakeScanner{}, "aws")
	svc.RepoScanAllowedTargets = []string{"owner/*"}
	svc.RepoScannerFactory = func(historyLimit int, maxFindings int) RepoScanExecutor {
		return &fakeRepoExecutor{
			result: repoexposure.ScanResult{
				Repository:     "owner/repo",
				CommitsScanned: historyLimit,
				FilesScanned:   3,
				Findings: []domain.Finding{
					{ID: "rf-cross-scope", Type: domain.FindingSecretExposure, Severity: domain.SeverityHigh, CreatedAt: time.Now().UTC()},
				},
			},
		}
	}
	tenantScopeCtx := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	record, err := svc.EnqueueRepoScan(tenantScopeCtx, RepoScanRequest{
		Repository:   "owner/repo",
		HistoryLimit: 10,
		MaxFindings:  20,
	})
	if err != nil {
		t.Fatalf("enqueue scoped repo scan: %v", err)
	}

	processed, err := svc.ProcessNextQueuedRepoScan(defaultScopeContext())
	if err != nil {
		t.Fatalf("process scoped repo scan from default scope context: %v", err)
	}
	if !processed {
		t.Fatal("expected queued scoped repo scan to be processed")
	}

	stored, err := svc.GetRepoScan(tenantScopeCtx, record.ID)
	if err != nil {
		t.Fatalf("get scoped repo scan: %v", err)
	}
	if stored.Status != "succeeded" {
		t.Fatalf("expected succeeded repo scan status, got %q", stored.Status)
	}
}

func TestServiceProcessNextQueuedRepoScanFailsStaleRunningScan(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 5, 18, 23, 45, 0, 0, time.UTC)
	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	executor := &fakeRepoExecutor{
		result: repoexposure.ScanResult{
			Repository:     "owner/repo",
			CommitsScanned: 10,
			FilesScanned:   2,
		},
	}
	svc.RepoScannerFactory = func(historyLimit int, maxFindings int) RepoScanExecutor {
		return executor
	}
	staleRunning, err := store.CreateRepoScan(defaultScopeContext(), "owner/repo", db.RepoScanSource{}, db.RepoScanContext{}, now.Add(-40*time.Minute))
	if err != nil {
		t.Fatalf("create stale running repo scan: %v", err)
	}

	processed, err := svc.ProcessNextQueuedRepoScan(defaultScopeContext())
	if err != nil {
		t.Fatalf("process stale running repo scan: %v", err)
	}
	if !processed {
		t.Fatal("expected stale running repo scan to be handled")
	}
	stored, err := svc.GetRepoScan(defaultScopeContext(), staleRunning.ID)
	if err != nil {
		t.Fatalf("get failed stale repo scan: %v", err)
	}
	if stored.Status != "failed" {
		t.Fatalf("expected stale running repo scan to fail, got %+v", stored)
	}
	if stored.FinishedAt == nil {
		t.Fatalf("expected stale running repo scan to have finished_at set, got %+v", stored)
	}
	if stored.ErrorMessage != staleRepoScanFailureMessage {
		t.Fatalf("expected stale running repo scan error %q, got %q", staleRepoScanFailureMessage, stored.ErrorMessage)
	}
	if executor.calls != 0 {
		t.Fatalf("expected stale running repo scan not to run scanner, got %d calls", executor.calls)
	}
}

func TestServiceEnqueueRepoScanConcurrentDeduplicatesTarget(t *testing.T) {
	svc := NewService(db.NewMemoryStore(), fakeScanner{}, "aws")
	svc.RepoScanAllowedTargets = []string{"owner/*"}
	svc.RepoQueueMaxPending = 100

	const workers = 12
	start := make(chan struct{})
	var wg sync.WaitGroup
	var successCount int32
	var inProgressCount int32
	var queueFullCount int32
	var unexpectedErrCount int32

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := svc.EnqueueRepoScan(defaultScopeContext(), RepoScanRequest{Repository: "owner/repo"})
			switch {
			case err == nil:
				atomic.AddInt32(&successCount, 1)
			case errors.Is(err, ErrRepoScanInProgress):
				atomic.AddInt32(&inProgressCount, 1)
			case errors.Is(err, ErrRepoScanQueueFull):
				atomic.AddInt32(&queueFullCount, 1)
			default:
				atomic.AddInt32(&unexpectedErrCount, 1)
			}
		}()
	}

	close(start)
	wg.Wait()

	if unexpectedErrCount != 0 {
		t.Fatalf("expected no unexpected enqueue errors, got %d", unexpectedErrCount)
	}
	if queueFullCount != 0 {
		t.Fatalf("expected no queue-full errors, got %d", queueFullCount)
	}
	if successCount != 1 {
		t.Fatalf("expected exactly one successful enqueue, got %d", successCount)
	}
	if inProgressCount != workers-1 {
		t.Fatalf("expected %d in-progress responses, got %d", workers-1, inProgressCount)
	}
}

func TestServiceProcessQueuedRepoScanRequeuesWhenExecutionLockHeld(t *testing.T) {
	store := db.NewMemoryStore()
	svc := NewService(store, fakeScanner{}, "aws")
	svc.RepoScanAllowedTargets = []string{"owner/*"}
	queuedAt := time.Date(2026, 3, 24, 10, 0, 0, 0, time.UTC)
	svc.Now = func() time.Time { return queuedAt }

	record, err := svc.EnqueueRepoScan(defaultScopeContext(), RepoScanRequest{Repository: "owner/repo"})
	if err != nil {
		t.Fatalf("enqueue repo scan: %v", err)
	}
	locker := scheduler.NewInMemoryLocker()
	release, ok := locker.TryAcquire(context.Background(), "identrail:repo-scan:owner/repo")
	if !ok {
		t.Fatal("expected lock acquire")
	}
	defer release(context.Background())
	svc.Locker = locker

	processed, err := svc.ProcessNextQueuedRepoScan(defaultScopeContext())
	if err != nil {
		t.Fatalf("process queued repo scan: %v", err)
	}
	if !processed {
		t.Fatal("expected requeue handling to count as queue progress")
	}
	stored, err := svc.GetRepoScan(defaultScopeContext(), record.ID)
	if err != nil {
		t.Fatalf("get repo scan: %v", err)
	}
	if stored.Status != "queued" {
		t.Fatalf("expected repo scan to be requeued, got status %q", stored.Status)
	}
	if !stored.StartedAt.After(queuedAt) {
		t.Fatalf("expected requeued repo scan to move to the back of the queue")
	}
}

func TestServiceProcessQueuedRepoScanContinuesToNextTargetAfterRequeue(t *testing.T) {
	store := db.NewMemoryStore()
	svc := NewService(store, fakeScanner{}, "aws")
	svc.RepoScanAllowedTargets = []string{"owner/*"}
	now := time.Date(2026, 3, 24, 11, 0, 0, 0, time.UTC)
	svc.Now = func() time.Time { return now }
	svc.RepoScannerFactory = func(historyLimit int, maxFindings int) RepoScanExecutor {
		return &fakeRepoExecutor{
			result: repoexposure.ScanResult{
				Repository:     "owner/repo-b",
				CommitsScanned: historyLimit,
				FilesScanned:   2,
				Findings: []domain.Finding{
					{ID: "rf-next", Type: domain.FindingSecretExposure, Severity: domain.SeverityHigh, CreatedAt: now},
				},
			},
		}
	}

	repoA, err := svc.EnqueueRepoScan(defaultScopeContext(), RepoScanRequest{Repository: "owner/repo-a"})
	if err != nil {
		t.Fatalf("enqueue repo-a scan: %v", err)
	}
	repoB, err := svc.EnqueueRepoScan(defaultScopeContext(), RepoScanRequest{Repository: "owner/repo-b"})
	if err != nil {
		t.Fatalf("enqueue repo-b scan: %v", err)
	}

	locker := scheduler.NewInMemoryLocker()
	release, ok := locker.TryAcquire(context.Background(), "identrail:repo-scan:owner/repo-a")
	if !ok {
		t.Fatal("expected lock acquire")
	}
	defer release(context.Background())
	svc.Locker = locker

	processed, err := svc.ProcessNextQueuedRepoScan(defaultScopeContext())
	if err != nil {
		t.Fatalf("first queue process failed: %v", err)
	}
	if !processed {
		t.Fatal("expected first queue pass to requeue locked target")
	}

	processed, err = svc.ProcessNextQueuedRepoScan(defaultScopeContext())
	if err != nil {
		t.Fatalf("second queue process failed: %v", err)
	}
	if !processed {
		t.Fatal("expected second queue pass to process next target")
	}

	repoARecord, err := svc.GetRepoScan(defaultScopeContext(), repoA.ID)
	if err != nil {
		t.Fatalf("get repo-a scan: %v", err)
	}
	if repoARecord.Status != "queued" {
		t.Fatalf("expected repo-a to remain queued while lock is held, got %q", repoARecord.Status)
	}

	repoBRecord, err := svc.GetRepoScan(defaultScopeContext(), repoB.ID)
	if err != nil {
		t.Fatalf("get repo-b scan: %v", err)
	}
	if repoBRecord.Status != "succeeded" {
		t.Fatalf("expected repo-b to complete, got %q", repoBRecord.Status)
	}
}

func TestServiceProcessQueuedRepoScanFailureDoesNotBlockLaterQueuedTarget(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 3, 24, 12, 0, 0, 0, time.UTC)
	svc := NewService(store, fakeScanner{}, "aws")
	svc.RepoScanAllowedTargets = []string{"owner/*"}
	svc.Now = func() time.Time { return now }

	factoryCalls := 0
	svc.RepoScannerFactory = func(historyLimit int, maxFindings int) RepoScanExecutor {
		factoryCalls++
		if factoryCalls == 1 {
			return &fakeRepoExecutor{err: errors.New("repo-a scanner failed")}
		}
		return &fakeRepoExecutor{
			result: repoexposure.ScanResult{
				Repository:     "owner/repo-b",
				CommitsScanned: historyLimit,
				FilesScanned:   4,
				Findings: []domain.Finding{
					{ID: "rf-batch-continue", Type: domain.FindingSecretExposure, Severity: domain.SeverityHigh, CreatedAt: now},
				},
			},
		}
	}

	repoA, err := svc.EnqueueRepoScan(defaultScopeContext(), RepoScanRequest{Repository: "owner/repo-a"})
	if err != nil {
		t.Fatalf("enqueue repo-a scan: %v", err)
	}
	repoB, err := svc.EnqueueRepoScan(defaultScopeContext(), RepoScanRequest{Repository: "owner/repo-b"})
	if err != nil {
		t.Fatalf("enqueue repo-b scan: %v", err)
	}

	processed, err := svc.ProcessNextQueuedRepoScan(defaultScopeContext())
	if !processed {
		t.Fatal("expected first queued repo scan to be processed")
	}
	if err == nil {
		t.Fatal("expected first queued repo scan to fail")
	}

	processed, err = svc.ProcessNextQueuedRepoScan(defaultScopeContext())
	if err != nil {
		t.Fatalf("expected second queued repo scan to succeed, got %v", err)
	}
	if !processed {
		t.Fatal("expected second queued repo scan to be processed")
	}

	repoARecord, err := svc.GetRepoScan(defaultScopeContext(), repoA.ID)
	if err != nil {
		t.Fatalf("get repo-a scan: %v", err)
	}
	if repoARecord.Status != "failed" || repoARecord.ErrorMessage == "" {
		t.Fatalf("expected failed repo-a scan with error message, got %+v", repoARecord)
	}

	repoBRecord, err := svc.GetRepoScan(defaultScopeContext(), repoB.ID)
	if err != nil {
		t.Fatalf("get repo-b scan: %v", err)
	}
	if repoBRecord.Status != "succeeded" || repoBRecord.FindingCount != 1 {
		t.Fatalf("expected repo-b succeeded with findings, got %+v", repoBRecord)
	}

	repoScans, err := svc.ListRepoScans(defaultScopeContext(), 10)
	if err != nil {
		t.Fatalf("list repo scans: %v", err)
	}
	queuedOrRunning := 0
	for _, scan := range repoScans {
		if scan.Status == "queued" || scan.Status == "running" {
			queuedOrRunning++
		}
	}
	if queuedOrRunning != 0 {
		t.Fatalf("expected no leftover queued/running records, got %d (%+v)", queuedOrRunning, repoScans)
	}
}

func TestRepoTargetAllowed(t *testing.T) {
	if repoTargetAllowed("owner/repo", nil) {
		t.Fatal("expected empty allowlist to deny target")
	}
	if !repoTargetAllowed("trusted/team-repo", []string{"trusted/*"}) {
		t.Fatal("expected wildcard allowlist to allow target")
	}
	if repoTargetAllowed("owner/repo", []string{"trusted/*"}) {
		t.Fatal("expected disallowed target")
	}
}

func TestServiceRunRepoScanRejectsLocalRepositoryTarget(t *testing.T) {
	svc := NewService(db.NewMemoryStore(), fakeScanner{}, "aws")
	svc.RepoScanAllowedTargets = []string{"*"}

	repo := t.TempDir()
	if output, err := exec.Command("git", "init", "--quiet", repo).CombinedOutput(); err != nil {
		t.Fatalf("prepare local repo fixture: %v (%s)", err, string(output))
	}

	if _, err := svc.RunRepoScan(defaultScopeContext(), RepoScanRequest{Repository: repo}); !errors.Is(err, ErrRepoTargetNotAllowed) {
		t.Fatalf("expected local repo target rejection, got %v", err)
	}
}

func TestServiceRunRepoScanRejectsCredentialBearingRepositoryURL(t *testing.T) {
	svc := NewService(db.NewMemoryStore(), fakeScanner{}, "aws")
	svc.RepoScanAllowedTargets = []string{"*"}

	_, err := svc.RunRepoScan(defaultScopeContext(), RepoScanRequest{
		Repository: "https://token@example.com/org/repo.git",
	})
	if err == nil || !errors.Is(err, ErrInvalidRepoScanRequest) || err.Error() != "repository target must not include credentials in URL userinfo" {
		t.Fatalf("expected invalid repo scan request for credential-bearing url, got %v", err)
	}
}

func TestServiceRepoTargetContainsURLCredentials(t *testing.T) {
	testCases := []struct {
		target   string
		expected bool
	}{
		{target: "https://token@example.com/org/repo.git", expected: true},
		{target: "ssh://git@example.com/owner/repo.git", expected: false},
		{target: "ssh://git:password@example.com/owner/repo.git", expected: true},
		{target: "git@github.com:owner/repo.git", expected: false},
		{target: "ssh://@example.com/owner/repo.git", expected: true},
	}

	for _, tc := range testCases {
		t.Run(tc.target, func(t *testing.T) {
			if got, want := repoTargetContainsURLCredentials(tc.target), tc.expected; got != want {
				t.Fatalf("expected %v for %q, got %v", want, tc.target, got)
			}
		})
	}
}

func TestSanitizeRepoScanLimit(t *testing.T) {
	got, err := sanitizeRepoScanLimit(0, 100, 500)
	if err != nil || got != 100 {
		t.Fatalf("expected fallback 100, got=%d err=%v", got, err)
	}
	if _, err := sanitizeRepoScanLimit(-1, 100, 500); !errors.Is(err, ErrInvalidRepoScanRequest) {
		t.Fatalf("expected invalid error for negative value, got %v", err)
	}
	if _, err := sanitizeRepoScanLimit(600, 100, 500); !errors.Is(err, ErrInvalidRepoScanRequest) {
		t.Fatalf("expected invalid error for over max value, got %v", err)
	}
}

func TestServiceLockKeyNamespace(t *testing.T) {
	svc := NewService(db.NewMemoryStore(), fakeScanner{}, "aws")
	if got := svc.lockKey("scan:aws"); got != "identrail:scan:aws" {
		t.Fatalf("unexpected default namespaced lock key %q", got)
	}
	svc.LockNamespace = ""
	if got := svc.lockKey("scan:aws"); got != "scan:aws" {
		t.Fatalf("unexpected lock key without namespace %q", got)
	}
}

func seedAWSConnectorForScanTest(t *testing.T, store db.Store, ctx context.Context, projectID string, connectorID string, status domain.ConnectorStatus, health string, updatedAt time.Time) {
	t.Helper()
	if err := store.UpsertTenancyConnector(ctx, db.TenancyConnector{
		WorkspaceID: "default",
		ProjectID:   projectID,
		ConnectorID: connectorID,
		Type:        domain.ConnectorTypeAWS,
		DisplayName: "AWS " + connectorID,
		Status:      status,
		CreatedAt:   updatedAt,
		UpdatedAt:   updatedAt,
	}, db.TenancyConnectorState{
		WorkspaceID:  "default",
		ProjectID:    projectID,
		ConnectorID:  connectorID,
		HealthStatus: health,
		Metadata: map[string]any{
			"role_arn":          "arn:aws:iam::123456789012:role/" + connectorID,
			"region":            "us-east-1",
			"permission_checks": []AWSConnectionPermissionCheck{},
			"diagnostics":       []AWSConnectionDiagnostic{},
		},
		ObservedAt: updatedAt,
		UpdatedAt:  updatedAt,
	}); err != nil {
		t.Fatalf("seed aws connector %s: %v", connectorID, err)
	}
}

func TestServiceQueuedAWSScanUsesProjectScopedConnector(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 5, 25, 10, 0, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-a")
	seedDefaultProject(t, store, ctx, "project-b")
	seedAWSConnectorForScanTest(t, store, ctx, "project-a", "aws-project-a", domain.ConnectorStatusActive, "healthy", now)
	seedAWSConnectorForScanTest(t, store, ctx, "project-b", "aws-project-b", domain.ConnectorStatusActive, "healthy", now.Add(time.Hour))

	svc := NewService(store, fakeScanner{err: errors.New("default scanner should not run")}, "aws")
	svc.Now = func() time.Time { return now }
	var connectorID string
	svc.AWSScannerFactory = func(_ context.Context, connection AWSConnectionStatus) (ScannerRunner, error) {
		connectorID = connection.ConnectorID
		return fakeScanner{result: app.ScanResult{Assets: 1}}, nil
	}

	record, err := svc.EnqueueScan(ctx, ScanRequest{ProjectID: "project-a"})
	if err != nil {
		t.Fatalf("enqueue project-scoped scan: %v", err)
	}
	if record.ProjectID != "project-a" || record.ConnectorID != "" {
		t.Fatalf("unexpected scan source metadata: %+v", record)
	}
	processed, err := svc.ProcessNextQueuedScan(ctx)
	if err != nil {
		t.Fatalf("process project-scoped scan: %v", err)
	}
	if !processed {
		t.Fatal("expected queued scan to be processed")
	}
	if connectorID != "aws-project-a" {
		t.Fatalf("expected project-a connector, got %q", connectorID)
	}
}

func TestServiceQueuedAWSScanUsesExplicitConnectorOnly(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 5, 25, 10, 0, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-a")
	seedAWSConnectorForScanTest(t, store, ctx, "project-a", "aws-primary", domain.ConnectorStatusActive, "healthy", now.Add(time.Hour))
	seedAWSConnectorForScanTest(t, store, ctx, "project-a", "aws-requested", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{err: errors.New("default scanner should not run")}, "aws")
	svc.Now = func() time.Time { return now }
	var connectorID string
	svc.AWSScannerFactory = func(_ context.Context, connection AWSConnectionStatus) (ScannerRunner, error) {
		connectorID = connection.ConnectorID
		return fakeScanner{result: app.ScanResult{Assets: 1}}, nil
	}

	record, err := svc.EnqueueScan(ctx, ScanRequest{ProjectID: "project-a", ConnectorID: "aws-requested"})
	if err != nil {
		t.Fatalf("enqueue explicit connector scan: %v", err)
	}
	if record.ProjectID != "project-a" || record.ConnectorID != "aws-requested" {
		t.Fatalf("unexpected explicit scan source metadata: %+v", record)
	}
	processed, err := svc.ProcessNextQueuedScan(ctx)
	if err != nil {
		t.Fatalf("process explicit connector scan: %v", err)
	}
	if !processed {
		t.Fatal("expected queued scan to be processed")
	}
	if connectorID != "aws-requested" {
		t.Fatalf("expected requested connector only, got %q", connectorID)
	}
}

func TestServiceProjectScopedAWSScanWithoutConnectorDoesNotUseOtherProjectConnector(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 5, 25, 10, 0, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-a")
	seedDefaultProject(t, store, ctx, "project-b")
	seedAWSConnectorForScanTest(t, store, ctx, "project-b", "aws-project-b", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{result: app.ScanResult{Assets: 1}}, "aws")
	svc.Now = func() time.Time { return now }
	factoryCalled := false
	svc.AWSScannerFactory = func(_ context.Context, connection AWSConnectionStatus) (ScannerRunner, error) {
		factoryCalled = true
		return fakeScanner{err: fmt.Errorf("unexpected connector %s", connection.ConnectorID)}, nil
	}

	var notReady AWSPlatformBaselineNotReadyError
	if _, err := svc.EnqueueScan(ctx, ScanRequest{ProjectID: "project-a"}); !errors.As(err, &notReady) {
		t.Fatalf("expected aws baseline not ready error, got %v", err)
	}
	if notReady.Result.Status != db.AWSPlatformBaselineStatusBlocked || notReady.Result.RequiredChecksPassed {
		t.Fatalf("expected blocked baseline result, got %+v", notReady.Result)
	}
	if len(notReady.Result.FailureReasons) == 0 || !strings.Contains(notReady.Result.FailureReasons[0], "connector") {
		t.Fatalf("expected connector failure reason, got %+v", notReady.Result.FailureReasons)
	}
	if _, err := store.GetAWSPlatformBaselineResult(ctx, db.AWSPlatformBaselineFilter{WorkspaceID: "default", ProjectID: "project-a"}); err != nil {
		t.Fatalf("expected persisted baseline failure: %v", err)
	}
	if factoryCalled {
		t.Fatal("expected project-a scan not to hydrate project-b connector")
	}
}

func TestServiceNonAWSProviderIgnoresScanSourceScope(t *testing.T) {
	svc := NewService(db.NewMemoryStore(), fakeScanner{result: app.ScanResult{Assets: 1}}, "kubernetes")
	svc.ScanQueueMaxPending = 1
	ctx := defaultScopeContext()

	first, err := svc.EnqueueScan(ctx, ScanRequest{ProjectID: "project-a"})
	if err != nil {
		t.Fatalf("enqueue first non-aws scan: %v", err)
	}
	if first.ProjectID != "" || first.ConnectorID != "" {
		t.Fatalf("expected non-aws scan to drop source scope, got %+v", first)
	}

	// A scan scoped to a different project must still hit the single pending-scan
	// guard, proving the source scope did not partition the queue for non-AWS providers.
	if _, err := svc.EnqueueScan(ctx, ScanRequest{ProjectID: "project-b"}); !errors.Is(err, ErrScanInProgress) {
		t.Fatalf("expected ErrScanInProgress for non-aws provider, got %v", err)
	}
}
