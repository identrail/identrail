package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/app"
	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/domain"
)

func TestVerifyAWSPlatformBaselineReadyPersists(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 4, 9, 0, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-a")
	seedAWSConnectorForScanTest(t, store, ctx, "project-a", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{result: app.ScanResult{Assets: 1}}, "aws")
	svc.Now = func() time.Time { return now }
	svc.AWSBaselineGitSHA = "6dd631b1"

	result, err := svc.VerifyAWSPlatformBaseline(ctx, "default", "project-a", AWSPlatformBaselineRequest{ConnectorID: "aws-prod"})
	if err != nil {
		t.Fatalf("verify baseline: %v", err)
	}
	if result.Status != db.AWSPlatformBaselineStatusReady || !result.RequiredChecksPassed {
		t.Fatalf("expected ready baseline, got %+v", result)
	}
	if result.GitSHA != "6dd631b1" || result.ConnectorID != "aws-prod" || result.GraphContractVersion == "" {
		t.Fatalf("expected revision and connector metadata, got %+v", result)
	}
	if len(result.Checks) != 5 {
		t.Fatalf("expected five baseline checks, got %+v", result.Checks)
	}
	reloaded, err := store.GetAWSPlatformBaselineResult(ctx, db.AWSPlatformBaselineFilter{
		WorkspaceID: "default",
		ProjectID:   "project-a",
		ConnectorID: "aws-prod",
	})
	if err != nil {
		t.Fatalf("reload persisted baseline: %v", err)
	}
	if reloaded.Status != db.AWSPlatformBaselineStatusReady || reloaded.Checks[0].Name != "aws_connector_health" {
		t.Fatalf("unexpected persisted baseline: %+v", reloaded)
	}
}

func TestGetAWSPlatformBaselineReturnsNotRunPayload(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 4, 9, 15, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-a")

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	svc.AWSBaselineGitSHA = "6dd631b1"

	result, err := svc.GetAWSPlatformBaseline(ctx, "default", "project-a", AWSPlatformBaselineRequest{})
	if err != nil {
		t.Fatalf("get baseline: %v", err)
	}
	if result.Status != db.AWSPlatformBaselineStatusNotRun || result.RequiredChecksPassed {
		t.Fatalf("expected deterministic not-run payload, got %+v", result)
	}
	if result.GitSHA != "6dd631b1" || result.SourceMode != "sdk" || result.FixtureOnly {
		t.Fatalf("expected default metadata in not-run payload, got %+v", result)
	}
	if len(result.Checks) != 1 || result.Checks[0].Name != "aws_platform_baseline" {
		t.Fatalf("expected single not-run check, got %+v", result.Checks)
	}
	if result.Checks[0].EvidenceURL != "/app/default/default/aws?environment=project-a" {
		t.Fatalf("unexpected evidence URL %q", result.Checks[0].EvidenceURL)
	}
	if len(result.FailureReasons) != 1 || result.FailureReasons[0] != "aws platform baseline has not run" {
		t.Fatalf("unexpected failure reasons: %+v", result.FailureReasons)
	}
	if !result.VerifiedAt.Equal(now) {
		t.Fatalf("expected verified_at %v, got %v", now, result.VerifiedAt)
	}
}

func TestGetAWSPlatformBaselineFallsBackToActiveConnectorResult(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 4, 9, 20, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-a")
	if _, err := store.UpsertAWSPlatformBaselineResult(ctx, db.AWSPlatformBaselineResult{
		WorkspaceID:          "default",
		ProjectID:            "project-a",
		Status:               db.AWSPlatformBaselineStatusBlocked,
		RequiredChecksPassed: false,
		FailureReasons:       []string{"aws connector is missing"},
		Checks: []db.AWSPlatformBaselineCheck{{
			Name:          "aws_connector_health",
			Required:      true,
			Status:        db.AWSPlatformBaselineCheckFailed,
			FailureReason: "aws connector is missing",
			CheckedAt:     now.Add(-time.Minute),
		}},
		VerifiedAt: now.Add(-time.Minute),
		CreatedAt:  now.Add(-time.Minute),
		UpdatedAt:  now.Add(-time.Minute),
	}); err != nil {
		t.Fatalf("seed stale project-level baseline: %v", err)
	}
	seedAWSConnectorForScanTest(t, store, ctx, "project-a", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	verified, err := svc.VerifyAWSPlatformBaseline(ctx, "default", "project-a", AWSPlatformBaselineRequest{ConnectorID: "aws-prod"})
	if err != nil {
		t.Fatalf("verify connector baseline: %v", err)
	}
	if verified.ConnectorID != "aws-prod" {
		t.Fatalf("expected connector-specific baseline, got %+v", verified)
	}

	result, err := svc.GetAWSPlatformBaseline(ctx, "default", "project-a", AWSPlatformBaselineRequest{})
	if err != nil {
		t.Fatalf("get connector fallback baseline: %v", err)
	}
	if result.ConnectorID != "aws-prod" || result.Status != db.AWSPlatformBaselineStatusReady {
		t.Fatalf("expected active connector fallback result, got %+v", result)
	}
	if result.FailureReasons != nil && len(result.FailureReasons) > 0 && result.FailureReasons[0] == "aws connector is missing" {
		t.Fatalf("default read returned stale project-level baseline: %+v", result)
	}
}

func TestVerifyAWSPlatformBaselineFixtureModeRequiresReadableFixtures(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 4, 9, 30, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-a")

	svc := NewService(store, fakeScanner{result: app.ScanResult{Assets: 1}}, "aws")
	svc.Now = func() time.Time { return now }
	svc.AWSBaselineSourceMode = "fixture"
	svc.AWSBaselineFixturePaths = []string{filepath.Join(t.TempDir(), "missing.json")}

	blocked, err := svc.VerifyAWSPlatformBaseline(ctx, "default", "project-a", AWSPlatformBaselineRequest{})
	if err != nil {
		t.Fatalf("verify missing fixture baseline: %v", err)
	}
	if blocked.Status != db.AWSPlatformBaselineStatusBlocked || blocked.RequiredChecksPassed {
		t.Fatalf("expected fixture baseline to block, got %+v", blocked)
	}
	if len(blocked.FailureReasons) == 0 || blocked.FailureReasons[0] != "aws fixtures are unavailable" {
		t.Fatalf("expected fixture failure reason, got %+v", blocked.FailureReasons)
	}
	blockedConnectorCheck := requireAWSBaselineCheck(t, blocked.Checks, "aws_connector_health")
	if blockedConnectorCheck.Required || blockedConnectorCheck.Status != db.AWSPlatformBaselineCheckSkipped {
		t.Fatalf("expected fixture mode to skip connector health, got %+v", blockedConnectorCheck)
	}

	fixtureDir := t.TempDir()
	fixturePath := filepath.Join(fixtureDir, "roles.json")
	if err := os.WriteFile(fixturePath, []byte(`{"roles":[]}`), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	svc.AWSBaselineFixturePaths = []string{fixtureDir}
	ready, err := svc.VerifyAWSPlatformBaseline(ctx, "default", "project-a", AWSPlatformBaselineRequest{})
	if err != nil {
		t.Fatalf("verify readable fixture baseline: %v", err)
	}
	if ready.Status != db.AWSPlatformBaselineStatusReady || !ready.FixtureOnly {
		t.Fatalf("expected readable fixture baseline to pass, got %+v", ready)
	}
	readyConnectorCheck := requireAWSBaselineCheck(t, ready.Checks, "aws_connector_health")
	if readyConnectorCheck.Required || readyConnectorCheck.Status != db.AWSPlatformBaselineCheckSkipped {
		t.Fatalf("expected readable fixture baseline to skip connector health, got %+v", readyConnectorCheck)
	}
}

func TestVerifyAWSPlatformBaselineExplainsUnhealthyConnectorAndFullQueue(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 4, 9, 45, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-a")
	if err := store.UpsertTenancyConnector(ctx, db.TenancyConnector{
		WorkspaceID: "default",
		ProjectID:   "project-a",
		ConnectorID: "aws-prod",
		Type:        domain.ConnectorTypeAWS,
		DisplayName: "AWS production",
		Status:      domain.ConnectorStatusPending,
		CreatedAt:   now,
		UpdatedAt:   now,
	}, db.TenancyConnectorState{
		WorkspaceID:  "default",
		ProjectID:    "project-a",
		ConnectorID:  "aws-prod",
		HealthStatus: "error",
		Metadata: map[string]any{
			"account_id": "123456789012",
			"region":     "us-east-1",
			"permission_checks": []AWSConnectionPermissionCheck{{
				Name:    "iam:GetRole",
				Passed:  false,
				Message: "iam:GetRole denied",
			}},
			"diagnostics": []AWSConnectionDiagnostic{{
				Code:    "AccessDenied",
				Message: "sts:AssumeRole denied",
			}},
		},
		ObservedAt: now,
		UpdatedAt:  now,
	}); err != nil {
		t.Fatalf("seed unhealthy aws connector: %v", err)
	}
	if _, err := store.CreateQueuedScanWithSource(ctx, "aws", db.ScanSource{ProjectID: "project-a", ConnectorID: "aws-prod"}, now); err != nil {
		t.Fatalf("seed queued aws scan: %v", err)
	}

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	svc.ScanQueueMaxPending = 1

	result, err := svc.VerifyAWSPlatformBaseline(ctx, "default", "project-a", AWSPlatformBaselineRequest{ConnectorID: "aws-prod"})
	if err != nil {
		t.Fatalf("verify unhealthy baseline: %v", err)
	}
	if result.Status != db.AWSPlatformBaselineStatusBlocked || result.RequiredChecksPassed {
		t.Fatalf("expected blocked baseline, got %+v", result)
	}
	connectorCheck := requireAWSBaselineCheck(t, result.Checks, "aws_connector_health")
	if connectorCheck.Status != db.AWSPlatformBaselineCheckPermissionDenied || connectorCheck.FailureReason != "sts:AssumeRole denied" {
		t.Fatalf("expected permission-denied connector check, got %+v", connectorCheck)
	}
	queueCheck := requireAWSBaselineCheck(t, result.Checks, "worker_queue_availability")
	if queueCheck.Status != db.AWSPlatformBaselineCheckFailed || queueCheck.FailureReason != "worker queue is full" {
		t.Fatalf("expected full queue check, got %+v", queueCheck)
	}
}

func TestVerifyAWSPlatformBaselineQueueCheckIsSourceScoped(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 4, 9, 50, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-a")
	seedDefaultProject(t, store, ctx, "project-b")
	seedAWSConnectorForScanTest(t, store, ctx, "project-a", "aws-prod", domain.ConnectorStatusActive, "healthy", now)
	if _, err := store.CreateQueuedScanWithSource(ctx, "aws", db.ScanSource{ProjectID: "project-b"}, now); err != nil {
		t.Fatalf("seed unrelated queued aws scan: %v", err)
	}

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	svc.ScanQueueMaxPending = 1

	result, err := svc.VerifyAWSPlatformBaseline(ctx, "default", "project-a", AWSPlatformBaselineRequest{})
	if err != nil {
		t.Fatalf("verify source-scoped baseline: %v", err)
	}
	if result.Status != db.AWSPlatformBaselineStatusReady || !result.RequiredChecksPassed {
		t.Fatalf("expected unrelated project queue not to block baseline, got %+v", result)
	}
	queueCheck := requireAWSBaselineCheck(t, result.Checks, "worker_queue_availability")
	if queueCheck.Status != db.AWSPlatformBaselineCheckPassed {
		t.Fatalf("expected source-scoped queue check to pass, got %+v", queueCheck)
	}
	if queueCheck.Evidence["pending_queue_count"] != 0 {
		t.Fatalf("expected project-a source queue count 0, got %+v", queueCheck.Evidence)
	}
	if queueCheck.Evidence["queue_count_mode"] != "queued_running" {
		t.Fatalf("expected default queue check to use queued/running mode, got %+v", queueCheck.Evidence)
	}
}

func TestVerifyAWSPlatformBaselineBlocksRunningScanForDefaultLimit(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 4, 9, 52, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-a")
	seedAWSConnectorForScanTest(t, store, ctx, "project-a", "aws-prod", domain.ConnectorStatusActive, "healthy", now)
	queued, err := store.CreateQueuedScanWithSource(ctx, "aws", db.ScanSource{ProjectID: "project-a"}, now)
	if err != nil {
		t.Fatalf("seed queued aws scan: %v", err)
	}
	running, err := store.ClaimNextQueuedScan(ctx, "aws")
	if err != nil {
		t.Fatalf("claim queued aws scan: %v", err)
	}
	if running.ID != queued.ID || running.Status != "running" {
		t.Fatalf("expected seeded scan to be running, got %+v", running)
	}

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	svc.ScanQueueMaxPending = 1

	result, err := svc.VerifyAWSPlatformBaseline(ctx, "default", "project-a", AWSPlatformBaselineRequest{})
	if err != nil {
		t.Fatalf("verify running-scan baseline: %v", err)
	}
	if result.Status != db.AWSPlatformBaselineStatusBlocked || result.RequiredChecksPassed {
		t.Fatalf("expected running scan to block default baseline, got %+v", result)
	}
	queueCheck := requireAWSBaselineCheck(t, result.Checks, "worker_queue_availability")
	if queueCheck.Status != db.AWSPlatformBaselineCheckFailed || queueCheck.Evidence["pending_queue_count"] != 1 || queueCheck.Evidence["queue_count_mode"] != "queued_running" {
		t.Fatalf("expected running scan to count against default queue gate, got %+v", queueCheck)
	}
}

func TestVerifyAWSPlatformBaselineBlocksArchivedProject(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 4, 9, 55, 0, 0, time.UTC)
	archivedAt := now.Add(-time.Hour)
	seedDefaultProject(t, store, ctx, "project-a")
	if err := store.UpsertProject(ctx, db.TenancyProject{
		WorkspaceID: "default",
		ProjectID:   "project-a",
		Name:        "Project project-a",
		Slug:        "project-a",
		ArchivedAt:  &archivedAt,
	}); err != nil {
		t.Fatalf("archive project: %v", err)
	}
	seedAWSConnectorForScanTest(t, store, ctx, "project-a", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }

	result, err := svc.VerifyAWSPlatformBaseline(ctx, "default", "project-a", AWSPlatformBaselineRequest{ConnectorID: "aws-prod"})
	if err != nil {
		t.Fatalf("verify archived project baseline: %v", err)
	}
	if result.Status != db.AWSPlatformBaselineStatusBlocked || result.RequiredChecksPassed {
		t.Fatalf("expected archived project to block baseline, got %+v", result)
	}
	appCheck := requireAWSBaselineCheck(t, result.Checks, "app_validation_prerequisites")
	if appCheck.Status != db.AWSPlatformBaselineCheckFailed || appCheck.FailureReason != "project is archived" {
		t.Fatalf("expected archived app validation check, got %+v", appCheck)
	}
}

func TestRouterAWSScanBlockedByBaselineReturnsPrecondition(t *testing.T) {
	r := newAWSConnectionTestRouter(t, &fakeAWSConnectorValidator{})

	resp := doAWSConnectionAPI(t, r, http.MethodPost, "/v1/scans", `{"project_id":"project-1"}`)
	if resp.Code != http.StatusPreconditionFailed {
		t.Fatalf("expected baseline precondition failure, got %d body=%s", resp.Code, resp.Body.String())
	}

	var body struct {
		ErrorCode      string                       `json:"error_code"`
		FailureReasons []string                     `json:"failure_reasons"`
		Baseline       db.AWSPlatformBaselineResult `json:"baseline"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode baseline response: %v", err)
	}
	if body.ErrorCode != "aws_platform_baseline_not_ready" {
		t.Fatalf("unexpected error code: %+v", body)
	}
	if body.Baseline.Status != db.AWSPlatformBaselineStatusBlocked || body.Baseline.ProjectID != "project-1" {
		t.Fatalf("unexpected baseline payload: %+v", body.Baseline)
	}
	if len(body.FailureReasons) == 0 || body.FailureReasons[0] != "aws connector is missing" {
		t.Fatalf("expected connector failure reason, got %+v", body.FailureReasons)
	}
}

func TestEnsureAWSPlatformBaselineBlocksMissingConnector(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 4, 10, 0, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-a")

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }

	err := svc.ensureAWSPlatformBaselineReadyForScan(ctx, "aws", db.ScanSource{ProjectID: "project-a"})
	var notReady AWSPlatformBaselineNotReadyError
	if !errorsAsAWSBaseline(err, &notReady) {
		t.Fatalf("expected baseline not ready error, got %v", err)
	}
	if notReady.Result.VerifiedAt != now || notReady.Result.Status != db.AWSPlatformBaselineStatusBlocked {
		t.Fatalf("unexpected not ready result: %+v", notReady.Result)
	}
}

func TestEnsureAWSPlatformBaselineAllowsFixtureModeWithoutConnector(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 4, 10, 5, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-a")
	fixtureDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(fixtureDir, "roles.json"), []byte(`{"roles":[]}`), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	svc.AWSBaselineSourceMode = "fixture"
	svc.AWSBaselineFixturePaths = []string{fixtureDir}

	if err := svc.ensureAWSPlatformBaselineReadyForScan(ctx, "aws", db.ScanSource{ProjectID: "project-a"}); err != nil {
		t.Fatalf("expected fixture baseline to allow scan without connector: %v", err)
	}
	result, err := store.GetAWSPlatformBaselineResult(ctx, db.AWSPlatformBaselineFilter{
		WorkspaceID: "default",
		ProjectID:   "project-a",
	})
	if err != nil {
		t.Fatalf("reload fixture baseline: %v", err)
	}
	connectorCheck := requireAWSBaselineCheck(t, result.Checks, "aws_connector_health")
	if result.Status != db.AWSPlatformBaselineStatusReady || !result.RequiredChecksPassed || connectorCheck.Required || connectorCheck.Status != db.AWSPlatformBaselineCheckSkipped {
		t.Fatalf("expected ready fixture baseline with skipped connector health, got result=%+v connector=%+v", result, connectorCheck)
	}
}

func TestAWSPlatformBaselineNotReadyErrorMatchesSentinel(t *testing.T) {
	err := AWSPlatformBaselineNotReadyError{}
	if err.Error() != ErrAWSPlatformBaselineNotReady.Error() {
		t.Fatalf("unexpected error text %q", err.Error())
	}
	if !errors.Is(err, ErrAWSPlatformBaselineNotReady) {
		t.Fatalf("expected not-ready error to match sentinel")
	}
}

func requireAWSBaselineCheck(t *testing.T, checks []db.AWSPlatformBaselineCheck, name string) db.AWSPlatformBaselineCheck {
	t.Helper()
	for _, check := range checks {
		if check.Name == name {
			return check
		}
	}
	t.Fatalf("missing baseline check %q in %+v", name, checks)
	return db.AWSPlatformBaselineCheck{}
}

func errorsAsAWSBaseline(err error, target *AWSPlatformBaselineNotReadyError) bool {
	if err == nil {
		return false
	}
	var notReady AWSPlatformBaselineNotReadyError
	if !errors.As(err, &notReady) {
		return false
	}
	*target = notReady
	return true
}
