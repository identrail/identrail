package api

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/domain"
	"github.com/identrail/identrail/internal/telemetry"
	"go.uber.org/zap"
)

func TestGetAWSFanOutExecutionSuccess(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 12, 15, 0, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-a")
	seedAWSConnectorForScanTest(t, store, ctx, "project-a", "aws-prod", domain.ConnectorStatusActive, "healthy", now)
	seedAWSCoverageCursorRow(t, store, ctx, "project-a", "aws-prod", db.AWSAccountRegionCoverage{
		AccountID:      "123456789012",
		AccountAlias:   "Production",
		Region:         "us-east-1",
		CoverageStatus: db.AWSAccountRegionCoveragePending,
		ScanCursor: map[string]any{"services": map[string]any{
			"iam":    map[string]any{"collector": "iam_roles", "state": "covered", "observed_at": now.Format(time.RFC3339Nano)},
			"lambda": map[string]any{"collector": "lambda_execution_roles", "state": "in_progress", "cursor": "lambda-page-2", "attempts": 1, "observed_at": now.Format(time.RFC3339Nano)},
		}},
		UpdatedAt: now,
	})

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }

	result, err := svc.GetAWSFanOutExecution(ctx, "default", "project-a", AWSFanOutExecutionRequest{ConnectorID: "aws-prod", MaxConcurrency: 2})
	if err != nil {
		t.Fatalf("get fan-out execution: %v", err)
	}
	if result.Status != awsPlatformDependencyStatusReady || result.CurrentIssueRef != "#1500" {
		t.Fatalf("unexpected execution metadata: %+v", result)
	}
	if result.Summary.ConcurrencyLimit != 2 || result.Summary.InProgressTargets > 2 {
		t.Fatalf("expected bounded execution, got %+v", result.Summary)
	}
	if result.Summary.CoveredTargets == 0 || result.Summary.QueuedTargets == 0 {
		t.Fatalf("expected covered and queued execution state, got %+v", result.Summary)
	}
	for _, target := range result.Targets {
		if target.WorkerState == "" || target.EvidenceRef == "" || target.NextAction == "" {
			t.Fatalf("target missing operator-visible execution fields: %+v", target)
		}
		if target.ConcurrencySlot > 2 {
			t.Fatalf("target exceeded concurrency limit: %+v", target)
		}
	}
	lambda := result.Targets[0]
	for _, target := range result.Targets {
		if target.Service == "lambda" {
			lambda = target
			break
		}
	}
	if lambda.Collector != "lambda_execution_roles" || lambda.Checkpoint != "lambda-page-2" {
		t.Fatalf("expected lambda fan-out target to replay persisted checkpoint, got %+v", lambda)
	}
}

func TestGetAWSFanOutExecutionDegradedAndDenied(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 12, 15, 30, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-a")
	seedAWSConnectorForScanTest(t, store, ctx, "project-a", "aws-prod", domain.ConnectorStatusActive, "healthy", now)
	seedAWSCoverageCursorRow(t, store, ctx, "project-a", "aws-prod", db.AWSAccountRegionCoverage{
		AccountID:      "123456789012",
		Region:         "us-east-1",
		CoverageStatus: db.AWSAccountRegionCoveragePending,
		ScanCursor:     map[string]any{"services": map[string]any{"iam": map[string]any{"state": "covered", "observed_at": now.Format(time.RFC3339Nano)}}},
		UpdatedAt:      now,
	})

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }

	degraded, err := svc.GetAWSFanOutExecution(ctx, "default", "project-a", AWSFanOutExecutionRequest{ConnectorID: "aws-prod", FixtureState: "partial_failure"})
	if err != nil {
		t.Fatalf("get degraded fan-out execution: %v", err)
	}
	if degraded.Status != awsPlatformDependencyStatusDegraded || degraded.Summary.RetryableTargets == 0 || degraded.Summary.ThrottledTargets == 0 {
		t.Fatalf("expected retryable degraded execution, got %+v", degraded)
	}
	if len(degraded.Diagnostics) == 0 || len(degraded.RemediationHints) == 0 {
		t.Fatalf("degraded execution should carry diagnostics and hints: %+v", degraded)
	}

	denied, err := svc.GetAWSFanOutExecution(ctx, "default", "project-a", AWSFanOutExecutionRequest{ConnectorID: "aws-prod", FixtureState: "permission_denied"})
	if err != nil {
		t.Fatalf("get denied fan-out execution: %v", err)
	}
	if denied.Status != awsPlatformDependencyStatusBlocked || denied.Summary.PermissionDeniedTargets == 0 {
		t.Fatalf("expected blocked permission-denied execution, got %+v", denied)
	}
}

func TestGetAWSFanOutExecutionFilters(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 12, 16, 0, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-a")
	seedAWSConnectorForScanTest(t, store, ctx, "project-a", "aws-prod", domain.ConnectorStatusActive, "healthy", now)
	seedAWSCoverageCursorRow(t, store, ctx, "project-a", "aws-prod", db.AWSAccountRegionCoverage{
		AccountID:      "123456789012",
		Region:         "us-east-1",
		CoverageStatus: db.AWSAccountRegionCoveragePending,
		ScanCursor:     map[string]any{"services": map[string]any{"iam": map[string]any{"state": "covered", "observed_at": now.Format(time.RFC3339Nano)}}},
		UpdatedAt:      now,
	})

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }

	covered, err := svc.GetAWSFanOutExecution(ctx, "default", "project-a", AWSFanOutExecutionRequest{ConnectorID: "aws-prod", State: "covered"})
	if err != nil {
		t.Fatalf("get covered fan-out execution: %v", err)
	}
	if covered.FilteredTargets == 0 {
		t.Fatalf("expected covered targets")
	}
	for _, target := range covered.Targets {
		if target.State != "covered" && target.WorkerState != "covered" {
			t.Fatalf("state filter leaked non-covered target: %+v", target)
		}
	}

	if _, err := svc.GetAWSFanOutExecution(ctx, "default", "project-a", AWSFanOutExecutionRequest{ConnectorID: "aws-prod", State: "bogus"}); err == nil {
		t.Fatalf("expected invalid state error")
	}
	if _, err := svc.GetAWSFanOutExecution(ctx, "default", "project-a", AWSFanOutExecutionRequest{ConnectorID: "aws-prod", MaxConcurrency: 65}); err == nil {
		t.Fatalf("expected invalid max concurrency error")
	}
}

func TestRouterAWSFanOutExecutionPartialFailureAndInvalid(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 12, 16, 30, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-1")
	seedAWSConnectorForScanTest(t, store, ctx, "project-1", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	r := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{})

	resp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-1/aws/fanout-execution?connector_id=aws-prod&fixture_state=partial_failure&max_concurrency=2", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	var body struct {
		Execution AWSFanOutExecutionResult `json:"execution"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Execution.Status != awsPlatformDependencyStatusDegraded || body.Execution.Summary.ThrottledTargets == 0 {
		t.Fatalf("expected degraded fan-out execution, got %+v", body.Execution)
	}

	for _, query := range []string{"fixture_state=bogus", "state=bogus", "max_concurrency=bad"} {
		bad := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-1/aws/fanout-execution?connector_id=aws-prod&"+query, "")
		if bad.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for %q, got %d body=%s", query, bad.Code, bad.Body.String())
		}
	}
}
