package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/domain"
	"github.com/identrail/identrail/internal/telemetry"
	"go.uber.org/zap"
)

func TestGetAWSCoveragePlanSuccess(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 12, 9, 0, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-a")
	seedAWSConnectorForScanTest(t, store, ctx, "project-a", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }

	result, err := svc.GetAWSCoveragePlan(ctx, "default", "project-a", AWSCoveragePlanRequest{ConnectorID: "aws-prod"})
	if err != nil {
		t.Fatalf("get coverage plan: %v", err)
	}
	if result.Status != awsPlatformDependencyStatusReady || result.Confidence < 0.9 {
		t.Fatalf("expected ready plan, got %+v", result)
	}
	if result.CurrentIssueRef != "#1499" || result.Version == "" {
		t.Fatalf("unexpected metadata: %+v", result)
	}
	if result.Summary.AccountCount != 3 || result.Summary.RegionCount != 3 || result.Summary.ServiceCount != 6 {
		t.Fatalf("unexpected dimension counts: %+v", result.Summary)
	}
	if result.Summary.CoveredTargets != 3 || result.Summary.CoveragePercent <= 0 {
		t.Fatalf("expected covered targets and positive coverage percent, got %+v", result.Summary)
	}
	if result.Summary.DisabledTargets == 0 {
		t.Fatalf("expected disabled targets from the decommissioned account, got %+v", result.Summary)
	}
	// Determinism: targets must be sorted by priority rank then key.
	for i := 1; i < len(result.Targets); i++ {
		prev, cur := result.Targets[i-1], result.Targets[i]
		if prev.PriorityRank > cur.PriorityRank {
			t.Fatalf("targets out of priority order at %d", i)
		}
		if prev.PriorityRank == cur.PriorityRank && prev.Key > cur.Key {
			t.Fatalf("targets out of key order at %d", i)
		}
	}
	// Every target carries an explicit state, evidence ref, and next action.
	for _, target := range result.Targets {
		if target.State == "" || target.EvidenceRef == "" || target.NextAction == "" {
			t.Fatalf("target missing explicit fields: %+v", target)
		}
	}
}

func TestGetAWSCoveragePlanGlobalServicePlannedOncePerAccount(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 12, 9, 30, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-a")
	seedAWSConnectorForScanTest(t, store, ctx, "project-a", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }

	result, err := svc.GetAWSCoveragePlan(ctx, "default", "project-a", AWSCoveragePlanRequest{ConnectorID: "aws-prod", Service: "iam"})
	if err != nil {
		t.Fatalf("get coverage plan: %v", err)
	}
	perAccount := map[string]int{}
	for _, target := range result.Targets {
		if !target.Global {
			t.Fatalf("iam targets should be global, got %+v", target)
		}
		perAccount[target.AccountID]++
	}
	if len(perAccount) == 0 {
		t.Fatalf("expected iam targets")
	}
	for accountID, count := range perAccount {
		if count != 1 {
			t.Fatalf("account %s has %d iam targets, want 1 (global)", accountID, count)
		}
	}
}

func TestGetAWSCoveragePlanFilters(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 12, 10, 0, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-a")
	seedAWSConnectorForScanTest(t, store, ctx, "project-a", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }

	covered, err := svc.GetAWSCoveragePlan(ctx, "default", "project-a", AWSCoveragePlanRequest{ConnectorID: "aws-prod", State: "covered"})
	if err != nil {
		t.Fatalf("get state-filtered plan: %v", err)
	}
	if covered.FilteredTargets != covered.Summary.CoveredTargets || covered.FilteredTargets == 0 {
		t.Fatalf("state filter mismatch: filtered=%d covered=%d", covered.FilteredTargets, covered.Summary.CoveredTargets)
	}
	for _, target := range covered.Targets {
		if target.State != "covered" {
			t.Fatalf("state filter leaked %q", target.State)
		}
	}

	disabled, err := svc.GetAWSCoveragePlan(ctx, "default", "project-a", AWSCoveragePlanRequest{ConnectorID: "aws-prod", State: "disabled"})
	if err != nil {
		t.Fatalf("get disabled plan: %v", err)
	}
	for _, target := range disabled.Targets {
		if target.Enabled {
			t.Fatalf("disabled filter returned enabled target: %+v", target)
		}
	}

	if _, err := svc.GetAWSCoveragePlan(ctx, "default", "project-a", AWSCoveragePlanRequest{ConnectorID: "aws-prod", State: "bogus"}); err == nil {
		t.Fatalf("expected invalid state filter error")
	}
}

func TestGetAWSCoveragePlanEmptyAndDegradedAndDenied(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 12, 11, 0, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-a")
	seedAWSConnectorForScanTest(t, store, ctx, "project-a", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }

	empty, err := svc.GetAWSCoveragePlan(ctx, "default", "project-a", AWSCoveragePlanRequest{ConnectorID: "aws-prod", FixtureState: "empty"})
	if err != nil {
		t.Fatalf("get empty plan: %v", err)
	}
	if empty.Status != awsPlatformDependencyStatusReady || empty.Summary.TotalTargets != 0 {
		t.Fatalf("expected empty ready plan, got %+v", empty.Summary)
	}
	if len(empty.RemediationHints) == 0 {
		t.Fatalf("empty plan should hint at configuring targets")
	}

	degraded, err := svc.GetAWSCoveragePlan(ctx, "default", "project-a", AWSCoveragePlanRequest{ConnectorID: "aws-prod", FixtureState: "degraded"})
	if err != nil {
		t.Fatalf("get degraded plan: %v", err)
	}
	if degraded.Status != awsPlatformDependencyStatusDegraded || len(degraded.Diagnostics) == 0 {
		t.Fatalf("expected degraded diagnostics, got %+v", degraded)
	}
	if degraded.Summary.FailedTargets == 0 || degraded.Summary.ResumableTargets == 0 {
		t.Fatalf("expected failed/resumable targets in degraded plan, got %+v", degraded.Summary)
	}
	if degraded.Summary.StateCounts["blocked"] == 0 {
		t.Fatalf("expected blocked availability example in degraded plan: %+v", degraded.Summary.StateCounts)
	}
	if degraded.Summary.StateCounts["unsupported"] == 0 {
		t.Fatalf("expected unsupported availability example in degraded plan: %+v", degraded.Summary.StateCounts)
	}

	denied, err := svc.GetAWSCoveragePlan(ctx, "default", "project-a", AWSCoveragePlanRequest{ConnectorID: "aws-prod", FixtureState: "permission_denied"})
	if err != nil {
		t.Fatalf("get denied plan: %v", err)
	}
	if denied.Status != awsPlatformDependencyStatusBlocked || denied.Summary.PermissionDenied == 0 || len(denied.Diagnostics) == 0 {
		t.Fatalf("expected blocked permission-denied plan, got %+v", denied)
	}
	if denied.Summary.StateCounts["permission_denied"] == 0 {
		t.Fatalf("expected permission-denied state in denied plan: %+v", denied.Summary.StateCounts)
	}
}

func TestGetAWSCoveragePlanNeverLeaksValues(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-a")
	seedAWSConnectorForScanTest(t, store, ctx, "project-a", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }

	result, err := svc.GetAWSCoveragePlan(ctx, "default", "project-a", AWSCoveragePlanRequest{ConnectorID: "aws-prod"})
	if err != nil {
		t.Fatalf("get coverage plan: %v", err)
	}
	payload, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	lower := strings.ToLower(string(payload))
	for _, forbidden := range []string{"getsecretvalue", "secretstring", "plaintext", "password=", "=sk-"} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("value-like content leaked into plan: %s", payload)
		}
	}
}

func TestRouterAWSCoveragePlanPartialFailureAndInvalid(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 12, 13, 0, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-1")
	seedAWSConnectorForScanTest(t, store, ctx, "project-1", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	r := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{})

	resp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-1/aws/coverage-plan?connector_id=aws-prod&fixture_state=partial_failure", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	var body struct {
		Plan AWSCoveragePlanResult `json:"plan"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Plan.Status != awsPlatformDependencyStatusDegraded || body.Plan.Summary.FailedTargets == 0 {
		t.Fatalf("expected degraded partial plan, got %+v", body.Plan)
	}

	for _, query := range []string{"fixture_state=bogus", "state=bogus"} {
		bad := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-1/aws/coverage-plan?connector_id=aws-prod&"+query, "")
		if bad.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for %q, got %d body=%s", query, bad.Code, bad.Body.String())
		}
	}
}
