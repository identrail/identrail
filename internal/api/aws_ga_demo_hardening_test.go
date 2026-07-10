package api

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/telemetry"
	"go.uber.org/zap"
)

func newGADemoHardeningService(t *testing.T, project string, now time.Time) (*Service, string) {
	t.Helper()
	return newBlastRadiusService(t, project, now)
}

func TestGetAWSGADemoHardeningBuildsContract(t *testing.T) {
	now := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	svc, ws := newGADemoHardeningService(t, "project-ga-demo-hardening", now)

	result, err := svc.GetAWSGADemoHardening(defaultScopeContext(), ws, "project-ga-demo-hardening", AWSGADemoHardeningRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
	})
	if err != nil {
		t.Fatalf("get ga demo hardening: %v", err)
	}
	if result.CurrentIssueRef != "#1557" || result.Version != awsGADemoHardeningVersion {
		t.Fatalf("unexpected issue/version: %+v", result)
	}
	if result.Summary.TotalStages != 11 || result.Summary.FilteredStages != len(result.Stages) {
		t.Fatalf("unexpected stage summary: %+v stages=%d", result.Summary, len(result.Stages))
	}
	required := map[string]bool{
		"onboarding":    false,
		"discovery":     false,
		"agents":        false,
		"runtime":       false,
		"risk":          false,
		"remediation":   false,
		"approval":      false,
		"verification":  false,
		"governance":    false,
		"reporting":     false,
		"observability": false,
	}
	for _, stage := range result.Stages {
		if stage.EvidenceBoundary != awsGADemoHardeningBoundary {
			t.Fatalf("unexpected evidence boundary: %+v", stage)
		}
		if _, ok := required[stage.StageID]; ok {
			required[stage.StageID] = true
		}
	}
	for id, seen := range required {
		if !seen {
			t.Fatalf("missing ga demo stage %q in %+v", id, result.Stages)
		}
	}
	if len(result.ReadinessChecks) == 0 || result.Summary.RequiredChecks == 0 {
		t.Fatalf("expected readiness checks, got %+v", result)
	}
	if len(result.Permissions) == 0 || len(result.SafetyNotes) == 0 || len(result.Limitations) == 0 {
		t.Fatalf("expected permission, safety, and limitation docs in contract: %+v", result)
	}
}

func TestAWSGADemoHardeningFiltersStageStatusAndSearch(t *testing.T) {
	now := time.Date(2026, 7, 10, 9, 5, 0, 0, time.UTC)
	svc, ws := newGADemoHardeningService(t, "project-ga-demo-hardening-filter", now)

	result, err := svc.GetAWSGADemoHardening(defaultScopeContext(), ws, "project-ga-demo-hardening-filter", AWSGADemoHardeningRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
		Stage:        "governance",
		Search:       "export",
	})
	if err != nil {
		t.Fatalf("get filtered ga demo hardening: %v", err)
	}
	if result.AppliedFilters["stage"] != "governance" || result.AppliedFilters["search"] != "export" {
		t.Fatalf("expected applied filters, got %+v", result.AppliedFilters)
	}
	if len(result.Stages) != 1 || result.Stages[0].StageID != "governance" {
		t.Fatalf("expected only governance stage, got %+v", result.Stages)
	}
	if _, err := svc.GetAWSGADemoHardening(defaultScopeContext(), ws, "project-ga-demo-hardening-filter", AWSGADemoHardeningRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
		Stage:        "not-a-stage",
	}); err != ErrInvalidAWSConnectionRequest {
		t.Fatalf("expected invalid stage to be rejected, got %v", err)
	}
}

func TestAWSGADemoHardeningPermissionDeniedIsExplicit(t *testing.T) {
	now := time.Date(2026, 7, 10, 9, 10, 0, 0, time.UTC)
	svc, ws := newGADemoHardeningService(t, "project-ga-demo-hardening-denied", now)

	result, err := svc.GetAWSGADemoHardening(defaultScopeContext(), ws, "project-ga-demo-hardening-denied", AWSGADemoHardeningRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "permission_denied",
	})
	if err != nil {
		t.Fatalf("get permission denied ga demo hardening: %v", err)
	}
	if result.Status != awsPlatformDependencyStatusBlocked || result.Summary.BlockedStages == 0 {
		t.Fatalf("expected blocked ga demo hardening, got %+v", result)
	}
	if len(result.Troubleshooting) == 0 || len(result.FailureReasons) == 0 {
		t.Fatalf("expected troubleshooting and failure reasons for permission denied, got %+v", result)
	}
}

func TestRouterAWSGADemoHardening(t *testing.T) {
	now := time.Date(2026, 7, 10, 9, 15, 0, 0, time.UTC)
	svc, _ := newGADemoHardeningService(t, "project-ga-demo-hardening-route", now)
	r := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{})

	query := url.Values{}
	query.Set("connector_id", "aws-prod")
	query.Set("fixture_state", "success")
	query.Set("stage", "governance")
	resp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-ga-demo-hardening-route/aws/ga-demo-hardening?"+query.Encode(), "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	var body struct {
		GADemo AWSGADemoHardeningResult `json:"ga_demo_hardening"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.GADemo.CurrentIssueRef != "#1557" || body.GADemo.AppliedFilters["stage"] != "governance" {
		t.Fatalf("unexpected route payload: %+v", body.GADemo)
	}
	if len(body.GADemo.Stages) != 1 || body.GADemo.Stages[0].StageID != "governance" {
		t.Fatalf("route did not apply stage filter: %+v", body.GADemo.Stages)
	}
}
