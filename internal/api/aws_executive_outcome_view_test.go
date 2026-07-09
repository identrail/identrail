package api

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/telemetry"
	"go.uber.org/zap"
)

func newExecutiveOutcomeViewService(t *testing.T, project string, now time.Time) (*Service, string) {
	t.Helper()
	return newBlastRadiusService(t, project, now)
}

func TestGetAWSExecutiveOutcomeViewBuildsContract(t *testing.T) {
	now := time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)
	svc, ws := newExecutiveOutcomeViewService(t, "project-executive-outcomes", now)

	result, err := svc.GetAWSExecutiveOutcomeView(defaultScopeContext(), ws, "project-executive-outcomes", AWSExecutiveOutcomeViewRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
	})
	if err != nil {
		t.Fatalf("get executive outcome view: %v", err)
	}
	if result.CurrentIssueRef != "#1555" || result.Version != awsExecutiveOutcomeViewVersion {
		t.Fatalf("unexpected result metadata: %+v", result)
	}
	if result.Status != "ready" {
		t.Fatalf("expected ready result, got %q failures=%+v", result.Status, result.FailureReasons)
	}
	if result.Summary.TotalMetrics < 5 || len(result.Metrics) != result.Summary.FilteredMetrics {
		t.Fatalf("expected populated executive metrics, summary=%+v metrics=%+v", result.Summary, result.Metrics)
	}
	required := map[string]bool{
		"risk_reduction": false,
		"coverage":       false,
		"remediation":    false,
		"enforcement":    false,
		"exposure":       false,
		"governance":     false,
	}
	for _, metric := range result.Metrics {
		if _, ok := required[metric.OutcomeType]; ok {
			required[metric.OutcomeType] = true
		}
		if metric.EvidenceBoundary != awsExecutiveOutcomeViewBoundary {
			t.Fatalf("metric crossed evidence boundary: %+v", metric)
		}
		if metric.EvidenceRef == "" || metric.NextAction == "" {
			t.Fatalf("metric missing evidence/next action: %+v", metric)
		}
	}
	for outcomeType, seen := range required {
		if !seen {
			t.Fatalf("expected outcome type %s in metrics: %+v", outcomeType, result.Metrics)
		}
	}
	if result.Summary.ScanCoveragePct == 0 || result.Summary.GovernanceRecordCount == 0 {
		t.Fatalf("expected coverage and governance rollups in summary: %+v", result.Summary)
	}

	serialized, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	lower := strings.ToLower(string(serialized))
	for _, forbidden := range []string{"\"secret_access_key\"", "\"private_key\"", "\"prompt\"", "\"completion\"", "\"database_rows\"", "\"object_contents\"", "\"payload\""} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("executive outcome view serialized forbidden marker %q", forbidden)
		}
	}
}

func TestAWSExecutiveOutcomeViewFiltersOutcomeSeverityAndSearch(t *testing.T) {
	now := time.Date(2026, 7, 9, 12, 30, 0, 0, time.UTC)
	svc, ws := newExecutiveOutcomeViewService(t, "project-executive-outcomes-filter", now)

	result, err := svc.GetAWSExecutiveOutcomeView(defaultScopeContext(), ws, "project-executive-outcomes-filter", AWSExecutiveOutcomeViewRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
		OutcomeType:  "coverage",
		Search:       "scan",
	})
	if err != nil {
		t.Fatalf("get filtered executive outcome view: %v", err)
	}
	if result.AppliedFilters["outcome_type"] != "coverage" || result.AppliedFilters["search"] != "scan" {
		t.Fatalf("expected applied filters, got %+v", result.AppliedFilters)
	}
	if len(result.Metrics) != 1 || result.Metrics[0].MetricID != "scan-coverage" {
		t.Fatalf("expected only scan coverage metric, got %+v", result.Metrics)
	}
	if result.Summary.FilteredMetrics != 1 || result.Summary.OutcomeTypeCounts["coverage"] != 1 {
		t.Fatalf("expected filtered summary to reflect coverage metric, got %+v", result.Summary)
	}
}

func TestAWSExecutiveOutcomeViewPermissionDeniedIsExplicit(t *testing.T) {
	now := time.Date(2026, 7, 9, 13, 0, 0, 0, time.UTC)
	svc, ws := newExecutiveOutcomeViewService(t, "project-executive-outcomes-denied", now)

	result, err := svc.GetAWSExecutiveOutcomeView(defaultScopeContext(), ws, "project-executive-outcomes-denied", AWSExecutiveOutcomeViewRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "permission_denied",
	})
	if err != nil {
		t.Fatalf("get permission denied executive outcome view: %v", err)
	}
	if result.Status != "blocked" {
		t.Fatalf("expected blocked result, got %q", result.Status)
	}
	if len(result.FailureReasons) == 0 || len(result.Diagnostics) == 0 {
		t.Fatalf("expected explicit failure reasons and diagnostics, got failures=%+v diagnostics=%+v", result.FailureReasons, result.Diagnostics)
	}
}

func TestRouterAWSExecutiveOutcomeView(t *testing.T) {
	now := time.Date(2026, 7, 9, 13, 30, 0, 0, time.UTC)
	svc, _ := newExecutiveOutcomeViewService(t, "project-executive-outcomes-route", now)
	r := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{})

	query := url.Values{}
	query.Set("connector_id", "aws-prod")
	query.Set("fixture_state", "success")
	query.Set("outcome_type", "governance")
	resp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-executive-outcomes-route/aws/executive-outcomes?"+query.Encode(), "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	var body struct {
		Outcomes AWSExecutiveOutcomeViewResult `json:"executive_outcomes"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Outcomes.CurrentIssueRef != "#1555" || body.Outcomes.AppliedFilters["outcome_type"] != "governance" {
		t.Fatalf("unexpected route payload: %+v", body.Outcomes)
	}
	for _, metric := range body.Outcomes.Metrics {
		if metric.OutcomeType != "governance" {
			t.Fatalf("route did not apply outcome_type filter: %+v", metric)
		}
	}
}
