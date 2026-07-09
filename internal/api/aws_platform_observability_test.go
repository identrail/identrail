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

func newPlatformObservabilityService(t *testing.T, project string, now time.Time) (*Service, string) {
	t.Helper()
	return newBlastRadiusService(t, project, now)
}

func TestGetAWSPlatformObservabilityBuildsContract(t *testing.T) {
	now := time.Date(2026, 7, 9, 15, 0, 0, 0, time.UTC)
	svc, ws := newPlatformObservabilityService(t, "project-platform-observability", now)

	result, err := svc.GetAWSPlatformObservability(defaultScopeContext(), ws, "project-platform-observability", AWSPlatformObservabilityRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
	})
	if err != nil {
		t.Fatalf("get platform observability: %v", err)
	}
	if result.CurrentIssueRef != "#1556" || result.Version != awsPlatformObservabilityVersion {
		t.Fatalf("unexpected issue/version: %+v", result)
	}
	if result.Status != awsPlatformDependencyStatusDegraded {
		t.Fatalf("expected degraded platform observability from failed verification outcomes, got %+v", result)
	}
	if result.Summary.TotalMetrics != 9 || result.Summary.FilteredMetrics != len(result.Metrics) {
		t.Fatalf("unexpected metric summary: %+v metrics=%d", result.Summary, len(result.Metrics))
	}
	if result.Summary.TotalTraces == 0 || len(result.Traces) == 0 {
		t.Fatalf("expected trace rows for collector/runtime/verification sources, got %+v", result.Summary)
	}
	required := map[string]bool{
		"scan-throughput":       false,
		"queue-lag":             false,
		"runtime-lag":           false,
		"remediation-state":     false,
		"verification-outcomes": false,
	}
	for _, metric := range result.Metrics {
		if metric.EvidenceBoundary != awsPlatformObservabilityBoundary {
			t.Fatalf("unexpected metric boundary: %+v", metric)
		}
		if _, ok := required[metric.MetricID]; ok {
			required[metric.MetricID] = true
		}
	}
	for id, seen := range required {
		if !seen {
			t.Fatalf("missing platform metric %q in %+v", id, result.Metrics)
		}
	}
	if len(result.Alerts) == 0 || result.Summary.CriticalAlertCount != 0 {
		t.Fatalf("expected non-critical platform alerts for failed verification outcomes, got %+v", result.Alerts)
	}
}

func TestAWSPlatformObservabilityFiltersComponentStatusAndSearch(t *testing.T) {
	now := time.Date(2026, 7, 9, 15, 5, 0, 0, time.UTC)
	svc, ws := newPlatformObservabilityService(t, "project-platform-observability-filter", now)

	result, err := svc.GetAWSPlatformObservability(defaultScopeContext(), ws, "project-platform-observability-filter", AWSPlatformObservabilityRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "partial_failure",
		Component:    "collector",
		Status:       "degraded",
		Search:       "throttling",
	})
	if err != nil {
		t.Fatalf("get filtered platform observability: %v", err)
	}
	if result.AppliedFilters["component"] != "collector" || result.AppliedFilters["status"] != "degraded" || result.AppliedFilters["search"] != "throttling" {
		t.Fatalf("expected filters to be applied, got %+v", result.AppliedFilters)
	}
	if len(result.Metrics) == 0 {
		t.Fatalf("expected degraded collector metrics, got %+v", result)
	}
	for _, metric := range result.Metrics {
		if metric.Component != "collector" || metric.Status != awsPlatformDependencyStatusDegraded {
			t.Fatalf("metric did not honor collector/degraded filters: %+v", metric)
		}
	}
	if _, err := svc.GetAWSPlatformObservability(defaultScopeContext(), ws, "project-platform-observability-filter", AWSPlatformObservabilityRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
		Status:       "bogus",
	}); err != ErrInvalidAWSConnectionRequest {
		t.Fatalf("expected invalid status to be rejected, got %v", err)
	}
}

func TestAWSPlatformObservabilityPermissionDeniedIsExplicit(t *testing.T) {
	now := time.Date(2026, 7, 9, 15, 10, 0, 0, time.UTC)
	svc, ws := newPlatformObservabilityService(t, "project-platform-observability-denied", now)

	result, err := svc.GetAWSPlatformObservability(defaultScopeContext(), ws, "project-platform-observability-denied", AWSPlatformObservabilityRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "permission_denied",
	})
	if err != nil {
		t.Fatalf("get permission denied platform observability: %v", err)
	}
	if result.Status != awsPlatformDependencyStatusBlocked || result.Summary.BlockedSignals == 0 {
		t.Fatalf("expected blocked platform observability, got %+v", result)
	}
	if len(result.Alerts) == 0 || result.Summary.CriticalAlertCount == 0 {
		t.Fatalf("expected critical alerts for blocked platform observability, got %+v", result)
	}
	if len(result.CoverageGaps) == 0 && len(result.Diagnostics) == 0 {
		t.Fatalf("expected explicit diagnostics or coverage gaps for permission denied, got %+v", result)
	}
}

func TestRouterAWSPlatformObservability(t *testing.T) {
	now := time.Date(2026, 7, 9, 15, 15, 0, 0, time.UTC)
	svc, _ := newPlatformObservabilityService(t, "project-platform-observability-route", now)
	r := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{})

	query := url.Values{}
	query.Set("connector_id", "aws-prod")
	query.Set("fixture_state", "partial_failure")
	query.Set("component", "collector")
	query.Set("status", "degraded")
	query.Set("service", "ecs")
	resp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-platform-observability-route/aws/platform-observability?"+query.Encode(), "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	var body struct {
		Observability AWSPlatformObservabilityResult `json:"platform_observability"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Observability.CurrentIssueRef != "#1556" || body.Observability.AppliedFilters["component"] != "collector" {
		t.Fatalf("unexpected route payload: %+v", body.Observability)
	}
	for _, metric := range body.Observability.Metrics {
		if metric.Component != "collector" || metric.Status != awsPlatformDependencyStatusDegraded {
			t.Fatalf("route did not apply filters: %+v", metric)
		}
	}
}
