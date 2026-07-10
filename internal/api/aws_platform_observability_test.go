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

func TestGetAWSPlatformObservabilityLeavesUnfilteredScopeUnlabeled(t *testing.T) {
	now := time.Date(2026, 7, 9, 15, 0, 30, 0, time.UTC)
	svc, ws := newPlatformObservabilityService(t, "project-platform-observability-unfiltered-scope", now)

	result, err := svc.GetAWSPlatformObservability(defaultScopeContext(), ws, "project-platform-observability-unfiltered-scope", AWSPlatformObservabilityRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
	})
	if err != nil {
		t.Fatalf("get unfiltered platform observability: %v", err)
	}
	if result.AccountID != "" || result.Region != "" {
		t.Fatalf("expected unfiltered platform scope to remain empty, got account=%q region=%q", result.AccountID, result.Region)
	}
	for _, metric := range result.Metrics {
		if metric.AccountID != "" || metric.Region != "" {
			t.Fatalf("expected aggregate platform metric scope to remain empty, got %+v", metric)
		}
	}
	if result.Summary.AccountCounts["123456789012"] == 0 || result.Summary.RegionCounts["us-east-1"] == 0 {
		t.Fatalf("expected source traces to preserve real account/region counts, got %+v", result.Summary)
	}
}

func TestGetAWSPlatformObservabilityNormalizesServiceBeforeSourcePushdown(t *testing.T) {
	now := time.Date(2026, 7, 9, 15, 0, 45, 0, time.UTC)
	svc, ws := newPlatformObservabilityService(t, "project-platform-observability-service-pushdown", now)

	result, err := svc.GetAWSPlatformObservability(defaultScopeContext(), ws, "project-platform-observability-service-pushdown", AWSPlatformObservabilityRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
		Service:      "secrets-manager.amazonaws.com",
	})
	if err != nil {
		t.Fatalf("get service-filtered platform observability: %v", err)
	}
	if result.AppliedFilters["service"] != "secrets-manager.amazonaws.com" {
		t.Fatalf("expected original service filter to remain visible, got %+v", result.AppliedFilters)
	}
	collectorTrace := false
	for _, trace := range result.Traces {
		if trace.Component != "collector" {
			continue
		}
		collectorTrace = true
		if trace.Service != "secretsmanager" {
			t.Fatalf("expected collector trace to use canonical service token, got %+v", trace)
		}
	}
	if !collectorTrace {
		t.Fatalf("expected normalized service pushdown to keep collector traces, got %+v", result.Traces)
	}
	for _, metric := range result.Metrics {
		if metric.Component == "collector" || metric.Component == "queue" {
			if metric.Service != "secretsmanager" {
				t.Fatalf("expected source-scoped metric to use canonical service token, got %+v", metric)
			}
			if metric.AccountID != "" || metric.Region != "" {
				t.Fatalf("expected service-only metrics to avoid connector account/region labels, got %+v", metric)
			}
		}
	}
}

func TestGetAWSPlatformObservabilityScopesStatusToFilteredSignals(t *testing.T) {
	now := time.Date(2026, 7, 9, 15, 1, 0, 0, time.UTC)
	svc, ws := newPlatformObservabilityService(t, "project-platform-observability-filtered-status", now)

	result, err := svc.GetAWSPlatformObservability(defaultScopeContext(), ws, "project-platform-observability-filtered-status", AWSPlatformObservabilityRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
		Component:    "collector",
		Status:       awsPlatformDependencyStatusReady,
	})
	if err != nil {
		t.Fatalf("get status-filtered platform observability: %v", err)
	}
	if result.Status != awsPlatformDependencyStatusReady || result.Confidence != 0.9 {
		t.Fatalf("expected response status to follow returned ready collector signals, got %+v", result)
	}
	if len(result.Metrics) == 0 {
		t.Fatalf("expected ready collector metrics, got %+v", result)
	}
	for _, metric := range result.Metrics {
		if metric.Component != "collector" || metric.Status != awsPlatformDependencyStatusReady {
			t.Fatalf("expected only ready collector metrics, got %+v", metric)
		}
	}
	if len(result.Alerts) != 0 {
		t.Fatalf("expected no alerts for ready filtered response, got %+v", result.Alerts)
	}
}

func TestAWSPlatformObservabilityTraceOnlyStatusAndAlerts(t *testing.T) {
	now := time.Date(2026, 7, 9, 15, 1, 30, 0, time.UTC)
	metrics := []AWSPlatformObservabilityMetric{
		{MetricID: "runtime-lag", Component: "runtime", Service: "all", Status: awsPlatformDependencyStatusReady},
	}
	traces := []AWSPlatformObservabilityTrace{
		{
			TraceID:     "runtime-secretsmanager-delayed",
			SpanName:    "aws.runtime.collect",
			Component:   "runtime",
			AccountID:   "123456789012",
			Region:      "us-east-1",
			Service:     "secretsmanager",
			Status:      awsPlatformDependencyStatusDegraded,
			EvidenceRef: "aws-runtime://secret-runtime",
			NextAction:  "Review delayed runtime delivery.",
		},
	}

	filteredMetrics, filteredTraces, _ := filterAWSPlatformObservability(metrics, traces, AWSPlatformObservabilityRequest{Service: "secretsmanager"})
	if len(filteredMetrics) != 0 || len(filteredTraces) != 1 {
		t.Fatalf("expected service filter to leave only runtime trace rows, metrics=%+v traces=%+v", filteredMetrics, filteredTraces)
	}
	status, confidence := summarizeAWSPlatformObservabilityStatus(filteredMetrics, filteredTraces, true)
	if status != awsPlatformDependencyStatusDegraded || confidence != 0.72 {
		t.Fatalf("expected trace-only degraded response status, got status=%q confidence=%v", status, confidence)
	}
	alerts := awsPlatformObservabilityAlerts(filteredMetrics, filteredTraces, true, now)
	if len(alerts) != 1 || alerts[0].Status != awsPlatformDependencyStatusDegraded || alerts[0].Component != "runtime" {
		t.Fatalf("expected trace-only degraded alert, got %+v", alerts)
	}
}

func TestAWSPlatformObservabilityScopedStatusIncludesMetricAndTraceSignals(t *testing.T) {
	now := time.Date(2026, 7, 9, 15, 1, 45, 0, time.UTC)
	metrics := []AWSPlatformObservabilityMetric{
		{MetricID: "scan-throughput", Component: "collector", Service: "secretsmanager", Status: awsPlatformDependencyStatusReady},
		{MetricID: "queue-lag", Component: "queue", Service: "secretsmanager", Status: awsPlatformDependencyStatusReady},
	}
	traces := []AWSPlatformObservabilityTrace{
		{
			TraceID:     "runtime-secretsmanager-delayed",
			SpanName:    "aws.runtime.collect",
			Component:   "runtime",
			AccountID:   "123456789012",
			Region:      "us-east-1",
			Service:     "secretsmanager",
			Status:      awsPlatformDependencyStatusDegraded,
			EvidenceRef: "aws-runtime://secret-runtime",
			NextAction:  "Review delayed runtime delivery.",
		},
	}

	filteredMetrics, filteredTraces, _ := filterAWSPlatformObservability(metrics, traces, AWSPlatformObservabilityRequest{Service: "secretsmanager"})
	if len(filteredMetrics) != 2 || len(filteredTraces) != 1 {
		t.Fatalf("expected service filter to keep ready metrics and degraded trace, metrics=%+v traces=%+v", filteredMetrics, filteredTraces)
	}
	status, confidence := summarizeAWSPlatformObservabilityStatus(filteredMetrics, filteredTraces, true)
	if status != awsPlatformDependencyStatusDegraded || confidence != 0.72 {
		t.Fatalf("expected scoped status to include degraded trace beside ready metrics, got status=%q confidence=%v", status, confidence)
	}
	alerts := awsPlatformObservabilityAlerts(filteredMetrics, filteredTraces, true, now)
	if len(alerts) != 1 || alerts[0].Status != awsPlatformDependencyStatusDegraded || alerts[0].Component != "runtime" {
		t.Fatalf("expected scoped trace alert beside ready metrics, got %+v", alerts)
	}
	summary := summarizeAWSPlatformObservability(metrics, filteredMetrics, traces, filteredTraces, alerts)
	if summary.ReadySignals != 2 || summary.DegradedSignals != 1 || summary.StatusCounts[awsPlatformDependencyStatusDegraded] != 1 {
		t.Fatalf("expected trace status to contribute to scoped signal totals, got %+v", summary)
	}
}

func TestAWSPlatformObservabilityAllFiltersDoNotEnableScopedTraceSignals(t *testing.T) {
	request := AWSPlatformObservabilityRequest{Component: "all", Status: "all"}
	if awsPlatformObservabilityHasResultFilter(request) {
		t.Fatalf("expected all component/status tokens to behave like absent result filters")
	}

	metrics := []AWSPlatformObservabilityMetric{
		{MetricID: "scan-throughput", Component: "collector", Service: "all", Status: awsPlatformDependencyStatusReady},
	}
	traces := []AWSPlatformObservabilityTrace{
		{TraceID: "runtime-delayed", Component: "runtime", Service: "secretsmanager", Status: awsPlatformDependencyStatusDegraded},
	}
	filteredMetrics, filteredTraces, _ := filterAWSPlatformObservability(metrics, traces, request)
	status, confidence := summarizeAWSPlatformObservabilityStatus(filteredMetrics, filteredTraces, awsPlatformObservabilityHasResultFilter(request))
	if status != awsPlatformDependencyStatusReady || confidence != 0.9 {
		t.Fatalf("expected explicit all filters to match omitted filter status behavior, got status=%q confidence=%v", status, confidence)
	}
}

func TestAWSPlatformObservabilityMetricsUseLagAndScopedServiceLabels(t *testing.T) {
	now := time.Date(2026, 7, 9, 15, 2, 0, 0, time.UTC)
	sources := awsPlatformObservabilitySources{
		Coverage: AWSAccountRegionCoverageResult{
			Status:     awsPlatformDependencyStatusReady,
			Confidence: 0.98,
		},
		FanOut: AWSFanOutExecutionResult{
			Status:     awsPlatformDependencyStatusReady,
			Confidence: 0.96,
			Targets: []AWSFanOutExecutionTarget{
				{Key: "ecs-queued-1", AccountID: "123456789012", Region: "us-east-1", Service: "ecs", State: "queued", WorkerState: "queued", Enabled: true, Retryable: true},
				{Key: "ecs-queued-2", AccountID: "123456789012", Region: "us-east-1", Service: "ecs", State: "queued", WorkerState: "queued", Enabled: true, Retryable: true},
				{Key: "ecs-queued-3", AccountID: "123456789012", Region: "us-east-1", Service: "ecs", State: "queued", WorkerState: "queued", Enabled: true, Retryable: true},
				{Key: "ecs-queued-4", AccountID: "123456789012", Region: "us-east-1", Service: "ecs", State: "queued", WorkerState: "queued", Enabled: true, Retryable: true},
			},
		},
		Runtime: AWSRuntimeEventResult{
			Status:     awsPlatformDependencyStatusReady,
			Confidence: 0.94,
			Records: []AWSRuntimeEventRecord{
				{
					EventID:     "runtime-lagged",
					AccountID:   "123456789012",
					Region:      "us-east-1",
					EventSource: "cloudtrail",
					ObservedAt:  now.Add(-20 * time.Minute),
					CollectedAt: now,
				},
			},
		},
		Cases: AWSRemediationCaseResult{
			Status:     awsPlatformDependencyStatusReady,
			Confidence: 0.93,
		},
		Verification: AWSPostRemediationVerificationResult{
			Status:     awsPlatformDependencyStatusReady,
			Confidence: 0.92,
		},
		Enforcement: AWSLimitedEnforcementResult{
			Status:     awsPlatformDependencyStatusReady,
			Confidence: 0.91,
		},
		Governance: AWSGovernanceAuditReportingResult{
			Status:     awsPlatformDependencyStatusReady,
			Confidence: 0.9,
		},
	}

	metrics := awsPlatformObservabilityMetrics(sources, AWSPlatformObservabilityRequest{Service: "ecs"}, "123456789012", "us-east-1", "ecs", now)
	byID := map[string]AWSPlatformObservabilityMetric{}
	for _, metric := range metrics {
		byID[metric.MetricID] = metric
	}
	for _, id := range []string{"queue-lag", "runtime-lag"} {
		metric, ok := byID[id]
		if !ok {
			t.Fatalf("missing lag metric %q in %+v", id, metrics)
		}
		if metric.Status != awsPlatformDependencyStatusDegraded || metric.Severity != "high" {
			t.Fatalf("expected lag metric %q to be degraded/high, got %+v", id, metric)
		}
	}
	for _, id := range []string{"runtime-lag", "remediation-state", "verification-outcomes", "enforcement-health", "governance-outcomes"} {
		metric, ok := byID[id]
		if !ok {
			t.Fatalf("missing aggregate metric %q in %+v", id, metrics)
		}
		if metric.Service != "all" {
			t.Fatalf("expected aggregate metric %q to remain service=all, got %+v", id, metric)
		}
	}

	filtered, _, _ := filterAWSPlatformObservability(metrics, nil, AWSPlatformObservabilityRequest{Service: "ecs"})
	for _, metric := range filtered {
		if metric.Service != "ecs" {
			t.Fatalf("service filter should not keep unscoped aggregate metrics: %+v", metric)
		}
	}
}

func TestAWSPlatformObservabilityFanOutMetricsUseFilteredTargets(t *testing.T) {
	now := time.Date(2026, 7, 9, 15, 3, 0, 0, time.UTC)
	sources := awsPlatformObservabilitySources{
		Coverage: AWSAccountRegionCoverageResult{
			Status:     awsPlatformDependencyStatusDegraded,
			Confidence: 0.98,
			Summary: AWSAccountRegionCoverageSummary{
				CoveredRecords:  12,
				DegradedRecords: 4,
			},
			Records: []AWSAccountRegionCoverageRecord{
				{Key: "ecs-covered", AccountID: "123456789012", Region: "us-east-1", Service: "ecs", CoverageStatus: "covered", State: "covered"},
			},
		},
		FanOut: AWSFanOutExecutionResult{
			Status:     awsPlatformDependencyStatusDegraded,
			Confidence: 0.96,
			Summary: AWSFanOutExecutionSummary{
				CoveredTargets:   12,
				QueuedTargets:    9,
				ThrottledTargets: 7,
				RetryableTargets: 7,
			},
			Targets: []AWSFanOutExecutionTarget{
				{Key: "ecs-covered", AccountID: "123456789012", Region: "us-east-1", Service: "ecs", State: "covered", WorkerState: "covered", Enabled: true},
			},
		},
	}

	metrics := awsPlatformObservabilityMetrics(sources, AWSPlatformObservabilityRequest{Service: "ecs"}, "123456789012", "us-east-1", "ecs", now)
	byID := map[string]AWSPlatformObservabilityMetric{}
	for _, metric := range metrics {
		byID[metric.MetricID] = metric
	}
	if got := byID["scan-throughput"].Value; got != 1 {
		t.Fatalf("expected scan throughput to use filtered fan-out targets, got %d", got)
	}
	if metric := byID["scan-throughput"]; metric.Status != awsPlatformDependencyStatusReady || metric.Severity != "low" {
		t.Fatalf("expected scan throughput status to use filtered source rows, got %+v", metric)
	}
	if got := byID["queue-lag"].Value; got != 0 {
		t.Fatalf("expected queue lag to ignore unfiltered fan-out summary backlog, got %d", got)
	}
	if metric := byID["throttling"]; metric.Value != 0 || metric.Status != awsPlatformDependencyStatusReady {
		t.Fatalf("expected throttling to use filtered fan-out targets, got %+v", metric)
	}
	if metric := byID["collector-failures"]; metric.Value != 0 || metric.Status != awsPlatformDependencyStatusReady {
		t.Fatalf("expected collector failures to use filtered coverage rows, got %+v", metric)
	}
}

func TestAWSPlatformObservabilityTreatsPendingFanOutAsQueuedBacklog(t *testing.T) {
	now := time.Date(2026, 7, 9, 15, 3, 30, 0, time.UTC)
	targets := make([]AWSFanOutExecutionTarget, 0, 8)
	for i := 0; i < 8; i++ {
		targets = append(targets, AWSFanOutExecutionTarget{
			Key:         "ecs-pending",
			AccountID:   "123456789012",
			Region:      "us-east-1",
			Service:     "ecs",
			State:       "pending",
			WorkerState: "pending",
			Enabled:     true,
		})
	}
	sources := awsPlatformObservabilitySources{
		FanOut: AWSFanOutExecutionResult{
			Status:     awsPlatformDependencyStatusReady,
			Confidence: 0.96,
			Targets:    targets,
		},
	}

	metrics := awsPlatformObservabilityMetrics(sources, AWSPlatformObservabilityRequest{Service: "ecs"}, "123456789012", "us-east-1", "ecs", now)
	byID := map[string]AWSPlatformObservabilityMetric{}
	for _, metric := range metrics {
		byID[metric.MetricID] = metric
	}
	if metric := byID["queue-lag"]; metric.Value != int((16*time.Minute).Milliseconds()) || metric.Status != awsPlatformDependencyStatusDegraded {
		t.Fatalf("expected pending fan-out rows to contribute queued backlog, got %+v", metric)
	}

	traces := awsPlatformObservabilityTraces(sources, now)
	if len(traces) == 0 {
		t.Fatalf("expected pending fan-out traces, got none")
	}
	for _, trace := range traces {
		if trace.Component != "collector" {
			continue
		}
		if trace.QueueLagMs != int((2 * time.Minute).Milliseconds()) {
			t.Fatalf("expected pending fan-out trace to use queued lag, got %+v", trace)
		}
	}
}

func TestAWSPlatformObservabilityRuntimeTraceStatusIncludesDelayed(t *testing.T) {
	now := time.Date(2026, 7, 9, 15, 4, 0, 0, time.UTC)
	traces := awsPlatformObservabilityTraces(awsPlatformObservabilitySources{
		Runtime: AWSRuntimeEventResult{
			Records: []AWSRuntimeEventRecord{
				{
					EventID:     "delayed-runtime",
					AccountID:   "123456789012",
					Region:      "us-east-1",
					EventSource: "cloudtrail",
					Status:      "delayed",
					ObservedAt:  now.Add(-20 * time.Minute),
					CollectedAt: now,
					EvidenceRef: "aws-runtime://delayed-runtime",
					NextAction:  "Wait for delayed runtime delivery to catch up.",
					Confidence:  0.71,
				},
			},
		},
	}, now)
	if len(traces) != 1 {
		t.Fatalf("expected one runtime trace, got %+v", traces)
	}
	if traces[0].Status != awsPlatformDependencyStatusDegraded {
		t.Fatalf("expected delayed runtime trace to be degraded, got %+v", traces[0])
	}
}

func TestAWSPlatformObservabilityNormalizesRuntimeServiceTokens(t *testing.T) {
	now := time.Date(2026, 7, 9, 15, 4, 30, 0, time.UTC)
	traces := awsPlatformObservabilityTraces(awsPlatformObservabilitySources{
		Runtime: AWSRuntimeEventResult{
			Records: []AWSRuntimeEventRecord{
				{
					EventID:     "secret-runtime",
					AccountID:   "123456789012",
					Region:      "us-east-1",
					EventSource: "secretsmanager.amazonaws.com",
					Status:      "observed",
					ObservedAt:  now.Add(-5 * time.Minute),
					CollectedAt: now,
					EvidenceRef: "aws-runtime://secret-runtime",
					NextAction:  "Review secret runtime access.",
				},
			},
		},
	}, now)
	if len(traces) != 1 || traces[0].Service != "secretsmanager" {
		t.Fatalf("expected runtime event source to normalize to service token, got %+v", traces)
	}

	metrics := []AWSPlatformObservabilityMetric{
		{MetricID: "s3-throughput", Component: "collector", Service: "s3", Status: awsPlatformDependencyStatusReady},
	}
	serviceTraces := []AWSPlatformObservabilityTrace{
		{TraceID: "runtime-s3", Component: "runtime", Service: "s3", Status: awsPlatformDependencyStatusReady},
	}
	filteredMetrics, filteredTraces, _ := filterAWSPlatformObservability(metrics, serviceTraces, AWSPlatformObservabilityRequest{Service: "s3.amazonaws.com"})
	if len(filteredMetrics) != 1 || len(filteredTraces) != 1 {
		t.Fatalf("expected endpoint-form service filter to match canonical service tokens, metrics=%+v traces=%+v", filteredMetrics, filteredTraces)
	}
}

func TestAWSPlatformObservabilityP95UsesNearestRank(t *testing.T) {
	if got := awsPlatformObservabilityP95([]int{10, 100}); got != 100 {
		t.Fatalf("expected two-sample p95 to select upper nearest rank, got %d", got)
	}
	if got := awsPlatformObservabilityP95([]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}); got != 10 {
		t.Fatalf("expected ten-sample p95 to select upper nearest rank, got %d", got)
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
