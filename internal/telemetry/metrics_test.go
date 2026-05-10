package telemetry

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestNewMetricsCountersAndHistogram(t *testing.T) {
	m := NewMetrics()
	if m == nil {
		t.Fatal("metrics must not be nil")
	}

	m.ScanRunsTotal.Add(1)
	m.ScanEnqueueTotal.Add(1)
	m.ScanEnqueueFailureTotal.Add(1)
	m.ScanEnqueueDurationMS.Observe(25)
	m.ScanSuccessTotal.Add(1)
	m.ScanFailureTotal.Add(1)
	m.ScanPartialTotal.Add(1)
	m.ScanInFlight.Set(0)
	m.FindingsGenerated.Add(2)
	m.ScanDurationMS.Observe(250)
	m.RepoScanRunsTotal.Add(1)
	m.RepoScanEnqueueTotal.Add(1)
	m.RepoScanEnqueueFailureTotal.Add(1)
	m.RepoScanEnqueueDurationMS.Observe(25)
	m.RepoScanSuccessTotal.Add(1)
	m.RepoScanFailureTotal.Add(1)
	m.RepoScanTruncatedTotal.Add(1)
	m.RepoScanDurationMS.Observe(300)
	m.RepoFindingsGenerated.Add(4)
	m.APIDeniedRequestsTotal.WithLabelValues("unauthorized", "auth").Add(1)
	m.APIDeniedRequestsTotal.WithLabelValues("forbidden", "authz").Add(1)
	m.APIDeniedRequestsTotal.WithLabelValues("rate_limited", "rate_limit").Add(1)
	m.APIDeniedRequestsTotal.WithLabelValues("validation_denied", "validation").Add(1)
	m.AuthzPolicyShadowEvaluationsTotal.Add(2)
	m.AuthzPolicyShadowDivergencesTotal.Add(1)
	m.AuthzPolicyShadowEvaluationErrorsTotal.Add(1)
	m.AuthzPolicyShadowDivergenceRate.Set(0.5)
	m.AuthzPolicyRollbacksTotal.Add(1)
	m.AuthzPolicyDecisionsByVersionTotal.WithLabelValues("1", "persisted_active_version", "disabled", "true").Add(3)

	if got := testutil.ToFloat64(m.ScanRunsTotal); got != 1 {
		t.Fatalf("expected scan runs 1, got %v", got)
	}
	if got := testutil.ToFloat64(m.ScanEnqueueTotal); got != 1 {
		t.Fatalf("expected scan enqueues 1, got %v", got)
	}
	if got := testutil.ToFloat64(m.ScanEnqueueFailureTotal); got != 1 {
		t.Fatalf("expected scan enqueue failures 1, got %v", got)
	}
	if got := testutil.ToFloat64(m.ScanSuccessTotal); got != 1 {
		t.Fatalf("expected scan success 1, got %v", got)
	}
	if got := testutil.ToFloat64(m.ScanFailureTotal); got != 1 {
		t.Fatalf("expected scan failures 1, got %v", got)
	}
	if got := testutil.ToFloat64(m.ScanPartialTotal); got != 1 {
		t.Fatalf("expected scan partial 1, got %v", got)
	}
	if got := testutil.ToFloat64(m.FindingsGenerated); got != 2 {
		t.Fatalf("expected findings generated 2, got %v", got)
	}
	if got := testutil.ToFloat64(m.RepoScanRunsTotal); got != 1 {
		t.Fatalf("expected repo scan runs 1, got %v", got)
	}
	if got := testutil.ToFloat64(m.RepoScanEnqueueTotal); got != 1 {
		t.Fatalf("expected repo scan enqueues 1, got %v", got)
	}
	if got := testutil.ToFloat64(m.RepoScanEnqueueFailureTotal); got != 1 {
		t.Fatalf("expected repo scan enqueue failures 1, got %v", got)
	}
	if got := testutil.ToFloat64(m.RepoScanSuccessTotal); got != 1 {
		t.Fatalf("expected repo scan successes 1, got %v", got)
	}
	if got := testutil.ToFloat64(m.RepoScanFailureTotal); got != 1 {
		t.Fatalf("expected repo scan failures 1, got %v", got)
	}
	if got := testutil.ToFloat64(m.RepoScanTruncatedTotal); got != 1 {
		t.Fatalf("expected repo scan truncations 1, got %v", got)
	}
	if got := testutil.ToFloat64(m.RepoFindingsGenerated); got != 4 {
		t.Fatalf("expected repo findings generated 4, got %v", got)
	}
	for _, tc := range []struct {
		kind   string
		source string
	}{
		{kind: "unauthorized", source: "auth"},
		{kind: "forbidden", source: "authz"},
		{kind: "rate_limited", source: "rate_limit"},
		{kind: "validation_denied", source: "validation"},
	} {
		if got := testutil.ToFloat64(m.APIDeniedRequestsTotal.WithLabelValues(tc.kind, tc.source)); got != 1 {
			t.Fatalf("expected api denied metric for %s/%s to be 1, got %v", tc.kind, tc.source, got)
		}
	}
	if got := testutil.ToFloat64(m.AuthzPolicyShadowEvaluationsTotal); got != 2 {
		t.Fatalf("expected shadow evaluations 2, got %v", got)
	}
	if got := testutil.ToFloat64(m.AuthzPolicyShadowDivergencesTotal); got != 1 {
		t.Fatalf("expected shadow divergences 1, got %v", got)
	}
	if got := testutil.ToFloat64(m.AuthzPolicyShadowEvaluationErrorsTotal); got != 1 {
		t.Fatalf("expected shadow evaluation errors 1, got %v", got)
	}
	if got := testutil.ToFloat64(m.AuthzPolicyShadowDivergenceRate); got != 0.5 {
		t.Fatalf("expected shadow divergence rate 0.5, got %v", got)
	}
	if got := testutil.ToFloat64(m.AuthzPolicyRollbacksTotal); got != 1 {
		t.Fatalf("expected rollback count 1, got %v", got)
	}
	if got := testutil.ToFloat64(m.AuthzPolicyDecisionsByVersionTotal.WithLabelValues("1", "persisted_active_version", "disabled", "true")); got != 3 {
		t.Fatalf("expected decisions-by-version count 3, got %v", got)
	}
}
