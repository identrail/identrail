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
	if result.Summary.ScanCoveragePct == 0 || result.Summary.ScanCoveragePct != result.Metrics[0].Value {
		t.Fatalf("expected scan coverage summary to follow visible coverage metric, got metric=%+v summary=%+v", result.Metrics[0], result.Summary)
	}
	if result.Summary.HighestScore != result.Metrics[0].Score {
		t.Fatalf("expected highest score to come from visible metrics, got metric=%+v summary=%+v", result.Metrics[0], result.Summary)
	}
	if result.Summary.VerifiedRemediationCount != 0 ||
		result.Summary.EnforcementReadyCount != 0 ||
		result.Summary.RemainingExposureCount != 0 ||
		result.Summary.GovernanceRecordCount != 0 ||
		result.Summary.ExceptionCount != 0 {
		t.Fatalf("expected hidden outcome summary buckets to be zeroed, got %+v", result.Summary)
	}

	severityResult, err := svc.GetAWSExecutiveOutcomeView(defaultScopeContext(), ws, "project-executive-outcomes-filter", AWSExecutiveOutcomeViewRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
		Severity:     "high",
	})
	if err != nil {
		t.Fatalf("get severity-filtered executive outcome view: %v", err)
	}
	if severityResult.AppliedFilters["severity"] != "high" {
		t.Fatalf("expected severity filter to be applied, got %+v", severityResult.AppliedFilters)
	}
	if len(severityResult.Metrics) == 0 {
		t.Fatalf("expected high severity executive metrics, got none")
	}
	for _, metric := range severityResult.Metrics {
		if metric.Severity != "high" {
			t.Fatalf("expected only high severity metrics, got %+v", severityResult.Metrics)
		}
	}
	if severityResult.Summary.SeverityCounts["high"] != len(severityResult.Metrics) {
		t.Fatalf("expected severity summary to match filtered metrics, got %+v", severityResult.Summary)
	}
}

func TestAWSExecutiveOutcomeViewKeepsRequestedScopeMetricsVisible(t *testing.T) {
	now := time.Date(2026, 7, 9, 12, 35, 0, 0, time.UTC)
	svc, ws := newExecutiveOutcomeViewService(t, "project-executive-outcomes-scope", now)

	result, err := svc.GetAWSExecutiveOutcomeView(defaultScopeContext(), ws, "project-executive-outcomes-scope", AWSExecutiveOutcomeViewRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
		AccountID:    "123456789012",
		Region:       "us-east-1",
	})
	if err != nil {
		t.Fatalf("get scoped executive outcome view: %v", err)
	}
	if result.AccountID != "123456789012" || result.Region != "us-east-1" {
		t.Fatalf("expected requested scope on result, got account=%q region=%q", result.AccountID, result.Region)
	}
	if len(result.Metrics) == 0 {
		t.Fatalf("expected requested scope to keep executive metrics visible")
	}
	for _, metric := range result.Metrics {
		if metric.AccountID != "123456789012" || metric.Region != "us-east-1" {
			t.Fatalf("expected metric to keep requested scope, got %+v", metric)
		}
	}
	if result.Summary.FilteredMetrics != len(result.Metrics) {
		t.Fatalf("expected filtered summary to match visible metrics, got summary=%+v metrics=%+v", result.Summary, result.Metrics)
	}
}

func TestAWSExecutiveOutcomeViewHidesUnsupportedRequestedScopeMetrics(t *testing.T) {
	now := time.Date(2026, 7, 9, 12, 37, 0, 0, time.UTC)
	svc, ws := newExecutiveOutcomeViewService(t, "project-executive-outcomes-empty-scope", now)

	result, err := svc.GetAWSExecutiveOutcomeView(defaultScopeContext(), ws, "project-executive-outcomes-empty-scope", AWSExecutiveOutcomeViewRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
		AccountID:    "999999999999",
		Region:       "eu-north-1",
	})
	if err != nil {
		t.Fatalf("get unsupported scoped executive outcome view: %v", err)
	}
	if result.AppliedFilters["account_id"] != "999999999999" || result.AppliedFilters["region"] != "eu-north-1" {
		t.Fatalf("expected requested scope filters to be applied, got %+v", result.AppliedFilters)
	}
	if len(result.Metrics) != 0 || result.Summary.FilteredMetrics != 0 {
		t.Fatalf("expected unsupported requested scope to hide aggregate metrics, summary=%+v metrics=%+v", result.Summary, result.Metrics)
	}

	prefixScoped, err := svc.GetAWSExecutiveOutcomeView(defaultScopeContext(), ws, "project-executive-outcomes-empty-scope", AWSExecutiveOutcomeViewRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
		AccountID:    "12345678901",
		Region:       "us",
	})
	if err != nil {
		t.Fatalf("get prefix scoped executive outcome view: %v", err)
	}
	if prefixScoped.AppliedFilters["account_id"] != "12345678901" || prefixScoped.AppliedFilters["region"] != "us" {
		t.Fatalf("expected prefix scope filters to be applied, got %+v", prefixScoped.AppliedFilters)
	}
	if len(prefixScoped.Metrics) != 0 || prefixScoped.Summary.FilteredMetrics != 0 {
		t.Fatalf("expected prefix scoped request to hide aggregate metrics, summary=%+v metrics=%+v", prefixScoped.Summary, prefixScoped.Metrics)
	}
}

func TestAWSExecutiveOutcomeViewTreatsAllAccountRegionAsUnscoped(t *testing.T) {
	now := time.Date(2026, 7, 9, 12, 40, 0, 0, time.UTC)
	svc, ws := newExecutiveOutcomeViewService(t, "project-executive-outcomes-all-scope", now)

	unscoped, err := svc.GetAWSExecutiveOutcomeView(defaultScopeContext(), ws, "project-executive-outcomes-all-scope", AWSExecutiveOutcomeViewRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
	})
	if err != nil {
		t.Fatalf("get unscoped executive outcome view: %v", err)
	}
	allScoped, err := svc.GetAWSExecutiveOutcomeView(defaultScopeContext(), ws, "project-executive-outcomes-all-scope", AWSExecutiveOutcomeViewRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
		AccountID:    "all",
		Region:       "all",
	})
	if err != nil {
		t.Fatalf("get all-scoped executive outcome view: %v", err)
	}
	if _, ok := allScoped.AppliedFilters["account_id"]; ok {
		t.Fatalf("expected account_id=all to stay unapplied, got %+v", allScoped.AppliedFilters)
	}
	if _, ok := allScoped.AppliedFilters["region"]; ok {
		t.Fatalf("expected region=all to stay unapplied, got %+v", allScoped.AppliedFilters)
	}
	if allScoped.Summary.ScanCoveragePct == 0 || allScoped.Summary.ScanCoveragePct != unscoped.Summary.ScanCoveragePct {
		t.Fatalf("expected account/region all to preserve unscoped coverage, unscoped=%+v all=%+v", unscoped.Summary, allScoped.Summary)
	}
	if allScoped.Summary.TotalMetrics != unscoped.Summary.TotalMetrics || len(allScoped.Metrics) != len(unscoped.Metrics) {
		t.Fatalf("expected account/region all to preserve unscoped metrics, unscoped=%+v all=%+v", unscoped.Summary, allScoped.Summary)
	}
}

func TestAWSExecutiveOutcomeViewSummaryHighestScoreUsesCoveragePercent(t *testing.T) {
	coverage := AWSAccountRegionCoverageResult{
		Summary: AWSAccountRegionCoverageSummary{CoveredRecords: 250, TotalRecords: 500},
		Records: []AWSAccountRegionCoverageRecord{
			{AccountID: "123456789012", Region: "us-east-1", Service: "iam", CoverageStatus: "covered"},
			{AccountID: "123456789012", Region: "us-east-1", Service: "s3", CoverageStatus: "missing"},
		},
	}
	metrics := []AWSExecutiveOutcomeMetric{{
		MetricID: "scan-coverage",
		Value:    50,
		Score:    50,
	}}
	summary := summarizeAWSExecutiveOutcomeView(metrics, metrics,
		coverage,
		AWSBlastRadiusResult{Summary: AWSBlastRadiusSummary{HighestScore: 40}},
		AWSLeastPrivilegeResult{Summary: AWSLeastPrivilegeSummary{HighestScore: 30}},
		AWSRemediationCaseResult{Summary: AWSRemediationCaseSummary{HighestScore: 20}},
		AWSPostRemediationVerificationResult{Summary: AWSPostRemediationVerificationSummary{HighestScore: 10}},
		AWSLimitedEnforcementResult{Summary: AWSLimitedEnforcementSummary{HighestScore: 45}},
		AWSGovernanceAuditReportingResult{Summary: AWSGovernanceAuditReportingSummary{HighestScore: 35}},
	)
	if summary.ScanCoveragePct != 50 {
		t.Fatalf("expected scan coverage percent 50, got %+v", summary)
	}
	if summary.HighestScore != 50 {
		t.Fatalf("expected highest score to use coverage percent, got %+v", summary)
	}
}

func TestAWSExecutiveOutcomeViewUsesFilteredSourceRowsForExecutiveTotals(t *testing.T) {
	now := time.Date(2026, 7, 9, 12, 45, 0, 0, time.UTC)

	metrics := awsExecutiveOutcomeMetrics(
		AWSAccountRegionCoverageResult{
			Summary: AWSAccountRegionCoverageSummary{CoveredRecords: 1000, TotalRecords: 1000},
			Records: []AWSAccountRegionCoverageRecord{
				{AccountID: "123456789012", Region: "us-east-1", Service: "iam", CoverageStatus: "covered"},
				{AccountID: "123456789012", Region: "us-east-1", Service: "s3", CoverageStatus: "missing"},
			},
		},
		AWSBlastRadiusResult{Summary: AWSBlastRadiusSummary{FilteredFindings: 99, HighestScore: 99}},
		AWSLeastPrivilegeResult{
			Summary: AWSLeastPrivilegeSummary{RemoveCount: 99, ReviewCount: 99, HighestScore: 99},
			Recommendations: []AWSLeastPrivilegeRecommendation{{
				RecommendationID: "lp-filtered-review",
				Decision:         "review",
				Severity:         "critical",
				Status:           "open",
				Score:            42,
				Confidence:       0.9,
				AccountID:        "123456789012",
				Region:           "us-east-1",
				Service:          "iam",
			}},
		},
		AWSRemediationCaseResult{Summary: AWSRemediationCaseSummary{VerificationPlanCount: 99, HighestScore: 99}},
		AWSPostRemediationVerificationResult{Summary: AWSPostRemediationVerificationSummary{VerifiedCount: 99, HighestScore: 99}},
		AWSLimitedEnforcementResult{Summary: AWSLimitedEnforcementSummary{CanaryReadyCount: 99, HighestScore: 99}},
		AWSGovernanceAuditReportingResult{Summary: AWSGovernanceAuditReportingSummary{FilteredRecords: 99, HighestScore: 99}},
		"123456789012",
		"us-east-1",
		now,
	)

	byID := map[string]AWSExecutiveOutcomeMetric{}
	for _, metric := range metrics {
		byID[metric.MetricID] = metric
	}
	if got := byID["scan-coverage"].Value; got != 50 {
		t.Fatalf("expected scan coverage to use filtered coverage records, got %d", got)
	}
	if got := byID["remaining-exposure"].Value; got != 1 {
		t.Fatalf("expected remaining exposure to use filtered findings/recommendations, got %d", got)
	}
	if got := byID["risk-reduction"].Value; got != 0 {
		t.Fatalf("expected risk reduction to ignore unfiltered source summary totals, got %d", got)
	}
	if got := byID["verified-remediation"].Value; got != 0 {
		t.Fatalf("expected verified remediation to use filtered verification entries, got %d", got)
	}
	if got := byID["enforcement-status"].Value; got != 0 {
		t.Fatalf("expected enforcement readiness to use filtered enforcement entries, got %d", got)
	}
	if got := byID["governance-outcomes"].Value; got != 0 {
		t.Fatalf("expected governance outcomes to use filtered governance records, got %d", got)
	}
}

func TestAWSExecutiveOutcomeViewDerivesEnforcementSeverityFromRows(t *testing.T) {
	now := time.Date(2026, 7, 9, 12, 50, 0, 0, time.UTC)
	metrics := awsExecutiveOutcomeMetrics(
		AWSAccountRegionCoverageResult{},
		AWSBlastRadiusResult{},
		AWSLeastPrivilegeResult{},
		AWSRemediationCaseResult{},
		AWSPostRemediationVerificationResult{},
		AWSLimitedEnforcementResult{
			Entries: []AWSLimitedEnforcementEntry{{
				Severity:            "critical",
				ReadyForCanary:      true,
				ReadyForEnforcement: true,
				Score:               92,
				Confidence:          0.93,
			}},
		},
		AWSGovernanceAuditReportingResult{},
		"123456789012",
		"us-east-1",
		now,
	)

	critical, _ := filterAWSExecutiveOutcomeMetrics(metrics, AWSExecutiveOutcomeViewRequest{Severity: "critical"})
	if _, ok := metricByID(critical, "enforcement-status"); !ok {
		t.Fatalf("expected critical enforcement rows to keep enforcement metric visible: %+v", critical)
	}

	metrics = awsExecutiveOutcomeMetrics(
		AWSAccountRegionCoverageResult{},
		AWSBlastRadiusResult{},
		AWSLeastPrivilegeResult{},
		AWSRemediationCaseResult{},
		AWSPostRemediationVerificationResult{},
		AWSLimitedEnforcementResult{
			Entries: []AWSLimitedEnforcementEntry{{
				Severity:            "medium",
				ReadyForCanary:      true,
				ReadyForEnforcement: true,
				Score:               48,
				Confidence:          0.82,
			}},
		},
		AWSGovernanceAuditReportingResult{},
		"123456789012",
		"us-east-1",
		now,
	)
	high, _ := filterAWSExecutiveOutcomeMetrics(metrics, AWSExecutiveOutcomeViewRequest{Severity: "high"})
	if metric, ok := metricByID(high, "enforcement-status"); ok {
		t.Fatalf("expected high filter to drop medium enforcement metric, got %+v", metric)
	}
}

func TestAWSExecutiveOutcomeViewDoesNotTagEmptySeverityRollupsLow(t *testing.T) {
	now := time.Date(2026, 7, 9, 12, 52, 0, 0, time.UTC)
	metrics := awsExecutiveOutcomeMetrics(
		AWSAccountRegionCoverageResult{},
		AWSBlastRadiusResult{},
		AWSLeastPrivilegeResult{},
		AWSRemediationCaseResult{},
		AWSPostRemediationVerificationResult{},
		AWSLimitedEnforcementResult{},
		AWSGovernanceAuditReportingResult{},
		"123456789012",
		"us-east-1",
		now,
	)
	low, applied := filterAWSExecutiveOutcomeMetrics(metrics, AWSExecutiveOutcomeViewRequest{Severity: "low"})
	if applied["severity"] != "low" {
		t.Fatalf("expected low severity filter to be recorded, got %+v", applied)
	}
	if len(low) != 0 {
		t.Fatalf("expected empty source rollups to stay hidden from low severity filter, got %+v", low)
	}

	metrics = awsExecutiveOutcomeMetrics(
		AWSAccountRegionCoverageResult{},
		AWSBlastRadiusResult{},
		AWSLeastPrivilegeResult{
			Recommendations: []AWSLeastPrivilegeRecommendation{{
				RecommendationID: "lp-low-review",
				Decision:         "review",
				Severity:         "low",
				Status:           "open",
				Score:            16,
				Confidence:       0.88,
				AccountID:        "123456789012",
				Region:           "us-east-1",
				Service:          "iam",
			}},
		},
		AWSRemediationCaseResult{},
		AWSPostRemediationVerificationResult{},
		AWSLimitedEnforcementResult{},
		AWSGovernanceAuditReportingResult{},
		"123456789012",
		"us-east-1",
		now,
	)
	low, _ = filterAWSExecutiveOutcomeMetrics(metrics, AWSExecutiveOutcomeViewRequest{Severity: "low"})
	if _, ok := metricByID(low, "remaining-exposure"); !ok {
		t.Fatalf("expected real low severity source rows to stay visible, got %+v", low)
	}
}

func TestAWSExecutiveOutcomeViewCountsDistinctEnforcementReadyRows(t *testing.T) {
	now := time.Date(2026, 7, 9, 12, 55, 0, 0, time.UTC)
	enforcement := AWSLimitedEnforcementResult{
		Entries: []AWSLimitedEnforcementEntry{{
			Severity:            "high",
			ReadyForCanary:      true,
			ReadyForEnforcement: true,
			Score:               88,
			Confidence:          0.91,
		}},
	}
	metrics := awsExecutiveOutcomeMetrics(
		AWSAccountRegionCoverageResult{},
		AWSBlastRadiusResult{},
		AWSLeastPrivilegeResult{},
		AWSRemediationCaseResult{},
		AWSPostRemediationVerificationResult{},
		enforcement,
		AWSGovernanceAuditReportingResult{},
		"123456789012",
		"us-east-1",
		now,
	)

	metric, ok := metricByID(metrics, "enforcement-status")
	if !ok {
		t.Fatalf("expected enforcement metric in executive view: %+v", metrics)
	}
	if metric.Value != 1 || metric.TrendDelta != 1 {
		t.Fatalf("expected one distinct ready enforcement row, got metric=%+v", metric)
	}

	summary := summarizeAWSExecutiveOutcomeView(metrics, metrics,
		AWSAccountRegionCoverageResult{},
		AWSBlastRadiusResult{},
		AWSLeastPrivilegeResult{},
		AWSRemediationCaseResult{},
		AWSPostRemediationVerificationResult{},
		enforcement,
		AWSGovernanceAuditReportingResult{},
	)
	if summary.EnforcementReadyCount != 1 {
		t.Fatalf("expected summary to count one distinct ready enforcement row, got %+v", summary)
	}
}

func TestAWSExecutiveOutcomeViewFiltersEnforcementRowsBeforeSeverityRollup(t *testing.T) {
	now := time.Date(2026, 7, 9, 13, 0, 0, 0, time.UTC)
	enforcement := awsExecutiveOutcomeFilterLimitedEnforcementRows(AWSLimitedEnforcementResult{
		Entries: []AWSLimitedEnforcementEntry{
			{
				Severity:   "high",
				Score:      42,
				Confidence: 0.84,
			},
			{
				Severity:            "low",
				ReadyForCanary:      true,
				ReadyForEnforcement: true,
				Score:               96,
				Confidence:          0.96,
			},
		},
	}, AWSExecutiveOutcomeViewRequest{Severity: "high"})
	metrics := awsExecutiveOutcomeMetrics(
		AWSAccountRegionCoverageResult{},
		AWSBlastRadiusResult{},
		AWSLeastPrivilegeResult{},
		AWSRemediationCaseResult{},
		AWSPostRemediationVerificationResult{},
		enforcement,
		AWSGovernanceAuditReportingResult{},
		"123456789012",
		"us-east-1",
		now,
	)
	high, _ := filterAWSExecutiveOutcomeMetrics(metrics, AWSExecutiveOutcomeViewRequest{Severity: "high"})
	metric, ok := metricByID(high, "enforcement-status")
	if !ok {
		t.Fatalf("expected high enforcement metric after severity rollup filtering: %+v", high)
	}
	if metric.Value != 0 || metric.Score != 42 {
		t.Fatalf("expected high rollup to exclude low ready rows, got %+v", metric)
	}

	summary := summarizeAWSExecutiveOutcomeView(metrics, high,
		AWSAccountRegionCoverageResult{},
		AWSBlastRadiusResult{},
		AWSLeastPrivilegeResult{},
		AWSRemediationCaseResult{},
		AWSPostRemediationVerificationResult{},
		enforcement,
		AWSGovernanceAuditReportingResult{},
	)
	if summary.EnforcementReadyCount != 0 {
		t.Fatalf("expected high summary to exclude low ready rows, got %+v", summary)
	}
}

func metricByID(metrics []AWSExecutiveOutcomeMetric, id string) (AWSExecutiveOutcomeMetric, bool) {
	for _, metric := range metrics {
		if metric.MetricID == id {
			return metric, true
		}
	}
	return AWSExecutiveOutcomeMetric{}, false
}

func TestAWSExecutiveOutcomeViewStatusPreservesSourceStateWithNoMetrics(t *testing.T) {
	status, confidence := summarizeAWSExecutiveOutcomeViewStatus(nil, "permission_denied", "ready")
	if status != "blocked" || confidence != 0.55 {
		t.Fatalf("expected blocked source status to survive empty filters, got status=%q confidence=%v", status, confidence)
	}

	status, confidence = summarizeAWSExecutiveOutcomeViewStatus(nil, "ready")
	if status != "ready" || confidence != 0.8 {
		t.Fatalf("expected empty ready source to stay ready, got status=%q confidence=%v", status, confidence)
	}
}

func TestAWSExecutiveOutcomeViewStatusTreatsFilteredEmptySourcesAsReady(t *testing.T) {
	statuses := awsExecutiveOutcomeSourceStatuses(
		AWSExecutiveOutcomeViewRequest{Severity: "critical"},
		"success",
		AWSAccountRegionCoverageResult{Status: awsPlatformDependencyStatusReady},
		AWSBlastRadiusResult{Status: awsPlatformDependencyStatusDegraded},
		AWSLeastPrivilegeResult{Status: awsPlatformDependencyStatusDegraded},
		AWSRemediationCaseResult{Status: awsPlatformDependencyStatusDegraded},
		AWSPostRemediationVerificationResult{Status: awsPlatformDependencyStatusReady},
		AWSLimitedEnforcementResult{Status: awsPlatformDependencyStatusReady},
		AWSGovernanceAuditReportingResult{Status: awsPlatformDependencyStatusReady},
	)
	status, confidence := summarizeAWSExecutiveOutcomeViewStatus(nil, statuses...)
	if status != awsPlatformDependencyStatusReady || confidence != 0.8 {
		t.Fatalf("expected empty filtered sources to stay ready, got status=%q confidence=%v statuses=%+v", status, confidence, statuses)
	}
}

func TestAWSExecutiveOutcomeViewStatusScopesCoverageToFilteredRows(t *testing.T) {
	request := AWSExecutiveOutcomeViewRequest{AccountID: "222222222222", Region: "us-west-2"}
	healthyScopedCoverage := AWSAccountRegionCoverageResult{
		Status: awsPlatformDependencyStatusDegraded,
		Records: []AWSAccountRegionCoverageRecord{
			{AccountID: "222222222222", Region: "us-west-2", Service: "iam", CoverageStatus: "covered"},
		},
	}
	statuses := awsExecutiveOutcomeSourceStatuses(
		request,
		"",
		healthyScopedCoverage,
		AWSBlastRadiusResult{Status: awsPlatformDependencyStatusReady},
		AWSLeastPrivilegeResult{Status: awsPlatformDependencyStatusReady},
		AWSRemediationCaseResult{Status: awsPlatformDependencyStatusReady},
		AWSPostRemediationVerificationResult{Status: awsPlatformDependencyStatusReady},
		AWSLimitedEnforcementResult{Status: awsPlatformDependencyStatusReady},
		AWSGovernanceAuditReportingResult{Status: awsPlatformDependencyStatusReady},
	)
	status, confidence := summarizeAWSExecutiveOutcomeViewStatus(nil, statuses...)
	if status != awsPlatformDependencyStatusReady || confidence != 0.8 {
		t.Fatalf("expected healthy scoped coverage rows to override unscoped degradation, got status=%q confidence=%v statuses=%+v", status, confidence, statuses)
	}

	scopedPermissionDenied := healthyScopedCoverage
	scopedPermissionDenied.Status = awsPlatformDependencyStatusReady
	scopedPermissionDenied.Records[0].CoverageStatus = "permission_denied"
	statuses = awsExecutiveOutcomeSourceStatuses(
		request,
		"",
		scopedPermissionDenied,
		AWSBlastRadiusResult{Status: awsPlatformDependencyStatusReady},
		AWSLeastPrivilegeResult{Status: awsPlatformDependencyStatusReady},
		AWSRemediationCaseResult{Status: awsPlatformDependencyStatusReady},
		AWSPostRemediationVerificationResult{Status: awsPlatformDependencyStatusReady},
		AWSLimitedEnforcementResult{Status: awsPlatformDependencyStatusReady},
		AWSGovernanceAuditReportingResult{Status: awsPlatformDependencyStatusReady},
	)
	status, confidence = summarizeAWSExecutiveOutcomeViewStatus(nil, statuses...)
	if status != awsPlatformDependencyStatusBlocked || confidence != 0.55 {
		t.Fatalf("expected scoped permission-denied coverage row to stay blocked, got status=%q confidence=%v statuses=%+v", status, confidence, statuses)
	}
}

func TestAWSExecutiveOutcomeViewStatusKeepsRealSourceDegradation(t *testing.T) {
	statuses := awsExecutiveOutcomeSourceStatuses(
		AWSExecutiveOutcomeViewRequest{Severity: "critical"},
		"success",
		AWSAccountRegionCoverageResult{Status: awsPlatformDependencyStatusReady},
		AWSBlastRadiusResult{
			Status:         awsPlatformDependencyStatusDegraded,
			FailureReasons: []string{"blast radius source returned retryable diagnostics"},
		},
		AWSLeastPrivilegeResult{Status: awsPlatformDependencyStatusReady},
		AWSRemediationCaseResult{Status: awsPlatformDependencyStatusReady},
		AWSPostRemediationVerificationResult{Status: awsPlatformDependencyStatusReady},
		AWSLimitedEnforcementResult{Status: awsPlatformDependencyStatusReady},
		AWSGovernanceAuditReportingResult{Status: awsPlatformDependencyStatusReady},
	)
	status, confidence := summarizeAWSExecutiveOutcomeViewStatus(nil, statuses...)
	if status != awsPlatformDependencyStatusDegraded || confidence != 0.74 {
		t.Fatalf("expected real source degradation to survive empty filters, got status=%q confidence=%v statuses=%+v", status, confidence, statuses)
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
