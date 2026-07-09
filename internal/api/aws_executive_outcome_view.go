package api

import (
	"context"
	"sort"
	"strings"
	"time"
)

const (
	awsExecutiveOutcomeViewCurrentIssue = 1555
	awsExecutiveOutcomeViewVersion      = "aws-executive-outcome-view-v1"
	awsExecutiveOutcomeViewBoundary     = "metadata_only_outcome_metrics_no_secret_values_no_customer_payloads"
)

// AWSExecutiveOutcomeViewRequest scopes the executive outcome rollup to one
// AWS connector plus operator-visible filters. The endpoint composes existing
// read-only AWS evidence contracts and never reads or persists payload content.
type AWSExecutiveOutcomeViewRequest struct {
	ConnectorID  string `json:"connector_id,omitempty"`
	FixtureState string `json:"fixture_state,omitempty"`
	AccountID    string `json:"account_id,omitempty"`
	Region       string `json:"region,omitempty"`
	OU           string `json:"ou,omitempty"`
	IdentityType string `json:"identity_type,omitempty"`
	Severity     string `json:"severity,omitempty"`
	OutcomeType  string `json:"outcome_type,omitempty"`
	Trend        string `json:"trend,omitempty"`
	Search       string `json:"search,omitempty"`
}

type AWSExecutiveOutcomeMetric struct {
	MetricID         string    `json:"metric_id"`
	Category         string    `json:"category"`
	OutcomeType      string    `json:"outcome_type"`
	Title            string    `json:"title"`
	Summary          string    `json:"summary"`
	Value            int       `json:"value"`
	Unit             string    `json:"unit"`
	Trend            string    `json:"trend"`
	TrendDelta       int       `json:"trend_delta"`
	Score            int       `json:"score"`
	Confidence       float64   `json:"confidence"`
	AccountID        string    `json:"account_id,omitempty"`
	Region           string    `json:"region,omitempty"`
	OU               string    `json:"ou,omitempty"`
	IdentityType     string    `json:"identity_type,omitempty"`
	Severity         string    `json:"severity,omitempty"`
	EvidenceLinks    []string  `json:"evidence_links"`
	EvidenceRef      string    `json:"evidence_ref,omitempty"`
	EvidenceBoundary string    `json:"evidence_boundary"`
	NextAction       string    `json:"next_action"`
	UpdatedAt        time.Time `json:"updated_at"`
}

type AWSExecutiveOutcomeCoverageGap struct {
	Capability  string `json:"capability"`
	Status      string `json:"status"`
	Reason      string `json:"reason"`
	Remediation string `json:"remediation,omitempty"`
}

type AWSExecutiveOutcomeDiagnostic struct {
	Collector   string `json:"collector"`
	SourceID    string `json:"source_id,omitempty"`
	Code        string `json:"code"`
	Message     string `json:"message"`
	Remediation string `json:"remediation,omitempty"`
	Retryable   bool   `json:"retryable"`
}

type AWSExecutiveOutcomeViewSummary struct {
	TotalMetrics             int            `json:"total_metrics"`
	FilteredMetrics          int            `json:"filtered_metrics"`
	RiskReductionScore       int            `json:"risk_reduction_score"`
	ScanCoveragePct          int            `json:"scan_coverage_pct"`
	VerifiedRemediationCount int            `json:"verified_remediation_count"`
	EnforcementReadyCount    int            `json:"enforcement_ready_count"`
	RemainingExposureCount   int            `json:"remaining_exposure_count"`
	DegradedCoverageCount    int            `json:"degraded_coverage_count"`
	GovernanceRecordCount    int            `json:"governance_record_count"`
	ExceptionCount           int            `json:"exception_count"`
	AccountCounts            map[string]int `json:"account_counts"`
	OUCounts                 map[string]int `json:"ou_counts"`
	IdentityTypeCounts       map[string]int `json:"identity_type_counts"`
	SeverityCounts           map[string]int `json:"severity_counts"`
	OutcomeTypeCounts        map[string]int `json:"outcome_type_counts"`
	TrendCounts              map[string]int `json:"trend_counts"`
	HighestScore             int            `json:"highest_score"`
	AverageConfidencePct     int            `json:"average_confidence_pct"`
}

type AWSExecutiveOutcomeViewResult struct {
	TenantID           string                           `json:"tenant_id"`
	WorkspaceID        string                           `json:"workspace_id"`
	ProjectID          string                           `json:"project_id"`
	ConnectorID        string                           `json:"connector_id,omitempty"`
	AccountID          string                           `json:"account_id,omitempty"`
	Region             string                           `json:"region,omitempty"`
	ParentIssueNumber  int                              `json:"parent_issue_number"`
	ParentIssueRef     string                           `json:"parent_issue_ref"`
	CurrentIssueNumber int                              `json:"current_issue_number"`
	CurrentIssueRef    string                           `json:"current_issue_ref"`
	Version            string                           `json:"version"`
	Status             string                           `json:"status"`
	FixtureState       string                           `json:"fixture_state,omitempty"`
	Confidence         float64                          `json:"confidence"`
	CalculationVersion string                           `json:"calculation_version"`
	AppliedFilters     map[string]string                `json:"applied_filters"`
	Summary            AWSExecutiveOutcomeViewSummary   `json:"summary"`
	Metrics            []AWSExecutiveOutcomeMetric      `json:"metrics"`
	Caveats            []string                         `json:"caveats"`
	FailureReasons     []string                         `json:"failure_reasons"`
	RemediationHints   []string                         `json:"remediation_hints"`
	EvidenceLinks      []string                         `json:"evidence_links"`
	CoverageGaps       []AWSExecutiveOutcomeCoverageGap `json:"coverage_gaps"`
	Diagnostics        []AWSExecutiveOutcomeDiagnostic  `json:"diagnostics"`
	GeneratedAt        time.Time                        `json:"generated_at"`
	UpdatedAt          time.Time                        `json:"updated_at"`
}

type awsExecutiveOutcomeSourceSummaries struct {
	Coverage     AWSAccountRegionCoverageSummary
	Blast        AWSBlastRadiusSummary
	Least        AWSLeastPrivilegeSummary
	Cases        AWSRemediationCaseSummary
	Verification AWSPostRemediationVerificationSummary
	Enforcement  AWSLimitedEnforcementSummary
	Governance   AWSGovernanceAuditReportingSummary
}

func (s *Service) GetAWSExecutiveOutcomeView(ctx context.Context, workspaceID string, projectID string, request AWSExecutiveOutcomeViewRequest) (AWSExecutiveOutcomeViewResult, error) {
	project, scope, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return AWSExecutiveOutcomeViewResult{}, err
	}
	connection, hasConnection, err := s.awsBaselineConnection(ctx, project, strings.TrimSpace(request.ConnectorID))
	if err != nil {
		return AWSExecutiveOutcomeViewResult{}, err
	}
	now := s.Now().UTC()
	fixtureState := normalizeAWSGovernanceAuditReportingFixtureState(request.FixtureState, connection, hasConnection)
	if fixtureState == "" {
		return AWSExecutiveOutcomeViewResult{}, ErrInvalidAWSConnectionRequest
	}
	accountID := awsExecutiveOutcomeScopeValue(request.AccountID, connection.AccountID, "123456789012")
	region := awsExecutiveOutcomeScopeValue(request.Region, connection.Region, "us-east-1")
	connectorID := firstNonEmptyAWSValue(connection.ConnectorID, strings.TrimSpace(request.ConnectorID))
	sourceAccountID := awsExecutiveOutcomeSourceScopeFilter(request.AccountID)
	sourceRegion := awsExecutiveOutcomeSourceScopeFilter(request.Region)
	sourceFixtureState := fixtureState
	if strings.TrimSpace(request.FixtureState) == "" && hasConnection && connection.Connected {
		sourceFixtureState = ""
	}

	coverage, err := s.GetAWSAccountRegionCoverage(ctx, workspaceID, projectID, AWSAccountRegionCoverageRequest{
		ConnectorID:  connectorID,
		FixtureState: sourceFixtureState,
		Account:      sourceAccountID,
		Region:       sourceRegion,
	})
	if err != nil {
		return AWSExecutiveOutcomeViewResult{}, err
	}
	blast, err := s.GetAWSBlastRadius(ctx, workspaceID, projectID, AWSBlastRadiusRequest{
		ConnectorID:  connectorID,
		FixtureState: sourceFixtureState,
		AccountID:    sourceAccountID,
		Region:       sourceRegion,
		Severity:     request.Severity,
	})
	if err != nil {
		return AWSExecutiveOutcomeViewResult{}, err
	}
	least, err := s.GetAWSLeastPrivilegeRecommendations(ctx, workspaceID, projectID, AWSLeastPrivilegeRequest{
		ConnectorID:  connectorID,
		FixtureState: sourceFixtureState,
		AccountID:    sourceAccountID,
		Region:       sourceRegion,
		Severity:     request.Severity,
	})
	if err != nil {
		return AWSExecutiveOutcomeViewResult{}, err
	}
	cases, err := s.GetAWSRemediationCases(ctx, workspaceID, projectID, AWSRemediationCaseRequest{
		ConnectorID:  connectorID,
		FixtureState: sourceFixtureState,
		AccountID:    sourceAccountID,
		Region:       sourceRegion,
		Severity:     request.Severity,
	})
	if err != nil {
		return AWSExecutiveOutcomeViewResult{}, err
	}
	verification, err := s.GetAWSPostRemediationVerification(ctx, workspaceID, projectID, AWSPostRemediationVerificationRequest{
		ConnectorID:  connectorID,
		FixtureState: sourceFixtureState,
		AccountID:    sourceAccountID,
		Region:       sourceRegion,
		Severity:     request.Severity,
	})
	if err != nil {
		return AWSExecutiveOutcomeViewResult{}, err
	}
	enforcement, err := s.GetAWSLimitedEnforcement(ctx, workspaceID, projectID, AWSLimitedEnforcementRequest{
		ConnectorID:  connectorID,
		FixtureState: sourceFixtureState,
		AccountID:    sourceAccountID,
		Region:       sourceRegion,
	})
	if err != nil {
		return AWSExecutiveOutcomeViewResult{}, err
	}
	enforcement = awsExecutiveOutcomeFilterLimitedEnforcementRows(enforcement, request)
	governance, err := s.GetAWSGovernanceAuditReporting(ctx, workspaceID, projectID, AWSGovernanceAuditReportingRequest{
		ConnectorID:  connectorID,
		FixtureState: sourceFixtureState,
		AccountID:    sourceAccountID,
		Region:       sourceRegion,
		OU:           request.OU,
		Search:       request.Search,
	})
	if err != nil {
		return AWSExecutiveOutcomeViewResult{}, err
	}

	hasScopedSourceRows := awsExecutiveOutcomeHasSourceRows(coverage, blast, least, cases, verification, enforcement, governance)
	metricAccountID := awsExecutiveOutcomeMetricScopeValue(request.AccountID, connection.AccountID, "123456789012", hasScopedSourceRows)
	metricRegion := awsExecutiveOutcomeMetricScopeValue(request.Region, connection.Region, "us-east-1", hasScopedSourceRows)
	metrics := awsExecutiveOutcomeMetrics(coverage, blast, least, cases, verification, enforcement, governance, metricAccountID, metricRegion, now)
	filtered, applied := filterAWSExecutiveOutcomeMetrics(metrics, request)
	summary := summarizeAWSExecutiveOutcomeView(metrics, filtered, coverage, blast, least, cases, verification, enforcement, governance)
	status, confidence := summarizeAWSExecutiveOutcomeViewStatus(filtered, awsExecutiveOutcomeSourceStatuses(request, sourceFixtureState, coverage, blast, least, cases, verification, enforcement, governance)...)
	return AWSExecutiveOutcomeViewResult{
		TenantID:           scope.TenantID,
		WorkspaceID:        project.WorkspaceID,
		ProjectID:          project.ProjectID,
		ConnectorID:        connectorID,
		AccountID:          accountID,
		Region:             region,
		ParentIssueNumber:  awsPlatformDependencyParentIssue,
		ParentIssueRef:     awsIssueRef(awsPlatformDependencyParentIssue),
		CurrentIssueNumber: awsExecutiveOutcomeViewCurrentIssue,
		CurrentIssueRef:    awsIssueRef(awsExecutiveOutcomeViewCurrentIssue),
		Version:            awsExecutiveOutcomeViewVersion,
		Status:             status,
		FixtureState:       sourceFixtureState,
		Confidence:         confidence,
		CalculationVersion: awsExecutiveOutcomeViewVersion,
		AppliedFilters:     applied,
		Summary:            summary,
		Metrics:            filtered,
		Caveats:            awsExecutiveOutcomeViewCaveats(),
		FailureReasons:     dedupeStrings(append(append(append(append(append(append([]string{}, coverage.FailureReasons...), blast.FailureReasons...), least.FailureReasons...), cases.FailureReasons...), verification.FailureReasons...), append(enforcement.FailureReasons, governance.FailureReasons...)...)),
		RemediationHints:   awsExecutiveOutcomeViewRemediationHints(),
		EvidenceLinks: dedupeStrings([]string{
			awsIssueURL(awsPlatformDependencyParentIssue),
			awsIssueURL(awsExecutiveOutcomeViewCurrentIssue),
			awsIssueURL(awsAccountRegionCoverageAPICurrentIssue),
			awsIssueURL(awsPostRemediationVerificationCurrentIssue),
			awsIssueURL(awsGovernanceAuditReportingCurrentIssue),
			"/docs/aws-executive-outcome-view",
			awsBaselineProjectEvidenceURL(scope, project),
		}),
		CoverageGaps: awsExecutiveOutcomeCoverageGaps(coverage.CoverageGaps, blast.CoverageGaps, least.CoverageGaps, cases.CoverageGaps, verification.CoverageGaps, enforcement.CoverageGaps, governance.CoverageGaps),
		Diagnostics:  awsExecutiveOutcomeDiagnostics(coverage.Diagnostics, blast.Diagnostics, least.Diagnostics, cases.Diagnostics, verification.Diagnostics, enforcement.Diagnostics, governance.Diagnostics),
		GeneratedAt:  now,
		UpdatedAt:    now,
	}, nil
}

func awsExecutiveOutcomeMetrics(
	coverage AWSAccountRegionCoverageResult,
	blast AWSBlastRadiusResult,
	least AWSLeastPrivilegeResult,
	cases AWSRemediationCaseResult,
	verification AWSPostRemediationVerificationResult,
	enforcement AWSLimitedEnforcementResult,
	governance AWSGovernanceAuditReportingResult,
	accountID string,
	region string,
	now time.Time,
) []AWSExecutiveOutcomeMetric {
	summaries := awsExecutiveOutcomeFilteredSourceSummaries(coverage, blast, least, cases, verification, enforcement, governance)
	coveragePct := percent(summaries.Coverage.CoveredRecords, summaries.Coverage.TotalRecords)
	remainingExposure := summaries.Blast.FilteredFindings + summaries.Least.ReviewCount
	riskReduction := clampInt(summaries.Least.RemoveCount*12+summaries.Cases.VerificationPlanCount*10+summaries.Verification.VerifiedCount*18+summaries.Enforcement.CanaryReadyCount*8-remainingExposure*5, 0, 100)
	degradedCoverage := summaries.Coverage.DegradedRecords + summaries.Coverage.UnreachableRecords + summaries.Coverage.PermissionDeniedRecords + summaries.Coverage.StaleRecords
	enforcementReady := awsExecutiveOutcomeLimitedEnforcementReadyCount(enforcement.Entries)
	metrics := []AWSExecutiveOutcomeMetric{
		{
			MetricID:         "risk-reduction",
			Category:         "risk_reduction",
			OutcomeType:      "risk_reduction",
			Title:            "Risk reduction",
			Summary:          "Projected reduction from least-privilege recommendations, remediation planning, verified remediation, and enforcement readiness.",
			Value:            riskReduction,
			Unit:             "score",
			Trend:            trendFromDelta(riskReduction - remainingExposure),
			TrendDelta:       riskReduction - remainingExposure,
			Score:            riskReduction,
			Confidence:       averageFloat64(blast.Confidence, least.Confidence, cases.Confidence, verification.Confidence),
			AccountID:        accountID,
			Region:           region,
			IdentityType:     "machine_identity",
			Severity:         severityFromCounts(summaries.Blast.SeverityCounts, summaries.Least.SeverityCounts, summaries.Cases.SeverityCounts),
			EvidenceLinks:    dedupeStrings(append(append([]string{}, least.EvidenceLinks...), cases.EvidenceLinks...)),
			EvidenceRef:      "aws-executive-outcome://risk-reduction",
			EvidenceBoundary: awsExecutiveOutcomeViewBoundary,
			NextAction:       "Review the top remaining exposures and approve low-breakage remediation plans.",
			UpdatedAt:        now,
		},
		{
			MetricID:         "scan-coverage",
			Category:         "scan_coverage",
			OutcomeType:      "coverage",
			Title:            "Scan coverage",
			Summary:          "Account, region, service, and collector coverage across the selected AWS connector.",
			Value:            coveragePct,
			Unit:             "percent",
			Trend:            trendFromDelta(summaries.Coverage.CoveredRecords - degradedCoverage),
			TrendDelta:       summaries.Coverage.CoveredRecords - degradedCoverage,
			Score:            coveragePct,
			Confidence:       coverage.Confidence,
			AccountID:        accountID,
			Region:           region,
			IdentityType:     "coverage_target",
			Severity:         severityFromFailureCount(degradedCoverage, summaries.Coverage.TotalRecords),
			EvidenceLinks:    coverage.EvidenceLinks,
			EvidenceRef:      "aws-executive-outcome://scan-coverage",
			EvidenceBoundary: awsExecutiveOutcomeViewBoundary,
			NextAction:       "Close degraded, stale, or permission-denied coverage before treating the outcome view as complete.",
			UpdatedAt:        coverage.UpdatedAt,
		},
		{
			MetricID:         "verified-remediation",
			Category:         "verified_remediation",
			OutcomeType:      "remediation",
			Title:            "Verified remediation",
			Summary:          "Post-remediation verification and rollback state from read-only executor projections.",
			Value:            summaries.Verification.VerifiedCount,
			Unit:             "verified",
			Trend:            trendFromDelta(summaries.Verification.VerifiedCount - summaries.Verification.FailedCount - summaries.Verification.BlockedCount),
			TrendDelta:       summaries.Verification.VerifiedCount - summaries.Verification.FailedCount - summaries.Verification.BlockedCount,
			Score:            summaries.Verification.HighestScore,
			Confidence:       verification.Confidence,
			AccountID:        accountID,
			Region:           region,
			IdentityType:     "remediation_target",
			Severity:         severityFromCounts(summaries.Verification.SeverityCounts),
			EvidenceLinks:    verification.EvidenceLinks,
			EvidenceRef:      "aws-executive-outcome://verified-remediation",
			EvidenceBoundary: awsExecutiveOutcomeViewBoundary,
			NextAction:       "Review failed, pending, or rollback-planned verification records before reporting closure.",
			UpdatedAt:        verification.UpdatedAt,
		},
		{
			MetricID:         "enforcement-status",
			Category:         "enforcement_status",
			OutcomeType:      "enforcement",
			Title:            "Enforcement readiness",
			Summary:          "Limited enforcement readiness, canary safety, and kill-switch status.",
			Value:            enforcementReady,
			Unit:             "ready",
			Trend:            trendFromDelta(enforcementReady - summaries.Enforcement.KillSwitchEngagedCount - summaries.Enforcement.FailedGateCount),
			TrendDelta:       enforcementReady - summaries.Enforcement.KillSwitchEngagedCount - summaries.Enforcement.FailedGateCount,
			Score:            summaries.Enforcement.HighestScore,
			Confidence:       enforcement.Confidence,
			AccountID:        accountID,
			Region:           region,
			IdentityType:     "governed_identity",
			Severity:         awsExecutiveOutcomeLimitedEnforcementSeverity(enforcement.Entries),
			EvidenceLinks:    enforcement.EvidenceLinks,
			EvidenceRef:      "aws-executive-outcome://enforcement-status",
			EvidenceBoundary: awsExecutiveOutcomeViewBoundary,
			NextAction:       "Keep enforcement in advisory or canary mode until every safety gate and rollback path is explicit.",
			UpdatedAt:        enforcement.UpdatedAt,
		},
		{
			MetricID:         "remaining-exposure",
			Category:         "remaining_exposure",
			OutcomeType:      "exposure",
			Title:            "Remaining exposure",
			Summary:          "Open blast-radius findings and least-privilege review work that still require operator action.",
			Value:            remainingExposure,
			Unit:             "open",
			Trend:            trendFromDelta(-remainingExposure),
			TrendDelta:       -remainingExposure,
			Score:            maxInt(summaries.Blast.HighestScore, summaries.Least.HighestScore),
			Confidence:       averageFloat64(blast.Confidence, least.Confidence),
			AccountID:        accountID,
			Region:           region,
			IdentityType:     "machine_identity",
			Severity:         severityFromCounts(summaries.Blast.SeverityCounts, summaries.Least.SeverityCounts),
			EvidenceLinks:    dedupeStrings(append(append([]string{}, blast.EvidenceLinks...), least.EvidenceLinks...)),
			EvidenceRef:      "aws-executive-outcome://remaining-exposure",
			EvidenceBoundary: awsExecutiveOutcomeViewBoundary,
			NextAction:       "Prioritize critical and high residual exposure before expanding live enforcement.",
			UpdatedAt:        now,
		},
		{
			MetricID:         "governance-outcomes",
			Category:         "governance_outcomes",
			OutcomeType:      "governance",
			Title:            "Governance outcomes",
			Summary:          "Export-safe decision, approval, remediation, enforcement, and exception rows available to leadership.",
			Value:            summaries.Governance.FilteredRecords,
			Unit:             "records",
			Trend:            trendFromDelta(summaries.Governance.EnforcementOutcomeCount + summaries.Governance.RemediationCount - summaries.Governance.ExceptionCount),
			TrendDelta:       summaries.Governance.EnforcementOutcomeCount + summaries.Governance.RemediationCount - summaries.Governance.ExceptionCount,
			Score:            summaries.Governance.HighestScore,
			Confidence:       governance.Confidence,
			AccountID:        accountID,
			Region:           region,
			OU:               awsExecutiveOutcomeMetricOU(governance.Records),
			IdentityType:     "governance_record",
			Severity:         severityFromFailureCount(summaries.Governance.ExceptionCount, summaries.Governance.FilteredRecords),
			EvidenceLinks:    governance.EvidenceLinks,
			EvidenceRef:      "aws-executive-outcome://governance-outcomes",
			EvidenceBoundary: awsExecutiveOutcomeViewBoundary,
			NextAction:       "Export governance rows for leadership review and investigate exception records.",
			UpdatedAt:        governance.UpdatedAt,
		},
	}
	for i := range metrics {
		metrics[i].EvidenceLinks = dedupeStrings(metrics[i].EvidenceLinks)
	}
	sort.SliceStable(metrics, func(i, j int) bool {
		if metrics[i].Score == metrics[j].Score {
			return metrics[i].MetricID < metrics[j].MetricID
		}
		return metrics[i].Score > metrics[j].Score
	})
	return metrics
}

func awsExecutiveOutcomeScopeValue(requestValue string, connectionValue string, fallback string) string {
	requestValue = strings.TrimSpace(requestValue)
	if requestValue != "" && !strings.EqualFold(requestValue, "all") {
		return requestValue
	}
	return firstNonEmptyAWSValue(connectionValue, fallback)
}

func awsExecutiveOutcomeMetricScopeValue(requestValue string, connectionValue string, fallback string, hasScopedSourceRows bool) string {
	requestValue = strings.TrimSpace(requestValue)
	if requestValue != "" && !strings.EqualFold(requestValue, "all") && hasScopedSourceRows {
		return requestValue
	}
	return firstNonEmptyAWSValue(connectionValue, fallback)
}

func awsExecutiveOutcomeSourceScopeFilter(value string) string {
	value = strings.TrimSpace(value)
	if strings.EqualFold(value, "all") {
		return ""
	}
	return value
}

func awsExecutiveOutcomeHasSourceRows(
	coverage AWSAccountRegionCoverageResult,
	blast AWSBlastRadiusResult,
	least AWSLeastPrivilegeResult,
	cases AWSRemediationCaseResult,
	verification AWSPostRemediationVerificationResult,
	enforcement AWSLimitedEnforcementResult,
	governance AWSGovernanceAuditReportingResult,
) bool {
	return len(coverage.Records)+len(blast.Findings)+len(least.Recommendations)+len(cases.Cases)+len(verification.Entries)+len(enforcement.Entries)+len(governance.Records) > 0
}

func awsExecutiveOutcomeFilterLimitedEnforcementRows(result AWSLimitedEnforcementResult, request AWSExecutiveOutcomeViewRequest) AWSLimitedEnforcementResult {
	severity := normalizeAWSRuntimeEventFilterToken(request.Severity)
	if severity == "" || severity == "all" {
		return result
	}
	out := result
	out.Entries = make([]AWSLimitedEnforcementEntry, 0, len(result.Entries))
	for _, entry := range result.Entries {
		if normalizeAWSRuntimeEventFilterToken(entry.Severity) == severity {
			out.Entries = append(out.Entries, entry)
		}
	}
	return out
}

func awsExecutiveOutcomeLimitedEnforcementReadyCount(entries []AWSLimitedEnforcementEntry) int {
	count := 0
	for _, entry := range entries {
		if entry.ReadyForCanary || entry.ReadyForEnforcement {
			count++
		}
	}
	return count
}

func awsExecutiveOutcomeLimitedEnforcementSeverity(entries []AWSLimitedEnforcementEntry) string {
	counts := map[string]int{}
	for _, entry := range entries {
		severity := normalizeAWSRuntimeEventFilterToken(entry.Severity)
		if severity == "" || severity == "all" {
			continue
		}
		counts[severity]++
	}
	return severityFromCounts(counts)
}

func awsExecutiveOutcomeFilteredSourceSummaries(
	coverage AWSAccountRegionCoverageResult,
	blast AWSBlastRadiusResult,
	least AWSLeastPrivilegeResult,
	cases AWSRemediationCaseResult,
	verification AWSPostRemediationVerificationResult,
	enforcement AWSLimitedEnforcementResult,
	governance AWSGovernanceAuditReportingResult,
) awsExecutiveOutcomeSourceSummaries {
	return awsExecutiveOutcomeSourceSummaries{
		Coverage:     summarizeAWSAccountRegionCoverage(coverage.Records, len(coverage.Records)),
		Blast:        summarizeAWSBlastRadius(blast.Findings, blast.Findings, nil),
		Least:        summarizeAWSLeastPrivilege(least.Recommendations, least.Recommendations, nil),
		Cases:        summarizeAWSRemediationCases(cases.Cases, cases.Cases, nil),
		Verification: summarizeAWSPostRemediationVerificationEntries(verification.Entries, verification.Entries, nil),
		Enforcement:  summarizeAWSLimitedEnforcementEntries(enforcement.Entries, enforcement.Entries, nil),
		Governance:   summarizeAWSGovernanceAuditReportRecords(governance.Records, governance.Records),
	}
}

func filterAWSExecutiveOutcomeMetrics(metrics []AWSExecutiveOutcomeMetric, request AWSExecutiveOutcomeViewRequest) ([]AWSExecutiveOutcomeMetric, map[string]string) {
	applied := map[string]string{}
	matchToken := func(value, want string) bool {
		want = strings.ToLower(strings.TrimSpace(want))
		if want == "" || want == "all" {
			return true
		}
		return strings.ToLower(strings.TrimSpace(value)) == want
	}
	matchDelimitedToken := func(value, want string) bool {
		want = strings.ToLower(strings.TrimSpace(want))
		if want == "" || want == "all" {
			return true
		}
		for _, token := range strings.Split(value, ",") {
			if strings.ToLower(strings.TrimSpace(token)) == want {
				return true
			}
		}
		return false
	}
	filtered := make([]AWSExecutiveOutcomeMetric, 0, len(metrics))
	for _, metric := range metrics {
		if !matchToken(metric.AccountID, request.AccountID) {
			continue
		}
		if !matchToken(metric.Region, request.Region) {
			continue
		}
		if !matchDelimitedToken(metric.OU, request.OU) {
			continue
		}
		if !matchToken(metric.IdentityType, request.IdentityType) {
			continue
		}
		if !matchToken(metric.Severity, request.Severity) {
			continue
		}
		if !matchToken(metric.OutcomeType, request.OutcomeType) {
			continue
		}
		if !matchToken(metric.Trend, request.Trend) {
			continue
		}
		search := strings.ToLower(strings.TrimSpace(request.Search))
		if search != "" && !strings.Contains(strings.ToLower(strings.Join([]string{metric.Title, metric.Summary, metric.Category, metric.OutcomeType, metric.NextAction}, " ")), search) {
			continue
		}
		filtered = append(filtered, metric)
	}
	setAppliedAWSExecutiveOutcomeFilter(applied, "connector_id", request.ConnectorID)
	setAppliedAWSExecutiveOutcomeFilter(applied, "fixture_state", request.FixtureState)
	setAppliedAWSExecutiveOutcomeFilter(applied, "account_id", request.AccountID)
	setAppliedAWSExecutiveOutcomeFilter(applied, "region", request.Region)
	setAppliedAWSExecutiveOutcomeFilter(applied, "ou", request.OU)
	setAppliedAWSExecutiveOutcomeFilter(applied, "identity_type", request.IdentityType)
	setAppliedAWSExecutiveOutcomeFilter(applied, "severity", request.Severity)
	setAppliedAWSExecutiveOutcomeFilter(applied, "outcome_type", request.OutcomeType)
	setAppliedAWSExecutiveOutcomeFilter(applied, "trend", request.Trend)
	setAppliedAWSExecutiveOutcomeFilter(applied, "search", request.Search)
	return filtered, applied
}

func setAppliedAWSExecutiveOutcomeFilter(applied map[string]string, key, value string) {
	value = strings.TrimSpace(value)
	if value != "" && value != "all" {
		applied[key] = value
	}
}

func summarizeAWSExecutiveOutcomeView(
	all []AWSExecutiveOutcomeMetric,
	filtered []AWSExecutiveOutcomeMetric,
	coverage AWSAccountRegionCoverageResult,
	blast AWSBlastRadiusResult,
	least AWSLeastPrivilegeResult,
	cases AWSRemediationCaseResult,
	verification AWSPostRemediationVerificationResult,
	enforcement AWSLimitedEnforcementResult,
	governance AWSGovernanceAuditReportingResult,
) AWSExecutiveOutcomeViewSummary {
	summaries := awsExecutiveOutcomeFilteredSourceSummaries(coverage, blast, least, cases, verification, enforcement, governance)
	summary := AWSExecutiveOutcomeViewSummary{
		TotalMetrics:       len(all),
		FilteredMetrics:    len(filtered),
		RiskReductionScore: 0,
		AccountCounts:      map[string]int{},
		OUCounts:           map[string]int{},
		IdentityTypeCounts: map[string]int{},
		SeverityCounts:     map[string]int{},
		OutcomeTypeCounts:  map[string]int{},
		TrendCounts:        map[string]int{},
	}
	confidenceTotal := 0.0
	for _, metric := range filtered {
		switch metric.MetricID {
		case "risk-reduction":
			summary.RiskReductionScore = metric.Value
		case "scan-coverage":
			summary.ScanCoveragePct = metric.Value
			summary.DegradedCoverageCount = summaries.Coverage.DegradedRecords + summaries.Coverage.UnreachableRecords + summaries.Coverage.PermissionDeniedRecords + summaries.Coverage.StaleRecords
		case "verified-remediation":
			summary.VerifiedRemediationCount = metric.Value
		case "enforcement-status":
			summary.EnforcementReadyCount = metric.Value
		case "remaining-exposure":
			summary.RemainingExposureCount = metric.Value
		case "governance-outcomes":
			summary.GovernanceRecordCount = metric.Value
			summary.ExceptionCount = summaries.Governance.ExceptionCount
		}
		incrementCount(summary.AccountCounts, metric.AccountID)
		incrementDelimitedCount(summary.OUCounts, metric.OU)
		incrementCount(summary.IdentityTypeCounts, metric.IdentityType)
		incrementCount(summary.SeverityCounts, metric.Severity)
		incrementCount(summary.OutcomeTypeCounts, metric.OutcomeType)
		incrementCount(summary.TrendCounts, metric.Trend)
		summary.HighestScore = maxInt(summary.HighestScore, metric.Score)
		confidenceTotal += metric.Confidence
	}
	if len(filtered) > 0 {
		summary.AverageConfidencePct = int((confidenceTotal/float64(len(filtered)))*100 + 0.5)
	}
	return summary
}

func awsExecutiveOutcomeSourceStatuses(
	request AWSExecutiveOutcomeViewRequest,
	sourceFixtureState string,
	coverage AWSAccountRegionCoverageResult,
	blast AWSBlastRadiusResult,
	least AWSLeastPrivilegeResult,
	cases AWSRemediationCaseResult,
	verification AWSPostRemediationVerificationResult,
	enforcement AWSLimitedEnforcementResult,
	governance AWSGovernanceAuditReportingResult,
) []string {
	accountRegionFilterActive := awsExecutiveOutcomeSourceScopeFilter(request.AccountID) != "" || awsExecutiveOutcomeSourceScopeFilter(request.Region) != ""
	severitySourceFilterActive := accountRegionFilterActive || strings.TrimSpace(request.Severity) != ""
	governanceFilterActive := accountRegionFilterActive || strings.TrimSpace(request.OU) != "" || strings.TrimSpace(request.Search) != ""

	return []string{
		awsExecutiveOutcomeCoverageStatus(coverage, accountRegionFilterActive, sourceFixtureState),
		awsExecutiveOutcomeFilteredEmptyStatus(blast.Status, len(blast.Findings), severitySourceFilterActive, sourceFixtureState, blast.FailureReasons, len(blast.Diagnostics)),
		awsExecutiveOutcomeFilteredEmptyStatus(least.Status, len(least.Recommendations), severitySourceFilterActive, sourceFixtureState, least.FailureReasons, len(least.Diagnostics)),
		awsExecutiveOutcomeFilteredEmptyStatus(cases.Status, len(cases.Cases), severitySourceFilterActive, sourceFixtureState, cases.FailureReasons, len(cases.Diagnostics)),
		awsExecutiveOutcomeFilteredEmptyStatus(verification.Status, len(verification.Entries), severitySourceFilterActive, sourceFixtureState, verification.FailureReasons, len(verification.Diagnostics)),
		awsExecutiveOutcomeFilteredEmptyStatus(enforcement.Status, len(enforcement.Entries), accountRegionFilterActive, sourceFixtureState, enforcement.FailureReasons, len(enforcement.Diagnostics)),
		awsExecutiveOutcomeFilteredEmptyStatus(governance.Status, len(governance.Records), governanceFilterActive, sourceFixtureState, governance.FailureReasons, len(governance.Diagnostics)),
	}
}

func awsExecutiveOutcomeCoverageStatus(coverage AWSAccountRegionCoverageResult, filterActive bool, sourceFixtureState string) string {
	if !filterActive {
		return coverage.Status
	}
	fixtureState := strings.ToLower(strings.TrimSpace(sourceFixtureState))
	if fixtureState != "" && fixtureState != "success" {
		return coverage.Status
	}
	if len(coverage.Records) == 0 {
		return awsExecutiveOutcomeFilteredEmptyStatus(coverage.Status, 0, true, sourceFixtureState, coverage.FailureReasons, len(coverage.Diagnostics))
	}
	summary := summarizeAWSAccountRegionCoverage(coverage.Records, len(coverage.Records))
	switch {
	case summary.PermissionDeniedRecords > 0:
		return awsPlatformDependencyStatusBlocked
	case summary.DegradedRecords+summary.UnreachableRecords+summary.SuspendedRecords+summary.StaleRecords > 0:
		return awsPlatformDependencyStatusDegraded
	default:
		return awsPlatformDependencyStatusReady
	}
}

func awsExecutiveOutcomeFilteredEmptyStatus(status string, rowCount int, filterActive bool, sourceFixtureState string, failureReasons []string, diagnosticCount int) string {
	if strings.ToLower(strings.TrimSpace(status)) != awsPlatformDependencyStatusDegraded {
		return status
	}
	if rowCount != 0 || !filterActive || len(failureReasons) != 0 || diagnosticCount != 0 {
		return status
	}
	fixtureState := strings.ToLower(strings.TrimSpace(sourceFixtureState))
	if fixtureState != "" && fixtureState != "success" {
		return status
	}
	return awsPlatformDependencyStatusReady
}

func summarizeAWSExecutiveOutcomeViewStatus(metrics []AWSExecutiveOutcomeMetric, statuses ...string) (string, float64) {
	blocked := false
	degraded := false
	for _, status := range statuses {
		switch strings.ToLower(strings.TrimSpace(status)) {
		case "blocked", "permission_denied":
			blocked = true
		case "degraded", "partial", "partial_failure":
			degraded = true
		}
	}
	if blocked {
		return "blocked", 0.55
	}
	if degraded {
		return "degraded", 0.74
	}
	if len(metrics) == 0 {
		return "ready", 0.8
	}
	return "ready", 0.9
}

func awsExecutiveOutcomeViewCaveats() []string {
	return []string{
		"Executive outcomes are metadata-only rollups over existing AWS evidence; they do not prove live mutation or collect customer payloads.",
		"Coverage gaps, permission-denied sources, and stale collectors reduce confidence instead of being counted as successful outcomes.",
	}
}

func awsExecutiveOutcomeViewRemediationHints() []string {
	return []string{
		"Use coverage gaps and exception rows to explain why an executive outcome is degraded.",
		"Treat enforcement readiness as advisory until canary, rollback, and governance audit records are all present.",
	}
}

func awsExecutiveOutcomeCoverageGaps(
	coverage []AWSCoveragePlanCoverageGap,
	blast []AWSBlastRadiusCoverageGap,
	least []AWSLeastPrivilegeCoverageGap,
	cases []AWSRemediationCaseCoverageGap,
	verification []AWSPostRemediationVerificationCoverageGap,
	enforcement []AWSLimitedEnforcementCoverageGap,
	governance []AWSGovernanceAuditReportingCoverageGap,
) []AWSExecutiveOutcomeCoverageGap {
	out := []AWSExecutiveOutcomeCoverageGap{}
	for _, gap := range coverage {
		out = append(out, AWSExecutiveOutcomeCoverageGap(gap))
	}
	for _, gap := range blast {
		out = append(out, AWSExecutiveOutcomeCoverageGap(gap))
	}
	for _, group := range [][]AWSLeastPrivilegeCoverageGap{least, cases, verification, enforcement, governance} {
		for _, gap := range group {
			out = append(out, AWSExecutiveOutcomeCoverageGap(gap))
		}
	}
	seen := map[string]bool{}
	filtered := []AWSExecutiveOutcomeCoverageGap{}
	for _, gap := range out {
		key := strings.Join([]string{gap.Capability, gap.Status, gap.Reason, gap.Remediation}, "\x00")
		if seen[key] {
			continue
		}
		seen[key] = true
		filtered = append(filtered, gap)
	}
	return filtered
}

func awsExecutiveOutcomeDiagnostics(
	coverage []AWSCoveragePlanDiagnostic,
	blast []AWSBlastRadiusDiagnostic,
	least []AWSLeastPrivilegeDiagnostic,
	cases []AWSRemediationCaseDiagnostic,
	verification []AWSPostRemediationVerificationDiagnostic,
	enforcement []AWSLimitedEnforcementDiagnostic,
	governance []AWSGovernanceAuditReportingDiagnostic,
) []AWSExecutiveOutcomeDiagnostic {
	out := []AWSExecutiveOutcomeDiagnostic{}
	for _, diagnostic := range coverage {
		out = append(out, AWSExecutiveOutcomeDiagnostic{
			Collector:   firstNonEmptyAWSValue(diagnostic.Collector, diagnostic.Source),
			SourceID:    diagnostic.Scope,
			Code:        diagnostic.Code,
			Message:     diagnostic.Message,
			Remediation: diagnostic.Remediation,
			Retryable:   diagnostic.Retryable,
		})
	}
	for _, diagnostic := range blast {
		out = append(out, AWSExecutiveOutcomeDiagnostic(diagnostic))
	}
	for _, group := range [][]AWSLeastPrivilegeDiagnostic{least, cases, verification, enforcement, governance} {
		for _, diagnostic := range group {
			out = append(out, AWSExecutiveOutcomeDiagnostic(diagnostic))
		}
	}
	seen := map[string]bool{}
	filtered := []AWSExecutiveOutcomeDiagnostic{}
	for _, diagnostic := range out {
		key := strings.Join([]string{diagnostic.Collector, diagnostic.SourceID, diagnostic.Code, diagnostic.Message}, "\x00")
		if seen[key] {
			continue
		}
		seen[key] = true
		filtered = append(filtered, diagnostic)
	}
	return filtered
}

func percent(part, total int) int {
	if total <= 0 {
		return 0
	}
	return int((float64(part)/float64(total))*100 + 0.5)
}

func trendFromDelta(delta int) string {
	switch {
	case delta > 0:
		return "improving"
	case delta < 0:
		return "needs_attention"
	default:
		return "stable"
	}
}

func severityFromCounts(groups ...map[string]int) string {
	total := 0
	for _, group := range groups {
		for _, count := range group {
			total += count
		}
		if group["critical"] > 0 {
			return "critical"
		}
	}
	for _, group := range groups {
		if group["high"] > 0 {
			return "high"
		}
	}
	for _, group := range groups {
		if group["medium"] > 0 {
			return "medium"
		}
	}
	for _, group := range groups {
		if group["low"] > 0 {
			return "low"
		}
	}
	if total == 0 {
		return ""
	}
	return "low"
}

func severityFromFailureCount(count int, total int) string {
	if count > 0 {
		return "high"
	}
	if total <= 0 {
		return ""
	}
	return "low"
}

func incrementCount(counts map[string]int, key string) {
	key = strings.TrimSpace(key)
	if key == "" {
		return
	}
	counts[key]++
}

func incrementDelimitedCount(counts map[string]int, keys string) {
	for _, key := range strings.Split(keys, ",") {
		incrementCount(counts, key)
	}
}

func awsExecutiveOutcomeMetricOU(records []AWSGovernanceAuditReportRecord) string {
	values := []string{}
	seen := map[string]bool{}
	for _, record := range records {
		for _, value := range strings.Split(record.OU, ",") {
			value = strings.TrimSpace(value)
			if value == "" || seen[value] {
				continue
			}
			seen[value] = true
			values = append(values, value)
		}
	}
	sort.Strings(values)
	return strings.Join(values, ",")
}

func clampInt(value, min, max int) int {
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}

func maxInt(values ...int) int {
	max := 0
	for _, value := range values {
		if value > max {
			max = value
		}
	}
	return max
}

func averageFloat64(values ...float64) float64 {
	total := 0.0
	count := 0
	for _, value := range values {
		if value <= 0 {
			continue
		}
		total += value
		count++
	}
	if count == 0 {
		return 0
	}
	return total / float64(count)
}
