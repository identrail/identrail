package api

import (
	"context"
	"sort"
	"strings"
	"time"
)

const (
	awsPlatformObservabilityCurrentIssue = 1556
	awsPlatformObservabilityVersion      = "aws-platform-observability-v1"
	awsPlatformObservabilityBoundary     = "metadata_only_platform_observability_no_secret_values_no_customer_payloads"
)

// AWSPlatformObservabilityRequest scopes the read-only AWS platform health
// dashboard to one connector and bounded operator filters.
type AWSPlatformObservabilityRequest struct {
	ConnectorID  string `json:"connector_id,omitempty"`
	FixtureState string `json:"fixture_state,omitempty"`
	AccountID    string `json:"account_id,omitempty"`
	Region       string `json:"region,omitempty"`
	Service      string `json:"service,omitempty"`
	Component    string `json:"component,omitempty"`
	Status       string `json:"status,omitempty"`
	Search       string `json:"search,omitempty"`
}

type AWSPlatformObservabilityMetric struct {
	MetricID         string    `json:"metric_id"`
	Component        string    `json:"component"`
	Signal           string    `json:"signal"`
	Title            string    `json:"title"`
	Summary          string    `json:"summary"`
	Value            int       `json:"value"`
	Unit             string    `json:"unit"`
	Status           string    `json:"status"`
	Severity         string    `json:"severity,omitempty"`
	Confidence       float64   `json:"confidence"`
	AccountID        string    `json:"account_id,omitempty"`
	Region           string    `json:"region,omitempty"`
	Service          string    `json:"service,omitempty"`
	TraceID          string    `json:"trace_id"`
	EvidenceRef      string    `json:"evidence_ref,omitempty"`
	EvidenceLinks    []string  `json:"evidence_links"`
	EvidenceBoundary string    `json:"evidence_boundary"`
	NextAction       string    `json:"next_action"`
	ObservedAt       time.Time `json:"observed_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

type AWSPlatformObservabilityTrace struct {
	TraceID          string    `json:"trace_id"`
	ParentTraceID    string    `json:"parent_trace_id,omitempty"`
	SpanName         string    `json:"span_name"`
	Component        string    `json:"component"`
	AccountID        string    `json:"account_id,omitempty"`
	Region           string    `json:"region,omitempty"`
	Service          string    `json:"service,omitempty"`
	Status           string    `json:"status"`
	DurationMs       int       `json:"duration_ms,omitempty"`
	QueueLagMs       int       `json:"queue_lag_ms,omitempty"`
	RuntimeLagMs     int       `json:"runtime_lag_ms,omitempty"`
	RetryCount       int       `json:"retry_count,omitempty"`
	Throttled        bool      `json:"throttled"`
	EvidenceRef      string    `json:"evidence_ref,omitempty"`
	EvidenceLinks    []string  `json:"evidence_links"`
	EvidenceBoundary string    `json:"evidence_boundary"`
	NextAction       string    `json:"next_action"`
	StartedAt        time.Time `json:"started_at,omitempty"`
	EndedAt          time.Time `json:"ended_at,omitempty"`
}

type AWSPlatformObservabilityAlert struct {
	AlertID          string    `json:"alert_id"`
	Severity         string    `json:"severity"`
	Component        string    `json:"component"`
	Status           string    `json:"status"`
	Title            string    `json:"title"`
	Summary          string    `json:"summary"`
	EvidenceRef      string    `json:"evidence_ref,omitempty"`
	EvidenceBoundary string    `json:"evidence_boundary"`
	NextAction       string    `json:"next_action"`
	TriggeredAt      time.Time `json:"triggered_at"`
}

type AWSPlatformObservabilityCoverageGap struct {
	Capability  string `json:"capability"`
	Status      string `json:"status"`
	Reason      string `json:"reason"`
	Remediation string `json:"remediation,omitempty"`
}

type AWSPlatformObservabilityDiagnostic struct {
	Collector   string `json:"collector"`
	SourceID    string `json:"source_id,omitempty"`
	Code        string `json:"code"`
	Message     string `json:"message"`
	Remediation string `json:"remediation,omitempty"`
	Retryable   bool   `json:"retryable"`
}

type AWSPlatformObservabilitySummary struct {
	TotalMetrics             int            `json:"total_metrics"`
	FilteredMetrics          int            `json:"filtered_metrics"`
	TotalTraces              int            `json:"total_traces"`
	FilteredTraces           int            `json:"filtered_traces"`
	ReadySignals             int            `json:"ready_signals"`
	DegradedSignals          int            `json:"degraded_signals"`
	BlockedSignals           int            `json:"blocked_signals"`
	AlertCount               int            `json:"alert_count"`
	CriticalAlertCount       int            `json:"critical_alert_count"`
	ScanThroughputPerHour    int            `json:"scan_throughput_per_hour"`
	QueueLagP95Ms            int            `json:"queue_lag_p95_ms"`
	RuntimeLagP95Ms          int            `json:"runtime_lag_p95_ms"`
	CollectorFailureCount    int            `json:"collector_failure_count"`
	ThrottledTargetCount     int            `json:"throttled_target_count"`
	RemediationPendingCount  int            `json:"remediation_pending_count"`
	VerificationFailedCount  int            `json:"verification_failed_count"`
	GovernanceExceptionCount int            `json:"governance_exception_count"`
	AccountCounts            map[string]int `json:"account_counts"`
	RegionCounts             map[string]int `json:"region_counts"`
	ServiceCounts            map[string]int `json:"service_counts"`
	ComponentCounts          map[string]int `json:"component_counts"`
	StatusCounts             map[string]int `json:"status_counts"`
}

type AWSPlatformObservabilityResult struct {
	TenantID           string                                `json:"tenant_id"`
	WorkspaceID        string                                `json:"workspace_id"`
	ProjectID          string                                `json:"project_id"`
	ConnectorID        string                                `json:"connector_id,omitempty"`
	AccountID          string                                `json:"account_id,omitempty"`
	Region             string                                `json:"region,omitempty"`
	ParentIssueNumber  int                                   `json:"parent_issue_number"`
	ParentIssueRef     string                                `json:"parent_issue_ref"`
	CurrentIssueNumber int                                   `json:"current_issue_number"`
	CurrentIssueRef    string                                `json:"current_issue_ref"`
	Version            string                                `json:"version"`
	Status             string                                `json:"status"`
	FixtureState       string                                `json:"fixture_state,omitempty"`
	Confidence         float64                               `json:"confidence"`
	CalculationVersion string                                `json:"calculation_version"`
	AppliedFilters     map[string]string                     `json:"applied_filters"`
	Summary            AWSPlatformObservabilitySummary       `json:"summary"`
	Metrics            []AWSPlatformObservabilityMetric      `json:"metrics"`
	Traces             []AWSPlatformObservabilityTrace       `json:"traces"`
	Alerts             []AWSPlatformObservabilityAlert       `json:"alerts"`
	Caveats            []string                              `json:"caveats"`
	FailureReasons     []string                              `json:"failure_reasons"`
	RemediationHints   []string                              `json:"remediation_hints"`
	EvidenceLinks      []string                              `json:"evidence_links"`
	CoverageGaps       []AWSPlatformObservabilityCoverageGap `json:"coverage_gaps"`
	Diagnostics        []AWSPlatformObservabilityDiagnostic  `json:"diagnostics"`
	GeneratedAt        time.Time                             `json:"generated_at"`
	UpdatedAt          time.Time                             `json:"updated_at"`
}

type awsPlatformObservabilitySources struct {
	Coverage     AWSAccountRegionCoverageResult
	FanOut       AWSFanOutExecutionResult
	Runtime      AWSRuntimeEventResult
	Cases        AWSRemediationCaseResult
	Verification AWSPostRemediationVerificationResult
	Enforcement  AWSLimitedEnforcementResult
	Governance   AWSGovernanceAuditReportingResult
}

func (s *Service) GetAWSPlatformObservability(ctx context.Context, workspaceID string, projectID string, request AWSPlatformObservabilityRequest) (AWSPlatformObservabilityResult, error) {
	if !validAWSPlatformObservabilityFilter(request) {
		return AWSPlatformObservabilityResult{}, ErrInvalidAWSConnectionRequest
	}
	project, scope, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return AWSPlatformObservabilityResult{}, err
	}
	connection, hasConnection, err := s.awsBaselineConnection(ctx, project, strings.TrimSpace(request.ConnectorID))
	if err != nil {
		return AWSPlatformObservabilityResult{}, err
	}
	now := s.Now().UTC()
	fixtureState := normalizeAWSGovernanceAuditReportingFixtureState(request.FixtureState, connection, hasConnection)
	if fixtureState == "" {
		return AWSPlatformObservabilityResult{}, ErrInvalidAWSConnectionRequest
	}
	sourceFixtureState := fixtureState
	if strings.TrimSpace(request.FixtureState) == "" && hasConnection && connection.Connected {
		sourceFixtureState = ""
	}
	connectorID := firstNonEmptyAWSValue(connection.ConnectorID, strings.TrimSpace(request.ConnectorID))
	sourceAccountID := awsExecutiveOutcomeSourceScopeFilter(request.AccountID)
	sourceRegion := awsExecutiveOutcomeSourceScopeFilter(request.Region)
	sourceService := awsPlatformObservabilitySourceServiceFilter(request.Service)
	accountID := awsPlatformObservabilityRequestedScopeValue(request.AccountID)
	region := awsPlatformObservabilityRequestedScopeValue(request.Region)

	coverage, err := s.GetAWSAccountRegionCoverage(ctx, workspaceID, projectID, AWSAccountRegionCoverageRequest{
		ConnectorID:  connectorID,
		FixtureState: sourceFixtureState,
		Account:      sourceAccountID,
		Region:       sourceRegion,
		Service:      sourceService,
	})
	if err != nil {
		return AWSPlatformObservabilityResult{}, err
	}
	fanout, err := s.GetAWSFanOutExecution(ctx, workspaceID, projectID, AWSFanOutExecutionRequest{
		ConnectorID:  connectorID,
		FixtureState: sourceFixtureState,
		Account:      sourceAccountID,
		Region:       sourceRegion,
		Service:      sourceService,
	})
	if err != nil {
		return AWSPlatformObservabilityResult{}, err
	}
	runtime, err := s.GetAWSRuntimeEvents(ctx, workspaceID, projectID, AWSRuntimeEventRequest{
		ConnectorID:  connectorID,
		FixtureState: sourceFixtureState,
		AccountID:    sourceAccountID,
		Region:       sourceRegion,
	})
	if err != nil {
		return AWSPlatformObservabilityResult{}, err
	}
	cases, err := s.GetAWSRemediationCases(ctx, workspaceID, projectID, AWSRemediationCaseRequest{
		ConnectorID:  connectorID,
		FixtureState: sourceFixtureState,
		AccountID:    sourceAccountID,
		Region:       sourceRegion,
	})
	if err != nil {
		return AWSPlatformObservabilityResult{}, err
	}
	verification, err := s.GetAWSPostRemediationVerification(ctx, workspaceID, projectID, AWSPostRemediationVerificationRequest{
		ConnectorID:  connectorID,
		FixtureState: sourceFixtureState,
		AccountID:    sourceAccountID,
		Region:       sourceRegion,
	})
	if err != nil {
		return AWSPlatformObservabilityResult{}, err
	}
	enforcement, err := s.GetAWSLimitedEnforcement(ctx, workspaceID, projectID, AWSLimitedEnforcementRequest{
		ConnectorID:  connectorID,
		FixtureState: sourceFixtureState,
		AccountID:    sourceAccountID,
		Region:       sourceRegion,
	})
	if err != nil {
		return AWSPlatformObservabilityResult{}, err
	}
	governance, err := s.GetAWSGovernanceAuditReporting(ctx, workspaceID, projectID, AWSGovernanceAuditReportingRequest{
		ConnectorID:  connectorID,
		FixtureState: sourceFixtureState,
		AccountID:    sourceAccountID,
		Region:       sourceRegion,
	})
	if err != nil {
		return AWSPlatformObservabilityResult{}, err
	}

	sources := awsPlatformObservabilitySources{
		Coverage:     coverage,
		FanOut:       fanout,
		Runtime:      runtime,
		Cases:        cases,
		Verification: verification,
		Enforcement:  enforcement,
		Governance:   governance,
	}
	metrics := awsPlatformObservabilityMetrics(sources, request, accountID, region, sourceService, now)
	traces := awsPlatformObservabilityTraces(sources, now)
	filteredMetrics, filteredTraces, applied := filterAWSPlatformObservability(metrics, traces, request)
	includeTraceSignals := awsPlatformObservabilityHasResultFilter(request)
	alerts := awsPlatformObservabilityAlerts(filteredMetrics, filteredTraces, includeTraceSignals, now)
	summary := summarizeAWSPlatformObservability(metrics, filteredMetrics, traces, filteredTraces, alerts)
	status, confidence := summarizeAWSPlatformObservabilityStatus(filteredMetrics, filteredTraces, includeTraceSignals)
	return AWSPlatformObservabilityResult{
		TenantID:           scope.TenantID,
		WorkspaceID:        project.WorkspaceID,
		ProjectID:          project.ProjectID,
		ConnectorID:        connectorID,
		AccountID:          accountID,
		Region:             region,
		ParentIssueNumber:  awsPlatformDependencyParentIssue,
		ParentIssueRef:     awsIssueRef(awsPlatformDependencyParentIssue),
		CurrentIssueNumber: awsPlatformObservabilityCurrentIssue,
		CurrentIssueRef:    awsIssueRef(awsPlatformObservabilityCurrentIssue),
		Version:            awsPlatformObservabilityVersion,
		Status:             status,
		FixtureState:       sourceFixtureState,
		Confidence:         confidence,
		CalculationVersion: awsPlatformObservabilityVersion,
		AppliedFilters:     applied,
		Summary:            summary,
		Metrics:            filteredMetrics,
		Traces:             filteredTraces,
		Alerts:             alerts,
		Caveats:            awsPlatformObservabilityCaveats(),
		FailureReasons:     awsPlatformObservabilityFailureReasons(sources),
		RemediationHints:   awsPlatformObservabilityRemediationHints(sources),
		EvidenceLinks: dedupeStrings([]string{
			awsIssueURL(awsPlatformDependencyParentIssue),
			awsIssueURL(awsPlatformObservabilityCurrentIssue),
			awsIssueURL(awsFanOutExecutionCurrentIssue),
			awsIssueURL(awsRuntimeEventsCurrentIssue),
			awsIssueURL(awsPostRemediationVerificationCurrentIssue),
			"/docs/aws-platform-observability",
			"/docs/observability",
			awsBaselineProjectEvidenceURL(scope, project),
		}),
		CoverageGaps: awsPlatformObservabilityCoverageGaps(sources),
		Diagnostics:  awsPlatformObservabilityDiagnostics(sources),
		GeneratedAt:  now,
		UpdatedAt:    now,
	}, nil
}

func validAWSPlatformObservabilityFilter(request AWSPlatformObservabilityRequest) bool {
	return validAWSPlatformObservabilityToken(request.Component, []string{"collector", "queue", "runtime", "remediation", "verification", "enforcement", "governance"}) &&
		validAWSPlatformObservabilityToken(request.Status, []string{awsPlatformDependencyStatusReady, awsPlatformDependencyStatusDegraded, awsPlatformDependencyStatusBlocked})
}

func validAWSPlatformObservabilityToken(value string, allowed []string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" || value == "all" {
		return true
	}
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}

func awsPlatformObservabilityMetrics(sources awsPlatformObservabilitySources, request AWSPlatformObservabilityRequest, accountID, region, service string, now time.Time) []AWSPlatformObservabilityMetric {
	if service == "" {
		service = strings.TrimSpace(request.Service)
	}
	if service == "" {
		service = "all"
	}
	aggregateService := "all"
	sourceScoped := awsPlatformObservabilityHasSourceScopeFilter(request)
	coverageSummary := awsPlatformObservabilityCoverageSummary(sources.Coverage)
	fanOutSummary := awsPlatformObservabilityFanOutSummary(sources.FanOut)
	coverageStatus := awsPlatformObservabilityCoverageStatus(coverageSummary, sources.Coverage.Status, sourceScoped)
	fanOutStatus := awsPlatformObservabilityFanOutSummaryStatus(fanOutSummary, sources.FanOut.Status, sourceScoped)
	collectorFailures := coverageSummary.DegradedRecords + coverageSummary.UnreachableRecords + coverageSummary.StaleRecords + coverageSummary.PermissionDeniedRecords
	if !sourceScoped {
		collectorFailures += len(sources.Coverage.Diagnostics)
	}
	queueLag := awsPlatformObservabilityQueueLag(fanOutSummary)
	runtimeLag := awsPlatformObservabilityRuntimeLag(sources.Runtime.Records)
	remediationPending := sources.Cases.Summary.ApprovalRequiredCount + sources.Verification.Summary.PendingCount
	verificationFailures := sources.Verification.Summary.FailedCount + sources.Verification.Summary.RollbackPlannedCount + sources.Verification.Summary.BlockedCount
	enforcementBlocked := sources.Enforcement.Summary.KillSwitchEngagedCount + sources.Enforcement.Summary.FailedGateCount
	return []AWSPlatformObservabilityMetric{
		{
			MetricID:         "scan-throughput",
			Component:        "collector",
			Signal:           "scan_throughput",
			Title:            "Scan throughput",
			Summary:          "Account, region, and service targets completed by the bounded fan-out and coverage collectors.",
			Value:            maxInt(fanOutSummary.CoveredTargets, coverageSummary.CoveredRecords),
			Unit:             "targets_per_hour",
			Status:           awsPlatformObservabilitySourceStatus(coverageStatus, fanOutStatus),
			Severity:         awsPlatformObservabilityMetricSeverity(coverageStatus, fanOutStatus),
			Confidence:       averageFloat64(sources.Coverage.Confidence, sources.FanOut.Confidence),
			AccountID:        accountID,
			Region:           region,
			Service:          service,
			TraceID:          awsPlatformObservabilityTraceID("metric", "collector", accountID, region, service, "scan-throughput"),
			EvidenceRef:      "aws-platform-observability://scan-throughput",
			EvidenceLinks:    dedupeStrings(append(append([]string{}, sources.Coverage.EvidenceLinks...), sources.FanOut.EvidenceLinks...)),
			EvidenceBoundary: awsPlatformObservabilityBoundary,
			NextAction:       "Use coverage and fan-out traces to confirm every expected account, region, and service is advancing.",
			ObservedAt:       now,
			UpdatedAt:        now,
		},
		{
			MetricID:         "queue-lag",
			Component:        "queue",
			Signal:           "queue_lag",
			Title:            "Queue lag",
			Summary:          "Estimated backlog lag from queued and in-progress fan-out targets.",
			Value:            queueLag,
			Unit:             "milliseconds",
			Status:           awsPlatformObservabilityLagStatus(queueLag, fanOutStatus),
			Severity:         awsPlatformObservabilityLagSeverity(queueLag, fanOutStatus),
			Confidence:       sources.FanOut.Confidence,
			AccountID:        accountID,
			Region:           region,
			Service:          service,
			TraceID:          awsPlatformObservabilityTraceID("metric", "queue", accountID, region, service, "queue-lag"),
			EvidenceRef:      "aws-platform-observability://queue-lag",
			EvidenceLinks:    sources.FanOut.EvidenceLinks,
			EvidenceBoundary: awsPlatformObservabilityBoundary,
			NextAction:       "Review queued and retryable targets before increasing scan concurrency.",
			ObservedAt:       now,
			UpdatedAt:        now,
		},
		{
			MetricID:         "throttling",
			Component:        "collector",
			Signal:           "throttling",
			Title:            "Throttling",
			Summary:          "Fan-out targets currently throttled or waiting for bounded retry.",
			Value:            fanOutSummary.ThrottledTargets,
			Unit:             "targets",
			Status:           awsPlatformObservabilityCountStatus(fanOutSummary.ThrottledTargets, fanOutStatus),
			Severity:         awsPlatformObservabilityCountSeverity(fanOutSummary.ThrottledTargets, fanOutStatus),
			Confidence:       sources.FanOut.Confidence,
			AccountID:        accountID,
			Region:           region,
			Service:          service,
			TraceID:          awsPlatformObservabilityTraceID("metric", "collector", accountID, region, service, "throttling"),
			EvidenceRef:      "aws-platform-observability://throttling",
			EvidenceLinks:    sources.FanOut.EvidenceLinks,
			EvidenceBoundary: awsPlatformObservabilityBoundary,
			NextAction:       "Let bounded backoff complete or reduce concurrency for throttled services.",
			ObservedAt:       now,
			UpdatedAt:        now,
		},
		{
			MetricID:         "collector-failures",
			Component:        "collector",
			Signal:           "collector_failures",
			Title:            "Collector failures",
			Summary:          "Explicit degraded, unreachable, stale, permission-denied, or diagnostic collector states.",
			Value:            collectorFailures,
			Unit:             "signals",
			Status:           awsPlatformObservabilityCountStatus(collectorFailures, coverageStatus),
			Severity:         awsPlatformObservabilityCountSeverity(collectorFailures, coverageStatus),
			Confidence:       sources.Coverage.Confidence,
			AccountID:        accountID,
			Region:           region,
			Service:          service,
			TraceID:          awsPlatformObservabilityTraceID("metric", "collector", accountID, region, service, "collector-failures"),
			EvidenceRef:      "aws-platform-observability://collector-failures",
			EvidenceLinks:    sources.Coverage.EvidenceLinks,
			EvidenceBoundary: awsPlatformObservabilityBoundary,
			NextAction:       "Inspect diagnostics and coverage gaps before treating the scan as complete.",
			ObservedAt:       now,
			UpdatedAt:        now,
		},
		{
			MetricID:         "runtime-lag",
			Component:        "runtime",
			Signal:           "runtime_lag",
			Title:            "Runtime lag",
			Summary:          "P95 delay between runtime observation and collection for CloudTrail, last-used, and Access Analyzer signals.",
			Value:            runtimeLag,
			Unit:             "milliseconds",
			Status:           awsPlatformObservabilityLagStatus(runtimeLag, sources.Runtime.Status),
			Severity:         awsPlatformObservabilityLagSeverity(runtimeLag, sources.Runtime.Status),
			Confidence:       sources.Runtime.Confidence,
			AccountID:        accountID,
			Region:           region,
			Service:          aggregateService,
			TraceID:          awsPlatformObservabilityTraceID("metric", "runtime", accountID, region, aggregateService, "runtime-lag"),
			EvidenceRef:      "aws-platform-observability://runtime-lag",
			EvidenceLinks:    sources.Runtime.EvidenceLinks,
			EvidenceBoundary: awsPlatformObservabilityBoundary,
			NextAction:       "Review runtime diagnostics when lag exceeds the ingestion window or live evidence is capability-gated.",
			ObservedAt:       now,
			UpdatedAt:        now,
		},
		{
			MetricID:         "remediation-state",
			Component:        "remediation",
			Signal:           "remediation_state",
			Title:            "Remediation state",
			Summary:          "Remediation cases awaiting ownership, approval, verification, or rollback review.",
			Value:            remediationPending,
			Unit:             "items",
			Status:           awsPlatformObservabilitySourceStatus(sources.Cases.Status, sources.Verification.Status),
			Severity:         awsPlatformObservabilityMetricSeverity(sources.Cases.Status, sources.Verification.Status),
			Confidence:       averageFloat64(sources.Cases.Confidence, sources.Verification.Confidence),
			AccountID:        accountID,
			Region:           region,
			Service:          aggregateService,
			TraceID:          awsPlatformObservabilityTraceID("metric", "remediation", accountID, region, aggregateService, "remediation-state"),
			EvidenceRef:      "aws-platform-observability://remediation-state",
			EvidenceLinks:    dedupeStrings(append(append([]string{}, sources.Cases.EvidenceLinks...), sources.Verification.EvidenceLinks...)),
			EvidenceBoundary: awsPlatformObservabilityBoundary,
			NextAction:       "Assign pending remediation cases and keep verification evidence attached before closure.",
			ObservedAt:       now,
			UpdatedAt:        now,
		},
		{
			MetricID:         "verification-outcomes",
			Component:        "verification",
			Signal:           "verification_outcomes",
			Title:            "Verification outcomes",
			Summary:          "Failed, blocked, and rollback-planned verification outcomes after remediation projections.",
			Value:            verificationFailures,
			Unit:             "outcomes",
			Status:           awsPlatformObservabilityCountStatus(verificationFailures, sources.Verification.Status),
			Severity:         awsPlatformObservabilityCountSeverity(verificationFailures, sources.Verification.Status),
			Confidence:       sources.Verification.Confidence,
			AccountID:        accountID,
			Region:           region,
			Service:          aggregateService,
			TraceID:          awsPlatformObservabilityTraceID("metric", "verification", accountID, region, aggregateService, "verification-outcomes"),
			EvidenceRef:      "aws-platform-observability://verification-outcomes",
			EvidenceLinks:    sources.Verification.EvidenceLinks,
			EvidenceBoundary: awsPlatformObservabilityBoundary,
			NextAction:       "Review failed checks and rollback plans before reporting remediation success.",
			ObservedAt:       now,
			UpdatedAt:        now,
		},
		{
			MetricID:         "enforcement-health",
			Component:        "enforcement",
			Signal:           "enforcement_health",
			Title:            "Enforcement health",
			Summary:          "Limited-enforcement kill switch, failed gates, and ready-for-enforcement states.",
			Value:            enforcementBlocked,
			Unit:             "gates",
			Status:           awsPlatformObservabilityCountStatus(enforcementBlocked, sources.Enforcement.Status),
			Severity:         awsPlatformObservabilityCountSeverity(enforcementBlocked, sources.Enforcement.Status),
			Confidence:       sources.Enforcement.Confidence,
			AccountID:        accountID,
			Region:           region,
			Service:          aggregateService,
			TraceID:          awsPlatformObservabilityTraceID("metric", "enforcement", accountID, region, aggregateService, "enforcement-health"),
			EvidenceRef:      "aws-platform-observability://enforcement-health",
			EvidenceLinks:    sources.Enforcement.EvidenceLinks,
			EvidenceBoundary: awsPlatformObservabilityBoundary,
			NextAction:       "Keep enforcement in advisory or canary mode until failed gates and kill switches are clear.",
			ObservedAt:       now,
			UpdatedAt:        now,
		},
		{
			MetricID:         "governance-outcomes",
			Component:        "governance",
			Signal:           "governance_outcomes",
			Title:            "Governance outcomes",
			Summary:          "Export-safe decisions, approvals, remediations, enforcement outcomes, and exceptions.",
			Value:            sources.Governance.Summary.ExceptionCount,
			Unit:             "exceptions",
			Status:           awsPlatformObservabilitySourceStatus(sources.Governance.Status),
			Severity:         awsPlatformObservabilityMetricSeverity(sources.Governance.Status),
			Confidence:       sources.Governance.Confidence,
			AccountID:        accountID,
			Region:           region,
			Service:          aggregateService,
			TraceID:          awsPlatformObservabilityTraceID("metric", "governance", accountID, region, aggregateService, "governance-outcomes"),
			EvidenceRef:      "aws-platform-observability://governance-outcomes",
			EvidenceLinks:    sources.Governance.EvidenceLinks,
			EvidenceBoundary: awsPlatformObservabilityBoundary,
			NextAction:       "Export governance rows and investigate exceptions before leadership reporting.",
			ObservedAt:       now,
			UpdatedAt:        now,
		},
	}
}

func awsPlatformObservabilityTraces(sources awsPlatformObservabilitySources, now time.Time) []AWSPlatformObservabilityTrace {
	traces := []AWSPlatformObservabilityTrace{}
	for _, target := range sources.FanOut.Targets {
		status := awsPlatformObservabilityFanOutStatus(target)
		traceID := awsPlatformObservabilityTraceID("fanout", "collector", target.AccountID, target.Region, target.Service, target.Key)
		traces = append(traces, AWSPlatformObservabilityTrace{
			TraceID:          traceID,
			SpanName:         "aws.collector.fanout",
			Component:        "collector",
			AccountID:        target.AccountID,
			Region:           target.Region,
			Service:          target.Service,
			Status:           status,
			DurationMs:       maxInt(target.Attempts, 1) * 1000,
			QueueLagMs:       awsPlatformObservabilityTargetQueueLag(target),
			RetryCount:       target.Attempts,
			Throttled:        target.Throttled,
			EvidenceRef:      target.EvidenceRef,
			EvidenceLinks:    sources.FanOut.EvidenceLinks,
			EvidenceBoundary: awsPlatformObservabilityBoundary,
			NextAction:       target.NextAction,
			StartedAt:        firstNonZeroTime(target.ObservedAt, now),
			EndedAt:          now,
		})
	}
	for _, record := range sources.Runtime.Records {
		traces = append(traces, AWSPlatformObservabilityTrace{
			TraceID:          awsPlatformObservabilityTraceID("runtime", "runtime", record.AccountID, record.Region, record.EventSource, record.EventID),
			SpanName:         "aws.runtime.evidence",
			Component:        "runtime",
			AccountID:        record.AccountID,
			Region:           record.Region,
			Service:          awsPlatformObservabilityServiceToken(record.EventSource),
			Status:           awsPlatformObservabilityRuntimeStatus(record.Status),
			RuntimeLagMs:     awsPlatformObservabilityDurationMs(record.ObservedAt, record.CollectedAt),
			EvidenceRef:      record.EvidenceRef,
			EvidenceLinks:    sources.Runtime.EvidenceLinks,
			EvidenceBoundary: awsPlatformObservabilityBoundary,
			NextAction:       record.NextAction,
			StartedAt:        record.ObservedAt,
			EndedAt:          record.CollectedAt,
		})
	}
	for _, entry := range sources.Verification.Entries {
		traces = append(traces, AWSPlatformObservabilityTrace{
			TraceID:          awsPlatformObservabilityTraceID("verification", "verification", entry.AccountID, entry.Region, entry.SourceType, entry.VerificationID),
			SpanName:         "aws.remediation.verify",
			Component:        "verification",
			AccountID:        entry.AccountID,
			Region:           entry.Region,
			Service:          entry.SourceType,
			Status:           awsPlatformObservabilityVerificationStatus(entry.State),
			EvidenceRef:      entry.Rollback.EvidenceRef,
			EvidenceLinks:    entry.EvidenceLinks,
			EvidenceBoundary: awsPlatformObservabilityBoundary,
			NextAction:       entry.NextAction,
			StartedAt:        entry.ProjectedAt,
			EndedAt:          entry.UpdatedAt,
		})
	}
	sort.SliceStable(traces, func(i, j int) bool {
		if traces[i].Status == traces[j].Status {
			return traces[i].TraceID < traces[j].TraceID
		}
		return awsPlatformObservabilityStatusRank(traces[i].Status) > awsPlatformObservabilityStatusRank(traces[j].Status)
	})
	return traces
}

func filterAWSPlatformObservability(metrics []AWSPlatformObservabilityMetric, traces []AWSPlatformObservabilityTrace, request AWSPlatformObservabilityRequest) ([]AWSPlatformObservabilityMetric, []AWSPlatformObservabilityTrace, map[string]string) {
	applied := map[string]string{}
	matchToken := func(value, want string) bool {
		want = strings.ToLower(strings.TrimSpace(want))
		if want == "" || want == "all" {
			return true
		}
		return strings.ToLower(strings.TrimSpace(value)) == want
	}
	matchServiceToken := func(value, want string) bool {
		want = awsPlatformObservabilityServiceToken(want)
		if want == "" || want == "all" {
			return true
		}
		return awsPlatformObservabilityServiceToken(value) == want
	}
	matchSearch := func(values ...string) bool {
		search := strings.ToLower(strings.TrimSpace(request.Search))
		if search == "" {
			return true
		}
		return strings.Contains(strings.ToLower(strings.Join(values, " ")), search)
	}
	filteredMetrics := make([]AWSPlatformObservabilityMetric, 0, len(metrics))
	for _, metric := range metrics {
		if !matchToken(metric.AccountID, request.AccountID) || !matchToken(metric.Region, request.Region) || !matchServiceToken(metric.Service, request.Service) {
			continue
		}
		if !matchToken(metric.Component, request.Component) || !matchToken(metric.Status, request.Status) {
			continue
		}
		if !matchSearch(metric.MetricID, metric.Component, metric.Signal, metric.Title, metric.Summary, metric.Status, metric.TraceID, metric.EvidenceRef, metric.NextAction) {
			continue
		}
		filteredMetrics = append(filteredMetrics, metric)
	}
	filteredTraces := make([]AWSPlatformObservabilityTrace, 0, len(traces))
	for _, trace := range traces {
		if !matchToken(trace.AccountID, request.AccountID) || !matchToken(trace.Region, request.Region) || !matchServiceToken(trace.Service, request.Service) {
			continue
		}
		if !matchToken(trace.Component, request.Component) || !matchToken(trace.Status, request.Status) {
			continue
		}
		if !matchSearch(trace.TraceID, trace.SpanName, trace.Component, trace.Status, trace.Service, trace.EvidenceRef, trace.NextAction) {
			continue
		}
		filteredTraces = append(filteredTraces, trace)
	}
	setAppliedAWSExecutiveOutcomeFilter(applied, "connector_id", request.ConnectorID)
	setAppliedAWSExecutiveOutcomeFilter(applied, "fixture_state", request.FixtureState)
	setAppliedAWSExecutiveOutcomeFilter(applied, "account_id", request.AccountID)
	setAppliedAWSExecutiveOutcomeFilter(applied, "region", request.Region)
	setAppliedAWSExecutiveOutcomeFilter(applied, "service", request.Service)
	setAppliedAWSExecutiveOutcomeFilter(applied, "component", request.Component)
	setAppliedAWSExecutiveOutcomeFilter(applied, "status", request.Status)
	setAppliedAWSExecutiveOutcomeFilter(applied, "search", request.Search)
	return filteredMetrics, filteredTraces, applied
}

func awsPlatformObservabilityHasResultFilter(request AWSPlatformObservabilityRequest) bool {
	return awsPlatformObservabilityRequestedScopeValue(request.AccountID) != "" ||
		awsPlatformObservabilityRequestedScopeValue(request.Region) != "" ||
		awsPlatformObservabilitySourceServiceFilter(request.Service) != "" ||
		awsPlatformObservabilityRequestedScopeValue(request.Component) != "" ||
		awsPlatformObservabilityRequestedScopeValue(request.Status) != "" ||
		strings.TrimSpace(request.Search) != ""
}

func summarizeAWSPlatformObservability(allMetrics []AWSPlatformObservabilityMetric, filteredMetrics []AWSPlatformObservabilityMetric, allTraces []AWSPlatformObservabilityTrace, filteredTraces []AWSPlatformObservabilityTrace, alerts []AWSPlatformObservabilityAlert) AWSPlatformObservabilitySummary {
	summary := AWSPlatformObservabilitySummary{
		TotalMetrics:    len(allMetrics),
		FilteredMetrics: len(filteredMetrics),
		TotalTraces:     len(allTraces),
		FilteredTraces:  len(filteredTraces),
		AccountCounts:   map[string]int{},
		RegionCounts:    map[string]int{},
		ServiceCounts:   map[string]int{},
		ComponentCounts: map[string]int{},
		StatusCounts:    map[string]int{},
		AlertCount:      len(alerts),
	}
	for _, alert := range alerts {
		if alert.Severity == "critical" {
			summary.CriticalAlertCount++
		}
	}
	for _, metric := range filteredMetrics {
		incrementCount(summary.AccountCounts, metric.AccountID)
		incrementCount(summary.RegionCounts, metric.Region)
		incrementCount(summary.ServiceCounts, metric.Service)
		incrementCount(summary.ComponentCounts, metric.Component)
		incrementCount(summary.StatusCounts, metric.Status)
		switch metric.Status {
		case awsPlatformDependencyStatusBlocked:
			summary.BlockedSignals++
		case awsPlatformDependencyStatusDegraded:
			summary.DegradedSignals++
		default:
			summary.ReadySignals++
		}
		switch metric.MetricID {
		case "scan-throughput":
			summary.ScanThroughputPerHour = metric.Value
		case "queue-lag":
			summary.QueueLagP95Ms = metric.Value
		case "runtime-lag":
			summary.RuntimeLagP95Ms = metric.Value
		case "collector-failures":
			summary.CollectorFailureCount = metric.Value
		case "throttling":
			summary.ThrottledTargetCount = metric.Value
		case "remediation-state":
			summary.RemediationPendingCount = metric.Value
		case "verification-outcomes":
			summary.VerificationFailedCount = metric.Value
		case "governance-outcomes":
			summary.GovernanceExceptionCount = metric.Value
		}
	}
	for _, trace := range filteredTraces {
		incrementCount(summary.AccountCounts, trace.AccountID)
		incrementCount(summary.RegionCounts, trace.Region)
		incrementCount(summary.ServiceCounts, trace.Service)
		incrementCount(summary.ComponentCounts, trace.Component)
		incrementCount(summary.StatusCounts, trace.Status)
		switch trace.Status {
		case awsPlatformDependencyStatusBlocked:
			summary.BlockedSignals++
		case awsPlatformDependencyStatusDegraded:
			summary.DegradedSignals++
		default:
			summary.ReadySignals++
		}
		if trace.QueueLagMs > summary.QueueLagP95Ms {
			summary.QueueLagP95Ms = trace.QueueLagMs
		}
		if trace.RuntimeLagMs > summary.RuntimeLagP95Ms {
			summary.RuntimeLagP95Ms = trace.RuntimeLagMs
		}
	}
	return summary
}

func summarizeAWSPlatformObservabilityStatus(metrics []AWSPlatformObservabilityMetric, traces []AWSPlatformObservabilityTrace, includeTraceSignals bool) (string, float64) {
	statuses := awsPlatformObservabilityMetricStatuses(metrics)
	if includeTraceSignals {
		statuses = append(statuses, awsPlatformObservabilityTraceStatuses(traces)...)
	} else if len(statuses) == 0 {
		statuses = awsPlatformObservabilityTraceStatuses(traces)
	}
	status := awsPlatformObservabilitySourceStatus(statuses...)
	switch status {
	case awsPlatformDependencyStatusBlocked:
		return status, 0.48
	case awsPlatformDependencyStatusDegraded:
		return status, 0.72
	default:
		if len(metrics) == 0 {
			return awsPlatformDependencyStatusReady, 0.8
		}
		return awsPlatformDependencyStatusReady, 0.9
	}
}

func awsPlatformObservabilityMetricStatuses(metrics []AWSPlatformObservabilityMetric) []string {
	statuses := make([]string, 0, len(metrics))
	for _, metric := range metrics {
		statuses = append(statuses, metric.Status)
	}
	return statuses
}

func awsPlatformObservabilityTraceStatuses(traces []AWSPlatformObservabilityTrace) []string {
	statuses := make([]string, 0, len(traces))
	for _, trace := range traces {
		statuses = append(statuses, trace.Status)
	}
	return statuses
}

func awsPlatformObservabilitySourceStatuses(sources awsPlatformObservabilitySources) []string {
	return []string{
		sources.Coverage.Status,
		sources.FanOut.Status,
		sources.Runtime.Status,
		sources.Cases.Status,
		sources.Verification.Status,
		sources.Enforcement.Status,
		sources.Governance.Status,
	}
}

func awsPlatformObservabilitySourceStatus(statuses ...string) string {
	status := awsPlatformDependencyStatusReady
	for _, candidate := range statuses {
		switch strings.ToLower(strings.TrimSpace(candidate)) {
		case awsPlatformDependencyStatusBlocked, "permission_denied":
			return awsPlatformDependencyStatusBlocked
		case awsPlatformDependencyStatusDegraded, "partial", "partial_failure":
			status = awsPlatformDependencyStatusDegraded
		}
	}
	return status
}

func awsPlatformObservabilityCountStatus(count int, statuses ...string) string {
	if awsPlatformObservabilitySourceStatus(statuses...) == awsPlatformDependencyStatusBlocked {
		return awsPlatformDependencyStatusBlocked
	}
	if count > 0 || awsPlatformObservabilitySourceStatus(statuses...) == awsPlatformDependencyStatusDegraded {
		return awsPlatformDependencyStatusDegraded
	}
	return awsPlatformDependencyStatusReady
}

func awsPlatformObservabilityLagStatus(lagMs int, statuses ...string) string {
	if awsPlatformObservabilitySourceStatus(statuses...) == awsPlatformDependencyStatusBlocked {
		return awsPlatformDependencyStatusBlocked
	}
	if lagMs > int((15*time.Minute).Milliseconds()) || awsPlatformObservabilitySourceStatus(statuses...) == awsPlatformDependencyStatusDegraded {
		return awsPlatformDependencyStatusDegraded
	}
	return awsPlatformDependencyStatusReady
}

func awsPlatformObservabilityMetricSeverity(statuses ...string) string {
	switch awsPlatformObservabilitySourceStatus(statuses...) {
	case awsPlatformDependencyStatusBlocked:
		return "critical"
	case awsPlatformDependencyStatusDegraded:
		return "high"
	default:
		return "low"
	}
}

func awsPlatformObservabilityCountSeverity(count int, statuses ...string) string {
	if awsPlatformObservabilitySourceStatus(statuses...) == awsPlatformDependencyStatusBlocked {
		return "critical"
	}
	if count > 0 || awsPlatformObservabilitySourceStatus(statuses...) == awsPlatformDependencyStatusDegraded {
		return "high"
	}
	return "low"
}

func awsPlatformObservabilityLagSeverity(lagMs int, statuses ...string) string {
	if awsPlatformObservabilitySourceStatus(statuses...) == awsPlatformDependencyStatusBlocked {
		return "critical"
	}
	if lagMs > int((15*time.Minute).Milliseconds()) || awsPlatformObservabilitySourceStatus(statuses...) == awsPlatformDependencyStatusDegraded {
		return "high"
	}
	return "low"
}

func awsPlatformObservabilityAlerts(metrics []AWSPlatformObservabilityMetric, traces []AWSPlatformObservabilityTrace, includeTraceSignals bool, now time.Time) []AWSPlatformObservabilityAlert {
	alerts := []AWSPlatformObservabilityAlert{}
	for _, metric := range metrics {
		if metric.Status == awsPlatformDependencyStatusReady {
			continue
		}
		alerts = append(alerts, AWSPlatformObservabilityAlert{
			AlertID:          awsPlatformObservabilityTraceID("alert", metric.Component, metric.AccountID, metric.Region, metric.Service, metric.MetricID),
			Severity:         metric.Severity,
			Component:        metric.Component,
			Status:           metric.Status,
			Title:            metric.Title,
			Summary:          metric.Summary,
			EvidenceRef:      metric.EvidenceRef,
			EvidenceBoundary: awsPlatformObservabilityBoundary,
			NextAction:       metric.NextAction,
			TriggeredAt:      now,
		})
	}
	if !includeTraceSignals && len(metrics) > 0 {
		return alerts
	}
	for _, trace := range traces {
		if trace.Status == awsPlatformDependencyStatusReady {
			continue
		}
		alerts = append(alerts, AWSPlatformObservabilityAlert{
			AlertID:          awsPlatformObservabilityTraceID("alert", trace.Component, trace.AccountID, trace.Region, trace.Service, trace.TraceID),
			Severity:         awsPlatformObservabilityMetricSeverity(trace.Status),
			Component:        trace.Component,
			Status:           trace.Status,
			Title:            trace.SpanName,
			Summary:          trace.NextAction,
			EvidenceRef:      trace.EvidenceRef,
			EvidenceBoundary: awsPlatformObservabilityBoundary,
			NextAction:       trace.NextAction,
			TriggeredAt:      now,
		})
	}
	return alerts
}

func awsPlatformObservabilityQueueLag(summary AWSFanOutExecutionSummary) int {
	return (summary.QueuedTargets * int((2 * time.Minute).Milliseconds())) + (summary.InProgressTargets * int((30 * time.Second).Milliseconds())) + (summary.RetryableTargets * int((5 * time.Minute).Milliseconds()))
}

func awsPlatformObservabilityCoverageSummary(result AWSAccountRegionCoverageResult) AWSAccountRegionCoverageSummary {
	summary := AWSAccountRegionCoverageSummary{
		TotalRecords:    len(result.Records),
		FilteredRecords: len(result.Records),
		StatusCounts:    map[string]int{},
		StateCounts:     map[string]int{},
		CollectorCounts: map[string]int{},
	}
	accounts := map[string]struct{}{}
	regions := map[string]struct{}{}
	services := map[string]struct{}{}
	for _, record := range result.Records {
		accounts[strings.TrimSpace(record.AccountID)] = struct{}{}
		regions[strings.ToLower(strings.TrimSpace(record.Region))] = struct{}{}
		services[awsPlatformObservabilityServiceToken(record.Service)] = struct{}{}
		summary.StatusCounts[record.CoverageStatus]++
		summary.StateCounts[record.State]++
		if strings.TrimSpace(record.Collector) != "" {
			summary.CollectorCounts[record.Collector]++
		}
		if record.Retryable {
			summary.RetryableRecords++
		}
		switch strings.ToLower(strings.TrimSpace(record.CoverageStatus)) {
		case "covered":
			summary.CoveredRecords++
		case "missing":
			summary.MissingRecords++
		case "degraded":
			summary.DegradedRecords++
		case "unreachable":
			summary.UnreachableRecords++
		case "suspended":
			summary.SuspendedRecords++
		case "disabled":
			summary.DisabledRecords++
		case "stale":
			summary.StaleRecords++
		case "permission_denied":
			summary.PermissionDeniedRecords++
		}
	}
	summary.AccountCount = len(accounts)
	summary.RegionCount = len(regions)
	summary.ServiceCount = len(services)
	return summary
}

func awsPlatformObservabilityCoverageStatus(summary AWSAccountRegionCoverageSummary, fallback string, sourceScoped bool) string {
	if summary.TotalRecords == 0 {
		status := awsPlatformObservabilitySourceStatus(fallback)
		if sourceScoped && status != awsPlatformDependencyStatusBlocked {
			return awsPlatformDependencyStatusReady
		}
		return status
	}
	switch {
	case summary.PermissionDeniedRecords > 0:
		return awsPlatformDependencyStatusBlocked
	case summary.StaleRecords > 0 || summary.DegradedRecords > 0 || summary.UnreachableRecords > 0 || summary.SuspendedRecords > 0:
		return awsPlatformDependencyStatusDegraded
	default:
		return awsPlatformDependencyStatusReady
	}
}

func awsPlatformObservabilityFanOutSummary(result AWSFanOutExecutionResult) AWSFanOutExecutionSummary {
	summary := AWSFanOutExecutionSummary{
		ConcurrencyLimit: result.Summary.ConcurrencyLimit,
		MaxAttempts:      result.Summary.MaxAttempts,
	}
	for _, target := range result.Targets {
		state := strings.ToLower(strings.TrimSpace(target.State))
		workerState := strings.ToLower(strings.TrimSpace(target.WorkerState))
		combined := strings.TrimSpace(state + " " + workerState + " " + strings.ToLower(strings.TrimSpace(target.FailureReason)))
		summary.TotalTargets++
		if target.Enabled {
			summary.ExecutableTargets++
		} else {
			summary.SkippedTargets++
		}
		switch {
		case strings.Contains(combined, "permission_denied"):
			summary.PermissionDeniedTargets++
		case strings.Contains(combined, "partial"):
			summary.PartialTargets++
		case strings.Contains(combined, "failed"):
			summary.FailedTargets++
		case state == "covered" || workerState == "covered" || workerState == "complete" || workerState == "completed":
			summary.CoveredTargets++
		}
		if awsPlatformObservabilityIsQueuedFanOutState(state) || awsPlatformObservabilityIsQueuedFanOutState(workerState) {
			summary.QueuedTargets++
		}
		if state == "in_progress" || workerState == "in_progress" || workerState == "running" {
			summary.InProgressTargets++
		}
		if target.Throttled || strings.Contains(combined, "throttled") {
			summary.ThrottledTargets++
		}
		if target.Retryable {
			summary.RetryableTargets++
		}
	}
	return summary
}

func awsPlatformObservabilityFanOutSummaryStatus(summary AWSFanOutExecutionSummary, fallback string, sourceScoped bool) string {
	if summary.TotalTargets == 0 {
		status := awsPlatformObservabilitySourceStatus(fallback)
		if sourceScoped && status != awsPlatformDependencyStatusBlocked {
			return awsPlatformDependencyStatusReady
		}
		return status
	}
	switch {
	case summary.PermissionDeniedTargets > 0:
		return awsPlatformDependencyStatusBlocked
	case summary.FailedTargets > 0 || summary.PartialTargets > 0 || summary.ThrottledTargets > 0:
		return awsPlatformDependencyStatusDegraded
	default:
		return awsPlatformDependencyStatusReady
	}
}

func awsPlatformObservabilityHasSourceScopeFilter(request AWSPlatformObservabilityRequest) bool {
	service := awsPlatformObservabilityServiceToken(request.Service)
	return (service != "" && service != "all") ||
		awsPlatformObservabilityRequestedScopeValue(request.AccountID) != "" ||
		awsPlatformObservabilityRequestedScopeValue(request.Region) != ""
}

func awsPlatformObservabilityRequestedScopeValue(value string) string {
	value = strings.TrimSpace(value)
	if strings.EqualFold(value, "all") {
		return ""
	}
	return value
}

func awsPlatformObservabilitySourceServiceFilter(value string) string {
	value = awsExecutiveOutcomeSourceScopeFilter(value)
	if value == "" {
		return ""
	}
	service := awsPlatformObservabilityServiceToken(value)
	if service == "all" {
		return ""
	}
	return service
}

func awsPlatformObservabilityServiceToken(value string) string {
	token := strings.ToLower(strings.TrimSpace(value))
	token = strings.TrimPrefix(token, "aws-service://")
	token = strings.TrimSuffix(token, ".")
	for _, suffix := range []string{".amazonaws.com.cn", ".amazonaws.com"} {
		if strings.HasSuffix(token, suffix) {
			token = strings.TrimSuffix(token, suffix)
			break
		}
	}
	if dot := strings.Index(token, "."); dot > 0 {
		token = token[:dot]
	}
	token = normalizeAWSRuntimeEventFilterToken(token)
	switch token {
	case "secrets-manager":
		return "secretsmanager"
	case "states":
		return "stepfunctions"
	case "events":
		return "eventbridge"
	default:
		return token
	}
}

func awsPlatformObservabilityTargetQueueLag(target AWSFanOutExecutionTarget) int {
	state := strings.ToLower(strings.TrimSpace(firstNonEmptyAWSValue(target.WorkerState, target.State)))
	switch {
	case target.Throttled:
		return int((5 * time.Minute).Milliseconds())
	case awsPlatformObservabilityIsQueuedFanOutState(state):
		return int((2 * time.Minute).Milliseconds())
	case state == "in_progress":
		return int((30 * time.Second).Milliseconds())
	case target.Retryable:
		return int((5 * time.Minute).Milliseconds())
	default:
		return 0
	}
}

func awsPlatformObservabilityIsQueuedFanOutState(state string) bool {
	switch strings.ToLower(strings.TrimSpace(state)) {
	case "queued", "pending":
		return true
	default:
		return false
	}
}

func awsPlatformObservabilityRuntimeLag(records []AWSRuntimeEventRecord) int {
	values := []int{}
	for _, record := range records {
		lag := awsPlatformObservabilityDurationMs(record.ObservedAt, record.CollectedAt)
		if lag > 0 {
			values = append(values, lag)
		}
	}
	return awsPlatformObservabilityP95(values)
}

func awsPlatformObservabilityDurationMs(start, end time.Time) int {
	if start.IsZero() || end.IsZero() || end.Before(start) {
		return 0
	}
	return int(end.Sub(start).Milliseconds())
}

func awsPlatformObservabilityP95(values []int) int {
	if len(values) == 0 {
		return 0
	}
	sort.Ints(values)
	index := ((95*len(values))+99)/100 - 1
	return values[index]
}

func awsPlatformObservabilityFanOutStatus(target AWSFanOutExecutionTarget) string {
	state := strings.ToLower(strings.TrimSpace(strings.Join([]string{target.WorkerState, target.State, target.FailureReason}, " ")))
	switch {
	case strings.Contains(state, "permission_denied"):
		return awsPlatformDependencyStatusBlocked
	case target.Throttled || target.Retryable || strings.Contains(state, "failed") || strings.Contains(state, "partial") || strings.Contains(state, "throttled"):
		return awsPlatformDependencyStatusDegraded
	default:
		return awsPlatformDependencyStatusReady
	}
}

func awsPlatformObservabilityRuntimeStatus(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "permission_denied", "blocked":
		return awsPlatformDependencyStatusBlocked
	case "partial", "partial_failure", "degraded", "stale", "delayed":
		return awsPlatformDependencyStatusDegraded
	default:
		return awsPlatformDependencyStatusReady
	}
}

func awsPlatformObservabilityVerificationStatus(state string) string {
	switch strings.ToLower(strings.TrimSpace(state)) {
	case "blocked", "not_ready":
		return awsPlatformDependencyStatusBlocked
	case "verification_failed", "rollback_planned", "verification_pending", "pending":
		return awsPlatformDependencyStatusDegraded
	default:
		return awsPlatformDependencyStatusReady
	}
}

func awsPlatformObservabilityStatusRank(status string) int {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case awsPlatformDependencyStatusBlocked:
		return 3
	case awsPlatformDependencyStatusDegraded:
		return 2
	default:
		return 1
	}
}

func awsPlatformObservabilityTraceID(parts ...string) string {
	clean := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.ToLower(strings.TrimSpace(part))
		part = strings.ReplaceAll(part, ":", "-")
		part = strings.ReplaceAll(part, "/", "-")
		part = strings.ReplaceAll(part, "|", "-")
		part = strings.ReplaceAll(part, " ", "-")
		part = strings.Trim(part, "-")
		if part != "" && part != "all" {
			clean = append(clean, part)
		}
	}
	return strings.Join(clean, ":")
}

func awsPlatformObservabilityCaveats() []string {
	return []string{
		"Platform observability is metadata-only and links to evidence refs instead of exposing secret values, payloads, prompts, completions, browser output, database rows, object contents, or customer content.",
		"Queue lag and runtime lag are dashboard signals derived from bounded source contracts; use trace rows and diagnostics for account, region, and service-level debugging.",
		"Read-only fixtures keep loading, empty, degraded, and permission-denied states stable when live AWS observability sources are unavailable.",
	}
}

func awsPlatformObservabilityFailureReasons(sources awsPlatformObservabilitySources) []string {
	out := []string{}
	for _, failures := range [][]string{
		sources.Coverage.FailureReasons,
		sources.FanOut.FailureReasons,
		sources.Runtime.FailureReasons,
		sources.Cases.FailureReasons,
		sources.Verification.FailureReasons,
		sources.Enforcement.FailureReasons,
		sources.Governance.FailureReasons,
	} {
		out = append(out, failures...)
	}
	return dedupeStrings(out)
}

func awsPlatformObservabilityRemediationHints(sources awsPlatformObservabilitySources) []string {
	out := []string{
		"Start with blocked or degraded alert rows, then drill into traces for the affected account, region, service, and evidence ref.",
	}
	for _, hints := range [][]string{
		sources.Coverage.RemediationHints,
		sources.FanOut.RemediationHints,
		sources.Runtime.RemediationHints,
		sources.Cases.RemediationHints,
		sources.Verification.RemediationHints,
		sources.Enforcement.RemediationHints,
		sources.Governance.RemediationHints,
	} {
		out = append(out, hints...)
	}
	return dedupeStrings(out)
}

func awsPlatformObservabilityCoverageGaps(sources awsPlatformObservabilitySources) []AWSPlatformObservabilityCoverageGap {
	out := []AWSPlatformObservabilityCoverageGap{}
	seen := map[string]bool{}
	add := func(capability, status, reason, remediation string) {
		if capability == "" && status == "" && reason == "" {
			return
		}
		key := strings.Join([]string{capability, status, reason, remediation}, "\x00")
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, AWSPlatformObservabilityCoverageGap{Capability: capability, Status: status, Reason: reason, Remediation: remediation})
	}
	for _, gap := range sources.Coverage.CoverageGaps {
		add(gap.Capability, gap.Status, gap.Reason, gap.Remediation)
	}
	for _, gap := range sources.FanOut.CoverageGaps {
		add(gap.Capability, gap.Status, gap.Reason, gap.Remediation)
	}
	for _, gap := range sources.Runtime.CoverageGaps {
		add(gap.Capability, gap.Status, gap.Reason, gap.Remediation)
	}
	for _, gap := range sources.Cases.CoverageGaps {
		add(gap.Capability, gap.Status, gap.Reason, gap.Remediation)
	}
	for _, gap := range sources.Verification.CoverageGaps {
		add(gap.Capability, gap.Status, gap.Reason, gap.Remediation)
	}
	for _, gap := range sources.Enforcement.CoverageGaps {
		add(gap.Capability, gap.Status, gap.Reason, gap.Remediation)
	}
	for _, gap := range sources.Governance.CoverageGaps {
		add(gap.Capability, gap.Status, gap.Reason, gap.Remediation)
	}
	return out
}

func awsPlatformObservabilityDiagnostics(sources awsPlatformObservabilitySources) []AWSPlatformObservabilityDiagnostic {
	out := []AWSPlatformObservabilityDiagnostic{}
	seen := map[string]bool{}
	add := func(collector, sourceID, code, message, remediation string, retryable bool) {
		if collector == "" && code == "" && message == "" {
			return
		}
		key := strings.Join([]string{collector, sourceID, code, message, remediation}, "\x00")
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, AWSPlatformObservabilityDiagnostic{Collector: collector, SourceID: sourceID, Code: code, Message: message, Remediation: remediation, Retryable: retryable})
	}
	for _, diagnostic := range sources.Coverage.Diagnostics {
		add(firstNonEmptyAWSValue(diagnostic.Collector, diagnostic.Source), diagnostic.Scope, diagnostic.Code, diagnostic.Message, diagnostic.Remediation, diagnostic.Retryable)
	}
	for _, diagnostic := range sources.FanOut.Diagnostics {
		add(firstNonEmptyAWSValue(diagnostic.Collector, diagnostic.Source), diagnostic.Scope, diagnostic.Code, diagnostic.Message, diagnostic.Remediation, diagnostic.Retryable)
	}
	for _, diagnostic := range sources.Runtime.Diagnostics {
		add(diagnostic.Collector, diagnostic.SourceID, diagnostic.Code, diagnostic.Message, diagnostic.Remediation, diagnostic.Retryable)
	}
	for _, diagnostic := range sources.Cases.Diagnostics {
		add(diagnostic.Collector, diagnostic.SourceID, diagnostic.Code, diagnostic.Message, diagnostic.Remediation, diagnostic.Retryable)
	}
	for _, diagnostic := range sources.Verification.Diagnostics {
		add(diagnostic.Collector, diagnostic.SourceID, diagnostic.Code, diagnostic.Message, diagnostic.Remediation, diagnostic.Retryable)
	}
	for _, diagnostic := range sources.Enforcement.Diagnostics {
		add(diagnostic.Collector, diagnostic.SourceID, diagnostic.Code, diagnostic.Message, diagnostic.Remediation, diagnostic.Retryable)
	}
	for _, diagnostic := range sources.Governance.Diagnostics {
		add(diagnostic.Collector, diagnostic.SourceID, diagnostic.Code, diagnostic.Message, diagnostic.Remediation, diagnostic.Retryable)
	}
	return out
}
