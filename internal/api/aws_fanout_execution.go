package api

import (
	"context"
	"strings"
	"time"

	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/providers/awscontract"
)

const awsFanOutExecutionCurrentIssue = 1500

// AWSFanOutExecutionRequest filters and pins the deterministic fan-out worker view.
type AWSFanOutExecutionRequest struct {
	ConnectorID    string `json:"connector_id,omitempty"`
	FixtureState   string `json:"fixture_state,omitempty"`
	Account        string `json:"account,omitempty"`
	Region         string `json:"region,omitempty"`
	Service        string `json:"service,omitempty"`
	State          string `json:"state,omitempty"`
	MaxConcurrency int    `json:"max_concurrency,omitempty"`
}

// AWSFanOutExecutionTarget is one operator-visible worker execution unit.
type AWSFanOutExecutionTarget struct {
	Key             string    `json:"key"`
	AccountID       string    `json:"account_id"`
	Region          string    `json:"region"`
	Service         string    `json:"service"`
	Collector       string    `json:"collector,omitempty"`
	Priority        string    `json:"priority"`
	State           string    `json:"state"`
	WorkerState     string    `json:"worker_state"`
	Enabled         bool      `json:"enabled"`
	Attempts        int       `json:"attempts"`
	MaxAttempts     int       `json:"max_attempts"`
	ConcurrencySlot int       `json:"concurrency_slot,omitempty"`
	Checkpoint      string    `json:"checkpoint,omitempty"`
	Retryable       bool      `json:"retryable"`
	Throttled       bool      `json:"throttled"`
	RetryAfter      string    `json:"retry_after,omitempty"`
	FailureReason   string    `json:"failure_reason,omitempty"`
	EvidenceRef     string    `json:"evidence_ref"`
	NextAction      string    `json:"next_action"`
	ObservedAt      time.Time `json:"observed_at,omitempty"`
}

// AWSFanOutExecutionSummary aggregates bounded worker state for dashboards.
type AWSFanOutExecutionSummary struct {
	TotalTargets            int `json:"total_targets"`
	ExecutableTargets       int `json:"executable_targets"`
	SkippedTargets          int `json:"skipped_targets"`
	QueuedTargets           int `json:"queued_targets"`
	InProgressTargets       int `json:"in_progress_targets"`
	CoveredTargets          int `json:"covered_targets"`
	PartialTargets          int `json:"partial_targets"`
	FailedTargets           int `json:"failed_targets"`
	PermissionDeniedTargets int `json:"permission_denied_targets"`
	ThrottledTargets        int `json:"throttled_targets"`
	RetryableTargets        int `json:"retryable_targets"`
	ConcurrencyLimit        int `json:"concurrency_limit"`
	MaxAttempts             int `json:"max_attempts"`
}

// AWSFanOutExecutionResult is the full deterministic fan-out worker response.
type AWSFanOutExecutionResult struct {
	TenantID           string                       `json:"tenant_id"`
	WorkspaceID        string                       `json:"workspace_id"`
	ProjectID          string                       `json:"project_id"`
	ConnectorID        string                       `json:"connector_id,omitempty"`
	AccountID          string                       `json:"account_id,omitempty"`
	Region             string                       `json:"region,omitempty"`
	ParentIssueNumber  int                          `json:"parent_issue_number"`
	ParentIssueRef     string                       `json:"parent_issue_ref"`
	CurrentIssueNumber int                          `json:"current_issue_number"`
	CurrentIssueRef    string                       `json:"current_issue_ref"`
	Version            string                       `json:"version"`
	Status             string                       `json:"status"`
	FixtureState       string                       `json:"fixture_state,omitempty"`
	Confidence         float64                      `json:"confidence"`
	FilteredTargets    int                          `json:"filtered_targets"`
	Summary            AWSFanOutExecutionSummary    `json:"summary"`
	Targets            []AWSFanOutExecutionTarget   `json:"targets"`
	FailureReasons     []string                     `json:"failure_reasons"`
	RemediationHints   []string                     `json:"remediation_hints"`
	EvidenceLinks      []string                     `json:"evidence_links"`
	PartialFailures    []AWSPartialFailureReport    `json:"partial_failure_reports"`
	CoverageGaps       []AWSCoveragePlanCoverageGap `json:"coverage_gaps"`
	Diagnostics        []AWSCoveragePlanDiagnostic  `json:"diagnostics"`
	GeneratedAt        time.Time                    `json:"generated_at"`
	UpdatedAt          time.Time                    `json:"updated_at"`
}

// GetAWSFanOutExecution returns the deterministic account/region/service fan-out
// worker state for a project's AWS connector. It is metadata-only and read-only.
func (s *Service) GetAWSFanOutExecution(ctx context.Context, workspaceID string, projectID string, request AWSFanOutExecutionRequest) (AWSFanOutExecutionResult, error) {
	project, scope, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return AWSFanOutExecutionResult{}, err
	}
	connection, hasConnection, err := s.awsBaselineConnection(ctx, project, strings.TrimSpace(request.ConnectorID))
	if err != nil {
		return AWSFanOutExecutionResult{}, err
	}
	coverageRows := []db.AWSAccountRegionCoverage{}
	if strings.TrimSpace(request.FixtureState) == "" && hasConnection {
		coverageRows, err = awsCoverageListRows(ctx, s.Store, db.AWSAccountRegionCoverageFilter{
			WorkspaceID: project.WorkspaceID,
			ProjectID:   project.ProjectID,
			ConnectorID: strings.TrimSpace(connection.ConnectorID),
			Limit:       awsCoveragePlannerAccountRegionPageSize,
		})
		if err != nil {
			return AWSFanOutExecutionResult{}, err
		}
	}
	return buildAWSFanOutExecution(scope, project, connection, hasConnection, request, coverageRows, s.Now().UTC())
}

func buildAWSFanOutExecution(scope db.Scope, project db.TenancyProject, connection AWSConnectionStatus, hasConnection bool, request AWSFanOutExecutionRequest, coverageRows []db.AWSAccountRegionCoverage, checkedAt time.Time) (AWSFanOutExecutionResult, error) {
	fixtureState := normalizeAWSCoveragePlanFixtureState(request.FixtureState, connection, hasConnection)
	if strings.TrimSpace(request.FixtureState) != "" && fixtureState == "" {
		return AWSFanOutExecutionResult{}, ErrInvalidAWSConnectionRequest
	}
	if !validAWSCoveragePlanStateFilter(request.State) {
		return AWSFanOutExecutionResult{}, ErrInvalidAWSConnectionRequest
	}
	maxConcurrency := request.MaxConcurrency
	if maxConcurrency < 0 || maxConcurrency > 64 {
		return AWSFanOutExecutionResult{}, ErrInvalidAWSConnectionRequest
	}
	accountID := firstNonEmptyAWSValue(strings.TrimSpace(connection.AccountID), "111111111111")
	region := firstNonEmptyAWSValue(strings.TrimSpace(connection.Region), "us-east-1")
	connectorID := firstNonEmptyAWSValue(strings.TrimSpace(connection.ConnectorID), strings.TrimSpace(request.ConnectorID), "aws-fixture")

	var config awscontract.CoveragePlanConfig
	var diagnostics []AWSCoveragePlanDiagnostic
	var gaps []AWSCoveragePlanCoverageGap
	if fixtureState != "" {
		config, diagnostics, gaps = awsCoveragePlanFixtureConfig(connectorID, accountID, region, fixtureState)
	} else {
		config, diagnostics, gaps = awsCoveragePlanLiveConfig(connectorID, accountID, region, hasConnection, connection.Connected, coverageRows, checkedAt)
	}
	coverage, err := awscontract.PlanCoverage(config, checkedAt)
	if err != nil {
		return AWSFanOutExecutionResult{}, err
	}
	execution, err := awscontract.PlanFanOutExecution(awscontract.FanOutExecutionConfig{
		Plan:               coverage,
		MaxConcurrency:     firstPositiveInt(maxConcurrency, 4),
		MaxAttempts:        3,
		ThrottleRetryAfter: 30 * time.Second,
		Outcomes:           awsFanOutFixtureOutcomes(coverage, accountID, region, fixtureState, checkedAt),
		StartedAt:          checkedAt,
	})
	if err != nil {
		return AWSFanOutExecutionResult{}, err
	}
	targets := mapAWSFanOutExecutionTargets(execution.Targets)
	filtered := filterAWSFanOutExecutionTargets(targets, request)
	status, confidence, failures, remediations := summarizeAWSFanOutExecution(fixtureState, diagnostics, execution)

	return AWSFanOutExecutionResult{
		TenantID:           scope.TenantID,
		WorkspaceID:        project.WorkspaceID,
		ProjectID:          project.ProjectID,
		ConnectorID:        connectorID,
		AccountID:          accountID,
		Region:             region,
		ParentIssueNumber:  awsPlatformDependencyParentIssue,
		ParentIssueRef:     awsIssueRef(awsPlatformDependencyParentIssue),
		CurrentIssueNumber: awsPartialFailureReportingCurrentIssue,
		CurrentIssueRef:    awsIssueRef(awsPartialFailureReportingCurrentIssue),
		Version:            execution.Version,
		Status:             status,
		FixtureState:       fixtureState,
		Confidence:         confidence,
		FilteredTargets:    len(filtered),
		Summary:            mapAWSFanOutExecutionSummary(execution.Summary),
		Targets:            filtered,
		FailureReasons:     failures,
		RemediationHints:   remediations,
		EvidenceLinks: dedupeStrings([]string{
			awsIssueURL(awsPlatformDependencyParentIssue),
			awsIssueURL(awsPartialFailureReportingCurrentIssue),
			awsIssueURL(awsFanOutExecutionCurrentIssue),
			"/docs/aws-account-region-fanout-worker",
			"/docs/aws-account-region-coverage-planner",
			awsBaselineProjectEvidenceURL(scope, project),
		}),
		PartialFailures: buildAWSFanOutPartialFailureReports(filtered),
		CoverageGaps:    gaps,
		Diagnostics:     diagnostics,
		GeneratedAt:     checkedAt,
		UpdatedAt:       checkedAt,
	}, nil
}

func awsFanOutFixtureOutcomes(plan awscontract.CoveragePlan, accountID, region, fixtureState string, checkedAt time.Time) []awscontract.FanOutTargetOutcome {
	if fixtureState == "" || fixtureState == "empty" || fixtureState == "permission_denied" {
		return nil
	}
	outcomes := []awscontract.FanOutTargetOutcome{}
	add := func(key string, outcome awscontract.FanOutExecutionOutcome, cursor string, failure string, retryable bool) {
		if hasCoverageTarget(plan, key) {
			outcomes = append(outcomes, awscontract.FanOutTargetOutcome{Key: key, Outcome: outcome, Cursor: cursor, FailureReason: failure, Retryable: retryable, ObservedAt: checkedAt})
		}
	}
	add(accountID+"|"+awsCoveragePlannerGlobalServiceHomeRegion+"|iam", awscontract.FanOutExecutionOutcomeCovered, "", "", false)
	add(accountID+"|"+region+"|lambda", awscontract.FanOutExecutionOutcomeCovered, "", "", false)

	if fixtureState == "degraded" || fixtureState == "partial_failure" {
		secondaryAccount := awsCoveragePlanSiblingAccount(accountID)
		secondaryRegion := awsCoveragePlanSecondaryRegion(region)
		add(secondaryAccount+"|"+secondaryRegion+"|ecs", awscontract.FanOutExecutionOutcomeThrottled, "ecs-page-2", "Throttling: ecs:ListServices throttled after bounded retries", true)
		add(secondaryAccount+"|"+region+"|lambda", awscontract.FanOutExecutionOutcomePartial, "lambda-page-3", "lambda returned partial page before retry window elapsed", true)
	}
	return outcomes
}

func hasCoverageTarget(plan awscontract.CoveragePlan, key string) bool {
	for _, target := range plan.Targets {
		if target.Key == key {
			return true
		}
	}
	return false
}

func mapAWSFanOutExecutionTargets(targets []awscontract.FanOutExecutionTarget) []AWSFanOutExecutionTarget {
	out := make([]AWSFanOutExecutionTarget, 0, len(targets))
	for _, target := range targets {
		out = append(out, AWSFanOutExecutionTarget{
			Key:             target.Key,
			AccountID:       target.AccountID,
			Region:          target.Region,
			Service:         target.Service,
			Collector:       target.Collector,
			Priority:        string(target.Priority),
			State:           string(target.State),
			WorkerState:     string(target.WorkerState),
			Enabled:         target.Enabled,
			Attempts:        target.Attempts,
			MaxAttempts:     target.MaxAttempts,
			ConcurrencySlot: target.ConcurrencySlot,
			Checkpoint:      target.Checkpoint,
			Retryable:       target.Retryable,
			Throttled:       target.Throttled,
			RetryAfter:      target.RetryAfter,
			FailureReason:   target.FailureReason,
			EvidenceRef:     target.EvidenceRef,
			NextAction:      target.NextAction,
			ObservedAt:      target.ObservedAt,
		})
	}
	return out
}

func mapAWSFanOutExecutionSummary(summary awscontract.FanOutExecutionSummary) AWSFanOutExecutionSummary {
	return AWSFanOutExecutionSummary{
		TotalTargets:            summary.TotalTargets,
		ExecutableTargets:       summary.ExecutableTargets,
		SkippedTargets:          summary.SkippedTargets,
		QueuedTargets:           summary.QueuedTargets,
		InProgressTargets:       summary.InProgressTargets,
		CoveredTargets:          summary.CoveredTargets,
		PartialTargets:          summary.PartialTargets,
		FailedTargets:           summary.FailedTargets,
		PermissionDeniedTargets: summary.PermissionDeniedTargets,
		ThrottledTargets:        summary.ThrottledTargets,
		RetryableTargets:        summary.RetryableTargets,
		ConcurrencyLimit:        summary.ConcurrencyLimit,
		MaxAttempts:             summary.MaxAttempts,
	}
}

func filterAWSFanOutExecutionTargets(targets []AWSFanOutExecutionTarget, request AWSFanOutExecutionRequest) []AWSFanOutExecutionTarget {
	account := strings.TrimSpace(request.Account)
	region := strings.ToLower(strings.TrimSpace(request.Region))
	service := strings.ToLower(strings.TrimSpace(request.Service))
	state := strings.ToLower(strings.TrimSpace(request.State))
	if account == "" && region == "" && service == "" && state == "" {
		return targets
	}
	filtered := make([]AWSFanOutExecutionTarget, 0, len(targets))
	for _, target := range targets {
		if account != "" && target.AccountID != account {
			continue
		}
		if region != "" && strings.ToLower(target.Region) != region {
			continue
		}
		if service != "" && strings.ToLower(target.Service) != service {
			continue
		}
		if state != "" && strings.ToLower(target.WorkerState) != state && strings.ToLower(target.State) != state {
			continue
		}
		filtered = append(filtered, target)
	}
	return filtered
}

func buildAWSFanOutPartialFailureReports(targets []AWSFanOutExecutionTarget) []AWSPartialFailureReport {
	reports := []AWSPartialFailureReport{}
	for _, target := range targets {
		state := strings.ToLower(strings.TrimSpace(target.WorkerState))
		if state == "" {
			state = strings.ToLower(strings.TrimSpace(target.State))
		}
		if !awsCoverageStateIsPartialFailure(state) {
			continue
		}
		reports = append(reports, AWSPartialFailureReport{
			Key:           target.Key,
			AccountID:     target.AccountID,
			Region:        target.Region,
			Service:       target.Service,
			Collector:     target.Collector,
			State:         strings.ToLower(strings.TrimSpace(target.State)),
			WorkerState:   state,
			ReasonCode:    awsCoveragePartialFailureReasonCode(state, target.FailureReason, target.NextAction),
			FailureReason: target.FailureReason,
			Retryable:     target.Retryable,
			Attempts:      target.Attempts,
			Cursor:        target.Checkpoint,
			EvidenceRef:   target.EvidenceRef,
			NextAction:    target.NextAction,
			ObservedAt:    target.ObservedAt,
		})
	}
	return reports
}

func summarizeAWSFanOutExecution(fixtureState string, diagnostics []AWSCoveragePlanDiagnostic, execution awscontract.FanOutExecutionPlan) (string, float64, []string, []string) {
	if fixtureState == "permission_denied" || execution.Summary.PermissionDeniedTargets > 0 || awsCoveragePlanHasDiagnosticCode(diagnostics, "permission_denied") {
		return awsPlatformDependencyStatusBlocked, 0.34,
			awsCoveragePlanDiagnosticMessages(diagnostics),
			[]string{"Deploy read-only collector roles into denied accounts/regions before rerunning fan-out execution."}
	}
	if fixtureState == "partial_failure" || fixtureState == "degraded" || execution.Summary.FailedTargets > 0 || execution.Summary.PartialTargets > 0 || len(diagnostics) > 0 {
		return awsPlatformDependencyStatusDegraded, 0.74,
			awsCoveragePlanDiagnosticMessages(diagnostics),
			[]string{"Retry throttled or partial targets with bounded backoff; completed targets stay checkpointed."}
	}
	if execution.Summary.TotalTargets == 0 {
		return awsPlatformDependencyStatusReady, 0.8, nil,
			[]string{"No executable AWS targets are configured; add accounts, regions, and services before starting fan-out execution."}
	}
	return awsPlatformDependencyStatusReady, 0.94, nil,
		[]string{"Fan-out execution is bounded, target-scoped, and resumable across account/region/service checkpoints."}
}

func firstPositiveInt(values ...int) int {
	for _, value := range values {
		if value > 0 {
			return value
		}
	}
	return 0
}
