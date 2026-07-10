package api

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	awsGADemoHardeningCurrentIssue = 1557
	awsGADemoHardeningVersion      = "aws-ga-demo-hardening-v1"
	awsGADemoHardeningBoundary     = "metadata_only_ga_demo_no_secret_values_no_customer_payloads"
)

// AWSGADemoHardeningRequest scopes the end-to-end AWS platform demo to one
// connector and bounded operator filters. The response composes existing
// read-only AWS contracts rather than creating another collector.
type AWSGADemoHardeningRequest struct {
	ConnectorID  string `json:"connector_id,omitempty"`
	FixtureState string `json:"fixture_state,omitempty"`
	AccountID    string `json:"account_id,omitempty"`
	Region       string `json:"region,omitempty"`
	Stage        string `json:"stage,omitempty"`
	Status       string `json:"status,omitempty"`
	Search       string `json:"search,omitempty"`
}

type AWSGADemoHardeningStage struct {
	StageID          string    `json:"stage_id"`
	Order            int       `json:"order"`
	Title            string    `json:"title"`
	Summary          string    `json:"summary"`
	Status           string    `json:"status"`
	Confidence       float64   `json:"confidence"`
	AccountID        string    `json:"account_id,omitempty"`
	Region           string    `json:"region,omitempty"`
	PrimaryRoute     string    `json:"primary_route"`
	EvidenceRef      string    `json:"evidence_ref"`
	EvidenceLinks    []string  `json:"evidence_links"`
	EvidenceBoundary string    `json:"evidence_boundary"`
	NextAction       string    `json:"next_action"`
	FailureReason    string    `json:"failure_reason,omitempty"`
	UpdatedAt        time.Time `json:"updated_at"`
}

type AWSGADemoHardeningReadinessCheck struct {
	CheckID     string   `json:"check_id"`
	Title       string   `json:"title"`
	Status      string   `json:"status"`
	Owner       string   `json:"owner"`
	Summary     string   `json:"summary"`
	Evidence    []string `json:"evidence"`
	NextAction  string   `json:"next_action"`
	Required    bool     `json:"required"`
	Permissions []string `json:"permissions,omitempty"`
}

type AWSGADemoHardeningSummary struct {
	TotalStages        int            `json:"total_stages"`
	FilteredStages     int            `json:"filtered_stages"`
	ReadyStages        int            `json:"ready_stages"`
	DegradedStages     int            `json:"degraded_stages"`
	BlockedStages      int            `json:"blocked_stages"`
	ReadinessChecks    int            `json:"readiness_checks"`
	PassedChecks       int            `json:"passed_checks"`
	RequiredChecks     int            `json:"required_checks"`
	FailedChecks       int            `json:"failed_checks"`
	PermissionWarnings int            `json:"permission_warnings"`
	StatusCounts       map[string]int `json:"status_counts"`
	StageCounts        map[string]int `json:"stage_counts"`
}

type AWSGADemoHardeningResult struct {
	TenantID           string                             `json:"tenant_id"`
	WorkspaceID        string                             `json:"workspace_id"`
	ProjectID          string                             `json:"project_id"`
	ConnectorID        string                             `json:"connector_id,omitempty"`
	AccountID          string                             `json:"account_id,omitempty"`
	Region             string                             `json:"region,omitempty"`
	ParentIssueNumber  int                                `json:"parent_issue_number"`
	ParentIssueRef     string                             `json:"parent_issue_ref"`
	CurrentIssueNumber int                                `json:"current_issue_number"`
	CurrentIssueRef    string                             `json:"current_issue_ref"`
	Version            string                             `json:"version"`
	Status             string                             `json:"status"`
	FixtureState       string                             `json:"fixture_state,omitempty"`
	Confidence         float64                            `json:"confidence"`
	CalculationVersion string                             `json:"calculation_version"`
	AppliedFilters     map[string]string                  `json:"applied_filters"`
	Summary            AWSGADemoHardeningSummary          `json:"summary"`
	Stages             []AWSGADemoHardeningStage          `json:"stages"`
	ReadinessChecks    []AWSGADemoHardeningReadinessCheck `json:"readiness_checks"`
	Permissions        []string                           `json:"permissions"`
	SafetyNotes        []string                           `json:"safety_notes"`
	Limitations        []string                           `json:"limitations"`
	Troubleshooting    []string                           `json:"troubleshooting"`
	Caveats            []string                           `json:"caveats"`
	FailureReasons     []string                           `json:"failure_reasons"`
	RemediationHints   []string                           `json:"remediation_hints"`
	EvidenceLinks      []string                           `json:"evidence_links"`
	GeneratedAt        time.Time                          `json:"generated_at"`
	UpdatedAt          time.Time                          `json:"updated_at"`
}

type awsGADemoHardeningSources struct {
	Validation    AWSPlatformValidationHarnessResult
	Agents        AWSAIAgentIdentityInventoryResult
	Graph         AWSGraphExplorerResult
	Remediation   AWSRemediationCenterResult
	Governance    AWSGovernanceAuditReportingResult
	Outcomes      AWSExecutiveOutcomeViewResult
	Observability AWSPlatformObservabilityResult
}

func (s *Service) GetAWSGADemoHardening(ctx context.Context, workspaceID string, projectID string, request AWSGADemoHardeningRequest) (AWSGADemoHardeningResult, error) {
	if !validAWSGADemoHardeningFilter(request) {
		return AWSGADemoHardeningResult{}, ErrInvalidAWSConnectionRequest
	}
	project, scope, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return AWSGADemoHardeningResult{}, err
	}
	connection, hasConnection, err := s.awsBaselineConnection(ctx, project, strings.TrimSpace(request.ConnectorID))
	if err != nil {
		return AWSGADemoHardeningResult{}, err
	}
	now := s.Now().UTC()
	fixtureState := normalizeAWSGovernanceAuditReportingFixtureState(request.FixtureState, connection, hasConnection)
	if fixtureState == "" {
		return AWSGADemoHardeningResult{}, ErrInvalidAWSConnectionRequest
	}
	sourceFixtureState := fixtureState
	if strings.TrimSpace(request.FixtureState) == "" && hasConnection && connection.Connected {
		sourceFixtureState = ""
	}
	connectorID := firstNonEmptyAWSValue(connection.ConnectorID, strings.TrimSpace(request.ConnectorID))
	sourceAccountID := awsExecutiveOutcomeSourceScopeFilter(request.AccountID)
	sourceRegion := awsExecutiveOutcomeSourceScopeFilter(request.Region)
	accountID := awsExecutiveOutcomeScopeValue(request.AccountID, connection.AccountID, "123456789012")
	region := awsExecutiveOutcomeScopeValue(request.Region, connection.Region, "us-east-1")

	validation, err := s.GetAWSPlatformValidationHarness(ctx, workspaceID, projectID, AWSPlatformValidationHarnessRequest{ConnectorID: connectorID})
	if err != nil {
		return AWSGADemoHardeningResult{}, err
	}
	agents, err := s.GetAWSAIAgentIdentityInventory(ctx, workspaceID, projectID, AWSAIAgentIdentityInventoryRequest{
		ConnectorID:  connectorID,
		FixtureState: sourceFixtureState,
		AccountID:    sourceAccountID,
		Region:       sourceRegion,
	})
	if err != nil {
		return AWSGADemoHardeningResult{}, err
	}
	graph, err := s.GetAWSGraphExplorer(ctx, workspaceID, projectID, AWSGraphExplorerRequest{
		ConnectorID:  connectorID,
		FixtureState: sourceFixtureState,
		AccountID:    sourceAccountID,
		Region:       sourceRegion,
	})
	if err != nil {
		return AWSGADemoHardeningResult{}, err
	}
	remediation, err := s.GetAWSRemediationCenter(ctx, workspaceID, projectID, AWSRemediationCenterRequest{
		ConnectorID:  connectorID,
		FixtureState: sourceFixtureState,
		AccountID:    sourceAccountID,
		Region:       sourceRegion,
	})
	if err != nil {
		return AWSGADemoHardeningResult{}, err
	}
	governance, err := s.GetAWSGovernanceAuditReporting(ctx, workspaceID, projectID, AWSGovernanceAuditReportingRequest{
		ConnectorID:  connectorID,
		FixtureState: sourceFixtureState,
		AccountID:    sourceAccountID,
		Region:       sourceRegion,
	})
	if err != nil {
		return AWSGADemoHardeningResult{}, err
	}
	outcomes, err := s.GetAWSExecutiveOutcomeView(ctx, workspaceID, projectID, AWSExecutiveOutcomeViewRequest{
		ConnectorID:  connectorID,
		FixtureState: sourceFixtureState,
		AccountID:    sourceAccountID,
		Region:       sourceRegion,
	})
	if err != nil {
		return AWSGADemoHardeningResult{}, err
	}
	observability, err := s.GetAWSPlatformObservability(ctx, workspaceID, projectID, AWSPlatformObservabilityRequest{
		ConnectorID:  connectorID,
		FixtureState: sourceFixtureState,
		AccountID:    sourceAccountID,
		Region:       sourceRegion,
	})
	if err != nil {
		return AWSGADemoHardeningResult{}, err
	}

	sources := awsGADemoHardeningSources{
		Validation:    validation,
		Agents:        agents,
		Graph:         graph,
		Remediation:   remediation,
		Governance:    governance,
		Outcomes:      outcomes,
		Observability: observability,
	}
	stages := awsGADemoHardeningStages(sources, accountID, region, scope.TenantID, project.WorkspaceID, project.ProjectID, now)
	filteredStages, applied := filterAWSGADemoHardeningStages(stages, request)
	checks := awsGADemoHardeningReadinessChecks(sources)
	filteredChecks := filterAWSGADemoHardeningReadinessChecks(checks, request)
	summary := summarizeAWSGADemoHardening(stages, filteredStages, filteredChecks)
	status, confidence := summarizeAWSGADemoHardeningStatus(filteredStages, filteredChecks)

	return AWSGADemoHardeningResult{
		TenantID:           scope.TenantID,
		WorkspaceID:        project.WorkspaceID,
		ProjectID:          project.ProjectID,
		ConnectorID:        connectorID,
		AccountID:          accountID,
		Region:             region,
		ParentIssueNumber:  awsPlatformDependencyParentIssue,
		ParentIssueRef:     awsIssueRef(awsPlatformDependencyParentIssue),
		CurrentIssueNumber: awsGADemoHardeningCurrentIssue,
		CurrentIssueRef:    awsIssueRef(awsGADemoHardeningCurrentIssue),
		Version:            awsGADemoHardeningVersion,
		Status:             status,
		FixtureState:       sourceFixtureState,
		Confidence:         confidence,
		CalculationVersion: awsGADemoHardeningVersion,
		AppliedFilters:     applied,
		Summary:            summary,
		Stages:             filteredStages,
		ReadinessChecks:    filteredChecks,
		Permissions:        awsGADemoHardeningPermissions(),
		SafetyNotes:        awsGADemoHardeningSafetyNotes(),
		Limitations:        awsGADemoHardeningLimitations(),
		Troubleshooting:    awsGADemoHardeningTroubleshooting(sources),
		Caveats:            awsGADemoHardeningCaveats(),
		FailureReasons:     awsGADemoHardeningFailureReasons(sources),
		RemediationHints:   awsGADemoHardeningRemediationHints(sources),
		EvidenceLinks:      awsGADemoHardeningEvidenceLinks(sources),
		GeneratedAt:        now,
		UpdatedAt:          now,
	}, nil
}

func validAWSGADemoHardeningFilter(request AWSGADemoHardeningRequest) bool {
	return validAWSPlatformObservabilityToken(request.Status, []string{awsPlatformDependencyStatusReady, awsPlatformDependencyStatusDegraded, awsPlatformDependencyStatusBlocked}) &&
		validAWSPlatformObservabilityToken(request.Stage, []string{"onboarding", "discovery", "agents", "runtime", "risk", "remediation", "approval", "verification", "governance", "reporting", "observability"})
}

func awsGADemoHardeningStages(s awsGADemoHardeningSources, accountID, region, tenantID, workspaceID, projectID string, now time.Time) []AWSGADemoHardeningStage {
	return []AWSGADemoHardeningStage{
		awsGADemoStage("onboarding", 1, "Onboarding and validation", "AWS connector setup and deterministic app/API validation fixtures are available for the operator walkthrough.", s.Validation.Status, s.Validation.Confidence, accountID, region, awsGADemoHardeningAppRoute(tenantID, workspaceID, projectID, "connect"), "aws-ga-demo://onboarding", s.Validation.EvidenceLinks, "Open connector diagnostics and run success, empty, degraded, and permission-denied fixtures.", firstAWSGADemoString(s.Validation.FailureReasons), now),
		awsGADemoStage("discovery", 2, "Discovery and graph", "Machine identities, resources, edges, impacted paths, and evidence refs are ready for graph drilldown.", s.Graph.Status, s.Graph.Confidence, accountID, region, awsGADemoHardeningAppRoute(tenantID, workspaceID, projectID, "graph"), "aws-ga-demo://discovery-graph", s.Graph.EvidenceLinks, "Review graph nodes, edges, runtime paths, PassRole paths, and evidence refs.", firstAWSGADemoString(s.Graph.FailureReasons), now),
		awsGADemoStage("agents", 3, "Agent identities", "Bedrock, AgentCore, gateway, capability, custom, and external provider agent identities are mapped without resolving secrets.", s.Agents.Status, s.Agents.Confidence, accountID, region, awsGADemoHardeningAppRoute(tenantID, workspaceID, projectID, "agents"), "aws-ga-demo://agent-identities", s.Agents.EvidenceLinks, "Open agent details to inspect provider, runtime role, tools, capability metadata, and credential-reference refs.", firstAWSGADemoString(s.Agents.FailureReasons), now),
		awsGADemoStage("runtime", 4, "Runtime evidence", "Runtime traces and platform lag signals show what roles and agents actually did across observed evidence sources.", s.Observability.Status, s.Observability.Confidence, accountID, region, awsGADemoHardeningAppRoute(tenantID, workspaceID, projectID, "runtime"), "aws-ga-demo://runtime-evidence", s.Observability.EvidenceLinks, "Use runtime and observability filters to confirm lag, throttling, and source diagnostics.", firstAWSGADemoString(s.Observability.FailureReasons), now),
		awsGADemoStage("risk", 5, "Risk and outcomes", "Executive outcome metrics summarize risk reduction, scan coverage, verified fixes, enforcement readiness, and remaining exposure.", s.Outcomes.Status, s.Outcomes.Confidence, accountID, region, awsGADemoHardeningAppRoute(tenantID, workspaceID, projectID, "outcomes"), "aws-ga-demo://risk-outcomes", s.Outcomes.EvidenceLinks, "Review outcome metrics and remaining exposure before reporting GA readiness.", firstAWSGADemoString(s.Outcomes.FailureReasons), now),
		awsGADemoStage("remediation", 6, "Remediation center", "Cases, approvals, dry-runs, live-action projections, verification, rollback, and audit trail rows are joined by case.", s.Remediation.Status, s.Remediation.Confidence, accountID, region, awsGADemoHardeningAppRoute(tenantID, workspaceID, projectID, "remediation/center"), "aws-ga-demo://remediation-center", s.Remediation.EvidenceLinks, "Assign owners and keep approvals, dry-runs, and verification evidence attached before closure.", firstAWSGADemoString(s.Remediation.FailureReasons), now),
		awsGADemoStage("approval", 7, "Approval and safety gates", "Approval, RBAC, feature-flag, dry-run, kill-switch, and rollback gates remain operator-visible before any execution layer.", s.Remediation.Status, s.Remediation.Confidence, accountID, region, awsGADemoHardeningAppRoute(tenantID, workspaceID, projectID, "remediation/center"), "aws-ga-demo://approval-safety", s.Remediation.EvidenceLinks, "Confirm approval and dry-run gates before treating a remediation as executable.", firstAWSGADemoString(s.Remediation.FailureReasons), now),
		awsGADemoStage("verification", 8, "Verification", "Post-remediation verification and rollback states are visible in remediation and observability signals.", s.Observability.Status, s.Observability.Confidence, accountID, region, awsGADemoHardeningAppRoute(tenantID, workspaceID, projectID, "observability"), "aws-ga-demo://verification", s.Observability.EvidenceLinks, "Investigate failed or rollback-planned verification outcomes before marking success.", firstAWSGADemoString(s.Observability.FailureReasons), now),
		awsGADemoStage("governance", 9, "Governance reporting", "Decision, approval, remediation, enforcement, exception, and audit metadata can be exported without payloads.", s.Governance.Status, s.Governance.Confidence, accountID, region, awsGADemoHardeningAppRoute(tenantID, workspaceID, projectID, "governance"), "aws-ga-demo://governance-reporting", s.Governance.EvidenceLinks, "Export governance rows and resolve exceptions before executive handoff.", firstAWSGADemoString(s.Governance.FailureReasons), now),
		awsGADemoStage("reporting", 10, "Executive handoff", "Leadership-ready coverage, risk, remediation, enforcement, governance, confidence, caveats, and evidence links are in one flow.", s.Outcomes.Status, s.Outcomes.Confidence, accountID, region, awsGADemoHardeningAppRoute(tenantID, workspaceID, projectID, "outcomes"), "aws-ga-demo://executive-handoff", s.Outcomes.EvidenceLinks, "Share outcome view together with permission, limitation, and troubleshooting docs.", firstAWSGADemoString(s.Outcomes.FailureReasons), now),
		awsGADemoStage("observability", 11, "GA operations", "Platform health metrics, traces, alerts, degraded states, and confidence handling are visible to operators.", s.Observability.Status, s.Observability.Confidence, accountID, region, awsGADemoHardeningAppRoute(tenantID, workspaceID, projectID, "observability"), "aws-ga-demo://ga-operations", s.Observability.EvidenceLinks, "Keep observability clear of critical alerts before GA handoff.", firstAWSGADemoString(s.Observability.FailureReasons), now),
	}
}

func awsGADemoHardeningAppRoute(tenantID string, workspaceID string, projectID string, suffix string) string {
	path := "aws"
	suffix = strings.Trim(strings.TrimSpace(suffix), "/")
	if suffix != "" {
		path += "/" + suffix
	}
	return fmt.Sprintf(
		"/app/%s/%s/%s?environment=%s",
		url.PathEscape(tenantID),
		url.PathEscape(workspaceID),
		path,
		url.QueryEscape(projectID),
	)
}

func awsGADemoStage(id string, order int, title, summary, status string, confidence float64, accountID, region, route, evidenceRef string, evidenceLinks []string, nextAction, failureReason string, now time.Time) AWSGADemoHardeningStage {
	return AWSGADemoHardeningStage{
		StageID:          id,
		Order:            order,
		Title:            title,
		Summary:          summary,
		Status:           awsGADemoHardeningStatus(status),
		Confidence:       confidence,
		AccountID:        accountID,
		Region:           region,
		PrimaryRoute:     route,
		EvidenceRef:      evidenceRef,
		EvidenceLinks:    evidenceLinks,
		EvidenceBoundary: awsGADemoHardeningBoundary,
		NextAction:       nextAction,
		FailureReason:    failureReason,
		UpdatedAt:        now,
	}
}

func filterAWSGADemoHardeningStages(stages []AWSGADemoHardeningStage, request AWSGADemoHardeningRequest) ([]AWSGADemoHardeningStage, map[string]string) {
	applied := map[string]string{}
	filtered := make([]AWSGADemoHardeningStage, 0, len(stages))
	matchToken := func(value, want string) bool {
		want = strings.ToLower(strings.TrimSpace(want))
		if want == "" || want == "all" {
			return true
		}
		return strings.ToLower(strings.TrimSpace(value)) == want
	}
	matchSearch := func(stage AWSGADemoHardeningStage) bool {
		search := strings.ToLower(strings.TrimSpace(request.Search))
		if search == "" {
			return true
		}
		return strings.Contains(strings.ToLower(strings.Join([]string{stage.StageID, stage.Title, stage.Summary, stage.Status, stage.EvidenceRef, stage.NextAction, stage.FailureReason}, " ")), search)
	}
	for _, stage := range stages {
		if !matchToken(stage.StageID, request.Stage) || !matchToken(stage.Status, request.Status) || !matchToken(stage.AccountID, request.AccountID) || !matchToken(stage.Region, request.Region) || !matchSearch(stage) {
			continue
		}
		filtered = append(filtered, stage)
	}
	setAppliedAWSExecutiveOutcomeFilter(applied, "connector_id", request.ConnectorID)
	setAppliedAWSExecutiveOutcomeFilter(applied, "fixture_state", request.FixtureState)
	setAppliedAWSExecutiveOutcomeFilter(applied, "account_id", request.AccountID)
	setAppliedAWSExecutiveOutcomeFilter(applied, "region", request.Region)
	setAppliedAWSExecutiveOutcomeFilter(applied, "stage", request.Stage)
	setAppliedAWSExecutiveOutcomeFilter(applied, "status", request.Status)
	setAppliedAWSExecutiveOutcomeFilter(applied, "search", request.Search)
	return filtered, applied
}

func filterAWSGADemoHardeningReadinessChecks(checks []AWSGADemoHardeningReadinessCheck, request AWSGADemoHardeningRequest) []AWSGADemoHardeningReadinessCheck {
	filtered := make([]AWSGADemoHardeningReadinessCheck, 0, len(checks))
	matchStatus := func(status string) bool {
		want := strings.ToLower(strings.TrimSpace(request.Status))
		if want == "" || want == "all" {
			return true
		}
		return strings.ToLower(strings.TrimSpace(status)) == want
	}
	matchSearch := func(check AWSGADemoHardeningReadinessCheck) bool {
		search := strings.ToLower(strings.TrimSpace(request.Search))
		if search == "" {
			return true
		}
		values := []string{
			check.CheckID,
			check.Title,
			check.Status,
			check.Owner,
			check.Summary,
			check.NextAction,
		}
		values = append(values, check.Evidence...)
		values = append(values, check.Permissions...)
		return strings.Contains(strings.ToLower(strings.Join(values, " ")), search)
	}
	for _, check := range checks {
		if !matchStatus(check.Status) || !matchSearch(check) {
			continue
		}
		filtered = append(filtered, check)
	}
	return filtered
}

func summarizeAWSGADemoHardening(all []AWSGADemoHardeningStage, filtered []AWSGADemoHardeningStage, checks []AWSGADemoHardeningReadinessCheck) AWSGADemoHardeningSummary {
	summary := AWSGADemoHardeningSummary{
		TotalStages:     len(all),
		FilteredStages:  len(filtered),
		ReadinessChecks: len(checks),
		StatusCounts:    map[string]int{},
		StageCounts:     map[string]int{},
	}
	for _, stage := range filtered {
		incrementCount(summary.StatusCounts, stage.Status)
		incrementCount(summary.StageCounts, stage.StageID)
		switch stage.Status {
		case awsPlatformDependencyStatusBlocked:
			summary.BlockedStages++
		case awsPlatformDependencyStatusDegraded:
			summary.DegradedStages++
		default:
			summary.ReadyStages++
		}
	}
	for _, check := range checks {
		if check.Required {
			summary.RequiredChecks++
		}
		switch check.Status {
		case awsPlatformDependencyStatusBlocked:
			summary.FailedChecks++
		case awsPlatformDependencyStatusDegraded:
			summary.PermissionWarnings++
		default:
			summary.PassedChecks++
		}
	}
	return summary
}

func summarizeAWSGADemoHardeningStatus(stages []AWSGADemoHardeningStage, checks []AWSGADemoHardeningReadinessCheck) (string, float64) {
	if len(stages) == 0 {
		return awsPlatformDependencyStatusBlocked, 0.4
	}
	status := awsPlatformDependencyStatusReady
	confidences := make([]float64, 0, len(stages)+len(checks))
	for _, stage := range stages {
		confidences = append(confidences, stage.Confidence)
		if stage.Status == awsPlatformDependencyStatusBlocked {
			status = awsPlatformDependencyStatusBlocked
		} else if stage.Status == awsPlatformDependencyStatusDegraded && status == awsPlatformDependencyStatusReady {
			status = awsPlatformDependencyStatusDegraded
		}
	}
	for _, check := range checks {
		if check.Required && check.Status == awsPlatformDependencyStatusBlocked {
			status = awsPlatformDependencyStatusBlocked
		} else if check.Status == awsPlatformDependencyStatusDegraded && status == awsPlatformDependencyStatusReady {
			status = awsPlatformDependencyStatusDegraded
		}
	}
	return status, averageFloat64(confidences...)
}

func awsGADemoHardeningReadinessChecks(s awsGADemoHardeningSources) []AWSGADemoHardeningReadinessCheck {
	return []AWSGADemoHardeningReadinessCheck{
		{CheckID: "validation-fixtures", Title: "App and API fixtures", Status: awsGADemoHardeningStatus(s.Validation.Status), Owner: "platform", Summary: "Success, empty, degraded, partial-failure, permission-denied, and unsupported-service scenarios are documented for app validation.", Evidence: s.Validation.EvidenceLinks, NextAction: "Run the validation harness before merging GA-facing AWS changes.", Required: true},
		{CheckID: "read-only-boundary", Title: "Read-only safety boundary", Status: awsPlatformDependencyStatusReady, Owner: "security", Summary: "The GA demo composes metadata-only evidence and does not call AWS write APIs.", Evidence: []string{"/docs/aws-ga-demo-hardening", "/docs/aws-platform-baseline"}, NextAction: "Keep remediation execution behind approval and safety-gated endpoints.", Required: true},
		{CheckID: "permission-docs", Title: "Permission documentation", Status: awsPlatformDependencyStatusReady, Owner: "security", Summary: "Prerequisites list IAM read APIs and explicitly excludes secret values, prompts, completions, browser pages, database rows, object contents, and customer payloads.", Evidence: []string{"/docs/aws-ga-demo-hardening", "/docs/aws-service-collector-contract"}, NextAction: "Attach permission docs to onboarding and handoff material.", Required: true, Permissions: awsGADemoHardeningPermissions()},
		{CheckID: "source-confidence", Title: "Source confidence", Status: awsGADemoHardeningStatus(s.Observability.Status), Owner: "operations", Summary: "Platform observability carries confidence, trace, degraded, and alert state for GA checks.", Evidence: s.Observability.EvidenceLinks, NextAction: "Clear blocked observability signals before marking GA-ready.", Required: true},
		{CheckID: "governance-export", Title: "Governance export", Status: awsGADemoHardeningStatus(s.Governance.Status), Owner: "governance", Summary: "Governance reporting exposes export-safe decision, approval, remediation, enforcement, exception, and audit metadata.", Evidence: s.Governance.EvidenceLinks, NextAction: "Resolve governance exceptions before executive handoff.", Required: false},
	}
}

func awsGADemoHardeningStatus(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case awsPlatformDependencyStatusReady:
		return awsPlatformDependencyStatusReady
	case awsPlatformDependencyStatusBlocked, "permission_denied":
		return awsPlatformDependencyStatusBlocked
	case awsPlatformDependencyStatusDegraded, "partial_failure":
		return awsPlatformDependencyStatusDegraded
	default:
		return awsPlatformDependencyStatusDegraded
	}
}

func awsGADemoHardeningEvidenceLinks(s awsGADemoHardeningSources) []string {
	links := []string{
		awsIssueURL(awsPlatformDependencyParentIssue),
		awsIssueURL(awsGADemoHardeningCurrentIssue),
		"/docs/aws-ga-demo-hardening",
		"/docs/aws-platform-baseline",
		"/docs/aws-platform-validation-harness",
		"/docs/aws-service-collector-contract",
	}
	links = append(links, s.Validation.EvidenceLinks...)
	links = append(links, s.Agents.EvidenceLinks...)
	links = append(links, s.Graph.EvidenceLinks...)
	links = append(links, s.Remediation.EvidenceLinks...)
	links = append(links, s.Governance.EvidenceLinks...)
	links = append(links, s.Outcomes.EvidenceLinks...)
	links = append(links, s.Observability.EvidenceLinks...)
	return dedupeStrings(links)
}

func awsGADemoHardeningFailureReasons(s awsGADemoHardeningSources) []string {
	reasons := []string{}
	reasons = append(reasons, s.Validation.FailureReasons...)
	reasons = append(reasons, s.Agents.FailureReasons...)
	reasons = append(reasons, s.Graph.FailureReasons...)
	reasons = append(reasons, s.Remediation.FailureReasons...)
	reasons = append(reasons, s.Governance.FailureReasons...)
	reasons = append(reasons, s.Outcomes.FailureReasons...)
	reasons = append(reasons, s.Observability.FailureReasons...)
	return dedupeStrings(reasons)
}

func awsGADemoHardeningRemediationHints(s awsGADemoHardeningSources) []string {
	hints := []string{}
	hints = append(hints, s.Validation.RemediationHints...)
	hints = append(hints, s.Agents.RemediationHints...)
	hints = append(hints, s.Graph.RemediationHints...)
	hints = append(hints, s.Remediation.RemediationHints...)
	hints = append(hints, s.Governance.RemediationHints...)
	hints = append(hints, s.Outcomes.RemediationHints...)
	hints = append(hints, s.Observability.RemediationHints...)
	return dedupeStrings(hints)
}

func awsGADemoHardeningTroubleshooting(s awsGADemoHardeningSources) []string {
	items := []string{
		"If onboarding is blocked, verify the connector role ARN, external ID, account ID, and region in the AWS connection diagnostics.",
		"If discovery is empty, run the validation harness with empty and degraded fixtures before treating missing rows as success.",
		"If remediation or governance is degraded, inspect case approvals, dry-run outcomes, verification states, and governance exceptions.",
		"If observability is degraded, review queue lag, throttling, collector failures, runtime lag, and verification alerts.",
	}
	items = append(items, awsGADemoHardeningFailureReasons(s)...)
	return dedupeStrings(items)
}

func awsGADemoHardeningPermissions() []string {
	return []string{
		"sts:GetCallerIdentity",
		"iam:GetRole",
		"iam:ListRoles",
		"iam:GetPolicy",
		"iam:GetPolicyVersion",
		"iam:ListAttachedRolePolicies",
		"iam:ListRolePolicies",
		"iam:GetRolePolicy",
		"access-analyzer:ListAnalyzers",
		"access-analyzer:ListFindings",
		"cloudtrail:LookupEvents",
		"organizations:ListAccounts",
		"organizations:ListRoots",
		"organizations:ListOrganizationalUnitsForParent",
		"lambda:ListFunctions",
		"ecs:ListClusters",
		"ecs:ListServices",
		"eks:ListClusters",
		"secretsmanager:ListSecrets",
		"kms:ListKeys",
		"s3:ListAllMyBuckets",
	}
}

func awsGADemoHardeningSafetyNotes() []string {
	return []string{
		"Read-only: this endpoint does not mutate AWS IAM, resource policies, permission boundaries, SCPs, secrets, objects, queues, databases, agents, or Identrail governance state.",
		"Metadata-only: secret values, prompts, completions, browser pages, code-interpreter output, database rows, object contents, and customer payloads are never returned.",
		"Tenant/workspace/project/connector/account/region boundaries are preserved by the same scoped services used by the underlying AWS surfaces.",
		"Remediation and enforcement remain projections unless a downstream, approved, safety-gated execution endpoint is explicitly invoked.",
	}
}

func awsGADemoHardeningLimitations() []string {
	return []string{
		"The GA demo reflects the evidence available to the configured connector and fixture state; it does not prove coverage for services outside the configured collector contracts.",
		"Permission-denied and degraded states are first-class outputs, not successful collection results.",
		"Executive and governance metrics are derived from existing metadata-only source contracts and should be interpreted with their attached confidence and caveats.",
	}
}

func awsGADemoHardeningCaveats() []string {
	return []string{
		"GA readiness depends on current connector permissions, source freshness, and unresolved degraded or blocked stage state.",
		"Evidence links point to Identrail routes and documentation, not raw AWS customer payloads.",
	}
}

func firstAWSGADemoString(values []string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
