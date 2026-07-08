package api

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/identrail/identrail/internal/db"
)

const (
	awsRemediationCenterCurrentIssue = 1552
	awsRemediationCenterVersion      = "aws-remediation-center-v1"
	awsRemediationCenterPolicyID     = "aws-remediation-center-policy-v1"

	// Lifecycle stages a case can reach, ordered from earliest to latest.
	awsRemediationCenterStageCase         = "case"
	awsRemediationCenterStageApproval     = "approval"
	awsRemediationCenterStageDryRun       = "dry_run"
	awsRemediationCenterStageLiveAction   = "live_action"
	awsRemediationCenterStageVerification = "verification"
	awsRemediationCenterStageRollback     = "rollback"
)

// AWSRemediationCenterRequest scopes the unified remediation center to one AWS
// connector plus the operator drill-down filters shared across the remediation
// lifecycle (severity, confidence, account, identity type, action type, status).
type AWSRemediationCenterRequest struct {
	ConnectorID  string `json:"connector_id,omitempty"`
	FixtureState string `json:"fixture_state,omitempty"`
	AccountID    string `json:"account_id,omitempty"`
	Region       string `json:"region,omitempty"`
	Severity     string `json:"severity,omitempty"`
	Confidence   string `json:"confidence,omitempty"`
	IdentityType string `json:"identity_type,omitempty"`
	ActionType   string `json:"action_type,omitempty"`
	Status       string `json:"status,omitempty"`
	Stage        string `json:"stage,omitempty"`
	CaseID       string `json:"case_id,omitempty"`
	Tab          string `json:"tab,omitempty"`
	Search       string `json:"search,omitempty"`
}

// Reuse the shared detail-page shapes so the remediation center's tabs,
// diagnostics, and coverage-gap contracts stay consistent with the rest of
// the Wave 10 app surface.
type AWSRemediationCenterTab = AWSMachineIdentityDetailTab
type AWSRemediationCenterDiagnostic = AWSMachineIdentityDetailDiagnostic
type AWSRemediationCenterCoverageGap = AWSMachineIdentityDetailCoverageGap

// AWSRemediationCenterSafetyGate is one consolidated safety gate an operator
// must clear before a case advances. Gates are gathered across the approval
// (RBAC + feature flags), dry-run (prerequisites), and verification
// (preconditions) stages so the "safety gates before action" summary is a
// single list.
type AWSRemediationCenterSafetyGate struct {
	Source    string `json:"source"`
	Name      string `json:"name"`
	Status    string `json:"status"`
	Rationale string `json:"rationale,omitempty"`
}

// AWSRemediationCenterCase is one case-keyed rollup across the remediation
// lifecycle. It stitches the case, its approval-queue entry, dry-run, live
// action, and verification/rollback record into a single row so operators can
// see where each fix is without reading every stage table. It is
// metadata-only and never carries rendered policy bodies or secret values.
type AWSRemediationCenterCase struct {
	CaseID                 string                           `json:"case_id"`
	Title                  string                           `json:"title"`
	Summary                string                           `json:"summary"`
	SourceType             string                           `json:"source_type"`
	ActionType             string                           `json:"action_type"`
	Lifecycle              string                           `json:"lifecycle"`
	Stage                  string                           `json:"stage"`
	Severity               string                           `json:"severity"`
	Score                  int                              `json:"score"`
	Confidence             float64                          `json:"confidence"`
	AccountID              string                           `json:"account_id,omitempty"`
	TargetAccountIDs       []string                         `json:"target_account_ids,omitempty"`
	Region                 string                           `json:"region,omitempty"`
	IdentityNodeID         string                           `json:"identity_node_id,omitempty"`
	IdentityName           string                           `json:"identity_name,omitempty"`
	IdentityType           string                           `json:"identity_type,omitempty"`
	Owner                  string                           `json:"owner,omitempty"`
	OwnerAssigned          bool                             `json:"owner_assigned"`
	ApprovalRequired       bool                             `json:"approval_required"`
	ApprovalState          string                           `json:"approval_state,omitempty"`
	ApprovalID             string                           `json:"approval_id,omitempty"`
	DryRunID               string                           `json:"dry_run_id,omitempty"`
	DryRunOutcome          string                           `json:"dry_run_outcome,omitempty"`
	ExecutionID            string                           `json:"execution_id,omitempty"`
	ExecutionState         string                           `json:"execution_state,omitempty"`
	VerificationID         string                           `json:"verification_id,omitempty"`
	VerificationState      string                           `json:"verification_state,omitempty"`
	VerificationEntryCount int                              `json:"verification_entry_count,omitempty"`
	VerificationStates     []string                         `json:"verification_states,omitempty"`
	RollbackState          string                           `json:"rollback_state,omitempty"`
	RollbackStrategy       string                           `json:"rollback_strategy,omitempty"`
	ReadyForApply          bool                             `json:"ready_for_apply"`
	KillSwitchEngaged      bool                             `json:"kill_switch_engaged"`
	Tradeoffs              []AWSRemediationTradeoff         `json:"tradeoffs"`
	SafetyGates            []AWSRemediationCenterSafetyGate `json:"safety_gates"`
	NextAction             string                           `json:"next_action"`
	EvidenceRefs           []string                         `json:"evidence_refs,omitempty"`
	EvidenceBoundary       string                           `json:"evidence_boundary"`
	AuditTrail             []AWSRemediationCenterAuditEntry `json:"audit_trail"`
	AuditEntryCount        int                              `json:"audit_entry_count"`
	UpdatedAt              time.Time                        `json:"updated_at,omitzero"`

	nonVerificationKillSwitchEngaged bool
	verificationKillSwitchEngaged    bool
}

// AWSRemediationCenterAuditEntry is one immutable audit record projected from a
// lifecycle stage (case, approval, dry-run, live action, or verification) and
// tagged with the case it belongs to plus the stage that produced it, so the
// audit tab consolidates the whole lifecycle rather than only verification. It
// is metadata-only.
type AWSRemediationCenterAuditEntry struct {
	CaseID      string    `json:"case_id"`
	Stage       string    `json:"stage"`
	EventID     string    `json:"event_id"`
	EventType   string    `json:"event_type"`
	Actor       string    `json:"actor"`
	OccurredAt  time.Time `json:"occurred_at"`
	EvidenceRef string    `json:"evidence_ref,omitempty"`
	Notes       string    `json:"notes,omitempty"`
}

// AWSRemediationCenterSummary aggregates the unfiltered and filtered case set
// plus lifecycle-stage and safety rollups.
type AWSRemediationCenterSummary struct {
	TotalCases           int            `json:"total_cases"`
	FilteredCases        int            `json:"filtered_cases"`
	StageCounts          map[string]int `json:"stage_counts"`
	SeverityCounts       map[string]int `json:"severity_counts"`
	StatusCounts         map[string]int `json:"status_counts"`
	ActionTypeCounts     map[string]int `json:"action_type_counts"`
	IdentityTypeCounts   map[string]int `json:"identity_type_counts"`
	ApprovalPendingCount int            `json:"approval_pending_count"`
	DryRunCount          int            `json:"dry_run_count"`
	LiveActionCount      int            `json:"live_action_count"`
	VerificationCount    int            `json:"verification_count"`
	RollbackCount        int            `json:"rollback_count"`
	ReadyForApplyCount   int            `json:"ready_for_apply_count"`
	KillSwitchCount      int            `json:"kill_switch_engaged_count"`
	BlockedGateCount     int            `json:"blocked_safety_gate_count"`
	AuditEntryCount      int            `json:"audit_entry_count"`
	HighestScore         int            `json:"highest_score"`
	AverageConfidencePct int            `json:"average_confidence_pct"`
}

// AWSRemediationCenterResult is the deterministic unified-center envelope. It
// embeds the underlying stage results so the app tabs can render full stage
// tables, mirroring the Wave 10 detail-page pattern.
type AWSRemediationCenterResult struct {
	TenantID           string                               `json:"tenant_id"`
	WorkspaceID        string                               `json:"workspace_id"`
	ProjectID          string                               `json:"project_id"`
	ConnectorID        string                               `json:"connector_id,omitempty"`
	AccountID          string                               `json:"account_id,omitempty"`
	Region             string                               `json:"region,omitempty"`
	ParentIssueNumber  int                                  `json:"parent_issue_number"`
	ParentIssueRef     string                               `json:"parent_issue_ref"`
	CurrentIssueNumber int                                  `json:"current_issue_number"`
	CurrentIssueRef    string                               `json:"current_issue_ref"`
	Version            string                               `json:"version"`
	Status             string                               `json:"status"`
	FixtureState       string                               `json:"fixture_state,omitempty"`
	Confidence         float64                              `json:"confidence"`
	PolicyVersion      string                               `json:"policy_version"`
	AppliedFilters     map[string]string                    `json:"applied_filters"`
	Summary            AWSRemediationCenterSummary          `json:"summary"`
	Tabs               []AWSRemediationCenterTab            `json:"tabs"`
	Cases              []AWSRemediationCenterCase           `json:"cases"`
	RemediationCases   AWSRemediationCaseResult             `json:"remediation_cases"`
	ApprovalQueue      AWSRemediationApprovalResult         `json:"approval_queue"`
	DryRuns            AWSRemediationDryRunResult           `json:"dry_runs"`
	LiveActions        AWSLowRiskRemediationResult          `json:"live_actions"`
	Verification       AWSPostRemediationVerificationResult `json:"verification"`
	AuditTrail         []AWSRemediationCenterAuditEntry     `json:"audit_trail"`
	FailureReasons     []string                             `json:"failure_reasons"`
	RemediationHints   []string                             `json:"remediation_hints"`
	EvidenceLinks      []string                             `json:"evidence_links"`
	CoverageGaps       []AWSRemediationCenterCoverageGap    `json:"coverage_gaps"`
	Diagnostics        []AWSRemediationCenterDiagnostic     `json:"diagnostics"`
	GeneratedAt        time.Time                            `json:"generated_at"`
	UpdatedAt          time.Time                            `json:"updated_at"`
}

// GetAWSRemediationCenter composes the unified operator remediation center by
// joining the remediation case engine (#1529), approval queue (#1536), dry-run
// executor (#1537), low-risk live remediation (#1538), and post-remediation
// verification/rollback (#1542) into one case-keyed lifecycle view. It is
// read-only: it never mutates AWS, never reads secret values or workload
// payloads, and surfaces unknown/permission-denied/degraded states explicitly.
func (s *Service) GetAWSRemediationCenter(ctx context.Context, workspaceID string, projectID string, request AWSRemediationCenterRequest) (AWSRemediationCenterResult, error) {
	project, scope, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return AWSRemediationCenterResult{}, err
	}
	connection, hasConnection, err := s.awsBaselineConnection(ctx, project, strings.TrimSpace(request.ConnectorID))
	if err != nil {
		return AWSRemediationCenterResult{}, err
	}
	now := s.Now().UTC()
	fixtureState := normalizeAWSRemediationCenterFixtureState(request.FixtureState, connection, hasConnection)
	if fixtureState == "" {
		return AWSRemediationCenterResult{}, ErrInvalidAWSConnectionRequest
	}
	sourceFixtureState := fixtureState
	if strings.TrimSpace(request.FixtureState) == "" && hasConnection && connection.Connected {
		sourceFixtureState = ""
	}
	accountID := firstNonEmptyAWSValue(connection.AccountID, strings.TrimSpace(request.AccountID), "123456789012")
	region := firstNonEmptyAWSValue(connection.Region, strings.TrimSpace(request.Region), "us-east-1")
	connectorID := firstNonEmptyAWSValue(connection.ConnectorID, strings.TrimSpace(request.ConnectorID))
	if !hasConnection && sourceFixtureState == "permission_denied" {
		return awsRemediationCenterNoConnectorResult(scope, project, request, connectorID, accountID, region, sourceFixtureState, now), nil
	}

	cases, err := s.GetAWSRemediationCases(ctx, workspaceID, projectID, AWSRemediationCaseRequest{
		ConnectorID:  connectorID,
		FixtureState: sourceFixtureState,
	})
	if err != nil {
		return AWSRemediationCenterResult{}, fmt.Errorf("remediation center cases: %w", err)
	}
	approvals, err := s.GetAWSRemediationApprovalQueue(ctx, workspaceID, projectID, AWSRemediationApprovalRequest{
		ConnectorID:  connectorID,
		FixtureState: sourceFixtureState,
	})
	if err != nil {
		return AWSRemediationCenterResult{}, fmt.Errorf("remediation center approvals: %w", err)
	}
	dryRuns, err := s.GetAWSRemediationDryRun(ctx, workspaceID, projectID, AWSRemediationDryRunRequest{
		ConnectorID:  connectorID,
		FixtureState: sourceFixtureState,
	})
	if err != nil {
		return AWSRemediationCenterResult{}, fmt.Errorf("remediation center dry runs: %w", err)
	}
	liveActions, err := s.GetAWSLowRiskRemediation(ctx, workspaceID, projectID, AWSLowRiskRemediationRequest{
		ConnectorID:  connectorID,
		FixtureState: sourceFixtureState,
	})
	if err != nil {
		return AWSRemediationCenterResult{}, fmt.Errorf("remediation center live actions: %w", err)
	}
	verification, err := s.GetAWSPostRemediationVerification(ctx, workspaceID, projectID, AWSPostRemediationVerificationRequest{
		ConnectorID:  connectorID,
		FixtureState: sourceFixtureState,
	})
	if err != nil {
		return AWSRemediationCenterResult{}, fmt.Errorf("remediation center verification: %w", err)
	}

	centerCases := awsRemediationCenterCases(cases, approvals, dryRuns, liveActions, verification)
	sort.SliceStable(centerCases, func(i, j int) bool {
		if centerCases[i].Score == centerCases[j].Score {
			return centerCases[i].CaseID < centerCases[j].CaseID
		}
		return centerCases[i].Score > centerCases[j].Score
	})
	filtered, applied := filterAWSRemediationCenterCases(centerCases, request)
	stageDeferred := awsRemediationCenterShouldDeferStageFilter(applied)
	statusDeferred := awsRemediationCenterShouldDeferStatusFilter(applied)
	diagnostics := awsRemediationCenterDiagnostics(cases, approvals, dryRuns, liveActions, verification)
	coverageGaps := awsRemediationCenterCoverageGaps(cases, verification)
	evidenceLinks := awsRemediationCenterEvidenceLinks(scope, project, cases, approvals, dryRuns, liveActions, verification)
	status, confidence := summarizeAWSRemediationCenterStatus(fixtureState, cases, approvals, dryRuns, liveActions, verification, diagnostics)

	// Scope the embedded lifecycle payloads (rendered directly by the app tabs)
	// and the consolidated audit trail to the filtered case set, so a filtered
	// deep link never surfaces rows from cases that fell outside the filter.
	// Diagnostics, status, and evidence links stay on the full source results
	// because they report collector health across the whole connector scope.
	scopedCaseIDs := awsRemediationCenterCaseIDSet(filtered)
	allApprovalEntries, allDryRunEntries, allLiveActionEntries, allVerificationEntries := approvals.Entries, dryRuns.Entries, liveActions.Entries, verification.Entries
	approvals.Entries = awsRemediationCenterScopeEntries(approvals.Entries, scopedCaseIDs, func(e AWSRemediationApprovalEntry) string { return e.CaseID })
	approvals.Relationships = awsRemediationCenterScopeEntries(approvals.Relationships, awsRemediationCenterStringSet(approvals.Entries, func(e AWSRemediationApprovalEntry) string { return e.ApprovalID }), func(r AWSRemediationApprovalRelationship) string { return r.ApprovalID })
	approvals.Summary = summarizeAWSRemediationApprovalEntries(allApprovalEntries, approvals.Entries, approvals.Relationships)
	dryRuns.Entries = awsRemediationCenterScopeEntries(dryRuns.Entries, scopedCaseIDs, func(e AWSRemediationDryRunEntry) string { return e.CaseID })
	dryRuns.Relationships = awsRemediationCenterScopeEntries(dryRuns.Relationships, awsRemediationCenterStringSet(dryRuns.Entries, func(e AWSRemediationDryRunEntry) string { return e.DryRunID }), func(r AWSRemediationDryRunRelationship) string { return r.DryRunID })
	dryRuns.Summary = summarizeAWSRemediationDryRunEntries(allDryRunEntries, dryRuns.Entries, dryRuns.Relationships)
	liveActions.Entries = awsRemediationCenterScopeEntries(liveActions.Entries, scopedCaseIDs, func(e AWSLowRiskRemediationEntry) string { return e.CaseID })
	liveActions.Relationships = awsRemediationCenterScopeEntries(liveActions.Relationships, awsRemediationCenterStringSet(liveActions.Entries, func(e AWSLowRiskRemediationEntry) string { return e.ExecutionID }), func(r AWSLowRiskRemediationRelationship) string { return r.ExecutionID })
	liveActions.Summary = summarizeAWSLowRiskRemediationEntries(allLiveActionEntries, liveActions.Entries, liveActions.Relationships)
	verification.Entries = awsRemediationCenterScopeVerificationEntries(verification.Entries, scopedCaseIDs, filtered, applied["status"], applied["account_id"])
	verification.Relationships = awsRemediationCenterScopeEntries(verification.Relationships, awsRemediationCenterStringSet(verification.Entries, func(e AWSPostRemediationVerificationEntry) string { return e.VerificationID }), func(r AWSPostRemediationVerificationRelationship) string { return r.VerificationID })
	verification.Summary = summarizeAWSPostRemediationVerificationEntries(allVerificationEntries, verification.Entries, verification.Relationships)
	filtered = awsRemediationCenterCasesWithScopedVerificationRows(filtered, verification.Entries, applied["status"], applied["stage"])
	if stageDeferred || statusDeferred {
		scopedCaseIDs = awsRemediationCenterCaseIDSet(filtered)
		approvals.Entries = awsRemediationCenterScopeEntries(approvals.Entries, scopedCaseIDs, func(e AWSRemediationApprovalEntry) string { return e.CaseID })
		approvals.Relationships = awsRemediationCenterScopeEntries(approvals.Relationships, awsRemediationCenterStringSet(approvals.Entries, func(e AWSRemediationApprovalEntry) string { return e.ApprovalID }), func(r AWSRemediationApprovalRelationship) string { return r.ApprovalID })
		approvals.Summary = summarizeAWSRemediationApprovalEntries(allApprovalEntries, approvals.Entries, approvals.Relationships)
		dryRuns.Entries = awsRemediationCenterScopeEntries(dryRuns.Entries, scopedCaseIDs, func(e AWSRemediationDryRunEntry) string { return e.CaseID })
		dryRuns.Relationships = awsRemediationCenterScopeEntries(dryRuns.Relationships, awsRemediationCenterStringSet(dryRuns.Entries, func(e AWSRemediationDryRunEntry) string { return e.DryRunID }), func(r AWSRemediationDryRunRelationship) string { return r.DryRunID })
		dryRuns.Summary = summarizeAWSRemediationDryRunEntries(allDryRunEntries, dryRuns.Entries, dryRuns.Relationships)
		liveActions.Entries = awsRemediationCenterScopeEntries(liveActions.Entries, scopedCaseIDs, func(e AWSLowRiskRemediationEntry) string { return e.CaseID })
		liveActions.Relationships = awsRemediationCenterScopeEntries(liveActions.Relationships, awsRemediationCenterStringSet(liveActions.Entries, func(e AWSLowRiskRemediationEntry) string { return e.ExecutionID }), func(r AWSLowRiskRemediationRelationship) string { return r.ExecutionID })
		liveActions.Summary = summarizeAWSLowRiskRemediationEntries(allLiveActionEntries, liveActions.Entries, liveActions.Relationships)
		verification.Entries = awsRemediationCenterScopeEntries(verification.Entries, scopedCaseIDs, func(e AWSPostRemediationVerificationEntry) string { return e.CaseID })
		verification.Relationships = awsRemediationCenterScopeEntries(verification.Relationships, awsRemediationCenterStringSet(verification.Entries, func(e AWSPostRemediationVerificationEntry) string { return e.VerificationID }), func(r AWSPostRemediationVerificationRelationship) string { return r.VerificationID })
		verification.Summary = summarizeAWSPostRemediationVerificationEntries(allVerificationEntries, verification.Entries, verification.Relationships)
	}
	summary := summarizeAWSRemediationCenterCases(centerCases, filtered)
	auditTrail := awsRemediationCenterAuditTrail(filtered)

	return AWSRemediationCenterResult{
		TenantID:           scope.TenantID,
		WorkspaceID:        project.WorkspaceID,
		ProjectID:          project.ProjectID,
		ConnectorID:        connectorID,
		AccountID:          accountID,
		Region:             region,
		ParentIssueNumber:  awsPlatformDependencyParentIssue,
		ParentIssueRef:     awsIssueRef(awsPlatformDependencyParentIssue),
		CurrentIssueNumber: awsRemediationCenterCurrentIssue,
		CurrentIssueRef:    awsIssueRef(awsRemediationCenterCurrentIssue),
		Version:            awsRemediationCenterVersion,
		Status:             status,
		FixtureState:       fixtureState,
		Confidence:         confidence,
		PolicyVersion:      awsRemediationCenterPolicyID,
		AppliedFilters:     applied,
		Summary:            summary,
		Tabs:               awsRemediationCenterTabs(summary, status, len(approvals.Entries)),
		Cases:              filtered,
		RemediationCases:   cases,
		ApprovalQueue:      approvals,
		DryRuns:            dryRuns,
		LiveActions:        liveActions,
		Verification:       verification,
		AuditTrail:         auditTrail,
		FailureReasons:     awsRemediationCenterFailureReasons(cases, approvals, dryRuns, liveActions, verification),
		RemediationHints:   awsRemediationCenterRemediationHints(cases, approvals, dryRuns, liveActions, verification),
		EvidenceLinks:      evidenceLinks,
		CoverageGaps:       coverageGaps,
		Diagnostics:        diagnostics,
		GeneratedAt:        now,
		UpdatedAt:          now,
	}, nil
}

func awsRemediationCenterNoConnectorResult(scope db.Scope, project db.TenancyProject, request AWSRemediationCenterRequest, connectorID, accountID, region, fixtureState string, now time.Time) AWSRemediationCenterResult {
	status := "permission_denied"
	confidence := 0.2
	filtered, applied := filterAWSRemediationCenterCases(nil, request)
	summary := summarizeAWSRemediationCenterCases(nil, filtered)
	failureReasons := []string{"AWS access is unavailable because this project has no AWS connector."}
	remediationHints := []string{"Connect an AWS connector before viewing remediation lifecycle evidence."}
	cases := AWSRemediationCaseResult{
		TenantID:           scope.TenantID,
		WorkspaceID:        project.WorkspaceID,
		ProjectID:          project.ProjectID,
		ConnectorID:        connectorID,
		AccountID:          accountID,
		Region:             region,
		ParentIssueNumber:  awsPlatformDependencyParentIssue,
		ParentIssueRef:     awsIssueRef(awsPlatformDependencyParentIssue),
		CurrentIssueNumber: awsRemediationCaseCurrentIssue,
		CurrentIssueRef:    awsIssueRef(awsRemediationCaseCurrentIssue),
		Version:            awsRemediationCaseVersion,
		Status:             status,
		FixtureState:       fixtureState,
		Confidence:         confidence,
		CalculationVersion: awsRemediationCaseVersion,
		AppliedFilters:     map[string]string{},
		Summary:            summarizeAWSRemediationCases(nil, nil, nil),
		Caveats:            awsRemediationCaseCaveats(),
		FailureReasons:     failureReasons,
		RemediationHints:   remediationHints,
		EvidenceLinks: dedupeStrings([]string{
			awsIssueURL(awsPlatformDependencyParentIssue),
			awsIssueURL(awsRemediationCaseCurrentIssue),
			"/docs/aws-remediation-case-model",
			awsBaselineProjectEvidenceURL(scope, project),
		}),
		GeneratedAt: now,
		UpdatedAt:   now,
	}
	approvals := AWSRemediationApprovalResult{
		TenantID:           scope.TenantID,
		WorkspaceID:        project.WorkspaceID,
		ProjectID:          project.ProjectID,
		ConnectorID:        connectorID,
		AccountID:          accountID,
		Region:             region,
		ParentIssueNumber:  awsPlatformDependencyParentIssue,
		ParentIssueRef:     awsIssueRef(awsPlatformDependencyParentIssue),
		CurrentIssueNumber: awsRemediationApprovalCurrentIssue,
		CurrentIssueRef:    awsIssueRef(awsRemediationApprovalCurrentIssue),
		Version:            awsRemediationApprovalVersion,
		Status:             status,
		FixtureState:       fixtureState,
		Confidence:         confidence,
		CalculationVersion: awsRemediationApprovalVersion,
		AppliedFilters:     map[string]string{},
		Summary:            summarizeAWSRemediationApprovalEntries(nil, nil, nil),
		Caveats:            awsRemediationApprovalCaveats(),
		FailureReasons:     failureReasons,
		RemediationHints:   remediationHints,
		EvidenceLinks: dedupeStrings([]string{
			awsIssueURL(awsPlatformDependencyParentIssue),
			awsIssueURL(awsRemediationApprovalCurrentIssue),
			awsIssueURL(awsRemediationCaseCurrentIssue),
			"/docs/aws-remediation-approval-rbac",
			awsBaselineProjectEvidenceURL(scope, project),
		}),
		GeneratedAt: now,
		UpdatedAt:   now,
	}
	dryRuns := AWSRemediationDryRunResult{
		TenantID:           scope.TenantID,
		WorkspaceID:        project.WorkspaceID,
		ProjectID:          project.ProjectID,
		ConnectorID:        connectorID,
		AccountID:          accountID,
		Region:             region,
		ParentIssueNumber:  awsPlatformDependencyParentIssue,
		ParentIssueRef:     awsIssueRef(awsPlatformDependencyParentIssue),
		CurrentIssueNumber: awsRemediationDryRunCurrentIssue,
		CurrentIssueRef:    awsIssueRef(awsRemediationDryRunCurrentIssue),
		Version:            awsRemediationDryRunVersion,
		Status:             status,
		FixtureState:       fixtureState,
		Confidence:         confidence,
		CalculationVersion: awsRemediationDryRunVersion,
		AppliedFilters:     map[string]string{},
		Summary:            summarizeAWSRemediationDryRunEntries(nil, nil, nil),
		Caveats:            awsRemediationDryRunCaveats(),
		FailureReasons:     failureReasons,
		RemediationHints:   remediationHints,
		EvidenceLinks: dedupeStrings([]string{
			awsIssueURL(awsPlatformDependencyParentIssue),
			awsIssueURL(awsRemediationDryRunCurrentIssue),
			awsIssueURL(awsRemediationApprovalCurrentIssue),
			"/docs/aws-remediation-dry-run-executor",
			awsBaselineProjectEvidenceURL(scope, project),
		}),
		GeneratedAt: now,
		UpdatedAt:   now,
	}
	liveActions := AWSLowRiskRemediationResult{
		TenantID:           scope.TenantID,
		WorkspaceID:        project.WorkspaceID,
		ProjectID:          project.ProjectID,
		ConnectorID:        connectorID,
		AccountID:          accountID,
		Region:             region,
		ParentIssueNumber:  awsPlatformDependencyParentIssue,
		ParentIssueRef:     awsIssueRef(awsPlatformDependencyParentIssue),
		CurrentIssueNumber: awsLowRiskRemediationCurrentIssue,
		CurrentIssueRef:    awsIssueRef(awsLowRiskRemediationCurrentIssue),
		Version:            awsLowRiskRemediationVersion,
		Status:             status,
		FixtureState:       fixtureState,
		Confidence:         confidence,
		CalculationVersion: awsLowRiskRemediationVersion,
		AppliedFilters:     map[string]string{},
		Allowlist:          awsLowRiskRemediationAllowlist(),
		Summary:            summarizeAWSLowRiskRemediationEntries(nil, nil, nil),
		Caveats:            awsLowRiskRemediationCaveats(),
		FailureReasons:     failureReasons,
		RemediationHints:   remediationHints,
		EvidenceLinks: dedupeStrings([]string{
			awsIssueURL(awsPlatformDependencyParentIssue),
			awsIssueURL(awsLowRiskRemediationCurrentIssue),
			awsIssueURL(awsRemediationDryRunCurrentIssue),
			"/docs/aws-low-risk-live-remediation",
			awsBaselineProjectEvidenceURL(scope, project),
		}),
		GeneratedAt: now,
		UpdatedAt:   now,
	}
	verification := AWSPostRemediationVerificationResult{
		TenantID:           scope.TenantID,
		WorkspaceID:        project.WorkspaceID,
		ProjectID:          project.ProjectID,
		ConnectorID:        connectorID,
		AccountID:          accountID,
		Region:             region,
		ParentIssueNumber:  awsPlatformDependencyParentIssue,
		ParentIssueRef:     awsIssueRef(awsPlatformDependencyParentIssue),
		CurrentIssueNumber: awsPostRemediationVerificationCurrentIssue,
		CurrentIssueRef:    awsIssueRef(awsPostRemediationVerificationCurrentIssue),
		Version:            awsPostRemediationVerificationVersion,
		Status:             status,
		FixtureState:       fixtureState,
		Confidence:         confidence,
		CalculationVersion: awsPostRemediationVerificationVersion,
		AppliedFilters:     map[string]string{},
		Summary:            summarizeAWSPostRemediationVerificationEntries(nil, nil, nil),
		Caveats:            awsPostRemediationVerificationCaveats(),
		FailureReasons:     failureReasons,
		RemediationHints:   remediationHints,
		EvidenceLinks: dedupeStrings([]string{
			awsIssueURL(awsPlatformDependencyParentIssue),
			awsIssueURL(awsPostRemediationVerificationCurrentIssue),
			awsIssueURL(awsLowRiskRemediationCurrentIssue),
			"/docs/aws-post-remediation-verification",
			awsBaselineProjectEvidenceURL(scope, project),
		}),
		GeneratedAt: now,
		UpdatedAt:   now,
	}
	return AWSRemediationCenterResult{
		TenantID:           scope.TenantID,
		WorkspaceID:        project.WorkspaceID,
		ProjectID:          project.ProjectID,
		ConnectorID:        connectorID,
		AccountID:          accountID,
		Region:             region,
		ParentIssueNumber:  awsPlatformDependencyParentIssue,
		ParentIssueRef:     awsIssueRef(awsPlatformDependencyParentIssue),
		CurrentIssueNumber: awsRemediationCenterCurrentIssue,
		CurrentIssueRef:    awsIssueRef(awsRemediationCenterCurrentIssue),
		Version:            awsRemediationCenterVersion,
		Status:             status,
		FixtureState:       fixtureState,
		Confidence:         confidence,
		PolicyVersion:      awsRemediationCenterPolicyID,
		AppliedFilters:     applied,
		Summary:            summary,
		Tabs:               awsRemediationCenterTabs(summary, status, 0),
		Cases:              filtered,
		RemediationCases:   cases,
		ApprovalQueue:      approvals,
		DryRuns:            dryRuns,
		LiveActions:        liveActions,
		Verification:       verification,
		FailureReasons:     failureReasons,
		RemediationHints:   remediationHints,
		EvidenceLinks:      awsRemediationCenterEvidenceLinks(scope, project, cases, approvals, dryRuns, liveActions, verification),
		GeneratedAt:        now,
		UpdatedAt:          now,
	}
}

func normalizeAWSRemediationCenterFixtureState(requested string, connection AWSConnectionStatus, hasConnection bool) string {
	switch strings.ToLower(strings.TrimSpace(requested)) {
	case "":
		if !hasConnection || !connection.Connected {
			return "permission_denied"
		}
		return "success"
	case "success", "empty", "degraded", "partial_failure", "permission_denied":
		return strings.ToLower(strings.TrimSpace(requested))
	default:
		return ""
	}
}

// awsRemediationCenterCases builds the case-keyed lifecycle rollups by joining
// every stage back to its originating case.
func awsRemediationCenterCases(cases AWSRemediationCaseResult, approvals AWSRemediationApprovalResult, dryRuns AWSRemediationDryRunResult, liveActions AWSLowRiskRemediationResult, verification AWSPostRemediationVerificationResult) []AWSRemediationCenterCase {
	approvalByCase := map[string]AWSRemediationApprovalEntry{}
	for _, entry := range approvals.Entries {
		if key := strings.TrimSpace(entry.CaseID); key != "" {
			if _, ok := approvalByCase[key]; !ok {
				approvalByCase[key] = entry
			}
		}
	}
	dryRunByCase := map[string]AWSRemediationDryRunEntry{}
	for _, entry := range dryRuns.Entries {
		if key := strings.TrimSpace(entry.CaseID); key != "" {
			if _, ok := dryRunByCase[key]; !ok {
				dryRunByCase[key] = entry
			}
		}
	}
	liveByCase := map[string]AWSLowRiskRemediationEntry{}
	for _, entry := range liveActions.Entries {
		if key := strings.TrimSpace(entry.CaseID); key != "" {
			if _, ok := liveByCase[key]; !ok {
				liveByCase[key] = entry
			}
		}
	}
	verificationByCase := map[string][]AWSPostRemediationVerificationEntry{}
	for _, entry := range verification.Entries {
		key := strings.TrimSpace(entry.CaseID)
		if key == "" {
			continue
		}
		verificationByCase[key] = append(verificationByCase[key], entry)
	}

	out := make([]AWSRemediationCenterCase, 0, len(cases.Cases))
	for _, c := range cases.Cases {
		approval, hasApproval := approvalByCase[c.CaseID]
		dryRun, hasDryRun := dryRunByCase[c.CaseID]
		live, hasLive := liveByCase[c.CaseID]
		verifications := verificationByCase[c.CaseID]
		verify, hasVerify := awsRemediationCenterSelectedVerification(verifications)
		out = append(out, awsRemediationCenterCaseFromLifecycleWithVerifications(c, approval, hasApproval, dryRun, hasDryRun, live, hasLive, verify, hasVerify, verifications))
	}
	return out
}

func awsRemediationCenterSelectedVerification(entries []AWSPostRemediationVerificationEntry) (AWSPostRemediationVerificationEntry, bool) {
	var selected AWSPostRemediationVerificationEntry
	hasSelected := false
	for _, entry := range entries {
		if !hasSelected || awsRemediationCenterVerificationRank(entry) > awsRemediationCenterVerificationRank(selected) {
			selected = entry
			hasSelected = true
		}
	}
	return selected, hasSelected
}

func awsRemediationCenterVerificationRank(entry AWSPostRemediationVerificationEntry) int {
	if entry.KillSwitchEngaged {
		return 100
	}
	switch entry.State {
	case awsPostRemediationVerificationStateFailed, awsPostRemediationVerificationStateRollback:
		return 90
	case awsPostRemediationVerificationStateBlocked:
		return 80
	case awsPostRemediationVerificationStateNotReady:
		return 40
	case awsPostRemediationVerificationStatePending:
		return 30
	case awsPostRemediationVerificationStateSkipped:
		return 20
	case awsPostRemediationVerificationStateVerified:
		return 10
	}
	return 0
}

func awsRemediationCenterCaseFromLifecycle(c AWSRemediationCase, approval AWSRemediationApprovalEntry, hasApproval bool, dryRun AWSRemediationDryRunEntry, hasDryRun bool, live AWSLowRiskRemediationEntry, hasLive bool, verify AWSPostRemediationVerificationEntry, hasVerify bool) AWSRemediationCenterCase {
	return awsRemediationCenterCaseFromLifecycleWithVerifications(c, approval, hasApproval, dryRun, hasDryRun, live, hasLive, verify, hasVerify, nil)
}

func awsRemediationCenterCaseFromLifecycleWithVerifications(c AWSRemediationCase, approval AWSRemediationApprovalEntry, hasApproval bool, dryRun AWSRemediationDryRunEntry, hasDryRun bool, live AWSLowRiskRemediationEntry, hasLive bool, verify AWSPostRemediationVerificationEntry, hasVerify bool, verifications []AWSPostRemediationVerificationEntry) AWSRemediationCenterCase {
	stage := awsRemediationCenterStageCase
	killSwitch := false
	nonVerificationKillSwitch := false
	verificationKillSwitch := false
	tradeoffs := append([]AWSRemediationTradeoff{}, c.Tradeoffs...)
	gates := []AWSRemediationCenterSafetyGate{}
	seenAuditEvents := map[string]struct{}{}
	audit := awsRemediationCenterAuditEntries(c.CaseID, awsRemediationCenterStageCase, c.AuditTrail, seenAuditEvents)
	entry := AWSRemediationCenterCase{
		CaseID:           c.CaseID,
		Title:            c.Title,
		Summary:          c.Summary,
		SourceType:       c.SourceType,
		ActionType:       awsRemediationCenterActionType(c),
		Lifecycle:        c.Lifecycle,
		Severity:         c.Severity,
		Score:            c.Score,
		Confidence:       c.Confidence,
		AccountID:        firstNonEmptyAWSValue(c.AccountID, firstString(c.TargetAccountIDs)),
		TargetAccountIDs: emptyStrings(dedupeStrings(c.TargetAccountIDs)),
		Region:           c.Region,
		IdentityNodeID:   c.IdentityNodeID,
		IdentityName:     firstNonEmptyAWSValue(c.IdentityName, c.IdentityARN),
		IdentityType:     c.IdentityType,
		Owner:            c.Owner,
		OwnerAssigned:    c.OwnerAssigned,
		ApprovalRequired: c.ApprovalRequired,
		ApprovalState:    c.ApprovalState,
		EvidenceBoundary: awsRemediationCenterEvidenceBoundary(),
		UpdatedAt:        c.UpdatedAt,
	}
	evidenceRefs := awsRemediationCenterCaseEvidenceRefs(c)

	if hasApproval {
		stage = awsRemediationCenterStageApproval
		entry.ApprovalID = approval.ApprovalID
		entry.ApprovalState = firstNonEmptyAWSValue(approval.State, entry.ApprovalState)
		killSwitch = killSwitch || approval.KillSwitchEngaged
		nonVerificationKillSwitch = nonVerificationKillSwitch || approval.KillSwitchEngaged
		audit = append(audit, awsRemediationCenterAuditEntries(c.CaseID, awsRemediationCenterStageApproval, approval.AuditTrail, seenAuditEvents)...)
		tradeoffs = append(tradeoffs, approval.Tradeoffs...)
		for _, gate := range approval.RBACGates {
			gates = append(gates, AWSRemediationCenterSafetyGate{Source: "approval_rbac", Name: gate.Name, Status: gate.Status, Rationale: gate.Rationale})
		}
		for _, flag := range approval.FeatureFlags {
			gates = append(gates, AWSRemediationCenterSafetyGate{Source: "approval_feature_flag", Name: flag.Name, Status: awsRemediationCenterFlagStatus(flag.Enabled), Rationale: flag.Rationale})
		}
	}
	if hasDryRun {
		stage = awsRemediationCenterStageDryRun
		entry.DryRunID = dryRun.DryRunID
		entry.DryRunOutcome = dryRun.Outcome
		killSwitch = killSwitch || dryRun.KillSwitchEngaged
		nonVerificationKillSwitch = nonVerificationKillSwitch || dryRun.KillSwitchEngaged
		audit = append(audit, awsRemediationCenterAuditEntries(c.CaseID, awsRemediationCenterStageDryRun, dryRun.AuditTrail, seenAuditEvents)...)
		for _, prereq := range dryRun.SatisfiedPrereqs {
			gates = append(gates, AWSRemediationCenterSafetyGate{Source: "dry_run_prerequisite", Name: prereq.Name, Status: firstNonEmptyAWSValue(prereq.Status, "passed"), Rationale: prereq.Rationale})
		}
		for _, prereq := range dryRun.FailedPrereqs {
			gates = append(gates, AWSRemediationCenterSafetyGate{Source: "dry_run_prerequisite", Name: prereq.Name, Status: firstNonEmptyAWSValue(prereq.Status, "blocked"), Rationale: prereq.Rationale})
		}
		entry.ReadyForApply = dryRun.ReadyForApply
	}
	if hasLive {
		stage = awsRemediationCenterStageLiveAction
		entry.ExecutionID = live.ExecutionID
		entry.ExecutionState = live.State
		killSwitch = killSwitch || live.KillSwitchEngaged
		nonVerificationKillSwitch = nonVerificationKillSwitch || live.KillSwitchEngaged
		audit = append(audit, awsRemediationCenterAuditEntries(c.CaseID, awsRemediationCenterStageLiveAction, live.AuditTrail, seenAuditEvents)...)
		for _, preflight := range live.Preflights {
			gates = append(gates, AWSRemediationCenterSafetyGate{Source: "live_action_preflight", Name: preflight.Name, Status: preflight.Status, Rationale: preflight.Rationale})
		}
	}
	if hasVerify {
		stage = awsRemediationCenterStageVerification
		entry.VerificationID = verify.VerificationID
		entry.VerificationState = verify.State
		entry.VerificationEntryCount = len(verifications)
		if entry.VerificationEntryCount == 0 {
			entry.VerificationEntryCount = 1
			verifications = []AWSPostRemediationVerificationEntry{verify}
		}
		entry.VerificationStates = awsRemediationCenterVerificationStates(verifications)
		entry.RollbackState = verify.Rollback.State
		entry.RollbackStrategy = verify.Rollback.Strategy
		if verify.State == awsPostRemediationVerificationStateRollback || verify.State == awsPostRemediationVerificationStateFailed {
			stage = awsRemediationCenterStageRollback
		}
		for _, verification := range verifications {
			killSwitch = killSwitch || verification.KillSwitchEngaged
			verificationKillSwitch = verificationKillSwitch || verification.KillSwitchEngaged
			audit = append(audit, awsRemediationCenterAuditEntries(c.CaseID, awsRemediationCenterStageVerification, verification.AuditTrail, seenAuditEvents)...)
			for _, precondition := range verification.Preconditions {
				gates = append(gates, AWSRemediationCenterSafetyGate{Source: "verification_precondition", Name: precondition.Name, Status: precondition.Status, Rationale: precondition.Rationale})
			}
		}
		entry.NextAction = verify.NextAction
	}
	if entry.NextAction == "" {
		entry.NextAction = firstNonEmptyAWSValue(firstString(c.NextActions), awsRemediationCenterStageNextAction(stage))
	}
	entry.Stage = stage
	entry.KillSwitchEngaged = killSwitch
	entry.nonVerificationKillSwitchEngaged = nonVerificationKillSwitch
	entry.verificationKillSwitchEngaged = verificationKillSwitch
	entry.Tradeoffs = awsRemediationCenterDedupeTradeoffs(tradeoffs)
	entry.SafetyGates = gates
	entry.EvidenceRefs = evidenceRefs
	entry.AuditTrail = audit
	entry.AuditEntryCount = len(audit)
	return entry
}

// awsRemediationCenterCaseIDSet collects the case IDs of the given rollups so
// the embedded lifecycle payloads can be reconciled against the filtered set.
func awsRemediationCenterCaseIDSet(cases []AWSRemediationCenterCase) map[string]struct{} {
	set := make(map[string]struct{}, len(cases))
	for _, c := range cases {
		if key := strings.TrimSpace(c.CaseID); key != "" {
			set[key] = struct{}{}
		}
	}
	return set
}

func awsRemediationCenterStringSet[T any](items []T, key func(T) string) map[string]struct{} {
	set := make(map[string]struct{}, len(items))
	for _, item := range items {
		if value := strings.TrimSpace(key(item)); value != "" {
			set[value] = struct{}{}
		}
	}
	return set
}

// awsRemediationCenterScopeEntries keeps only the entries whose case ID is in the
// allowed set, preserving order.
func awsRemediationCenterScopeEntries[T any](entries []T, allow map[string]struct{}, caseID func(T) string) []T {
	out := make([]T, 0, len(entries))
	for _, entry := range entries {
		if _, ok := allow[strings.TrimSpace(caseID(entry))]; ok {
			out = append(out, entry)
		}
	}
	return out
}

// awsRemediationCenterScopeVerificationEntries keeps verification rows in sync
// with the filtered case set. If a case matched status through a verification
// row state, the tab renders only matching rows; lifecycle/approval/stage status
// matches keep all verification rows for that case.
func awsRemediationCenterScopeVerificationEntries(entries []AWSPostRemediationVerificationEntry, allow map[string]struct{}, cases []AWSRemediationCenterCase, status, accountID string) []AWSPostRemediationVerificationEntry {
	status = normalizeAWSRuntimeEventFilterToken(status)
	accountID = strings.TrimSpace(accountID)
	statusCaseIDs := awsRemediationCenterVerificationStatusCaseIDSet(cases, status)
	out := make([]AWSPostRemediationVerificationEntry, 0, len(entries))
	for _, entry := range entries {
		caseID := strings.TrimSpace(entry.CaseID)
		if _, ok := allow[caseID]; !ok {
			continue
		}
		if accountID != "" && !awsRemediationCenterVerificationAccountMatch(entry, accountID) {
			continue
		}
		if _, ok := statusCaseIDs[caseID]; ok && status != normalizeAWSRuntimeEventFilterToken(entry.State) {
			continue
		}
		out = append(out, entry)
	}
	return out
}

func awsRemediationCenterVerificationAccountMatch(entry AWSPostRemediationVerificationEntry, accountID string) bool {
	if strings.EqualFold(strings.TrimSpace(entry.AccountID), accountID) {
		return true
	}
	for _, target := range entry.TargetAccountIDs {
		if strings.EqualFold(strings.TrimSpace(target), accountID) {
			return true
		}
	}
	return false
}

func awsRemediationCenterVerificationStatusCaseIDSet(cases []AWSRemediationCenterCase, status string) map[string]struct{} {
	out := map[string]struct{}{}
	if status == "" || strings.EqualFold(status, "all") {
		return out
	}
	for _, entry := range cases {
		for _, state := range entry.VerificationStates {
			if status == normalizeAWSRuntimeEventFilterToken(state) {
				if caseID := strings.TrimSpace(entry.CaseID); caseID != "" {
					out[caseID] = struct{}{}
				}
				break
			}
		}
	}
	return out
}

func awsRemediationCenterCasesWithScopedVerificationRows(cases []AWSRemediationCenterCase, entries []AWSPostRemediationVerificationEntry, status, stage string) []AWSRemediationCenterCase {
	counts := map[string]int{}
	entriesByCase := map[string][]AWSPostRemediationVerificationEntry{}
	verificationAuditEvents := map[string]map[string]struct{}{}
	for _, entry := range entries {
		key := strings.TrimSpace(entry.CaseID)
		if key == "" {
			continue
		}
		counts[key]++
		entriesByCase[key] = append(entriesByCase[key], entry)
		if _, ok := verificationAuditEvents[key]; !ok {
			verificationAuditEvents[key] = map[string]struct{}{}
		}
		for _, audit := range entry.AuditTrail {
			if eventID := strings.TrimSpace(audit.EventID); eventID != "" {
				verificationAuditEvents[key][eventID] = struct{}{}
			}
		}
	}
	statusCaseIDs := awsRemediationCenterVerificationStatusCaseIDSet(cases, normalizeAWSRuntimeEventFilterToken(status))
	status = normalizeAWSRuntimeEventFilterToken(status)
	stage = normalizeAWSRuntimeEventFilterToken(stage)
	out := make([]AWSRemediationCenterCase, 0, len(cases))
	for _, entry := range cases {
		caseID := strings.TrimSpace(entry.CaseID)
		if entry.VerificationID == "" {
			if status != "" && !awsRemediationCenterStatusMatch(entry, status) {
				continue
			}
			if stage != "" && stage != normalizeAWSRuntimeEventFilterToken(entry.Stage) {
				continue
			}
			out = append(out, entry)
			continue
		}
		scopedRows := entriesByCase[caseID]
		if _, ok := statusCaseIDs[caseID]; ok && len(scopedRows) == 0 {
			continue
		}
		entry.VerificationEntryCount = counts[caseID]
		if selected, ok := awsRemediationCenterSelectedVerification(scopedRows); ok {
			entry.VerificationID = selected.VerificationID
			entry.VerificationState = selected.State
			entry.VerificationStates = awsRemediationCenterVerificationStates(scopedRows)
			entry.RollbackState = selected.Rollback.State
			entry.RollbackStrategy = selected.Rollback.Strategy
			entry.Stage = awsRemediationCenterStageVerification
			if selected.State == awsPostRemediationVerificationStateRollback || selected.State == awsPostRemediationVerificationStateFailed {
				entry.Stage = awsRemediationCenterStageRollback
			}
			entry.NextAction = selected.NextAction
		}
		entry.AuditTrail = awsRemediationCenterAuditTrailWithScopedVerificationEvents(entry.AuditTrail, verificationAuditEvents[caseID])
		entry.SafetyGates = awsRemediationCenterSafetyGatesWithScopedVerificationRows(entry.SafetyGates, scopedRows)
		scopedVerificationKillSwitch := awsRemediationCenterVerificationKillSwitch(scopedRows)
		entry.KillSwitchEngaged = entry.nonVerificationKillSwitchEngaged || scopedVerificationKillSwitch || (entry.KillSwitchEngaged && !entry.verificationKillSwitchEngaged)
		entry.verificationKillSwitchEngaged = scopedVerificationKillSwitch
		entry.AuditEntryCount = len(entry.AuditTrail)
		if status != "" && !awsRemediationCenterStatusMatch(entry, status) {
			continue
		}
		if stage != "" && stage != normalizeAWSRuntimeEventFilterToken(entry.Stage) {
			continue
		}
		out = append(out, entry)
	}
	return out
}

func awsRemediationCenterSafetyGatesWithScopedVerificationRows(gates []AWSRemediationCenterSafetyGate, rows []AWSPostRemediationVerificationEntry) []AWSRemediationCenterSafetyGate {
	out := make([]AWSRemediationCenterSafetyGate, 0, len(gates))
	for _, gate := range gates {
		if gate.Source == "verification_precondition" {
			continue
		}
		out = append(out, gate)
	}
	for _, row := range rows {
		for _, precondition := range row.Preconditions {
			out = append(out, AWSRemediationCenterSafetyGate{
				Source:    "verification_precondition",
				Name:      precondition.Name,
				Status:    precondition.Status,
				Rationale: precondition.Rationale,
			})
		}
	}
	return out
}

func awsRemediationCenterVerificationKillSwitch(rows []AWSPostRemediationVerificationEntry) bool {
	for _, row := range rows {
		if row.KillSwitchEngaged {
			return true
		}
	}
	return false
}

func awsRemediationCenterAuditTrailWithScopedVerificationEvents(entries []AWSRemediationCenterAuditEntry, verificationEvents map[string]struct{}) []AWSRemediationCenterAuditEntry {
	out := make([]AWSRemediationCenterAuditEntry, 0, len(entries))
	for _, entry := range entries {
		if entry.Stage == awsRemediationCenterStageVerification {
			if _, ok := verificationEvents[strings.TrimSpace(entry.EventID)]; !ok {
				continue
			}
		}
		out = append(out, entry)
	}
	return out
}

// awsRemediationCenterAuditTrail flattens the per-case audit records into one
// consolidated, filter-scoped list so the audit tab renders the same entries its
// count reflects, across every lifecycle stage rather than verification alone.
func awsRemediationCenterAuditTrail(cases []AWSRemediationCenterCase) []AWSRemediationCenterAuditEntry {
	out := []AWSRemediationCenterAuditEntry{}
	for _, c := range cases {
		out = append(out, c.AuditTrail...)
	}
	return out
}

// awsRemediationCenterAuditEntries projects only the first occurrence of each
// event ID into the center trail. Downstream stage trails are cumulative, so the
// first lifecycle stage that emits an event is the stage that owns it.
func awsRemediationCenterAuditEntries(caseID, stage string, trail []AWSRemediationAuditEntry, seen map[string]struct{}) []AWSRemediationCenterAuditEntry {
	out := make([]AWSRemediationCenterAuditEntry, 0, len(trail))
	for _, a := range trail {
		eventID := strings.TrimSpace(a.EventID)
		if eventID != "" {
			if _, ok := seen[eventID]; ok {
				continue
			}
			seen[eventID] = struct{}{}
		}
		out = append(out, AWSRemediationCenterAuditEntry{
			CaseID:      caseID,
			Stage:       stage,
			EventID:     eventID,
			EventType:   a.EventType,
			Actor:       a.Actor,
			OccurredAt:  a.OccurredAt,
			EvidenceRef: a.EvidenceRef,
			Notes:       a.Notes,
		})
	}
	return out
}

func awsRemediationCenterVerificationStates(entries []AWSPostRemediationVerificationEntry) []string {
	states := make([]string, 0, len(entries))
	for _, entry := range entries {
		if state := strings.TrimSpace(entry.State); state != "" {
			states = append(states, state)
		}
	}
	return dedupeStrings(states)
}

func awsRemediationCenterActionType(c AWSRemediationCase) string {
	if kind := strings.TrimSpace(c.DiffIntent.Kind); kind != "" {
		return kind
	}
	return c.SourceType
}

func awsRemediationCenterFlagStatus(enabled bool) string {
	if enabled {
		return "enabled"
	}
	return "blocked"
}

func awsRemediationCenterStageNextAction(stage string) string {
	switch stage {
	case awsRemediationCenterStageCase:
		return "Assign an owner and advance the case to the approval queue."
	case awsRemediationCenterStageApproval:
		return "Advance the approval workflow so the case can reach a dry-run."
	case awsRemediationCenterStageDryRun:
		return "Review the dry-run projection and its prerequisites before scheduling a live action."
	case awsRemediationCenterStageLiveAction:
		return "Confirm live-action preflights and let the wave-8 apply runtime record verification."
	case awsRemediationCenterStageVerification:
		return "Confirm verification checks pass; the change is recorded once verified."
	case awsRemediationCenterStageRollback:
		return "Verification failed or rolled back; follow the rollback plan and refresh upstream evidence."
	}
	return "Inspect the case for its next action."
}

func awsRemediationCenterCaseEvidenceRefs(c AWSRemediationCase) []string {
	refs := []string{}
	if ref := strings.TrimSpace(c.DiffIntent.BeforeRef); ref != "" {
		refs = append(refs, ref)
	}
	for _, evidence := range c.Evidence {
		if ref := strings.TrimSpace(evidence.EvidenceRef); ref != "" {
			refs = append(refs, ref)
		}
	}
	return dedupeStrings(refs)
}

func awsRemediationCenterDedupeTradeoffs(items []AWSRemediationTradeoff) []AWSRemediationTradeoff {
	seen := map[string]struct{}{}
	out := []AWSRemediationTradeoff{}
	for _, item := range items {
		key := strings.ToLower(strings.Join([]string{item.Dimension, item.Direction, item.Description, item.Severity}, "\x00"))
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, item)
	}
	return out
}

func filterAWSRemediationCenterCases(centerCases []AWSRemediationCenterCase, request AWSRemediationCenterRequest) ([]AWSRemediationCenterCase, map[string]string) {
	filters := map[string]string{
		"account_id":    strings.TrimSpace(request.AccountID),
		"region":        strings.TrimSpace(request.Region),
		"severity":      normalizeAWSRuntimeEventFilterToken(request.Severity),
		"identity_type": normalizeAWSRuntimeEventFilterToken(request.IdentityType),
		"action_type":   normalizeAWSRuntimeEventFilterToken(request.ActionType),
		"status":        normalizeAWSRuntimeEventFilterToken(request.Status),
		"stage":         normalizeAWSRuntimeEventFilterToken(request.Stage),
		"case_id":       strings.TrimSpace(request.CaseID),
		"confidence":    strings.TrimSpace(request.Confidence),
		"search":        strings.TrimSpace(request.Search),
	}
	for key, value := range filters {
		if strings.TrimSpace(value) == "" || strings.EqualFold(value, "all") {
			delete(filters, key)
		}
	}
	minConfidence, hasMinConfidence := awsRemediationCenterConfidenceFloor(filters["confidence"])
	deferStageFilter := awsRemediationCenterShouldDeferStageFilter(filters)
	deferStatusFilter := awsRemediationCenterShouldDeferStatusFilter(filters)
	applied := map[string]string{}
	for key, value := range filters {
		applied[key] = value
	}
	filtered := make([]AWSRemediationCenterCase, 0, len(centerCases))
	for _, entry := range centerCases {
		if filters["account_id"] != "" && !awsRemediationCenterAccountMatch(entry, filters["account_id"]) {
			continue
		}
		if filters["region"] != "" && strings.TrimSpace(entry.Region) != "" && !strings.EqualFold(filters["region"], strings.TrimSpace(entry.Region)) {
			continue
		}
		if filters["severity"] != "" && filters["severity"] != normalizeAWSRuntimeEventFilterToken(entry.Severity) {
			continue
		}
		if filters["identity_type"] != "" && filters["identity_type"] != normalizeAWSRuntimeEventFilterToken(entry.IdentityType) {
			continue
		}
		if filters["action_type"] != "" && filters["action_type"] != normalizeAWSRuntimeEventFilterToken(entry.ActionType) && filters["action_type"] != normalizeAWSRuntimeEventFilterToken(entry.SourceType) {
			continue
		}
		if filters["status"] != "" && !deferStatusFilter && !awsRemediationCenterStatusMatch(entry, filters["status"]) {
			continue
		}
		if filters["stage"] != "" && !deferStageFilter && filters["stage"] != normalizeAWSRuntimeEventFilterToken(entry.Stage) {
			continue
		}
		if filters["case_id"] != "" && !strings.EqualFold(filters["case_id"], entry.CaseID) {
			continue
		}
		if hasMinConfidence && entry.Confidence < minConfidence {
			continue
		}
		if filters["search"] != "" && !awsRemediationCenterSearchMatch(entry, filters["search"]) {
			continue
		}
		filtered = append(filtered, entry)
	}
	return filtered, applied
}

func awsRemediationCenterShouldDeferStageFilter(filters map[string]string) bool {
	if filters["stage"] == "" {
		return false
	}
	return filters["account_id"] != "" || awsRemediationCenterFilterTokenIsVerificationState(filters["status"])
}

func awsRemediationCenterShouldDeferStatusFilter(filters map[string]string) bool {
	return filters["status"] != "" && filters["account_id"] != ""
}

func awsRemediationCenterFilterTokenIsVerificationState(status string) bool {
	switch normalizeAWSRuntimeEventFilterToken(status) {
	case normalizeAWSRuntimeEventFilterToken(awsPostRemediationVerificationStatePending),
		normalizeAWSRuntimeEventFilterToken(awsPostRemediationVerificationStateVerified),
		normalizeAWSRuntimeEventFilterToken(awsPostRemediationVerificationStateFailed),
		normalizeAWSRuntimeEventFilterToken(awsPostRemediationVerificationStateRollback),
		normalizeAWSRuntimeEventFilterToken(awsPostRemediationVerificationStateSkipped),
		normalizeAWSRuntimeEventFilterToken(awsPostRemediationVerificationStateBlocked),
		normalizeAWSRuntimeEventFilterToken(awsPostRemediationVerificationStateNotReady):
		return true
	default:
		return false
	}
}

// awsRemediationCenterConfidenceFloor parses the confidence filter as either a
// 0..1 float threshold or a high/medium/low bucket floor.
func awsRemediationCenterConfidenceFloor(value string) (float64, bool) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return 0, false
	}
	switch value {
	case "high":
		return 0.85, true
	case "medium", "med":
		return 0.6, true
	case "low":
		return 0, true
	}
	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil || parsed < 0 || parsed > 1 {
		return 0, false
	}
	return parsed, true
}

func awsRemediationCenterAccountMatch(entry AWSRemediationCenterCase, accountID string) bool {
	if strings.EqualFold(strings.TrimSpace(entry.AccountID), accountID) {
		return true
	}
	for _, target := range entry.TargetAccountIDs {
		if strings.EqualFold(strings.TrimSpace(target), accountID) {
			return true
		}
	}
	return false
}

// awsRemediationCenterStatusMatch matches the status filter against the
// case lifecycle, approval state, or the furthest execution/verification
// state so operators can filter by any lifecycle status token.
func awsRemediationCenterStatusMatch(entry AWSRemediationCenterCase, status string) bool {
	for _, value := range []string{entry.Lifecycle, entry.ApprovalState, entry.ExecutionState, entry.VerificationState, entry.Stage} {
		if status == normalizeAWSRuntimeEventFilterToken(value) {
			return true
		}
	}
	for _, value := range entry.VerificationStates {
		if status == normalizeAWSRuntimeEventFilterToken(value) {
			return true
		}
	}
	return false
}

func awsRemediationCenterSearchMatch(entry AWSRemediationCenterCase, needle string) bool {
	needle = strings.ToLower(strings.TrimSpace(needle))
	if needle == "" {
		return true
	}
	values := []string{
		entry.CaseID, entry.Title, entry.Summary, entry.SourceType, entry.ActionType,
		entry.Lifecycle, entry.Stage, entry.Severity, entry.IdentityNodeID, entry.IdentityName,
		entry.IdentityType, entry.Owner, entry.ApprovalState, entry.ApprovalID, entry.DryRunID,
		entry.DryRunOutcome, entry.ExecutionID, entry.ExecutionState, entry.VerificationID,
		entry.VerificationState, entry.RollbackState, entry.RollbackStrategy, entry.NextAction,
	}
	values = append(values, entry.TargetAccountIDs...)
	values = append(values, entry.EvidenceRefs...)
	for _, gate := range entry.SafetyGates {
		values = append(values, gate.Name, gate.Status, gate.Rationale)
	}
	for _, tradeoff := range entry.Tradeoffs {
		values = append(values, tradeoff.Dimension, tradeoff.Description)
	}
	for _, value := range values {
		if strings.Contains(strings.ToLower(value), needle) {
			return true
		}
	}
	return false
}

func summarizeAWSRemediationCenterCases(all, filtered []AWSRemediationCenterCase) AWSRemediationCenterSummary {
	summary := AWSRemediationCenterSummary{
		TotalCases:         len(all),
		FilteredCases:      len(filtered),
		StageCounts:        map[string]int{},
		SeverityCounts:     map[string]int{},
		StatusCounts:       map[string]int{},
		ActionTypeCounts:   map[string]int{},
		IdentityTypeCounts: map[string]int{},
	}
	confidenceTotal := 0.0
	for _, entry := range filtered {
		if entry.Stage != "" {
			summary.StageCounts[entry.Stage]++
		}
		if entry.Severity != "" {
			summary.SeverityCounts[entry.Severity]++
		}
		if entry.Lifecycle != "" {
			summary.StatusCounts[entry.Lifecycle]++
		}
		if entry.ActionType != "" {
			summary.ActionTypeCounts[entry.ActionType]++
		}
		if entry.IdentityType != "" {
			summary.IdentityTypeCounts[entry.IdentityType]++
		}
		if entry.ApprovalID != "" && awsRemediationCenterApprovalIsPending(entry.ApprovalState) {
			summary.ApprovalPendingCount++
		}
		if entry.DryRunID != "" {
			summary.DryRunCount++
		}
		if entry.ExecutionID != "" {
			summary.LiveActionCount++
		}
		if entry.VerificationID != "" {
			verificationCount := entry.VerificationEntryCount
			if verificationCount == 0 && len(entry.VerificationStates) == 0 {
				verificationCount = 1
			}
			summary.VerificationCount += verificationCount
		}
		if entry.Stage == awsRemediationCenterStageRollback {
			summary.RollbackCount++
		}
		if entry.ReadyForApply {
			summary.ReadyForApplyCount++
		}
		if entry.KillSwitchEngaged {
			summary.KillSwitchCount++
		}
		for _, gate := range entry.SafetyGates {
			if gate.Status == "blocked" || gate.Status == "failed" {
				summary.BlockedGateCount++
			}
		}
		summary.AuditEntryCount += entry.AuditEntryCount
		if entry.Score > summary.HighestScore {
			summary.HighestScore = entry.Score
		}
		confidenceTotal += entry.Confidence
	}
	if len(filtered) > 0 {
		summary.AverageConfidencePct = int((confidenceTotal/float64(len(filtered)))*100 + 0.5)
	}
	return summary
}

func awsRemediationCenterApprovalIsPending(state string) bool {
	switch normalizeAWSRuntimeEventFilterToken(state) {
	case normalizeAWSRuntimeEventFilterToken(awsRemediationApprovalStateRequested),
		normalizeAWSRuntimeEventFilterToken(awsRemediationApprovalStateReview),
		"pending", "pending-approver", "in-review", "review":
		return true
	}
	return false
}

func awsRemediationCenterTabs(summary AWSRemediationCenterSummary, status string, approvalEntryCount int) []AWSRemediationCenterTab {
	tabStatus := status
	if tabStatus == "" {
		tabStatus = "success"
	}
	return []AWSRemediationCenterTab{
		{ID: "overview", Label: "Overview", Status: tabStatus, Count: summary.FilteredCases},
		{ID: "cases", Label: "Cases", Status: tabStatus, Count: summary.FilteredCases},
		{ID: "approvals", Label: "Approvals", Status: tabStatus, Count: approvalEntryCount},
		{ID: "dry_runs", Label: "Dry-runs", Status: tabStatus, Count: summary.DryRunCount},
		{ID: "live_actions", Label: "Live actions", Status: tabStatus, Count: summary.LiveActionCount},
		{ID: "verification", Label: "Verification", Status: tabStatus, Count: summary.VerificationCount},
		{ID: "audit", Label: "Audit", Status: tabStatus, Count: summary.AuditEntryCount},
	}
}

func summarizeAWSRemediationCenterStatus(fixtureState string, cases AWSRemediationCaseResult, approvals AWSRemediationApprovalResult, dryRuns AWSRemediationDryRunResult, liveActions AWSLowRiskRemediationResult, verification AWSPostRemediationVerificationResult, diagnostics []AWSRemediationCenterDiagnostic) (string, float64) {
	if fixtureState == "permission_denied" {
		return "permission_denied", 0.2
	}
	statuses := []string{cases.Status, approvals.Status, dryRuns.Status, liveActions.Status, verification.Status}
	for _, status := range statuses {
		if status == awsPlatformDependencyStatusBlocked {
			return awsPlatformDependencyStatusBlocked, 0.35
		}
	}
	for _, diagnostic := range diagnostics {
		if diagnostic.Retryable {
			return awsPlatformDependencyStatusDegraded, 0.72
		}
	}
	for _, status := range statuses {
		if status == awsPlatformDependencyStatusDegraded {
			return awsPlatformDependencyStatusDegraded, 0.74
		}
	}
	if fixtureState == "degraded" || fixtureState == "partial_failure" {
		return awsPlatformDependencyStatusDegraded, 0.74
	}
	if len(cases.Cases) == 0 {
		return awsPlatformDependencyStatusReady, 0.82
	}
	return awsPlatformDependencyStatusReady, 0.9
}

func awsRemediationCenterFailureReasons(cases AWSRemediationCaseResult, approvals AWSRemediationApprovalResult, dryRuns AWSRemediationDryRunResult, liveActions AWSLowRiskRemediationResult, verification AWSPostRemediationVerificationResult) []string {
	out := []string{}
	out = append(out, cases.FailureReasons...)
	out = append(out, approvals.FailureReasons...)
	out = append(out, dryRuns.FailureReasons...)
	out = append(out, liveActions.FailureReasons...)
	out = append(out, verification.FailureReasons...)
	return dedupeStrings(out)
}

func awsRemediationCenterRemediationHints(cases AWSRemediationCaseResult, approvals AWSRemediationApprovalResult, dryRuns AWSRemediationDryRunResult, liveActions AWSLowRiskRemediationResult, verification AWSPostRemediationVerificationResult) []string {
	out := []string{}
	out = append(out, cases.RemediationHints...)
	out = append(out, approvals.RemediationHints...)
	out = append(out, dryRuns.RemediationHints...)
	out = append(out, liveActions.RemediationHints...)
	out = append(out, verification.RemediationHints...)
	return dedupeStrings(out)
}

func awsRemediationCenterDiagnostics(cases AWSRemediationCaseResult, approvals AWSRemediationApprovalResult, dryRuns AWSRemediationDryRunResult, liveActions AWSLowRiskRemediationResult, verification AWSPostRemediationVerificationResult) []AWSRemediationCenterDiagnostic {
	out := []AWSRemediationCenterDiagnostic{}
	for _, d := range cases.Diagnostics {
		out = append(out, AWSRemediationCenterDiagnostic{Collector: d.Collector, SourceID: d.SourceID, Code: d.Code, Message: d.Message, Remediation: d.Remediation, Retryable: d.Retryable})
	}
	for _, d := range approvals.Diagnostics {
		out = append(out, AWSRemediationCenterDiagnostic{Collector: d.Collector, SourceID: d.SourceID, Code: d.Code, Message: d.Message, Remediation: d.Remediation, Retryable: d.Retryable})
	}
	for _, d := range dryRuns.Diagnostics {
		out = append(out, AWSRemediationCenterDiagnostic{Collector: d.Collector, SourceID: d.SourceID, Code: d.Code, Message: d.Message, Remediation: d.Remediation, Retryable: d.Retryable})
	}
	for _, d := range liveActions.Diagnostics {
		out = append(out, AWSRemediationCenterDiagnostic{Collector: d.Collector, SourceID: d.SourceID, Code: d.Code, Message: d.Message, Remediation: d.Remediation, Retryable: d.Retryable})
	}
	for _, d := range verification.Diagnostics {
		out = append(out, AWSRemediationCenterDiagnostic{Collector: d.Collector, SourceID: d.SourceID, Code: d.Code, Message: d.Message, Remediation: d.Remediation, Retryable: d.Retryable})
	}
	return awsMachineIdentityDedupeDiagnostics(out)
}

func awsRemediationCenterCoverageGaps(cases AWSRemediationCaseResult, verification AWSPostRemediationVerificationResult) []AWSRemediationCenterCoverageGap {
	out := []AWSRemediationCenterCoverageGap{}
	for _, gap := range cases.CoverageGaps {
		out = append(out, AWSRemediationCenterCoverageGap{Capability: gap.Capability, Status: gap.Status, Reason: gap.Reason, Remediation: gap.Remediation})
	}
	for _, gap := range verification.CoverageGaps {
		out = append(out, AWSRemediationCenterCoverageGap{Capability: gap.Capability, Status: gap.Status, Reason: gap.Reason, Remediation: gap.Remediation})
	}
	return out
}

func awsRemediationCenterEvidenceLinks(scope db.Scope, project db.TenancyProject, cases AWSRemediationCaseResult, approvals AWSRemediationApprovalResult, dryRuns AWSRemediationDryRunResult, liveActions AWSLowRiskRemediationResult, verification AWSPostRemediationVerificationResult) []string {
	links := []string{
		awsIssueURL(awsPlatformDependencyParentIssue),
		awsIssueURL(awsRemediationCenterCurrentIssue),
		awsIssueURL(awsRemediationCaseCurrentIssue),
		awsIssueURL(awsRemediationApprovalCurrentIssue),
		awsIssueURL(awsRemediationDryRunCurrentIssue),
		awsIssueURL(awsLowRiskRemediationCurrentIssue),
		awsIssueURL(awsPostRemediationVerificationCurrentIssue),
		"/docs/aws-remediation-center",
		awsBaselineProjectEvidenceURL(scope, project),
	}
	links = append(links, cases.EvidenceLinks...)
	links = append(links, approvals.EvidenceLinks...)
	links = append(links, dryRuns.EvidenceLinks...)
	links = append(links, liveActions.EvidenceLinks...)
	links = append(links, verification.EvidenceLinks...)
	return dedupeStrings(links)
}

func awsRemediationCenterEvidenceBoundary() string {
	return "metadata_only_no_rendered_policy_bodies_no_secret_values_no_workload_payloads_tenant_workspace_project_connector_account_region_scoped"
}
