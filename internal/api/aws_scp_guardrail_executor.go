package api

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	awsScpGuardrailExecutorCurrentIssue = 1541
	awsScpGuardrailExecutorVersion      = "aws-scp-guardrail-executor-v1"

	awsScpGuardrailExecutorStateProjected          = "projected"
	awsScpGuardrailExecutorStatePreconditionFailed = "precondition_failed"
	awsScpGuardrailExecutorStateBlocked            = "blocked"
)

// AWSScpGuardrailExecutorRequest scopes the deterministic SCP guardrail
// executor projection to one AWS connector plus optional drill-down filters.
type AWSScpGuardrailExecutorRequest struct {
	ConnectorID  string `json:"connector_id,omitempty"`
	FixtureState string `json:"fixture_state,omitempty"`
	AccountID    string `json:"account_id,omitempty"`
	Region       string `json:"region,omitempty"`
	DryRunID     string `json:"dry_run_id,omitempty"`
	CaseID       string `json:"case_id,omitempty"`
	PlanID       string `json:"plan_id,omitempty"`
	Operation    string `json:"operation,omitempty"`
	TargetScope  string `json:"target_scope,omitempty"`
	State        string `json:"state,omitempty"`
	Severity     string `json:"severity,omitempty"`
	Search       string `json:"search,omitempty"`
}

type AWSScpGuardrailExecutorEvidence = AWSPermissionBoundarySCPEvidence
type AWSScpGuardrailExecutorPathStep = AWSPermissionBoundarySCPPathStep
type AWSScpGuardrailExecutorDiagnostic = AWSPermissionBoundarySCPDiagnostic
type AWSScpGuardrailExecutorCoverageGap = AWSPermissionBoundarySCPCoverageGap
type AWSScpGuardrailExecutorAuditEntry = AWSRemediationApprovalAuditEntry

type awsScpGuardrailExecutorTarget struct {
	Scope string
	ID    string
}

// AWSScpGuardrailExecutorPrecondition is one safety check that must pass
// before the executor marks a record ready_for_live_apply.
type AWSScpGuardrailExecutorPrecondition struct {
	Name      string `json:"name"`
	Status    string `json:"status"`
	Rationale string `json:"rationale"`
}

// AWSScpGuardrailExecutorSimulation records the metadata-only simulator result
// used to decide whether an SCP guardrail is safe to apply.
type AWSScpGuardrailExecutorSimulation struct {
	SimulationRef      string   `json:"simulation_ref"`
	Outcome            string   `json:"outcome"`
	BeforeRef          string   `json:"before_ref"`
	AfterRef           string   `json:"after_ref"`
	DeniedActionCount  int      `json:"denied_action_count"`
	TargetAccountCount int      `json:"target_account_count"`
	TargetOUCount      int      `json:"target_ou_count"`
	Signals            []string `json:"signals,omitempty"`
}

// AWSScpGuardrailExecutorVerification describes one post-apply check a
// downstream live executor must record before the execution can be considered
// succeeded.
type AWSScpGuardrailExecutorVerification struct {
	Source      string `json:"source"`
	Signal      string `json:"signal"`
	Status      string `json:"status"`
	Description string `json:"description"`
}

// AWSScpGuardrailExecutorRelationship surfaces executor->graph edges.
type AWSScpGuardrailExecutorRelationship struct {
	ExecutionID string `json:"execution_id"`
	Type        string `json:"type"`
	FromNodeID  string `json:"from_node_id"`
	ToNodeID    string `json:"to_node_id"`
	EvidenceRef string `json:"evidence_ref,omitempty"`
}

// AWSScpGuardrailExecutorEntry is the persisted-record-shaped contract
// for an approved SCP guardrail execution projection. It carries metadata refs
// only and never inlines rendered policy documents, secret values, or workload
// payloads.
type AWSScpGuardrailExecutorEntry struct {
	ExecutionID        string                                     `json:"execution_id"`
	CalculationVersion string                                     `json:"calculation_version"`
	DryRunID           string                                     `json:"dry_run_id"`
	ApprovalID         string                                     `json:"approval_id"`
	CaseID             string                                     `json:"case_id"`
	PlanID             string                                     `json:"plan_id"`
	SourceArtifactID   string                                     `json:"source_artifact_id"`
	State              string                                     `json:"state"`
	Severity           string                                     `json:"severity"`
	Score              int                                        `json:"score"`
	Confidence         float64                                    `json:"confidence"`
	Title              string                                     `json:"title"`
	Summary            string                                     `json:"summary"`
	AccountID          string                                     `json:"account_id"`
	Region             string                                     `json:"region"`
	Operation          string                                     `json:"operation"`
	IdempotencyKey     string                                     `json:"idempotency_key"`
	TargetAccountIDs   []string                                   `json:"target_account_ids,omitempty"`
	TargetOUPaths      []string                                   `json:"target_ou_paths,omitempty"`
	PreventedBehavior  string                                     `json:"prevented_behavior"`
	StatementSnippets  []AWSPermissionBoundarySCPStatementSnippet `json:"statement_snippets"`
	BreakageProjection AWSPermissionBoundarySCPBreakageProjection `json:"breakage_projection"`
	IntendedAPICall    AWSRemediationDryRunIntendedAPICall        `json:"intended_api_call"`
	Preconditions      []AWSScpGuardrailExecutorPrecondition      `json:"preconditions"`
	BoundarySimulation AWSScpGuardrailExecutorSimulation          `json:"boundary_simulation"`
	Verifications      []AWSScpGuardrailExecutorVerification      `json:"verifications"`
	RollbackPlan       AWSPermissionBoundarySCPRollbackPlan       `json:"rollback_plan"`
	VerificationPlan   AWSPermissionBoundarySCPVerificationPlan   `json:"verification_plan"`
	AuditTrail         []AWSScpGuardrailExecutorAuditEntry        `json:"audit_trail"`
	KillSwitchEngaged  bool                                       `json:"kill_switch_engaged"`
	ReadyForLiveApply  bool                                       `json:"ready_for_live_apply"`
	ReadOnlyProjection bool                                       `json:"read_only_projection"`
	SourceSignals      []string                                   `json:"source_signals"`
	Evidence           []AWSScpGuardrailExecutorEvidence          `json:"evidence"`
	EvidenceBoundary   string                                     `json:"evidence_boundary"`
	ImpactedNodes      []string                                   `json:"impacted_nodes"`
	ImpactedPath       []AWSScpGuardrailExecutorPathStep          `json:"impacted_path"`
	NextAction         string                                     `json:"next_action"`
	ProjectedAt        time.Time                                  `json:"projected_at"`
	CreatedAt          time.Time                                  `json:"created_at"`
	UpdatedAt          time.Time                                  `json:"updated_at"`
}

// AWSScpGuardrailExecutorSummary aggregates the unfiltered/filtered set.
type AWSScpGuardrailExecutorSummary struct {
	TotalEntries            int            `json:"total_entries"`
	FilteredEntries         int            `json:"filtered_entries"`
	StateCounts             map[string]int `json:"state_counts"`
	OperationCounts         map[string]int `json:"operation_counts"`
	SeverityCounts          map[string]int `json:"severity_counts"`
	ReadyForLiveApplyCount  int            `json:"ready_for_live_apply_count"`
	KillSwitchEngagedCount  int            `json:"kill_switch_engaged_count"`
	FailedPreconditionCount int            `json:"failed_precondition_count"`
	TargetAccountCount      int            `json:"target_account_count"`
	TargetOUCount           int            `json:"target_ou_count"`
	VerificationCount       int            `json:"verification_count"`
	RelationshipCount       int            `json:"relationship_count"`
	HighestScore            int            `json:"highest_score"`
	AverageConfidencePct    int            `json:"average_confidence_pct"`
}

// AWSScpGuardrailExecutorResult is the deterministic endpoint envelope.
type AWSScpGuardrailExecutorResult struct {
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
	Summary            AWSScpGuardrailExecutorSummary        `json:"summary"`
	Entries            []AWSScpGuardrailExecutorEntry        `json:"entries"`
	Relationships      []AWSScpGuardrailExecutorRelationship `json:"relationships"`
	Caveats            []string                              `json:"caveats"`
	FailureReasons     []string                              `json:"failure_reasons"`
	RemediationHints   []string                              `json:"remediation_hints"`
	EvidenceLinks      []string                              `json:"evidence_links"`
	CoverageGaps       []AWSScpGuardrailExecutorCoverageGap  `json:"coverage_gaps"`
	Diagnostics        []AWSScpGuardrailExecutorDiagnostic   `json:"diagnostics"`
	GeneratedAt        time.Time                             `json:"generated_at"`
	UpdatedAt          time.Time                             `json:"updated_at"`
}

// GetAWSScpGuardrailExecutor projects approved SCP guardrail executions by
// joining remediation dry-run entries (#1537) with SCP planner metadata (#1532).
// This layer is metadata-only: it records controlled Organizations intent,
// preconditions, idempotency key, rollback metadata, and verification plan
// without calling live AWS write APIs.
func (s *Service) GetAWSScpGuardrailExecutor(ctx context.Context, workspaceID string, projectID string, request AWSScpGuardrailExecutorRequest) (AWSScpGuardrailExecutorResult, error) {
	project, scope, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return AWSScpGuardrailExecutorResult{}, err
	}
	connection, hasConnection, err := s.awsBaselineConnection(ctx, project, strings.TrimSpace(request.ConnectorID))
	if err != nil {
		return AWSScpGuardrailExecutorResult{}, err
	}
	now := s.Now().UTC()
	fixtureState := normalizeAWSScpGuardrailExecutorFixtureState(request.FixtureState, connection, hasConnection)
	if fixtureState == "" {
		return AWSScpGuardrailExecutorResult{}, ErrInvalidAWSConnectionRequest
	}

	accountID := firstNonEmptyAWSValue(connection.AccountID, strings.TrimSpace(request.AccountID), "123456789012")
	region := firstNonEmptyAWSValue(connection.Region, strings.TrimSpace(request.Region), "us-east-1")
	connectorID := firstNonEmptyAWSValue(connection.ConnectorID, strings.TrimSpace(request.ConnectorID))
	sourceFixtureState := fixtureState
	if strings.TrimSpace(request.FixtureState) == "" && hasConnection && connection.Connected {
		sourceFixtureState = ""
	}

	dryRun, err := s.GetAWSRemediationDryRun(ctx, workspaceID, projectID, AWSRemediationDryRunRequest{ConnectorID: connectorID, FixtureState: sourceFixtureState})
	if err != nil {
		return AWSScpGuardrailExecutorResult{}, fmt.Errorf("scp guardrail executor dry-run: %w", err)
	}
	plans, err := s.GetAWSPermissionBoundarySCPPlans(ctx, workspaceID, projectID, AWSPermissionBoundarySCPRequest{ConnectorID: connectorID, FixtureState: sourceFixtureState, Kind: awsSCPKind})
	if err != nil {
		return AWSScpGuardrailExecutorResult{}, fmt.Errorf("scp guardrail executor plans: %w", err)
	}

	planByID := map[string]AWSPermissionBoundarySCPPlan{}
	for _, plan := range plans.Plans {
		if strings.EqualFold(plan.Kind, awsSCPKind) {
			planByID[plan.PlanID] = plan
		}
	}

	entries := awsScpGuardrailExecutorEntries(dryRun.Entries, planByID, now)
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].Score == entries[j].Score {
			return entries[i].ExecutionID < entries[j].ExecutionID
		}
		return entries[i].Score > entries[j].Score
	})
	filtered, applied := filterAWSScpGuardrailExecutorEntries(entries, request)
	relationships := awsScpGuardrailExecutorRelationships(filtered)
	diagnostics := awsScpGuardrailExecutorDiagnostics(dryRun.Diagnostics, plans.Diagnostics)
	coverageGaps := awsScpGuardrailExecutorCoverageGaps(dryRun.CoverageGaps, plans.CoverageGaps)
	status, confidence := summarizeAWSScpGuardrailExecutorStatus(dryRun.Status, plans.Status, filtered, diagnostics)

	return AWSScpGuardrailExecutorResult{
		TenantID:           scope.TenantID,
		WorkspaceID:        project.WorkspaceID,
		ProjectID:          project.ProjectID,
		ConnectorID:        connectorID,
		AccountID:          accountID,
		Region:             region,
		ParentIssueNumber:  awsPlatformDependencyParentIssue,
		ParentIssueRef:     awsIssueRef(awsPlatformDependencyParentIssue),
		CurrentIssueNumber: awsScpGuardrailExecutorCurrentIssue,
		CurrentIssueRef:    awsIssueRef(awsScpGuardrailExecutorCurrentIssue),
		Version:            awsScpGuardrailExecutorVersion,
		Status:             status,
		FixtureState:       sourceFixtureState,
		Confidence:         confidence,
		CalculationVersion: awsScpGuardrailExecutorVersion,
		AppliedFilters:     applied,
		Summary:            summarizeAWSScpGuardrailExecutorEntries(entries, filtered, relationships),
		Entries:            filtered,
		Relationships:      relationships,
		Caveats:            awsScpGuardrailExecutorCaveats(),
		FailureReasons:     dedupeStrings(append(append([]string{}, dryRun.FailureReasons...), plans.FailureReasons...)),
		RemediationHints:   awsScpGuardrailExecutorRemediationHints(append(dryRun.RemediationHints, plans.RemediationHints...)),
		EvidenceLinks: dedupeStrings([]string{
			awsIssueURL(awsPlatformDependencyParentIssue),
			awsIssueURL(awsScpGuardrailExecutorCurrentIssue),
			awsIssueURL(awsRemediationDryRunCurrentIssue),
			awsIssueURL(awsPermissionBoundarySCPCurrentIssue),
			"/docs/aws-scp-guardrail-executor",
			"/docs/aws-remediation-dry-run-executor",
			"/docs/aws-permission-boundary-scp-planner",
			awsBaselineProjectEvidenceURL(scope, project),
		}),
		CoverageGaps: coverageGaps,
		Diagnostics:  diagnostics,
		GeneratedAt:  now,
		UpdatedAt:    now,
	}, nil
}

func normalizeAWSScpGuardrailExecutorFixtureState(requested string, connection AWSConnectionStatus, hasConnection bool) string {
	switch strings.ToLower(strings.TrimSpace(requested)) {
	case "":
		if !hasConnection || !connection.Connected {
			return "permission_denied"
		}
		return "success"
	case "success", "ready":
		return "success"
	case "empty", "degraded", "partial_failure", "permission_denied":
		return strings.ToLower(strings.TrimSpace(requested))
	default:
		return ""
	}
}

func awsScpGuardrailExecutorEntries(dryRunEntries []AWSRemediationDryRunEntry, planByID map[string]AWSPermissionBoundarySCPPlan, now time.Time) []AWSScpGuardrailExecutorEntry {
	entries := []AWSScpGuardrailExecutorEntry{}
	for _, entry := range dryRunEntries {
		if !awsScpGuardrailExecutorAdmits(entry) {
			continue
		}
		plan, ok := planByID[entry.SourceArtifactID]
		if !ok {
			continue
		}
		entries = append(entries, awsScpGuardrailExecutorEntriesFromDryRun(entry, plan, now)...)
	}
	return entries
}

func awsScpGuardrailExecutorAdmits(entry AWSRemediationDryRunEntry) bool {
	if !strings.EqualFold(entry.SourceType, "aws_permission_boundary_scp") {
		return false
	}
	if entry.DiffIntent.NoOp {
		return false
	}
	if !strings.EqualFold(strings.TrimSpace(entry.DiffIntent.Kind), "scp_diff") {
		return false
	}
	call := awsScpGuardrailExecutorIntendedCall(entry)
	switch call.Operation {
	case "CreatePolicy", "AttachPolicy":
		return true
	default:
		return false
	}
}

func awsScpGuardrailExecutorEntriesFromDryRun(entry AWSRemediationDryRunEntry, plan AWSPermissionBoundarySCPPlan, now time.Time) []AWSScpGuardrailExecutorEntry {
	targets := awsScpGuardrailExecutorPlanTargets(plan)
	if len(targets) == 0 {
		return nil
	}
	entries := make([]AWSScpGuardrailExecutorEntry, 0, len(targets))
	for _, target := range targets {
		scopedEntry := entry
		scopedEntry.IdempotencyKey = awsScpGuardrailExecutorScopedIdempotencyKey(entry, target)
		scopedPlan := awsScpGuardrailExecutorScopedPlan(plan, target)
		call := awsScpGuardrailExecutorIntendedCallForTarget(scopedEntry, scopedPlan, target)
		out := awsScpGuardrailExecutorEntryFromDryRunWithCall(scopedEntry, scopedPlan, call, now)
		out.ExecutionID = "aws-scp-guardrail-executor:" + stableAWSBlastRadiusToken("execution", entry.DryRunID, plan.PlanID, target.Scope, target.ID)
		entries = append(entries, out)
	}
	return entries
}

func awsScpGuardrailExecutorEntryFromDryRun(entry AWSRemediationDryRunEntry, plan AWSPermissionBoundarySCPPlan, now time.Time) AWSScpGuardrailExecutorEntry {
	return awsScpGuardrailExecutorEntryFromDryRunWithCall(entry, plan, awsScpGuardrailExecutorIntendedCall(entry), now)
}

func awsScpGuardrailExecutorEntryFromDryRunWithCall(entry AWSRemediationDryRunEntry, plan AWSPermissionBoundarySCPPlan, call AWSRemediationDryRunIntendedAPICall, now time.Time) AWSScpGuardrailExecutorEntry {
	preconditions := awsScpGuardrailExecutorPreconditions(entry, plan, call)
	simulation := awsScpGuardrailExecutorSimulation(entry, plan)
	verifications := awsScpGuardrailExecutorVerifications(entry, plan)
	state := awsScpGuardrailExecutorState(entry, preconditions)
	executionID := "aws-scp-guardrail-executor:" + stableAWSBlastRadiusToken("execution", entry.DryRunID, plan.PlanID)
	out := AWSScpGuardrailExecutorEntry{
		ExecutionID:        executionID,
		CalculationVersion: awsScpGuardrailExecutorVersion,
		DryRunID:           entry.DryRunID,
		ApprovalID:         entry.ApprovalID,
		CaseID:             entry.CaseID,
		PlanID:             plan.PlanID,
		SourceArtifactID:   entry.SourceArtifactID,
		State:              state,
		Severity:           firstNonEmptyAWSValue(entry.Severity, plan.Severity),
		Score:              entry.Score,
		Confidence:         entry.Confidence,
		Title:              fmt.Sprintf("SCP guardrail execution: %s", firstNonEmptyAWSValue(plan.Title, entry.Title)),
		Summary:            fmt.Sprintf("Approved SCP guardrail execution record for plan %s (dry-run %s); Identrail records the projected Organizations intent and never calls AWS write APIs at this layer.", plan.PlanID, entry.DryRunID),
		AccountID:          firstNonEmptyAWSValue(entry.AccountID, plan.AccountID),
		Region:             firstNonEmptyAWSValue(entry.Region, plan.Region),
		Operation:          call.Operation,
		IdempotencyKey:     entry.IdempotencyKey,
		TargetAccountIDs:   emptyStrings(dedupeStrings(plan.TargetAccountIDs)),
		TargetOUPaths:      emptyStrings(dedupeStrings(plan.TargetOUPaths)),
		PreventedBehavior:  plan.PreventedBehavior,
		StatementSnippets:  plan.StatementSnippets,
		BreakageProjection: plan.BreakageProjection,
		IntendedAPICall:    call,
		Preconditions:      preconditions,
		BoundarySimulation: simulation,
		Verifications:      verifications,
		RollbackPlan:       plan.RollbackPlan,
		VerificationPlan:   plan.VerificationPlan,
		AuditTrail:         awsScpGuardrailExecutorAuditTrail(entry, state, plan, now),
		KillSwitchEngaged:  entry.KillSwitchEngaged,
		ReadOnlyProjection: true,
		SourceSignals:      dedupeStrings(append([]string{"aws_permission_boundary_scp", "scp", "scp_guardrail_executor", "remediation_dry_run"}, entry.SourceSignals...)),
		Evidence:           plan.Evidence,
		EvidenceBoundary:   awsScpGuardrailExecutorEvidenceBoundary(),
		ImpactedNodes:      dedupeStrings(append(append(append([]string{}, plan.TargetAccountIDs...), plan.TargetOUPaths...), append(entry.ImpactedNodes, plan.ImpactedNodes...)...)),
		ImpactedPath:       plan.ImpactedPath,
		NextAction:         awsScpGuardrailExecutorNextAction(state, call.Operation),
		ProjectedAt:        now,
		CreatedAt:          firstNonZeroAWSScpGuardrailExecutorTime(entry.CreatedAt, plan.CreatedAt, now),
		UpdatedAt:          now,
	}
	out.ReadyForLiveApply = state == awsScpGuardrailExecutorStateProjected && entry.ReadyForApply && !entry.KillSwitchEngaged
	return out
}

func awsScpGuardrailExecutorPlanTargets(plan AWSPermissionBoundarySCPPlan) []awsScpGuardrailExecutorTarget {
	targets := []awsScpGuardrailExecutorTarget{}
	for _, ou := range emptyStrings(dedupeStrings(plan.TargetOUPaths)) {
		scope := "ou"
		if strings.TrimSpace(ou) == "/" {
			scope = "root"
		}
		targets = append(targets, awsScpGuardrailExecutorTarget{Scope: scope, ID: ou})
	}
	for _, accountID := range emptyStrings(dedupeStrings(plan.TargetAccountIDs)) {
		targets = append(targets, awsScpGuardrailExecutorTarget{Scope: "account", ID: accountID})
	}
	return targets
}

func awsScpGuardrailExecutorScopedPlan(plan AWSPermissionBoundarySCPPlan, target awsScpGuardrailExecutorTarget) AWSPermissionBoundarySCPPlan {
	scoped := plan
	switch target.Scope {
	case "account":
		scoped.TargetAccountIDs = []string{target.ID}
		scoped.TargetOUPaths = nil
	default:
		scoped.TargetAccountIDs = nil
		scoped.TargetOUPaths = []string{target.ID}
	}
	scoped.ImpactedNodes = dedupeStrings(append([]string{target.ID}, plan.ImpactedNodes...))
	return scoped
}

func awsScpGuardrailExecutorScopedIdempotencyKey(entry AWSRemediationDryRunEntry, target awsScpGuardrailExecutorTarget) string {
	key := strings.TrimSpace(entry.IdempotencyKey)
	if key == "" {
		return ""
	}
	return key + "#" + stableAWSBlastRadiusToken("scp-target", target.Scope, target.ID)
}

func awsScpGuardrailExecutorIntendedCall(entry AWSRemediationDryRunEntry) AWSRemediationDryRunIntendedAPICall {
	if len(entry.IntendedAPICalls) > 0 {
		call := entry.IntendedAPICalls[0]
		if len(call.ParameterRefs) > 0 {
			call.ParameterRefs = append([]string{}, call.ParameterRefs...)
		}
		return call
	}
	return AWSRemediationDryRunIntendedAPICall{
		Service:          "organizations",
		Operation:        "AttachPolicy",
		TargetResource:   firstString(entry.ImpactedNodes),
		ParameterRefs:    []string{entry.IdempotencyKey, "scp_ref://" + entry.CaseID + "/after"},
		Idempotent:       true,
		RequiresApproval: true,
	}
}

func awsScpGuardrailExecutorIntendedCallForTarget(entry AWSRemediationDryRunEntry, plan AWSPermissionBoundarySCPPlan, target awsScpGuardrailExecutorTarget) AWSRemediationDryRunIntendedAPICall {
	call := awsScpGuardrailExecutorIntendedCall(entry)
	call.Service = "organizations"
	call.Operation = "AttachPolicy"
	call.TargetResource = firstNonEmptyAWSValue(target.ID, firstString(emptyStrings(plan.TargetOUPaths)), firstString(emptyStrings(plan.TargetAccountIDs)), call.TargetResource, firstString(entry.ImpactedNodes))
	if len(call.ParameterRefs) == 0 {
		call.ParameterRefs = []string{entry.IdempotencyKey, "scp_ref://" + entry.CaseID + "/after"}
	} else {
		call.ParameterRefs[0] = entry.IdempotencyKey
		if len(call.ParameterRefs) == 1 {
			call.ParameterRefs = append(call.ParameterRefs, "scp_ref://"+entry.CaseID+"/after")
		}
	}
	call.Idempotent = true
	call.RequiresApproval = true
	return call
}

func awsScpGuardrailExecutorPreconditions(entry AWSRemediationDryRunEntry, plan AWSPermissionBoundarySCPPlan, call AWSRemediationDryRunIntendedAPICall) []AWSScpGuardrailExecutorPrecondition {
	targetScopeCount := len(emptyStrings(plan.TargetAccountIDs)) + len(emptyStrings(plan.TargetOUPaths))
	preconditions := []AWSScpGuardrailExecutorPrecondition{
		{Name: "dry_run_would_succeed", Status: awsScpGuardrailExecutorGateStatus(entry.Outcome == awsRemediationDryRunOutcomeWouldSucceed), Rationale: "Upstream dry-run must project would_succeed before any live apply."},
		{Name: "ready_for_apply", Status: awsScpGuardrailExecutorGateStatus(entry.ReadyForApply), Rationale: "Upstream dry-run must declare ready_for_apply=true before any live apply."},
		{Name: "kill_switch_off", Status: awsScpGuardrailExecutorGateStatus(!entry.KillSwitchEngaged), Rationale: "Tenant-scoped remediation kill switch must be off."},
		{Name: "idempotency_key_present", Status: awsScpGuardrailExecutorGateStatus(strings.TrimSpace(entry.IdempotencyKey) != ""), Rationale: "Deterministic idempotency key must be present so retries do not double-apply."},
		{Name: "scp_guardrail_plan", Status: awsScpGuardrailExecutorGateStatus(strings.EqualFold(plan.Kind, awsSCPKind)), Rationale: "Only SCP guardrail plans are executable here; permission boundary execution belongs to its own executor."},
		{Name: "plan_ready_for_apply", Status: awsScpGuardrailExecutorGateStatus(plan.ReadyForApply), Rationale: "Upstream SCP guardrail plan must declare ready_for_apply=true."},
		{Name: "target_scope_captured", Status: awsScpGuardrailExecutorGateStatus(targetScopeCount > 0), Rationale: "At least one captured Organizations account or OU target must be present."},
		{Name: "breakage_level_low", Status: awsScpGuardrailExecutorGateStatus(strings.EqualFold(plan.BreakageProjection.Level, "low")), Rationale: "SCP guardrail breakage projection must be low before live apply."},
		{Name: "operation_supported", Status: awsScpGuardrailExecutorGateStatus(call.Service == "organizations" && (call.Operation == "AttachPolicy" || call.Operation == "CreatePolicy")), Rationale: "Executor only supports AWS Organizations SCP policy create/attach operations."},
	}
	if len(entry.FailedPrereqs) > 0 {
		preconditions = append(preconditions, AWSScpGuardrailExecutorPrecondition{
			Name:      "upstream_prerequisites",
			Status:    "blocked",
			Rationale: fmt.Sprintf("Upstream dry-run still has %d failed prerequisite(s); resolve them before retrying.", len(entry.FailedPrereqs)),
		})
	}
	return preconditions
}

func awsScpGuardrailExecutorGateStatus(ok bool) string {
	if ok {
		return "passed"
	}
	return "blocked"
}

func awsScpGuardrailExecutorSimulation(entry AWSRemediationDryRunEntry, plan AWSPermissionBoundarySCPPlan) AWSScpGuardrailExecutorSimulation {
	beforeRef := firstNonEmptyAWSValue(entry.DiffIntent.BeforeRef, "scp_before://"+plan.PlanID)
	afterRef := firstNonEmptyAWSValue(entry.DiffIntent.AfterRef, "scp_after://"+plan.PlanID)
	outcome := "would_attach_guardrail"
	if !strings.EqualFold(plan.BreakageProjection.Level, "low") {
		outcome = "regression_risk"
	}
	if !plan.ReadyForApply {
		outcome = "pending_planner_evidence"
	}
	return AWSScpGuardrailExecutorSimulation{
		SimulationRef:      fmt.Sprintf("organizations:scp_simulate://%s/scp-guardrail", plan.PlanID),
		Outcome:            outcome,
		BeforeRef:          beforeRef,
		AfterRef:           afterRef,
		DeniedActionCount:  len(awsRemediationSCPDeniedActions(plan)),
		TargetAccountCount: len(emptyStrings(plan.TargetAccountIDs)),
		TargetOUCount:      len(emptyStrings(plan.TargetOUPaths)),
		Signals:            dedupeStrings(append([]string{"scp_guardrail"}, plan.BreakageProjection.Signals...)),
	}
}

func awsScpGuardrailExecutorVerifications(entry AWSRemediationDryRunEntry, plan AWSPermissionBoundarySCPPlan) []AWSScpGuardrailExecutorVerification {
	out := []AWSScpGuardrailExecutorVerification{
		{Source: "cloudtrail", Signal: "expected_api_call_observed", Status: "pending", Description: "After live execution, confirm the Organizations SCP policy attach appears in CloudTrail for the target account or OU."},
		{Source: "organizations", Signal: "effective_policy_matches", Status: "pending", Description: "Confirm the effective SCP for the target account or OU includes the intended guardrail statement metadata ref."},
		{Source: "cross_account_trust", Signal: "finding_resolved", Status: "pending", Description: "Re-run cross-account trust analysis and confirm the source finding is resolved or no longer reintroduced."},
	}
	for _, check := range entry.VerificationChecks {
		if check.Source == "" {
			continue
		}
		out = append(out, AWSScpGuardrailExecutorVerification{Source: check.Source, Signal: check.Signal, Status: "pending", Description: check.Description})
	}
	for _, signal := range plan.VerificationPlan.SuccessSignals {
		out = append(out, AWSScpGuardrailExecutorVerification{Source: "planner", Signal: signal, Status: "pending", Description: "Confirm the planner success signal after live execution."})
	}
	return out
}

func awsScpGuardrailExecutorState(entry AWSRemediationDryRunEntry, preconditions []AWSScpGuardrailExecutorPrecondition) string {
	if entry.KillSwitchEngaged {
		return awsScpGuardrailExecutorStateBlocked
	}
	if entry.Outcome == awsRemediationDryRunOutcomeBlocked || entry.Outcome == awsRemediationDryRunOutcomeKillSwitched {
		return awsScpGuardrailExecutorStateBlocked
	}
	hasBlockedPrecondition := false
	for _, precondition := range preconditions {
		if precondition.Status != "blocked" {
			continue
		}
		hasBlockedPrecondition = true
		if awsScpGuardrailExecutorPreconditionIsSafety(precondition.Name) {
			return awsScpGuardrailExecutorStateBlocked
		}
	}
	if hasBlockedPrecondition {
		return awsScpGuardrailExecutorStatePreconditionFailed
	}
	if entry.Outcome != awsRemediationDryRunOutcomeWouldSucceed || !entry.ReadyForApply {
		return awsScpGuardrailExecutorStatePreconditionFailed
	}
	return awsScpGuardrailExecutorStateProjected
}

func awsScpGuardrailExecutorPreconditionIsSafety(name string) bool {
	switch name {
	case "kill_switch_off", "idempotency_key_present", "scp_guardrail_plan", "target_scope_captured", "operation_supported":
		return true
	}
	return false
}

func awsScpGuardrailExecutorNextAction(state, operation string) string {
	switch state {
	case awsScpGuardrailExecutorStateProjected:
		return fmt.Sprintf("SCP guardrail operation=%s is ready for the wave-8 apply runtime once its feature flag opens.", operation)
	case awsScpGuardrailExecutorStatePreconditionFailed:
		return "One or more preconditions failed; advance the upstream dry-run or SCP guardrail plan before retrying."
	case awsScpGuardrailExecutorStateBlocked:
		return "A safety precondition or the tenant kill switch is blocking this entry; satisfy the failing check before retrying."
	}
	return "Inspect this entry for the projected next action."
}

func awsScpGuardrailExecutorAuditTrail(entry AWSRemediationDryRunEntry, state string, plan AWSPermissionBoundarySCPPlan, now time.Time) []AWSScpGuardrailExecutorAuditEntry {
	trail := []AWSScpGuardrailExecutorAuditEntry{}
	trail = append(trail, entry.AuditTrail...)
	trail = append(trail, AWSScpGuardrailExecutorAuditEntry{
		EventID:    stableAWSBlastRadiusToken("scp-guardrail-projected", entry.DryRunID, plan.PlanID),
		Actor:      "identrail-scp-guardrail-executor",
		EventType:  "scp_guardrail_execution_projected",
		OccurredAt: now,
		Notes:      fmt.Sprintf("Plan=%s state=%s target_accounts=%d target_ous=%d; Identrail did not call any AWS write API at this layer.", plan.PlanID, state, len(emptyStrings(plan.TargetAccountIDs)), len(emptyStrings(plan.TargetOUPaths))),
	})
	return trail
}

func awsScpGuardrailExecutorRelationships(entries []AWSScpGuardrailExecutorEntry) []AWSScpGuardrailExecutorRelationship {
	relationships := []AWSScpGuardrailExecutorRelationship{}
	for _, entry := range entries {
		evidenceRef := awsScpGuardrailExecutorFirstEvidenceRef(entry.Evidence)
		for _, target := range append(append([]string{}, entry.TargetAccountIDs...), entry.TargetOUPaths...) {
			if strings.TrimSpace(target) == "" {
				continue
			}
			relationships = append(relationships, AWSScpGuardrailExecutorRelationship{
				ExecutionID: entry.ExecutionID,
				Type:        "scp_guardrail_targets_scope",
				FromNodeID:  entry.ExecutionID,
				ToNodeID:    target,
				EvidenceRef: evidenceRef,
			})
		}
	}
	return relationships
}

func awsScpGuardrailExecutorFirstEvidenceRef(evidence []AWSScpGuardrailExecutorEvidence) string {
	for _, item := range evidence {
		if strings.TrimSpace(item.EvidenceRef) != "" {
			return item.EvidenceRef
		}
	}
	return ""
}

func summarizeAWSScpGuardrailExecutorEntries(all, filtered []AWSScpGuardrailExecutorEntry, relationships []AWSScpGuardrailExecutorRelationship) AWSScpGuardrailExecutorSummary {
	summary := AWSScpGuardrailExecutorSummary{
		TotalEntries:    len(all),
		FilteredEntries: len(filtered),
		StateCounts:     map[string]int{},
		OperationCounts: map[string]int{},
		SeverityCounts:  map[string]int{},
	}
	confidenceTotal := 0.0
	for _, entry := range filtered {
		summary.StateCounts[entry.State]++
		if strings.TrimSpace(entry.Operation) != "" {
			summary.OperationCounts[entry.Operation]++
		}
		if strings.TrimSpace(entry.Severity) != "" {
			summary.SeverityCounts[entry.Severity]++
		}
		if entry.ReadyForLiveApply {
			summary.ReadyForLiveApplyCount++
		}
		if entry.KillSwitchEngaged {
			summary.KillSwitchEngagedCount++
		}
		for _, precondition := range entry.Preconditions {
			if precondition.Status == "blocked" {
				summary.FailedPreconditionCount++
			}
		}
		summary.TargetAccountCount += len(entry.TargetAccountIDs)
		summary.TargetOUCount += len(entry.TargetOUPaths)
		summary.VerificationCount += len(entry.Verifications)
		if entry.Score > summary.HighestScore {
			summary.HighestScore = entry.Score
		}
		confidenceTotal += entry.Confidence
	}
	summary.RelationshipCount = len(relationships)
	if len(filtered) > 0 {
		summary.AverageConfidencePct = int((confidenceTotal/float64(len(filtered)))*100 + 0.5)
	}
	return summary
}

func filterAWSScpGuardrailExecutorEntries(entries []AWSScpGuardrailExecutorEntry, request AWSScpGuardrailExecutorRequest) ([]AWSScpGuardrailExecutorEntry, map[string]string) {
	filters := map[string]string{
		"account_id":   strings.TrimSpace(request.AccountID),
		"region":       strings.TrimSpace(request.Region),
		"dry_run_id":   strings.TrimSpace(request.DryRunID),
		"case_id":      strings.TrimSpace(request.CaseID),
		"plan_id":      strings.TrimSpace(request.PlanID),
		"operation":    normalizeAWSRuntimeEventFilterToken(request.Operation),
		"target_scope": normalizeAWSRuntimeEventFilterToken(request.TargetScope),
		"state":        normalizeAWSRuntimeEventFilterToken(request.State),
		"severity":     normalizeAWSRuntimeEventFilterToken(request.Severity),
		"search":       strings.TrimSpace(request.Search),
	}
	for key, value := range filters {
		if strings.TrimSpace(value) == "" || strings.EqualFold(value, "all") {
			delete(filters, key)
		}
	}
	applied := map[string]string{}
	for key, value := range filters {
		applied[key] = value
	}
	filtered := make([]AWSScpGuardrailExecutorEntry, 0, len(entries))
	for _, entry := range entries {
		if filters["account_id"] != "" && !awsScpGuardrailExecutorAccountMatch(entry, filters["account_id"]) {
			continue
		}
		if filters["region"] != "" && !awsScpGuardrailExecutorRegionMatch(entry, filters["region"]) {
			continue
		}
		if filters["dry_run_id"] != "" && !strings.EqualFold(filters["dry_run_id"], entry.DryRunID) {
			continue
		}
		if filters["case_id"] != "" && !strings.EqualFold(filters["case_id"], entry.CaseID) {
			continue
		}
		if filters["plan_id"] != "" && !strings.EqualFold(filters["plan_id"], entry.PlanID) {
			continue
		}
		if filters["operation"] != "" && filters["operation"] != normalizeAWSRuntimeEventFilterToken(entry.Operation) {
			continue
		}
		if filters["target_scope"] != "" && filters["target_scope"] != awsScpGuardrailExecutorTargetScope(entry) {
			continue
		}
		if filters["state"] != "" && filters["state"] != normalizeAWSRuntimeEventFilterToken(entry.State) {
			continue
		}
		if filters["severity"] != "" && filters["severity"] != normalizeAWSRuntimeEventFilterToken(entry.Severity) {
			continue
		}
		if filters["search"] != "" && !awsScpGuardrailExecutorSearchMatch(entry, filters["search"]) {
			continue
		}
		filtered = append(filtered, entry)
	}
	return filtered, applied
}

func awsScpGuardrailExecutorRegionMatch(entry AWSScpGuardrailExecutorEntry, region string) bool {
	region = strings.TrimSpace(region)
	if region == "" {
		return true
	}
	if strings.TrimSpace(entry.Region) == "" {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(entry.Region), region)
}

func awsScpGuardrailExecutorAccountMatch(entry AWSScpGuardrailExecutorEntry, accountID string) bool {
	accountID = strings.TrimSpace(accountID)
	if accountID == "" {
		return true
	}
	if strings.TrimSpace(entry.AccountID) == accountID {
		return true
	}
	for _, targetAccountID := range entry.TargetAccountIDs {
		if strings.TrimSpace(targetAccountID) == accountID {
			return true
		}
	}
	return false
}

func awsScpGuardrailExecutorTargetScope(entry AWSScpGuardrailExecutorEntry) string {
	if len(emptyStrings(entry.TargetAccountIDs)) > 0 {
		return "account"
	}
	for _, target := range emptyStrings(entry.TargetOUPaths) {
		if strings.TrimSpace(target) == "/" {
			return "root"
		}
		return "ou"
	}
	return ""
}

func awsScpGuardrailExecutorSearchMatch(entry AWSScpGuardrailExecutorEntry, needle string) bool {
	needle = strings.ToLower(strings.TrimSpace(needle))
	if needle == "" {
		return true
	}
	values := []string{
		entry.ExecutionID, entry.DryRunID, entry.ApprovalID, entry.CaseID, entry.PlanID,
		entry.SourceArtifactID, entry.State, entry.Severity, entry.Title, entry.Summary,
		entry.Operation, entry.IdempotencyKey, entry.PreventedBehavior, entry.NextAction,
		entry.IntendedAPICall.Service, entry.IntendedAPICall.Operation, entry.IntendedAPICall.TargetResource,
		entry.BoundarySimulation.SimulationRef, entry.BoundarySimulation.Outcome, entry.BoundarySimulation.BeforeRef, entry.BoundarySimulation.AfterRef,
		entry.BreakageProjection.Level, entry.BreakageProjection.Rationale,
	}
	values = append(values, entry.TargetAccountIDs...)
	values = append(values, entry.TargetOUPaths...)
	values = append(values, entry.SourceSignals...)
	values = append(values, entry.IntendedAPICall.ParameterRefs...)
	values = append(values, entry.BoundarySimulation.Signals...)
	for _, snippet := range entry.StatementSnippets {
		values = append(values, snippet.StatementSID, snippet.Effect, snippet.ChangeKind, snippet.BeforeRef, snippet.AfterRef, snippet.Rationale)
		values = append(values, snippet.DeniedActions...)
		values = append(values, snippet.AllowedActions...)
		values = append(values, snippet.ResourceScope...)
		values = append(values, snippet.ConditionKeys...)
	}
	for _, precondition := range entry.Preconditions {
		values = append(values, precondition.Name, precondition.Status, precondition.Rationale)
	}
	for _, verification := range entry.Verifications {
		values = append(values, verification.Source, verification.Signal, verification.Status, verification.Description)
	}
	for _, audit := range entry.AuditTrail {
		values = append(values, audit.EventType, audit.Actor, audit.Notes)
	}
	for _, evidence := range entry.Evidence {
		values = append(values, evidence.Source, evidence.Label, evidence.EvidenceRef, evidence.Relationship)
	}
	for _, value := range values {
		if strings.Contains(strings.ToLower(value), needle) {
			return true
		}
	}
	return false
}

func summarizeAWSScpGuardrailExecutorStatus(dryRunStatus, planStatus string, filtered []AWSScpGuardrailExecutorEntry, diagnostics []AWSScpGuardrailExecutorDiagnostic) (string, float64) {
	if dryRunStatus == awsPlatformDependencyStatusBlocked || planStatus == awsPlatformDependencyStatusBlocked {
		return awsPlatformDependencyStatusBlocked, 0.35
	}
	for _, diagnostic := range diagnostics {
		if diagnostic.Retryable {
			return awsPlatformDependencyStatusDegraded, 0.72
		}
	}
	if dryRunStatus == awsPlatformDependencyStatusDegraded || planStatus == awsPlatformDependencyStatusDegraded {
		return awsPlatformDependencyStatusDegraded, 0.74
	}
	if len(filtered) == 0 {
		return awsPlatformDependencyStatusReady, 0.82
	}
	return awsPlatformDependencyStatusReady, 0.9
}

func awsScpGuardrailExecutorCaveats() []string {
	return []string{
		"SCP guardrail executor entries are read-only projections; Identrail never calls IAM/Organizations write APIs at this layer.",
		"Every precondition (approval dry-run readiness, planner readiness, bounded account/OU scope, low breakage, idempotency key) must pass before ready_for_live_apply becomes true.",
		"Rendered SCP policy documents stay behind metadata refs; this endpoint exposes scope, audit, rollback, and verification metadata only.",
	}
}

func awsScpGuardrailExecutorRemediationHints(source []string) []string {
	hints := []string{
		"Resolve any failed precondition before retrying; the dry-run and SCP planner upstreams own those gates.",
		"Use the idempotency key recorded here as the deterministic id when the wave-8 apply runtime creates or attaches the Organizations SCP.",
		"If the simulation outcome is `regression_risk`, reduce scope or refresh cross-account-trust evidence before live apply.",
	}
	hints = append(hints, source...)
	return dedupeStrings(hints)
}

func awsScpGuardrailExecutorDiagnostics(dryRun []AWSRemediationApprovalDiagnostic, planner []AWSPermissionBoundarySCPDiagnostic) []AWSScpGuardrailExecutorDiagnostic {
	out := make([]AWSScpGuardrailExecutorDiagnostic, 0, len(dryRun)+len(planner))
	for _, diagnostic := range dryRun {
		out = append(out, AWSScpGuardrailExecutorDiagnostic{
			Collector:   diagnostic.Collector,
			SourceID:    diagnostic.SourceID,
			Code:        diagnostic.Code,
			Message:     diagnostic.Message,
			Remediation: diagnostic.Remediation,
			Retryable:   diagnostic.Retryable,
		})
	}
	for _, diagnostic := range planner {
		out = append(out, AWSScpGuardrailExecutorDiagnostic(diagnostic))
	}
	return out
}

func awsScpGuardrailExecutorCoverageGaps(dryRun []AWSRemediationApprovalCoverageGap, planner []AWSPermissionBoundarySCPCoverageGap) []AWSScpGuardrailExecutorCoverageGap {
	gaps := []AWSScpGuardrailExecutorCoverageGap{}
	for _, gap := range dryRun {
		gaps = append(gaps, AWSScpGuardrailExecutorCoverageGap{
			Capability:  gap.Capability,
			Status:      gap.Status,
			Reason:      gap.Reason,
			Remediation: gap.Remediation,
		})
	}
	for _, gap := range planner {
		gaps = append(gaps, AWSScpGuardrailExecutorCoverageGap(gap))
	}
	return gaps
}

func awsScpGuardrailExecutorEvidenceBoundary() string {
	return "metadata_only_no_rendered_policy_bodies_no_secret_values_no_workload_payloads_tenant_workspace_project_connector_account_region_scoped"
}

func firstNonZeroAWSScpGuardrailExecutorTime(values ...time.Time) time.Time {
	for _, value := range values {
		if !value.IsZero() {
			return value
		}
	}
	return time.Time{}
}
