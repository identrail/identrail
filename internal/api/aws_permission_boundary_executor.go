package api

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	awsPermissionBoundaryExecutorCurrentIssue = 1540
	awsPermissionBoundaryExecutorVersion      = "aws-permission-boundary-executor-v1"

	awsPermissionBoundaryExecutorStateProjected          = "projected"
	awsPermissionBoundaryExecutorStatePreconditionFailed = "precondition_failed"
	awsPermissionBoundaryExecutorStateBlocked            = "blocked"
)

// AWSPermissionBoundaryExecutorRequest scopes the deterministic permission
// boundary executor projection to one AWS connector plus optional drill-down
// filters.
type AWSPermissionBoundaryExecutorRequest struct {
	ConnectorID  string `json:"connector_id,omitempty"`
	FixtureState string `json:"fixture_state,omitempty"`
	AccountID    string `json:"account_id,omitempty"`
	Region       string `json:"region,omitempty"`
	DryRunID     string `json:"dry_run_id,omitempty"`
	CaseID       string `json:"case_id,omitempty"`
	PlanID       string `json:"plan_id,omitempty"`
	Operation    string `json:"operation,omitempty"`
	State        string `json:"state,omitempty"`
	Severity     string `json:"severity,omitempty"`
	Search       string `json:"search,omitempty"`
}

type AWSPermissionBoundaryExecutorEvidence = AWSPermissionBoundarySCPEvidence
type AWSPermissionBoundaryExecutorPathStep = AWSPermissionBoundarySCPPathStep
type AWSPermissionBoundaryExecutorDiagnostic = AWSPermissionBoundarySCPDiagnostic
type AWSPermissionBoundaryExecutorCoverageGap = AWSPermissionBoundarySCPCoverageGap
type AWSPermissionBoundaryExecutorAuditEntry = AWSRemediationApprovalAuditEntry

// AWSPermissionBoundaryExecutorPrecondition is one safety check that must pass
// before the executor marks a record ready_for_live_apply.
type AWSPermissionBoundaryExecutorPrecondition struct {
	Name      string `json:"name"`
	Status    string `json:"status"`
	Rationale string `json:"rationale"`
}

// AWSPermissionBoundaryExecutorSimulation records the metadata-only simulator
// result used to decide whether a boundary is safe to apply.
type AWSPermissionBoundaryExecutorSimulation struct {
	SimulationRef       string   `json:"simulation_ref"`
	Outcome             string   `json:"outcome"`
	BeforeRef           string   `json:"before_ref"`
	AfterRef            string   `json:"after_ref"`
	DeniedActionCount   int      `json:"denied_action_count"`
	TargetIdentityCount int      `json:"target_identity_count"`
	Signals             []string `json:"signals,omitempty"`
}

// AWSPermissionBoundaryExecutorVerification describes one post-apply check a
// downstream live executor must record before the execution can be considered
// succeeded.
type AWSPermissionBoundaryExecutorVerification struct {
	Source      string `json:"source"`
	Signal      string `json:"signal"`
	Status      string `json:"status"`
	Description string `json:"description"`
}

// AWSPermissionBoundaryExecutorRelationship surfaces executor->graph edges.
type AWSPermissionBoundaryExecutorRelationship struct {
	ExecutionID string `json:"execution_id"`
	Type        string `json:"type"`
	FromNodeID  string `json:"from_node_id"`
	ToNodeID    string `json:"to_node_id"`
	EvidenceRef string `json:"evidence_ref,omitempty"`
}

// AWSPermissionBoundaryExecutorEntry is the persisted-record-shaped contract
// for an approved permission boundary execution projection. It carries
// metadata refs only and never inlines rendered IAM policy documents, secret
// values, or workload payloads.
type AWSPermissionBoundaryExecutorEntry struct {
	ExecutionID           string                                      `json:"execution_id"`
	CalculationVersion    string                                      `json:"calculation_version"`
	DryRunID              string                                      `json:"dry_run_id"`
	ApprovalID            string                                      `json:"approval_id"`
	CaseID                string                                      `json:"case_id"`
	PlanID                string                                      `json:"plan_id"`
	SourceArtifactID      string                                      `json:"source_artifact_id"`
	State                 string                                      `json:"state"`
	Severity              string                                      `json:"severity"`
	Score                 int                                         `json:"score"`
	Confidence            float64                                     `json:"confidence"`
	Title                 string                                      `json:"title"`
	Summary               string                                      `json:"summary"`
	AccountID             string                                      `json:"account_id"`
	Region                string                                      `json:"region"`
	Operation             string                                      `json:"operation"`
	IdempotencyKey        string                                      `json:"idempotency_key"`
	TargetIdentityNodeIDs []string                                    `json:"target_identity_node_ids,omitempty"`
	TargetAccountIDs      []string                                    `json:"target_account_ids,omitempty"`
	TargetOUPaths         []string                                    `json:"target_ou_paths,omitempty"`
	PreventedBehavior     string                                      `json:"prevented_behavior"`
	StatementSnippets     []AWSPermissionBoundarySCPStatementSnippet  `json:"statement_snippets"`
	BreakageProjection    AWSPermissionBoundarySCPBreakageProjection  `json:"breakage_projection"`
	IntendedAPICall       AWSRemediationDryRunIntendedAPICall         `json:"intended_api_call"`
	Preconditions         []AWSPermissionBoundaryExecutorPrecondition `json:"preconditions"`
	BoundarySimulation    AWSPermissionBoundaryExecutorSimulation     `json:"boundary_simulation"`
	Verifications         []AWSPermissionBoundaryExecutorVerification `json:"verifications"`
	RollbackPlan          AWSPermissionBoundarySCPRollbackPlan        `json:"rollback_plan"`
	VerificationPlan      AWSPermissionBoundarySCPVerificationPlan    `json:"verification_plan"`
	AuditTrail            []AWSPermissionBoundaryExecutorAuditEntry   `json:"audit_trail"`
	KillSwitchEngaged     bool                                        `json:"kill_switch_engaged"`
	ReadyForLiveApply     bool                                        `json:"ready_for_live_apply"`
	ReadOnlyProjection    bool                                        `json:"read_only_projection"`
	SourceSignals         []string                                    `json:"source_signals"`
	Evidence              []AWSPermissionBoundaryExecutorEvidence     `json:"evidence"`
	EvidenceBoundary      string                                      `json:"evidence_boundary"`
	ImpactedNodes         []string                                    `json:"impacted_nodes"`
	ImpactedPath          []AWSPermissionBoundaryExecutorPathStep     `json:"impacted_path"`
	NextAction            string                                      `json:"next_action"`
	ProjectedAt           time.Time                                   `json:"projected_at"`
	CreatedAt             time.Time                                   `json:"created_at"`
	UpdatedAt             time.Time                                   `json:"updated_at"`
}

// AWSPermissionBoundaryExecutorSummary aggregates the unfiltered/filtered set.
type AWSPermissionBoundaryExecutorSummary struct {
	TotalEntries            int            `json:"total_entries"`
	FilteredEntries         int            `json:"filtered_entries"`
	StateCounts             map[string]int `json:"state_counts"`
	OperationCounts         map[string]int `json:"operation_counts"`
	SeverityCounts          map[string]int `json:"severity_counts"`
	ReadyForLiveApplyCount  int            `json:"ready_for_live_apply_count"`
	KillSwitchEngagedCount  int            `json:"kill_switch_engaged_count"`
	FailedPreconditionCount int            `json:"failed_precondition_count"`
	TargetIdentityCount     int            `json:"target_identity_count"`
	VerificationCount       int            `json:"verification_count"`
	RelationshipCount       int            `json:"relationship_count"`
	HighestScore            int            `json:"highest_score"`
	AverageConfidencePct    int            `json:"average_confidence_pct"`
}

// AWSPermissionBoundaryExecutorResult is the deterministic endpoint envelope.
type AWSPermissionBoundaryExecutorResult struct {
	TenantID           string                                      `json:"tenant_id"`
	WorkspaceID        string                                      `json:"workspace_id"`
	ProjectID          string                                      `json:"project_id"`
	ConnectorID        string                                      `json:"connector_id,omitempty"`
	AccountID          string                                      `json:"account_id,omitempty"`
	Region             string                                      `json:"region,omitempty"`
	ParentIssueNumber  int                                         `json:"parent_issue_number"`
	ParentIssueRef     string                                      `json:"parent_issue_ref"`
	CurrentIssueNumber int                                         `json:"current_issue_number"`
	CurrentIssueRef    string                                      `json:"current_issue_ref"`
	Version            string                                      `json:"version"`
	Status             string                                      `json:"status"`
	FixtureState       string                                      `json:"fixture_state,omitempty"`
	Confidence         float64                                     `json:"confidence"`
	CalculationVersion string                                      `json:"calculation_version"`
	AppliedFilters     map[string]string                           `json:"applied_filters"`
	Summary            AWSPermissionBoundaryExecutorSummary        `json:"summary"`
	Entries            []AWSPermissionBoundaryExecutorEntry        `json:"entries"`
	Relationships      []AWSPermissionBoundaryExecutorRelationship `json:"relationships"`
	Caveats            []string                                    `json:"caveats"`
	FailureReasons     []string                                    `json:"failure_reasons"`
	RemediationHints   []string                                    `json:"remediation_hints"`
	EvidenceLinks      []string                                    `json:"evidence_links"`
	CoverageGaps       []AWSPermissionBoundaryExecutorCoverageGap  `json:"coverage_gaps"`
	Diagnostics        []AWSPermissionBoundaryExecutorDiagnostic   `json:"diagnostics"`
	GeneratedAt        time.Time                                   `json:"generated_at"`
	UpdatedAt          time.Time                                   `json:"updated_at"`
}

// GetAWSPermissionBoundaryExecutor projects approved permission boundary
// executions by joining remediation dry-run entries (#1537) with permission
// boundary planner metadata (#1532). This layer is metadata-only: it records
// the controlled intent, preconditions, idempotency key, rollback metadata,
// and verification plan without calling live AWS write APIs.
func (s *Service) GetAWSPermissionBoundaryExecutor(ctx context.Context, workspaceID string, projectID string, request AWSPermissionBoundaryExecutorRequest) (AWSPermissionBoundaryExecutorResult, error) {
	project, scope, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return AWSPermissionBoundaryExecutorResult{}, err
	}
	connection, hasConnection, err := s.awsBaselineConnection(ctx, project, strings.TrimSpace(request.ConnectorID))
	if err != nil {
		return AWSPermissionBoundaryExecutorResult{}, err
	}
	now := s.Now().UTC()
	fixtureState := normalizeAWSPermissionBoundaryExecutorFixtureState(request.FixtureState, connection, hasConnection)
	if fixtureState == "" {
		return AWSPermissionBoundaryExecutorResult{}, ErrInvalidAWSConnectionRequest
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
		return AWSPermissionBoundaryExecutorResult{}, fmt.Errorf("permission boundary executor dry-run: %w", err)
	}
	plans, err := s.GetAWSPermissionBoundarySCPPlans(ctx, workspaceID, projectID, AWSPermissionBoundarySCPRequest{ConnectorID: connectorID, FixtureState: sourceFixtureState, Kind: awsPermissionBoundaryKind})
	if err != nil {
		return AWSPermissionBoundaryExecutorResult{}, fmt.Errorf("permission boundary executor plans: %w", err)
	}

	planByID := map[string]AWSPermissionBoundarySCPPlan{}
	for _, plan := range plans.Plans {
		if strings.EqualFold(plan.Kind, awsPermissionBoundaryKind) {
			planByID[plan.PlanID] = plan
		}
	}

	entries := awsPermissionBoundaryExecutorEntries(dryRun.Entries, planByID, now)
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].Score == entries[j].Score {
			return entries[i].ExecutionID < entries[j].ExecutionID
		}
		return entries[i].Score > entries[j].Score
	})
	filtered, applied := filterAWSPermissionBoundaryExecutorEntries(entries, request)
	relationships := awsPermissionBoundaryExecutorRelationships(filtered)
	diagnostics := awsPermissionBoundaryExecutorDiagnostics(dryRun.Diagnostics, plans.Diagnostics)
	coverageGaps := awsPermissionBoundaryExecutorCoverageGaps(dryRun.CoverageGaps, plans.CoverageGaps)
	status, confidence := summarizeAWSPermissionBoundaryExecutorStatus(dryRun.Status, plans.Status, filtered, diagnostics)

	return AWSPermissionBoundaryExecutorResult{
		TenantID:           scope.TenantID,
		WorkspaceID:        project.WorkspaceID,
		ProjectID:          project.ProjectID,
		ConnectorID:        connectorID,
		AccountID:          accountID,
		Region:             region,
		ParentIssueNumber:  awsPlatformDependencyParentIssue,
		ParentIssueRef:     awsIssueRef(awsPlatformDependencyParentIssue),
		CurrentIssueNumber: awsPermissionBoundaryExecutorCurrentIssue,
		CurrentIssueRef:    awsIssueRef(awsPermissionBoundaryExecutorCurrentIssue),
		Version:            awsPermissionBoundaryExecutorVersion,
		Status:             status,
		FixtureState:       sourceFixtureState,
		Confidence:         confidence,
		CalculationVersion: awsPermissionBoundaryExecutorVersion,
		AppliedFilters:     applied,
		Summary:            summarizeAWSPermissionBoundaryExecutorEntries(entries, filtered, relationships),
		Entries:            filtered,
		Relationships:      relationships,
		Caveats:            awsPermissionBoundaryExecutorCaveats(),
		FailureReasons:     dedupeStrings(append(append([]string{}, dryRun.FailureReasons...), plans.FailureReasons...)),
		RemediationHints:   awsPermissionBoundaryExecutorRemediationHints(append(dryRun.RemediationHints, plans.RemediationHints...)),
		EvidenceLinks: dedupeStrings([]string{
			awsIssueURL(awsPlatformDependencyParentIssue),
			awsIssueURL(awsPermissionBoundaryExecutorCurrentIssue),
			awsIssueURL(awsRemediationDryRunCurrentIssue),
			awsIssueURL(awsPermissionBoundarySCPCurrentIssue),
			"/docs/aws-permission-boundary-executor",
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

func normalizeAWSPermissionBoundaryExecutorFixtureState(requested string, connection AWSConnectionStatus, hasConnection bool) string {
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

func awsPermissionBoundaryExecutorEntries(dryRunEntries []AWSRemediationDryRunEntry, planByID map[string]AWSPermissionBoundarySCPPlan, now time.Time) []AWSPermissionBoundaryExecutorEntry {
	entries := []AWSPermissionBoundaryExecutorEntry{}
	for _, entry := range dryRunEntries {
		if !awsPermissionBoundaryExecutorAdmits(entry) {
			continue
		}
		plan, ok := planByID[entry.SourceArtifactID]
		if !ok {
			continue
		}
		entries = append(entries, awsPermissionBoundaryExecutorEntriesFromDryRun(entry, plan, now)...)
	}
	return entries
}

func awsPermissionBoundaryExecutorAdmits(entry AWSRemediationDryRunEntry) bool {
	if !strings.EqualFold(entry.SourceType, "aws_permission_boundary_scp") {
		return false
	}
	if entry.DiffIntent.NoOp {
		return false
	}
	if !strings.EqualFold(strings.TrimSpace(entry.DiffIntent.Kind), "permission_boundary_diff") {
		return false
	}
	call := awsPermissionBoundaryExecutorIntendedCall(entry)
	switch call.Operation {
	case "PutRolePermissionsBoundary", "PutUserPermissionsBoundary":
		return true
	default:
		return false
	}
}

func awsPermissionBoundaryExecutorEntriesFromDryRun(entry AWSRemediationDryRunEntry, plan AWSPermissionBoundarySCPPlan, now time.Time) []AWSPermissionBoundaryExecutorEntry {
	originalTargets := emptyStrings(plan.TargetIdentityNodeIDs)
	supportedTargets := awsPermissionBoundaryExecutorSupportedTargets(plan.TargetIdentityNodeIDs)
	if len(supportedTargets) == 0 {
		return nil
	}
	plan.TargetIdentityNodeIDs = supportedTargets
	targetsByOperation := awsPermissionBoundaryExecutorTargetsByOperation(supportedTargets)
	entries := make([]AWSPermissionBoundaryExecutorEntry, 0, len(supportedTargets))
	operations := make([]string, 0, len(targetsByOperation))
	for operation := range targetsByOperation {
		operations = append(operations, operation)
	}
	sort.Strings(operations)
	// The plan's account list was captured before unsupported targets were
	// filtered out and before this split into per-target entries, so it can
	// only be trusted as a fallback when the plan always described exactly
	// one target; otherwise it may carry accounts that belong to a dropped
	// target or a sibling target instead of the one this entry projects.
	accountFallback := plan.TargetAccountIDs
	if len(originalTargets) != 1 {
		accountFallback = nil
	}
	for _, operation := range operations {
		for _, target := range targetsByOperation[operation] {
			scopedPlan := plan
			scopedPlan.TargetIdentityNodeIDs = []string{target}
			scopedPlan.TargetAccountIDs = awsPermissionBoundaryExecutorScopedAccountsForTargets(scopedPlan.TargetIdentityNodeIDs, accountFallback)
			scopedPlan.AccountID = firstString(scopedPlan.TargetAccountIDs)
			scopedPlan.ImpactedNodes = emptyStrings(dedupeStrings(append(append([]string{}, scopedPlan.TargetIdentityNodeIDs...), plan.ImpactedNodes...)))
			scopedEntry := entry
			scopedEntry.IdempotencyKey = awsPermissionBoundaryExecutorScopedIdempotencyKey(entry, operation, scopedPlan.TargetIdentityNodeIDs)
			scopedEntry.AccountID = scopedPlan.AccountID
			out := awsPermissionBoundaryExecutorEntryFromDryRunWithCall(scopedEntry, scopedPlan, awsPermissionBoundaryExecutorIntendedCallForTargets(scopedEntry, scopedPlan.TargetIdentityNodeIDs, operation), now)
			if len(supportedTargets) > 1 {
				out.ExecutionID = "aws-permission-boundary-executor:" + stableAWSBlastRadiusToken("execution", entry.DryRunID, plan.PlanID, operation, target)
			}
			entries = append(entries, out)
		}
	}
	return entries
}

func awsPermissionBoundaryExecutorScopedIdempotencyKey(entry AWSRemediationDryRunEntry, operation string, targets []string) string {
	base := strings.TrimSpace(entry.IdempotencyKey)
	if base == "" {
		return ""
	}
	scopedTargets := strings.TrimSpace(strings.Join(emptyStrings(dedupeStrings(targets)), "|"))
	if scopedTargets == "" {
		return stableAWSBlastRadiusToken(base, operation)
	}
	return stableAWSBlastRadiusToken(base, operation, scopedTargets)
}

func awsPermissionBoundaryExecutorTargetsByOperation(targets []string) map[string][]string {
	out := map[string][]string{}
	for _, target := range emptyStrings(dedupeStrings(targets)) {
		operation := awsRemediationDryRunPutBoundaryOperation(target)
		out[operation] = append(out[operation], target)
	}
	return out
}

// awsPermissionBoundaryExecutorSupportedTargets keeps only explicitly
// classified IAM users and roles because permission boundaries cannot be
// attached to IAM groups or non-IAM resources.
func awsPermissionBoundaryExecutorSupportedTargets(targets []string) []string {
	out := []string{}
	for _, target := range emptyStrings(dedupeStrings(targets)) {
		switch awsRemediationDryRunClassifiedIAMPrincipalKind(target) {
		case "role", "user":
			out = append(out, target)
		default:
			continue
		}
	}
	return out
}

func awsPermissionBoundaryExecutorEntryFromDryRun(entry AWSRemediationDryRunEntry, plan AWSPermissionBoundarySCPPlan, now time.Time) AWSPermissionBoundaryExecutorEntry {
	return awsPermissionBoundaryExecutorEntryFromDryRunWithCall(entry, plan, awsPermissionBoundaryExecutorIntendedCall(entry), now)
}

func awsPermissionBoundaryExecutorEntryFromDryRunWithCall(entry AWSRemediationDryRunEntry, plan AWSPermissionBoundarySCPPlan, call AWSRemediationDryRunIntendedAPICall, now time.Time) AWSPermissionBoundaryExecutorEntry {
	preconditions := awsPermissionBoundaryExecutorPreconditions(entry, plan, call)
	simulation := awsPermissionBoundaryExecutorSimulation(entry, plan)
	verifications := awsPermissionBoundaryExecutorVerifications(entry, plan)
	state := awsPermissionBoundaryExecutorState(entry, preconditions)
	executionID := "aws-permission-boundary-executor:" + stableAWSBlastRadiusToken("execution", entry.DryRunID, plan.PlanID)
	out := AWSPermissionBoundaryExecutorEntry{
		ExecutionID:           executionID,
		CalculationVersion:    awsPermissionBoundaryExecutorVersion,
		DryRunID:              entry.DryRunID,
		ApprovalID:            entry.ApprovalID,
		CaseID:                entry.CaseID,
		PlanID:                plan.PlanID,
		SourceArtifactID:      entry.SourceArtifactID,
		State:                 state,
		Severity:              firstNonEmptyAWSValue(entry.Severity, plan.Severity),
		Score:                 entry.Score,
		Confidence:            entry.Confidence,
		Title:                 fmt.Sprintf("Permission boundary execution: %s", firstNonEmptyAWSValue(plan.Title, entry.Title)),
		Summary:               fmt.Sprintf("Approved permission boundary execution record for plan %s (dry-run %s); Identrail records the projected IAM boundary intent and never calls AWS write APIs at this layer.", plan.PlanID, entry.DryRunID),
		AccountID:             firstNonEmptyAWSValue(entry.AccountID, plan.AccountID),
		Region:                firstNonEmptyAWSValue(entry.Region, plan.Region),
		Operation:             call.Operation,
		IdempotencyKey:        entry.IdempotencyKey,
		TargetIdentityNodeIDs: emptyStrings(dedupeStrings(plan.TargetIdentityNodeIDs)),
		TargetAccountIDs:      emptyStrings(dedupeStrings(plan.TargetAccountIDs)),
		TargetOUPaths:         emptyStrings(dedupeStrings(plan.TargetOUPaths)),
		PreventedBehavior:     plan.PreventedBehavior,
		StatementSnippets:     plan.StatementSnippets,
		BreakageProjection:    plan.BreakageProjection,
		IntendedAPICall:       call,
		Preconditions:         preconditions,
		BoundarySimulation:    simulation,
		Verifications:         verifications,
		RollbackPlan:          plan.RollbackPlan,
		VerificationPlan:      plan.VerificationPlan,
		AuditTrail:            awsPermissionBoundaryExecutorAuditTrail(entry, state, plan, now),
		KillSwitchEngaged:     entry.KillSwitchEngaged,
		ReadOnlyProjection:    true,
		SourceSignals:         dedupeStrings(append([]string{"aws_permission_boundary_scp", "permission_boundary_executor", "remediation_dry_run"}, entry.SourceSignals...)),
		Evidence:              plan.Evidence,
		EvidenceBoundary:      awsPermissionBoundaryExecutorEvidenceBoundary(),
		ImpactedNodes:         dedupeStrings(append(append([]string{}, plan.TargetIdentityNodeIDs...), append(entry.ImpactedNodes, plan.ImpactedNodes...)...)),
		ImpactedPath:          plan.ImpactedPath,
		NextAction:            awsPermissionBoundaryExecutorNextAction(state, call.Operation),
		ProjectedAt:           now,
		CreatedAt:             firstNonZeroAWSPermissionBoundaryExecutorTime(entry.CreatedAt, plan.CreatedAt, now),
		UpdatedAt:             now,
	}
	out.ReadyForLiveApply = state == awsPermissionBoundaryExecutorStateProjected && entry.ReadyForApply && !entry.KillSwitchEngaged
	return out
}

func awsPermissionBoundaryExecutorAccountsForTargets(targets []string) []string {
	accounts := []string{}
	for _, target := range emptyStrings(dedupeStrings(targets)) {
		accountID := awsPermissionBoundaryExecutorAccountFromTarget(target)
		if accountID != "" {
			accounts = append(accounts, accountID)
		}
	}
	return emptyStrings(dedupeStrings(accounts))
}

func awsPermissionBoundaryExecutorScopedAccountsForTargets(targets []string, fallback []string) []string {
	derived := awsPermissionBoundaryExecutorAccountsForTargets(targets)
	if len(derived) > 0 {
		return derived
	}
	return emptyStrings(dedupeStrings(fallback))
}

func awsPermissionBoundaryExecutorAccountFromTarget(target string) string {
	trimmed := strings.TrimSpace(target)
	if idx := strings.Index(trimmed, "arn:"); idx >= 0 {
		trimmed = trimmed[idx:]
	}
	parts := strings.Split(trimmed, ":")
	if len(parts) >= 5 && strings.EqualFold(parts[2], "iam") {
		return strings.TrimSpace(parts[4])
	}
	return ""
}

func awsPermissionBoundaryExecutorIntendedCall(entry AWSRemediationDryRunEntry) AWSRemediationDryRunIntendedAPICall {
	if len(entry.IntendedAPICalls) > 0 {
		call := entry.IntendedAPICalls[0]
		if len(call.ParameterRefs) > 0 {
			call.ParameterRefs = append([]string{}, call.ParameterRefs...)
		}
		return call
	}
	return AWSRemediationDryRunIntendedAPICall{
		Service:          "iam",
		Operation:        "PutRolePermissionsBoundary",
		TargetResource:   firstString(entry.ImpactedNodes),
		ParameterRefs:    []string{entry.IdempotencyKey, "boundary_ref://" + entry.CaseID + "/after"},
		Idempotent:       true,
		RequiresApproval: true,
	}
}

func awsPermissionBoundaryExecutorIntendedCallForTargets(entry AWSRemediationDryRunEntry, targets []string, operation string) AWSRemediationDryRunIntendedAPICall {
	call := awsPermissionBoundaryExecutorIntendedCall(entry)
	call.Service = firstNonEmptyAWSValue(call.Service, "iam")
	call.Operation = operation
	call.TargetResource = firstNonEmptyAWSValue(firstString(emptyStrings(targets)), call.TargetResource, firstString(entry.ImpactedNodes))
	if len(call.ParameterRefs) == 0 {
		call.ParameterRefs = []string{entry.IdempotencyKey, "boundary_ref://" + entry.CaseID + "/after"}
	} else {
		call.ParameterRefs[0] = entry.IdempotencyKey
		if len(call.ParameterRefs) == 1 {
			call.ParameterRefs = append(call.ParameterRefs, "boundary_ref://"+entry.CaseID+"/after")
		}
	}
	call.Idempotent = true
	call.RequiresApproval = true
	return call
}

func awsPermissionBoundaryExecutorPreconditions(entry AWSRemediationDryRunEntry, plan AWSPermissionBoundarySCPPlan, call AWSRemediationDryRunIntendedAPICall) []AWSPermissionBoundaryExecutorPrecondition {
	identityCount := len(emptyStrings(plan.TargetIdentityNodeIDs))
	preconditions := []AWSPermissionBoundaryExecutorPrecondition{
		{Name: "dry_run_would_succeed", Status: awsPermissionBoundaryExecutorGateStatus(entry.Outcome == awsRemediationDryRunOutcomeWouldSucceed), Rationale: "Upstream dry-run must project would_succeed before any live apply."},
		{Name: "ready_for_apply", Status: awsPermissionBoundaryExecutorGateStatus(entry.ReadyForApply), Rationale: "Upstream dry-run must declare ready_for_apply=true before any live apply."},
		{Name: "kill_switch_off", Status: awsPermissionBoundaryExecutorGateStatus(!entry.KillSwitchEngaged), Rationale: "Tenant-scoped remediation kill switch must be off."},
		{Name: "idempotency_key_present", Status: awsPermissionBoundaryExecutorGateStatus(strings.TrimSpace(entry.IdempotencyKey) != ""), Rationale: "Deterministic idempotency key must be present so retries do not double-apply."},
		{Name: "permission_boundary_plan", Status: awsPermissionBoundaryExecutorGateStatus(strings.EqualFold(plan.Kind, awsPermissionBoundaryKind)), Rationale: "Only permission boundary plans are executable here; SCP execution belongs to its own issue."},
		{Name: "plan_ready_for_apply", Status: awsPermissionBoundaryExecutorGateStatus(plan.ReadyForApply), Rationale: "Upstream permission boundary plan must declare ready_for_apply=true."},
		{Name: "target_identities_present", Status: awsPermissionBoundaryExecutorGateStatus(identityCount > 0), Rationale: "At least one captured IAM identity target must be present."},
		{Name: "canary_scope_captured", Status: awsPermissionBoundaryExecutorGateStatus(identityCount > 0 && len(plan.TargetAccountIDs) > 0), Rationale: "The plan must carry captured identity and account scope so apply can run as a bounded canary."},
		{Name: "breakage_level_low", Status: awsPermissionBoundaryExecutorGateStatus(strings.EqualFold(plan.BreakageProjection.Level, "low")), Rationale: "Permission boundary breakage projection must be low before live apply."},
		{Name: "operation_supported", Status: awsPermissionBoundaryExecutorGateStatus(call.Operation == "PutRolePermissionsBoundary" || call.Operation == "PutUserPermissionsBoundary"), Rationale: "Executor only supports IAM role/user permission boundary operations."},
	}
	if len(entry.FailedPrereqs) > 0 {
		preconditions = append(preconditions, AWSPermissionBoundaryExecutorPrecondition{
			Name:      "upstream_prerequisites",
			Status:    "blocked",
			Rationale: fmt.Sprintf("Upstream dry-run still has %d failed prerequisite(s); resolve them before retrying.", len(entry.FailedPrereqs)),
		})
	}
	return preconditions
}

func awsPermissionBoundaryExecutorGateStatus(ok bool) string {
	if ok {
		return "passed"
	}
	return "blocked"
}

func awsPermissionBoundaryExecutorSimulation(entry AWSRemediationDryRunEntry, plan AWSPermissionBoundarySCPPlan) AWSPermissionBoundaryExecutorSimulation {
	beforeRef := firstNonEmptyAWSValue(entry.DiffIntent.BeforeRef, "permission_boundary_before://"+plan.PlanID)
	afterRef := firstNonEmptyAWSValue(entry.DiffIntent.AfterRef, "permission_boundary_after://"+plan.PlanID)
	outcome := "would_limit_actions"
	if !strings.EqualFold(plan.BreakageProjection.Level, "low") {
		outcome = "regression_risk"
	}
	if !plan.ReadyForApply {
		outcome = "pending_planner_evidence"
	}
	return AWSPermissionBoundaryExecutorSimulation{
		SimulationRef:       fmt.Sprintf("iam:policy_simulate://%s/permission-boundary", plan.PlanID),
		Outcome:             outcome,
		BeforeRef:           beforeRef,
		AfterRef:            afterRef,
		DeniedActionCount:   len(awsRemediationPermissionBoundaryDeniedActions(plan)),
		TargetIdentityCount: len(emptyStrings(plan.TargetIdentityNodeIDs)),
		Signals:             dedupeStrings(append([]string{"permission_boundary"}, plan.BreakageProjection.Signals...)),
	}
}

func awsPermissionBoundaryExecutorVerifications(entry AWSRemediationDryRunEntry, plan AWSPermissionBoundarySCPPlan) []AWSPermissionBoundaryExecutorVerification {
	out := []AWSPermissionBoundaryExecutorVerification{
		{Source: "cloudtrail", Signal: "expected_api_call_observed", Status: "pending", Description: "After live execution, confirm the IAM permission boundary operation appears in CloudTrail for the target account and region."},
		{Source: "iam:policy_simulate", Signal: "boundary_denies_projected_actions", Status: "pending", Description: "Re-run IAM policy simulation for each captured identity and confirm the boundary denies the projected unused action set without blocking observed actions."},
		{Source: "least_privilege", Signal: "recommendation_resolved", Status: "pending", Description: "Re-run least-privilege analysis and confirm the source recommendations no longer require permission expansion."},
	}
	for _, check := range entry.VerificationChecks {
		if check.Source == "" {
			continue
		}
		out = append(out, AWSPermissionBoundaryExecutorVerification{Source: check.Source, Signal: check.Signal, Status: "pending", Description: check.Description})
	}
	for _, signal := range plan.VerificationPlan.SuccessSignals {
		out = append(out, AWSPermissionBoundaryExecutorVerification{Source: "planner", Signal: signal, Status: "pending", Description: "Confirm the planner success signal after live execution."})
	}
	return out
}

func awsPermissionBoundaryExecutorState(entry AWSRemediationDryRunEntry, preconditions []AWSPermissionBoundaryExecutorPrecondition) string {
	if entry.KillSwitchEngaged {
		return awsPermissionBoundaryExecutorStateBlocked
	}
	if entry.Outcome == awsRemediationDryRunOutcomeBlocked || entry.Outcome == awsRemediationDryRunOutcomeKillSwitched {
		return awsPermissionBoundaryExecutorStateBlocked
	}
	hasBlockedPrecondition := false
	for _, precondition := range preconditions {
		if precondition.Status != "blocked" {
			continue
		}
		hasBlockedPrecondition = true
		if awsPermissionBoundaryExecutorPreconditionIsSafety(precondition.Name) {
			return awsPermissionBoundaryExecutorStateBlocked
		}
	}
	if hasBlockedPrecondition {
		return awsPermissionBoundaryExecutorStatePreconditionFailed
	}
	if entry.Outcome != awsRemediationDryRunOutcomeWouldSucceed || !entry.ReadyForApply {
		return awsPermissionBoundaryExecutorStatePreconditionFailed
	}
	return awsPermissionBoundaryExecutorStateProjected
}

func awsPermissionBoundaryExecutorPreconditionIsSafety(name string) bool {
	switch name {
	case "kill_switch_off", "idempotency_key_present", "permission_boundary_plan", "target_identities_present", "operation_supported":
		return true
	}
	return false
}

func awsPermissionBoundaryExecutorNextAction(state, operation string) string {
	switch state {
	case awsPermissionBoundaryExecutorStateProjected:
		return fmt.Sprintf("Permission boundary operation=%s is ready for the wave-8 apply runtime once its feature flag opens.", operation)
	case awsPermissionBoundaryExecutorStatePreconditionFailed:
		return "One or more preconditions failed; advance the upstream dry-run or permission boundary plan before retrying."
	case awsPermissionBoundaryExecutorStateBlocked:
		return "A safety precondition or the tenant kill switch is blocking this entry; satisfy the failing check before retrying."
	}
	return "Inspect this entry for the projected next action."
}

func awsPermissionBoundaryExecutorAuditTrail(entry AWSRemediationDryRunEntry, state string, plan AWSPermissionBoundarySCPPlan, now time.Time) []AWSPermissionBoundaryExecutorAuditEntry {
	trail := []AWSPermissionBoundaryExecutorAuditEntry{}
	trail = append(trail, entry.AuditTrail...)
	trail = append(trail, AWSPermissionBoundaryExecutorAuditEntry{
		EventID:    stableAWSBlastRadiusToken("permission-boundary-projected", entry.DryRunID, plan.PlanID),
		Actor:      "identrail-permission-boundary-executor",
		EventType:  "permission_boundary_execution_projected",
		OccurredAt: now,
		Notes:      fmt.Sprintf("Plan=%s state=%s target_identities=%d; Identrail did not call any AWS write API at this layer.", plan.PlanID, state, len(emptyStrings(plan.TargetIdentityNodeIDs))),
	})
	return trail
}

func awsPermissionBoundaryExecutorRelationships(entries []AWSPermissionBoundaryExecutorEntry) []AWSPermissionBoundaryExecutorRelationship {
	relationships := []AWSPermissionBoundaryExecutorRelationship{}
	for _, entry := range entries {
		evidenceRef := awsPermissionBoundaryExecutorFirstEvidenceRef(entry.Evidence)
		for _, target := range entry.TargetIdentityNodeIDs {
			if strings.TrimSpace(target) == "" {
				continue
			}
			relationships = append(relationships, AWSPermissionBoundaryExecutorRelationship{
				ExecutionID: entry.ExecutionID,
				Type:        "permission_boundary_targets_identity",
				FromNodeID:  entry.ExecutionID,
				ToNodeID:    target,
				EvidenceRef: evidenceRef,
			})
		}
	}
	return relationships
}

func awsPermissionBoundaryExecutorFirstEvidenceRef(evidence []AWSPermissionBoundaryExecutorEvidence) string {
	for _, item := range evidence {
		if strings.TrimSpace(item.EvidenceRef) != "" {
			return item.EvidenceRef
		}
	}
	return ""
}

func summarizeAWSPermissionBoundaryExecutorEntries(all, filtered []AWSPermissionBoundaryExecutorEntry, relationships []AWSPermissionBoundaryExecutorRelationship) AWSPermissionBoundaryExecutorSummary {
	summary := AWSPermissionBoundaryExecutorSummary{
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
		summary.TargetIdentityCount += len(entry.TargetIdentityNodeIDs)
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

func filterAWSPermissionBoundaryExecutorEntries(entries []AWSPermissionBoundaryExecutorEntry, request AWSPermissionBoundaryExecutorRequest) ([]AWSPermissionBoundaryExecutorEntry, map[string]string) {
	filters := map[string]string{
		"account_id": strings.TrimSpace(request.AccountID),
		"region":     strings.TrimSpace(request.Region),
		"dry_run_id": strings.TrimSpace(request.DryRunID),
		"case_id":    strings.TrimSpace(request.CaseID),
		"plan_id":    strings.TrimSpace(request.PlanID),
		"operation":  normalizeAWSRuntimeEventFilterToken(request.Operation),
		"state":      normalizeAWSRuntimeEventFilterToken(request.State),
		"severity":   normalizeAWSRuntimeEventFilterToken(request.Severity),
		"search":     strings.TrimSpace(request.Search),
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
	filtered := make([]AWSPermissionBoundaryExecutorEntry, 0, len(entries))
	for _, entry := range entries {
		if filters["account_id"] != "" && !awsPermissionBoundaryExecutorAccountMatch(entry, filters["account_id"]) {
			continue
		}
		if filters["region"] != "" && !awsPermissionBoundaryExecutorRegionMatch(entry, filters["region"]) {
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
		if filters["state"] != "" && filters["state"] != normalizeAWSRuntimeEventFilterToken(entry.State) {
			continue
		}
		if filters["severity"] != "" && filters["severity"] != normalizeAWSRuntimeEventFilterToken(entry.Severity) {
			continue
		}
		if filters["search"] != "" && !awsPermissionBoundaryExecutorSearchMatch(entry, filters["search"]) {
			continue
		}
		filtered = append(filtered, entry)
	}
	return filtered, applied
}

func awsPermissionBoundaryExecutorRegionMatch(entry AWSPermissionBoundaryExecutorEntry, region string) bool {
	region = strings.TrimSpace(region)
	if region == "" {
		return true
	}
	if strings.TrimSpace(entry.Region) == "" {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(entry.Region), region)
}

func awsPermissionBoundaryExecutorAccountMatch(entry AWSPermissionBoundaryExecutorEntry, accountID string) bool {
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

func awsPermissionBoundaryExecutorSearchMatch(entry AWSPermissionBoundaryExecutorEntry, needle string) bool {
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
	values = append(values, entry.TargetIdentityNodeIDs...)
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

func summarizeAWSPermissionBoundaryExecutorStatus(dryRunStatus, planStatus string, filtered []AWSPermissionBoundaryExecutorEntry, diagnostics []AWSPermissionBoundaryExecutorDiagnostic) (string, float64) {
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

func awsPermissionBoundaryExecutorCaveats() []string {
	return []string{
		"Permission boundary executor entries are read-only projections; Identrail never calls IAM/Organizations write APIs at this layer.",
		"Every precondition (approval dry-run readiness, planner readiness, bounded canary scope, low breakage, idempotency key) must pass before ready_for_live_apply becomes true.",
		"SCP plans are intentionally excluded from this executor; org-level SCP execution belongs to the dedicated SCP executor issue.",
	}
}

func awsPermissionBoundaryExecutorRemediationHints(source []string) []string {
	hints := []string{
		"Resolve any failed precondition before retrying; the dry-run and permission-boundary planner upstreams own those gates.",
		"Use the idempotency key recorded here as the deterministic id when the wave-8 apply runtime executes the IAM permission boundary call.",
		"If the simulation outcome is `regression_risk`, reduce scope or refresh least-privilege evidence before live apply.",
	}
	hints = append(hints, source...)
	return dedupeStrings(hints)
}

func awsPermissionBoundaryExecutorDiagnostics(dryRun []AWSRemediationApprovalDiagnostic, planner []AWSPermissionBoundarySCPDiagnostic) []AWSPermissionBoundaryExecutorDiagnostic {
	out := make([]AWSPermissionBoundaryExecutorDiagnostic, 0, len(dryRun)+len(planner))
	for _, diagnostic := range dryRun {
		out = append(out, AWSPermissionBoundaryExecutorDiagnostic{
			Collector:   diagnostic.Collector,
			SourceID:    diagnostic.SourceID,
			Code:        diagnostic.Code,
			Message:     diagnostic.Message,
			Remediation: diagnostic.Remediation,
			Retryable:   diagnostic.Retryable,
		})
	}
	for _, diagnostic := range planner {
		out = append(out, AWSPermissionBoundaryExecutorDiagnostic(diagnostic))
	}
	return out
}

func awsPermissionBoundaryExecutorCoverageGaps(dryRun []AWSRemediationApprovalCoverageGap, planner []AWSPermissionBoundarySCPCoverageGap) []AWSPermissionBoundaryExecutorCoverageGap {
	gaps := []AWSPermissionBoundaryExecutorCoverageGap{{
		Capability:  "aws_scp_live_apply",
		Status:      "out_of_scope",
		Reason:      "Issue #1540 executes permission boundary projections only; SCP guardrail execution is handled by its own wave-8 issue.",
		Remediation: "Wire the controlled SCP executor in the matching issue after Organizations-side safety gates are in place.",
	}}
	for _, gap := range dryRun {
		gaps = append(gaps, AWSPermissionBoundaryExecutorCoverageGap{
			Capability:  gap.Capability,
			Status:      gap.Status,
			Reason:      gap.Reason,
			Remediation: gap.Remediation,
		})
	}
	for _, gap := range planner {
		gaps = append(gaps, AWSPermissionBoundaryExecutorCoverageGap(gap))
	}
	return gaps
}

func awsPermissionBoundaryExecutorEvidenceBoundary() string {
	return "metadata_only_no_rendered_policy_bodies_no_secret_values_no_workload_payloads_tenant_workspace_project_connector_account_region_scoped"
}

func firstNonZeroAWSPermissionBoundaryExecutorTime(values ...time.Time) time.Time {
	for _, value := range values {
		if !value.IsZero() {
			return value
		}
	}
	return time.Time{}
}
