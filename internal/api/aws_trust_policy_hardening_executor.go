package api

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	awsTrustPolicyHardeningExecutorCurrentIssue = 1539
	awsTrustPolicyHardeningExecutorVersion      = "aws-trust-policy-hardening-executor-v1"

	awsTrustPolicyHardeningExecutorStateProjected          = "projected"
	awsTrustPolicyHardeningExecutorStatePreconditionFailed = "precondition_failed"
	awsTrustPolicyHardeningExecutorStateBlocked            = "blocked"
)

// AWSTrustPolicyHardeningExecutorRequest scopes the deterministic trust-policy
// hardening executor projection to one AWS connector plus optional operator
// drill-down filters.
type AWSTrustPolicyHardeningExecutorRequest struct {
	ConnectorID        string `json:"connector_id,omitempty"`
	FixtureState       string `json:"fixture_state,omitempty"`
	AccountID          string `json:"account_id,omitempty"`
	Region             string `json:"region,omitempty"`
	DryRunID           string `json:"dry_run_id,omitempty"`
	CaseID             string `json:"case_id,omitempty"`
	PlanID             string `json:"plan_id,omitempty"`
	HardeningDirection string `json:"hardening_direction,omitempty"`
	State              string `json:"state,omitempty"`
	Severity           string `json:"severity,omitempty"`
	Search             string `json:"search,omitempty"`
}

// Reuse upstream shapes so the executor record stays consistent with the
// trust-hardening planner and the dry-run/approval layer.
type AWSTrustPolicyHardeningExecutorEvidence = AWSTrustPolicyHardeningEvidence
type AWSTrustPolicyHardeningExecutorPathStep = AWSTrustPolicyHardeningPathStep
type AWSTrustPolicyHardeningExecutorDiagnostic = AWSTrustPolicyHardeningDiagnostic
type AWSTrustPolicyHardeningExecutorCoverageGap = AWSTrustPolicyHardeningCoverageGap
type AWSTrustPolicyHardeningExecutorAuditEntry = AWSRemediationApprovalAuditEntry

// AWSTrustPolicyHardeningExecutorPrecondition is one safety check the executor
// runs before declaring a record `ready_for_live_apply`. The set covers the
// upstream dry-run readiness plus trust-policy-specific gates: no public
// principal remains after the change, IAM policy simulation succeeded, and
// breakage projection is bounded.
type AWSTrustPolicyHardeningExecutorPrecondition struct {
	Name      string `json:"name"`
	Status    string `json:"status"`
	Rationale string `json:"rationale"`
}

// AWSTrustPolicyHardeningExecutorPolicySimulation records the deterministic
// IAM policy simulator outcome the executor consults before declaring the
// change ready for live apply. Identrail never inlines rendered policy
// documents; the simulator output is referenced via metadata only.
type AWSTrustPolicyHardeningExecutorPolicySimulation struct {
	SimulationRef string   `json:"simulation_ref"`
	Outcome       string   `json:"outcome"`
	BeforeRef     string   `json:"before_ref"`
	AfterRef      string   `json:"after_ref"`
	AllowedCount  int      `json:"allowed_count"`
	DeniedCount   int      `json:"denied_count"`
	Signals       []string `json:"signals,omitempty"`
}

// AWSTrustPolicyHardeningExecutorVerification describes a deterministic
// post-execution verification step that must succeed before the change is
// recorded as `succeeded` by a downstream apply runtime.
type AWSTrustPolicyHardeningExecutorVerification struct {
	Source      string `json:"source"`
	Signal      string `json:"signal"`
	Status      string `json:"status"`
	Description string `json:"description"`
}

// AWSTrustPolicyHardeningExecutorRelationship surfaces executor→graph node
// edges.
type AWSTrustPolicyHardeningExecutorRelationship struct {
	ExecutionID string `json:"execution_id"`
	Type        string `json:"type"`
	FromNodeID  string `json:"from_node_id"`
	ToNodeID    string `json:"to_node_id"`
	EvidenceRef string `json:"evidence_ref,omitempty"`
}

// AWSTrustPolicyHardeningExecutorEntry is the persisted-record-shaped contract
// emitted by the approved trust-policy hardening executor. It is
// metadata-only: it carries no rendered policy bodies, no secret material,
// and no workload payloads. Live IAM/STS/Organizations write APIs remain
// gated to the wave-8 apply runtime; this endpoint records the deterministic
// projected intent operators can review before any live mutation.
type AWSTrustPolicyHardeningExecutorEntry struct {
	ExecutionID        string                                          `json:"execution_id"`
	CalculationVersion string                                          `json:"calculation_version"`
	DryRunID           string                                          `json:"dry_run_id"`
	ApprovalID         string                                          `json:"approval_id"`
	CaseID             string                                          `json:"case_id"`
	PlanID             string                                          `json:"plan_id"`
	SourceArtifactID   string                                          `json:"source_artifact_id"`
	State              string                                          `json:"state"`
	HardeningDirection string                                          `json:"hardening_direction"`
	Severity           string                                          `json:"severity"`
	Score              int                                             `json:"score"`
	Confidence         float64                                         `json:"confidence"`
	Title              string                                          `json:"title"`
	Summary            string                                          `json:"summary"`
	AccountID          string                                          `json:"account_id"`
	Region             string                                          `json:"region"`
	IdempotencyKey     string                                          `json:"idempotency_key"`
	ResourceNodeID     string                                          `json:"resource_node_id"`
	ResourceARN        string                                          `json:"resource_arn,omitempty"`
	ResourceLabel      string                                          `json:"resource_label,omitempty"`
	PublicPrincipal    bool                                            `json:"public_principal"`
	PrincipalChange    AWSTrustPolicyPrincipalChange                   `json:"principal_change"`
	ConditionRecs      []AWSTrustPolicyConditionRecommendation         `json:"condition_recommendations"`
	StatementSnippets  []AWSTrustPolicyStatementSnippet                `json:"statement_snippets"`
	AffectedCallers    []AWSTrustPolicyAffectedCaller                  `json:"affected_callers"`
	BreakageProjection AWSTrustPolicyHardeningBreakageProjection       `json:"breakage_projection"`
	IntendedAPICall    AWSRemediationDryRunIntendedAPICall             `json:"intended_api_call"`
	Preconditions      []AWSTrustPolicyHardeningExecutorPrecondition   `json:"preconditions"`
	PolicySimulation   AWSTrustPolicyHardeningExecutorPolicySimulation `json:"policy_simulation"`
	Verifications      []AWSTrustPolicyHardeningExecutorVerification   `json:"verifications"`
	RollbackPlan       AWSTrustPolicyHardeningRollbackPlan             `json:"rollback_plan"`
	VerificationPlan   AWSTrustPolicyHardeningVerificationPlan         `json:"verification_plan"`
	AuditTrail         []AWSTrustPolicyHardeningExecutorAuditEntry     `json:"audit_trail"`
	KillSwitchEngaged  bool                                            `json:"kill_switch_engaged"`
	ReadyForLiveApply  bool                                            `json:"ready_for_live_apply"`
	ReadOnlyProjection bool                                            `json:"read_only_projection"`
	SourceSignals      []string                                        `json:"source_signals"`
	Evidence           []AWSTrustPolicyHardeningExecutorEvidence       `json:"evidence"`
	EvidenceBoundary   string                                          `json:"evidence_boundary"`
	ImpactedNodes      []string                                        `json:"impacted_nodes"`
	ImpactedPath       []AWSTrustPolicyHardeningExecutorPathStep       `json:"impacted_path"`
	NextAction         string                                          `json:"next_action"`
	ProjectedAt        time.Time                                       `json:"projected_at"`
	CreatedAt          time.Time                                       `json:"created_at"`
	UpdatedAt          time.Time                                       `json:"updated_at"`
}

// AWSTrustPolicyHardeningExecutorSummary aggregates the unfiltered/filtered
// set.
type AWSTrustPolicyHardeningExecutorSummary struct {
	TotalEntries             int            `json:"total_entries"`
	FilteredEntries          int            `json:"filtered_entries"`
	StateCounts              map[string]int `json:"state_counts"`
	HardeningDirectionCounts map[string]int `json:"hardening_direction_counts"`
	SeverityCounts           map[string]int `json:"severity_counts"`
	ReadyForLiveApplyCount   int            `json:"ready_for_live_apply_count"`
	KillSwitchEngagedCount   int            `json:"kill_switch_engaged_count"`
	PublicPrincipalCount     int            `json:"public_principal_count"`
	FailedPreconditionCount  int            `json:"failed_precondition_count"`
	VerificationCount        int            `json:"verification_count"`
	RelationshipCount        int            `json:"relationship_count"`
	HighestScore             int            `json:"highest_score"`
	AverageConfidencePct     int            `json:"average_confidence_pct"`
}

// AWSTrustPolicyHardeningExecutorResult is the deterministic envelope returned
// by the executor endpoint.
type AWSTrustPolicyHardeningExecutorResult struct {
	TenantID           string                                        `json:"tenant_id"`
	WorkspaceID        string                                        `json:"workspace_id"`
	ProjectID          string                                        `json:"project_id"`
	ConnectorID        string                                        `json:"connector_id,omitempty"`
	AccountID          string                                        `json:"account_id,omitempty"`
	Region             string                                        `json:"region,omitempty"`
	ParentIssueNumber  int                                           `json:"parent_issue_number"`
	ParentIssueRef     string                                        `json:"parent_issue_ref"`
	CurrentIssueNumber int                                           `json:"current_issue_number"`
	CurrentIssueRef    string                                        `json:"current_issue_ref"`
	Version            string                                        `json:"version"`
	Status             string                                        `json:"status"`
	FixtureState       string                                        `json:"fixture_state,omitempty"`
	Confidence         float64                                       `json:"confidence"`
	CalculationVersion string                                        `json:"calculation_version"`
	AppliedFilters     map[string]string                             `json:"applied_filters"`
	Summary            AWSTrustPolicyHardeningExecutorSummary        `json:"summary"`
	Entries            []AWSTrustPolicyHardeningExecutorEntry        `json:"entries"`
	Relationships      []AWSTrustPolicyHardeningExecutorRelationship `json:"relationships"`
	Caveats            []string                                      `json:"caveats"`
	FailureReasons     []string                                      `json:"failure_reasons"`
	RemediationHints   []string                                      `json:"remediation_hints"`
	EvidenceLinks      []string                                      `json:"evidence_links"`
	CoverageGaps       []AWSTrustPolicyHardeningExecutorCoverageGap  `json:"coverage_gaps"`
	Diagnostics        []AWSTrustPolicyHardeningExecutorDiagnostic   `json:"diagnostics"`
	GeneratedAt        time.Time                                     `json:"generated_at"`
	UpdatedAt          time.Time                                     `json:"updated_at"`
}

// GetAWSTrustPolicyHardeningExecutor projects the deterministic, read-only
// approved trust-policy hardening executor record set. It joins the upstream
// dry-run executor (#1537) with the trust-policy hardening planner (#1531)
// for entries whose source_type is `trust_policy_hardening` and whose dry-run
// diff kind targets an IAM trust-policy mutation. The endpoint never calls
// IAM/STS/Organizations write APIs and never reads, exposes, logs, or
// persists rendered policy documents, secret values, customer payloads,
// prompts, completions, browser pages, code-interpreter output, database
// rows, or object contents. Controlled live apply belongs to the wave-8
// apply runtime and its own feature flags.
func (s *Service) GetAWSTrustPolicyHardeningExecutor(ctx context.Context, workspaceID string, projectID string, request AWSTrustPolicyHardeningExecutorRequest) (AWSTrustPolicyHardeningExecutorResult, error) {
	project, scope, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return AWSTrustPolicyHardeningExecutorResult{}, err
	}
	connection, hasConnection, err := s.awsBaselineConnection(ctx, project, strings.TrimSpace(request.ConnectorID))
	if err != nil {
		return AWSTrustPolicyHardeningExecutorResult{}, err
	}
	now := s.Now().UTC()
	fixtureState := normalizeAWSTrustPolicyHardeningExecutorFixtureState(request.FixtureState, connection, hasConnection)
	if fixtureState == "" {
		return AWSTrustPolicyHardeningExecutorResult{}, ErrInvalidAWSConnectionRequest
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
		return AWSTrustPolicyHardeningExecutorResult{}, fmt.Errorf("trust-policy hardening executor dry-run: %w", err)
	}
	plans, err := s.GetAWSTrustPolicyHardeningPlans(ctx, workspaceID, projectID, AWSTrustPolicyHardeningRequest{ConnectorID: connectorID, FixtureState: sourceFixtureState})
	if err != nil {
		return AWSTrustPolicyHardeningExecutorResult{}, fmt.Errorf("trust-policy hardening executor plans: %w", err)
	}

	planByID := map[string]AWSTrustPolicyHardeningPlan{}
	for _, plan := range plans.Plans {
		planByID[plan.PlanID] = plan
	}

	entries := awsTrustPolicyHardeningExecutorEntries(dryRun.Entries, planByID, now)
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].Score == entries[j].Score {
			return entries[i].ExecutionID < entries[j].ExecutionID
		}
		return entries[i].Score > entries[j].Score
	})
	filtered, applied := filterAWSTrustPolicyHardeningExecutorEntries(entries, request)
	relationships := awsTrustPolicyHardeningExecutorRelationships(filtered)
	diagnostics := awsTrustPolicyHardeningExecutorDiagnostics(dryRun.Diagnostics, plans.Diagnostics)
	coverageGaps := awsTrustPolicyHardeningExecutorCoverageGaps(dryRun.CoverageGaps, plans.CoverageGaps)
	status, confidence := summarizeAWSTrustPolicyHardeningExecutorStatus(dryRun.Status, plans.Status, filtered, diagnostics)

	return AWSTrustPolicyHardeningExecutorResult{
		TenantID:           scope.TenantID,
		WorkspaceID:        project.WorkspaceID,
		ProjectID:          project.ProjectID,
		ConnectorID:        connectorID,
		AccountID:          accountID,
		Region:             region,
		ParentIssueNumber:  awsPlatformDependencyParentIssue,
		ParentIssueRef:     awsIssueRef(awsPlatformDependencyParentIssue),
		CurrentIssueNumber: awsTrustPolicyHardeningExecutorCurrentIssue,
		CurrentIssueRef:    awsIssueRef(awsTrustPolicyHardeningExecutorCurrentIssue),
		Version:            awsTrustPolicyHardeningExecutorVersion,
		Status:             status,
		FixtureState:       sourceFixtureState,
		Confidence:         confidence,
		CalculationVersion: awsTrustPolicyHardeningExecutorVersion,
		AppliedFilters:     applied,
		Summary:            summarizeAWSTrustPolicyHardeningExecutorEntries(entries, filtered, relationships),
		Entries:            filtered,
		Relationships:      relationships,
		Caveats:            awsTrustPolicyHardeningExecutorCaveats(),
		FailureReasons:     dedupeStrings(append(append([]string{}, dryRun.FailureReasons...), plans.FailureReasons...)),
		RemediationHints:   awsTrustPolicyHardeningExecutorRemediationHints(append(dryRun.RemediationHints, plans.RemediationHints...)),
		EvidenceLinks: dedupeStrings([]string{
			awsIssueURL(awsPlatformDependencyParentIssue),
			awsIssueURL(awsTrustPolicyHardeningExecutorCurrentIssue),
			awsIssueURL(awsRemediationDryRunCurrentIssue),
			awsIssueURL(awsTrustPolicyHardeningCurrentIssue),
			"/docs/aws-trust-policy-hardening-executor",
			"/docs/aws-remediation-dry-run-executor",
			"/docs/aws-trust-policy-hardening-planner",
			awsBaselineProjectEvidenceURL(scope, project),
		}),
		CoverageGaps: coverageGaps,
		Diagnostics:  diagnostics,
		GeneratedAt:  now,
		UpdatedAt:    now,
	}, nil
}

func normalizeAWSTrustPolicyHardeningExecutorFixtureState(requested string, connection AWSConnectionStatus, hasConnection bool) string {
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

func awsTrustPolicyHardeningExecutorEntries(dryRunEntries []AWSRemediationDryRunEntry, planByID map[string]AWSTrustPolicyHardeningPlan, now time.Time) []AWSTrustPolicyHardeningExecutorEntry {
	entries := []AWSTrustPolicyHardeningExecutorEntry{}
	for _, entry := range dryRunEntries {
		if !awsTrustPolicyHardeningExecutorAdmits(entry) {
			continue
		}
		plan, ok := planByID[entry.SourceArtifactID]
		if !ok {
			continue
		}
		entries = append(entries, awsTrustPolicyHardeningExecutorEntryFromDryRun(entry, plan, now))
	}
	return entries
}

// awsTrustPolicyHardeningExecutorAdmits guards the executor to the
// `trust_policy_hardening` source type AND an IAM trust-policy diff kind so
// non-trust dry-runs never bleed into this projection.
func awsTrustPolicyHardeningExecutorAdmits(entry AWSRemediationDryRunEntry) bool {
	if !strings.EqualFold(entry.SourceType, "trust_policy_hardening") {
		return false
	}
	if entry.DiffIntent.NoOp {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(entry.DiffIntent.Kind)) {
	case "iam_trust_diff", "iac_trust_policy_pr":
		return true
	}
	return false
}

func awsTrustPolicyHardeningExecutorEntryFromDryRun(entry AWSRemediationDryRunEntry, plan AWSTrustPolicyHardeningPlan, now time.Time) AWSTrustPolicyHardeningExecutorEntry {
	call := awsTrustPolicyHardeningExecutorIntendedCall(entry)
	preconditions := awsTrustPolicyHardeningExecutorPreconditions(entry, plan)
	simulation := awsTrustPolicyHardeningExecutorSimulation(entry, plan)
	verifications := awsTrustPolicyHardeningExecutorVerifications(entry, plan)
	state := awsTrustPolicyHardeningExecutorState(entry, preconditions)
	executionID := "aws-trust-policy-hardening-executor:" + stableAWSBlastRadiusToken("execution", entry.DryRunID, plan.PlanID)
	out := AWSTrustPolicyHardeningExecutorEntry{
		ExecutionID:        executionID,
		CalculationVersion: awsTrustPolicyHardeningExecutorVersion,
		DryRunID:           entry.DryRunID,
		ApprovalID:         entry.ApprovalID,
		CaseID:             entry.CaseID,
		PlanID:             plan.PlanID,
		SourceArtifactID:   entry.SourceArtifactID,
		State:              state,
		HardeningDirection: plan.HardeningDirection,
		Severity:           firstNonEmptyAWSValue(entry.Severity, plan.Severity),
		Score:              entry.Score,
		Confidence:         entry.Confidence,
		Title:              fmt.Sprintf("Trust-policy hardening: %s", firstNonEmptyAWSValue(plan.Title, entry.Title)),
		Summary:            fmt.Sprintf("Approved trust-policy hardening execution record for plan %s (dry-run %s); Identrail records the projected IAM UpdateAssumeRolePolicy intent and never calls AWS write APIs at this layer.", plan.PlanID, entry.DryRunID),
		AccountID:          firstNonEmptyAWSValue(entry.AccountID, plan.AccountID),
		Region:             firstNonEmptyAWSValue(entry.Region, plan.Region),
		IdempotencyKey:     entry.IdempotencyKey,
		ResourceNodeID:     plan.ResourceNodeID,
		ResourceARN:        plan.ResourceARN,
		ResourceLabel:      plan.ResourceLabel,
		PublicPrincipal:    plan.PublicPrincipal,
		PrincipalChange:    plan.PrincipalChange,
		ConditionRecs:      plan.ConditionRecommendations,
		StatementSnippets:  plan.StatementSnippets,
		AffectedCallers:    plan.AffectedCallers,
		BreakageProjection: plan.BreakageProjection,
		IntendedAPICall:    call,
		Preconditions:      preconditions,
		PolicySimulation:   simulation,
		Verifications:      verifications,
		RollbackPlan:       plan.RollbackPlan,
		VerificationPlan:   plan.VerificationPlan,
		AuditTrail:         awsTrustPolicyHardeningExecutorAuditTrail(entry, state, plan, now),
		KillSwitchEngaged:  entry.KillSwitchEngaged,
		ReadOnlyProjection: true,
		SourceSignals:      dedupeStrings(append([]string{"trust_policy_hardening", "remediation_dry_run"}, entry.SourceSignals...)),
		Evidence:           plan.Evidence,
		EvidenceBoundary:   awsTrustPolicyHardeningExecutorEvidenceBoundary(),
		ImpactedNodes:      dedupeStrings(append(append([]string{plan.ResourceNodeID}, entry.ImpactedNodes...), plan.ImpactedNodes...)),
		ImpactedPath:       plan.ImpactedPath,
		NextAction:         awsTrustPolicyHardeningExecutorNextAction(state, plan.HardeningDirection),
		ProjectedAt:        now,
		CreatedAt:          firstNonZeroAWSTrustPolicyHardeningExecutorTime(entry.CreatedAt, plan.CreatedAt, now),
		UpdatedAt:          now,
	}
	out.ReadyForLiveApply = state == awsTrustPolicyHardeningExecutorStateProjected && entry.ReadyForApply && !entry.KillSwitchEngaged
	return out
}

func awsTrustPolicyHardeningExecutorIntendedCall(entry AWSRemediationDryRunEntry) AWSRemediationDryRunIntendedAPICall {
	if len(entry.IntendedAPICalls) > 0 {
		return entry.IntendedAPICalls[0]
	}
	return AWSRemediationDryRunIntendedAPICall{
		Service:          "iam",
		Operation:        "UpdateAssumeRolePolicy",
		ParameterRefs:    []string{entry.IdempotencyKey, "trust_policy_ref://" + entry.CaseID + "/after"},
		Idempotent:       true,
		RequiresApproval: true,
	}
}

func awsTrustPolicyHardeningExecutorPreconditions(entry AWSRemediationDryRunEntry, plan AWSTrustPolicyHardeningPlan) []AWSTrustPolicyHardeningExecutorPrecondition {
	preconditions := []AWSTrustPolicyHardeningExecutorPrecondition{
		{Name: "dry_run_would_succeed", Status: awsTrustPolicyHardeningExecutorGateStatus(entry.Outcome == awsRemediationDryRunOutcomeWouldSucceed), Rationale: "Upstream dry-run must project would_succeed before any live apply."},
		{Name: "ready_for_apply", Status: awsTrustPolicyHardeningExecutorGateStatus(entry.ReadyForApply), Rationale: "Upstream dry-run must declare ready_for_apply=true before any live apply."},
		{Name: "kill_switch_off", Status: awsTrustPolicyHardeningExecutorGateStatus(!entry.KillSwitchEngaged), Rationale: "Tenant-scoped remediation kill switch must be off."},
		{Name: "idempotency_key_present", Status: awsTrustPolicyHardeningExecutorGateStatus(strings.TrimSpace(entry.IdempotencyKey) != ""), Rationale: "Deterministic idempotency key must be present so retries do not double-apply."},
		{Name: "plan_ready_for_apply", Status: awsTrustPolicyHardeningExecutorGateStatus(plan.ReadyForApply), Rationale: "Upstream trust-policy hardening plan must declare ready_for_apply=true."},
		{Name: "no_public_principal_after_change", Status: awsTrustPolicyHardeningExecutorGateStatus(!plan.PublicPrincipal), Rationale: "Trust policy must not retain a public principal after the projected change."},
		{Name: "breakage_level_low", Status: awsTrustPolicyHardeningExecutorGateStatus(strings.EqualFold(plan.BreakageProjection.Level, "low")), Rationale: "Trust-hardening breakage projection must be low before live apply."},
	}
	if len(entry.FailedPrereqs) > 0 {
		preconditions = append(preconditions, AWSTrustPolicyHardeningExecutorPrecondition{
			Name:      "upstream_prerequisites",
			Status:    "blocked",
			Rationale: fmt.Sprintf("Upstream dry-run still has %d failed prerequisite(s); resolve them before retrying.", len(entry.FailedPrereqs)),
		})
	}
	return preconditions
}

func awsTrustPolicyHardeningExecutorGateStatus(ok bool) string {
	if ok {
		return "passed"
	}
	return "blocked"
}

func awsTrustPolicyHardeningExecutorSimulation(entry AWSRemediationDryRunEntry, plan AWSTrustPolicyHardeningPlan) AWSTrustPolicyHardeningExecutorPolicySimulation {
	beforeRef := firstNonEmptyAWSValue(entry.DiffIntent.BeforeRef, "trust_policy_before://"+plan.PlanID)
	afterRef := firstNonEmptyAWSValue(entry.DiffIntent.AfterRef, "trust_policy_after://"+plan.PlanID)
	signals := []string{}
	if plan.RuntimeObserved {
		signals = append(signals, "runtime_observed")
	}
	if plan.AnalyzerBacked {
		signals = append(signals, "access_analyzer_backed")
	}
	outcome := "no_regression"
	if plan.PublicPrincipal {
		outcome = "regression_risk"
	}
	if !plan.ReadyForApply {
		outcome = "pending_planner_evidence"
	}
	return AWSTrustPolicyHardeningExecutorPolicySimulation{
		SimulationRef: fmt.Sprintf("iam:policy_simulate://%s/trust", plan.PlanID),
		Outcome:       outcome,
		BeforeRef:     beforeRef,
		AfterRef:      afterRef,
		AllowedCount:  len(plan.AffectedCallers),
		DeniedCount:   len(plan.ConditionRecommendations),
		Signals:       signals,
	}
}

func awsTrustPolicyHardeningExecutorVerifications(entry AWSRemediationDryRunEntry, plan AWSTrustPolicyHardeningPlan) []AWSTrustPolicyHardeningExecutorVerification {
	out := []AWSTrustPolicyHardeningExecutorVerification{
		{Source: "cloudtrail", Signal: "expected_api_call_observed", Status: "pending", Description: "After live execution, confirm iam:UpdateAssumeRolePolicy appears in CloudTrail for the target account and region."},
		{Source: "access_analyzer", Signal: "no_new_external_findings", Status: "pending", Description: "Re-run Access Analyzer after live execution to confirm no new external-trust findings."},
	}
	if len(plan.ConditionRecommendations) > 0 {
		out = append(out, AWSTrustPolicyHardeningExecutorVerification{Source: "iam:policy_simulate", Signal: "conditions_enforced", Status: "pending", Description: "Re-run the policy simulator after live execution to confirm the new trust conditions are enforced."})
	}
	for _, check := range entry.VerificationChecks {
		if check.Source == "" {
			continue
		}
		out = append(out, AWSTrustPolicyHardeningExecutorVerification{Source: check.Source, Signal: check.Signal, Status: "pending", Description: check.Description})
	}
	return out
}

func awsTrustPolicyHardeningExecutorState(entry AWSRemediationDryRunEntry, preconditions []AWSTrustPolicyHardeningExecutorPrecondition) string {
	if entry.KillSwitchEngaged {
		return awsTrustPolicyHardeningExecutorStateBlocked
	}
	if entry.Outcome == awsRemediationDryRunOutcomeBlocked || entry.Outcome == awsRemediationDryRunOutcomeKillSwitched {
		return awsTrustPolicyHardeningExecutorStateBlocked
	}
	hasBlockedPrecondition := false
	for _, precondition := range preconditions {
		if precondition.Status != "blocked" {
			continue
		}
		hasBlockedPrecondition = true
		if awsTrustPolicyHardeningExecutorPreconditionIsSafety(precondition.Name) {
			return awsTrustPolicyHardeningExecutorStateBlocked
		}
	}
	if hasBlockedPrecondition {
		return awsTrustPolicyHardeningExecutorStatePreconditionFailed
	}
	if entry.Outcome != awsRemediationDryRunOutcomeWouldSucceed || !entry.ReadyForApply {
		return awsTrustPolicyHardeningExecutorStatePreconditionFailed
	}
	return awsTrustPolicyHardeningExecutorStateProjected
}

// awsTrustPolicyHardeningExecutorPreconditionIsSafety names the precondition
// checks that put the entry into `blocked`. Other failures (planner not yet
// ready, breakage level not yet low) are surfaced as `precondition_failed`
// so operators can see the difference between "unsafe" and "not yet ready".
func awsTrustPolicyHardeningExecutorPreconditionIsSafety(name string) bool {
	switch name {
	case "kill_switch_off", "idempotency_key_present", "no_public_principal_after_change":
		return true
	}
	return false
}

func awsTrustPolicyHardeningExecutorNextAction(state, direction string) string {
	switch state {
	case awsTrustPolicyHardeningExecutorStateProjected:
		return fmt.Sprintf("Trust-policy hardening direction=%s is ready for the wave-8 apply runtime once its feature flag opens.", direction)
	case awsTrustPolicyHardeningExecutorStatePreconditionFailed:
		return "One or more preconditions failed; advance the upstream dry-run or trust-policy plan before retrying."
	case awsTrustPolicyHardeningExecutorStateBlocked:
		return "A safety precondition or the tenant kill switch is blocking this entry; satisfy the failing check before retrying."
	}
	return "Inspect this entry for the projected next action."
}

func awsTrustPolicyHardeningExecutorAuditTrail(entry AWSRemediationDryRunEntry, state string, plan AWSTrustPolicyHardeningPlan, now time.Time) []AWSTrustPolicyHardeningExecutorAuditEntry {
	trail := []AWSTrustPolicyHardeningExecutorAuditEntry{}
	trail = append(trail, entry.AuditTrail...)
	trail = append(trail, AWSTrustPolicyHardeningExecutorAuditEntry{
		EventID:    stableAWSBlastRadiusToken("trust-hardening-projected", entry.DryRunID, plan.PlanID),
		Actor:      "identrail-trust-policy-hardening-executor",
		EventType:  "trust_policy_hardening_execution_projected",
		OccurredAt: now,
		Notes:      fmt.Sprintf("Plan=%s direction=%s state=%s; Identrail did not call any AWS write API at this layer.", plan.PlanID, plan.HardeningDirection, state),
	})
	return trail
}

func awsTrustPolicyHardeningExecutorRelationships(entries []AWSTrustPolicyHardeningExecutorEntry) []AWSTrustPolicyHardeningExecutorRelationship {
	relationships := []AWSTrustPolicyHardeningExecutorRelationship{}
	for _, entry := range entries {
		evidenceRef := awsTrustPolicyHardeningExecutorFirstEvidenceRef(entry.Evidence)
		target := strings.TrimSpace(entry.ResourceNodeID)
		if target != "" {
			relationships = append(relationships, AWSTrustPolicyHardeningExecutorRelationship{
				ExecutionID: entry.ExecutionID,
				Type:        "trust_policy_targets_resource",
				FromNodeID:  entry.ExecutionID,
				ToNodeID:    target,
				EvidenceRef: evidenceRef,
			})
		}
	}
	return relationships
}

func awsTrustPolicyHardeningExecutorFirstEvidenceRef(evidence []AWSTrustPolicyHardeningExecutorEvidence) string {
	for _, item := range evidence {
		if strings.TrimSpace(item.EvidenceRef) != "" {
			return item.EvidenceRef
		}
	}
	return ""
}

func summarizeAWSTrustPolicyHardeningExecutorEntries(all, filtered []AWSTrustPolicyHardeningExecutorEntry, relationships []AWSTrustPolicyHardeningExecutorRelationship) AWSTrustPolicyHardeningExecutorSummary {
	summary := AWSTrustPolicyHardeningExecutorSummary{
		TotalEntries:             len(all),
		FilteredEntries:          len(filtered),
		StateCounts:              map[string]int{},
		HardeningDirectionCounts: map[string]int{},
		SeverityCounts:           map[string]int{},
	}
	confidenceTotal := 0.0
	for _, entry := range filtered {
		summary.StateCounts[entry.State]++
		if strings.TrimSpace(entry.HardeningDirection) != "" {
			summary.HardeningDirectionCounts[entry.HardeningDirection]++
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
		if entry.PublicPrincipal {
			summary.PublicPrincipalCount++
		}
		for _, precondition := range entry.Preconditions {
			if precondition.Status == "blocked" {
				summary.FailedPreconditionCount++
			}
		}
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

func filterAWSTrustPolicyHardeningExecutorEntries(entries []AWSTrustPolicyHardeningExecutorEntry, request AWSTrustPolicyHardeningExecutorRequest) ([]AWSTrustPolicyHardeningExecutorEntry, map[string]string) {
	filters := map[string]string{
		"account_id":          strings.TrimSpace(request.AccountID),
		"region":              strings.TrimSpace(request.Region),
		"dry_run_id":          strings.TrimSpace(request.DryRunID),
		"case_id":             strings.TrimSpace(request.CaseID),
		"plan_id":             strings.TrimSpace(request.PlanID),
		"hardening_direction": normalizeAWSRuntimeEventFilterToken(request.HardeningDirection),
		"state":               normalizeAWSRuntimeEventFilterToken(request.State),
		"severity":            normalizeAWSRuntimeEventFilterToken(request.Severity),
		"search":              strings.TrimSpace(request.Search),
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
	filtered := make([]AWSTrustPolicyHardeningExecutorEntry, 0, len(entries))
	for _, entry := range entries {
		if filters["account_id"] != "" && filters["account_id"] != entry.AccountID {
			continue
		}
		if filters["region"] != "" && !strings.EqualFold(filters["region"], entry.Region) {
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
		if filters["hardening_direction"] != "" && filters["hardening_direction"] != normalizeAWSRuntimeEventFilterToken(entry.HardeningDirection) {
			continue
		}
		if filters["state"] != "" && filters["state"] != normalizeAWSRuntimeEventFilterToken(entry.State) {
			continue
		}
		if filters["severity"] != "" && filters["severity"] != normalizeAWSRuntimeEventFilterToken(entry.Severity) {
			continue
		}
		if filters["search"] != "" && !awsTrustPolicyHardeningExecutorSearchMatch(entry, filters["search"]) {
			continue
		}
		filtered = append(filtered, entry)
	}
	return filtered, applied
}

func awsTrustPolicyHardeningExecutorSearchMatch(entry AWSTrustPolicyHardeningExecutorEntry, needle string) bool {
	needle = strings.ToLower(strings.TrimSpace(needle))
	if needle == "" {
		return true
	}
	values := []string{
		entry.ExecutionID, entry.DryRunID, entry.ApprovalID, entry.CaseID, entry.PlanID,
		entry.SourceArtifactID, entry.State, entry.Severity, entry.Title, entry.Summary,
		entry.IdempotencyKey, entry.HardeningDirection, entry.ResourceNodeID, entry.ResourceARN,
		entry.ResourceLabel, entry.NextAction,
		entry.IntendedAPICall.Service, entry.IntendedAPICall.Operation, entry.IntendedAPICall.TargetResource,
		entry.PolicySimulation.SimulationRef, entry.PolicySimulation.Outcome, entry.PolicySimulation.BeforeRef, entry.PolicySimulation.AfterRef,
	}
	values = append(values, entry.SourceSignals...)
	values = append(values, entry.IntendedAPICall.ParameterRefs...)
	values = append(values, entry.PolicySimulation.Signals...)
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

func summarizeAWSTrustPolicyHardeningExecutorStatus(dryRunStatus, planStatus string, filtered []AWSTrustPolicyHardeningExecutorEntry, diagnostics []AWSTrustPolicyHardeningExecutorDiagnostic) (string, float64) {
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

func awsTrustPolicyHardeningExecutorCaveats() []string {
	return []string{
		"Trust-policy hardening executor entries are read-only projections; Identrail never calls IAM/STS/Organizations write APIs at this layer.",
		"Every preconditioning step (dry-run readiness, planner readiness, no public principal after change, breakage level low) must pass before ready_for_live_apply becomes true.",
		"Public-principal trust policies stay non-executable: the planner-side public-principal flag blocks ready_for_live_apply and the executor records `regression_risk` simulation outcome.",
	}
}

func awsTrustPolicyHardeningExecutorRemediationHints(source []string) []string {
	hints := []string{
		"Resolve any failed precondition before retrying; the dry-run and trust-policy planner upstreams own those gates.",
		"Use the idempotency key recorded here as the deterministic id when the wave-8 apply runtime executes the IAM UpdateAssumeRolePolicy call.",
		"If the simulation outcome is `regression_risk`, verify the principal change does not leave a public principal in the trust policy.",
	}
	hints = append(hints, source...)
	return dedupeStrings(hints)
}

func awsTrustPolicyHardeningExecutorDiagnostics(dryRun []AWSRemediationApprovalDiagnostic, planner []AWSTrustPolicyHardeningDiagnostic) []AWSTrustPolicyHardeningExecutorDiagnostic {
	out := make([]AWSTrustPolicyHardeningExecutorDiagnostic, 0, len(dryRun)+len(planner))
	for _, diagnostic := range dryRun {
		out = append(out, AWSTrustPolicyHardeningExecutorDiagnostic{
			Collector:   diagnostic.Collector,
			SourceID:    diagnostic.SourceID,
			Code:        diagnostic.Code,
			Message:     diagnostic.Message,
			Remediation: diagnostic.Remediation,
			Retryable:   diagnostic.Retryable,
		})
	}
	for _, diagnostic := range planner {
		out = append(out, AWSTrustPolicyHardeningExecutorDiagnostic(diagnostic))
	}
	return out
}

func awsTrustPolicyHardeningExecutorCoverageGaps(dryRun []AWSRemediationApprovalCoverageGap, planner []AWSTrustPolicyHardeningCoverageGap) []AWSTrustPolicyHardeningExecutorCoverageGap {
	gaps := []AWSTrustPolicyHardeningExecutorCoverageGap{{
		Capability:  "aws_trust_policy_hardening_live_apply",
		Status:      "out_of_scope",
		Reason:      "Issue #1539 emits trust-policy hardening execution projections only; the live IAM UpdateAssumeRolePolicy call is gated to the wave-8 apply runtime.",
		Remediation: "Wire the controlled live-apply executor in the matching wave-8 issue once its safety gates are in place.",
	}}
	for _, gap := range dryRun {
		gaps = append(gaps, AWSTrustPolicyHardeningExecutorCoverageGap{
			Capability:  gap.Capability,
			Status:      gap.Status,
			Reason:      gap.Reason,
			Remediation: gap.Remediation,
		})
	}
	for _, gap := range planner {
		gaps = append(gaps, AWSTrustPolicyHardeningExecutorCoverageGap(gap))
	}
	return gaps
}

func awsTrustPolicyHardeningExecutorEvidenceBoundary() string {
	return "metadata_only_no_rendered_policy_bodies_no_secret_values_no_workload_payloads_tenant_workspace_project_connector_account_region_scoped"
}

func firstNonZeroAWSTrustPolicyHardeningExecutorTime(values ...time.Time) time.Time {
	for _, value := range values {
		if !value.IsZero() {
			return value
		}
	}
	return time.Time{}
}
