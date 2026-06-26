package api

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	awsRemediationApprovalCurrentIssue = 1536
	awsRemediationApprovalVersion      = "aws-remediation-approval-rbac-v1"

	awsRemediationApprovalStateRequested = "requested"
	awsRemediationApprovalStateReview    = "under_review"
	awsRemediationApprovalStateApproved  = "approved"
	awsRemediationApprovalStateDenied    = "denied"
	awsRemediationApprovalStateExpired   = "expired"
	awsRemediationApprovalStateBlocked   = "blocked"

	awsRemediationApprovalRiskCritical = "critical"
	awsRemediationApprovalRiskHigh     = "high"
	awsRemediationApprovalRiskMedium   = "medium"
	awsRemediationApprovalRiskLow      = "low"

	awsRemediationApprovalDefaultGraceHours = 72
)

// AWSRemediationApprovalRequest scopes the deterministic approval-queue
// projection to one AWS connector plus optional operator drill-down filters.
type AWSRemediationApprovalRequest struct {
	ConnectorID       string `json:"connector_id,omitempty"`
	FixtureState      string `json:"fixture_state,omitempty"`
	AccountID         string `json:"account_id,omitempty"`
	Region            string `json:"region,omitempty"`
	CaseID            string `json:"case_id,omitempty"`
	State             string `json:"state,omitempty"`
	RiskTier          string `json:"risk_tier,omitempty"`
	ScopeType         string `json:"scope_type,omitempty"`
	Requestor         string `json:"requestor,omitempty"`
	ApproverRole      string `json:"approver_role,omitempty"`
	Severity          string `json:"severity,omitempty"`
	ReadyForExecution string `json:"ready_for_execution,omitempty"`
	KillSwitchEngaged string `json:"kill_switch_engaged,omitempty"`
	Search            string `json:"search,omitempty"`
}

// Reuse upstream evidence and path-step shapes so the approval-queue contract
// stays consistent with its source cases.
type AWSRemediationApprovalEvidence = AWSRemediationCaseEvidence
type AWSRemediationApprovalPathStep = AWSRemediationCasePathStep
type AWSRemediationApprovalDiagnostic = AWSRemediationCaseDiagnostic
type AWSRemediationApprovalCoverageGap = AWSRemediationCaseCoverageGap
type AWSRemediationApprovalAuditEntry = AWSRemediationAuditEntry

// AWSRemediationApprovalActor names one operator role with explicit
// requestor/approver context. Roles are deterministic strings.
type AWSRemediationApprovalActor struct {
	Role         string `json:"role"`
	Label        string `json:"label"`
	Required     bool   `json:"required"`
	Acknowledged bool   `json:"acknowledged"`
}

// AWSRemediationApprovalScope records the explicit blast surface the approval
// applies to. Tenancy boundaries are preserved by carrying the connector,
// account, and region context on every entry.
type AWSRemediationApprovalScope struct {
	ScopeType       string   `json:"scope_type"`
	AccountIDs      []string `json:"account_ids,omitempty"`
	Regions         []string `json:"regions,omitempty"`
	ConnectorIDs    []string `json:"connector_ids,omitempty"`
	IdentityNodeIDs []string `json:"identity_node_ids,omitempty"`
	ResourceNodeIDs []string `json:"resource_node_ids,omitempty"`
}

// AWSRemediationApprovalRBACGate explains one role-based access check the
// approval workflow enforces. Each gate carries a deterministic status and
// rationale so the app can show which check blocks the workflow.
type AWSRemediationApprovalRBACGate struct {
	Name         string `json:"name"`
	Status       string `json:"status"`
	RequiredRole string `json:"required_role"`
	Rationale    string `json:"rationale"`
}

// AWSRemediationApprovalFeatureFlag pins the deterministic feature-flag state
// at projection time so operators can see why a queue entry is or isn't
// executable.
type AWSRemediationApprovalFeatureFlag struct {
	Name      string `json:"name"`
	Enabled   bool   `json:"enabled"`
	Scope     string `json:"scope"`
	Rationale string `json:"rationale"`
}

// AWSRemediationApprovalEntry is the persisted-record-shaped contract emitted
// by the approval workflow. It is metadata-only: it carries no rendered IAC
// or policy bodies, no secret material, and no workload payloads. The entry
// records *what* approval is required and *what* state it is in; live AWS
// mutation belongs to later wave executors.
type AWSRemediationApprovalEntry struct {
	ApprovalID         string                              `json:"approval_id"`
	CalculationVersion string                              `json:"calculation_version"`
	CaseID             string                              `json:"case_id"`
	SourceArtifactID   string                              `json:"source_artifact_id"`
	SourceType         string                              `json:"source_type"`
	State              string                              `json:"state"`
	RiskTier           string                              `json:"risk_tier"`
	Severity           string                              `json:"severity"`
	Score              int                                 `json:"score"`
	Confidence         float64                             `json:"confidence"`
	Title              string                              `json:"title"`
	Summary            string                              `json:"summary"`
	AccountID          string                              `json:"account_id"`
	Region             string                              `json:"region"`
	Requestor          AWSRemediationApprovalActor         `json:"requestor"`
	RequiredApprovers  []AWSRemediationApprovalActor       `json:"required_approvers"`
	Scope              AWSRemediationApprovalScope         `json:"scope"`
	RBACGates          []AWSRemediationApprovalRBACGate    `json:"rbac_gates"`
	FeatureFlags       []AWSRemediationApprovalFeatureFlag `json:"feature_flags"`
	IdempotencyKey     string                              `json:"idempotency_key"`
	DryRunRef          string                              `json:"dry_run_ref,omitempty"`
	DiffIntent         AWSRemediationDiffIntent            `json:"diff_intent"`
	Tradeoffs          []AWSRemediationTradeoff            `json:"tradeoffs"`
	RollbackPlan       AWSRemediationRollbackPlan          `json:"rollback_plan"`
	VerificationPlan   AWSRemediationVerificationPlan      `json:"verification_plan"`
	AuditTrail         []AWSRemediationApprovalAuditEntry  `json:"audit_trail"`
	ReadyForExecution  bool                                `json:"ready_for_execution"`
	KillSwitchEngaged  bool                                `json:"kill_switch_engaged"`
	ReadOnlyProjection bool                                `json:"read_only_projection"`
	SourceSignals      []string                            `json:"source_signals"`
	Evidence           []AWSRemediationApprovalEvidence    `json:"evidence"`
	EvidenceBoundary   string                              `json:"evidence_boundary"`
	ImpactedNodes      []string                            `json:"impacted_nodes"`
	ImpactedPath       []AWSRemediationApprovalPathStep    `json:"impacted_path"`
	NextAction         string                              `json:"next_action"`
	RequestedAt        time.Time                           `json:"requested_at"`
	ExpiresAt          time.Time                           `json:"expires_at"`
	CreatedAt          time.Time                           `json:"created_at"`
	UpdatedAt          time.Time                           `json:"updated_at"`
}

// AWSRemediationApprovalSummary aggregates the unfiltered and filtered queue.
type AWSRemediationApprovalSummary struct {
	TotalEntries          int            `json:"total_entries"`
	FilteredEntries       int            `json:"filtered_entries"`
	StateCounts           map[string]int `json:"state_counts"`
	RiskTierCounts        map[string]int `json:"risk_tier_counts"`
	SeverityCounts        map[string]int `json:"severity_counts"`
	ScopeTypeCounts       map[string]int `json:"scope_type_counts"`
	RequiredApproverCount int            `json:"required_approver_count"`
	ReadyForExecution     int            `json:"ready_for_execution_count"`
	KillSwitchEngaged     int            `json:"kill_switch_engaged_count"`
	RBACGateBlockedCount  int            `json:"rbac_gate_blocked_count"`
	AuditEntryCount       int            `json:"audit_entry_count"`
	RelationshipCount     int            `json:"relationship_count"`
	HighestScore          int            `json:"highest_score"`
	AverageConfidencePct  int            `json:"average_confidence_pct"`
}

// AWSRemediationApprovalRelationship surfaces approval→graph node edges so the
// app can join approvals against the same impacted nodes as their source case.
type AWSRemediationApprovalRelationship struct {
	ApprovalID  string `json:"approval_id"`
	Type        string `json:"type"`
	FromNodeID  string `json:"from_node_id"`
	ToNodeID    string `json:"to_node_id"`
	EvidenceRef string `json:"evidence_ref,omitempty"`
}

// AWSRemediationApprovalResult is the deterministic envelope returned by the
// approval-queue endpoint.
type AWSRemediationApprovalResult struct {
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
	CalculationVersion string                               `json:"calculation_version"`
	AppliedFilters     map[string]string                    `json:"applied_filters"`
	Summary            AWSRemediationApprovalSummary        `json:"summary"`
	Entries            []AWSRemediationApprovalEntry        `json:"entries"`
	Relationships      []AWSRemediationApprovalRelationship `json:"relationships"`
	Caveats            []string                             `json:"caveats"`
	FailureReasons     []string                             `json:"failure_reasons"`
	RemediationHints   []string                             `json:"remediation_hints"`
	EvidenceLinks      []string                             `json:"evidence_links"`
	CoverageGaps       []AWSRemediationApprovalCoverageGap  `json:"coverage_gaps"`
	Diagnostics        []AWSRemediationApprovalDiagnostic   `json:"diagnostics"`
	GeneratedAt        time.Time                            `json:"generated_at"`
	UpdatedAt          time.Time                            `json:"updated_at"`
}

// GetAWSRemediationApprovalQueue projects a deterministic, read-only AWS
// remediation approval queue from upstream remediation cases. It enforces the
// approval, RBAC, feature-flag, and scope gates server-side but never mutates
// AWS, never calls IAM/STS/Organizations write APIs, and never reads, exposes,
// logs, or persists rendered policies, secret values, customer payloads,
// prompts, completions, browser pages, code-interpreter output, database rows,
// or object contents.
func (s *Service) GetAWSRemediationApprovalQueue(ctx context.Context, workspaceID string, projectID string, request AWSRemediationApprovalRequest) (AWSRemediationApprovalResult, error) {
	project, scope, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return AWSRemediationApprovalResult{}, err
	}
	connection, hasConnection, err := s.awsBaselineConnection(ctx, project, strings.TrimSpace(request.ConnectorID))
	if err != nil {
		return AWSRemediationApprovalResult{}, err
	}
	now := s.Now().UTC()
	fixtureState := normalizeAWSRemediationApprovalFixtureState(request.FixtureState, connection, hasConnection)
	if fixtureState == "" {
		return AWSRemediationApprovalResult{}, ErrInvalidAWSConnectionRequest
	}

	accountID := firstNonEmptyAWSValue(connection.AccountID, strings.TrimSpace(request.AccountID), "123456789012")
	region := firstNonEmptyAWSValue(connection.Region, strings.TrimSpace(request.Region), "us-east-1")
	connectorID := firstNonEmptyAWSValue(connection.ConnectorID, strings.TrimSpace(request.ConnectorID))
	sourceFixtureState := fixtureState
	if strings.TrimSpace(request.FixtureState) == "" && hasConnection && connection.Connected {
		sourceFixtureState = ""
	}

	cases, err := s.GetAWSRemediationCases(ctx, workspaceID, projectID, AWSRemediationCaseRequest{ConnectorID: connectorID, FixtureState: sourceFixtureState})
	if err != nil {
		return AWSRemediationApprovalResult{}, fmt.Errorf("remediation approval cases: %w", err)
	}

	entries := awsRemediationApprovalEntries(cases.Cases, now, connectorID)
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].Score == entries[j].Score {
			return entries[i].ApprovalID < entries[j].ApprovalID
		}
		return entries[i].Score > entries[j].Score
	})
	filtered, applied := filterAWSRemediationApprovalEntries(entries, request)
	relationships := awsRemediationApprovalRelationships(filtered)
	diagnostics := awsRemediationApprovalDiagnostics(cases.Diagnostics)
	coverageGaps := awsRemediationApprovalCoverageGaps(cases.CoverageGaps)
	status, confidence := summarizeAWSRemediationApprovalStatus(cases.Status, filtered, diagnostics)

	return AWSRemediationApprovalResult{
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
		FixtureState:       sourceFixtureState,
		Confidence:         confidence,
		CalculationVersion: awsRemediationApprovalVersion,
		AppliedFilters:     applied,
		Summary:            summarizeAWSRemediationApprovalEntries(entries, filtered, relationships),
		Entries:            filtered,
		Relationships:      relationships,
		Caveats:            awsRemediationApprovalCaveats(),
		FailureReasons:     dedupeStrings(cases.FailureReasons),
		RemediationHints:   awsRemediationApprovalRemediationHints(cases.RemediationHints),
		EvidenceLinks: dedupeStrings([]string{
			awsIssueURL(awsPlatformDependencyParentIssue),
			awsIssueURL(awsRemediationApprovalCurrentIssue),
			awsIssueURL(awsRemediationCaseCurrentIssue),
			"/docs/aws-remediation-approval-rbac",
			"/docs/aws-remediation-case-model",
			awsBaselineProjectEvidenceURL(scope, project),
		}),
		CoverageGaps: coverageGaps,
		Diagnostics:  diagnostics,
		GeneratedAt:  now,
		UpdatedAt:    now,
	}, nil
}

func normalizeAWSRemediationApprovalFixtureState(requested string, connection AWSConnectionStatus, hasConnection bool) string {
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

func awsRemediationApprovalEntries(cases []AWSRemediationCase, now time.Time, connectorID string) []AWSRemediationApprovalEntry {
	entries := make([]AWSRemediationApprovalEntry, 0, len(cases))
	for _, source := range cases {
		entries = append(entries, awsRemediationApprovalEntryFromCase(source, now, connectorID))
	}
	return entries
}

func awsRemediationApprovalEntryFromCase(source AWSRemediationCase, now time.Time, connectorID string) AWSRemediationApprovalEntry {
	riskTier := awsRemediationApprovalRiskTier(source)
	requestor := awsRemediationApprovalRequestor(source)
	approvers := awsRemediationApprovalRequiredApprovers(source, riskTier)
	scope := awsRemediationApprovalScope(source, connectorID)
	gates := awsRemediationApprovalRBACGates(source, approvers)
	flags := awsRemediationApprovalFeatureFlags(source, riskTier)
	killSwitch := awsRemediationApprovalFeatureFlagEngaged(flags, "remediation_kill_switch")
	state := awsRemediationApprovalDeriveState(source, gates, killSwitch)
	idempotency := awsRemediationApprovalIdempotencyKey(source)
	expires := awsRemediationApprovalExpiresAt(source, now, riskTier)
	audit := awsRemediationApprovalAuditTrail(source, state, requestor, approvers, now)
	evidenceRef := firstAWSRemediationCaseEvidenceRef(source.Evidence)
	entry := AWSRemediationApprovalEntry{
		ApprovalID:         "aws-remediation-approval:" + stableAWSBlastRadiusToken("approval", source.CaseID, riskTier),
		CalculationVersion: awsRemediationApprovalVersion,
		CaseID:             source.CaseID,
		SourceArtifactID:   source.SourceFindingID,
		SourceType:         source.SourceType,
		State:              state,
		RiskTier:           riskTier,
		Severity:           source.Severity,
		Score:              source.Score,
		Confidence:         source.Confidence,
		Title:              fmt.Sprintf("Approval: %s", source.Title),
		Summary:            fmt.Sprintf("RBAC-gated approval workflow for remediation case %s. Identrail does not mutate AWS; later wave executors apply the change after approval.", source.CaseID),
		AccountID:          source.AccountID,
		Region:             source.Region,
		Requestor:          requestor,
		RequiredApprovers:  approvers,
		Scope:              scope,
		RBACGates:          gates,
		FeatureFlags:       flags,
		IdempotencyKey:     idempotency,
		DryRunRef:          fmt.Sprintf("dry-run://%s/%s/proposed", source.SourceType, source.CaseID),
		DiffIntent:         source.DiffIntent,
		Tradeoffs:          source.Tradeoffs,
		RollbackPlan:       source.RollbackPlan,
		VerificationPlan:   source.VerificationPlan,
		AuditTrail:         audit,
		KillSwitchEngaged:  killSwitch,
		ReadOnlyProjection: true,
		SourceSignals:      dedupeStrings(append([]string{"remediation_case"}, source.SourceSignals...)),
		Evidence:           source.Evidence,
		EvidenceBoundary:   awsRemediationApprovalEvidenceBoundary(),
		ImpactedNodes:      source.ImpactedNodes,
		ImpactedPath:       source.ImpactedPath,
		NextAction:         awsRemediationApprovalNextAction(state, riskTier),
		RequestedAt:        source.CreatedAt,
		ExpiresAt:          expires,
		CreatedAt:          source.CreatedAt,
		UpdatedAt:          firstNonZeroAWSRemediationApprovalTime(source.UpdatedAt, now),
	}
	entry.ReadyForExecution = state == awsRemediationApprovalStateApproved && !killSwitch && awsRemediationApprovalAllGatesPassed(gates)
	if entry.RequestedAt.IsZero() {
		entry.RequestedAt = now
	}
	_ = evidenceRef
	return entry
}

func awsRemediationApprovalRiskTier(source AWSRemediationCase) string {
	switch strings.ToLower(strings.TrimSpace(source.Severity)) {
	case "critical":
		return awsRemediationApprovalRiskCritical
	case "high":
		return awsRemediationApprovalRiskHigh
	case "medium":
		return awsRemediationApprovalRiskMedium
	default:
		return awsRemediationApprovalRiskLow
	}
}

func awsRemediationApprovalRequestor(source AWSRemediationCase) AWSRemediationApprovalActor {
	if source.OwnerAssigned && strings.TrimSpace(source.Owner) != "" {
		return AWSRemediationApprovalActor{
			Role:         "remediation-requestor",
			Label:        source.Owner,
			Required:     true,
			Acknowledged: true,
		}
	}
	return AWSRemediationApprovalActor{
		Role:         "remediation-requestor",
		Label:        "unassigned",
		Required:     true,
		Acknowledged: false,
	}
}

func awsRemediationApprovalRequiredApprovers(source AWSRemediationCase, riskTier string) []AWSRemediationApprovalActor {
	approvers := []AWSRemediationApprovalActor{
		{Role: "security-reviewer", Label: "security-reviewer", Required: true},
		{Role: "platform-operator", Label: "platform-operator", Required: true},
	}
	if riskTier == awsRemediationApprovalRiskCritical || riskTier == awsRemediationApprovalRiskHigh {
		approvers = append(approvers, AWSRemediationApprovalActor{Role: "incident-commander", Label: "incident-commander", Required: true})
	}
	if strings.EqualFold(source.SourceType, "ai_agent_risk") || strings.EqualFold(source.SourceType, "secret_permission_equivalence") {
		approvers = append(approvers, AWSRemediationApprovalActor{Role: "data-protection-reviewer", Label: "data-protection-reviewer", Required: true})
	}
	return approvers
}

func awsRemediationApprovalScope(source AWSRemediationCase, connectorID string) AWSRemediationApprovalScope {
	scopeType := "identity"
	if len(source.ResourceNodeIDs) > 0 {
		scopeType = "resource"
	}
	if strings.EqualFold(source.SourceType, "blast_radius") {
		scopeType = "account"
	}
	connectors := []string{}
	if strings.TrimSpace(connectorID) != "" {
		connectors = append(connectors, connectorID)
	}
	identityNodes := []string{}
	if strings.TrimSpace(source.IdentityNodeID) != "" {
		identityNodes = append(identityNodes, source.IdentityNodeID)
	}
	return AWSRemediationApprovalScope{
		ScopeType:       scopeType,
		AccountIDs:      emptyStrings(dedupeStrings([]string{source.AccountID})),
		Regions:         emptyStrings(dedupeStrings([]string{source.Region})),
		ConnectorIDs:    connectors,
		IdentityNodeIDs: identityNodes,
		ResourceNodeIDs: emptyStrings(dedupeStrings(source.ResourceNodeIDs)),
	}
}

func awsRemediationApprovalRBACGates(source AWSRemediationCase, approvers []AWSRemediationApprovalActor) []AWSRemediationApprovalRBACGate {
	gates := []AWSRemediationApprovalRBACGate{
		{Name: "tenant_scope", Status: "passed", RequiredRole: "tenant-member", Rationale: "Tenant, workspace, project, and connector boundaries are preserved on every approval entry."},
		{Name: "read_only_projection", Status: "passed", RequiredRole: "remediation-viewer", Rationale: "Identrail emits approval metadata only; no AWS write API is called here."},
		{Name: "requestor_assigned", Status: awsRemediationApprovalGateStatus(source.OwnerAssigned), RequiredRole: "remediation-requestor", Rationale: "An accountable requestor must be assigned before the approval workflow can advance."},
		{Name: "approver_quorum", Status: awsRemediationApprovalGateStatus(len(approvers) >= 2), RequiredRole: "remediation-approver", Rationale: "At least two required approver roles must acknowledge the request before execution."},
	}
	if source.Confidence < 0.7 {
		gates = append(gates, AWSRemediationApprovalRBACGate{Name: "confidence_floor", Status: "blocked", RequiredRole: "remediation-approver", Rationale: "Upstream evidence confidence is below the 0.7 threshold required to advance the approval."})
	}
	if !source.ApprovalRequired {
		gates = append(gates, AWSRemediationApprovalRBACGate{Name: "approval_required", Status: "blocked", RequiredRole: "remediation-approver", Rationale: "Source case is marked no-approval-required; this queue entry is informational only."})
	}
	return gates
}

func awsRemediationApprovalGateStatus(ok bool) string {
	if ok {
		return "passed"
	}
	return "blocked"
}

func awsRemediationApprovalFeatureFlags(source AWSRemediationCase, riskTier string) []AWSRemediationApprovalFeatureFlag {
	flags := []AWSRemediationApprovalFeatureFlag{
		{Name: "aws_remediation_approval_workflow", Enabled: true, Scope: "tenant", Rationale: "Approval workflow projection is always-on; later wave executors gate live AWS mutation behind their own flags."},
		{Name: "remediation_kill_switch", Enabled: false, Scope: "tenant", Rationale: "Tenant-scoped kill switch for AWS remediation execution; default off in this projection."},
		{Name: "live_aws_mutation", Enabled: false, Scope: "tenant", Rationale: "Live AWS mutation is intentionally disabled at this layer; later wave executors implement controlled execution."},
	}
	if riskTier == awsRemediationApprovalRiskCritical {
		flags = append(flags, AWSRemediationApprovalFeatureFlag{Name: "critical_risk_dual_control", Enabled: true, Scope: "case", Rationale: "Critical-risk approvals require dual-control acknowledgement before execution."})
	}
	if strings.EqualFold(source.SourceType, "aws_iac_remediation") {
		flags = append(flags, AWSRemediationApprovalFeatureFlag{Name: "iac_remediation_pr_required", Enabled: true, Scope: "case", Rationale: "IaC remediation cases require an operator-owned source-control PR before approval can advance."})
	}
	return flags
}

func awsRemediationApprovalFeatureFlagEngaged(flags []AWSRemediationApprovalFeatureFlag, name string) bool {
	for _, flag := range flags {
		if flag.Name == name {
			return flag.Enabled
		}
	}
	return false
}

func awsRemediationApprovalDeriveState(source AWSRemediationCase, gates []AWSRemediationApprovalRBACGate, killSwitch bool) string {
	if killSwitch {
		return awsRemediationApprovalStateBlocked
	}
	for _, gate := range gates {
		if gate.Status == "blocked" {
			return awsRemediationApprovalStateBlocked
		}
	}
	switch strings.ToLower(strings.TrimSpace(source.ApprovalState)) {
	case "approved":
		return awsRemediationApprovalStateApproved
	case "pending_approver":
		return awsRemediationApprovalStateReview
	case "denied":
		return awsRemediationApprovalStateDenied
	case "expired":
		return awsRemediationApprovalStateExpired
	case "under_review", "review":
		return awsRemediationApprovalStateReview
	}
	switch strings.ToLower(strings.TrimSpace(source.Lifecycle)) {
	case "proposed", "pending":
		return awsRemediationApprovalStateRequested
	case "in_review", "under_review", "review":
		return awsRemediationApprovalStateReview
	case "approved":
		return awsRemediationApprovalStateApproved
	case "denied":
		return awsRemediationApprovalStateDenied
	case "expired":
		return awsRemediationApprovalStateExpired
	}
	if !source.ApprovalRequired {
		return awsRemediationApprovalStateBlocked
	}
	return awsRemediationApprovalStateRequested
}

func awsRemediationApprovalIdempotencyKey(source AWSRemediationCase) string {
	return "aws-remediation-approval:" + stableAWSBlastRadiusToken("idempotency", source.CaseID, source.CalculationVersion)
}

func awsRemediationApprovalExpiresAt(source AWSRemediationCase, now time.Time, riskTier string) time.Time {
	base := source.UpdatedAt
	if base.IsZero() {
		base = now
	}
	grace := time.Duration(awsRemediationApprovalDefaultGraceHours) * time.Hour
	switch riskTier {
	case awsRemediationApprovalRiskCritical:
		grace = 12 * time.Hour
	case awsRemediationApprovalRiskHigh:
		grace = 24 * time.Hour
	case awsRemediationApprovalRiskMedium:
		grace = 48 * time.Hour
	}
	return base.Add(grace)
}

func awsRemediationApprovalAuditTrail(source AWSRemediationCase, state string, requestor AWSRemediationApprovalActor, approvers []AWSRemediationApprovalActor, now time.Time) []AWSRemediationApprovalAuditEntry {
	occurredAt := source.CreatedAt
	if occurredAt.IsZero() {
		occurredAt = now
	}
	trail := []AWSRemediationApprovalAuditEntry{}
	trail = append(trail, source.AuditTrail...)
	trail = append(trail, AWSRemediationApprovalAuditEntry{
		EventID:     stableAWSBlastRadiusToken("approval-request", source.CaseID, requestor.Label),
		Actor:       requestor.Label,
		EventType:   "approval_requested",
		OccurredAt:  occurredAt,
		EvidenceRef: firstAWSRemediationCaseEvidenceRef(source.Evidence),
		Notes:       fmt.Sprintf("Approval workflow entry projected; state=%s.", state),
	})
	for _, approver := range approvers {
		trail = append(trail, AWSRemediationApprovalAuditEntry{
			EventID:    stableAWSBlastRadiusToken("approval-required", source.CaseID, approver.Role),
			Actor:      approver.Label,
			EventType:  "approval_required",
			OccurredAt: occurredAt,
			Notes:      fmt.Sprintf("Required approver role %s pending acknowledgement.", approver.Role),
		})
	}
	return trail
}

func awsRemediationApprovalNextAction(state, riskTier string) string {
	switch state {
	case awsRemediationApprovalStateApproved:
		return "Approval granted; later wave executors may run the dry-run, apply, and verify workflow when their feature flag opens."
	case awsRemediationApprovalStateDenied:
		return "Approval denied; revisit the source remediation case before re-requesting."
	case awsRemediationApprovalStateExpired:
		return "Approval window expired; re-evaluate evidence and re-request approval if the change is still required."
	case awsRemediationApprovalStateBlocked:
		return "Approval blocked by an RBAC gate or kill switch; satisfy the failing gate before retrying."
	case awsRemediationApprovalStateReview:
		return fmt.Sprintf("Approver quorum is reviewing; risk_tier=%s. Capture any additional evidence before voting.", riskTier)
	}
	return fmt.Sprintf("Awaiting approver acknowledgement; required quorum varies by risk_tier=%s.", riskTier)
}

func awsRemediationApprovalAllGatesPassed(gates []AWSRemediationApprovalRBACGate) bool {
	for _, gate := range gates {
		if gate.Status == "blocked" {
			return false
		}
	}
	return true
}

func firstNonZeroAWSRemediationApprovalTime(values ...time.Time) time.Time {
	for _, value := range values {
		if !value.IsZero() {
			return value
		}
	}
	return time.Time{}
}

func firstAWSRemediationCaseEvidenceRef(evidence []AWSRemediationCaseEvidence) string {
	for _, item := range evidence {
		if strings.TrimSpace(item.EvidenceRef) != "" {
			return item.EvidenceRef
		}
	}
	return ""
}

func filterAWSRemediationApprovalEntries(entries []AWSRemediationApprovalEntry, request AWSRemediationApprovalRequest) ([]AWSRemediationApprovalEntry, map[string]string) {
	filters := map[string]string{
		"account_id":          strings.TrimSpace(request.AccountID),
		"region":              strings.TrimSpace(request.Region),
		"case_id":             strings.TrimSpace(request.CaseID),
		"state":               normalizeAWSRuntimeEventFilterToken(request.State),
		"risk_tier":           normalizeAWSRuntimeEventFilterToken(request.RiskTier),
		"scope_type":          normalizeAWSRuntimeEventFilterToken(request.ScopeType),
		"requestor":           normalizeAWSRuntimeEventFilterToken(request.Requestor),
		"approver_role":       normalizeAWSRuntimeEventFilterToken(request.ApproverRole),
		"severity":            normalizeAWSRuntimeEventFilterToken(request.Severity),
		"ready_for_execution": strings.ToLower(strings.TrimSpace(request.ReadyForExecution)),
		"kill_switch_engaged": strings.ToLower(strings.TrimSpace(request.KillSwitchEngaged)),
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
	filtered := make([]AWSRemediationApprovalEntry, 0, len(entries))
	for _, entry := range entries {
		if filters["account_id"] != "" && filters["account_id"] != entry.AccountID {
			continue
		}
		if filters["region"] != "" && !strings.EqualFold(filters["region"], entry.Region) {
			continue
		}
		if filters["case_id"] != "" && !strings.EqualFold(filters["case_id"], entry.CaseID) {
			continue
		}
		if filters["state"] != "" && filters["state"] != normalizeAWSRuntimeEventFilterToken(entry.State) {
			continue
		}
		if filters["risk_tier"] != "" && filters["risk_tier"] != normalizeAWSRuntimeEventFilterToken(entry.RiskTier) {
			continue
		}
		if filters["scope_type"] != "" && filters["scope_type"] != normalizeAWSRuntimeEventFilterToken(entry.Scope.ScopeType) {
			continue
		}
		if filters["severity"] != "" && filters["severity"] != normalizeAWSRuntimeEventFilterToken(entry.Severity) {
			continue
		}
		if filters["requestor"] != "" && filters["requestor"] != normalizeAWSRuntimeEventFilterToken(entry.Requestor.Label) {
			continue
		}
		if filters["approver_role"] != "" && !awsRemediationApprovalHasApproverRole(entry, filters["approver_role"]) {
			continue
		}
		if filters["ready_for_execution"] != "" {
			want := filters["ready_for_execution"]
			if (want == "true" || want == "yes") != entry.ReadyForExecution {
				continue
			}
		}
		if filters["kill_switch_engaged"] != "" {
			want := filters["kill_switch_engaged"]
			if (want == "true" || want == "yes") != entry.KillSwitchEngaged {
				continue
			}
		}
		if filters["search"] != "" && !awsRemediationApprovalSearchMatch(entry, filters["search"]) {
			continue
		}
		filtered = append(filtered, entry)
	}
	return filtered, applied
}

func awsRemediationApprovalHasApproverRole(entry AWSRemediationApprovalEntry, needle string) bool {
	needle = normalizeAWSRuntimeEventFilterToken(needle)
	if needle == "" {
		return true
	}
	for _, approver := range entry.RequiredApprovers {
		if normalizeAWSRuntimeEventFilterToken(approver.Role) == needle {
			return true
		}
	}
	return false
}

func awsRemediationApprovalSearchMatch(entry AWSRemediationApprovalEntry, needle string) bool {
	needle = strings.ToLower(strings.TrimSpace(needle))
	if needle == "" {
		return true
	}
	values := []string{
		entry.ApprovalID, entry.CaseID, entry.SourceArtifactID, entry.SourceType, entry.State, entry.RiskTier,
		entry.Severity, entry.Title, entry.Summary, entry.IdempotencyKey, entry.DryRunRef, entry.NextAction,
		entry.Requestor.Role, entry.Requestor.Label, entry.Scope.ScopeType,
		entry.DiffIntent.Kind, entry.DiffIntent.DiffSummary,
		entry.RollbackPlan.Strategy, entry.VerificationPlan.Strategy,
	}
	values = append(values, entry.SourceSignals...)
	values = append(values, entry.Scope.AccountIDs...)
	values = append(values, entry.Scope.Regions...)
	values = append(values, entry.Scope.ConnectorIDs...)
	values = append(values, entry.Scope.IdentityNodeIDs...)
	values = append(values, entry.Scope.ResourceNodeIDs...)
	for _, approver := range entry.RequiredApprovers {
		values = append(values, approver.Role, approver.Label)
	}
	for _, gate := range entry.RBACGates {
		values = append(values, gate.Name, gate.Status, gate.RequiredRole, gate.Rationale)
	}
	for _, flag := range entry.FeatureFlags {
		values = append(values, flag.Name, flag.Scope, flag.Rationale)
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

func awsRemediationApprovalRelationships(entries []AWSRemediationApprovalEntry) []AWSRemediationApprovalRelationship {
	relationships := []AWSRemediationApprovalRelationship{}
	for _, entry := range entries {
		evidenceRef := firstAWSRemediationCaseEvidenceRef(entry.Evidence)
		for _, target := range entry.ImpactedNodes {
			if strings.TrimSpace(target) == "" {
				continue
			}
			relationships = append(relationships, AWSRemediationApprovalRelationship{
				ApprovalID:  entry.ApprovalID,
				Type:        "approval_targets_node",
				FromNodeID:  entry.ApprovalID,
				ToNodeID:    target,
				EvidenceRef: evidenceRef,
			})
		}
	}
	return relationships
}

func summarizeAWSRemediationApprovalEntries(all, filtered []AWSRemediationApprovalEntry, relationships []AWSRemediationApprovalRelationship) AWSRemediationApprovalSummary {
	summary := AWSRemediationApprovalSummary{
		TotalEntries:    len(all),
		FilteredEntries: len(filtered),
		StateCounts:     map[string]int{},
		RiskTierCounts:  map[string]int{},
		SeverityCounts:  map[string]int{},
		ScopeTypeCounts: map[string]int{},
	}
	confidenceTotal := 0.0
	auditTotal := 0
	gateBlockedTotal := 0
	for _, entry := range filtered {
		summary.StateCounts[entry.State]++
		summary.RiskTierCounts[entry.RiskTier]++
		summary.SeverityCounts[entry.Severity]++
		summary.ScopeTypeCounts[entry.Scope.ScopeType]++
		summary.RequiredApproverCount += len(entry.RequiredApprovers)
		if entry.ReadyForExecution {
			summary.ReadyForExecution++
		}
		if entry.KillSwitchEngaged {
			summary.KillSwitchEngaged++
		}
		for _, gate := range entry.RBACGates {
			if gate.Status == "blocked" {
				gateBlockedTotal++
			}
		}
		auditTotal += len(entry.AuditTrail)
		if entry.Score > summary.HighestScore {
			summary.HighestScore = entry.Score
		}
		confidenceTotal += entry.Confidence
	}
	summary.RBACGateBlockedCount = gateBlockedTotal
	summary.AuditEntryCount = auditTotal
	summary.RelationshipCount = len(relationships)
	if len(filtered) > 0 {
		summary.AverageConfidencePct = int((confidenceTotal/float64(len(filtered)))*100 + 0.5)
	}
	return summary
}

func summarizeAWSRemediationApprovalStatus(sourceStatus string, filtered []AWSRemediationApprovalEntry, diagnostics []AWSRemediationApprovalDiagnostic) (string, float64) {
	if sourceStatus == awsPlatformDependencyStatusBlocked {
		return awsPlatformDependencyStatusBlocked, 0.35
	}
	for _, diagnostic := range diagnostics {
		if diagnostic.Retryable {
			return awsPlatformDependencyStatusDegraded, 0.72
		}
	}
	if sourceStatus == awsPlatformDependencyStatusDegraded {
		return awsPlatformDependencyStatusDegraded, 0.74
	}
	if len(filtered) == 0 {
		return awsPlatformDependencyStatusReady, 0.82
	}
	return awsPlatformDependencyStatusReady, 0.9
}

func awsRemediationApprovalCaveats() []string {
	return []string{
		"Approval workflow entries are read-only projections; Identrail never calls IAM, STS, or Organizations write APIs at this layer.",
		"RBAC gates, feature flags, kill switch, idempotency keys, and scope checks are enforced server-side before any entry can become ready_for_execution.",
		"ready_for_execution is only a planning signal — controlled live execution belongs to the wave 8 executors and their own feature flags.",
	}
}

func awsRemediationApprovalRemediationHints(source []string) []string {
	hints := []string{
		"Approvers should attach acknowledgement evidence (e.g. ticket link, change request) to the source remediation case before voting.",
		"If the kill switch engages, all approvals stay blocked until the tenant feature flag flips off; later wave executors honour the same gate.",
		"Use the idempotency key as the deterministic id when wiring later wave dry-run, apply, and verify executors so retries do not double-apply.",
	}
	hints = append(hints, source...)
	return dedupeStrings(hints)
}

func awsRemediationApprovalDiagnostics(source []AWSRemediationCaseDiagnostic) []AWSRemediationApprovalDiagnostic {
	out := make([]AWSRemediationApprovalDiagnostic, 0, len(source))
	for _, diagnostic := range source {
		out = append(out, AWSRemediationApprovalDiagnostic(diagnostic))
	}
	return out
}

func awsRemediationApprovalCoverageGaps(source []AWSRemediationCaseCoverageGap) []AWSRemediationApprovalCoverageGap {
	gaps := []AWSRemediationApprovalCoverageGap{{
		Capability:  "aws_remediation_live_execution",
		Status:      "out_of_scope",
		Reason:      "Issue #1536 implements the approval workflow and RBAC gates only; live IAM/STS/Organizations write APIs are not called by this endpoint.",
		Remediation: "Wire the dry-run, apply, and verify executors in wave 8 issues (#1537, #1538, #1539, #1540, #1541, #1542) once their safety gates are in place.",
	}}
	for _, gap := range source {
		gaps = append(gaps, AWSRemediationApprovalCoverageGap(gap))
	}
	return gaps
}

func awsRemediationApprovalEvidenceBoundary() string {
	return "metadata_only_no_rendered_policy_bodies_no_secret_values_no_workload_payloads_tenant_workspace_project_connector_account_region_scoped"
}
