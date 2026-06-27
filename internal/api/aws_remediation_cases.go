package api

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	awsRemediationCaseCurrentIssue = 1529
	awsRemediationCaseVersion      = "aws-remediation-case-model-v1"
)

// AWSRemediationCaseRequest scopes the deterministic remediation case engine
// to one AWS connector plus optional operator drill-down filters.
type AWSRemediationCaseRequest struct {
	ConnectorID   string `json:"connector_id,omitempty"`
	FixtureState  string `json:"fixture_state,omitempty"`
	AccountID     string `json:"account_id,omitempty"`
	Region        string `json:"region,omitempty"`
	Identity      string `json:"identity,omitempty"`
	SourceType    string `json:"source_type,omitempty"`
	Lifecycle     string `json:"lifecycle,omitempty"`
	Severity      string `json:"severity,omitempty"`
	Status        string `json:"status,omitempty"`
	ApprovalState string `json:"approval_state,omitempty"`
	OwnerAssigned string `json:"owner_assigned,omitempty"`
	Search        string `json:"search,omitempty"`
}

// AWSRemediationCaseEvidence and path step reuse the least-privilege contract
// so the case model stays consistent with upstream intelligence engines.
type AWSRemediationCaseEvidence = AWSLeastPrivilegeEvidence
type AWSRemediationCasePathStep = AWSLeastPrivilegePathStep
type AWSRemediationCaseDiagnostic = AWSLeastPrivilegeDiagnostic
type AWSRemediationCaseCoverageGap = AWSLeastPrivilegeCoverageGap

// AWSRemediationDiffIntent describes the read-only before/after intent of a
// remediation case. It carries metadata refs only; no policy bodies, secret
// values, or rendered diffs are inlined.
type AWSRemediationDiffIntent struct {
	Kind               string `json:"kind"`
	BeforeRef          string `json:"before_ref,omitempty"`
	AfterRef           string `json:"after_ref,omitempty"`
	DiffSummary        string `json:"diff_summary"`
	NoOp               bool   `json:"no_op"`
	ReadOnlyProjection bool   `json:"read_only_projection"`
}

// AWSRemediationTradeoff explains an operator-visible cost the case introduces
// (breakage risk, observability impact, etc.).
type AWSRemediationTradeoff struct {
	Dimension   string `json:"dimension"`
	Direction   string `json:"direction"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
}

// AWSRemediationRollbackPlan documents how an executed change can be undone.
type AWSRemediationRollbackPlan struct {
	Strategy    string   `json:"strategy"`
	Steps       []string `json:"steps"`
	EvidenceRef string   `json:"evidence_ref,omitempty"`
}

// AWSRemediationVerificationPlan documents how an executed change is verified.
type AWSRemediationVerificationPlan struct {
	Strategy       string   `json:"strategy"`
	Steps          []string `json:"steps"`
	SuccessSignals []string `json:"success_signals,omitempty"`
	FailureSignals []string `json:"failure_signals,omitempty"`
	EvidenceRef    string   `json:"evidence_ref,omitempty"`
}

// AWSRemediationAuditEntry is a deterministic audit row attached to the case.
// Because no execution happens in this issue, the only entry is the
// system-generated proposal event.
type AWSRemediationAuditEntry struct {
	EventID     string    `json:"event_id"`
	Actor       string    `json:"actor"`
	EventType   string    `json:"event_type"`
	OccurredAt  time.Time `json:"occurred_at"`
	EvidenceRef string    `json:"evidence_ref,omitempty"`
	Notes       string    `json:"notes,omitempty"`
}

// AWSRemediationRelationship surfaces case→graph node edges so the app and
// downstream graph consumers can show why a case touches a node.
type AWSRemediationRelationship struct {
	CaseID      string `json:"case_id"`
	Type        string `json:"type"`
	FromNodeID  string `json:"from_node_id"`
	ToNodeID    string `json:"to_node_id"`
	EvidenceRef string `json:"evidence_ref,omitempty"`
}

// AWSRemediationCase is the persisted-record-shaped contract emitted by the
// remediation case engine. It intentionally carries only metadata evidence
// refs and graph nodes; no policy bodies, secret values, prompts,
// completions, tool payloads, browser pages, code-interpreter output,
// database rows, object contents, or customer payloads are inlined.
type AWSRemediationCase struct {
	CaseID             string                         `json:"case_id"`
	CalculationVersion string                         `json:"calculation_version"`
	SourceType         string                         `json:"source_type"`
	SourceFindingID    string                         `json:"source_finding_id"`
	Lifecycle          string                         `json:"lifecycle"`
	Severity           string                         `json:"severity"`
	Status             string                         `json:"status"`
	Score              int                            `json:"score"`
	Confidence         float64                        `json:"confidence"`
	Title              string                         `json:"title"`
	Summary            string                         `json:"summary"`
	AccountID          string                         `json:"account_id"`
	Region             string                         `json:"region"`
	IdentityNodeID     string                         `json:"identity_node_id,omitempty"`
	IdentityARN        string                         `json:"identity_arn,omitempty"`
	IdentityName       string                         `json:"identity_name,omitempty"`
	IdentityType       string                         `json:"identity_type,omitempty"`
	Provider           string                         `json:"provider,omitempty"`
	ResourceNodeIDs    []string                       `json:"resource_node_ids,omitempty"`
	Owner              string                         `json:"owner,omitempty"`
	OwnerAssigned      bool                           `json:"owner_assigned"`
	ApprovalRequired   bool                           `json:"approval_required"`
	ApprovalState      string                         `json:"approval_state"`
	DiffIntent         AWSRemediationDiffIntent       `json:"diff_intent"`
	Tradeoffs          []AWSRemediationTradeoff       `json:"tradeoffs"`
	RollbackPlan       AWSRemediationRollbackPlan     `json:"rollback_plan"`
	VerificationPlan   AWSRemediationVerificationPlan `json:"verification_plan"`
	SourceSignals      []string                       `json:"source_signals"`
	Evidence           []AWSRemediationCaseEvidence   `json:"evidence"`
	EvidenceBoundary   string                         `json:"evidence_boundary"`
	ImpactedNodes      []string                       `json:"impacted_nodes"`
	ImpactedPath       []AWSRemediationCasePathStep   `json:"impacted_path"`
	NextActions        []string                       `json:"next_actions"`
	AuditTrail         []AWSRemediationAuditEntry     `json:"audit_trail"`
	CreatedAt          time.Time                      `json:"created_at"`
	UpdatedAt          time.Time                      `json:"updated_at"`
}

// AWSRemediationCaseSummary aggregates the unfiltered and filtered case set.
type AWSRemediationCaseSummary struct {
	TotalCases              int            `json:"total_cases"`
	FilteredCases           int            `json:"filtered_cases"`
	SeverityCounts          map[string]int `json:"severity_counts"`
	StatusCounts            map[string]int `json:"status_counts"`
	LifecycleCounts         map[string]int `json:"lifecycle_counts"`
	SourceTypeCounts        map[string]int `json:"source_type_counts"`
	ApprovalStateCounts     map[string]int `json:"approval_state_counts"`
	OwnerAssignedCount      int            `json:"owner_assigned_count"`
	OwnerlessCount          int            `json:"ownerless_count"`
	ApprovalRequiredCount   int            `json:"approval_required_count"`
	ReadOnlyProjectionCount int            `json:"read_only_projection_count"`
	RollbackPlanCount       int            `json:"rollback_plan_count"`
	VerificationPlanCount   int            `json:"verification_plan_count"`
	RelationshipCount       int            `json:"relationship_count"`
	AuditEntryCount         int            `json:"audit_entry_count"`
	HighestScore            int            `json:"highest_score"`
	AverageConfidencePct    int            `json:"average_confidence_pct"`
}

// AWSRemediationCaseResult is the deterministic case-model envelope.
type AWSRemediationCaseResult struct {
	TenantID           string                          `json:"tenant_id"`
	WorkspaceID        string                          `json:"workspace_id"`
	ProjectID          string                          `json:"project_id"`
	ConnectorID        string                          `json:"connector_id,omitempty"`
	AccountID          string                          `json:"account_id,omitempty"`
	Region             string                          `json:"region,omitempty"`
	ParentIssueNumber  int                             `json:"parent_issue_number"`
	ParentIssueRef     string                          `json:"parent_issue_ref"`
	CurrentIssueNumber int                             `json:"current_issue_number"`
	CurrentIssueRef    string                          `json:"current_issue_ref"`
	Version            string                          `json:"version"`
	Status             string                          `json:"status"`
	FixtureState       string                          `json:"fixture_state,omitempty"`
	Confidence         float64                         `json:"confidence"`
	CalculationVersion string                          `json:"calculation_version"`
	AppliedFilters     map[string]string               `json:"applied_filters"`
	Summary            AWSRemediationCaseSummary       `json:"summary"`
	Cases              []AWSRemediationCase            `json:"cases"`
	Relationships      []AWSRemediationRelationship    `json:"relationships"`
	Caveats            []string                        `json:"caveats"`
	FailureReasons     []string                        `json:"failure_reasons"`
	RemediationHints   []string                        `json:"remediation_hints"`
	EvidenceLinks      []string                        `json:"evidence_links"`
	CoverageGaps       []AWSRemediationCaseCoverageGap `json:"coverage_gaps"`
	Diagnostics        []AWSRemediationCaseDiagnostic  `json:"diagnostics"`
	GeneratedAt        time.Time                       `json:"generated_at"`
	UpdatedAt          time.Time                       `json:"updated_at"`
}

type awsRemediationCaseSources struct {
	risk        AWSAIAgentRiskResult
	least       AWSLeastPrivilegeResult
	equivalence AWSSecretPermissionEquivalenceResult
	blast       AWSBlastRadiusResult
	trust       AWSTrustPolicyHardeningResult
}

// GetAWSRemediationCases composes ranked, explainable remediation cases from
// upstream AI agent risk, least-privilege, secret-permission equivalence, and
// blast-radius findings. The engine is read-only: it never mutates AWS, never
// reads secret values or workload payloads, and treats unknown or denied
// evidence as explicit states instead of deterministic truth.
func (s *Service) GetAWSRemediationCases(ctx context.Context, workspaceID string, projectID string, request AWSRemediationCaseRequest) (AWSRemediationCaseResult, error) {
	project, scope, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return AWSRemediationCaseResult{}, err
	}
	connection, hasConnection, err := s.awsBaselineConnection(ctx, project, strings.TrimSpace(request.ConnectorID))
	if err != nil {
		return AWSRemediationCaseResult{}, err
	}
	now := s.Now().UTC()
	fixtureState := normalizeAWSRemediationCaseFixtureState(request.FixtureState, connection, hasConnection)
	if fixtureState == "" {
		return AWSRemediationCaseResult{}, ErrInvalidAWSConnectionRequest
	}

	accountID := firstNonEmptyAWSValue(connection.AccountID, strings.TrimSpace(request.AccountID), "123456789012")
	region := firstNonEmptyAWSValue(connection.Region, strings.TrimSpace(request.Region), "us-east-1")
	connectorID := firstNonEmptyAWSValue(connection.ConnectorID, strings.TrimSpace(request.ConnectorID))
	sourceFixtureState := fixtureState
	if strings.TrimSpace(request.FixtureState) == "" && hasConnection && connection.Connected {
		sourceFixtureState = ""
	}

	sources, err := s.awsRemediationCaseSourceSignals(ctx, workspaceID, projectID, connectorID, sourceFixtureState)
	if err != nil {
		return AWSRemediationCaseResult{}, err
	}
	cases := awsRemediationCases(sources, now)
	sort.SliceStable(cases, func(i, j int) bool {
		if cases[i].Score == cases[j].Score {
			return cases[i].CaseID < cases[j].CaseID
		}
		return cases[i].Score > cases[j].Score
	})
	filtered, applied := filterAWSRemediationCases(cases, request)
	relationships := awsRemediationCaseRelationships(filtered)
	diagnostics := awsRemediationCaseDiagnostics(sources)
	coverageGaps := awsRemediationCaseCoverageGaps(sources)
	status, confidence := summarizeAWSRemediationCaseStatus(sources, filtered, diagnostics)

	return AWSRemediationCaseResult{
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
		FixtureState:       sourceFixtureState,
		Confidence:         confidence,
		CalculationVersion: awsRemediationCaseVersion,
		AppliedFilters:     applied,
		Summary:            summarizeAWSRemediationCases(cases, filtered, relationships),
		Cases:              filtered,
		Relationships:      relationships,
		Caveats:            awsRemediationCaseCaveats(),
		FailureReasons:     awsRemediationCaseFailureReasons(sources),
		RemediationHints:   awsRemediationCaseRemediationHints(sources),
		EvidenceLinks: dedupeStrings([]string{
			awsIssueURL(awsPlatformDependencyParentIssue),
			awsIssueURL(awsRemediationCaseCurrentIssue),
			awsIssueURL(awsAIAgentRiskCurrentIssue),
			awsIssueURL(awsLeastPrivilegeCurrentIssue),
			awsIssueURL(awsSecretPermissionEquivalenceCurrentIssue),
			awsIssueURL(awsBlastRadiusCurrentIssue),
			awsIssueURL(awsTrustPolicyHardeningCurrentIssue),
			"/docs/aws-remediation-case-model",
			"/docs/aws-ai-agent-risk-engine",
			"/docs/aws-least-privilege",
			"/docs/aws-secret-permission-equivalence-engine",
			"/docs/aws-blast-radius-engine",
			"/docs/aws-trust-policy-hardening-planner",
			awsBaselineProjectEvidenceURL(scope, project),
		}),
		CoverageGaps: coverageGaps,
		Diagnostics:  diagnostics,
		GeneratedAt:  now,
		UpdatedAt:    now,
	}, nil
}

func normalizeAWSRemediationCaseFixtureState(requested string, connection AWSConnectionStatus, hasConnection bool) string {
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

func (s *Service) awsRemediationCaseSourceSignals(ctx context.Context, workspaceID, projectID, connectorID, fixtureState string) (awsRemediationCaseSources, error) {
	risk, err := s.GetAWSAIAgentRisk(ctx, workspaceID, projectID, AWSAIAgentRiskRequest{ConnectorID: connectorID, FixtureState: fixtureState})
	if err != nil {
		return awsRemediationCaseSources{}, fmt.Errorf("remediation case ai agent risk: %w", err)
	}
	least, err := s.GetAWSLeastPrivilegeRecommendations(ctx, workspaceID, projectID, AWSLeastPrivilegeRequest{ConnectorID: connectorID, FixtureState: fixtureState})
	if err != nil {
		return awsRemediationCaseSources{}, fmt.Errorf("remediation case least privilege: %w", err)
	}
	equivalence, err := s.GetAWSSecretPermissionEquivalence(ctx, workspaceID, projectID, AWSSecretPermissionEquivalenceRequest{ConnectorID: connectorID, FixtureState: fixtureState})
	if err != nil {
		return awsRemediationCaseSources{}, fmt.Errorf("remediation case secret permission equivalence: %w", err)
	}
	blast, err := s.GetAWSBlastRadius(ctx, workspaceID, projectID, AWSBlastRadiusRequest{ConnectorID: connectorID, FixtureState: fixtureState})
	if err != nil {
		return awsRemediationCaseSources{}, fmt.Errorf("remediation case blast radius: %w", err)
	}
	trust, err := s.GetAWSTrustPolicyHardeningPlans(ctx, workspaceID, projectID, AWSTrustPolicyHardeningRequest{ConnectorID: connectorID, FixtureState: fixtureState})
	if err != nil {
		return awsRemediationCaseSources{}, fmt.Errorf("remediation case trust policy hardening: %w", err)
	}
	return awsRemediationCaseSources{risk: risk, least: least, equivalence: equivalence, blast: blast, trust: trust}, nil
}

func awsRemediationCases(sources awsRemediationCaseSources, now time.Time) []AWSRemediationCase {
	cases := []AWSRemediationCase{}
	for _, finding := range sources.risk.Findings {
		if c, ok := awsRemediationCaseFromAIAgentRisk(finding, now); ok {
			cases = append(cases, c)
		}
	}
	for _, recommendation := range sources.least.Recommendations {
		if c, ok := awsRemediationCaseFromLeastPrivilege(recommendation, now); ok {
			cases = append(cases, c)
		}
	}
	for _, finding := range sources.equivalence.Findings {
		if c, ok := awsRemediationCaseFromSecretEquivalence(finding, now); ok {
			cases = append(cases, c)
		}
	}
	for _, finding := range sources.blast.Findings {
		if c, ok := awsRemediationCaseFromBlastRadius(finding, now); ok {
			cases = append(cases, c)
		}
	}
	for _, plan := range sources.trust.Plans {
		if c, ok := awsRemediationCaseFromTrustPolicyHardening(plan, now); ok {
			cases = append(cases, c)
		}
	}
	return awsRemediationCaseDedupe(cases)
}

func awsRemediationCaseFromAIAgentRisk(finding AWSAIAgentRiskFinding, now time.Time) (AWSRemediationCase, bool) {
	if finding.FindingID == "" {
		return AWSRemediationCase{}, false
	}
	caseID := "aws-remediation-case:" + stableAWSBlastRadiusToken("ai-agent-risk", finding.FindingID)
	diff := awsRemediationDiffIntentForRiskType(finding.RiskType)
	approvalRequired := awsRemediationApprovalRequired(finding.Severity, diff.Kind)
	owner, ownerAssigned := awsRemediationOwnerFromAgent(finding)
	approvalState := awsRemediationApprovalState(approvalRequired, ownerAssigned, finding.Status)
	lifecycle := awsRemediationLifecycle(finding.Status, finding.Confidence, ownerAssigned, approvalState, diff)
	identityType := "ai_agent"
	identityNodeID := finding.AgentNodeID
	identityARN := finding.RuntimeRoleARN
	identityName := firstNonEmptyAWSValue(finding.AgentName, finding.AgentID)
	if strings.HasPrefix(finding.RiskType, "backing_role") {
		identityType = "iam_role"
		identityNodeID = firstNonEmptyAWSValue(finding.RuntimeRoleNodeID, awsIdentityNodeIDForAPI(finding.RuntimeRoleARN), finding.AgentNodeID)
		identityName = firstNonEmptyAWSValue(shortAWSARN(finding.RuntimeRoleARN), finding.RuntimeRoleARN, finding.RuntimeRoleNodeID, finding.AgentName, finding.AgentID)
	}
	c := AWSRemediationCase{
		CaseID:             caseID,
		CalculationVersion: awsRemediationCaseVersion,
		SourceType:         "ai_agent_risk",
		SourceFindingID:    finding.FindingID,
		Lifecycle:          lifecycle,
		Severity:           finding.Severity,
		Status:             finding.Status,
		Score:              finding.Score,
		Confidence:         finding.Confidence,
		Title:              awsRemediationTitleForRiskType(finding.RiskType, finding.AgentName, finding.AgentID),
		Summary:            finding.Rationale,
		AccountID:          finding.AccountID,
		Region:             finding.Region,
		IdentityNodeID:     identityNodeID,
		IdentityARN:        identityARN,
		IdentityName:       identityName,
		IdentityType:       identityType,
		Provider:           finding.Provider,
		ResourceNodeIDs:    awsRemediationResourceNodes(finding.SensitiveResources, finding.ImpactedNodes, finding.AgentNodeID, finding.RuntimeRoleNodeID),
		Owner:              owner,
		OwnerAssigned:      ownerAssigned,
		ApprovalRequired:   approvalRequired,
		ApprovalState:      approvalState,
		DiffIntent:         diff,
		Tradeoffs:          awsRemediationTradeoffsForRiskType(finding.RiskType, finding.Severity),
		RollbackPlan:       awsRemediationRollbackForDiff(diff, evidenceRefFromAIAgentRisk(finding)),
		VerificationPlan:   awsRemediationVerificationForRiskType(finding.RiskType, evidenceRefFromAIAgentRisk(finding)),
		SourceSignals:      finding.SourceSignals,
		Evidence:           finding.Evidence,
		EvidenceBoundary:   awsRemediationCaseEvidenceBoundary(),
		ImpactedNodes:      finding.ImpactedNodes,
		ImpactedPath:       finding.ImpactedPath,
		NextActions:        awsRemediationNextActionList(finding.NextAction, diff),
		CreatedAt:          now,
		UpdatedAt:          now,
	}
	return finalizeAWSRemediationCase(c, now), true
}

func awsRemediationCaseFromLeastPrivilege(recommendation AWSLeastPrivilegeRecommendation, now time.Time) (AWSRemediationCase, bool) {
	if recommendation.RecommendationID == "" || recommendation.Decision == "keep" {
		return AWSRemediationCase{}, false
	}
	caseID := "aws-remediation-case:" + stableAWSBlastRadiusToken("least-privilege", recommendation.RecommendationID)
	evidenceRef := firstString(awsRemediationEvidenceRefs(recommendation.Evidence))
	diffKind := awsRemediationLeastPrivilegeDiffKind(recommendation)
	noOp := recommendation.Decision != "remove"
	diffSummary := fmt.Sprintf("Decision=%s on %s; remove %d granted action(s) and keep %d observed action(s).", recommendation.Decision, recommendation.DisplayName, len(recommendation.RemoveActions), len(recommendation.KeepActions))
	if recommendation.Decision == "review" {
		diffSummary = fmt.Sprintf("Decision=review on %s; least-privilege evidence is not yet conclusive — manual review required before any diff is projected.", recommendation.DisplayName)
	}
	afterRef := "least-privilege://" + recommendation.RecommendationID + "/intended-scope"
	if recommendation.Decision == "review" {
		afterRef = ""
	}
	diff := AWSRemediationDiffIntent{
		Kind:               diffKind,
		BeforeRef:          evidenceRef,
		AfterRef:           afterRef,
		DiffSummary:        diffSummary,
		NoOp:               noOp,
		ReadOnlyProjection: true,
	}
	approvalRequired := awsRemediationApprovalRequired(recommendation.Severity, diff.Kind)
	owner, ownerAssigned := "iam-platform", true
	approvalState := awsRemediationApprovalState(approvalRequired, ownerAssigned, recommendation.Status)
	lifecycle := awsRemediationLifecycle(recommendation.Status, recommendation.Confidence, ownerAssigned, approvalState, diff)
	c := AWSRemediationCase{
		CaseID:             caseID,
		CalculationVersion: awsRemediationCaseVersion,
		SourceType:         "least_privilege",
		SourceFindingID:    recommendation.RecommendationID,
		Lifecycle:          lifecycle,
		Severity:           recommendation.Severity,
		Status:             recommendation.Status,
		Score:              recommendation.Score,
		Confidence:         recommendation.Confidence,
		Title:              fmt.Sprintf("Least-privilege %s for %s", recommendation.Decision, firstNonEmptyAWSValue(recommendation.DisplayName, recommendation.IdentityNodeID)),
		Summary:            recommendation.Rationale,
		AccountID:          recommendation.AccountID,
		Region:             recommendation.Region,
		IdentityNodeID:     recommendation.IdentityNodeID,
		IdentityARN:        recommendation.PrincipalARN,
		IdentityName:       recommendation.DisplayName,
		IdentityType:       "iam_role",
		ResourceNodeIDs:    awsRemediationResourceNodes([]string{recommendation.ResourceNodeID}, recommendation.ImpactedNodes, recommendation.IdentityNodeID),
		Owner:              owner,
		OwnerAssigned:      ownerAssigned,
		ApprovalRequired:   approvalRequired,
		ApprovalState:      approvalState,
		DiffIntent:         diff,
		Tradeoffs:          awsRemediationTradeoffsForLeastPrivilege(recommendation),
		RollbackPlan:       awsRemediationRollbackForDiff(diff, evidenceRef),
		VerificationPlan:   awsRemediationVerificationForLeastPrivilege(recommendation, evidenceRef),
		SourceSignals:      []string{"least_privilege"},
		Evidence:           recommendation.Evidence,
		EvidenceBoundary:   awsRemediationCaseEvidenceBoundary(),
		ImpactedNodes:      recommendation.ImpactedNodes,
		ImpactedPath:       recommendation.ImpactedPath,
		NextActions:        awsRemediationNextActionList(recommendation.NextAction, diff),
		CreatedAt:          now,
		UpdatedAt:          now,
	}
	return finalizeAWSRemediationCase(c, now), true
}

func awsRemediationCaseFromSecretEquivalence(finding AWSSecretPermissionEquivalenceFinding, now time.Time) (AWSRemediationCase, bool) {
	if finding.FindingID == "" {
		return AWSRemediationCase{}, false
	}
	caseID := "aws-remediation-case:" + stableAWSBlastRadiusToken("secret-permission-equivalence", finding.FindingID)
	diff := awsRemediationDiffIntentForEquivalence(finding)
	approvalRequired := awsRemediationApprovalRequired(finding.Severity, diff.Kind)
	owner, ownerAssigned := awsRemediationOwnerFromEquivalence(finding)
	approvalState := awsRemediationApprovalState(approvalRequired, ownerAssigned, finding.Status)
	lifecycle := awsRemediationLifecycle(finding.Status, finding.Confidence, ownerAssigned, approvalState, diff)
	c := AWSRemediationCase{
		CaseID:             caseID,
		CalculationVersion: awsRemediationCaseVersion,
		SourceType:         "secret_permission_equivalence",
		SourceFindingID:    finding.FindingID,
		Lifecycle:          lifecycle,
		Severity:           finding.Severity,
		Status:             finding.Status,
		Score:              finding.Score,
		Confidence:         finding.Confidence,
		Title:              fmt.Sprintf("Secret-permission equivalence: %s", firstNonEmptyAWSValue(finding.SecretLabel, finding.SecretARN, finding.Provider)),
		Summary:            finding.Rationale,
		AccountID:          finding.AccountID,
		Region:             finding.Region,
		IdentityNodeID:     finding.IdentityNodeID,
		IdentityARN:        finding.PrincipalARN,
		IdentityName:       firstNonEmptyAWSValue(finding.AgentName, finding.AgentID, shortAWSARN(finding.PrincipalARN)),
		IdentityType:       awsRemediationEquivalenceIdentityType(finding),
		Provider:           finding.Provider,
		ResourceNodeIDs:    awsRemediationResourceNodes([]string{finding.SecretNodeID}, finding.ImpactedNodes, finding.IdentityNodeID),
		Owner:              owner,
		OwnerAssigned:      ownerAssigned,
		ApprovalRequired:   approvalRequired,
		ApprovalState:      approvalState,
		DiffIntent:         diff,
		Tradeoffs:          awsRemediationTradeoffsForEquivalence(finding),
		RollbackPlan:       awsRemediationRollbackForDiff(diff, evidenceRefFromEquivalence(finding)),
		VerificationPlan:   awsRemediationVerificationForEquivalence(finding, evidenceRefFromEquivalence(finding)),
		SourceSignals:      finding.SourceSignals,
		Evidence:           finding.Evidence,
		EvidenceBoundary:   awsRemediationCaseEvidenceBoundary(),
		ImpactedNodes:      finding.ImpactedNodes,
		ImpactedPath:       finding.ImpactedPath,
		NextActions:        awsRemediationNextActionList(finding.NextAction, diff),
		CreatedAt:          now,
		UpdatedAt:          now,
	}
	return finalizeAWSRemediationCase(c, now), true
}

func awsRemediationCaseFromBlastRadius(finding AWSBlastRadiusFinding, now time.Time) (AWSRemediationCase, bool) {
	if finding.FindingID == "" {
		return AWSRemediationCase{}, false
	}
	caseID := "aws-remediation-case:" + stableAWSBlastRadiusToken("blast-radius", finding.FindingID)
	blastEvidence := awsRemediationEvidenceFromBlastRadius(finding.Evidence)
	blastEvidenceRef := firstString(awsRemediationEvidenceRefs(blastEvidence))
	diff := AWSRemediationDiffIntent{
		Kind:               awsRemediationBlastRadiusDiffKind(finding.RiskType),
		BeforeRef:          blastEvidenceRef,
		AfterRef:           "blast-radius://" + finding.FindingID + "/scoped-projection",
		DiffSummary:        fmt.Sprintf("Restrict %s reachability for %s; review %d impacted node(s) and %d agent/tool path(s).", finding.RiskType, firstNonEmptyAWSValue(finding.DisplayName, finding.IdentityNodeID), len(finding.ImpactedNodes), len(finding.AgentToolPaths)),
		NoOp:               false,
		ReadOnlyProjection: true,
	}
	approvalRequired := awsRemediationApprovalRequired(finding.Severity, diff.Kind)
	approvalState := awsRemediationApprovalState(approvalRequired, false, finding.Status)
	lifecycle := awsRemediationLifecycle(finding.Status, finding.Confidence, false, approvalState, diff)
	c := AWSRemediationCase{
		CaseID:             caseID,
		CalculationVersion: awsRemediationCaseVersion,
		SourceType:         "blast_radius",
		SourceFindingID:    finding.FindingID,
		Lifecycle:          lifecycle,
		Severity:           finding.Severity,
		Status:             finding.Status,
		Score:              finding.Score,
		Confidence:         finding.Confidence,
		Title:              fmt.Sprintf("Blast-radius scope review for %s", firstNonEmptyAWSValue(finding.DisplayName, finding.IdentityNodeID)),
		Summary:            finding.Rationale,
		AccountID:          finding.AccountID,
		Region:             finding.Region,
		IdentityNodeID:     finding.IdentityNodeID,
		IdentityARN:        finding.PrincipalARN,
		IdentityName:       finding.DisplayName,
		IdentityType:       "iam_identity",
		ResourceNodeIDs:    awsRemediationResourceNodes(finding.SensitiveNodes, finding.ImpactedNodes, finding.IdentityNodeID),
		ApprovalRequired:   approvalRequired,
		ApprovalState:      approvalState,
		DiffIntent:         diff,
		Tradeoffs:          awsRemediationTradeoffsForBlastRadius(finding),
		RollbackPlan:       awsRemediationRollbackForDiff(diff, blastEvidenceRef),
		VerificationPlan:   awsRemediationVerificationForBlastRadius(blastEvidenceRef),
		SourceSignals:      []string{"blast_radius"},
		Evidence:           blastEvidence,
		EvidenceBoundary:   awsRemediationCaseEvidenceBoundary(),
		ImpactedNodes:      finding.ImpactedNodes,
		ImpactedPath:       awsRemediationPathFromBlastRadius(finding.ImpactedPath),
		NextActions:        awsRemediationNextActionList(finding.NextAction, diff),
		CreatedAt:          now,
		UpdatedAt:          now,
	}
	return finalizeAWSRemediationCase(c, now), true
}

func awsRemediationCaseFromTrustPolicyHardening(plan AWSTrustPolicyHardeningPlan, now time.Time) (AWSRemediationCase, bool) {
	if plan.PlanID == "" {
		return AWSRemediationCase{}, false
	}
	if !awsRemediationTrustPolicyHardeningIsIAMRole(plan) {
		return AWSRemediationCase{}, false
	}
	caseID := "aws-remediation-case:" + stableAWSBlastRadiusToken("trust-policy-hardening", plan.PlanID)
	evidenceRef := firstString(awsRemediationEvidenceRefs(plan.Evidence))
	diff := AWSRemediationDiffIntent{
		Kind:               "iam_trust_diff",
		BeforeRef:          evidenceRef,
		AfterRef:           "trust-policy-hardening://" + plan.PlanID + "/intended-policy",
		DiffSummary:        fmt.Sprintf("Apply trust-policy hardening direction=%s for %s; enforce %d condition recommendation(s) before live execution.", firstNonEmptyAWSValue(plan.HardeningDirection, "manual_review"), firstNonEmptyAWSValue(plan.ResourceLabel, plan.ResourceNodeID, "the IAM role"), len(plan.ConditionRecommendations)),
		ReadOnlyProjection: true,
	}
	owner, ownerAssigned := "iam-platform", true
	approvalRequired := awsRemediationApprovalRequired(plan.Severity, diff.Kind)
	approvalState := awsRemediationApprovalState(approvalRequired, ownerAssigned, plan.Status)
	if plan.ReadyForApply && normalizeAWSRuntimeEventFilterToken(plan.Status) == "action-required" {
		approvalState = "approved"
	}
	lifecycle := awsRemediationLifecycle(plan.Status, plan.Confidence, ownerAssigned, approvalState, diff)
	c := AWSRemediationCase{
		CaseID:             caseID,
		CalculationVersion: awsRemediationCaseVersion,
		SourceType:         "trust_policy_hardening",
		SourceFindingID:    plan.PlanID,
		Lifecycle:          lifecycle,
		Severity:           plan.Severity,
		Status:             plan.Status,
		Score:              plan.Score,
		Confidence:         plan.Confidence,
		Title:              fmt.Sprintf("Trust-policy hardening for %s", firstNonEmptyAWSValue(plan.ResourceLabel, plan.ResourceNodeID, "IAM role")),
		Summary:            plan.Summary,
		AccountID:          plan.AccountID,
		Region:             plan.Region,
		IdentityNodeID:     plan.ResourceNodeID,
		IdentityARN:        plan.ResourceARN,
		IdentityName:       firstNonEmptyAWSValue(plan.ResourceLabel, shortAWSARN(plan.ResourceARN), plan.ResourceNodeID),
		IdentityType:       "iam_role",
		ResourceNodeIDs:    awsRemediationResourceNodes(plan.ResourceNodeID, plan.ImpactedNodes),
		Owner:              owner,
		OwnerAssigned:      ownerAssigned,
		ApprovalRequired:   approvalRequired,
		ApprovalState:      approvalState,
		DiffIntent:         diff,
		Tradeoffs:          awsRemediationTradeoffsForTrustPolicyHardening(plan),
		RollbackPlan:       awsRemediationRollbackFromTrustPolicyHardening(plan, evidenceRef),
		VerificationPlan:   awsRemediationVerificationFromTrustPolicyHardening(plan, evidenceRef),
		SourceSignals:      dedupeStrings(append([]string{"trust_policy_hardening"}, plan.SourceSignals...)),
		Evidence:           plan.Evidence,
		EvidenceBoundary:   awsRemediationCaseEvidenceBoundary(),
		ImpactedNodes:      plan.ImpactedNodes,
		ImpactedPath:       plan.ImpactedPath,
		NextActions:        awsRemediationNextActionList(plan.NextAction, diff),
		CreatedAt:          now,
		UpdatedAt:          now,
	}
	return finalizeAWSRemediationCase(c, now), true
}

func awsRemediationTrustPolicyHardeningIsIAMRole(plan AWSTrustPolicyHardeningPlan) bool {
	if normalizeAWSRuntimeEventFilterToken(plan.ResourceType) == "iam-role" {
		return true
	}
	resourceARN := strings.ToLower(strings.TrimSpace(plan.ResourceARN))
	if strings.Contains(resourceARN, ":role/") {
		return true
	}
	resourceNodeID := strings.ToLower(strings.TrimSpace(plan.ResourceNodeID))
	return strings.Contains(resourceNodeID, ":role/")
}

func finalizeAWSRemediationCase(c AWSRemediationCase, now time.Time) AWSRemediationCase {
	c.SourceSignals = dedupeStrings(c.SourceSignals)
	c.ImpactedNodes = emptyStrings(dedupeStrings(c.ImpactedNodes))
	c.ResourceNodeIDs = emptyStrings(dedupeStrings(c.ResourceNodeIDs))
	c.NextActions = dedupeStrings(c.NextActions)
	if c.Lifecycle == "" {
		c.Lifecycle = "proposed"
	}
	if c.ApprovalState == "" {
		c.ApprovalState = "not_required"
	}
	if strings.TrimSpace(c.DiffIntent.Kind) == "" {
		c.DiffIntent.Kind = "manual_review"
	}
	c.DiffIntent.ReadOnlyProjection = true
	c.AuditTrail = []AWSRemediationAuditEntry{{
		EventID:     c.CaseID + "/proposed",
		Actor:       "system",
		EventType:   "proposed",
		OccurredAt:  now,
		EvidenceRef: firstString(awsRemediationEvidenceRefs(c.Evidence)),
		Notes:       fmt.Sprintf("Deterministic case proposed from %s evidence at lifecycle=%s.", c.SourceType, c.Lifecycle),
	}}
	return c
}

func awsRemediationCaseDedupe(cases []AWSRemediationCase) []AWSRemediationCase {
	seen := map[string]int{}
	out := []AWSRemediationCase{}
	for _, c := range cases {
		key := strings.ToLower(strings.TrimSpace(c.CaseID))
		if key == "" {
			continue
		}
		if idx, ok := seen[key]; ok {
			out[idx] = mergeAWSRemediationCase(out[idx], c)
			continue
		}
		seen[key] = len(out)
		out = append(out, c)
	}
	return out
}

func mergeAWSRemediationCase(existing, incoming AWSRemediationCase) AWSRemediationCase {
	merged := existing
	if incoming.Score > merged.Score {
		merged.Score = incoming.Score
		merged.Severity = incoming.Severity
		merged.Status = incoming.Status
		merged.Lifecycle = incoming.Lifecycle
		merged.Title = incoming.Title
		merged.Summary = incoming.Summary
		merged.DiffIntent = incoming.DiffIntent
	}
	if incoming.Confidence > merged.Confidence {
		merged.Confidence = incoming.Confidence
	}
	merged.SourceSignals = dedupeStrings(append(append([]string{}, merged.SourceSignals...), incoming.SourceSignals...))
	merged.Evidence = append(append([]AWSRemediationCaseEvidence{}, merged.Evidence...), incoming.Evidence...)
	merged.ImpactedNodes = emptyStrings(dedupeStrings(append(merged.ImpactedNodes, incoming.ImpactedNodes...)))
	merged.ResourceNodeIDs = emptyStrings(dedupeStrings(append(merged.ResourceNodeIDs, incoming.ResourceNodeIDs...)))
	merged.NextActions = dedupeStrings(append(merged.NextActions, incoming.NextActions...))
	merged.Tradeoffs = append(merged.Tradeoffs, incoming.Tradeoffs...)
	merged.AuditTrail = append(merged.AuditTrail, incoming.AuditTrail...)
	return merged
}

func awsRemediationDiffIntentForRiskType(riskType string) AWSRemediationDiffIntent {
	switch riskType {
	case "external_credential_exposure":
		return AWSRemediationDiffIntent{Kind: "secret_rotation", DiffSummary: "Rotate or scope the external provider credential and any equivalent secret reference.", ReadOnlyProjection: true}
	case "broad_tool_access", "sensitive_data_reachability", "declared_unused_tool", "undeclared_tool_runtime", "runtime_tool_anomaly":
		return AWSRemediationDiffIntent{Kind: "ai_agent_scope_change", DiffSummary: "Narrow the AI agent's tool, capability, and resource surface before rerunning runtime correlation.", ReadOnlyProjection: true}
	case "ownerless_agent":
		return AWSRemediationDiffIntent{Kind: "owner_assignment", DiffSummary: "Assign an accountable owner tag and re-evaluate the agent inventory.", NoOp: true, ReadOnlyProjection: true}
	case "backing_role_scope", "backing_role_mismatch":
		return AWSRemediationDiffIntent{Kind: "role_scope_diff", DiffSummary: "Scope the agent backing role to observed actions and resources, removing declared-only privileges.", ReadOnlyProjection: true}
	default:
		return AWSRemediationDiffIntent{Kind: "manual_review", DiffSummary: "Manual review: no deterministic diff projected for this risk type.", NoOp: true, ReadOnlyProjection: true}
	}
}

func awsRemediationLeastPrivilegeDiffKind(recommendation AWSLeastPrivilegeRecommendation) string {
	switch recommendation.Decision {
	case "remove":
		return "iam_policy_diff"
	case "review":
		return "manual_review"
	default:
		return "role_scope_diff"
	}
}

func awsRemediationDiffIntentForEquivalence(finding AWSSecretPermissionEquivalenceFinding) AWSRemediationDiffIntent {
	evidenceRef := evidenceRefFromEquivalence(finding)
	normalized := strings.ToLower(strings.TrimSpace(finding.EquivalenceType))
	switch {
	case strings.Contains(normalized, "kms"):
		return AWSRemediationDiffIntent{Kind: "kms_grant_diff", BeforeRef: evidenceRef, AfterRef: "kms://" + finding.SecretNodeID + "/scoped-grants", DiffSummary: "Remove broad KMS decrypt/admin reachability that equates to secret read.", ReadOnlyProjection: true}
	case strings.Contains(normalized, "provider_key"):
		return AWSRemediationDiffIntent{Kind: "secret_rotation", BeforeRef: evidenceRef, AfterRef: "secret://" + finding.SecretNodeID + "/scoped-projection", DiffSummary: "Rotate the provider key reference and scope downstream secret reads.", ReadOnlyProjection: true}
	case strings.Contains(normalized, "admin"):
		return AWSRemediationDiffIntent{Kind: "iam_policy_diff", BeforeRef: evidenceRef, AfterRef: "secret://" + finding.SecretNodeID + "/scoped-admin", DiffSummary: "Remove the admin-equivalent secret-permission path; keep only scoped read for owner-approved callers.", ReadOnlyProjection: true}
	case strings.Contains(normalized, "blast_radius"):
		return AWSRemediationDiffIntent{Kind: "iam_policy_diff", BeforeRef: evidenceRef, AfterRef: "secret://" + finding.SecretNodeID + "/scoped-read", DiffSummary: "Reduce the blast-radius-derived secret reachability to the minimum observed reader set.", ReadOnlyProjection: true}
	case strings.Contains(normalized, "runtime_secret_access"), strings.Contains(normalized, "secret_read_policy"):
		return AWSRemediationDiffIntent{Kind: "iam_policy_diff", BeforeRef: evidenceRef, AfterRef: "secret://" + finding.SecretNodeID + "/scoped-read", DiffSummary: "Scope the identity's secret read permission to observed access and add monitoring.", ReadOnlyProjection: true}
	default:
		return AWSRemediationDiffIntent{Kind: "secret_rotation", BeforeRef: evidenceRef, DiffSummary: "Rotate or scope the equivalent secret-permission path.", ReadOnlyProjection: true}
	}
}

func awsRemediationBlastRadiusDiffKind(riskType string) string {
	normalized := normalizeAWSRuntimeEventFilterToken(riskType)
	if strings.Contains(normalized, "cross-account") {
		return "iam_trust_diff"
	}
	if strings.Contains(normalized, "agent-tool-path") || strings.Contains(normalized, "ai-agent") {
		return "ai_agent_scope_change"
	}
	if strings.Contains(normalized, "kms") {
		return "kms_grant_diff"
	}
	if strings.Contains(normalized, "secret-runtime-access") || strings.Contains(normalized, "s3-runtime-access") || strings.Contains(normalized, "sensitive-resource-reach") {
		return "role_scope_diff"
	}
	return "iam_policy_diff"
}

func awsRemediationApprovalRequired(severity, diffKind string) bool {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical", "high":
		return true
	}
	switch diffKind {
	case "secret_rotation", "iam_trust_diff", "kms_grant_diff":
		return true
	}
	return false
}

func awsRemediationApprovalState(required, ownerAssigned bool, status string) string {
	if !required {
		return "not_required"
	}
	if !ownerAssigned {
		return "pending_owner"
	}
	if normalizeAWSRuntimeEventFilterToken(status) == "action-required" {
		return "pending_approver"
	}
	return "pending_owner_review"
}

func awsRemediationLifecycle(status string, confidence float64, ownerAssigned bool, approvalState string, diff AWSRemediationDiffIntent) string {
	if confidence > 0 && confidence < 0.55 {
		return "proposed"
	}
	executable := awsRemediationDiffIsExecutable(diff)
	switch normalizeAWSRuntimeEventFilterToken(status) {
	case "action-required":
		if !ownerAssigned {
			return "in_review"
		}
		if executable && (approvalState == "pending_approver" || approvalState == "not_required" || approvalState == "approved") {
			return "approved"
		}
		return "in_review"
	case "review":
		return "in_review"
	case "monitor":
		return "proposed"
	}
	return "proposed"
}

func awsRemediationDiffIsExecutable(diff AWSRemediationDiffIntent) bool {
	if diff.NoOp {
		return false
	}
	if diff.Kind == "manual_review" {
		return false
	}
	return true
}

func awsRemediationTitleForRiskType(riskType, agentName, agentID string) string {
	display := firstNonEmptyAWSValue(agentName, agentID, "AI agent")
	switch riskType {
	case "external_credential_exposure":
		return "Rotate external credential for " + display
	case "broad_tool_access":
		return "Narrow tool surface for " + display
	case "sensitive_data_reachability":
		return "Restrict sensitive reachability for " + display
	case "ownerless_agent":
		return "Assign owner for " + display
	case "undeclared_tool_runtime":
		return "Reconcile undeclared runtime tool for " + display
	case "declared_unused_tool":
		return "Retire unused declared tool for " + display
	case "backing_role_mismatch":
		return "Reconcile backing role for " + display
	case "backing_role_scope":
		return "Scope backing role for " + display
	case "runtime_tool_anomaly":
		return "Investigate runtime tool anomaly for " + display
	default:
		return "Review AI agent risk for " + display
	}
}

func awsRemediationOwnerFromAgent(finding AWSAIAgentRiskFinding) (string, bool) {
	if strings.EqualFold(finding.RiskType, "ownerless_agent") {
		return "", false
	}
	for _, evidence := range finding.Evidence {
		if rel := strings.ToLower(evidence.Relationship); rel == "missing_owner" {
			return "", false
		}
	}
	return "ai-platform", true
}

func awsRemediationOwnerFromEquivalence(finding AWSSecretPermissionEquivalenceFinding) (string, bool) {
	if strings.TrimSpace(finding.AgentID) != "" {
		return "ai-platform", true
	}
	return "iam-platform", true
}

func awsRemediationTradeoffsForRiskType(riskType, severity string) []AWSRemediationTradeoff {
	out := []AWSRemediationTradeoff{}
	switch riskType {
	case "external_credential_exposure":
		out = append(out,
			AWSRemediationTradeoff{Dimension: "downstream_blast_radius", Direction: "improves", Description: "Rotating the external key revokes any leaked equivalents and shrinks the agent's external reach.", Severity: severity},
			AWSRemediationTradeoff{Dimension: "rotation_risk", Direction: "worsens", Description: "Active sessions tied to the previous key fail until callers refresh their credentials.", Severity: "medium"},
		)
	case "broad_tool_access", "sensitive_data_reachability", "declared_unused_tool":
		out = append(out,
			AWSRemediationTradeoff{Dimension: "breakage_risk", Direction: "worsens", Description: "Narrowing tool surface may break flows that depend on declared but unobserved capabilities.", Severity: "medium"},
			AWSRemediationTradeoff{Dimension: "downstream_blast_radius", Direction: "improves", Description: "Smaller tool surface reduces lateral reach for compromised agents.", Severity: severity},
		)
	case "ownerless_agent":
		out = append(out, AWSRemediationTradeoff{Dimension: "observability_impact", Direction: "improves", Description: "Adding owner metadata routes future approvals deterministically and unblocks downstream cases.", Severity: severity})
	case "backing_role_mismatch", "backing_role_scope":
		out = append(out,
			AWSRemediationTradeoff{Dimension: "breakage_risk", Direction: "worsens", Description: "Scoping the role to observed actions may block declared paths that have not been exercised yet.", Severity: "medium"},
			AWSRemediationTradeoff{Dimension: "downstream_blast_radius", Direction: "improves", Description: "Removing declared-only privileges shrinks the trust surface of the agent backing role.", Severity: severity},
		)
	case "undeclared_tool_runtime", "runtime_tool_anomaly":
		out = append(out, AWSRemediationTradeoff{Dimension: "observability_impact", Direction: "improves", Description: "Reconciling declared and observed tool usage closes runtime evidence gaps.", Severity: severity})
	}
	return out
}

func awsRemediationTradeoffsForLeastPrivilege(recommendation AWSLeastPrivilegeRecommendation) []AWSRemediationTradeoff {
	out := []AWSRemediationTradeoff{
		{Dimension: "downstream_blast_radius", Direction: "improves", Description: fmt.Sprintf("Removing %d unused action(s) shrinks the identity's effective reach.", len(recommendation.RemoveActions)), Severity: recommendation.Severity},
	}
	if recommendation.BreakagePrediction == "high" || recommendation.BreakagePrediction == "medium" {
		out = append(out, AWSRemediationTradeoff{Dimension: "breakage_risk", Direction: "worsens", Description: recommendation.BreakageRationale, Severity: recommendation.BreakagePrediction})
	} else {
		out = append(out, AWSRemediationTradeoff{Dimension: "breakage_risk", Direction: "neutral", Description: "Removed actions have no observed callers in the runtime evidence window.", Severity: "low"})
	}
	return out
}

func awsRemediationTradeoffsForEquivalence(finding AWSSecretPermissionEquivalenceFinding) []AWSRemediationTradeoff {
	return []AWSRemediationTradeoff{
		{Dimension: "downstream_blast_radius", Direction: "improves", Description: fmt.Sprintf("Scoping %s reachability removes the equivalent secret-read path across %d impacted node(s).", finding.EquivalenceType, len(finding.ImpactedNodes)), Severity: finding.Severity},
		{Dimension: "rotation_risk", Direction: "worsens", Description: "Workloads holding the previous secret reference must refresh before the change is complete.", Severity: "medium"},
	}
}

func awsRemediationTradeoffsForBlastRadius(finding AWSBlastRadiusFinding) []AWSRemediationTradeoff {
	return []AWSRemediationTradeoff{
		{Dimension: "downstream_blast_radius", Direction: "improves", Description: fmt.Sprintf("Restricting %s reduces reachability across %d impacted node(s).", finding.RiskType, len(finding.ImpactedNodes)), Severity: finding.Severity},
		{Dimension: "observability_impact", Direction: "improves", Description: "Narrower blast radius lets downstream remediation cases run with tighter evidence.", Severity: "medium"},
	}
}

func awsRemediationTradeoffsForTrustPolicyHardening(plan AWSTrustPolicyHardeningPlan) []AWSRemediationTradeoff {
	out := []AWSRemediationTradeoff{
		{Dimension: "downstream_blast_radius", Direction: "improves", Description: fmt.Sprintf("Hardening the trust policy reduces cross-account reach across %d impacted node(s).", len(plan.ImpactedNodes)), Severity: plan.Severity},
	}
	if strings.EqualFold(plan.BreakageProjection.Level, "low") {
		out = append(out, AWSRemediationTradeoff{Dimension: "breakage_risk", Direction: "neutral", Description: plan.BreakageProjection.Rationale, Severity: "low"})
	} else {
		out = append(out, AWSRemediationTradeoff{Dimension: "breakage_risk", Direction: "worsens", Description: plan.BreakageProjection.Rationale, Severity: firstNonEmptyAWSValue(plan.BreakageProjection.Level, "medium")})
	}
	return out
}

func awsRemediationRollbackForDiff(diff AWSRemediationDiffIntent, evidenceRef string) AWSRemediationRollbackPlan {
	switch diff.Kind {
	case "iam_policy_diff", "role_scope_diff":
		return AWSRemediationRollbackPlan{Strategy: "re_attach_policy", Steps: []string{"Re-attach the removed managed policy or inline statement.", "Re-run least-privilege evaluation to confirm restored reach."}, EvidenceRef: evidenceRef}
	case "iam_trust_diff":
		return AWSRemediationRollbackPlan{Strategy: "restore_trust_policy", Steps: []string{"Restore the previous trust policy from the captured before_ref.", "Re-run cross-account blast-radius evaluation."}, EvidenceRef: evidenceRef}
	case "secret_rotation":
		return AWSRemediationRollbackPlan{Strategy: "re_create_secret_reference", Steps: []string{"Reissue the prior credential or restore the previous reference if the workload regressed.", "Capture rotation evidence in the case audit trail."}, EvidenceRef: evidenceRef}
	case "kms_grant_diff":
		return AWSRemediationRollbackPlan{Strategy: "restore_grant", Steps: []string{"Restore the previous KMS grant or key policy statement.", "Re-run KMS-decrypt reachability to confirm the rollback."}, EvidenceRef: evidenceRef}
	case "ai_agent_scope_change":
		return AWSRemediationRollbackPlan{Strategy: "re_enable_tool", Steps: []string{"Re-enable the removed tool or capability scope on the AI agent definition.", "Re-run runtime/tool-call correlation."}, EvidenceRef: evidenceRef}
	case "owner_assignment":
		return AWSRemediationRollbackPlan{Strategy: "manual_review", Steps: []string{"Owner assignment is a metadata change; remove the owner tag to revert if assigned in error."}, EvidenceRef: evidenceRef}
	default:
		return AWSRemediationRollbackPlan{Strategy: "manual_review", Steps: []string{"No deterministic rollback projected; document the manual rollback path before execution."}, EvidenceRef: evidenceRef}
	}
}

func awsRemediationVerificationForRiskType(riskType, evidenceRef string) AWSRemediationVerificationPlan {
	switch riskType {
	case "external_credential_exposure":
		return AWSRemediationVerificationPlan{
			Strategy:       "secret_access_re_evaluate",
			Steps:          []string{"Confirm the previous credential is revoked.", "Re-run secret-permission equivalence to confirm the agent path is closed."},
			SuccessSignals: []string{"secret-permission-equivalence:no-equivalence", "agent_runtime_access:no-credential-use"},
			FailureSignals: []string{"secret-permission-equivalence:still-equivalent"},
			EvidenceRef:    evidenceRef,
		}
	case "broad_tool_access", "sensitive_data_reachability", "declared_unused_tool", "undeclared_tool_runtime", "runtime_tool_anomaly":
		return AWSRemediationVerificationPlan{
			Strategy:       "runtime_observe",
			Steps:          []string{"Re-run agent runtime correlation for the next collection window.", "Confirm the targeted tool is no longer observed or matches the new scope."},
			SuccessSignals: []string{"agent_runtime_access:scope-matches-declared"},
			FailureSignals: []string{"agent_runtime_access:undeclared-tool-observed", "agent_runtime_access:declared-unused-tool"},
			EvidenceRef:    evidenceRef,
		}
	case "ownerless_agent":
		return AWSRemediationVerificationPlan{
			Strategy:       "inventory_re_evaluate",
			Steps:          []string{"Re-run agent inventory to confirm owner tag presence."},
			SuccessSignals: []string{"ai_agent_identities:owner-tag-present"},
			FailureSignals: []string{"ai_agent_identities:owner-tag-missing"},
			EvidenceRef:    evidenceRef,
		}
	case "backing_role_mismatch", "backing_role_scope":
		return AWSRemediationVerificationPlan{
			Strategy:       "least_privilege_re_evaluate",
			Steps:          []string{"Re-run least-privilege analysis for the backing role.", "Confirm decision flips from remove/review to keep."},
			SuccessSignals: []string{"least_privilege:decision-keep"},
			FailureSignals: []string{"least_privilege:decision-remove", "least_privilege:decision-review"},
			EvidenceRef:    evidenceRef,
		}
	default:
		return AWSRemediationVerificationPlan{
			Strategy:    "manual_review",
			Steps:       []string{"No deterministic verification projected; document the manual verification before execution."},
			EvidenceRef: evidenceRef,
		}
	}
}

func awsRemediationVerificationForLeastPrivilege(recommendation AWSLeastPrivilegeRecommendation, evidenceRef string) AWSRemediationVerificationPlan {
	if recommendation.Decision != "remove" {
		return AWSRemediationVerificationPlan{
			Strategy:    "manual_review",
			Steps:       []string{"Least-privilege evidence is inconclusive; no projected diff to simulate.", "Re-run least-privilege after upstream evidence settles into a remove/keep decision."},
			EvidenceRef: evidenceRef,
		}
	}
	return AWSRemediationVerificationPlan{
		Strategy:       "policy_simulate",
		Steps:          []string{"Run IAM policy simulator with observed actions to confirm none regress.", "Re-run least-privilege to confirm the recommendation flips to keep."},
		SuccessSignals: []string{"policy_simulate:no-regression", "least_privilege:decision-keep"},
		FailureSignals: []string{"policy_simulate:denied-observed-action"},
		EvidenceRef:    evidenceRef,
	}
}

func awsRemediationVerificationForEquivalence(finding AWSSecretPermissionEquivalenceFinding, evidenceRef string) AWSRemediationVerificationPlan {
	return AWSRemediationVerificationPlan{
		Strategy:       "secret_access_re_evaluate",
		Steps:          []string{"Re-run secret-permission equivalence after the change.", "Confirm runtime evidence no longer reports an equivalent reader."},
		SuccessSignals: []string{"secret-permission-equivalence:no-equivalence"},
		FailureSignals: []string{"secret-permission-equivalence:still-equivalent", "secrets_kms_runtime_access:still-observed"},
		EvidenceRef:    evidenceRef,
	}
}

func awsRemediationVerificationForBlastRadius(evidenceRef string) AWSRemediationVerificationPlan {
	return AWSRemediationVerificationPlan{
		Strategy:       "blast_radius_re_evaluate",
		Steps:          []string{"Re-run blast-radius for the identity after the change.", "Confirm impacted nodes and cross-account edges drop."},
		SuccessSignals: []string{"blast_radius:scope-reduced"},
		FailureSignals: []string{"blast_radius:scope-unchanged"},
		EvidenceRef:    evidenceRef,
	}
}

func awsRemediationRollbackFromTrustPolicyHardening(plan AWSTrustPolicyHardeningPlan, evidenceRef string) AWSRemediationRollbackPlan {
	rollback := plan.RollbackPlan
	if len(rollback.Steps) == 0 {
		return awsRemediationRollbackForDiff(AWSRemediationDiffIntent{Kind: "iam_trust_diff"}, evidenceRef)
	}
	return AWSRemediationRollbackPlan{
		Strategy:    firstNonEmptyAWSValue(rollback.Strategy, "restore_trust_policy"),
		Steps:       rollback.Steps,
		EvidenceRef: firstNonEmptyAWSValue(rollback.EvidenceRef, evidenceRef),
	}
}

func awsRemediationVerificationFromTrustPolicyHardening(plan AWSTrustPolicyHardeningPlan, evidenceRef string) AWSRemediationVerificationPlan {
	verification := plan.VerificationPlan
	if len(verification.Steps) == 0 {
		return AWSRemediationVerificationPlan{
			Strategy:       "trust_policy_re_evaluate",
			Steps:          []string{"Re-run trust-policy hardening after the change.", "Confirm public or unconditioned external trust is no longer present."},
			SuccessSignals: []string{"trust_policy_hardening:scope-reduced"},
			FailureSignals: []string{"trust_policy_hardening:still-exposed"},
			EvidenceRef:    evidenceRef,
		}
	}
	return AWSRemediationVerificationPlan{
		Strategy:       firstNonEmptyAWSValue(verification.Strategy, "trust_policy_re_evaluate"),
		Steps:          verification.Steps,
		SuccessSignals: verification.SuccessSignals,
		FailureSignals: verification.FailureSignals,
		EvidenceRef:    firstNonEmptyAWSValue(verification.EvidenceRef, evidenceRef),
	}
}

func awsRemediationResourceNodes(values ...interface{}) []string {
	out := []string{}
	for _, item := range values {
		switch v := item.(type) {
		case string:
			if strings.TrimSpace(v) != "" {
				out = append(out, v)
			}
		case []string:
			for _, s := range v {
				if strings.TrimSpace(s) != "" {
					out = append(out, s)
				}
			}
		}
	}
	return emptyStrings(dedupeStrings(out))
}

func awsRemediationNextActionList(primary string, diff AWSRemediationDiffIntent) []string {
	out := []string{}
	if trimmed := strings.TrimSpace(primary); trimmed != "" {
		out = append(out, trimmed)
	}
	if trimmed := strings.TrimSpace(diff.DiffSummary); trimmed != "" {
		out = append(out, trimmed)
	}
	if diff.AfterRef != "" {
		out = append(out, "Compare against projected after_ref before approval: "+diff.AfterRef)
	}
	return dedupeStrings(out)
}

func awsRemediationCaseRelationships(cases []AWSRemediationCase) []AWSRemediationRelationship {
	relationships := []AWSRemediationRelationship{}
	for _, c := range cases {
		if c.IdentityNodeID == "" && len(c.ResourceNodeIDs) == 0 {
			continue
		}
		fromNode := firstNonEmptyAWSValue(c.IdentityNodeID, firstString(c.ResourceNodeIDs))
		if fromNode == "" {
			continue
		}
		for _, target := range c.ImpactedNodes {
			if target == "" || target == fromNode {
				continue
			}
			relationships = append(relationships, AWSRemediationRelationship{
				CaseID:      c.CaseID,
				Type:        "remediation_case_path",
				FromNodeID:  fromNode,
				ToNodeID:    target,
				EvidenceRef: firstString(awsRemediationEvidenceRefs(c.Evidence)),
			})
		}
	}
	return relationships
}

func summarizeAWSRemediationCases(all, filtered []AWSRemediationCase, relationships []AWSRemediationRelationship) AWSRemediationCaseSummary {
	summary := AWSRemediationCaseSummary{
		TotalCases:          len(all),
		FilteredCases:       len(filtered),
		SeverityCounts:      map[string]int{},
		StatusCounts:        map[string]int{},
		LifecycleCounts:     map[string]int{},
		SourceTypeCounts:    map[string]int{},
		ApprovalStateCounts: map[string]int{},
		RelationshipCount:   len(relationships),
	}
	confidenceTotal := 0.0
	for _, c := range filtered {
		summary.SeverityCounts[c.Severity]++
		summary.StatusCounts[c.Status]++
		summary.LifecycleCounts[c.Lifecycle]++
		summary.SourceTypeCounts[c.SourceType]++
		summary.ApprovalStateCounts[c.ApprovalState]++
		if c.OwnerAssigned {
			summary.OwnerAssignedCount++
		} else {
			summary.OwnerlessCount++
		}
		if c.ApprovalRequired {
			summary.ApprovalRequiredCount++
		}
		if c.DiffIntent.ReadOnlyProjection {
			summary.ReadOnlyProjectionCount++
		}
		if len(c.RollbackPlan.Steps) > 0 {
			summary.RollbackPlanCount++
		}
		if len(c.VerificationPlan.Steps) > 0 {
			summary.VerificationPlanCount++
		}
		summary.AuditEntryCount += len(c.AuditTrail)
		if c.Score > summary.HighestScore {
			summary.HighestScore = c.Score
		}
		confidenceTotal += c.Confidence
	}
	if len(filtered) > 0 {
		summary.AverageConfidencePct = int((confidenceTotal/float64(len(filtered)))*100 + 0.5)
	}
	return summary
}

func filterAWSRemediationCases(cases []AWSRemediationCase, request AWSRemediationCaseRequest) ([]AWSRemediationCase, map[string]string) {
	filters := map[string]string{
		"account_id":     strings.TrimSpace(request.AccountID),
		"region":         strings.TrimSpace(request.Region),
		"identity":       strings.TrimSpace(request.Identity),
		"source_type":    normalizeAWSRuntimeEventFilterToken(request.SourceType),
		"lifecycle":      normalizeAWSRuntimeEventFilterToken(request.Lifecycle),
		"severity":       normalizeAWSRuntimeEventFilterToken(request.Severity),
		"status":         normalizeAWSRuntimeEventFilterToken(request.Status),
		"approval_state": normalizeAWSRuntimeEventFilterToken(request.ApprovalState),
		"owner_assigned": strings.ToLower(strings.TrimSpace(request.OwnerAssigned)),
		"search":         strings.TrimSpace(request.Search),
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
	filtered := make([]AWSRemediationCase, 0, len(cases))
	for _, c := range cases {
		if filters["account_id"] != "" && filters["account_id"] != c.AccountID {
			continue
		}
		if filters["region"] != "" && !strings.EqualFold(filters["region"], c.Region) {
			continue
		}
		if filters["source_type"] != "" && filters["source_type"] != normalizeAWSRuntimeEventFilterToken(c.SourceType) {
			continue
		}
		if filters["lifecycle"] != "" && filters["lifecycle"] != normalizeAWSRuntimeEventFilterToken(c.Lifecycle) {
			continue
		}
		if filters["severity"] != "" && filters["severity"] != normalizeAWSRuntimeEventFilterToken(c.Severity) {
			continue
		}
		if filters["status"] != "" && filters["status"] != normalizeAWSRuntimeEventFilterToken(c.Status) {
			continue
		}
		if filters["approval_state"] != "" && filters["approval_state"] != normalizeAWSRuntimeEventFilterToken(c.ApprovalState) {
			continue
		}
		if filters["owner_assigned"] != "" {
			want := filters["owner_assigned"]
			if (want == "true" || want == "yes") != c.OwnerAssigned {
				continue
			}
		}
		if filters["identity"] != "" && !awsRemediationCaseIdentityMatch(c, filters["identity"]) {
			continue
		}
		if filters["search"] != "" && !awsRemediationCaseSearchMatch(c, filters["search"]) {
			continue
		}
		filtered = append(filtered, c)
	}
	return filtered, applied
}

func awsRemediationCaseIdentityMatch(c AWSRemediationCase, needle string) bool {
	needle = strings.ToLower(strings.TrimSpace(needle))
	if needle == "" {
		return true
	}
	hay := strings.ToLower(strings.Join([]string{c.IdentityNodeID, c.IdentityARN, c.IdentityName, c.IdentityType, c.Owner}, " "))
	return strings.Contains(hay, needle)
}

func awsRemediationCaseSearchMatch(c AWSRemediationCase, needle string) bool {
	needle = strings.ToLower(strings.TrimSpace(needle))
	if needle == "" {
		return true
	}
	values := []string{c.CaseID, c.Title, c.Summary, c.SourceFindingID, c.SourceType, c.Lifecycle, c.Severity, c.Status, c.ApprovalState, c.IdentityNodeID, c.IdentityARN, c.IdentityName, c.Provider, c.Owner, c.DiffIntent.Kind, c.DiffIntent.DiffSummary, c.DiffIntent.BeforeRef, c.DiffIntent.AfterRef, c.RollbackPlan.Strategy, c.VerificationPlan.Strategy}
	values = append(values, c.ResourceNodeIDs...)
	values = append(values, c.SourceSignals...)
	values = append(values, c.ImpactedNodes...)
	values = append(values, c.NextActions...)
	for _, tradeoff := range c.Tradeoffs {
		values = append(values, tradeoff.Dimension, tradeoff.Direction, tradeoff.Description, tradeoff.Severity)
	}
	for _, evidence := range c.Evidence {
		values = append(values, evidence.Source, evidence.Label, evidence.EvidenceRef, evidence.Relationship)
	}
	for _, audit := range c.AuditTrail {
		values = append(values, audit.EventID, audit.Actor, audit.EventType, audit.Notes, audit.EvidenceRef)
	}
	for _, value := range values {
		if strings.Contains(strings.ToLower(value), needle) {
			return true
		}
	}
	return false
}

func summarizeAWSRemediationCaseStatus(sources awsRemediationCaseSources, filtered []AWSRemediationCase, diagnostics []AWSRemediationCaseDiagnostic) (string, float64) {
	statuses := []string{sources.risk.Status, sources.least.Status, sources.equivalence.Status, sources.blast.Status, sources.trust.Status}
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
			return awsPlatformDependencyStatusDegraded, 0.76
		}
	}
	if len(filtered) == 0 {
		return awsPlatformDependencyStatusReady, 0.82
	}
	return awsPlatformDependencyStatusReady, 0.9
}

func awsRemediationCaseFailureReasons(sources awsRemediationCaseSources) []string {
	out := []string{}
	for _, messages := range [][]string{
		sources.risk.FailureReasons,
		sources.least.FailureReasons,
		sources.equivalence.FailureReasons,
		sources.blast.FailureReasons,
		sources.trust.FailureReasons,
	} {
		out = append(out, messages...)
	}
	return dedupeStrings(out)
}

func awsRemediationCaseRemediationHints(sources awsRemediationCaseSources) []string {
	out := []string{
		"Approve each remediation case before applying its diff: the engine never mutates AWS state itself.",
		"Pair every approved case with its rollback and verification plan before scheduling execution.",
	}
	for _, messages := range [][]string{
		sources.risk.RemediationHints,
		sources.least.RemediationHints,
		sources.equivalence.RemediationHints,
		sources.blast.RemediationHints,
		sources.trust.RemediationHints,
	} {
		out = append(out, messages...)
	}
	return dedupeStrings(out)
}

func awsRemediationCaseCaveats() []string {
	return []string{
		"Remediation cases are read-only projections; the engine never applies an AWS change.",
		"Diff before/after refs point at metadata evidence, never at rendered policy bodies, secret values, or workload payloads.",
		"Lifecycle is derived deterministically from upstream finding status, confidence, and owner metadata; approve/execute transitions belong to a future wave issue.",
	}
}

func awsRemediationCaseDiagnostics(sources awsRemediationCaseSources) []AWSRemediationCaseDiagnostic {
	out := []AWSRemediationCaseDiagnostic{}
	appendDiag := func(collector, sourceID, code, message, remediation string, retryable bool) {
		if strings.TrimSpace(message) == "" && strings.TrimSpace(code) == "" {
			return
		}
		out = append(out, AWSRemediationCaseDiagnostic{Collector: collector, SourceID: sourceID, Code: code, Message: message, Remediation: remediation, Retryable: retryable})
	}
	for _, d := range sources.risk.Diagnostics {
		appendDiag(d.Collector, d.SourceID, d.Code, d.Message, d.Remediation, d.Retryable)
	}
	for _, d := range sources.least.Diagnostics {
		appendDiag(d.Collector, d.SourceID, d.Code, d.Message, d.Remediation, d.Retryable)
	}
	for _, d := range sources.equivalence.Diagnostics {
		appendDiag(d.Collector, d.SourceID, d.Code, d.Message, d.Remediation, d.Retryable)
	}
	for _, d := range sources.blast.Diagnostics {
		appendDiag(d.Collector, d.SourceID, d.Code, d.Message, d.Remediation, d.Retryable)
	}
	for _, d := range sources.trust.Diagnostics {
		appendDiag(d.Collector, d.SourceID, d.Code, d.Message, d.Remediation, d.Retryable)
	}
	return out
}

func awsRemediationCaseCoverageGaps(sources awsRemediationCaseSources) []AWSRemediationCaseCoverageGap {
	out := []AWSRemediationCaseCoverageGap{{
		Capability:  "remediation_execution",
		Status:      "out_of_scope",
		Reason:      "Issue #1529 implements the case model only; approve/execute/verify transitions are future-wave work and never mutate AWS here.",
		Remediation: "Wire the approve/execute/verify endpoints in the relevant remediation/governance issue once the safety gates are in place.",
	}}
	appendGap := func(capability, status, reason, remediation string) {
		out = append(out, AWSRemediationCaseCoverageGap{Capability: capability, Status: status, Reason: reason, Remediation: remediation})
	}
	for _, g := range sources.risk.CoverageGaps {
		appendGap(g.Capability, g.Status, g.Reason, g.Remediation)
	}
	for _, g := range sources.least.CoverageGaps {
		appendGap(g.Capability, g.Status, g.Reason, g.Remediation)
	}
	for _, g := range sources.equivalence.CoverageGaps {
		appendGap(g.Capability, g.Status, g.Reason, g.Remediation)
	}
	for _, g := range sources.blast.CoverageGaps {
		appendGap(g.Capability, g.Status, g.Reason, g.Remediation)
	}
	for _, g := range sources.trust.CoverageGaps {
		appendGap(g.Capability, g.Status, g.Reason, g.Remediation)
	}
	return out
}

func awsRemediationCaseEvidenceBoundary() string {
	return "metadata_only_no_secret_values_no_prompts_no_completions_no_tool_payloads_no_rendered_policy_bodies"
}

func awsRemediationEvidenceRefs(evidence []AWSRemediationCaseEvidence) []string {
	out := []string{}
	for _, item := range evidence {
		if strings.TrimSpace(item.EvidenceRef) != "" {
			out = append(out, item.EvidenceRef)
		}
	}
	return dedupeStrings(out)
}

func evidenceRefFromAIAgentRisk(finding AWSAIAgentRiskFinding) string {
	return firstString(awsRemediationEvidenceRefs(finding.Evidence))
}

func evidenceRefFromEquivalence(finding AWSSecretPermissionEquivalenceFinding) string {
	refs := []string{}
	for _, e := range finding.Evidence {
		if strings.TrimSpace(e.EvidenceRef) != "" {
			refs = append(refs, e.EvidenceRef)
		}
	}
	return firstString(refs)
}

func awsRemediationEvidenceFromBlastRadius(evidence []AWSBlastRadiusEvidence) []AWSRemediationCaseEvidence {
	out := make([]AWSRemediationCaseEvidence, 0, len(evidence))
	for _, item := range evidence {
		out = append(out, AWSRemediationCaseEvidence{
			Source:       item.Source,
			EvidenceRef:  item.EvidenceRef,
			Label:        item.Label,
			Confidence:   item.Confidence,
			ObservedAt:   item.ObservedAt,
			Relationship: item.Relationship,
		})
	}
	return out
}

func awsRemediationPathFromBlastRadius(path []AWSBlastRadiusPathStep) []AWSRemediationCasePathStep {
	out := make([]AWSRemediationCasePathStep, 0, len(path))
	for _, step := range path {
		out = append(out, AWSRemediationCasePathStep{
			NodeID:    step.NodeID,
			NodeType:  step.NodeType,
			Label:     step.Label,
			AccountID: step.AccountID,
			Region:    step.Region,
		})
	}
	return out
}

func awsRemediationEquivalenceIdentityType(finding AWSSecretPermissionEquivalenceFinding) string {
	if strings.TrimSpace(finding.AgentID) != "" {
		return "ai_agent"
	}
	return "iam_identity"
}
