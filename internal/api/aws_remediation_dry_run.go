package api

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	awsRemediationDryRunCurrentIssue = 1537
	awsRemediationDryRunVersion      = "aws-remediation-dry-run-executor-v1"

	awsRemediationDryRunOutcomeWouldSucceed   = "would_succeed"
	awsRemediationDryRunOutcomeWouldFail      = "would_fail"
	awsRemediationDryRunOutcomeRequiresReview = "requires_review"
	awsRemediationDryRunOutcomeBlocked        = "blocked"
	awsRemediationDryRunOutcomeKillSwitched   = "kill_switch_engaged"
)

// AWSRemediationDryRunRequest scopes the deterministic dry-run executor to
// one AWS connector plus optional operator drill-down filters.
type AWSRemediationDryRunRequest struct {
	ConnectorID  string `json:"connector_id,omitempty"`
	FixtureState string `json:"fixture_state,omitempty"`
	AccountID    string `json:"account_id,omitempty"`
	Region       string `json:"region,omitempty"`
	ApprovalID   string `json:"approval_id,omitempty"`
	CaseID       string `json:"case_id,omitempty"`
	SourceType   string `json:"source_type,omitempty"`
	Outcome      string `json:"outcome,omitempty"`
	RiskTier     string `json:"risk_tier,omitempty"`
	Severity     string `json:"severity,omitempty"`
	Search       string `json:"search,omitempty"`
}

// AWSRemediationDryRunIntendedAPICall describes one AWS API call the executor
// would make when run live. The executor never invokes the API; this is a
// metadata-only projection.
type AWSRemediationDryRunIntendedAPICall struct {
	Service          string   `json:"service"`
	Operation        string   `json:"operation"`
	TargetResource   string   `json:"target_resource,omitempty"`
	ParameterRefs    []string `json:"parameter_refs,omitempty"`
	Idempotent       bool     `json:"idempotent"`
	RequiresApproval bool     `json:"requires_approval"`
}

// AWSRemediationDryRunAffectedResource records one resource that would change
// when the executor runs live. Carries metadata refs only.
type AWSRemediationDryRunAffectedResource struct {
	NodeID       string `json:"node_id"`
	ResourceARN  string `json:"resource_arn,omitempty"`
	ResourceType string `json:"resource_type,omitempty"`
	ChangeKind   string `json:"change_kind"`
	BeforeRef    string `json:"before_ref,omitempty"`
	AfterRef     string `json:"after_ref,omitempty"`
}

// AWSRemediationDryRunPrerequisite is one safety prerequisite the executor
// checks deterministically before declaring `would_succeed`.
type AWSRemediationDryRunPrerequisite struct {
	Name      string `json:"name"`
	Status    string `json:"status"`
	Rationale string `json:"rationale"`
}

// AWSRemediationDryRunVerificationCheck is one verification step the executor
// would run after live execution to confirm the change took effect.
type AWSRemediationDryRunVerificationCheck struct {
	Source      string `json:"source"`
	Signal      string `json:"signal"`
	Description string `json:"description"`
}

// AWSRemediationDryRunRelationship surfaces dry-run → graph node edges.
type AWSRemediationDryRunRelationship struct {
	DryRunID    string `json:"dry_run_id"`
	Type        string `json:"type"`
	FromNodeID  string `json:"from_node_id"`
	ToNodeID    string `json:"to_node_id"`
	EvidenceRef string `json:"evidence_ref,omitempty"`
}

// AWSRemediationDryRunEntry is the persisted-record-shaped contract emitted
// by the dry-run executor. It is metadata-only: it carries no rendered policy
// bodies, no secret material, and no workload payloads.
type AWSRemediationDryRunEntry struct {
	DryRunID           string                                  `json:"dry_run_id"`
	CalculationVersion string                                  `json:"calculation_version"`
	ApprovalID         string                                  `json:"approval_id"`
	CaseID             string                                  `json:"case_id"`
	SourceArtifactID   string                                  `json:"source_artifact_id"`
	SourceType         string                                  `json:"source_type"`
	Outcome            string                                  `json:"outcome"`
	RiskTier           string                                  `json:"risk_tier"`
	Severity           string                                  `json:"severity"`
	Score              int                                     `json:"score"`
	Confidence         float64                                 `json:"confidence"`
	Title              string                                  `json:"title"`
	Summary            string                                  `json:"summary"`
	AccountID          string                                  `json:"account_id"`
	Region             string                                  `json:"region"`
	IdempotencyKey     string                                  `json:"idempotency_key"`
	DryRunRef          string                                  `json:"dry_run_ref"`
	DiffIntent         AWSRemediationDiffIntent                `json:"diff_intent"`
	IntendedAPICalls   []AWSRemediationDryRunIntendedAPICall   `json:"intended_api_calls"`
	AffectedResources  []AWSRemediationDryRunAffectedResource  `json:"affected_resources"`
	SatisfiedPrereqs   []AWSRemediationDryRunPrerequisite      `json:"satisfied_prerequisites"`
	FailedPrereqs      []AWSRemediationDryRunPrerequisite      `json:"failed_prerequisites"`
	VerificationChecks []AWSRemediationDryRunVerificationCheck `json:"verification_checks"`
	RollbackPlan       AWSRemediationRollbackPlan              `json:"rollback_plan"`
	VerificationPlan   AWSRemediationVerificationPlan          `json:"verification_plan"`
	Tradeoffs          []AWSRemediationTradeoff                `json:"tradeoffs"`
	AuditTrail         []AWSRemediationApprovalAuditEntry      `json:"audit_trail"`
	KillSwitchEngaged  bool                                    `json:"kill_switch_engaged"`
	ReadyForApply      bool                                    `json:"ready_for_apply"`
	ReadOnlyProjection bool                                    `json:"read_only_projection"`
	SourceSignals      []string                                `json:"source_signals"`
	Evidence           []AWSRemediationApprovalEvidence        `json:"evidence"`
	EvidenceBoundary   string                                  `json:"evidence_boundary"`
	ImpactedNodes      []string                                `json:"impacted_nodes"`
	ImpactedPath       []AWSRemediationApprovalPathStep        `json:"impacted_path"`
	NextAction         string                                  `json:"next_action"`
	SimulatedAt        time.Time                               `json:"simulated_at"`
	CreatedAt          time.Time                               `json:"created_at"`
	UpdatedAt          time.Time                               `json:"updated_at"`
}

// AWSRemediationDryRunSummary aggregates the unfiltered and filtered set.
type AWSRemediationDryRunSummary struct {
	TotalEntries           int            `json:"total_entries"`
	FilteredEntries        int            `json:"filtered_entries"`
	OutcomeCounts          map[string]int `json:"outcome_counts"`
	SourceTypeCounts       map[string]int `json:"source_type_counts"`
	RiskTierCounts         map[string]int `json:"risk_tier_counts"`
	SeverityCounts         map[string]int `json:"severity_counts"`
	APICallCount           int            `json:"api_call_count"`
	AffectedResourceCount  int            `json:"affected_resource_count"`
	FailedPrereqCount      int            `json:"failed_prerequisite_count"`
	VerificationCount      int            `json:"verification_check_count"`
	ReadyForApplyCount     int            `json:"ready_for_apply_count"`
	KillSwitchEngagedCount int            `json:"kill_switch_engaged_count"`
	RelationshipCount      int            `json:"relationship_count"`
	HighestScore           int            `json:"highest_score"`
	AverageConfidencePct   int            `json:"average_confidence_pct"`
}

// AWSRemediationDryRunResult is the deterministic envelope returned by the
// dry-run executor.
type AWSRemediationDryRunResult struct {
	TenantID           string                              `json:"tenant_id"`
	WorkspaceID        string                              `json:"workspace_id"`
	ProjectID          string                              `json:"project_id"`
	ConnectorID        string                              `json:"connector_id,omitempty"`
	AccountID          string                              `json:"account_id,omitempty"`
	Region             string                              `json:"region,omitempty"`
	ParentIssueNumber  int                                 `json:"parent_issue_number"`
	ParentIssueRef     string                              `json:"parent_issue_ref"`
	CurrentIssueNumber int                                 `json:"current_issue_number"`
	CurrentIssueRef    string                              `json:"current_issue_ref"`
	Version            string                              `json:"version"`
	Status             string                              `json:"status"`
	FixtureState       string                              `json:"fixture_state,omitempty"`
	Confidence         float64                             `json:"confidence"`
	CalculationVersion string                              `json:"calculation_version"`
	AppliedFilters     map[string]string                   `json:"applied_filters"`
	Summary            AWSRemediationDryRunSummary         `json:"summary"`
	Entries            []AWSRemediationDryRunEntry         `json:"entries"`
	Relationships      []AWSRemediationDryRunRelationship  `json:"relationships"`
	Caveats            []string                            `json:"caveats"`
	FailureReasons     []string                            `json:"failure_reasons"`
	RemediationHints   []string                            `json:"remediation_hints"`
	EvidenceLinks      []string                            `json:"evidence_links"`
	CoverageGaps       []AWSRemediationApprovalCoverageGap `json:"coverage_gaps"`
	Diagnostics        []AWSRemediationApprovalDiagnostic  `json:"diagnostics"`
	GeneratedAt        time.Time                           `json:"generated_at"`
	UpdatedAt          time.Time                           `json:"updated_at"`
}

// GetAWSRemediationDryRun projects a deterministic, read-only dry-run for
// approved remediation cases. It enforces the same approval/RBAC/feature-flag/
// kill-switch gates as the approval queue and emits a metadata-only simulation
// of the live AWS execution: intended API calls, affected resources, satisfied
// and failed prerequisites, and verification checks. It never calls IAM/STS/
// Organizations write APIs, never reads, exposes, logs, or persists rendered
// policies, secret values, customer payloads, prompts, completions, browser
// pages, code-interpreter output, database rows, or object contents.
func (s *Service) GetAWSRemediationDryRun(ctx context.Context, workspaceID string, projectID string, request AWSRemediationDryRunRequest) (AWSRemediationDryRunResult, error) {
	project, scope, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return AWSRemediationDryRunResult{}, err
	}
	connection, hasConnection, err := s.awsBaselineConnection(ctx, project, strings.TrimSpace(request.ConnectorID))
	if err != nil {
		return AWSRemediationDryRunResult{}, err
	}
	now := s.Now().UTC()
	fixtureState := normalizeAWSRemediationDryRunFixtureState(request.FixtureState, connection, hasConnection)
	if fixtureState == "" {
		return AWSRemediationDryRunResult{}, ErrInvalidAWSConnectionRequest
	}

	accountID := firstNonEmptyAWSValue(connection.AccountID, strings.TrimSpace(request.AccountID), "123456789012")
	region := firstNonEmptyAWSValue(connection.Region, strings.TrimSpace(request.Region), "us-east-1")
	connectorID := firstNonEmptyAWSValue(connection.ConnectorID, strings.TrimSpace(request.ConnectorID))
	sourceFixtureState := fixtureState
	if strings.TrimSpace(request.FixtureState) == "" && hasConnection && connection.Connected {
		sourceFixtureState = ""
	}

	queue, err := s.GetAWSRemediationApprovalQueue(ctx, workspaceID, projectID, AWSRemediationApprovalRequest{ConnectorID: connectorID, FixtureState: sourceFixtureState})
	if err != nil {
		return AWSRemediationDryRunResult{}, fmt.Errorf("remediation dry-run approval queue: %w", err)
	}

	entries := awsRemediationDryRunEntries(queue.Entries, now)
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].Score == entries[j].Score {
			return entries[i].DryRunID < entries[j].DryRunID
		}
		return entries[i].Score > entries[j].Score
	})
	filtered, applied := filterAWSRemediationDryRunEntries(entries, request)
	relationships := awsRemediationDryRunRelationships(filtered)
	diagnostics := awsRemediationDryRunDiagnostics(queue.Diagnostics)
	coverageGaps := awsRemediationDryRunCoverageGaps(queue.CoverageGaps)
	status, confidence := summarizeAWSRemediationDryRunStatus(queue.Status, filtered, diagnostics)

	return AWSRemediationDryRunResult{
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
		FixtureState:       sourceFixtureState,
		Confidence:         confidence,
		CalculationVersion: awsRemediationDryRunVersion,
		AppliedFilters:     applied,
		Summary:            summarizeAWSRemediationDryRunEntries(entries, filtered, relationships),
		Entries:            filtered,
		Relationships:      relationships,
		Caveats:            awsRemediationDryRunCaveats(),
		FailureReasons:     dedupeStrings(queue.FailureReasons),
		RemediationHints:   awsRemediationDryRunRemediationHints(queue.RemediationHints),
		EvidenceLinks: dedupeStrings([]string{
			awsIssueURL(awsPlatformDependencyParentIssue),
			awsIssueURL(awsRemediationDryRunCurrentIssue),
			awsIssueURL(awsRemediationApprovalCurrentIssue),
			"/docs/aws-remediation-dry-run-executor",
			"/docs/aws-remediation-approval-rbac",
			awsBaselineProjectEvidenceURL(scope, project),
		}),
		CoverageGaps: coverageGaps,
		Diagnostics:  diagnostics,
		GeneratedAt:  now,
		UpdatedAt:    now,
	}, nil
}

func normalizeAWSRemediationDryRunFixtureState(requested string, connection AWSConnectionStatus, hasConnection bool) string {
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

func awsRemediationDryRunEntries(approvals []AWSRemediationApprovalEntry, now time.Time) []AWSRemediationDryRunEntry {
	entries := make([]AWSRemediationDryRunEntry, 0, len(approvals))
	for _, approval := range approvals {
		entries = append(entries, awsRemediationDryRunEntryFromApproval(approval, now))
	}
	return entries
}

func awsRemediationDryRunEntryFromApproval(approval AWSRemediationApprovalEntry, now time.Time) AWSRemediationDryRunEntry {
	intended := awsRemediationDryRunIntendedAPICalls(approval)
	resources := awsRemediationDryRunAffectedResources(approval, intended)
	satisfied, failed := awsRemediationDryRunPrerequisites(approval)
	checks := awsRemediationDryRunVerificationChecks(approval)
	outcome := awsRemediationDryRunOutcome(approval, failed)
	dryRunID := "aws-remediation-dry-run:" + stableAWSBlastRadiusToken("dry-run", approval.ApprovalID, outcome)
	entry := AWSRemediationDryRunEntry{
		DryRunID:           dryRunID,
		CalculationVersion: awsRemediationDryRunVersion,
		ApprovalID:         approval.ApprovalID,
		CaseID:             approval.CaseID,
		SourceArtifactID:   approval.SourceArtifactID,
		SourceType:         approval.SourceType,
		Outcome:            outcome,
		RiskTier:           approval.RiskTier,
		Severity:           approval.Severity,
		Score:              approval.Score,
		Confidence:         approval.Confidence,
		Title:              fmt.Sprintf("Dry-run: %s", approval.Title),
		Summary:            fmt.Sprintf("Read-only simulation of remediation case %s. Identrail never calls AWS write APIs; later wave executors apply the change after approval.", approval.CaseID),
		AccountID:          approval.AccountID,
		Region:             approval.Region,
		IdempotencyKey:     approval.IdempotencyKey,
		DryRunRef:          firstNonEmptyAWSValue(approval.DryRunRef, fmt.Sprintf("dry-run://%s/%s/simulated", approval.SourceType, approval.CaseID)),
		DiffIntent:         approval.DiffIntent,
		IntendedAPICalls:   intended,
		AffectedResources:  resources,
		SatisfiedPrereqs:   satisfied,
		FailedPrereqs:      failed,
		VerificationChecks: checks,
		RollbackPlan:       approval.RollbackPlan,
		VerificationPlan:   approval.VerificationPlan,
		Tradeoffs:          approval.Tradeoffs,
		AuditTrail:         awsRemediationDryRunAuditTrail(approval, outcome, now),
		KillSwitchEngaged:  approval.KillSwitchEngaged,
		ReadOnlyProjection: true,
		SourceSignals:      dedupeStrings(append([]string{"remediation_approval"}, approval.SourceSignals...)),
		Evidence:           approval.Evidence,
		EvidenceBoundary:   awsRemediationDryRunEvidenceBoundary(),
		ImpactedNodes:      approval.ImpactedNodes,
		ImpactedPath:       approval.ImpactedPath,
		NextAction:         awsRemediationDryRunNextAction(outcome),
		SimulatedAt:        now,
		CreatedAt:          now,
		UpdatedAt:          now,
	}
	entry.ReadyForApply = outcome == awsRemediationDryRunOutcomeWouldSucceed && approval.ReadyForExecution && !approval.KillSwitchEngaged
	return entry
}

func awsRemediationDryRunIntendedAPICalls(approval AWSRemediationApprovalEntry) []AWSRemediationDryRunIntendedAPICall {
	targets := awsRemediationDryRunTargets(approval)
	if approval.DiffIntent.NoOp {
		return []AWSRemediationDryRunIntendedAPICall{awsRemediationDryRunNoOpCall(targets.identity, approval.IdempotencyKey)}
	}
	caseID := approval.CaseID
	if call, ok := awsRemediationDryRunCallForDiffKind(approval.DiffIntent, targets, approval.IdempotencyKey, caseID); ok {
		return []AWSRemediationDryRunIntendedAPICall{call}
	}
	if call, ok := awsRemediationDryRunCallForSourceType(approval.SourceType, targets, approval.IdempotencyKey, caseID); ok {
		return []AWSRemediationDryRunIntendedAPICall{call}
	}
	return []AWSRemediationDryRunIntendedAPICall{awsRemediationDryRunNoOpCall(targets.identity, approval.IdempotencyKey)}
}

// awsRemediationDryRunTargetSet pairs the identity-first and resource-first
// node IDs for an approval so each routing branch can pick the target that
// matches the AWS API being projected. Identity-mutating calls (PutRolePolicy,
// UpdateAccessKey, …) want the principal node, while resource-mutating calls
// (RotateSecret, PutKeyPolicy) want the secret or KMS key node. `byNodeType`
// is populated from the impacted-path so KMS-grant diffs whose
// `ResourceNodeIDs` lead with the protected secret can still pick the actual
// KMS key node.
type awsRemediationDryRunTargetSet struct {
	identity   string
	resource   string
	byNodeType map[string]string
}

func awsRemediationDryRunTargets(approval AWSRemediationApprovalEntry) awsRemediationDryRunTargetSet {
	identity := firstNonEmptyAWSValue(awsRemediationDryRunFirstNode(approval.Scope.IdentityNodeIDs), awsRemediationDryRunFirstNode(approval.Scope.ResourceNodeIDs), awsRemediationDryRunFirstNode(approval.ImpactedNodes), approval.CaseID)
	resource := firstNonEmptyAWSValue(awsRemediationDryRunFirstNode(approval.Scope.ResourceNodeIDs), awsRemediationDryRunFirstNode(approval.Scope.IdentityNodeIDs), awsRemediationDryRunFirstNode(approval.ImpactedNodes), approval.CaseID)
	byNodeType := map[string]string{}
	for _, step := range approval.ImpactedPath {
		nodeType := strings.ToLower(strings.TrimSpace(step.NodeType))
		nodeID := strings.TrimSpace(step.NodeID)
		if nodeType == "" || nodeID == "" {
			continue
		}
		if _, ok := byNodeType[nodeType]; ok {
			continue
		}
		byNodeType[nodeType] = nodeID
	}
	return awsRemediationDryRunTargetSet{identity: identity, resource: resource, byNodeType: byNodeType}
}

func awsRemediationDryRunFirstNode(nodes []string) string {
	for _, node := range nodes {
		if strings.TrimSpace(node) != "" {
			return node
		}
	}
	return ""
}

// resourceOfType returns the impacted-path node whose type matches one of the
// given hints, falling back to the generic resource target when no typed
// match exists. This lets KMS-grant diffs target the KMS key node when the
// approval scope's first `ResourceNodeIDs` entry is the protected secret.
func (t awsRemediationDryRunTargetSet) resourceOfType(types ...string) string {
	for _, nodeType := range types {
		if node, ok := t.byNodeType[strings.ToLower(strings.TrimSpace(nodeType))]; ok && node != "" {
			return node
		}
	}
	return t.resource
}

// awsRemediationDryRunNoOpCall is the deterministic "no live AWS write is
// planned" projection. NoOp diff intents (manual_review, owner_assignment)
// must surface this directly so the dry-run never advertises a write the
// case engine declined to project.
func awsRemediationDryRunNoOpCall(target, idempotencyKey string) AWSRemediationDryRunIntendedAPICall {
	return AWSRemediationDryRunIntendedAPICall{
		Service:          "manual_review",
		Operation:        "noop",
		TargetResource:   target,
		ParameterRefs:    []string{idempotencyKey},
		Idempotent:       true,
		RequiresApproval: true,
	}
}

// awsRemediationDryRunCallForDiffKind routes to an AWS API call based on the
// case's projected diff intent. Source-type-only routing can mis-pick the API
// for sources whose diff intent varies — for example a
// `secret_permission_equivalence` case with `Kind=secret_rotation` is a
// Secrets Manager rotation, not a KMS key-policy change.
func awsRemediationDryRunCallForDiffKind(diff AWSRemediationDiffIntent, targets awsRemediationDryRunTargetSet, idempotencyKey, caseID string) (AWSRemediationDryRunIntendedAPICall, bool) {
	if diff.NoOp {
		return AWSRemediationDryRunIntendedAPICall{}, false
	}
	switch strings.ToLower(strings.TrimSpace(diff.Kind)) {
	case "iam_policy_diff", "role_scope_diff", "iac_iam_policy_pr":
		return AWSRemediationDryRunIntendedAPICall{
			Service:          "iam",
			Operation:        awsRemediationDryRunPutPolicyOperation(targets.identity),
			TargetResource:   targets.identity,
			ParameterRefs:    []string{idempotencyKey, "policy_document_ref://" + caseID + "/after"},
			Idempotent:       true,
			RequiresApproval: true,
		}, true
	case "iam_trust_diff", "iac_trust_policy_pr":
		return AWSRemediationDryRunIntendedAPICall{
			Service:          "iam",
			Operation:        "UpdateAssumeRolePolicy",
			TargetResource:   targets.identity,
			ParameterRefs:    []string{idempotencyKey, "trust_policy_ref://" + caseID + "/after"},
			Idempotent:       true,
			RequiresApproval: true,
		}, true
	case "kms_grant_diff":
		return AWSRemediationDryRunIntendedAPICall{
			Service:          "kms",
			Operation:        "PutKeyPolicy",
			TargetResource:   targets.resourceOfType("kms_key", "kms"),
			ParameterRefs:    []string{idempotencyKey, "key_policy_ref://" + caseID + "/after"},
			Idempotent:       true,
			RequiresApproval: true,
		}, true
	case "secret_rotation":
		return AWSRemediationDryRunIntendedAPICall{
			Service:          "secretsmanager",
			Operation:        "RotateSecret",
			TargetResource:   targets.resourceOfType("provider_key_reference", "permission_bearing_secret", "secret", "secretsmanager_secret"),
			ParameterRefs:    []string{idempotencyKey, "secret_ref://" + caseID + "/rotate"},
			Idempotent:       true,
			RequiresApproval: true,
		}, true
	case "access_key_quarantine":
		return AWSRemediationDryRunIntendedAPICall{
			Service:          "iam",
			Operation:        "UpdateAccessKey",
			TargetResource:   targets.identity,
			ParameterRefs:    []string{idempotencyKey, "status://inactive"},
			Idempotent:       true,
			RequiresApproval: true,
		}, true
	case "ai_agent_scope_change":
		return AWSRemediationDryRunIntendedAPICall{
			Service:          "bedrock-agent",
			Operation:        "UpdateAgent",
			TargetResource:   targets.identity,
			ParameterRefs:    []string{idempotencyKey, "scope_ref://" + caseID + "/after"},
			Idempotent:       true,
			RequiresApproval: true,
		}, true
	}
	return AWSRemediationDryRunIntendedAPICall{}, false
}

func awsRemediationDryRunCallForSourceType(sourceType string, targets awsRemediationDryRunTargetSet, idempotencyKey, caseID string) (AWSRemediationDryRunIntendedAPICall, bool) {
	switch strings.ToLower(strings.TrimSpace(sourceType)) {
	case "least_privilege", "aws_iac_remediation", "aws_iam_policy_diff":
		return AWSRemediationDryRunIntendedAPICall{
			Service:          "iam",
			Operation:        awsRemediationDryRunPutPolicyOperation(targets.identity),
			TargetResource:   targets.identity,
			ParameterRefs:    []string{idempotencyKey, "policy_document_ref://" + caseID + "/after"},
			Idempotent:       true,
			RequiresApproval: true,
		}, true
	case "trust_policy_hardening":
		return AWSRemediationDryRunIntendedAPICall{
			Service:          "iam",
			Operation:        "UpdateAssumeRolePolicy",
			TargetResource:   targets.identity,
			ParameterRefs:    []string{idempotencyKey, "trust_policy_ref://" + caseID + "/after"},
			Idempotent:       true,
			RequiresApproval: true,
		}, true
	case "aws_permission_boundary_scp":
		return AWSRemediationDryRunIntendedAPICall{
			Service:          "iam",
			Operation:        awsRemediationDryRunPutBoundaryOperation(targets.identity),
			TargetResource:   targets.identity,
			ParameterRefs:    []string{idempotencyKey, "boundary_ref://" + caseID + "/after"},
			Idempotent:       true,
			RequiresApproval: true,
		}, true
	case "aws_secret_key_rotation":
		return AWSRemediationDryRunIntendedAPICall{
			Service:          "secretsmanager",
			Operation:        "RotateSecret",
			TargetResource:   targets.resourceOfType("provider_key_reference", "permission_bearing_secret", "secret", "secretsmanager_secret"),
			ParameterRefs:    []string{idempotencyKey},
			Idempotent:       true,
			RequiresApproval: true,
		}, true
	case "aws_access_key_quarantine":
		return AWSRemediationDryRunIntendedAPICall{
			Service:          "iam",
			Operation:        "UpdateAccessKey",
			TargetResource:   targets.identity,
			ParameterRefs:    []string{idempotencyKey, "status://inactive"},
			Idempotent:       true,
			RequiresApproval: true,
		}, true
	case "secret_permission_equivalence":
		return AWSRemediationDryRunIntendedAPICall{
			Service:          "kms",
			Operation:        "PutKeyPolicy",
			TargetResource:   targets.resourceOfType("kms_key", "kms"),
			ParameterRefs:    []string{idempotencyKey, "key_policy_ref://" + caseID + "/after"},
			Idempotent:       true,
			RequiresApproval: true,
		}, true
	case "ai_agent_risk":
		return AWSRemediationDryRunIntendedAPICall{
			Service:          "bedrock-agent",
			Operation:        "UpdateAgent",
			TargetResource:   targets.identity,
			ParameterRefs:    []string{idempotencyKey, "scope_ref://" + caseID + "/after"},
			Idempotent:       true,
			RequiresApproval: true,
		}, true
	case "blast_radius":
		return AWSRemediationDryRunIntendedAPICall{
			Service:          "iam",
			Operation:        awsRemediationDryRunDetachPolicyOperation(targets.identity),
			TargetResource:   targets.identity,
			ParameterRefs:    []string{idempotencyKey},
			Idempotent:       true,
			RequiresApproval: true,
		}, true
	}
	return AWSRemediationDryRunIntendedAPICall{}, false
}

// awsRemediationDryRunIAMPrincipalKind classifies the target IAM principal as
// role/user/group from its node ID or ARN so the dry-run can route IAM
// inline-policy and permissions-boundary operations correctly. Returns
// "role" when the principal type cannot be determined, which matches the
// most common AWS machine-identity remediation target.
func awsRemediationDryRunIAMPrincipalKind(target string) string {
	normalized := strings.ToLower(strings.TrimSpace(target))
	switch {
	case normalized == "":
		return "role"
	case strings.Contains(normalized, ":user/"), strings.Contains(normalized, ":identity:user/"):
		return "user"
	case strings.Contains(normalized, ":group/"), strings.Contains(normalized, ":identity:group/"):
		return "group"
	default:
		return "role"
	}
}

func awsRemediationDryRunPutPolicyOperation(target string) string {
	switch awsRemediationDryRunIAMPrincipalKind(target) {
	case "user":
		return "PutUserPolicy"
	case "group":
		return "PutGroupPolicy"
	default:
		return "PutRolePolicy"
	}
}

func awsRemediationDryRunPutBoundaryOperation(target string) string {
	if awsRemediationDryRunIAMPrincipalKind(target) == "user" {
		return "PutUserPermissionsBoundary"
	}
	return "PutRolePermissionsBoundary"
}

func awsRemediationDryRunDetachPolicyOperation(target string) string {
	switch awsRemediationDryRunIAMPrincipalKind(target) {
	case "user":
		return "DetachUserPolicy"
	case "group":
		return "DetachGroupPolicy"
	default:
		return "DetachRolePolicy"
	}
}

func awsRemediationDryRunAffectedResources(approval AWSRemediationApprovalEntry, intended []AWSRemediationDryRunIntendedAPICall) []AWSRemediationDryRunAffectedResource {
	resources := []AWSRemediationDryRunAffectedResource{}
	seen := map[string]struct{}{}
	add := func(nodeID, kind string) {
		nodeID = strings.TrimSpace(nodeID)
		if nodeID == "" {
			return
		}
		if _, ok := seen[nodeID]; ok {
			return
		}
		seen[nodeID] = struct{}{}
		resources = append(resources, AWSRemediationDryRunAffectedResource{
			NodeID:     nodeID,
			ChangeKind: kind,
			BeforeRef:  firstNonEmptyAWSValue(approval.DiffIntent.BeforeRef, approval.CaseID),
			AfterRef:   firstNonEmptyAWSValue(approval.DiffIntent.AfterRef, fmt.Sprintf("after://%s", approval.CaseID)),
		})
	}
	// No-op diff intents (manual_review, owner_assignment) project the
	// `manual_review:noop` call and have no AWS write to apply. Mark the
	// scope/impacted nodes as `context` instead of `would_change` so
	// operators and later automation never treat manual-review entries as
	// executable mutations.
	if approval.DiffIntent.NoOp {
		for _, node := range approval.Scope.IdentityNodeIDs {
			add(node, "context")
		}
		for _, node := range approval.Scope.ResourceNodeIDs {
			add(node, "context")
		}
		for _, node := range approval.ImpactedNodes {
			add(node, "context")
		}
		return resources
	}
	for _, call := range intended {
		add(call.TargetResource, "api_target")
	}
	for _, node := range approval.Scope.IdentityNodeIDs {
		add(node, "identity")
	}
	for _, node := range approval.Scope.ResourceNodeIDs {
		add(node, "resource")
	}
	for _, node := range approval.ImpactedNodes {
		add(node, "impacted")
	}
	return resources
}

func awsRemediationDryRunPrerequisites(approval AWSRemediationApprovalEntry) ([]AWSRemediationDryRunPrerequisite, []AWSRemediationDryRunPrerequisite) {
	satisfied := []AWSRemediationDryRunPrerequisite{}
	failed := []AWSRemediationDryRunPrerequisite{}
	add := func(name, status, rationale string) {
		entry := AWSRemediationDryRunPrerequisite{Name: name, Status: status, Rationale: rationale}
		if status == "passed" {
			satisfied = append(satisfied, entry)
			return
		}
		failed = append(failed, entry)
	}
	add("approval_state_approved", awsRemediationDryRunGateStatus(approval.State == awsRemediationApprovalStateApproved), "Approval queue entry must be in state=approved before live execution.")
	add("kill_switch_off", awsRemediationDryRunGateStatus(!approval.KillSwitchEngaged), "Tenant-scoped remediation kill switch must be off.")
	add("ready_for_execution", awsRemediationDryRunGateStatus(approval.ReadyForExecution), "Approval entry must declare ready_for_execution=true.")
	for _, gate := range approval.RBACGates {
		add("rbac:"+gate.Name, awsRemediationDryRunGateStatus(gate.Status == "passed"), gate.Rationale)
	}
	for _, flag := range approval.FeatureFlags {
		if awsRemediationDryRunFeatureFlagMustBeDisabled(flag.Name) {
			add("feature_flag:"+flag.Name, awsRemediationDryRunGateStatus(!flag.Enabled), flag.Rationale)
			continue
		}
		add("feature_flag:"+flag.Name, awsRemediationDryRunGateStatus(flag.Enabled), flag.Rationale)
	}
	return satisfied, failed
}

func awsRemediationDryRunGateStatus(ok bool) string {
	if ok {
		return "passed"
	}
	return "blocked"
}

// awsRemediationDryRunFeatureFlagMustBeDisabled lists the safety flags whose
// disabled state is the healthy default at the dry-run layer. The tenant
// remediation kill switch and the live-AWS-mutation gate are both expected to
// stay off until later wave executors open them; treating them as "passed
// when enabled" would incorrectly mark healthy approvals as blocked.
func awsRemediationDryRunFeatureFlagMustBeDisabled(name string) bool {
	switch name {
	case "live_aws_mutation", "remediation_kill_switch":
		return true
	}
	return false
}

func awsRemediationDryRunVerificationChecks(approval AWSRemediationApprovalEntry) []AWSRemediationDryRunVerificationCheck {
	if approval.DiffIntent.NoOp {
		return []AWSRemediationDryRunVerificationCheck{{
			Source:      "manual_review",
			Signal:      "noop",
			Description: "No live AWS API call is planned for this dry-run; the source case is a manual review or owner-assignment with no deterministic diff to verify.",
		}}
	}
	checks := []AWSRemediationDryRunVerificationCheck{
		{Source: "cloudtrail", Signal: "expected_api_call_observed", Description: "After live execution, confirm the intended API call appears in CloudTrail for the target account and region."},
	}
	if awsRemediationDryRunWantsIAMSimulator(approval) {
		checks = append(checks, AWSRemediationDryRunVerificationCheck{Source: "iam:policy_simulate", Signal: "no_regression", Description: "Re-run the IAM policy simulator after live execution to confirm no regression on kept actions."})
	}
	switch strings.ToLower(strings.TrimSpace(approval.DiffIntent.Kind)) {
	case "secret_rotation":
		checks = append(checks, AWSRemediationDryRunVerificationCheck{Source: "secretsmanager", Signal: "rotation_success", Description: "Confirm the projected secret rotation completed and downstream readers picked up the new credential reference."})
	case "kms_grant_diff":
		checks = append(checks, AWSRemediationDryRunVerificationCheck{Source: "kms", Signal: "grant_policy_applied", Description: "Confirm the projected KMS key-policy change applied and the broad decrypt/admin reachability is gone."})
	case "ai_agent_scope_change":
		checks = append(checks, AWSRemediationDryRunVerificationCheck{Source: "bedrock-agent", Signal: "agent_scope_applied", Description: "Confirm the agent scope change applied and the narrowed tool/capability surface is reflected in runtime evidence."})
	}
	if strings.EqualFold(approval.SourceType, "trust_policy_hardening") || strings.EqualFold(approval.SourceType, "blast_radius") {
		checks = append(checks, AWSRemediationDryRunVerificationCheck{Source: "access_analyzer", Signal: "no_new_external_findings", Description: "Re-run Access Analyzer after live execution to confirm no new external-trust findings."})
	}
	if strings.EqualFold(approval.SourceType, "aws_access_key_quarantine") {
		checks = append(checks, AWSRemediationDryRunVerificationCheck{Source: "iam:last_used", Signal: "no_runtime_after_disable", Description: "Re-check IAM last-used/runtime evidence after disable to confirm no further key activity."})
	}
	return checks
}

// awsRemediationDryRunWantsIAMSimulator returns true when the projected change
// affects an IAM identity/trust policy or boundary, so the IAM policy simulator
// has something to simulate. Non-policy mutations (secret rotation, KMS grant
// policy, agent scope change, access key quarantine) should not advertise an
// IAM simulator check.
func awsRemediationDryRunWantsIAMSimulator(approval AWSRemediationApprovalEntry) bool {
	switch strings.ToLower(strings.TrimSpace(approval.DiffIntent.Kind)) {
	case "iam_policy_diff", "role_scope_diff", "iac_iam_policy_pr",
		"iam_trust_diff", "iac_trust_policy_pr",
		"permission_boundary_diff":
		return true
	case "":
		// Fall through to the source-type gate when the case engine omitted
		// the diff kind.
	default:
		return false
	}
	switch strings.ToLower(strings.TrimSpace(approval.SourceType)) {
	case "least_privilege", "aws_iac_remediation", "aws_iam_policy_diff",
		"trust_policy_hardening", "aws_permission_boundary_scp", "blast_radius":
		return true
	}
	return false
}

func awsRemediationDryRunOutcome(approval AWSRemediationApprovalEntry, failed []AWSRemediationDryRunPrerequisite) string {
	if approval.KillSwitchEngaged {
		return awsRemediationDryRunOutcomeKillSwitched
	}
	if approval.State == awsRemediationApprovalStateBlocked {
		return awsRemediationDryRunOutcomeBlocked
	}
	if approval.State != awsRemediationApprovalStateApproved {
		return awsRemediationDryRunOutcomeRequiresReview
	}
	if len(failed) > 0 {
		return awsRemediationDryRunOutcomeWouldFail
	}
	if !approval.ReadyForExecution {
		return awsRemediationDryRunOutcomeRequiresReview
	}
	return awsRemediationDryRunOutcomeWouldSucceed
}

func awsRemediationDryRunNextAction(outcome string) string {
	switch outcome {
	case awsRemediationDryRunOutcomeWouldSucceed:
		return "Dry-run satisfied; later wave executors may schedule a controlled live apply when their feature flag opens."
	case awsRemediationDryRunOutcomeWouldFail:
		return "Resolve the failed prerequisites listed on this entry before retrying the dry-run."
	case awsRemediationDryRunOutcomeRequiresReview:
		return "Approval queue entry is not yet approved or ready for execution; advance the approval workflow first."
	case awsRemediationDryRunOutcomeBlocked:
		return "Approval queue entry is blocked by an RBAC gate; satisfy the failing gate before retrying."
	case awsRemediationDryRunOutcomeKillSwitched:
		return "Tenant remediation kill switch is engaged; disable it before retrying."
	}
	return "Inspect the dry-run entry for the projected next action."
}

func awsRemediationDryRunAuditTrail(approval AWSRemediationApprovalEntry, outcome string, now time.Time) []AWSRemediationApprovalAuditEntry {
	trail := []AWSRemediationApprovalAuditEntry{}
	trail = append(trail, approval.AuditTrail...)
	trail = append(trail, AWSRemediationApprovalAuditEntry{
		EventID:    stableAWSBlastRadiusToken("dry-run-projected", approval.ApprovalID, outcome),
		Actor:      "identrail-dry-run-executor",
		EventType:  "dry_run_simulated",
		OccurredAt: now,
		Notes:      fmt.Sprintf("Dry-run projected outcome=%s for approval %s.", outcome, approval.ApprovalID),
	})
	return trail
}

func awsRemediationDryRunRelationships(entries []AWSRemediationDryRunEntry) []AWSRemediationDryRunRelationship {
	relationships := []AWSRemediationDryRunRelationship{}
	for _, entry := range entries {
		evidenceRef := firstAWSRemediationCaseEvidenceRef(entry.Evidence)
		for _, resource := range entry.AffectedResources {
			if strings.TrimSpace(resource.NodeID) == "" {
				continue
			}
			relationships = append(relationships, AWSRemediationDryRunRelationship{
				DryRunID:    entry.DryRunID,
				Type:        "dry_run_targets_node",
				FromNodeID:  entry.DryRunID,
				ToNodeID:    resource.NodeID,
				EvidenceRef: evidenceRef,
			})
		}
	}
	return relationships
}

func summarizeAWSRemediationDryRunEntries(all, filtered []AWSRemediationDryRunEntry, relationships []AWSRemediationDryRunRelationship) AWSRemediationDryRunSummary {
	summary := AWSRemediationDryRunSummary{
		TotalEntries:     len(all),
		FilteredEntries:  len(filtered),
		OutcomeCounts:    map[string]int{},
		SourceTypeCounts: map[string]int{},
		RiskTierCounts:   map[string]int{},
		SeverityCounts:   map[string]int{},
	}
	confidenceTotal := 0.0
	for _, entry := range filtered {
		summary.OutcomeCounts[entry.Outcome]++
		if strings.TrimSpace(entry.SourceType) != "" {
			summary.SourceTypeCounts[entry.SourceType]++
		}
		if strings.TrimSpace(entry.RiskTier) != "" {
			summary.RiskTierCounts[entry.RiskTier]++
		}
		if strings.TrimSpace(entry.Severity) != "" {
			summary.SeverityCounts[entry.Severity]++
		}
		summary.APICallCount += len(entry.IntendedAPICalls)
		summary.AffectedResourceCount += len(entry.AffectedResources)
		summary.FailedPrereqCount += len(entry.FailedPrereqs)
		summary.VerificationCount += len(entry.VerificationChecks)
		if entry.ReadyForApply {
			summary.ReadyForApplyCount++
		}
		if entry.KillSwitchEngaged {
			summary.KillSwitchEngagedCount++
		}
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

func filterAWSRemediationDryRunEntries(entries []AWSRemediationDryRunEntry, request AWSRemediationDryRunRequest) ([]AWSRemediationDryRunEntry, map[string]string) {
	filters := map[string]string{
		"account_id":  strings.TrimSpace(request.AccountID),
		"region":      strings.TrimSpace(request.Region),
		"approval_id": strings.TrimSpace(request.ApprovalID),
		"case_id":     strings.TrimSpace(request.CaseID),
		"source_type": normalizeAWSRuntimeEventFilterToken(request.SourceType),
		"outcome":     normalizeAWSRuntimeEventFilterToken(request.Outcome),
		"risk_tier":   normalizeAWSRuntimeEventFilterToken(request.RiskTier),
		"severity":    normalizeAWSRuntimeEventFilterToken(request.Severity),
		"search":      strings.TrimSpace(request.Search),
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
	filtered := make([]AWSRemediationDryRunEntry, 0, len(entries))
	for _, entry := range entries {
		if filters["account_id"] != "" && filters["account_id"] != entry.AccountID {
			continue
		}
		if filters["region"] != "" && !strings.EqualFold(filters["region"], entry.Region) {
			continue
		}
		if filters["approval_id"] != "" && !strings.EqualFold(filters["approval_id"], entry.ApprovalID) {
			continue
		}
		if filters["case_id"] != "" && !strings.EqualFold(filters["case_id"], entry.CaseID) {
			continue
		}
		if filters["source_type"] != "" && filters["source_type"] != normalizeAWSRuntimeEventFilterToken(entry.SourceType) {
			continue
		}
		if filters["outcome"] != "" && filters["outcome"] != normalizeAWSRuntimeEventFilterToken(entry.Outcome) {
			continue
		}
		if filters["risk_tier"] != "" && filters["risk_tier"] != normalizeAWSRuntimeEventFilterToken(entry.RiskTier) {
			continue
		}
		if filters["severity"] != "" && filters["severity"] != normalizeAWSRuntimeEventFilterToken(entry.Severity) {
			continue
		}
		if filters["search"] != "" && !awsRemediationDryRunSearchMatch(entry, filters["search"]) {
			continue
		}
		filtered = append(filtered, entry)
	}
	return filtered, applied
}

func awsRemediationDryRunSearchMatch(entry AWSRemediationDryRunEntry, needle string) bool {
	needle = strings.ToLower(strings.TrimSpace(needle))
	if needle == "" {
		return true
	}
	values := []string{
		entry.DryRunID, entry.ApprovalID, entry.CaseID, entry.SourceArtifactID, entry.SourceType,
		entry.Outcome, entry.RiskTier, entry.Severity, entry.Title, entry.Summary,
		entry.IdempotencyKey, entry.DryRunRef, entry.NextAction,
		entry.DiffIntent.Kind, entry.DiffIntent.DiffSummary,
		entry.RollbackPlan.Strategy, entry.VerificationPlan.Strategy,
	}
	values = append(values, entry.SourceSignals...)
	for _, call := range entry.IntendedAPICalls {
		values = append(values, call.Service, call.Operation, call.TargetResource)
		values = append(values, call.ParameterRefs...)
	}
	for _, resource := range entry.AffectedResources {
		values = append(values, resource.NodeID, resource.ResourceARN, resource.ResourceType, resource.ChangeKind)
	}
	for _, prereq := range entry.SatisfiedPrereqs {
		values = append(values, prereq.Name, prereq.Status, prereq.Rationale)
	}
	for _, prereq := range entry.FailedPrereqs {
		values = append(values, prereq.Name, prereq.Status, prereq.Rationale)
	}
	for _, check := range entry.VerificationChecks {
		values = append(values, check.Source, check.Signal, check.Description)
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

func summarizeAWSRemediationDryRunStatus(sourceStatus string, filtered []AWSRemediationDryRunEntry, diagnostics []AWSRemediationApprovalDiagnostic) (string, float64) {
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

func awsRemediationDryRunCaveats() []string {
	return []string{
		"Dry-run entries are read-only projections; Identrail never calls IAM, STS, Secrets Manager, KMS, or Organizations write APIs at this layer.",
		"Failed prerequisites, RBAC gates, feature flags, and the tenant kill switch are enforced server-side before any entry can declare ready_for_apply.",
		"ready_for_apply is only a planning signal — controlled live execution belongs to wave 8 executors and their own feature flags.",
	}
}

func awsRemediationDryRunRemediationHints(source []string) []string {
	hints := []string{
		"Resolve any failed prerequisites on the dry-run entry before scheduling a live apply.",
		"Re-run the dry-run after lifecycle, approval, or feature-flag changes; the executor is safe to re-query.",
		"Use the idempotency key from the dry-run entry when wiring later wave apply/verify executors so retries do not double-apply.",
	}
	hints = append(hints, source...)
	return dedupeStrings(hints)
}

func awsRemediationDryRunDiagnostics(source []AWSRemediationApprovalDiagnostic) []AWSRemediationApprovalDiagnostic {
	out := make([]AWSRemediationApprovalDiagnostic, 0, len(source))
	for _, diagnostic := range source {
		out = append(out, AWSRemediationApprovalDiagnostic(diagnostic))
	}
	return out
}

func awsRemediationDryRunCoverageGaps(source []AWSRemediationApprovalCoverageGap) []AWSRemediationApprovalCoverageGap {
	gaps := []AWSRemediationApprovalCoverageGap{{
		Capability:  "aws_remediation_live_apply",
		Status:      "out_of_scope",
		Reason:      "Issue #1537 emits dry-run projections only; live IAM/STS/Secrets/KMS/Organizations write APIs are reserved for the wave 8 apply executors (#1538 and later).",
		Remediation: "Wire the controlled live-apply executors in the matching wave 8 issues once their safety gates are in place.",
	}}
	for _, gap := range source {
		gaps = append(gaps, AWSRemediationApprovalCoverageGap(gap))
	}
	return gaps
}

func awsRemediationDryRunEvidenceBoundary() string {
	return "metadata_only_no_rendered_policy_bodies_no_secret_values_no_workload_payloads_tenant_workspace_project_connector_account_region_scoped"
}
