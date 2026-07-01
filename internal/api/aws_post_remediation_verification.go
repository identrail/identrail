package api

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	awsPostRemediationVerificationCurrentIssue = 1542
	awsPostRemediationVerificationVersion      = "aws-post-remediation-verification-v1"

	awsPostRemediationVerificationStatePending  = "verification_pending"
	awsPostRemediationVerificationStateVerified = "verification_verified"
	awsPostRemediationVerificationStateFailed   = "verification_failed"
	awsPostRemediationVerificationStateRollback = "rollback_planned"
	awsPostRemediationVerificationStateSkipped  = "skipped"
	awsPostRemediationVerificationStateBlocked  = "blocked"
	awsPostRemediationVerificationStateNotReady = "not_ready"

	awsPostRemediationVerificationCheckStatusPending = "pending"
	awsPostRemediationVerificationCheckStatusPassed  = "passed"
	awsPostRemediationVerificationCheckStatusFailed  = "failed"
)

// AWSPostRemediationVerificationRequest scopes the deterministic
// post-remediation verification/rollback projection to one AWS connector plus
// optional operator drill-down filters.
type AWSPostRemediationVerificationRequest struct {
	ConnectorID  string `json:"connector_id,omitempty"`
	FixtureState string `json:"fixture_state,omitempty"`
	AccountID    string `json:"account_id,omitempty"`
	Region       string `json:"region,omitempty"`
	SourceType   string `json:"source_type,omitempty"`
	ExecutionID  string `json:"execution_id,omitempty"`
	DryRunID     string `json:"dry_run_id,omitempty"`
	CaseID       string `json:"case_id,omitempty"`
	State        string `json:"state,omitempty"`
	Severity     string `json:"severity,omitempty"`
	Operation    string `json:"operation,omitempty"`
	Search       string `json:"search,omitempty"`
}

type AWSPostRemediationVerificationAuditEntry = AWSRemediationApprovalAuditEntry
type AWSPostRemediationVerificationCoverageGap = AWSRemediationApprovalCoverageGap
type AWSPostRemediationVerificationDiagnostic = AWSRemediationApprovalDiagnostic

// AWSPostRemediationVerificationCheck is one deterministic post-apply signal
// the downstream apply runtime must record. Statuses are `pending` until the
// live executor writes an observed outcome, then `passed`/`failed`.
type AWSPostRemediationVerificationCheck struct {
	Source      string `json:"source"`
	Signal      string `json:"signal"`
	Status      string `json:"status"`
	Description string `json:"description"`
}

// AWSPostRemediationVerificationRollback describes the deterministic rollback
// contract for one upstream execution. The record is metadata-only and never
// carries rendered policy bodies or secret material.
type AWSPostRemediationVerificationRollback struct {
	Strategy       string   `json:"strategy"`
	Steps          []string `json:"steps"`
	SuccessSignals []string `json:"success_signals,omitempty"`
	FailureSignals []string `json:"failure_signals,omitempty"`
	EvidenceRef    string   `json:"evidence_ref,omitempty"`
	State          string   `json:"state"`
	Rationale      string   `json:"rationale"`
}

// AWSPostRemediationVerificationGate documents one precondition the
// verification executor evaluates before advancing state.
type AWSPostRemediationVerificationGate struct {
	Name      string `json:"name"`
	Status    string `json:"status"`
	Rationale string `json:"rationale"`
}

// AWSPostRemediationVerificationRelationship surfaces verification→graph edges
// used by downstream operator UIs and audit consumers.
type AWSPostRemediationVerificationRelationship struct {
	VerificationID string `json:"verification_id"`
	Type           string `json:"type"`
	FromNodeID     string `json:"from_node_id"`
	ToNodeID       string `json:"to_node_id"`
	EvidenceRef    string `json:"evidence_ref,omitempty"`
}

// AWSPostRemediationVerificationEntry is the persisted-record-shaped contract
// emitted per approved upstream executor projection. It records deterministic
// verification checks, rollback metadata, gating preconditions, and immutable
// audit rows without calling any AWS write APIs.
type AWSPostRemediationVerificationEntry struct {
	VerificationID     string                                     `json:"verification_id"`
	CalculationVersion string                                     `json:"calculation_version"`
	SourceType         string                                     `json:"source_type"`
	SourceExecutionID  string                                     `json:"source_execution_id"`
	DryRunID           string                                     `json:"dry_run_id"`
	ApprovalID         string                                     `json:"approval_id"`
	CaseID             string                                     `json:"case_id"`
	PlanID             string                                     `json:"plan_id,omitempty"`
	SourceArtifactID   string                                     `json:"source_artifact_id,omitempty"`
	State              string                                     `json:"state"`
	Severity           string                                     `json:"severity"`
	Score              int                                        `json:"score"`
	Confidence         float64                                    `json:"confidence"`
	Title              string                                     `json:"title"`
	Summary            string                                     `json:"summary"`
	AccountID          string                                     `json:"account_id,omitempty"`
	TargetAccountIDs   []string                                   `json:"target_account_ids,omitempty"`
	Region             string                                     `json:"region,omitempty"`
	Operation          string                                     `json:"operation,omitempty"`
	IdempotencyKey     string                                     `json:"idempotency_key,omitempty"`
	TargetResource     string                                     `json:"target_resource,omitempty"`
	ReadyForLiveApply  bool                                       `json:"ready_for_live_apply"`
	KillSwitchEngaged  bool                                       `json:"kill_switch_engaged"`
	ReadOnlyProjection bool                                       `json:"read_only_projection"`
	Preconditions      []AWSPostRemediationVerificationGate       `json:"preconditions"`
	Checks             []AWSPostRemediationVerificationCheck      `json:"checks"`
	Rollback           AWSPostRemediationVerificationRollback     `json:"rollback"`
	AuditTrail         []AWSPostRemediationVerificationAuditEntry `json:"audit_trail"`
	SourceSignals      []string                                   `json:"source_signals"`
	EvidenceLinks      []string                                   `json:"evidence_links"`
	EvidenceBoundary   string                                     `json:"evidence_boundary"`
	ImpactedNodes      []string                                   `json:"impacted_nodes"`
	NextAction         string                                     `json:"next_action"`
	ProjectedAt        time.Time                                  `json:"projected_at"`
	CreatedAt          time.Time                                  `json:"created_at"`
	UpdatedAt          time.Time                                  `json:"updated_at"`
}

// AWSPostRemediationVerificationSummary aggregates the unfiltered/filtered set.
type AWSPostRemediationVerificationSummary struct {
	TotalEntries            int            `json:"total_entries"`
	FilteredEntries         int            `json:"filtered_entries"`
	StateCounts             map[string]int `json:"state_counts"`
	SourceTypeCounts        map[string]int `json:"source_type_counts"`
	SeverityCounts          map[string]int `json:"severity_counts"`
	VerifiedCount           int            `json:"verified_count"`
	PendingCount            int            `json:"pending_count"`
	FailedCount             int            `json:"failed_count"`
	RollbackPlannedCount    int            `json:"rollback_planned_count"`
	BlockedCount            int            `json:"blocked_count"`
	KillSwitchEngagedCount  int            `json:"kill_switch_engaged_count"`
	FailedPreconditionCount int            `json:"failed_precondition_count"`
	CheckCount              int            `json:"check_count"`
	RelationshipCount       int            `json:"relationship_count"`
	HighestScore            int            `json:"highest_score"`
	AverageConfidencePct    int            `json:"average_confidence_pct"`
}

// AWSPostRemediationVerificationResult is the deterministic endpoint envelope.
type AWSPostRemediationVerificationResult struct {
	TenantID           string                                       `json:"tenant_id"`
	WorkspaceID        string                                       `json:"workspace_id"`
	ProjectID          string                                       `json:"project_id"`
	ConnectorID        string                                       `json:"connector_id,omitempty"`
	AccountID          string                                       `json:"account_id,omitempty"`
	Region             string                                       `json:"region,omitempty"`
	ParentIssueNumber  int                                          `json:"parent_issue_number"`
	ParentIssueRef     string                                       `json:"parent_issue_ref"`
	CurrentIssueNumber int                                          `json:"current_issue_number"`
	CurrentIssueRef    string                                       `json:"current_issue_ref"`
	Version            string                                       `json:"version"`
	Status             string                                       `json:"status"`
	FixtureState       string                                       `json:"fixture_state,omitempty"`
	Confidence         float64                                      `json:"confidence"`
	CalculationVersion string                                       `json:"calculation_version"`
	AppliedFilters     map[string]string                            `json:"applied_filters"`
	Summary            AWSPostRemediationVerificationSummary        `json:"summary"`
	Entries            []AWSPostRemediationVerificationEntry        `json:"entries"`
	Relationships      []AWSPostRemediationVerificationRelationship `json:"relationships"`
	Caveats            []string                                     `json:"caveats"`
	FailureReasons     []string                                     `json:"failure_reasons"`
	RemediationHints   []string                                     `json:"remediation_hints"`
	EvidenceLinks      []string                                     `json:"evidence_links"`
	CoverageGaps       []AWSPostRemediationVerificationCoverageGap  `json:"coverage_gaps"`
	Diagnostics        []AWSPostRemediationVerificationDiagnostic   `json:"diagnostics"`
	GeneratedAt        time.Time                                    `json:"generated_at"`
	UpdatedAt          time.Time                                    `json:"updated_at"`
}

// awsPostRemediationVerificationSource is the deterministic in-memory shape
// each upstream executor is projected into before the verification/rollback
// record is built. Every upstream executor contributes one record per approved
// entry; unsupported sources are not projected.
type awsPostRemediationVerificationSource struct {
	SourceType        string
	SourceExecutionID string
	DryRunID          string
	ApprovalID        string
	CaseID            string
	PlanID            string
	SourceArtifactID  string
	UpstreamState     string
	Severity          string
	Score             int
	Confidence        float64
	Title             string
	AccountID         string
	TargetAccountIDs  []string
	Region            string
	Operation         string
	IdempotencyKey    string
	TargetResource    string
	ReadyForLiveApply bool
	KillSwitchEngaged bool
	SourceSignals     []string
	ImpactedNodes     []string
	AuditTrail        []AWSPostRemediationVerificationAuditEntry
	RollbackStrategy  string
	RollbackSteps     []string
	RollbackEvidence  string
	SuccessSignals    []string
	FailureSignals    []string
	VerificationSteps []string
	FailedPreconds    int
	CreatedAt         time.Time
}

// GetAWSPostRemediationVerification projects deterministic post-remediation
// verification and rollback records from every approved wave-8 executor
// (low-risk live remediation #1538, trust-policy hardening executor #1539,
// permission boundary executor #1540, SCP guardrail executor #1541). The
// endpoint is metadata-only: it never calls IAM, STS, or Organizations write
// APIs and never reads or persists rendered policy bodies, secret values, or
// workload payloads.
func (s *Service) GetAWSPostRemediationVerification(ctx context.Context, workspaceID string, projectID string, request AWSPostRemediationVerificationRequest) (AWSPostRemediationVerificationResult, error) {
	project, scope, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return AWSPostRemediationVerificationResult{}, err
	}
	connection, hasConnection, err := s.awsBaselineConnection(ctx, project, strings.TrimSpace(request.ConnectorID))
	if err != nil {
		return AWSPostRemediationVerificationResult{}, err
	}
	now := s.Now().UTC()
	fixtureState := normalizeAWSPostRemediationVerificationFixtureState(request.FixtureState, connection, hasConnection)
	if fixtureState == "" {
		return AWSPostRemediationVerificationResult{}, ErrInvalidAWSConnectionRequest
	}

	accountID := firstNonEmptyAWSValue(connection.AccountID, strings.TrimSpace(request.AccountID), "123456789012")
	region := firstNonEmptyAWSValue(connection.Region, strings.TrimSpace(request.Region), "us-east-1")
	connectorID := firstNonEmptyAWSValue(connection.ConnectorID, strings.TrimSpace(request.ConnectorID))
	sourceFixtureState := fixtureState
	if strings.TrimSpace(request.FixtureState) == "" && hasConnection && connection.Connected {
		sourceFixtureState = ""
	}

	sources, upstreamStatus, failureReasons, remediationHints, coverageGaps, diagnostics, err := s.awsPostRemediationVerificationSources(ctx, workspaceID, projectID, connectorID, sourceFixtureState)
	if err != nil {
		return AWSPostRemediationVerificationResult{}, err
	}

	entries := awsPostRemediationVerificationEntries(sources, now)
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].Score == entries[j].Score {
			return entries[i].VerificationID < entries[j].VerificationID
		}
		return entries[i].Score > entries[j].Score
	})
	filtered, applied := filterAWSPostRemediationVerificationEntries(entries, request)
	relationships := awsPostRemediationVerificationRelationships(filtered)
	status, confidence := summarizeAWSPostRemediationVerificationStatus(upstreamStatus, filtered, diagnostics)

	return AWSPostRemediationVerificationResult{
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
		FixtureState:       sourceFixtureState,
		Confidence:         confidence,
		CalculationVersion: awsPostRemediationVerificationVersion,
		AppliedFilters:     applied,
		Summary:            summarizeAWSPostRemediationVerificationEntries(entries, filtered, relationships),
		Entries:            filtered,
		Relationships:      relationships,
		Caveats:            awsPostRemediationVerificationCaveats(),
		FailureReasons:     dedupeStrings(failureReasons),
		RemediationHints:   awsPostRemediationVerificationRemediationHints(remediationHints),
		EvidenceLinks: dedupeStrings([]string{
			awsIssueURL(awsPlatformDependencyParentIssue),
			awsIssueURL(awsPostRemediationVerificationCurrentIssue),
			awsIssueURL(awsLowRiskRemediationCurrentIssue),
			awsIssueURL(awsTrustPolicyHardeningExecutorCurrentIssue),
			awsIssueURL(awsPermissionBoundaryExecutorCurrentIssue),
			awsIssueURL(awsScpGuardrailExecutorCurrentIssue),
			"/docs/aws-post-remediation-verification",
			"/docs/aws-remediation-dry-run-executor",
			awsBaselineProjectEvidenceURL(scope, project),
		}),
		CoverageGaps: coverageGaps,
		Diagnostics:  diagnostics,
		GeneratedAt:  now,
		UpdatedAt:    now,
	}, nil
}

func normalizeAWSPostRemediationVerificationFixtureState(requested string, connection AWSConnectionStatus, hasConnection bool) string {
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

// awsPostRemediationVerificationSources fans out to each upstream wave-8
// executor and normalizes its projected entries into a single source shape.
// Upstream status/failure/coverage/diagnostic signals are merged so this
// endpoint stays deterministic when any upstream degrades.
func (s *Service) awsPostRemediationVerificationSources(ctx context.Context, workspaceID, projectID, connectorID, fixtureState string) ([]awsPostRemediationVerificationSource, string, []string, []string, []AWSPostRemediationVerificationCoverageGap, []AWSPostRemediationVerificationDiagnostic, error) {
	sources := []awsPostRemediationVerificationSource{}
	failureReasons := []string{}
	remediationHints := []string{}
	coverageGaps := []AWSPostRemediationVerificationCoverageGap{}
	diagnostics := []AWSPostRemediationVerificationDiagnostic{}
	upstreamStatuses := []string{}

	lowRisk, err := s.GetAWSLowRiskRemediation(ctx, workspaceID, projectID, AWSLowRiskRemediationRequest{ConnectorID: connectorID, FixtureState: fixtureState})
	if err != nil {
		return nil, "", nil, nil, nil, nil, fmt.Errorf("post-remediation verification low-risk source: %w", err)
	}
	upstreamStatuses = append(upstreamStatuses, lowRisk.Status)
	failureReasons = append(failureReasons, lowRisk.FailureReasons...)
	remediationHints = append(remediationHints, lowRisk.RemediationHints...)
	for _, gap := range lowRisk.CoverageGaps {
		coverageGaps = append(coverageGaps, AWSPostRemediationVerificationCoverageGap(gap))
	}
	for _, diag := range lowRisk.Diagnostics {
		diagnostics = append(diagnostics, AWSPostRemediationVerificationDiagnostic(diag))
	}
	for _, entry := range lowRisk.Entries {
		sources = append(sources, awsPostRemediationVerificationFromLowRisk(entry))
	}

	trust, err := s.GetAWSTrustPolicyHardeningExecutor(ctx, workspaceID, projectID, AWSTrustPolicyHardeningExecutorRequest{ConnectorID: connectorID, FixtureState: fixtureState})
	if err != nil {
		return nil, "", nil, nil, nil, nil, fmt.Errorf("post-remediation verification trust source: %w", err)
	}
	upstreamStatuses = append(upstreamStatuses, trust.Status)
	failureReasons = append(failureReasons, trust.FailureReasons...)
	remediationHints = append(remediationHints, trust.RemediationHints...)
	for _, gap := range trust.CoverageGaps {
		coverageGaps = append(coverageGaps, AWSPostRemediationVerificationCoverageGap{Capability: gap.Capability, Status: gap.Status, Reason: gap.Reason, Remediation: gap.Remediation})
	}
	for _, diag := range trust.Diagnostics {
		diagnostics = append(diagnostics, AWSPostRemediationVerificationDiagnostic{Collector: diag.Collector, SourceID: diag.SourceID, Code: diag.Code, Message: diag.Message, Remediation: diag.Remediation, Retryable: diag.Retryable})
	}
	for _, entry := range trust.Entries {
		sources = append(sources, awsPostRemediationVerificationFromTrust(entry))
	}

	boundary, err := s.GetAWSPermissionBoundaryExecutor(ctx, workspaceID, projectID, AWSPermissionBoundaryExecutorRequest{ConnectorID: connectorID, FixtureState: fixtureState})
	if err != nil {
		return nil, "", nil, nil, nil, nil, fmt.Errorf("post-remediation verification boundary source: %w", err)
	}
	upstreamStatuses = append(upstreamStatuses, boundary.Status)
	failureReasons = append(failureReasons, boundary.FailureReasons...)
	remediationHints = append(remediationHints, boundary.RemediationHints...)
	for _, gap := range boundary.CoverageGaps {
		coverageGaps = append(coverageGaps, AWSPostRemediationVerificationCoverageGap{Capability: gap.Capability, Status: gap.Status, Reason: gap.Reason, Remediation: gap.Remediation})
	}
	for _, diag := range boundary.Diagnostics {
		diagnostics = append(diagnostics, AWSPostRemediationVerificationDiagnostic{Collector: diag.Collector, SourceID: diag.SourceID, Code: diag.Code, Message: diag.Message, Remediation: diag.Remediation, Retryable: diag.Retryable})
	}
	for _, entry := range boundary.Entries {
		sources = append(sources, awsPostRemediationVerificationFromBoundary(entry))
	}

	scp, err := s.GetAWSScpGuardrailExecutor(ctx, workspaceID, projectID, AWSScpGuardrailExecutorRequest{ConnectorID: connectorID, FixtureState: fixtureState})
	if err != nil {
		return nil, "", nil, nil, nil, nil, fmt.Errorf("post-remediation verification scp source: %w", err)
	}
	upstreamStatuses = append(upstreamStatuses, scp.Status)
	failureReasons = append(failureReasons, scp.FailureReasons...)
	remediationHints = append(remediationHints, scp.RemediationHints...)
	for _, gap := range scp.CoverageGaps {
		coverageGaps = append(coverageGaps, AWSPostRemediationVerificationCoverageGap{Capability: gap.Capability, Status: gap.Status, Reason: gap.Reason, Remediation: gap.Remediation})
	}
	for _, diag := range scp.Diagnostics {
		diagnostics = append(diagnostics, AWSPostRemediationVerificationDiagnostic{Collector: diag.Collector, SourceID: diag.SourceID, Code: diag.Code, Message: diag.Message, Remediation: diag.Remediation, Retryable: diag.Retryable})
	}
	for _, entry := range scp.Entries {
		sources = append(sources, awsPostRemediationVerificationFromScp(entry))
	}

	return sources, mergeAWSPostRemediationVerificationStatuses(upstreamStatuses), failureReasons, remediationHints, coverageGaps, diagnostics, nil
}

func mergeAWSPostRemediationVerificationStatuses(statuses []string) string {
	worst := awsPlatformDependencyStatusReady
	for _, status := range statuses {
		switch status {
		case awsPlatformDependencyStatusBlocked:
			return awsPlatformDependencyStatusBlocked
		case awsPlatformDependencyStatusDegraded:
			worst = awsPlatformDependencyStatusDegraded
		}
	}
	return worst
}

func awsPostRemediationVerificationFromLowRisk(entry AWSLowRiskRemediationEntry) awsPostRemediationVerificationSource {
	failed := 0
	for _, preflight := range entry.Preflights {
		if preflight.Status == "blocked" {
			failed++
		}
	}
	return awsPostRemediationVerificationSource{
		SourceType:        "aws_low_risk_live_remediation",
		SourceExecutionID: entry.ExecutionID,
		DryRunID:          entry.DryRunID,
		ApprovalID:        entry.ApprovalID,
		CaseID:            entry.CaseID,
		SourceArtifactID:  entry.SourceArtifactID,
		UpstreamState:     entry.State,
		Severity:          entry.Severity,
		Score:             entry.Score,
		Confidence:        entry.Confidence,
		Title:             entry.Title,
		AccountID:         entry.AccountID,
		Region:            entry.Region,
		Operation:         entry.Mutation.Operation,
		IdempotencyKey:    entry.IdempotencyKey,
		TargetResource:    entry.Mutation.TargetResource,
		ReadyForLiveApply: entry.ReadyForLiveApply,
		KillSwitchEngaged: entry.KillSwitchEngaged,
		SourceSignals:     entry.SourceSignals,
		ImpactedNodes:     entry.ImpactedNodes,
		AuditTrail:        entry.AuditTrail,
		RollbackStrategy:  entry.RollbackPlan.Strategy,
		RollbackSteps:     entry.RollbackPlan.Steps,
		RollbackEvidence:  entry.RollbackPlan.EvidenceRef,
		SuccessSignals:    entry.VerificationPlan.SuccessSignals,
		FailureSignals:    entry.VerificationPlan.FailureSignals,
		VerificationSteps: entry.VerificationPlan.Steps,
		FailedPreconds:    failed,
		CreatedAt:         entry.CreatedAt,
	}
}

func awsPostRemediationVerificationFromTrust(entry AWSTrustPolicyHardeningExecutorEntry) awsPostRemediationVerificationSource {
	failed := 0
	for _, gate := range entry.Preconditions {
		if gate.Status == "blocked" {
			failed++
		}
	}
	return awsPostRemediationVerificationSource{
		SourceType:        "aws_trust_policy_hardening",
		SourceExecutionID: entry.ExecutionID,
		DryRunID:          entry.DryRunID,
		ApprovalID:        entry.ApprovalID,
		CaseID:            entry.CaseID,
		PlanID:            entry.PlanID,
		SourceArtifactID:  entry.SourceArtifactID,
		UpstreamState:     entry.State,
		Severity:          entry.Severity,
		Score:             entry.Score,
		Confidence:        entry.Confidence,
		Title:             entry.Title,
		AccountID:         entry.AccountID,
		Region:            entry.Region,
		Operation:         entry.IntendedAPICall.Operation,
		IdempotencyKey:    entry.IdempotencyKey,
		TargetResource:    entry.IntendedAPICall.TargetResource,
		ReadyForLiveApply: entry.ReadyForLiveApply,
		KillSwitchEngaged: entry.KillSwitchEngaged,
		SourceSignals:     entry.SourceSignals,
		ImpactedNodes:     entry.ImpactedNodes,
		AuditTrail:        entry.AuditTrail,
		RollbackStrategy:  entry.RollbackPlan.Strategy,
		RollbackSteps:     entry.RollbackPlan.Steps,
		RollbackEvidence:  entry.RollbackPlan.EvidenceRef,
		SuccessSignals:    entry.VerificationPlan.SuccessSignals,
		FailureSignals:    entry.VerificationPlan.FailureSignals,
		VerificationSteps: entry.VerificationPlan.Steps,
		FailedPreconds:    failed,
		CreatedAt:         entry.CreatedAt,
	}
}

func awsPostRemediationVerificationFromBoundary(entry AWSPermissionBoundaryExecutorEntry) awsPostRemediationVerificationSource {
	failed := 0
	for _, gate := range entry.Preconditions {
		if gate.Status == "blocked" {
			failed++
		}
	}
	return awsPostRemediationVerificationSource{
		SourceType:        "aws_permission_boundary_executor",
		SourceExecutionID: entry.ExecutionID,
		DryRunID:          entry.DryRunID,
		ApprovalID:        entry.ApprovalID,
		CaseID:            entry.CaseID,
		PlanID:            entry.PlanID,
		SourceArtifactID:  entry.SourceArtifactID,
		UpstreamState:     entry.State,
		Severity:          entry.Severity,
		Score:             entry.Score,
		Confidence:        entry.Confidence,
		Title:             entry.Title,
		AccountID:         entry.AccountID,
		TargetAccountIDs:  entry.TargetAccountIDs,
		Region:            entry.Region,
		Operation:         entry.Operation,
		IdempotencyKey:    entry.IdempotencyKey,
		TargetResource:    entry.IntendedAPICall.TargetResource,
		ReadyForLiveApply: entry.ReadyForLiveApply,
		KillSwitchEngaged: entry.KillSwitchEngaged,
		SourceSignals:     entry.SourceSignals,
		ImpactedNodes:     entry.ImpactedNodes,
		AuditTrail:        entry.AuditTrail,
		RollbackStrategy:  entry.RollbackPlan.Strategy,
		RollbackSteps:     entry.RollbackPlan.Steps,
		RollbackEvidence:  entry.RollbackPlan.EvidenceRef,
		SuccessSignals:    entry.VerificationPlan.SuccessSignals,
		FailureSignals:    entry.VerificationPlan.FailureSignals,
		VerificationSteps: entry.VerificationPlan.Steps,
		FailedPreconds:    failed,
		CreatedAt:         entry.CreatedAt,
	}
}

func awsPostRemediationVerificationFromScp(entry AWSScpGuardrailExecutorEntry) awsPostRemediationVerificationSource {
	failed := 0
	for _, gate := range entry.Preconditions {
		if gate.Status == "blocked" {
			failed++
		}
	}
	return awsPostRemediationVerificationSource{
		SourceType:        "aws_scp_guardrail_executor",
		SourceExecutionID: entry.ExecutionID,
		DryRunID:          entry.DryRunID,
		ApprovalID:        entry.ApprovalID,
		CaseID:            entry.CaseID,
		PlanID:            entry.PlanID,
		SourceArtifactID:  entry.SourceArtifactID,
		UpstreamState:     entry.State,
		Severity:          entry.Severity,
		Score:             entry.Score,
		Confidence:        entry.Confidence,
		Title:             entry.Title,
		AccountID:         entry.AccountID,
		TargetAccountIDs:  entry.TargetAccountIDs,
		Region:            entry.Region,
		Operation:         entry.Operation,
		IdempotencyKey:    entry.IdempotencyKey,
		TargetResource:    entry.IntendedAPICall.TargetResource,
		ReadyForLiveApply: entry.ReadyForLiveApply,
		KillSwitchEngaged: entry.KillSwitchEngaged,
		SourceSignals:     entry.SourceSignals,
		ImpactedNodes:     entry.ImpactedNodes,
		AuditTrail:        entry.AuditTrail,
		RollbackStrategy:  entry.RollbackPlan.Strategy,
		RollbackSteps:     entry.RollbackPlan.Steps,
		RollbackEvidence:  entry.RollbackPlan.EvidenceRef,
		SuccessSignals:    entry.VerificationPlan.SuccessSignals,
		FailureSignals:    entry.VerificationPlan.FailureSignals,
		VerificationSteps: entry.VerificationPlan.Steps,
		FailedPreconds:    failed,
		CreatedAt:         entry.CreatedAt,
	}
}

func awsPostRemediationVerificationEntries(sources []awsPostRemediationVerificationSource, now time.Time) []AWSPostRemediationVerificationEntry {
	entries := make([]AWSPostRemediationVerificationEntry, 0, len(sources))
	for _, source := range sources {
		entries = append(entries, awsPostRemediationVerificationEntryFromSource(source, now))
	}
	return entries
}

func awsPostRemediationVerificationEntryFromSource(source awsPostRemediationVerificationSource, now time.Time) AWSPostRemediationVerificationEntry {
	preconditions := awsPostRemediationVerificationPreconditions(source)
	checks := awsPostRemediationVerificationChecks(source)
	rollback := awsPostRemediationVerificationRollbackRecord(source)
	state := awsPostRemediationVerificationState(source, preconditions)
	verificationID := "aws-post-remediation-verification:" + stableAWSBlastRadiusToken("verification", source.SourceType, source.SourceExecutionID)
	return AWSPostRemediationVerificationEntry{
		VerificationID:     verificationID,
		CalculationVersion: awsPostRemediationVerificationVersion,
		SourceType:         source.SourceType,
		SourceExecutionID:  source.SourceExecutionID,
		DryRunID:           source.DryRunID,
		ApprovalID:         source.ApprovalID,
		CaseID:             source.CaseID,
		PlanID:             source.PlanID,
		SourceArtifactID:   source.SourceArtifactID,
		State:              state,
		Severity:           source.Severity,
		Score:              source.Score,
		Confidence:         source.Confidence,
		Title:              fmt.Sprintf("Post-remediation verification: %s", firstNonEmptyAWSValue(source.Title, source.SourceExecutionID)),
		Summary:            awsPostRemediationVerificationSummaryText(source, state),
		AccountID:          source.AccountID,
		TargetAccountIDs:   emptyStrings(dedupeStrings(source.TargetAccountIDs)),
		Region:             source.Region,
		Operation:          source.Operation,
		IdempotencyKey:     source.IdempotencyKey,
		TargetResource:     source.TargetResource,
		ReadyForLiveApply:  source.ReadyForLiveApply,
		KillSwitchEngaged:  source.KillSwitchEngaged,
		ReadOnlyProjection: true,
		Preconditions:      preconditions,
		Checks:             checks,
		Rollback:           rollback,
		AuditTrail:         awsPostRemediationVerificationAuditTrail(source, state, now),
		SourceSignals:      dedupeStrings(append([]string{source.SourceType, "post_remediation_verification"}, source.SourceSignals...)),
		EvidenceLinks:      awsPostRemediationVerificationEvidenceLinks(source),
		EvidenceBoundary:   awsPostRemediationVerificationEvidenceBoundary(),
		ImpactedNodes:      emptyStrings(dedupeStrings(source.ImpactedNodes)),
		NextAction:         awsPostRemediationVerificationNextAction(state),
		ProjectedAt:        now,
		CreatedAt:          firstNonZeroAWSPostRemediationVerificationTime(source.CreatedAt, now),
		UpdatedAt:          now,
	}
}

func awsPostRemediationVerificationPreconditions(source awsPostRemediationVerificationSource) []AWSPostRemediationVerificationGate {
	gates := []AWSPostRemediationVerificationGate{
		{Name: "upstream_executor_projected", Status: awsPostRemediationVerificationGateStatus(source.UpstreamState == "projected"), Rationale: "Upstream executor must project the record before a verification/rollback contract is generated."},
		{Name: "kill_switch_off", Status: awsPostRemediationVerificationGateStatus(!source.KillSwitchEngaged), Rationale: "Tenant-scoped remediation kill switch must be off before verification runs."},
		{Name: "upstream_ready_for_live_apply", Status: awsPostRemediationVerificationGateStatus(source.ReadyForLiveApply), Rationale: "Upstream executor must declare ready_for_live_apply=true before verification begins."},
		{Name: "idempotency_key_present", Status: awsPostRemediationVerificationGateStatus(strings.TrimSpace(source.IdempotencyKey) != ""), Rationale: "Deterministic idempotency key must be present so verification and rollback replay safely."},
		{Name: "rollback_plan_present", Status: awsPostRemediationVerificationGateStatus(strings.TrimSpace(source.RollbackStrategy) != "" && len(source.RollbackSteps) > 0), Rationale: "Every verifiable execution must carry a rollback strategy and steps before it can be considered safe to apply."},
		{Name: "verification_plan_present", Status: awsPostRemediationVerificationGateStatus(len(source.VerificationSteps) > 0), Rationale: "Every verifiable execution must carry deterministic verification steps."},
	}
	if source.FailedPreconds > 0 {
		gates = append(gates, AWSPostRemediationVerificationGate{
			Name:      "upstream_preconditions",
			Status:    "blocked",
			Rationale: fmt.Sprintf("Upstream executor still has %d failed precondition(s); resolve them before verification can advance.", source.FailedPreconds),
		})
	}
	return gates
}

func awsPostRemediationVerificationGateStatus(ok bool) string {
	if ok {
		return awsPostRemediationVerificationCheckStatusPassed
	}
	return "blocked"
}

func awsPostRemediationVerificationChecks(source awsPostRemediationVerificationSource) []AWSPostRemediationVerificationCheck {
	checks := []AWSPostRemediationVerificationCheck{
		{Source: "cloudtrail", Signal: "expected_api_call_observed", Status: awsPostRemediationVerificationCheckStatusPending, Description: "After live execution, confirm the intended AWS API call appears in CloudTrail for the target account and region."},
		{Source: "graph", Signal: "expected_state_matches", Status: awsPostRemediationVerificationCheckStatusPending, Description: "Re-normalize the impacted graph nodes and confirm they match the projected post-execution state."},
		{Source: "runtime", Signal: "no_unexpected_denials_observed", Status: awsPostRemediationVerificationCheckStatusPending, Description: "Watch runtime denials for the affected principals for the configured settling window and confirm no unexpected denials appear."},
	}
	for _, signal := range dedupeStrings(source.SuccessSignals) {
		checks = append(checks, AWSPostRemediationVerificationCheck{Source: "planner", Signal: signal, Status: awsPostRemediationVerificationCheckStatusPending, Description: "Confirm the upstream planner success signal after live execution."})
	}
	for _, signal := range dedupeStrings(source.FailureSignals) {
		checks = append(checks, AWSPostRemediationVerificationCheck{Source: "planner", Signal: signal, Status: awsPostRemediationVerificationCheckStatusPending, Description: "Watch for the planner failure signal after live execution; treat as verification failure if observed."})
	}
	return checks
}

func awsPostRemediationVerificationRollbackRecord(source awsPostRemediationVerificationSource) AWSPostRemediationVerificationRollback {
	strategy := strings.TrimSpace(source.RollbackStrategy)
	steps := emptyStrings(source.RollbackSteps)
	state := "ready"
	rationale := "Rollback contract mirrors the upstream planner rollback plan and is ready to execute if verification fails."
	if strategy == "" || len(steps) == 0 {
		state = "not_available"
		rationale = "Upstream planner did not carry a rollback plan; a verification failure requires manual recovery."
	}
	if source.KillSwitchEngaged {
		state = "blocked_by_kill_switch"
		rationale = "Tenant kill switch is engaged; rollback stays gated until the switch is disabled."
	}
	return AWSPostRemediationVerificationRollback{
		Strategy:       strategy,
		Steps:          steps,
		SuccessSignals: dedupeStrings(source.SuccessSignals),
		FailureSignals: dedupeStrings(source.FailureSignals),
		EvidenceRef:    strings.TrimSpace(source.RollbackEvidence),
		State:          state,
		Rationale:      rationale,
	}
}

func awsPostRemediationVerificationState(source awsPostRemediationVerificationSource, preconditions []AWSPostRemediationVerificationGate) string {
	if source.KillSwitchEngaged {
		return awsPostRemediationVerificationStateBlocked
	}
	for _, gate := range preconditions {
		if gate.Status != "blocked" {
			continue
		}
		if awsPostRemediationVerificationSafetyGate(gate.Name) {
			return awsPostRemediationVerificationStateBlocked
		}
	}
	// Classify explicit upstream terminal states before the generic
	// not-ready fallback so `blocked`, `skipped`, and any failed upstream
	// precondition surface as their own verification states rather than
	// collapsing to `not_ready`.
	switch strings.ToLower(strings.TrimSpace(source.UpstreamState)) {
	case "blocked":
		return awsPostRemediationVerificationStateBlocked
	case "skipped":
		return awsPostRemediationVerificationStateSkipped
	}
	if source.FailedPreconds > 0 {
		return awsPostRemediationVerificationStateBlocked
	}
	if source.UpstreamState != "projected" || !source.ReadyForLiveApply {
		return awsPostRemediationVerificationStateNotReady
	}
	return awsPostRemediationVerificationStatePending
}

func awsPostRemediationVerificationSafetyGate(name string) bool {
	switch name {
	case "kill_switch_off", "idempotency_key_present", "rollback_plan_present", "verification_plan_present":
		return true
	}
	return false
}

func awsPostRemediationVerificationSummaryText(source awsPostRemediationVerificationSource, state string) string {
	return fmt.Sprintf("Post-remediation verification contract for %s execution %s (state=%s); Identrail records verification checks, rollback intent, and audit only, and never calls AWS write APIs at this layer.", source.SourceType, source.SourceExecutionID, state)
}

func awsPostRemediationVerificationNextAction(state string) string {
	switch state {
	case awsPostRemediationVerificationStatePending:
		return "Verification contract is projected; the wave-8 apply runtime records observed check outcomes and advances to verified or failed."
	case awsPostRemediationVerificationStateVerified:
		return "All verification checks passed; the execution is recorded as verified."
	case awsPostRemediationVerificationStateFailed:
		return "One or more verification checks failed; follow the rollback plan and refresh upstream evidence before retrying."
	case awsPostRemediationVerificationStateRollback:
		return "Verification failed; rollback plan is queued. Confirm rollback completes and re-run planner/dry-run before retrying."
	case awsPostRemediationVerificationStateBlocked:
		return "A safety gate or the tenant kill switch is blocking verification; satisfy the failing gate before retrying."
	case awsPostRemediationVerificationStateSkipped:
		return "Verification was skipped because the upstream executor did not project a live-apply record."
	case awsPostRemediationVerificationStateNotReady:
		return "Upstream executor has not projected ready_for_live_apply; verification cannot advance yet."
	}
	return "Inspect this entry for the projected next action."
}

func awsPostRemediationVerificationEvidenceLinks(source awsPostRemediationVerificationSource) []string {
	links := []string{}
	if ref := strings.TrimSpace(source.RollbackEvidence); ref != "" {
		links = append(links, ref)
	}
	links = append(links, "/docs/aws-post-remediation-verification")
	return dedupeStrings(links)
}

func awsPostRemediationVerificationAuditTrail(source awsPostRemediationVerificationSource, state string, now time.Time) []AWSPostRemediationVerificationAuditEntry {
	trail := []AWSPostRemediationVerificationAuditEntry{}
	trail = append(trail, source.AuditTrail...)
	trail = append(trail, AWSPostRemediationVerificationAuditEntry{
		EventID:    stableAWSBlastRadiusToken("post-remediation-verification-projected", source.SourceType, source.SourceExecutionID),
		Actor:      "identrail-post-remediation-verification-executor",
		EventType:  "post_remediation_verification_projected",
		OccurredAt: now,
		Notes:      fmt.Sprintf("Source=%s execution=%s state=%s; Identrail did not call any AWS write API at this layer.", source.SourceType, source.SourceExecutionID, state),
	})
	return trail
}

func awsPostRemediationVerificationRelationships(entries []AWSPostRemediationVerificationEntry) []AWSPostRemediationVerificationRelationship {
	relationships := []AWSPostRemediationVerificationRelationship{}
	for _, entry := range entries {
		if strings.TrimSpace(entry.SourceExecutionID) == "" {
			continue
		}
		relationships = append(relationships, AWSPostRemediationVerificationRelationship{
			VerificationID: entry.VerificationID,
			Type:           "verifies_execution",
			FromNodeID:     entry.VerificationID,
			ToNodeID:       entry.SourceExecutionID,
			EvidenceRef:    firstString(entry.EvidenceLinks),
		})
		for _, node := range entry.ImpactedNodes {
			if strings.TrimSpace(node) == "" {
				continue
			}
			relationships = append(relationships, AWSPostRemediationVerificationRelationship{
				VerificationID: entry.VerificationID,
				Type:           "verifies_impacted_node",
				FromNodeID:     entry.VerificationID,
				ToNodeID:       node,
			})
		}
	}
	return relationships
}

func summarizeAWSPostRemediationVerificationEntries(all, filtered []AWSPostRemediationVerificationEntry, relationships []AWSPostRemediationVerificationRelationship) AWSPostRemediationVerificationSummary {
	summary := AWSPostRemediationVerificationSummary{
		TotalEntries:     len(all),
		FilteredEntries:  len(filtered),
		StateCounts:      map[string]int{},
		SourceTypeCounts: map[string]int{},
		SeverityCounts:   map[string]int{},
	}
	confidenceTotal := 0.0
	for _, entry := range filtered {
		summary.StateCounts[entry.State]++
		if strings.TrimSpace(entry.SourceType) != "" {
			summary.SourceTypeCounts[entry.SourceType]++
		}
		if strings.TrimSpace(entry.Severity) != "" {
			summary.SeverityCounts[entry.Severity]++
		}
		if entry.KillSwitchEngaged {
			summary.KillSwitchEngagedCount++
		}
		switch entry.State {
		case awsPostRemediationVerificationStateVerified:
			summary.VerifiedCount++
		case awsPostRemediationVerificationStatePending:
			summary.PendingCount++
		case awsPostRemediationVerificationStateFailed:
			summary.FailedCount++
		case awsPostRemediationVerificationStateRollback:
			summary.RollbackPlannedCount++
		case awsPostRemediationVerificationStateBlocked:
			summary.BlockedCount++
		}
		for _, gate := range entry.Preconditions {
			if gate.Status == "blocked" {
				summary.FailedPreconditionCount++
			}
		}
		summary.CheckCount += len(entry.Checks)
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

func filterAWSPostRemediationVerificationEntries(entries []AWSPostRemediationVerificationEntry, request AWSPostRemediationVerificationRequest) ([]AWSPostRemediationVerificationEntry, map[string]string) {
	filters := map[string]string{
		"account_id":   strings.TrimSpace(request.AccountID),
		"region":       strings.TrimSpace(request.Region),
		"source_type":  strings.TrimSpace(strings.ToLower(request.SourceType)),
		"execution_id": strings.TrimSpace(request.ExecutionID),
		"dry_run_id":   strings.TrimSpace(request.DryRunID),
		"case_id":      strings.TrimSpace(request.CaseID),
		"state":        normalizeAWSRuntimeEventFilterToken(request.State),
		"severity":     normalizeAWSRuntimeEventFilterToken(request.Severity),
		"operation":    normalizeAWSRuntimeEventFilterToken(request.Operation),
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
	filtered := make([]AWSPostRemediationVerificationEntry, 0, len(entries))
	for _, entry := range entries {
		if filters["account_id"] != "" && !awsPostRemediationVerificationAccountMatch(entry, filters["account_id"]) {
			continue
		}
		if filters["region"] != "" && strings.TrimSpace(entry.Region) != "" && !strings.EqualFold(filters["region"], strings.TrimSpace(entry.Region)) {
			continue
		}
		if filters["source_type"] != "" && !strings.EqualFold(filters["source_type"], entry.SourceType) {
			continue
		}
		if filters["execution_id"] != "" && !strings.EqualFold(filters["execution_id"], entry.SourceExecutionID) && !strings.EqualFold(filters["execution_id"], entry.VerificationID) {
			continue
		}
		if filters["dry_run_id"] != "" && !strings.EqualFold(filters["dry_run_id"], entry.DryRunID) {
			continue
		}
		if filters["case_id"] != "" && !strings.EqualFold(filters["case_id"], entry.CaseID) {
			continue
		}
		if filters["state"] != "" && filters["state"] != normalizeAWSRuntimeEventFilterToken(entry.State) {
			continue
		}
		if filters["severity"] != "" && filters["severity"] != normalizeAWSRuntimeEventFilterToken(entry.Severity) {
			continue
		}
		if filters["operation"] != "" && filters["operation"] != normalizeAWSRuntimeEventFilterToken(entry.Operation) {
			continue
		}
		if filters["search"] != "" && !awsPostRemediationVerificationSearchMatch(entry, filters["search"]) {
			continue
		}
		filtered = append(filtered, entry)
	}
	return filtered, applied
}

func awsPostRemediationVerificationAccountMatch(entry AWSPostRemediationVerificationEntry, accountID string) bool {
	accountID = strings.TrimSpace(accountID)
	if accountID == "" {
		return true
	}
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

func awsPostRemediationVerificationSearchMatch(entry AWSPostRemediationVerificationEntry, needle string) bool {
	needle = strings.ToLower(strings.TrimSpace(needle))
	if needle == "" {
		return true
	}
	values := []string{
		entry.VerificationID, entry.SourceExecutionID, entry.DryRunID, entry.ApprovalID, entry.CaseID,
		entry.PlanID, entry.SourceArtifactID, entry.SourceType, entry.State, entry.Severity, entry.Title,
		entry.Summary, entry.Operation, entry.IdempotencyKey, entry.TargetResource, entry.NextAction,
		entry.Rollback.Strategy, entry.Rollback.State, entry.Rollback.Rationale, entry.Rollback.EvidenceRef,
	}
	values = append(values, entry.SourceSignals...)
	values = append(values, entry.ImpactedNodes...)
	values = append(values, entry.TargetAccountIDs...)
	values = append(values, entry.EvidenceLinks...)
	values = append(values, entry.Rollback.Steps...)
	values = append(values, entry.Rollback.SuccessSignals...)
	values = append(values, entry.Rollback.FailureSignals...)
	for _, gate := range entry.Preconditions {
		values = append(values, gate.Name, gate.Status, gate.Rationale)
	}
	for _, check := range entry.Checks {
		values = append(values, check.Source, check.Signal, check.Status, check.Description)
	}
	for _, audit := range entry.AuditTrail {
		values = append(values, audit.EventType, audit.Actor, audit.Notes)
	}
	for _, value := range values {
		if strings.Contains(strings.ToLower(value), needle) {
			return true
		}
	}
	return false
}

func summarizeAWSPostRemediationVerificationStatus(upstreamStatus string, filtered []AWSPostRemediationVerificationEntry, diagnostics []AWSPostRemediationVerificationDiagnostic) (string, float64) {
	if upstreamStatus == awsPlatformDependencyStatusBlocked {
		return awsPlatformDependencyStatusBlocked, 0.35
	}
	for _, diagnostic := range diagnostics {
		if diagnostic.Retryable {
			return awsPlatformDependencyStatusDegraded, 0.72
		}
	}
	if upstreamStatus == awsPlatformDependencyStatusDegraded {
		return awsPlatformDependencyStatusDegraded, 0.74
	}
	if len(filtered) == 0 {
		return awsPlatformDependencyStatusReady, 0.82
	}
	return awsPlatformDependencyStatusReady, 0.9
}

func awsPostRemediationVerificationCaveats() []string {
	return []string{
		"Post-remediation verification entries are read-only projections; Identrail never calls IAM, STS, or Organizations write APIs at this layer.",
		"Verification checks stay in the `pending` state until the wave-8 apply runtime writes the observed outcome. This endpoint does not observe live AWS behavior itself.",
		"Rollback records mirror the upstream planner metadata; they never contain rendered policy bodies or secret values.",
	}
}

func awsPostRemediationVerificationRemediationHints(source []string) []string {
	hints := []string{
		"Resolve any failed upstream precondition before verification can advance; upstream dry-run and executor entries own those gates.",
		"Use the idempotency key recorded here so verification and rollback replay against the same AWS write intent.",
		"If any verification check fails, follow the rollback record and refresh planner evidence before retrying.",
	}
	hints = append(hints, source...)
	return dedupeStrings(hints)
}

func awsPostRemediationVerificationEvidenceBoundary() string {
	return "metadata_only_no_rendered_policy_bodies_no_secret_values_no_workload_payloads_tenant_workspace_project_connector_account_region_scoped"
}

func firstNonZeroAWSPostRemediationVerificationTime(values ...time.Time) time.Time {
	for _, value := range values {
		if !value.IsZero() {
			return value
		}
	}
	return time.Time{}
}
