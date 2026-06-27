package api

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	awsLowRiskRemediationCurrentIssue = 1538
	awsLowRiskRemediationVersion      = "aws-low-risk-live-remediation-v1"

	awsLowRiskRemediationStateProjected = "projected"
	awsLowRiskRemediationStateSkipped   = "skipped"
	awsLowRiskRemediationStateBlocked   = "blocked"
)

// AWSLowRiskRemediationRequest scopes the deterministic low-risk live
// remediation projection to one AWS connector plus optional operator
// drill-down filters.
type AWSLowRiskRemediationRequest struct {
	ConnectorID    string `json:"connector_id,omitempty"`
	FixtureState   string `json:"fixture_state,omitempty"`
	AccountID      string `json:"account_id,omitempty"`
	Region         string `json:"region,omitempty"`
	DryRunID       string `json:"dry_run_id,omitempty"`
	CaseID         string `json:"case_id,omitempty"`
	Action         string `json:"action,omitempty"`
	ActionCategory string `json:"action_category,omitempty"`
	State          string `json:"state,omitempty"`
	Severity       string `json:"severity,omitempty"`
	Search         string `json:"search,omitempty"`
}

// Reuse shapes from the dry-run/approval layers so the executor record stays
// consistent with the rest of the wave-8 stack.
type AWSLowRiskRemediationEvidence = AWSRemediationApprovalEvidence
type AWSLowRiskRemediationPathStep = AWSRemediationApprovalPathStep
type AWSLowRiskRemediationDiagnostic = AWSRemediationApprovalDiagnostic
type AWSLowRiskRemediationCoverageGap = AWSRemediationApprovalCoverageGap
type AWSLowRiskRemediationAuditEntry = AWSRemediationApprovalAuditEntry

// AWSLowRiskRemediationAllowlistRule names the deterministic rule that admits
// a dry-run action into the low-risk live remediation set. Operators and any
// later executor can trace every entry back to a rule by name.
type AWSLowRiskRemediationAllowlistRule struct {
	Name           string   `json:"name"`
	Category       string   `json:"category"`
	Action         string   `json:"action"`
	MatchSources   []string `json:"match_sources,omitempty"`
	MaxBlastRadius string   `json:"max_blast_radius,omitempty"`
	Rationale      string   `json:"rationale"`
}

// AWSLowRiskRemediationPreflight is one safety check the executor performs
// before declaring a record `ready_for_live_apply`. The set mirrors the
// upstream dry-run prerequisites plus the action allowlist and idempotency
// match.
type AWSLowRiskRemediationPreflight struct {
	Name      string `json:"name"`
	Status    string `json:"status"`
	Rationale string `json:"rationale"`
}

// AWSLowRiskRemediationMutationRecord describes what the executor would mutate
// in AWS. Identrail does not call AWS write APIs at this layer; the record
// captures the intent so the wave-8.04+ executors can replay it
// idempotently.
type AWSLowRiskRemediationMutationRecord struct {
	Service        string   `json:"service"`
	Operation      string   `json:"operation"`
	TargetResource string   `json:"target_resource"`
	ChangeKind     string   `json:"change_kind"`
	BeforeRef      string   `json:"before_ref,omitempty"`
	AfterRef       string   `json:"after_ref,omitempty"`
	ParameterRefs  []string `json:"parameter_refs,omitempty"`
}

// AWSLowRiskRemediationVerificationRecord describes the deterministic
// post-execution verification step that must succeed before the change is
// recorded as `succeeded` by a downstream executor.
type AWSLowRiskRemediationVerificationRecord struct {
	Source      string `json:"source"`
	Signal      string `json:"signal"`
	Status      string `json:"status"`
	Description string `json:"description"`
}

// AWSLowRiskRemediationRelationship surfaces execution→graph node edges.
type AWSLowRiskRemediationRelationship struct {
	ExecutionID string `json:"execution_id"`
	Type        string `json:"type"`
	FromNodeID  string `json:"from_node_id"`
	ToNodeID    string `json:"to_node_id"`
	EvidenceRef string `json:"evidence_ref,omitempty"`
}

// AWSLowRiskRemediationEntry is the persisted-record-shaped contract emitted
// by the low-risk live remediation executor. It is metadata-only: it carries
// no rendered policy bodies, no secret material, and no workload payloads.
// Live IAM/STS/Organizations write APIs are gated to wave-8.04+ executors.
type AWSLowRiskRemediationEntry struct {
	ExecutionID        string                                    `json:"execution_id"`
	CalculationVersion string                                    `json:"calculation_version"`
	DryRunID           string                                    `json:"dry_run_id"`
	ApprovalID         string                                    `json:"approval_id"`
	CaseID             string                                    `json:"case_id"`
	SourceArtifactID   string                                    `json:"source_artifact_id"`
	SourceType         string                                    `json:"source_type"`
	State              string                                    `json:"state"`
	Severity           string                                    `json:"severity"`
	Score              int                                       `json:"score"`
	Confidence         float64                                   `json:"confidence"`
	Title              string                                    `json:"title"`
	Summary            string                                    `json:"summary"`
	AccountID          string                                    `json:"account_id"`
	Region             string                                    `json:"region"`
	IdempotencyKey     string                                    `json:"idempotency_key"`
	AllowlistRule      AWSLowRiskRemediationAllowlistRule        `json:"allowlist_rule"`
	Mutation           AWSLowRiskRemediationMutationRecord       `json:"mutation"`
	Preflights         []AWSLowRiskRemediationPreflight          `json:"preflights"`
	Verifications      []AWSLowRiskRemediationVerificationRecord `json:"verifications"`
	RollbackPlan       AWSRemediationRollbackPlan                `json:"rollback_plan"`
	VerificationPlan   AWSRemediationVerificationPlan            `json:"verification_plan"`
	Tradeoffs          []AWSRemediationTradeoff                  `json:"tradeoffs"`
	AuditTrail         []AWSLowRiskRemediationAuditEntry         `json:"audit_trail"`
	KillSwitchEngaged  bool                                      `json:"kill_switch_engaged"`
	ReadyForLiveApply  bool                                      `json:"ready_for_live_apply"`
	ReadOnlyProjection bool                                      `json:"read_only_projection"`
	SourceSignals      []string                                  `json:"source_signals"`
	Evidence           []AWSLowRiskRemediationEvidence           `json:"evidence"`
	EvidenceBoundary   string                                    `json:"evidence_boundary"`
	ImpactedNodes      []string                                  `json:"impacted_nodes"`
	ImpactedPath       []AWSLowRiskRemediationPathStep           `json:"impacted_path"`
	NextAction         string                                    `json:"next_action"`
	ProjectedAt        time.Time                                 `json:"projected_at"`
	CreatedAt          time.Time                                 `json:"created_at"`
	UpdatedAt          time.Time                                 `json:"updated_at"`
}

// AWSLowRiskRemediationSummary aggregates the unfiltered and filtered set.
type AWSLowRiskRemediationSummary struct {
	TotalEntries           int            `json:"total_entries"`
	FilteredEntries        int            `json:"filtered_entries"`
	StateCounts            map[string]int `json:"state_counts"`
	ActionCounts           map[string]int `json:"action_counts"`
	CategoryCounts         map[string]int `json:"category_counts"`
	SeverityCounts         map[string]int `json:"severity_counts"`
	ReadyForLiveApplyCount int            `json:"ready_for_live_apply_count"`
	KillSwitchEngagedCount int            `json:"kill_switch_engaged_count"`
	FailedPreflightCount   int            `json:"failed_preflight_count"`
	MutationCount          int            `json:"mutation_count"`
	VerificationCount      int            `json:"verification_count"`
	RelationshipCount      int            `json:"relationship_count"`
	HighestScore           int            `json:"highest_score"`
	AverageConfidencePct   int            `json:"average_confidence_pct"`
}

// AWSLowRiskRemediationResult is the deterministic envelope returned by the
// low-risk live remediation endpoint.
type AWSLowRiskRemediationResult struct {
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
	Allowlist          []AWSLowRiskRemediationAllowlistRule `json:"allowlist"`
	Summary            AWSLowRiskRemediationSummary         `json:"summary"`
	Entries            []AWSLowRiskRemediationEntry         `json:"entries"`
	Relationships      []AWSLowRiskRemediationRelationship  `json:"relationships"`
	Caveats            []string                             `json:"caveats"`
	FailureReasons     []string                             `json:"failure_reasons"`
	RemediationHints   []string                             `json:"remediation_hints"`
	EvidenceLinks      []string                             `json:"evidence_links"`
	CoverageGaps       []AWSLowRiskRemediationCoverageGap   `json:"coverage_gaps"`
	Diagnostics        []AWSLowRiskRemediationDiagnostic    `json:"diagnostics"`
	GeneratedAt        time.Time                            `json:"generated_at"`
	UpdatedAt          time.Time                            `json:"updated_at"`
}

// awsLowRiskRemediationAllowlist is the deterministic, code-managed set of
// AWS actions admitted into the low-risk live remediation flow. The list is
// intentionally narrow: only approved detach/disable operations whose
// upstream dry-run already projects `would_succeed` at the `low` risk tier.
// Tagging and stale-metadata-cleanup categories are tracked for future
// rules but no rule is admitted until the dry-run routing emits the
// corresponding action; advertising a rule that the dry-run never produces
// would mislead operators. Any change to this list is a code change
// reviewed under the wave-8 safety controls.
func awsLowRiskRemediationAllowlist() []AWSLowRiskRemediationAllowlistRule {
	return []AWSLowRiskRemediationAllowlistRule{
		{
			Name:           "iam_update_access_key_quarantine",
			Category:       "approved_disable",
			Action:         "iam:UpdateAccessKey",
			MatchSources:   []string{"aws_access_key_quarantine"},
			MaxBlastRadius: "low",
			Rationale:      "Mark an IAM access key Inactive when the access-key quarantine planner approved the disable and the dry-run projected would_succeed at the low risk tier.",
		},
		{
			Name:           "iam_detach_role_policy_orphaned",
			Category:       "approved_detach",
			Action:         "iam:DetachRolePolicy",
			MatchSources:   []string{"least_privilege", "blast_radius"},
			MaxBlastRadius: "low",
			Rationale:      "Detach a role-managed policy that the upstream dry-run flagged as orphaned with no observed runtime use at the low risk tier.",
		},
	}
}

// GetAWSLowRiskRemediation projects the deterministic, read-only low-risk
// live remediation set from the upstream dry-run executor. Each entry pairs
// a dry-run record with one allowlist rule, preserves the idempotency key,
// captures the intended mutation/verification/rollback metadata, and never
// calls IAM/STS/Organizations write APIs at this layer. Controlled live
// execution belongs to the wave-8.04+ executors and their own feature flags.
func (s *Service) GetAWSLowRiskRemediation(ctx context.Context, workspaceID string, projectID string, request AWSLowRiskRemediationRequest) (AWSLowRiskRemediationResult, error) {
	project, scope, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return AWSLowRiskRemediationResult{}, err
	}
	connection, hasConnection, err := s.awsBaselineConnection(ctx, project, strings.TrimSpace(request.ConnectorID))
	if err != nil {
		return AWSLowRiskRemediationResult{}, err
	}
	now := s.Now().UTC()
	fixtureState := normalizeAWSLowRiskRemediationFixtureState(request.FixtureState, connection, hasConnection)
	if fixtureState == "" {
		return AWSLowRiskRemediationResult{}, ErrInvalidAWSConnectionRequest
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
		return AWSLowRiskRemediationResult{}, fmt.Errorf("low-risk remediation dry-run: %w", err)
	}

	allowlist := awsLowRiskRemediationAllowlist()
	allowlistByAction := map[string]AWSLowRiskRemediationAllowlistRule{}
	for _, rule := range allowlist {
		allowlistByAction[strings.ToLower(rule.Action)] = rule
	}
	entries := awsLowRiskRemediationEntries(dryRun.Entries, allowlistByAction, now)
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].Score == entries[j].Score {
			return entries[i].ExecutionID < entries[j].ExecutionID
		}
		return entries[i].Score > entries[j].Score
	})
	filtered, applied := filterAWSLowRiskRemediationEntries(entries, request)
	relationships := awsLowRiskRemediationRelationships(filtered)
	diagnostics := awsLowRiskRemediationDiagnostics(dryRun.Diagnostics)
	coverageGaps := awsLowRiskRemediationCoverageGaps(dryRun.CoverageGaps)
	status, confidence := summarizeAWSLowRiskRemediationStatus(dryRun.Status, filtered, diagnostics)

	return AWSLowRiskRemediationResult{
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
		FixtureState:       sourceFixtureState,
		Confidence:         confidence,
		CalculationVersion: awsLowRiskRemediationVersion,
		AppliedFilters:     applied,
		Allowlist:          allowlist,
		Summary:            summarizeAWSLowRiskRemediationEntries(entries, filtered, relationships),
		Entries:            filtered,
		Relationships:      relationships,
		Caveats:            awsLowRiskRemediationCaveats(),
		FailureReasons:     dedupeStrings(dryRun.FailureReasons),
		RemediationHints:   awsLowRiskRemediationRemediationHints(dryRun.RemediationHints),
		EvidenceLinks: dedupeStrings([]string{
			awsIssueURL(awsPlatformDependencyParentIssue),
			awsIssueURL(awsLowRiskRemediationCurrentIssue),
			awsIssueURL(awsRemediationDryRunCurrentIssue),
			awsIssueURL(awsRemediationApprovalCurrentIssue),
			"/docs/aws-low-risk-live-remediation",
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

func normalizeAWSLowRiskRemediationFixtureState(requested string, connection AWSConnectionStatus, hasConnection bool) string {
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

func awsLowRiskRemediationEntries(dryRunEntries []AWSRemediationDryRunEntry, allowlistByAction map[string]AWSLowRiskRemediationAllowlistRule, now time.Time) []AWSLowRiskRemediationEntry {
	entries := []AWSLowRiskRemediationEntry{}
	for _, entry := range dryRunEntries {
		if len(entry.IntendedAPICalls) == 0 {
			continue
		}
		call := entry.IntendedAPICalls[0]
		action := strings.ToLower(call.Service + ":" + call.Operation)
		rule, ok := allowlistByAction[action]
		if !ok {
			continue
		}
		if !awsLowRiskRemediationSourceAdmitted(rule, entry.SourceType) {
			continue
		}
		if !awsLowRiskRemediationRiskTierAdmitted(rule, entry) {
			continue
		}
		entries = append(entries, awsLowRiskRemediationEntryFromDryRun(entry, call, rule, now))
	}
	return entries
}

func awsLowRiskRemediationSourceAdmitted(rule AWSLowRiskRemediationAllowlistRule, sourceType string) bool {
	if len(rule.MatchSources) == 0 {
		return true
	}
	for _, match := range rule.MatchSources {
		if strings.EqualFold(match, sourceType) {
			return true
		}
	}
	return false
}

// awsLowRiskRemediationRiskTierAdmitted blocks any dry-run entry whose
// projected risk tier or severity exceeds the allowlist rule's
// MaxBlastRadius. Without this check, an approved high/critical entry
// matching by action+source could leak into the low-risk projection even
// though the rule declares MaxBlastRadius="low".
func awsLowRiskRemediationRiskTierAdmitted(rule AWSLowRiskRemediationAllowlistRule, entry AWSRemediationDryRunEntry) bool {
	ceiling := awsLowRiskRemediationRiskRank(rule.MaxBlastRadius)
	if ceiling < 0 {
		return true
	}
	if rank := awsLowRiskRemediationRiskRank(entry.RiskTier); rank >= 0 && rank > ceiling {
		return false
	}
	if rank := awsLowRiskRemediationRiskRank(entry.Severity); rank >= 0 && rank > ceiling {
		return false
	}
	return true
}

func awsLowRiskRemediationRiskRank(value string) int {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "low":
		return 0
	case "medium":
		return 1
	case "high":
		return 2
	case "critical":
		return 3
	}
	return -1
}

func awsLowRiskRemediationEntryFromDryRun(entry AWSRemediationDryRunEntry, call AWSRemediationDryRunIntendedAPICall, rule AWSLowRiskRemediationAllowlistRule, now time.Time) AWSLowRiskRemediationEntry {
	preflights := awsLowRiskRemediationPreflights(entry, rule)
	mutation := awsLowRiskRemediationMutation(entry, call, rule)
	verifications := awsLowRiskRemediationVerifications(entry)
	state := awsLowRiskRemediationState(entry, preflights)
	executionID := "aws-low-risk-remediation:" + stableAWSBlastRadiusToken("execution", entry.DryRunID, rule.Name)
	out := AWSLowRiskRemediationEntry{
		ExecutionID:        executionID,
		CalculationVersion: awsLowRiskRemediationVersion,
		DryRunID:           entry.DryRunID,
		ApprovalID:         entry.ApprovalID,
		CaseID:             entry.CaseID,
		SourceArtifactID:   entry.SourceArtifactID,
		SourceType:         entry.SourceType,
		State:              state,
		Severity:           entry.Severity,
		Score:              entry.Score,
		Confidence:         entry.Confidence,
		Title:              fmt.Sprintf("Low-risk remediation: %s", entry.Title),
		Summary:            fmt.Sprintf("Allowlisted low-risk live remediation for dry-run %s; Identrail records intent and idempotency only and never calls AWS write APIs at this layer.", entry.DryRunID),
		AccountID:          entry.AccountID,
		Region:             entry.Region,
		IdempotencyKey:     entry.IdempotencyKey,
		AllowlistRule:      rule,
		Mutation:           mutation,
		Preflights:         preflights,
		Verifications:      verifications,
		RollbackPlan:       entry.RollbackPlan,
		VerificationPlan:   entry.VerificationPlan,
		Tradeoffs:          entry.Tradeoffs,
		AuditTrail:         awsLowRiskRemediationAuditTrail(entry, state, rule, now),
		KillSwitchEngaged:  entry.KillSwitchEngaged,
		ReadOnlyProjection: true,
		SourceSignals:      dedupeStrings(append([]string{"remediation_dry_run", "low_risk_allowlist"}, entry.SourceSignals...)),
		Evidence:           entry.Evidence,
		EvidenceBoundary:   awsLowRiskRemediationEvidenceBoundary(),
		ImpactedNodes:      entry.ImpactedNodes,
		ImpactedPath:       entry.ImpactedPath,
		NextAction:         awsLowRiskRemediationNextAction(state, rule),
		ProjectedAt:        now,
		CreatedAt:          firstNonZeroAWSLowRiskRemediationTime(entry.CreatedAt, now),
		UpdatedAt:          now,
	}
	out.ReadyForLiveApply = state == awsLowRiskRemediationStateProjected && entry.ReadyForApply && !entry.KillSwitchEngaged
	return out
}

func awsLowRiskRemediationPreflights(entry AWSRemediationDryRunEntry, rule AWSLowRiskRemediationAllowlistRule) []AWSLowRiskRemediationPreflight {
	preflights := []AWSLowRiskRemediationPreflight{
		{
			Name:      "allowlist_action_admitted",
			Status:    "passed",
			Rationale: fmt.Sprintf("Action %s is admitted by allowlist rule %s.", rule.Action, rule.Name),
		},
		{
			Name:      "dry_run_would_succeed",
			Status:    awsLowRiskRemediationPreflightStatus(entry.Outcome == awsRemediationDryRunOutcomeWouldSucceed),
			Rationale: "Upstream dry-run must project would_succeed before any live apply.",
		},
		{
			Name:      "ready_for_apply",
			Status:    awsLowRiskRemediationPreflightStatus(entry.ReadyForApply),
			Rationale: "Upstream dry-run must declare ready_for_apply=true before any live apply.",
		},
		{
			Name:      "kill_switch_off",
			Status:    awsLowRiskRemediationPreflightStatus(!entry.KillSwitchEngaged),
			Rationale: "Tenant-scoped remediation kill switch must be off.",
		},
		{
			Name:      "idempotency_key_present",
			Status:    awsLowRiskRemediationPreflightStatus(strings.TrimSpace(entry.IdempotencyKey) != ""),
			Rationale: "Deterministic idempotency key must be present so retries do not double-apply.",
		},
	}
	if len(entry.FailedPrereqs) > 0 {
		preflights = append(preflights, AWSLowRiskRemediationPreflight{
			Name:      "upstream_prerequisites",
			Status:    "blocked",
			Rationale: fmt.Sprintf("Upstream dry-run still has %d failed prerequisite(s); resolve them before retrying.", len(entry.FailedPrereqs)),
		})
	}
	return preflights
}

func awsLowRiskRemediationPreflightStatus(ok bool) string {
	if ok {
		return "passed"
	}
	return "blocked"
}

func awsLowRiskRemediationMutation(entry AWSRemediationDryRunEntry, call AWSRemediationDryRunIntendedAPICall, rule AWSLowRiskRemediationAllowlistRule) AWSLowRiskRemediationMutationRecord {
	return AWSLowRiskRemediationMutationRecord{
		Service:        call.Service,
		Operation:      call.Operation,
		TargetResource: call.TargetResource,
		ChangeKind:     rule.Category,
		BeforeRef:      firstNonEmptyAWSValue(entry.DiffIntent.BeforeRef, entry.CaseID),
		AfterRef:       firstNonEmptyAWSValue(entry.DiffIntent.AfterRef, fmt.Sprintf("after://%s", entry.CaseID)),
		ParameterRefs:  call.ParameterRefs,
	}
}

func awsLowRiskRemediationVerifications(entry AWSRemediationDryRunEntry) []AWSLowRiskRemediationVerificationRecord {
	out := make([]AWSLowRiskRemediationVerificationRecord, 0, len(entry.VerificationChecks))
	for _, check := range entry.VerificationChecks {
		out = append(out, AWSLowRiskRemediationVerificationRecord{
			Source:      check.Source,
			Signal:      check.Signal,
			Status:      "pending",
			Description: check.Description,
		})
	}
	return out
}

func awsLowRiskRemediationState(entry AWSRemediationDryRunEntry, preflights []AWSLowRiskRemediationPreflight) string {
	if entry.KillSwitchEngaged {
		return awsLowRiskRemediationStateBlocked
	}
	for _, preflight := range preflights {
		if preflight.Status != "blocked" {
			continue
		}
		// Safety-preflight failures (kill switch, idempotency, allowlist,
		// upstream-prereq) put the entry into `blocked`; readiness failures
		// (dry-run outcome or ready_for_apply) put it into `skipped` so
		// operators see the difference between "unsafe" and "not yet ready".
		if awsLowRiskRemediationPreflightIsSafety(preflight.Name) {
			return awsLowRiskRemediationStateBlocked
		}
	}
	if entry.Outcome != awsRemediationDryRunOutcomeWouldSucceed || !entry.ReadyForApply {
		return awsLowRiskRemediationStateSkipped
	}
	return awsLowRiskRemediationStateProjected
}

func awsLowRiskRemediationPreflightIsSafety(name string) bool {
	switch name {
	case "allowlist_action_admitted", "kill_switch_off", "idempotency_key_present", "upstream_prerequisites":
		return true
	}
	return false
}

func awsLowRiskRemediationNextAction(state string, rule AWSLowRiskRemediationAllowlistRule) string {
	switch state {
	case awsLowRiskRemediationStateProjected:
		return fmt.Sprintf("Allowlist rule %s admits this mutation; the wave-8.04+ live executor may apply it idempotently when its feature flag opens.", rule.Name)
	case awsLowRiskRemediationStateSkipped:
		return "Upstream dry-run is not ready (outcome != would_succeed or ready_for_apply=false); advance the dry-run before retrying."
	case awsLowRiskRemediationStateBlocked:
		return "A preflight check or the tenant kill switch is blocking this entry; satisfy the failing check before retrying."
	}
	return "Inspect this entry for the projected next action."
}

func awsLowRiskRemediationAuditTrail(entry AWSRemediationDryRunEntry, state string, rule AWSLowRiskRemediationAllowlistRule, now time.Time) []AWSLowRiskRemediationAuditEntry {
	trail := []AWSLowRiskRemediationAuditEntry{}
	trail = append(trail, entry.AuditTrail...)
	trail = append(trail, AWSLowRiskRemediationAuditEntry{
		EventID:    stableAWSBlastRadiusToken("low-risk-projected", entry.DryRunID, rule.Name),
		Actor:      "identrail-low-risk-executor",
		EventType:  "low_risk_execution_projected",
		OccurredAt: now,
		Notes:      fmt.Sprintf("Allowlist rule=%s state=%s; Identrail did not call any AWS write API at this layer.", rule.Name, state),
	})
	return trail
}

func awsLowRiskRemediationRelationships(entries []AWSLowRiskRemediationEntry) []AWSLowRiskRemediationRelationship {
	relationships := []AWSLowRiskRemediationRelationship{}
	for _, entry := range entries {
		evidenceRef := firstAWSRemediationCaseEvidenceRef(entry.Evidence)
		target := strings.TrimSpace(entry.Mutation.TargetResource)
		if target != "" {
			relationships = append(relationships, AWSLowRiskRemediationRelationship{
				ExecutionID: entry.ExecutionID,
				Type:        "low_risk_targets_node",
				FromNodeID:  entry.ExecutionID,
				ToNodeID:    target,
				EvidenceRef: evidenceRef,
			})
		}
	}
	return relationships
}

func summarizeAWSLowRiskRemediationEntries(all, filtered []AWSLowRiskRemediationEntry, relationships []AWSLowRiskRemediationRelationship) AWSLowRiskRemediationSummary {
	summary := AWSLowRiskRemediationSummary{
		TotalEntries:    len(all),
		FilteredEntries: len(filtered),
		StateCounts:     map[string]int{},
		ActionCounts:    map[string]int{},
		CategoryCounts:  map[string]int{},
		SeverityCounts:  map[string]int{},
	}
	confidenceTotal := 0.0
	for _, entry := range filtered {
		summary.StateCounts[entry.State]++
		summary.ActionCounts[entry.AllowlistRule.Action]++
		summary.CategoryCounts[entry.AllowlistRule.Category]++
		if strings.TrimSpace(entry.Severity) != "" {
			summary.SeverityCounts[entry.Severity]++
		}
		if entry.ReadyForLiveApply {
			summary.ReadyForLiveApplyCount++
		}
		if entry.KillSwitchEngaged {
			summary.KillSwitchEngagedCount++
		}
		for _, preflight := range entry.Preflights {
			if preflight.Status == "blocked" {
				summary.FailedPreflightCount++
			}
		}
		summary.MutationCount++
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

func filterAWSLowRiskRemediationEntries(entries []AWSLowRiskRemediationEntry, request AWSLowRiskRemediationRequest) ([]AWSLowRiskRemediationEntry, map[string]string) {
	filters := map[string]string{
		"account_id":      strings.TrimSpace(request.AccountID),
		"region":          strings.TrimSpace(request.Region),
		"dry_run_id":      strings.TrimSpace(request.DryRunID),
		"case_id":         strings.TrimSpace(request.CaseID),
		"action":          strings.TrimSpace(request.Action),
		"action_category": normalizeAWSRuntimeEventFilterToken(request.ActionCategory),
		"state":           normalizeAWSRuntimeEventFilterToken(request.State),
		"severity":        normalizeAWSRuntimeEventFilterToken(request.Severity),
		"search":          strings.TrimSpace(request.Search),
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
	filtered := make([]AWSLowRiskRemediationEntry, 0, len(entries))
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
		if filters["action"] != "" && !strings.EqualFold(filters["action"], entry.AllowlistRule.Action) {
			continue
		}
		if filters["action_category"] != "" && filters["action_category"] != normalizeAWSRuntimeEventFilterToken(entry.AllowlistRule.Category) {
			continue
		}
		if filters["state"] != "" && filters["state"] != normalizeAWSRuntimeEventFilterToken(entry.State) {
			continue
		}
		if filters["severity"] != "" && filters["severity"] != normalizeAWSRuntimeEventFilterToken(entry.Severity) {
			continue
		}
		if filters["search"] != "" && !awsLowRiskRemediationSearchMatch(entry, filters["search"]) {
			continue
		}
		filtered = append(filtered, entry)
	}
	return filtered, applied
}

func awsLowRiskRemediationSearchMatch(entry AWSLowRiskRemediationEntry, needle string) bool {
	needle = strings.ToLower(strings.TrimSpace(needle))
	if needle == "" {
		return true
	}
	values := []string{
		entry.ExecutionID, entry.DryRunID, entry.ApprovalID, entry.CaseID,
		entry.SourceArtifactID, entry.SourceType, entry.State, entry.Severity,
		entry.Title, entry.Summary, entry.IdempotencyKey, entry.NextAction,
		entry.AllowlistRule.Name, entry.AllowlistRule.Category, entry.AllowlistRule.Action, entry.AllowlistRule.Rationale,
		entry.Mutation.Service, entry.Mutation.Operation, entry.Mutation.TargetResource, entry.Mutation.ChangeKind,
		entry.RollbackPlan.Strategy, entry.VerificationPlan.Strategy,
	}
	values = append(values, entry.SourceSignals...)
	values = append(values, entry.Mutation.ParameterRefs...)
	for _, preflight := range entry.Preflights {
		values = append(values, preflight.Name, preflight.Status, preflight.Rationale)
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

func summarizeAWSLowRiskRemediationStatus(sourceStatus string, filtered []AWSLowRiskRemediationEntry, diagnostics []AWSLowRiskRemediationDiagnostic) (string, float64) {
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

func awsLowRiskRemediationCaveats() []string {
	return []string{
		"Low-risk live remediation entries are read-only projections; Identrail never calls IAM, STS, Secrets Manager, KMS, or Organizations write APIs at this layer.",
		"Only allowlisted AWS actions are admitted (tagging, stale-metadata cleanup, approved detach/disable); any action outside the allowlist is excluded from this projection.",
		"ready_for_live_apply is a planning signal — controlled live execution belongs to the wave-8.04+ executors and their own feature flags.",
	}
}

func awsLowRiskRemediationRemediationHints(source []string) []string {
	hints := []string{
		"Resolve any failed preflight before retrying; the dry-run upstream determines outcome and ready_for_apply for these entries.",
		"Use the idempotency key recorded here as the deterministic id when later wave executors apply the change so retries cannot double-apply.",
		"Every allowlist rule is code-managed; any change to the allowlist is a code review under the wave-8 safety controls.",
	}
	hints = append(hints, source...)
	return dedupeStrings(hints)
}

func awsLowRiskRemediationDiagnostics(source []AWSRemediationApprovalDiagnostic) []AWSLowRiskRemediationDiagnostic {
	out := make([]AWSLowRiskRemediationDiagnostic, 0, len(source))
	for _, diagnostic := range source {
		out = append(out, AWSLowRiskRemediationDiagnostic(diagnostic))
	}
	return out
}

func awsLowRiskRemediationCoverageGaps(source []AWSRemediationApprovalCoverageGap) []AWSLowRiskRemediationCoverageGap {
	gaps := []AWSLowRiskRemediationCoverageGap{{
		Capability:  "aws_low_risk_live_apply",
		Status:      "out_of_scope",
		Reason:      "Issue #1538 emits low-risk live remediation projections only; the live IAM write call is gated to the wave-8.04+ apply executors.",
		Remediation: "Wire the controlled live-apply executors in the matching wave-8 issues once their safety gates are in place.",
	}}
	for _, gap := range source {
		gaps = append(gaps, AWSLowRiskRemediationCoverageGap(gap))
	}
	return gaps
}

func awsLowRiskRemediationEvidenceBoundary() string {
	return "metadata_only_no_rendered_policy_bodies_no_secret_values_no_workload_payloads_tenant_workspace_project_connector_account_region_scoped"
}

func firstNonZeroAWSLowRiskRemediationTime(values ...time.Time) time.Time {
	for _, value := range values {
		if !value.IsZero() {
			return value
		}
	}
	return time.Time{}
}
