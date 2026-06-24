package api

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	awsIAMPolicyDiffCurrentIssue = 1530
	awsIAMPolicyDiffVersion      = "aws-iam-policy-least-privilege-diff-v1"
)

// AWSIAMPolicyDiffRequest scopes the deterministic IAM policy diff generator
// to one AWS connector plus optional operator drill-down filters.
type AWSIAMPolicyDiffRequest struct {
	ConnectorID   string `json:"connector_id,omitempty"`
	FixtureState  string `json:"fixture_state,omitempty"`
	AccountID     string `json:"account_id,omitempty"`
	Region        string `json:"region,omitempty"`
	Identity      string `json:"identity,omitempty"`
	Service       string `json:"service,omitempty"`
	Decision      string `json:"decision,omitempty"`
	Severity      string `json:"severity,omitempty"`
	Status        string `json:"status,omitempty"`
	BreakageLevel string `json:"breakage_level,omitempty"`
	ReadyForApply string `json:"ready_for_apply,omitempty"`
	Search        string `json:"search,omitempty"`
}

// AWSIAMPolicyDiffEvidence and path step reuse the least-privilege contract
// so the diff generator stays consistent with its upstream source.
type AWSIAMPolicyDiffEvidence = AWSLeastPrivilegeEvidence
type AWSIAMPolicyDiffPathStep = AWSLeastPrivilegePathStep
type AWSIAMPolicyDiffDiagnostic = AWSLeastPrivilegeDiagnostic
type AWSIAMPolicyDiffCoverageGap = AWSLeastPrivilegeCoverageGap

// AWSIAMPolicyStatementDiff is the projected before/after state of a single
// IAM policy statement. It carries only action/resource/condition refs and
// labels; the engine never inlines rendered policy bodies, secret values, or
// workload payloads.
type AWSIAMPolicyStatementDiff struct {
	StatementSID    string   `json:"statement_sid"`
	Effect          string   `json:"effect"`
	ChangeKind      string   `json:"change_kind"`
	RemovedActions  []string `json:"removed_actions,omitempty"`
	KeptActions     []string `json:"kept_actions,omitempty"`
	ResourceBefore  []string `json:"resource_before,omitempty"`
	ResourceAfter   []string `json:"resource_after,omitempty"`
	ConditionBefore []string `json:"condition_before,omitempty"`
	ConditionAfter  []string `json:"condition_after,omitempty"`
	Rationale       string   `json:"rationale"`
}

// AWSIAMPolicyDiffBreakageProjection describes the expected workload
// breakage of applying the diff. Levels are strictly bucketed.
type AWSIAMPolicyDiffBreakageProjection struct {
	Level     string   `json:"level"`
	Rationale string   `json:"rationale"`
	Signals   []string `json:"signals,omitempty"`
}

// AWSIAMPolicyDiffRollbackPlan describes how an applied diff is reverted.
type AWSIAMPolicyDiffRollbackPlan struct {
	Strategy    string   `json:"strategy"`
	Steps       []string `json:"steps"`
	EvidenceRef string   `json:"evidence_ref,omitempty"`
}

// AWSIAMPolicyDiffVerificationPlan describes how an applied diff is checked.
type AWSIAMPolicyDiffVerificationPlan struct {
	Strategy       string   `json:"strategy"`
	Steps          []string `json:"steps"`
	SuccessSignals []string `json:"success_signals,omitempty"`
	FailureSignals []string `json:"failure_signals,omitempty"`
	EvidenceRef    string   `json:"evidence_ref,omitempty"`
}

// AWSIAMPolicyDiffRelationship surfaces diff→graph node edges so the app
// and downstream graph consumers can show why a diff touches a node.
type AWSIAMPolicyDiffRelationship struct {
	DiffID      string `json:"diff_id"`
	Type        string `json:"type"`
	FromNodeID  string `json:"from_node_id"`
	ToNodeID    string `json:"to_node_id"`
	EvidenceRef string `json:"evidence_ref,omitempty"`
}

// AWSIAMPolicyDiff is the persisted-record-shaped contract emitted by the
// IAM policy least-privilege diff generator. It intentionally carries only
// statement/action/resource metadata refs and graph nodes; no rendered
// policy bodies, secret values, prompts, completions, tool payloads,
// browser pages, code-interpreter output, database rows, object contents,
// or customer payloads are inlined.
type AWSIAMPolicyDiff struct {
	DiffID                 string                             `json:"diff_id"`
	CalculationVersion     string                             `json:"calculation_version"`
	SourceRecommendationID string                             `json:"source_recommendation_id"`
	Decision               string                             `json:"decision"`
	Severity               string                             `json:"severity"`
	Status                 string                             `json:"status"`
	Score                  int                                `json:"score"`
	Confidence             float64                            `json:"confidence"`
	Title                  string                             `json:"title"`
	Summary                string                             `json:"summary"`
	AccountID              string                             `json:"account_id"`
	Region                 string                             `json:"region"`
	Service                string                             `json:"service,omitempty"`
	IdentityNodeID         string                             `json:"identity_node_id"`
	IdentityARN            string                             `json:"identity_arn,omitempty"`
	IdentityName           string                             `json:"identity_name,omitempty"`
	ResourceNodeID         string                             `json:"resource_node_id,omitempty"`
	ResourceARN            string                             `json:"resource_arn,omitempty"`
	StatementChanges       []AWSIAMPolicyStatementDiff        `json:"statement_changes"`
	RemovedActions         []string                           `json:"removed_actions,omitempty"`
	KeptActions            []string                           `json:"kept_actions,omitempty"`
	ObservedActions        []string                           `json:"observed_actions,omitempty"`
	GrantedActions         []string                           `json:"granted_actions,omitempty"`
	ResourceScopeBefore    []string                           `json:"resource_scope_before,omitempty"`
	ResourceScopeAfter     []string                           `json:"resource_scope_after,omitempty"`
	BreakageProjection     AWSIAMPolicyDiffBreakageProjection `json:"breakage_projection"`
	RollbackPlan           AWSIAMPolicyDiffRollbackPlan       `json:"rollback_plan"`
	VerificationPlan       AWSIAMPolicyDiffVerificationPlan   `json:"verification_plan"`
	ReadyForApply          bool                               `json:"ready_for_apply"`
	ReadOnlyProjection     bool                               `json:"read_only_projection"`
	SourceSignals          []string                           `json:"source_signals"`
	Evidence               []AWSIAMPolicyDiffEvidence         `json:"evidence"`
	EvidenceBoundary       string                             `json:"evidence_boundary"`
	ImpactedNodes          []string                           `json:"impacted_nodes"`
	ImpactedPath           []AWSIAMPolicyDiffPathStep         `json:"impacted_path"`
	NextAction             string                             `json:"next_action"`
	CreatedAt              time.Time                          `json:"created_at"`
	UpdatedAt              time.Time                          `json:"updated_at"`
}

// AWSIAMPolicyDiffSummary aggregates the unfiltered and filtered diff set.
type AWSIAMPolicyDiffSummary struct {
	TotalDiffs           int            `json:"total_diffs"`
	FilteredDiffs        int            `json:"filtered_diffs"`
	DecisionCounts       map[string]int `json:"decision_counts"`
	SeverityCounts       map[string]int `json:"severity_counts"`
	StatusCounts         map[string]int `json:"status_counts"`
	BreakageLevelCounts  map[string]int `json:"breakage_level_counts"`
	ServiceCounts        map[string]int `json:"service_counts"`
	RemovedActionCount   int            `json:"removed_action_count"`
	KeptActionCount      int            `json:"kept_action_count"`
	StatementChangeCount int            `json:"statement_change_count"`
	ReadyForApplyCount   int            `json:"ready_for_apply_count"`
	ManualReviewCount    int            `json:"manual_review_count"`
	NoOpCount            int            `json:"no_op_count"`
	RelationshipCount    int            `json:"relationship_count"`
	HighestScore         int            `json:"highest_score"`
	AverageConfidencePct int            `json:"average_confidence_pct"`
}

// AWSIAMPolicyDiffResult is the deterministic diff-generator envelope.
type AWSIAMPolicyDiffResult struct {
	TenantID           string                         `json:"tenant_id"`
	WorkspaceID        string                         `json:"workspace_id"`
	ProjectID          string                         `json:"project_id"`
	ConnectorID        string                         `json:"connector_id,omitempty"`
	AccountID          string                         `json:"account_id,omitempty"`
	Region             string                         `json:"region,omitempty"`
	ParentIssueNumber  int                            `json:"parent_issue_number"`
	ParentIssueRef     string                         `json:"parent_issue_ref"`
	CurrentIssueNumber int                            `json:"current_issue_number"`
	CurrentIssueRef    string                         `json:"current_issue_ref"`
	Version            string                         `json:"version"`
	Status             string                         `json:"status"`
	FixtureState       string                         `json:"fixture_state,omitempty"`
	Confidence         float64                        `json:"confidence"`
	CalculationVersion string                         `json:"calculation_version"`
	AppliedFilters     map[string]string              `json:"applied_filters"`
	Summary            AWSIAMPolicyDiffSummary        `json:"summary"`
	Diffs              []AWSIAMPolicyDiff             `json:"diffs"`
	Relationships      []AWSIAMPolicyDiffRelationship `json:"relationships"`
	Caveats            []string                       `json:"caveats"`
	FailureReasons     []string                       `json:"failure_reasons"`
	RemediationHints   []string                       `json:"remediation_hints"`
	EvidenceLinks      []string                       `json:"evidence_links"`
	CoverageGaps       []AWSIAMPolicyDiffCoverageGap  `json:"coverage_gaps"`
	Diagnostics        []AWSIAMPolicyDiffDiagnostic   `json:"diagnostics"`
	GeneratedAt        time.Time                      `json:"generated_at"`
	UpdatedAt          time.Time                      `json:"updated_at"`
}

type awsIAMPolicyDiffSources struct {
	least AWSLeastPrivilegeResult
}

// GetAWSIAMPolicyDiffs composes ranked IAM policy least-privilege diffs from
// least-privilege recommendations. The engine is read-only: it never mutates
// AWS, never reads or returns rendered policy bodies, secret values, or
// workload payloads, and treats unknown or denied evidence as explicit
// states instead of deterministic truth.
func (s *Service) GetAWSIAMPolicyDiffs(ctx context.Context, workspaceID string, projectID string, request AWSIAMPolicyDiffRequest) (AWSIAMPolicyDiffResult, error) {
	project, scope, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return AWSIAMPolicyDiffResult{}, err
	}
	connection, hasConnection, err := s.awsBaselineConnection(ctx, project, strings.TrimSpace(request.ConnectorID))
	if err != nil {
		return AWSIAMPolicyDiffResult{}, err
	}
	now := s.Now().UTC()
	fixtureState := normalizeAWSIAMPolicyDiffFixtureState(request.FixtureState, connection, hasConnection)
	if fixtureState == "" {
		return AWSIAMPolicyDiffResult{}, ErrInvalidAWSConnectionRequest
	}

	accountID := firstNonEmptyAWSValue(connection.AccountID, strings.TrimSpace(request.AccountID), "123456789012")
	region := firstNonEmptyAWSValue(connection.Region, strings.TrimSpace(request.Region), "us-east-1")
	connectorID := firstNonEmptyAWSValue(connection.ConnectorID, strings.TrimSpace(request.ConnectorID))
	sourceFixtureState := fixtureState
	if strings.TrimSpace(request.FixtureState) == "" && hasConnection && connection.Connected {
		sourceFixtureState = ""
	}

	sources, err := s.awsIAMPolicyDiffSourceSignals(ctx, workspaceID, projectID, connectorID, sourceFixtureState)
	if err != nil {
		return AWSIAMPolicyDiffResult{}, err
	}
	diffs := awsIAMPolicyDiffs(sources, now)
	sort.SliceStable(diffs, func(i, j int) bool {
		if diffs[i].Score == diffs[j].Score {
			return diffs[i].DiffID < diffs[j].DiffID
		}
		return diffs[i].Score > diffs[j].Score
	})
	filtered, applied := filterAWSIAMPolicyDiffs(diffs, request)
	relationships := awsIAMPolicyDiffRelationships(filtered)
	diagnostics := awsIAMPolicyDiffDiagnostics(sources)
	coverageGaps := awsIAMPolicyDiffCoverageGaps(sources)
	status, confidence := summarizeAWSIAMPolicyDiffStatus(sources, filtered, diagnostics)

	return AWSIAMPolicyDiffResult{
		TenantID:           scope.TenantID,
		WorkspaceID:        project.WorkspaceID,
		ProjectID:          project.ProjectID,
		ConnectorID:        connectorID,
		AccountID:          accountID,
		Region:             region,
		ParentIssueNumber:  awsPlatformDependencyParentIssue,
		ParentIssueRef:     awsIssueRef(awsPlatformDependencyParentIssue),
		CurrentIssueNumber: awsIAMPolicyDiffCurrentIssue,
		CurrentIssueRef:    awsIssueRef(awsIAMPolicyDiffCurrentIssue),
		Version:            awsIAMPolicyDiffVersion,
		Status:             status,
		FixtureState:       sourceFixtureState,
		Confidence:         confidence,
		CalculationVersion: awsIAMPolicyDiffVersion,
		AppliedFilters:     applied,
		Summary:            summarizeAWSIAMPolicyDiffs(diffs, filtered, relationships),
		Diffs:              filtered,
		Relationships:      relationships,
		Caveats:            awsIAMPolicyDiffCaveats(),
		FailureReasons:     awsIAMPolicyDiffFailureReasons(sources),
		RemediationHints:   awsIAMPolicyDiffRemediationHints(sources),
		EvidenceLinks: dedupeStrings([]string{
			awsIssueURL(awsPlatformDependencyParentIssue),
			awsIssueURL(awsIAMPolicyDiffCurrentIssue),
			awsIssueURL(awsLeastPrivilegeCurrentIssue),
			awsIssueURL(awsRemediationCaseCurrentIssue),
			"/docs/aws-iam-policy-least-privilege-diff",
			"/docs/aws-least-privilege",
			"/docs/aws-remediation-case-model",
			awsBaselineProjectEvidenceURL(scope, project),
		}),
		CoverageGaps: coverageGaps,
		Diagnostics:  diagnostics,
		GeneratedAt:  now,
		UpdatedAt:    now,
	}, nil
}

func normalizeAWSIAMPolicyDiffFixtureState(requested string, connection AWSConnectionStatus, hasConnection bool) string {
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

func (s *Service) awsIAMPolicyDiffSourceSignals(ctx context.Context, workspaceID, projectID, connectorID, fixtureState string) (awsIAMPolicyDiffSources, error) {
	least, err := s.GetAWSLeastPrivilegeRecommendations(ctx, workspaceID, projectID, AWSLeastPrivilegeRequest{ConnectorID: connectorID, FixtureState: fixtureState})
	if err != nil {
		return awsIAMPolicyDiffSources{}, fmt.Errorf("iam policy diff least privilege: %w", err)
	}
	return awsIAMPolicyDiffSources{least: least}, nil
}

func awsIAMPolicyDiffs(sources awsIAMPolicyDiffSources, now time.Time) []AWSIAMPolicyDiff {
	diffs := []AWSIAMPolicyDiff{}
	for _, recommendation := range sources.least.Recommendations {
		if d, ok := awsIAMPolicyDiffFromRecommendation(recommendation, now); ok {
			diffs = append(diffs, d)
		}
	}
	return diffs
}

func awsIAMPolicyDiffFromRecommendation(recommendation AWSLeastPrivilegeRecommendation, now time.Time) (AWSIAMPolicyDiff, bool) {
	if recommendation.RecommendationID == "" || recommendation.Decision == "keep" {
		return AWSIAMPolicyDiff{}, false
	}
	diffID := "aws-iam-policy-diff:" + stableAWSBlastRadiusToken("least-privilege", recommendation.RecommendationID)
	evidenceRef := firstString(awsIAMPolicyDiffEvidenceRefs(recommendation.Evidence))
	resourceBefore := awsIAMPolicyDiffResourceScope(recommendation, "before")
	resourceAfter := awsIAMPolicyDiffResourceScope(recommendation, "after")
	statementChanges := awsIAMPolicyStatementChanges(recommendation, resourceBefore, resourceAfter)
	breakage := awsIAMPolicyDiffBreakage(recommendation)
	rollback := awsIAMPolicyDiffRollback(recommendation, evidenceRef)
	verification := awsIAMPolicyDiffVerification(recommendation, evidenceRef)
	readyForApply := awsIAMPolicyDiffReadyForApply(recommendation, breakage)
	title := awsIAMPolicyDiffTitle(recommendation)
	d := AWSIAMPolicyDiff{
		DiffID:                 diffID,
		CalculationVersion:     awsIAMPolicyDiffVersion,
		SourceRecommendationID: recommendation.RecommendationID,
		Decision:               recommendation.Decision,
		Severity:               recommendation.Severity,
		Status:                 recommendation.Status,
		Score:                  recommendation.Score,
		Confidence:             recommendation.Confidence,
		Title:                  title,
		Summary:                recommendation.Rationale,
		AccountID:              recommendation.AccountID,
		Region:                 recommendation.Region,
		Service:                recommendation.Service,
		IdentityNodeID:         recommendation.IdentityNodeID,
		IdentityARN:            recommendation.PrincipalARN,
		IdentityName:           recommendation.DisplayName,
		ResourceNodeID:         recommendation.ResourceNodeID,
		ResourceARN:            recommendation.ResourceARN,
		StatementChanges:       statementChanges,
		RemovedActions:         dedupeStrings(recommendation.RemoveActions),
		KeptActions:            dedupeStrings(recommendation.KeepActions),
		ObservedActions:        dedupeStrings(recommendation.ObservedActions),
		GrantedActions:         dedupeStrings(recommendation.GrantedActions),
		ResourceScopeBefore:    resourceBefore,
		ResourceScopeAfter:     resourceAfter,
		BreakageProjection:     breakage,
		RollbackPlan:           rollback,
		VerificationPlan:       verification,
		ReadyForApply:          readyForApply,
		ReadOnlyProjection:     true,
		SourceSignals:          []string{"least_privilege"},
		Evidence:               recommendation.Evidence,
		EvidenceBoundary:       awsIAMPolicyDiffEvidenceBoundary(),
		ImpactedNodes:          emptyStrings(dedupeStrings(append([]string{recommendation.IdentityNodeID, recommendation.ResourceNodeID}, recommendation.ImpactedNodes...))),
		ImpactedPath:           recommendation.ImpactedPath,
		NextAction:             recommendation.NextAction,
		CreatedAt:              now,
		UpdatedAt:              now,
	}
	return d, true
}

func awsIAMPolicyDiffResourceScope(recommendation AWSLeastPrivilegeRecommendation, phase string) []string {
	if phase == "before" {
		return dedupeStrings(emptyStrings([]string{recommendation.ResourceARN, recommendation.ResourceNodeID}))
	}
	if recommendation.Decision == "remove" && len(recommendation.KeepActions) == 0 {
		return []string{}
	}
	return dedupeStrings(emptyStrings([]string{recommendation.ResourceARN, recommendation.ResourceNodeID}))
}

func awsIAMPolicyStatementChanges(recommendation AWSLeastPrivilegeRecommendation, resourceBefore, resourceAfter []string) []AWSIAMPolicyStatementDiff {
	switch recommendation.Decision {
	case "remove":
		statement := AWSIAMPolicyStatementDiff{
			StatementSID:   "least-privilege-projection",
			Effect:         "Allow",
			ChangeKind:     "scope_removed",
			RemovedActions: dedupeStrings(recommendation.RemoveActions),
			KeptActions:    dedupeStrings(recommendation.KeepActions),
			ResourceBefore: resourceBefore,
			ResourceAfter:  resourceAfter,
			Rationale:      fmt.Sprintf("Remove %d unused action(s) and keep %d observed action(s) on %s.", len(recommendation.RemoveActions), len(recommendation.KeepActions), recommendation.DisplayName),
		}
		if len(recommendation.KeepActions) == 0 {
			statement.ChangeKind = "statement_removed"
			statement.Rationale = fmt.Sprintf("All %d granted action(s) on %s are unused; remove the statement entirely.", len(recommendation.RemoveActions), recommendation.DisplayName)
		}
		return []AWSIAMPolicyStatementDiff{statement}
	case "review":
		return []AWSIAMPolicyStatementDiff{{
			StatementSID:   "least-privilege-projection",
			Effect:         "Allow",
			ChangeKind:     "manual_review",
			KeptActions:    dedupeStrings(recommendation.KeepActions),
			ResourceBefore: resourceBefore,
			ResourceAfter:  resourceBefore,
			Rationale:      fmt.Sprintf("Least-privilege evidence on %s is not yet conclusive; no statement-level diff is projected.", recommendation.DisplayName),
		}}
	}
	return nil
}

func awsIAMPolicyDiffBreakage(recommendation AWSLeastPrivilegeRecommendation) AWSIAMPolicyDiffBreakageProjection {
	level := strings.ToLower(strings.TrimSpace(recommendation.BreakagePrediction))
	switch level {
	case "low", "medium", "high":
	case "":
		level = "unknown"
	default:
		level = "unknown"
	}
	signals := []string{}
	if len(recommendation.ObservedActions) > 0 {
		signals = append(signals, fmt.Sprintf("observed_actions:%d", len(recommendation.ObservedActions)))
	}
	if len(recommendation.RemoveActions) > 0 {
		signals = append(signals, fmt.Sprintf("removed_actions:%d", len(recommendation.RemoveActions)))
	}
	if len(recommendation.KeepActions) > 0 {
		signals = append(signals, fmt.Sprintf("kept_actions:%d", len(recommendation.KeepActions)))
	}
	if recommendation.Decision == "review" {
		level = "unknown"
	}
	rationale := recommendation.BreakageRationale
	if strings.TrimSpace(rationale) == "" {
		switch level {
		case "low":
			rationale = "Removed actions have no observed callers in the runtime evidence window."
		case "medium":
			rationale = "Some removed actions match infrequently observed callers; confirm before apply."
		case "high":
			rationale = "Removed actions overlap with recently observed callers; expect breakage."
		default:
			rationale = "Runtime evidence is incomplete; manual breakage review required before apply."
		}
	}
	return AWSIAMPolicyDiffBreakageProjection{
		Level:     level,
		Rationale: rationale,
		Signals:   signals,
	}
}

func awsIAMPolicyDiffRollback(recommendation AWSLeastPrivilegeRecommendation, evidenceRef string) AWSIAMPolicyDiffRollbackPlan {
	if recommendation.Decision == "review" {
		return AWSIAMPolicyDiffRollbackPlan{
			Strategy:    "manual_review",
			Steps:       []string{"No projected diff to roll back; rerun least-privilege after evidence settles."},
			EvidenceRef: evidenceRef,
		}
	}
	return AWSIAMPolicyDiffRollbackPlan{
		Strategy:    "re_attach_policy",
		Steps:       []string{"Re-attach the captured before_ref policy statement.", "Re-run least-privilege to confirm scope returned."},
		EvidenceRef: evidenceRef,
	}
}

func awsIAMPolicyDiffVerification(recommendation AWSLeastPrivilegeRecommendation, evidenceRef string) AWSIAMPolicyDiffVerificationPlan {
	if recommendation.Decision == "review" {
		return AWSIAMPolicyDiffVerificationPlan{
			Strategy:    "manual_review",
			Steps:       []string{"Least-privilege evidence is inconclusive; no projected diff to simulate.", "Re-run least-privilege after upstream evidence settles into a remove/keep decision."},
			EvidenceRef: evidenceRef,
		}
	}
	return AWSIAMPolicyDiffVerificationPlan{
		Strategy:       "policy_simulate",
		Steps:          []string{"Run IAM policy simulator against the kept actions to confirm no regression.", "Re-run least-privilege to confirm decision flips to keep."},
		SuccessSignals: []string{"policy_simulate:no-regression", "least_privilege:decision-keep"},
		FailureSignals: []string{"policy_simulate:denied-observed-action"},
		EvidenceRef:    evidenceRef,
	}
}

func awsIAMPolicyDiffReadyForApply(recommendation AWSLeastPrivilegeRecommendation, breakage AWSIAMPolicyDiffBreakageProjection) bool {
	if recommendation.Decision != "remove" {
		return false
	}
	if breakage.Level != "low" {
		return false
	}
	if recommendation.Confidence < 0.75 {
		return false
	}
	return true
}

func awsIAMPolicyDiffTitle(recommendation AWSLeastPrivilegeRecommendation) string {
	display := firstNonEmptyAWSValue(recommendation.DisplayName, recommendation.IdentityNodeID, "IAM identity")
	switch recommendation.Decision {
	case "remove":
		return fmt.Sprintf("Scope %s: remove %d action(s)", display, len(recommendation.RemoveActions))
	case "review":
		return fmt.Sprintf("Manual review for %s least-privilege diff", display)
	default:
		return fmt.Sprintf("Least-privilege diff for %s", display)
	}
}

func awsIAMPolicyDiffRelationships(diffs []AWSIAMPolicyDiff) []AWSIAMPolicyDiffRelationship {
	relationships := []AWSIAMPolicyDiffRelationship{}
	for _, d := range diffs {
		if d.IdentityNodeID == "" {
			continue
		}
		for _, target := range d.ImpactedNodes {
			if target == "" || target == d.IdentityNodeID {
				continue
			}
			relationships = append(relationships, AWSIAMPolicyDiffRelationship{
				DiffID:      d.DiffID,
				Type:        "iam_policy_diff_path",
				FromNodeID:  d.IdentityNodeID,
				ToNodeID:    target,
				EvidenceRef: firstString(awsIAMPolicyDiffEvidenceRefs(d.Evidence)),
			})
		}
	}
	return relationships
}

func summarizeAWSIAMPolicyDiffs(all, filtered []AWSIAMPolicyDiff, relationships []AWSIAMPolicyDiffRelationship) AWSIAMPolicyDiffSummary {
	summary := AWSIAMPolicyDiffSummary{
		TotalDiffs:          len(all),
		FilteredDiffs:       len(filtered),
		DecisionCounts:      map[string]int{},
		SeverityCounts:      map[string]int{},
		StatusCounts:        map[string]int{},
		BreakageLevelCounts: map[string]int{},
		ServiceCounts:       map[string]int{},
		RelationshipCount:   len(relationships),
	}
	confidenceTotal := 0.0
	for _, d := range filtered {
		summary.DecisionCounts[d.Decision]++
		summary.SeverityCounts[d.Severity]++
		summary.StatusCounts[d.Status]++
		summary.BreakageLevelCounts[d.BreakageProjection.Level]++
		if d.Service != "" {
			summary.ServiceCounts[d.Service]++
		}
		summary.RemovedActionCount += len(d.RemovedActions)
		summary.KeptActionCount += len(d.KeptActions)
		summary.StatementChangeCount += len(d.StatementChanges)
		if d.ReadyForApply {
			summary.ReadyForApplyCount++
		}
		if d.Decision == "review" {
			summary.ManualReviewCount++
		}
		if d.Decision == "remove" && len(d.RemovedActions) == 0 {
			summary.NoOpCount++
		}
		if d.Score > summary.HighestScore {
			summary.HighestScore = d.Score
		}
		confidenceTotal += d.Confidence
	}
	if len(filtered) > 0 {
		summary.AverageConfidencePct = int((confidenceTotal/float64(len(filtered)))*100 + 0.5)
	}
	return summary
}

func filterAWSIAMPolicyDiffs(diffs []AWSIAMPolicyDiff, request AWSIAMPolicyDiffRequest) ([]AWSIAMPolicyDiff, map[string]string) {
	filters := map[string]string{
		"account_id":      strings.TrimSpace(request.AccountID),
		"region":          strings.TrimSpace(request.Region),
		"identity":        strings.TrimSpace(request.Identity),
		"service":         strings.TrimSpace(request.Service),
		"decision":        normalizeAWSRuntimeEventFilterToken(request.Decision),
		"severity":        normalizeAWSRuntimeEventFilterToken(request.Severity),
		"status":          normalizeAWSRuntimeEventFilterToken(request.Status),
		"breakage_level":  normalizeAWSRuntimeEventFilterToken(request.BreakageLevel),
		"ready_for_apply": strings.ToLower(strings.TrimSpace(request.ReadyForApply)),
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
	filtered := make([]AWSIAMPolicyDiff, 0, len(diffs))
	for _, d := range diffs {
		if filters["account_id"] != "" && filters["account_id"] != d.AccountID {
			continue
		}
		if filters["region"] != "" && !strings.EqualFold(filters["region"], d.Region) {
			continue
		}
		if filters["service"] != "" && !strings.EqualFold(filters["service"], d.Service) {
			continue
		}
		if filters["decision"] != "" && filters["decision"] != normalizeAWSRuntimeEventFilterToken(d.Decision) {
			continue
		}
		if filters["severity"] != "" && filters["severity"] != normalizeAWSRuntimeEventFilterToken(d.Severity) {
			continue
		}
		if filters["status"] != "" && filters["status"] != normalizeAWSRuntimeEventFilterToken(d.Status) {
			continue
		}
		if filters["breakage_level"] != "" && filters["breakage_level"] != normalizeAWSRuntimeEventFilterToken(d.BreakageProjection.Level) {
			continue
		}
		if filters["ready_for_apply"] != "" {
			want := filters["ready_for_apply"]
			if (want == "true" || want == "yes") != d.ReadyForApply {
				continue
			}
		}
		if filters["identity"] != "" && !awsIAMPolicyDiffIdentityMatch(d, filters["identity"]) {
			continue
		}
		if filters["search"] != "" && !awsIAMPolicyDiffSearchMatch(d, filters["search"]) {
			continue
		}
		filtered = append(filtered, d)
	}
	return filtered, applied
}

func awsIAMPolicyDiffIdentityMatch(d AWSIAMPolicyDiff, needle string) bool {
	needle = strings.ToLower(strings.TrimSpace(needle))
	if needle == "" {
		return true
	}
	hay := strings.ToLower(strings.Join([]string{d.IdentityNodeID, d.IdentityARN, d.IdentityName}, " "))
	return strings.Contains(hay, needle)
}

func awsIAMPolicyDiffSearchMatch(d AWSIAMPolicyDiff, needle string) bool {
	needle = strings.ToLower(strings.TrimSpace(needle))
	if needle == "" {
		return true
	}
	values := []string{d.DiffID, d.Title, d.Summary, d.SourceRecommendationID, d.Service, d.Decision, d.Severity, d.Status, d.IdentityNodeID, d.IdentityARN, d.IdentityName, d.ResourceNodeID, d.ResourceARN, d.BreakageProjection.Level, d.BreakageProjection.Rationale, d.RollbackPlan.Strategy, d.RollbackPlan.EvidenceRef, d.VerificationPlan.Strategy, d.VerificationPlan.EvidenceRef, d.NextAction}
	values = append(values, d.RemovedActions...)
	values = append(values, d.KeptActions...)
	values = append(values, d.ObservedActions...)
	values = append(values, d.GrantedActions...)
	values = append(values, d.ResourceScopeBefore...)
	values = append(values, d.ResourceScopeAfter...)
	values = append(values, d.BreakageProjection.Signals...)
	values = append(values, d.RollbackPlan.Steps...)
	values = append(values, d.VerificationPlan.Steps...)
	values = append(values, d.VerificationPlan.SuccessSignals...)
	values = append(values, d.VerificationPlan.FailureSignals...)
	for _, statement := range d.StatementChanges {
		values = append(values, statement.StatementSID, statement.Effect, statement.ChangeKind, statement.Rationale)
		values = append(values, statement.RemovedActions...)
		values = append(values, statement.KeptActions...)
		values = append(values, statement.ResourceBefore...)
		values = append(values, statement.ResourceAfter...)
		values = append(values, statement.ConditionBefore...)
		values = append(values, statement.ConditionAfter...)
	}
	for _, evidence := range d.Evidence {
		values = append(values, evidence.Source, evidence.Label, evidence.EvidenceRef, evidence.Relationship)
	}
	for _, value := range values {
		if strings.Contains(strings.ToLower(value), needle) {
			return true
		}
	}
	return false
}

func summarizeAWSIAMPolicyDiffStatus(sources awsIAMPolicyDiffSources, filtered []AWSIAMPolicyDiff, diagnostics []AWSIAMPolicyDiffDiagnostic) (string, float64) {
	if sources.least.Status == awsPlatformDependencyStatusBlocked {
		return awsPlatformDependencyStatusBlocked, 0.35
	}
	for _, diagnostic := range diagnostics {
		if diagnostic.Retryable {
			return awsPlatformDependencyStatusDegraded, 0.72
		}
	}
	if sources.least.Status == awsPlatformDependencyStatusDegraded {
		return awsPlatformDependencyStatusDegraded, 0.76
	}
	if len(filtered) == 0 {
		return awsPlatformDependencyStatusReady, 0.82
	}
	return awsPlatformDependencyStatusReady, 0.9
}

func awsIAMPolicyDiffFailureReasons(sources awsIAMPolicyDiffSources) []string {
	return dedupeStrings(append([]string{}, sources.least.FailureReasons...))
}

func awsIAMPolicyDiffRemediationHints(sources awsIAMPolicyDiffSources) []string {
	out := []string{
		"Apply each diff only after the matching remediation case is approved; this engine is read-only and does not call any AWS write API.",
		"Pair each diff with its rollback and verification plan before scheduling execution.",
	}
	out = append(out, sources.least.RemediationHints...)
	return dedupeStrings(out)
}

func awsIAMPolicyDiffCaveats() []string {
	return []string{
		"IAM policy diffs are read-only projections; the engine never applies an AWS change.",
		"Statement diffs carry action, resource, and condition refs only — never rendered policy bodies, secret values, or workload payloads.",
		"ready_for_apply is derived deterministically from decision=remove + breakage_level=low + confidence >= 0.75; approval, execute, and verify transitions belong to future wave issues.",
	}
}

func awsIAMPolicyDiffDiagnostics(sources awsIAMPolicyDiffSources) []AWSIAMPolicyDiffDiagnostic {
	out := []AWSIAMPolicyDiffDiagnostic{}
	for _, d := range sources.least.Diagnostics {
		if strings.TrimSpace(d.Message) == "" && strings.TrimSpace(d.Code) == "" {
			continue
		}
		out = append(out, AWSIAMPolicyDiffDiagnostic{Collector: d.Collector, SourceID: d.SourceID, Code: d.Code, Message: d.Message, Remediation: d.Remediation, Retryable: d.Retryable})
	}
	return out
}

func awsIAMPolicyDiffCoverageGaps(sources awsIAMPolicyDiffSources) []AWSIAMPolicyDiffCoverageGap {
	out := []AWSIAMPolicyDiffCoverageGap{{
		Capability:  "iam_policy_apply",
		Status:      "out_of_scope",
		Reason:      "Issue #1530 implements the diff projection only; apply/verify transitions are future-wave work and never call IAM write APIs here.",
		Remediation: "Wire the approve/execute/verify endpoints in the relevant remediation/governance issue once the safety gates are in place.",
	}}
	for _, g := range sources.least.CoverageGaps {
		out = append(out, AWSIAMPolicyDiffCoverageGap{Capability: g.Capability, Status: g.Status, Reason: g.Reason, Remediation: g.Remediation})
	}
	return out
}

func awsIAMPolicyDiffEvidenceBoundary() string {
	return "metadata_only_no_rendered_policy_bodies_no_secret_values_no_workload_payloads"
}

func awsIAMPolicyDiffEvidenceRefs(evidence []AWSIAMPolicyDiffEvidence) []string {
	out := []string{}
	for _, item := range evidence {
		if strings.TrimSpace(item.EvidenceRef) != "" {
			out = append(out, item.EvidenceRef)
		}
	}
	return dedupeStrings(out)
}
