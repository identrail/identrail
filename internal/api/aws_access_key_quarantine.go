package api

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	awsAccessKeyQuarantineCurrentIssue = 1534
	awsAccessKeyQuarantineVersion      = "aws-access-key-quarantine-planner-v1"
)

// AWSAccessKeyQuarantineRequest scopes read-only access-key quarantine planning
// to one AWS connector plus optional operator drill-down filters.
type AWSAccessKeyQuarantineRequest struct {
	ConnectorID     string `json:"connector_id,omitempty"`
	FixtureState    string `json:"fixture_state,omitempty"`
	AccountID       string `json:"account_id,omitempty"`
	Region          string `json:"region,omitempty"`
	Identity        string `json:"identity,omitempty"`
	QuarantineState string `json:"quarantine_state,omitempty"`
	Owner           string `json:"owner,omitempty"`
	Severity        string `json:"severity,omitempty"`
	Status          string `json:"status,omitempty"`
	ReadyForApply   string `json:"ready_for_apply,omitempty"`
	Search          string `json:"search,omitempty"`
}

type AWSAccessKeyQuarantineEvidence = AWSLeastPrivilegeEvidence
type AWSAccessKeyQuarantinePathStep = AWSLeastPrivilegePathStep
type AWSAccessKeyQuarantineDiagnostic = AWSLeastPrivilegeDiagnostic
type AWSAccessKeyQuarantineCoverageGap = AWSLeastPrivilegeCoverageGap

type AWSAccessKeyQuarantineOwnerNotice struct {
	Owner          string   `json:"owner"`
	Assigned       bool     `json:"assigned"`
	Notification   string   `json:"notification"`
	GracePeriod    string   `json:"grace_period"`
	RequiredActors []string `json:"required_actors,omitempty"`
	Instructions   []string `json:"instructions,omitempty"`
}

type AWSAccessKeyQuarantineTarget struct {
	RefType     string `json:"ref_type"`
	AccessKeyID string `json:"access_key_id,omitempty"`
	NodeID      string `json:"node_id,omitempty"`
	Principal   string `json:"principal,omitempty"`
	Label       string `json:"label"`
	MetadataRef string `json:"metadata_ref,omitempty"`
}

type AWSAccessKeyQuarantineStep struct {
	Order       int      `json:"order"`
	Phase       string   `json:"phase"`
	Action      string   `json:"action"`
	Actor       string   `json:"actor,omitempty"`
	EvidenceRef string   `json:"evidence_ref,omitempty"`
	BlocksOn    []string `json:"blocks_on,omitempty"`
}

type AWSAccessKeyQuarantineGate struct {
	Name      string `json:"name"`
	Status    string `json:"status"`
	Rationale string `json:"rationale"`
}

type AWSAccessKeyQuarantinePlan struct {
	PlanID             string                            `json:"plan_id"`
	CalculationVersion string                            `json:"calculation_version"`
	QuarantineState    string                            `json:"quarantine_state"`
	Severity           string                            `json:"severity"`
	Status             string                            `json:"status"`
	Score              int                               `json:"score"`
	Confidence         float64                           `json:"confidence"`
	Title              string                            `json:"title"`
	Summary            string                            `json:"summary"`
	AccountID          string                            `json:"account_id"`
	Region             string                            `json:"region"`
	OwnerNotice        AWSAccessKeyQuarantineOwnerNotice `json:"owner_notice"`
	SourceFindingIDs   []string                          `json:"source_finding_ids"`
	TargetAccessKeys   []AWSAccessKeyQuarantineTarget    `json:"target_access_keys"`
	AffectedPrincipals []AWSAccessKeyQuarantineTarget    `json:"affected_principals,omitempty"`
	LastUsedAt         time.Time                         `json:"last_used_at,omitzero"`
	DormantDays        int                               `json:"dormant_days"`
	GracePeriodDays    int                               `json:"grace_period_days"`
	QuarantineOrder    []AWSAccessKeyQuarantineStep      `json:"quarantine_order"`
	DiffIntent         AWSRemediationDiffIntent          `json:"diff_intent"`
	Tradeoffs          []AWSRemediationTradeoff          `json:"tradeoffs"`
	RollbackPlan       AWSRemediationRollbackPlan        `json:"rollback_plan"`
	VerificationPlan   AWSRemediationVerificationPlan    `json:"verification_plan"`
	ReadinessGates     []AWSAccessKeyQuarantineGate      `json:"readiness_gates"`
	ReadyForApply      bool                              `json:"ready_for_apply"`
	ReadOnlyProjection bool                              `json:"read_only_projection"`
	SourceSignals      []string                          `json:"source_signals"`
	Evidence           []AWSAccessKeyQuarantineEvidence  `json:"evidence"`
	EvidenceBoundary   string                            `json:"evidence_boundary"`
	ImpactedNodes      []string                          `json:"impacted_nodes"`
	ImpactedPath       []AWSAccessKeyQuarantinePathStep  `json:"impacted_path"`
	NextAction         string                            `json:"next_action"`
	CreatedAt          time.Time                         `json:"created_at"`
	UpdatedAt          time.Time                         `json:"updated_at"`
}

type AWSAccessKeyQuarantineRelationship struct {
	PlanID      string `json:"plan_id"`
	Type        string `json:"type"`
	FromNodeID  string `json:"from_node_id"`
	ToNodeID    string `json:"to_node_id"`
	EvidenceRef string `json:"evidence_ref,omitempty"`
}

type AWSAccessKeyQuarantineSummary struct {
	TotalPlans             int            `json:"total_plans"`
	FilteredPlans          int            `json:"filtered_plans"`
	QuarantineStateCounts  map[string]int `json:"quarantine_state_counts"`
	SeverityCounts         map[string]int `json:"severity_counts"`
	StatusCounts           map[string]int `json:"status_counts"`
	OwnerAssignedCount     int            `json:"owner_assigned_count"`
	OwnerlessCount         int            `json:"ownerless_count"`
	ReadyForApplyCount     int            `json:"ready_for_apply_count"`
	AccessKeyCount         int            `json:"access_key_count"`
	AffectedPrincipalCount int            `json:"affected_principal_count"`
	RelationshipCount      int            `json:"relationship_count"`
	HighestScore           int            `json:"highest_score"`
	AverageConfidencePct   int            `json:"average_confidence_pct"`
}

type AWSAccessKeyQuarantineResult struct {
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
	Summary            AWSAccessKeyQuarantineSummary        `json:"summary"`
	Plans              []AWSAccessKeyQuarantinePlan         `json:"plans"`
	Relationships      []AWSAccessKeyQuarantineRelationship `json:"relationships"`
	Caveats            []string                             `json:"caveats"`
	FailureReasons     []string                             `json:"failure_reasons"`
	RemediationHints   []string                             `json:"remediation_hints"`
	EvidenceLinks      []string                             `json:"evidence_links"`
	CoverageGaps       []AWSAccessKeyQuarantineCoverageGap  `json:"coverage_gaps"`
	Diagnostics        []AWSAccessKeyQuarantineDiagnostic   `json:"diagnostics"`
	GeneratedAt        time.Time                            `json:"generated_at"`
	UpdatedAt          time.Time                            `json:"updated_at"`
}

// GetAWSAccessKeyQuarantinePlans composes ranked, read-only disable/quarantine
// workflows for stale or risky access-key evidence. It never disables keys and
// never reads, returns, logs, or persists secret access-key material.
func (s *Service) GetAWSAccessKeyQuarantinePlans(ctx context.Context, workspaceID string, projectID string, request AWSAccessKeyQuarantineRequest) (AWSAccessKeyQuarantineResult, error) {
	project, scope, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return AWSAccessKeyQuarantineResult{}, err
	}
	connection, hasConnection, err := s.awsBaselineConnection(ctx, project, strings.TrimSpace(request.ConnectorID))
	if err != nil {
		return AWSAccessKeyQuarantineResult{}, err
	}
	fixtureState := normalizeAWSAccessKeyQuarantineFixtureState(request.FixtureState, connection, hasConnection)
	if fixtureState == "" {
		return AWSAccessKeyQuarantineResult{}, ErrInvalidAWSConnectionRequest
	}
	accountID := firstNonEmptyAWSValue(connection.AccountID, strings.TrimSpace(request.AccountID), "123456789012")
	region := firstNonEmptyAWSValue(connection.Region, strings.TrimSpace(request.Region), "us-east-1")
	connectorID := firstNonEmptyAWSValue(connection.ConnectorID, strings.TrimSpace(request.ConnectorID))
	sourceFixtureState := fixtureState
	if strings.TrimSpace(request.FixtureState) == "" && hasConnection && connection.Connected {
		sourceFixtureState = ""
	}

	dormant, err := s.GetAWSUnusedDormantAccessFindings(ctx, workspaceID, projectID, AWSUnusedDormantAccessRequest{
		ConnectorID:  connectorID,
		FixtureState: sourceFixtureState,
		AccountID:    request.AccountID,
		Region:       request.Region,
	})
	if err != nil {
		return AWSAccessKeyQuarantineResult{}, fmt.Errorf("access key quarantine dormant access: %w", err)
	}
	plans := awsAccessKeyQuarantinePlansFromDormant(dormant.Findings, dormant.GeneratedAt)
	sort.SliceStable(plans, func(i, j int) bool {
		if plans[i].Score == plans[j].Score {
			return plans[i].PlanID < plans[j].PlanID
		}
		return plans[i].Score > plans[j].Score
	})
	filtered, applied := filterAWSAccessKeyQuarantinePlans(plans, request)
	relationships := awsAccessKeyQuarantineRelationships(filtered)
	status, confidence := summarizeAWSAccessKeyQuarantineStatus(dormant.Status, filtered, dormant.Diagnostics)

	return AWSAccessKeyQuarantineResult{
		TenantID:           scope.TenantID,
		WorkspaceID:        project.WorkspaceID,
		ProjectID:          project.ProjectID,
		ConnectorID:        connectorID,
		AccountID:          accountID,
		Region:             region,
		ParentIssueNumber:  awsPlatformDependencyParentIssue,
		ParentIssueRef:     awsIssueRef(awsPlatformDependencyParentIssue),
		CurrentIssueNumber: awsAccessKeyQuarantineCurrentIssue,
		CurrentIssueRef:    awsIssueRef(awsAccessKeyQuarantineCurrentIssue),
		Version:            awsAccessKeyQuarantineVersion,
		Status:             status,
		FixtureState:       sourceFixtureState,
		Confidence:         confidence,
		CalculationVersion: awsAccessKeyQuarantineVersion,
		AppliedFilters:     applied,
		Summary:            summarizeAWSAccessKeyQuarantinePlans(plans, filtered, relationships),
		Plans:              filtered,
		Relationships:      relationships,
		Caveats:            awsAccessKeyQuarantineCaveats(dormant.Caveats),
		FailureReasons:     dormant.FailureReasons,
		RemediationHints:   awsAccessKeyQuarantineRemediationHints(dormant.RemediationHints),
		EvidenceLinks: dedupeStrings(append(dormant.EvidenceLinks,
			awsIssueURL(awsAccessKeyQuarantineCurrentIssue),
			"/docs/aws-access-key-quarantine-planner",
		)),
		CoverageGaps: awsAccessKeyQuarantineCoverageGaps(dormant.CoverageGaps),
		Diagnostics:  awsAccessKeyQuarantineDiagnostics(dormant.Diagnostics),
		GeneratedAt:  dormant.GeneratedAt,
		UpdatedAt:    dormant.UpdatedAt,
	}, nil
}

func normalizeAWSAccessKeyQuarantineFixtureState(requested string, connection AWSConnectionStatus, hasConnection bool) string {
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

func awsAccessKeyQuarantinePlansFromDormant(findings []AWSUnusedDormantAccessFinding, now time.Time) []AWSAccessKeyQuarantinePlan {
	plans := []AWSAccessKeyQuarantinePlan{}
	for _, finding := range findings {
		if !awsAccessKeyQuarantineFindingQualifies(finding) {
			continue
		}
		plans = append(plans, awsAccessKeyQuarantinePlanFromFinding(finding, now))
	}
	return plans
}

func awsAccessKeyQuarantineFindingQualifies(finding AWSUnusedDormantAccessFinding) bool {
	return awsAccessKeyQuarantineAccessKeyID(finding) != ""
}

func awsAccessKeyQuarantinePlanFromFinding(finding AWSUnusedDormantAccessFinding, now time.Time) AWSAccessKeyQuarantinePlan {
	evidenceRef := firstLeastPrivilegeEvidenceRef(finding.Evidence)
	owner := awsAccessKeyQuarantineOwner(finding)
	ownerAssigned := owner != "unassigned"
	state := awsAccessKeyQuarantineState(finding)
	graceDays := awsAccessKeyQuarantineGracePeriodDays(finding)
	accessKeyID := awsAccessKeyQuarantineAccessKeyID(finding)
	targetNodeID := finding.ResourceNodeID
	if targetNodeID == "" && accessKeyID != "" {
		targetNodeID = "aws:iam-access-key:" + accessKeyID
	}
	target := AWSAccessKeyQuarantineTarget{
		RefType:     "iam_access_key",
		AccessKeyID: accessKeyID,
		NodeID:      targetNodeID,
		Principal:   finding.PrincipalARN,
		Label:       firstNonEmptyAWSValue(accessKeyID, "access key reference"),
		MetadataRef: evidenceRef,
	}
	plan := AWSAccessKeyQuarantinePlan{
		PlanID:             "aws-access-key-quarantine:" + stableAWSBlastRadiusToken(finding.FindingID, accessKeyID, state),
		CalculationVersion: awsAccessKeyQuarantineVersion,
		QuarantineState:    state,
		Severity:           finding.Severity,
		Status:             awsAccessKeyQuarantineStatusFromFinding(finding),
		Score:              finding.Score,
		Confidence:         finding.Confidence,
		Title:              fmt.Sprintf("Access key quarantine: %s", firstNonEmptyAWSValue(accessKeyID, finding.DisplayName, finding.IdentityNodeID)),
		Summary:            fmt.Sprintf("%s Plan a read-only disable/quarantine workflow with owner notice, grace period, rollback, and verification before any live IAM change.", finding.Rationale),
		AccountID:          finding.AccountID,
		Region:             finding.Region,
		OwnerNotice:        awsAccessKeyQuarantineOwnerNotice(owner, ownerAssigned, graceDays, state),
		SourceFindingIDs:   []string{finding.FindingID, finding.RemediationCase.CaseID},
		TargetAccessKeys:   []AWSAccessKeyQuarantineTarget{target},
		AffectedPrincipals: []AWSAccessKeyQuarantineTarget{awsAccessKeyQuarantinePrincipalTarget(finding, evidenceRef)},
		LastUsedAt:         finding.LastUsedAt,
		DormantDays:        finding.DormantDays,
		GracePeriodDays:    graceDays,
		QuarantineOrder:    awsAccessKeyQuarantineOrder(owner, evidenceRef, graceDays),
		DiffIntent: AWSRemediationDiffIntent{
			Kind:               "access_key_quarantine",
			BeforeRef:          evidenceRef,
			AfterRef:           "quarantine://" + finding.FindingID + "/disable-after-grace",
			DiffSummary:        "Plan DisableAccessKey after owner notice and grace-period verification; no live key disable is performed by this endpoint.",
			ReadOnlyProjection: true,
		},
		Tradeoffs:          awsAccessKeyQuarantineTradeoffs(finding),
		RollbackPlan:       awsAccessKeyQuarantineRollback(evidenceRef),
		VerificationPlan:   awsAccessKeyQuarantineVerification(evidenceRef),
		ReadinessGates:     awsAccessKeyQuarantineReadinessGates(finding, ownerAssigned),
		ReadOnlyProjection: true,
		SourceSignals:      dedupeStrings(append([]string{"unused_dormant_access"}, finding.EvidenceSources()...)),
		Evidence:           finding.Evidence,
		EvidenceBoundary:   awsAccessKeyQuarantineEvidenceBoundary(),
		ImpactedNodes:      emptyStrings(dedupeStrings(append([]string{target.NodeID, finding.IdentityNodeID, finding.PrincipalARN}, finding.ImpactedNodes...))),
		ImpactedPath:       finding.ImpactedPath,
		NextAction:         "Notify the owner, wait through the grace window, verify no runtime use, then execute DisableAccessKey outside Identrail with linked evidence.",
		CreatedAt:          firstNonZeroAWSAccessKeyQuarantineTime(finding.CreatedAt, now),
		UpdatedAt:          firstNonZeroAWSAccessKeyQuarantineTime(finding.UpdatedAt, now),
	}
	plan.ReadyForApply = ownerAssigned && plan.Confidence >= 0.75 && plan.Status == "ready_for_quarantine" && finding.DormancyState != "unknown"
	for _, gate := range plan.ReadinessGates {
		if gate.Status == "blocked" {
			plan.ReadyForApply = false
		}
	}
	return plan
}

func (finding AWSUnusedDormantAccessFinding) EvidenceSources() []string {
	out := []string{}
	for _, evidence := range finding.Evidence {
		out = append(out, evidence.Source)
	}
	return out
}

func awsAccessKeyQuarantineOwner(finding AWSUnusedDormantAccessFinding) string {
	for _, step := range finding.ImpactedPath {
		if strings.Contains(strings.ToLower(step.Label), "owner:") {
			return strings.TrimSpace(strings.TrimPrefix(step.Label, "owner:"))
		}
	}
	if strings.TrimSpace(finding.OwnerContext) != "" && !strings.Contains(finding.OwnerContext, "review") {
		return finding.OwnerContext
	}
	return "unassigned"
}

func awsAccessKeyQuarantineState(finding AWSUnusedDormantAccessFinding) string {
	switch finding.DormancyState {
	case "never_used":
		return "disable_candidate"
	case "stale":
		return "quarantine_candidate"
	case "no_runtime_evidence":
		return "grace_period_required"
	default:
		return "needs_review"
	}
}

func awsAccessKeyQuarantineStatusFromFinding(finding AWSUnusedDormantAccessFinding) string {
	if finding.Status == "cleanup_candidate" && finding.Confidence >= 0.75 {
		return "ready_for_quarantine"
	}
	if finding.DormancyState == "unknown" || finding.Confidence < 0.7 {
		return "review"
	}
	return "pending_owner"
}

func awsAccessKeyQuarantineGracePeriodDays(finding AWSUnusedDormantAccessFinding) int {
	switch finding.DormancyState {
	case "never_used":
		return 3
	case "stale":
		return 7
	case "no_runtime_evidence":
		return 14
	default:
		return 0
	}
}

func awsAccessKeyQuarantineAccessKeyID(finding AWSUnusedDormantAccessFinding) string {
	candidates := []string{finding.ResourceNodeID, finding.ResourceARN, finding.DisplayName, finding.PolicyScope}
	candidates = append(candidates, finding.CandidateActions...)
	for _, evidence := range finding.Evidence {
		candidates = append(candidates, evidence.Label, evidence.EvidenceRef)
	}
	for _, candidate := range candidates {
		for _, token := range strings.FieldsFunc(candidate, func(r rune) bool {
			return r == '/' || r == ':' || r == '|' || r == ' ' || r == ',' || r == ';'
		}) {
			token = strings.TrimSpace(token)
			normalized := strings.ToUpper(token)
			if strings.HasPrefix(normalized, "AKIA") {
				return normalized
			}
		}
	}
	return ""
}

func awsAccessKeyQuarantinePrincipalTarget(finding AWSUnusedDormantAccessFinding, evidenceRef string) AWSAccessKeyQuarantineTarget {
	return AWSAccessKeyQuarantineTarget{
		RefType:     "iam_principal",
		NodeID:      finding.IdentityNodeID,
		Principal:   finding.PrincipalARN,
		Label:       firstNonEmptyAWSValue(finding.DisplayName, shortAWSARN(finding.PrincipalARN), finding.IdentityNodeID, "principal"),
		MetadataRef: evidenceRef,
	}
}

func awsAccessKeyQuarantineOwnerNotice(owner string, assigned bool, graceDays int, state string) AWSAccessKeyQuarantineOwnerNotice {
	return AWSAccessKeyQuarantineOwnerNotice{
		Owner:        owner,
		Assigned:     assigned,
		Notification: "owner_notification_required",
		GracePeriod:  fmt.Sprintf("P%dD", graceDays),
		RequiredActors: []string{
			"identity-owner",
			"security-reviewer",
			"platform-operator",
		},
		Instructions: []string{
			fmt.Sprintf("Notify %s and record acknowledgement before quarantine.", firstNonEmptyAWSValue(owner, "the owner")),
			fmt.Sprintf("Keep the key active for the %s window unless emergency severity is approved.", formatAWSBlastRadiusLabel(state)),
		},
	}
}

func awsAccessKeyQuarantineOrder(owner string, evidenceRef string, graceDays int) []AWSAccessKeyQuarantineStep {
	actor := firstNonEmptyAWSValue(owner, "identity-owner")
	return []AWSAccessKeyQuarantineStep{
		{Order: 1, Phase: "notify", Action: "Notify the owner and capture acknowledgement for the access-key quarantine plan.", Actor: actor, EvidenceRef: evidenceRef},
		{Order: 2, Phase: "grace_period", Action: fmt.Sprintf("Wait %d day(s) while monitoring runtime use and breakage signals.", graceDays), Actor: "security-reviewer", EvidenceRef: evidenceRef, BlocksOn: []string{"notify"}},
		{Order: 3, Phase: "dry_run", Action: "Confirm dependent workloads can run without the key using metadata-only evidence and owner attestation.", Actor: "platform-operator", EvidenceRef: evidenceRef, BlocksOn: []string{"grace_period"}},
		{Order: 4, Phase: "apply", Action: "Disable the access key in IAM outside Identrail after approval; this planner does not mutate AWS.", Actor: "platform-operator", EvidenceRef: evidenceRef, BlocksOn: []string{"dry_run"}},
		{Order: 5, Phase: "verify", Action: "Verify no AccessDenied or fallback use appears after disable; link CloudTrail and IAM last-used evidence.", Actor: "security-reviewer", EvidenceRef: evidenceRef, BlocksOn: []string{"apply"}},
	}
}

func awsAccessKeyQuarantineTradeoffs(finding AWSUnusedDormantAccessFinding) []AWSRemediationTradeoff {
	return []AWSRemediationTradeoff{
		{Dimension: "credential_exposure", Direction: "improves", Description: "Disabling the key removes a long-lived credential path after the grace window.", Severity: finding.Severity},
		{Dimension: "breakage_risk", Direction: "worsens", Description: "Any workload still using the key can fail after disable; owner notice and dry-run evidence reduce that risk.", Severity: "medium"},
		{Dimension: "auditability", Direction: "improves", Description: "The plan preserves evidence refs, owner acknowledgement, rollback, and verification steps before live mutation.", Severity: "low"},
	}
}

func awsAccessKeyQuarantineRollback(evidenceRef string) AWSRemediationRollbackPlan {
	return AWSRemediationRollbackPlan{
		Strategy:    "reactivate_access_key_or_swap_credential",
		Steps:       []string{"Re-enable the disabled access key only if emergency owner approval is recorded.", "Prefer issuing a new scoped credential and updating dependent workloads instead of leaving the old key active.", "Re-run runtime and IAM last-used evidence checks after rollback."},
		EvidenceRef: evidenceRef,
	}
}

func awsAccessKeyQuarantineVerification(evidenceRef string) AWSRemediationVerificationPlan {
	return AWSRemediationVerificationPlan{
		Strategy:       "quarantine_re_evaluate",
		Steps:          []string{"Confirm the key has no last-used or runtime activity during the grace period.", "After disable, check CloudTrail and workload telemetry for AccessDenied or fallback credential use.", "Attach owner acknowledgement, dry-run, apply, and verify evidence to the remediation case."},
		SuccessSignals: []string{"iam:last-used-none-after-disable", "cloudtrail:no-access-key-use", "owner:acknowledged-quarantine"},
		FailureSignals: []string{"cloudtrail:access-key-use-observed", "workload:credential-breakage", "owner:business-exception"},
		EvidenceRef:    evidenceRef,
	}
}

func awsAccessKeyQuarantineReadinessGates(finding AWSUnusedDormantAccessFinding, ownerAssigned bool) []AWSAccessKeyQuarantineGate {
	gates := []AWSAccessKeyQuarantineGate{
		{Name: "read_only_projection", Status: "passed", Rationale: "Plan contains metadata refs and never disables access keys directly."},
		{Name: "owner_notice", Status: awsAccessKeyQuarantineGateStatus(ownerAssigned), Rationale: "Owner notification and acknowledgement are required before quarantine."},
		{Name: "runtime_evidence", Status: awsAccessKeyQuarantineGateStatus(finding.DormancyState != "unknown"), Rationale: "Last-used or runtime evidence must be explicit before disable planning."},
	}
	if finding.Confidence < 0.7 {
		gates = append(gates, AWSAccessKeyQuarantineGate{Name: "confidence", Status: "blocked", Rationale: "Low-confidence evidence cannot become a ready quarantine plan."})
	}
	return gates
}

func awsAccessKeyQuarantineGateStatus(ok bool) string {
	if ok {
		return "passed"
	}
	return "blocked"
}

func filterAWSAccessKeyQuarantinePlans(plans []AWSAccessKeyQuarantinePlan, request AWSAccessKeyQuarantineRequest) ([]AWSAccessKeyQuarantinePlan, map[string]string) {
	filters := map[string]string{
		"account_id":       strings.TrimSpace(request.AccountID),
		"region":           strings.TrimSpace(request.Region),
		"identity":         strings.TrimSpace(request.Identity),
		"quarantine_state": normalizeAWSRuntimeEventFilterToken(request.QuarantineState),
		"owner":            normalizeAWSRuntimeEventFilterToken(request.Owner),
		"severity":         normalizeAWSRuntimeEventFilterToken(request.Severity),
		"status":           normalizeAWSRuntimeEventFilterToken(request.Status),
		"ready_for_apply":  strings.ToLower(strings.TrimSpace(request.ReadyForApply)),
		"search":           strings.TrimSpace(request.Search),
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
	filtered := make([]AWSAccessKeyQuarantinePlan, 0, len(plans))
	for _, plan := range plans {
		if filters["account_id"] != "" && filters["account_id"] != plan.AccountID {
			continue
		}
		if filters["region"] != "" && !strings.EqualFold(filters["region"], plan.Region) {
			continue
		}
		if filters["quarantine_state"] != "" && filters["quarantine_state"] != normalizeAWSRuntimeEventFilterToken(plan.QuarantineState) {
			continue
		}
		if filters["owner"] != "" && filters["owner"] != normalizeAWSRuntimeEventFilterToken(plan.OwnerNotice.Owner) {
			continue
		}
		if filters["severity"] != "" && filters["severity"] != normalizeAWSRuntimeEventFilterToken(plan.Severity) {
			continue
		}
		if filters["status"] != "" && filters["status"] != normalizeAWSRuntimeEventFilterToken(plan.Status) {
			continue
		}
		if filters["ready_for_apply"] != "" {
			want := filters["ready_for_apply"]
			if (want == "true" || want == "yes") != plan.ReadyForApply {
				continue
			}
		}
		if filters["identity"] != "" && !awsRuntimeEventMatchesAny(filters["identity"], awsAccessKeyQuarantineIdentityValues(plan)...) {
			continue
		}
		if filters["search"] != "" && !awsAccessKeyQuarantineSearchMatch(plan, filters["search"]) {
			continue
		}
		filtered = append(filtered, plan)
	}
	return filtered, applied
}

func awsAccessKeyQuarantineIdentityValues(plan AWSAccessKeyQuarantinePlan) []string {
	out := []string{}
	for _, target := range append(plan.TargetAccessKeys, plan.AffectedPrincipals...) {
		out = append(out, target.NodeID, target.Principal, target.Label, target.AccessKeyID)
	}
	out = append(out, plan.ImpactedNodes...)
	for _, step := range plan.ImpactedPath {
		out = append(out, step.NodeID, step.Label)
	}
	return dedupeStrings(out)
}

func awsAccessKeyQuarantineSearchMatch(plan AWSAccessKeyQuarantinePlan, needle string) bool {
	needle = strings.ToLower(strings.TrimSpace(needle))
	if needle == "" {
		return true
	}
	haystack := []string{
		plan.PlanID, plan.QuarantineState, plan.Status, plan.Title, plan.Summary, plan.OwnerNotice.Owner,
		plan.DiffIntent.DiffSummary, plan.RollbackPlan.Strategy, plan.VerificationPlan.Strategy, plan.NextAction,
	}
	haystack = append(haystack, plan.SourceFindingIDs...)
	haystack = append(haystack, plan.SourceSignals...)
	haystack = append(haystack, plan.RollbackPlan.Steps...)
	haystack = append(haystack, plan.VerificationPlan.Steps...)
	haystack = append(haystack, plan.VerificationPlan.SuccessSignals...)
	haystack = append(haystack, plan.VerificationPlan.FailureSignals...)
	for _, target := range append(plan.TargetAccessKeys, plan.AffectedPrincipals...) {
		haystack = append(haystack, target.RefType, target.AccessKeyID, target.NodeID, target.Principal, target.Label, target.MetadataRef)
	}
	for _, tradeoff := range plan.Tradeoffs {
		haystack = append(haystack, tradeoff.Dimension, tradeoff.Direction, tradeoff.Description, tradeoff.Severity)
	}
	for _, gate := range plan.ReadinessGates {
		haystack = append(haystack, gate.Name, gate.Status, gate.Rationale)
	}
	for _, step := range plan.QuarantineOrder {
		haystack = append(haystack, step.Phase, step.Action, step.Actor)
	}
	for _, evidence := range plan.Evidence {
		haystack = append(haystack, evidence.Source, evidence.EvidenceRef, evidence.Label, evidence.Relationship)
	}
	return strings.Contains(strings.ToLower(strings.Join(haystack, " ")), needle)
}

func awsAccessKeyQuarantineRelationships(plans []AWSAccessKeyQuarantinePlan) []AWSAccessKeyQuarantineRelationship {
	out := []AWSAccessKeyQuarantineRelationship{}
	for _, plan := range plans {
		evidenceRef := firstLeastPrivilegeEvidenceRef(plan.Evidence)
		for _, target := range plan.TargetAccessKeys {
			to := firstNonEmptyAWSValue(target.NodeID, target.AccessKeyID, target.Label)
			if to != "" {
				out = append(out, AWSAccessKeyQuarantineRelationship{PlanID: plan.PlanID, Type: "quarantine_targets_access_key", FromNodeID: plan.PlanID, ToNodeID: to, EvidenceRef: evidenceRef})
			}
		}
		for _, principal := range plan.AffectedPrincipals {
			to := firstNonEmptyAWSValue(principal.NodeID, principal.Principal, principal.Label)
			if to != "" {
				out = append(out, AWSAccessKeyQuarantineRelationship{PlanID: plan.PlanID, Type: "quarantine_notifies_principal_owner", FromNodeID: plan.PlanID, ToNodeID: to, EvidenceRef: evidenceRef})
			}
		}
	}
	return out
}

func summarizeAWSAccessKeyQuarantinePlans(all, filtered []AWSAccessKeyQuarantinePlan, relationships []AWSAccessKeyQuarantineRelationship) AWSAccessKeyQuarantineSummary {
	summary := AWSAccessKeyQuarantineSummary{
		TotalPlans:            len(all),
		FilteredPlans:         len(filtered),
		QuarantineStateCounts: map[string]int{},
		SeverityCounts:        map[string]int{},
		StatusCounts:          map[string]int{},
		RelationshipCount:     len(relationships),
	}
	confidenceTotal := 0.0
	for _, plan := range filtered {
		summary.QuarantineStateCounts[plan.QuarantineState]++
		summary.SeverityCounts[plan.Severity]++
		summary.StatusCounts[plan.Status]++
		if plan.OwnerNotice.Assigned {
			summary.OwnerAssignedCount++
		} else {
			summary.OwnerlessCount++
		}
		if plan.ReadyForApply {
			summary.ReadyForApplyCount++
		}
		summary.AccessKeyCount += len(plan.TargetAccessKeys)
		summary.AffectedPrincipalCount += len(plan.AffectedPrincipals)
		if plan.Score > summary.HighestScore {
			summary.HighestScore = plan.Score
		}
		confidenceTotal += plan.Confidence
	}
	if len(filtered) > 0 {
		summary.AverageConfidencePct = int((confidenceTotal/float64(len(filtered)))*100 + 0.5)
	}
	return summary
}

func summarizeAWSAccessKeyQuarantineStatus(sourceStatus string, filtered []AWSAccessKeyQuarantinePlan, diagnostics []AWSUnusedDormantAccessDiagnostic) (string, float64) {
	if sourceStatus == awsPlatformDependencyStatusBlocked {
		return awsPlatformDependencyStatusBlocked, 0
	}
	if len(filtered) == 0 || sourceStatus == awsPlatformDependencyStatusDegraded || len(diagnostics) > 0 {
		return awsPlatformDependencyStatusDegraded, 0.64
	}
	return awsPlatformDependencyStatusReady, 0.82
}

func awsAccessKeyQuarantineCaveats(source []string) []string {
	return dedupeStrings(append(source, "This planner never disables IAM access keys; it emits owner-notice, grace-period, rollback, and verification metadata only."))
}

func awsAccessKeyQuarantineRemediationHints(source []string) []string {
	return emptyStrings(dedupeStrings(append(source, "Use these plans to coordinate owner-approved DisableAccessKey execution outside Identrail, then link dry-run/apply/verify evidence to the remediation case.")))
}

func awsAccessKeyQuarantineCoverageGaps(source []AWSUnusedDormantAccessCoverageGap) []AWSAccessKeyQuarantineCoverageGap {
	out := []AWSAccessKeyQuarantineCoverageGap{{
		Capability:  "access_key_quarantine_execution",
		Status:      "planned",
		Reason:      "This issue emits non-mutating quarantine plans only; live DisableAccessKey execution is intentionally out of scope.",
		Remediation: "Use approved remediation/governance executors in a later wave to perform live IAM mutation.",
	}}
	for _, gap := range source {
		out = append(out, AWSAccessKeyQuarantineCoverageGap(gap))
	}
	return out
}

func awsAccessKeyQuarantineDiagnostics(source []AWSUnusedDormantAccessDiagnostic) []AWSAccessKeyQuarantineDiagnostic {
	out := make([]AWSAccessKeyQuarantineDiagnostic, 0, len(source))
	for _, diagnostic := range source {
		out = append(out, AWSAccessKeyQuarantineDiagnostic(diagnostic))
	}
	return out
}

func awsAccessKeyQuarantineEvidenceBoundary() string {
	return "metadata-only: access key IDs, IAM last-used/runtime refs, owner labels, and remediation case refs; no secret access key material, customer payloads, rendered policies, prompts, completions, database rows, or object contents."
}

func firstNonZeroAWSAccessKeyQuarantineTime(values ...time.Time) time.Time {
	for _, value := range values {
		if !value.IsZero() {
			return value
		}
	}
	return time.Time{}
}
