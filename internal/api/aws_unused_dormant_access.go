package api

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	awsUnusedDormantAccessCurrentIssue = 1523
	awsUnusedDormantAccessVersion      = "aws-unused-dormant-access-engine-v1"
)

// AWSUnusedDormantAccessRequest scopes the unused/dormant calculation to AWS
// evidence and optional operator drill-down filters.
type AWSUnusedDormantAccessRequest struct {
	ConnectorID   string `json:"connector_id,omitempty"`
	FixtureState  string `json:"fixture_state,omitempty"`
	AccountID     string `json:"account_id,omitempty"`
	Region        string `json:"region,omitempty"`
	Identity      string `json:"identity,omitempty"`
	Resource      string `json:"resource,omitempty"`
	Service       string `json:"service,omitempty"`
	Severity      string `json:"severity,omitempty"`
	Status        string `json:"status,omitempty"`
	DormancyState string `json:"dormancy_state,omitempty"`
}

type AWSUnusedDormantAccessEvidence = AWSLeastPrivilegeEvidence
type AWSUnusedDormantAccessPathStep = AWSLeastPrivilegePathStep
type AWSUnusedDormantAccessRemediationCasePreview = AWSLeastPrivilegeRemediationCasePreview

// AWSUnusedDormantAccessRelationship lets graph consumers join findings back to
// identity, resource, and evidence nodes.
type AWSUnusedDormantAccessRelationship struct {
	FindingID   string `json:"finding_id"`
	Type        string `json:"type"`
	FromNodeID  string `json:"from_node_id"`
	ToNodeID    string `json:"to_node_id"`
	EvidenceRef string `json:"evidence_ref"`
}

// AWSUnusedDormantAccessFinding is the persisted-record-shaped output for
// unused, dormant, no-runtime-evidence, and unknown access decisions.
type AWSUnusedDormantAccessFinding struct {
	FindingID          string                                       `json:"finding_id"`
	CalculationVersion string                                       `json:"calculation_version"`
	FindingType        string                                       `json:"finding_type"`
	DormancyState      string                                       `json:"dormancy_state"`
	Severity           string                                       `json:"severity"`
	Status             string                                       `json:"status"`
	Score              int                                          `json:"score"`
	Confidence         float64                                      `json:"confidence"`
	AccountID          string                                       `json:"account_id"`
	Region             string                                       `json:"region"`
	Service            string                                       `json:"service"`
	IdentityNodeID     string                                       `json:"identity_node_id"`
	PrincipalARN       string                                       `json:"principal_arn,omitempty"`
	ResourceNodeID     string                                       `json:"resource_node_id,omitempty"`
	ResourceARN        string                                       `json:"resource_arn,omitempty"`
	DisplayName        string                                       `json:"display_name"`
	OwnerContext       string                                       `json:"owner_context"`
	PolicyScope        string                                       `json:"policy_scope"`
	Rationale          string                                       `json:"rationale"`
	LastUsedAt         time.Time                                    `json:"last_used_at,omitzero"`
	DormantDays        int                                          `json:"dormant_days"`
	ScanWindowDays     int                                          `json:"scan_window_days"`
	CandidateActions   []string                                     `json:"candidate_actions,omitempty"`
	ObservedActions    []string                                     `json:"observed_actions,omitempty"`
	GrantedActions     []string                                     `json:"granted_actions,omitempty"`
	ImpactedNodes      []string                                     `json:"impacted_nodes"`
	ImpactedPath       []AWSUnusedDormantAccessPathStep             `json:"impacted_path"`
	Evidence           []AWSUnusedDormantAccessEvidence             `json:"evidence"`
	NextAction         string                                       `json:"next_action"`
	RemediationCase    AWSUnusedDormantAccessRemediationCasePreview `json:"remediation_case"`
	CreatedAt          time.Time                                    `json:"created_at"`
	UpdatedAt          time.Time                                    `json:"updated_at"`
}

type AWSUnusedDormantAccessSummary struct {
	TotalFindings            int            `json:"total_findings"`
	FilteredFindings         int            `json:"filtered_findings"`
	DormancyStateCounts      map[string]int `json:"dormancy_state_counts"`
	SeverityCounts           map[string]int `json:"severity_counts"`
	StatusCounts             map[string]int `json:"status_counts"`
	ServiceCounts            map[string]int `json:"service_counts"`
	CleanupCandidateCount    int            `json:"cleanup_candidate_count"`
	ReviewRequiredCount      int            `json:"review_required_count"`
	NoRuntimeEvidenceCount   int            `json:"no_runtime_evidence_count"`
	UnknownEvidenceCount     int            `json:"unknown_evidence_count"`
	StaleAccessCount         int            `json:"stale_access_count"`
	RelationshipCount        int            `json:"relationship_count"`
	HighestScore             int            `json:"highest_score"`
	AverageConfidencePct     int            `json:"average_confidence_pct"`
	RemediationPreviewCount  int            `json:"remediation_preview_count"`
	PermissionDeniedEvidence int            `json:"permission_denied_evidence_count"`
}

type AWSUnusedDormantAccessDiagnostic = AWSLeastPrivilegeDiagnostic
type AWSUnusedDormantAccessCoverageGap = AWSLeastPrivilegeCoverageGap

type AWSUnusedDormantAccessResult struct {
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
	Summary            AWSUnusedDormantAccessSummary        `json:"summary"`
	Findings           []AWSUnusedDormantAccessFinding      `json:"findings"`
	Relationships      []AWSUnusedDormantAccessRelationship `json:"relationships"`
	Caveats            []string                             `json:"caveats"`
	FailureReasons     []string                             `json:"failure_reasons"`
	RemediationHints   []string                             `json:"remediation_hints"`
	EvidenceLinks      []string                             `json:"evidence_links"`
	CoverageGaps       []AWSUnusedDormantAccessCoverageGap  `json:"coverage_gaps"`
	Diagnostics        []AWSUnusedDormantAccessDiagnostic   `json:"diagnostics"`
	GeneratedAt        time.Time                            `json:"generated_at"`
	UpdatedAt          time.Time                            `json:"updated_at"`
}

// GetAWSUnusedDormantAccessFindings calculates ranked read-only findings for
// never-used, stale, no-runtime-evidence, and unknown access states.
func (s *Service) GetAWSUnusedDormantAccessFindings(ctx context.Context, workspaceID string, projectID string, request AWSUnusedDormantAccessRequest) (AWSUnusedDormantAccessResult, error) {
	leastPrivilege, err := s.GetAWSLeastPrivilegeRecommendations(ctx, workspaceID, projectID, AWSLeastPrivilegeRequest{
		ConnectorID:  request.ConnectorID,
		FixtureState: request.FixtureState,
		AccountID:    request.AccountID,
		Region:       request.Region,
		Identity:     request.Identity,
		Resource:     request.Resource,
		Service:      request.Service,
		Severity:     request.Severity,
	})
	if err != nil {
		return AWSUnusedDormantAccessResult{}, err
	}

	findings := awsUnusedDormantFindingsFromRecommendations(leastPrivilege.Recommendations, leastPrivilege.GeneratedAt)
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Score == findings[j].Score {
			return findings[i].FindingID < findings[j].FindingID
		}
		return findings[i].Score > findings[j].Score
	})
	filtered, applied := filterAWSUnusedDormantAccessFindings(findings, request)
	relationships := awsUnusedDormantAccessRelationships(filtered)
	summary := summarizeAWSUnusedDormantAccess(findings, filtered, relationships)

	return AWSUnusedDormantAccessResult{
		TenantID:           leastPrivilege.TenantID,
		WorkspaceID:        leastPrivilege.WorkspaceID,
		ProjectID:          leastPrivilege.ProjectID,
		ConnectorID:        leastPrivilege.ConnectorID,
		AccountID:          leastPrivilege.AccountID,
		Region:             leastPrivilege.Region,
		ParentIssueNumber:  awsPlatformDependencyParentIssue,
		ParentIssueRef:     awsIssueRef(awsPlatformDependencyParentIssue),
		CurrentIssueNumber: awsUnusedDormantAccessCurrentIssue,
		CurrentIssueRef:    awsIssueRef(awsUnusedDormantAccessCurrentIssue),
		Version:            awsUnusedDormantAccessVersion,
		Status:             awsUnusedDormantAccessStatus(leastPrivilege.Status, filtered, leastPrivilege.Diagnostics),
		FixtureState:       leastPrivilege.FixtureState,
		Confidence:         leastPrivilege.Confidence,
		CalculationVersion: awsUnusedDormantAccessVersion,
		AppliedFilters:     applied,
		Summary:            summary,
		Findings:           filtered,
		Relationships:      relationships,
		Caveats:            awsUnusedDormantAccessCaveats(leastPrivilege.Caveats),
		FailureReasons:     leastPrivilege.FailureReasons,
		RemediationHints:   awsUnusedDormantAccessRemediationHints(leastPrivilege.RemediationHints),
		EvidenceLinks: dedupeStrings(append(leastPrivilege.EvidenceLinks,
			awsIssueURL(awsUnusedDormantAccessCurrentIssue),
			"/docs/aws-unused-dormant-access-engine",
		)),
		CoverageGaps: awsUnusedDormantAccessCoverageGaps(leastPrivilege.CoverageGaps),
		Diagnostics:  awsUnusedDormantAccessDiagnostics(leastPrivilege.Diagnostics),
		GeneratedAt:  leastPrivilege.GeneratedAt,
		UpdatedAt:    leastPrivilege.UpdatedAt,
	}, nil
}

func awsUnusedDormantFindingsFromRecommendations(recommendations []AWSLeastPrivilegeRecommendation, now time.Time) []AWSUnusedDormantAccessFinding {
	findings := []AWSUnusedDormantAccessFinding{}
	for _, recommendation := range recommendations {
		if !awsUnusedDormantRecommendationQualifies(recommendation) {
			continue
		}
		findings = append(findings, awsUnusedDormantFindingFromRecommendation(recommendation, now))
	}
	return findings
}

func awsUnusedDormantRecommendationQualifies(recommendation AWSLeastPrivilegeRecommendation) bool {
	recommendationType := normalizeAWSRuntimeEventFilterToken(recommendation.RecommendationType)
	if strings.Contains(recommendationType, "unused") || strings.Contains(recommendationType, "stale") || strings.Contains(recommendationType, "no-runtime") || strings.Contains(recommendationType, "dormant") {
		return true
	}
	if recommendation.Decision == "remove" && awsUnusedDormantRecommendationHasDormantEvidence(recommendation) {
		return true
	}
	return recommendation.Decision == "review" && recommendation.BreakagePrediction == "unknown" && awsUnusedDormantRecommendationHasDormantEvidence(recommendation)
}

func awsUnusedDormantRecommendationHasDormantEvidence(recommendation AWSLeastPrivilegeRecommendation) bool {
	for _, evidence := range recommendation.Evidence {
		relationship := normalizeAWSRuntimeEventFilterToken(evidence.Relationship)
		source := normalizeAWSRuntimeEventFilterToken(evidence.Source)
		switch {
		case strings.Contains(relationship, "unused"), strings.Contains(relationship, "stale"), strings.Contains(relationship, "no-runtime"):
			return true
		case relationship == "permission-denied" || relationship == "partial-failure" || relationship == "degraded" || relationship == "unsupported" || relationship == "unavailable":
			return true
		case source == "coverage-gap" || source == "runtime-evidence-gap":
			return true
		}
	}
	return false
}

func awsUnusedDormantFindingFromRecommendation(recommendation AWSLeastPrivilegeRecommendation, now time.Time) AWSUnusedDormantAccessFinding {
	state := awsUnusedDormantState(recommendation)
	findingType := "cleanup_candidate"
	status := "review"
	if state == "unknown" {
		findingType = "unknown_evidence"
		status = "review"
	} else if state == "stale" {
		findingType = "dormant_access"
	} else if state == "no_runtime_evidence" {
		findingType = "no_runtime_evidence"
	}
	if recommendation.Decision == "remove" && recommendation.BreakagePrediction == "low" {
		status = "cleanup_candidate"
	}

	observedAt := firstUnusedDormantObservedAt(recommendation.Evidence)
	dormantDays := 0
	if !observedAt.IsZero() {
		dormantDays = int(now.Sub(observedAt).Hours() / 24)
		if dormantDays < 0 {
			dormantDays = 0
		}
	}

	candidateActions := recommendation.RemoveActions
	if len(candidateActions) == 0 {
		candidateActions = recommendation.KeepActions
	}
	if len(candidateActions) == 0 {
		candidateActions = recommendation.GrantedActions
	}

	return AWSUnusedDormantAccessFinding{
		FindingID:          "aws-unused-dormant-access:" + stableAWSBlastRadiusToken(recommendation.RecommendationID, state),
		CalculationVersion: awsUnusedDormantAccessVersion,
		FindingType:        findingType,
		DormancyState:      state,
		Severity:           recommendation.Severity,
		Status:             status,
		Score:              recommendation.Score,
		Confidence:         recommendation.Confidence,
		AccountID:          recommendation.AccountID,
		Region:             recommendation.Region,
		Service:            recommendation.Service,
		IdentityNodeID:     recommendation.IdentityNodeID,
		PrincipalARN:       recommendation.PrincipalARN,
		ResourceNodeID:     recommendation.ResourceNodeID,
		ResourceARN:        recommendation.ResourceARN,
		DisplayName:        recommendation.DisplayName,
		OwnerContext:       awsUnusedDormantOwnerContext(recommendation),
		PolicyScope:        awsUnusedDormantPolicyScope(recommendation),
		Rationale:          awsUnusedDormantRationale(recommendation, state),
		LastUsedAt:         observedAt,
		DormantDays:        dormantDays,
		ScanWindowDays:     awsUnusedDormantScanWindowDays(state, dormantDays),
		CandidateActions:   dedupeStrings(candidateActions),
		ObservedActions:    recommendation.ObservedActions,
		GrantedActions:     recommendation.GrantedActions,
		ImpactedNodes:      recommendation.ImpactedNodes,
		ImpactedPath:       recommendation.ImpactedPath,
		Evidence:           recommendation.Evidence,
		NextAction:         awsUnusedDormantNextAction(recommendation, state),
		RemediationCase:    awsUnusedDormantRemediationCase(recommendation, state),
		CreatedAt:          recommendation.CreatedAt,
		UpdatedAt:          recommendation.UpdatedAt,
	}
}

func awsUnusedDormantState(recommendation AWSLeastPrivilegeRecommendation) string {
	recommendationType := normalizeAWSRuntimeEventFilterToken(recommendation.RecommendationType)
	if strings.Contains(recommendationType, "stale") || strings.Contains(recommendation.Rationale, "not used for") {
		return "stale"
	}
	for _, evidence := range recommendation.Evidence {
		relationship := normalizeAWSRuntimeEventFilterToken(evidence.Relationship)
		if strings.Contains(relationship, "unused") || strings.Contains(relationship, "declared-unused") {
			return "never_used"
		}
		if strings.Contains(relationship, "stale") {
			return "stale"
		}
	}
	if recommendation.Decision == "remove" {
		return "no_runtime_evidence"
	}
	return "unknown"
}

func awsUnusedDormantOwnerContext(recommendation AWSLeastPrivilegeRecommendation) string {
	if strings.Contains(strings.ToLower(recommendation.IdentityNodeID), "agent") || strings.EqualFold(recommendation.Service, "agent-runtime") {
		return "agent-owner-review"
	}
	if recommendation.ResourceARN != "" {
		return "resource-owner-review"
	}
	return "identity-owner-review"
}

func awsUnusedDormantPolicyScope(recommendation AWSLeastPrivilegeRecommendation) string {
	actions := dedupeStrings(append(append([]string{}, recommendation.RemoveActions...), recommendation.GrantedActions...))
	if len(actions) == 0 {
		actions = recommendation.KeepActions
	}
	if len(actions) == 0 {
		return awsLeastPrivilegeServiceAction(recommendation.Service)
	}
	return strings.Join(actions, ", ")
}

func awsUnusedDormantRationale(recommendation AWSLeastPrivilegeRecommendation, state string) string {
	switch state {
	case "never_used":
		return fmt.Sprintf("%s has granted %s access with no matching runtime evidence in the scoped evidence window.", recommendation.DisplayName, recommendation.Service)
	case "stale":
		return fmt.Sprintf("%s has stale %s activity and needs owner confirmation before cleanup.", recommendation.DisplayName, recommendation.Service)
	case "no_runtime_evidence":
		return fmt.Sprintf("%s has removable %s policy scope, but the finding is bounded to available metadata-only runtime evidence.", recommendation.DisplayName, recommendation.Service)
	default:
		return "Evidence is incomplete or degraded, so this access remains a review finding instead of a cleanup instruction."
	}
}

func awsUnusedDormantNextAction(recommendation AWSLeastPrivilegeRecommendation, state string) string {
	switch state {
	case "never_used", "no_runtime_evidence":
		if recommendation.Decision == "remove" && recommendation.BreakagePrediction == "low" {
			return "Create a read-only cleanup case, confirm owner approval, and verify policy scope before generating an IAM diff."
		}
		return "Confirm runtime coverage and owner context before turning this into a cleanup case."
	case "stale":
		return "Ask the owner to confirm whether stale access is still required before planning removal."
	default:
		return "Close the evidence gap before classifying this as unused or dormant access."
	}
}

func awsUnusedDormantRemediationCase(recommendation AWSLeastPrivilegeRecommendation, state string) AWSUnusedDormantAccessRemediationCasePreview {
	preview := recommendation.RemediationCase
	preview.CaseID = "aws-unused-dormant-preview:" + stableAWSBlastRadiusToken(recommendation.RecommendationID, state)
	preview.Title = fmt.Sprintf("%s dormant-access %s", formatAWSBlastRadiusLabel(state), recommendation.Decision)
	if state == "unknown" {
		preview.RecommendedAction = "Create a review case; do not generate cleanup changes until evidence coverage is restored."
		preview.ApprovalRequired = true
		preview.BreakagePrediction = "unknown"
	}
	preview.ReadOnlyProjection = true
	return preview
}

func firstUnusedDormantObservedAt(evidence []AWSUnusedDormantAccessEvidence) time.Time {
	var latest time.Time
	for _, item := range evidence {
		if item.ObservedAt.After(latest) {
			latest = item.ObservedAt
		}
	}
	return latest
}

func awsUnusedDormantScanWindowDays(state string, dormantDays int) int {
	if dormantDays > 0 {
		return dormantDays
	}
	if state == "unknown" {
		return 0
	}
	return 90
}

func filterAWSUnusedDormantAccessFindings(findings []AWSUnusedDormantAccessFinding, request AWSUnusedDormantAccessRequest) ([]AWSUnusedDormantAccessFinding, map[string]string) {
	filters := map[string]string{
		"account_id":     strings.TrimSpace(request.AccountID),
		"region":         strings.TrimSpace(request.Region),
		"identity":       strings.TrimSpace(request.Identity),
		"resource":       strings.TrimSpace(request.Resource),
		"service":        normalizeAWSRuntimeEventFilterToken(request.Service),
		"severity":       normalizeAWSRuntimeEventFilterToken(request.Severity),
		"status":         normalizeAWSRuntimeEventFilterToken(request.Status),
		"dormancy_state": normalizeAWSRuntimeEventFilterToken(request.DormancyState),
	}
	for key, value := range filters {
		token := strings.TrimSpace(value)
		if token == "" || strings.EqualFold(token, "all") {
			delete(filters, key)
		}
	}
	applied := map[string]string{}
	for key, value := range filters {
		applied[key] = value
	}
	filtered := make([]AWSUnusedDormantAccessFinding, 0, len(findings))
	for _, finding := range findings {
		if filters["account_id"] != "" && filters["account_id"] != finding.AccountID {
			continue
		}
		if filters["region"] != "" && !strings.EqualFold(filters["region"], finding.Region) {
			continue
		}
		if filters["service"] != "" && filters["service"] != normalizeAWSRuntimeEventFilterToken(finding.Service) {
			continue
		}
		if filters["severity"] != "" && filters["severity"] != normalizeAWSRuntimeEventFilterToken(finding.Severity) {
			continue
		}
		if filters["status"] != "" && filters["status"] != normalizeAWSRuntimeEventFilterToken(finding.Status) {
			continue
		}
		if filters["dormancy_state"] != "" && filters["dormancy_state"] != normalizeAWSRuntimeEventFilterToken(finding.DormancyState) {
			continue
		}
		if filters["identity"] != "" && !awsRuntimeEventMatchesAny(filters["identity"], awsUnusedDormantIdentityMatchValues(finding)...) {
			continue
		}
		if filters["resource"] != "" && !awsRuntimeEventMatchesAny(filters["resource"], awsUnusedDormantResourceMatchValues(finding)...) {
			continue
		}
		filtered = append(filtered, finding)
	}
	return filtered, applied
}

func awsUnusedDormantIdentityMatchValues(finding AWSUnusedDormantAccessFinding) []string {
	candidates := []string{finding.IdentityNodeID, finding.PrincipalARN, finding.DisplayName}
	for _, step := range finding.ImpactedPath {
		if strings.EqualFold(strings.TrimSpace(step.NodeType), "identity") {
			candidates = append(candidates, step.NodeID, step.Label)
		}
	}
	return dedupeStrings(candidates)
}

func awsUnusedDormantResourceMatchValues(finding AWSUnusedDormantAccessFinding) []string {
	candidates := []string{finding.ResourceNodeID, finding.ResourceARN}
	candidates = append(candidates, finding.ImpactedNodes...)
	for _, step := range finding.ImpactedPath {
		candidates = append(candidates, step.NodeID, step.Label)
	}
	return dedupeStrings(candidates)
}

func awsUnusedDormantAccessRelationships(findings []AWSUnusedDormantAccessFinding) []AWSUnusedDormantAccessRelationship {
	relationships := []AWSUnusedDormantAccessRelationship{}
	for _, finding := range findings {
		for i := 0; i+1 < len(finding.ImpactedPath); i++ {
			from := strings.TrimSpace(finding.ImpactedPath[i].NodeID)
			to := strings.TrimSpace(finding.ImpactedPath[i+1].NodeID)
			if from == "" || to == "" {
				continue
			}
			relationships = append(relationships, AWSUnusedDormantAccessRelationship{
				FindingID:   finding.FindingID,
				Type:        "unused_dormant_access_scope",
				FromNodeID:  from,
				ToNodeID:    to,
				EvidenceRef: firstLeastPrivilegeEvidenceRef(finding.Evidence),
			})
		}
	}
	return relationships
}

func summarizeAWSUnusedDormantAccess(allFindings []AWSUnusedDormantAccessFinding, filtered []AWSUnusedDormantAccessFinding, relationships []AWSUnusedDormantAccessRelationship) AWSUnusedDormantAccessSummary {
	stateCounts := map[string]int{}
	severityCounts := map[string]int{}
	statusCounts := map[string]int{}
	serviceCounts := map[string]int{}
	totalConfidence := 0.0
	highest := 0
	remediationCases := map[string]struct{}{}
	for _, finding := range allFindings {
		stateCounts[finding.DormancyState]++
		severityCounts[finding.Severity]++
		statusCounts[finding.Status]++
		serviceCounts[finding.Service]++
		totalConfidence += finding.Confidence
		if finding.Score > highest {
			highest = finding.Score
		}
		if finding.RemediationCase.CaseID != "" {
			remediationCases[finding.RemediationCase.CaseID] = struct{}{}
		}
	}
	averageConfidence := 0
	if len(allFindings) > 0 {
		averageConfidence = int((totalConfidence / float64(len(allFindings))) * 100)
	}
	return AWSUnusedDormantAccessSummary{
		TotalFindings:            len(allFindings),
		FilteredFindings:         len(filtered),
		DormancyStateCounts:      stateCounts,
		SeverityCounts:           severityCounts,
		StatusCounts:             statusCounts,
		ServiceCounts:            serviceCounts,
		CleanupCandidateCount:    statusCounts["cleanup_candidate"],
		ReviewRequiredCount:      statusCounts["review"],
		NoRuntimeEvidenceCount:   stateCounts["no_runtime_evidence"],
		UnknownEvidenceCount:     stateCounts["unknown"],
		StaleAccessCount:         stateCounts["stale"],
		RelationshipCount:        len(relationships),
		HighestScore:             highest,
		AverageConfidencePct:     averageConfidence,
		RemediationPreviewCount:  len(remediationCases),
		PermissionDeniedEvidence: statusCounts["permission-denied"],
	}
}

func awsUnusedDormantAccessStatus(sourceStatus string, filtered []AWSUnusedDormantAccessFinding, diagnostics []AWSLeastPrivilegeDiagnostic) string {
	if sourceStatus == awsPlatformDependencyStatusBlocked {
		return awsPlatformDependencyStatusBlocked
	}
	if len(filtered) == 0 || sourceStatus == awsPlatformDependencyStatusDegraded || len(diagnostics) > 0 {
		return awsPlatformDependencyStatusDegraded
	}
	return awsPlatformDependencyStatusReady
}

func awsUnusedDormantAccessCaveats(source []string) []string {
	return dedupeStrings(append(source, "Unknown, degraded, or permission-denied evidence remains a review state and never becomes a cleanup candidate."))
}

func awsUnusedDormantAccessRemediationHints(source []string) []string {
	return emptyStrings(dedupeStrings(append(source, "Use unused/dormant findings as read-only cleanup candidates until owner approval and IAM policy diff generation are available.")))
}

func awsUnusedDormantAccessCoverageGaps(source []AWSLeastPrivilegeCoverageGap) []AWSUnusedDormantAccessCoverageGap {
	out := []AWSUnusedDormantAccessCoverageGap{{
		Capability:  "unused_dormant_access_persistence",
		Status:      "ready",
		Reason:      "The API emits stable finding IDs, calculation version, dormant state, evidence, policy scope, owner context, and remediation preview fields for downstream persistence/graph consumers.",
		Remediation: "Persist these findings into the shared AWS intelligence store when the dedicated findings table lands.",
	}}
	for _, gap := range source {
		out = append(out, AWSUnusedDormantAccessCoverageGap(gap))
	}
	return out
}

func awsUnusedDormantAccessDiagnostics(source []AWSLeastPrivilegeDiagnostic) []AWSUnusedDormantAccessDiagnostic {
	out := make([]AWSUnusedDormantAccessDiagnostic, 0, len(source))
	for _, diagnostic := range source {
		out = append(out, AWSUnusedDormantAccessDiagnostic(diagnostic))
	}
	return out
}
