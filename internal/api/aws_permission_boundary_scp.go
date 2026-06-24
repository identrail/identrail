package api

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	awsPermissionBoundarySCPCurrentIssue = 1532
	awsPermissionBoundarySCPVersion      = "aws-permission-boundary-scp-planner-v1"

	awsPermissionBoundaryKind = "permission_boundary"
	awsSCPKind                = "scp"
)

// AWSPermissionBoundarySCPRequest scopes the deterministic permission
// boundary / SCP planner to one AWS connector plus optional operator
// drill-down filters.
type AWSPermissionBoundarySCPRequest struct {
	ConnectorID   string `json:"connector_id,omitempty"`
	FixtureState  string `json:"fixture_state,omitempty"`
	AccountID     string `json:"account_id,omitempty"`
	Region        string `json:"region,omitempty"`
	Service       string `json:"service,omitempty"`
	Kind          string `json:"kind,omitempty"`
	TargetScope   string `json:"target_scope,omitempty"`
	Severity      string `json:"severity,omitempty"`
	Status        string `json:"status,omitempty"`
	BreakageLevel string `json:"breakage_level,omitempty"`
	ReadyForApply string `json:"ready_for_apply,omitempty"`
	Search        string `json:"search,omitempty"`
}

// AWSPermissionBoundarySCPEvidence and path step reuse the least-privilege
// contract so the planner stays consistent with its upstream sources.
type AWSPermissionBoundarySCPEvidence = AWSLeastPrivilegeEvidence
type AWSPermissionBoundarySCPPathStep = AWSLeastPrivilegePathStep
type AWSPermissionBoundarySCPDiagnostic = AWSLeastPrivilegeDiagnostic
type AWSPermissionBoundarySCPCoverageGap = AWSLeastPrivilegeCoverageGap

// AWSPermissionBoundarySCPStatementSnippet labels the before/after policy
// statement without inlining a rendered policy body.
type AWSPermissionBoundarySCPStatementSnippet struct {
	StatementSID   string   `json:"statement_sid"`
	Effect         string   `json:"effect"`
	ChangeKind     string   `json:"change_kind"`
	BeforeRef      string   `json:"before_ref,omitempty"`
	AfterRef       string   `json:"after_ref,omitempty"`
	DeniedActions  []string `json:"denied_actions,omitempty"`
	AllowedActions []string `json:"allowed_actions,omitempty"`
	ResourceScope  []string `json:"resource_scope,omitempty"`
	ConditionKeys  []string `json:"condition_keys,omitempty"`
	Rationale      string   `json:"rationale"`
}

// AWSPermissionBoundarySCPBreakageProjection bucketed expectation for the
// workload breakage of applying the plan.
type AWSPermissionBoundarySCPBreakageProjection struct {
	Level              string   `json:"level"`
	Rationale          string   `json:"rationale"`
	AffectedIdentities int      `json:"affected_identities"`
	AffectedAccounts   int      `json:"affected_accounts"`
	AffectedOUs        int      `json:"affected_ous"`
	Signals            []string `json:"signals,omitempty"`
}

// AWSPermissionBoundarySCPRollbackPlan documents how an applied plan is
// reverted.
type AWSPermissionBoundarySCPRollbackPlan struct {
	Strategy    string   `json:"strategy"`
	Steps       []string `json:"steps"`
	EvidenceRef string   `json:"evidence_ref,omitempty"`
}

// AWSPermissionBoundarySCPVerificationPlan documents how an applied plan is
// checked.
type AWSPermissionBoundarySCPVerificationPlan struct {
	Strategy       string   `json:"strategy"`
	Steps          []string `json:"steps"`
	SuccessSignals []string `json:"success_signals,omitempty"`
	FailureSignals []string `json:"failure_signals,omitempty"`
	EvidenceRef    string   `json:"evidence_ref,omitempty"`
}

// AWSPermissionBoundarySCPRelationship surfaces plan→graph node edges.
type AWSPermissionBoundarySCPRelationship struct {
	PlanID      string `json:"plan_id"`
	Type        string `json:"type"`
	FromNodeID  string `json:"from_node_id"`
	ToNodeID    string `json:"to_node_id"`
	EvidenceRef string `json:"evidence_ref,omitempty"`
}

// AWSPermissionBoundarySCPPlan is the persisted-record-shaped contract
// emitted by the planner. It carries statement-level metadata refs and
// graph nodes only; no rendered policy bodies, secret values, prompts,
// completions, tool payloads, browser pages, code-interpreter output,
// database rows, object contents, customer payloads, or workload payloads
// are inlined.
type AWSPermissionBoundarySCPPlan struct {
	PlanID                string                                     `json:"plan_id"`
	CalculationVersion    string                                     `json:"calculation_version"`
	Kind                  string                                     `json:"kind"`
	TargetScope           string                                     `json:"target_scope"`
	Severity              string                                     `json:"severity"`
	Status                string                                     `json:"status"`
	Score                 int                                        `json:"score"`
	Confidence            float64                                    `json:"confidence"`
	Title                 string                                     `json:"title"`
	Summary               string                                     `json:"summary"`
	AccountID             string                                     `json:"account_id,omitempty"`
	Region                string                                     `json:"region,omitempty"`
	Service               string                                     `json:"service,omitempty"`
	TargetAccountIDs      []string                                   `json:"target_account_ids,omitempty"`
	TargetOUPaths         []string                                   `json:"target_ou_paths,omitempty"`
	TargetIdentityNodeIDs []string                                   `json:"target_identity_node_ids,omitempty"`
	PreventedBehavior     string                                     `json:"prevented_behavior"`
	SourceFindingIDs      []string                                   `json:"source_finding_ids"`
	StatementSnippets     []AWSPermissionBoundarySCPStatementSnippet `json:"statement_snippets"`
	BreakageProjection    AWSPermissionBoundarySCPBreakageProjection `json:"breakage_projection"`
	RollbackPlan          AWSPermissionBoundarySCPRollbackPlan       `json:"rollback_plan"`
	VerificationPlan      AWSPermissionBoundarySCPVerificationPlan   `json:"verification_plan"`
	ReadyForApply         bool                                       `json:"ready_for_apply"`
	ReadOnlyProjection    bool                                       `json:"read_only_projection"`
	SourceSignals         []string                                   `json:"source_signals"`
	Evidence              []AWSPermissionBoundarySCPEvidence         `json:"evidence"`
	EvidenceBoundary      string                                     `json:"evidence_boundary"`
	ImpactedNodes         []string                                   `json:"impacted_nodes"`
	ImpactedPath          []AWSPermissionBoundarySCPPathStep         `json:"impacted_path"`
	NextAction            string                                     `json:"next_action"`
	CreatedAt             time.Time                                  `json:"created_at"`
	UpdatedAt             time.Time                                  `json:"updated_at"`
}

// AWSPermissionBoundarySCPSummary aggregates the unfiltered and filtered set.
type AWSPermissionBoundarySCPSummary struct {
	TotalPlans            int            `json:"total_plans"`
	FilteredPlans         int            `json:"filtered_plans"`
	KindCounts            map[string]int `json:"kind_counts"`
	TargetScopeCounts     map[string]int `json:"target_scope_counts"`
	SeverityCounts        map[string]int `json:"severity_counts"`
	StatusCounts          map[string]int `json:"status_counts"`
	BreakageLevelCounts   map[string]int `json:"breakage_level_counts"`
	BoundaryPlanCount     int            `json:"boundary_plan_count"`
	SCPPlanCount          int            `json:"scp_plan_count"`
	ReadyForApplyCount    int            `json:"ready_for_apply_count"`
	AffectedIdentityCount int            `json:"affected_identity_count"`
	AffectedAccountCount  int            `json:"affected_account_count"`
	AffectedOUCount       int            `json:"affected_ou_count"`
	RelationshipCount     int            `json:"relationship_count"`
	HighestScore          int            `json:"highest_score"`
	AverageConfidencePct  int            `json:"average_confidence_pct"`
}

// AWSPermissionBoundarySCPResult is the deterministic planner envelope.
type AWSPermissionBoundarySCPResult struct {
	TenantID           string                                 `json:"tenant_id"`
	WorkspaceID        string                                 `json:"workspace_id"`
	ProjectID          string                                 `json:"project_id"`
	ConnectorID        string                                 `json:"connector_id,omitempty"`
	AccountID          string                                 `json:"account_id,omitempty"`
	Region             string                                 `json:"region,omitempty"`
	ParentIssueNumber  int                                    `json:"parent_issue_number"`
	ParentIssueRef     string                                 `json:"parent_issue_ref"`
	CurrentIssueNumber int                                    `json:"current_issue_number"`
	CurrentIssueRef    string                                 `json:"current_issue_ref"`
	Version            string                                 `json:"version"`
	Status             string                                 `json:"status"`
	FixtureState       string                                 `json:"fixture_state,omitempty"`
	Confidence         float64                                `json:"confidence"`
	CalculationVersion string                                 `json:"calculation_version"`
	AppliedFilters     map[string]string                      `json:"applied_filters"`
	Summary            AWSPermissionBoundarySCPSummary        `json:"summary"`
	Plans              []AWSPermissionBoundarySCPPlan         `json:"plans"`
	Relationships      []AWSPermissionBoundarySCPRelationship `json:"relationships"`
	Caveats            []string                               `json:"caveats"`
	FailureReasons     []string                               `json:"failure_reasons"`
	RemediationHints   []string                               `json:"remediation_hints"`
	EvidenceLinks      []string                               `json:"evidence_links"`
	CoverageGaps       []AWSPermissionBoundarySCPCoverageGap  `json:"coverage_gaps"`
	Diagnostics        []AWSPermissionBoundarySCPDiagnostic   `json:"diagnostics"`
	GeneratedAt        time.Time                              `json:"generated_at"`
	UpdatedAt          time.Time                              `json:"updated_at"`
}

type awsPermissionBoundarySCPSources struct {
	least AWSLeastPrivilegeResult
	trust AWSCrossAccountTrustResult
	orgs  AWSOrganizationsTopologyResult
}

// GetAWSPermissionBoundarySCPPlans composes ranked permission boundary and
// SCP recommendations from upstream least-privilege, cross-account-trust,
// and Organizations topology evidence. The engine is read-only: it never
// mutates AWS, never reads or returns rendered policy bodies, secret
// values, or workload payloads, and treats unknown or denied evidence as
// explicit states instead of deterministic truth.
func (s *Service) GetAWSPermissionBoundarySCPPlans(ctx context.Context, workspaceID string, projectID string, request AWSPermissionBoundarySCPRequest) (AWSPermissionBoundarySCPResult, error) {
	project, scope, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return AWSPermissionBoundarySCPResult{}, err
	}
	connection, hasConnection, err := s.awsBaselineConnection(ctx, project, strings.TrimSpace(request.ConnectorID))
	if err != nil {
		return AWSPermissionBoundarySCPResult{}, err
	}
	now := s.Now().UTC()
	fixtureState := normalizeAWSPermissionBoundarySCPFixtureState(request.FixtureState, connection, hasConnection)
	if fixtureState == "" {
		return AWSPermissionBoundarySCPResult{}, ErrInvalidAWSConnectionRequest
	}

	accountID := firstNonEmptyAWSValue(connection.AccountID, strings.TrimSpace(request.AccountID), "123456789012")
	region := firstNonEmptyAWSValue(connection.Region, strings.TrimSpace(request.Region), "us-east-1")
	connectorID := firstNonEmptyAWSValue(connection.ConnectorID, strings.TrimSpace(request.ConnectorID))
	sourceFixtureState := fixtureState
	if strings.TrimSpace(request.FixtureState) == "" && hasConnection && connection.Connected {
		sourceFixtureState = ""
	}

	sources, err := s.awsPermissionBoundarySCPSourceSignals(ctx, workspaceID, projectID, connectorID, sourceFixtureState)
	if err != nil {
		return AWSPermissionBoundarySCPResult{}, err
	}
	plans := awsPermissionBoundarySCPPlans(sources, now)
	sort.SliceStable(plans, func(i, j int) bool {
		if plans[i].Score == plans[j].Score {
			return plans[i].PlanID < plans[j].PlanID
		}
		return plans[i].Score > plans[j].Score
	})
	filtered, applied := filterAWSPermissionBoundarySCPPlans(plans, request)
	relationships := awsPermissionBoundarySCPRelationships(filtered)
	diagnostics := awsPermissionBoundarySCPDiagnostics(sources)
	coverageGaps := awsPermissionBoundarySCPCoverageGaps(sources)
	status, confidence := summarizeAWSPermissionBoundarySCPStatus(sources, filtered, diagnostics)

	return AWSPermissionBoundarySCPResult{
		TenantID:           scope.TenantID,
		WorkspaceID:        project.WorkspaceID,
		ProjectID:          project.ProjectID,
		ConnectorID:        connectorID,
		AccountID:          accountID,
		Region:             region,
		ParentIssueNumber:  awsPlatformDependencyParentIssue,
		ParentIssueRef:     awsIssueRef(awsPlatformDependencyParentIssue),
		CurrentIssueNumber: awsPermissionBoundarySCPCurrentIssue,
		CurrentIssueRef:    awsIssueRef(awsPermissionBoundarySCPCurrentIssue),
		Version:            awsPermissionBoundarySCPVersion,
		Status:             status,
		FixtureState:       sourceFixtureState,
		Confidence:         confidence,
		CalculationVersion: awsPermissionBoundarySCPVersion,
		AppliedFilters:     applied,
		Summary:            summarizeAWSPermissionBoundarySCPPlans(plans, filtered, relationships),
		Plans:              filtered,
		Relationships:      relationships,
		Caveats:            awsPermissionBoundarySCPCaveats(),
		FailureReasons:     awsPermissionBoundarySCPFailureReasons(sources),
		RemediationHints:   awsPermissionBoundarySCPRemediationHints(sources),
		EvidenceLinks: dedupeStrings([]string{
			awsIssueURL(awsPlatformDependencyParentIssue),
			awsIssueURL(awsPermissionBoundarySCPCurrentIssue),
			awsIssueURL(awsLeastPrivilegeCurrentIssue),
			awsIssueURL(awsCrossAccountTrustCurrentIssue),
			awsIssueURL(awsOrganizationsTopologyCurrentIssue),
			awsIssueURL(awsRemediationCaseCurrentIssue),
			"/docs/aws-permission-boundary-scp-planner",
			"/docs/aws-least-privilege",
			"/docs/aws-cross-account-trust",
			"/docs/aws-organizations-topology",
			awsBaselineProjectEvidenceURL(scope, project),
		}),
		CoverageGaps: coverageGaps,
		Diagnostics:  diagnostics,
		GeneratedAt:  now,
		UpdatedAt:    now,
	}, nil
}

func normalizeAWSPermissionBoundarySCPFixtureState(requested string, connection AWSConnectionStatus, hasConnection bool) string {
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

func (s *Service) awsPermissionBoundarySCPSourceSignals(ctx context.Context, workspaceID, projectID, connectorID, fixtureState string) (awsPermissionBoundarySCPSources, error) {
	least, err := s.GetAWSLeastPrivilegeRecommendations(ctx, workspaceID, projectID, AWSLeastPrivilegeRequest{ConnectorID: connectorID, FixtureState: fixtureState})
	if err != nil {
		return awsPermissionBoundarySCPSources{}, fmt.Errorf("permission boundary scp least privilege: %w", err)
	}
	trust, err := s.GetAWSCrossAccountTrust(ctx, workspaceID, projectID, AWSCrossAccountTrustRequest{ConnectorID: connectorID, FixtureState: fixtureState})
	if err != nil {
		return awsPermissionBoundarySCPSources{}, fmt.Errorf("permission boundary scp cross account trust: %w", err)
	}
	orgs, err := s.GetAWSOrganizationsTopology(ctx, workspaceID, projectID, AWSOrganizationsTopologyRequest{ConnectorID: connectorID, FixtureState: fixtureState})
	if err != nil {
		return awsPermissionBoundarySCPSources{}, fmt.Errorf("permission boundary scp organizations topology: %w", err)
	}
	return awsPermissionBoundarySCPSources{least: least, trust: trust, orgs: orgs}, nil
}

func awsPermissionBoundarySCPPlans(sources awsPermissionBoundarySCPSources, now time.Time) []AWSPermissionBoundarySCPPlan {
	plans := awsPermissionBoundaryPlansFromLeastPrivilege(sources.least, sources.orgs, now)
	plans = append(plans, awsSCPPlansFromCrossAccountTrust(sources.trust, sources.orgs, now)...)
	return plans
}

// awsPermissionBoundaryPlansFromLeastPrivilege groups least-privilege remove
// recommendations by repeated action and proposes a permission boundary when
// at least two identities are recommended to remove the same action.
func awsPermissionBoundaryPlansFromLeastPrivilege(least AWSLeastPrivilegeResult, orgs AWSOrganizationsTopologyResult, now time.Time) []AWSPermissionBoundarySCPPlan {
	type bucket struct {
		action       string
		recommendIDs []string
		identityIDs  []string
		accountIDs   []string
		regions      []string
		services     []string
		evidence     []AWSPermissionBoundarySCPEvidence
		impactedRefs []string
		severities   map[string]int
		statuses     map[string]int
		breakage     map[string]int
		scoreSum     int
		scoreCount   int
		confidence   float64
		confCount    int
	}
	buckets := map[string]*bucket{}
	keyForAction := func(action string) string { return strings.ToLower(strings.TrimSpace(action)) }
	for _, recommendation := range least.Recommendations {
		if recommendation.Decision != "remove" {
			continue
		}
		for _, action := range dedupeStrings(recommendation.RemoveActions) {
			key := keyForAction(action)
			if key == "" {
				continue
			}
			b := buckets[key]
			if b == nil {
				b = &bucket{action: action, severities: map[string]int{}, statuses: map[string]int{}, breakage: map[string]int{}}
				buckets[key] = b
			}
			b.recommendIDs = append(b.recommendIDs, recommendation.RecommendationID)
			b.identityIDs = append(b.identityIDs, recommendation.IdentityNodeID)
			b.accountIDs = append(b.accountIDs, recommendation.AccountID)
			b.regions = append(b.regions, recommendation.Region)
			if recommendation.Service != "" {
				b.services = append(b.services, recommendation.Service)
			}
			for _, e := range recommendation.Evidence {
				b.evidence = append(b.evidence, e)
			}
			b.impactedRefs = append(b.impactedRefs, recommendation.IdentityNodeID)
			b.impactedRefs = append(b.impactedRefs, recommendation.ImpactedNodes...)
			b.severities[recommendation.Severity]++
			b.statuses[recommendation.Status]++
			b.breakage[strings.ToLower(strings.TrimSpace(recommendation.BreakagePrediction))]++
			b.scoreSum += recommendation.Score
			b.scoreCount++
			b.confidence += recommendation.Confidence
			b.confCount++
		}
	}
	out := []AWSPermissionBoundarySCPPlan{}
	for _, b := range buckets {
		identityIDs := emptyStrings(dedupeStrings(b.identityIDs))
		if len(identityIDs) < 2 {
			continue
		}
		accounts := emptyStrings(dedupeStrings(b.accountIDs))
		regions := emptyStrings(dedupeStrings(b.regions))
		region := ""
		if len(regions) == 1 {
			region = regions[0]
		}
		ouPaths := awsPermissionBoundarySCPOUPathsForAccounts(orgs, accounts)
		service := firstString(dedupeStrings(b.services))
		severity := awsPermissionBoundarySCPMostCommonKeyWithPriority(b.severities, "medium", awsPermissionBoundarySCPSeverityPriority)
		status := awsPermissionBoundarySCPMostCommonKeyWithPriority(b.statuses, "review", awsPermissionBoundarySCPStatusPriority)
		score := 0
		if b.scoreCount > 0 {
			score = b.scoreSum / b.scoreCount
			if score < 60 {
				score = 60
			}
		}
		confidence := 0.78
		if b.confCount > 0 {
			confidence = b.confidence / float64(b.confCount)
		}
		evidenceRef := firstString(awsPermissionBoundarySCPEvidenceRefs(b.evidence))
		breakage := awsPermissionBoundarySCPBoundaryBreakage(len(identityIDs), len(accounts), len(ouPaths))
		breakage = awsPermissionBoundarySCPBreakageWithUpstreamPrediction(breakage, awsPermissionBoundarySCPMostSeverePrediction(b.breakage, "low", awsPermissionBoundarySCPBreakagePredictionPriority))
		statement := AWSPermissionBoundarySCPStatementSnippet{
			StatementSID:   "permission-boundary-projection",
			Effect:         "Deny",
			ChangeKind:     "deny_repeated_action",
			BeforeRef:      evidenceRef,
			AfterRef:       "permission-boundary://repeated-action/" + keyForAction(b.action),
			DeniedActions:  []string{b.action},
			AllowedActions: []string{},
			ResourceScope:  []string{"*"},
			Rationale:      fmt.Sprintf("%d identities across %d account(s) all have least-privilege removal for %s; deny it at the permission boundary to prevent reintroduction.", len(identityIDs), len(accounts), b.action),
		}
		plan := AWSPermissionBoundarySCPPlan{
			PlanID:                "aws-permission-boundary-scp:" + stableAWSBlastRadiusToken("boundary", b.action),
			CalculationVersion:    awsPermissionBoundarySCPVersion,
			Kind:                  awsPermissionBoundaryKind,
			TargetScope:           "identity",
			Severity:              severity,
			Status:                status,
			Region:                region,
			Score:                 score,
			Confidence:            confidence,
			Title:                 fmt.Sprintf("Permission boundary: deny %s across %d identities", b.action, len(identityIDs)),
			Summary:               fmt.Sprintf("%d least-privilege recommendations agree that %s is unused; a permission boundary prevents reintroduction.", len(b.recommendIDs), b.action),
			Service:               service,
			TargetAccountIDs:      accounts,
			TargetOUPaths:         ouPaths,
			TargetIdentityNodeIDs: identityIDs,
			PreventedBehavior:     fmt.Sprintf("Re-grant or future use of %s by any boundary-bound identity.", b.action),
			SourceFindingIDs:      dedupeStrings(b.recommendIDs),
			StatementSnippets:     []AWSPermissionBoundarySCPStatementSnippet{statement},
			BreakageProjection:    breakage,
			RollbackPlan:          awsPermissionBoundarySCPRollback(awsPermissionBoundaryKind, evidenceRef),
			VerificationPlan:      awsPermissionBoundarySCPVerification(awsPermissionBoundaryKind, evidenceRef),
			ReadyForApply:         awsPermissionBoundarySCPReadyForApply(awsPermissionBoundaryKind, breakage, confidence),
			ReadOnlyProjection:    true,
			SourceSignals:         []string{"least_privilege"},
			Evidence:              b.evidence,
			EvidenceBoundary:      awsPermissionBoundarySCPEvidenceBoundary(),
			ImpactedNodes:         emptyStrings(dedupeStrings(append(append([]string{}, identityIDs...), b.impactedRefs...))),
			NextAction:            "Confirm the affected identities, then publish the boundary via the IAM remediation executor when one lands.",
			CreatedAt:             now,
			UpdatedAt:             now,
		}
		out = append(out, plan)
	}
	return out
}

// awsSCPPlansFromCrossAccountTrust proposes an SCP for each org-level trust
// risk (public principals or unconditional cross-account grants).
func awsSCPPlansFromCrossAccountTrust(trust AWSCrossAccountTrustResult, orgs AWSOrganizationsTopologyResult, now time.Time) []AWSPermissionBoundarySCPPlan {
	out := []AWSPermissionBoundarySCPPlan{}
	for _, finding := range trust.Findings {
		if !awsSCPCandidate(finding) {
			continue
		}
		evidenceRef := firstString(awsPermissionBoundarySCPEvidenceRefs(finding.Evidence))
		targetScope, accounts, ouPaths := awsSCPTargetScope(finding, orgs)
		breakage := awsPermissionBoundarySCPSCPBreakage(finding, len(accounts), len(ouPaths))
		denied := awsSCPDeniedActions(finding)
		if len(denied) == 0 {
			continue
		}
		statement := AWSPermissionBoundarySCPStatementSnippet{
			StatementSID:  "scp-projection",
			Effect:        "Deny",
			ChangeKind:    awsSCPChangeKind(finding),
			BeforeRef:     evidenceRef,
			AfterRef:      "scp://" + finding.FindingID + "/scoped-projection",
			DeniedActions: denied,
			ResourceScope: dedupeStrings([]string{finding.ResourceARN, finding.ResourceNodeID}),
			ConditionKeys: dedupeStrings(append(append([]string{}, finding.ConditionKeys...), awsSCPRecommendedConditionKeys(finding)...)),
			Rationale:     fmt.Sprintf("Block %s at the org/OU level so the trust finding cannot reappear in another account.", finding.FindingType),
		}
		plan := AWSPermissionBoundarySCPPlan{
			PlanID:             "aws-permission-boundary-scp:" + stableAWSBlastRadiusToken("scp", finding.FindingID),
			CalculationVersion: awsPermissionBoundarySCPVersion,
			Kind:               awsSCPKind,
			TargetScope:        targetScope,
			Severity:           finding.Severity,
			Status:             finding.Status,
			Score:              finding.Score,
			Confidence:         finding.Confidence,
			Title:              awsSCPTitle(finding, targetScope),
			Summary:            finding.Rationale,
			AccountID:          finding.AccountID,
			Region:             finding.Region,
			Service:            finding.Service,
			TargetAccountIDs:   accounts,
			TargetOUPaths:      ouPaths,
			PreventedBehavior:  awsSCPPreventedBehavior(finding),
			SourceFindingIDs:   []string{finding.FindingID},
			StatementSnippets:  []AWSPermissionBoundarySCPStatementSnippet{statement},
			BreakageProjection: breakage,
			RollbackPlan:       awsPermissionBoundarySCPRollback(awsSCPKind, evidenceRef),
			VerificationPlan:   awsPermissionBoundarySCPVerification(awsSCPKind, evidenceRef),
			ReadyForApply:      awsPermissionBoundarySCPReadyForApply(awsSCPKind, breakage, finding.Confidence),
			ReadOnlyProjection: true,
			SourceSignals:      []string{"cross_account_trust", "organizations_topology"},
			Evidence:           finding.Evidence,
			EvidenceBoundary:   awsPermissionBoundarySCPEvidenceBoundary(),
			ImpactedNodes:      emptyStrings(dedupeStrings(append([]string{finding.ResourceNodeID}, finding.ImpactedNodes...))),
			ImpactedPath:       finding.ImpactedPath,
			NextAction:         finding.NextAction,
			CreatedAt:          now,
			UpdatedAt:          now,
		}
		out = append(out, plan)
	}
	return out
}

func awsSCPCandidate(finding AWSCrossAccountTrustFinding) bool {
	if finding.PublicPrincipal {
		return true
	}
	if !finding.HasCondition {
		return true
	}
	switch finding.FindingType {
	case "access_analyzer_external_access", "cross_account_graph_path":
		return true
	}
	return false
}

func awsSCPDeniedActions(finding AWSCrossAccountTrustFinding) []string {
	switch finding.FindingType {
	case "public_resource_trust":
		action := awsSCPDenyActionForResourceWithSource(finding, "Put")
		if action == "" {
			return nil
		}
		return []string{action}
	case "runtime_cross_account_assumption":
		return []string{"sts:AssumeRole"}
	case "cross_account_resource_access":
		action := awsSCPDenyActionForResourceWithSource(finding, "Put")
		if action == "" {
			return nil
		}
		return []string{action}
	case "access_analyzer_external_access":
		action := awsSCPDenyActionForResourceWithSource(finding, "Put")
		if action == "" {
			return nil
		}
		return []string{action}
	case "cross_account_graph_path":
		return []string{"iam:PassRole", "sts:AssumeRole"}
	default:
		return []string{"*"}
	}
}

func awsSCPDenyActionForResourceWithSource(finding AWSCrossAccountTrustFinding, modePrefix string) string {
	if finding.ResourceType == "" {
		return ""
	}
	resourceType := normalizeAWSRuntimeEventFilterToken(finding.ResourceType)
	if resourceType == "" {
		return ""
	}
	switch resourceType {
	case "kms", "kms-key", "kms_key":
		if awsSCPFindingHasEvidenceSource(finding, "kms_live_grant") {
			return "kms:CreateGrant"
		}
	}
	return awsSCPDenyActionForResource(finding.ResourceType, modePrefix)
}

func awsSCPFindingHasEvidenceSource(finding AWSCrossAccountTrustFinding, source string) bool {
	target := normalizeAWSRuntimeEventFilterToken(source)
	if target == "" {
		return false
	}
	for _, evidence := range finding.Evidence {
		if normalizeAWSRuntimeEventFilterToken(evidence.Source) == target {
			return true
		}
	}
	return false
}

func awsSCPDenyActionForResource(resourceType, modePrefix string) string {
	resourceType = normalizeAWSRuntimeEventFilterToken(resourceType)
	modePrefix = normalizeAWSRuntimeEventFilterToken(modePrefix)
	if modePrefix == "" || modePrefix == "allow" {
		modePrefix = "put"
	}
	if modePrefix != "" {
		modePrefix = strings.ToUpper(modePrefix[:1]) + modePrefix[1:]
	}
	switch resourceType {
	case "s3", "s3-bucket", "s3_bucket":
		return "s3:" + modePrefix + "BucketPolicy"
	case "iam", "iam-role", "iam_role":
		return "iam:UpdateAssumeRolePolicy"
	case "kms", "kms-key", "kms_key":
		return "kms:PutKeyPolicy"
	case "secret", "secret-manager", "secrets", "secrets-manager", "secrets_manager", "secretsmanager":
		return "secretsmanager:PutResourcePolicy"
	default:
		return ""
	}
}

func awsSCPChangeKind(finding AWSCrossAccountTrustFinding) string {
	if finding.PublicPrincipal {
		return "deny_public_principal_creation"
	}
	if !finding.HasCondition {
		return "require_org_condition"
	}
	return "deny_org_unsafe_pattern"
}

func awsSCPRecommendedConditionKeys(finding AWSCrossAccountTrustFinding) []string {
	out := []string{}
	if !finding.HasCondition || !finding.TrustedWithinOrganization {
		out = append(out, "aws:PrincipalOrgID")
	}
	switch finding.FindingType {
	case "runtime_cross_account_assumption":
		out = append(out, "sts:ExternalId", "aws:SourceIdentity")
	case "public_resource_trust":
		out = append(out, "aws:SecureTransport")
	}
	return out
}

func awsSCPTargetScope(finding AWSCrossAccountTrustFinding, orgs AWSOrganizationsTopologyResult) (string, []string, []string) {
	if finding.PublicPrincipal {
		return "org_root", awsPermissionBoundarySCPAllAccounts(orgs), awsPermissionBoundarySCPAllOUPaths(orgs)
	}
	if awsSCPIsResourcePolicyFinding(finding.FindingType) && finding.AccountID != "" {
		return "account", []string{finding.AccountID}, awsPermissionBoundarySCPOUPathsForAccounts(orgs, []string{finding.AccountID})
	}
	if finding.ExternalPrincipalOUPath != "" {
		paths := []string{finding.ExternalPrincipalOUPath}
		return "ou", awsPermissionBoundarySCPAccountsForOUPath(orgs, finding.ExternalPrincipalOUPath), paths
	}
	if finding.AccountID != "" {
		return "account", []string{finding.AccountID}, awsPermissionBoundarySCPOUPathsForAccounts(orgs, []string{finding.AccountID})
	}
	return "org_root", awsPermissionBoundarySCPAllAccounts(orgs), awsPermissionBoundarySCPAllOUPaths(orgs)
}

func awsSCPIsResourcePolicyFinding(findingType string) bool {
	switch strings.ToLower(strings.TrimSpace(strings.ReplaceAll(normalizeAWSRuntimeEventFilterToken(findingType), "-", "_"))) {
	case "cross_account_resource_access", "access_analyzer_external_access":
		return true
	default:
		return false
	}
}

func awsSCPTitle(finding AWSCrossAccountTrustFinding, scope string) string {
	display := firstNonEmptyAWSValue(finding.ResourceLabel, finding.ResourceARN, finding.Service, "AWS resource")
	switch scope {
	case "org_root":
		return fmt.Sprintf("SCP at org root: %s for %s", awsSCPChangeKind(finding), display)
	case "ou":
		return fmt.Sprintf("SCP at OU %s: %s for %s", finding.ExternalPrincipalOUPath, awsSCPChangeKind(finding), display)
	default:
		return fmt.Sprintf("SCP at account %s: %s for %s", finding.AccountID, awsSCPChangeKind(finding), display)
	}
}

func awsSCPPreventedBehavior(finding AWSCrossAccountTrustFinding) string {
	switch finding.FindingType {
	case "public_resource_trust":
		return "Creating or restoring a resource policy with a wildcard public principal."
	case "runtime_cross_account_assumption":
		return "Cross-account AssumeRole calls that do not satisfy the recommended condition keys."
	case "access_analyzer_external_access":
		return "Re-introduction of the Access Analyzer-flagged external grant on any account in scope."
	case "cross_account_graph_path":
		return "Cross-account passrole / assume-role transitions that bypass the recommended org boundary."
	default:
		return "Re-introduction of the upstream cross-account-trust risk on any account in scope."
	}
}

func awsPermissionBoundarySCPBoundaryBreakage(identityCount, accountCount, ouCount int) AWSPermissionBoundarySCPBreakageProjection {
	signals := []string{
		fmt.Sprintf("affected_identities:%d", identityCount),
		fmt.Sprintf("affected_accounts:%d", accountCount),
	}
	if ouCount > 0 {
		signals = append(signals, fmt.Sprintf("affected_ous:%d", ouCount))
	}
	level := "low"
	rationale := "All affected identities already have a least-privilege remove decision for the denied action; the boundary only blocks re-introduction."
	if identityCount > 10 {
		level = "medium"
		rationale = "Boundary affects more than ten identities; stage the rollout per OU before applying globally."
	}
	if accountCount > 3 {
		level = "medium"
		rationale = "Boundary spans more than three accounts; review breakage per account before apply."
	}
	return AWSPermissionBoundarySCPBreakageProjection{
		Level:              level,
		Rationale:          rationale,
		AffectedIdentities: identityCount,
		AffectedAccounts:   accountCount,
		AffectedOUs:        ouCount,
		Signals:            signals,
	}
}

func awsPermissionBoundarySCPMostSeverePrediction(predictions map[string]int, fallback string, priorities map[string]int) string {
	bestPrediction := ""
	bestPriority := -1
	for prediction, count := range predictions {
		prediction = normalizeAWSRuntimeEventFilterToken(prediction)
		if count <= 0 || prediction == "" {
			continue
		}
		priority, ok := priorities[prediction]
		if !ok {
			continue
		}
		if priority > bestPriority {
			bestPrediction = prediction
			bestPriority = priority
			continue
		}
		if priority == bestPriority && (bestPrediction == "" || prediction < bestPrediction) {
			bestPrediction = prediction
		}
	}
	if bestPrediction == "" {
		return fallback
	}
	return bestPrediction
}

func awsPermissionBoundarySCPBreakageWithUpstreamPrediction(breakage AWSPermissionBoundarySCPBreakageProjection, upstreamBreakage string) AWSPermissionBoundarySCPBreakageProjection {
	upstreamBreakage = normalizeAWSRuntimeEventFilterToken(upstreamBreakage)
	switch upstreamBreakage {
	case "", "low":
		return breakage
	case "medium", "high", "unknown":
		breakage.Level = upstreamBreakage
		breakage.Rationale = fmt.Sprintf("Upstream least-privilege evidence indicates %s breakage; review before apply.", upstreamBreakage)
		breakage.Signals = append(breakage.Signals, "upstream_breakage_prediction:"+upstreamBreakage)
	}
	return breakage
}

func awsPermissionBoundarySCPSCPBreakage(finding AWSCrossAccountTrustFinding, accountCount, ouCount int) AWSPermissionBoundarySCPBreakageProjection {
	signals := []string{
		fmt.Sprintf("affected_accounts:%d", accountCount),
		fmt.Sprintf("public_principal:%t", finding.PublicPrincipal),
		fmt.Sprintf("has_condition:%t", finding.HasCondition),
	}
	if ouCount > 0 {
		signals = append(signals, fmt.Sprintf("affected_ous:%d", ouCount))
	}
	if finding.RuntimeObserved {
		signals = append(signals, "runtime_observed:true")
	}
	if finding.AnalyzerBacked {
		signals = append(signals, "analyzer_backed:true")
	}
	level := "unknown"
	rationale := "SCP affects multiple accounts; no runtime evidence proves which callers rely on the pattern."
	switch {
	case finding.PublicPrincipal:
		level = "high"
		rationale = "SCP denies wildcard public-trust creation across the org; unknown callers may rely on it. Owner approval required before apply."
	case finding.RuntimeObserved && finding.AnalyzerBacked:
		level = "low"
		rationale = "Runtime and Access Analyzer both confirm the caller set; the SCP only blocks re-introduction of the flagged pattern."
	case finding.RuntimeObserved || finding.AnalyzerBacked:
		level = "medium"
		rationale = "Only one of runtime or Access Analyzer confirms the caller set; review per-account before apply."
	}
	return AWSPermissionBoundarySCPBreakageProjection{
		Level:            level,
		Rationale:        rationale,
		AffectedAccounts: accountCount,
		AffectedOUs:      ouCount,
		Signals:          signals,
	}
}

func awsPermissionBoundarySCPRollback(kind, evidenceRef string) AWSPermissionBoundarySCPRollbackPlan {
	if kind == awsSCPKind {
		return AWSPermissionBoundarySCPRollbackPlan{
			Strategy:    "detach_scp",
			Steps:       []string{"Detach the projected SCP from the captured target OU/root.", "Re-run cross-account-trust to confirm the previous reachability returns."},
			EvidenceRef: evidenceRef,
		}
	}
	return AWSPermissionBoundarySCPRollbackPlan{
		Strategy:    "detach_permission_boundary",
		Steps:       []string{"Detach the projected permission boundary from each captured identity.", "Re-run least-privilege to confirm the previous decision set returns."},
		EvidenceRef: evidenceRef,
	}
}

func awsPermissionBoundarySCPVerification(kind, evidenceRef string) AWSPermissionBoundarySCPVerificationPlan {
	if kind == awsSCPKind {
		return AWSPermissionBoundarySCPVerificationPlan{
			Strategy:       "scp_simulate",
			Steps:          []string{"Use IAM Access Analyzer / policy-simulator to confirm the SCP denies the prevented behavior in every target account.", "Re-run cross-account-trust and confirm the finding resolves."},
			SuccessSignals: []string{"cross_account_trust:finding-resolved", "scp_simulate:no-regression"},
			FailureSignals: []string{"cross_account_trust:finding-unchanged", "scp_simulate:denied-observed-action"},
			EvidenceRef:    evidenceRef,
		}
	}
	return AWSPermissionBoundarySCPVerificationPlan{
		Strategy:       "policy_simulate",
		Steps:          []string{"Use IAM policy simulator to confirm the boundary denies the action for each affected identity without blocking observed actions.", "Re-run least-privilege and confirm the recommendation flips to keep."},
		SuccessSignals: []string{"policy_simulate:no-regression", "least_privilege:decision-keep"},
		FailureSignals: []string{"policy_simulate:denied-observed-action"},
		EvidenceRef:    evidenceRef,
	}
}

func awsPermissionBoundarySCPReadyForApply(kind string, breakage AWSPermissionBoundarySCPBreakageProjection, confidence float64) bool {
	if breakage.Level != "low" {
		return false
	}
	if confidence < 0.75 {
		return false
	}
	if kind == awsSCPKind && breakage.AffectedAccounts == 0 {
		return false
	}
	if kind == awsPermissionBoundaryKind && breakage.AffectedIdentities < 2 {
		return false
	}
	return true
}

func awsPermissionBoundarySCPMostCommonKey(counts map[string]int, fallback string) string {
	return awsPermissionBoundarySCPMostCommonKeyWithPriority(counts, fallback, nil)
}

func awsPermissionBoundarySCPMostCommonKeyWithPriority(counts map[string]int, fallback string, priorities map[string]int) string {
	best := ""
	bestCount := -1
	bestPriority := -1
	for key, count := range counts {
		if count <= 0 || key == "" {
			continue
		}
		priority := -1
		if priorities != nil {
			priority = priorities[normalizeAWSRuntimeEventFilterToken(key)]
		}
		if count > bestCount {
			best = key
			bestCount = count
			bestPriority = priority
			continue
		}
		if count < bestCount {
			continue
		}
		if priority > bestPriority {
			best = key
			bestPriority = priority
			continue
		}
		if priority < bestPriority {
			continue
		}
		if normalizeAWSRuntimeEventFilterToken(key) >= normalizeAWSRuntimeEventFilterToken(best) {
			continue
		}
		best = key
	}
	if best == "" {
		return fallback
	}
	return best
}

var awsPermissionBoundarySCPStatusPriority = map[string]int{
	"action_required": 2,
	"review":          1,
	"ready":           0,
	"deferred":        -1,
}

var awsPermissionBoundarySCPSeverityPriority = map[string]int{
	"critical": 4,
	"high":     3,
	"medium":   2,
	"low":      1,
	"info":     0,
}
var awsPermissionBoundarySCPBreakagePredictionPriority = map[string]int{
	"low":     0,
	"medium":  1,
	"high":    2,
	"unknown": 3,
}

func awsPermissionBoundarySCPOUPathsForAccounts(orgs AWSOrganizationsTopologyResult, accounts []string) []string {
	if len(accounts) == 0 {
		return nil
	}
	wanted := map[string]struct{}{}
	for _, account := range accounts {
		wanted[account] = struct{}{}
	}
	seen := map[string]struct{}{}
	out := []string{}
	for _, account := range orgs.Accounts {
		if _, ok := wanted[account.AccountID]; !ok {
			continue
		}
		if account.OUPath == "" {
			continue
		}
		if _, ok := seen[account.OUPath]; ok {
			continue
		}
		seen[account.OUPath] = struct{}{}
		out = append(out, account.OUPath)
	}
	sort.Strings(out)
	return out
}

func awsPermissionBoundarySCPAccountsForOUPath(orgs AWSOrganizationsTopologyResult, ouPath string) []string {
	out := []string{}
	for _, account := range orgs.Accounts {
		if account.OUPath == ouPath || strings.HasPrefix(account.OUPath, ouPath+"/") {
			out = append(out, account.AccountID)
		}
	}
	sort.Strings(out)
	return out
}

func awsPermissionBoundarySCPAllAccounts(orgs AWSOrganizationsTopologyResult) []string {
	out := []string{}
	for _, account := range orgs.Accounts {
		out = append(out, account.AccountID)
	}
	sort.Strings(out)
	return out
}

func awsPermissionBoundarySCPAllOUPaths(orgs AWSOrganizationsTopologyResult) []string {
	out := []string{}
	seen := map[string]struct{}{}
	for _, ou := range orgs.OrganizationalUnits {
		if ou.Path == "" {
			continue
		}
		if _, ok := seen[ou.Path]; ok {
			continue
		}
		seen[ou.Path] = struct{}{}
		out = append(out, ou.Path)
	}
	sort.Strings(out)
	return out
}

func awsPermissionBoundarySCPRelationships(plans []AWSPermissionBoundarySCPPlan) []AWSPermissionBoundarySCPRelationship {
	relationships := []AWSPermissionBoundarySCPRelationship{}
	for _, p := range plans {
		anchor := firstNonEmptyAWSValue(p.AccountID, firstString(p.TargetAccountIDs), firstString(p.TargetOUPaths), firstString(p.TargetIdentityNodeIDs), p.PlanID)
		evidenceRef := firstString(awsPermissionBoundarySCPEvidenceRefs(p.Evidence))
		for _, identity := range p.TargetIdentityNodeIDs {
			if identity == "" || identity == anchor {
				continue
			}
			relationships = append(relationships, AWSPermissionBoundarySCPRelationship{
				PlanID:      p.PlanID,
				Type:        "permission_boundary_target",
				FromNodeID:  anchor,
				ToNodeID:    identity,
				EvidenceRef: evidenceRef,
			})
		}
		for _, account := range p.TargetAccountIDs {
			if account == "" || account == anchor {
				continue
			}
			relationships = append(relationships, AWSPermissionBoundarySCPRelationship{
				PlanID:      p.PlanID,
				Type:        "scp_target_account",
				FromNodeID:  anchor,
				ToNodeID:    "aws:account:" + account,
				EvidenceRef: evidenceRef,
			})
		}
		for _, ou := range p.TargetOUPaths {
			if ou == "" {
				continue
			}
			relationships = append(relationships, AWSPermissionBoundarySCPRelationship{
				PlanID:      p.PlanID,
				Type:        "scp_target_ou",
				FromNodeID:  anchor,
				ToNodeID:    "aws:ou:" + ou,
				EvidenceRef: evidenceRef,
			})
		}
	}
	return relationships
}

func summarizeAWSPermissionBoundarySCPPlans(all, filtered []AWSPermissionBoundarySCPPlan, relationships []AWSPermissionBoundarySCPRelationship) AWSPermissionBoundarySCPSummary {
	summary := AWSPermissionBoundarySCPSummary{
		TotalPlans:          len(all),
		FilteredPlans:       len(filtered),
		KindCounts:          map[string]int{},
		TargetScopeCounts:   map[string]int{},
		SeverityCounts:      map[string]int{},
		StatusCounts:        map[string]int{},
		BreakageLevelCounts: map[string]int{},
		RelationshipCount:   len(relationships),
	}
	confidenceTotal := 0.0
	for _, p := range filtered {
		summary.KindCounts[p.Kind]++
		summary.TargetScopeCounts[p.TargetScope]++
		summary.SeverityCounts[p.Severity]++
		summary.StatusCounts[p.Status]++
		summary.BreakageLevelCounts[p.BreakageProjection.Level]++
		if p.Kind == awsPermissionBoundaryKind {
			summary.BoundaryPlanCount++
		}
		if p.Kind == awsSCPKind {
			summary.SCPPlanCount++
		}
		if p.ReadyForApply {
			summary.ReadyForApplyCount++
		}
		summary.AffectedIdentityCount += p.BreakageProjection.AffectedIdentities
		summary.AffectedAccountCount += p.BreakageProjection.AffectedAccounts
		summary.AffectedOUCount += p.BreakageProjection.AffectedOUs
		if p.Score > summary.HighestScore {
			summary.HighestScore = p.Score
		}
		confidenceTotal += p.Confidence
	}
	if len(filtered) > 0 {
		summary.AverageConfidencePct = int((confidenceTotal/float64(len(filtered)))*100 + 0.5)
	}
	return summary
}

func filterAWSPermissionBoundarySCPPlans(plans []AWSPermissionBoundarySCPPlan, request AWSPermissionBoundarySCPRequest) ([]AWSPermissionBoundarySCPPlan, map[string]string) {
	filters := map[string]string{
		"account_id":      strings.TrimSpace(request.AccountID),
		"region":          strings.TrimSpace(request.Region),
		"service":         strings.TrimSpace(request.Service),
		"kind":            normalizeAWSRuntimeEventFilterToken(request.Kind),
		"target_scope":    normalizeAWSRuntimeEventFilterToken(request.TargetScope),
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
	filtered := make([]AWSPermissionBoundarySCPPlan, 0, len(plans))
	for _, p := range plans {
		if filters["account_id"] != "" && filters["account_id"] != p.AccountID && !awsStringSliceContains(p.TargetAccountIDs, filters["account_id"]) {
			continue
		}
		if filters["region"] != "" && p.Region != "" && !strings.EqualFold(filters["region"], p.Region) {
			continue
		}
		if filters["service"] != "" && !strings.EqualFold(filters["service"], p.Service) {
			continue
		}
		if filters["kind"] != "" && filters["kind"] != normalizeAWSRuntimeEventFilterToken(p.Kind) {
			continue
		}
		if filters["target_scope"] != "" && filters["target_scope"] != normalizeAWSRuntimeEventFilterToken(p.TargetScope) {
			continue
		}
		if filters["severity"] != "" && filters["severity"] != normalizeAWSRuntimeEventFilterToken(p.Severity) {
			continue
		}
		if filters["status"] != "" && filters["status"] != normalizeAWSRuntimeEventFilterToken(p.Status) {
			continue
		}
		if filters["breakage_level"] != "" && filters["breakage_level"] != normalizeAWSRuntimeEventFilterToken(p.BreakageProjection.Level) {
			continue
		}
		if filters["ready_for_apply"] != "" {
			want := filters["ready_for_apply"]
			if (want == "true" || want == "yes") != p.ReadyForApply {
				continue
			}
		}
		if filters["search"] != "" && !awsPermissionBoundarySCPSearchMatch(p, filters["search"]) {
			continue
		}
		filtered = append(filtered, p)
	}
	return filtered, applied
}

func awsPermissionBoundarySCPSearchMatch(p AWSPermissionBoundarySCPPlan, needle string) bool {
	needle = strings.ToLower(strings.TrimSpace(needle))
	if needle == "" {
		return true
	}
	values := []string{p.PlanID, p.Title, p.Summary, p.Kind, p.TargetScope, p.Severity, p.Status, p.Service, p.PreventedBehavior, p.BreakageProjection.Level, p.BreakageProjection.Rationale, p.RollbackPlan.Strategy, p.RollbackPlan.EvidenceRef, p.VerificationPlan.Strategy, p.VerificationPlan.EvidenceRef, p.NextAction}
	values = append(values, p.SourceFindingIDs...)
	values = append(values, p.TargetAccountIDs...)
	values = append(values, p.TargetOUPaths...)
	values = append(values, p.TargetIdentityNodeIDs...)
	values = append(values, p.BreakageProjection.Signals...)
	values = append(values, p.RollbackPlan.Steps...)
	values = append(values, p.VerificationPlan.Steps...)
	values = append(values, p.VerificationPlan.SuccessSignals...)
	values = append(values, p.VerificationPlan.FailureSignals...)
	for _, snippet := range p.StatementSnippets {
		values = append(values, snippet.StatementSID, snippet.Effect, snippet.ChangeKind, snippet.Rationale, snippet.BeforeRef, snippet.AfterRef)
		values = append(values, snippet.DeniedActions...)
		values = append(values, snippet.AllowedActions...)
		values = append(values, snippet.ResourceScope...)
		values = append(values, snippet.ConditionKeys...)
	}
	for _, evidence := range p.Evidence {
		values = append(values, evidence.Source, evidence.Label, evidence.EvidenceRef, evidence.Relationship)
	}
	for _, value := range values {
		if strings.Contains(strings.ToLower(value), needle) {
			return true
		}
	}
	return false
}

func summarizeAWSPermissionBoundarySCPStatus(sources awsPermissionBoundarySCPSources, filtered []AWSPermissionBoundarySCPPlan, diagnostics []AWSPermissionBoundarySCPDiagnostic) (string, float64) {
	for _, status := range []string{sources.least.Status, sources.trust.Status, sources.orgs.Status} {
		if status == awsPlatformDependencyStatusBlocked {
			return awsPlatformDependencyStatusBlocked, 0.35
		}
	}
	for _, diagnostic := range diagnostics {
		if diagnostic.Retryable {
			return awsPlatformDependencyStatusDegraded, 0.72
		}
	}
	for _, status := range []string{sources.least.Status, sources.trust.Status, sources.orgs.Status} {
		if status == awsPlatformDependencyStatusDegraded {
			return awsPlatformDependencyStatusDegraded, 0.76
		}
	}
	if len(filtered) == 0 {
		return awsPlatformDependencyStatusReady, 0.82
	}
	return awsPlatformDependencyStatusReady, 0.9
}

func awsPermissionBoundarySCPFailureReasons(sources awsPermissionBoundarySCPSources) []string {
	out := []string{}
	out = append(out, sources.least.FailureReasons...)
	out = append(out, sources.trust.FailureReasons...)
	out = append(out, sources.orgs.FailureReasons...)
	return dedupeStrings(out)
}

func awsPermissionBoundarySCPRemediationHints(sources awsPermissionBoundarySCPSources) []string {
	out := []string{
		"Apply each plan only after the matching remediation case is approved; this engine is read-only and does not call any IAM or Organizations write API.",
		"Stage permission boundaries and SCPs per OU before rolling them out across the whole org.",
	}
	out = append(out, sources.least.RemediationHints...)
	out = append(out, sources.trust.RemediationHints...)
	out = append(out, sources.orgs.RemediationHints...)
	return dedupeStrings(out)
}

func awsPermissionBoundarySCPCaveats() []string {
	return []string{
		"Permission boundary and SCP plans are read-only projections; the engine never applies an AWS change.",
		"Statement snippets carry deny/allow action lists and condition-key labels only — never rendered JSON policy bodies, secret values, or workload payloads.",
		"ready_for_apply is derived deterministically (breakage_level=low + confidence >= 0.75 + non-empty targets); approve/execute/verify transitions belong to future wave issues.",
	}
}

func awsPermissionBoundarySCPDiagnostics(sources awsPermissionBoundarySCPSources) []AWSPermissionBoundarySCPDiagnostic {
	out := []AWSPermissionBoundarySCPDiagnostic{}
	for _, d := range sources.least.Diagnostics {
		if strings.TrimSpace(d.Message) == "" && strings.TrimSpace(d.Code) == "" {
			continue
		}
		out = append(out, AWSPermissionBoundarySCPDiagnostic{Collector: d.Collector, SourceID: d.SourceID, Code: d.Code, Message: d.Message, Remediation: d.Remediation, Retryable: d.Retryable})
	}
	for _, d := range sources.trust.Diagnostics {
		if strings.TrimSpace(d.Message) == "" && strings.TrimSpace(d.Code) == "" {
			continue
		}
		out = append(out, AWSPermissionBoundarySCPDiagnostic{Collector: d.Collector, SourceID: d.SourceID, Code: d.Code, Message: d.Message, Remediation: d.Remediation, Retryable: d.Retryable})
	}
	for _, d := range sources.orgs.Diagnostics {
		if strings.TrimSpace(d.Message) == "" && strings.TrimSpace(d.Code) == "" {
			continue
		}
		out = append(out, AWSPermissionBoundarySCPDiagnostic{Collector: d.Source, SourceID: d.Scope, Code: d.Code, Message: d.Message, Remediation: d.Remediation, Retryable: d.Retryable})
	}
	return out
}

func awsPermissionBoundarySCPCoverageGaps(sources awsPermissionBoundarySCPSources) []AWSPermissionBoundarySCPCoverageGap {
	out := []AWSPermissionBoundarySCPCoverageGap{{
		Capability:  "permission_boundary_scp_apply",
		Status:      "out_of_scope",
		Reason:      "Issue #1532 implements the boundary/SCP projection only; apply/verify transitions are future-wave work and never call IAM or Organizations write APIs here.",
		Remediation: "Wire the approve/execute/verify endpoints in the relevant remediation/governance issue once the safety gates are in place.",
	}}
	for _, g := range sources.least.CoverageGaps {
		out = append(out, AWSPermissionBoundarySCPCoverageGap{Capability: g.Capability, Status: g.Status, Reason: g.Reason, Remediation: g.Remediation})
	}
	for _, g := range sources.trust.CoverageGaps {
		out = append(out, AWSPermissionBoundarySCPCoverageGap{Capability: g.Capability, Status: g.Status, Reason: g.Reason, Remediation: g.Remediation})
	}
	for _, g := range sources.orgs.CoverageGaps {
		out = append(out, AWSPermissionBoundarySCPCoverageGap{Capability: g.Capability, Status: g.Status, Reason: g.Reason, Remediation: g.Remediation})
	}
	return out
}

func awsPermissionBoundarySCPEvidenceBoundary() string {
	return "metadata_only_no_rendered_policy_bodies_no_secret_values_no_workload_payloads"
}

func awsPermissionBoundarySCPEvidenceRefs(evidence []AWSPermissionBoundarySCPEvidence) []string {
	out := []string{}
	for _, item := range evidence {
		if strings.TrimSpace(item.EvidenceRef) != "" {
			out = append(out, item.EvidenceRef)
		}
	}
	return dedupeStrings(out)
}
