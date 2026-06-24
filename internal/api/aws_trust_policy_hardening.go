package api

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	awsTrustPolicyHardeningCurrentIssue = 1531
	awsTrustPolicyHardeningVersion      = "aws-trust-policy-hardening-planner-v1"
)

// AWSTrustPolicyHardeningRequest scopes the deterministic trust-policy
// hardening planner to one AWS connector plus optional operator drill-down
// filters.
type AWSTrustPolicyHardeningRequest struct {
	ConnectorID        string `json:"connector_id,omitempty"`
	FixtureState       string `json:"fixture_state,omitempty"`
	AccountID          string `json:"account_id,omitempty"`
	Region             string `json:"region,omitempty"`
	Service            string `json:"service,omitempty"`
	Resource           string `json:"resource,omitempty"`
	Principal          string `json:"principal,omitempty"`
	HardeningDirection string `json:"hardening_direction,omitempty"`
	BreakageLevel      string `json:"breakage_level,omitempty"`
	Severity           string `json:"severity,omitempty"`
	Status             string `json:"status,omitempty"`
	ReadyForApply      string `json:"ready_for_apply,omitempty"`
	Search             string `json:"search,omitempty"`
}

// AWSTrustPolicyHardeningEvidence and path step reuse the least-privilege
// contract so the planner stays consistent with its upstream source.
type AWSTrustPolicyHardeningEvidence = AWSLeastPrivilegeEvidence
type AWSTrustPolicyHardeningPathStep = AWSLeastPrivilegePathStep
type AWSTrustPolicyHardeningDiagnostic = AWSLeastPrivilegeDiagnostic
type AWSTrustPolicyHardeningCoverageGap = AWSLeastPrivilegeCoverageGap

// AWSTrustPolicyPrincipalChange is the read-only before/after intent for the
// `Principal` element of a trust policy statement. It carries identifier
// metadata only — never a rendered JSON principal block.
type AWSTrustPolicyPrincipalChange struct {
	BeforePrincipals       []string `json:"before_principals,omitempty"`
	AfterPrincipals        []string `json:"after_principals,omitempty"`
	PublicPrincipalRemoved bool     `json:"public_principal_removed"`
	Rationale              string   `json:"rationale"`
}

// AWSTrustPolicyConditionRecommendation describes a single condition the
// planner is recommending be added to the trust statement. The value carries
// a placeholder/identifier — never a rendered secret or workload payload.
type AWSTrustPolicyConditionRecommendation struct {
	Operator    string `json:"operator"`
	Key         string `json:"key"`
	Value       string `json:"value"`
	Rationale   string `json:"rationale"`
	EvidenceRef string `json:"evidence_ref,omitempty"`
}

// AWSTrustPolicyStatementSnippet labels the before/after trust statement
// without inlining a rendered policy body.
type AWSTrustPolicyStatementSnippet struct {
	StatementSID    string   `json:"statement_sid"`
	Effect          string   `json:"effect"`
	ChangeKind      string   `json:"change_kind"`
	BeforeRef       string   `json:"before_ref,omitempty"`
	AfterRef        string   `json:"after_ref,omitempty"`
	ConditionBefore []string `json:"condition_before,omitempty"`
	ConditionAfter  []string `json:"condition_after,omitempty"`
	Rationale       string   `json:"rationale"`
}

// AWSTrustPolicyAffectedCaller is one external principal known to use the
// trust path. Identifiers only — no secrets, no rendered policy bodies, no
// workload payloads.
type AWSTrustPolicyAffectedCaller struct {
	PrincipalARN       string `json:"principal_arn"`
	PrincipalAccountID string `json:"principal_account_id,omitempty"`
	OUPath             string `json:"ou_path,omitempty"`
	TrustedWithinOrg   bool   `json:"trusted_within_organization"`
	RuntimeObserved    bool   `json:"runtime_observed"`
	AnalyzerBacked     bool   `json:"analyzer_backed"`
	EvidenceRef        string `json:"evidence_ref,omitempty"`
}

// AWSTrustPolicyHardeningBreakageProjection bucketed expectation for the
// workload breakage of applying the plan.
type AWSTrustPolicyHardeningBreakageProjection struct {
	Level     string   `json:"level"`
	Rationale string   `json:"rationale"`
	Signals   []string `json:"signals,omitempty"`
}

// AWSTrustPolicyHardeningRollbackPlan documents how an applied plan is
// reverted.
type AWSTrustPolicyHardeningRollbackPlan struct {
	Strategy    string   `json:"strategy"`
	Steps       []string `json:"steps"`
	EvidenceRef string   `json:"evidence_ref,omitempty"`
}

// AWSTrustPolicyHardeningVerificationPlan documents how an applied plan is
// checked.
type AWSTrustPolicyHardeningVerificationPlan struct {
	Strategy       string   `json:"strategy"`
	Steps          []string `json:"steps"`
	SuccessSignals []string `json:"success_signals,omitempty"`
	FailureSignals []string `json:"failure_signals,omitempty"`
	EvidenceRef    string   `json:"evidence_ref,omitempty"`
}

// AWSTrustPolicyHardeningRelationship surfaces plan→graph node edges so the
// app and downstream graph consumers can show why a plan touches a node.
type AWSTrustPolicyHardeningRelationship struct {
	PlanID      string `json:"plan_id"`
	Type        string `json:"type"`
	FromNodeID  string `json:"from_node_id"`
	ToNodeID    string `json:"to_node_id"`
	EvidenceRef string `json:"evidence_ref,omitempty"`
}

// AWSTrustPolicyHardeningPlan is the persisted-record-shaped contract
// emitted by the planner. It carries statement-level metadata refs and
// graph nodes only; no rendered policy bodies, secret values, prompts,
// completions, tool payloads, browser pages, code-interpreter output,
// database rows, object contents, customer payloads, or workload payloads
// are inlined.
type AWSTrustPolicyHardeningPlan struct {
	PlanID                    string                                    `json:"plan_id"`
	CalculationVersion        string                                    `json:"calculation_version"`
	SourceFindingID           string                                    `json:"source_finding_id"`
	FindingType               string                                    `json:"finding_type"`
	HardeningDirection        string                                    `json:"hardening_direction"`
	Severity                  string                                    `json:"severity"`
	Status                    string                                    `json:"status"`
	Score                     int                                       `json:"score"`
	Confidence                float64                                   `json:"confidence"`
	Title                     string                                    `json:"title"`
	Summary                   string                                    `json:"summary"`
	AccountID                 string                                    `json:"account_id"`
	Region                    string                                    `json:"region"`
	Service                   string                                    `json:"service,omitempty"`
	ResourceType              string                                    `json:"resource_type,omitempty"`
	ResourceNodeID            string                                    `json:"resource_node_id,omitempty"`
	ResourceARN               string                                    `json:"resource_arn,omitempty"`
	ResourceLabel             string                                    `json:"resource_label,omitempty"`
	PublicPrincipal           bool                                      `json:"public_principal"`
	TrustedWithinOrganization bool                                      `json:"trusted_within_organization"`
	RuntimeObserved           bool                                      `json:"runtime_observed"`
	AnalyzerBacked            bool                                      `json:"analyzer_backed"`
	PrincipalChange           AWSTrustPolicyPrincipalChange             `json:"principal_change"`
	ConditionRecommendations  []AWSTrustPolicyConditionRecommendation   `json:"condition_recommendations"`
	StatementSnippets         []AWSTrustPolicyStatementSnippet          `json:"statement_snippets"`
	AffectedCallers           []AWSTrustPolicyAffectedCaller            `json:"affected_callers"`
	BreakageProjection        AWSTrustPolicyHardeningBreakageProjection `json:"breakage_projection"`
	RollbackPlan              AWSTrustPolicyHardeningRollbackPlan       `json:"rollback_plan"`
	VerificationPlan          AWSTrustPolicyHardeningVerificationPlan   `json:"verification_plan"`
	ReadyForApply             bool                                      `json:"ready_for_apply"`
	ReadOnlyProjection        bool                                      `json:"read_only_projection"`
	SourceSignals             []string                                  `json:"source_signals"`
	Evidence                  []AWSTrustPolicyHardeningEvidence         `json:"evidence"`
	EvidenceBoundary          string                                    `json:"evidence_boundary"`
	ImpactedNodes             []string                                  `json:"impacted_nodes"`
	ImpactedPath              []AWSTrustPolicyHardeningPathStep         `json:"impacted_path"`
	NextAction                string                                    `json:"next_action"`
	CreatedAt                 time.Time                                 `json:"created_at"`
	UpdatedAt                 time.Time                                 `json:"updated_at"`
}

// AWSTrustPolicyHardeningSummary aggregates the unfiltered and filtered set.
type AWSTrustPolicyHardeningSummary struct {
	TotalPlans               int            `json:"total_plans"`
	FilteredPlans            int            `json:"filtered_plans"`
	SeverityCounts           map[string]int `json:"severity_counts"`
	StatusCounts             map[string]int `json:"status_counts"`
	FindingTypeCounts        map[string]int `json:"finding_type_counts"`
	HardeningDirectionCounts map[string]int `json:"hardening_direction_counts"`
	BreakageLevelCounts      map[string]int `json:"breakage_level_counts"`
	PublicPrincipalCount     int            `json:"public_principal_count"`
	CrossAccountCount        int            `json:"cross_account_count"`
	ConditionedCount         int            `json:"conditioned_count"`
	RuntimeObservedCount     int            `json:"runtime_observed_count"`
	AnalyzerBackedCount      int            `json:"analyzer_backed_count"`
	ReadyForApplyCount       int            `json:"ready_for_apply_count"`
	ManualReviewCount        int            `json:"manual_review_count"`
	AffectedCallerCount      int            `json:"affected_caller_count"`
	RelationshipCount        int            `json:"relationship_count"`
	HighestScore             int            `json:"highest_score"`
	AverageConfidencePct     int            `json:"average_confidence_pct"`
}

// AWSTrustPolicyHardeningResult is the deterministic planner envelope.
type AWSTrustPolicyHardeningResult struct {
	TenantID           string                                `json:"tenant_id"`
	WorkspaceID        string                                `json:"workspace_id"`
	ProjectID          string                                `json:"project_id"`
	ConnectorID        string                                `json:"connector_id,omitempty"`
	AccountID          string                                `json:"account_id,omitempty"`
	Region             string                                `json:"region,omitempty"`
	ParentIssueNumber  int                                   `json:"parent_issue_number"`
	ParentIssueRef     string                                `json:"parent_issue_ref"`
	CurrentIssueNumber int                                   `json:"current_issue_number"`
	CurrentIssueRef    string                                `json:"current_issue_ref"`
	Version            string                                `json:"version"`
	Status             string                                `json:"status"`
	FixtureState       string                                `json:"fixture_state,omitempty"`
	Confidence         float64                               `json:"confidence"`
	CalculationVersion string                                `json:"calculation_version"`
	AppliedFilters     map[string]string                     `json:"applied_filters"`
	Summary            AWSTrustPolicyHardeningSummary        `json:"summary"`
	Plans              []AWSTrustPolicyHardeningPlan         `json:"plans"`
	Relationships      []AWSTrustPolicyHardeningRelationship `json:"relationships"`
	Caveats            []string                              `json:"caveats"`
	FailureReasons     []string                              `json:"failure_reasons"`
	RemediationHints   []string                              `json:"remediation_hints"`
	EvidenceLinks      []string                              `json:"evidence_links"`
	CoverageGaps       []AWSTrustPolicyHardeningCoverageGap  `json:"coverage_gaps"`
	Diagnostics        []AWSTrustPolicyHardeningDiagnostic   `json:"diagnostics"`
	GeneratedAt        time.Time                             `json:"generated_at"`
	UpdatedAt          time.Time                             `json:"updated_at"`
}

type awsTrustPolicyHardeningSources struct {
	trust AWSCrossAccountTrustResult
}

// GetAWSTrustPolicyHardeningPlans composes ranked trust-policy hardening
// plans from upstream cross-account-trust findings. The engine is read-only:
// it never mutates AWS, never reads or returns rendered policy bodies, secret
// values, or workload payloads, and treats unknown or denied evidence as
// explicit states instead of deterministic truth.
func (s *Service) GetAWSTrustPolicyHardeningPlans(ctx context.Context, workspaceID string, projectID string, request AWSTrustPolicyHardeningRequest) (AWSTrustPolicyHardeningResult, error) {
	project, scope, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return AWSTrustPolicyHardeningResult{}, err
	}
	connection, hasConnection, err := s.awsBaselineConnection(ctx, project, strings.TrimSpace(request.ConnectorID))
	if err != nil {
		return AWSTrustPolicyHardeningResult{}, err
	}
	now := s.Now().UTC()
	fixtureState := normalizeAWSTrustPolicyHardeningFixtureState(request.FixtureState, connection, hasConnection)
	if fixtureState == "" {
		return AWSTrustPolicyHardeningResult{}, ErrInvalidAWSConnectionRequest
	}

	accountID := firstNonEmptyAWSValue(connection.AccountID, strings.TrimSpace(request.AccountID), "123456789012")
	region := firstNonEmptyAWSValue(connection.Region, strings.TrimSpace(request.Region), "us-east-1")
	connectorID := firstNonEmptyAWSValue(connection.ConnectorID, strings.TrimSpace(request.ConnectorID))
	sourceFixtureState := fixtureState
	if strings.TrimSpace(request.FixtureState) == "" && hasConnection && connection.Connected {
		sourceFixtureState = ""
	}

	sources, err := s.awsTrustPolicyHardeningSourceSignals(ctx, workspaceID, projectID, connectorID, sourceFixtureState)
	if err != nil {
		return AWSTrustPolicyHardeningResult{}, err
	}
	plans := awsTrustPolicyHardeningPlans(sources, now)
	sort.SliceStable(plans, func(i, j int) bool {
		if plans[i].Score == plans[j].Score {
			return plans[i].PlanID < plans[j].PlanID
		}
		return plans[i].Score > plans[j].Score
	})
	filtered, applied := filterAWSTrustPolicyHardeningPlans(plans, request)
	relationships := awsTrustPolicyHardeningRelationships(filtered)
	diagnostics := awsTrustPolicyHardeningDiagnostics(sources)
	coverageGaps := awsTrustPolicyHardeningCoverageGaps(sources)
	status, confidence := summarizeAWSTrustPolicyHardeningStatus(sources, filtered, diagnostics)

	return AWSTrustPolicyHardeningResult{
		TenantID:           scope.TenantID,
		WorkspaceID:        project.WorkspaceID,
		ProjectID:          project.ProjectID,
		ConnectorID:        connectorID,
		AccountID:          accountID,
		Region:             region,
		ParentIssueNumber:  awsPlatformDependencyParentIssue,
		ParentIssueRef:     awsIssueRef(awsPlatformDependencyParentIssue),
		CurrentIssueNumber: awsTrustPolicyHardeningCurrentIssue,
		CurrentIssueRef:    awsIssueRef(awsTrustPolicyHardeningCurrentIssue),
		Version:            awsTrustPolicyHardeningVersion,
		Status:             status,
		FixtureState:       sourceFixtureState,
		Confidence:         confidence,
		CalculationVersion: awsTrustPolicyHardeningVersion,
		AppliedFilters:     applied,
		Summary:            summarizeAWSTrustPolicyHardeningPlans(plans, filtered, relationships),
		Plans:              filtered,
		Relationships:      relationships,
		Caveats:            awsTrustPolicyHardeningCaveats(),
		FailureReasons:     awsTrustPolicyHardeningFailureReasons(sources),
		RemediationHints:   awsTrustPolicyHardeningRemediationHints(sources),
		EvidenceLinks: dedupeStrings([]string{
			awsIssueURL(awsPlatformDependencyParentIssue),
			awsIssueURL(awsTrustPolicyHardeningCurrentIssue),
			awsIssueURL(awsCrossAccountTrustCurrentIssue),
			awsIssueURL(awsRemediationCaseCurrentIssue),
			"/docs/aws-trust-policy-hardening-planner",
			"/docs/aws-cross-account-trust",
			"/docs/aws-remediation-case-model",
			awsBaselineProjectEvidenceURL(scope, project),
		}),
		CoverageGaps: coverageGaps,
		Diagnostics:  diagnostics,
		GeneratedAt:  now,
		UpdatedAt:    now,
	}, nil
}

func normalizeAWSTrustPolicyHardeningFixtureState(requested string, connection AWSConnectionStatus, hasConnection bool) string {
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

func (s *Service) awsTrustPolicyHardeningSourceSignals(ctx context.Context, workspaceID, projectID, connectorID, fixtureState string) (awsTrustPolicyHardeningSources, error) {
	trust, err := s.GetAWSCrossAccountTrust(ctx, workspaceID, projectID, AWSCrossAccountTrustRequest{ConnectorID: connectorID, FixtureState: fixtureState})
	if err != nil {
		return awsTrustPolicyHardeningSources{}, fmt.Errorf("trust policy hardening cross account trust: %w", err)
	}
	return awsTrustPolicyHardeningSources{trust: trust}, nil
}

func awsTrustPolicyHardeningPlans(sources awsTrustPolicyHardeningSources, now time.Time) []AWSTrustPolicyHardeningPlan {
	plans := []AWSTrustPolicyHardeningPlan{}
	for _, finding := range sources.trust.Findings {
		if plan, ok := awsTrustPolicyHardeningPlanFromFinding(finding, now); ok {
			plans = append(plans, plan)
		}
	}
	return plans
}

func awsTrustPolicyHardeningPlanFromFinding(finding AWSCrossAccountTrustFinding, now time.Time) (AWSTrustPolicyHardeningPlan, bool) {
	if finding.FindingID == "" {
		return AWSTrustPolicyHardeningPlan{}, false
	}
	planID := "aws-trust-policy-hardening:" + stableAWSBlastRadiusToken("trust-hardening", finding.FindingID)
	evidenceRef := firstString(awsTrustPolicyHardeningEvidenceRefs(finding.Evidence))
	direction := awsTrustPolicyHardeningDirectionFromFinding(finding)
	principalChange := awsTrustPolicyHardeningPrincipalChange(finding)
	conditions := awsTrustPolicyHardeningConditions(finding, evidenceRef)
	statements := awsTrustPolicyHardeningStatementSnippets(finding, principalChange, conditions, evidenceRef)
	callers := awsTrustPolicyHardeningAffectedCallers(finding, evidenceRef)
	breakage := awsTrustPolicyHardeningBreakage(finding, callers)
	rollback := awsTrustPolicyHardeningRollback(finding, evidenceRef)
	verification := awsTrustPolicyHardeningVerification(finding, evidenceRef)
	readyForApply := awsTrustPolicyHardeningReadyForApply(finding, breakage, conditions)
	title := awsTrustPolicyHardeningTitle(finding, direction)
	plan := AWSTrustPolicyHardeningPlan{
		PlanID:                    planID,
		CalculationVersion:        awsTrustPolicyHardeningVersion,
		SourceFindingID:           finding.FindingID,
		FindingType:               finding.FindingType,
		HardeningDirection:        direction,
		Severity:                  finding.Severity,
		Status:                    finding.Status,
		Score:                     finding.Score,
		Confidence:                finding.Confidence,
		Title:                     title,
		Summary:                   finding.Rationale,
		AccountID:                 finding.AccountID,
		Region:                    finding.Region,
		Service:                   finding.Service,
		ResourceType:              finding.ResourceType,
		ResourceNodeID:            finding.ResourceNodeID,
		ResourceARN:               finding.ResourceARN,
		ResourceLabel:             finding.ResourceLabel,
		PublicPrincipal:           finding.PublicPrincipal,
		TrustedWithinOrganization: finding.TrustedWithinOrganization,
		RuntimeObserved:           finding.RuntimeObserved,
		AnalyzerBacked:            finding.AnalyzerBacked,
		PrincipalChange:           principalChange,
		ConditionRecommendations:  conditions,
		StatementSnippets:         statements,
		AffectedCallers:           callers,
		BreakageProjection:        breakage,
		RollbackPlan:              rollback,
		VerificationPlan:          verification,
		ReadyForApply:             readyForApply,
		ReadOnlyProjection:        true,
		SourceSignals:             []string{"cross_account_trust"},
		Evidence:                  finding.Evidence,
		EvidenceBoundary:          awsTrustPolicyHardeningEvidenceBoundary(),
		ImpactedNodes:             emptyStrings(dedupeStrings(append([]string{finding.ResourceNodeID}, finding.ImpactedNodes...))),
		ImpactedPath:              finding.ImpactedPath,
		NextAction:                finding.NextAction,
		CreatedAt:                 now,
		UpdatedAt:                 now,
	}
	return plan, true
}

var awsTrustPolicyHardeningDirectionTokens = map[string]struct{}{
	"remove_public_principal":           {},
	"add_org_or_source_condition":       {},
	"scope_to_known_external_principal": {},
	"tighten_existing_condition":        {},
}

func awsTrustPolicyHardeningDirectionFromFinding(finding AWSCrossAccountTrustFinding) string {
	candidate := strings.ToLower(strings.TrimSpace(finding.HardeningDirection))
	if _, ok := awsTrustPolicyHardeningDirectionTokens[candidate]; ok {
		return candidate
	}
	return awsTrustPolicyHardeningDirection(finding)
}

func awsTrustPolicyHardeningDirection(finding AWSCrossAccountTrustFinding) string {
	if finding.PublicPrincipal {
		return "remove_public_principal"
	}
	if !finding.HasCondition {
		return "add_org_or_source_condition"
	}
	if !finding.TrustedWithinOrganization {
		return "scope_to_known_external_principal"
	}
	return "tighten_existing_condition"
}

func awsTrustPolicyHardeningPrincipalChange(finding AWSCrossAccountTrustFinding) AWSTrustPolicyPrincipalChange {
	if finding.PublicPrincipal {
		afterPrincipals := []string{}
		if finding.ExternalPrincipalARN != "" {
			afterPrincipals = append(afterPrincipals, finding.ExternalPrincipalARN)
		}
		if len(afterPrincipals) == 0 && finding.ExternalPrincipalAccount != "" {
			afterPrincipals = append(afterPrincipals, "arn:aws:iam::"+finding.ExternalPrincipalAccount+":root")
		}
		if len(afterPrincipals) == 0 {
			afterPrincipals = []string{"owner-approved-principal-arn"}
		}
		return AWSTrustPolicyPrincipalChange{
			BeforePrincipals:       []string{"*"},
			AfterPrincipals:        afterPrincipals,
			PublicPrincipalRemoved: true,
			Rationale:              "Replace wildcard public principal with an explicit, owner-approved external principal ARN.",
		}
	}
	if finding.ExternalPrincipalARN == "" {
		return AWSTrustPolicyPrincipalChange{
			Rationale: "Principal is already explicit; the plan focuses on adding boundary conditions instead of narrowing the principal.",
		}
	}
	return AWSTrustPolicyPrincipalChange{
		BeforePrincipals: []string{finding.ExternalPrincipalARN},
		AfterPrincipals:  []string{finding.ExternalPrincipalARN},
		Rationale:        "Keep the explicit external principal and harden the statement via additional conditions below.",
	}
}

func awsTrustPolicyHardeningConditions(finding AWSCrossAccountTrustFinding, evidenceRef string) []AWSTrustPolicyConditionRecommendation {
	out := []AWSTrustPolicyConditionRecommendation{}
	existing := map[string]struct{}{}
	for _, key := range finding.ConditionKeys {
		existing[strings.ToLower(strings.TrimSpace(key))] = struct{}{}
	}
	addCondition := func(operator, key, value, rationale string) {
		if _, ok := existing[strings.ToLower(key)]; ok {
			return
		}
		out = append(out, AWSTrustPolicyConditionRecommendation{
			Operator:    operator,
			Key:         key,
			Value:       value,
			Rationale:   rationale,
			EvidenceRef: evidenceRef,
		})
	}
	if finding.TrustedWithinOrganization {
		addCondition("StringEquals", "aws:PrincipalOrgID", "<owner-approved-org-id>", "Restrict the trust statement to principals inside the approved AWS organization.")
	}
	if !finding.TrustedWithinOrganization && finding.ExternalPrincipalAccount != "" {
		addCondition("StringEquals", "aws:PrincipalAccount", finding.ExternalPrincipalAccount, "Pin the cross-account grant to the known external account id.")
	}
	switch finding.FindingType {
	case "runtime_cross_account_assumption":
		addCondition("StringEquals", "sts:ExternalId", "<owner-approved-external-id>", "Require a shared sts:ExternalId for cross-account role assumption to mitigate confused-deputy risk.")
		addCondition("StringEquals", "aws:SourceIdentity", "<workload-identity>", "Require an aws:SourceIdentity claim from the calling workload so audit logs preserve attribution.")
	case "access_analyzer_external_access":
		addCondition("ArnEquals", "aws:SourceArn", "<owner-approved-source-arn>", "Pin Access Analyzer-flagged external access to an explicit source ARN.")
	case "public_resource_trust":
		addCondition("Bool", "aws:SecureTransport", "true", "Require TLS for any remaining public access to the resource.")
	case "cross_account_graph_path":
		addCondition("StringEquals", "aws:PrincipalOrgID", "<owner-approved-org-id>", "Restrict the cross-account graph path to principals inside the approved AWS organization.")
	}
	if !finding.HasCondition && len(out) == 0 {
		addCondition("StringEquals", "aws:PrincipalOrgID", "<owner-approved-org-id>", "Trust statement carries no condition; bound the principal scope before approving downstream remediation.")
	}
	return out
}

func awsTrustPolicyHardeningStatementSnippets(finding AWSCrossAccountTrustFinding, principal AWSTrustPolicyPrincipalChange, conditions []AWSTrustPolicyConditionRecommendation, evidenceRef string) []AWSTrustPolicyStatementSnippet {
	statement := AWSTrustPolicyStatementSnippet{
		StatementSID:    "trust-policy-hardening-projection",
		Effect:          "Allow",
		ChangeKind:      "principal_and_condition_tightened",
		BeforeRef:       evidenceRef,
		AfterRef:        "trust-policy://" + finding.FindingID + "/scoped-projection",
		ConditionBefore: finding.ConditionKeys,
		ConditionAfter:  awsTrustPolicyHardeningProjectedConditionKeys(finding.ConditionKeys, conditions),
	}
	switch {
	case principal.PublicPrincipalRemoved:
		statement.ChangeKind = "public_principal_removed"
		statement.Rationale = "Remove the wildcard public principal and add the recommended condition boundary."
	case len(conditions) > 0 && len(principal.AfterPrincipals) > 0 && len(principal.BeforePrincipals) == 0:
		statement.ChangeKind = "principal_added"
		statement.Rationale = "Add an explicit principal and a condition boundary in place of the implicit/public trust."
	case len(conditions) > 0:
		statement.ChangeKind = "condition_added"
		statement.Rationale = "Keep the explicit principal and add the recommended condition boundary."
	default:
		statement.ChangeKind = "manual_review"
		statement.Rationale = "Trust path needs manual review: no automatic condition recommendation matched this finding."
	}
	return []AWSTrustPolicyStatementSnippet{statement}
}

func awsTrustPolicyHardeningProjectedConditionKeys(existing []string, conditions []AWSTrustPolicyConditionRecommendation) []string {
	out := make([]string, 0, len(existing)+len(conditions))
	seen := map[string]struct{}{}
	for _, key := range existing {
		trimmed := strings.TrimSpace(key)
		if trimmed == "" {
			continue
		}
		lower := strings.ToLower(trimmed)
		if _, ok := seen[lower]; ok {
			continue
		}
		seen[lower] = struct{}{}
		out = append(out, trimmed)
	}
	for _, condition := range conditions {
		lower := strings.ToLower(condition.Key)
		if _, ok := seen[lower]; ok {
			continue
		}
		seen[lower] = struct{}{}
		out = append(out, condition.Key)
	}
	return out
}

func awsTrustPolicyHardeningAffectedCallers(finding AWSCrossAccountTrustFinding, evidenceRef string) []AWSTrustPolicyAffectedCaller {
	if finding.ExternalPrincipalARN == "" {
		return nil
	}
	return []AWSTrustPolicyAffectedCaller{{
		PrincipalARN:       finding.ExternalPrincipalARN,
		PrincipalAccountID: finding.ExternalPrincipalAccount,
		OUPath:             finding.ExternalPrincipalOUPath,
		TrustedWithinOrg:   finding.TrustedWithinOrganization,
		RuntimeObserved:    finding.RuntimeObserved,
		AnalyzerBacked:     finding.AnalyzerBacked,
		EvidenceRef:        evidenceRef,
	}}
}

func awsTrustPolicyHardeningBreakage(finding AWSCrossAccountTrustFinding, callers []AWSTrustPolicyAffectedCaller) AWSTrustPolicyHardeningBreakageProjection {
	signals := []string{}
	if finding.RuntimeObserved {
		signals = append(signals, "runtime_observed:true")
	}
	if finding.AnalyzerBacked {
		signals = append(signals, "analyzer_backed:true")
	}
	if finding.HasCondition {
		signals = append(signals, "existing_condition:true")
	}
	if len(callers) > 0 {
		signals = append(signals, fmt.Sprintf("affected_callers:%d", len(callers)))
	}
	if finding.PublicPrincipal {
		return AWSTrustPolicyHardeningBreakageProjection{
			Level:     "high",
			Rationale: "Public principal: unknown callers may depend on the wildcard trust. Owner approval is required before applying.",
			Signals:   signals,
		}
	}
	if !finding.RuntimeObserved && !finding.AnalyzerBacked {
		return AWSTrustPolicyHardeningBreakageProjection{
			Level:     "unknown",
			Rationale: "No runtime or Access Analyzer evidence proves which callers rely on this trust; manual breakage review required.",
			Signals:   signals,
		}
	}
	if finding.RuntimeObserved && finding.AnalyzerBacked {
		return AWSTrustPolicyHardeningBreakageProjection{
			Level:     "low",
			Rationale: "Runtime correlation and Access Analyzer both confirm the known caller set; condition boundary should not break new callers.",
			Signals:   signals,
		}
	}
	return AWSTrustPolicyHardeningBreakageProjection{
		Level:     "medium",
		Rationale: "Only one of runtime or Access Analyzer confirms the caller set; review affected callers before apply.",
		Signals:   signals,
	}
}

func awsTrustPolicyHardeningRollback(finding AWSCrossAccountTrustFinding, evidenceRef string) AWSTrustPolicyHardeningRollbackPlan {
	if finding.PublicPrincipal {
		return AWSTrustPolicyHardeningRollbackPlan{
			Strategy:    "restore_trust_policy",
			Steps:       []string{"Restore the previous trust policy from the captured before_ref.", "Re-run cross-account-trust to confirm the wildcard principal returns.", "Document the rollback in the remediation case audit trail."},
			EvidenceRef: evidenceRef,
		}
	}
	return AWSTrustPolicyHardeningRollbackPlan{
		Strategy:    "restore_trust_policy",
		Steps:       []string{"Restore the previous trust statement from the captured before_ref.", "Re-run cross-account-trust to confirm the previous principal/condition set."},
		EvidenceRef: evidenceRef,
	}
}

func awsTrustPolicyHardeningVerification(finding AWSCrossAccountTrustFinding, evidenceRef string) AWSTrustPolicyHardeningVerificationPlan {
	steps := []string{"Re-run cross-account-trust after the change and confirm the finding's severity drops or it disappears."}
	successSignals := []string{"cross_account_trust:finding-resolved"}
	failureSignals := []string{"cross_account_trust:finding-unchanged"}
	switch finding.FindingType {
	case "runtime_cross_account_assumption":
		steps = append(steps, "Watch the next runtime correlation window for an STS AssumeRole failure from any caller that does not satisfy the new sts:ExternalId / aws:SourceIdentity condition.")
		failureSignals = append(failureSignals, "agent_runtime_access:assume-role-denied-unexpected")
	case "access_analyzer_external_access":
		steps = append(steps, "Wait one Access Analyzer scan cycle and confirm the analyzer finding clears.")
		successSignals = append(successSignals, "access_analyzer:finding-cleared")
	case "public_resource_trust":
		steps = append(steps, "Re-run resource-policy reachability to confirm no public principal path remains.")
		successSignals = append(successSignals, "blast_radius:no-public-principal")
	}
	return AWSTrustPolicyHardeningVerificationPlan{
		Strategy:       "trust_policy_re_evaluate",
		Steps:          steps,
		SuccessSignals: successSignals,
		FailureSignals: failureSignals,
		EvidenceRef:    evidenceRef,
	}
}

func awsTrustPolicyHardeningReadyForApply(finding AWSCrossAccountTrustFinding, breakage AWSTrustPolicyHardeningBreakageProjection, conditions []AWSTrustPolicyConditionRecommendation) bool {
	if finding.PublicPrincipal {
		return false
	}
	if breakage.Level != "low" {
		return false
	}
	if len(conditions) == 0 {
		return false
	}
	if finding.Confidence < 0.8 {
		return false
	}
	return true
}

func awsTrustPolicyHardeningTitle(finding AWSCrossAccountTrustFinding, direction string) string {
	display := firstNonEmptyAWSValue(finding.ResourceLabel, finding.ResourceARN, finding.ResourceNodeID, finding.Service)
	switch direction {
	case "remove_public_principal":
		return fmt.Sprintf("Remove public trust on %s", display)
	case "add_org_or_source_condition":
		return fmt.Sprintf("Add org/source condition to %s trust", display)
	case "scope_to_known_external_principal":
		return fmt.Sprintf("Scope %s trust to known external principal", display)
	case "tighten_existing_condition":
		return fmt.Sprintf("Tighten existing trust condition on %s", display)
	default:
		return fmt.Sprintf("Harden trust policy on %s", display)
	}
}

func awsTrustPolicyHardeningRelationships(plans []AWSTrustPolicyHardeningPlan) []AWSTrustPolicyHardeningRelationship {
	relationships := []AWSTrustPolicyHardeningRelationship{}
	for _, p := range plans {
		from := firstNonEmptyAWSValue(p.ResourceNodeID, p.ResourceARN)
		if from == "" {
			continue
		}
		for _, target := range p.ImpactedNodes {
			if target == "" || target == from {
				continue
			}
			relationships = append(relationships, AWSTrustPolicyHardeningRelationship{
				PlanID:      p.PlanID,
				Type:        "trust_policy_hardening_path",
				FromNodeID:  from,
				ToNodeID:    target,
				EvidenceRef: firstString(awsTrustPolicyHardeningEvidenceRefs(p.Evidence)),
			})
		}
		for _, caller := range p.AffectedCallers {
			if caller.PrincipalARN == "" || caller.PrincipalARN == from {
				continue
			}
			relationships = append(relationships, AWSTrustPolicyHardeningRelationship{
				PlanID:      p.PlanID,
				Type:        "trust_policy_hardening_affected_caller",
				FromNodeID:  from,
				ToNodeID:    caller.PrincipalARN,
				EvidenceRef: caller.EvidenceRef,
			})
		}
	}
	return relationships
}

func summarizeAWSTrustPolicyHardeningPlans(all, filtered []AWSTrustPolicyHardeningPlan, relationships []AWSTrustPolicyHardeningRelationship) AWSTrustPolicyHardeningSummary {
	summary := AWSTrustPolicyHardeningSummary{
		TotalPlans:               len(all),
		FilteredPlans:            len(filtered),
		SeverityCounts:           map[string]int{},
		StatusCounts:             map[string]int{},
		FindingTypeCounts:        map[string]int{},
		HardeningDirectionCounts: map[string]int{},
		BreakageLevelCounts:      map[string]int{},
		RelationshipCount:        len(relationships),
	}
	confidenceTotal := 0.0
	for _, p := range filtered {
		summary.SeverityCounts[p.Severity]++
		summary.StatusCounts[p.Status]++
		summary.FindingTypeCounts[p.FindingType]++
		summary.HardeningDirectionCounts[p.HardeningDirection]++
		summary.BreakageLevelCounts[p.BreakageProjection.Level]++
		if p.PublicPrincipal {
			summary.PublicPrincipalCount++
		}
		if !p.TrustedWithinOrganization {
			summary.CrossAccountCount++
		}
		if len(p.ConditionRecommendations) > 0 {
			summary.ConditionedCount++
		}
		if p.RuntimeObserved {
			summary.RuntimeObservedCount++
		}
		if p.AnalyzerBacked {
			summary.AnalyzerBackedCount++
		}
		if p.ReadyForApply {
			summary.ReadyForApplyCount++
		}
		for _, snippet := range p.StatementSnippets {
			if snippet.ChangeKind == "manual_review" {
				summary.ManualReviewCount++
			}
		}
		summary.AffectedCallerCount += len(p.AffectedCallers)
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

func filterAWSTrustPolicyHardeningPlans(plans []AWSTrustPolicyHardeningPlan, request AWSTrustPolicyHardeningRequest) ([]AWSTrustPolicyHardeningPlan, map[string]string) {
	filters := map[string]string{
		"account_id":          strings.TrimSpace(request.AccountID),
		"region":              strings.TrimSpace(request.Region),
		"service":             strings.TrimSpace(request.Service),
		"resource":            strings.TrimSpace(request.Resource),
		"principal":           strings.TrimSpace(request.Principal),
		"hardening_direction": normalizeAWSRuntimeEventFilterToken(request.HardeningDirection),
		"breakage_level":      normalizeAWSRuntimeEventFilterToken(request.BreakageLevel),
		"severity":            normalizeAWSRuntimeEventFilterToken(request.Severity),
		"status":              normalizeAWSRuntimeEventFilterToken(request.Status),
		"ready_for_apply":     strings.ToLower(strings.TrimSpace(request.ReadyForApply)),
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
	filtered := make([]AWSTrustPolicyHardeningPlan, 0, len(plans))
	for _, p := range plans {
		if filters["account_id"] != "" && filters["account_id"] != p.AccountID {
			continue
		}
		if filters["region"] != "" && !strings.EqualFold(filters["region"], p.Region) {
			continue
		}
		if filters["service"] != "" && !strings.EqualFold(filters["service"], p.Service) {
			continue
		}
		if filters["hardening_direction"] != "" && filters["hardening_direction"] != normalizeAWSRuntimeEventFilterToken(p.HardeningDirection) {
			continue
		}
		if filters["breakage_level"] != "" && filters["breakage_level"] != normalizeAWSRuntimeEventFilterToken(p.BreakageProjection.Level) {
			continue
		}
		if filters["severity"] != "" && filters["severity"] != normalizeAWSRuntimeEventFilterToken(p.Severity) {
			continue
		}
		if filters["status"] != "" && filters["status"] != normalizeAWSRuntimeEventFilterToken(p.Status) {
			continue
		}
		if filters["ready_for_apply"] != "" {
			want := filters["ready_for_apply"]
			if (want == "true" || want == "yes") != p.ReadyForApply {
				continue
			}
		}
		if filters["resource"] != "" && !awsTrustPolicyHardeningResourceMatch(p, filters["resource"]) {
			continue
		}
		if filters["principal"] != "" && !awsTrustPolicyHardeningPrincipalMatch(p, filters["principal"]) {
			continue
		}
		if filters["search"] != "" && !awsTrustPolicyHardeningSearchMatch(p, filters["search"]) {
			continue
		}
		filtered = append(filtered, p)
	}
	return filtered, applied
}

func awsTrustPolicyHardeningResourceMatch(p AWSTrustPolicyHardeningPlan, needle string) bool {
	needle = strings.ToLower(strings.TrimSpace(needle))
	if needle == "" {
		return true
	}
	hay := strings.ToLower(strings.Join([]string{p.ResourceNodeID, p.ResourceARN, p.ResourceLabel, p.ResourceType, p.Service}, " "))
	return strings.Contains(hay, needle)
}

func awsTrustPolicyHardeningPrincipalMatch(p AWSTrustPolicyHardeningPlan, needle string) bool {
	needle = strings.ToLower(strings.TrimSpace(needle))
	if needle == "" {
		return true
	}
	values := []string{}
	for _, caller := range p.AffectedCallers {
		values = append(values, caller.PrincipalARN, caller.PrincipalAccountID, caller.OUPath)
	}
	values = append(values, p.PrincipalChange.BeforePrincipals...)
	values = append(values, p.PrincipalChange.AfterPrincipals...)
	for _, value := range values {
		if strings.Contains(strings.ToLower(value), needle) {
			return true
		}
	}
	return false
}

func awsTrustPolicyHardeningSearchMatch(p AWSTrustPolicyHardeningPlan, needle string) bool {
	needle = strings.ToLower(strings.TrimSpace(needle))
	if needle == "" {
		return true
	}
	values := []string{p.PlanID, p.Title, p.Summary, p.SourceFindingID, p.FindingType, p.HardeningDirection, p.Severity, p.Status, p.Service, p.ResourceType, p.ResourceNodeID, p.ResourceARN, p.ResourceLabel, p.BreakageProjection.Level, p.BreakageProjection.Rationale, p.RollbackPlan.Strategy, p.RollbackPlan.EvidenceRef, p.VerificationPlan.Strategy, p.VerificationPlan.EvidenceRef, p.NextAction, p.PrincipalChange.Rationale}
	values = append(values, p.PrincipalChange.BeforePrincipals...)
	values = append(values, p.PrincipalChange.AfterPrincipals...)
	values = append(values, p.BreakageProjection.Signals...)
	values = append(values, p.RollbackPlan.Steps...)
	values = append(values, p.VerificationPlan.Steps...)
	values = append(values, p.VerificationPlan.SuccessSignals...)
	values = append(values, p.VerificationPlan.FailureSignals...)
	for _, condition := range p.ConditionRecommendations {
		values = append(values, condition.Operator, condition.Key, condition.Value, condition.Rationale, condition.EvidenceRef)
	}
	for _, snippet := range p.StatementSnippets {
		values = append(values, snippet.StatementSID, snippet.Effect, snippet.ChangeKind, snippet.Rationale, snippet.BeforeRef, snippet.AfterRef)
		values = append(values, snippet.ConditionBefore...)
		values = append(values, snippet.ConditionAfter...)
	}
	for _, caller := range p.AffectedCallers {
		values = append(values, caller.PrincipalARN, caller.PrincipalAccountID, caller.OUPath, caller.EvidenceRef)
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

func summarizeAWSTrustPolicyHardeningStatus(sources awsTrustPolicyHardeningSources, filtered []AWSTrustPolicyHardeningPlan, diagnostics []AWSTrustPolicyHardeningDiagnostic) (string, float64) {
	if sources.trust.Status == awsPlatformDependencyStatusBlocked {
		return awsPlatformDependencyStatusBlocked, 0.35
	}
	for _, diagnostic := range diagnostics {
		if diagnostic.Retryable {
			return awsPlatformDependencyStatusDegraded, 0.72
		}
	}
	if sources.trust.Status == awsPlatformDependencyStatusDegraded {
		return awsPlatformDependencyStatusDegraded, 0.76
	}
	if len(filtered) == 0 {
		return awsPlatformDependencyStatusReady, 0.82
	}
	return awsPlatformDependencyStatusReady, 0.9
}

func awsTrustPolicyHardeningFailureReasons(sources awsTrustPolicyHardeningSources) []string {
	return dedupeStrings(append([]string{}, sources.trust.FailureReasons...))
}

func awsTrustPolicyHardeningRemediationHints(sources awsTrustPolicyHardeningSources) []string {
	out := []string{
		"Apply each plan only after the matching remediation case is approved; this engine is read-only and does not call any IAM write API.",
		"Pair each plan with its rollback and verification plan before scheduling execution.",
	}
	out = append(out, sources.trust.RemediationHints...)
	return dedupeStrings(out)
}

func awsTrustPolicyHardeningCaveats() []string {
	return []string{
		"Trust policy hardening plans are read-only projections; the engine never applies an AWS change.",
		"Principal and condition snippets carry identifier metadata only — never rendered JSON policy bodies, secret values, or workload payloads.",
		"ready_for_apply is derived deterministically (non-public principal + breakage_level=low + at least one condition recommendation + confidence >= 0.80); approve/execute/verify transitions belong to future wave issues.",
	}
}

func awsTrustPolicyHardeningDiagnostics(sources awsTrustPolicyHardeningSources) []AWSTrustPolicyHardeningDiagnostic {
	out := []AWSTrustPolicyHardeningDiagnostic{}
	for _, d := range sources.trust.Diagnostics {
		if strings.TrimSpace(d.Message) == "" && strings.TrimSpace(d.Code) == "" {
			continue
		}
		out = append(out, AWSTrustPolicyHardeningDiagnostic{Collector: d.Collector, SourceID: d.SourceID, Code: d.Code, Message: d.Message, Remediation: d.Remediation, Retryable: d.Retryable})
	}
	return out
}

func awsTrustPolicyHardeningCoverageGaps(sources awsTrustPolicyHardeningSources) []AWSTrustPolicyHardeningCoverageGap {
	out := []AWSTrustPolicyHardeningCoverageGap{{
		Capability:  "trust_policy_apply",
		Status:      "out_of_scope",
		Reason:      "Issue #1531 implements the trust policy hardening projection only; apply/verify transitions are future-wave work and never call IAM write APIs here.",
		Remediation: "Wire the approve/execute/verify endpoints in the relevant remediation/governance issue once the safety gates are in place.",
	}}
	for _, g := range sources.trust.CoverageGaps {
		out = append(out, AWSTrustPolicyHardeningCoverageGap{Capability: g.Capability, Status: g.Status, Reason: g.Reason, Remediation: g.Remediation})
	}
	return out
}

func awsTrustPolicyHardeningEvidenceBoundary() string {
	return "metadata_only_no_rendered_policy_bodies_no_secret_values_no_workload_payloads"
}

func awsTrustPolicyHardeningEvidenceRefs(evidence []AWSTrustPolicyHardeningEvidence) []string {
	out := []string{}
	for _, item := range evidence {
		if strings.TrimSpace(item.EvidenceRef) != "" {
			out = append(out, item.EvidenceRef)
		}
	}
	return dedupeStrings(out)
}
