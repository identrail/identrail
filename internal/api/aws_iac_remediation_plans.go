package api

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	awsIaCRemediationCurrentIssue = 1535
	awsIaCRemediationVersion      = "aws-iac-remediation-plan-generator-v1"

	awsIaCTargetTerraform      = "terraform"
	awsIaCTargetCloudFormation = "cloudformation"
	awsIaCTargetCDK            = "cdk"
	awsIaCTargetPolicyAsCode   = "policy_as_code"

	awsIaCChangeKindIAMPolicyDiff       = "iam_policy_diff"
	awsIaCChangeKindTrustPolicyHardened = "trust_policy_hardening"
)

// AWSIaCRemediationRequest scopes the deterministic IaC remediation PR
// generator to one AWS connector plus optional operator drill-down filters.
type AWSIaCRemediationRequest struct {
	ConnectorID   string `json:"connector_id,omitempty"`
	FixtureState  string `json:"fixture_state,omitempty"`
	AccountID     string `json:"account_id,omitempty"`
	Region        string `json:"region,omitempty"`
	Identity      string `json:"identity,omitempty"`
	IaCTarget     string `json:"iac_target,omitempty"`
	ChangeKind    string `json:"change_kind,omitempty"`
	Severity      string `json:"severity,omitempty"`
	Status        string `json:"status,omitempty"`
	ReadyForApply string `json:"ready_for_apply,omitempty"`
	Search        string `json:"search,omitempty"`
}

// Reuse upstream evidence shapes so the generator stays consistent with its
// IAM-diff and trust-hardening sources.
type AWSIaCRemediationEvidence = AWSLeastPrivilegeEvidence
type AWSIaCRemediationPathStep = AWSLeastPrivilegePathStep
type AWSIaCRemediationDiagnostic = AWSLeastPrivilegeDiagnostic
type AWSIaCRemediationCoverageGap = AWSLeastPrivilegeCoverageGap

// AWSIaCFileChange describes one file the generated PR would touch. Bodies are
// intentionally not inlined; the generator emits change intent and references
// to upstream before/after metadata only.
type AWSIaCFileChange struct {
	Path         string `json:"path"`
	ChangeIntent string `json:"change_intent"`
	ResourceType string `json:"resource_type,omitempty"`
	BeforeRef    string `json:"before_ref,omitempty"`
	AfterRef     string `json:"after_ref,omitempty"`
	Rationale    string `json:"rationale"`
}

// AWSIaCValidationHint records a local validation step the operator should run
// before opening the PR. Commands are operator-runnable but the generator does
// not execute them.
type AWSIaCValidationHint struct {
	Tool        string `json:"tool"`
	Command     string `json:"command"`
	Description string `json:"description"`
}

// AWSIaCCloudVerificationCheck records a cloud-side verification step after
// the PR ships. Each entry is metadata-only and refers to evidence sources.
type AWSIaCCloudVerificationCheck struct {
	Source      string `json:"source"`
	Signal      string `json:"signal"`
	Description string `json:"description"`
}

// AWSIaCPRNotes is the deterministic PR-body skeleton the generator emits.
// The generator never opens a PR externally; this is metadata only.
type AWSIaCPRNotes struct {
	Title        string   `json:"title"`
	Summary      string   `json:"summary"`
	Labels       []string `json:"labels,omitempty"`
	EvidenceRefs []string `json:"evidence_refs,omitempty"`
	Reviewers    []string `json:"reviewers,omitempty"`
}

// AWSIaCReadinessGate explains one prerequisite the operator must satisfy
// before the IaC PR can ship.
type AWSIaCReadinessGate struct {
	Name      string `json:"name"`
	Status    string `json:"status"`
	Rationale string `json:"rationale"`
}

// AWSIaCRemediationRelationship surfaces plan→graph node edges so the app and
// downstream graph consumers can show why a plan touches a node.
type AWSIaCRemediationRelationship struct {
	PlanID      string `json:"plan_id"`
	Type        string `json:"type"`
	FromNodeID  string `json:"from_node_id"`
	ToNodeID    string `json:"to_node_id"`
	EvidenceRef string `json:"evidence_ref,omitempty"`
}

// AWSIaCRemediationPlan is the persisted-record-shaped contract emitted by the
// IaC remediation PR generator. It carries change intent, file paths,
// validation hints, cloud verification, PR notes, rollback, and verification
// metadata only. Rendered IaC bodies, secret values, and customer payloads are
// never inlined.
type AWSIaCRemediationPlan struct {
	PlanID             string                         `json:"plan_id"`
	CalculationVersion string                         `json:"calculation_version"`
	ChangeKind         string                         `json:"change_kind"`
	IaCTarget          string                         `json:"iac_target"`
	SourceArtifactID   string                         `json:"source_artifact_id"`
	SourceCaseID       string                         `json:"source_case_id,omitempty"`
	Severity           string                         `json:"severity"`
	Status             string                         `json:"status"`
	Score              int                            `json:"score"`
	Confidence         float64                        `json:"confidence"`
	Title              string                         `json:"title"`
	Summary            string                         `json:"summary"`
	AccountID          string                         `json:"account_id"`
	Region             string                         `json:"region"`
	Service            string                         `json:"service,omitempty"`
	IdentityNodeID     string                         `json:"identity_node_id,omitempty"`
	IdentityARN        string                         `json:"identity_arn,omitempty"`
	IdentityName       string                         `json:"identity_name,omitempty"`
	ResourceNodeID     string                         `json:"resource_node_id,omitempty"`
	ResourceARN        string                         `json:"resource_arn,omitempty"`
	FileChanges        []AWSIaCFileChange             `json:"file_changes"`
	ValidationHints    []AWSIaCValidationHint         `json:"validation_hints"`
	CloudVerification  []AWSIaCCloudVerificationCheck `json:"cloud_verification"`
	PRNotes            AWSIaCPRNotes                  `json:"pr_notes"`
	DiffIntent         AWSRemediationDiffIntent       `json:"diff_intent"`
	Tradeoffs          []AWSRemediationTradeoff       `json:"tradeoffs"`
	RollbackPlan       AWSRemediationRollbackPlan     `json:"rollback_plan"`
	VerificationPlan   AWSRemediationVerificationPlan `json:"verification_plan"`
	ReadinessGates     []AWSIaCReadinessGate          `json:"readiness_gates"`
	ReadyForApply      bool                           `json:"ready_for_apply"`
	ReadOnlyProjection bool                           `json:"read_only_projection"`
	SourceSignals      []string                       `json:"source_signals"`
	Evidence           []AWSIaCRemediationEvidence    `json:"evidence"`
	EvidenceBoundary   string                         `json:"evidence_boundary"`
	ImpactedNodes      []string                       `json:"impacted_nodes"`
	ImpactedPath       []AWSIaCRemediationPathStep    `json:"impacted_path"`
	NextAction         string                         `json:"next_action"`
	CreatedAt          time.Time                      `json:"created_at"`
	UpdatedAt          time.Time                      `json:"updated_at"`
}

// AWSIaCRemediationSummary aggregates the unfiltered and filtered plan set.
type AWSIaCRemediationSummary struct {
	TotalPlans           int            `json:"total_plans"`
	FilteredPlans        int            `json:"filtered_plans"`
	ChangeKindCounts     map[string]int `json:"change_kind_counts"`
	IaCTargetCounts      map[string]int `json:"iac_target_counts"`
	SeverityCounts       map[string]int `json:"severity_counts"`
	StatusCounts         map[string]int `json:"status_counts"`
	ReadyForApplyCount   int            `json:"ready_for_apply_count"`
	ManualReviewCount    int            `json:"manual_review_count"`
	FileChangeCount      int            `json:"file_change_count"`
	ValidationHintCount  int            `json:"validation_hint_count"`
	VerificationCount    int            `json:"verification_count"`
	RelationshipCount    int            `json:"relationship_count"`
	HighestScore         int            `json:"highest_score"`
	AverageConfidencePct int            `json:"average_confidence_pct"`
}

// AWSIaCRemediationResult is the deterministic generator envelope.
type AWSIaCRemediationResult struct {
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
	Summary            AWSIaCRemediationSummary        `json:"summary"`
	Plans              []AWSIaCRemediationPlan         `json:"plans"`
	Relationships      []AWSIaCRemediationRelationship `json:"relationships"`
	Caveats            []string                        `json:"caveats"`
	FailureReasons     []string                        `json:"failure_reasons"`
	RemediationHints   []string                        `json:"remediation_hints"`
	EvidenceLinks      []string                        `json:"evidence_links"`
	CoverageGaps       []AWSIaCRemediationCoverageGap  `json:"coverage_gaps"`
	Diagnostics        []AWSIaCRemediationDiagnostic   `json:"diagnostics"`
	GeneratedAt        time.Time                       `json:"generated_at"`
	UpdatedAt          time.Time                       `json:"updated_at"`
}

type awsIaCRemediationSources struct {
	iamPolicyDiffs       AWSIAMPolicyDiffResult
	trustPolicyHardening AWSTrustPolicyHardeningResult
}

// GetAWSIaCRemediationPlans composes ranked IaC remediation PR and
// verification plans from upstream IAM policy diffs and trust policy hardening
// plans. The generator is read-only: it never opens a real PR, never mutates
// AWS, never reads or returns rendered IaC bodies, secret values, or workload
// payloads, and treats unknown or denied evidence as explicit states instead
// of deterministic truth.
func (s *Service) GetAWSIaCRemediationPlans(ctx context.Context, workspaceID string, projectID string, request AWSIaCRemediationRequest) (AWSIaCRemediationResult, error) {
	project, scope, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return AWSIaCRemediationResult{}, err
	}
	connection, hasConnection, err := s.awsBaselineConnection(ctx, project, strings.TrimSpace(request.ConnectorID))
	if err != nil {
		return AWSIaCRemediationResult{}, err
	}
	now := s.Now().UTC()
	fixtureState := normalizeAWSIaCRemediationFixtureState(request.FixtureState, connection, hasConnection)
	if fixtureState == "" {
		return AWSIaCRemediationResult{}, ErrInvalidAWSConnectionRequest
	}

	accountID := firstNonEmptyAWSValue(connection.AccountID, strings.TrimSpace(request.AccountID), "123456789012")
	region := firstNonEmptyAWSValue(connection.Region, strings.TrimSpace(request.Region), "us-east-1")
	connectorID := firstNonEmptyAWSValue(connection.ConnectorID, strings.TrimSpace(request.ConnectorID))
	sourceFixtureState := fixtureState
	if strings.TrimSpace(request.FixtureState) == "" && hasConnection && connection.Connected {
		sourceFixtureState = ""
	}

	sources, err := s.awsIaCRemediationSources(ctx, workspaceID, projectID, connectorID, sourceFixtureState)
	if err != nil {
		return AWSIaCRemediationResult{}, err
	}
	plans := awsIaCRemediationPlans(sources, now)
	sort.SliceStable(plans, func(i, j int) bool {
		if plans[i].Score == plans[j].Score {
			return plans[i].PlanID < plans[j].PlanID
		}
		return plans[i].Score > plans[j].Score
	})
	filtered, applied := filterAWSIaCRemediationPlans(plans, request)
	relationships := awsIaCRemediationRelationships(filtered)
	diagnostics := awsIaCRemediationDiagnostics(sources)
	coverageGaps := awsIaCRemediationCoverageGaps(sources)
	status, confidence := summarizeAWSIaCRemediationStatus(sources, filtered, diagnostics)

	return AWSIaCRemediationResult{
		TenantID:           scope.TenantID,
		WorkspaceID:        project.WorkspaceID,
		ProjectID:          project.ProjectID,
		ConnectorID:        connectorID,
		AccountID:          accountID,
		Region:             region,
		ParentIssueNumber:  awsPlatformDependencyParentIssue,
		ParentIssueRef:     awsIssueRef(awsPlatformDependencyParentIssue),
		CurrentIssueNumber: awsIaCRemediationCurrentIssue,
		CurrentIssueRef:    awsIssueRef(awsIaCRemediationCurrentIssue),
		Version:            awsIaCRemediationVersion,
		Status:             status,
		FixtureState:       sourceFixtureState,
		Confidence:         confidence,
		CalculationVersion: awsIaCRemediationVersion,
		AppliedFilters:     applied,
		Summary:            summarizeAWSIaCRemediationPlans(plans, filtered, relationships),
		Plans:              filtered,
		Relationships:      relationships,
		Caveats:            awsIaCRemediationCaveats(),
		FailureReasons:     awsIaCRemediationFailureReasons(sources),
		RemediationHints:   awsIaCRemediationRemediationHints(sources),
		EvidenceLinks: dedupeStrings([]string{
			awsIssueURL(awsPlatformDependencyParentIssue),
			awsIssueURL(awsIaCRemediationCurrentIssue),
			awsIssueURL(awsIAMPolicyDiffCurrentIssue),
			awsIssueURL(awsTrustPolicyHardeningCurrentIssue),
			"/docs/aws-iac-remediation-planner",
			"/docs/aws-iam-policy-least-privilege-diff",
			"/docs/aws-trust-policy-hardening-planner",
			awsBaselineProjectEvidenceURL(scope, project),
		}),
		CoverageGaps: coverageGaps,
		Diagnostics:  diagnostics,
		GeneratedAt:  now,
		UpdatedAt:    now,
	}, nil
}

func normalizeAWSIaCRemediationFixtureState(requested string, connection AWSConnectionStatus, hasConnection bool) string {
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

func (s *Service) awsIaCRemediationSources(ctx context.Context, workspaceID, projectID, connectorID, fixtureState string) (awsIaCRemediationSources, error) {
	diffs, err := s.GetAWSIAMPolicyDiffs(ctx, workspaceID, projectID, AWSIAMPolicyDiffRequest{ConnectorID: connectorID, FixtureState: fixtureState})
	if err != nil {
		return awsIaCRemediationSources{}, fmt.Errorf("iac remediation iam policy diffs: %w", err)
	}
	trust, err := s.GetAWSTrustPolicyHardeningPlans(ctx, workspaceID, projectID, AWSTrustPolicyHardeningRequest{ConnectorID: connectorID, FixtureState: fixtureState})
	if err != nil {
		return awsIaCRemediationSources{}, fmt.Errorf("iac remediation trust policy hardening: %w", err)
	}
	return awsIaCRemediationSources{iamPolicyDiffs: diffs, trustPolicyHardening: trust}, nil
}

func awsIaCRemediationPlans(sources awsIaCRemediationSources, now time.Time) []AWSIaCRemediationPlan {
	plans := []AWSIaCRemediationPlan{}
	for _, diff := range sources.iamPolicyDiffs.Diffs {
		if plan, ok := awsIaCRemediationPlanFromIAMDiff(diff, now); ok {
			plans = append(plans, plan)
		}
	}
	for _, hardening := range sources.trustPolicyHardening.Plans {
		if plan, ok := awsIaCRemediationPlanFromTrustHardening(hardening, now); ok {
			plans = append(plans, plan)
		}
	}
	return plans
}

func awsIaCRemediationPlanFromIAMDiff(diff AWSIAMPolicyDiff, now time.Time) (AWSIaCRemediationPlan, bool) {
	if diff.DiffID == "" {
		return AWSIaCRemediationPlan{}, false
	}
	target := awsIaCTargetForService(diff.Service, diff.ResourceARN)
	resourceSlug := awsIaCResourceSlug(firstNonEmptyAWSValue(diff.IdentityName, diff.IdentityNodeID, diff.DiffID))
	evidenceRef := firstString(awsIAMPolicyDiffEvidenceRefs(diff.Evidence))
	files := awsIaCFileChangesForIAMDiff(diff, target, resourceSlug, evidenceRef)
	validation := awsIaCValidationHintsForTarget(target, files)
	verification := awsIaCCloudVerificationForIAMDiff(diff)
	gates := awsIaCReadinessGatesForIAMDiff(diff)
	pr := awsIaCPRNotesForIAMDiff(diff)
	plan := AWSIaCRemediationPlan{
		PlanID:             "aws-iac-remediation:" + stableAWSBlastRadiusToken(awsIaCChangeKindIAMPolicyDiff, target, diff.DiffID),
		CalculationVersion: awsIaCRemediationVersion,
		ChangeKind:         awsIaCChangeKindIAMPolicyDiff,
		IaCTarget:          target,
		SourceArtifactID:   diff.DiffID,
		Severity:           diff.Severity,
		Status:             diff.Status,
		Score:              diff.Score,
		Confidence:         diff.Confidence,
		Title:              fmt.Sprintf("IaC PR (%s): scope %s least-privilege", awsIaCTargetLabel(target), firstNonEmptyAWSValue(diff.IdentityName, diff.IdentityNodeID, "IAM identity")),
		Summary:            diff.Summary,
		AccountID:          diff.AccountID,
		Region:             diff.Region,
		Service:            diff.Service,
		IdentityNodeID:     diff.IdentityNodeID,
		IdentityARN:        diff.IdentityARN,
		IdentityName:       diff.IdentityName,
		ResourceNodeID:     diff.ResourceNodeID,
		ResourceARN:        diff.ResourceARN,
		FileChanges:        files,
		ValidationHints:    validation,
		CloudVerification:  verification,
		PRNotes:            pr,
		DiffIntent: AWSRemediationDiffIntent{
			Kind:               "iac_iam_policy_pr",
			BeforeRef:          firstNonEmptyAWSValue(evidenceRef, diff.DiffID),
			AfterRef:           fmt.Sprintf("iac://%s/%s/after", target, diff.DiffID),
			DiffSummary:        fmt.Sprintf("Apply the projected IAM least-privilege diff via %s; no AWS write API is called by Identrail.", awsIaCTargetLabel(target)),
			ReadOnlyProjection: true,
		},
		Tradeoffs:          awsIaCTradeoffsForIAMDiff(diff),
		RollbackPlan:       awsIaCRollbackForIAMDiff(diff, evidenceRef),
		VerificationPlan:   awsIaCVerificationPlanForIAMDiff(diff, evidenceRef),
		ReadinessGates:     gates,
		ReadyForApply:      awsIaCReadyForApply(gates, diff.ReadyForApply),
		ReadOnlyProjection: true,
		SourceSignals:      []string{"iam_policy_diff"},
		Evidence:           diff.Evidence,
		EvidenceBoundary:   awsIaCRemediationEvidenceBoundary(),
		ImpactedNodes:      diff.ImpactedNodes,
		ImpactedPath:       diff.ImpactedPath,
		NextAction:         "Open the generated IaC PR in the operator's source-control system; Identrail does not push or create PRs.",
		CreatedAt:          now,
		UpdatedAt:          now,
	}
	return plan, true
}

func awsIaCRemediationPlanFromTrustHardening(hardening AWSTrustPolicyHardeningPlan, now time.Time) (AWSIaCRemediationPlan, bool) {
	if hardening.PlanID == "" {
		return AWSIaCRemediationPlan{}, false
	}
	target := awsIaCTargetForService(hardening.Service, hardening.ResourceARN)
	resourceSlug := awsIaCResourceSlug(firstNonEmptyAWSValue(hardening.ResourceLabel, hardening.ResourceNodeID, hardening.PlanID))
	evidenceRef := firstString(awsIAMPolicyDiffEvidenceRefs(hardening.Evidence))
	files := awsIaCFileChangesForTrustHardening(hardening, target, resourceSlug, evidenceRef)
	validation := awsIaCValidationHintsForTarget(target, files)
	verification := awsIaCCloudVerificationForTrustHardening(hardening)
	gates := awsIaCReadinessGatesForTrustHardening(hardening)
	pr := awsIaCPRNotesForTrustHardening(hardening)
	plan := AWSIaCRemediationPlan{
		PlanID:             "aws-iac-remediation:" + stableAWSBlastRadiusToken(awsIaCChangeKindTrustPolicyHardened, target, hardening.PlanID),
		CalculationVersion: awsIaCRemediationVersion,
		ChangeKind:         awsIaCChangeKindTrustPolicyHardened,
		IaCTarget:          target,
		SourceArtifactID:   hardening.PlanID,
		Severity:           hardening.Severity,
		Status:             hardening.Status,
		Score:              hardening.Score,
		Confidence:         hardening.Confidence,
		Title:              fmt.Sprintf("IaC PR (%s): harden trust policy for %s", awsIaCTargetLabel(target), firstNonEmptyAWSValue(hardening.ResourceLabel, hardening.ResourceNodeID, "trusting resource")),
		Summary:            hardening.Summary,
		AccountID:          hardening.AccountID,
		Region:             hardening.Region,
		Service:            hardening.Service,
		ResourceNodeID:     hardening.ResourceNodeID,
		ResourceARN:        hardening.ResourceARN,
		IdentityName:       hardening.ResourceLabel,
		FileChanges:        files,
		ValidationHints:    validation,
		CloudVerification:  verification,
		PRNotes:            pr,
		DiffIntent: AWSRemediationDiffIntent{
			Kind:               "iac_trust_policy_pr",
			BeforeRef:          firstNonEmptyAWSValue(evidenceRef, hardening.PlanID),
			AfterRef:           fmt.Sprintf("iac://%s/%s/after", target, hardening.PlanID),
			DiffSummary:        fmt.Sprintf("Apply trust-policy hardening (%s) via %s; no AWS write API is called by Identrail.", formatAWSBlastRadiusLabel(hardening.HardeningDirection), awsIaCTargetLabel(target)),
			ReadOnlyProjection: true,
		},
		Tradeoffs:          awsIaCTradeoffsForTrustHardening(hardening),
		RollbackPlan:       awsIaCRollbackForTrustHardening(hardening, evidenceRef),
		VerificationPlan:   awsIaCVerificationPlanForTrustHardening(hardening, evidenceRef),
		ReadinessGates:     gates,
		ReadyForApply:      awsIaCReadyForApply(gates, hardening.ReadyForApply),
		ReadOnlyProjection: true,
		SourceSignals:      []string{"trust_policy_hardening"},
		Evidence:           hardening.Evidence,
		EvidenceBoundary:   awsIaCRemediationEvidenceBoundary(),
		ImpactedNodes:      hardening.ImpactedNodes,
		ImpactedPath:       hardening.ImpactedPath,
		NextAction:         "Open the generated IaC PR in the operator's source-control system; Identrail does not push or create PRs.",
		CreatedAt:          now,
		UpdatedAt:          now,
	}
	return plan, true
}

func awsIaCTargetForService(service string, resourceARN string) string {
	lower := strings.ToLower(strings.TrimSpace(resourceARN))
	if strings.Contains(lower, ":cloudformation:") || strings.Contains(lower, ":stack/") {
		return awsIaCTargetCloudFormation
	}
	switch strings.ToLower(strings.TrimSpace(service)) {
	case "organizations", "scp", "config":
		return awsIaCTargetPolicyAsCode
	case "cdk":
		return awsIaCTargetCDK
	}
	return awsIaCTargetTerraform
}

func awsIaCTargetLabel(target string) string {
	switch target {
	case awsIaCTargetTerraform:
		return "Terraform"
	case awsIaCTargetCloudFormation:
		return "CloudFormation"
	case awsIaCTargetCDK:
		return "CDK"
	case awsIaCTargetPolicyAsCode:
		return "policy-as-code"
	default:
		return strings.TrimSpace(target)
	}
}

func awsIaCResourceSlug(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "identrail-remediation"
	}
	cleaned := strings.Builder{}
	prevDash := false
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			cleaned.WriteRune(r)
			prevDash = false
		case r == '-' || r == '_':
			cleaned.WriteRune('-')
			prevDash = r == '-'
		default:
			if !prevDash {
				cleaned.WriteRune('-')
				prevDash = true
			}
		}
	}
	slug := strings.Trim(cleaned.String(), "-")
	if slug == "" {
		return "identrail-remediation"
	}
	if len(slug) > 60 {
		slug = slug[:60]
		slug = strings.Trim(slug, "-")
	}
	return slug
}

func awsIaCFileChangesForIAMDiff(diff AWSIAMPolicyDiff, target, slug, evidenceRef string) []AWSIaCFileChange {
	dir := awsIaCDirectoryForTarget(target)
	file := dir + "/" + slug + awsIaCFileExtensionForTarget(target, awsIaCChangeKindIAMPolicyDiff)
	resourceType := awsIaCResourceTypeForIAMPolicy(target)
	changeIntent := "scope_least_privilege"
	rationale := fmt.Sprintf("Remove %d unused action(s) and keep %d observed action(s) on %s.", len(diff.RemovedActions), len(diff.KeptActions), firstNonEmptyAWSValue(diff.IdentityName, diff.IdentityNodeID, "the identity"))
	if diff.Decision == "review" {
		changeIntent = "manual_review"
		rationale = "Least-privilege decision is not yet conclusive; PR placeholder reserves the path and links the manual-review evidence."
	}
	files := []AWSIaCFileChange{{
		Path:         file,
		ChangeIntent: changeIntent,
		ResourceType: resourceType,
		BeforeRef:    firstNonEmptyAWSValue(evidenceRef, diff.DiffID),
		AfterRef:     fmt.Sprintf("iac://%s/%s/policy-after", target, diff.DiffID),
		Rationale:    rationale,
	}}
	files = append(files, AWSIaCFileChange{
		Path:         dir + "/" + slug + "/README.md",
		ChangeIntent: "documentation",
		BeforeRef:    diff.DiffID,
		AfterRef:     fmt.Sprintf("iac://%s/%s/readme-after", target, diff.DiffID),
		Rationale:    "Operator-readable summary of the projected least-privilege diff, validation, and verification steps.",
	})
	return files
}

func awsIaCFileChangesForTrustHardening(hardening AWSTrustPolicyHardeningPlan, target, slug, evidenceRef string) []AWSIaCFileChange {
	dir := awsIaCDirectoryForTarget(target)
	file := dir + "/" + slug + awsIaCFileExtensionForTarget(target, awsIaCChangeKindTrustPolicyHardened)
	resourceType := awsIaCResourceTypeForTrustPolicy(target)
	rationale := fmt.Sprintf("Harden trust policy direction=%s with %d condition recommendation(s) for %s.", firstNonEmptyAWSValue(hardening.HardeningDirection, "manual_review"), len(hardening.ConditionRecommendations), firstNonEmptyAWSValue(hardening.ResourceLabel, hardening.ResourceNodeID, "the trusting resource"))
	files := []AWSIaCFileChange{{
		Path:         file,
		ChangeIntent: "harden_trust_policy",
		ResourceType: resourceType,
		BeforeRef:    firstNonEmptyAWSValue(evidenceRef, hardening.PlanID),
		AfterRef:     fmt.Sprintf("iac://%s/%s/trust-after", target, hardening.PlanID),
		Rationale:    rationale,
	}}
	files = append(files, AWSIaCFileChange{
		Path:         dir + "/" + slug + "/README.md",
		ChangeIntent: "documentation",
		BeforeRef:    hardening.PlanID,
		AfterRef:     fmt.Sprintf("iac://%s/%s/readme-after", target, hardening.PlanID),
		Rationale:    "Operator-readable summary of the trust-hardening change, validation, and cloud verification steps.",
	})
	return files
}

func awsIaCDirectoryForTarget(target string) string {
	switch target {
	case awsIaCTargetCloudFormation:
		return "cloudformation/identrail"
	case awsIaCTargetCDK:
		return "cdk/identrail"
	case awsIaCTargetPolicyAsCode:
		return "policies/identrail"
	default:
		return "terraform/identrail"
	}
}

func awsIaCFileExtensionForTarget(target, changeKind string) string {
	switch target {
	case awsIaCTargetCloudFormation:
		if changeKind == awsIaCChangeKindTrustPolicyHardened {
			return "/trust_policy.yaml"
		}
		return "/iam_policy.yaml"
	case awsIaCTargetCDK:
		if changeKind == awsIaCChangeKindTrustPolicyHardened {
			return "/trust_policy.ts"
		}
		return "/iam_policy.ts"
	case awsIaCTargetPolicyAsCode:
		if changeKind == awsIaCChangeKindTrustPolicyHardened {
			return "/trust_policy.rego"
		}
		return "/policy.rego"
	default:
		if changeKind == awsIaCChangeKindTrustPolicyHardened {
			return "/trust_policy.tf"
		}
		return "/iam_policy.tf"
	}
}

func awsIaCResourceTypeForIAMPolicy(target string) string {
	switch target {
	case awsIaCTargetCloudFormation:
		return "AWS::IAM::ManagedPolicy"
	case awsIaCTargetCDK:
		return "iam.ManagedPolicy"
	case awsIaCTargetPolicyAsCode:
		return "rego.iam.policy"
	default:
		return "aws_iam_policy"
	}
}

func awsIaCResourceTypeForTrustPolicy(target string) string {
	switch target {
	case awsIaCTargetCloudFormation:
		return "AWS::IAM::Role.AssumeRolePolicyDocument"
	case awsIaCTargetCDK:
		return "iam.Role.assumeRolePolicy"
	case awsIaCTargetPolicyAsCode:
		return "rego.iam.trust_policy"
	default:
		return "aws_iam_role.assume_role_policy"
	}
}

func awsIaCValidationHintsForTarget(target string, fileChanges []AWSIaCFileChange) []AWSIaCValidationHint {
	switch target {
	case awsIaCTargetCloudFormation:
		cloudTemplateCommands := []AWSIaCValidationHint{}
		for _, file := range fileChanges {
			if !strings.HasSuffix(file.Path, ".yaml") {
				continue
			}
			cloudTemplateCommands = append(cloudTemplateCommands, AWSIaCValidationHint{
				Tool:        "aws cloudformation validate-template",
				Command:     fmt.Sprintf("aws cloudformation validate-template --template-body file://%s", file.Path),
				Description: "Validate each generated CloudFormation template before opening the PR.",
			})
		}
		return append([]AWSIaCValidationHint{
			{Tool: "cfn-lint", Command: "cfn-lint cloudformation/identrail/**/*.yaml", Description: "Lint the generated CloudFormation templates before opening the PR."},
		}, cloudTemplateCommands...)
	case awsIaCTargetCDK:
		return []AWSIaCValidationHint{
			{Tool: "cdk synth", Command: "cdk synth --strict", Description: "Synthesize the CDK app and fail on warnings before opening the PR."},
			{Tool: "cdk diff", Command: "cdk diff", Description: "Confirm the projected resource diff matches the IaC plan."},
		}
	case awsIaCTargetPolicyAsCode:
		return []AWSIaCValidationHint{
			{Tool: "opa fmt", Command: "opa fmt -d policies/identrail", Description: "Format and lint the Rego policy bundle."},
			{Tool: "conftest test", Command: "conftest test policies/identrail", Description: "Run the policy-as-code unit tests for the new guardrail."},
		}
	default:
		return []AWSIaCValidationHint{
			{Tool: "terraform validate", Command: "terraform -chdir=terraform/identrail validate", Description: "Run terraform validate before opening the PR."},
			{Tool: "terraform plan", Command: "terraform -chdir=terraform/identrail plan -out plan.tfplan", Description: "Confirm the projected resource changes match the IaC plan."},
		}
	}
}

func awsIaCCloudVerificationForIAMDiff(diff AWSIAMPolicyDiff) []AWSIaCCloudVerificationCheck {
	checks := []AWSIaCCloudVerificationCheck{
		{Source: "iam:policy_simulate", Signal: "no_regression_on_kept_actions", Description: "Use the IAM policy simulator to confirm kept actions still evaluate as Allow after merge."},
		{Source: "cloudtrail", Signal: "no_access_denied_observed", Description: "Watch CloudTrail for AccessDenied events on observed callers in the first 24 hours after merge."},
	}
	if len(diff.ObservedActions) > 0 {
		checks = append(checks, AWSIaCCloudVerificationCheck{Source: "iam:last_used", Signal: "observed_actions_still_callable", Description: "Re-check IAM Access Analyzer / last-used signals for the observed action set."})
	}
	return checks
}

func awsIaCCloudVerificationForTrustHardening(hardening AWSTrustPolicyHardeningPlan) []AWSIaCCloudVerificationCheck {
	checks := []AWSIaCCloudVerificationCheck{
		{Source: "cloudtrail:AssumeRole", Signal: "expected_principals_only", Description: "Verify CloudTrail AssumeRole events only originate from the hardened principal set."},
		{Source: "access_analyzer", Signal: "no_new_external_findings", Description: "Re-run Access Analyzer to confirm no new external-trust findings appear after merge."},
	}
	if len(hardening.ConditionRecommendations) > 0 {
		checks = append(checks, AWSIaCCloudVerificationCheck{Source: "iam:policy_simulate", Signal: "conditions_enforced", Description: "Simulate the new trust policy conditions against representative caller contexts."})
	}
	return checks
}

func awsIaCReadinessGatesForIAMDiff(diff AWSIAMPolicyDiff) []AWSIaCReadinessGate {
	gates := []AWSIaCReadinessGate{{Name: "read_only_projection", Status: "passed", Rationale: "Generator emits change intent and metadata refs only; no PR is opened by Identrail."}}
	if diff.Decision == "review" {
		gates = append(gates, AWSIaCReadinessGate{Name: "upstream_decision", Status: "blocked", Rationale: "Upstream IAM diff is in manual review; the PR placeholder cannot be applied yet."})
		return gates
	}
	if !diff.ReadyForApply {
		gates = append(gates, AWSIaCReadinessGate{Name: "upstream_ready_for_apply", Status: "blocked", Rationale: "Upstream IAM diff is not yet ready for apply (breakage or confidence gate not met)."})
	} else {
		gates = append(gates, AWSIaCReadinessGate{Name: "upstream_ready_for_apply", Status: "passed", Rationale: "Upstream IAM diff is ready for apply at low projected breakage."})
	}
	if diff.Confidence < 0.75 {
		gates = append(gates, AWSIaCReadinessGate{Name: "confidence", Status: "blocked", Rationale: "Upstream confidence is below the 0.75 threshold required for an applyable IaC PR."})
	}
	return gates
}

func awsIaCReadinessGatesForTrustHardening(hardening AWSTrustPolicyHardeningPlan) []AWSIaCReadinessGate {
	gates := []AWSIaCReadinessGate{{Name: "read_only_projection", Status: "passed", Rationale: "Generator emits change intent and metadata refs only; no PR is opened by Identrail."}}
	if !hardening.ReadyForApply {
		gates = append(gates, AWSIaCReadinessGate{Name: "upstream_ready_for_apply", Status: "blocked", Rationale: "Upstream trust-hardening plan is not yet ready for apply."})
	} else {
		gates = append(gates, AWSIaCReadinessGate{Name: "upstream_ready_for_apply", Status: "passed", Rationale: "Upstream trust-hardening plan is ready for apply."})
	}
	if hardening.PublicPrincipal {
		gates = append(gates, AWSIaCReadinessGate{Name: "public_principal_review", Status: "blocked", Rationale: "Trust policy currently permits a public principal; an additional reviewer is required before the PR can ship."})
	}
	return gates
}

func awsIaCReadyForApply(gates []AWSIaCReadinessGate, upstreamReady bool) bool {
	if !upstreamReady {
		return false
	}
	for _, gate := range gates {
		if gate.Status == "blocked" {
			return false
		}
	}
	return true
}

func awsIaCPRNotesForIAMDiff(diff AWSIAMPolicyDiff) AWSIaCPRNotes {
	return AWSIaCPRNotes{
		Title:        fmt.Sprintf("identrail: scope %s least-privilege (diff %s)", firstNonEmptyAWSValue(diff.IdentityName, diff.IdentityNodeID, "IAM identity"), diff.DiffID),
		Summary:      fmt.Sprintf("Applies the projected least-privilege diff from Identrail IAM analysis. Decision=%s, breakage=%s, confidence=%.2f. Review the validation steps before merge.", diff.Decision, diff.BreakageProjection.Level, diff.Confidence),
		Labels:       dedupeStrings([]string{"identrail", "iam-least-privilege", diff.Decision}),
		EvidenceRefs: awsIAMPolicyDiffEvidenceRefs(diff.Evidence),
		Reviewers:    []string{"identity-owner", "security-reviewer"},
	}
}

func awsIaCPRNotesForTrustHardening(hardening AWSTrustPolicyHardeningPlan) AWSIaCPRNotes {
	return AWSIaCPRNotes{
		Title:        fmt.Sprintf("identrail: harden trust policy %s (plan %s)", firstNonEmptyAWSValue(hardening.ResourceLabel, hardening.ResourceNodeID, "AWS role"), hardening.PlanID),
		Summary:      fmt.Sprintf("Applies the projected trust-policy hardening from Identrail cross-account-trust analysis. Direction=%s, breakage=%s, confidence=%.2f. Review the validation steps before merge.", hardening.HardeningDirection, hardening.BreakageProjection.Level, hardening.Confidence),
		Labels:       dedupeStrings([]string{"identrail", "trust-policy-hardening", hardening.HardeningDirection}),
		EvidenceRefs: awsIAMPolicyDiffEvidenceRefs(hardening.Evidence),
		Reviewers:    []string{"resource-owner", "security-reviewer"},
	}
}

func awsIaCTradeoffsForIAMDiff(diff AWSIAMPolicyDiff) []AWSRemediationTradeoff {
	return []AWSRemediationTradeoff{
		{Dimension: "least_privilege", Direction: "improves", Description: fmt.Sprintf("Removes %d unused IAM action(s) from %s.", len(diff.RemovedActions), firstNonEmptyAWSValue(diff.IdentityName, diff.IdentityNodeID, "the identity")), Severity: diff.Severity},
		{Dimension: "breakage_risk", Direction: "worsens", Description: fmt.Sprintf("Projected breakage level after merge is %s; rely on the validation and verification plans before rollout.", diff.BreakageProjection.Level), Severity: "medium"},
		{Dimension: "review_velocity", Direction: "improves", Description: "IaC PR keeps the change reviewable, auditable, and reversible via source control.", Severity: "low"},
	}
}

func awsIaCTradeoffsForTrustHardening(hardening AWSTrustPolicyHardeningPlan) []AWSRemediationTradeoff {
	return []AWSRemediationTradeoff{
		{Dimension: "trust_surface", Direction: "improves", Description: fmt.Sprintf("Hardens trust direction=%s with %d condition recommendation(s).", hardening.HardeningDirection, len(hardening.ConditionRecommendations)), Severity: hardening.Severity},
		{Dimension: "breakage_risk", Direction: "worsens", Description: fmt.Sprintf("Projected breakage level after merge is %s; pair with cloud verification before rollout.", hardening.BreakageProjection.Level), Severity: "medium"},
		{Dimension: "auditability", Direction: "improves", Description: "IaC PR records the trust-policy change history in source control alongside Identrail evidence refs.", Severity: "low"},
	}
}

func awsIaCRollbackForIAMDiff(diff AWSIAMPolicyDiff, evidenceRef string) AWSRemediationRollbackPlan {
	return AWSRemediationRollbackPlan{
		Strategy:    "revert_iac_pr",
		Steps:       []string{"Revert the merged IaC PR to restore the prior IAM policy state.", "Re-run terraform/cdk/cloudformation apply to reconcile drift.", "Re-evaluate Identrail least-privilege after rollback to confirm decision flipped back."},
		EvidenceRef: firstNonEmptyAWSValue(evidenceRef, diff.DiffID),
	}
}

func awsIaCRollbackForTrustHardening(hardening AWSTrustPolicyHardeningPlan, evidenceRef string) AWSRemediationRollbackPlan {
	return AWSRemediationRollbackPlan{
		Strategy:    "revert_iac_pr",
		Steps:       []string{"Revert the merged IaC PR to restore the prior trust policy.", "Re-run terraform/cdk/cloudformation apply to reconcile drift.", "Re-run Access Analyzer to confirm the previous trust surface is restored."},
		EvidenceRef: firstNonEmptyAWSValue(evidenceRef, hardening.PlanID),
	}
}

func awsIaCVerificationPlanForIAMDiff(diff AWSIAMPolicyDiff, evidenceRef string) AWSRemediationVerificationPlan {
	return AWSRemediationVerificationPlan{
		Strategy:       "iac_pr_verification",
		Steps:          []string{"Run the validation hints locally before opening the PR.", "After merge, monitor CloudTrail and IAM last-used signals during the verification window.", "Re-run Identrail least-privilege analysis and confirm the decision flips to keep."},
		SuccessSignals: []string{"policy_simulate:no-regression", "least_privilege:decision-keep", "cloudtrail:no-access-denied"},
		FailureSignals: []string{"policy_simulate:denied-observed-action", "cloudtrail:access-denied-spike"},
		EvidenceRef:    firstNonEmptyAWSValue(evidenceRef, diff.DiffID),
	}
}

func awsIaCVerificationPlanForTrustHardening(hardening AWSTrustPolicyHardeningPlan, evidenceRef string) AWSRemediationVerificationPlan {
	return AWSRemediationVerificationPlan{
		Strategy:       "iac_pr_verification",
		Steps:          []string{"Run the validation hints locally before opening the PR.", "After merge, watch CloudTrail AssumeRole telemetry for the expected principal set.", "Re-run Access Analyzer to confirm no new external findings."},
		SuccessSignals: []string{"cloudtrail:expected-principals", "access_analyzer:no-external-findings", "policy_simulate:conditions-enforced"},
		FailureSignals: []string{"cloudtrail:unexpected-principal", "access_analyzer:new-external-finding"},
		EvidenceRef:    firstNonEmptyAWSValue(evidenceRef, hardening.PlanID),
	}
}

func awsIaCRemediationRelationships(plans []AWSIaCRemediationPlan) []AWSIaCRemediationRelationship {
	relationships := []AWSIaCRemediationRelationship{}
	for _, plan := range plans {
		evidenceRef := firstString(awsIAMPolicyDiffEvidenceRefs(plan.Evidence))
		from := firstNonEmptyAWSValue(plan.IdentityNodeID, plan.ResourceNodeID, plan.PlanID)
		for _, target := range plan.ImpactedNodes {
			if target == "" || target == from {
				continue
			}
			relationships = append(relationships, AWSIaCRemediationRelationship{
				PlanID:      plan.PlanID,
				Type:        "iac_remediation_target",
				FromNodeID:  from,
				ToNodeID:    target,
				EvidenceRef: evidenceRef,
			})
		}
	}
	return relationships
}

func summarizeAWSIaCRemediationPlans(all, filtered []AWSIaCRemediationPlan, relationships []AWSIaCRemediationRelationship) AWSIaCRemediationSummary {
	summary := AWSIaCRemediationSummary{
		TotalPlans:        len(all),
		FilteredPlans:     len(filtered),
		ChangeKindCounts:  map[string]int{},
		IaCTargetCounts:   map[string]int{},
		SeverityCounts:    map[string]int{},
		StatusCounts:      map[string]int{},
		RelationshipCount: len(relationships),
	}
	confidenceTotal := 0.0
	for _, plan := range filtered {
		summary.ChangeKindCounts[plan.ChangeKind]++
		summary.IaCTargetCounts[plan.IaCTarget]++
		summary.SeverityCounts[plan.Severity]++
		summary.StatusCounts[plan.Status]++
		if plan.ReadyForApply {
			summary.ReadyForApplyCount++
		}
		if plan.Status == "review" || plan.Status == "manual_review" {
			summary.ManualReviewCount++
		}
		summary.FileChangeCount += len(plan.FileChanges)
		summary.ValidationHintCount += len(plan.ValidationHints)
		summary.VerificationCount += len(plan.CloudVerification)
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

func filterAWSIaCRemediationPlans(plans []AWSIaCRemediationPlan, request AWSIaCRemediationRequest) ([]AWSIaCRemediationPlan, map[string]string) {
	filters := map[string]string{
		"account_id":      strings.TrimSpace(request.AccountID),
		"region":          strings.TrimSpace(request.Region),
		"identity":        strings.TrimSpace(request.Identity),
		"iac_target":      normalizeAWSRuntimeEventFilterToken(request.IaCTarget),
		"change_kind":     normalizeAWSRuntimeEventFilterToken(request.ChangeKind),
		"severity":        normalizeAWSRuntimeEventFilterToken(request.Severity),
		"status":          normalizeAWSRuntimeEventFilterToken(request.Status),
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
	filtered := make([]AWSIaCRemediationPlan, 0, len(plans))
	for _, plan := range plans {
		if filters["account_id"] != "" && filters["account_id"] != plan.AccountID {
			continue
		}
		if filters["region"] != "" && !strings.EqualFold(filters["region"], plan.Region) {
			continue
		}
		if filters["iac_target"] != "" && filters["iac_target"] != normalizeAWSRuntimeEventFilterToken(plan.IaCTarget) {
			continue
		}
		if filters["change_kind"] != "" && filters["change_kind"] != normalizeAWSRuntimeEventFilterToken(plan.ChangeKind) {
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
		if filters["identity"] != "" && !awsIaCRemediationIdentityMatch(plan, filters["identity"]) {
			continue
		}
		if filters["search"] != "" && !awsIaCRemediationSearchMatch(plan, filters["search"]) {
			continue
		}
		filtered = append(filtered, plan)
	}
	return filtered, applied
}

func awsIaCRemediationIdentityMatch(plan AWSIaCRemediationPlan, needle string) bool {
	needle = strings.ToLower(strings.TrimSpace(needle))
	if needle == "" {
		return true
	}
	hay := strings.ToLower(strings.Join([]string{plan.IdentityNodeID, plan.IdentityARN, plan.IdentityName, plan.ResourceNodeID, plan.ResourceARN}, " "))
	return strings.Contains(hay, needle)
}

func awsIaCRemediationSearchMatch(plan AWSIaCRemediationPlan, needle string) bool {
	needle = strings.ToLower(strings.TrimSpace(needle))
	if needle == "" {
		return true
	}
	values := []string{
		plan.PlanID, plan.Title, plan.Summary, plan.SourceArtifactID, plan.ChangeKind, plan.IaCTarget,
		plan.Severity, plan.Status, plan.Service, plan.IdentityNodeID, plan.IdentityARN, plan.IdentityName,
		plan.ResourceNodeID, plan.ResourceARN, plan.NextAction, plan.PRNotes.Title, plan.PRNotes.Summary,
		plan.DiffIntent.DiffSummary, plan.RollbackPlan.Strategy, plan.VerificationPlan.Strategy,
	}
	values = append(values, plan.SourceSignals...)
	values = append(values, plan.PRNotes.Labels...)
	values = append(values, plan.PRNotes.EvidenceRefs...)
	values = append(values, plan.PRNotes.Reviewers...)
	values = append(values, plan.RollbackPlan.Steps...)
	values = append(values, plan.VerificationPlan.Steps...)
	values = append(values, plan.VerificationPlan.SuccessSignals...)
	values = append(values, plan.VerificationPlan.FailureSignals...)
	for _, file := range plan.FileChanges {
		values = append(values, file.Path, file.ChangeIntent, file.ResourceType, file.Rationale)
	}
	for _, hint := range plan.ValidationHints {
		values = append(values, hint.Tool, hint.Command, hint.Description)
	}
	for _, check := range plan.CloudVerification {
		values = append(values, check.Source, check.Signal, check.Description)
	}
	for _, gate := range plan.ReadinessGates {
		values = append(values, gate.Name, gate.Status, gate.Rationale)
	}
	for _, tradeoff := range plan.Tradeoffs {
		values = append(values, tradeoff.Dimension, tradeoff.Direction, tradeoff.Description, tradeoff.Severity)
	}
	for _, evidence := range plan.Evidence {
		values = append(values, evidence.Source, evidence.Label, evidence.EvidenceRef, evidence.Relationship)
	}
	for _, value := range values {
		if strings.Contains(strings.ToLower(value), needle) {
			return true
		}
	}
	return false
}

func summarizeAWSIaCRemediationStatus(sources awsIaCRemediationSources, filtered []AWSIaCRemediationPlan, diagnostics []AWSIaCRemediationDiagnostic) (string, float64) {
	if sources.iamPolicyDiffs.Status == awsPlatformDependencyStatusBlocked && sources.trustPolicyHardening.Status == awsPlatformDependencyStatusBlocked {
		return awsPlatformDependencyStatusBlocked, 0.35
	}
	if sources.iamPolicyDiffs.Status == awsPlatformDependencyStatusBlocked || sources.trustPolicyHardening.Status == awsPlatformDependencyStatusBlocked {
		return awsPlatformDependencyStatusDegraded, 0.6
	}
	for _, diagnostic := range diagnostics {
		if diagnostic.Retryable {
			return awsPlatformDependencyStatusDegraded, 0.72
		}
	}
	if sources.iamPolicyDiffs.Status == awsPlatformDependencyStatusDegraded || sources.trustPolicyHardening.Status == awsPlatformDependencyStatusDegraded {
		return awsPlatformDependencyStatusDegraded, 0.74
	}
	if len(filtered) == 0 {
		return awsPlatformDependencyStatusReady, 0.82
	}
	return awsPlatformDependencyStatusReady, 0.9
}

func awsIaCRemediationCaveats() []string {
	return []string{
		"IaC remediation plans are read-only PR projections; Identrail never opens, pushes, or merges a PR on the operator's behalf.",
		"File-change rationale and validation hints carry metadata refs only — never rendered IaC bodies, IAM policy bodies, secret values, or workload payloads.",
		"ready_for_apply is derived deterministically from upstream IAM-diff/trust-hardening readiness plus a public-principal review gate; approval, execute, and verify transitions belong to future wave issues.",
	}
}

func awsIaCRemediationFailureReasons(sources awsIaCRemediationSources) []string {
	return dedupeStrings(append(append([]string{}, sources.iamPolicyDiffs.FailureReasons...), sources.trustPolicyHardening.FailureReasons...))
}

func awsIaCRemediationRemediationHints(sources awsIaCRemediationSources) []string {
	hints := []string{
		"Open each generated PR in your source-control system manually; Identrail does not push commits or open PRs.",
		"Run the validation hints locally and link the run output in the PR body alongside Identrail evidence refs.",
		"After merge, follow the cloud verification checks; revert the PR if a failure signal appears in the first verification window.",
	}
	hints = append(hints, sources.iamPolicyDiffs.RemediationHints...)
	hints = append(hints, sources.trustPolicyHardening.RemediationHints...)
	return dedupeStrings(hints)
}

func awsIaCRemediationDiagnostics(sources awsIaCRemediationSources) []AWSIaCRemediationDiagnostic {
	out := []AWSIaCRemediationDiagnostic{}
	for _, d := range sources.iamPolicyDiffs.Diagnostics {
		out = append(out, AWSIaCRemediationDiagnostic{Collector: d.Collector, SourceID: d.SourceID, Code: d.Code, Message: d.Message, Remediation: d.Remediation, Retryable: d.Retryable})
	}
	for _, d := range sources.trustPolicyHardening.Diagnostics {
		out = append(out, AWSIaCRemediationDiagnostic{Collector: d.Collector, SourceID: d.SourceID, Code: d.Code, Message: d.Message, Remediation: d.Remediation, Retryable: d.Retryable})
	}
	return out
}

func awsIaCRemediationCoverageGaps(sources awsIaCRemediationSources) []AWSIaCRemediationCoverageGap {
	out := []AWSIaCRemediationCoverageGap{{
		Capability:  "iac_pr_publish",
		Status:      "out_of_scope",
		Reason:      "Issue #1535 emits IaC PR plans only; opening, pushing, or merging the PR happens in the operator's source-control system, not in Identrail.",
		Remediation: "Use the operator's source-control workflow to land the generated PR; later waves wire approval and execution gates around live AWS apply.",
	}}
	for _, g := range sources.iamPolicyDiffs.CoverageGaps {
		out = append(out, AWSIaCRemediationCoverageGap{Capability: g.Capability, Status: g.Status, Reason: g.Reason, Remediation: g.Remediation})
	}
	for _, g := range sources.trustPolicyHardening.CoverageGaps {
		out = append(out, AWSIaCRemediationCoverageGap{Capability: g.Capability, Status: g.Status, Reason: g.Reason, Remediation: g.Remediation})
	}
	return out
}

func awsIaCRemediationEvidenceBoundary() string {
	return "metadata_only_no_rendered_iac_bodies_no_rendered_policy_bodies_no_secret_values_no_workload_payloads"
}
