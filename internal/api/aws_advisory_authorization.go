package api

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	awsAdvisoryAuthorizationCurrentIssue = 1543
	awsAdvisoryAuthorizationVersion      = "aws-advisory-authorization-v1"
	awsAdvisoryAuthorizationPolicyID     = "aws-advisory-authorization-policy-v1"

	awsAdvisoryAuthorizationOutcomeAllow           = "allow"
	awsAdvisoryAuthorizationOutcomeWarn            = "warn"
	awsAdvisoryAuthorizationOutcomeRequireApproval = "require_approval"
	awsAdvisoryAuthorizationOutcomeRecommendDeny   = "recommend_deny"
	awsAdvisoryAuthorizationOutcomeQuarantine      = "quarantine"

	awsAdvisoryAuthorizationModeAdvisory = "advisory"
)

// AWSAdvisoryAuthorizationRequest scopes the advisory authorization decision
// projection to one AWS connector plus optional operator drill-down filters.
type AWSAdvisoryAuthorizationRequest struct {
	ConnectorID    string `json:"connector_id,omitempty"`
	FixtureState   string `json:"fixture_state,omitempty"`
	AccountID      string `json:"account_id,omitempty"`
	Region         string `json:"region,omitempty"`
	PrincipalID    string `json:"principal_id,omitempty"`
	Action         string `json:"action,omitempty"`
	Outcome        string `json:"outcome,omitempty"`
	Severity       string `json:"severity,omitempty"`
	SourceType     string `json:"source_type,omitempty"`
	CaseID         string `json:"case_id,omitempty"`
	VerificationID string `json:"verification_id,omitempty"`
	Search         string `json:"search,omitempty"`
}

type AWSAdvisoryAuthorizationAuditEntry = AWSRemediationApprovalAuditEntry
type AWSAdvisoryAuthorizationCoverageGap = AWSRemediationApprovalCoverageGap
type AWSAdvisoryAuthorizationDiagnostic = AWSRemediationApprovalDiagnostic

// AWSAdvisoryAuthorizationEvidence is one metadata reference the decision
// engine used to reach its recommendation. No rendered policy bodies or
// secret material is inlined.
type AWSAdvisoryAuthorizationEvidence struct {
	Source      string `json:"source"`
	Label       string `json:"label"`
	EvidenceRef string `json:"evidence_ref,omitempty"`
}

// AWSAdvisoryAuthorizationInputHash records the deterministic hash of the
// inputs that produced the decision. Operators use this to detect drift when
// upstream signals change.
type AWSAdvisoryAuthorizationInputHash struct {
	Value      string   `json:"value"`
	Components []string `json:"components,omitempty"`
}

// AWSAdvisoryAuthorizationProvenance records the deterministic derivation
// path: which upstream sources contributed, which policy version was applied,
// and the operator-visible policy rule name that produced the outcome.
type AWSAdvisoryAuthorizationProvenance struct {
	PolicyVersion string   `json:"policy_version"`
	PolicyRule    string   `json:"policy_rule"`
	SourceTypes   []string `json:"source_types"`
	Signals       []string `json:"signals,omitempty"`
}

// AWSAdvisoryAuthorizationRelationship surfaces decision→graph node edges.
type AWSAdvisoryAuthorizationRelationship struct {
	DecisionID  string `json:"decision_id"`
	Type        string `json:"type"`
	FromNodeID  string `json:"from_node_id"`
	ToNodeID    string `json:"to_node_id"`
	EvidenceRef string `json:"evidence_ref,omitempty"`
}

// AWSAdvisoryAuthorizationDecision is the persisted-record-shaped contract
// for one advisory authorization decision. Identrail never enforces the
// decision at this layer; downstream governance executors and operator
// workflows decide whether and how to act on the recommendation.
type AWSAdvisoryAuthorizationDecision struct {
	DecisionID         string                               `json:"decision_id"`
	CalculationVersion string                               `json:"calculation_version"`
	Mode               string                               `json:"mode"`
	Outcome            string                               `json:"outcome"`
	Confidence         float64                              `json:"confidence"`
	Severity           string                               `json:"severity"`
	Score              int                                  `json:"score"`
	Title              string                               `json:"title"`
	Summary            string                               `json:"summary"`
	Rationale          string                               `json:"rationale"`
	AccountID          string                               `json:"account_id,omitempty"`
	TargetAccountIDs   []string                             `json:"target_account_ids,omitempty"`
	Region             string                               `json:"region,omitempty"`
	PrincipalNodeID    string                               `json:"principal_node_id,omitempty"`
	PrincipalARN       string                               `json:"principal_arn,omitempty"`
	PrincipalType      string                               `json:"principal_type,omitempty"`
	Action             string                               `json:"action"`
	ResourceScope      []string                             `json:"resource_scope,omitempty"`
	SourceType         string                               `json:"source_type"`
	CaseID             string                               `json:"case_id,omitempty"`
	VerificationID     string                               `json:"verification_id,omitempty"`
	InputHash          AWSAdvisoryAuthorizationInputHash    `json:"input_hash"`
	Provenance         AWSAdvisoryAuthorizationProvenance   `json:"provenance"`
	Evidence           []AWSAdvisoryAuthorizationEvidence   `json:"evidence"`
	EvidenceLinks      []string                             `json:"evidence_links"`
	EvidenceBoundary   string                               `json:"evidence_boundary"`
	AuditTrail         []AWSAdvisoryAuthorizationAuditEntry `json:"audit_trail"`
	KillSwitchEngaged  bool                                 `json:"kill_switch_engaged"`
	ReadOnlyProjection bool                                 `json:"read_only_projection"`
	NextAction         string                               `json:"next_action"`
	DecidedAt          time.Time                            `json:"decided_at"`
	UpdatedAt          time.Time                            `json:"updated_at"`
}

// AWSAdvisoryAuthorizationSummary aggregates the unfiltered/filtered set.
type AWSAdvisoryAuthorizationSummary struct {
	TotalDecisions         int            `json:"total_decisions"`
	FilteredDecisions      int            `json:"filtered_decisions"`
	OutcomeCounts          map[string]int `json:"outcome_counts"`
	SeverityCounts         map[string]int `json:"severity_counts"`
	SourceTypeCounts       map[string]int `json:"source_type_counts"`
	AllowCount             int            `json:"allow_count"`
	WarnCount              int            `json:"warn_count"`
	RequireApprovalCount   int            `json:"require_approval_count"`
	RecommendDenyCount     int            `json:"recommend_deny_count"`
	QuarantineCount        int            `json:"quarantine_count"`
	KillSwitchEngagedCount int            `json:"kill_switch_engaged_count"`
	RelationshipCount      int            `json:"relationship_count"`
	HighestScore           int            `json:"highest_score"`
	AverageConfidencePct   int            `json:"average_confidence_pct"`
}

// AWSAdvisoryAuthorizationResult is the deterministic endpoint envelope.
type AWSAdvisoryAuthorizationResult struct {
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
	PolicyVersion      string                                 `json:"policy_version"`
	Mode               string                                 `json:"mode"`
	AppliedFilters     map[string]string                      `json:"applied_filters"`
	Summary            AWSAdvisoryAuthorizationSummary        `json:"summary"`
	Decisions          []AWSAdvisoryAuthorizationDecision     `json:"decisions"`
	Relationships      []AWSAdvisoryAuthorizationRelationship `json:"relationships"`
	Caveats            []string                               `json:"caveats"`
	FailureReasons     []string                               `json:"failure_reasons"`
	RemediationHints   []string                               `json:"remediation_hints"`
	EvidenceLinks      []string                               `json:"evidence_links"`
	CoverageGaps       []AWSAdvisoryAuthorizationCoverageGap  `json:"coverage_gaps"`
	Diagnostics        []AWSAdvisoryAuthorizationDiagnostic   `json:"diagnostics"`
	GeneratedAt        time.Time                              `json:"generated_at"`
	UpdatedAt          time.Time                              `json:"updated_at"`
}

// GetAWSAdvisoryAuthorization projects deterministic advisory authorization
// decisions from the remediation-case engine (#1529) joined with the
// post-remediation verification and rollback executor (#1542). Each decision
// records the recommended outcome (allow, warn, require_approval,
// recommend_deny, quarantine), the deterministic input hash, the policy
// version and rule that produced the recommendation, and an immutable audit
// trail. The endpoint is advisory-only: Identrail never enforces the decision
// at this layer.
func (s *Service) GetAWSAdvisoryAuthorization(ctx context.Context, workspaceID string, projectID string, request AWSAdvisoryAuthorizationRequest) (AWSAdvisoryAuthorizationResult, error) {
	project, scope, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return AWSAdvisoryAuthorizationResult{}, err
	}
	connection, hasConnection, err := s.awsBaselineConnection(ctx, project, strings.TrimSpace(request.ConnectorID))
	if err != nil {
		return AWSAdvisoryAuthorizationResult{}, err
	}
	now := s.Now().UTC()
	fixtureState := normalizeAWSAdvisoryAuthorizationFixtureState(request.FixtureState, connection, hasConnection)
	if fixtureState == "" {
		return AWSAdvisoryAuthorizationResult{}, ErrInvalidAWSConnectionRequest
	}

	accountID := firstNonEmptyAWSValue(connection.AccountID, strings.TrimSpace(request.AccountID), "123456789012")
	region := firstNonEmptyAWSValue(connection.Region, strings.TrimSpace(request.Region), "us-east-1")
	connectorID := firstNonEmptyAWSValue(connection.ConnectorID, strings.TrimSpace(request.ConnectorID))
	sourceFixtureState := fixtureState
	if strings.TrimSpace(request.FixtureState) == "" && hasConnection && connection.Connected {
		sourceFixtureState = ""
	}

	cases, err := s.GetAWSRemediationCases(ctx, workspaceID, projectID, AWSRemediationCaseRequest{ConnectorID: connectorID, FixtureState: sourceFixtureState})
	if err != nil {
		return AWSAdvisoryAuthorizationResult{}, fmt.Errorf("advisory authorization cases: %w", err)
	}
	verification, err := s.GetAWSPostRemediationVerification(ctx, workspaceID, projectID, AWSPostRemediationVerificationRequest{ConnectorID: connectorID, FixtureState: sourceFixtureState})
	if err != nil {
		return AWSAdvisoryAuthorizationResult{}, fmt.Errorf("advisory authorization verification: %w", err)
	}

	// When one case fans out into multiple verification records (per-target
	// splits, retries), keep all entries grouped by case. Non-split cases
	// still choose the most safety-critical entry, while split advisory rows
	// can join to their target-specific verification record first.
	verificationByCase := map[string][]AWSPostRemediationVerificationEntry{}
	for _, entry := range verification.Entries {
		if strings.TrimSpace(entry.CaseID) == "" {
			continue
		}
		verificationByCase[entry.CaseID] = append(verificationByCase[entry.CaseID], entry)
	}

	decisions := awsAdvisoryAuthorizationDecisions(cases.Cases, verificationByCase, now)
	sort.SliceStable(decisions, func(i, j int) bool {
		if decisions[i].Score == decisions[j].Score {
			return decisions[i].DecisionID < decisions[j].DecisionID
		}
		return decisions[i].Score > decisions[j].Score
	})
	filtered, applied := filterAWSAdvisoryAuthorizationDecisions(decisions, request)
	relationships := awsAdvisoryAuthorizationRelationships(filtered)
	diagnostics := awsAdvisoryAuthorizationDiagnostics(cases.Diagnostics, verification.Diagnostics)
	coverageGaps := awsAdvisoryAuthorizationCoverageGaps(cases.CoverageGaps, verification.CoverageGaps)
	status, confidence := summarizeAWSAdvisoryAuthorizationStatus(cases.Status, verification.Status, filtered, diagnostics)

	return AWSAdvisoryAuthorizationResult{
		TenantID:           scope.TenantID,
		WorkspaceID:        project.WorkspaceID,
		ProjectID:          project.ProjectID,
		ConnectorID:        connectorID,
		AccountID:          accountID,
		Region:             region,
		ParentIssueNumber:  awsPlatformDependencyParentIssue,
		ParentIssueRef:     awsIssueRef(awsPlatformDependencyParentIssue),
		CurrentIssueNumber: awsAdvisoryAuthorizationCurrentIssue,
		CurrentIssueRef:    awsIssueRef(awsAdvisoryAuthorizationCurrentIssue),
		Version:            awsAdvisoryAuthorizationVersion,
		Status:             status,
		FixtureState:       sourceFixtureState,
		Confidence:         confidence,
		CalculationVersion: awsAdvisoryAuthorizationVersion,
		PolicyVersion:      awsAdvisoryAuthorizationPolicyID,
		Mode:               awsAdvisoryAuthorizationModeAdvisory,
		AppliedFilters:     applied,
		Summary:            summarizeAWSAdvisoryAuthorizationDecisions(decisions, filtered, relationships),
		Decisions:          filtered,
		Relationships:      relationships,
		Caveats:            awsAdvisoryAuthorizationCaveats(),
		FailureReasons:     dedupeStrings(append(append([]string{}, cases.FailureReasons...), verification.FailureReasons...)),
		RemediationHints:   awsAdvisoryAuthorizationRemediationHints(append(cases.RemediationHints, verification.RemediationHints...)),
		EvidenceLinks: dedupeStrings([]string{
			awsIssueURL(awsPlatformDependencyParentIssue),
			awsIssueURL(awsAdvisoryAuthorizationCurrentIssue),
			awsIssueURL(awsRemediationCaseCurrentIssue),
			awsIssueURL(awsPostRemediationVerificationCurrentIssue),
			"/docs/aws-advisory-authorization",
			"/docs/aws-remediation-cases",
			"/docs/aws-post-remediation-verification",
			awsBaselineProjectEvidenceURL(scope, project),
		}),
		CoverageGaps: coverageGaps,
		Diagnostics:  diagnostics,
		GeneratedAt:  now,
		UpdatedAt:    now,
	}, nil
}

func normalizeAWSAdvisoryAuthorizationFixtureState(requested string, connection AWSConnectionStatus, hasConnection bool) string {
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

func awsAdvisoryAuthorizationDecisions(cases []AWSRemediationCase, verificationByCase map[string][]AWSPostRemediationVerificationEntry, now time.Time) []AWSAdvisoryAuthorizationDecision {
	decisions := make([]AWSAdvisoryAuthorizationDecision, 0, len(cases))
	for _, c := range cases {
		decisions = append(decisions, awsAdvisoryAuthorizationDecisionsFromCase(c, verificationByCase[c.CaseID], now)...)
	}
	return decisions
}

func awsAdvisoryAuthorizationDecisionsFromCase(c AWSRemediationCase, verifications []AWSPostRemediationVerificationEntry, now time.Time) []AWSAdvisoryAuthorizationDecision {
	if targets := awsAdvisoryAuthorizationSplitPermissionBoundaryTargets(c); len(targets) > 0 {
		decisions := make([]AWSAdvisoryAuthorizationDecision, 0, len(targets))
		for _, target := range targets {
			scoped := awsAdvisoryAuthorizationCaseForPermissionBoundaryTarget(c, target)
			verification := awsAdvisoryAuthorizationVerificationForTarget(verifications, target)
			decisionScope := ""
			if len(targets) > 1 {
				decisionScope = target
			}
			decisions = append(decisions, awsAdvisoryAuthorizationDecisionFromCaseWithScope(scoped, verification, now, decisionScope))
		}
		return decisions
	}
	return []AWSAdvisoryAuthorizationDecision{awsAdvisoryAuthorizationDecisionFromCase(c, awsAdvisoryAuthorizationMostSevereVerification(verifications), now)}
}

func awsAdvisoryAuthorizationMostSevereVerification(verifications []AWSPostRemediationVerificationEntry) AWSPostRemediationVerificationEntry {
	var selected AWSPostRemediationVerificationEntry
	for _, entry := range verifications {
		if selected.VerificationID == "" || awsAdvisoryAuthorizationVerificationSeverityRank(entry) > awsAdvisoryAuthorizationVerificationSeverityRank(selected) {
			selected = entry
		}
	}
	return selected
}

func awsAdvisoryAuthorizationVerificationForTarget(verifications []AWSPostRemediationVerificationEntry, target string) AWSPostRemediationVerificationEntry {
	matches := []AWSPostRemediationVerificationEntry{}
	for _, entry := range verifications {
		if awsAdvisoryAuthorizationVerificationMatchesTarget(entry, target) {
			matches = append(matches, entry)
		}
	}
	if len(matches) > 0 {
		return awsAdvisoryAuthorizationMostSevereVerification(matches)
	}
	return awsAdvisoryAuthorizationMostSevereVerification(verifications)
}

func awsAdvisoryAuthorizationVerificationMatchesTarget(entry AWSPostRemediationVerificationEntry, target string) bool {
	return awsAdvisoryAuthorizationTargetsEqual(entry.TargetResource, target)
}

func awsAdvisoryAuthorizationTargetsEqual(a, b string) bool {
	a = strings.TrimSpace(a)
	b = strings.TrimSpace(b)
	if a == "" || b == "" {
		return false
	}
	if strings.EqualFold(a, b) {
		return true
	}
	aARN := awsAdvisoryAuthorizationARNFromTarget(a)
	bARN := awsAdvisoryAuthorizationARNFromTarget(b)
	return aARN != "" && bARN != "" && strings.EqualFold(aARN, bARN)
}

func awsAdvisoryAuthorizationSplitPermissionBoundaryTargets(c AWSRemediationCase) []string {
	if c.DiffIntent.NoOp {
		return nil
	}
	if !strings.EqualFold(strings.TrimSpace(c.DiffIntent.Kind), "permission_boundary_diff") && !strings.EqualFold(c.SourceType, "aws_permission_boundary_scp") {
		return nil
	}
	return awsPermissionBoundaryExecutorSupportedTargets(c.ResourceNodeIDs)
}

func awsAdvisoryAuthorizationCaseForPermissionBoundaryTarget(c AWSRemediationCase, target string) AWSRemediationCase {
	scoped := c
	scoped.IdentityNodeID = target
	if arn := awsAdvisoryAuthorizationARNFromTarget(target); arn != "" {
		scoped.IdentityARN = arn
	}
	scoped.IdentityName = firstNonEmptyAWSValue(shortAWSARN(target), target)
	scoped.IdentityType = awsRemediationPermissionBoundaryIdentityType(target)
	scoped.ResourceNodeIDs = []string{target}
	scoped.ImpactedNodes = dedupeStrings(append([]string{target}, c.ImpactedNodes...))
	accountFallback := []string(nil)
	if len(awsAdvisoryAuthorizationSplitPermissionBoundaryTargets(c)) == 1 {
		accountFallback = c.TargetAccountIDs
	}
	scoped.TargetAccountIDs = awsPermissionBoundaryExecutorScopedAccountsForTargets([]string{target}, accountFallback)
	scoped.AccountID = firstString(scoped.TargetAccountIDs)
	return scoped
}

func awsAdvisoryAuthorizationARNFromTarget(target string) string {
	trimmed := strings.TrimSpace(target)
	if idx := strings.Index(strings.ToLower(trimmed), "arn:"); idx >= 0 {
		return trimmed[idx:]
	}
	return ""
}

func awsAdvisoryAuthorizationDecisionFromCase(c AWSRemediationCase, verification AWSPostRemediationVerificationEntry, now time.Time) AWSAdvisoryAuthorizationDecision {
	return awsAdvisoryAuthorizationDecisionFromCaseWithScope(c, verification, now, "")
}

func awsAdvisoryAuthorizationDecisionFromCaseWithScope(c AWSRemediationCase, verification AWSPostRemediationVerificationEntry, now time.Time, decisionScope string) AWSAdvisoryAuthorizationDecision {
	action := awsAdvisoryAuthorizationActionForCase(c)
	outcome, rule, rationale, confidence := awsAdvisoryAuthorizationClassify(c, verification)
	decisionID := "aws-advisory-authorization:" + stableAWSBlastRadiusToken("decision", c.CaseID, action, decisionScope)
	principalNodeID := firstNonEmptyAWSValue(c.IdentityNodeID, firstString(c.ResourceNodeIDs))
	resourceScope := emptyStrings(dedupeStrings(c.ResourceNodeIDs))
	if len(resourceScope) == 0 {
		resourceScope = emptyStrings(dedupeStrings(c.ImpactedNodes))
	}
	sourceTypes := dedupeStrings([]string{c.SourceType})
	signals := dedupeStrings([]string{"remediation_case", c.Lifecycle, c.ApprovalState})
	if verification.VerificationID != "" {
		sourceTypes = append(sourceTypes, "post_remediation_verification")
		signals = append(signals, "verification:"+verification.State)
	}
	evidence := awsAdvisoryAuthorizationEvidenceFromCase(c, verification)
	evidenceLinks := awsAdvisoryAuthorizationEvidenceLinksFromCase(c, verification)
	// Hash every input the classifier reads. If any of these change the
	// outcome/rationale can change, so operators must be able to detect the
	// drift by comparing hashes across runs.
	killSwitchToken := "false"
	if verification.KillSwitchEngaged {
		killSwitchToken = "true"
	}
	approvalRequiredToken := "false"
	if c.ApprovalRequired {
		approvalRequiredToken = "true"
	}
	inputHash := AWSAdvisoryAuthorizationInputHash{
		Value: stableAWSBlastRadiusToken(
			"input",
			c.CaseID,
			c.Lifecycle,
			c.ApprovalState,
			approvalRequiredToken,
			c.Severity,
			verification.State,
			verification.VerificationID,
			killSwitchToken,
			awsAdvisoryAuthorizationVersion,
			awsAdvisoryAuthorizationPolicyID,
		),
		Components: []string{
			"case_id=" + c.CaseID,
			"lifecycle=" + c.Lifecycle,
			"approval_state=" + c.ApprovalState,
			"approval_required=" + approvalRequiredToken,
			"severity=" + c.Severity,
			"verification_state=" + verification.State,
			"kill_switch_engaged=" + killSwitchToken,
			"policy_version=" + awsAdvisoryAuthorizationPolicyID,
		},
	}
	return AWSAdvisoryAuthorizationDecision{
		DecisionID:         decisionID,
		CalculationVersion: awsAdvisoryAuthorizationVersion,
		Mode:               awsAdvisoryAuthorizationModeAdvisory,
		Outcome:            outcome,
		Confidence:         confidence,
		Severity:           c.Severity,
		Score:              c.Score,
		Title:              fmt.Sprintf("Advisory decision: %s", firstNonEmptyAWSValue(c.Title, c.CaseID)),
		Summary:            fmt.Sprintf("Advisory-only authorization decision for %s (outcome=%s). Identrail records the recommendation, provenance, and audit only; no live IAM/STS/Organizations write API is called at this layer.", firstNonEmptyAWSValue(principalNodeID, c.CaseID), outcome),
		Rationale:          rationale,
		AccountID:          firstNonEmptyAWSValue(c.AccountID, firstString(c.TargetAccountIDs)),
		TargetAccountIDs:   emptyStrings(dedupeStrings(append(append([]string{}, c.TargetAccountIDs...), c.AccountID))),
		Region:             c.Region,
		PrincipalNodeID:    principalNodeID,
		PrincipalARN:       c.IdentityARN,
		PrincipalType:      c.IdentityType,
		Action:             action,
		ResourceScope:      resourceScope,
		SourceType:         c.SourceType,
		CaseID:             c.CaseID,
		VerificationID:     verification.VerificationID,
		InputHash:          inputHash,
		Provenance: AWSAdvisoryAuthorizationProvenance{
			PolicyVersion: awsAdvisoryAuthorizationPolicyID,
			PolicyRule:    rule,
			SourceTypes:   dedupeStrings(sourceTypes),
			Signals:       dedupeStrings(signals),
		},
		Evidence:           evidence,
		EvidenceLinks:      evidenceLinks,
		EvidenceBoundary:   awsAdvisoryAuthorizationEvidenceBoundary(),
		AuditTrail:         awsAdvisoryAuthorizationAuditTrail(c, verification, outcome, rule, now),
		KillSwitchEngaged:  verification.KillSwitchEngaged,
		ReadOnlyProjection: true,
		NextAction:         awsAdvisoryAuthorizationNextAction(outcome),
		DecidedAt:          now,
		UpdatedAt:          now,
	}
}

// awsAdvisoryAuthorizationClassify is the deterministic decision policy. It
// maps upstream case + verification state to one of the advertised outcomes
// and returns the operator-visible rule name plus rationale. Ordering matters:
// safety-critical states (kill switch, verification failed) win over general
// approval state so a compromised or reverted execution can never be recorded
// as `allow`.
// awsAdvisoryAuthorizationVerificationSeverityRank orders verification entries
// so the most safety-critical wins when multiple entries share a case ID.
// Higher rank = more severe. The order mirrors awsAdvisoryAuthorizationClassify
// so the entry that would produce a `quarantine` or `recommend_deny` decision
// takes precedence over one that would produce `allow` or `verification_pending`.
func awsAdvisoryAuthorizationVerificationSeverityRank(entry AWSPostRemediationVerificationEntry) int {
	if entry.KillSwitchEngaged {
		return 100
	}
	switch entry.State {
	case awsPostRemediationVerificationStateFailed, awsPostRemediationVerificationStateRollback:
		return 90
	case awsPostRemediationVerificationStateBlocked:
		return 80
	// verification_pending outranks not_ready and skipped: pending
	// classifies as the stricter require_approval, while not_ready and
	// skipped classify as warn. Keeping pending on top of a per-case
	// tie ensures the case-level decision matches the in-flight state
	// rather than understating it.
	case awsPostRemediationVerificationStatePending:
		return 50
	case awsPostRemediationVerificationStateNotReady:
		return 40
	case awsPostRemediationVerificationStateSkipped:
		return 30
	case awsPostRemediationVerificationStateVerified:
		return 10
	}
	return 0
}

func awsAdvisoryAuthorizationClassify(c AWSRemediationCase, verification AWSPostRemediationVerificationEntry) (outcome, rule, rationale string, confidence float64) {
	if verification.KillSwitchEngaged {
		return awsAdvisoryAuthorizationOutcomeQuarantine, "kill_switch_engaged", "Tenant remediation kill switch is engaged; recommend quarantining new authorization until the switch is disabled.", 0.95
	}
	switch verification.State {
	case awsPostRemediationVerificationStateFailed, awsPostRemediationVerificationStateRollback:
		return awsAdvisoryAuthorizationOutcomeQuarantine, "verification_failed", "Post-remediation verification failed; recommend quarantining the principal until the rollback record is applied and evidence is refreshed.", 0.9
	case awsPostRemediationVerificationStateVerified:
		return awsAdvisoryAuthorizationOutcomeAllow, "verification_verified", "Post-remediation verification confirmed the intended state; allow the projected authorization.", 0.9
	case awsPostRemediationVerificationStateBlocked:
		return awsAdvisoryAuthorizationOutcomeRecommendDeny, "verification_blocked", "Verification is blocked by a safety gate or an unresolved upstream precondition; recommend deny until the failing gate clears.", 0.85
	case awsPostRemediationVerificationStatePending:
		return awsAdvisoryAuthorizationOutcomeRequireApproval, "verification_pending", "Execution is projected but post-remediation verification has not recorded outcomes yet; require approval workflow to reach a verified state before allowing the new posture.", 0.8
	case awsPostRemediationVerificationStateNotReady:
		return awsAdvisoryAuthorizationOutcomeWarn, "verification_not_ready", "Upstream executor has not declared ready_for_live_apply; warn operators and refresh planner/dry-run evidence before allowing the projected authorization.", 0.75
	case awsPostRemediationVerificationStateSkipped:
		return awsAdvisoryAuthorizationOutcomeWarn, "verification_skipped", "Upstream executor did not project a live-apply record; warn operators and re-run planner/dry-run before allowing the projected authorization.", 0.75
	}
	if strings.EqualFold(c.Lifecycle, "resolved") {
		return awsAdvisoryAuthorizationOutcomeAllow, "case_resolved", "Remediation case is resolved and no active risk finding is present; allow the projected authorization.", 0.85
	}
	if strings.EqualFold(c.ApprovalState, "blocked") {
		return awsAdvisoryAuthorizationOutcomeRecommendDeny, "approval_blocked", "Approval workflow blocked the change; recommend deny until the failing gate is satisfied.", 0.85
	}
	if strings.EqualFold(c.ApprovalState, "approved") {
		return awsAdvisoryAuthorizationOutcomeRequireApproval, "approved_awaiting_apply", "Change is approved but has not been applied and verified; require approval workflow to reach live execution before allowing the new posture.", 0.82
	}
	if c.ApprovalRequired {
		return awsAdvisoryAuthorizationOutcomeRequireApproval, "approval_required", "Case still requires approval before it can be executed; require approval before altering authorization.", 0.8
	}
	switch strings.ToLower(strings.TrimSpace(c.Severity)) {
	case "critical", "high":
		return awsAdvisoryAuthorizationOutcomeWarn, "high_severity_finding", "Upstream risk finding is high severity but no execution is in flight; warn operators and prioritize case triage.", 0.75
	}
	return awsAdvisoryAuthorizationOutcomeAllow, "no_active_risk", "No active risk finding or in-flight execution blocks the projected authorization; allow with advisory monitoring.", 0.7
}

// awsAdvisoryAuthorizationActionForCase derives the AWS API action the
// downstream dry-run/executor will project for the case, honoring the
// case's IAM principal kind so IAM-user targets surface the `PutUser*`
// variant instead of the role-only default. Callers filter by `action`,
// so returning the wrong variant would silently drop the decision from
// drill-downs.
func awsAdvisoryAuthorizationActionForCase(c AWSRemediationCase) string {
	// No-op diffs (manual review, owner assignment) never project a live
	// AWS write; the dry-run collapses them to `manual_review:noop`.
	// Reporting `iam:PutRolePolicy` here would advertise an IAM write
	// operators would never see and would mis-scope action drill-downs.
	if c.DiffIntent.NoOp {
		return "advisory:review"
	}
	kind := awsAdvisoryAuthorizationCasePrincipalKind(c)
	switch strings.ToLower(strings.TrimSpace(c.DiffIntent.Kind)) {
	case "iam_policy_diff", "role_scope_diff", "iac_iam_policy_pr":
		return awsAdvisoryAuthorizationPutPolicyAction(kind)
	case "iam_trust_diff", "iac_trust_policy_pr":
		return "iam:UpdateAssumeRolePolicy"
	case "permission_boundary_diff":
		return awsAdvisoryAuthorizationPutBoundaryAction(kind)
	case "scp_diff":
		return "organizations:AttachPolicy"
	case "kms_grant_diff":
		return "kms:PutKeyPolicy"
	case "secret_rotation":
		return "secretsmanager:RotateSecret"
	case "access_key_quarantine":
		return "iam:UpdateAccessKey"
	case "ai_agent_scope_change":
		return "bedrock-agent:UpdateAgent"
	}
	switch strings.ToLower(strings.TrimSpace(c.SourceType)) {
	case "least_privilege":
		return awsAdvisoryAuthorizationPutPolicyAction(kind)
	case "aws_permission_boundary_scp":
		return awsAdvisoryAuthorizationPutBoundaryAction(kind)
	case "trust_policy_hardening":
		return "iam:UpdateAssumeRolePolicy"
	case "aws_secret_key_rotation":
		return "secretsmanager:RotateSecret"
	case "aws_access_key_quarantine":
		return "iam:UpdateAccessKey"
	}
	return "advisory:review"
}

// awsAdvisoryAuthorizationCasePrincipalKind returns "user", "group", or
// "role" for the case's IAM principal. It parses the concrete identity node ID
// or ARN first, matching the dry-run router, because some upstream builders use
// a generic or hard-coded IdentityType while the target itself carries the true
// IAM principal kind.
func awsAdvisoryAuthorizationCasePrincipalKind(c AWSRemediationCase) string {
	if kind := awsRemediationDryRunClassifiedIAMPrincipalKind(c.IdentityNodeID); kind != "" {
		return kind
	}
	if kind := awsRemediationDryRunClassifiedIAMPrincipalKind(c.IdentityARN); kind != "" {
		return kind
	}
	switch strings.ToLower(strings.TrimSpace(c.IdentityType)) {
	case "iam_user":
		return "user"
	case "iam_group":
		return "group"
	case "iam_role":
		return "role"
	}
	return "role"
}

func awsAdvisoryAuthorizationPutPolicyAction(kind string) string {
	switch kind {
	case "user":
		return "iam:PutUserPolicy"
	case "group":
		return "iam:PutGroupPolicy"
	}
	return "iam:PutRolePolicy"
}

// awsAdvisoryAuthorizationPutBoundaryAction routes to a permission-boundary
// API only when the principal is an IAM user or role; groups cannot receive
// permission boundaries, so a group principal falls back to `advisory:review`
// rather than advertising a call AWS would reject.
func awsAdvisoryAuthorizationPutBoundaryAction(kind string) string {
	switch kind {
	case "user":
		return "iam:PutUserPermissionsBoundary"
	case "group":
		return "advisory:review"
	}
	return "iam:PutRolePermissionsBoundary"
}

func awsAdvisoryAuthorizationEvidenceFromCase(c AWSRemediationCase, verification AWSPostRemediationVerificationEntry) []AWSAdvisoryAuthorizationEvidence {
	out := []AWSAdvisoryAuthorizationEvidence{
		{Source: "remediation_case", Label: c.SourceType, EvidenceRef: awsAdvisoryAuthorizationCaseEvidenceRef(c)},
	}
	if verification.VerificationID != "" {
		out = append(out, AWSAdvisoryAuthorizationEvidence{
			Source:      "post_remediation_verification",
			Label:       verification.State,
			EvidenceRef: firstString(verification.EvidenceLinks),
		})
	}
	return out
}

func awsAdvisoryAuthorizationCaseEvidenceRef(c AWSRemediationCase) string {
	if ref := strings.TrimSpace(c.DiffIntent.BeforeRef); ref != "" {
		return ref
	}
	for _, evidence := range c.Evidence {
		if ref := strings.TrimSpace(evidence.EvidenceRef); ref != "" {
			return ref
		}
	}
	return ""
}

func awsAdvisoryAuthorizationEvidenceLinksFromCase(c AWSRemediationCase, verification AWSPostRemediationVerificationEntry) []string {
	links := []string{}
	if ref := awsAdvisoryAuthorizationCaseEvidenceRef(c); ref != "" {
		links = append(links, ref)
	}
	for _, link := range verification.EvidenceLinks {
		if link != "" {
			links = append(links, link)
		}
	}
	links = append(links, "/docs/aws-advisory-authorization")
	return dedupeStrings(links)
}

func awsAdvisoryAuthorizationAuditTrail(c AWSRemediationCase, verification AWSPostRemediationVerificationEntry, outcome, rule string, now time.Time) []AWSAdvisoryAuthorizationAuditEntry {
	trail := []AWSAdvisoryAuthorizationAuditEntry{}
	trail = append(trail, AWSAdvisoryAuthorizationAuditEntry{
		EventID:    stableAWSBlastRadiusToken("advisory-decision-projected", c.CaseID, outcome, rule),
		Actor:      "identrail-advisory-authorization-engine",
		EventType:  "advisory_decision_projected",
		OccurredAt: now,
		Notes:      fmt.Sprintf("Case=%s outcome=%s rule=%s policy_version=%s verification=%s; Identrail did not call any AWS write API at this layer.", c.CaseID, outcome, rule, awsAdvisoryAuthorizationPolicyID, verification.State),
	})
	return trail
}

func awsAdvisoryAuthorizationNextAction(outcome string) string {
	switch outcome {
	case awsAdvisoryAuthorizationOutcomeAllow:
		return "Recommendation is `allow`. Continue advisory monitoring; no operator action is required unless upstream signals change."
	case awsAdvisoryAuthorizationOutcomeWarn:
		return "Recommendation is `warn`. Prioritize case triage; consider raising the case severity or scheduling remediation."
	case awsAdvisoryAuthorizationOutcomeRequireApproval:
		return "Recommendation is `require_approval`. Advance the approval workflow and let the wave-8 apply runtime complete verification before treating the authorization as safe."
	case awsAdvisoryAuthorizationOutcomeRecommendDeny:
		return "Recommendation is `recommend_deny`. Do not extend or renew the authorization until the failing gate clears and the case is re-projected."
	case awsAdvisoryAuthorizationOutcomeQuarantine:
		return "Recommendation is `quarantine`. Disable the projected authorization until verification succeeds, rollback is applied, or the tenant kill switch is cleared."
	}
	return "Inspect the decision entry for the projected next action."
}

func awsAdvisoryAuthorizationRelationships(decisions []AWSAdvisoryAuthorizationDecision) []AWSAdvisoryAuthorizationRelationship {
	relationships := []AWSAdvisoryAuthorizationRelationship{}
	for _, decision := range decisions {
		if strings.TrimSpace(decision.PrincipalNodeID) != "" {
			relationships = append(relationships, AWSAdvisoryAuthorizationRelationship{
				DecisionID:  decision.DecisionID,
				Type:        "advises_principal",
				FromNodeID:  decision.DecisionID,
				ToNodeID:    decision.PrincipalNodeID,
				EvidenceRef: firstString(decision.EvidenceLinks),
			})
		}
		if strings.TrimSpace(decision.CaseID) != "" {
			relationships = append(relationships, AWSAdvisoryAuthorizationRelationship{
				DecisionID: decision.DecisionID,
				Type:       "derives_from_case",
				FromNodeID: decision.DecisionID,
				ToNodeID:   decision.CaseID,
			})
		}
		if strings.TrimSpace(decision.VerificationID) != "" {
			relationships = append(relationships, AWSAdvisoryAuthorizationRelationship{
				DecisionID: decision.DecisionID,
				Type:       "derives_from_verification",
				FromNodeID: decision.DecisionID,
				ToNodeID:   decision.VerificationID,
			})
		}
	}
	return relationships
}

func summarizeAWSAdvisoryAuthorizationDecisions(all, filtered []AWSAdvisoryAuthorizationDecision, relationships []AWSAdvisoryAuthorizationRelationship) AWSAdvisoryAuthorizationSummary {
	summary := AWSAdvisoryAuthorizationSummary{
		TotalDecisions:    len(all),
		FilteredDecisions: len(filtered),
		OutcomeCounts:     map[string]int{},
		SeverityCounts:    map[string]int{},
		SourceTypeCounts:  map[string]int{},
	}
	confidenceTotal := 0.0
	for _, decision := range filtered {
		summary.OutcomeCounts[decision.Outcome]++
		if decision.Severity != "" {
			summary.SeverityCounts[decision.Severity]++
		}
		if decision.SourceType != "" {
			summary.SourceTypeCounts[decision.SourceType]++
		}
		switch decision.Outcome {
		case awsAdvisoryAuthorizationOutcomeAllow:
			summary.AllowCount++
		case awsAdvisoryAuthorizationOutcomeWarn:
			summary.WarnCount++
		case awsAdvisoryAuthorizationOutcomeRequireApproval:
			summary.RequireApprovalCount++
		case awsAdvisoryAuthorizationOutcomeRecommendDeny:
			summary.RecommendDenyCount++
		case awsAdvisoryAuthorizationOutcomeQuarantine:
			summary.QuarantineCount++
		}
		if decision.KillSwitchEngaged {
			summary.KillSwitchEngagedCount++
		}
		if decision.Score > summary.HighestScore {
			summary.HighestScore = decision.Score
		}
		confidenceTotal += decision.Confidence
	}
	summary.RelationshipCount = len(relationships)
	if len(filtered) > 0 {
		summary.AverageConfidencePct = int((confidenceTotal/float64(len(filtered)))*100 + 0.5)
	}
	return summary
}

func filterAWSAdvisoryAuthorizationDecisions(decisions []AWSAdvisoryAuthorizationDecision, request AWSAdvisoryAuthorizationRequest) ([]AWSAdvisoryAuthorizationDecision, map[string]string) {
	filters := map[string]string{
		"account_id":      strings.TrimSpace(request.AccountID),
		"region":          strings.TrimSpace(request.Region),
		"principal_id":    strings.TrimSpace(request.PrincipalID),
		"action":          strings.TrimSpace(request.Action),
		"outcome":         normalizeAWSRuntimeEventFilterToken(request.Outcome),
		"severity":        normalizeAWSRuntimeEventFilterToken(request.Severity),
		"source_type":     strings.ToLower(strings.TrimSpace(request.SourceType)),
		"case_id":         strings.TrimSpace(request.CaseID),
		"verification_id": strings.TrimSpace(request.VerificationID),
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
	filtered := make([]AWSAdvisoryAuthorizationDecision, 0, len(decisions))
	for _, decision := range decisions {
		if filters["account_id"] != "" && !awsAdvisoryAuthorizationAccountMatch(decision, filters["account_id"]) {
			continue
		}
		if filters["region"] != "" && !strings.EqualFold(filters["region"], strings.TrimSpace(decision.Region)) {
			continue
		}
		if filters["principal_id"] != "" && !strings.EqualFold(filters["principal_id"], strings.TrimSpace(decision.PrincipalNodeID)) && !strings.EqualFold(filters["principal_id"], strings.TrimSpace(decision.PrincipalARN)) {
			continue
		}
		if filters["action"] != "" && !strings.EqualFold(filters["action"], strings.TrimSpace(decision.Action)) {
			continue
		}
		if filters["outcome"] != "" && filters["outcome"] != normalizeAWSRuntimeEventFilterToken(decision.Outcome) {
			continue
		}
		if filters["severity"] != "" && filters["severity"] != normalizeAWSRuntimeEventFilterToken(decision.Severity) {
			continue
		}
		if filters["source_type"] != "" && !strings.EqualFold(filters["source_type"], decision.SourceType) {
			continue
		}
		if filters["case_id"] != "" && !strings.EqualFold(filters["case_id"], decision.CaseID) {
			continue
		}
		if filters["verification_id"] != "" && !strings.EqualFold(filters["verification_id"], decision.VerificationID) {
			continue
		}
		if filters["search"] != "" && !awsAdvisoryAuthorizationSearchMatch(decision, filters["search"]) {
			continue
		}
		filtered = append(filtered, decision)
	}
	return filtered, applied
}

func awsAdvisoryAuthorizationAccountMatch(decision AWSAdvisoryAuthorizationDecision, accountID string) bool {
	accountID = strings.TrimSpace(accountID)
	if accountID == "" {
		return true
	}
	if strings.EqualFold(strings.TrimSpace(decision.AccountID), accountID) {
		return true
	}
	for _, target := range decision.TargetAccountIDs {
		if strings.EqualFold(strings.TrimSpace(target), accountID) {
			return true
		}
	}
	return false
}

func awsAdvisoryAuthorizationSearchMatch(decision AWSAdvisoryAuthorizationDecision, needle string) bool {
	needle = strings.ToLower(strings.TrimSpace(needle))
	if needle == "" {
		return true
	}
	values := []string{
		decision.DecisionID, decision.Outcome, decision.Severity, decision.Title, decision.Summary,
		decision.Rationale, decision.PrincipalNodeID, decision.PrincipalARN, decision.PrincipalType,
		decision.Action, decision.SourceType, decision.CaseID, decision.VerificationID, decision.NextAction,
		decision.Provenance.PolicyRule, decision.Provenance.PolicyVersion,
	}
	values = append(values, decision.ResourceScope...)
	values = append(values, decision.TargetAccountIDs...)
	values = append(values, decision.Provenance.SourceTypes...)
	values = append(values, decision.Provenance.Signals...)
	values = append(values, decision.EvidenceLinks...)
	values = append(values, decision.InputHash.Components...)
	for _, evidence := range decision.Evidence {
		values = append(values, evidence.Source, evidence.Label, evidence.EvidenceRef)
	}
	for _, audit := range decision.AuditTrail {
		values = append(values, audit.EventType, audit.Actor, audit.Notes)
	}
	for _, value := range values {
		if strings.Contains(strings.ToLower(value), needle) {
			return true
		}
	}
	return false
}

func summarizeAWSAdvisoryAuthorizationStatus(caseStatus, verificationStatus string, filtered []AWSAdvisoryAuthorizationDecision, diagnostics []AWSAdvisoryAuthorizationDiagnostic) (string, float64) {
	if caseStatus == awsPlatformDependencyStatusBlocked || verificationStatus == awsPlatformDependencyStatusBlocked {
		return awsPlatformDependencyStatusBlocked, 0.35
	}
	for _, diagnostic := range diagnostics {
		if diagnostic.Retryable {
			return awsPlatformDependencyStatusDegraded, 0.72
		}
	}
	if caseStatus == awsPlatformDependencyStatusDegraded || verificationStatus == awsPlatformDependencyStatusDegraded {
		return awsPlatformDependencyStatusDegraded, 0.74
	}
	if len(filtered) == 0 {
		return awsPlatformDependencyStatusReady, 0.82
	}
	return awsPlatformDependencyStatusReady, 0.9
}

func awsAdvisoryAuthorizationCaveats() []string {
	return []string{
		"Advisory authorization decisions are read-only recommendations; Identrail never enforces the outcome at this layer.",
		"Every decision carries a deterministic input hash and policy version so operators can detect drift when upstream signals change.",
		"Kill-switch and verification-failed states always classify as quarantine; the policy prevents a compromised or reverted execution from being recorded as `allow`.",
	}
}

func awsAdvisoryAuthorizationRemediationHints(source []string) []string {
	hints := []string{
		"Treat this endpoint as advisory input to policy decision points; downstream governance executors decide whether and how to enforce.",
		"If a decision moves to `quarantine`, investigate the upstream verification/kill-switch signal before making any live change.",
		"When the policy version changes, expect decision IDs and input hashes to change; log both for audit.",
	}
	hints = append(hints, source...)
	return dedupeStrings(hints)
}

func awsAdvisoryAuthorizationDiagnostics(caseDiag []AWSRemediationCaseDiagnostic, verifDiag []AWSPostRemediationVerificationDiagnostic) []AWSAdvisoryAuthorizationDiagnostic {
	out := []AWSAdvisoryAuthorizationDiagnostic{}
	for _, diagnostic := range caseDiag {
		out = append(out, AWSAdvisoryAuthorizationDiagnostic{
			Collector:   diagnostic.Collector,
			SourceID:    diagnostic.SourceID,
			Code:        diagnostic.Code,
			Message:     diagnostic.Message,
			Remediation: diagnostic.Remediation,
			Retryable:   diagnostic.Retryable,
		})
	}
	for _, diagnostic := range verifDiag {
		out = append(out, AWSAdvisoryAuthorizationDiagnostic(diagnostic))
	}
	return out
}

func awsAdvisoryAuthorizationCoverageGaps(caseGaps []AWSRemediationCaseCoverageGap, verifGaps []AWSPostRemediationVerificationCoverageGap) []AWSAdvisoryAuthorizationCoverageGap {
	out := []AWSAdvisoryAuthorizationCoverageGap{}
	for _, gap := range caseGaps {
		out = append(out, AWSAdvisoryAuthorizationCoverageGap{
			Capability:  gap.Capability,
			Status:      gap.Status,
			Reason:      gap.Reason,
			Remediation: gap.Remediation,
		})
	}
	for _, gap := range verifGaps {
		out = append(out, AWSAdvisoryAuthorizationCoverageGap(gap))
	}
	return out
}

func awsAdvisoryAuthorizationEvidenceBoundary() string {
	return "metadata_only_no_rendered_policy_bodies_no_secret_values_no_workload_payloads_tenant_workspace_project_connector_account_region_scoped"
}
