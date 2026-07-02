package api

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	awsSessionPolicyRecommendationCurrentIssue = 1544
	awsSessionPolicyRecommendationVersion      = "aws-session-policy-recommendation-v1"
	awsSessionPolicyRecommendationPolicyID     = "aws-session-policy-recommendation-policy-v1"
	awsSessionPolicyRecommendationModeAdvisory = "advisory"
)

// AWSSessionPolicyRecommendationRequest scopes the deterministic session
// policy recommendation projection to one AWS connector plus optional
// operator drill-down filters.
type AWSSessionPolicyRecommendationRequest struct {
	ConnectorID      string `json:"connector_id,omitempty"`
	FixtureState     string `json:"fixture_state,omitempty"`
	AccountID        string `json:"account_id,omitempty"`
	Region           string `json:"region,omitempty"`
	PrincipalID      string `json:"principal_id,omitempty"`
	RecommendationID string `json:"recommendation_id,omitempty"`
	Decision         string `json:"decision,omitempty"`
	Severity         string `json:"severity,omitempty"`
	Search           string `json:"search,omitempty"`
}

type AWSSessionPolicyRecommendationEvidence = AWSLeastPrivilegeEvidence
type AWSSessionPolicyRecommendationPathStep = AWSLeastPrivilegePathStep
type AWSSessionPolicyRecommendationDiagnostic = AWSLeastPrivilegeDiagnostic
type AWSSessionPolicyRecommendationCoverageGap = AWSLeastPrivilegeCoverageGap
type AWSSessionPolicyRecommendationAuditEntry = AWSRemediationApprovalAuditEntry

// AWSSessionPolicyRecommendationValidationSignal records one deterministic
// runtime or analyzer signal that validated (or would invalidate) the
// recommended session policy. Counts are metadata only; observed action
// payloads and rendered policy bodies are never inlined.
type AWSSessionPolicyRecommendationValidationSignal struct {
	Source      string `json:"source"`
	Signal      string `json:"signal"`
	Status      string `json:"status"`
	Count       int    `json:"count,omitempty"`
	Description string `json:"description"`
}

// AWSSessionPolicyRecommendationExpectedBehavior projects the allow/deny
// outcome operators should see after applying the recommended session
// policy. Actions live in the entry's allow/deny lists; this record
// summarizes the counts and the observed evidence that justifies them.
type AWSSessionPolicyRecommendationExpectedBehavior struct {
	AllowedActionCount  int `json:"allowed_action_count"`
	DeniedActionCount   int `json:"denied_action_count"`
	ObservedActionCount int `json:"observed_action_count"`
}

// AWSSessionPolicyRecommendationProvenance records the deterministic
// derivation path so operators can trace which policy version and source
// signals produced the recommendation.
type AWSSessionPolicyRecommendationProvenance struct {
	PolicyVersion  string   `json:"policy_version"`
	SourceRuleName string   `json:"source_rule_name"`
	Signals        []string `json:"signals,omitempty"`
}

// AWSSessionPolicyRecommendationRelationship surfaces recommendation→graph
// node edges for downstream UI and audit consumers.
type AWSSessionPolicyRecommendationRelationship struct {
	RecommendationID string `json:"recommendation_id"`
	Type             string `json:"type"`
	FromNodeID       string `json:"from_node_id"`
	ToNodeID         string `json:"to_node_id"`
	EvidenceRef      string `json:"evidence_ref,omitempty"`
}

// AWSSessionPolicyRecommendationEntry is the persisted-record-shaped contract
// for one session policy recommendation. It never inlines rendered JSON
// policy bodies; the recommended policy is exposed as a metadata reference
// (`session_policy_ref`) the downstream apply runtime can resolve when a
// controlled execution runs.
type AWSSessionPolicyRecommendationEntry struct {
	RecommendationID     string                                           `json:"recommendation_id"`
	CalculationVersion   string                                           `json:"calculation_version"`
	Mode                 string                                           `json:"mode"`
	Decision             string                                           `json:"decision"`
	Severity             string                                           `json:"severity"`
	Score                int                                              `json:"score"`
	Confidence           float64                                          `json:"confidence"`
	Title                string                                           `json:"title"`
	Summary              string                                           `json:"summary"`
	Rationale            string                                           `json:"rationale"`
	AccountID            string                                           `json:"account_id,omitempty"`
	Region               string                                           `json:"region,omitempty"`
	PrincipalNodeID      string                                           `json:"principal_node_id"`
	PrincipalARN         string                                           `json:"principal_arn,omitempty"`
	PrincipalDisplayName string                                           `json:"principal_display_name,omitempty"`
	SessionPolicyRef     string                                           `json:"session_policy_ref"`
	SessionDurationHint  string                                           `json:"session_duration_hint,omitempty"`
	AllowActions         []string                                         `json:"allow_actions"`
	DenyActions          []string                                         `json:"deny_actions,omitempty"`
	ResourceScope        []string                                         `json:"resource_scope,omitempty"`
	ConditionKeys        []string                                         `json:"condition_keys,omitempty"`
	ExpectedBehavior     AWSSessionPolicyRecommendationExpectedBehavior   `json:"expected_behavior"`
	ValidationSignals    []AWSSessionPolicyRecommendationValidationSignal `json:"validation_signals"`
	Provenance           AWSSessionPolicyRecommendationProvenance         `json:"provenance"`
	Evidence             []AWSSessionPolicyRecommendationEvidence         `json:"evidence"`
	EvidenceBoundary     string                                           `json:"evidence_boundary"`
	ImpactedNodes        []string                                         `json:"impacted_nodes"`
	ImpactedPath         []AWSSessionPolicyRecommendationPathStep         `json:"impacted_path"`
	AuditTrail           []AWSSessionPolicyRecommendationAuditEntry       `json:"audit_trail"`
	ReadOnlyProjection   bool                                             `json:"read_only_projection"`
	SourceSignals        []string                                         `json:"source_signals"`
	NextAction           string                                           `json:"next_action"`
	ProjectedAt          time.Time                                        `json:"projected_at"`
	CreatedAt            time.Time                                        `json:"created_at"`
	UpdatedAt            time.Time                                        `json:"updated_at"`
}

// AWSSessionPolicyRecommendationSummary aggregates the unfiltered/filtered
// recommendation set.
type AWSSessionPolicyRecommendationSummary struct {
	TotalRecommendations    int            `json:"total_recommendations"`
	FilteredRecommendations int            `json:"filtered_recommendations"`
	DecisionCounts          map[string]int `json:"decision_counts"`
	SeverityCounts          map[string]int `json:"severity_counts"`
	AllowActionCount        int            `json:"allow_action_count"`
	DenyActionCount         int            `json:"deny_action_count"`
	ObservedActionCount     int            `json:"observed_action_count"`
	ValidationSignalCount   int            `json:"validation_signal_count"`
	RelationshipCount       int            `json:"relationship_count"`
	HighestScore            int            `json:"highest_score"`
	AverageConfidencePct    int            `json:"average_confidence_pct"`
}

// AWSSessionPolicyRecommendationResult is the deterministic endpoint envelope.
type AWSSessionPolicyRecommendationResult struct {
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
	PolicyVersion      string                                       `json:"policy_version"`
	Mode               string                                       `json:"mode"`
	AppliedFilters     map[string]string                            `json:"applied_filters"`
	Summary            AWSSessionPolicyRecommendationSummary        `json:"summary"`
	Recommendations    []AWSSessionPolicyRecommendationEntry        `json:"recommendations"`
	Relationships      []AWSSessionPolicyRecommendationRelationship `json:"relationships"`
	Caveats            []string                                     `json:"caveats"`
	FailureReasons     []string                                     `json:"failure_reasons"`
	RemediationHints   []string                                     `json:"remediation_hints"`
	EvidenceLinks      []string                                     `json:"evidence_links"`
	CoverageGaps       []AWSSessionPolicyRecommendationCoverageGap  `json:"coverage_gaps"`
	Diagnostics        []AWSSessionPolicyRecommendationDiagnostic   `json:"diagnostics"`
	GeneratedAt        time.Time                                    `json:"generated_at"`
	UpdatedAt          time.Time                                    `json:"updated_at"`
}

// GetAWSSessionPolicyRecommendations projects deterministic advisory session
// policy recommendations from the least-privilege recommendation engine
// (#1522). Each entry pairs an observed-usage profile with the recommended
// STS session-policy scope operators can attach on AssumeRole to constrain
// downstream sessions. The endpoint is advisory-only; Identrail never calls
// IAM/STS write APIs at this layer and never inlines rendered policy JSON.
func (s *Service) GetAWSSessionPolicyRecommendations(ctx context.Context, workspaceID string, projectID string, request AWSSessionPolicyRecommendationRequest) (AWSSessionPolicyRecommendationResult, error) {
	project, scope, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return AWSSessionPolicyRecommendationResult{}, err
	}
	connection, hasConnection, err := s.awsBaselineConnection(ctx, project, strings.TrimSpace(request.ConnectorID))
	if err != nil {
		return AWSSessionPolicyRecommendationResult{}, err
	}
	now := s.Now().UTC()
	fixtureState := normalizeAWSSessionPolicyRecommendationFixtureState(request.FixtureState, connection, hasConnection)
	if fixtureState == "" {
		return AWSSessionPolicyRecommendationResult{}, ErrInvalidAWSConnectionRequest
	}

	accountID := firstNonEmptyAWSValue(connection.AccountID, strings.TrimSpace(request.AccountID), "123456789012")
	region := firstNonEmptyAWSValue(connection.Region, strings.TrimSpace(request.Region), "us-east-1")
	connectorID := firstNonEmptyAWSValue(connection.ConnectorID, strings.TrimSpace(request.ConnectorID))
	sourceFixtureState := fixtureState
	if strings.TrimSpace(request.FixtureState) == "" && hasConnection && connection.Connected {
		sourceFixtureState = ""
	}

	upstream, err := s.GetAWSLeastPrivilegeRecommendations(ctx, workspaceID, projectID, AWSLeastPrivilegeRequest{ConnectorID: connectorID, FixtureState: sourceFixtureState})
	if err != nil {
		return AWSSessionPolicyRecommendationResult{}, fmt.Errorf("session policy recommendations upstream: %w", err)
	}

	recommendations := awsSessionPolicyRecommendationEntries(upstream.Recommendations, now)
	sort.SliceStable(recommendations, func(i, j int) bool {
		if recommendations[i].Score == recommendations[j].Score {
			return recommendations[i].RecommendationID < recommendations[j].RecommendationID
		}
		return recommendations[i].Score > recommendations[j].Score
	})
	filtered, applied := filterAWSSessionPolicyRecommendations(recommendations, request)
	relationships := awsSessionPolicyRecommendationRelationships(filtered)
	diagnostics := awsSessionPolicyRecommendationDiagnostics(upstream.Diagnostics)
	coverageGaps := awsSessionPolicyRecommendationCoverageGaps(upstream.CoverageGaps)
	status, confidence := summarizeAWSSessionPolicyRecommendationStatus(upstream.Status, filtered, diagnostics)

	return AWSSessionPolicyRecommendationResult{
		TenantID:           scope.TenantID,
		WorkspaceID:        project.WorkspaceID,
		ProjectID:          project.ProjectID,
		ConnectorID:        connectorID,
		AccountID:          accountID,
		Region:             region,
		ParentIssueNumber:  awsPlatformDependencyParentIssue,
		ParentIssueRef:     awsIssueRef(awsPlatformDependencyParentIssue),
		CurrentIssueNumber: awsSessionPolicyRecommendationCurrentIssue,
		CurrentIssueRef:    awsIssueRef(awsSessionPolicyRecommendationCurrentIssue),
		Version:            awsSessionPolicyRecommendationVersion,
		Status:             status,
		FixtureState:       sourceFixtureState,
		Confidence:         confidence,
		CalculationVersion: awsSessionPolicyRecommendationVersion,
		PolicyVersion:      awsSessionPolicyRecommendationPolicyID,
		Mode:               awsSessionPolicyRecommendationModeAdvisory,
		AppliedFilters:     applied,
		Summary:            summarizeAWSSessionPolicyRecommendations(recommendations, filtered, relationships),
		Recommendations:    filtered,
		Relationships:      relationships,
		Caveats:            awsSessionPolicyRecommendationCaveats(),
		FailureReasons:     dedupeStrings(upstream.FailureReasons),
		RemediationHints:   awsSessionPolicyRecommendationHints(upstream.RemediationHints),
		EvidenceLinks: dedupeStrings([]string{
			awsIssueURL(awsPlatformDependencyParentIssue),
			awsIssueURL(awsSessionPolicyRecommendationCurrentIssue),
			awsIssueURL(awsLeastPrivilegeCurrentIssue),
			"/docs/aws-session-policy-recommendation",
			"/docs/aws-least-privilege",
			awsBaselineProjectEvidenceURL(scope, project),
		}),
		CoverageGaps: coverageGaps,
		Diagnostics:  diagnostics,
		GeneratedAt:  now,
		UpdatedAt:    now,
	}, nil
}

func normalizeAWSSessionPolicyRecommendationFixtureState(requested string, connection AWSConnectionStatus, hasConnection bool) string {
	// Mirror the upstream least-privilege normalizer so an explicit
	// `success`/`ready` fixture never advertises success when the
	// connection has been downgraded to permission_denied; the two
	// endpoints must return consistent fixture metadata.
	switch strings.ToLower(strings.TrimSpace(requested)) {
	case "", "success", "ready":
		if !hasConnection || !connection.Connected {
			return "permission_denied"
		}
		return "success"
	case "empty", "degraded", "partial_failure", "permission_denied":
		return strings.ToLower(strings.TrimSpace(requested))
	default:
		return ""
	}
}

// awsSessionPolicyRecommendationEntries admits only least-privilege
// recommendations that carry an actionable observed-usage profile. `keep`
// decisions carry no reduction to apply, and records without observed or
// keep actions produce no session-policy scope operators could reason about.
func awsSessionPolicyRecommendationEntries(source []AWSLeastPrivilegeRecommendation, now time.Time) []AWSSessionPolicyRecommendationEntry {
	entries := make([]AWSSessionPolicyRecommendationEntry, 0, len(source))
	for _, rec := range source {
		if !awsSessionPolicyRecommendationAdmits(rec) {
			continue
		}
		entries = append(entries, awsSessionPolicyRecommendationFromLeastPrivilege(rec, now))
	}
	return entries
}

func awsSessionPolicyRecommendationAdmits(rec AWSLeastPrivilegeRecommendation) bool {
	decision := strings.ToLower(strings.TrimSpace(rec.Decision))
	if decision != "remove" && decision != "review" {
		return false
	}
	if strings.TrimSpace(rec.IdentityNodeID) == "" {
		return false
	}
	// Session policies attach to STS AssumeRole calls and only make sense
	// for assumable role identities. Reject IAM users, groups, external
	// principals, and any identity whose kind cannot be parsed — the
	// downstream apply path has no valid place to attach the recommendation
	// for those.
	if !awsSessionPolicyRecommendationIsAssumableRole(rec) {
		return false
	}
	// Session policies can only carry AWS IAM `service:action` values.
	// Reject records whose actionable set does not contain a valid IAM
	// action after synthetic prefixes (agent-tool, etc.) are filtered out
	// — a downstream renderer could not build a valid session policy from
	// those inputs. Whitespace-only entries are trimmed by
	// awsSessionPolicyRecommendationValidIAMActions.
	if len(awsSessionPolicyRecommendationValidIAMActions(rec.KeepActions)) == 0 && len(awsSessionPolicyRecommendationValidIAMActions(rec.ObservedActions)) == 0 {
		return false
	}
	return true
}

// awsSessionPolicyRecommendationIsAssumableRole reports whether the record's
// target is an IAM role (or assumed-role) identity that STS AssumeRole can
// bind a session policy to. It parses the identity node ID and ARN with the
// dry-run principal-kind helper so records that classify as `user` or
// `group` are rejected; records where neither field parses to `role` are
// also rejected because emitting STS guidance for an unassumable principal
// would mislead operators.
func awsSessionPolicyRecommendationIsAssumableRole(rec AWSLeastPrivilegeRecommendation) bool {
	if kind := awsRemediationDryRunClassifiedIAMPrincipalKind(rec.IdentityNodeID); kind != "" {
		return kind == "role"
	}
	if kind := awsRemediationDryRunClassifiedIAMPrincipalKind(rec.PrincipalARN); kind != "" {
		return kind == "role"
	}
	return false
}

// awsSessionPolicyRecommendationValidIAMActions keeps only entries shaped
// like a real AWS IAM `service:action` value. It drops empty and
// whitespace-only entries and rejects known synthetic prefixes (currently
// `agent-tool:`, emitted by agent-runtime least-privilege records) that
// cannot appear in an IAM `Action` element.
func awsSessionPolicyRecommendationValidIAMActions(actions []string) []string {
	out := make([]string, 0, len(actions))
	seen := map[string]struct{}{}
	for _, action := range actions {
		trimmed := strings.TrimSpace(action)
		if trimmed == "" {
			continue
		}
		if !awsSessionPolicyRecommendationIsValidIAMAction(trimmed) {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	return out
}

func awsSessionPolicyRecommendationIsValidIAMAction(action string) bool {
	if action == "*" {
		return true
	}
	// Must be `service:action` with a non-empty service prefix.
	idx := strings.Index(action, ":")
	if idx <= 0 || idx == len(action)-1 {
		return false
	}
	service := strings.ToLower(action[:idx])
	// Reject known synthetic prefixes. Neither belongs in an IAM Action
	// element: `agent-tool:*` comes from agent-runtime least-privilege
	// records; `aws-service:*` is the upstream placeholder emitted by
	// awsLeastPrivilegeServiceAction when an IAM-last-used signal lacks a
	// resolvable target service.
	switch service {
	case "agent-tool", "aws-service":
		return false
	}
	return true
}

func awsSessionPolicyRecommendationFromLeastPrivilege(rec AWSLeastPrivilegeRecommendation, now time.Time) AWSSessionPolicyRecommendationEntry {
	allow := awsSessionPolicyRecommendationAllowActions(rec)
	deny := awsSessionPolicyRecommendationValidIAMActions(rec.RemoveActions)
	resourceScope := awsSessionPolicyRecommendationResourceScope(rec)
	sessionPolicyRef := "session-policy://" + rec.RecommendationID + "/proposed"
	recommendationID := "aws-session-policy-recommendation:" + stableAWSBlastRadiusToken("session-policy", rec.RecommendationID, rec.IdentityNodeID)
	validation := awsSessionPolicyRecommendationValidationSignals(rec)
	provenance := AWSSessionPolicyRecommendationProvenance{
		PolicyVersion:  awsSessionPolicyRecommendationPolicyID,
		SourceRuleName: awsSessionPolicyRecommendationRuleName(rec),
		Signals:        awsSessionPolicyRecommendationSignals(rec),
	}
	return AWSSessionPolicyRecommendationEntry{
		RecommendationID:     recommendationID,
		CalculationVersion:   awsSessionPolicyRecommendationVersion,
		Mode:                 awsSessionPolicyRecommendationModeAdvisory,
		Decision:             strings.ToLower(strings.TrimSpace(rec.Decision)),
		Severity:             rec.Severity,
		Score:                rec.Score,
		Confidence:           rec.Confidence,
		Title:                fmt.Sprintf("Session policy recommendation: %s", firstNonEmptyAWSValue(rec.DisplayName, rec.IdentityNodeID)),
		Summary:              fmt.Sprintf("Advisory session-policy scope derived from observed usage. Attach on STS AssumeRole to constrain sessions for %s. No live IAM/STS write API is called at this layer; the recommended policy stays behind %s.", firstNonEmptyAWSValue(rec.DisplayName, rec.IdentityNodeID), sessionPolicyRef),
		Rationale:            rec.Rationale,
		AccountID:            rec.AccountID,
		Region:               rec.Region,
		PrincipalNodeID:      rec.IdentityNodeID,
		PrincipalARN:         rec.PrincipalARN,
		PrincipalDisplayName: rec.DisplayName,
		SessionPolicyRef:     sessionPolicyRef,
		SessionDurationHint:  "3600s",
		AllowActions:         allow,
		DenyActions:          deny,
		ResourceScope:        resourceScope,
		ConditionKeys:        nil,
		ExpectedBehavior: AWSSessionPolicyRecommendationExpectedBehavior{
			AllowedActionCount:  len(allow),
			DeniedActionCount:   len(deny),
			ObservedActionCount: len(emptyStrings(rec.ObservedActions)),
		},
		ValidationSignals:  validation,
		Provenance:         provenance,
		Evidence:           rec.Evidence,
		EvidenceBoundary:   awsSessionPolicyRecommendationEvidenceBoundary(),
		ImpactedNodes:      emptyStrings(dedupeStrings(rec.ImpactedNodes)),
		ImpactedPath:       rec.ImpactedPath,
		AuditTrail:         awsSessionPolicyRecommendationAuditTrail(rec, now),
		ReadOnlyProjection: true,
		SourceSignals:      dedupeStrings([]string{"least_privilege", "session_policy_recommendation"}),
		NextAction:         awsSessionPolicyRecommendationNextAction(rec.Decision),
		ProjectedAt:        now,
		CreatedAt:          firstNonZeroAWSSessionPolicyRecommendationTime(rec.CreatedAt, now),
		UpdatedAt:          now,
	}
}

// awsSessionPolicyRecommendationAllowActions prefers the least-privilege
// keep-list; when the upstream carries no explicit keep list the observed
// action set is the safest baseline for the recommended session-policy
// allow-list. Synthetic action names (agent-tool, etc.) are filtered out so
// the projected allow-list only contains values a downstream renderer can
// place in an IAM `Action` element.
func awsSessionPolicyRecommendationAllowActions(rec AWSLeastPrivilegeRecommendation) []string {
	if keep := awsSessionPolicyRecommendationValidIAMActions(rec.KeepActions); len(keep) > 0 {
		return keep
	}
	return awsSessionPolicyRecommendationValidIAMActions(rec.ObservedActions)
}

// awsSessionPolicyRecommendationResourceScope returns only values a
// downstream renderer can place in an IAM `Resource` element: real ARNs or
// the `*` wildcard. Graph node IDs (aws:resource:..., aws:identity:...) are
// dropped here — they surface through impacted_nodes and relationships, not
// through the session-policy resource scope. When the record targets an S3
// bucket ARN it is expanded to include the `/*` object scope so object-level
// actions like `s3:GetObject` still match the recommended policy.
func awsSessionPolicyRecommendationResourceScope(rec AWSLeastPrivilegeRecommendation) []string {
	scope := []string{}
	if arn := strings.TrimSpace(rec.ResourceARN); awsSessionPolicyRecommendationIsValidResource(arn) {
		scope = append(scope, arn)
		if object := awsSessionPolicyRecommendationS3ObjectScope(arn); object != "" {
			scope = append(scope, object)
		}
	}
	if len(scope) == 0 {
		scope = append(scope, "*")
	}
	return dedupeStrings(scope)
}

// awsSessionPolicyRecommendationS3ObjectScope returns `arn:aws:s3:::<bucket>/*`
// when the input is an S3 bucket ARN so object-level allow-list actions
// still match. Bucket ARNs never contain `/`; object/prefix ARNs already do
// and are returned unchanged (empty).
func awsSessionPolicyRecommendationS3ObjectScope(arn string) string {
	const prefix = "arn:aws:s3:::"
	if !strings.HasPrefix(arn, prefix) {
		return ""
	}
	bucket := strings.TrimPrefix(arn, prefix)
	if bucket == "" || strings.Contains(bucket, "/") {
		return ""
	}
	return arn + "/*"
}

func awsSessionPolicyRecommendationIsValidResource(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	if value == "*" {
		return true
	}
	return strings.HasPrefix(value, "arn:")
}

func awsSessionPolicyRecommendationValidationSignals(rec AWSLeastPrivilegeRecommendation) []AWSSessionPolicyRecommendationValidationSignal {
	signals := []AWSSessionPolicyRecommendationValidationSignal{
		{
			Source:      "runtime",
			Signal:      "observed_action_coverage",
			Status:      awsSessionPolicyRecommendationSignalStatus(len(emptyStrings(rec.ObservedActions)) > 0),
			Count:       len(emptyStrings(rec.ObservedActions)),
			Description: "Observed action set from runtime evidence covering the projected session-policy allow-list.",
		},
		{
			Source:      "least_privilege",
			Signal:      "removed_action_projection",
			Status:      awsSessionPolicyRecommendationSignalStatus(len(emptyStrings(rec.RemoveActions)) > 0),
			Count:       len(emptyStrings(rec.RemoveActions)),
			Description: "Actions the upstream least-privilege analyzer projects as safe to remove for this principal.",
		},
		{
			Source:      "breakage_prediction",
			Signal:      "expected_breakage_level",
			Status:      awsSessionPolicyRecommendationBreakageStatus(rec.BreakagePrediction),
			Description: fmt.Sprintf("Breakage prediction=%s. %s", rec.BreakagePrediction, rec.BreakageRationale),
		},
	}
	return signals
}

func awsSessionPolicyRecommendationSignalStatus(ok bool) string {
	if ok {
		return "passed"
	}
	return "pending"
}

func awsSessionPolicyRecommendationBreakageStatus(prediction string) string {
	switch strings.ToLower(strings.TrimSpace(prediction)) {
	case "low":
		return "passed"
	case "unknown", "":
		return "pending"
	}
	return "warn"
}

func awsSessionPolicyRecommendationRuleName(rec AWSLeastPrivilegeRecommendation) string {
	switch strings.ToLower(strings.TrimSpace(rec.Decision)) {
	case "remove":
		return "constrain_unused_actions"
	case "review":
		return "surface_review_candidates"
	}
	return "advisory_review"
}

func awsSessionPolicyRecommendationSignals(rec AWSLeastPrivilegeRecommendation) []string {
	signals := []string{
		"decision=" + strings.ToLower(strings.TrimSpace(rec.Decision)),
	}
	if strings.TrimSpace(rec.RecommendationType) != "" {
		signals = append(signals, "recommendation_type="+rec.RecommendationType)
	}
	if strings.TrimSpace(rec.BreakagePrediction) != "" {
		signals = append(signals, "breakage="+rec.BreakagePrediction)
	}
	return dedupeStrings(signals)
}

func awsSessionPolicyRecommendationNextAction(decision string) string {
	switch strings.ToLower(strings.TrimSpace(decision)) {
	case "remove":
		return "Attach the recommended session policy on STS AssumeRole/AssumeRoleWithWebIdentity for this principal to constrain downstream sessions. This endpoint records the intent; no live IAM/STS write is performed here."
	case "review":
		return "Surface the recommended session policy to operators for review before enabling on AssumeRole call sites. Refresh runtime evidence if the observed-action set is empty."
	}
	return "Advisory only; inspect the recommendation entry for the projected session-policy scope."
}

func awsSessionPolicyRecommendationAuditTrail(rec AWSLeastPrivilegeRecommendation, now time.Time) []AWSSessionPolicyRecommendationAuditEntry {
	return []AWSSessionPolicyRecommendationAuditEntry{{
		EventID:    stableAWSBlastRadiusToken("session-policy-projected", rec.RecommendationID, awsSessionPolicyRecommendationPolicyID),
		Actor:      "identrail-session-policy-recommender",
		EventType:  "session_policy_recommendation_projected",
		OccurredAt: now,
		Notes:      fmt.Sprintf("RecommendationID=%s decision=%s policy_version=%s; Identrail did not call any AWS write API at this layer.", rec.RecommendationID, rec.Decision, awsSessionPolicyRecommendationPolicyID),
	}}
}

func awsSessionPolicyRecommendationRelationships(entries []AWSSessionPolicyRecommendationEntry) []AWSSessionPolicyRecommendationRelationship {
	relationships := []AWSSessionPolicyRecommendationRelationship{}
	for _, entry := range entries {
		if strings.TrimSpace(entry.PrincipalNodeID) != "" {
			relationships = append(relationships, AWSSessionPolicyRecommendationRelationship{
				RecommendationID: entry.RecommendationID,
				Type:             "recommends_session_policy_for_principal",
				FromNodeID:       entry.RecommendationID,
				ToNodeID:         entry.PrincipalNodeID,
				EvidenceRef:      entry.SessionPolicyRef,
			})
		}
		for _, node := range entry.ResourceScope {
			if strings.TrimSpace(node) == "" || node == "*" {
				continue
			}
			relationships = append(relationships, AWSSessionPolicyRecommendationRelationship{
				RecommendationID: entry.RecommendationID,
				Type:             "scopes_session_policy_to_resource",
				FromNodeID:       entry.RecommendationID,
				ToNodeID:         node,
			})
		}
	}
	return relationships
}

func summarizeAWSSessionPolicyRecommendations(all, filtered []AWSSessionPolicyRecommendationEntry, relationships []AWSSessionPolicyRecommendationRelationship) AWSSessionPolicyRecommendationSummary {
	summary := AWSSessionPolicyRecommendationSummary{
		TotalRecommendations:    len(all),
		FilteredRecommendations: len(filtered),
		DecisionCounts:          map[string]int{},
		SeverityCounts:          map[string]int{},
	}
	confidenceTotal := 0.0
	for _, entry := range filtered {
		if entry.Decision != "" {
			summary.DecisionCounts[entry.Decision]++
		}
		if entry.Severity != "" {
			summary.SeverityCounts[entry.Severity]++
		}
		summary.AllowActionCount += len(entry.AllowActions)
		summary.DenyActionCount += len(entry.DenyActions)
		summary.ObservedActionCount += entry.ExpectedBehavior.ObservedActionCount
		summary.ValidationSignalCount += len(entry.ValidationSignals)
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

func filterAWSSessionPolicyRecommendations(entries []AWSSessionPolicyRecommendationEntry, request AWSSessionPolicyRecommendationRequest) ([]AWSSessionPolicyRecommendationEntry, map[string]string) {
	filters := map[string]string{
		"account_id":        strings.TrimSpace(request.AccountID),
		"region":            strings.TrimSpace(request.Region),
		"principal_id":      strings.TrimSpace(request.PrincipalID),
		"recommendation_id": strings.TrimSpace(request.RecommendationID),
		"decision":          normalizeAWSRuntimeEventFilterToken(request.Decision),
		"severity":          normalizeAWSRuntimeEventFilterToken(request.Severity),
		"search":            strings.TrimSpace(request.Search),
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
	filtered := make([]AWSSessionPolicyRecommendationEntry, 0, len(entries))
	for _, entry := range entries {
		if filters["account_id"] != "" && !strings.EqualFold(filters["account_id"], strings.TrimSpace(entry.AccountID)) {
			continue
		}
		if filters["region"] != "" && !strings.EqualFold(filters["region"], strings.TrimSpace(entry.Region)) {
			continue
		}
		if filters["principal_id"] != "" && !strings.EqualFold(filters["principal_id"], strings.TrimSpace(entry.PrincipalNodeID)) && !strings.EqualFold(filters["principal_id"], strings.TrimSpace(entry.PrincipalARN)) {
			continue
		}
		if filters["recommendation_id"] != "" && !strings.EqualFold(filters["recommendation_id"], entry.RecommendationID) {
			continue
		}
		if filters["decision"] != "" && filters["decision"] != normalizeAWSRuntimeEventFilterToken(entry.Decision) {
			continue
		}
		if filters["severity"] != "" && filters["severity"] != normalizeAWSRuntimeEventFilterToken(entry.Severity) {
			continue
		}
		if filters["search"] != "" && !awsSessionPolicyRecommendationSearchMatch(entry, filters["search"]) {
			continue
		}
		filtered = append(filtered, entry)
	}
	return filtered, applied
}

func awsSessionPolicyRecommendationSearchMatch(entry AWSSessionPolicyRecommendationEntry, needle string) bool {
	needle = strings.ToLower(strings.TrimSpace(needle))
	if needle == "" {
		return true
	}
	values := []string{
		entry.RecommendationID, entry.Decision, entry.Severity, entry.Title, entry.Summary,
		entry.Rationale, entry.PrincipalNodeID, entry.PrincipalARN, entry.PrincipalDisplayName,
		entry.SessionPolicyRef, entry.NextAction, entry.Provenance.SourceRuleName,
	}
	values = append(values, entry.AllowActions...)
	values = append(values, entry.DenyActions...)
	values = append(values, entry.ResourceScope...)
	values = append(values, entry.ConditionKeys...)
	values = append(values, entry.ImpactedNodes...)
	values = append(values, entry.SourceSignals...)
	values = append(values, entry.Provenance.Signals...)
	for _, signal := range entry.ValidationSignals {
		values = append(values, signal.Source, signal.Signal, signal.Status, signal.Description)
	}
	for _, audit := range entry.AuditTrail {
		values = append(values, audit.EventType, audit.Actor, audit.Notes)
	}
	for _, evidence := range entry.Evidence {
		values = append(values, evidence.Source, evidence.Label, evidence.EvidenceRef)
	}
	for _, value := range values {
		if strings.Contains(strings.ToLower(value), needle) {
			return true
		}
	}
	return false
}

func summarizeAWSSessionPolicyRecommendationStatus(upstream string, filtered []AWSSessionPolicyRecommendationEntry, diagnostics []AWSSessionPolicyRecommendationDiagnostic) (string, float64) {
	if upstream == awsPlatformDependencyStatusBlocked {
		return awsPlatformDependencyStatusBlocked, 0.35
	}
	for _, diagnostic := range diagnostics {
		if diagnostic.Retryable {
			return awsPlatformDependencyStatusDegraded, 0.72
		}
	}
	if upstream == awsPlatformDependencyStatusDegraded {
		return awsPlatformDependencyStatusDegraded, 0.74
	}
	if len(filtered) == 0 {
		return awsPlatformDependencyStatusReady, 0.82
	}
	return awsPlatformDependencyStatusReady, 0.9
}

func awsSessionPolicyRecommendationCaveats() []string {
	return []string{
		"Session-policy recommendations are advisory-only; Identrail never calls IAM/STS write APIs at this layer.",
		"Rendered session-policy JSON stays behind session_policy_ref metadata references; this endpoint exposes scope, expected behavior, validation signals, and audit metadata only.",
		"Downstream apply runtime is responsible for attaching the policy to STS AssumeRole calls; the recommendation itself never mutates AWS.",
	}
}

func awsSessionPolicyRecommendationHints(source []string) []string {
	hints := []string{
		"Refresh runtime action evidence before applying so the observed-usage baseline captures current workload behavior.",
		"Roll out session-policy attachment to one AssumeRole call site first and expand only after the projected allow/deny counts hold.",
		"If breakage prediction is `unknown`, keep the recommendation in review until runtime evidence lifts confidence.",
	}
	hints = append(hints, source...)
	return dedupeStrings(hints)
}

func awsSessionPolicyRecommendationDiagnostics(source []AWSLeastPrivilegeDiagnostic) []AWSSessionPolicyRecommendationDiagnostic {
	out := make([]AWSSessionPolicyRecommendationDiagnostic, 0, len(source))
	for _, diagnostic := range source {
		out = append(out, AWSSessionPolicyRecommendationDiagnostic(diagnostic))
	}
	return out
}

func awsSessionPolicyRecommendationCoverageGaps(source []AWSLeastPrivilegeCoverageGap) []AWSSessionPolicyRecommendationCoverageGap {
	out := make([]AWSSessionPolicyRecommendationCoverageGap, 0, len(source))
	for _, gap := range source {
		out = append(out, AWSSessionPolicyRecommendationCoverageGap(gap))
	}
	return out
}

func awsSessionPolicyRecommendationEvidenceBoundary() string {
	return "metadata_only_no_rendered_policy_bodies_no_secret_values_no_workload_payloads_tenant_workspace_project_connector_account_region_scoped"
}

func firstNonZeroAWSSessionPolicyRecommendationTime(values ...time.Time) time.Time {
	for _, value := range values {
		if !value.IsZero() {
			return value
		}
	}
	return time.Time{}
}
