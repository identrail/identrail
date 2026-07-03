package api

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	awsLimitedEnforcementCurrentIssue = 1546
	awsLimitedEnforcementVersion      = "aws-limited-enforcement-v1"
	awsLimitedEnforcementPolicyID     = "aws-limited-enforcement-policy-v1"

	awsLimitedEnforcementModeWarnOnly         = "warn_only"
	awsLimitedEnforcementModeAdvisory         = "advisory"
	awsLimitedEnforcementModeApprovalRequired = "approval_required"
	awsLimitedEnforcementModeLimitedEnforce   = "limited_enforce"

	awsLimitedEnforcementStateWarnOnly              = "warn_only"
	awsLimitedEnforcementStateAdvisoryOnly          = "advisory_only"
	awsLimitedEnforcementStateApprovalRequired      = "approval_required"
	awsLimitedEnforcementStateCanaryReady           = "canary_ready"
	awsLimitedEnforcementStateLimitedEnforceReady   = "limited_enforce_ready"
	awsLimitedEnforcementStateBlockedBySafetyConfig = "blocked_by_safety_config"
	awsLimitedEnforcementStateBlockedByKillSwitch   = "blocked_by_kill_switch"
	awsLimitedEnforcementStateRollbackRequired      = "rollback_required"
)

// AWSLimitedEnforcementRequest scopes the limited-enforcement framework to
// one AWS connector plus optional operator drill-down and safety-config
// filters. The safety config is explicit so enforcement cannot activate from
// defaults.
type AWSLimitedEnforcementRequest struct {
	ConnectorID      string `json:"connector_id,omitempty"`
	FixtureState     string `json:"fixture_state,omitempty"`
	AccountID        string `json:"account_id,omitempty"`
	Region           string `json:"region,omitempty"`
	Mode             string `json:"mode,omitempty"`
	EnforcementState string `json:"enforcement_state,omitempty"`
	DecisionID       string `json:"decision_id,omitempty"`
	SourceType       string `json:"source_type,omitempty"`
	Outcome          string `json:"outcome,omitempty"`
	Cohort           string `json:"cohort,omitempty"`
	FeatureFlag      string `json:"feature_flag,omitempty"`
	KillSwitch       string `json:"kill_switch,omitempty"`
	CanaryPercent    int    `json:"canary_percent,omitempty"`
	Search           string `json:"search,omitempty"`
}

type AWSLimitedEnforcementAuditEntry = AWSRemediationApprovalAuditEntry
type AWSLimitedEnforcementCoverageGap = AWSRemediationApprovalCoverageGap
type AWSLimitedEnforcementDiagnostic = AWSRemediationApprovalDiagnostic

type AWSLimitedEnforcementSafetyConfig struct {
	FeatureFlagEnabled bool   `json:"feature_flag_enabled"`
	KillSwitchEngaged  bool   `json:"kill_switch_engaged"`
	CanaryPercent      int    `json:"canary_percent"`
	Cohort             string `json:"cohort,omitempty"`
	RollbackRequired   bool   `json:"rollback_required"`
	AuditRequired      bool   `json:"audit_required"`
}

type AWSLimitedEnforcementGate struct {
	Name      string `json:"name"`
	Status    string `json:"status"`
	Rationale string `json:"rationale"`
}

type AWSLimitedEnforcementEvidence struct {
	Source      string `json:"source"`
	Label       string `json:"label"`
	EvidenceRef string `json:"evidence_ref,omitempty"`
}

type AWSLimitedEnforcementRollback struct {
	Strategy    string   `json:"strategy"`
	Steps       []string `json:"steps"`
	EvidenceRef string   `json:"evidence_ref,omitempty"`
	State       string   `json:"state"`
	Rationale   string   `json:"rationale"`
}

type AWSLimitedEnforcementRelationship struct {
	EnforcementID string `json:"enforcement_id"`
	Type          string `json:"type"`
	FromNodeID    string `json:"from_node_id"`
	ToNodeID      string `json:"to_node_id"`
	EvidenceRef   string `json:"evidence_ref,omitempty"`
}

// AWSLimitedEnforcementEntry is the persisted-record-shaped contract for one
// limited-enforcement framework projection. It records the safety config,
// canary/cohort gate, rollback intent, audit row, policy version, confidence,
// and evidence references without calling AWS write APIs.
type AWSLimitedEnforcementEntry struct {
	EnforcementID       string                              `json:"enforcement_id"`
	CalculationVersion  string                              `json:"calculation_version"`
	PolicyVersion       string                              `json:"policy_version"`
	SourceType          string                              `json:"source_type"`
	SourceID            string                              `json:"source_id"`
	Mode                string                              `json:"mode"`
	EnforcementState    string                              `json:"enforcement_state"`
	Outcome             string                              `json:"outcome"`
	Confidence          float64                             `json:"confidence"`
	Severity            string                              `json:"severity"`
	Score               int                                 `json:"score"`
	Title               string                              `json:"title"`
	Summary             string                              `json:"summary"`
	AccountID           string                              `json:"account_id,omitempty"`
	TargetAccountIDs    []string                            `json:"target_account_ids,omitempty"`
	Region              string                              `json:"region,omitempty"`
	PrincipalNodeID     string                              `json:"principal_node_id,omitempty"`
	Action              string                              `json:"action,omitempty"`
	TargetScope         []string                            `json:"target_scope,omitempty"`
	SafetyConfig        AWSLimitedEnforcementSafetyConfig   `json:"safety_config"`
	Gates               []AWSLimitedEnforcementGate         `json:"gates"`
	Rollback            AWSLimitedEnforcementRollback       `json:"rollback"`
	Evidence            []AWSLimitedEnforcementEvidence     `json:"evidence"`
	EvidenceLinks       []string                            `json:"evidence_links"`
	EvidenceBoundary    string                              `json:"evidence_boundary"`
	InputHash           string                              `json:"input_hash"`
	AuditTrail          []AWSLimitedEnforcementAuditEntry   `json:"audit_trail"`
	Relationships       []AWSLimitedEnforcementRelationship `json:"relationships,omitempty"`
	ReadOnlyProjection  bool                                `json:"read_only_projection"`
	ReadyForCanary      bool                                `json:"ready_for_canary"`
	ReadyForEnforcement bool                                `json:"ready_for_enforcement"`
	NextAction          string                              `json:"next_action"`
	ProjectedAt         time.Time                           `json:"projected_at"`
	UpdatedAt           time.Time                           `json:"updated_at"`
}

type AWSLimitedEnforcementSummary struct {
	TotalEntries             int            `json:"total_entries"`
	FilteredEntries          int            `json:"filtered_entries"`
	ModeCounts               map[string]int `json:"mode_counts"`
	EnforcementStateCounts   map[string]int `json:"enforcement_state_counts"`
	OutcomeCounts            map[string]int `json:"outcome_counts"`
	SourceTypeCounts         map[string]int `json:"source_type_counts"`
	WarnOnlyCount            int            `json:"warn_only_count"`
	AdvisoryCount            int            `json:"advisory_count"`
	ApprovalRequiredCount    int            `json:"approval_required_count"`
	LimitedEnforceCount      int            `json:"limited_enforce_count"`
	CanaryReadyCount         int            `json:"canary_ready_count"`
	ReadyForEnforcementCount int            `json:"ready_for_enforcement_count"`
	KillSwitchEngagedCount   int            `json:"kill_switch_engaged_count"`
	FailedGateCount          int            `json:"failed_gate_count"`
	RelationshipCount        int            `json:"relationship_count"`
	HighestScore             int            `json:"highest_score"`
	AverageConfidencePct     int            `json:"average_confidence_pct"`
}

type AWSLimitedEnforcementResult struct {
	TenantID           string                              `json:"tenant_id"`
	WorkspaceID        string                              `json:"workspace_id"`
	ProjectID          string                              `json:"project_id"`
	ConnectorID        string                              `json:"connector_id,omitempty"`
	AccountID          string                              `json:"account_id,omitempty"`
	Region             string                              `json:"region,omitempty"`
	ParentIssueNumber  int                                 `json:"parent_issue_number"`
	ParentIssueRef     string                              `json:"parent_issue_ref"`
	CurrentIssueNumber int                                 `json:"current_issue_number"`
	CurrentIssueRef    string                              `json:"current_issue_ref"`
	Version            string                              `json:"version"`
	Status             string                              `json:"status"`
	FixtureState       string                              `json:"fixture_state,omitempty"`
	Confidence         float64                             `json:"confidence"`
	CalculationVersion string                              `json:"calculation_version"`
	PolicyVersion      string                              `json:"policy_version"`
	SafetyConfig       AWSLimitedEnforcementSafetyConfig   `json:"safety_config"`
	AppliedFilters     map[string]string                   `json:"applied_filters"`
	Summary            AWSLimitedEnforcementSummary        `json:"summary"`
	Entries            []AWSLimitedEnforcementEntry        `json:"entries"`
	Relationships      []AWSLimitedEnforcementRelationship `json:"relationships"`
	Caveats            []string                            `json:"caveats"`
	FailureReasons     []string                            `json:"failure_reasons"`
	RemediationHints   []string                            `json:"remediation_hints"`
	EvidenceLinks      []string                            `json:"evidence_links"`
	CoverageGaps       []AWSLimitedEnforcementCoverageGap  `json:"coverage_gaps"`
	Diagnostics        []AWSLimitedEnforcementDiagnostic   `json:"diagnostics"`
	GeneratedAt        time.Time                           `json:"generated_at"`
	UpdatedAt          time.Time                           `json:"updated_at"`
}

// GetAWSLimitedEnforcement projects a feature-flagged limited-enforcement
// framework over advisory authorization (#1543) and AgentCore gateway policy
// advisories (#1545). It is metadata-only: the endpoint records canary,
// cohort, kill-switch, rollback, confidence, and audit state but never calls
// IAM, STS, Organizations, Bedrock, or AgentCore write APIs.
func (s *Service) GetAWSLimitedEnforcement(ctx context.Context, workspaceID string, projectID string, request AWSLimitedEnforcementRequest) (AWSLimitedEnforcementResult, error) {
	project, scope, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return AWSLimitedEnforcementResult{}, err
	}
	connection, hasConnection, err := s.awsBaselineConnection(ctx, project, strings.TrimSpace(request.ConnectorID))
	if err != nil {
		return AWSLimitedEnforcementResult{}, err
	}
	now := s.Now().UTC()
	fixtureState := normalizeAWSLimitedEnforcementFixtureState(request.FixtureState, connection, hasConnection)
	if fixtureState == "" {
		return AWSLimitedEnforcementResult{}, ErrInvalidAWSConnectionRequest
	}

	accountID := firstNonEmptyAWSValue(connection.AccountID, strings.TrimSpace(request.AccountID), "123456789012")
	region := firstNonEmptyAWSValue(connection.Region, strings.TrimSpace(request.Region), "us-east-1")
	connectorID := firstNonEmptyAWSValue(connection.ConnectorID, strings.TrimSpace(request.ConnectorID))
	sourceFixtureState := fixtureState
	if strings.TrimSpace(request.FixtureState) == "" && hasConnection && connection.Connected {
		sourceFixtureState = ""
	}
	safety := awsLimitedEnforcementSafetyConfig(request)

	advisory, err := s.GetAWSAdvisoryAuthorization(ctx, workspaceID, projectID, AWSAdvisoryAuthorizationRequest{ConnectorID: connectorID, FixtureState: sourceFixtureState})
	if err != nil {
		return AWSLimitedEnforcementResult{}, fmt.Errorf("limited enforcement advisory authorization: %w", err)
	}
	agentcore, err := s.GetAWSAgentCoreGatewayPolicyAdvisory(ctx, workspaceID, projectID, AWSAgentCoreGatewayPolicyAdvisoryRequest{ConnectorID: connectorID, FixtureState: sourceFixtureState})
	if err != nil {
		return AWSLimitedEnforcementResult{}, fmt.Errorf("limited enforcement agentcore gateway policy advisory: %w", err)
	}

	entries := awsLimitedEnforcementEntries(advisory.Decisions, agentcore.Advisories, safety, request, now)
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].Score == entries[j].Score {
			return entries[i].EnforcementID < entries[j].EnforcementID
		}
		return entries[i].Score > entries[j].Score
	})
	filtered, applied := filterAWSLimitedEnforcementEntries(entries, request)
	relationships := awsLimitedEnforcementRelationships(filtered)
	diagnostics := awsLimitedEnforcementDiagnostics(advisory.Diagnostics, agentcore.Diagnostics)
	status, confidence := summarizeAWSLimitedEnforcementStatus(advisory.Status, agentcore.Status, filtered, diagnostics)
	return AWSLimitedEnforcementResult{
		TenantID:           scope.TenantID,
		WorkspaceID:        project.WorkspaceID,
		ProjectID:          project.ProjectID,
		ConnectorID:        connectorID,
		AccountID:          accountID,
		Region:             region,
		ParentIssueNumber:  awsPlatformDependencyParentIssue,
		ParentIssueRef:     awsIssueRef(awsPlatformDependencyParentIssue),
		CurrentIssueNumber: awsLimitedEnforcementCurrentIssue,
		CurrentIssueRef:    awsIssueRef(awsLimitedEnforcementCurrentIssue),
		Version:            awsLimitedEnforcementVersion,
		Status:             status,
		FixtureState:       sourceFixtureState,
		Confidence:         confidence,
		CalculationVersion: awsLimitedEnforcementVersion,
		PolicyVersion:      awsLimitedEnforcementPolicyID,
		SafetyConfig:       safety,
		AppliedFilters:     applied,
		Summary:            summarizeAWSLimitedEnforcementEntries(entries, filtered, relationships),
		Entries:            filtered,
		Relationships:      relationships,
		Caveats:            awsLimitedEnforcementCaveats(),
		FailureReasons:     dedupeStrings(append(append([]string{}, advisory.FailureReasons...), agentcore.FailureReasons...)),
		RemediationHints:   awsLimitedEnforcementRemediationHints(append(advisory.RemediationHints, agentcore.RemediationHints...)),
		EvidenceLinks: dedupeStrings([]string{
			awsIssueURL(awsPlatformDependencyParentIssue),
			awsIssueURL(awsLimitedEnforcementCurrentIssue),
			awsIssueURL(awsAdvisoryAuthorizationCurrentIssue),
			awsIssueURL(awsAgentCoreGatewayPolicyAdvisoryCurrentIssue),
			"/docs/aws-limited-enforcement",
			"/docs/aws-advisory-authorization",
			"/docs/aws-agentcore-gateway-policy-advisory",
			awsBaselineProjectEvidenceURL(scope, project),
		}),
		CoverageGaps: awsLimitedEnforcementCoverageGaps(advisory.CoverageGaps, agentcore.CoverageGaps),
		Diagnostics:  diagnostics,
		GeneratedAt:  now,
		UpdatedAt:    now,
	}, nil
}

func normalizeAWSLimitedEnforcementFixtureState(requested string, connection AWSConnectionStatus, hasConnection bool) string {
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

func awsLimitedEnforcementSafetyConfig(request AWSLimitedEnforcementRequest) AWSLimitedEnforcementSafetyConfig {
	return AWSLimitedEnforcementSafetyConfig{
		FeatureFlagEnabled: normalizeAWSLimitedEnforcementBool(request.FeatureFlag),
		KillSwitchEngaged:  normalizeAWSLimitedEnforcementBool(request.KillSwitch),
		CanaryPercent:      clampAWSLimitedEnforcementCanary(request.CanaryPercent),
		Cohort:             strings.TrimSpace(request.Cohort),
		RollbackRequired:   true,
		AuditRequired:      true,
	}
}

func normalizeAWSLimitedEnforcementBool(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on", "enabled":
		return true
	}
	return false
}

func clampAWSLimitedEnforcementCanary(value int) int {
	if value < 0 {
		return 0
	}
	if value > 100 {
		return 100
	}
	return value
}

func parseAWSLimitedEnforcementCanary(value string) (int, bool) {
	if strings.TrimSpace(value) == "" {
		return 0, true
	}
	parsed, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		return 0, false
	}
	if parsed < 0 || parsed > 100 {
		return 0, false
	}
	return parsed, true
}

func awsLimitedEnforcementEntries(decisions []AWSAdvisoryAuthorizationDecision, advisories []AWSAgentCoreGatewayPolicyAdvisoryEntry, safety AWSLimitedEnforcementSafetyConfig, request AWSLimitedEnforcementRequest, now time.Time) []AWSLimitedEnforcementEntry {
	entries := make([]AWSLimitedEnforcementEntry, 0, len(decisions)+len(advisories))
	for _, decision := range decisions {
		entries = append(entries, awsLimitedEnforcementEntryFromDecision(decision, safety, request, now))
	}
	for _, advisory := range advisories {
		entries = append(entries, awsLimitedEnforcementEntryFromAgentCoreAdvisory(advisory, safety, request, now))
	}
	return entries
}

func awsLimitedEnforcementEntryFromDecision(decision AWSAdvisoryAuthorizationDecision, safety AWSLimitedEnforcementSafetyConfig, request AWSLimitedEnforcementRequest, now time.Time) AWSLimitedEnforcementEntry {
	mode, state := awsLimitedEnforcementClassifyDecision(decision, safety, request)
	enforcementID := "aws-limited-enforcement:" + stableAWSBlastRadiusToken("decision", decision.DecisionID, mode, state, safety.Cohort, fmt.Sprint(safety.CanaryPercent))
	gates := awsLimitedEnforcementGates(mode, state, safety, decision.Confidence, decision.KillSwitchEngaged, decision.Outcome)
	readyCanary := mode == awsLimitedEnforcementModeLimitedEnforce && awsLimitedEnforcementGatePassed(gates, "canary_configured") && !awsLimitedEnforcementHasFailedGate(gates)
	readyEnforce := mode == awsLimitedEnforcementModeLimitedEnforce && state == awsLimitedEnforcementStateLimitedEnforceReady && !awsLimitedEnforcementHasFailedGate(gates)
	rollback := awsLimitedEnforcementRollback("advisory_authorization", firstString(decision.EvidenceLinks), state)
	evidence := []AWSLimitedEnforcementEvidence{{Source: "advisory_authorization", Label: decision.Outcome, EvidenceRef: firstString(decision.EvidenceLinks)}}
	for _, item := range decision.Evidence {
		evidence = append(evidence, AWSLimitedEnforcementEvidence(item))
	}
	return AWSLimitedEnforcementEntry{
		EnforcementID:       enforcementID,
		CalculationVersion:  awsLimitedEnforcementVersion,
		PolicyVersion:       awsLimitedEnforcementPolicyID,
		SourceType:          "advisory_authorization",
		SourceID:            decision.DecisionID,
		Mode:                mode,
		EnforcementState:    state,
		Outcome:             decision.Outcome,
		Confidence:          decision.Confidence,
		Severity:            decision.Severity,
		Score:               decision.Score,
		Title:               fmt.Sprintf("Limited enforcement framework: %s", decision.Title),
		Summary:             fmt.Sprintf("Framework projection for advisory authorization decision %s. Identrail records feature flag, cohort, canary, kill-switch, rollback, and audit gates; no live AWS write API is called.", decision.DecisionID),
		AccountID:           decision.AccountID,
		TargetAccountIDs:    decision.TargetAccountIDs,
		Region:              decision.Region,
		PrincipalNodeID:     decision.PrincipalNodeID,
		Action:              decision.Action,
		TargetScope:         decision.ResourceScope,
		SafetyConfig:        safety,
		Gates:               gates,
		Rollback:            rollback,
		Evidence:            evidence,
		EvidenceLinks:       dedupeStrings(append(append([]string{}, decision.EvidenceLinks...), "/docs/aws-limited-enforcement")),
		EvidenceBoundary:    awsLimitedEnforcementEvidenceBoundary(),
		InputHash:           stableAWSBlastRadiusToken("limited-enforcement-input", decision.InputHash.Value, mode, state, safety.Cohort, fmt.Sprint(safety.CanaryPercent), awsLimitedEnforcementPolicyID),
		AuditTrail:          awsLimitedEnforcementAuditTrail(enforcementID, decision.DecisionID, mode, state, now),
		ReadOnlyProjection:  true,
		ReadyForCanary:      readyCanary,
		ReadyForEnforcement: readyEnforce,
		NextAction:          awsLimitedEnforcementNextAction(mode, state),
		ProjectedAt:         now,
		UpdatedAt:           now,
	}
}

func awsLimitedEnforcementEntryFromAgentCoreAdvisory(advisory AWSAgentCoreGatewayPolicyAdvisoryEntry, safety AWSLimitedEnforcementSafetyConfig, request AWSLimitedEnforcementRequest, now time.Time) AWSLimitedEnforcementEntry {
	mode, state := awsLimitedEnforcementClassifyAgentCoreAdvisory(advisory, safety, request)
	enforcementID := "aws-limited-enforcement:" + stableAWSBlastRadiusToken("agentcore", advisory.AdvisoryID, mode, state, safety.Cohort, fmt.Sprint(safety.CanaryPercent))
	gates := awsLimitedEnforcementGates(mode, state, safety, advisory.Confidence, false, advisory.Outcome)
	readyCanary := mode == awsLimitedEnforcementModeLimitedEnforce && awsLimitedEnforcementGatePassed(gates, "canary_configured") && !awsLimitedEnforcementHasFailedGate(gates)
	readyEnforce := mode == awsLimitedEnforcementModeLimitedEnforce && state == awsLimitedEnforcementStateLimitedEnforceReady && !awsLimitedEnforcementHasFailedGate(gates)
	evidenceLinks := awsLimitedEnforcementAgentCoreEvidenceLinks(advisory)
	evidence := []AWSLimitedEnforcementEvidence{{Source: "agentcore_gateway_policy_advisory", Label: advisory.Outcome, EvidenceRef: firstString(evidenceLinks)}}
	for _, item := range advisory.Evidence {
		evidence = append(evidence, AWSLimitedEnforcementEvidence{Source: item.Source, Label: item.Label, EvidenceRef: item.EvidenceRef})
	}
	return AWSLimitedEnforcementEntry{
		EnforcementID:       enforcementID,
		CalculationVersion:  awsLimitedEnforcementVersion,
		PolicyVersion:       awsLimitedEnforcementPolicyID,
		SourceType:          "agentcore_gateway_policy_advisory",
		SourceID:            advisory.AdvisoryID,
		Mode:                mode,
		EnforcementState:    state,
		Outcome:             advisory.Outcome,
		Confidence:          advisory.Confidence,
		Severity:            advisory.Severity,
		Score:               advisory.Score,
		Title:               fmt.Sprintf("Limited enforcement framework: %s", advisory.Title),
		Summary:             fmt.Sprintf("Framework projection for AgentCore gateway advisory %s. Identrail records feature flag, cohort, canary, kill-switch, rollback, and audit gates; no live AgentCore or IAM write API is called.", advisory.AdvisoryID),
		AccountID:           advisory.AccountID,
		TargetAccountIDs:    emptyStrings([]string{advisory.AccountID}),
		Region:              advisory.Region,
		PrincipalNodeID:     advisory.AgentNodeID,
		Action:              "agentcore:GatewayPolicy",
		TargetScope:         dedupeStrings(append(append(append([]string{}, advisory.AllowedToolNames...), append(advisory.RestrictedToolNames, advisory.BlockedToolNames...)...), advisory.SensitiveResources...)),
		SafetyConfig:        safety,
		Gates:               gates,
		Rollback:            awsLimitedEnforcementRollback("agentcore_gateway_policy_advisory", firstString(evidenceLinks), state),
		Evidence:            evidence,
		EvidenceLinks:       dedupeStrings(append(evidenceLinks, "/docs/aws-limited-enforcement")),
		EvidenceBoundary:    awsLimitedEnforcementEvidenceBoundary(),
		InputHash:           stableAWSBlastRadiusToken("limited-enforcement-input", advisory.InputHash.Value, mode, state, safety.Cohort, fmt.Sprint(safety.CanaryPercent), awsLimitedEnforcementPolicyID),
		AuditTrail:          awsLimitedEnforcementAuditTrail(enforcementID, advisory.AdvisoryID, mode, state, now),
		ReadOnlyProjection:  true,
		ReadyForCanary:      readyCanary,
		ReadyForEnforcement: readyEnforce,
		NextAction:          awsLimitedEnforcementNextAction(mode, state),
		ProjectedAt:         now,
		UpdatedAt:           now,
	}
}

func awsLimitedEnforcementClassifyDecision(decision AWSAdvisoryAuthorizationDecision, safety AWSLimitedEnforcementSafetyConfig, request AWSLimitedEnforcementRequest) (string, string) {
	if safety.KillSwitchEngaged || decision.KillSwitchEngaged {
		return awsLimitedEnforcementModeAdvisory, awsLimitedEnforcementStateBlockedByKillSwitch
	}
	switch decision.Outcome {
	case awsAdvisoryAuthorizationOutcomeQuarantine:
		return awsLimitedEnforcementModeAdvisory, awsLimitedEnforcementStateRollbackRequired
	case awsAdvisoryAuthorizationOutcomeRequireApproval:
		return awsLimitedEnforcementModeApprovalRequired, awsLimitedEnforcementStateApprovalRequired
	case awsAdvisoryAuthorizationOutcomeWarn:
		return awsLimitedEnforcementModeWarnOnly, awsLimitedEnforcementStateWarnOnly
	case awsAdvisoryAuthorizationOutcomeRecommendDeny:
		return awsLimitedEnforcementModeAdvisory, awsLimitedEnforcementStateAdvisoryOnly
	}
	return awsLimitedEnforcementRequestedEnforcementMode(request, safety, decision.Confidence)
}

func awsLimitedEnforcementClassifyAgentCoreAdvisory(advisory AWSAgentCoreGatewayPolicyAdvisoryEntry, safety AWSLimitedEnforcementSafetyConfig, request AWSLimitedEnforcementRequest) (string, string) {
	if safety.KillSwitchEngaged {
		return awsLimitedEnforcementModeAdvisory, awsLimitedEnforcementStateBlockedByKillSwitch
	}
	switch advisory.Outcome {
	case awsAgentCoreGatewayPolicyOutcomeBlockTools:
		return awsLimitedEnforcementModeAdvisory, awsLimitedEnforcementStateRollbackRequired
	case awsAgentCoreGatewayPolicyOutcomeRequireApproval:
		return awsLimitedEnforcementModeApprovalRequired, awsLimitedEnforcementStateApprovalRequired
	case awsAgentCoreGatewayPolicyOutcomeWarn:
		return awsLimitedEnforcementModeWarnOnly, awsLimitedEnforcementStateWarnOnly
	}
	return awsLimitedEnforcementRequestedEnforcementMode(request, safety, advisory.Confidence)
}

func awsLimitedEnforcementAgentCoreEvidenceLinks(advisory AWSAgentCoreGatewayPolicyAdvisoryEntry) []string {
	links := []string{}
	for _, evidence := range advisory.Evidence {
		if strings.TrimSpace(evidence.EvidenceRef) != "" {
			links = append(links, evidence.EvidenceRef)
		}
	}
	links = append(links, "/docs/aws-agentcore-gateway-policy-advisory")
	return dedupeStrings(links)
}

func awsLimitedEnforcementRequestedEnforcementMode(request AWSLimitedEnforcementRequest, safety AWSLimitedEnforcementSafetyConfig, confidence float64) (string, string) {
	switch strings.ToLower(strings.TrimSpace(request.Mode)) {
	case awsLimitedEnforcementModeWarnOnly:
		return awsLimitedEnforcementModeWarnOnly, awsLimitedEnforcementStateWarnOnly
	case awsLimitedEnforcementModeApprovalRequired:
		return awsLimitedEnforcementModeApprovalRequired, awsLimitedEnforcementStateApprovalRequired
	case awsLimitedEnforcementModeLimitedEnforce:
		if !safety.FeatureFlagEnabled || safety.CanaryPercent <= 0 || strings.TrimSpace(safety.Cohort) == "" || confidence < 0.8 {
			return awsLimitedEnforcementModeAdvisory, awsLimitedEnforcementStateBlockedBySafetyConfig
		}
		if safety.CanaryPercent < 100 {
			return awsLimitedEnforcementModeLimitedEnforce, awsLimitedEnforcementStateCanaryReady
		}
		return awsLimitedEnforcementModeLimitedEnforce, awsLimitedEnforcementStateLimitedEnforceReady
	}
	return awsLimitedEnforcementModeAdvisory, awsLimitedEnforcementStateAdvisoryOnly
}

func awsLimitedEnforcementGates(mode, state string, safety AWSLimitedEnforcementSafetyConfig, confidence float64, sourceKillSwitch bool, outcome string) []AWSLimitedEnforcementGate {
	requiresLimitedSafety := mode == awsLimitedEnforcementModeLimitedEnforce || state == awsLimitedEnforcementStateBlockedBySafetyConfig
	return []AWSLimitedEnforcementGate{
		{Name: "feature_flag_enabled", Status: awsLimitedEnforcementGateStatus(!requiresLimitedSafety || safety.FeatureFlagEnabled), Rationale: "Limited enforcement requires an explicit feature flag before any canary can be marked ready."},
		{Name: "kill_switch_off", Status: awsLimitedEnforcementGateStatus(!safety.KillSwitchEngaged && !sourceKillSwitch), Rationale: "Tenant and source kill switches must be off before enforcement can leave advisory mode."},
		{Name: "canary_configured", Status: awsLimitedEnforcementGateStatus(!requiresLimitedSafety || (safety.CanaryPercent > 0 && strings.TrimSpace(safety.Cohort) != "")), Rationale: "Limited enforcement requires a non-empty cohort and a canary percentage greater than zero."},
		{Name: "rollback_ready", Status: awsLimitedEnforcementGateStatus(safety.RollbackRequired), Rationale: "Every limited-enforcement entry records rollback metadata before it can be used by a downstream executor."},
		{Name: "audit_ready", Status: awsLimitedEnforcementGateStatus(safety.AuditRequired), Rationale: "Every mode transition must emit an immutable audit record."},
		{Name: "confidence_floor", Status: awsLimitedEnforcementGateStatus(!requiresLimitedSafety || confidence >= 0.8), Rationale: "Limited enforcement requires at least 80 percent confidence in the upstream advisory signal."},
		{Name: "unsafe_outcome_blocked", Status: awsLimitedEnforcementGateStatus(state != awsLimitedEnforcementStateRollbackRequired && state != awsLimitedEnforcementStateBlockedByKillSwitch), Rationale: fmt.Sprintf("Outcome %s cannot activate enforcement while rollback or kill-switch state is present.", outcome)},
	}
}

func awsLimitedEnforcementGateStatus(passed bool) string {
	if passed {
		return "passed"
	}
	return "failed"
}

func awsLimitedEnforcementHasFailedGate(gates []AWSLimitedEnforcementGate) bool {
	for _, gate := range gates {
		if gate.Status == "failed" {
			return true
		}
	}
	return false
}

func awsLimitedEnforcementGatePassed(gates []AWSLimitedEnforcementGate, name string) bool {
	for _, gate := range gates {
		if gate.Name == name && gate.Status == "passed" {
			return true
		}
	}
	return false
}

func awsLimitedEnforcementRollback(sourceType, evidenceRef, state string) AWSLimitedEnforcementRollback {
	rollbackState := "available"
	if state == awsLimitedEnforcementStateAdvisoryOnly || state == awsLimitedEnforcementStateWarnOnly {
		rollbackState = "not_required"
	}
	return AWSLimitedEnforcementRollback{
		Strategy:    "disable_limited_enforcement_and_revert_to_advisory",
		Steps:       []string{"Engage the tenant kill switch or set the feature flag off.", "Return the affected cohort to advisory mode.", "Refresh advisory authorization and AgentCore gateway policy evidence before re-enabling any canary."},
		EvidenceRef: evidenceRef,
		State:       rollbackState,
		Rationale:   fmt.Sprintf("Rollback is metadata-only for %s; downstream executors must use the audit row and safety config before any live control change.", sourceType),
	}
}

func awsLimitedEnforcementAuditTrail(enforcementID, sourceID, mode, state string, now time.Time) []AWSLimitedEnforcementAuditEntry {
	return []AWSLimitedEnforcementAuditEntry{{
		EventID:    stableAWSBlastRadiusToken("limited-enforcement-projected", enforcementID, sourceID, mode, state),
		Actor:      "identrail-limited-enforcement-framework",
		EventType:  "limited_enforcement_projected",
		OccurredAt: now,
		Notes:      fmt.Sprintf("Source=%s mode=%s state=%s policy_version=%s; Identrail did not call any AWS write API at this layer.", sourceID, mode, state, awsLimitedEnforcementPolicyID),
	}}
}

func awsLimitedEnforcementNextAction(mode, state string) string {
	switch state {
	case awsLimitedEnforcementStateBlockedByKillSwitch:
		return "Keep enforcement disabled until the kill switch is cleared and advisory evidence is refreshed."
	case awsLimitedEnforcementStateBlockedBySafetyConfig:
		return "Provide explicit feature flag, cohort, canary percentage, confidence, rollback, and audit config before limited enforcement can activate."
	case awsLimitedEnforcementStateRollbackRequired:
		return "Keep this entry out of enforcement and follow rollback or quarantine guidance from the upstream advisory."
	case awsLimitedEnforcementStateCanaryReady:
		return "Canary configuration is ready for a downstream executor; monitor the cohort before expanding rollout."
	case awsLimitedEnforcementStateLimitedEnforceReady:
		return "Safety gates are ready for limited enforcement; downstream executors still own any live control change."
	case awsLimitedEnforcementStateApprovalRequired:
		return "Advance operator approval before moving this decision beyond advisory governance."
	case awsLimitedEnforcementStateWarnOnly:
		return "Keep warn-only behavior and refresh evidence if runtime or remediation state changes."
	}
	if mode == awsLimitedEnforcementModeAdvisory {
		return "Keep advisory mode until operators explicitly configure a canary and feature flag."
	}
	return "Inspect the limited-enforcement entry for the next action."
}

func awsLimitedEnforcementRelationships(entries []AWSLimitedEnforcementEntry) []AWSLimitedEnforcementRelationship {
	relationships := []AWSLimitedEnforcementRelationship{}
	for _, entry := range entries {
		source := strings.TrimSpace(entry.SourceID)
		if source != "" {
			relationships = append(relationships, AWSLimitedEnforcementRelationship{
				EnforcementID: entry.EnforcementID,
				Type:          "derives_from_source",
				FromNodeID:    entry.EnforcementID,
				ToNodeID:      source,
				EvidenceRef:   firstString(entry.EvidenceLinks),
			})
		}
		if principal := strings.TrimSpace(entry.PrincipalNodeID); principal != "" {
			relationships = append(relationships, AWSLimitedEnforcementRelationship{
				EnforcementID: entry.EnforcementID,
				Type:          "governs_principal",
				FromNodeID:    entry.EnforcementID,
				ToNodeID:      principal,
				EvidenceRef:   firstString(entry.EvidenceLinks),
			})
		}
		for _, target := range entry.TargetScope {
			if strings.TrimSpace(target) == "" || strings.EqualFold(target, entry.PrincipalNodeID) {
				continue
			}
			relationships = append(relationships, AWSLimitedEnforcementRelationship{
				EnforcementID: entry.EnforcementID,
				Type:          "scopes_target",
				FromNodeID:    entry.EnforcementID,
				ToNodeID:      target,
				EvidenceRef:   firstString(entry.EvidenceLinks),
			})
		}
	}
	return relationships
}

func summarizeAWSLimitedEnforcementEntries(all, filtered []AWSLimitedEnforcementEntry, relationships []AWSLimitedEnforcementRelationship) AWSLimitedEnforcementSummary {
	summary := AWSLimitedEnforcementSummary{
		TotalEntries:           len(all),
		FilteredEntries:        len(filtered),
		ModeCounts:             map[string]int{},
		EnforcementStateCounts: map[string]int{},
		OutcomeCounts:          map[string]int{},
		SourceTypeCounts:       map[string]int{},
	}
	confidenceTotal := 0.0
	for _, entry := range filtered {
		summary.ModeCounts[entry.Mode]++
		summary.EnforcementStateCounts[entry.EnforcementState]++
		summary.OutcomeCounts[entry.Outcome]++
		summary.SourceTypeCounts[entry.SourceType]++
		switch entry.Mode {
		case awsLimitedEnforcementModeWarnOnly:
			summary.WarnOnlyCount++
		case awsLimitedEnforcementModeAdvisory:
			summary.AdvisoryCount++
		case awsLimitedEnforcementModeApprovalRequired:
			summary.ApprovalRequiredCount++
		case awsLimitedEnforcementModeLimitedEnforce:
			summary.LimitedEnforceCount++
		}
		if entry.ReadyForCanary {
			summary.CanaryReadyCount++
		}
		if entry.ReadyForEnforcement {
			summary.ReadyForEnforcementCount++
		}
		if entry.SafetyConfig.KillSwitchEngaged || entry.EnforcementState == awsLimitedEnforcementStateBlockedByKillSwitch {
			summary.KillSwitchEngagedCount++
		}
		for _, gate := range entry.Gates {
			if gate.Status == "failed" {
				summary.FailedGateCount++
			}
		}
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

func filterAWSLimitedEnforcementEntries(entries []AWSLimitedEnforcementEntry, request AWSLimitedEnforcementRequest) ([]AWSLimitedEnforcementEntry, map[string]string) {
	filters := map[string]string{
		"account_id":        strings.TrimSpace(request.AccountID),
		"region":            strings.TrimSpace(request.Region),
		"mode":              normalizeAWSRuntimeEventFilterToken(request.Mode),
		"enforcement_state": normalizeAWSRuntimeEventFilterToken(request.EnforcementState),
		"decision_id":       strings.TrimSpace(request.DecisionID),
		"source_type":       normalizeAWSRuntimeEventFilterToken(request.SourceType),
		"outcome":           normalizeAWSRuntimeEventFilterToken(request.Outcome),
		"cohort":            strings.TrimSpace(request.Cohort),
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
	filtered := make([]AWSLimitedEnforcementEntry, 0, len(entries))
	for _, entry := range entries {
		if filters["account_id"] != "" && !awsLimitedEnforcementAccountMatch(entry, filters["account_id"]) {
			continue
		}
		if filters["region"] != "" && !strings.EqualFold(filters["region"], entry.Region) {
			continue
		}
		if filters["mode"] != "" && !awsLimitedEnforcementModeFilterMatch(entry, filters["mode"]) {
			continue
		}
		if filters["enforcement_state"] != "" && filters["enforcement_state"] != normalizeAWSRuntimeEventFilterToken(entry.EnforcementState) {
			continue
		}
		if filters["decision_id"] != "" && !strings.EqualFold(filters["decision_id"], entry.SourceID) && !strings.EqualFold(filters["decision_id"], entry.EnforcementID) {
			continue
		}
		if filters["source_type"] != "" && filters["source_type"] != normalizeAWSRuntimeEventFilterToken(entry.SourceType) {
			continue
		}
		if filters["outcome"] != "" && filters["outcome"] != normalizeAWSRuntimeEventFilterToken(entry.Outcome) {
			continue
		}
		if filters["cohort"] != "" && !strings.EqualFold(filters["cohort"], entry.SafetyConfig.Cohort) {
			continue
		}
		if filters["search"] != "" && !awsLimitedEnforcementSearchMatch(entry, filters["search"]) {
			continue
		}
		filtered = append(filtered, entry)
	}
	return filtered, applied
}

func awsLimitedEnforcementModeFilterMatch(entry AWSLimitedEnforcementEntry, mode string) bool {
	if mode == normalizeAWSRuntimeEventFilterToken(entry.Mode) {
		return true
	}
	if mode != normalizeAWSRuntimeEventFilterToken(awsLimitedEnforcementModeLimitedEnforce) {
		return false
	}
	switch normalizeAWSRuntimeEventFilterToken(entry.EnforcementState) {
	case normalizeAWSRuntimeEventFilterToken(awsLimitedEnforcementStateBlockedBySafetyConfig),
		normalizeAWSRuntimeEventFilterToken(awsLimitedEnforcementStateBlockedByKillSwitch),
		normalizeAWSRuntimeEventFilterToken(awsLimitedEnforcementStateRollbackRequired):
		return true
	default:
		return false
	}
}

func awsLimitedEnforcementAccountMatch(entry AWSLimitedEnforcementEntry, accountID string) bool {
	if strings.EqualFold(strings.TrimSpace(entry.AccountID), strings.TrimSpace(accountID)) {
		return true
	}
	for _, target := range entry.TargetAccountIDs {
		if strings.EqualFold(strings.TrimSpace(target), strings.TrimSpace(accountID)) {
			return true
		}
	}
	return false
}

func awsLimitedEnforcementSearchMatch(entry AWSLimitedEnforcementEntry, needle string) bool {
	needle = strings.ToLower(strings.TrimSpace(needle))
	if needle == "" {
		return true
	}
	values := []string{
		entry.EnforcementID, entry.SourceID, entry.SourceType, entry.Mode, entry.EnforcementState,
		entry.Outcome, entry.Severity, entry.Title, entry.Summary, entry.PrincipalNodeID, entry.Action,
		entry.SafetyConfig.Cohort, entry.Rollback.Strategy, entry.Rollback.State, entry.NextAction, entry.InputHash,
	}
	values = append(values, entry.TargetScope...)
	values = append(values, entry.TargetAccountIDs...)
	values = append(values, entry.EvidenceLinks...)
	for _, gate := range entry.Gates {
		values = append(values, gate.Name, gate.Status, gate.Rationale)
	}
	for _, evidence := range entry.Evidence {
		values = append(values, evidence.Source, evidence.Label, evidence.EvidenceRef)
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

func summarizeAWSLimitedEnforcementStatus(advisoryStatus, agentcoreStatus string, filtered []AWSLimitedEnforcementEntry, diagnostics []AWSLimitedEnforcementDiagnostic) (string, float64) {
	if advisoryStatus == awsPlatformDependencyStatusBlocked || agentcoreStatus == awsPlatformDependencyStatusBlocked {
		return awsPlatformDependencyStatusBlocked, 0.35
	}
	for _, diagnostic := range diagnostics {
		if diagnostic.Retryable {
			return awsPlatformDependencyStatusDegraded, 0.72
		}
	}
	if advisoryStatus == awsPlatformDependencyStatusDegraded || agentcoreStatus == awsPlatformDependencyStatusDegraded {
		return awsPlatformDependencyStatusDegraded, 0.74
	}
	if len(filtered) == 0 {
		return awsPlatformDependencyStatusReady, 0.82
	}
	return awsPlatformDependencyStatusReady, 0.9
}

func awsLimitedEnforcementDiagnostics(advisory []AWSAdvisoryAuthorizationDiagnostic, agentcore []AWSAgentCoreGatewayPolicyAdvisoryDiagnostic) []AWSLimitedEnforcementDiagnostic {
	out := []AWSLimitedEnforcementDiagnostic{}
	for _, diagnostic := range advisory {
		out = append(out, AWSLimitedEnforcementDiagnostic(diagnostic))
	}
	for _, diagnostic := range agentcore {
		out = append(out, AWSLimitedEnforcementDiagnostic(diagnostic))
	}
	return out
}

func awsLimitedEnforcementCoverageGaps(advisory []AWSAdvisoryAuthorizationCoverageGap, agentcore []AWSAgentCoreGatewayPolicyAdvisoryCoverageGap) []AWSLimitedEnforcementCoverageGap {
	out := []AWSLimitedEnforcementCoverageGap{}
	for _, gap := range advisory {
		out = append(out, AWSLimitedEnforcementCoverageGap(gap))
	}
	for _, gap := range agentcore {
		out = append(out, AWSLimitedEnforcementCoverageGap(gap))
	}
	return out
}

func awsLimitedEnforcementCaveats() []string {
	return []string{
		"Limited enforcement framework entries are read-only projections; Identrail does not call AWS write APIs at this layer.",
		"Limited enforcement requires explicit feature flag, cohort, canary percentage, rollback, audit, confidence, and kill-switch gates before it can be marked ready.",
		"Warn-only, advisory, approval-required, and limited-enforce modes are represented as explicit states so unsupported or blocked paths cannot appear successful.",
	}
}

func awsLimitedEnforcementRemediationHints(source []string) []string {
	hints := []string{
		"Start in warn_only or advisory mode, then enable a narrow cohort and canary only after upstream advisory and AgentCore evidence is current.",
		"Use the tenant kill switch to return all entries to advisory-only behavior before troubleshooting failed verification or rollback signals.",
		"Log the policy version, input hash, cohort, canary percentage, and source decision for every downstream enforcement transition.",
	}
	hints = append(hints, source...)
	return dedupeStrings(hints)
}

func awsLimitedEnforcementEvidenceBoundary() string {
	return "metadata_only_no_rendered_policy_bodies_no_secret_values_no_workload_payloads_tenant_workspace_project_connector_account_region_scoped"
}
