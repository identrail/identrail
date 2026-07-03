package api

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	awsLimitedEnforcementPilotCurrentIssue = 1547
	awsLimitedEnforcementPilotVersion      = "aws-limited-enforcement-pilot-v1"
	awsLimitedEnforcementPilotPolicyID     = "aws-limited-enforcement-pilot-policy-v1"
	awsLimitedEnforcementPilotModePilot    = "pilot"

	// awsLimitedEnforcementPilotConfidenceFloor is intentionally stricter
	// than the framework's 0.8 gate: the pilot admits high-confidence
	// signals only.
	awsLimitedEnforcementPilotConfidenceFloor = 0.9
	// awsLimitedEnforcementPilotMaxCanaryPercent caps pilot rollout to a
	// narrow cohort; broader rollout belongs to a later wave.
	awsLimitedEnforcementPilotMaxCanaryPercent = 25

	awsLimitedEnforcementPilotStateCanaryReady  = "pilot_canary_ready"
	awsLimitedEnforcementPilotStateEnforceReady = "pilot_enforce_ready"
	awsLimitedEnforcementPilotStateIneligible   = "ineligible"
	awsLimitedEnforcementPilotStateOverrideHold = "override_hold"
	awsLimitedEnforcementPilotStateKillSwitched = "blocked_by_kill_switch"
)

// AWSLimitedEnforcementPilotRequest scopes the high-confidence enforcement
// pilot to one AWS connector. The safety config (feature flag, kill switch,
// cohort, canary percent) is forwarded to the limited-enforcement framework
// so the pilot evaluates the same explicit configuration; the operator
// override is a pilot-level control that holds every decision.
type AWSLimitedEnforcementPilotRequest struct {
	ConnectorID      string `json:"connector_id,omitempty"`
	FixtureState     string `json:"fixture_state,omitempty"`
	AccountID        string `json:"account_id,omitempty"`
	Region           string `json:"region,omitempty"`
	Cohort           string `json:"cohort,omitempty"`
	FeatureFlag      string `json:"feature_flag,omitempty"`
	KillSwitch       string `json:"kill_switch,omitempty"`
	CanaryPercent    int    `json:"canary_percent,omitempty"`
	OperatorOverride string `json:"operator_override,omitempty"`
	PilotState       string `json:"pilot_state,omitempty"`
	SourceType       string `json:"source_type,omitempty"`
	Outcome          string `json:"outcome,omitempty"`
	EnforcementID    string `json:"enforcement_id,omitempty"`
	Severity         string `json:"severity,omitempty"`
	Search           string `json:"search,omitempty"`
}

type AWSLimitedEnforcementPilotAuditEntry = AWSRemediationApprovalAuditEntry
type AWSLimitedEnforcementPilotCoverageGap = AWSRemediationApprovalCoverageGap
type AWSLimitedEnforcementPilotDiagnostic = AWSRemediationApprovalDiagnostic

// AWSLimitedEnforcementPilotEligibilityRule is one deterministic rule the
// pilot evaluates before a framework entry can enter the pilot cohort.
type AWSLimitedEnforcementPilotEligibilityRule struct {
	Name      string `json:"name"`
	Status    string `json:"status"`
	Rationale string `json:"rationale"`
}

// AWSLimitedEnforcementPilotRollbackThresholds is the deterministic rollback
// contract every pilot decision carries. A downstream executor must
// auto-rollback the canary when any threshold trips.
type AWSLimitedEnforcementPilotRollbackThresholds struct {
	MaxDenialRegressionPct int    `json:"max_denial_regression_pct"`
	ObservationWindow      string `json:"observation_window"`
	AutoRollbackOnKill     bool   `json:"auto_rollback_on_kill_switch"`
	OperatorOverrideHalts  bool   `json:"operator_override_halts_pilot"`
}

// AWSLimitedEnforcementPilotMetrics records deterministic per-decision
// counters operators use to audit each pilot evaluation. Counts are
// metadata only; no runtime payloads are collected.
type AWSLimitedEnforcementPilotMetrics struct {
	EligibilityRulesPassed int `json:"eligibility_rules_passed"`
	EligibilityRulesTotal  int `json:"eligibility_rules_total"`
	FrameworkGatesPassed   int `json:"framework_gates_passed"`
	FrameworkGatesTotal    int `json:"framework_gates_total"`
	ConfidencePct          int `json:"confidence_pct"`
	CanaryPercent          int `json:"canary_percent"`
}

// AWSLimitedEnforcementPilotRelationship surfaces pilot→graph node edges.
type AWSLimitedEnforcementPilotRelationship struct {
	PilotID     string `json:"pilot_id"`
	Type        string `json:"type"`
	FromNodeID  string `json:"from_node_id"`
	ToNodeID    string `json:"to_node_id"`
	EvidenceRef string `json:"evidence_ref,omitempty"`
}

// AWSLimitedEnforcementPilotDecision is the persisted-record-shaped contract
// for one pilot evaluation over a limited-enforcement framework entry. It is
// metadata-only; the pilot never calls AWS write APIs and downstream
// executors own any live control change.
type AWSLimitedEnforcementPilotDecision struct {
	PilotID            string                                       `json:"pilot_id"`
	CalculationVersion string                                       `json:"calculation_version"`
	PolicyVersion      string                                       `json:"policy_version"`
	Mode               string                                       `json:"mode"`
	PilotState         string                                       `json:"pilot_state"`
	Eligible           bool                                         `json:"eligible"`
	EnforcementID      string                                       `json:"enforcement_id"`
	SourceType         string                                       `json:"source_type"`
	SourceID           string                                       `json:"source_id"`
	Outcome            string                                       `json:"outcome"`
	Confidence         float64                                      `json:"confidence"`
	Severity           string                                       `json:"severity"`
	Score              int                                          `json:"score"`
	Title              string                                       `json:"title"`
	Summary            string                                       `json:"summary"`
	Rationale          string                                       `json:"rationale"`
	AccountID          string                                       `json:"account_id,omitempty"`
	TargetAccountIDs   []string                                     `json:"target_account_ids,omitempty"`
	Region             string                                       `json:"region,omitempty"`
	PrincipalNodeID    string                                       `json:"principal_node_id,omitempty"`
	Action             string                                       `json:"action,omitempty"`
	Cohort             string                                       `json:"cohort,omitempty"`
	OperatorOverride   string                                       `json:"operator_override,omitempty"`
	EligibilityRules   []AWSLimitedEnforcementPilotEligibilityRule  `json:"eligibility_rules"`
	RollbackThresholds AWSLimitedEnforcementPilotRollbackThresholds `json:"rollback_thresholds"`
	Metrics            AWSLimitedEnforcementPilotMetrics            `json:"metrics"`
	EvidenceLinks      []string                                     `json:"evidence_links"`
	EvidenceBoundary   string                                       `json:"evidence_boundary"`
	InputHash          string                                       `json:"input_hash"`
	AuditTrail         []AWSLimitedEnforcementPilotAuditEntry       `json:"audit_trail"`
	ReadOnlyProjection bool                                         `json:"read_only_projection"`
	NextAction         string                                       `json:"next_action"`
	ProjectedAt        time.Time                                    `json:"projected_at"`
	UpdatedAt          time.Time                                    `json:"updated_at"`
}

// AWSLimitedEnforcementPilotSummary aggregates the unfiltered/filtered set.
type AWSLimitedEnforcementPilotSummary struct {
	TotalDecisions         int            `json:"total_decisions"`
	FilteredDecisions      int            `json:"filtered_decisions"`
	PilotStateCounts       map[string]int `json:"pilot_state_counts"`
	OutcomeCounts          map[string]int `json:"outcome_counts"`
	SourceTypeCounts       map[string]int `json:"source_type_counts"`
	SeverityCounts         map[string]int `json:"severity_counts"`
	EligibleCount          int            `json:"eligible_count"`
	IneligibleCount        int            `json:"ineligible_count"`
	CanaryReadyCount       int            `json:"canary_ready_count"`
	EnforceReadyCount      int            `json:"enforce_ready_count"`
	OverrideHoldCount      int            `json:"override_hold_count"`
	KillSwitchEngagedCount int            `json:"kill_switch_engaged_count"`
	FailedRuleCount        int            `json:"failed_rule_count"`
	RelationshipCount      int            `json:"relationship_count"`
	HighestScore           int            `json:"highest_score"`
	AverageConfidencePct   int            `json:"average_confidence_pct"`
}

// AWSLimitedEnforcementPilotResult is the deterministic endpoint envelope.
type AWSLimitedEnforcementPilotResult struct {
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
	OperatorOverride   string                                       `json:"operator_override,omitempty"`
	SafetyConfig       AWSLimitedEnforcementSafetyConfig            `json:"safety_config"`
	RollbackThresholds AWSLimitedEnforcementPilotRollbackThresholds `json:"rollback_thresholds"`
	AppliedFilters     map[string]string                            `json:"applied_filters"`
	Summary            AWSLimitedEnforcementPilotSummary            `json:"summary"`
	Decisions          []AWSLimitedEnforcementPilotDecision         `json:"decisions"`
	Relationships      []AWSLimitedEnforcementPilotRelationship     `json:"relationships"`
	Caveats            []string                                     `json:"caveats"`
	FailureReasons     []string                                     `json:"failure_reasons"`
	RemediationHints   []string                                     `json:"remediation_hints"`
	EvidenceLinks      []string                                     `json:"evidence_links"`
	CoverageGaps       []AWSLimitedEnforcementPilotCoverageGap      `json:"coverage_gaps"`
	Diagnostics        []AWSLimitedEnforcementPilotDiagnostic       `json:"diagnostics"`
	GeneratedAt        time.Time                                    `json:"generated_at"`
	UpdatedAt          time.Time                                    `json:"updated_at"`
}

// GetAWSLimitedEnforcementPilot projects the high-confidence enforcement
// pilot over the limited-enforcement framework (#1546). Only framework
// entries that pass every pilot eligibility rule (limited-enforce mode,
// confidence >= 0.9, all framework gates passed, canary within the pilot
// cap, kill switch off, no operator override) are marked pilot-ready. The
// endpoint is metadata-only: it records eligibility, canary criteria,
// rollback thresholds, override state, metrics, and audit rows but never
// calls AWS write APIs.
func (s *Service) GetAWSLimitedEnforcementPilot(ctx context.Context, workspaceID string, projectID string, request AWSLimitedEnforcementPilotRequest) (AWSLimitedEnforcementPilotResult, error) {
	project, scope, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return AWSLimitedEnforcementPilotResult{}, err
	}
	connection, hasConnection, err := s.awsBaselineConnection(ctx, project, strings.TrimSpace(request.ConnectorID))
	if err != nil {
		return AWSLimitedEnforcementPilotResult{}, err
	}
	now := s.Now().UTC()
	fixtureState := normalizeAWSLimitedEnforcementPilotFixtureState(request.FixtureState, connection, hasConnection)
	if fixtureState == "" {
		return AWSLimitedEnforcementPilotResult{}, ErrInvalidAWSConnectionRequest
	}
	override := normalizeAWSLimitedEnforcementPilotOverride(request.OperatorOverride)
	if override == "" && strings.TrimSpace(request.OperatorOverride) != "" {
		return AWSLimitedEnforcementPilotResult{}, ErrInvalidAWSConnectionRequest
	}

	accountID := firstNonEmptyAWSValue(connection.AccountID, strings.TrimSpace(request.AccountID), "123456789012")
	region := firstNonEmptyAWSValue(connection.Region, strings.TrimSpace(request.Region), "us-east-1")
	connectorID := firstNonEmptyAWSValue(connection.ConnectorID, strings.TrimSpace(request.ConnectorID))
	sourceFixtureState := fixtureState
	if strings.TrimSpace(request.FixtureState) == "" && hasConnection && connection.Connected {
		sourceFixtureState = ""
	}

	// The pilot always asks the framework for limited-enforce mode so it
	// evaluates exactly what a downstream executor would see when the
	// operator's explicit safety config is applied.
	framework, err := s.GetAWSLimitedEnforcement(ctx, workspaceID, projectID, AWSLimitedEnforcementRequest{
		ConnectorID:   connectorID,
		FixtureState:  sourceFixtureState,
		Mode:          awsLimitedEnforcementModeLimitedEnforce,
		Cohort:        strings.TrimSpace(request.Cohort),
		FeatureFlag:   request.FeatureFlag,
		KillSwitch:    request.KillSwitch,
		CanaryPercent: request.CanaryPercent,
	})
	if err != nil {
		return AWSLimitedEnforcementPilotResult{}, fmt.Errorf("limited enforcement pilot framework: %w", err)
	}

	thresholds := awsLimitedEnforcementPilotRollbackThresholds()
	decisions := awsLimitedEnforcementPilotDecisions(framework.Entries, framework.SafetyConfig, thresholds, override, now)
	sort.SliceStable(decisions, func(i, j int) bool {
		if decisions[i].Score == decisions[j].Score {
			return decisions[i].PilotID < decisions[j].PilotID
		}
		return decisions[i].Score > decisions[j].Score
	})
	filtered, applied := filterAWSLimitedEnforcementPilotDecisions(decisions, request)
	relationships := awsLimitedEnforcementPilotRelationships(filtered)
	diagnostics := awsLimitedEnforcementPilotDiagnostics(framework.Diagnostics)
	status, confidence := summarizeAWSLimitedEnforcementPilotStatus(framework.Status, filtered, diagnostics)

	return AWSLimitedEnforcementPilotResult{
		TenantID:           scope.TenantID,
		WorkspaceID:        project.WorkspaceID,
		ProjectID:          project.ProjectID,
		ConnectorID:        connectorID,
		AccountID:          accountID,
		Region:             region,
		ParentIssueNumber:  awsPlatformDependencyParentIssue,
		ParentIssueRef:     awsIssueRef(awsPlatformDependencyParentIssue),
		CurrentIssueNumber: awsLimitedEnforcementPilotCurrentIssue,
		CurrentIssueRef:    awsIssueRef(awsLimitedEnforcementPilotCurrentIssue),
		Version:            awsLimitedEnforcementPilotVersion,
		Status:             status,
		FixtureState:       sourceFixtureState,
		Confidence:         confidence,
		CalculationVersion: awsLimitedEnforcementPilotVersion,
		PolicyVersion:      awsLimitedEnforcementPilotPolicyID,
		Mode:               awsLimitedEnforcementPilotModePilot,
		OperatorOverride:   override,
		SafetyConfig:       framework.SafetyConfig,
		RollbackThresholds: thresholds,
		AppliedFilters:     applied,
		Summary:            summarizeAWSLimitedEnforcementPilotDecisions(decisions, filtered, relationships),
		Decisions:          filtered,
		Relationships:      relationships,
		Caveats:            awsLimitedEnforcementPilotCaveats(),
		FailureReasons:     dedupeStrings(framework.FailureReasons),
		RemediationHints:   awsLimitedEnforcementPilotRemediationHints(framework.RemediationHints),
		EvidenceLinks: dedupeStrings([]string{
			awsIssueURL(awsPlatformDependencyParentIssue),
			awsIssueURL(awsLimitedEnforcementPilotCurrentIssue),
			awsIssueURL(awsLimitedEnforcementCurrentIssue),
			"/docs/aws-limited-enforcement-pilot",
			"/docs/aws-limited-enforcement",
			awsBaselineProjectEvidenceURL(scope, project),
		}),
		CoverageGaps: awsLimitedEnforcementPilotCoverageGaps(framework.CoverageGaps),
		Diagnostics:  diagnostics,
		GeneratedAt:  now,
		UpdatedAt:    now,
	}, nil
}

func normalizeAWSLimitedEnforcementPilotFixtureState(requested string, connection AWSConnectionStatus, hasConnection bool) string {
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

// normalizeAWSLimitedEnforcementPilotOverride validates the operator
// override control. `hold` pauses every pilot decision; `resume` (or empty)
// lets eligibility drive the state. Unknown values are rejected by the
// caller so a typo can never silently resume a held pilot.
func normalizeAWSLimitedEnforcementPilotOverride(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "":
		return "resume"
	case "hold", "pause":
		return "hold"
	case "resume":
		return "resume"
	default:
		return ""
	}
}

func awsLimitedEnforcementPilotRollbackThresholds() AWSLimitedEnforcementPilotRollbackThresholds {
	return AWSLimitedEnforcementPilotRollbackThresholds{
		MaxDenialRegressionPct: 1,
		ObservationWindow:      "24h",
		AutoRollbackOnKill:     true,
		OperatorOverrideHalts:  true,
	}
}

func awsLimitedEnforcementPilotDecisions(entries []AWSLimitedEnforcementEntry, safety AWSLimitedEnforcementSafetyConfig, thresholds AWSLimitedEnforcementPilotRollbackThresholds, override string, now time.Time) []AWSLimitedEnforcementPilotDecision {
	decisions := make([]AWSLimitedEnforcementPilotDecision, 0, len(entries))
	for _, entry := range entries {
		decisions = append(decisions, awsLimitedEnforcementPilotDecisionFromEntry(entry, safety, thresholds, override, now))
	}
	return decisions
}

func awsLimitedEnforcementPilotDecisionFromEntry(entry AWSLimitedEnforcementEntry, safety AWSLimitedEnforcementSafetyConfig, thresholds AWSLimitedEnforcementPilotRollbackThresholds, override string, now time.Time) AWSLimitedEnforcementPilotDecision {
	rules := awsLimitedEnforcementPilotEligibilityRules(entry, safety, override)
	state, eligible, rationale := awsLimitedEnforcementPilotState(entry, safety, override, rules)
	pilotID := "aws-limited-enforcement-pilot:" + stableAWSBlastRadiusToken("pilot", entry.EnforcementID, state, override)
	passed := 0
	for _, rule := range rules {
		if rule.Status == "passed" {
			passed++
		}
	}
	gatesPassed := 0
	for _, gate := range entry.Gates {
		if gate.Status == "passed" {
			gatesPassed++
		}
	}
	return AWSLimitedEnforcementPilotDecision{
		PilotID:            pilotID,
		CalculationVersion: awsLimitedEnforcementPilotVersion,
		PolicyVersion:      awsLimitedEnforcementPilotPolicyID,
		Mode:               awsLimitedEnforcementPilotModePilot,
		PilotState:         state,
		Eligible:           eligible,
		EnforcementID:      entry.EnforcementID,
		SourceType:         entry.SourceType,
		SourceID:           entry.SourceID,
		Outcome:            entry.Outcome,
		Confidence:         entry.Confidence,
		Severity:           entry.Severity,
		Score:              entry.Score,
		Title:              fmt.Sprintf("Enforcement pilot: %s", strings.TrimPrefix(entry.Title, "Limited enforcement framework: ")),
		Summary:            fmt.Sprintf("High-confidence enforcement pilot evaluation for framework entry %s (state=%s). Identrail records eligibility, canary criteria, rollback thresholds, override state, metrics, and audit only; no live AWS write API is called.", entry.EnforcementID, state),
		Rationale:          rationale,
		AccountID:          entry.AccountID,
		TargetAccountIDs:   entry.TargetAccountIDs,
		Region:             entry.Region,
		PrincipalNodeID:    entry.PrincipalNodeID,
		Action:             entry.Action,
		Cohort:             safety.Cohort,
		OperatorOverride:   override,
		EligibilityRules:   rules,
		RollbackThresholds: thresholds,
		Metrics: AWSLimitedEnforcementPilotMetrics{
			EligibilityRulesPassed: passed,
			EligibilityRulesTotal:  len(rules),
			FrameworkGatesPassed:   gatesPassed,
			FrameworkGatesTotal:    len(entry.Gates),
			ConfidencePct:          int(entry.Confidence*100 + 0.5),
			CanaryPercent:          safety.CanaryPercent,
		},
		EvidenceLinks:      dedupeStrings(append(append([]string{}, entry.EvidenceLinks...), "/docs/aws-limited-enforcement-pilot")),
		EvidenceBoundary:   awsLimitedEnforcementPilotEvidenceBoundary(),
		InputHash:          stableAWSBlastRadiusToken("limited-enforcement-pilot-input", entry.InputHash, state, override, fmt.Sprint(safety.CanaryPercent), safety.Cohort, awsLimitedEnforcementPilotPolicyID),
		AuditTrail:         awsLimitedEnforcementPilotAuditTrail(pilotID, entry.EnforcementID, state, override, now),
		ReadOnlyProjection: true,
		NextAction:         awsLimitedEnforcementPilotNextAction(state),
		ProjectedAt:        now,
		UpdatedAt:          now,
	}
}

// awsLimitedEnforcementPilotEligibilityRules is the deterministic rule set
// every framework entry is evaluated against before it can enter the pilot.
func awsLimitedEnforcementPilotEligibilityRules(entry AWSLimitedEnforcementEntry, safety AWSLimitedEnforcementSafetyConfig, override string) []AWSLimitedEnforcementPilotEligibilityRule {
	return []AWSLimitedEnforcementPilotEligibilityRule{
		{Name: "limited_enforce_mode", Status: awsLimitedEnforcementGateStatus(entry.Mode == awsLimitedEnforcementModeLimitedEnforce), Rationale: "Only framework entries that reached limited-enforce mode with explicit safety config can enter the pilot."},
		{Name: "high_confidence", Status: awsLimitedEnforcementGateStatus(entry.Confidence >= awsLimitedEnforcementPilotConfidenceFloor), Rationale: fmt.Sprintf("Pilot admits high-confidence signals only (>= %d percent).", int(awsLimitedEnforcementPilotConfidenceFloor*100))},
		{Name: "framework_gates_passed", Status: awsLimitedEnforcementGateStatus(!awsLimitedEnforcementHasFailedGate(entry.Gates)), Rationale: "Every limited-enforcement framework gate must pass before the pilot evaluates the entry."},
		{Name: "canary_within_pilot_cap", Status: awsLimitedEnforcementGateStatus(safety.CanaryPercent > 0 && safety.CanaryPercent <= awsLimitedEnforcementPilotMaxCanaryPercent), Rationale: fmt.Sprintf("Pilot canaries are capped at %d percent of the cohort; broader rollout belongs to a later wave.", awsLimitedEnforcementPilotMaxCanaryPercent)},
		{Name: "kill_switch_off", Status: awsLimitedEnforcementGateStatus(!safety.KillSwitchEngaged && entry.EnforcementState != awsLimitedEnforcementStateBlockedByKillSwitch), Rationale: "The tenant kill switch immediately removes every entry from the pilot."},
		{Name: "operator_override_clear", Status: awsLimitedEnforcementGateStatus(override != "hold"), Rationale: "An operator hold pauses every pilot decision until explicitly resumed."},
	}
}

// awsLimitedEnforcementPilotState orders safety controls above eligibility:
// kill switch, then operator hold, then the rule set. Eligible entries map
// to the framework's canary/enforce readiness.
func awsLimitedEnforcementPilotState(entry AWSLimitedEnforcementEntry, safety AWSLimitedEnforcementSafetyConfig, override string, rules []AWSLimitedEnforcementPilotEligibilityRule) (string, bool, string) {
	if safety.KillSwitchEngaged || entry.EnforcementState == awsLimitedEnforcementStateBlockedByKillSwitch {
		return awsLimitedEnforcementPilotStateKillSwitched, false, "Tenant kill switch is engaged; the pilot holds every decision until it is cleared."
	}
	if override == "hold" {
		return awsLimitedEnforcementPilotStateOverrideHold, false, "Operator override is holding the pilot; resume explicitly after reviewing canary metrics."
	}
	for _, rule := range rules {
		if rule.Status != "passed" {
			return awsLimitedEnforcementPilotStateIneligible, false, fmt.Sprintf("Entry failed pilot eligibility rule %q: %s", rule.Name, rule.Rationale)
		}
	}
	if entry.EnforcementState == awsLimitedEnforcementStateLimitedEnforceReady {
		return awsLimitedEnforcementPilotStateEnforceReady, true, "Every eligibility rule passed and the framework entry is limited-enforce ready within the pilot canary cap."
	}
	return awsLimitedEnforcementPilotStateCanaryReady, true, "Every eligibility rule passed; the entry is enrolled in the pilot canary cohort."
}

func awsLimitedEnforcementPilotNextAction(state string) string {
	switch state {
	case awsLimitedEnforcementPilotStateCanaryReady:
		return "Pilot canary is ready for a downstream executor; watch denial-regression metrics against the rollback thresholds before expanding."
	case awsLimitedEnforcementPilotStateEnforceReady:
		return "Pilot decision is enforce-ready within the canary cap; downstream executors still own any live control change."
	case awsLimitedEnforcementPilotStateIneligible:
		return "Resolve the failed eligibility rule before re-evaluating this entry for the pilot."
	case awsLimitedEnforcementPilotStateOverrideHold:
		return "Operator hold is active; resume the pilot explicitly after reviewing canary metrics and rollback thresholds."
	case awsLimitedEnforcementPilotStateKillSwitched:
		return "Clear the tenant kill switch and refresh framework evidence before the pilot can re-evaluate."
	}
	return "Inspect the pilot decision for the next action."
}

func awsLimitedEnforcementPilotAuditTrail(pilotID, enforcementID, state, override string, now time.Time) []AWSLimitedEnforcementPilotAuditEntry {
	return []AWSLimitedEnforcementPilotAuditEntry{{
		EventID:    stableAWSBlastRadiusToken("limited-enforcement-pilot-projected", pilotID, enforcementID, state, override),
		Actor:      "identrail-limited-enforcement-pilot",
		EventType:  "limited_enforcement_pilot_projected",
		OccurredAt: now,
		Notes:      fmt.Sprintf("Enforcement=%s pilot_state=%s override=%s policy_version=%s; Identrail did not call any AWS write API at this layer.", enforcementID, state, override, awsLimitedEnforcementPilotPolicyID),
	}}
}

func awsLimitedEnforcementPilotRelationships(decisions []AWSLimitedEnforcementPilotDecision) []AWSLimitedEnforcementPilotRelationship {
	relationships := []AWSLimitedEnforcementPilotRelationship{}
	for _, decision := range decisions {
		if strings.TrimSpace(decision.EnforcementID) != "" {
			relationships = append(relationships, AWSLimitedEnforcementPilotRelationship{
				PilotID:     decision.PilotID,
				Type:        "pilots_enforcement_entry",
				FromNodeID:  decision.PilotID,
				ToNodeID:    decision.EnforcementID,
				EvidenceRef: firstString(decision.EvidenceLinks),
			})
		}
		if principal := strings.TrimSpace(decision.PrincipalNodeID); principal != "" {
			relationships = append(relationships, AWSLimitedEnforcementPilotRelationship{
				PilotID:    decision.PilotID,
				Type:       "governs_principal",
				FromNodeID: decision.PilotID,
				ToNodeID:   principal,
			})
		}
	}
	return relationships
}

func summarizeAWSLimitedEnforcementPilotDecisions(all, filtered []AWSLimitedEnforcementPilotDecision, relationships []AWSLimitedEnforcementPilotRelationship) AWSLimitedEnforcementPilotSummary {
	summary := AWSLimitedEnforcementPilotSummary{
		TotalDecisions:    len(all),
		FilteredDecisions: len(filtered),
		PilotStateCounts:  map[string]int{},
		OutcomeCounts:     map[string]int{},
		SourceTypeCounts:  map[string]int{},
		SeverityCounts:    map[string]int{},
	}
	confidenceTotal := 0.0
	for _, decision := range filtered {
		summary.PilotStateCounts[decision.PilotState]++
		if decision.Outcome != "" {
			summary.OutcomeCounts[decision.Outcome]++
		}
		if decision.SourceType != "" {
			summary.SourceTypeCounts[decision.SourceType]++
		}
		if decision.Severity != "" {
			summary.SeverityCounts[decision.Severity]++
		}
		if decision.Eligible {
			summary.EligibleCount++
		} else {
			summary.IneligibleCount++
		}
		switch decision.PilotState {
		case awsLimitedEnforcementPilotStateCanaryReady:
			summary.CanaryReadyCount++
		case awsLimitedEnforcementPilotStateEnforceReady:
			summary.EnforceReadyCount++
		case awsLimitedEnforcementPilotStateOverrideHold:
			summary.OverrideHoldCount++
		case awsLimitedEnforcementPilotStateKillSwitched:
			summary.KillSwitchEngagedCount++
		}
		for _, rule := range decision.EligibilityRules {
			if rule.Status == "failed" {
				summary.FailedRuleCount++
			}
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

func filterAWSLimitedEnforcementPilotDecisions(decisions []AWSLimitedEnforcementPilotDecision, request AWSLimitedEnforcementPilotRequest) ([]AWSLimitedEnforcementPilotDecision, map[string]string) {
	filters := map[string]string{
		"account_id":     strings.TrimSpace(request.AccountID),
		"region":         strings.TrimSpace(request.Region),
		"pilot_state":    normalizeAWSRuntimeEventFilterToken(request.PilotState),
		"source_type":    normalizeAWSRuntimeEventFilterToken(request.SourceType),
		"outcome":        normalizeAWSRuntimeEventFilterToken(request.Outcome),
		"enforcement_id": strings.TrimSpace(request.EnforcementID),
		"severity":       normalizeAWSRuntimeEventFilterToken(request.Severity),
		"search":         strings.TrimSpace(request.Search),
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
	filtered := make([]AWSLimitedEnforcementPilotDecision, 0, len(decisions))
	for _, decision := range decisions {
		if filters["account_id"] != "" && !awsLimitedEnforcementPilotAccountMatch(decision, filters["account_id"]) {
			continue
		}
		if filters["region"] != "" && !strings.EqualFold(filters["region"], strings.TrimSpace(decision.Region)) {
			continue
		}
		if filters["pilot_state"] != "" && filters["pilot_state"] != normalizeAWSRuntimeEventFilterToken(decision.PilotState) {
			continue
		}
		if filters["source_type"] != "" && filters["source_type"] != normalizeAWSRuntimeEventFilterToken(decision.SourceType) {
			continue
		}
		if filters["outcome"] != "" && filters["outcome"] != normalizeAWSRuntimeEventFilterToken(decision.Outcome) {
			continue
		}
		if filters["enforcement_id"] != "" && !strings.EqualFold(filters["enforcement_id"], decision.EnforcementID) && !strings.EqualFold(filters["enforcement_id"], decision.PilotID) && !strings.EqualFold(filters["enforcement_id"], decision.SourceID) {
			continue
		}
		if filters["severity"] != "" && filters["severity"] != normalizeAWSRuntimeEventFilterToken(decision.Severity) {
			continue
		}
		if filters["search"] != "" && !awsLimitedEnforcementPilotSearchMatch(decision, filters["search"]) {
			continue
		}
		filtered = append(filtered, decision)
	}
	return filtered, applied
}

func awsLimitedEnforcementPilotAccountMatch(decision AWSLimitedEnforcementPilotDecision, accountID string) bool {
	if strings.EqualFold(strings.TrimSpace(decision.AccountID), strings.TrimSpace(accountID)) {
		return true
	}
	for _, target := range decision.TargetAccountIDs {
		if strings.EqualFold(strings.TrimSpace(target), strings.TrimSpace(accountID)) {
			return true
		}
	}
	return false
}

func awsLimitedEnforcementPilotSearchMatch(decision AWSLimitedEnforcementPilotDecision, needle string) bool {
	needle = strings.ToLower(strings.TrimSpace(needle))
	if needle == "" {
		return true
	}
	values := []string{
		decision.PilotID, decision.EnforcementID, decision.SourceID, decision.SourceType,
		decision.PilotState, decision.Outcome, decision.Severity, decision.Title, decision.Summary,
		decision.Rationale, decision.PrincipalNodeID, decision.Action, decision.Cohort,
		decision.OperatorOverride, decision.NextAction, decision.InputHash,
	}
	values = append(values, decision.TargetAccountIDs...)
	values = append(values, decision.EvidenceLinks...)
	for _, rule := range decision.EligibilityRules {
		values = append(values, rule.Name, rule.Status, rule.Rationale)
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

func summarizeAWSLimitedEnforcementPilotStatus(frameworkStatus string, filtered []AWSLimitedEnforcementPilotDecision, diagnostics []AWSLimitedEnforcementPilotDiagnostic) (string, float64) {
	if frameworkStatus == awsPlatformDependencyStatusBlocked {
		return awsPlatformDependencyStatusBlocked, 0.35
	}
	for _, diagnostic := range diagnostics {
		if diagnostic.Retryable {
			return awsPlatformDependencyStatusDegraded, 0.72
		}
	}
	if frameworkStatus == awsPlatformDependencyStatusDegraded {
		return awsPlatformDependencyStatusDegraded, 0.74
	}
	if len(filtered) == 0 {
		return awsPlatformDependencyStatusReady, 0.82
	}
	return awsPlatformDependencyStatusReady, 0.9
}

func awsLimitedEnforcementPilotCaveats() []string {
	return []string{
		"Enforcement pilot decisions are read-only projections; Identrail never calls AWS write APIs at this layer and downstream executors own any live control change.",
		"The pilot admits high-confidence signals only: limited-enforce mode, confidence >= 90 percent, every framework gate passed, canary within the pilot cap, kill switch off, and no operator hold.",
		"Rollback thresholds (denial-regression budget, observation window, kill-switch and override halts) travel with every decision so a downstream executor can auto-rollback deterministically.",
	}
}

func awsLimitedEnforcementPilotRemediationHints(source []string) []string {
	hints := []string{
		"Keep the pilot canary at or below the cap and expand only after the observation window closes with no denial regressions.",
		"Use operator_override=hold to pause every pilot decision without touching the tenant kill switch; resume explicitly after review.",
		"Log the pilot policy version, input hash, cohort, canary percentage, and enforcement ID for every downstream transition.",
	}
	hints = append(hints, source...)
	return dedupeStrings(hints)
}

func awsLimitedEnforcementPilotDiagnostics(source []AWSLimitedEnforcementDiagnostic) []AWSLimitedEnforcementPilotDiagnostic {
	out := make([]AWSLimitedEnforcementPilotDiagnostic, 0, len(source))
	for _, diagnostic := range source {
		out = append(out, AWSLimitedEnforcementPilotDiagnostic(diagnostic))
	}
	return out
}

func awsLimitedEnforcementPilotCoverageGaps(source []AWSLimitedEnforcementCoverageGap) []AWSLimitedEnforcementPilotCoverageGap {
	out := make([]AWSLimitedEnforcementPilotCoverageGap, 0, len(source))
	for _, gap := range source {
		out = append(out, AWSLimitedEnforcementPilotCoverageGap(gap))
	}
	return out
}

func awsLimitedEnforcementPilotEvidenceBoundary() string {
	return "metadata_only_no_rendered_policy_bodies_no_secret_values_no_workload_payloads_tenant_workspace_project_connector_account_region_scoped"
}
