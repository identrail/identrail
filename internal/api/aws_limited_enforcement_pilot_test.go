package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/telemetry"
	"go.uber.org/zap"
)

func newLimitedEnforcementPilotService(t *testing.T, project string, now time.Time) (*Service, string) {
	t.Helper()
	return newBlastRadiusService(t, project, now)
}

func TestGetAWSLimitedEnforcementPilotBuildsContract(t *testing.T) {
	now := time.Date(2026, 7, 3, 15, 0, 0, 0, time.UTC)
	svc, ws := newLimitedEnforcementPilotService(t, "project-limited-enforcement-pilot", now)

	result, err := svc.GetAWSLimitedEnforcementPilot(defaultScopeContext(), ws, "project-limited-enforcement-pilot", AWSLimitedEnforcementPilotRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
	})
	if err != nil {
		t.Fatalf("get limited enforcement pilot: %v", err)
	}
	if result.CurrentIssueRef != "#1547" || result.Version != awsLimitedEnforcementPilotVersion || result.Mode != awsLimitedEnforcementPilotModePilot {
		t.Fatalf("unexpected contract metadata: %+v", result)
	}
	if result.PolicyVersion != awsLimitedEnforcementPilotPolicyID {
		t.Fatalf("expected stable policy version, got %q", result.PolicyVersion)
	}
	if result.RollbackThresholds.MaxDenialRegressionPct <= 0 || result.RollbackThresholds.ObservationWindow == "" || !result.RollbackThresholds.AutoRollbackOnKill {
		t.Fatalf("expected deterministic rollback thresholds: %+v", result.RollbackThresholds)
	}
	if len(result.Decisions) == 0 {
		t.Fatalf("expected pilot decisions projected from framework entries: %+v", result.Summary)
	}
	if result.Summary.RelationshipCount != len(result.Relationships) {
		t.Fatalf("relationship count mismatch: %+v", result.Summary)
	}
	for _, decision := range result.Decisions {
		if decision.PilotID == "" || decision.CalculationVersion != awsLimitedEnforcementPilotVersion {
			t.Fatalf("decision missing stable metadata: %+v", decision)
		}
		switch decision.PilotState {
		case awsLimitedEnforcementPilotStateCanaryReady, awsLimitedEnforcementPilotStateEnforceReady, awsLimitedEnforcementPilotStateIneligible, awsLimitedEnforcementPilotStateOverrideHold, awsLimitedEnforcementPilotStateKillSwitched:
		default:
			t.Fatalf("decision has unknown pilot state: %+v", decision)
		}
		// Without explicit safety config (feature flag, cohort, canary) no
		// decision may claim pilot readiness.
		if decision.Eligible {
			t.Fatalf("pilot must not mark decisions eligible without explicit safety config: %+v", decision)
		}
		if decision.EnforcementID == "" {
			t.Fatalf("decision must reference its framework entry: %+v", decision)
		}
		if len(decision.EligibilityRules) == 0 || len(decision.AuditTrail) == 0 {
			t.Fatalf("decision missing eligibility rules or audit trail: %+v", decision)
		}
		if decision.Metrics.EligibilityRulesTotal != len(decision.EligibilityRules) {
			t.Fatalf("metrics must reflect the evaluated rule set: %+v", decision.Metrics)
		}
		if decision.InputHash == "" || !decision.ReadOnlyProjection {
			t.Fatalf("decision missing input hash or read-only projection: %+v", decision)
		}
		if decision.EvidenceBoundary != awsLimitedEnforcementPilotEvidenceBoundary() {
			t.Fatalf("decision crossed evidence boundary: %+v", decision)
		}
	}

	serialized, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	lower := strings.ToLower(string(serialized))
	for _, forbidden := range []string{"\"secret_access_key\"", "\"private_key\"", "\"policy_document_body\"", "\"rendered_policy\""} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("limited enforcement pilot serialized forbidden sensitive payload marker %q", forbidden)
		}
	}
}

func pilotFrameworkEntry(mode, state string, confidence float64, gates []AWSLimitedEnforcementGate) AWSLimitedEnforcementEntry {
	if gates == nil {
		gates = []AWSLimitedEnforcementGate{{Name: "feature_flag_enabled", Status: "passed"}}
	}
	return AWSLimitedEnforcementEntry{
		EnforcementID:    "aws-limited-enforcement:test",
		SourceType:       "advisory_authorization",
		SourceID:         "decision-1",
		Mode:             mode,
		EnforcementState: state,
		Outcome:          "allow",
		Confidence:       confidence,
		Severity:         "medium",
		Score:            70,
		Title:            "Limited enforcement framework: test",
		Gates:            gates,
		InputHash:        "hash-1",
	}
}

func TestAWSLimitedEnforcementPilotStateOrdering(t *testing.T) {
	now := time.Date(2026, 7, 3, 15, 30, 0, 0, time.UTC)
	safety := AWSLimitedEnforcementSafetyConfig{FeatureFlagEnabled: true, CanaryPercent: 10, Cohort: "pilot-cohort", RollbackRequired: true, AuditRequired: true}
	thresholds := awsLimitedEnforcementPilotRollbackThresholds()
	eligible := pilotFrameworkEntry(awsLimitedEnforcementModeLimitedEnforce, awsLimitedEnforcementStateCanaryReady, 0.95, nil)

	decision := awsLimitedEnforcementPilotDecisionFromEntry(eligible, safety, thresholds, "resume", now)
	if decision.PilotState != awsLimitedEnforcementPilotStateCanaryReady || !decision.Eligible {
		t.Fatalf("eligible canary entry must be pilot_canary_ready: %+v", decision)
	}

	enforceReady := pilotFrameworkEntry(awsLimitedEnforcementModeLimitedEnforce, awsLimitedEnforcementStateLimitedEnforceReady, 0.95, nil)
	decision = awsLimitedEnforcementPilotDecisionFromEntry(enforceReady, safety, thresholds, "resume", now)
	if decision.PilotState != awsLimitedEnforcementPilotStateEnforceReady || !decision.Eligible {
		t.Fatalf("enforce-ready entry must be pilot_enforce_ready: %+v", decision)
	}

	killed := safety
	killed.KillSwitchEngaged = true
	decision = awsLimitedEnforcementPilotDecisionFromEntry(eligible, killed, thresholds, "resume", now)
	if decision.PilotState != awsLimitedEnforcementPilotStateKillSwitched || decision.Eligible {
		t.Fatalf("kill switch must override every eligibility rule: %+v", decision)
	}

	decision = awsLimitedEnforcementPilotDecisionFromEntry(eligible, safety, thresholds, "hold", now)
	if decision.PilotState != awsLimitedEnforcementPilotStateOverrideHold || decision.Eligible {
		t.Fatalf("operator hold must pause the pilot: %+v", decision)
	}

	lowConfidence := pilotFrameworkEntry(awsLimitedEnforcementModeLimitedEnforce, awsLimitedEnforcementStateCanaryReady, 0.85, nil)
	decision = awsLimitedEnforcementPilotDecisionFromEntry(lowConfidence, safety, thresholds, "resume", now)
	if decision.PilotState != awsLimitedEnforcementPilotStateIneligible || decision.Eligible {
		t.Fatalf("confidence below the pilot floor must be ineligible: %+v", decision)
	}
	if !strings.Contains(decision.Rationale, "high_confidence") {
		t.Fatalf("ineligible rationale must name the failed rule: %q", decision.Rationale)
	}

	advisoryMode := pilotFrameworkEntry(awsLimitedEnforcementModeAdvisory, awsLimitedEnforcementStateAdvisoryOnly, 0.95, nil)
	decision = awsLimitedEnforcementPilotDecisionFromEntry(advisoryMode, safety, thresholds, "resume", now)
	if decision.PilotState != awsLimitedEnforcementPilotStateIneligible || decision.Eligible {
		t.Fatalf("non-limited-enforce mode must be ineligible: %+v", decision)
	}

	failedGate := pilotFrameworkEntry(awsLimitedEnforcementModeLimitedEnforce, awsLimitedEnforcementStateCanaryReady, 0.95, []AWSLimitedEnforcementGate{{Name: "confidence_floor", Status: "failed"}})
	decision = awsLimitedEnforcementPilotDecisionFromEntry(failedGate, safety, thresholds, "resume", now)
	if decision.PilotState != awsLimitedEnforcementPilotStateIneligible || decision.Eligible {
		t.Fatalf("failed framework gate must be ineligible: %+v", decision)
	}

	broadCanary := safety
	broadCanary.CanaryPercent = 50
	decision = awsLimitedEnforcementPilotDecisionFromEntry(eligible, broadCanary, thresholds, "resume", now)
	if decision.PilotState != awsLimitedEnforcementPilotStateIneligible || decision.Eligible {
		t.Fatalf("canary above the pilot cap must be ineligible: %+v", decision)
	}
	if !strings.Contains(decision.Rationale, "canary_within_pilot_cap") {
		t.Fatalf("ineligible rationale must name the canary cap rule: %q", decision.Rationale)
	}
}

func TestAWSLimitedEnforcementPilotOverrideNormalization(t *testing.T) {
	cases := []struct {
		value string
		want  string
	}{
		{"", "resume"},
		{"hold", "hold"},
		{"pause", "hold"},
		{"HOLD", "hold"},
		{"resume", "resume"},
		{"bogus", ""},
	}
	for _, tc := range cases {
		if got := normalizeAWSLimitedEnforcementPilotOverride(tc.value); got != tc.want {
			t.Fatalf("value=%q got %q want %q", tc.value, got, tc.want)
		}
	}
}

func TestGetAWSLimitedEnforcementPilotRejectsUnknownOverride(t *testing.T) {
	now := time.Date(2026, 7, 3, 16, 0, 0, 0, time.UTC)
	svc, ws := newLimitedEnforcementPilotService(t, "project-limited-enforcement-pilot-override", now)

	if _, err := svc.GetAWSLimitedEnforcementPilot(defaultScopeContext(), ws, "project-limited-enforcement-pilot-override", AWSLimitedEnforcementPilotRequest{
		ConnectorID:      "aws-prod",
		FixtureState:     "success",
		OperatorOverride: "bogus",
	}); err == nil {
		t.Fatalf("unknown operator override must be rejected so a typo can never resume a held pilot")
	}
}

func TestGetAWSLimitedEnforcementPilotHighConfidencePath(t *testing.T) {
	now := time.Date(2026, 7, 3, 16, 30, 0, 0, time.UTC)
	svc, ws := newLimitedEnforcementPilotService(t, "project-limited-enforcement-pilot-hc", now)

	result, err := svc.GetAWSLimitedEnforcementPilot(defaultScopeContext(), ws, "project-limited-enforcement-pilot-hc", AWSLimitedEnforcementPilotRequest{
		ConnectorID:   "aws-prod",
		FixtureState:  "success",
		FeatureFlag:   "true",
		Cohort:        "pilot-cohort",
		CanaryPercent: 10,
	})
	if err != nil {
		t.Fatalf("get limited enforcement pilot with safety config: %v", err)
	}
	for _, decision := range result.Decisions {
		if !decision.Eligible {
			continue
		}
		if decision.Confidence < awsLimitedEnforcementPilotConfidenceFloor {
			t.Fatalf("eligible decision below the pilot confidence floor: %+v", decision)
		}
		if decision.PilotState != awsLimitedEnforcementPilotStateCanaryReady && decision.PilotState != awsLimitedEnforcementPilotStateEnforceReady {
			t.Fatalf("eligible decision has non-ready state: %+v", decision)
		}
		for _, rule := range decision.EligibilityRules {
			if rule.Status != "passed" {
				t.Fatalf("eligible decision carries a failed rule: %+v", decision.EligibilityRules)
			}
		}
	}

	held, err := svc.GetAWSLimitedEnforcementPilot(defaultScopeContext(), ws, "project-limited-enforcement-pilot-hc", AWSLimitedEnforcementPilotRequest{
		ConnectorID:      "aws-prod",
		FixtureState:     "success",
		FeatureFlag:      "true",
		Cohort:           "pilot-cohort",
		CanaryPercent:    10,
		OperatorOverride: "hold",
	})
	if err != nil {
		t.Fatalf("get limited enforcement pilot with hold: %v", err)
	}
	if held.OperatorOverride != "hold" {
		t.Fatalf("expected override echoed on result, got %q", held.OperatorOverride)
	}
	for _, decision := range held.Decisions {
		if decision.PilotState == awsLimitedEnforcementPilotStateKillSwitched {
			continue
		}
		if decision.PilotState != awsLimitedEnforcementPilotStateOverrideHold || decision.Eligible {
			t.Fatalf("operator hold must pause every pilot decision: %+v", decision)
		}
	}
}

func TestFilterAWSLimitedEnforcementPilotDecisions(t *testing.T) {
	decisions := []AWSLimitedEnforcementPilotDecision{
		{
			PilotID:       "pilot-ready",
			EnforcementID: "enf-1",
			SourceType:    "advisory_authorization",
			PilotState:    awsLimitedEnforcementPilotStateCanaryReady,
			Outcome:       "allow",
			Severity:      "medium",
			AccountID:     "111111111111",
			Region:        "us-east-1",
		},
		{
			PilotID:          "pilot-ineligible",
			EnforcementID:    "enf-2",
			SourceType:       "agentcore_gateway_policy_advisory",
			PilotState:       awsLimitedEnforcementPilotStateIneligible,
			Outcome:          "allow_tools",
			Severity:         "high",
			AccountID:        "222222222222",
			Region:           "us-west-2",
			TargetAccountIDs: []string{"333333333333"},
			Rationale:        "Entry failed pilot eligibility rule \"high_confidence\"",
		},
	}

	filtered, applied := filterAWSLimitedEnforcementPilotDecisions(decisions, AWSLimitedEnforcementPilotRequest{PilotState: "pilot_canary_ready"})
	if applied["pilot_state"] != normalizeAWSRuntimeEventFilterToken("pilot_canary_ready") || len(filtered) != 1 || filtered[0].PilotID != "pilot-ready" {
		t.Fatalf("pilot_state filter did not scope decisions: applied=%+v filtered=%+v", applied, filtered)
	}

	filtered, applied = filterAWSLimitedEnforcementPilotDecisions(decisions, AWSLimitedEnforcementPilotRequest{AccountID: "333333333333"})
	if applied["account_id"] != "333333333333" || len(filtered) != 1 || filtered[0].PilotID != "pilot-ineligible" {
		t.Fatalf("account_id filter must match target accounts: applied=%+v filtered=%+v", applied, filtered)
	}

	filtered, applied = filterAWSLimitedEnforcementPilotDecisions(decisions, AWSLimitedEnforcementPilotRequest{EnforcementID: "enf-2"})
	if applied["enforcement_id"] != "enf-2" || len(filtered) != 1 || filtered[0].PilotID != "pilot-ineligible" {
		t.Fatalf("enforcement_id filter did not scope decisions: applied=%+v filtered=%+v", applied, filtered)
	}

	filtered, applied = filterAWSLimitedEnforcementPilotDecisions(decisions, AWSLimitedEnforcementPilotRequest{Search: "high_confidence"})
	if applied["search"] != "high_confidence" || len(filtered) != 1 || filtered[0].PilotID != "pilot-ineligible" {
		t.Fatalf("search must reach the rationale: applied=%+v filtered=%+v", applied, filtered)
	}
}

func TestAWSLimitedEnforcementPilotFixtureStates(t *testing.T) {
	now := time.Date(2026, 7, 3, 17, 0, 0, 0, time.UTC)
	svc, ws := newLimitedEnforcementPilotService(t, "project-limited-enforcement-pilot-fixture", now)

	for _, state := range []string{"success", "empty", "degraded", "partial_failure", "permission_denied"} {
		result, err := svc.GetAWSLimitedEnforcementPilot(defaultScopeContext(), ws, "project-limited-enforcement-pilot-fixture", AWSLimitedEnforcementPilotRequest{
			ConnectorID:  "aws-prod",
			FixtureState: state,
		})
		if err != nil {
			t.Fatalf("%s: %v", state, err)
		}
		if result.FixtureState != state {
			t.Fatalf("%s: expected fixture_state echoed, got %q", state, result.FixtureState)
		}
		if result.Status == "" {
			t.Fatalf("%s: missing status", state)
		}
	}
}

func TestRouterAWSLimitedEnforcementPilot(t *testing.T) {
	now := time.Date(2026, 7, 3, 18, 0, 0, 0, time.UTC)
	svc, _ := newLimitedEnforcementPilotService(t, "project-limited-enforcement-pilot-route", now)
	r := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{})

	resp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-limited-enforcement-pilot-route/aws/limited-enforcement-pilot?connector_id=aws-prod&fixture_state=success&operator_override=hold", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	var body struct {
		Pilot AWSLimitedEnforcementPilotResult `json:"limited_enforcement_pilot"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Pilot.CurrentIssueRef != "#1547" || body.Pilot.PolicyVersion != awsLimitedEnforcementPilotPolicyID || body.Pilot.OperatorOverride != "hold" {
		t.Fatalf("unexpected route payload: %+v", body.Pilot)
	}

	badOverride := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-limited-enforcement-pilot-route/aws/limited-enforcement-pilot?connector_id=aws-prod&fixture_state=success&operator_override=bogus", "")
	if badOverride.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unknown override, got %d body=%s", badOverride.Code, badOverride.Body.String())
	}

	badCanary := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-limited-enforcement-pilot-route/aws/limited-enforcement-pilot?connector_id=aws-prod&fixture_state=success&canary_percent=200", "")
	if badCanary.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for out-of-range canary, got %d body=%s", badCanary.Code, badCanary.Body.String())
	}
}
