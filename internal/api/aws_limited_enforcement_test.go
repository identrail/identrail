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

func newLimitedEnforcementService(t *testing.T, project string, now time.Time) (*Service, string) {
	t.Helper()
	return newBlastRadiusService(t, project, now)
}

func TestGetAWSLimitedEnforcementBuildsContract(t *testing.T) {
	now := time.Date(2026, 7, 3, 10, 0, 0, 0, time.UTC)
	svc, ws := newLimitedEnforcementService(t, "project-limited-enforcement", now)

	result, err := svc.GetAWSLimitedEnforcement(defaultScopeContext(), ws, "project-limited-enforcement", AWSLimitedEnforcementRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
	})
	if err != nil {
		t.Fatalf("get limited enforcement: %v", err)
	}
	if result.CurrentIssueRef != "#1546" || result.Version != awsLimitedEnforcementVersion || result.PolicyVersion != awsLimitedEnforcementPolicyID {
		t.Fatalf("unexpected contract metadata: %+v", result)
	}
	if len(result.Entries) == 0 {
		t.Fatalf("expected limited enforcement entries from advisory sources: %+v", result.Summary)
	}
	if result.Summary.RelationshipCount != len(result.Relationships) {
		t.Fatalf("relationship count mismatch: %+v", result.Summary)
	}
	for _, entry := range result.Entries {
		if entry.EnforcementID == "" || entry.CalculationVersion != awsLimitedEnforcementVersion {
			t.Fatalf("entry missing stable metadata: %+v", entry)
		}
		if entry.PolicyVersion != awsLimitedEnforcementPolicyID || strings.TrimSpace(entry.InputHash) == "" {
			t.Fatalf("entry missing policy/hash metadata: %+v", entry)
		}
		if !entry.ReadOnlyProjection || entry.ReadyForEnforcement {
			t.Fatalf("default framework must stay read-only advisory unless safety config is explicit: %+v", entry)
		}
		if entry.EvidenceBoundary != awsLimitedEnforcementEvidenceBoundary() {
			t.Fatalf("entry crossed evidence boundary: %+v", entry)
		}
		if len(entry.Gates) == 0 || len(entry.AuditTrail) == 0 || entry.Rollback.Strategy == "" {
			t.Fatalf("entry missing gates/audit/rollback: %+v", entry)
		}
	}

	serialized, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	lower := strings.ToLower(string(serialized))
	for _, forbidden := range []string{"\"secret_access_key\"", "\"private_key\"", "\"policy_document_body\"", "\"rendered_policy\"", "\"prompt\"", "\"completion\""} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("limited enforcement serialized forbidden sensitive payload marker %q", forbidden)
		}
	}
}

func TestAWSLimitedEnforcementRequiresExplicitSafetyConfig(t *testing.T) {
	decision := AWSAdvisoryAuthorizationDecision{
		DecisionID:         "decision-1",
		Outcome:            awsAdvisoryAuthorizationOutcomeAllow,
		Confidence:         0.9,
		Score:              80,
		SourceType:         "advisory_authorization",
		InputHash:          AWSAdvisoryAuthorizationInputHash{Value: "input-a"},
		ReadOnlyProjection: true,
	}
	safety := AWSLimitedEnforcementSafetyConfig{RollbackRequired: true, AuditRequired: true}
	entry := awsLimitedEnforcementEntryFromDecision(decision, safety, AWSLimitedEnforcementRequest{Mode: awsLimitedEnforcementModeLimitedEnforce}, time.Now().UTC())
	if entry.Mode != awsLimitedEnforcementModeAdvisory || entry.EnforcementState != awsLimitedEnforcementStateBlockedBySafetyConfig || entry.ReadyForEnforcement {
		t.Fatalf("missing safety config must block limited enforcement: %+v", entry)
	}
	for _, gateName := range []string{"feature_flag_enabled", "canary_configured"} {
		if got := awsLimitedEnforcementTestGateStatus(entry.Gates, gateName); got != "failed" {
			t.Fatalf("%s gate must report failed when safety config blocks enforcement, got %s gates=%+v", gateName, got, entry.Gates)
		}
	}

	safety.FeatureFlagEnabled = true
	safety.CanaryPercent = 10
	safety.Cohort = "pilot-a"
	entry = awsLimitedEnforcementEntryFromDecision(decision, safety, AWSLimitedEnforcementRequest{Mode: awsLimitedEnforcementModeLimitedEnforce}, time.Now().UTC())
	if entry.Mode != awsLimitedEnforcementModeLimitedEnforce || entry.EnforcementState != awsLimitedEnforcementStateCanaryReady || !entry.ReadyForCanary || entry.ReadyForEnforcement {
		t.Fatalf("partial canary config should be canary-ready only: %+v", entry)
	}

	safety.CanaryPercent = 100
	entry = awsLimitedEnforcementEntryFromDecision(decision, safety, AWSLimitedEnforcementRequest{Mode: awsLimitedEnforcementModeLimitedEnforce}, time.Now().UTC())
	if entry.EnforcementState != awsLimitedEnforcementStateLimitedEnforceReady || !entry.ReadyForEnforcement {
		t.Fatalf("complete safety config should mark enforcement ready: %+v", entry)
	}
}

func TestAWSLimitedEnforcementKillSwitchWins(t *testing.T) {
	decision := AWSAdvisoryAuthorizationDecision{
		DecisionID: "decision-kill",
		Outcome:    awsAdvisoryAuthorizationOutcomeAllow,
		Confidence: 0.95,
		Score:      90,
		InputHash:  AWSAdvisoryAuthorizationInputHash{Value: "input-kill"},
	}
	safety := AWSLimitedEnforcementSafetyConfig{
		FeatureFlagEnabled: true,
		KillSwitchEngaged:  true,
		CanaryPercent:      100,
		Cohort:             "pilot-a",
		RollbackRequired:   true,
		AuditRequired:      true,
	}
	entry := awsLimitedEnforcementEntryFromDecision(decision, safety, AWSLimitedEnforcementRequest{Mode: awsLimitedEnforcementModeLimitedEnforce}, time.Now().UTC())
	if entry.EnforcementState != awsLimitedEnforcementStateBlockedByKillSwitch || entry.ReadyForCanary || entry.ReadyForEnforcement {
		t.Fatalf("kill switch must block canary and enforcement readiness: %+v", entry)
	}
}

func TestAWSLimitedEnforcementFixtureStates(t *testing.T) {
	now := time.Date(2026, 7, 3, 11, 0, 0, 0, time.UTC)
	svc, ws := newLimitedEnforcementService(t, "project-limited-enforcement-fixture", now)

	for _, state := range []string{"success", "empty", "degraded", "partial_failure", "permission_denied"} {
		result, err := svc.GetAWSLimitedEnforcement(defaultScopeContext(), ws, "project-limited-enforcement-fixture", AWSLimitedEnforcementRequest{
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

func TestRouterAWSLimitedEnforcement(t *testing.T) {
	now := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	svc, _ := newLimitedEnforcementService(t, "project-limited-enforcement-route", now)
	r := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{})

	resp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-limited-enforcement-route/aws/limited-enforcement?connector_id=aws-prod&fixture_state=success&mode=limited_enforce&feature_flag=true&canary_percent=25&cohort=pilot-a", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	var body struct {
		Framework AWSLimitedEnforcementResult `json:"limited_enforcement"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Framework.CurrentIssueRef != "#1546" || body.Framework.PolicyVersion != awsLimitedEnforcementPolicyID {
		t.Fatalf("unexpected route payload: %+v", body.Framework)
	}
	if body.Framework.SafetyConfig.CanaryPercent != 25 || body.Framework.SafetyConfig.Cohort != "pilot-a" || !body.Framework.SafetyConfig.FeatureFlagEnabled {
		t.Fatalf("route did not preserve safety config: %+v", body.Framework.SafetyConfig)
	}
}

func TestRouterAWSLimitedEnforcementPreservesBlockedLimitedEnforceEntries(t *testing.T) {
	now := time.Date(2026, 7, 3, 12, 15, 0, 0, time.UTC)
	svc, _ := newLimitedEnforcementService(t, "project-limited-enforcement-blocked-route", now)
	r := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{})

	resp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-limited-enforcement-blocked-route/aws/limited-enforcement?connector_id=aws-prod&fixture_state=success&mode=limited_enforce", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	var body struct {
		Framework AWSLimitedEnforcementResult `json:"limited_enforcement"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(body.Framework.Entries) == 0 {
		t.Fatalf("mode=limited_enforce must preserve blocked entries so operators can see failed gates: %+v", body.Framework.Summary)
	}
	foundBlocked := false
	for _, entry := range body.Framework.Entries {
		if entry.EnforcementState != awsLimitedEnforcementStateBlockedBySafetyConfig {
			continue
		}
		foundBlocked = true
		if entry.Mode != awsLimitedEnforcementModeAdvisory {
			t.Fatalf("blocked safety entry should remain advisory output mode: %+v", entry)
		}
		for _, gateName := range []string{"feature_flag_enabled", "canary_configured"} {
			if got := awsLimitedEnforcementTestGateStatus(entry.Gates, gateName); got != "failed" {
				t.Fatalf("%s gate must explain why limited enforcement is blocked, got %s entry=%+v", gateName, got, entry)
			}
		}
	}
	if !foundBlocked {
		t.Fatalf("expected at least one blocked_by_safety_config entry for missing safety config: %+v", body.Framework.Entries)
	}
}

func TestRouterAWSLimitedEnforcementRejectsInvalidCanaryPercent(t *testing.T) {
	now := time.Date(2026, 7, 3, 12, 30, 0, 0, time.UTC)
	svc, _ := newLimitedEnforcementService(t, "project-limited-enforcement-bad-canary", now)
	r := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{})

	for _, raw := range []string{"not-a-number", "-1", "101"} {
		resp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-limited-enforcement-bad-canary/aws/limited-enforcement?connector_id=aws-prod&fixture_state=success&canary_percent="+raw, "")
		if resp.Code != http.StatusBadRequest {
			t.Fatalf("%s: expected 400 for invalid canary_percent, got %d body=%s", raw, resp.Code, resp.Body.String())
		}
	}
}

func awsLimitedEnforcementTestGateStatus(gates []AWSLimitedEnforcementGate, name string) string {
	for _, gate := range gates {
		if gate.Name == name {
			return gate.Status
		}
	}
	return ""
}
