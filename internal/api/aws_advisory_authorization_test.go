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

func newAdvisoryAuthorizationService(t *testing.T, project string, now time.Time) (*Service, string) {
	t.Helper()
	return newBlastRadiusService(t, project, now)
}

func TestGetAWSAdvisoryAuthorizationBuildsContract(t *testing.T) {
	now := time.Date(2026, 7, 2, 10, 0, 0, 0, time.UTC)
	svc, ws := newAdvisoryAuthorizationService(t, "project-advisory-authorization", now)

	result, err := svc.GetAWSAdvisoryAuthorization(defaultScopeContext(), ws, "project-advisory-authorization", AWSAdvisoryAuthorizationRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
	})
	if err != nil {
		t.Fatalf("get advisory authorization: %v", err)
	}
	if result.CurrentIssueRef != "#1543" || result.Version != awsAdvisoryAuthorizationVersion || result.Mode != awsAdvisoryAuthorizationModeAdvisory {
		t.Fatalf("unexpected contract metadata: %+v", result)
	}
	if result.PolicyVersion != awsAdvisoryAuthorizationPolicyID {
		t.Fatalf("expected policy version to be stable, got %q", result.PolicyVersion)
	}
	if len(result.Decisions) == 0 {
		t.Fatalf("expected advisory decisions to be projected from remediation cases: %+v", result.Summary)
	}
	if result.Summary.RelationshipCount != len(result.Relationships) {
		t.Fatalf("expected relationship count to match: %+v", result.Summary)
	}
	for _, decision := range result.Decisions {
		if decision.DecisionID == "" || decision.CalculationVersion != awsAdvisoryAuthorizationVersion {
			t.Fatalf("decision missing stable metadata: %+v", decision)
		}
		if decision.Mode != awsAdvisoryAuthorizationModeAdvisory {
			t.Fatalf("decision must remain advisory: %+v", decision)
		}
		switch decision.Outcome {
		case awsAdvisoryAuthorizationOutcomeAllow, awsAdvisoryAuthorizationOutcomeWarn, awsAdvisoryAuthorizationOutcomeRequireApproval, awsAdvisoryAuthorizationOutcomeRecommendDeny, awsAdvisoryAuthorizationOutcomeQuarantine:
		default:
			t.Fatalf("decision has unknown outcome: %+v", decision)
		}
		if strings.TrimSpace(decision.Provenance.PolicyVersion) == "" || strings.TrimSpace(decision.Provenance.PolicyRule) == "" {
			t.Fatalf("decision missing provenance: %+v", decision.Provenance)
		}
		if strings.TrimSpace(decision.InputHash.Value) == "" {
			t.Fatalf("decision missing input hash: %+v", decision.InputHash)
		}
		if decision.CaseID == "" {
			t.Fatalf("decision must reference its source case: %+v", decision)
		}
		if decision.EvidenceBoundary != awsAdvisoryAuthorizationEvidenceBoundary() {
			t.Fatalf("decision crossed evidence boundary: %+v", decision)
		}
		if !decision.ReadOnlyProjection {
			t.Fatalf("decision must remain a read-only projection: %+v", decision)
		}
	}

	serialized, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	lower := strings.ToLower(string(serialized))
	for _, forbidden := range []string{"\"secret_access_key\"", "\"private_key\"", "\"policy_document_body\"", "\"rendered_policy\""} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("advisory authorization serialized forbidden sensitive payload marker %q", forbidden)
		}
	}
}

func TestAWSAdvisoryAuthorizationClassifyPolicyOrder(t *testing.T) {
	baseCase := AWSRemediationCase{
		CaseID:        "case-1",
		Severity:      "high",
		Lifecycle:     "proposed",
		ApprovalState: "pending_approver",
		DiffIntent:    AWSRemediationDiffIntent{Kind: "iam_policy_diff"},
	}

	killed := AWSPostRemediationVerificationEntry{KillSwitchEngaged: true, State: awsPostRemediationVerificationStateBlocked}
	out, rule, _, _ := awsAdvisoryAuthorizationClassify(baseCase, killed)
	if out != awsAdvisoryAuthorizationOutcomeQuarantine || rule != "kill_switch_engaged" {
		t.Fatalf("kill switch must override every other signal: %s / %s", out, rule)
	}

	failed := AWSPostRemediationVerificationEntry{State: awsPostRemediationVerificationStateFailed}
	if out, rule, _, _ := awsAdvisoryAuthorizationClassify(baseCase, failed); out != awsAdvisoryAuthorizationOutcomeQuarantine || rule != "verification_failed" {
		t.Fatalf("failed verification must classify as quarantine: %s / %s", out, rule)
	}

	verified := AWSPostRemediationVerificationEntry{State: awsPostRemediationVerificationStateVerified}
	if out, rule, _, _ := awsAdvisoryAuthorizationClassify(baseCase, verified); out != awsAdvisoryAuthorizationOutcomeAllow || rule != "verification_verified" {
		t.Fatalf("verified verification must classify as allow: %s / %s", out, rule)
	}

	blockedVerify := AWSPostRemediationVerificationEntry{State: awsPostRemediationVerificationStateBlocked}
	if out, rule, _, _ := awsAdvisoryAuthorizationClassify(baseCase, blockedVerify); out != awsAdvisoryAuthorizationOutcomeRecommendDeny || rule != "verification_blocked" {
		t.Fatalf("blocked verification must classify as recommend_deny: %s / %s", out, rule)
	}

	empty := AWSPostRemediationVerificationEntry{}
	approvedCase := baseCase
	approvedCase.ApprovalState = "approved"
	if out, rule, _, _ := awsAdvisoryAuthorizationClassify(approvedCase, empty); out != awsAdvisoryAuthorizationOutcomeRequireApproval || rule != "approved_awaiting_apply" {
		t.Fatalf("approved but unverified must require approval: %s / %s", out, rule)
	}

	blockedApproval := baseCase
	blockedApproval.ApprovalState = "blocked"
	if out, rule, _, _ := awsAdvisoryAuthorizationClassify(blockedApproval, empty); out != awsAdvisoryAuthorizationOutcomeRecommendDeny || rule != "approval_blocked" {
		t.Fatalf("blocked approval must classify as recommend_deny: %s / %s", out, rule)
	}

	resolved := baseCase
	resolved.Lifecycle = "resolved"
	if out, rule, _, _ := awsAdvisoryAuthorizationClassify(resolved, empty); out != awsAdvisoryAuthorizationOutcomeAllow || rule != "case_resolved" {
		t.Fatalf("resolved case must classify as allow: %s / %s", out, rule)
	}

	approvalRequired := AWSRemediationCase{CaseID: "case-2", Severity: "low", ApprovalRequired: true, ApprovalState: "pending_owner"}
	if out, rule, _, _ := awsAdvisoryAuthorizationClassify(approvalRequired, empty); out != awsAdvisoryAuthorizationOutcomeRequireApproval || rule != "approval_required" {
		t.Fatalf("approval-required case must classify as require_approval: %s / %s", out, rule)
	}

	if out, rule, _, _ := awsAdvisoryAuthorizationClassify(baseCase, empty); out != awsAdvisoryAuthorizationOutcomeWarn || rule != "high_severity_finding" {
		t.Fatalf("high severity without in-flight execution must warn: %s / %s", out, rule)
	}

	low := AWSRemediationCase{CaseID: "case-3", Severity: "low"}
	if out, rule, _, _ := awsAdvisoryAuthorizationClassify(low, empty); out != awsAdvisoryAuthorizationOutcomeAllow || rule != "no_active_risk" {
		t.Fatalf("low severity fallthrough must allow: %s / %s", out, rule)
	}
}

func TestFilterAWSAdvisoryAuthorizationDecisions(t *testing.T) {
	decisions := []AWSAdvisoryAuthorizationDecision{
		{
			DecisionID:      "d-allow",
			Outcome:         awsAdvisoryAuthorizationOutcomeAllow,
			Severity:        "medium",
			PrincipalNodeID: "aws:identity:arn:aws:iam::111111111111:role/app",
			AccountID:       "111111111111",
			Action:          "iam:PutRolePolicy",
			SourceType:      "least_privilege",
			CaseID:          "case-1",
		},
		{
			DecisionID:      "d-deny",
			Outcome:         awsAdvisoryAuthorizationOutcomeRecommendDeny,
			Severity:        "high",
			PrincipalNodeID: "aws:identity:arn:aws:iam::222222222222:user/bot",
			AccountID:       "222222222222",
			Action:          "iam:UpdateAccessKey",
			SourceType:      "aws_access_key_quarantine",
			CaseID:          "case-2",
		},
	}

	filtered, applied := filterAWSAdvisoryAuthorizationDecisions(decisions, AWSAdvisoryAuthorizationRequest{Outcome: "recommend_deny"})
	if applied["outcome"] != normalizeAWSRuntimeEventFilterToken("recommend_deny") || len(filtered) != 1 || filtered[0].DecisionID != "d-deny" {
		t.Fatalf("outcome filter did not scope decisions: applied=%+v filtered=%+v", applied, filtered)
	}

	filtered, _ = filterAWSAdvisoryAuthorizationDecisions(decisions, AWSAdvisoryAuthorizationRequest{PrincipalID: "aws:identity:arn:aws:iam::222222222222:user/bot"})
	if len(filtered) != 1 || filtered[0].DecisionID != "d-deny" {
		t.Fatalf("principal_id filter did not scope decisions: %+v", filtered)
	}

	filtered, _ = filterAWSAdvisoryAuthorizationDecisions(decisions, AWSAdvisoryAuthorizationRequest{Action: "iam:PutRolePolicy"})
	if len(filtered) != 1 || filtered[0].DecisionID != "d-allow" {
		t.Fatalf("action filter did not scope decisions: %+v", filtered)
	}

	filtered, _ = filterAWSAdvisoryAuthorizationDecisions(decisions, AWSAdvisoryAuthorizationRequest{Search: "case-2"})
	if len(filtered) != 1 || filtered[0].DecisionID != "d-deny" {
		t.Fatalf("search must reach case_id: %+v", filtered)
	}
}

func TestAWSAdvisoryAuthorizationFixtureStates(t *testing.T) {
	now := time.Date(2026, 7, 2, 11, 0, 0, 0, time.UTC)
	svc, ws := newAdvisoryAuthorizationService(t, "project-advisory-authorization-fixture", now)

	for _, state := range []string{"success", "empty", "degraded", "partial_failure", "permission_denied"} {
		result, err := svc.GetAWSAdvisoryAuthorization(defaultScopeContext(), ws, "project-advisory-authorization-fixture", AWSAdvisoryAuthorizationRequest{
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

func TestRouterAWSAdvisoryAuthorization(t *testing.T) {
	now := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	svc, _ := newAdvisoryAuthorizationService(t, "project-advisory-authorization-route", now)
	r := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{})

	resp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-advisory-authorization-route/aws/advisory-authorization?connector_id=aws-prod&fixture_state=success", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	var body struct {
		Advisory AWSAdvisoryAuthorizationResult `json:"advisory_authorization"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Advisory.CurrentIssueRef != "#1543" || body.Advisory.PolicyVersion != awsAdvisoryAuthorizationPolicyID {
		t.Fatalf("unexpected route payload: %+v", body.Advisory)
	}
}
