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

func TestAWSAdvisoryAuthorizationClassifyBlocksAllowOnNonTerminalVerification(t *testing.T) {
	resolved := AWSRemediationCase{CaseID: "case-resolved", Lifecycle: "resolved", Severity: "low"}
	low := AWSRemediationCase{CaseID: "case-low", Lifecycle: "proposed", Severity: "low"}

	pending := AWSPostRemediationVerificationEntry{VerificationID: "v-1", State: awsPostRemediationVerificationStatePending}
	if out, rule, _, _ := awsAdvisoryAuthorizationClassify(resolved, pending); out != awsAdvisoryAuthorizationOutcomeRequireApproval || rule != "verification_pending" {
		t.Fatalf("pending verification must not let a resolved case be allowed: outcome=%s rule=%s", out, rule)
	}
	if out, rule, _, _ := awsAdvisoryAuthorizationClassify(low, pending); out != awsAdvisoryAuthorizationOutcomeRequireApproval || rule != "verification_pending" {
		t.Fatalf("pending verification must gate low-severity cases: outcome=%s rule=%s", out, rule)
	}

	notReady := AWSPostRemediationVerificationEntry{VerificationID: "v-2", State: awsPostRemediationVerificationStateNotReady}
	if out, rule, _, _ := awsAdvisoryAuthorizationClassify(resolved, notReady); out != awsAdvisoryAuthorizationOutcomeWarn || rule != "verification_not_ready" {
		t.Fatalf("not-ready verification must warn even on resolved case: outcome=%s rule=%s", out, rule)
	}

	skipped := AWSPostRemediationVerificationEntry{VerificationID: "v-3", State: awsPostRemediationVerificationStateSkipped}
	if out, rule, _, _ := awsAdvisoryAuthorizationClassify(low, skipped); out != awsAdvisoryAuthorizationOutcomeWarn || rule != "verification_skipped" {
		t.Fatalf("skipped verification must warn even for low-severity cases: outcome=%s rule=%s", out, rule)
	}
}

func TestAWSAdvisoryAuthorizationInputHashCoversAllClassifierInputs(t *testing.T) {
	now := time.Date(2026, 7, 3, 10, 0, 0, 0, time.UTC)
	base := AWSRemediationCase{
		CaseID:        "case-hash",
		Lifecycle:     "proposed",
		ApprovalState: "pending_approver",
		Severity:      "low",
	}
	baseVerify := AWSPostRemediationVerificationEntry{VerificationID: "v-hash", State: awsPostRemediationVerificationStatePending}
	baseHash := awsAdvisoryAuthorizationDecisionFromCase(base, baseVerify, now).InputHash.Value

	killed := baseVerify
	killed.KillSwitchEngaged = true
	if h := awsAdvisoryAuthorizationDecisionFromCase(base, killed, now).InputHash.Value; h == baseHash {
		t.Fatalf("kill_switch_engaged must be part of the input hash so drift is detectable: %s", h)
	}

	severityChanged := base
	severityChanged.Severity = "critical"
	if h := awsAdvisoryAuthorizationDecisionFromCase(severityChanged, baseVerify, now).InputHash.Value; h == baseHash {
		t.Fatalf("severity change must move the input hash: %s", h)
	}

	approvalRequired := base
	approvalRequired.ApprovalRequired = true
	if h := awsAdvisoryAuthorizationDecisionFromCase(approvalRequired, baseVerify, now).InputHash.Value; h == baseHash {
		t.Fatalf("approval_required toggle must move the input hash: %s", h)
	}
}

func TestAWSAdvisoryAuthorizationVerificationSeverityRankPrefersSafetySignals(t *testing.T) {
	pending := AWSPostRemediationVerificationEntry{State: awsPostRemediationVerificationStatePending}
	notReady := AWSPostRemediationVerificationEntry{State: awsPostRemediationVerificationStateNotReady}
	skipped := AWSPostRemediationVerificationEntry{State: awsPostRemediationVerificationStateSkipped}
	verified := AWSPostRemediationVerificationEntry{State: awsPostRemediationVerificationStateVerified}
	failed := AWSPostRemediationVerificationEntry{State: awsPostRemediationVerificationStateFailed}
	killed := AWSPostRemediationVerificationEntry{State: awsPostRemediationVerificationStatePending, KillSwitchEngaged: true}

	if awsAdvisoryAuthorizationVerificationSeverityRank(killed) <= awsAdvisoryAuthorizationVerificationSeverityRank(failed) {
		t.Fatalf("kill switch must outrank failed verification: killed=%d failed=%d", awsAdvisoryAuthorizationVerificationSeverityRank(killed), awsAdvisoryAuthorizationVerificationSeverityRank(failed))
	}
	if awsAdvisoryAuthorizationVerificationSeverityRank(failed) <= awsAdvisoryAuthorizationVerificationSeverityRank(verified) {
		t.Fatalf("failed verification must outrank verified: failed=%d verified=%d", awsAdvisoryAuthorizationVerificationSeverityRank(failed), awsAdvisoryAuthorizationVerificationSeverityRank(verified))
	}
	if awsAdvisoryAuthorizationVerificationSeverityRank(pending) <= awsAdvisoryAuthorizationVerificationSeverityRank(verified) {
		t.Fatalf("pending must outrank verified so a not-yet-verified execution isn't classified as allow: pending=%d verified=%d", awsAdvisoryAuthorizationVerificationSeverityRank(pending), awsAdvisoryAuthorizationVerificationSeverityRank(verified))
	}
	if awsAdvisoryAuthorizationVerificationSeverityRank(pending) <= awsAdvisoryAuthorizationVerificationSeverityRank(notReady) {
		t.Fatalf("pending must outrank not_ready so an in-flight verification is not understated as warn: pending=%d not_ready=%d", awsAdvisoryAuthorizationVerificationSeverityRank(pending), awsAdvisoryAuthorizationVerificationSeverityRank(notReady))
	}
	if awsAdvisoryAuthorizationVerificationSeverityRank(pending) <= awsAdvisoryAuthorizationVerificationSeverityRank(skipped) {
		t.Fatalf("pending must outrank skipped: pending=%d skipped=%d", awsAdvisoryAuthorizationVerificationSeverityRank(pending), awsAdvisoryAuthorizationVerificationSeverityRank(skipped))
	}
}

func TestAWSAdvisoryAuthorizationActionForCaseHonorsPrincipalKind(t *testing.T) {
	cases := []struct {
		name       string
		c          AWSRemediationCase
		wantAction string
	}{
		{
			name: "permission boundary on IAM user projects PutUser variant",
			c: AWSRemediationCase{
				SourceType:   "aws_permission_boundary_scp",
				IdentityType: "iam_user",
				DiffIntent:   AWSRemediationDiffIntent{Kind: "permission_boundary_diff"},
			},
			wantAction: "iam:PutUserPermissionsBoundary",
		},
		{
			name: "permission boundary on IAM role projects PutRole variant",
			c: AWSRemediationCase{
				SourceType:   "aws_permission_boundary_scp",
				IdentityType: "iam_role",
				DiffIntent:   AWSRemediationDiffIntent{Kind: "permission_boundary_diff"},
			},
			wantAction: "iam:PutRolePermissionsBoundary",
		},
		{
			name: "iam policy diff on IAM user projects PutUserPolicy",
			c: AWSRemediationCase{
				SourceType:   "least_privilege",
				IdentityType: "iam_user",
				DiffIntent:   AWSRemediationDiffIntent{Kind: "iam_policy_diff"},
			},
			wantAction: "iam:PutUserPolicy",
		},
		{
			name: "source-type fallthrough on IAM user still projects PutUser variant",
			c: AWSRemediationCase{
				SourceType:   "aws_permission_boundary_scp",
				IdentityType: "iam_user",
			},
			wantAction: "iam:PutUserPermissionsBoundary",
		},
		{
			name: "no-op diff never advertises an IAM write even for least-privilege sources",
			c: AWSRemediationCase{
				SourceType: "least_privilege",
				DiffIntent: AWSRemediationDiffIntent{Kind: "manual_review", NoOp: true},
			},
			wantAction: "advisory:review",
		},
		{
			name: "role_scope_diff routes to Put*Policy like iam_policy_diff for ai_agent_risk",
			c: AWSRemediationCase{
				SourceType: "ai_agent_risk",
				DiffIntent: AWSRemediationDiffIntent{Kind: "role_scope_diff"},
			},
			wantAction: "iam:PutRolePolicy",
		},
		{
			name: "role_scope_diff on IAM user projects PutUserPolicy",
			c: AWSRemediationCase{
				SourceType:   "blast_radius",
				IdentityType: "iam_user",
				DiffIntent:   AWSRemediationDiffIntent{Kind: "role_scope_diff"},
			},
			wantAction: "iam:PutUserPolicy",
		},
		{
			name: "generic identity type falls back to identity node ID (user)",
			c: AWSRemediationCase{
				SourceType:     "least_privilege",
				IdentityType:   "iam_identity",
				IdentityNodeID: "aws:identity:arn:aws:iam::111111111111:user/actor",
				DiffIntent:     AWSRemediationDiffIntent{Kind: "iam_policy_diff"},
			},
			wantAction: "iam:PutUserPolicy",
		},
		{
			name: "hard-coded role identity type still parses user node ID first",
			c: AWSRemediationCase{
				SourceType:     "least_privilege",
				IdentityType:   "iam_role",
				IdentityNodeID: "aws:identity:arn:aws:iam::111111111111:user/actor",
				DiffIntent:     AWSRemediationDiffIntent{Kind: "iam_policy_diff"},
			},
			wantAction: "iam:PutUserPolicy",
		},
		{
			name: "generic identity type falls back to identity ARN (group)",
			c: AWSRemediationCase{
				SourceType:   "blast_radius",
				IdentityType: "iam_identity",
				IdentityARN:  "arn:aws:iam::111111111111:group/analysts",
				DiffIntent:   AWSRemediationDiffIntent{Kind: "iam_policy_diff"},
			},
			wantAction: "iam:PutGroupPolicy",
		},
		{
			name: "group principal on permission boundary falls back to advisory:review",
			c: AWSRemediationCase{
				SourceType:     "aws_permission_boundary_scp",
				IdentityNodeID: "aws:identity:arn:aws:iam::111111111111:group/app-group",
				DiffIntent:     AWSRemediationDiffIntent{Kind: "permission_boundary_diff"},
			},
			wantAction: "advisory:review",
		},
	}
	for _, tc := range cases {
		if got := awsAdvisoryAuthorizationActionForCase(tc.c); got != tc.wantAction {
			t.Fatalf("%s: got %q want %q", tc.name, got, tc.wantAction)
		}
	}
}

func TestAWSAdvisoryAuthorizationSplitsMixedPermissionBoundaryTargets(t *testing.T) {
	now := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	roleARN := "arn:aws:iam::111111111111:role/app"
	userARN := "arn:aws:iam::222222222222:user/operator"
	roleTarget := "aws:identity:" + roleARN
	userTarget := "aws:identity:" + userARN
	c := AWSRemediationCase{
		CaseID:          "case-boundary-mixed",
		SourceType:      "aws_permission_boundary_scp",
		Severity:        "medium",
		IdentityType:    "iam_role",
		IdentityNodeID:  roleTarget,
		ResourceNodeIDs: []string{roleTarget, userTarget},
		DiffIntent:      AWSRemediationDiffIntent{Kind: "permission_boundary_diff"},
	}

	decisions := awsAdvisoryAuthorizationDecisionsFromCase(c, nil, now)
	if len(decisions) != 2 {
		t.Fatalf("mixed permission-boundary targets must produce one decision per supported target, got %d: %+v", len(decisions), decisions)
	}

	byAction := map[string]AWSAdvisoryAuthorizationDecision{}
	for _, decision := range decisions {
		if byAction[decision.Action].DecisionID != "" {
			t.Fatalf("expected distinct action rows for mixed user/role boundary targets: %+v", decisions)
		}
		byAction[decision.Action] = decision
		if len(decision.ResourceScope) != 1 {
			t.Fatalf("split decision must scope to exactly one boundary target: %+v", decision)
		}
	}

	roleDecision := byAction["iam:PutRolePermissionsBoundary"]
	if roleDecision.PrincipalNodeID != roleTarget || roleDecision.PrincipalARN != roleARN || roleDecision.AccountID != "111111111111" {
		t.Fatalf("role boundary decision scoped to wrong target/account: %+v", roleDecision)
	}
	userDecision := byAction["iam:PutUserPermissionsBoundary"]
	if userDecision.PrincipalNodeID != userTarget || userDecision.PrincipalARN != userARN || userDecision.AccountID != "222222222222" {
		t.Fatalf("user boundary decision scoped to wrong target/account: %+v", userDecision)
	}
	if roleDecision.DecisionID == userDecision.DecisionID {
		t.Fatalf("split boundary decisions must have distinct decision IDs: role=%s user=%s", roleDecision.DecisionID, userDecision.DecisionID)
	}
}

func TestAWSAdvisoryAuthorizationNormalizesSinglePermissionBoundaryTargetARN(t *testing.T) {
	now := time.Date(2026, 7, 3, 12, 30, 0, 0, time.UTC)
	roleARN := "arn:aws:iam::111111111111:role/single-app"
	roleTarget := "aws:identity:" + roleARN
	c := AWSRemediationCase{
		CaseID:           "case-boundary-single",
		SourceType:       "aws_permission_boundary_scp",
		Severity:         "medium",
		IdentityNodeID:   roleTarget,
		ResourceNodeIDs:  []string{roleTarget},
		TargetAccountIDs: []string{"111111111111"},
		DiffIntent:       AWSRemediationDiffIntent{Kind: "permission_boundary_diff"},
	}

	decisions := awsAdvisoryAuthorizationDecisionsFromCase(c, nil, now)
	if len(decisions) != 1 {
		t.Fatalf("single permission-boundary target must stay one advisory decision, got %d: %+v", len(decisions), decisions)
	}
	decision := decisions[0]
	if decision.PrincipalNodeID != roleTarget || decision.PrincipalARN != roleARN {
		t.Fatalf("single boundary target must preserve node ID and expose embedded ARN: %+v", decision)
	}
	if decision.Action != "iam:PutRolePermissionsBoundary" || decision.AccountID != "111111111111" {
		t.Fatalf("single boundary decision scoped to wrong action/account: %+v", decision)
	}
	wantID := "aws-advisory-authorization:" + stableAWSBlastRadiusToken("decision", c.CaseID, decision.Action)
	if decision.DecisionID != wantID {
		t.Fatalf("single boundary decision ID should not add a split target scope: got %q want %q", decision.DecisionID, wantID)
	}
}

func TestAWSAdvisoryAuthorizationSplitTargetsUseMatchingVerification(t *testing.T) {
	now := time.Date(2026, 7, 3, 13, 0, 0, 0, time.UTC)
	roleTarget := "aws:identity:arn:aws:iam::111111111111:role/app"
	userTarget := "aws:identity:arn:aws:iam::222222222222:user/operator"
	c := AWSRemediationCase{
		CaseID:          "case-boundary-verification",
		SourceType:      "aws_permission_boundary_scp",
		Severity:        "medium",
		IdentityNodeID:  roleTarget,
		ResourceNodeIDs: []string{roleTarget, userTarget},
		DiffIntent:      AWSRemediationDiffIntent{Kind: "permission_boundary_diff"},
	}
	verifications := []AWSPostRemediationVerificationEntry{
		{
			VerificationID: "v-role",
			CaseID:         c.CaseID,
			State:          awsPostRemediationVerificationStateVerified,
			TargetResource: roleTarget,
			ImpactedNodes:  []string{roleTarget, userTarget},
		},
		{
			VerificationID: "v-user",
			CaseID:         c.CaseID,
			State:          awsPostRemediationVerificationStatePending,
			TargetResource: "arn:aws:iam::222222222222:user/operator",
			ImpactedNodes:  []string{userTarget, roleTarget},
		},
	}

	decisions := awsAdvisoryAuthorizationDecisionsFromCase(c, verifications, now)
	byAction := map[string]AWSAdvisoryAuthorizationDecision{}
	for _, decision := range decisions {
		byAction[decision.Action] = decision
	}

	roleDecision := byAction["iam:PutRolePermissionsBoundary"]
	if roleDecision.VerificationID != "v-role" || roleDecision.Outcome != awsAdvisoryAuthorizationOutcomeAllow {
		t.Fatalf("role split decision must use role verification, got %+v", roleDecision)
	}
	userDecision := byAction["iam:PutUserPermissionsBoundary"]
	if userDecision.VerificationID != "v-user" || userDecision.Outcome != awsAdvisoryAuthorizationOutcomeRequireApproval {
		t.Fatalf("user split decision must use user verification, got %+v", userDecision)
	}
}

func TestAWSAdvisoryAuthorizationAccountFilterMatchesTargetAccounts(t *testing.T) {
	decisions := []AWSAdvisoryAuthorizationDecision{
		{
			DecisionID:       "d-multi",
			AccountID:        "111111111111",
			TargetAccountIDs: []string{"111111111111", "222222222222", "333333333333"},
			Outcome:          awsAdvisoryAuthorizationOutcomeRequireApproval,
		},
	}

	filtered, _ := filterAWSAdvisoryAuthorizationDecisions(decisions, AWSAdvisoryAuthorizationRequest{AccountID: "333333333333"})
	if len(filtered) != 1 || filtered[0].DecisionID != "d-multi" {
		t.Fatalf("account_id filter must match target_account_ids on the decision, not just the primary account: %+v", filtered)
	}

	filtered, _ = filterAWSAdvisoryAuthorizationDecisions(decisions, AWSAdvisoryAuthorizationRequest{AccountID: "111111111111"})
	if len(filtered) != 1 {
		t.Fatalf("primary account match still required: %+v", filtered)
	}

	filtered, _ = filterAWSAdvisoryAuthorizationDecisions(decisions, AWSAdvisoryAuthorizationRequest{AccountID: "999999999999"})
	if len(filtered) != 0 {
		t.Fatalf("account filter must exclude decisions with no matching target: %+v", filtered)
	}
}

func TestAWSAdvisoryAuthorizationRegionFilterIsStrict(t *testing.T) {
	decisions := []AWSAdvisoryAuthorizationDecision{
		{DecisionID: "d-regional", Region: "us-east-1", Outcome: awsAdvisoryAuthorizationOutcomeAllow},
		{DecisionID: "d-regionless", Region: "", Outcome: awsAdvisoryAuthorizationOutcomeAllow},
		{DecisionID: "d-other-region", Region: "us-west-2", Outcome: awsAdvisoryAuthorizationOutcomeAllow},
	}
	filtered, _ := filterAWSAdvisoryAuthorizationDecisions(decisions, AWSAdvisoryAuthorizationRequest{Region: "us-east-1"})
	if len(filtered) != 1 || filtered[0].DecisionID != "d-regional" {
		t.Fatalf("region filter must be strict: regionless and mismatched-region decisions must be excluded: %+v", filtered)
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
