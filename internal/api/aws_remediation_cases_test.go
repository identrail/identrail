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

func newRemediationCaseService(t *testing.T, project string, now time.Time) (*Service, string) {
	t.Helper()
	return newBlastRadiusService(t, project, now)
}

func TestGetAWSRemediationCasesBuildsContract(t *testing.T) {
	now := time.Date(2026, 6, 23, 10, 0, 0, 0, time.UTC)
	svc, ws := newRemediationCaseService(t, "project-remediation-cases", now)

	result, err := svc.GetAWSRemediationCases(defaultScopeContext(), ws, "project-remediation-cases", AWSRemediationCaseRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
	})
	if err != nil {
		t.Fatalf("get remediation cases: %v", err)
	}
	if result.CurrentIssueRef != "#1529" || result.Version != awsRemediationCaseVersion || result.Status != "ready" {
		t.Fatalf("unexpected contract metadata: %+v", result)
	}
	if len(result.Cases) == 0 || result.Summary.TotalCases != len(result.Cases) {
		t.Fatalf("expected case summary to match payload: %+v", result.Summary)
	}
	if result.Summary.SourceTypeCounts["ai_agent_risk"] == 0 && result.Summary.SourceTypeCounts["least_privilege"] == 0 {
		t.Fatalf("expected at least one upstream source emitting cases: %+v", result.Summary.SourceTypeCounts)
	}
	if result.Summary.SourceTypeCounts["trust_policy_hardening"] == 0 {
		t.Fatalf("expected IAM role trust-policy hardening cases for downstream dry-run/executor joins: %+v", result.Summary.SourceTypeCounts)
	}
	if result.Summary.RelationshipCount != len(result.Relationships) || len(result.Relationships) == 0 {
		t.Fatalf("expected relationships and matching count: summary=%+v relationships=%+v", result.Summary, result.Relationships)
	}
	if len(result.Caveats) == 0 || len(result.CoverageGaps) == 0 {
		t.Fatalf("expected caveats and coverage gaps: %+v", result)
	}
	for i := 1; i < len(result.Cases); i++ {
		if result.Cases[i-1].Score < result.Cases[i].Score {
			t.Fatalf("cases are not ranked by descending score: %+v", result.Cases)
		}
	}
	for _, c := range result.Cases {
		if c.CaseID == "" || c.CalculationVersion != awsRemediationCaseVersion || c.SourceType == "" || c.SourceFindingID == "" {
			t.Fatalf("case missing stable metadata: %+v", c)
		}
		if c.Lifecycle == "" || c.Severity == "" || c.Status == "" || c.ApprovalState == "" || c.Title == "" {
			t.Fatalf("case missing classification fields: %+v", c)
		}
		if c.DiffIntent.Kind == "" || !c.DiffIntent.ReadOnlyProjection {
			t.Fatalf("case missing read-only diff intent: %+v", c.DiffIntent)
		}
		if len(c.RollbackPlan.Steps) == 0 || c.RollbackPlan.Strategy == "" {
			t.Fatalf("case missing rollback plan: %+v", c.RollbackPlan)
		}
		if len(c.VerificationPlan.Steps) == 0 || c.VerificationPlan.Strategy == "" {
			t.Fatalf("case missing verification plan: %+v", c.VerificationPlan)
		}
		if c.EvidenceBoundary != awsRemediationCaseEvidenceBoundary() {
			t.Fatalf("case crossed evidence boundary: %+v", c)
		}
		if c.SourceType == "trust_policy_hardening" && (c.IdentityType != "iam_role" || c.DiffIntent.Kind != "iam_trust_diff") {
			t.Fatalf("trust-policy hardening case must stay scoped to IAM role trust diffs: %+v", c)
		}
		if len(c.AuditTrail) == 0 || c.AuditTrail[0].EventType != "proposed" {
			t.Fatalf("case missing proposed audit entry: %+v", c.AuditTrail)
		}
		if strings.Contains(strings.ToLower(c.Summary), "secret value") && !strings.Contains(strings.ToLower(c.Summary), "not collected") {
			t.Fatalf("summary must not imply secret value collection: %s", c.Summary)
		}
	}
}

func TestAWSRemediationCasesAggregateTrustPolicySourceHealth(t *testing.T) {
	sources := awsRemediationCaseSources{
		risk:        AWSAIAgentRiskResult{Status: awsPlatformDependencyStatusReady},
		least:       AWSLeastPrivilegeResult{Status: awsPlatformDependencyStatusReady},
		equivalence: AWSSecretPermissionEquivalenceResult{Status: awsPlatformDependencyStatusReady},
		blast:       AWSBlastRadiusResult{Status: awsPlatformDependencyStatusReady},
		trust: AWSTrustPolicyHardeningResult{
			Status:           awsPlatformDependencyStatusDegraded,
			FailureReasons:   []string{"trust policy planner degraded"},
			RemediationHints: []string{"retry trust policy hardening"},
			Diagnostics: []AWSTrustPolicyHardeningDiagnostic{{
				Collector:   "aws_trust_policy_hardening",
				SourceID:    "cross-account-trust",
				Code:        "trust_source_delayed",
				Message:     "Trust source delayed.",
				Remediation: "Retry trust source.",
				Retryable:   true,
			}},
			CoverageGaps: []AWSTrustPolicyHardeningCoverageGap{{
				Capability:  "trust_policy_runtime_evidence",
				Status:      "partial_failure",
				Reason:      "Runtime trust evidence delayed.",
				Remediation: "Retry runtime trust evidence.",
			}},
		},
	}
	diagnostics := awsRemediationCaseDiagnostics(sources)
	status, _ := summarizeAWSRemediationCaseStatus(sources, nil, diagnostics)
	if status != awsPlatformDependencyStatusDegraded {
		t.Fatalf("trust source health must affect remediation-case status, got %s", status)
	}
	if !awsStringSliceContains(awsRemediationCaseFailureReasons(sources), "trust policy planner degraded") {
		t.Fatalf("trust failure reasons were not propagated")
	}
	if !awsStringSliceContains(awsRemediationCaseRemediationHints(sources), "retry trust policy hardening") {
		t.Fatalf("trust remediation hints were not propagated")
	}
	if len(diagnostics) != 1 || diagnostics[0].Collector != "aws_trust_policy_hardening" || !diagnostics[0].Retryable {
		t.Fatalf("trust diagnostics were not propagated: %+v", diagnostics)
	}
	gaps := awsRemediationCaseCoverageGaps(sources)
	foundTrustGap := false
	for _, gap := range gaps {
		if gap.Capability == "trust_policy_runtime_evidence" {
			foundTrustGap = true
			break
		}
	}
	if !foundTrustGap {
		t.Fatalf("trust coverage gaps were not propagated: %+v", gaps)
	}
}

func TestGetAWSRemediationCasesAppliesFilters(t *testing.T) {
	now := time.Date(2026, 6, 23, 10, 5, 0, 0, time.UTC)
	svc, ws := newRemediationCaseService(t, "project-remediation-case-filters", now)

	leastOnly, err := svc.GetAWSRemediationCases(defaultScopeContext(), ws, "project-remediation-case-filters", AWSRemediationCaseRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
		SourceType:   "least_privilege",
	})
	if err != nil {
		t.Fatalf("source filter: %v", err)
	}
	if len(leastOnly.Cases) == 0 {
		t.Fatalf("expected least-privilege cases in the success fixture")
	}
	for _, c := range leastOnly.Cases {
		if c.SourceType != "least_privilege" {
			t.Fatalf("source filter leaked %s case: %+v", c.SourceType, c)
		}
	}
	if leastOnly.AppliedFilters["source_type"] != "least-privilege" {
		t.Fatalf("expected applied source_type filter, got %+v", leastOnly.AppliedFilters)
	}

	highOnly, err := svc.GetAWSRemediationCases(defaultScopeContext(), ws, "project-remediation-case-filters", AWSRemediationCaseRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
		Severity:     "high",
	})
	if err != nil {
		t.Fatalf("severity filter: %v", err)
	}
	for _, c := range highOnly.Cases {
		if c.Severity != "high" {
			t.Fatalf("severity filter leaked %s case: %+v", c.Severity, c)
		}
	}

	owned, err := svc.GetAWSRemediationCases(defaultScopeContext(), ws, "project-remediation-case-filters", AWSRemediationCaseRequest{
		ConnectorID:   "aws-prod",
		FixtureState:  "success",
		OwnerAssigned: "true",
	})
	if err != nil {
		t.Fatalf("owner filter: %v", err)
	}
	for _, c := range owned.Cases {
		if !c.OwnerAssigned {
			t.Fatalf("owner filter leaked ownerless case: %+v", c)
		}
	}

	search, err := svc.GetAWSRemediationCases(defaultScopeContext(), ws, "project-remediation-case-filters", AWSRemediationCaseRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
		Search:       "rotation",
	})
	if err != nil {
		t.Fatalf("search filter: %v", err)
	}
	if len(search.Cases) == 0 {
		t.Fatalf("expected rotation cases in the success fixture")
	}
}

func TestAWSRemediationCaseDerivesLifecycleAndApproval(t *testing.T) {
	now := time.Date(2026, 6, 23, 10, 10, 0, 0, time.UTC)
	ownerless := AWSAIAgentRiskFinding{
		FindingID:        "aws-ai-agent-risk:ownerless-test",
		RiskType:         "ownerless_agent",
		Severity:         "high",
		Status:           "action_required",
		Score:            72,
		Confidence:       0.82,
		AccountID:        "123456789012",
		Region:           "us-east-1",
		AgentNodeID:      "aws:agent:123456789012:us-east-1:custom_agent/lonely-agent",
		AgentID:          "lonely-agent",
		AgentName:        "lonely-agent",
		AgentType:        "custom_agent",
		SourceSignals:    []string{"ai_agent_identities"},
		Rationale:        "lonely-agent has no owner tag.",
		EvidenceBoundary: awsAIAgentRiskEvidenceBoundary(),
		ImpactedNodes:    []string{"aws:agent:123456789012:us-east-1:custom_agent/lonely-agent"},
	}
	ownerCase, ok := awsRemediationCaseFromAIAgentRisk(ownerless, now)
	if !ok {
		t.Fatalf("expected ownerless agent to produce a case")
	}
	if ownerCase.OwnerAssigned {
		t.Fatalf("ownerless agent must not be owner-assigned")
	}
	if ownerCase.ApprovalState != "pending_owner" {
		t.Fatalf("ownerless high-severity case must wait on owner approval: %s", ownerCase.ApprovalState)
	}
	if ownerCase.Lifecycle != "in_review" {
		t.Fatalf("expected in_review lifecycle when owner is missing, got %s", ownerCase.Lifecycle)
	}
	if ownerCase.DiffIntent.Kind != "owner_assignment" {
		t.Fatalf("ownerless agent should propose owner_assignment diff, got %s", ownerCase.DiffIntent.Kind)
	}
	if !ownerCase.DiffIntent.NoOp {
		t.Fatalf("owner assignment diff should be a no-op AWS change: %+v", ownerCase.DiffIntent)
	}

	rotation := AWSAIAgentRiskFinding{
		FindingID:        "aws-ai-agent-risk:rotation-test",
		RiskType:         "external_credential_exposure",
		Severity:         "critical",
		Status:           "action_required",
		Score:            92,
		Confidence:       0.9,
		AccountID:        "123456789012",
		Region:           "us-east-1",
		AgentNodeID:      "aws:agent:123456789012:us-east-1:custom_agent/billing-agent",
		AgentID:          "billing-agent",
		AgentName:        "billing-agent",
		AgentType:        "custom_agent",
		Provider:         "openai",
		SourceSignals:    []string{"ai_agent_identities"},
		Rationale:        "billing-agent references an openai key.",
		EvidenceBoundary: awsAIAgentRiskEvidenceBoundary(),
	}
	rotationCase, ok := awsRemediationCaseFromAIAgentRisk(rotation, now)
	if !ok {
		t.Fatalf("expected rotation case")
	}
	if !rotationCase.ApprovalRequired {
		t.Fatalf("critical secret rotation must require approval: %+v", rotationCase)
	}
	if rotationCase.ApprovalState != "pending_approver" {
		t.Fatalf("owner-assigned critical case must enter pending_approver state, got %s", rotationCase.ApprovalState)
	}
	if rotationCase.Lifecycle != "approved" {
		t.Fatalf("owner-assigned critical action_required case should reach approved lifecycle, got %s", rotationCase.Lifecycle)
	}
	if rotationCase.DiffIntent.Kind != "secret_rotation" {
		t.Fatalf("rotation case should propose secret_rotation diff, got %s", rotationCase.DiffIntent.Kind)
	}
	if rotationCase.RollbackPlan.Strategy != "re_create_secret_reference" {
		t.Fatalf("secret_rotation must use re_create_secret_reference rollback, got %s", rotationCase.RollbackPlan.Strategy)
	}
	if rotationCase.VerificationPlan.Strategy != "secret_access_re_evaluate" {
		t.Fatalf("rotation must use secret_access_re_evaluate verification, got %s", rotationCase.VerificationPlan.Strategy)
	}

	lowConfidence := rotation
	lowConfidence.FindingID = "aws-ai-agent-risk:low-confidence"
	lowConfidence.Confidence = 0.4
	lowCase, ok := awsRemediationCaseFromAIAgentRisk(lowConfidence, now)
	if !ok {
		t.Fatalf("expected low-confidence case")
	}
	if lowCase.Lifecycle != "proposed" {
		t.Fatalf("low-confidence cases must stay proposed, got %s", lowCase.Lifecycle)
	}
}

func TestAWSRemediationCaseBackingRoleAnchorsOnRole(t *testing.T) {
	now := time.Date(2026, 6, 23, 10, 12, 0, 0, time.UTC)
	backingRole := AWSAIAgentRiskFinding{
		FindingID:         "aws-ai-agent-risk:backing-role-scope-test",
		RiskType:          "backing_role_scope",
		Severity:          "high",
		Status:            "review",
		Score:             80,
		Confidence:        0.86,
		AccountID:         "123456789012",
		Region:            "us-east-1",
		AgentNodeID:       "aws:agent:123456789012:us-east-1:custom_agent/payments-agent",
		AgentID:           "payments-agent",
		AgentName:         "payments-agent",
		AgentType:         "custom_agent",
		RuntimeRoleARN:    "arn:aws:iam::123456789012:role/payments-agent-task",
		RuntimeRoleNodeID: "aws:identity:arn:aws:iam::123456789012:role/payments-agent-task",
		SourceSignals:     []string{"least_privilege"},
		Rationale:         "Backing role for payments-agent has removable least-privilege scope.",
		EvidenceBoundary:  awsAIAgentRiskEvidenceBoundary(),
	}
	c, ok := awsRemediationCaseFromAIAgentRisk(backingRole, now)
	if !ok {
		t.Fatalf("expected backing-role case to be emitted")
	}
	if c.IdentityType != "iam_role" {
		t.Fatalf("expected iam_role identity type, got %s", c.IdentityType)
	}
	if c.IdentityNodeID != backingRole.RuntimeRoleNodeID {
		t.Fatalf("backing-role case must anchor identity_node_id on the role, got %q (want %q)", c.IdentityNodeID, backingRole.RuntimeRoleNodeID)
	}
	if c.IdentityARN != backingRole.RuntimeRoleARN {
		t.Fatalf("backing-role case must anchor identity_arn on the role ARN, got %q (want %q)", c.IdentityARN, backingRole.RuntimeRoleARN)
	}
	if strings.Contains(c.IdentityName, "payments-agent") && c.IdentityName == backingRole.AgentName {
		t.Fatalf("backing-role case identity_name must surface the role, not the agent name, got %q", c.IdentityName)
	}
}

func TestAWSRemediationCaseReachesApprovedWhenApprovalNotRequired(t *testing.T) {
	now := time.Date(2026, 6, 23, 10, 35, 0, 0, time.UTC)
	ready := AWSLeastPrivilegeRecommendation{
		RecommendationID:   "least-priv:ready-medium",
		CalculationVersion: "aws-least-privilege-v1",
		Decision:           "remove",
		Severity:           "medium",
		Status:             "action_required",
		Score:              68,
		Confidence:         0.82,
		AccountID:          "123456789012",
		Region:             "us-east-1",
		IdentityNodeID:     "aws:identity:arn:aws:iam::123456789012:role/ready-role",
		PrincipalARN:       "arn:aws:iam::123456789012:role/ready-role",
		DisplayName:        "ready-role",
		RemoveActions:      []string{"s3:DeleteObject"},
		KeepActions:        []string{"s3:GetObject"},
		Rationale:          "Observed actions exclude the granted s3:DeleteObject permission.",
		ImpactedNodes:      []string{"aws:identity:arn:aws:iam::123456789012:role/ready-role"},
	}
	c, ok := awsRemediationCaseFromLeastPrivilege(ready, now)
	if !ok {
		t.Fatalf("expected ready remove case")
	}
	if c.ApprovalRequired {
		t.Fatalf("medium-severity iam_policy_diff should not require approval (severity=%s diff=%+v)", c.Severity, c.DiffIntent)
	}
	if c.ApprovalState != "not_required" {
		t.Fatalf("expected approval_state=not_required, got %s", c.ApprovalState)
	}
	if c.Lifecycle != "approved" {
		t.Fatalf("executable action_required case with no approval gate should reach approved lifecycle, got %s", c.Lifecycle)
	}
}

func TestAWSRemediationCaseTrustPolicyHardeningReadyPlanPreservesApprovedState(t *testing.T) {
	now := time.Date(2026, 6, 29, 10, 40, 0, 0, time.UTC)
	plan := AWSTrustPolicyHardeningPlan{
		PlanID:             "aws-trust-policy-hardening:ready-plan",
		Severity:           "high",
		Status:             "action_required",
		Score:              82,
		Confidence:         0.9,
		AccountID:          "123456789012",
		Region:             "us-east-1",
		ResourceType:       "iam_role",
		ResourceNodeID:     "aws:identity:arn:aws:iam::123456789012:role/payments-cross-account",
		ResourceARN:        "arn:aws:iam::123456789012:role/payments-cross-account",
		ResourceLabel:      "payments-cross-account",
		HardeningDirection: "add_org_or_source_condition",
		Summary:            "Runtime evidence supports adding trust-policy conditions.",
		ReadyForApply:      true,
		PublicPrincipal:    false,
		BreakageProjection: AWSTrustPolicyHardeningBreakageProjection{Level: "low", Rationale: "Runtime callers are known."},
		RollbackPlan:       AWSTrustPolicyHardeningRollbackPlan{Strategy: "restore_trust_policy", Steps: []string{"Restore the previous trust policy."}},
		VerificationPlan:   AWSTrustPolicyHardeningVerificationPlan{Strategy: "trust_policy_re_evaluate", Steps: []string{"Re-run trust-policy hardening."}},
		ImpactedNodes:      []string{"aws:identity:arn:aws:iam::123456789012:role/payments-cross-account"},
		CreatedAt:          now,
		UpdatedAt:          now,
	}
	c, ok := awsRemediationCaseFromTrustPolicyHardening(plan, now)
	if !ok {
		t.Fatalf("expected trust-policy hardening case")
	}
	if !c.ApprovalRequired {
		t.Fatalf("iam_trust_diff trust-policy case must require approval: %+v", c)
	}
	if c.ApprovalState != "approved" {
		t.Fatalf("ready trust-policy plan must preserve approved state for dry-run/executor flow, got %s", c.ApprovalState)
	}
	if c.Lifecycle != "approved" {
		t.Fatalf("ready trust-policy plan must remain approved lifecycle, got %s", c.Lifecycle)
	}
}

func TestAWSRemediationCaseTrustPolicyHardeningSkipsNonIAMRolePlans(t *testing.T) {
	now := time.Date(2026, 6, 29, 10, 45, 0, 0, time.UTC)
	plan := AWSTrustPolicyHardeningPlan{
		PlanID:             "aws-trust-policy-hardening:s3-resource-policy",
		Severity:           "high",
		Status:             "action_required",
		Score:              81,
		Confidence:         0.91,
		AccountID:          "123456789012",
		Region:             "us-east-1",
		Service:            "s3",
		ResourceType:       "s3_bucket",
		ResourceNodeID:     "aws:resource:s3:::payments-data",
		ResourceARN:        "arn:aws:s3:::payments-data",
		ResourceLabel:      "payments-data",
		HardeningDirection: "add_org_or_source_condition",
		Summary:            "Runtime evidence supports hardening a resource policy.",
		ReadyForApply:      true,
		PublicPrincipal:    false,
		BreakageProjection: AWSTrustPolicyHardeningBreakageProjection{Level: "low", Rationale: "Runtime callers are known."},
		RollbackPlan:       AWSTrustPolicyHardeningRollbackPlan{Strategy: "restore_resource_policy", Steps: []string{"Restore the previous resource policy."}},
		VerificationPlan:   AWSTrustPolicyHardeningVerificationPlan{Strategy: "resource_policy_re_evaluate", Steps: []string{"Re-run trust-policy hardening."}},
		ImpactedNodes:      []string{"aws:resource:s3:::payments-data"},
		CreatedAt:          now,
		UpdatedAt:          now,
	}
	if c, ok := awsRemediationCaseFromTrustPolicyHardening(plan, now); ok {
		t.Fatalf("non-IAM role trust-policy plan must not become an IAM trust diff case: %+v", c)
	}
}

func TestAWSRemediationCaseLeastPrivilegeReviewStaysInReviewLifecycle(t *testing.T) {
	now := time.Date(2026, 6, 23, 10, 30, 0, 0, time.UTC)
	review := AWSLeastPrivilegeRecommendation{
		RecommendationID:   "least-priv:review-action-required",
		CalculationVersion: "aws-least-privilege-v1",
		Decision:           "review",
		Severity:           "high",
		Status:             "action_required",
		Score:              82,
		Confidence:         0.86,
		AccountID:          "123456789012",
		Region:             "us-east-1",
		IdentityNodeID:     "aws:identity:arn:aws:iam::123456789012:role/review-role",
		PrincipalARN:       "arn:aws:iam::123456789012:role/review-role",
		DisplayName:        "review-role",
		Rationale:          "Observed-without-declaration evidence raised status to action_required.",
		KeepActions:        []string{"s3:GetObject"},
		ImpactedNodes:      []string{"aws:identity:arn:aws:iam::123456789012:role/review-role"},
	}
	c, ok := awsRemediationCaseFromLeastPrivilege(review, now)
	if !ok {
		t.Fatalf("expected review case")
	}
	if c.Lifecycle == "approved" {
		t.Fatalf("review-decision case must never advance to approved lifecycle, got %s (status=%s, diff=%+v)", c.Lifecycle, c.Status, c.DiffIntent)
	}
	if c.Lifecycle != "in_review" {
		t.Fatalf("review-decision case with action_required status must stay in_review, got %s", c.Lifecycle)
	}
}

func TestAWSRemediationDiffIsExecutable(t *testing.T) {
	cases := []struct {
		name string
		diff AWSRemediationDiffIntent
		want bool
	}{
		{"executable iam_policy_diff", AWSRemediationDiffIntent{Kind: "iam_policy_diff"}, true},
		{"executable secret_rotation", AWSRemediationDiffIntent{Kind: "secret_rotation"}, true},
		{"manual review", AWSRemediationDiffIntent{Kind: "manual_review"}, false},
		{"no-op owner assignment", AWSRemediationDiffIntent{Kind: "owner_assignment", NoOp: true}, false},
		{"no-op fallthrough", AWSRemediationDiffIntent{Kind: "iam_policy_diff", NoOp: true}, false},
	}
	for _, tc := range cases {
		got := awsRemediationDiffIsExecutable(tc.diff)
		if got != tc.want {
			t.Fatalf("awsRemediationDiffIsExecutable(%s) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestAWSRemediationCaseLeastPrivilegeReviewIsNonExecutable(t *testing.T) {
	now := time.Date(2026, 6, 23, 10, 13, 0, 0, time.UTC)
	review := AWSLeastPrivilegeRecommendation{
		RecommendationID:   "least-priv:review-pending",
		CalculationVersion: "aws-least-privilege-v1",
		Decision:           "review",
		Severity:           "medium",
		Status:             "review",
		Score:              60,
		Confidence:         0.7,
		AccountID:          "123456789012",
		Region:             "us-east-1",
		IdentityNodeID:     "aws:identity:arn:aws:iam::123456789012:role/review-role",
		PrincipalARN:       "arn:aws:iam::123456789012:role/review-role",
		DisplayName:        "review-role",
		Rationale:          "Least-privilege evidence is inconclusive; manual review required.",
		KeepActions:        []string{"s3:GetObject"},
		ImpactedNodes:      []string{"aws:identity:arn:aws:iam::123456789012:role/review-role"},
	}
	c, ok := awsRemediationCaseFromLeastPrivilege(review, now)
	if !ok {
		t.Fatalf("expected review case to be emitted")
	}
	if c.DiffIntent.Kind != "manual_review" {
		t.Fatalf("review-decision case must route to manual_review diff kind, got %s", c.DiffIntent.Kind)
	}
	if !c.DiffIntent.NoOp {
		t.Fatalf("review-decision case must be NoOp until the upstream decision is conclusive: %+v", c.DiffIntent)
	}
	if c.DiffIntent.AfterRef != "" {
		t.Fatalf("review-decision case must not project a scoped after_ref, got %q", c.DiffIntent.AfterRef)
	}
	if c.RollbackPlan.Strategy != "manual_review" {
		t.Fatalf("review-decision case must use manual_review rollback, got %s", c.RollbackPlan.Strategy)
	}
	if c.VerificationPlan.Strategy != "manual_review" {
		t.Fatalf("review-decision case must use manual_review verification, got %s", c.VerificationPlan.Strategy)
	}
	if len(c.VerificationPlan.SuccessSignals) != 0 || len(c.VerificationPlan.FailureSignals) != 0 {
		t.Fatalf("review-decision verification must not advertise simulatable signals: %+v", c.VerificationPlan)
	}
}

func TestAWSRemediationCaseBlastRadiusDiffKindMatchesEmittedTokens(t *testing.T) {
	cases := []struct {
		riskType string
		want     string
	}{
		{"cross-account-secret-runtime-access", "iam_trust_diff"},
		{"cross-account-s3-runtime-access", "iam_trust_diff"},
		{"secret-runtime-access", "role_scope_diff"},
		{"agent-tool-path", "ai_agent_scope_change"},
		{"undeclared-agent-tool-path", "ai_agent_scope_change"},
		{"unused-agent-tool-path", "ai_agent_scope_change"},
		{"agent-tool-path-with-caveats", "ai_agent_scope_change"},
		{"s3-runtime-access", "role_scope_diff"},
		{"sensitive-s3-runtime-access", "role_scope_diff"},
	}
	for _, tc := range cases {
		got := awsRemediationBlastRadiusDiffKind(tc.riskType)
		if got != tc.want {
			t.Fatalf("awsRemediationBlastRadiusDiffKind(%q) = %q, want %q", tc.riskType, got, tc.want)
		}
	}
}

func TestAWSRemediationCaseEquivalenceDiffIntentMatchesEmittedTypes(t *testing.T) {
	cases := []struct {
		equivalenceType string
		wantKind        string
	}{
		{"kms_decrypt_secret_equivalence", "kms_grant_diff"},
		{"kms_live_grant_secret_equivalence", "kms_grant_diff"},
		{"agent_provider_key_equivalence", "secret_rotation"},
		{"workload_provider_key_equivalence", "secret_rotation"},
		{"admin_equivalent_secret_permission", "iam_policy_diff"},
		{"blast_radius_secret_equivalence", "iam_policy_diff"},
		{"runtime_secret_access_equivalence", "iam_policy_diff"},
		{"secret_read_policy_equivalence", "iam_policy_diff"},
	}
	for _, tc := range cases {
		diff := awsRemediationDiffIntentForEquivalence(AWSSecretPermissionEquivalenceFinding{
			EquivalenceType: tc.equivalenceType,
			SecretNodeID:    "aws:resource:secrets-manager-secret/test",
		})
		if diff.Kind != tc.wantKind {
			t.Fatalf("awsRemediationDiffIntentForEquivalence(%q) kind = %q, want %q", tc.equivalenceType, diff.Kind, tc.wantKind)
		}
	}
}

func TestAWSRemediationCaseDedupesAcrossSources(t *testing.T) {
	now := time.Date(2026, 6, 23, 10, 15, 0, 0, time.UTC)
	base := AWSRemediationCase{
		CaseID:             "aws-remediation-case:duplicate-key",
		CalculationVersion: awsRemediationCaseVersion,
		SourceType:         "ai_agent_risk",
		Score:              70,
		Severity:           "high",
		Lifecycle:          "in_review",
		ApprovalState:      "pending_owner",
		DiffIntent:         AWSRemediationDiffIntent{Kind: "ai_agent_scope_change", ReadOnlyProjection: true},
		SourceSignals:      []string{"ai_agent_identities"},
		Evidence:           []AWSRemediationCaseEvidence{{Source: "ai_agent_identities", EvidenceRef: "evidence://agent/a"}},
		ImpactedNodes:      []string{"aws:agent:1", "aws:identity:role:a"},
		ResourceNodeIDs:    []string{"aws:agent:1"},
		AuditTrail:         []AWSRemediationAuditEntry{{EventID: "1", Actor: "system", EventType: "proposed", OccurredAt: now}},
		CreatedAt:          now,
		UpdatedAt:          now,
	}
	incoming := base
	incoming.SourceType = "least_privilege"
	incoming.Score = 88
	incoming.Severity = "critical"
	incoming.Lifecycle = "approved"
	incoming.DiffIntent = AWSRemediationDiffIntent{Kind: "iam_policy_diff", ReadOnlyProjection: true}
	incoming.SourceSignals = []string{"least_privilege"}
	incoming.Evidence = []AWSRemediationCaseEvidence{{Source: "least_privilege", EvidenceRef: "evidence://least/a"}}
	incoming.AuditTrail = []AWSRemediationAuditEntry{{EventID: "2", Actor: "system", EventType: "proposed", OccurredAt: now}}

	deduped := awsRemediationCaseDedupe([]AWSRemediationCase{base, incoming})
	if len(deduped) != 1 {
		t.Fatalf("expected dedupe to keep one case, got %d", len(deduped))
	}
	merged := deduped[0]
	if merged.Score != 88 || merged.Severity != "critical" || merged.Lifecycle != "approved" || merged.DiffIntent.Kind != "iam_policy_diff" {
		t.Fatalf("higher-score case must win the merge, got %+v", merged)
	}
	if !awsStringSliceContains(merged.SourceSignals, "ai_agent_identities") || !awsStringSliceContains(merged.SourceSignals, "least_privilege") {
		t.Fatalf("merged signals must include both sources: %+v", merged.SourceSignals)
	}
	if len(merged.Evidence) != 2 || len(merged.AuditTrail) != 2 {
		t.Fatalf("merged evidence and audit trail must compose both sources, got evidence=%d audit=%d", len(merged.Evidence), len(merged.AuditTrail))
	}
}

func TestGetAWSRemediationCasesFailureStates(t *testing.T) {
	now := time.Date(2026, 6, 23, 10, 20, 0, 0, time.UTC)
	svc, ws := newRemediationCaseService(t, "project-remediation-case-states", now)

	denied, err := svc.GetAWSRemediationCases(defaultScopeContext(), ws, "project-remediation-case-states", AWSRemediationCaseRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "permission_denied",
	})
	if err != nil {
		t.Fatalf("permission denied: %v", err)
	}
	if denied.Status != "blocked" || len(denied.Cases) != 0 || len(denied.Diagnostics) == 0 || len(denied.FailureReasons) == 0 {
		t.Fatalf("permission denied must be explicit and suppress deterministic cases: %+v", denied)
	}

	empty, err := svc.GetAWSRemediationCases(defaultScopeContext(), ws, "project-remediation-case-states", AWSRemediationCaseRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "empty",
	})
	if err != nil {
		t.Fatalf("empty: %v", err)
	}
	if empty.Status != "degraded" || empty.Summary.TotalCases != 0 || len(empty.FailureReasons) == 0 {
		t.Fatalf("empty fixture should be explicit degraded no-evidence state: %+v", empty)
	}

	if _, err := svc.GetAWSRemediationCases(defaultScopeContext(), ws, "project-remediation-case-states", AWSRemediationCaseRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "garbage",
	}); err == nil {
		t.Fatalf("invalid fixture state should fail validation")
	}
}

func TestRouterAWSRemediationCases(t *testing.T) {
	now := time.Date(2026, 6, 23, 10, 25, 0, 0, time.UTC)
	svc, _ := newRemediationCaseService(t, "project-remediation-case-route", now)
	r := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{})

	resp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-remediation-case-route/aws/remediation-cases?connector_id=aws-prod&fixture_state=success&source_type=ai_agent_risk", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	var body struct {
		Cases AWSRemediationCaseResult `json:"cases"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Cases.CurrentIssueRef != "#1529" || body.Cases.AppliedFilters["source_type"] != "ai-agent-risk" {
		t.Fatalf("unexpected route payload: %+v", body.Cases)
	}
	if len(body.Cases.Cases) == 0 {
		t.Fatalf("expected ai_agent_risk-sourced cases via the route: %+v", body.Cases)
	}
}
