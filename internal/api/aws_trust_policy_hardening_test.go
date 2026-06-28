package api

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/telemetry"
	"go.uber.org/zap"
)

func newTrustPolicyHardeningService(t *testing.T, project string, now time.Time) (*Service, string) {
	t.Helper()
	return newBlastRadiusService(t, project, now)
}

func TestGetAWSTrustPolicyHardeningPlansBuildsContract(t *testing.T) {
	now := time.Date(2026, 6, 24, 10, 0, 0, 0, time.UTC)
	svc, ws := newTrustPolicyHardeningService(t, "project-trust-policy-hardening", now)

	result, err := svc.GetAWSTrustPolicyHardeningPlans(defaultScopeContext(), ws, "project-trust-policy-hardening", AWSTrustPolicyHardeningRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
	})
	if err != nil {
		t.Fatalf("get trust policy hardening: %v", err)
	}
	if result.CurrentIssueRef != "#1531" || result.Version != awsTrustPolicyHardeningVersion || result.Status != "ready" {
		t.Fatalf("unexpected contract metadata: %+v", result)
	}
	if len(result.Plans) == 0 || result.Summary.TotalPlans != len(result.Plans) {
		t.Fatalf("expected plan summary to match payload: %+v", result.Summary)
	}
	if len(result.Caveats) == 0 || len(result.CoverageGaps) == 0 {
		t.Fatalf("expected caveats and coverage gaps: %+v", result)
	}
	readyIAMRolePlan := false
	for i := 1; i < len(result.Plans); i++ {
		if result.Plans[i-1].Score < result.Plans[i].Score {
			t.Fatalf("plans are not ranked by descending score: %+v", result.Plans)
		}
	}
	for _, p := range result.Plans {
		if p.PlanID == "" || p.CalculationVersion != awsTrustPolicyHardeningVersion || p.SourceFindingID == "" {
			t.Fatalf("plan missing stable metadata: %+v", p)
		}
		if p.FindingType == "" || p.HardeningDirection == "" || p.Severity == "" || p.Status == "" || p.Title == "" {
			t.Fatalf("plan missing classification fields: %+v", p)
		}
		if !p.ReadOnlyProjection {
			t.Fatalf("plan must be a read-only projection: %+v", p)
		}
		if len(p.StatementSnippets) == 0 {
			t.Fatalf("plan missing statement snippets: %+v", p)
		}
		if p.BreakageProjection.Level == "" || p.BreakageProjection.Rationale == "" {
			t.Fatalf("plan missing breakage projection: %+v", p.BreakageProjection)
		}
		if p.RollbackPlan.Strategy == "" || len(p.RollbackPlan.Steps) == 0 {
			t.Fatalf("plan missing rollback plan: %+v", p.RollbackPlan)
		}
		if p.VerificationPlan.Strategy == "" || len(p.VerificationPlan.Steps) == 0 {
			t.Fatalf("plan missing verification plan: %+v", p.VerificationPlan)
		}
		if p.EvidenceBoundary != awsTrustPolicyHardeningEvidenceBoundary() {
			t.Fatalf("plan crossed evidence boundary: %+v", p)
		}
		if p.ReadyForApply && normalizeAWSRuntimeEventFilterToken(p.ResourceType) == "iam-role" {
			readyIAMRolePlan = true
		}
	}
	if !readyIAMRolePlan {
		t.Fatalf("success fixture must include an analyzer-backed runtime IAM role plan ready for apply: %+v", result.Plans)
	}
}

func TestGetAWSTrustPolicyHardeningPlansAppliesFilters(t *testing.T) {
	now := time.Date(2026, 6, 24, 10, 5, 0, 0, time.UTC)
	svc, ws := newTrustPolicyHardeningService(t, "project-trust-policy-filters", now)

	highOnly, err := svc.GetAWSTrustPolicyHardeningPlans(defaultScopeContext(), ws, "project-trust-policy-filters", AWSTrustPolicyHardeningRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
		Severity:     "high",
	})
	if err != nil {
		t.Fatalf("severity filter: %v", err)
	}
	for _, p := range highOnly.Plans {
		if p.Severity != "high" {
			t.Fatalf("severity filter leaked %s plan: %+v", p.Severity, p)
		}
	}
	if highOnly.AppliedFilters["severity"] != "high" {
		t.Fatalf("expected applied severity filter, got %+v", highOnly.AppliedFilters)
	}
}

func TestAWSTrustPolicyHardeningPlanFromFinding(t *testing.T) {
	now := time.Date(2026, 6, 24, 10, 10, 0, 0, time.UTC)

	public := AWSCrossAccountTrustFinding{
		FindingID:            "aws-cross-account-trust:public-bucket",
		CalculationVersion:   "aws-cross-account-trust-engine-v1",
		FindingType:          "public_resource_trust",
		Severity:             "critical",
		Status:               "action_required",
		Score:                92,
		Confidence:           0.9,
		AccountID:            "123456789012",
		Region:               "us-east-1",
		Service:              "s3",
		ResourceType:         "s3_bucket",
		ResourceARN:          "arn:aws:s3:::public-bucket",
		ResourceNodeID:       "aws:resource:s3-bucket/public-bucket",
		ResourceLabel:        "public-bucket",
		ExternalPrincipalARN: "",
		PublicPrincipal:      true,
		HasCondition:         false,
		ConditionKeys:        nil,
		Rationale:            "Bucket policy allows *.",
		HardeningDirection:   "",
	}
	p, ok := awsTrustPolicyHardeningPlanFromFinding(public, now)
	if !ok {
		t.Fatalf("expected plan for public principal")
	}
	if p.HardeningDirection != "remove_public_principal" {
		t.Fatalf("expected remove_public_principal direction, got %s", p.HardeningDirection)
	}
	if !p.PrincipalChange.PublicPrincipalRemoved {
		t.Fatalf("public principal change must mark PublicPrincipalRemoved: %+v", p.PrincipalChange)
	}
	if len(p.PrincipalChange.AfterPrincipals) == 0 {
		t.Fatalf("public principal change must propose an explicit after_principal: %+v", p.PrincipalChange)
	}
	if p.ReadyForApply {
		t.Fatalf("public principal plan must not be ready_for_apply: %+v", p)
	}
	if p.BreakageProjection.Level != "high" {
		t.Fatalf("public principal plan must project high breakage, got %s", p.BreakageProjection.Level)
	}

	proseDirection := AWSCrossAccountTrustFinding{
		FindingID:                 "aws-cross-account-trust:prose-direction",
		FindingType:               "runtime_cross_account_assumption",
		Status:                    "action_required",
		Severity:                  "high",
		ExternalPrincipalAccount:  "555555555555",
		ExternalPrincipalARN:      "arn:aws:iam::555555555555:role/billing-runner",
		TrustedWithinOrganization: false,
		HasCondition:              true,
		RuntimeObserved:           true,
		AnalyzerBacked:            true,
		HardeningDirection:        "Review trust policy principal scope, source identity, external ID, and session-tag requirements for this observed cross-account assumption.",
		Rationale:                 "Runtime AssumeRole observed without sts:ExternalId.",
		ResourceType:              "iam_role",
		ResourceARN:               "arn:aws:iam::123456789012:role/payments-cross-account",
		ResourceNodeID:            "aws:identity:arn:aws:iam::123456789012:role/payments-cross-account",
	}
	prosePlan, ok := awsTrustPolicyHardeningPlanFromFinding(proseDirection, now)
	if !ok {
		t.Fatalf("expected plan for prose direction fallback case")
	}
	if prosePlan.HardeningDirection != "scope_to_known_external_principal" {
		t.Fatalf("expected derived enum direction for prose input, got %s", prosePlan.HardeningDirection)
	}

	knownCaller := AWSCrossAccountTrustFinding{
		FindingID:                 "aws-cross-account-trust:known-caller",
		CalculationVersion:        "aws-cross-account-trust-engine-v1",
		FindingType:               "runtime_cross_account_assumption",
		Severity:                  "high",
		Status:                    "action_required",
		Score:                     78,
		Confidence:                0.88,
		AccountID:                 "123456789012",
		Region:                    "us-east-1",
		Service:                   "iam",
		ResourceType:              "iam_role",
		ResourceARN:               "arn:aws:iam::123456789012:role/payments-cross-account",
		ResourceNodeID:            "aws:identity:arn:aws:iam::123456789012:role/payments-cross-account",
		ResourceLabel:             "payments-cross-account",
		ExternalPrincipalARN:      "arn:aws:iam::555555555555:role/billing-runner",
		ExternalPrincipalAccount:  "555555555555",
		TrustedWithinOrganization: false,
		HasCondition:              false,
		RuntimeObserved:           true,
		AnalyzerBacked:            true,
		Rationale:                 "Runtime AssumeRole observed without sts:ExternalId.",
	}
	plan, ok := awsTrustPolicyHardeningPlanFromFinding(knownCaller, now)
	if !ok {
		t.Fatalf("expected plan for known caller finding")
	}
	if plan.PublicPrincipal {
		t.Fatalf("known-caller plan must not be flagged public")
	}
	if plan.BreakageProjection.Level != "low" {
		t.Fatalf("runtime + analyzer-backed plan should project low breakage, got %s", plan.BreakageProjection.Level)
	}
	if !plan.ReadyForApply {
		t.Fatalf("known-caller plan with conditions and low breakage must be ready_for_apply: %+v", plan)
	}
	var sawExternalID, sawSourceIdentity, sawAccount bool
	for _, condition := range plan.ConditionRecommendations {
		switch condition.Key {
		case "sts:ExternalId":
			sawExternalID = true
		case "aws:SourceIdentity":
			sawSourceIdentity = true
		case "aws:PrincipalAccount":
			sawAccount = true
		}
	}
	if !sawExternalID || !sawSourceIdentity || !sawAccount {
		t.Fatalf("runtime_cross_account_assumption plan must recommend sts:ExternalId, aws:SourceIdentity, and aws:PrincipalAccount conditions: %+v", plan.ConditionRecommendations)
	}
	if len(plan.AffectedCallers) != 1 || plan.AffectedCallers[0].PrincipalARN != knownCaller.ExternalPrincipalARN {
		t.Fatalf("expected one affected caller equal to the external principal: %+v", plan.AffectedCallers)
	}

	unknown := knownCaller
	unknown.FindingID = "aws-cross-account-trust:unknown"
	unknown.RuntimeObserved = false
	unknown.AnalyzerBacked = false
	unknownPlan, ok := awsTrustPolicyHardeningPlanFromFinding(unknown, now)
	if !ok {
		t.Fatalf("expected plan for unknown-caller finding")
	}
	if unknownPlan.BreakageProjection.Level != "unknown" {
		t.Fatalf("no runtime/analyzer evidence must project unknown breakage, got %s", unknownPlan.BreakageProjection.Level)
	}
	if unknownPlan.ReadyForApply {
		t.Fatalf("unknown-breakage plan must not be ready_for_apply: %+v", unknownPlan)
	}

	existingCondition := knownCaller
	existingCondition.FindingID = "aws-cross-account-trust:existing-condition"
	existingCondition.ConditionKeys = []string{"sts:ExternalId", "aws:SourceIdentity", "aws:PrincipalAccount"}
	existingPlan, ok := awsTrustPolicyHardeningPlanFromFinding(existingCondition, now)
	if !ok {
		t.Fatalf("expected plan for existing-condition finding")
	}
	for _, condition := range existingPlan.ConditionRecommendations {
		switch condition.Key {
		case "sts:ExternalId", "aws:SourceIdentity", "aws:PrincipalAccount":
			t.Fatalf("planner should not re-recommend an already-present condition: %+v", condition)
		}
	}
}

func TestAWSTrustPolicyHardeningSearchMatchesPlanDetails(t *testing.T) {
	plan := AWSTrustPolicyHardeningPlan{
		PlanID: "aws-trust-policy-hardening:search-test",
		Title:  "Harden trust on payments-cross-account",
		ConditionRecommendations: []AWSTrustPolicyConditionRecommendation{{
			Operator:  "StringEquals",
			Key:       "sts:ExternalId",
			Value:     "<owner-approved-external-id>",
			Rationale: "Require sts:ExternalId for cross-account assumption.",
		}},
		StatementSnippets: []AWSTrustPolicyStatementSnippet{{
			ConditionBefore: []string{"aws:SourceVpce"},
			ConditionAfter:  []string{"aws:SourceVpce", "sts:ExternalId"},
		}},
		BreakageProjection: AWSTrustPolicyHardeningBreakageProjection{
			Signals: []string{"runtime_observed:true"},
		},
		RollbackPlan: AWSTrustPolicyHardeningRollbackPlan{
			Steps:       []string{"Restore the previous trust statement from the captured before_ref."},
			EvidenceRef: "evidence://trust/known",
		},
		VerificationPlan: AWSTrustPolicyHardeningVerificationPlan{
			Steps:          []string{"Re-run cross-account-trust and confirm the finding resolves."},
			SuccessSignals: []string{"cross_account_trust:finding-resolved"},
			FailureSignals: []string{"agent_runtime_access:assume-role-denied-unexpected"},
		},
		AffectedCallers: []AWSTrustPolicyAffectedCaller{{PrincipalARN: "arn:aws:iam::555555555555:role/billing-runner"}},
	}
	cases := []struct {
		name   string
		needle string
	}{
		{"condition key", "sts:ExternalId"},
		{"rollback step", "before_ref"},
		{"verification success signal", "finding-resolved"},
		{"verification failure signal", "assume-role-denied-unexpected"},
		{"breakage signal", "runtime_observed:true"},
		{"affected caller", "billing-runner"},
	}
	for _, tc := range cases {
		if !awsTrustPolicyHardeningSearchMatch(plan, tc.needle) {
			t.Fatalf("search did not match %s needle %q", tc.name, tc.needle)
		}
	}
}

func TestGetAWSTrustPolicyHardeningPlansFailureStates(t *testing.T) {
	now := time.Date(2026, 6, 24, 10, 20, 0, 0, time.UTC)
	svc, ws := newTrustPolicyHardeningService(t, "project-trust-policy-states", now)

	denied, err := svc.GetAWSTrustPolicyHardeningPlans(defaultScopeContext(), ws, "project-trust-policy-states", AWSTrustPolicyHardeningRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "permission_denied",
	})
	if err != nil {
		t.Fatalf("permission denied: %v", err)
	}
	if denied.Status != "blocked" || len(denied.Plans) != 0 || len(denied.Diagnostics) == 0 || len(denied.FailureReasons) == 0 {
		t.Fatalf("permission denied must be explicit and suppress plans: %+v", denied)
	}

	empty, err := svc.GetAWSTrustPolicyHardeningPlans(defaultScopeContext(), ws, "project-trust-policy-states", AWSTrustPolicyHardeningRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "empty",
	})
	if err != nil {
		t.Fatalf("empty: %v", err)
	}
	if empty.Summary.TotalPlans != 0 || len(empty.FailureReasons) == 0 {
		t.Fatalf("empty fixture should produce no plans and explicit failure reasons: %+v", empty)
	}
	if empty.Status == "blocked" {
		t.Fatalf("empty fixture should not be marked blocked, got %s", empty.Status)
	}

	if _, err := svc.GetAWSTrustPolicyHardeningPlans(defaultScopeContext(), ws, "project-trust-policy-states", AWSTrustPolicyHardeningRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "garbage",
	}); err == nil {
		t.Fatalf("invalid fixture state should fail validation")
	}
}

func TestRouterAWSTrustPolicyHardening(t *testing.T) {
	now := time.Date(2026, 6, 24, 10, 25, 0, 0, time.UTC)
	svc, _ := newTrustPolicyHardeningService(t, "project-trust-policy-route", now)
	r := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{})

	resp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-trust-policy-route/aws/trust-policy-hardening?connector_id=aws-prod&fixture_state=success&severity=high", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	var body struct {
		Plans AWSTrustPolicyHardeningResult `json:"plans"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Plans.CurrentIssueRef != "#1531" || body.Plans.AppliedFilters["severity"] != "high" {
		t.Fatalf("unexpected route payload: %+v", body.Plans)
	}
}
