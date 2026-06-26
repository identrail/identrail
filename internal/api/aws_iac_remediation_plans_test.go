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

func newIaCRemediationService(t *testing.T, project string, now time.Time) (*Service, string) {
	t.Helper()
	return newBlastRadiusService(t, project, now)
}

func TestGetAWSIaCRemediationPlansBuildsContract(t *testing.T) {
	now := time.Date(2026, 6, 26, 10, 0, 0, 0, time.UTC)
	svc, ws := newIaCRemediationService(t, "project-iac-remediation", now)

	result, err := svc.GetAWSIaCRemediationPlans(defaultScopeContext(), ws, "project-iac-remediation", AWSIaCRemediationRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
	})
	if err != nil {
		t.Fatalf("get iac remediation plans: %v", err)
	}
	if result.CurrentIssueRef != "#1535" || result.Version != awsIaCRemediationVersion {
		t.Fatalf("unexpected contract metadata: %+v", result)
	}
	if len(result.Plans) == 0 || result.Summary.TotalPlans != len(result.Plans) {
		t.Fatalf("expected iac remediation plans and matching summary: %+v", result)
	}
	if result.Summary.RelationshipCount != len(result.Relationships) {
		t.Fatalf("expected relationship count to match: summary=%+v relationships=%+v", result.Summary, result.Relationships)
	}
	if len(result.Caveats) == 0 || len(result.CoverageGaps) == 0 {
		t.Fatalf("expected caveats and coverage gaps: %+v", result)
	}
	for i := 1; i < len(result.Plans); i++ {
		if result.Plans[i-1].Score < result.Plans[i].Score {
			t.Fatalf("plans are not ranked by descending score: %+v", result.Plans)
		}
	}
	sawIAM := false
	sawTrust := false
	for _, plan := range result.Plans {
		if plan.PlanID == "" || plan.CalculationVersion != awsIaCRemediationVersion || plan.SourceArtifactID == "" {
			t.Fatalf("plan missing stable metadata: %+v", plan)
		}
		if !plan.ReadOnlyProjection {
			t.Fatalf("plan must be a read-only projection: %+v", plan)
		}
		if plan.IaCTarget == "" || plan.ChangeKind == "" {
			t.Fatalf("plan missing IaC target or change kind: %+v", plan)
		}
		if len(plan.FileChanges) == 0 || len(plan.ValidationHints) == 0 || len(plan.CloudVerification) == 0 {
			t.Fatalf("plan missing file changes, validation, or verification: %+v", plan)
		}
		if plan.RollbackPlan.Strategy == "" || plan.VerificationPlan.Strategy == "" {
			t.Fatalf("plan missing rollback or verification plan: %+v", plan)
		}
		if plan.PRNotes.Title == "" || plan.PRNotes.Summary == "" {
			t.Fatalf("plan missing PR notes: %+v", plan.PRNotes)
		}
		if plan.EvidenceBoundary != awsIaCRemediationEvidenceBoundary() {
			t.Fatalf("plan crossed evidence boundary: %+v", plan)
		}
		if plan.ChangeKind == awsIaCChangeKindIAMPolicyDiff {
			sawIAM = true
		}
		if plan.ChangeKind == awsIaCChangeKindTrustPolicyHardened {
			sawTrust = true
		}
	}
	if !sawIAM && !sawTrust {
		t.Fatalf("expected at least one IAM-diff or trust-hardening plan in the contract output")
	}

	serialized, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	lower := strings.ToLower(string(serialized))
	for _, forbidden := range []string{"\"secret_access_key\"", "\"private_key\"", "\"policy_document_body\"", "\"rendered_policy\""} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("plan serialized forbidden sensitive payload marker %q", forbidden)
		}
	}
}

func TestGetAWSIaCRemediationPlansAppliesFilters(t *testing.T) {
	now := time.Date(2026, 6, 26, 10, 15, 0, 0, time.UTC)
	svc, ws := newIaCRemediationService(t, "project-iac-remediation-filters", now)

	iamOnly, err := svc.GetAWSIaCRemediationPlans(defaultScopeContext(), ws, "project-iac-remediation-filters", AWSIaCRemediationRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
		ChangeKind:   awsIaCChangeKindIAMPolicyDiff,
	})
	if err != nil {
		t.Fatalf("change_kind filter: %v", err)
	}
	if iamOnly.AppliedFilters["change_kind"] != strings.ReplaceAll(awsIaCChangeKindIAMPolicyDiff, "_", "-") {
		t.Fatalf("expected applied change_kind filter, got %+v", iamOnly.AppliedFilters)
	}
	for _, plan := range iamOnly.Plans {
		if plan.ChangeKind != awsIaCChangeKindIAMPolicyDiff {
			t.Fatalf("change_kind filter leaked %s plan: %+v", plan.ChangeKind, plan)
		}
	}

	terraformOnly, err := svc.GetAWSIaCRemediationPlans(defaultScopeContext(), ws, "project-iac-remediation-filters", AWSIaCRemediationRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
		IaCTarget:    awsIaCTargetTerraform,
		Search:       "terraform validate",
	})
	if err != nil {
		t.Fatalf("iac_target filter: %v", err)
	}
	if terraformOnly.AppliedFilters["iac_target"] != awsIaCTargetTerraform {
		t.Fatalf("expected applied iac_target filter, got %+v", terraformOnly.AppliedFilters)
	}
	for _, plan := range terraformOnly.Plans {
		if plan.IaCTarget != awsIaCTargetTerraform {
			t.Fatalf("iac_target filter leaked %s plan: %+v", plan.IaCTarget, plan)
		}
	}
}

func TestFilterAWSIaCRemediationPlansNormalizesReadyForApplyAliases(t *testing.T) {
	plans := []AWSIaCRemediationPlan{
		{
			PlanID:        "ready",
			AccountID:     "123456789012",
			Region:        "us-east-1",
			ChangeKind:    awsIaCChangeKindIAMPolicyDiff,
			IaCTarget:     awsIaCTargetTerraform,
			ReadyForApply: true,
		},
		{
			PlanID:        "not-ready",
			AccountID:     "123456789012",
			Region:        "us-east-1",
			ChangeKind:    awsIaCChangeKindTrustPolicyHardened,
			IaCTarget:     awsIaCTargetTerraform,
			ReadyForApply: false,
		},
	}

	ready, readyApplied := filterAWSIaCRemediationPlans(plans, AWSIaCRemediationRequest{ReadyForApply: "yes"})
	if readyApplied["ready_for_apply"] != "yes" || len(ready) != 1 || ready[0].PlanID != "ready" {
		t.Fatalf("expected ready_for_apply=yes to match ready plans, got applied=%+v plans=%+v", readyApplied, ready)
	}

	notReady, notReadyApplied := filterAWSIaCRemediationPlans(plans, AWSIaCRemediationRequest{ReadyForApply: "no"})
	if notReadyApplied["ready_for_apply"] != "no" || len(notReady) != 1 || notReady[0].PlanID != "not-ready" {
		t.Fatalf("expected ready_for_apply=no to match non-ready plans, got applied=%+v plans=%+v", notReadyApplied, notReady)
	}
}

func TestAWSIaCRemediationFileChangesUseTargetSpecificPaths(t *testing.T) {
	diff := AWSIAMPolicyDiff{
		DiffID:       "aws-iam-policy-diff:test",
		Service:      "lambda",
		ResourceARN:  "arn:aws:lambda:us-east-1:123456789012:function/orders",
		Decision:     "remove",
		IdentityName: "orders-ci",
		KeptActions:  []string{"s3:GetObject"},
	}

	for _, target := range []string{awsIaCTargetTerraform, awsIaCTargetCloudFormation, awsIaCTargetCDK, awsIaCTargetPolicyAsCode} {
		files := awsIaCFileChangesForIAMDiff(diff, target, "orders-ci", "evidence://orders-ci")
		if len(files) < 2 {
			t.Fatalf("%s: expected at least two file changes, got %+v", target, files)
		}
		root := awsIaCDirectoryForTarget(target)
		if !strings.HasPrefix(files[0].Path, root+"/") || !strings.HasPrefix(files[1].Path, root+"/") {
			t.Fatalf("%s: file path missing target directory: %+v", target, files)
		}
		if files[0].BeforeRef == "" || files[0].AfterRef == "" {
			t.Fatalf("%s: file change missing before/after refs: %+v", target, files[0])
		}
	}
}

func TestAWSIaCReadyForApplyHonorsUpstreamGates(t *testing.T) {
	hardening := AWSTrustPolicyHardeningPlan{
		PlanID:             "aws-trust-policy-hardening:1",
		HardeningDirection: "narrow_principal",
		PublicPrincipal:    true,
		ReadyForApply:      true,
	}
	plan, ok := awsIaCRemediationPlanFromTrustHardening(hardening, time.Now().UTC())
	if !ok {
		t.Fatalf("expected plan from trust hardening")
	}
	if plan.ReadyForApply {
		t.Fatalf("expected public-principal gate to block ready_for_apply: %+v", plan.ReadinessGates)
	}
	if blocked := false; func() bool {
		for _, gate := range plan.ReadinessGates {
			if gate.Name == "public_principal_review" && gate.Status == "blocked" {
				blocked = true
			}
		}
		return blocked
	}() != true {
		t.Fatalf("expected public_principal_review gate to be present and blocked: %+v", plan.ReadinessGates)
	}
}

func TestGetAWSIaCRemediationPlansFailureStates(t *testing.T) {
	now := time.Date(2026, 6, 26, 10, 30, 0, 0, time.UTC)
	svc, ws := newIaCRemediationService(t, "project-iac-remediation-states", now)

	denied, err := svc.GetAWSIaCRemediationPlans(defaultScopeContext(), ws, "project-iac-remediation-states", AWSIaCRemediationRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "permission_denied",
	})
	if err != nil {
		t.Fatalf("permission denied: %v", err)
	}
	if denied.Status != "blocked" || len(denied.Plans) != 0 {
		t.Fatalf("permission denied must be explicit and suppress plans: %+v", denied)
	}

	empty, err := svc.GetAWSIaCRemediationPlans(defaultScopeContext(), ws, "project-iac-remediation-states", AWSIaCRemediationRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "empty",
	})
	if err != nil {
		t.Fatalf("empty: %v", err)
	}
	if empty.Status == "blocked" {
		t.Fatalf("empty fixture should not produce a blocked status: %+v", empty)
	}

	if _, err := svc.GetAWSIaCRemediationPlans(defaultScopeContext(), ws, "project-iac-remediation-states", AWSIaCRemediationRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "garbage",
	}); err == nil {
		t.Fatalf("invalid fixture state should fail validation")
	}
}

func TestRouterAWSIaCRemediationPlans(t *testing.T) {
	now := time.Date(2026, 6, 26, 10, 45, 0, 0, time.UTC)
	svc, _ := newIaCRemediationService(t, "project-iac-remediation-route", now)
	r := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{})

	resp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-iac-remediation-route/aws/iac-remediation-plans?connector_id=aws-prod&fixture_state=success&iac_target=terraform", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	var body struct {
		Plans AWSIaCRemediationResult `json:"plans"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Plans.CurrentIssueRef != "#1535" || body.Plans.AppliedFilters["iac_target"] != "terraform" {
		t.Fatalf("unexpected route payload: %+v", body.Plans)
	}
}
