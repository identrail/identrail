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

func newTrustPolicyHardeningExecutorService(t *testing.T, project string, now time.Time) (*Service, string) {
	t.Helper()
	return newBlastRadiusService(t, project, now)
}

func TestGetAWSTrustPolicyHardeningExecutorBuildsContract(t *testing.T) {
	now := time.Date(2026, 6, 29, 10, 0, 0, 0, time.UTC)
	svc, ws := newTrustPolicyHardeningExecutorService(t, "project-trust-hardening-executor", now)

	result, err := svc.GetAWSTrustPolicyHardeningExecutor(defaultScopeContext(), ws, "project-trust-hardening-executor", AWSTrustPolicyHardeningExecutorRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
	})
	if err != nil {
		t.Fatalf("get trust-policy hardening executor: %v", err)
	}
	if result.CurrentIssueRef != "#1539" || result.Version != awsTrustPolicyHardeningExecutorVersion {
		t.Fatalf("unexpected contract metadata: %+v", result)
	}
	if result.Summary.RelationshipCount != len(result.Relationships) {
		t.Fatalf("expected relationship count to match: summary=%+v relationships=%+v", result.Summary, result.Relationships)
	}
	if len(result.Caveats) == 0 || len(result.CoverageGaps) == 0 {
		t.Fatalf("expected caveats and coverage gaps: %+v", result)
	}
	for i := 1; i < len(result.Entries); i++ {
		if result.Entries[i-1].Score < result.Entries[i].Score {
			t.Fatalf("entries are not ranked by descending score: %+v", result.Entries)
		}
	}
	for _, entry := range result.Entries {
		if entry.ExecutionID == "" || entry.CalculationVersion != awsTrustPolicyHardeningExecutorVersion {
			t.Fatalf("entry missing stable metadata: %+v", entry)
		}
		if entry.DryRunID == "" || entry.PlanID == "" {
			t.Fatalf("entry missing source IDs: %+v", entry)
		}
		if !entry.ReadOnlyProjection {
			t.Fatalf("entry must remain a read-only projection: %+v", entry)
		}
		if entry.IntendedAPICall.Service != "iam" || entry.IntendedAPICall.Operation != "UpdateAssumeRolePolicy" {
			t.Fatalf("entry must project iam:UpdateAssumeRolePolicy: %+v", entry.IntendedAPICall)
		}
		if len(entry.Preconditions) == 0 {
			t.Fatalf("entry missing preconditions: %+v", entry)
		}
		if entry.PolicySimulation.SimulationRef == "" {
			t.Fatalf("entry missing policy simulation: %+v", entry.PolicySimulation)
		}
		if entry.EvidenceBoundary != awsTrustPolicyHardeningExecutorEvidenceBoundary() {
			t.Fatalf("entry crossed evidence boundary: %+v", entry)
		}
		if entry.State == "" {
			t.Fatalf("entry missing state: %+v", entry)
		}
	}

	serialized, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	lower := strings.ToLower(string(serialized))
	for _, forbidden := range []string{"\"secret_access_key\"", "\"private_key\"", "\"policy_document_body\"", "\"rendered_policy\""} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("trust-policy executor serialized forbidden sensitive payload marker %q", forbidden)
		}
	}
}

func TestAWSTrustPolicyHardeningExecutorAdmitsOnlyTrustPolicyDryRuns(t *testing.T) {
	cases := []struct {
		name      string
		entry     AWSRemediationDryRunEntry
		wantAdmit bool
	}{
		{
			name: "trust_policy_hardening with iam_trust_diff is admitted",
			entry: AWSRemediationDryRunEntry{
				SourceType: "trust_policy_hardening",
				DiffIntent: AWSRemediationDiffIntent{Kind: "iam_trust_diff"},
			},
			wantAdmit: true,
		},
		{
			name: "trust_policy_hardening with iac_trust_policy_pr is admitted",
			entry: AWSRemediationDryRunEntry{
				SourceType: "trust_policy_hardening",
				DiffIntent: AWSRemediationDiffIntent{Kind: "iac_trust_policy_pr"},
			},
			wantAdmit: true,
		},
		{
			name: "trust_policy_hardening with iam_policy_diff is excluded",
			entry: AWSRemediationDryRunEntry{
				SourceType: "trust_policy_hardening",
				DiffIntent: AWSRemediationDiffIntent{Kind: "iam_policy_diff"},
			},
			wantAdmit: false,
		},
		{
			name: "blast_radius with iam_trust_diff is excluded",
			entry: AWSRemediationDryRunEntry{
				SourceType: "blast_radius",
				DiffIntent: AWSRemediationDiffIntent{Kind: "iam_trust_diff"},
			},
			wantAdmit: false,
		},
		{
			name: "noop trust-policy diff is excluded",
			entry: AWSRemediationDryRunEntry{
				SourceType: "trust_policy_hardening",
				DiffIntent: AWSRemediationDiffIntent{Kind: "manual_review", NoOp: true},
			},
			wantAdmit: false,
		},
	}
	for _, tc := range cases {
		got := awsTrustPolicyHardeningExecutorAdmits(tc.entry)
		if got != tc.wantAdmit {
			t.Fatalf("%s: admits=%v want=%v", tc.name, got, tc.wantAdmit)
		}
	}
}

func TestAWSTrustPolicyHardeningExecutorStateHonorsPreconditions(t *testing.T) {
	now := time.Date(2026, 6, 29, 11, 0, 0, 0, time.UTC)
	ready := AWSTrustPolicyHardeningPlan{
		PlanID:             "plan-ready",
		HardeningDirection: "add_condition",
		ReadyForApply:      true,
		PublicPrincipal:    false,
		BreakageProjection: AWSTrustPolicyHardeningBreakageProjection{Level: "low"},
	}
	entry := AWSRemediationDryRunEntry{
		DryRunID:         "dr-ready",
		CaseID:           "case-ready",
		SourceType:       "trust_policy_hardening",
		SourceArtifactID: "plan-ready",
		IdempotencyKey:   "idk",
		Outcome:          awsRemediationDryRunOutcomeWouldSucceed,
		ReadyForApply:    true,
		DiffIntent:       AWSRemediationDiffIntent{Kind: "iam_trust_diff"},
	}
	out := awsTrustPolicyHardeningExecutorEntryFromDryRun(entry, ready, now)
	if out.State != awsTrustPolicyHardeningExecutorStateProjected || !out.ReadyForLiveApply {
		t.Fatalf("ready entry must reach projected/ready_for_live_apply, got %+v", out)
	}

	public := ready
	public.PublicPrincipal = true
	out = awsTrustPolicyHardeningExecutorEntryFromDryRun(entry, public, now)
	if out.State != awsTrustPolicyHardeningExecutorStateBlocked {
		t.Fatalf("public principal must block live apply, got state=%q", out.State)
	}

	planNotReady := ready
	planNotReady.ReadyForApply = false
	out = awsTrustPolicyHardeningExecutorEntryFromDryRun(entry, planNotReady, now)
	if out.State != awsTrustPolicyHardeningExecutorStatePreconditionFailed {
		t.Fatalf("planner not ready must surface precondition_failed, got state=%q", out.State)
	}

	highBreakage := ready
	highBreakage.BreakageProjection.Level = "high"
	out = awsTrustPolicyHardeningExecutorEntryFromDryRun(entry, highBreakage, now)
	if out.State != awsTrustPolicyHardeningExecutorStatePreconditionFailed {
		t.Fatalf("high breakage must surface precondition_failed, got state=%q", out.State)
	}

	killSwitch := entry
	killSwitch.KillSwitchEngaged = true
	out = awsTrustPolicyHardeningExecutorEntryFromDryRun(killSwitch, ready, now)
	if out.State != awsTrustPolicyHardeningExecutorStateBlocked || out.ReadyForLiveApply {
		t.Fatalf("kill switch must block, got %+v", out)
	}
}

func TestFilterAWSTrustPolicyHardeningExecutorEntriesAppliesFilters(t *testing.T) {
	entries := []AWSTrustPolicyHardeningExecutorEntry{
		{
			ExecutionID:        "exec-narrow",
			DryRunID:           "dr-1",
			CaseID:             "case-1",
			PlanID:             "plan-narrow",
			AccountID:          "123456789012",
			Region:             "us-east-1",
			State:              awsTrustPolicyHardeningExecutorStateProjected,
			Severity:           "high",
			HardeningDirection: "narrow_principal",
		},
		{
			ExecutionID:        "exec-condition",
			DryRunID:           "dr-2",
			CaseID:             "case-2",
			PlanID:             "plan-condition",
			AccountID:          "123456789012",
			Region:             "us-east-1",
			State:              awsTrustPolicyHardeningExecutorStateBlocked,
			Severity:           "critical",
			HardeningDirection: "add_condition",
		},
	}

	projected, applied := filterAWSTrustPolicyHardeningExecutorEntries(entries, AWSTrustPolicyHardeningExecutorRequest{State: awsTrustPolicyHardeningExecutorStateProjected})
	if applied["state"] != awsTrustPolicyHardeningExecutorStateProjected || len(projected) != 1 || projected[0].ExecutionID != "exec-narrow" {
		t.Fatalf("expected state=projected filter: applied=%+v entries=%+v", applied, projected)
	}

	direction, applied := filterAWSTrustPolicyHardeningExecutorEntries(entries, AWSTrustPolicyHardeningExecutorRequest{HardeningDirection: "add_condition"})
	if applied["hardening_direction"] != "add-condition" || len(direction) != 1 || direction[0].ExecutionID != "exec-condition" {
		t.Fatalf("expected hardening_direction filter: applied=%+v entries=%+v", applied, direction)
	}

	plan, applied := filterAWSTrustPolicyHardeningExecutorEntries(entries, AWSTrustPolicyHardeningExecutorRequest{PlanID: "plan-narrow"})
	if applied["plan_id"] != "plan-narrow" || len(plan) != 1 || plan[0].ExecutionID != "exec-narrow" {
		t.Fatalf("expected plan_id filter: applied=%+v entries=%+v", applied, plan)
	}
}

func TestGetAWSTrustPolicyHardeningExecutorFailureStates(t *testing.T) {
	now := time.Date(2026, 6, 29, 12, 0, 0, 0, time.UTC)
	svc, ws := newTrustPolicyHardeningExecutorService(t, "project-trust-hardening-executor-states", now)

	denied, err := svc.GetAWSTrustPolicyHardeningExecutor(defaultScopeContext(), ws, "project-trust-hardening-executor-states", AWSTrustPolicyHardeningExecutorRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "permission_denied",
	})
	if err != nil {
		t.Fatalf("permission denied: %v", err)
	}
	if denied.Status != "blocked" || len(denied.Entries) != 0 {
		t.Fatalf("permission denied must be explicit and suppress entries: %+v", denied)
	}

	empty, err := svc.GetAWSTrustPolicyHardeningExecutor(defaultScopeContext(), ws, "project-trust-hardening-executor-states", AWSTrustPolicyHardeningExecutorRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "empty",
	})
	if err != nil {
		t.Fatalf("empty: %v", err)
	}
	if empty.Status == "blocked" {
		t.Fatalf("empty fixture should not produce a blocked status: %+v", empty)
	}

	if _, err := svc.GetAWSTrustPolicyHardeningExecutor(defaultScopeContext(), ws, "project-trust-hardening-executor-states", AWSTrustPolicyHardeningExecutorRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "garbage",
	}); err == nil {
		t.Fatalf("invalid fixture state should fail validation")
	}
}

func TestRouterAWSTrustPolicyHardeningExecutor(t *testing.T) {
	now := time.Date(2026, 6, 29, 13, 0, 0, 0, time.UTC)
	svc, _ := newTrustPolicyHardeningExecutorService(t, "project-trust-hardening-executor-route", now)
	r := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{})

	resp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-trust-hardening-executor-route/aws/trust-policy-hardening-executor?connector_id=aws-prod&fixture_state=success&state=projected", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	var body struct {
		Executor AWSTrustPolicyHardeningExecutorResult `json:"trust_policy_hardening_executor"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Executor.CurrentIssueRef != "#1539" || body.Executor.AppliedFilters["state"] != "projected" {
		t.Fatalf("unexpected route payload: %+v", body.Executor)
	}
}
