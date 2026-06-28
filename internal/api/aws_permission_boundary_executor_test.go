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

func newPermissionBoundaryExecutorService(t *testing.T, project string, now time.Time) (*Service, string) {
	t.Helper()
	return newBlastRadiusService(t, project, now)
}

func TestGetAWSPermissionBoundaryExecutorBuildsContract(t *testing.T) {
	now := time.Date(2026, 6, 30, 10, 0, 0, 0, time.UTC)
	svc, ws := newPermissionBoundaryExecutorService(t, "project-permission-boundary-executor", now)

	result, err := svc.GetAWSPermissionBoundaryExecutor(defaultScopeContext(), ws, "project-permission-boundary-executor", AWSPermissionBoundaryExecutorRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
	})
	if err != nil {
		t.Fatalf("get permission boundary executor: %v", err)
	}
	if result.CurrentIssueRef != "#1540" || result.Version != awsPermissionBoundaryExecutorVersion {
		t.Fatalf("unexpected contract metadata: %+v", result)
	}
	if result.Summary.RelationshipCount != len(result.Relationships) {
		t.Fatalf("expected relationship count to match: summary=%+v relationships=%+v", result.Summary, result.Relationships)
	}
	if len(result.Entries) == 0 {
		t.Fatalf("expected permission-boundary dry-run entries to join to planner records: summary=%+v", result.Summary)
	}
	if len(result.Caveats) == 0 || len(result.CoverageGaps) == 0 {
		t.Fatalf("expected caveats and coverage gaps: %+v", result)
	}
	blockedEntries := 0
	for i := 1; i < len(result.Entries); i++ {
		if result.Entries[i-1].Score < result.Entries[i].Score {
			t.Fatalf("entries are not ranked by descending score: %+v", result.Entries)
		}
	}
	for _, entry := range result.Entries {
		if entry.ExecutionID == "" || entry.CalculationVersion != awsPermissionBoundaryExecutorVersion {
			t.Fatalf("entry missing stable metadata: %+v", entry)
		}
		if entry.DryRunID == "" || entry.PlanID == "" || entry.CaseID == "" {
			t.Fatalf("entry missing source IDs: %+v", entry)
		}
		if !entry.ReadOnlyProjection {
			t.Fatalf("entry must remain a read-only projection: %+v", entry)
		}
		if entry.IntendedAPICall.Service != "iam" {
			t.Fatalf("entry must project IAM calls: %+v", entry.IntendedAPICall)
		}
		if entry.IntendedAPICall.Operation != "PutRolePermissionsBoundary" && entry.IntendedAPICall.Operation != "PutUserPermissionsBoundary" {
			t.Fatalf("entry must project permission boundary operations: %+v", entry.IntendedAPICall)
		}
		if len(entry.TargetIdentityNodeIDs) == 0 || len(entry.Preconditions) == 0 {
			t.Fatalf("entry missing target identities or preconditions: %+v", entry)
		}
		if entry.BoundarySimulation.SimulationRef == "" || entry.BoundarySimulation.TargetIdentityCount == 0 {
			t.Fatalf("entry missing boundary simulation: %+v", entry.BoundarySimulation)
		}
		if entry.EvidenceBoundary != awsPermissionBoundaryExecutorEvidenceBoundary() {
			t.Fatalf("entry crossed evidence boundary: %+v", entry)
		}
		if entry.State == awsPermissionBoundaryExecutorStateBlocked {
			blockedEntries++
		}
	}
	if blockedEntries == 0 {
		t.Fatalf("success fixture must surface blocked unsafe boundary entries: %+v", result.Entries)
	}

	serialized, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	lower := strings.ToLower(string(serialized))
	for _, forbidden := range []string{"\"secret_access_key\"", "\"private_key\"", "\"policy_document_body\"", "\"rendered_policy\""} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("permission boundary executor serialized forbidden sensitive payload marker %q", forbidden)
		}
	}
}

func TestAWSPermissionBoundaryExecutorAdmitsOnlyBoundaryDryRuns(t *testing.T) {
	cases := []struct {
		name      string
		entry     AWSRemediationDryRunEntry
		wantAdmit bool
	}{
		{
			name: "permission boundary dry-run is admitted",
			entry: AWSRemediationDryRunEntry{
				SourceType:       "aws_permission_boundary_scp",
				DiffIntent:       AWSRemediationDiffIntent{Kind: "permission_boundary_diff"},
				IntendedAPICalls: []AWSRemediationDryRunIntendedAPICall{{Service: "iam", Operation: "PutRolePermissionsBoundary"}},
			},
			wantAdmit: true,
		},
		{
			name: "user boundary dry-run is admitted",
			entry: AWSRemediationDryRunEntry{
				SourceType:       "aws_permission_boundary_scp",
				DiffIntent:       AWSRemediationDiffIntent{Kind: "permission_boundary_diff"},
				IntendedAPICalls: []AWSRemediationDryRunIntendedAPICall{{Service: "iam", Operation: "PutUserPermissionsBoundary"}},
			},
			wantAdmit: true,
		},
		{
			name: "scp diff is excluded",
			entry: AWSRemediationDryRunEntry{
				SourceType:       "aws_permission_boundary_scp",
				DiffIntent:       AWSRemediationDiffIntent{Kind: "scp_diff"},
				IntendedAPICalls: []AWSRemediationDryRunIntendedAPICall{{Service: "organizations", Operation: "AttachPolicy"}},
			},
			wantAdmit: false,
		},
		{
			name: "trust-policy source is excluded",
			entry: AWSRemediationDryRunEntry{
				SourceType:       "trust_policy_hardening",
				DiffIntent:       AWSRemediationDiffIntent{Kind: "permission_boundary_diff"},
				IntendedAPICalls: []AWSRemediationDryRunIntendedAPICall{{Service: "iam", Operation: "PutRolePermissionsBoundary"}},
			},
			wantAdmit: false,
		},
		{
			name: "noop boundary diff is excluded",
			entry: AWSRemediationDryRunEntry{
				SourceType:       "aws_permission_boundary_scp",
				DiffIntent:       AWSRemediationDiffIntent{Kind: "permission_boundary_diff", NoOp: true},
				IntendedAPICalls: []AWSRemediationDryRunIntendedAPICall{{Service: "iam", Operation: "PutRolePermissionsBoundary"}},
			},
			wantAdmit: false,
		},
		{
			name: "unsupported operation is excluded",
			entry: AWSRemediationDryRunEntry{
				SourceType:       "aws_permission_boundary_scp",
				DiffIntent:       AWSRemediationDiffIntent{Kind: "permission_boundary_diff"},
				IntendedAPICalls: []AWSRemediationDryRunIntendedAPICall{{Service: "iam", Operation: "PutRolePolicy"}},
			},
			wantAdmit: false,
		},
	}
	for _, tc := range cases {
		got := awsPermissionBoundaryExecutorAdmits(tc.entry)
		if got != tc.wantAdmit {
			t.Fatalf("%s: admits=%v want=%v", tc.name, got, tc.wantAdmit)
		}
	}
}

func TestAWSPermissionBoundaryExecutorStateHonorsPreconditions(t *testing.T) {
	now := time.Date(2026, 6, 30, 11, 0, 0, 0, time.UTC)
	readyPlan := AWSPermissionBoundarySCPPlan{
		PlanID:                "plan-ready",
		Kind:                  awsPermissionBoundaryKind,
		ReadyForApply:         true,
		TargetIdentityNodeIDs: []string{"aws:identity:arn:aws:iam::123456789012:role/app-a", "aws:identity:arn:aws:iam::123456789012:role/app-b"},
		TargetAccountIDs:      []string{"123456789012"},
		BreakageProjection:    AWSPermissionBoundarySCPBreakageProjection{Level: "low"},
	}
	entry := AWSRemediationDryRunEntry{
		DryRunID:         "dr-ready",
		CaseID:           "case-ready",
		SourceType:       "aws_permission_boundary_scp",
		SourceArtifactID: "plan-ready",
		IdempotencyKey:   "idk",
		Outcome:          awsRemediationDryRunOutcomeWouldSucceed,
		ReadyForApply:    true,
		DiffIntent:       AWSRemediationDiffIntent{Kind: "permission_boundary_diff"},
		IntendedAPICalls: []AWSRemediationDryRunIntendedAPICall{{Service: "iam", Operation: "PutRolePermissionsBoundary"}},
	}
	out := awsPermissionBoundaryExecutorEntryFromDryRun(entry, readyPlan, now)
	if out.State != awsPermissionBoundaryExecutorStateProjected || !out.ReadyForLiveApply {
		t.Fatalf("ready entry must reach projected/ready_for_live_apply, got %+v", out)
	}

	noTargets := readyPlan
	noTargets.TargetIdentityNodeIDs = nil
	out = awsPermissionBoundaryExecutorEntryFromDryRun(entry, noTargets, now)
	if out.State != awsPermissionBoundaryExecutorStateBlocked {
		t.Fatalf("missing targets must block live apply, got state=%q", out.State)
	}

	planNotReady := readyPlan
	planNotReady.ReadyForApply = false
	out = awsPermissionBoundaryExecutorEntryFromDryRun(entry, planNotReady, now)
	if out.State != awsPermissionBoundaryExecutorStatePreconditionFailed {
		t.Fatalf("planner not ready must surface precondition_failed, got state=%q", out.State)
	}

	highBreakage := readyPlan
	highBreakage.BreakageProjection.Level = "high"
	out = awsPermissionBoundaryExecutorEntryFromDryRun(entry, highBreakage, now)
	if out.State != awsPermissionBoundaryExecutorStatePreconditionFailed {
		t.Fatalf("high breakage must surface precondition_failed, got state=%q", out.State)
	}

	killSwitch := entry
	killSwitch.KillSwitchEngaged = true
	out = awsPermissionBoundaryExecutorEntryFromDryRun(killSwitch, readyPlan, now)
	if out.State != awsPermissionBoundaryExecutorStateBlocked || out.ReadyForLiveApply {
		t.Fatalf("kill switch must block, got %+v", out)
	}
}

func TestGetAWSPermissionBoundaryExecutorFailureStates(t *testing.T) {
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	svc, ws := newPermissionBoundaryExecutorService(t, "project-permission-boundary-executor-states", now)

	denied, err := svc.GetAWSPermissionBoundaryExecutor(defaultScopeContext(), ws, "project-permission-boundary-executor-states", AWSPermissionBoundaryExecutorRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "permission_denied",
	})
	if err != nil {
		t.Fatalf("permission denied: %v", err)
	}
	if denied.Status != "blocked" || len(denied.Entries) != 0 {
		t.Fatalf("permission denied must be explicit and suppress entries: %+v", denied)
	}

	if _, err := svc.GetAWSPermissionBoundaryExecutor(defaultScopeContext(), ws, "project-permission-boundary-executor-states", AWSPermissionBoundaryExecutorRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "garbage",
	}); err == nil {
		t.Fatalf("invalid fixture state should fail validation")
	}
}

func TestAWSPermissionBoundaryExecutorAggregatesDryRunDiagnostics(t *testing.T) {
	diagnostics := awsPermissionBoundaryExecutorDiagnostics(
		[]AWSRemediationApprovalDiagnostic{{
			Collector:   "aws_remediation_dry_run",
			SourceID:    "dry-run-source",
			Code:        "dry_run_partial_failure",
			Message:     "Dry-run source was partially unavailable.",
			Remediation: "Retry the dry-run source.",
			Retryable:   true,
		}},
		[]AWSPermissionBoundarySCPDiagnostic{{
			Collector:   "aws_permission_boundary_scp",
			SourceID:    "planner-source",
			Code:        "planner_degraded",
			Message:     "Planner source was degraded.",
			Remediation: "Retry the planner source.",
			Retryable:   true,
		}},
	)
	if len(diagnostics) != 2 || diagnostics[0].Collector != "aws_remediation_dry_run" || diagnostics[1].Collector != "aws_permission_boundary_scp" {
		t.Fatalf("executor diagnostics must preserve dry-run and planner sources: %+v", diagnostics)
	}

	gaps := awsPermissionBoundaryExecutorCoverageGaps(
		[]AWSRemediationApprovalCoverageGap{{
			Capability:  "dry_run_approval_queue",
			Status:      "partial_failure",
			Reason:      "Approval queue source was partially unavailable.",
			Remediation: "Retry approval queue collection.",
		}},
		[]AWSPermissionBoundarySCPCoverageGap{{
			Capability:  "permission_boundary_runtime_evidence",
			Status:      "degraded",
			Reason:      "Runtime evidence was delayed.",
			Remediation: "Retry runtime evidence collection.",
		}},
	)
	foundDryRunGap := false
	foundPlannerGap := false
	for _, gap := range gaps {
		switch gap.Capability {
		case "dry_run_approval_queue":
			foundDryRunGap = true
		case "permission_boundary_runtime_evidence":
			foundPlannerGap = true
		}
	}
	if !foundDryRunGap || !foundPlannerGap {
		t.Fatalf("executor coverage gaps must preserve dry-run and planner sources: %+v", gaps)
	}
}

func TestRouterAWSPermissionBoundaryExecutor(t *testing.T) {
	now := time.Date(2026, 6, 30, 13, 0, 0, 0, time.UTC)
	svc, _ := newPermissionBoundaryExecutorService(t, "project-permission-boundary-executor-route", now)
	r := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{})

	resp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-permission-boundary-executor-route/aws/permission-boundary-executor?connector_id=aws-prod&fixture_state=success&state=blocked", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	var body struct {
		Executor AWSPermissionBoundaryExecutorResult `json:"permission_boundary_executor"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Executor.CurrentIssueRef != "#1540" || body.Executor.AppliedFilters["state"] != "blocked" {
		t.Fatalf("unexpected route payload: %+v", body.Executor)
	}
	if len(body.Executor.Entries) == 0 {
		t.Fatalf("blocked success fixture route must return unsafe executor entries: %+v", body.Executor)
	}
	for _, entry := range body.Executor.Entries {
		if entry.State != awsPermissionBoundaryExecutorStateBlocked || entry.ReadyForLiveApply {
			t.Fatalf("blocked route returned executable entry: %+v", entry)
		}
	}
}
