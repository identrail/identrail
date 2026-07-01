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

func newScpGuardrailExecutorService(t *testing.T, project string, now time.Time) (*Service, string) {
	t.Helper()
	return newBlastRadiusService(t, project, now)
}

func TestGetAWSScpGuardrailExecutorBuildsContract(t *testing.T) {
	now := time.Date(2026, 7, 1, 10, 0, 0, 0, time.UTC)
	svc, ws := newScpGuardrailExecutorService(t, "project-scp-guardrail-executor", now)

	result, err := svc.GetAWSScpGuardrailExecutor(defaultScopeContext(), ws, "project-scp-guardrail-executor", AWSScpGuardrailExecutorRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
	})
	if err != nil {
		t.Fatalf("get scp guardrail executor: %v", err)
	}
	if result.CurrentIssueRef != "#1541" || result.Version != awsScpGuardrailExecutorVersion {
		t.Fatalf("unexpected contract metadata: %+v", result)
	}
	if result.Summary.RelationshipCount != len(result.Relationships) {
		t.Fatalf("expected relationship count to match: summary=%+v relationships=%+v", result.Summary, result.Relationships)
	}
	if len(result.Entries) == 0 {
		t.Fatalf("expected scp dry-run entries to join to planner records: summary=%+v", result.Summary)
	}
	for _, entry := range result.Entries {
		if entry.ExecutionID == "" || entry.CalculationVersion != awsScpGuardrailExecutorVersion {
			t.Fatalf("entry missing stable metadata: %+v", entry)
		}
		if entry.DryRunID == "" || entry.PlanID == "" || entry.CaseID == "" {
			t.Fatalf("entry missing source IDs: %+v", entry)
		}
		if !entry.ReadOnlyProjection {
			t.Fatalf("entry must remain a read-only projection: %+v", entry)
		}
		if entry.IntendedAPICall.Service != "organizations" || entry.IntendedAPICall.Operation != "AttachPolicy" {
			t.Fatalf("entry must project Organizations SCP attach calls: %+v", entry.IntendedAPICall)
		}
		if len(entry.TargetAccountIDs)+len(entry.TargetOUPaths) == 0 || len(entry.Preconditions) == 0 {
			t.Fatalf("entry missing target scope or preconditions: %+v", entry)
		}
		if entry.BoundarySimulation.SimulationRef == "" || entry.BoundarySimulation.DeniedActionCount == 0 {
			t.Fatalf("entry missing scp simulation: %+v", entry.BoundarySimulation)
		}
		if entry.EvidenceBoundary != awsScpGuardrailExecutorEvidenceBoundary() {
			t.Fatalf("entry crossed evidence boundary: %+v", entry)
		}
	}

	serialized, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	lower := strings.ToLower(string(serialized))
	for _, forbidden := range []string{"\"secret_access_key\"", "\"private_key\"", "\"policy_document_body\"", "\"rendered_policy\""} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("scp guardrail executor serialized forbidden sensitive payload marker %q", forbidden)
		}
	}
}

func TestAWSScpGuardrailExecutorAdmitsOnlySCPDryRuns(t *testing.T) {
	cases := []struct {
		name      string
		entry     AWSRemediationDryRunEntry
		wantAdmit bool
	}{
		{
			name: "scp dry-run is admitted",
			entry: AWSRemediationDryRunEntry{
				SourceType:       "aws_permission_boundary_scp",
				DiffIntent:       AWSRemediationDiffIntent{Kind: "scp_diff"},
				IntendedAPICalls: []AWSRemediationDryRunIntendedAPICall{{Service: "organizations", Operation: "AttachPolicy"}},
			},
			wantAdmit: true,
		},
		{
			name: "permission boundary dry-run is excluded",
			entry: AWSRemediationDryRunEntry{
				SourceType:       "aws_permission_boundary_scp",
				DiffIntent:       AWSRemediationDiffIntent{Kind: "permission_boundary_diff"},
				IntendedAPICalls: []AWSRemediationDryRunIntendedAPICall{{Service: "iam", Operation: "PutRolePermissionsBoundary"}},
			},
		},
		{
			name: "wrong operation is excluded",
			entry: AWSRemediationDryRunEntry{
				SourceType:       "aws_permission_boundary_scp",
				DiffIntent:       AWSRemediationDiffIntent{Kind: "scp_diff"},
				IntendedAPICalls: []AWSRemediationDryRunIntendedAPICall{{Service: "iam", Operation: "PutRolePolicy"}},
			},
		},
	}
	for _, tc := range cases {
		if got := awsScpGuardrailExecutorAdmits(tc.entry); got != tc.wantAdmit {
			t.Fatalf("%s: admit=%v want %v", tc.name, got, tc.wantAdmit)
		}
	}
}

func TestAWSScpGuardrailExecutorStateHonorsScopeAndPreconditions(t *testing.T) {
	now := time.Date(2026, 7, 1, 10, 30, 0, 0, time.UTC)
	readyPlan := AWSPermissionBoundarySCPPlan{
		PlanID:             "scp-plan-ready",
		Kind:               awsSCPKind,
		ReadyForApply:      true,
		TargetAccountIDs:   []string{"111111111111"},
		TargetOUPaths:      []string{"/engineering"},
		BreakageProjection: AWSPermissionBoundarySCPBreakageProjection{Level: "low"},
		StatementSnippets:  []AWSPermissionBoundarySCPStatementSnippet{{DeniedActions: []string{"sts:AssumeRole"}}},
	}
	entry := AWSRemediationDryRunEntry{
		DryRunID:         "dr-scp-ready",
		CaseID:           "case-scp-ready",
		SourceType:       "aws_permission_boundary_scp",
		SourceArtifactID: "scp-plan-ready",
		Outcome:          awsRemediationDryRunOutcomeWouldSucceed,
		ReadyForApply:    true,
		IdempotencyKey:   "idk",
		DiffIntent:       AWSRemediationDiffIntent{Kind: "scp_diff"},
		IntendedAPICalls: []AWSRemediationDryRunIntendedAPICall{{Service: "organizations", Operation: "AttachPolicy"}},
	}
	out := awsScpGuardrailExecutorEntryFromDryRun(entry, readyPlan, now)
	if out.State != awsScpGuardrailExecutorStateProjected || !out.ReadyForLiveApply {
		t.Fatalf("ready scp plan should project live-apply readiness: %+v", out)
	}

	noScope := readyPlan
	noScope.TargetAccountIDs = nil
	noScope.TargetOUPaths = nil
	if entries := awsScpGuardrailExecutorEntriesFromDryRun(entry, noScope, now); len(entries) != 0 {
		t.Fatalf("scp plan without account or OU scope must not produce entries: %+v", entries)
	}

	highBreakage := readyPlan
	highBreakage.BreakageProjection.Level = "high"
	out = awsScpGuardrailExecutorEntryFromDryRun(entry, highBreakage, now)
	if out.State != awsScpGuardrailExecutorStatePreconditionFailed || out.ReadyForLiveApply {
		t.Fatalf("high-breakage scp plan should fail preconditions: %+v", out)
	}
}

func TestFilterAWSScpGuardrailExecutorEntriesMatchesTargetScope(t *testing.T) {
	entries := []AWSScpGuardrailExecutorEntry{
		{
			ExecutionID:      "exec-ou",
			Region:           "",
			State:            awsScpGuardrailExecutorStateProjected,
			Severity:         "high",
			Operation:        "AttachPolicy",
			TargetAccountIDs: []string{"111111111111", "222222222222"},
			TargetOUPaths:    []string{"/engineering"},
		},
		{
			ExecutionID:      "exec-other",
			Region:           "us-west-2",
			State:            awsScpGuardrailExecutorStateBlocked,
			Severity:         "medium",
			Operation:        "AttachPolicy",
			TargetAccountIDs: []string{"333333333333"},
		},
	}

	filtered, applied := filterAWSScpGuardrailExecutorEntries(entries, AWSScpGuardrailExecutorRequest{AccountID: "222222222222", Region: "us-east-1"})
	if applied["account_id"] != "222222222222" || applied["region"] != "us-east-1" {
		t.Fatalf("expected applied account and region filters, got %+v", applied)
	}
	if len(filtered) != 1 || filtered[0].ExecutionID != "exec-ou" {
		t.Fatalf("expected matching target account and multi-region entry: %+v", filtered)
	}

	filtered, _ = filterAWSScpGuardrailExecutorEntries(entries, AWSScpGuardrailExecutorRequest{Search: "engineering"})
	if len(filtered) != 1 || filtered[0].ExecutionID != "exec-ou" {
		t.Fatalf("expected search to match target OU path: %+v", filtered)
	}
}

func TestRouterAWSScpGuardrailExecutor(t *testing.T) {
	now := time.Date(2026, 7, 1, 11, 0, 0, 0, time.UTC)
	svc, _ := newScpGuardrailExecutorService(t, "project-scp-guardrail-executor-route", now)
	r := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{})

	resp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-scp-guardrail-executor-route/aws/scp-guardrail-executor?connector_id=aws-prod&fixture_state=success", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	var body struct {
		Executor AWSScpGuardrailExecutorResult `json:"scp_guardrail_executor"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Executor.CurrentIssueRef != "#1541" || len(body.Executor.Entries) == 0 {
		t.Fatalf("unexpected route payload: %+v", body.Executor)
	}
}
