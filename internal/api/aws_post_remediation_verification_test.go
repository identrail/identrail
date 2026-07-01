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

func newPostRemediationVerificationService(t *testing.T, project string, now time.Time) (*Service, string) {
	t.Helper()
	return newBlastRadiusService(t, project, now)
}

func TestGetAWSPostRemediationVerificationBuildsContract(t *testing.T) {
	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	svc, ws := newPostRemediationVerificationService(t, "project-post-remediation-verification", now)

	result, err := svc.GetAWSPostRemediationVerification(defaultScopeContext(), ws, "project-post-remediation-verification", AWSPostRemediationVerificationRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
	})
	if err != nil {
		t.Fatalf("get post-remediation verification: %v", err)
	}
	if result.CurrentIssueRef != "#1542" || result.Version != awsPostRemediationVerificationVersion || result.CalculationVersion != awsPostRemediationVerificationVersion {
		t.Fatalf("unexpected contract metadata: %+v", result)
	}
	if result.ParentIssueRef != awsIssueRef(awsPlatformDependencyParentIssue) {
		t.Fatalf("expected parent epic ref: %+v", result)
	}
	if len(result.Entries) == 0 {
		t.Fatalf("expected post-remediation verification entries to project from upstream executors: %+v", result.Summary)
	}
	if result.Summary.RelationshipCount != len(result.Relationships) {
		t.Fatalf("expected relationship count to match: summary=%+v relationships=%+v", result.Summary, result.Relationships)
	}
	if len(result.Caveats) == 0 || len(result.EvidenceLinks) == 0 {
		t.Fatalf("expected caveats and evidence links: %+v", result)
	}
	seenSources := map[string]bool{}
	for _, entry := range result.Entries {
		if entry.VerificationID == "" || entry.CalculationVersion != awsPostRemediationVerificationVersion {
			t.Fatalf("entry missing stable metadata: %+v", entry)
		}
		if entry.SourceType == "" || entry.SourceExecutionID == "" {
			t.Fatalf("entry missing upstream identifiers: %+v", entry)
		}
		if !entry.ReadOnlyProjection {
			t.Fatalf("entry must remain a read-only projection: %+v", entry)
		}
		if len(entry.Preconditions) == 0 || len(entry.Checks) == 0 {
			t.Fatalf("entry missing preconditions or checks: %+v", entry)
		}
		if entry.EvidenceBoundary != awsPostRemediationVerificationEvidenceBoundary() {
			t.Fatalf("entry crossed evidence boundary: %+v", entry)
		}
		switch entry.State {
		case awsPostRemediationVerificationStatePending, awsPostRemediationVerificationStateVerified, awsPostRemediationVerificationStateFailed, awsPostRemediationVerificationStateRollback, awsPostRemediationVerificationStateBlocked, awsPostRemediationVerificationStateSkipped, awsPostRemediationVerificationStateNotReady:
		default:
			t.Fatalf("entry has unknown state: %+v", entry)
		}
		for _, check := range entry.Checks {
			if check.Status != awsPostRemediationVerificationCheckStatusPending {
				t.Fatalf("projected checks must stay pending until the apply runtime records outcomes: %+v", check)
			}
		}
		seenSources[entry.SourceType] = true
	}
	if !seenSources["aws_permission_boundary_executor"] || !seenSources["aws_scp_guardrail_executor"] || !seenSources["aws_trust_policy_hardening"] {
		t.Fatalf("expected upstream executors to contribute records at scale: %+v", result.Summary.SourceTypeCounts)
	}

	serialized, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	lower := strings.ToLower(string(serialized))
	for _, forbidden := range []string{"\"secret_access_key\"", "\"private_key\"", "\"policy_document_body\"", "\"rendered_policy\""} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("post-remediation verification serialized forbidden sensitive payload marker %q", forbidden)
		}
	}
}

func TestAWSPostRemediationVerificationStateHonorsGates(t *testing.T) {
	now := time.Date(2026, 7, 1, 12, 15, 0, 0, time.UTC)
	baseSource := awsPostRemediationVerificationSource{
		SourceType:        "aws_permission_boundary_executor",
		SourceExecutionID: "exec-boundary-1",
		DryRunID:          "dr-1",
		CaseID:            "case-1",
		UpstreamState:     "projected",
		ReadyForLiveApply: true,
		IdempotencyKey:    "idk",
		RollbackStrategy:  "restore_permission_boundary",
		RollbackSteps:     []string{"Restore prior permission boundary"},
		VerificationSteps: []string{"Re-run IAM policy simulator"},
	}

	entry := awsPostRemediationVerificationEntryFromSource(baseSource, now)
	if entry.State != awsPostRemediationVerificationStatePending {
		t.Fatalf("projected+ready source should yield verification_pending, got %s", entry.State)
	}
	if entry.Rollback.State != "ready" {
		t.Fatalf("healthy rollback should be ready: %+v", entry.Rollback)
	}

	killed := baseSource
	killed.KillSwitchEngaged = true
	if got := awsPostRemediationVerificationEntryFromSource(killed, now); got.State != awsPostRemediationVerificationStateBlocked {
		t.Fatalf("kill switch must block verification: %+v", got)
	}
	if got := awsPostRemediationVerificationEntryFromSource(killed, now).Rollback.State; got != "blocked_by_kill_switch" {
		t.Fatalf("kill switch must gate rollback: %s", got)
	}

	notReady := baseSource
	notReady.UpstreamState = "precondition_failed"
	notReady.ReadyForLiveApply = false
	if got := awsPostRemediationVerificationEntryFromSource(notReady, now); got.State != awsPostRemediationVerificationStateNotReady {
		t.Fatalf("upstream not ready must yield not_ready state: %+v", got)
	}

	noRollback := baseSource
	noRollback.RollbackStrategy = ""
	noRollback.RollbackSteps = nil
	entry = awsPostRemediationVerificationEntryFromSource(noRollback, now)
	if entry.State != awsPostRemediationVerificationStateBlocked {
		t.Fatalf("missing rollback plan must block verification: %+v", entry)
	}
	if entry.Rollback.State != "not_available" {
		t.Fatalf("missing rollback plan must surface not_available state: %+v", entry.Rollback)
	}

	failedUpstream := baseSource
	failedUpstream.FailedPreconds = 2
	entry = awsPostRemediationVerificationEntryFromSource(failedUpstream, now)
	if entry.State != awsPostRemediationVerificationStateBlocked {
		t.Fatalf("upstream failed preconds must block verification: %+v", entry)
	}

	failedNotReady := baseSource
	failedNotReady.UpstreamState = "precondition_failed"
	failedNotReady.ReadyForLiveApply = false
	failedNotReady.FailedPreconds = 3
	if got := awsPostRemediationVerificationEntryFromSource(failedNotReady, now); got.State != awsPostRemediationVerificationStateBlocked {
		t.Fatalf("failed upstream preconds must classify as blocked even when the source is also not ready: %+v", got)
	}

	upstreamBlocked := baseSource
	upstreamBlocked.UpstreamState = "blocked"
	upstreamBlocked.ReadyForLiveApply = false
	if got := awsPostRemediationVerificationEntryFromSource(upstreamBlocked, now); got.State != awsPostRemediationVerificationStateBlocked {
		t.Fatalf("upstream blocked state must surface as blocked, not not_ready: %+v", got)
	}

	upstreamSkipped := baseSource
	upstreamSkipped.UpstreamState = "skipped"
	upstreamSkipped.ReadyForLiveApply = false
	if got := awsPostRemediationVerificationEntryFromSource(upstreamSkipped, now); got.State != awsPostRemediationVerificationStateSkipped {
		t.Fatalf("upstream skipped state must surface as skipped, not not_ready: %+v", got)
	}
}

func TestFilterAWSPostRemediationVerificationEntriesMatchesTargetAccounts(t *testing.T) {
	entries := []AWSPostRemediationVerificationEntry{
		{
			VerificationID:    "v-boundary-multi-account",
			SourceType:        "aws_permission_boundary_executor",
			SourceExecutionID: "exec-boundary",
			AccountID:         "111111111111",
			TargetAccountIDs:  []string{"222222222222", "333333333333"},
			State:             awsPostRemediationVerificationStatePending,
		},
		{
			VerificationID:    "v-scp-account",
			SourceType:        "aws_scp_guardrail_executor",
			SourceExecutionID: "exec-scp",
			AccountID:         "444444444444",
			TargetAccountIDs:  []string{"555555555555"},
			State:             awsPostRemediationVerificationStatePending,
		},
	}

	filtered, applied := filterAWSPostRemediationVerificationEntries(entries, AWSPostRemediationVerificationRequest{AccountID: "333333333333"})
	if applied["account_id"] != "333333333333" || len(filtered) != 1 || filtered[0].VerificationID != "v-boundary-multi-account" {
		t.Fatalf("account_id filter must match target_account_ids on the entry, not just the connector account: applied=%+v filtered=%+v", applied, filtered)
	}

	filtered, _ = filterAWSPostRemediationVerificationEntries(entries, AWSPostRemediationVerificationRequest{AccountID: "555555555555"})
	if len(filtered) != 1 || filtered[0].VerificationID != "v-scp-account" {
		t.Fatalf("account_id filter must match SCP target accounts: %+v", filtered)
	}

	filtered, _ = filterAWSPostRemediationVerificationEntries(entries, AWSPostRemediationVerificationRequest{AccountID: "111111111111"})
	if len(filtered) != 1 || filtered[0].VerificationID != "v-boundary-multi-account" {
		t.Fatalf("account_id filter must still match the primary AccountID: %+v", filtered)
	}
}

func TestFilterAWSPostRemediationVerificationEntries(t *testing.T) {
	entries := []AWSPostRemediationVerificationEntry{
		{
			VerificationID:    "v1",
			SourceType:        "aws_permission_boundary_executor",
			SourceExecutionID: "exec-a",
			DryRunID:          "dr-1",
			CaseID:            "case-1",
			State:             awsPostRemediationVerificationStatePending,
			Severity:          "high",
			Operation:         "PutRolePermissionsBoundary",
			AccountID:         "111111111111",
			Region:            "us-east-1",
		},
		{
			VerificationID:    "v2",
			SourceType:        "aws_scp_guardrail_executor",
			SourceExecutionID: "exec-b",
			DryRunID:          "dr-2",
			CaseID:            "case-2",
			State:             awsPostRemediationVerificationStateBlocked,
			Severity:          "medium",
			Operation:         "AttachPolicy",
			AccountID:         "222222222222",
			Region:            "us-west-2",
			Rollback:          AWSPostRemediationVerificationRollback{Strategy: "restore_scp"},
		},
	}

	filtered, applied := filterAWSPostRemediationVerificationEntries(entries, AWSPostRemediationVerificationRequest{SourceType: "aws_scp_guardrail_executor"})
	if applied["source_type"] != "aws_scp_guardrail_executor" || len(filtered) != 1 || filtered[0].VerificationID != "v2" {
		t.Fatalf("source_type filter did not scope entries: applied=%+v filtered=%+v", applied, filtered)
	}

	filtered, _ = filterAWSPostRemediationVerificationEntries(entries, AWSPostRemediationVerificationRequest{AccountID: "111111111111"})
	if len(filtered) != 1 || filtered[0].AccountID != "111111111111" {
		t.Fatalf("account_id filter did not scope entries: %+v", filtered)
	}

	filtered, _ = filterAWSPostRemediationVerificationEntries(entries, AWSPostRemediationVerificationRequest{ExecutionID: "exec-a"})
	if len(filtered) != 1 || filtered[0].VerificationID != "v1" {
		t.Fatalf("execution_id filter must match upstream source execution: %+v", filtered)
	}

	filtered, _ = filterAWSPostRemediationVerificationEntries(entries, AWSPostRemediationVerificationRequest{Search: "restore_scp"})
	if len(filtered) != 1 || filtered[0].VerificationID != "v2" {
		t.Fatalf("search must reach rollback metadata: %+v", filtered)
	}

	filtered, applied = filterAWSPostRemediationVerificationEntries(entries, AWSPostRemediationVerificationRequest{State: "verification_pending"})
	if applied["state"] != normalizeAWSRuntimeEventFilterToken("verification_pending") || len(filtered) != 1 || filtered[0].VerificationID != "v1" {
		t.Fatalf("state filter did not scope entries: applied=%+v filtered=%+v", applied, filtered)
	}
}

func TestAWSPostRemediationVerificationFixtureStates(t *testing.T) {
	now := time.Date(2026, 7, 1, 12, 45, 0, 0, time.UTC)
	svc, ws := newPostRemediationVerificationService(t, "project-post-remediation-verification-fixture", now)

	for _, state := range []string{"success", "empty", "degraded", "partial_failure", "permission_denied"} {
		result, err := svc.GetAWSPostRemediationVerification(defaultScopeContext(), ws, "project-post-remediation-verification-fixture", AWSPostRemediationVerificationRequest{
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

func TestRouterAWSPostRemediationVerification(t *testing.T) {
	now := time.Date(2026, 7, 1, 13, 0, 0, 0, time.UTC)
	svc, _ := newPostRemediationVerificationService(t, "project-post-remediation-verification-route", now)
	r := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{})

	resp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-post-remediation-verification-route/aws/post-remediation-verification?connector_id=aws-prod&fixture_state=success&source_type=aws_scp_guardrail_executor", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	var body struct {
		Executor AWSPostRemediationVerificationResult `json:"post_remediation_verification"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Executor.CurrentIssueRef != "#1542" {
		t.Fatalf("unexpected route payload: %+v", body.Executor)
	}
	if body.Executor.AppliedFilters["source_type"] != "aws_scp_guardrail_executor" {
		t.Fatalf("expected route to apply source_type filter: %+v", body.Executor.AppliedFilters)
	}
	for _, entry := range body.Executor.Entries {
		if entry.SourceType != "aws_scp_guardrail_executor" {
			t.Fatalf("source_type filter returned wrong entry: %+v", entry)
		}
	}
}
