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

func TestAWSPermissionBoundaryExecutorSplitsMixedPrincipalKinds(t *testing.T) {
	now := time.Date(2026, 6, 30, 11, 30, 0, 0, time.UTC)
	plan := AWSPermissionBoundarySCPPlan{
		PlanID:                "plan-mixed-principals",
		Kind:                  awsPermissionBoundaryKind,
		ReadyForApply:         true,
		TargetIdentityNodeIDs: []string{"aws:identity:arn:aws:iam::111111111111:role/app-role", "aws:identity:arn:aws:iam::222222222222:user/app-user"},
		TargetAccountIDs:      []string{"111111111111", "222222222222"},
		BreakageProjection:    AWSPermissionBoundarySCPBreakageProjection{Level: "low"},
	}
	entry := AWSRemediationDryRunEntry{
		DryRunID:         "dr-mixed",
		CaseID:           "case-mixed",
		SourceType:       "aws_permission_boundary_scp",
		SourceArtifactID: "plan-mixed-principals",
		AccountID:        "111111111111",
		IdempotencyKey:   "idk",
		Outcome:          awsRemediationDryRunOutcomeWouldSucceed,
		ReadyForApply:    true,
		DiffIntent:       AWSRemediationDiffIntent{Kind: "permission_boundary_diff"},
		IntendedAPICalls: []AWSRemediationDryRunIntendedAPICall{{
			Service:          "iam",
			Operation:        "PutRolePermissionsBoundary",
			TargetResource:   "aws:identity:arn:aws:iam::111111111111:role/app-role",
			ParameterRefs:    []string{"idk", "boundary_ref://case-mixed/after"},
			Idempotent:       true,
			RequiresApproval: true,
		}},
	}

	entries := awsPermissionBoundaryExecutorEntriesFromDryRun(entry, plan, now)
	if len(entries) != 2 {
		t.Fatalf("expected mixed role/user plan to split into two executor entries: %+v", entries)
	}
	byOperation := map[string]AWSPermissionBoundaryExecutorEntry{}
	for _, out := range entries {
		byOperation[out.Operation] = out
	}
	roleEntry, ok := byOperation["PutRolePermissionsBoundary"]
	if !ok {
		t.Fatalf("missing role boundary entry: %+v", entries)
	}
	if len(roleEntry.TargetIdentityNodeIDs) != 1 || !strings.Contains(roleEntry.TargetIdentityNodeIDs[0], ":role/") {
		t.Fatalf("role entry retained non-role targets: %+v", roleEntry.TargetIdentityNodeIDs)
	}
	if len(roleEntry.TargetAccountIDs) != 1 || roleEntry.TargetAccountIDs[0] != "111111111111" {
		t.Fatalf("role entry retained wrong target accounts: %+v", roleEntry.TargetAccountIDs)
	}
	if roleEntry.AccountID != "111111111111" {
		t.Fatalf("role entry retained wrong primary account: %q", roleEntry.AccountID)
	}
	userEntry, ok := byOperation["PutUserPermissionsBoundary"]
	if !ok {
		t.Fatalf("missing user boundary entry: %+v", entries)
	}
	if len(userEntry.TargetIdentityNodeIDs) != 1 || !strings.Contains(userEntry.TargetIdentityNodeIDs[0], ":user/") {
		t.Fatalf("user entry retained non-user targets: %+v", userEntry.TargetIdentityNodeIDs)
	}
	if len(userEntry.TargetAccountIDs) != 1 || userEntry.TargetAccountIDs[0] != "222222222222" {
		t.Fatalf("user entry retained wrong target accounts: %+v", userEntry.TargetAccountIDs)
	}
	if userEntry.AccountID != "222222222222" {
		t.Fatalf("user entry retained wrong primary account: %q", userEntry.AccountID)
	}
	if userEntry.IntendedAPICall.Operation != "PutUserPermissionsBoundary" || !strings.Contains(userEntry.IntendedAPICall.TargetResource, ":user/") {
		t.Fatalf("user entry has wrong intended call: %+v", userEntry.IntendedAPICall)
	}
	if len(userEntry.IntendedAPICall.ParameterRefs) == 0 || userEntry.IntendedAPICall.ParameterRefs[0] != userEntry.IdempotencyKey {
		t.Fatalf("user entry intended call should refresh its idempotency parameter ref: %+v", userEntry.IntendedAPICall)
	}
	if roleEntry.IdempotencyKey == userEntry.IdempotencyKey {
		t.Fatalf("split entries should have distinct idempotency keys: role=%q user=%q", roleEntry.IdempotencyKey, userEntry.IdempotencyKey)
	}
	if roleEntry.IdempotencyKey != stableAWSBlastRadiusToken("idk", "PutRolePermissionsBoundary", roleEntry.TargetIdentityNodeIDs[0]) {
		t.Fatalf("unexpected role split idempotency key: %q", roleEntry.IdempotencyKey)
	}
	if userEntry.IdempotencyKey != stableAWSBlastRadiusToken("idk", "PutUserPermissionsBoundary", userEntry.TargetIdentityNodeIDs[0]) {
		t.Fatalf("unexpected user split idempotency key: %q", userEntry.IdempotencyKey)
	}
	filtered, _ := filterAWSPermissionBoundaryExecutorEntries(entries, AWSPermissionBoundaryExecutorRequest{AccountID: "111111111111"})
	if len(filtered) != 1 || filtered[0].Operation != "PutRolePermissionsBoundary" {
		t.Fatalf("account filter leaked cross-account split entries: %+v", filtered)
	}
	if roleEntry.ExecutionID == userEntry.ExecutionID {
		t.Fatalf("split entries must have distinct execution IDs: role=%q user=%q", roleEntry.ExecutionID, userEntry.ExecutionID)
	}
	if len(roleEntry.IntendedAPICall.ParameterRefs) == 0 || roleEntry.IntendedAPICall.ParameterRefs[0] != roleEntry.IdempotencyKey {
		t.Fatalf("role entry intended call should refresh its idempotency parameter ref: %+v", roleEntry.IntendedAPICall)
	}
}

func TestAWSPermissionBoundaryExecutorSplitsSameKindTargetsIntoCalls(t *testing.T) {
	now := time.Date(2026, 7, 1, 7, 30, 0, 0, time.UTC)
	plan := AWSPermissionBoundarySCPPlan{
		PlanID:                "plan-same-kind-principals",
		Kind:                  awsPermissionBoundaryKind,
		ReadyForApply:         true,
		TargetIdentityNodeIDs: []string{"aws:identity:arn:aws:iam::111111111111:role/app-a", "aws:identity:arn:aws:iam::111111111111:role/app-b"},
		TargetAccountIDs:      []string{"111111111111"},
		BreakageProjection:    AWSPermissionBoundarySCPBreakageProjection{Level: "low"},
	}
	entry := AWSRemediationDryRunEntry{
		DryRunID:         "dr-same-kind",
		CaseID:           "case-same-kind",
		SourceType:       "aws_permission_boundary_scp",
		SourceArtifactID: "plan-same-kind-principals",
		AccountID:        "111111111111",
		IdempotencyKey:   "idk",
		Outcome:          awsRemediationDryRunOutcomeWouldSucceed,
		ReadyForApply:    true,
		DiffIntent:       AWSRemediationDiffIntent{Kind: "permission_boundary_diff"},
		IntendedAPICalls: []AWSRemediationDryRunIntendedAPICall{{
			Service:          "iam",
			Operation:        "PutRolePermissionsBoundary",
			TargetResource:   "aws:identity:arn:aws:iam::111111111111:role/app-a",
			ParameterRefs:    []string{"idk", "boundary_ref://case-same-kind/after"},
			Idempotent:       true,
			RequiresApproval: true,
		}},
	}

	entries := awsPermissionBoundaryExecutorEntriesFromDryRun(entry, plan, now)
	if len(entries) != 2 {
		t.Fatalf("expected same-kind role plan to split into one entry per intended call: %+v", entries)
	}
	seenExecutions := map[string]bool{}
	seenKeys := map[string]bool{}
	seenTargets := map[string]bool{}
	for _, out := range entries {
		if len(out.TargetIdentityNodeIDs) != 1 {
			t.Fatalf("entry should retain exactly one target identity: %+v", out.TargetIdentityNodeIDs)
		}
		target := out.TargetIdentityNodeIDs[0]
		if out.IntendedAPICall.Operation != "PutRolePermissionsBoundary" || out.IntendedAPICall.TargetResource != target {
			t.Fatalf("intended call must target the retained identity: target=%q call=%+v", target, out.IntendedAPICall)
		}
		if len(out.IntendedAPICall.ParameterRefs) == 0 || out.IntendedAPICall.ParameterRefs[0] != out.IdempotencyKey {
			t.Fatalf("intended call should refresh its idempotency parameter ref: %+v", out.IntendedAPICall)
		}
		if seenExecutions[out.ExecutionID] {
			t.Fatalf("same-kind split entries must have distinct execution IDs: %+v", entries)
		}
		if seenKeys[out.IdempotencyKey] {
			t.Fatalf("same-kind split entries must have distinct idempotency keys: %+v", entries)
		}
		seenExecutions[out.ExecutionID] = true
		seenKeys[out.IdempotencyKey] = true
		seenTargets[target] = true
	}
	for _, target := range plan.TargetIdentityNodeIDs {
		if !seenTargets[target] {
			t.Fatalf("missing executor entry for target %q in %+v", target, entries)
		}
	}
}

func TestAWSPermissionBoundaryExecutorSplitAvoidsUnsafeAccountFallbackForNonARNTargets(t *testing.T) {
	now := time.Date(2026, 6, 30, 11, 45, 0, 0, time.UTC)
	plan := AWSPermissionBoundarySCPPlan{
		PlanID:                "plan-mixed-non-arn",
		Kind:                  awsPermissionBoundaryKind,
		ReadyForApply:         true,
		TargetIdentityNodeIDs: []string{"aws:identity:role/app-role", "aws:identity:user/app-user"},
		TargetAccountIDs:      []string{"111111111111", "222222222222"},
		BreakageProjection:    AWSPermissionBoundarySCPBreakageProjection{Level: "low"},
	}
	entry := AWSRemediationDryRunEntry{
		DryRunID:         "dr-mixed-non-arn",
		CaseID:           "case-mixed-non-arn",
		SourceType:       "aws_permission_boundary_scp",
		SourceArtifactID: "plan-mixed-non-arn",
		AccountID:        "111111111111",
		IdempotencyKey:   "idk",
		Outcome:          awsRemediationDryRunOutcomeWouldSucceed,
		ReadyForApply:    true,
		DiffIntent:       AWSRemediationDiffIntent{Kind: "permission_boundary_diff"},
		IntendedAPICalls: []AWSRemediationDryRunIntendedAPICall{{
			Service:          "iam",
			Operation:        "PutRolePermissionsBoundary",
			TargetResource:   "aws:identity:role/app-role",
			ParameterRefs:    []string{"idk", "boundary_ref://case-mixed-non-arn/after"},
			Idempotent:       true,
			RequiresApproval: true,
		}},
	}

	// Neither target's node ID carries an ARN-encoded account, and the plan
	// originally described two targets, so no split entry can prove which of
	// the planner's two accounts it belongs to. Each entry must leave its
	// account scope empty rather than inheriting the full planner list,
	// which would let one target masquerade under the other's account.
	entries := awsPermissionBoundaryExecutorEntriesFromDryRun(entry, plan, now)
	if len(entries) != 2 {
		t.Fatalf("expected mixed non-ARN role/user plan to split into two executor entries: %+v", entries)
	}
	for _, out := range entries {
		if len(out.TargetAccountIDs) != 0 || out.AccountID != "" {
			t.Fatalf("non-ARN split entry with an unresolved account must not inherit the planner's full account list: %+v", out)
		}
	}
	filtered, _ := filterAWSPermissionBoundaryExecutorEntries(entries, AWSPermissionBoundaryExecutorRequest{AccountID: "222222222222"})
	if len(filtered) != 0 {
		t.Fatalf("account drill-down must not match split entries with no proven account scope: %+v", filtered)
	}
}

func TestAWSPermissionBoundaryExecutorScopesSingleOperationAfterGroupFilter(t *testing.T) {
	now := time.Date(2026, 6, 30, 12, 45, 0, 0, time.UTC)
	plan := AWSPermissionBoundarySCPPlan{
		PlanID:                "plan-group-filtered-into-user",
		Kind:                  awsPermissionBoundaryKind,
		ReadyForApply:         true,
		TargetIdentityNodeIDs: []string{"aws:identity:arn:aws:iam::111111111111:group/app-group", "aws:identity:arn:aws:iam::222222222222:user/app-user"},
		TargetAccountIDs:      []string{"111111111111", "222222222222"},
		BreakageProjection:    AWSPermissionBoundarySCPBreakageProjection{Level: "low"},
		ImpactedNodes:         []string{"aws:identity:arn:aws:iam::111111111111:group/app-group", "aws:identity:arn:aws:iam::222222222222:user/app-user"},
	}
	entry := AWSRemediationDryRunEntry{
		DryRunID:         "dr-group-filtered-into-user",
		CaseID:           "case-group-filtered-into-user",
		SourceType:       "aws_permission_boundary_scp",
		SourceArtifactID: "plan-group-filtered-into-user",
		AccountID:        "111111111111",
		IdempotencyKey:   "idk",
		Outcome:          awsRemediationDryRunOutcomeWouldSucceed,
		ReadyForApply:    true,
		DiffIntent:       AWSRemediationDiffIntent{Kind: "permission_boundary_diff"},
		IntendedAPICalls: []AWSRemediationDryRunIntendedAPICall{{
			Service:          "iam",
			Operation:        "PutRolePermissionsBoundary",
			TargetResource:   "aws:identity:arn:aws:iam::111111111111:group/app-group",
			ParameterRefs:    []string{"idk", "boundary_ref://case-group-filtered-into-user/after"},
			Idempotent:       true,
			RequiresApproval: true,
		}},
	}

	entries := awsPermissionBoundaryExecutorEntriesFromDryRun(entry, plan, now)
	if len(entries) != 1 {
		t.Fatalf("group filter to single user should produce one executor entry: %+v", entries)
	}
	out := entries[0]
	if out.Operation != "PutUserPermissionsBoundary" {
		t.Fatalf("expected scoped single-operation entry to target user permissions boundary, got %q", out.Operation)
	}
	if out.IntendedAPICall.Operation != "PutUserPermissionsBoundary" {
		t.Fatalf("expected intended call to recompute for user-only split, got %+v", out.IntendedAPICall)
	}
	if len(out.IntendedAPICall.ParameterRefs) == 0 || out.IntendedAPICall.ParameterRefs[0] != out.IdempotencyKey {
		t.Fatalf("scoped single-operation intended call should refresh idempotency parameter ref: %+v", out.IntendedAPICall)
	}
	if len(out.TargetIdentityNodeIDs) != 1 || !strings.HasSuffix(out.TargetIdentityNodeIDs[0], ":user/app-user") {
		t.Fatalf("expected filtered target identities to keep only the user identity: %+v", out.TargetIdentityNodeIDs)
	}
	if len(out.TargetAccountIDs) != 1 || out.TargetAccountIDs[0] != "222222222222" {
		t.Fatalf("expected account scope to be narrowed to retained user account: %+v", out.TargetAccountIDs)
	}
	if out.AccountID != "222222222222" {
		t.Fatalf("expected primary account to be retained user account, got %q", out.AccountID)
	}
}

func TestAWSPermissionBoundaryExecutorAvoidsUnsafeAccountFallbackForUnresolvedSplitTarget(t *testing.T) {
	now := time.Date(2026, 6, 30, 12, 20, 0, 0, time.UTC)
	plan := AWSPermissionBoundarySCPPlan{
		PlanID:                "plan-multi-target-non-arn-user",
		Kind:                  awsPermissionBoundaryKind,
		ReadyForApply:         true,
		TargetIdentityNodeIDs: []string{"aws:identity:arn:aws:iam::111111111111:role/app-a", "aws:identity:user/app-user"},
		TargetAccountIDs:      []string{"111111111111", "222222222222"},
		BreakageProjection:    AWSPermissionBoundarySCPBreakageProjection{Level: "low"},
	}
	entry := AWSRemediationDryRunEntry{
		DryRunID:         "dr-multi-target-non-arn-user",
		CaseID:           "case-multi-target-non-arn-user",
		SourceType:       "aws_permission_boundary_scp",
		SourceArtifactID: "plan-multi-target-non-arn-user",
		IdempotencyKey:   "idk",
		Outcome:          awsRemediationDryRunOutcomeWouldSucceed,
		ReadyForApply:    true,
		DiffIntent:       AWSRemediationDiffIntent{Kind: "permission_boundary_diff"},
		IntendedAPICalls: []AWSRemediationDryRunIntendedAPICall{
			{
				Service:          "iam",
				Operation:        "PutRolePermissionsBoundary",
				TargetResource:   "aws:identity:arn:aws:iam::111111111111:role/app-a",
				ParameterRefs:    []string{"idk", "boundary_ref://case-multi-target-non-arn-user/after"},
				Idempotent:       true,
				RequiresApproval: true,
			},
			{
				Service:          "iam",
				Operation:        "PutUserPermissionsBoundary",
				TargetResource:   "aws:identity:user/app-user",
				ParameterRefs:    []string{"idk", "boundary_ref://case-multi-target-non-arn-user/after"},
				Idempotent:       true,
				RequiresApproval: true,
			},
		},
	}

	entries := awsPermissionBoundaryExecutorEntriesFromDryRun(entry, plan, now)
	if len(entries) != 2 {
		t.Fatalf("expected one executor entry per split target, got %+v", entries)
	}
	for _, out := range entries {
		if len(out.TargetIdentityNodeIDs) != 1 || out.TargetIdentityNodeIDs[0] != "aws:identity:user/app-user" {
			continue
		}
		if len(out.TargetAccountIDs) != 0 || out.AccountID != "" {
			t.Fatalf("non-ARN split target with no derivable account must not inherit the plan's full account list: %+v", out)
		}
	}
}

func TestAWSPermissionBoundaryExecutorFiltersUnsupportedTargets(t *testing.T) {
	now := time.Date(2026, 6, 30, 12, 15, 0, 0, time.UTC)
	plan := AWSPermissionBoundarySCPPlan{
		PlanID:                "plan-mixed-with-group",
		Kind:                  awsPermissionBoundaryKind,
		ReadyForApply:         true,
		TargetIdentityNodeIDs: []string{"aws:identity:arn:aws:iam::111111111111:role/app-role", "aws:identity:arn:aws:iam::111111111111:group/app-group", "aws:s3:::payments-prod"},
		TargetAccountIDs:      []string{"111111111111"},
		BreakageProjection:    AWSPermissionBoundarySCPBreakageProjection{Level: "low"},
	}
	entry := AWSRemediationDryRunEntry{
		DryRunID:         "dr-mixed-group",
		CaseID:           "case-mixed-group",
		SourceType:       "aws_permission_boundary_scp",
		SourceArtifactID: "plan-mixed-with-group",
		AccountID:        "111111111111",
		IdempotencyKey:   "idk",
		Outcome:          awsRemediationDryRunOutcomeWouldSucceed,
		ReadyForApply:    true,
		DiffIntent:       AWSRemediationDiffIntent{Kind: "permission_boundary_diff"},
		IntendedAPICalls: []AWSRemediationDryRunIntendedAPICall{{
			Service:          "iam",
			Operation:        "PutRolePermissionsBoundary",
			TargetResource:   "aws:identity:arn:aws:iam::111111111111:role/app-role",
			ParameterRefs:    []string{"idk", "boundary_ref://case-mixed-group/after"},
			Idempotent:       true,
			RequiresApproval: true,
		}},
	}

	entries := awsPermissionBoundaryExecutorEntriesFromDryRun(entry, plan, now)
	if len(entries) != 1 {
		t.Fatalf("group targets should be filtered, leaving a single role entry: %+v", entries)
	}
	out := entries[0]
	if out.Operation != "PutRolePermissionsBoundary" {
		t.Fatalf("expected role-only executor operation: %q", out.Operation)
	}
	for _, target := range out.TargetIdentityNodeIDs {
		if strings.Contains(target, ":group/") || strings.HasPrefix(target, "aws:s3:::") {
			t.Fatalf("unsupported target leaked into executor entry: %q", target)
		}
	}
}

func TestAWSPermissionBoundaryExecutorRejectsUnsupportedOnlyPlan(t *testing.T) {
	now := time.Date(2026, 6, 30, 12, 30, 0, 0, time.UTC)
	plan := AWSPermissionBoundarySCPPlan{
		PlanID:                "plan-group-only",
		Kind:                  awsPermissionBoundaryKind,
		ReadyForApply:         true,
		TargetIdentityNodeIDs: []string{"aws:identity:arn:aws:iam::111111111111:group/app-group", "aws:s3:::payments-prod"},
		TargetAccountIDs:      []string{"111111111111"},
		BreakageProjection:    AWSPermissionBoundarySCPBreakageProjection{Level: "low"},
	}
	entry := AWSRemediationDryRunEntry{
		DryRunID:         "dr-group-only",
		CaseID:           "case-group-only",
		SourceType:       "aws_permission_boundary_scp",
		SourceArtifactID: "plan-group-only",
		AccountID:        "111111111111",
		IdempotencyKey:   "idk",
		Outcome:          awsRemediationDryRunOutcomeWouldSucceed,
		ReadyForApply:    true,
		DiffIntent:       AWSRemediationDiffIntent{Kind: "permission_boundary_diff"},
		IntendedAPICalls: []AWSRemediationDryRunIntendedAPICall{{
			Service:          "iam",
			Operation:        "PutRolePermissionsBoundary",
			TargetResource:   "aws:identity:arn:aws:iam::111111111111:group/app-group",
			ParameterRefs:    []string{"idk", "boundary_ref://case-group-only/after"},
			Idempotent:       true,
			RequiresApproval: true,
		}},
	}

	if entries := awsPermissionBoundaryExecutorEntriesFromDryRun(entry, plan, now); len(entries) != 0 {
		t.Fatalf("unsupported-only boundary plan must not produce executor entries: %+v", entries)
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

func TestFilterAWSPermissionBoundaryExecutorEntriesMatchesTargetAccounts(t *testing.T) {
	entries := []AWSPermissionBoundaryExecutorEntry{
		{
			ExecutionID:      "exec-cross-account",
			DryRunID:         "dr-1",
			CaseID:           "case-1",
			PlanID:           "plan-cross-account",
			AccountID:        "",
			Region:           "us-east-1",
			State:            awsPermissionBoundaryExecutorStateBlocked,
			Severity:         "high",
			Operation:        "PutRolePermissionsBoundary",
			TargetAccountIDs: []string{"111111111111", "222222222222"},
		},
		{
			ExecutionID:      "exec-other-account",
			DryRunID:         "dr-2",
			CaseID:           "case-2",
			PlanID:           "plan-other-account",
			AccountID:        "333333333333",
			Region:           "us-east-1",
			State:            awsPermissionBoundaryExecutorStateProjected,
			Severity:         "medium",
			Operation:        "PutRolePermissionsBoundary",
			TargetAccountIDs: []string{"333333333333"},
		},
	}

	filtered, applied := filterAWSPermissionBoundaryExecutorEntries(entries, AWSPermissionBoundaryExecutorRequest{AccountID: "111111111111"})
	if applied["account_id"] != "111111111111" {
		t.Fatalf("expected applied account filter, got %+v", applied)
	}
	if len(filtered) != 1 || filtered[0].ExecutionID != "exec-cross-account" {
		t.Fatalf("expected target account match to retain cross-account entry: %+v", filtered)
	}

	filtered, _ = filterAWSPermissionBoundaryExecutorEntries(entries, AWSPermissionBoundaryExecutorRequest{AccountID: "444444444444"})
	if len(filtered) != 0 {
		t.Fatalf("unexpected entries for unmatched target account: %+v", filtered)
	}
}

func TestFilterAWSPermissionBoundaryExecutorEntriesKeepsMultiRegionEntries(t *testing.T) {
	entries := []AWSPermissionBoundaryExecutorEntry{
		{
			ExecutionID: "exec-multi-region",
			Region:      "",
			State:       awsPermissionBoundaryExecutorStateBlocked,
			Operation:   "PutRolePermissionsBoundary",
		},
		{
			ExecutionID: "exec-west",
			Region:      "us-west-2",
			State:       awsPermissionBoundaryExecutorStateProjected,
			Operation:   "PutRolePermissionsBoundary",
		},
	}

	filtered, applied := filterAWSPermissionBoundaryExecutorEntries(entries, AWSPermissionBoundaryExecutorRequest{Region: "us-east-1"})
	if applied["region"] != "us-east-1" {
		t.Fatalf("expected applied region filter, got %+v", applied)
	}
	if len(filtered) != 1 || filtered[0].ExecutionID != "exec-multi-region" {
		t.Fatalf("expected empty-region executor entry to survive region drill-down: %+v", filtered)
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
