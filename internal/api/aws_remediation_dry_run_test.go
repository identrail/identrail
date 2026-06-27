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

func newRemediationDryRunService(t *testing.T, project string, now time.Time) (*Service, string) {
	t.Helper()
	return newBlastRadiusService(t, project, now)
}

func TestGetAWSRemediationDryRunBuildsContract(t *testing.T) {
	now := time.Date(2026, 6, 27, 10, 0, 0, 0, time.UTC)
	svc, ws := newRemediationDryRunService(t, "project-remediation-dry-run", now)

	result, err := svc.GetAWSRemediationDryRun(defaultScopeContext(), ws, "project-remediation-dry-run", AWSRemediationDryRunRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
	})
	if err != nil {
		t.Fatalf("get remediation dry-run: %v", err)
	}
	if result.CurrentIssueRef != "#1537" || result.Version != awsRemediationDryRunVersion {
		t.Fatalf("unexpected contract metadata: %+v", result)
	}
	if len(result.Entries) == 0 || result.Summary.TotalEntries != len(result.Entries) {
		t.Fatalf("expected dry-run entries and matching summary: %+v", result)
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
		if entry.DryRunID == "" || entry.CalculationVersion != awsRemediationDryRunVersion || entry.ApprovalID == "" || entry.CaseID == "" {
			t.Fatalf("entry missing stable metadata: %+v", entry)
		}
		if entry.IdempotencyKey == "" || entry.DryRunRef == "" {
			t.Fatalf("entry missing idempotency key or dry_run_ref: %+v", entry)
		}
		if !entry.ReadOnlyProjection {
			t.Fatalf("entry must remain a read-only projection: %+v", entry)
		}
		if len(entry.IntendedAPICalls) == 0 {
			t.Fatalf("entry missing intended API calls: %+v", entry)
		}
		for _, call := range entry.IntendedAPICalls {
			if call.Service == "" || call.Operation == "" {
				t.Fatalf("intended API call missing service/operation: %+v", call)
			}
		}
		if len(entry.SatisfiedPrereqs)+len(entry.FailedPrereqs) == 0 {
			t.Fatalf("entry missing prerequisites: %+v", entry)
		}
		if len(entry.VerificationChecks) == 0 {
			t.Fatalf("entry missing verification checks: %+v", entry)
		}
		if entry.EvidenceBoundary != awsRemediationDryRunEvidenceBoundary() {
			t.Fatalf("entry crossed evidence boundary: %+v", entry)
		}
		if entry.Outcome == "" {
			t.Fatalf("entry missing outcome: %+v", entry)
		}
	}

	serialized, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	lower := strings.ToLower(string(serialized))
	for _, forbidden := range []string{"\"secret_access_key\"", "\"private_key\"", "\"policy_document_body\"", "\"rendered_policy\""} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("dry-run serialized forbidden sensitive payload marker %q", forbidden)
		}
	}
}

func TestFilterAWSRemediationDryRunEntriesAppliesFilters(t *testing.T) {
	entries := []AWSRemediationDryRunEntry{
		{
			DryRunID:   "ready",
			ApprovalID: "approval-a",
			CaseID:     "case-a",
			AccountID:  "123456789012",
			Region:     "us-east-1",
			SourceType: "least_privilege",
			Outcome:    awsRemediationDryRunOutcomeWouldSucceed,
			RiskTier:   awsRemediationApprovalRiskLow,
			Severity:   "low",
		},
		{
			DryRunID:   "kill",
			ApprovalID: "approval-b",
			CaseID:     "case-b",
			AccountID:  "123456789012",
			Region:     "us-east-1",
			SourceType: "trust_policy_hardening",
			Outcome:    awsRemediationDryRunOutcomeKillSwitched,
			RiskTier:   awsRemediationApprovalRiskCritical,
			Severity:   "critical",
		},
	}

	succeed, succeedApplied := filterAWSRemediationDryRunEntries(entries, AWSRemediationDryRunRequest{Outcome: awsRemediationDryRunOutcomeWouldSucceed})
	if succeedApplied["outcome"] != "would-succeed" || len(succeed) != 1 || succeed[0].DryRunID != "ready" {
		t.Fatalf("expected outcome=would_succeed filter: applied=%+v entries=%+v", succeedApplied, succeed)
	}

	trust, trustApplied := filterAWSRemediationDryRunEntries(entries, AWSRemediationDryRunRequest{SourceType: "trust_policy_hardening"})
	if trustApplied["source_type"] != "trust-policy-hardening" || len(trust) != 1 || trust[0].DryRunID != "kill" {
		t.Fatalf("expected source_type filter: applied=%+v entries=%+v", trustApplied, trust)
	}
}

func TestAWSRemediationDryRunOutcomeHonorsApprovalGates(t *testing.T) {
	now := time.Date(2026, 6, 27, 11, 0, 0, 0, time.UTC)

	approved := AWSRemediationApprovalEntry{
		ApprovalID:        "approval-approved",
		CaseID:            "case-approved",
		State:             awsRemediationApprovalStateApproved,
		ReadyForExecution: true,
		FeatureFlags:      []AWSRemediationApprovalFeatureFlag{{Name: "live_aws_mutation", Enabled: false, Rationale: "off"}},
		RBACGates:         []AWSRemediationApprovalRBACGate{{Name: "approver_quorum", Status: "passed"}},
		Scope:             AWSRemediationApprovalScope{IdentityNodeIDs: []string{"aws:identity:role/orders-ci"}},
	}
	if got := awsRemediationDryRunEntryFromApproval(approved, now).Outcome; got != awsRemediationDryRunOutcomeWouldSucceed {
		t.Fatalf("approved+ready entry must project would_succeed, got %q", got)
	}

	blocked := approved
	blocked.State = awsRemediationApprovalStateBlocked
	if got := awsRemediationDryRunEntryFromApproval(blocked, now).Outcome; got != awsRemediationDryRunOutcomeBlocked {
		t.Fatalf("blocked approval must project blocked outcome, got %q", got)
	}

	killSwitch := approved
	killSwitch.KillSwitchEngaged = true
	if got := awsRemediationDryRunEntryFromApproval(killSwitch, now).Outcome; got != awsRemediationDryRunOutcomeKillSwitched {
		t.Fatalf("kill switch must override outcome, got %q", got)
	}

	pending := approved
	pending.State = awsRemediationApprovalStateRequested
	if got := awsRemediationDryRunEntryFromApproval(pending, now).Outcome; got != awsRemediationDryRunOutcomeRequiresReview {
		t.Fatalf("pending approval must project requires_review, got %q", got)
	}

	failedGate := approved
	failedGate.RBACGates = []AWSRemediationApprovalRBACGate{{Name: "approver_quorum", Status: "blocked"}}
	entry := awsRemediationDryRunEntryFromApproval(failedGate, now)
	if entry.Outcome != awsRemediationDryRunOutcomeWouldFail {
		t.Fatalf("failed prerequisite must project would_fail, got %q", entry.Outcome)
	}
	if len(entry.FailedPrereqs) == 0 {
		t.Fatalf("failed prereqs must be populated when gate is blocked: %+v", entry.FailedPrereqs)
	}
	if entry.ReadyForApply {
		t.Fatalf("would_fail entry must not be ready_for_apply: %+v", entry)
	}
}

func TestAWSRemediationDryRunPrerequisitesTreatSafetyFlagsAsPassedWhenDisabled(t *testing.T) {
	approval := AWSRemediationApprovalEntry{
		ApprovalID:        "approval-safety-flags",
		CaseID:            "case-safety-flags",
		State:             awsRemediationApprovalStateApproved,
		ReadyForExecution: true,
		RBACGates:         []AWSRemediationApprovalRBACGate{{Name: "approver_quorum", Status: "passed"}},
		FeatureFlags: []AWSRemediationApprovalFeatureFlag{
			{Name: "aws_remediation_approval_workflow", Enabled: true, Rationale: "always on"},
			{Name: "remediation_kill_switch", Enabled: false, Rationale: "default off"},
			{Name: "live_aws_mutation", Enabled: false, Rationale: "default off"},
		},
	}
	satisfied, failed := awsRemediationDryRunPrerequisites(approval)
	if len(failed) != 0 {
		t.Fatalf("disabled kill switch / live_aws_mutation must not be a failed prereq: failed=%+v", failed)
	}
	for _, name := range []string{"feature_flag:remediation_kill_switch", "feature_flag:live_aws_mutation"} {
		found := false
		for _, prereq := range satisfied {
			if prereq.Name == name && prereq.Status == "passed" {
				found = true
			}
		}
		if !found {
			t.Fatalf("expected %s to be marked passed when disabled: satisfied=%+v", name, satisfied)
		}
	}
	entry := awsRemediationDryRunEntryFromApproval(approval, time.Date(2026, 6, 27, 14, 0, 0, 0, time.UTC))
	if entry.Outcome != awsRemediationDryRunOutcomeWouldSucceed || !entry.ReadyForApply {
		t.Fatalf("healthy approval with disabled safety flags must reach would_succeed/ready_for_apply, got outcome=%q ready=%v failed=%+v", entry.Outcome, entry.ReadyForApply, entry.FailedPrereqs)
	}

	// And the opposite: kill switch engaged must block.
	approvalKill := approval
	approvalKill.KillSwitchEngaged = true
	approvalKill.FeatureFlags = []AWSRemediationApprovalFeatureFlag{
		{Name: "remediation_kill_switch", Enabled: true, Rationale: "engaged"},
		{Name: "live_aws_mutation", Enabled: false, Rationale: "default off"},
	}
	_, failedKill := awsRemediationDryRunPrerequisites(approvalKill)
	sawKill := false
	for _, prereq := range failedKill {
		if prereq.Name == "feature_flag:remediation_kill_switch" {
			sawKill = true
		}
	}
	if !sawKill {
		t.Fatalf("expected engaged kill switch to register as a failed prereq: failed=%+v", failedKill)
	}
}

func TestAWSRemediationDryRunIntendedAPICallVariesBySourceType(t *testing.T) {
	cases := []struct {
		sourceType string
		service    string
		operation  string
	}{
		{"least_privilege", "iam", "PutRolePolicy"},
		{"trust_policy_hardening", "iam", "UpdateAssumeRolePolicy"},
		{"aws_permission_boundary_scp", "iam", "PutRolePermissionsBoundary"},
		{"aws_secret_key_rotation", "secretsmanager", "RotateSecret"},
		{"aws_access_key_quarantine", "iam", "UpdateAccessKey"},
		{"secret_permission_equivalence", "kms", "PutKeyPolicy"},
		{"ai_agent_risk", "bedrock-agent", "UpdateAgent"},
		{"blast_radius", "iam", "DetachRolePolicy"},
	}
	for _, tc := range cases {
		calls := awsRemediationDryRunIntendedAPICalls(AWSRemediationApprovalEntry{SourceType: tc.sourceType, CaseID: "case", IdempotencyKey: "idk"})
		if len(calls) == 0 || calls[0].Service != tc.service || calls[0].Operation != tc.operation {
			t.Fatalf("source_type=%q: expected %s.%s, got %+v", tc.sourceType, tc.service, tc.operation, calls)
		}
	}
}

func TestAWSRemediationDryRunIntendedAPICallPrefersDiffIntentKind(t *testing.T) {
	cases := []struct {
		name       string
		sourceType string
		diffKind   string
		service    string
		operation  string
	}{
		{name: "equivalence with secret_rotation diff", sourceType: "secret_permission_equivalence", diffKind: "secret_rotation", service: "secretsmanager", operation: "RotateSecret"},
		{name: "equivalence with iam_policy_diff", sourceType: "secret_permission_equivalence", diffKind: "iam_policy_diff", service: "iam", operation: "PutRolePolicy"},
		{name: "equivalence with kms grant diff", sourceType: "secret_permission_equivalence", diffKind: "kms_grant_diff", service: "kms", operation: "PutKeyPolicy"},
		{name: "blast radius with trust diff", sourceType: "blast_radius", diffKind: "iam_trust_diff", service: "iam", operation: "UpdateAssumeRolePolicy"},
		{name: "blast radius with ai agent scope", sourceType: "blast_radius", diffKind: "ai_agent_scope_change", service: "bedrock-agent", operation: "UpdateAgent"},
		{name: "iac trust pr", sourceType: "aws_iac_remediation", diffKind: "iac_trust_policy_pr", service: "iam", operation: "UpdateAssumeRolePolicy"},
	}
	for _, tc := range cases {
		approval := AWSRemediationApprovalEntry{
			SourceType:     tc.sourceType,
			CaseID:         "case-" + tc.name,
			IdempotencyKey: "idk",
			DiffIntent:     AWSRemediationDiffIntent{Kind: tc.diffKind},
		}
		calls := awsRemediationDryRunIntendedAPICalls(approval)
		if len(calls) == 0 || calls[0].Service != tc.service || calls[0].Operation != tc.operation {
			t.Fatalf("%s: expected %s.%s, got %+v", tc.name, tc.service, tc.operation, calls)
		}
	}

	// No-op diff intents (manual_review, owner_assignment) must surface as the
	// `manual_review:noop` call regardless of source type so the dry-run never
	// advertises a live AWS write the case engine declined to project.
	noopCases := []AWSRemediationApprovalEntry{
		{SourceType: "least_privilege", CaseID: "case-lp-noop", IdempotencyKey: "idk", DiffIntent: AWSRemediationDiffIntent{Kind: "manual_review", NoOp: true}},
		{SourceType: "ai_agent_risk", CaseID: "case-agent-noop", IdempotencyKey: "idk", DiffIntent: AWSRemediationDiffIntent{Kind: "owner_assignment", NoOp: true}},
		{SourceType: "blast_radius", CaseID: "case-blast-noop", IdempotencyKey: "idk", DiffIntent: AWSRemediationDiffIntent{Kind: "manual_review", NoOp: true}},
	}
	for _, noop := range noopCases {
		calls := awsRemediationDryRunIntendedAPICalls(noop)
		if len(calls) != 1 || calls[0].Service != "manual_review" || calls[0].Operation != "noop" {
			t.Fatalf("no-op diff intent (source=%s) must surface manual_review:noop, got %+v", noop.SourceType, calls)
		}
	}
}

func TestAWSRemediationDryRunIntendedAPICallTargetsResourceForResourceMutations(t *testing.T) {
	scope := AWSRemediationApprovalScope{
		IdentityNodeIDs: []string{"aws:identity:role/orders-ci"},
		ResourceNodeIDs: []string{"aws:secret:arn:aws:secretsmanager:us-east-1:123456789012:secret:orders-token"},
	}
	cases := []struct {
		name       string
		approval   AWSRemediationApprovalEntry
		wantTarget string
	}{
		{
			name: "secret_rotation diff targets the secret",
			approval: AWSRemediationApprovalEntry{
				SourceType:     "secret_permission_equivalence",
				CaseID:         "case-secret-rotation",
				IdempotencyKey: "idk",
				Scope:          scope,
				DiffIntent:     AWSRemediationDiffIntent{Kind: "secret_rotation"},
			},
			wantTarget: scope.ResourceNodeIDs[0],
		},
		{
			name: "kms grant diff targets the KMS resource",
			approval: AWSRemediationApprovalEntry{
				SourceType:     "secret_permission_equivalence",
				CaseID:         "case-kms",
				IdempotencyKey: "idk",
				Scope: AWSRemediationApprovalScope{
					IdentityNodeIDs: []string{"aws:identity:role/orders-ci"},
					ResourceNodeIDs: []string{"aws:kms:key/abcd"},
				},
				DiffIntent: AWSRemediationDiffIntent{Kind: "kms_grant_diff"},
			},
			wantTarget: "aws:kms:key/abcd",
		},
		{
			name: "iam policy diff targets the role identity",
			approval: AWSRemediationApprovalEntry{
				SourceType:     "secret_permission_equivalence",
				CaseID:         "case-iam",
				IdempotencyKey: "idk",
				Scope:          scope,
				DiffIntent:     AWSRemediationDiffIntent{Kind: "iam_policy_diff"},
			},
			wantTarget: scope.IdentityNodeIDs[0],
		},
		{
			name: "aws_secret_key_rotation source-type fallback targets the secret",
			approval: AWSRemediationApprovalEntry{
				SourceType:     "aws_secret_key_rotation",
				CaseID:         "case-rotation-source",
				IdempotencyKey: "idk",
				Scope:          scope,
			},
			wantTarget: scope.ResourceNodeIDs[0],
		},
	}
	for _, tc := range cases {
		calls := awsRemediationDryRunIntendedAPICalls(tc.approval)
		if len(calls) == 0 || calls[0].TargetResource != tc.wantTarget {
			t.Fatalf("%s: target_resource=%q want=%q calls=%+v", tc.name, calls[0].TargetResource, tc.wantTarget, calls)
		}
	}
}

func TestAWSRemediationDryRunKMSGrantDiffTargetsKMSKeyFromImpactedPath(t *testing.T) {
	// KMS-backed secret_permission_equivalence cases lead ResourceNodeIDs with
	// the protected secret and only carry the KMS key in the impacted path.
	// The dry-run must pick the KMS key as the PutKeyPolicy target.
	approval := AWSRemediationApprovalEntry{
		SourceType:     "secret_permission_equivalence",
		CaseID:         "case-kms-impacted",
		IdempotencyKey: "idk",
		Scope: AWSRemediationApprovalScope{
			IdentityNodeIDs: []string{"aws:identity:role/orders-ci"},
			ResourceNodeIDs: []string{"aws:secret:orders-token"},
		},
		ImpactedPath: []AWSRemediationApprovalPathStep{
			{NodeID: "aws:identity:role/orders-ci", NodeType: "identity", Label: "orders-ci"},
			{NodeID: "aws:kms:key/orders-cmk", NodeType: "kms_key", Label: "orders-cmk"},
			{NodeID: "aws:secret:orders-token", NodeType: "permission_bearing_secret", Label: "orders-token"},
		},
		DiffIntent: AWSRemediationDiffIntent{Kind: "kms_grant_diff"},
	}
	calls := awsRemediationDryRunIntendedAPICalls(approval)
	if len(calls) == 0 || calls[0].Service != "kms" || calls[0].Operation != "PutKeyPolicy" || calls[0].TargetResource != "aws:kms:key/orders-cmk" {
		t.Fatalf("kms_grant_diff must target the KMS key node from impacted_path, got %+v", calls)
	}

	// secret_rotation must still prefer the permission_bearing_secret node.
	approval.DiffIntent.Kind = "secret_rotation"
	approval.Scope.ResourceNodeIDs = []string{"aws:kms:key/orders-cmk"}
	calls = awsRemediationDryRunIntendedAPICalls(approval)
	if len(calls) == 0 || calls[0].Service != "secretsmanager" || calls[0].Operation != "RotateSecret" || calls[0].TargetResource != "aws:secret:orders-token" {
		t.Fatalf("secret_rotation must target the permission_bearing_secret node from impacted_path, got %+v", calls)
	}

	// When the impacted path is missing typed nodes, the generic resource
	// target still wins so the dry-run is never empty.
	approval.ImpactedPath = nil
	approval.Scope.ResourceNodeIDs = []string{"aws:secret:fallback"}
	approval.DiffIntent.Kind = "secret_rotation"
	calls = awsRemediationDryRunIntendedAPICalls(approval)
	if len(calls) == 0 || calls[0].TargetResource != "aws:secret:fallback" {
		t.Fatalf("missing impacted_path types must fall back to the generic resource target, got %+v", calls)
	}
}

func TestAWSRemediationDryRunVerificationSuppressesLiveChecksForNoOpDiffs(t *testing.T) {
	noop := AWSRemediationApprovalEntry{
		SourceType: "least_privilege",
		DiffIntent: AWSRemediationDiffIntent{Kind: "manual_review", NoOp: true},
	}
	checks := awsRemediationDryRunVerificationChecks(noop)
	if len(checks) != 1 || checks[0].Source != "manual_review" || checks[0].Signal != "noop" {
		t.Fatalf("no-op diff intent must surface a manual_review:noop verification check, got %+v", checks)
	}

	live := AWSRemediationApprovalEntry{
		SourceType: "trust_policy_hardening",
		DiffIntent: AWSRemediationDiffIntent{Kind: "iam_trust_diff"},
	}
	checks = awsRemediationDryRunVerificationChecks(live)
	if len(checks) < 2 {
		t.Fatalf("non-noop entries must keep live verification checks, got %+v", checks)
	}
	for _, check := range checks {
		if check.Source == "manual_review" && check.Signal == "noop" {
			t.Fatalf("non-noop entries must not include manual_review:noop, got %+v", checks)
		}
	}
}

func TestAWSRemediationDryRunIAMOperationFollowsPrincipalKind(t *testing.T) {
	cases := []struct {
		name       string
		approval   AWSRemediationApprovalEntry
		wantOp     string
		wantTarget string
	}{
		{
			name: "role principal keeps PutRolePolicy",
			approval: AWSRemediationApprovalEntry{
				SourceType:     "least_privilege",
				CaseID:         "case-role-lp",
				IdempotencyKey: "idk",
				Scope:          AWSRemediationApprovalScope{IdentityNodeIDs: []string{"aws:identity:role/orders-ci"}},
				DiffIntent:     AWSRemediationDiffIntent{Kind: "iam_policy_diff"},
			},
			wantOp:     "PutRolePolicy",
			wantTarget: "aws:identity:role/orders-ci",
		},
		{
			name: "user principal switches to PutUserPolicy",
			approval: AWSRemediationApprovalEntry{
				SourceType:     "least_privilege",
				CaseID:         "case-user-lp",
				IdempotencyKey: "idk",
				Scope:          AWSRemediationApprovalScope{IdentityNodeIDs: []string{"arn:aws:iam::123456789012:user/shakia-ci"}},
				DiffIntent:     AWSRemediationDiffIntent{Kind: "iam_policy_diff"},
			},
			wantOp:     "PutUserPolicy",
			wantTarget: "arn:aws:iam::123456789012:user/shakia-ci",
		},
		{
			name: "group principal switches to PutGroupPolicy",
			approval: AWSRemediationApprovalEntry{
				SourceType:     "least_privilege",
				CaseID:         "case-group-lp",
				IdempotencyKey: "idk",
				Scope:          AWSRemediationApprovalScope{IdentityNodeIDs: []string{"arn:aws:iam::123456789012:group/platform-engineers"}},
				DiffIntent:     AWSRemediationDiffIntent{Kind: "iam_policy_diff"},
			},
			wantOp:     "PutGroupPolicy",
			wantTarget: "arn:aws:iam::123456789012:group/platform-engineers",
		},
		{
			name: "user permission boundary switches to PutUserPermissionsBoundary",
			approval: AWSRemediationApprovalEntry{
				SourceType:     "aws_permission_boundary_scp",
				CaseID:         "case-user-boundary",
				IdempotencyKey: "idk",
				Scope:          AWSRemediationApprovalScope{IdentityNodeIDs: []string{"aws:identity:user/shakia-ci"}},
			},
			wantOp:     "PutUserPermissionsBoundary",
			wantTarget: "aws:identity:user/shakia-ci",
		},
		{
			name: "blast_radius user principal switches to DetachUserPolicy",
			approval: AWSRemediationApprovalEntry{
				SourceType:     "blast_radius",
				CaseID:         "case-blast-user",
				IdempotencyKey: "idk",
				Scope:          AWSRemediationApprovalScope{IdentityNodeIDs: []string{"arn:aws:iam::123456789012:user/shakia-ci"}},
			},
			wantOp:     "DetachUserPolicy",
			wantTarget: "arn:aws:iam::123456789012:user/shakia-ci",
		},
	}
	for _, tc := range cases {
		calls := awsRemediationDryRunIntendedAPICalls(tc.approval)
		if len(calls) == 0 || calls[0].Operation != tc.wantOp || calls[0].TargetResource != tc.wantTarget {
			t.Fatalf("%s: want op=%s target=%s, got %+v", tc.name, tc.wantOp, tc.wantTarget, calls)
		}
	}
}

func TestAWSRemediationDryRunVerificationChecksGateIAMSimulatorByDiffKind(t *testing.T) {
	cases := []struct {
		name          string
		approval      AWSRemediationApprovalEntry
		wantSimulator bool
		wantSignal    string
	}{
		{
			name: "iam_policy_diff includes simulator",
			approval: AWSRemediationApprovalEntry{
				SourceType: "least_privilege",
				DiffIntent: AWSRemediationDiffIntent{Kind: "iam_policy_diff"},
			},
			wantSimulator: true,
		},
		{
			name: "iam_trust_diff includes simulator",
			approval: AWSRemediationApprovalEntry{
				SourceType: "trust_policy_hardening",
				DiffIntent: AWSRemediationDiffIntent{Kind: "iam_trust_diff"},
			},
			wantSimulator: true,
		},
		{
			name:          "secret_rotation skips simulator and adds rotation_success",
			approval:      AWSRemediationApprovalEntry{SourceType: "secret_permission_equivalence", DiffIntent: AWSRemediationDiffIntent{Kind: "secret_rotation"}},
			wantSimulator: false,
			wantSignal:    "rotation_success",
		},
		{
			name:          "kms_grant_diff skips simulator and adds grant_policy_applied",
			approval:      AWSRemediationApprovalEntry{SourceType: "secret_permission_equivalence", DiffIntent: AWSRemediationDiffIntent{Kind: "kms_grant_diff"}},
			wantSimulator: false,
			wantSignal:    "grant_policy_applied",
		},
		{
			name:          "ai_agent_scope_change skips simulator and adds agent_scope_applied",
			approval:      AWSRemediationApprovalEntry{SourceType: "ai_agent_risk", DiffIntent: AWSRemediationDiffIntent{Kind: "ai_agent_scope_change"}},
			wantSimulator: false,
			wantSignal:    "agent_scope_applied",
		},
		{
			name:          "access_key_quarantine skips simulator and keeps last-used verification",
			approval:      AWSRemediationApprovalEntry{SourceType: "aws_access_key_quarantine", DiffIntent: AWSRemediationDiffIntent{Kind: "access_key_quarantine"}},
			wantSimulator: false,
			wantSignal:    "no_runtime_after_disable",
		},
		{
			name:          "empty diff kind falls back to source-type gate (least_privilege)",
			approval:      AWSRemediationApprovalEntry{SourceType: "least_privilege"},
			wantSimulator: true,
		},
		{
			name:          "empty diff kind for unrelated source skips simulator",
			approval:      AWSRemediationApprovalEntry{SourceType: "aws_secret_key_rotation"},
			wantSimulator: false,
		},
	}
	for _, tc := range cases {
		checks := awsRemediationDryRunVerificationChecks(tc.approval)
		sawSimulator := false
		sawSignal := tc.wantSignal == ""
		for _, check := range checks {
			if check.Source == "iam:policy_simulate" {
				sawSimulator = true
			}
			if tc.wantSignal != "" && check.Signal == tc.wantSignal {
				sawSignal = true
			}
		}
		if sawSimulator != tc.wantSimulator {
			t.Fatalf("%s: simulator presence=%v want=%v checks=%+v", tc.name, sawSimulator, tc.wantSimulator, checks)
		}
		if !sawSignal {
			t.Fatalf("%s: missing expected signal %q in checks=%+v", tc.name, tc.wantSignal, checks)
		}
	}
}

func TestAWSRemediationDryRunSecretRotationPicksProviderKeyNode(t *testing.T) {
	// AI-agent external_credential_exposure cases emit a secret_rotation diff
	// where `ResourceNodeIDs` only carries an empty sensitive resource — the
	// credential reference itself lives in the impacted path as a
	// `provider_key_reference` node. The dry-run must pick that node so the
	// RotateSecret target is the credential to rotate, not the agent identity.
	approval := AWSRemediationApprovalEntry{
		SourceType:     "ai_agent_risk",
		CaseID:         "case-provider-key",
		IdempotencyKey: "idk",
		Scope: AWSRemediationApprovalScope{
			IdentityNodeIDs: []string{"aws:identity:role/orders-agent"},
			ResourceNodeIDs: []string{},
		},
		ImpactedPath: []AWSRemediationApprovalPathStep{
			{NodeID: "aws:identity:role/orders-agent", NodeType: "identity", Label: "orders-agent"},
			{NodeID: "aws:provider-key:openai://orders-agent", NodeType: "provider_key_reference", Label: "openai key"},
		},
		DiffIntent: AWSRemediationDiffIntent{Kind: "secret_rotation"},
	}
	calls := awsRemediationDryRunIntendedAPICalls(approval)
	if len(calls) == 0 || calls[0].Service != "secretsmanager" || calls[0].Operation != "RotateSecret" {
		t.Fatalf("provider_key_reference cases must still route to secretsmanager:RotateSecret, got %+v", calls)
	}
	if calls[0].TargetResource != "aws:provider-key:openai://orders-agent" {
		t.Fatalf("secret_rotation must target the provider_key_reference node, got %q", calls[0].TargetResource)
	}
}

func TestAWSRemediationDryRunAffectedResourcesAreContextOnlyForNoOpDiffs(t *testing.T) {
	approval := AWSRemediationApprovalEntry{
		SourceType:     "least_privilege",
		CaseID:         "case-noop-affected",
		IdempotencyKey: "idk",
		Scope: AWSRemediationApprovalScope{
			IdentityNodeIDs: []string{"aws:identity:role/orders-ci"},
			ResourceNodeIDs: []string{"aws:s3:bucket/orders"},
		},
		ImpactedNodes: []string{"aws:identity:role/orders-ci", "aws:s3:bucket/orders", "aws:s3:bucket/exports"},
		DiffIntent:    AWSRemediationDiffIntent{Kind: "manual_review", NoOp: true},
	}
	intended := awsRemediationDryRunIntendedAPICalls(approval)
	resources := awsRemediationDryRunAffectedResources(approval, intended)
	if len(resources) == 0 {
		t.Fatalf("expected scope/impacted nodes to surface as context entries, got none")
	}
	for _, resource := range resources {
		if resource.ChangeKind != "context" {
			t.Fatalf("no-op diff intent must mark every affected resource as context, got %+v", resource)
		}
		if resource.NodeID == intended[0].TargetResource && resource.NodeID == "manual_review" {
			t.Fatalf("no-op diff intent must not record the noop call target as an api_target, got %+v", resource)
		}
	}
	// And the executable path should still record api_target / identity / resource / impacted kinds.
	live := approval
	live.DiffIntent = AWSRemediationDiffIntent{Kind: "iam_policy_diff"}
	liveCalls := awsRemediationDryRunIntendedAPICalls(live)
	liveResources := awsRemediationDryRunAffectedResources(live, liveCalls)
	sawAPITarget := false
	for _, resource := range liveResources {
		if resource.ChangeKind == "api_target" {
			sawAPITarget = true
		}
	}
	if !sawAPITarget {
		t.Fatalf("executable dry-run must still record an api_target affected resource, got %+v", liveResources)
	}
}

func TestGetAWSRemediationDryRunFailureStates(t *testing.T) {
	now := time.Date(2026, 6, 27, 12, 0, 0, 0, time.UTC)
	svc, ws := newRemediationDryRunService(t, "project-remediation-dry-run-states", now)

	denied, err := svc.GetAWSRemediationDryRun(defaultScopeContext(), ws, "project-remediation-dry-run-states", AWSRemediationDryRunRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "permission_denied",
	})
	if err != nil {
		t.Fatalf("permission denied: %v", err)
	}
	if denied.Status != "blocked" || len(denied.Entries) != 0 {
		t.Fatalf("permission denied must be explicit and suppress entries: %+v", denied)
	}

	empty, err := svc.GetAWSRemediationDryRun(defaultScopeContext(), ws, "project-remediation-dry-run-states", AWSRemediationDryRunRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "empty",
	})
	if err != nil {
		t.Fatalf("empty: %v", err)
	}
	if empty.Status == "blocked" {
		t.Fatalf("empty fixture should not produce a blocked status: %+v", empty)
	}

	if _, err := svc.GetAWSRemediationDryRun(defaultScopeContext(), ws, "project-remediation-dry-run-states", AWSRemediationDryRunRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "garbage",
	}); err == nil {
		t.Fatalf("invalid fixture state should fail validation")
	}
}

func TestRouterAWSRemediationDryRun(t *testing.T) {
	now := time.Date(2026, 6, 27, 13, 0, 0, 0, time.UTC)
	svc, _ := newRemediationDryRunService(t, "project-remediation-dry-run-route", now)
	r := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{})

	resp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-remediation-dry-run-route/aws/remediation-dry-run?connector_id=aws-prod&fixture_state=success&outcome=would_succeed", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	var body struct {
		DryRun AWSRemediationDryRunResult `json:"dry_run"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.DryRun.CurrentIssueRef != "#1537" || body.DryRun.AppliedFilters["outcome"] != "would-succeed" {
		t.Fatalf("unexpected route payload: %+v", body.DryRun)
	}
}
