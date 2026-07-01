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

func newRemediationApprovalService(t *testing.T, project string, now time.Time) (*Service, string) {
	t.Helper()
	return newBlastRadiusService(t, project, now)
}

func TestGetAWSRemediationApprovalQueueBuildsContract(t *testing.T) {
	now := time.Date(2026, 6, 26, 11, 0, 0, 0, time.UTC)
	svc, ws := newRemediationApprovalService(t, "project-remediation-approval", now)

	result, err := svc.GetAWSRemediationApprovalQueue(defaultScopeContext(), ws, "project-remediation-approval", AWSRemediationApprovalRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
	})
	if err != nil {
		t.Fatalf("get remediation approval queue: %v", err)
	}
	if result.CurrentIssueRef != "#1536" || result.Version != awsRemediationApprovalVersion {
		t.Fatalf("unexpected contract metadata: %+v", result)
	}
	if len(result.Entries) == 0 || result.Summary.TotalEntries != len(result.Entries) {
		t.Fatalf("expected approval entries and matching summary: %+v", result)
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
		if entry.ApprovalID == "" || entry.CalculationVersion != awsRemediationApprovalVersion || entry.CaseID == "" {
			t.Fatalf("entry missing stable metadata: %+v", entry)
		}
		if entry.IdempotencyKey == "" {
			t.Fatalf("entry missing idempotency key: %+v", entry)
		}
		if !entry.ReadOnlyProjection {
			t.Fatalf("entry must remain a read-only projection: %+v", entry)
		}
		if len(entry.RequiredApprovers) < 2 {
			t.Fatalf("entry must require at least two approvers: %+v", entry.RequiredApprovers)
		}
		if len(entry.RBACGates) == 0 || len(entry.FeatureFlags) == 0 {
			t.Fatalf("entry missing RBAC gates or feature flags: %+v", entry)
		}
		sawKillSwitch := false
		for _, flag := range entry.FeatureFlags {
			if flag.Name == "remediation_kill_switch" {
				sawKillSwitch = true
			}
		}
		if !sawKillSwitch {
			t.Fatalf("entry feature flags must include remediation_kill_switch: %+v", entry.FeatureFlags)
		}
		if entry.EvidenceBoundary != awsRemediationApprovalEvidenceBoundary() {
			t.Fatalf("entry crossed evidence boundary: %+v", entry)
		}
		if entry.ExpiresAt.IsZero() {
			t.Fatalf("entry expiry must be set: %+v", entry)
		}
	}

	serialized, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	lower := strings.ToLower(string(serialized))
	for _, forbidden := range []string{"\"secret_access_key\"", "\"private_key\"", "\"policy_document_body\"", "\"rendered_policy\""} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("approval queue serialized forbidden sensitive payload marker %q", forbidden)
		}
	}
}

func TestFilterAWSRemediationApprovalEntriesAppliesFilters(t *testing.T) {
	entries := []AWSRemediationApprovalEntry{
		{
			ApprovalID:        "ready",
			CaseID:            "case-a",
			AccountID:         "123456789012",
			Region:            "us-east-1",
			State:             awsRemediationApprovalStateApproved,
			RiskTier:          awsRemediationApprovalRiskLow,
			Severity:          "low",
			Scope:             AWSRemediationApprovalScope{ScopeType: "identity"},
			Requestor:         AWSRemediationApprovalActor{Role: "remediation-requestor", Label: "orders-platform"},
			RequiredApprovers: []AWSRemediationApprovalActor{{Role: "security-reviewer"}, {Role: "platform-operator"}},
			ReadyForExecution: true,
		},
		{
			ApprovalID:        "blocked",
			CaseID:            "case-b",
			AccountID:         "123456789012",
			Region:            "us-east-1",
			State:             awsRemediationApprovalStateBlocked,
			RiskTier:          awsRemediationApprovalRiskCritical,
			Severity:          "critical",
			Scope:             AWSRemediationApprovalScope{ScopeType: "account"},
			Requestor:         AWSRemediationApprovalActor{Role: "remediation-requestor", Label: "unassigned"},
			RequiredApprovers: []AWSRemediationApprovalActor{{Role: "security-reviewer"}, {Role: "platform-operator"}, {Role: "incident-commander"}},
			KillSwitchEngaged: true,
		},
	}

	ready, readyApplied := filterAWSRemediationApprovalEntries(entries, AWSRemediationApprovalRequest{ReadyForExecution: "yes"})
	if readyApplied["ready_for_execution"] != "yes" || len(ready) != 1 || ready[0].ApprovalID != "ready" {
		t.Fatalf("expected ready_for_execution=yes to match ready entries, got applied=%+v entries=%+v", readyApplied, ready)
	}

	critical, criticalApplied := filterAWSRemediationApprovalEntries(entries, AWSRemediationApprovalRequest{RiskTier: "critical"})
	if criticalApplied["risk_tier"] != "critical" || len(critical) != 1 || critical[0].ApprovalID != "blocked" {
		t.Fatalf("expected risk_tier=critical to match critical entries, got applied=%+v entries=%+v", criticalApplied, critical)
	}

	kill, killApplied := filterAWSRemediationApprovalEntries(entries, AWSRemediationApprovalRequest{KillSwitchEngaged: "true"})
	if killApplied["kill_switch_engaged"] != "true" || len(kill) != 1 || kill[0].ApprovalID != "blocked" {
		t.Fatalf("expected kill_switch_engaged=true to match killed entries, got applied=%+v entries=%+v", killApplied, kill)
	}

	approver, approverApplied := filterAWSRemediationApprovalEntries(entries, AWSRemediationApprovalRequest{ApproverRole: "incident-commander"})
	if approverApplied["approver_role"] != "incident-commander" || len(approver) != 1 || approver[0].ApprovalID != "blocked" {
		t.Fatalf("expected approver_role=incident-commander to match critical entries, got applied=%+v entries=%+v", approverApplied, approver)
	}
}

func TestFilterAWSRemediationApprovalEntriesMatchesScopeAccounts(t *testing.T) {
	entries := []AWSRemediationApprovalEntry{
		{
			ApprovalID: "boundary-cross-account",
			AccountID:  "",
			Scope:      AWSRemediationApprovalScope{ScopeType: "identity", AccountIDs: []string{"111111111111", "222222222222"}},
		},
		{
			ApprovalID: "boundary-other-account",
			AccountID:  "333333333333",
			Scope:      AWSRemediationApprovalScope{ScopeType: "identity", AccountIDs: []string{"333333333333"}},
		},
	}

	filtered, applied := filterAWSRemediationApprovalEntries(entries, AWSRemediationApprovalRequest{AccountID: "222222222222"})
	if applied["account_id"] != "222222222222" {
		t.Fatalf("expected applied account filter, got %+v", applied)
	}
	if len(filtered) != 1 || filtered[0].ApprovalID != "boundary-cross-account" {
		t.Fatalf("expected scope account match to retain approval entry: %+v", filtered)
	}
}

func TestFilterAWSRemediationApprovalEntriesKeepsMultiRegionBoundaryEntries(t *testing.T) {
	entries := []AWSRemediationApprovalEntry{
		{
			ApprovalID: "approval-multi-region-boundary",
			SourceType: "aws_permission_boundary_scp",
			Region:     "",
		},
		{
			ApprovalID: "approval-west-boundary",
			SourceType: "aws_permission_boundary_scp",
			Region:     "us-west-2",
		},
	}

	filtered, applied := filterAWSRemediationApprovalEntries(entries, AWSRemediationApprovalRequest{Region: "us-east-1"})
	if applied["region"] != "us-east-1" {
		t.Fatalf("expected applied region filter, got %+v", applied)
	}
	if len(filtered) != 1 || filtered[0].ApprovalID != "approval-multi-region-boundary" {
		t.Fatalf("expected empty-region boundary approval to survive region drill-down: %+v", filtered)
	}
}

func TestAWSRemediationApprovalEntryHonorsRBACGatesAndKillSwitch(t *testing.T) {
	source := AWSRemediationCase{
		CaseID:             "case-rbac",
		CalculationVersion: "test",
		Severity:           "high",
		Confidence:         0.92,
		OwnerAssigned:      false,
		Owner:              "",
		ApprovalRequired:   true,
		Lifecycle:          "proposed",
		ImpactedNodes:      []string{"aws:identity:role/orders-ci"},
	}
	entry := awsRemediationApprovalEntryFromCase(source, time.Date(2026, 6, 26, 11, 30, 0, 0, time.UTC), "aws-prod")
	if entry.State != awsRemediationApprovalStateBlocked {
		t.Fatalf("expected unassigned requestor to block approval, got state=%q gates=%+v", entry.State, entry.RBACGates)
	}
	if entry.ReadyForExecution {
		t.Fatalf("blocked entry must not be ready_for_execution: %+v", entry)
	}
	sawIncidentCommander := false
	for _, approver := range entry.RequiredApprovers {
		if approver.Role == "incident-commander" {
			sawIncidentCommander = true
		}
	}
	if !sawIncidentCommander {
		t.Fatalf("high-risk entry must require incident-commander approver: %+v", entry.RequiredApprovers)
	}
}

func TestAWSRemediationApprovalRequiresDataProtectionReviewerForSensitiveSources(t *testing.T) {
	cases := []struct {
		sourceType string
		want       bool
	}{
		{sourceType: "ai_agent_risk", want: true},
		{sourceType: "secret_permission_equivalence", want: true},
		{sourceType: "least_privilege", want: false},
		{sourceType: "aws_ai_agent_risk", want: false},
	}
	for _, tc := range cases {
		approvers := awsRemediationApprovalRequiredApprovers(AWSRemediationCase{SourceType: tc.sourceType}, awsRemediationApprovalRiskMedium)
		gotDataProtection := false
		for _, approver := range approvers {
			if approver.Role == "data-protection-reviewer" {
				gotDataProtection = true
			}
		}
		if gotDataProtection != tc.want {
			t.Fatalf("source_type=%q: data-protection-reviewer required=%v, got=%v approvers=%+v", tc.sourceType, tc.want, gotDataProtection, approvers)
		}
	}
}

func TestAWSRemediationApprovalScopeUsesAccountForBlastRadiusSource(t *testing.T) {
	cases := []struct {
		sourceType      string
		resourceNodeIDs []string
		want            string
	}{
		{sourceType: "blast_radius", resourceNodeIDs: []string{"aws:identity:role/orders-ci"}, want: "account"},
		{sourceType: "aws_blast_radius", resourceNodeIDs: []string{"aws:identity:role/orders-ci"}, want: "resource"},
		{sourceType: "least_privilege", resourceNodeIDs: []string{"aws:identity:role/orders-ci"}, want: "resource"},
		{sourceType: "least_privilege", resourceNodeIDs: nil, want: "identity"},
	}
	for _, tc := range cases {
		scope := awsRemediationApprovalScope(AWSRemediationCase{SourceType: tc.sourceType, ResourceNodeIDs: tc.resourceNodeIDs}, "aws-prod")
		if scope.ScopeType != tc.want {
			t.Fatalf("source_type=%q resourceNodes=%v: scope_type=%q want=%q", tc.sourceType, tc.resourceNodeIDs, scope.ScopeType, tc.want)
		}
	}
}

func TestAWSRemediationApprovalScopeFiltersPermissionBoundaryTargets(t *testing.T) {
	scope := awsRemediationApprovalScope(AWSRemediationCase{
		SourceType:     "aws_permission_boundary_scp",
		IdentityNodeID: "aws:identity:arn:aws:iam::111111111111:role/app-role",
		ResourceNodeIDs: []string{
			"aws:s3:::payments-prod",
			"aws:identity:arn:aws:iam::111111111111:group/app-group",
			"aws:identity:arn:aws:iam::222222222222:user/app-user",
		},
	}, "aws-prod")
	if scope.ScopeType != "identity" || len(scope.ResourceNodeIDs) != 0 {
		t.Fatalf("permission boundary scope should stay identity-only, got %+v", scope)
	}
	want := map[string]bool{
		"aws:identity:arn:aws:iam::111111111111:role/app-role": true,
		"aws:identity:arn:aws:iam::222222222222:user/app-user": true,
	}
	if len(scope.IdentityNodeIDs) != len(want) {
		t.Fatalf("expected only explicit IAM role/user targets, got %+v", scope.IdentityNodeIDs)
	}
	for _, target := range scope.IdentityNodeIDs {
		if !want[target] {
			t.Fatalf("unsupported permission boundary target leaked into approval scope: %q in %+v", target, scope.IdentityNodeIDs)
		}
	}
}

func TestAWSRemediationApprovalDeriveStatePreservesInReviewLifecycle(t *testing.T) {
	cases := []struct {
		lifecycle string
		want      string
	}{
		{lifecycle: "in_review", want: awsRemediationApprovalStateReview},
		{lifecycle: "under_review", want: awsRemediationApprovalStateReview},
		{lifecycle: "review", want: awsRemediationApprovalStateReview},
		{lifecycle: "proposed", want: awsRemediationApprovalStateRequested},
	}
	for _, tc := range cases {
		source := AWSRemediationCase{
			CaseID:           "case-lifecycle-" + tc.lifecycle,
			Lifecycle:        tc.lifecycle,
			Owner:            "orders-platform",
			OwnerAssigned:    true,
			ApprovalRequired: true,
			Confidence:       0.92,
		}
		gates := awsRemediationApprovalRBACGates(source, awsRemediationApprovalRequiredApprovers(source, awsRemediationApprovalRiskLow))
		got := awsRemediationApprovalDeriveState(source, gates, false)
		if got != tc.want {
			t.Fatalf("lifecycle=%q: state=%q want=%q gates=%+v", tc.lifecycle, got, tc.want, gates)
		}
	}
}

func TestAWSRemediationApprovalIdempotencyKeyIsDeterministic(t *testing.T) {
	source := AWSRemediationCase{CaseID: "case-determinism", CalculationVersion: "deterministic"}
	first := awsRemediationApprovalIdempotencyKey(source)
	second := awsRemediationApprovalIdempotencyKey(source)
	if first == "" || first != second {
		t.Fatalf("idempotency key must be deterministic and non-empty, got %q vs %q", first, second)
	}
}

func TestGetAWSRemediationApprovalQueueFailureStates(t *testing.T) {
	now := time.Date(2026, 6, 26, 12, 0, 0, 0, time.UTC)
	svc, ws := newRemediationApprovalService(t, "project-remediation-approval-states", now)

	denied, err := svc.GetAWSRemediationApprovalQueue(defaultScopeContext(), ws, "project-remediation-approval-states", AWSRemediationApprovalRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "permission_denied",
	})
	if err != nil {
		t.Fatalf("permission denied: %v", err)
	}
	if denied.Status != "blocked" || len(denied.Entries) != 0 {
		t.Fatalf("permission denied must be explicit and suppress entries: %+v", denied)
	}

	empty, err := svc.GetAWSRemediationApprovalQueue(defaultScopeContext(), ws, "project-remediation-approval-states", AWSRemediationApprovalRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "empty",
	})
	if err != nil {
		t.Fatalf("empty: %v", err)
	}
	if empty.Status == "blocked" {
		t.Fatalf("empty fixture should not produce a blocked status: %+v", empty)
	}

	if _, err := svc.GetAWSRemediationApprovalQueue(defaultScopeContext(), ws, "project-remediation-approval-states", AWSRemediationApprovalRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "garbage",
	}); err == nil {
		t.Fatalf("invalid fixture state should fail validation")
	}
}

func TestRouterAWSRemediationApprovalQueue(t *testing.T) {
	now := time.Date(2026, 6, 26, 12, 15, 0, 0, time.UTC)
	svc, _ := newRemediationApprovalService(t, "project-remediation-approval-route", now)
	r := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{})

	resp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-remediation-approval-route/aws/remediation-approval-queue?connector_id=aws-prod&fixture_state=success&risk_tier=high", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	var body struct {
		Queue AWSRemediationApprovalResult `json:"queue"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Queue.CurrentIssueRef != "#1536" || body.Queue.AppliedFilters["risk_tier"] != "high" {
		t.Fatalf("unexpected route payload: %+v", body.Queue)
	}
}
