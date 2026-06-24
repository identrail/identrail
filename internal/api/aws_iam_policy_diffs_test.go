package api

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/telemetry"
	"go.uber.org/zap"
)

func newIAMPolicyDiffService(t *testing.T, project string, now time.Time) (*Service, string) {
	t.Helper()
	return newBlastRadiusService(t, project, now)
}

func TestGetAWSIAMPolicyDiffsBuildsContract(t *testing.T) {
	now := time.Date(2026, 6, 24, 9, 0, 0, 0, time.UTC)
	svc, ws := newIAMPolicyDiffService(t, "project-iam-policy-diffs", now)

	result, err := svc.GetAWSIAMPolicyDiffs(defaultScopeContext(), ws, "project-iam-policy-diffs", AWSIAMPolicyDiffRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
	})
	if err != nil {
		t.Fatalf("get iam policy diffs: %v", err)
	}
	if result.CurrentIssueRef != "#1530" || result.Version != awsIAMPolicyDiffVersion || result.Status != "ready" {
		t.Fatalf("unexpected contract metadata: %+v", result)
	}
	if len(result.Diffs) == 0 || result.Summary.TotalDiffs != len(result.Diffs) {
		t.Fatalf("expected diff summary to match payload: %+v", result.Summary)
	}
	if result.Summary.DecisionCounts["remove"] == 0 && result.Summary.DecisionCounts["review"] == 0 {
		t.Fatalf("expected at least one remove or review decision: %+v", result.Summary.DecisionCounts)
	}
	if result.Summary.RelationshipCount != len(result.Relationships) || len(result.Relationships) == 0 {
		t.Fatalf("expected relationships and matching count: summary=%+v relationships=%+v", result.Summary, result.Relationships)
	}
	if len(result.Caveats) == 0 || len(result.CoverageGaps) == 0 {
		t.Fatalf("expected caveats and coverage gaps: %+v", result)
	}
	for i := 1; i < len(result.Diffs); i++ {
		if result.Diffs[i-1].Score < result.Diffs[i].Score {
			t.Fatalf("diffs are not ranked by descending score: %+v", result.Diffs)
		}
	}
	for _, d := range result.Diffs {
		if d.DiffID == "" || d.CalculationVersion != awsIAMPolicyDiffVersion || d.SourceRecommendationID == "" {
			t.Fatalf("diff missing stable metadata: %+v", d)
		}
		if d.Decision == "" || d.Severity == "" || d.Status == "" || d.Title == "" {
			t.Fatalf("diff missing classification fields: %+v", d)
		}
		if !d.ReadOnlyProjection {
			t.Fatalf("diff must be a read-only projection: %+v", d)
		}
		if len(d.StatementChanges) == 0 {
			t.Fatalf("diff missing statement changes: %+v", d)
		}
		if d.BreakageProjection.Level == "" || d.BreakageProjection.Rationale == "" {
			t.Fatalf("diff missing breakage projection: %+v", d.BreakageProjection)
		}
		if d.RollbackPlan.Strategy == "" || len(d.RollbackPlan.Steps) == 0 {
			t.Fatalf("diff missing rollback plan: %+v", d.RollbackPlan)
		}
		if d.VerificationPlan.Strategy == "" || len(d.VerificationPlan.Steps) == 0 {
			t.Fatalf("diff missing verification plan: %+v", d.VerificationPlan)
		}
		if d.EvidenceBoundary != awsIAMPolicyDiffEvidenceBoundary() {
			t.Fatalf("diff crossed evidence boundary: %+v", d)
		}
	}
}

func TestGetAWSIAMPolicyDiffsAppliesFilters(t *testing.T) {
	now := time.Date(2026, 6, 24, 9, 5, 0, 0, time.UTC)
	svc, ws := newIAMPolicyDiffService(t, "project-iam-policy-diff-filters", now)

	removeOnly, err := svc.GetAWSIAMPolicyDiffs(defaultScopeContext(), ws, "project-iam-policy-diff-filters", AWSIAMPolicyDiffRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
		Decision:     "remove",
	})
	if err != nil {
		t.Fatalf("decision filter: %v", err)
	}
	for _, d := range removeOnly.Diffs {
		if d.Decision != "remove" {
			t.Fatalf("decision filter leaked %s diff: %+v", d.Decision, d)
		}
	}
	if removeOnly.AppliedFilters["decision"] != "remove" {
		t.Fatalf("expected applied decision filter, got %+v", removeOnly.AppliedFilters)
	}

	highSeverity, err := svc.GetAWSIAMPolicyDiffs(defaultScopeContext(), ws, "project-iam-policy-diff-filters", AWSIAMPolicyDiffRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
		Severity:     "high",
	})
	if err != nil {
		t.Fatalf("severity filter: %v", err)
	}
	for _, d := range highSeverity.Diffs {
		if d.Severity != "high" {
			t.Fatalf("severity filter leaked %s diff: %+v", d.Severity, d)
		}
	}
}

func TestAWSIAMPolicyDiffFromRecommendation(t *testing.T) {
	now := time.Date(2026, 6, 24, 9, 10, 0, 0, time.UTC)

	remove := AWSLeastPrivilegeRecommendation{
		RecommendationID:   "least-priv:remove-test",
		CalculationVersion: "aws-least-privilege-v1",
		Decision:           "remove",
		Severity:           "medium",
		Status:             "action_required",
		Score:              74,
		Confidence:         0.84,
		AccountID:          "123456789012",
		Region:             "us-east-1",
		Service:            "s3",
		IdentityNodeID:     "aws:identity:arn:aws:iam::123456789012:role/data-loader",
		PrincipalARN:       "arn:aws:iam::123456789012:role/data-loader",
		ResourceNodeID:     "aws:resource:s3-bucket/data-loader",
		ResourceARN:        "arn:aws:s3:::data-loader",
		DisplayName:        "data-loader",
		BreakagePrediction: "low",
		Rationale:          "Removed actions have no observed callers.",
		RemoveActions:      []string{"s3:DeleteObject", "s3:DeleteBucket"},
		KeepActions:        []string{"s3:GetObject"},
		ObservedActions:    []string{"s3:GetObject"},
		GrantedActions:     []string{"s3:DeleteObject", "s3:DeleteBucket", "s3:GetObject"},
		ImpactedNodes:      []string{"aws:identity:arn:aws:iam::123456789012:role/data-loader", "aws:resource:s3-bucket/data-loader"},
	}
	d, ok := awsIAMPolicyDiffFromRecommendation(remove, now)
	if !ok {
		t.Fatalf("expected diff to be emitted for remove decision")
	}
	if len(d.RemovedActions) != 2 || len(d.KeptActions) != 1 {
		t.Fatalf("unexpected action sets: removed=%v kept=%v", d.RemovedActions, d.KeptActions)
	}
	if len(d.StatementChanges) != 1 || d.StatementChanges[0].ChangeKind != "scope_removed" {
		t.Fatalf("expected scope_removed statement change, got %+v", d.StatementChanges)
	}
	if !d.ReadyForApply {
		t.Fatalf("low-breakage, high-confidence remove diff should be ready_for_apply: %+v", d)
	}
	if d.VerificationPlan.Strategy != "policy_simulate" {
		t.Fatalf("remove diff must use policy_simulate verification, got %s", d.VerificationPlan.Strategy)
	}

	allRemoved := remove
	allRemoved.RecommendationID = "least-priv:remove-all"
	allRemoved.KeepActions = nil
	allRemoved.ObservedActions = nil
	allRemovedDiff, ok := awsIAMPolicyDiffFromRecommendation(allRemoved, now)
	if !ok {
		t.Fatalf("expected diff for full-remove case")
	}
	if allRemovedDiff.StatementChanges[0].ChangeKind != "statement_removed" {
		t.Fatalf("expected statement_removed change kind when no observed actions remain, got %+v", allRemovedDiff.StatementChanges)
	}
	if len(allRemovedDiff.ResourceScopeAfter) != 0 {
		t.Fatalf("full-remove diff should have empty resource_scope_after, got %+v", allRemovedDiff.ResourceScopeAfter)
	}

	review := remove
	review.RecommendationID = "least-priv:review"
	review.Decision = "review"
	review.BreakagePrediction = ""
	reviewDiff, ok := awsIAMPolicyDiffFromRecommendation(review, now)
	if !ok {
		t.Fatalf("expected diff for review case")
	}
	if reviewDiff.StatementChanges[0].ChangeKind != "manual_review" {
		t.Fatalf("review diff must use manual_review change kind, got %+v", reviewDiff.StatementChanges)
	}
	if reviewDiff.ReadyForApply {
		t.Fatalf("review diff must never be ready_for_apply: %+v", reviewDiff)
	}
	if reviewDiff.VerificationPlan.Strategy != "manual_review" || reviewDiff.RollbackPlan.Strategy != "manual_review" {
		t.Fatalf("review diff must use manual_review plans: rollback=%s verification=%s", reviewDiff.RollbackPlan.Strategy, reviewDiff.VerificationPlan.Strategy)
	}
	if reviewDiff.BreakageProjection.Level != "unknown" {
		t.Fatalf("review diff must report unknown breakage, got %s", reviewDiff.BreakageProjection.Level)
	}

	keep := remove
	keep.RecommendationID = "least-priv:keep"
	keep.Decision = "keep"
	if _, ok := awsIAMPolicyDiffFromRecommendation(keep, now); ok {
		t.Fatalf("keep decision must not produce a diff")
	}
}

func TestAWSIAMPolicyDiffSearchMatchesPlanDetails(t *testing.T) {
	diff := AWSIAMPolicyDiff{
		DiffID: "aws-iam-policy-diff:search-test",
		Title:  "Scope sample-role: remove 1 action(s)",
		BreakageProjection: AWSIAMPolicyDiffBreakageProjection{
			Level:   "low",
			Signals: []string{"observed_actions:5"},
		},
		RollbackPlan: AWSIAMPolicyDiffRollbackPlan{
			Strategy:    "re_attach_policy",
			Steps:       []string{"Re-attach the captured before_ref policy statement."},
			EvidenceRef: "evidence://least/sample-role",
		},
		VerificationPlan: AWSIAMPolicyDiffVerificationPlan{
			Strategy:       "policy_simulate",
			Steps:          []string{"Run IAM policy simulator against kept actions to confirm no regression."},
			SuccessSignals: []string{"policy_simulate:no-regression"},
			FailureSignals: []string{"policy_simulate:denied-observed-action"},
			EvidenceRef:    "evidence://least/sample-role",
		},
		StatementChanges: []AWSIAMPolicyStatementDiff{{
			ResourceBefore:  []string{"arn:aws:s3:::bucket-x"},
			ResourceAfter:   []string{"arn:aws:s3:::bucket-x"},
			ConditionBefore: []string{"aws:SourceVpce"},
			ConditionAfter:  []string{"aws:SourceVpce"},
		}},
	}
	cases := []struct {
		name   string
		needle string
	}{
		{"rollback step", "re-attach"},
		{"verification step", "simulator"},
		{"verification success signal", "no-regression"},
		{"verification failure signal", "denied-observed-action"},
		{"breakage signal", "observed_actions:5"},
		{"plan evidence ref", "evidence://least/sample-role"},
		{"statement resource", "bucket-x"},
		{"statement condition", "aws:SourceVpce"},
	}
	for _, tc := range cases {
		if !awsIAMPolicyDiffSearchMatch(diff, tc.needle) {
			t.Fatalf("search did not match %s needle %q", tc.name, tc.needle)
		}
	}
}

func TestAWSIAMPolicyDiffReadyForApplyGuards(t *testing.T) {
	now := time.Date(2026, 6, 24, 9, 15, 0, 0, time.UTC)
	base := AWSLeastPrivilegeRecommendation{
		RecommendationID:   "least-priv:ready-test",
		Decision:           "remove",
		Severity:           "medium",
		Status:             "action_required",
		Score:              72,
		Confidence:         0.84,
		AccountID:          "123456789012",
		Region:             "us-east-1",
		IdentityNodeID:     "aws:identity:arn:aws:iam::123456789012:role/ready-test",
		PrincipalARN:       "arn:aws:iam::123456789012:role/ready-test",
		DisplayName:        "ready-test",
		BreakagePrediction: "low",
		RemoveActions:      []string{"s3:DeleteObject"},
		KeepActions:        []string{"s3:GetObject"},
	}
	d, _ := awsIAMPolicyDiffFromRecommendation(base, now)
	if !d.ReadyForApply {
		t.Fatalf("low-breakage high-confidence remove must be ready_for_apply: %+v", d)
	}

	highBreakage := base
	highBreakage.RecommendationID = "least-priv:high-breakage"
	highBreakage.BreakagePrediction = "high"
	d2, _ := awsIAMPolicyDiffFromRecommendation(highBreakage, now)
	if d2.ReadyForApply {
		t.Fatalf("high-breakage diff must not be ready_for_apply: %+v", d2)
	}

	lowConf := base
	lowConf.RecommendationID = "least-priv:low-conf"
	lowConf.Confidence = 0.6
	d3, _ := awsIAMPolicyDiffFromRecommendation(lowConf, now)
	if d3.ReadyForApply {
		t.Fatalf("low-confidence diff must not be ready_for_apply: %+v", d3)
	}
}

func TestGetAWSIAMPolicyDiffsFailureStates(t *testing.T) {
	now := time.Date(2026, 6, 24, 9, 20, 0, 0, time.UTC)
	svc, ws := newIAMPolicyDiffService(t, "project-iam-policy-diff-states", now)

	denied, err := svc.GetAWSIAMPolicyDiffs(defaultScopeContext(), ws, "project-iam-policy-diff-states", AWSIAMPolicyDiffRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "permission_denied",
	})
	if err != nil {
		t.Fatalf("permission denied: %v", err)
	}
	if denied.Status != "blocked" || len(denied.Diffs) != 0 || len(denied.Diagnostics) == 0 || len(denied.FailureReasons) == 0 {
		t.Fatalf("permission denied must be explicit and suppress diffs: %+v", denied)
	}

	empty, err := svc.GetAWSIAMPolicyDiffs(defaultScopeContext(), ws, "project-iam-policy-diff-states", AWSIAMPolicyDiffRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "empty",
	})
	if err != nil {
		t.Fatalf("empty: %v", err)
	}
	if empty.Status != "degraded" || empty.Summary.TotalDiffs != 0 || len(empty.FailureReasons) == 0 {
		t.Fatalf("empty fixture should be explicit degraded no-evidence state: %+v", empty)
	}

	if _, err := svc.GetAWSIAMPolicyDiffs(defaultScopeContext(), ws, "project-iam-policy-diff-states", AWSIAMPolicyDiffRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "garbage",
	}); err == nil {
		t.Fatalf("invalid fixture state should fail validation")
	}
}

func TestRouterAWSIAMPolicyDiffs(t *testing.T) {
	now := time.Date(2026, 6, 24, 9, 25, 0, 0, time.UTC)
	svc, _ := newIAMPolicyDiffService(t, "project-iam-policy-diff-route", now)
	r := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{})

	resp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-iam-policy-diff-route/aws/iam-policy-diffs?connector_id=aws-prod&fixture_state=success&decision=remove", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	var body struct {
		Diffs AWSIAMPolicyDiffResult `json:"diffs"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Diffs.CurrentIssueRef != "#1530" || body.Diffs.AppliedFilters["decision"] != "remove" {
		t.Fatalf("unexpected route payload: %+v", body.Diffs)
	}
}
