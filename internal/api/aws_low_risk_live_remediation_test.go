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

func newLowRiskRemediationService(t *testing.T, project string, now time.Time) (*Service, string) {
	t.Helper()
	return newBlastRadiusService(t, project, now)
}

func TestGetAWSLowRiskRemediationBuildsContract(t *testing.T) {
	now := time.Date(2026, 6, 28, 10, 0, 0, 0, time.UTC)
	svc, ws := newLowRiskRemediationService(t, "project-low-risk-remediation", now)

	result, err := svc.GetAWSLowRiskRemediation(defaultScopeContext(), ws, "project-low-risk-remediation", AWSLowRiskRemediationRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
	})
	if err != nil {
		t.Fatalf("get low-risk remediation: %v", err)
	}
	if result.CurrentIssueRef != "#1538" || result.Version != awsLowRiskRemediationVersion {
		t.Fatalf("unexpected contract metadata: %+v", result)
	}
	if len(result.Allowlist) == 0 {
		t.Fatalf("expected allowlist to be present in the result: %+v", result)
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
		if entry.ExecutionID == "" || entry.CalculationVersion != awsLowRiskRemediationVersion || entry.DryRunID == "" || entry.CaseID == "" {
			t.Fatalf("entry missing stable metadata: %+v", entry)
		}
		if entry.IdempotencyKey == "" {
			t.Fatalf("entry missing idempotency key: %+v", entry)
		}
		if !entry.ReadOnlyProjection {
			t.Fatalf("entry must remain a read-only projection: %+v", entry)
		}
		if entry.Mutation.Service == "" || entry.Mutation.Operation == "" {
			t.Fatalf("entry missing mutation: %+v", entry)
		}
		if entry.AllowlistRule.Name == "" || entry.AllowlistRule.Action == "" {
			t.Fatalf("entry missing allowlist rule: %+v", entry)
		}
		if len(entry.Preflights) == 0 {
			t.Fatalf("entry missing preflights: %+v", entry)
		}
		if entry.EvidenceBoundary != awsLowRiskRemediationEvidenceBoundary() {
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
			t.Fatalf("low-risk remediation serialized forbidden sensitive payload marker %q", forbidden)
		}
	}
}

func TestAWSLowRiskRemediationOnlyAdmitsAllowlistedActions(t *testing.T) {
	now := time.Date(2026, 6, 28, 11, 0, 0, 0, time.UTC)
	allowlistByAction := map[string]AWSLowRiskRemediationAllowlistRule{}
	for _, rule := range awsLowRiskRemediationAllowlist() {
		allowlistByAction[strings.ToLower(rule.Action)] = rule
	}

	dryRunEntries := []AWSRemediationDryRunEntry{
		{
			DryRunID:       "dry-run-allowlisted",
			ApprovalID:     "approval-allowlisted",
			CaseID:         "case-allowlisted",
			SourceType:     "aws_access_key_quarantine",
			IdempotencyKey: "idk-1",
			Outcome:        awsRemediationDryRunOutcomeWouldSucceed,
			ReadyForApply:  true,
			IntendedAPICalls: []AWSRemediationDryRunIntendedAPICall{{
				Service:        "iam",
				Operation:      "UpdateAccessKey",
				TargetResource: "AKIA-orders",
				ParameterRefs:  []string{"status://inactive"},
			}},
		},
		{
			DryRunID:       "dry-run-not-allowlisted",
			ApprovalID:     "approval-not-allowlisted",
			CaseID:         "case-not-allowlisted",
			SourceType:     "trust_policy_hardening",
			IdempotencyKey: "idk-2",
			Outcome:        awsRemediationDryRunOutcomeWouldSucceed,
			ReadyForApply:  true,
			IntendedAPICalls: []AWSRemediationDryRunIntendedAPICall{{
				Service:        "iam",
				Operation:      "UpdateAssumeRolePolicy",
				TargetResource: "aws:identity:role/orders-ci",
			}},
		},
		{
			DryRunID:       "dry-run-wrong-source",
			ApprovalID:     "approval-wrong-source",
			CaseID:         "case-wrong-source",
			SourceType:     "blast_radius",
			IdempotencyKey: "idk-3",
			Outcome:        awsRemediationDryRunOutcomeWouldSucceed,
			ReadyForApply:  true,
			IntendedAPICalls: []AWSRemediationDryRunIntendedAPICall{{
				Service:        "iam",
				Operation:      "UpdateAccessKey",
				TargetResource: "AKIA-orders",
			}},
		},
	}

	entries := awsLowRiskRemediationEntries(dryRunEntries, allowlistByAction, now)
	if len(entries) != 1 {
		t.Fatalf("expected only the allowlisted-and-source-matched entry to admit, got %+v", entries)
	}
	if entries[0].DryRunID != "dry-run-allowlisted" {
		t.Fatalf("expected dry-run-allowlisted entry, got %+v", entries[0])
	}
	if entries[0].AllowlistRule.Name == "" || entries[0].AllowlistRule.Action != "iam:UpdateAccessKey" {
		t.Fatalf("admitted entry missing allowlist rule: %+v", entries[0].AllowlistRule)
	}
}

func TestAWSLowRiskRemediationEnforcesMaxBlastRadiusByRiskTier(t *testing.T) {
	now := time.Date(2026, 6, 28, 11, 30, 0, 0, time.UTC)
	allowlistByAction := map[string]AWSLowRiskRemediationAllowlistRule{}
	for _, rule := range awsLowRiskRemediationAllowlist() {
		allowlistByAction[strings.ToLower(rule.Action)] = rule
	}

	base := AWSRemediationDryRunEntry{
		CaseID:           "case-tier",
		SourceType:       "aws_access_key_quarantine",
		IdempotencyKey:   "idk",
		Outcome:          awsRemediationDryRunOutcomeWouldSucceed,
		ReadyForApply:    true,
		IntendedAPICalls: []AWSRemediationDryRunIntendedAPICall{{Service: "iam", Operation: "UpdateAccessKey", TargetResource: "AKIA-1"}},
	}

	low := base
	low.DryRunID = "dr-low"
	low.RiskTier = "low"
	low.Severity = "low"
	if got := awsLowRiskRemediationEntries([]AWSRemediationDryRunEntry{low}, allowlistByAction, now); len(got) != 1 {
		t.Fatalf("low risk_tier entry must be admitted, got %+v", got)
	}

	high := base
	high.DryRunID = "dr-high"
	high.RiskTier = "high"
	high.Severity = "high"
	if got := awsLowRiskRemediationEntries([]AWSRemediationDryRunEntry{high}, allowlistByAction, now); len(got) != 0 {
		t.Fatalf("high risk_tier entry must be excluded from the low-risk projection, got %+v", got)
	}

	criticalBySeverity := base
	criticalBySeverity.DryRunID = "dr-critical-severity"
	criticalBySeverity.RiskTier = "low"
	criticalBySeverity.Severity = "critical"
	if got := awsLowRiskRemediationEntries([]AWSRemediationDryRunEntry{criticalBySeverity}, allowlistByAction, now); len(got) != 0 {
		t.Fatalf("critical severity must be excluded even if risk_tier is reported low, got %+v", got)
	}

	mediumLow := base
	mediumLow.DryRunID = "dr-medium"
	mediumLow.RiskTier = "medium"
	mediumLow.Severity = "low"
	if got := awsLowRiskRemediationEntries([]AWSRemediationDryRunEntry{mediumLow}, allowlistByAction, now); len(got) != 0 {
		t.Fatalf("medium risk_tier exceeds MaxBlastRadius=low and must be excluded, got %+v", got)
	}
}

func TestAWSLowRiskRemediationAllowlistOnlyAdvertisesReachableActions(t *testing.T) {
	// Every allowlist rule must map to an AWS action the dry-run executor can
	// actually emit today. Advertising rules that the dry-run never produces
	// would mislead operators and the UI.
	reachable := map[string]struct{}{
		"iam:updateaccesskey":   {},
		"iam:detachrolepolicy":  {},
		"iam:detachuserpolicy":  {},
		"iam:detachgrouppolicy": {},
	}
	for _, rule := range awsLowRiskRemediationAllowlist() {
		if _, ok := reachable[strings.ToLower(rule.Action)]; !ok {
			t.Fatalf("allowlist rule %s advertises unreachable action %s; wire the dry-run executor before advertising it", rule.Name, rule.Action)
		}
	}
}

func TestAWSLowRiskRemediationStateHonorsDryRunGates(t *testing.T) {
	now := time.Date(2026, 6, 28, 12, 0, 0, 0, time.UTC)
	allowlistByAction := map[string]AWSLowRiskRemediationAllowlistRule{}
	for _, rule := range awsLowRiskRemediationAllowlist() {
		allowlistByAction[strings.ToLower(rule.Action)] = rule
	}
	ready := AWSRemediationDryRunEntry{
		DryRunID:         "dr-ready",
		CaseID:           "case-ready",
		SourceType:       "aws_access_key_quarantine",
		IdempotencyKey:   "idk",
		Outcome:          awsRemediationDryRunOutcomeWouldSucceed,
		ReadyForApply:    true,
		IntendedAPICalls: []AWSRemediationDryRunIntendedAPICall{{Service: "iam", Operation: "UpdateAccessKey", TargetResource: "AKIA-x"}},
	}
	entries := awsLowRiskRemediationEntries([]AWSRemediationDryRunEntry{ready}, allowlistByAction, now)
	if entries[0].State != awsLowRiskRemediationStateProjected || !entries[0].ReadyForLiveApply {
		t.Fatalf("ready dry-run must project ready-for-live-apply, got %+v", entries[0])
	}

	skipped := ready
	skipped.Outcome = awsRemediationDryRunOutcomeRequiresReview
	skipped.ReadyForApply = false
	skipped.DryRunID = "dr-skipped"
	skipped.CaseID = "case-skipped"
	entries = awsLowRiskRemediationEntries([]AWSRemediationDryRunEntry{skipped}, allowlistByAction, now)
	if entries[0].State != awsLowRiskRemediationStateSkipped || entries[0].ReadyForLiveApply {
		t.Fatalf("not-ready dry-run must surface skipped state, got %+v", entries[0])
	}

	blocked := ready
	blocked.DryRunID = "dr-blocked"
	blocked.CaseID = "case-blocked"
	blocked.KillSwitchEngaged = true
	entries = awsLowRiskRemediationEntries([]AWSRemediationDryRunEntry{blocked}, allowlistByAction, now)
	if entries[0].State != awsLowRiskRemediationStateBlocked || entries[0].ReadyForLiveApply {
		t.Fatalf("kill switch must block low-risk entry, got %+v", entries[0])
	}
}

func TestFilterAWSLowRiskRemediationEntriesAppliesFilters(t *testing.T) {
	entries := []AWSLowRiskRemediationEntry{
		{
			ExecutionID:   "exec-tag",
			DryRunID:      "dr-1",
			CaseID:        "case-1",
			AccountID:     "123456789012",
			Region:        "us-east-1",
			State:         awsLowRiskRemediationStateProjected,
			Severity:      "low",
			AllowlistRule: AWSLowRiskRemediationAllowlistRule{Name: "iam_tag_role_owner", Category: "tagging", Action: "iam:TagRole"},
			Mutation:      AWSLowRiskRemediationMutationRecord{Service: "iam", Operation: "TagRole"},
		},
		{
			ExecutionID:   "exec-detach",
			DryRunID:      "dr-2",
			CaseID:        "case-2",
			AccountID:     "123456789012",
			Region:        "us-east-1",
			State:         awsLowRiskRemediationStateBlocked,
			Severity:      "high",
			AllowlistRule: AWSLowRiskRemediationAllowlistRule{Name: "iam_detach_role_policy_orphaned", Category: "approved_detach", Action: "iam:DetachRolePolicy"},
			Mutation:      AWSLowRiskRemediationMutationRecord{Service: "iam", Operation: "DetachRolePolicy"},
		},
	}

	projected, applied := filterAWSLowRiskRemediationEntries(entries, AWSLowRiskRemediationRequest{State: awsLowRiskRemediationStateProjected})
	if applied["state"] != awsLowRiskRemediationStateProjected || len(projected) != 1 || projected[0].ExecutionID != "exec-tag" {
		t.Fatalf("expected state=projected filter: applied=%+v entries=%+v", applied, projected)
	}

	detach, applied := filterAWSLowRiskRemediationEntries(entries, AWSLowRiskRemediationRequest{ActionCategory: "approved_detach"})
	if applied["action_category"] != "approved-detach" || len(detach) != 1 || detach[0].ExecutionID != "exec-detach" {
		t.Fatalf("expected action_category filter: applied=%+v entries=%+v", applied, detach)
	}

	action, applied := filterAWSLowRiskRemediationEntries(entries, AWSLowRiskRemediationRequest{Action: "iam:TagRole"})
	if applied["action"] != "iam:TagRole" || len(action) != 1 || action[0].ExecutionID != "exec-tag" {
		t.Fatalf("expected action filter: applied=%+v entries=%+v", applied, action)
	}
}

func TestGetAWSLowRiskRemediationFailureStates(t *testing.T) {
	now := time.Date(2026, 6, 28, 13, 0, 0, 0, time.UTC)
	svc, ws := newLowRiskRemediationService(t, "project-low-risk-remediation-states", now)

	denied, err := svc.GetAWSLowRiskRemediation(defaultScopeContext(), ws, "project-low-risk-remediation-states", AWSLowRiskRemediationRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "permission_denied",
	})
	if err != nil {
		t.Fatalf("permission denied: %v", err)
	}
	if denied.Status != "blocked" || len(denied.Entries) != 0 {
		t.Fatalf("permission denied must be explicit and suppress entries: %+v", denied)
	}

	empty, err := svc.GetAWSLowRiskRemediation(defaultScopeContext(), ws, "project-low-risk-remediation-states", AWSLowRiskRemediationRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "empty",
	})
	if err != nil {
		t.Fatalf("empty: %v", err)
	}
	if empty.Status == "blocked" {
		t.Fatalf("empty fixture should not produce a blocked status: %+v", empty)
	}

	if _, err := svc.GetAWSLowRiskRemediation(defaultScopeContext(), ws, "project-low-risk-remediation-states", AWSLowRiskRemediationRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "garbage",
	}); err == nil {
		t.Fatalf("invalid fixture state should fail validation")
	}
}

func TestRouterAWSLowRiskRemediation(t *testing.T) {
	now := time.Date(2026, 6, 28, 14, 0, 0, 0, time.UTC)
	svc, _ := newLowRiskRemediationService(t, "project-low-risk-remediation-route", now)
	r := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{})

	resp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-low-risk-remediation-route/aws/low-risk-live-remediation?connector_id=aws-prod&fixture_state=success&state=projected", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	var body struct {
		LowRisk AWSLowRiskRemediationResult `json:"low_risk_live_remediation"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.LowRisk.CurrentIssueRef != "#1538" || body.LowRisk.AppliedFilters["state"] != "projected" {
		t.Fatalf("unexpected route payload: %+v", body.LowRisk)
	}
}
