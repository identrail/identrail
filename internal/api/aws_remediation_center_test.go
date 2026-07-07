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

func newRemediationCenterService(t *testing.T, project string, now time.Time) (*Service, string) {
	t.Helper()
	return newBlastRadiusService(t, project, now)
}

func TestGetAWSRemediationCenterBuildsContract(t *testing.T) {
	now := time.Date(2026, 7, 4, 10, 0, 0, 0, time.UTC)
	svc, ws := newRemediationCenterService(t, "project-remediation-center", now)

	result, err := svc.GetAWSRemediationCenter(defaultScopeContext(), ws, "project-remediation-center", AWSRemediationCenterRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
	})
	if err != nil {
		t.Fatalf("get remediation center: %v", err)
	}
	if result.CurrentIssueRef != "#1552" || result.Version != awsRemediationCenterVersion || result.PolicyVersion != awsRemediationCenterPolicyID {
		t.Fatalf("unexpected contract metadata: %+v", result)
	}
	if len(result.Cases) == 0 {
		t.Fatalf("expected case-keyed lifecycle rollups: %+v", result.Summary)
	}
	if result.Summary.TotalCases != len(result.RemediationCases.Cases) {
		t.Fatalf("summary total must match source case count: summary=%d cases=%d", result.Summary.TotalCases, len(result.RemediationCases.Cases))
	}
	if len(result.Tabs) == 0 {
		t.Fatalf("expected center tabs: %+v", result)
	}
	if len(result.EvidenceLinks) == 0 {
		t.Fatalf("expected evidence links: %+v", result)
	}
	validStages := map[string]bool{
		awsRemediationCenterStageCase: true, awsRemediationCenterStageApproval: true,
		awsRemediationCenterStageDryRun: true, awsRemediationCenterStageLiveAction: true,
		awsRemediationCenterStageVerification: true, awsRemediationCenterStageRollback: true,
	}
	for _, entry := range result.Cases {
		if entry.CaseID == "" || entry.Title == "" {
			t.Fatalf("case rollup missing identity fields: %+v", entry)
		}
		if !validStages[entry.Stage] {
			t.Fatalf("case rollup has unknown stage: %+v", entry)
		}
		if entry.EvidenceBoundary != awsRemediationCenterEvidenceBoundary() {
			t.Fatalf("case rollup crossed evidence boundary: %+v", entry)
		}
	}

	serialized, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	lower := strings.ToLower(string(serialized))
	for _, forbidden := range []string{"\"secret_value\"", "\"policy_document_body\"", "\"rendered_policy\"", "\"secret_access_key\""} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("remediation center serialized forbidden sensitive payload marker %q", forbidden)
		}
	}
}

func TestGetAWSRemediationCenterStitchesLifecycle(t *testing.T) {
	now := time.Date(2026, 7, 4, 10, 30, 0, 0, time.UTC)
	svc, ws := newRemediationCenterService(t, "project-remediation-center-lifecycle", now)

	result, err := svc.GetAWSRemediationCenter(defaultScopeContext(), ws, "project-remediation-center-lifecycle", AWSRemediationCenterRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
	})
	if err != nil {
		t.Fatalf("get remediation center: %v", err)
	}
	advanced := 0
	sawVerification := false
	for _, entry := range result.Cases {
		if entry.Stage == awsRemediationCenterStageCase {
			continue
		}
		advanced++
		// A case that advanced past `case` must carry the stage evidence
		// that drove it there.
		if entry.ApprovalID == "" {
			t.Fatalf("advanced case must carry its approval ID: %+v", entry)
		}
		if entry.Stage == awsRemediationCenterStageVerification || entry.Stage == awsRemediationCenterStageRollback {
			sawVerification = true
			if entry.VerificationID == "" || entry.DryRunID == "" {
				t.Fatalf("verification-stage case must carry verification and dry-run IDs: %+v", entry)
			}
		}
		if len(entry.SafetyGates) == 0 {
			t.Fatalf("advanced case must consolidate safety gates: %+v", entry)
		}
	}
	if advanced == 0 || !sawVerification {
		t.Fatalf("expected fixture cases to advance through the lifecycle incl. verification, got advanced=%d verification=%v", advanced, sawVerification)
	}
	if result.Summary.DryRunCount == 0 || result.Summary.VerificationCount == 0 {
		t.Fatalf("summary must count dry-run and verification stages: %+v", result.Summary)
	}
}

func TestFilterAWSRemediationCenterCases(t *testing.T) {
	entries := []AWSRemediationCenterCase{
		{CaseID: "c-1", Severity: "critical", Confidence: 0.95, IdentityType: "iam_role", ActionType: "iam_policy_diff", SourceType: "least_privilege", Lifecycle: "proposed", Stage: "dry_run", AccountID: "111111111111", Region: "us-east-1"},
		{CaseID: "c-2", Severity: "high", Confidence: 0.6, IdentityType: "iam_identity", ActionType: "secret_rotation", SourceType: "aws_secret_key_rotation", Lifecycle: "in_review", Stage: "verification", AccountID: "222222222222", Region: "us-west-2", VerificationState: "verification_verified"},
	}

	filtered, applied := filterAWSRemediationCenterCases(entries, AWSRemediationCenterRequest{Severity: "critical"})
	if applied["severity"] != normalizeAWSRuntimeEventFilterToken("critical") || len(filtered) != 1 || filtered[0].CaseID != "c-1" {
		t.Fatalf("severity filter did not scope: applied=%+v filtered=%+v", applied, filtered)
	}

	filtered, _ = filterAWSRemediationCenterCases(entries, AWSRemediationCenterRequest{Stage: "verification"})
	if len(filtered) != 1 || filtered[0].CaseID != "c-2" {
		t.Fatalf("stage filter did not scope: %+v", filtered)
	}

	filtered, applied = filterAWSRemediationCenterCases(entries, AWSRemediationCenterRequest{Confidence: "0.9"})
	if applied["confidence"] != "0.9" || len(filtered) != 1 || filtered[0].CaseID != "c-1" {
		t.Fatalf("numeric confidence floor did not scope: applied=%+v filtered=%+v", applied, filtered)
	}

	filtered, _ = filterAWSRemediationCenterCases(entries, AWSRemediationCenterRequest{Confidence: "high"})
	if len(filtered) != 1 || filtered[0].CaseID != "c-1" {
		t.Fatalf("bucket confidence floor did not scope: %+v", filtered)
	}

	filtered, _ = filterAWSRemediationCenterCases(entries, AWSRemediationCenterRequest{IdentityType: "iam_role"})
	if len(filtered) != 1 || filtered[0].CaseID != "c-1" {
		t.Fatalf("identity_type filter did not scope: %+v", filtered)
	}

	filtered, _ = filterAWSRemediationCenterCases(entries, AWSRemediationCenterRequest{ActionType: "secret_rotation"})
	if len(filtered) != 1 || filtered[0].CaseID != "c-2" {
		t.Fatalf("action_type filter did not scope: %+v", filtered)
	}

	filtered, _ = filterAWSRemediationCenterCases(entries, AWSRemediationCenterRequest{AccountID: "222222222222"})
	if len(filtered) != 1 || filtered[0].CaseID != "c-2" {
		t.Fatalf("account_id filter did not scope: %+v", filtered)
	}

	filtered, _ = filterAWSRemediationCenterCases(entries, AWSRemediationCenterRequest{Status: "verification_verified"})
	if len(filtered) != 1 || filtered[0].CaseID != "c-2" {
		t.Fatalf("status filter must match execution/verification state: %+v", filtered)
	}
}

func TestAWSRemediationCenterConfidenceFloor(t *testing.T) {
	cases := []struct {
		value string
		want  float64
		ok    bool
	}{
		{"", 0, false},
		{"high", 0.85, true},
		{"medium", 0.6, true},
		{"low", 0, true},
		{"0.75", 0.75, true},
		{"1", 1, true},
		{"0", 0, true},
		{"1.5", 0, false},
		{"-0.1", 0, false},
		{"bogus", 0, false},
	}
	for _, tc := range cases {
		got, ok := awsRemediationCenterConfidenceFloor(tc.value)
		if ok != tc.ok || (ok && got != tc.want) {
			t.Fatalf("value=%q got (%v,%v) want (%v,%v)", tc.value, got, ok, tc.want, tc.ok)
		}
	}
}

func TestGetAWSRemediationCenterFixtureStates(t *testing.T) {
	now := time.Date(2026, 7, 4, 11, 0, 0, 0, time.UTC)
	svc, ws := newRemediationCenterService(t, "project-remediation-center-fixture", now)

	for _, state := range []string{"success", "empty", "degraded", "partial_failure", "permission_denied"} {
		result, err := svc.GetAWSRemediationCenter(defaultScopeContext(), ws, "project-remediation-center-fixture", AWSRemediationCenterRequest{
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
		if state == "permission_denied" && result.Status != "permission_denied" {
			t.Fatalf("permission denied must surface as explicit status, got %q", result.Status)
		}
	}
}

func TestRouterAWSRemediationCenter(t *testing.T) {
	now := time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC)
	svc, _ := newRemediationCenterService(t, "project-remediation-center-route", now)
	r := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{})

	resp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-remediation-center-route/aws/remediation-center?connector_id=aws-prod&fixture_state=success&stage=verification", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	var body struct {
		Center AWSRemediationCenterResult `json:"remediation_center"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Center.CurrentIssueRef != "#1552" || body.Center.AppliedFilters["stage"] != "verification" {
		t.Fatalf("unexpected route payload: %+v", body.Center)
	}
	for _, entry := range body.Center.Cases {
		if entry.Stage != awsRemediationCenterStageVerification {
			t.Fatalf("stage=verification route returned wrong stage: %+v", entry)
		}
	}

	badFixture := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-remediation-center-route/aws/remediation-center?connector_id=aws-prod&fixture_state=bogus", "")
	if badFixture.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid fixture state, got %d body=%s", badFixture.Code, badFixture.Body.String())
	}
}
