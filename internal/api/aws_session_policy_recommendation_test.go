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

func newSessionPolicyRecommendationService(t *testing.T, project string, now time.Time) (*Service, string) {
	t.Helper()
	return newBlastRadiusService(t, project, now)
}

func TestGetAWSSessionPolicyRecommendationsBuildsContract(t *testing.T) {
	now := time.Date(2026, 7, 3, 10, 0, 0, 0, time.UTC)
	svc, ws := newSessionPolicyRecommendationService(t, "project-session-policy-recommendation", now)

	result, err := svc.GetAWSSessionPolicyRecommendations(defaultScopeContext(), ws, "project-session-policy-recommendation", AWSSessionPolicyRecommendationRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
	})
	if err != nil {
		t.Fatalf("get session policy recommendations: %v", err)
	}
	if result.CurrentIssueRef != "#1544" || result.Version != awsSessionPolicyRecommendationVersion || result.Mode != awsSessionPolicyRecommendationModeAdvisory {
		t.Fatalf("unexpected contract metadata: %+v", result)
	}
	if result.PolicyVersion != awsSessionPolicyRecommendationPolicyID {
		t.Fatalf("expected stable policy version, got %q", result.PolicyVersion)
	}
	if len(result.Recommendations) == 0 {
		t.Fatalf("expected recommendations to be projected from least-privilege source: %+v", result.Summary)
	}
	for _, rec := range result.Recommendations {
		if rec.RecommendationID == "" || rec.CalculationVersion != awsSessionPolicyRecommendationVersion {
			t.Fatalf("recommendation missing stable metadata: %+v", rec)
		}
		if rec.Mode != awsSessionPolicyRecommendationModeAdvisory {
			t.Fatalf("recommendation must remain advisory: %+v", rec)
		}
		switch rec.Decision {
		case "remove", "review":
		default:
			t.Fatalf("recommendation has unsupported decision: %+v", rec)
		}
		if !strings.HasPrefix(rec.SessionPolicyRef, "session-policy://") {
			t.Fatalf("recommendation must carry a metadata session_policy_ref: %+v", rec)
		}
		if rec.PrincipalNodeID == "" {
			t.Fatalf("recommendation must carry a principal_node_id: %+v", rec)
		}
		if len(rec.AllowActions) == 0 {
			t.Fatalf("recommendation must carry an allow-list derived from observed usage: %+v", rec)
		}
		if rec.EvidenceBoundary != awsSessionPolicyRecommendationEvidenceBoundary() {
			t.Fatalf("recommendation crossed evidence boundary: %+v", rec)
		}
		if !rec.ReadOnlyProjection {
			t.Fatalf("recommendation must remain read-only: %+v", rec)
		}
		if rec.Provenance.PolicyVersion == "" || rec.Provenance.SourceRuleName == "" {
			t.Fatalf("recommendation missing provenance: %+v", rec.Provenance)
		}
	}

	serialized, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	lower := strings.ToLower(string(serialized))
	for _, forbidden := range []string{"\"secret_access_key\"", "\"private_key\"", "\"policy_document_body\"", "\"rendered_policy\"", "\"session_policy_body\""} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("session policy recommendation serialized forbidden sensitive payload marker %q", forbidden)
		}
	}
}

func TestAWSSessionPolicyRecommendationAdmitsOnlyActionableRecords(t *testing.T) {
	cases := []struct {
		name string
		rec  AWSLeastPrivilegeRecommendation
		want bool
	}{
		{
			name: "remove decision with observed actions is admitted",
			rec: AWSLeastPrivilegeRecommendation{
				Decision:        "remove",
				IdentityNodeID:  "aws:identity:arn:aws:iam::111111111111:role/app",
				ObservedActions: []string{"s3:GetObject"},
			},
			want: true,
		},
		{
			name: "review decision with keep actions is admitted",
			rec: AWSLeastPrivilegeRecommendation{
				Decision:       "review",
				IdentityNodeID: "aws:identity:arn:aws:iam::111111111111:role/app",
				KeepActions:    []string{"s3:GetObject"},
			},
			want: true,
		},
		{
			name: "keep decision is not admitted",
			rec: AWSLeastPrivilegeRecommendation{
				Decision:        "keep",
				IdentityNodeID:  "aws:identity:arn:aws:iam::111111111111:role/app",
				ObservedActions: []string{"s3:GetObject"},
			},
			want: false,
		},
		{
			name: "no principal is not admitted",
			rec: AWSLeastPrivilegeRecommendation{
				Decision:        "remove",
				ObservedActions: []string{"s3:GetObject"},
			},
			want: false,
		},
		{
			name: "no observed or keep actions is not admitted",
			rec: AWSLeastPrivilegeRecommendation{
				Decision:       "remove",
				IdentityNodeID: "aws:identity:arn:aws:iam::111111111111:role/app",
			},
			want: false,
		},
	}
	for _, tc := range cases {
		if got := awsSessionPolicyRecommendationAdmits(tc.rec); got != tc.want {
			t.Fatalf("%s: admit=%v want %v", tc.name, got, tc.want)
		}
	}
}

func TestAWSSessionPolicyRecommendationFromLeastPrivilegeShape(t *testing.T) {
	now := time.Date(2026, 7, 3, 10, 30, 0, 0, time.UTC)
	rec := AWSLeastPrivilegeRecommendation{
		RecommendationID:   "lp-1",
		Decision:           "remove",
		Severity:           "medium",
		Score:              72,
		Confidence:         0.85,
		AccountID:          "111111111111",
		Region:             "us-east-1",
		IdentityNodeID:     "aws:identity:arn:aws:iam::111111111111:role/app",
		PrincipalARN:       "arn:aws:iam::111111111111:role/app",
		ResourceARN:        "arn:aws:s3:::payments/*",
		BreakagePrediction: "low",
		BreakageRationale:  "no observed use for six weeks",
		KeepActions:        []string{"s3:GetObject", "s3:ListBucket"},
		RemoveActions:      []string{"s3:DeleteObject"},
		ObservedActions:    []string{"s3:GetObject", "s3:ListBucket"},
	}
	out := awsSessionPolicyRecommendationFromLeastPrivilege(rec, now)
	if len(out.AllowActions) != 2 || out.AllowActions[0] != "s3:GetObject" {
		t.Fatalf("allow list must come from KeepActions when present: %+v", out.AllowActions)
	}
	if len(out.DenyActions) != 1 || out.DenyActions[0] != "s3:DeleteObject" {
		t.Fatalf("deny list must mirror RemoveActions: %+v", out.DenyActions)
	}
	if out.ExpectedBehavior.ObservedActionCount != 2 {
		t.Fatalf("expected observed count to reflect ObservedActions: %+v", out.ExpectedBehavior)
	}
	if out.SessionPolicyRef == "" || out.Provenance.SourceRuleName != "constrain_unused_actions" {
		t.Fatalf("remove decision must map to constrain_unused_actions rule: %+v", out.Provenance)
	}

	fallback := rec
	fallback.KeepActions = nil
	fallback.Decision = "review"
	back := awsSessionPolicyRecommendationFromLeastPrivilege(fallback, now)
	if len(back.AllowActions) != 2 || back.AllowActions[0] != "s3:GetObject" {
		t.Fatalf("allow list must fall back to ObservedActions when KeepActions is empty: %+v", back.AllowActions)
	}
	if back.Provenance.SourceRuleName != "surface_review_candidates" {
		t.Fatalf("review decision must map to surface_review_candidates rule: %+v", back.Provenance)
	}
}

func TestFilterAWSSessionPolicyRecommendations(t *testing.T) {
	entries := []AWSSessionPolicyRecommendationEntry{
		{
			RecommendationID: "aws-session-policy-recommendation:one",
			Decision:         "remove",
			Severity:         "high",
			AccountID:        "111111111111",
			Region:           "us-east-1",
			PrincipalNodeID:  "aws:identity:arn:aws:iam::111111111111:role/a",
			PrincipalARN:     "arn:aws:iam::111111111111:role/a",
			AllowActions:     []string{"s3:GetObject"},
		},
		{
			RecommendationID: "aws-session-policy-recommendation:two",
			Decision:         "review",
			Severity:         "medium",
			AccountID:        "222222222222",
			Region:           "us-west-2",
			PrincipalNodeID:  "aws:identity:arn:aws:iam::222222222222:role/b",
			AllowActions:     []string{"s3:ListBucket"},
		},
	}

	filtered, applied := filterAWSSessionPolicyRecommendations(entries, AWSSessionPolicyRecommendationRequest{Decision: "review"})
	if applied["decision"] != normalizeAWSRuntimeEventFilterToken("review") || len(filtered) != 1 || !strings.HasSuffix(filtered[0].RecommendationID, ":two") {
		t.Fatalf("decision filter did not scope entries: applied=%+v filtered=%+v", applied, filtered)
	}

	filtered, _ = filterAWSSessionPolicyRecommendations(entries, AWSSessionPolicyRecommendationRequest{AccountID: "111111111111"})
	if len(filtered) != 1 || !strings.HasSuffix(filtered[0].RecommendationID, ":one") {
		t.Fatalf("account_id filter did not scope entries: %+v", filtered)
	}

	filtered, _ = filterAWSSessionPolicyRecommendations(entries, AWSSessionPolicyRecommendationRequest{PrincipalID: "arn:aws:iam::111111111111:role/a"})
	if len(filtered) != 1 || !strings.HasSuffix(filtered[0].RecommendationID, ":one") {
		t.Fatalf("principal_id filter must match either node ID or ARN: %+v", filtered)
	}

	filtered, _ = filterAWSSessionPolicyRecommendations(entries, AWSSessionPolicyRecommendationRequest{Search: "listbucket"})
	if len(filtered) != 1 || !strings.HasSuffix(filtered[0].RecommendationID, ":two") {
		t.Fatalf("search must reach allow_actions: %+v", filtered)
	}
}

func TestAWSSessionPolicyRecommendationFixtureStates(t *testing.T) {
	now := time.Date(2026, 7, 3, 11, 0, 0, 0, time.UTC)
	svc, ws := newSessionPolicyRecommendationService(t, "project-session-policy-recommendation-fixture", now)

	for _, state := range []string{"success", "empty", "degraded", "partial_failure", "permission_denied"} {
		result, err := svc.GetAWSSessionPolicyRecommendations(defaultScopeContext(), ws, "project-session-policy-recommendation-fixture", AWSSessionPolicyRecommendationRequest{
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

func TestRouterAWSSessionPolicyRecommendations(t *testing.T) {
	now := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	svc, _ := newSessionPolicyRecommendationService(t, "project-session-policy-recommendation-route", now)
	r := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{})

	resp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-session-policy-recommendation-route/aws/session-policy-recommendations?connector_id=aws-prod&fixture_state=success", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	var body struct {
		Recs AWSSessionPolicyRecommendationResult `json:"session_policy_recommendations"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Recs.CurrentIssueRef != "#1544" || body.Recs.PolicyVersion != awsSessionPolicyRecommendationPolicyID {
		t.Fatalf("unexpected route payload: %+v", body.Recs)
	}
}
