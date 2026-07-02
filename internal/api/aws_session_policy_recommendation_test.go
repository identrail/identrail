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
			name: "whitespace-only observed and keep actions is not admitted",
			rec: AWSLeastPrivilegeRecommendation{
				Decision:        "remove",
				IdentityNodeID:  "aws:identity:arn:aws:iam::111111111111:role/app",
				KeepActions:     []string{"   ", ""},
				ObservedActions: []string{"\t"},
			},
			want: false,
		},
		{
			name: "agent-tool synthetic actions are not admitted",
			rec: AWSLeastPrivilegeRecommendation{
				Decision:        "remove",
				IdentityNodeID:  "aws:identity:arn:aws:iam::111111111111:role/agent-runtime",
				KeepActions:     []string{"agent-tool:filesystem"},
				ObservedActions: []string{"agent-tool:web"},
			},
			want: false,
		},
		{
			name: "aws-service placeholder actions are not admitted",
			rec: AWSLeastPrivilegeRecommendation{
				Decision:        "remove",
				IdentityNodeID:  "arn:aws:iam::111111111111:role/stale-service",
				KeepActions:     []string{"aws-service:*"},
				ObservedActions: []string{"aws-service:*"},
			},
			want: false,
		},
		{
			name: "mixed valid and synthetic actions are admitted (only IAM actions kept)",
			rec: AWSLeastPrivilegeRecommendation{
				Decision:        "remove",
				IdentityNodeID:  "aws:identity:arn:aws:iam::111111111111:role/agent-runtime",
				KeepActions:     []string{"agent-tool:filesystem", "s3:GetObject"},
				ObservedActions: []string{},
			},
			want: true,
		},
		{
			name: "IAM user principal is not admitted (STS AssumeRole requires a role)",
			rec: AWSLeastPrivilegeRecommendation{
				Decision:        "remove",
				IdentityNodeID:  "arn:aws:iam::111111111111:user/actor",
				PrincipalARN:    "arn:aws:iam::111111111111:user/actor",
				ObservedActions: []string{"s3:GetObject"},
			},
			want: false,
		},
		{
			name: "IAM group principal is not admitted",
			rec: AWSLeastPrivilegeRecommendation{
				Decision:        "remove",
				IdentityNodeID:  "arn:aws:iam::111111111111:group/analysts",
				ObservedActions: []string{"s3:GetObject"},
			},
			want: false,
		},
		{
			name: "unparseable identity is not admitted (avoid misleading STS guidance)",
			rec: AWSLeastPrivilegeRecommendation{
				Decision:        "remove",
				IdentityNodeID:  "some-opaque-node-id",
				ObservedActions: []string{"s3:GetObject"},
			},
			want: false,
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

func TestAWSSessionPolicyRecommendationFiltersSyntheticActions(t *testing.T) {
	now := time.Date(2026, 7, 3, 10, 45, 0, 0, time.UTC)
	rec := AWSLeastPrivilegeRecommendation{
		RecommendationID: "lp-agent",
		Decision:         "remove",
		IdentityNodeID:   "aws:identity:arn:aws:iam::111111111111:role/agent-runtime",
		KeepActions:      []string{"agent-tool:filesystem", "s3:GetObject", "  ", "kms:Decrypt"},
		RemoveActions:    []string{"agent-tool:web", "iam:DeleteRole"},
		ObservedActions:  []string{"agent-tool:filesystem"},
	}
	out := awsSessionPolicyRecommendationFromLeastPrivilege(rec, now)
	for _, action := range out.AllowActions {
		if strings.HasPrefix(action, "agent-tool:") {
			t.Fatalf("allow_actions must not contain synthetic agent-tool actions: %+v", out.AllowActions)
		}
	}
	if len(out.AllowActions) != 2 || out.AllowActions[0] != "s3:GetObject" || out.AllowActions[1] != "kms:Decrypt" {
		t.Fatalf("allow_actions must retain valid IAM actions in order: %+v", out.AllowActions)
	}
	for _, action := range out.DenyActions {
		if strings.HasPrefix(action, "agent-tool:") {
			t.Fatalf("deny_actions must not contain synthetic agent-tool actions: %+v", out.DenyActions)
		}
	}
	if len(out.DenyActions) != 1 || out.DenyActions[0] != "iam:DeleteRole" {
		t.Fatalf("deny_actions must retain valid IAM actions: %+v", out.DenyActions)
	}
}

func TestAWSSessionPolicyRecommendationResourceScopeExcludesGraphNodes(t *testing.T) {
	now := time.Date(2026, 7, 3, 10, 50, 0, 0, time.UTC)

	graphOnly := AWSLeastPrivilegeRecommendation{
		RecommendationID: "lp-graph-only",
		Decision:         "remove",
		IdentityNodeID:   "aws:identity:arn:aws:iam::111111111111:role/app",
		ResourceNodeID:   "aws:resource:secrets-manager-secret:openai/api-key",
		KeepActions:      []string{"secretsmanager:GetSecretValue"},
	}
	out := awsSessionPolicyRecommendationFromLeastPrivilege(graphOnly, now)
	if len(out.ResourceScope) != 1 || out.ResourceScope[0] != "*" {
		t.Fatalf("graph-node-only records must fall back to `*` for the session-policy resource scope: %+v", out.ResourceScope)
	}

	mixed := AWSLeastPrivilegeRecommendation{
		RecommendationID: "lp-mixed",
		Decision:         "remove",
		IdentityNodeID:   "aws:identity:arn:aws:iam::111111111111:role/app",
		ResourceARN:      "arn:aws:secretsmanager:us-east-1:111111111111:secret:openai/api-key",
		ResourceNodeID:   "aws:resource:secrets-manager-secret:openai/api-key",
		KeepActions:      []string{"secretsmanager:GetSecretValue"},
	}
	out = awsSessionPolicyRecommendationFromLeastPrivilege(mixed, now)
	if len(out.ResourceScope) != 1 || out.ResourceScope[0] != "arn:aws:secretsmanager:us-east-1:111111111111:secret:openai/api-key" {
		t.Fatalf("mixed records must keep only ARNs in the session-policy resource scope: %+v", out.ResourceScope)
	}
	for _, value := range out.ResourceScope {
		if strings.HasPrefix(value, "aws:") {
			t.Fatalf("session-policy resource scope must not carry graph node IDs: %+v", out.ResourceScope)
		}
	}
}

func TestAWSSessionPolicyRecommendationExpandsS3BucketScope(t *testing.T) {
	now := time.Date(2026, 7, 3, 10, 55, 0, 0, time.UTC)

	bucketOnly := AWSLeastPrivilegeRecommendation{
		RecommendationID: "lp-s3-bucket",
		Decision:         "remove",
		IdentityNodeID:   "aws:identity:arn:aws:iam::111111111111:role/reader",
		Service:          "s3",
		ResourceARN:      "arn:aws:s3:::payments-prod",
		KeepActions:      []string{"s3:GetObject", "s3:ListBucket"},
	}
	out := awsSessionPolicyRecommendationFromLeastPrivilege(bucketOnly, now)
	if len(out.ResourceScope) != 2 {
		t.Fatalf("S3 bucket ARN must expand to include object scope: %+v", out.ResourceScope)
	}
	sawBucket, sawObject := false, false
	for _, value := range out.ResourceScope {
		if value == "arn:aws:s3:::payments-prod" {
			sawBucket = true
		}
		if value == "arn:aws:s3:::payments-prod/*" {
			sawObject = true
		}
	}
	if !sawBucket || !sawObject {
		t.Fatalf("S3 scope must contain both the bucket ARN and the /* object ARN: %+v", out.ResourceScope)
	}

	objectARN := bucketOnly
	objectARN.RecommendationID = "lp-s3-object"
	objectARN.ResourceARN = "arn:aws:s3:::payments-prod/reports/*"
	out = awsSessionPolicyRecommendationFromLeastPrivilege(objectARN, now)
	if len(out.ResourceScope) != 1 || out.ResourceScope[0] != "arn:aws:s3:::payments-prod/reports/*" {
		t.Fatalf("already-object-scoped S3 ARN must not double-expand: %+v", out.ResourceScope)
	}
}

func TestAWSSessionPolicyRecommendationS3ObjectScope(t *testing.T) {
	cases := []struct {
		arn  string
		want string
	}{
		{"arn:aws:s3:::payments-prod", "arn:aws:s3:::payments-prod/*"},
		{"arn:aws:s3:::my-bucket-123", "arn:aws:s3:::my-bucket-123/*"},
		{"arn:aws:s3:::payments-prod/*", ""},
		{"arn:aws:s3:::payments-prod/reports/*", ""},
		{"arn:aws:s3:::", ""},
		{"arn:aws:secretsmanager:us-east-1:111111111111:secret:openai/api-key", ""},
		{"*", ""},
	}
	for _, tc := range cases {
		if got := awsSessionPolicyRecommendationS3ObjectScope(tc.arn); got != tc.want {
			t.Fatalf("arn=%q got %q want %q", tc.arn, got, tc.want)
		}
	}
}

func TestAWSSessionPolicyRecommendationIsValidResource(t *testing.T) {
	cases := []struct {
		value string
		want  bool
	}{
		{"arn:aws:s3:::payments-prod", true},
		{"arn:aws:secretsmanager:us-east-1:111111111111:secret:openai/api-key", true},
		{"*", true},
		{"aws:resource:secrets-manager-secret:openai/api-key", false},
		{"aws:identity:arn:aws:iam::111111111111:role/app", false},
		{"", false},
		{"   ", false},
		{"my-bucket", false},
	}
	for _, tc := range cases {
		if got := awsSessionPolicyRecommendationIsValidResource(tc.value); got != tc.want {
			t.Fatalf("value=%q got %v want %v", tc.value, got, tc.want)
		}
	}
}

func TestAWSSessionPolicyRecommendationIsValidIAMAction(t *testing.T) {
	cases := []struct {
		action string
		want   bool
	}{
		{"s3:GetObject", true},
		{"kms:Decrypt", true},
		{"iam:PutRolePolicy", true},
		{"*", true},
		{"agent-tool:filesystem", false},
		{"aws-service:*", false},
		{"aws-service:lambda", false},
		{"", false},
		{"noservice", false},
		{":action", false},
		{"service:", false},
	}
	for _, tc := range cases {
		if got := awsSessionPolicyRecommendationIsValidIAMAction(tc.action); got != tc.want {
			t.Fatalf("action=%q got %v want %v", tc.action, got, tc.want)
		}
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

	filtered, applied = filterAWSSessionPolicyRecommendations(entries, AWSSessionPolicyRecommendationRequest{AccountID: "111111111111"})
	if applied["account_id"] != "111111111111" || len(filtered) != 1 || !strings.HasSuffix(filtered[0].RecommendationID, ":one") {
		t.Fatalf("account_id filter did not scope entries: applied=%+v filtered=%+v", applied, filtered)
	}

	filtered, applied = filterAWSSessionPolicyRecommendations(entries, AWSSessionPolicyRecommendationRequest{PrincipalID: "arn:aws:iam::111111111111:role/a"})
	if applied["principal_id"] != "arn:aws:iam::111111111111:role/a" || len(filtered) != 1 || !strings.HasSuffix(filtered[0].RecommendationID, ":one") {
		t.Fatalf("principal_id filter must match either node ID or ARN and echo applied: applied=%+v filtered=%+v", applied, filtered)
	}

	filtered, applied = filterAWSSessionPolicyRecommendations(entries, AWSSessionPolicyRecommendationRequest{Search: "listbucket"})
	if applied["search"] != "listbucket" || len(filtered) != 1 || !strings.HasSuffix(filtered[0].RecommendationID, ":two") {
		t.Fatalf("search must reach allow_actions and echo applied: applied=%+v filtered=%+v", applied, filtered)
	}
}

func TestAWSSessionPolicyRecommendationFixtureNormalizerRespectsConnectionState(t *testing.T) {
	disconnected := AWSConnectionStatus{Connected: false}
	connected := AWSConnectionStatus{Connected: true}

	// Explicit success/ready must degrade to permission_denied when the
	// connection is down so this endpoint's fixture metadata stays in
	// sync with the upstream least-privilege source.
	if got := normalizeAWSSessionPolicyRecommendationFixtureState("success", disconnected, true); got != "permission_denied" {
		t.Fatalf("explicit success on disconnected connection must degrade: got %q", got)
	}
	if got := normalizeAWSSessionPolicyRecommendationFixtureState("ready", disconnected, false); got != "permission_denied" {
		t.Fatalf("explicit ready with no connection must degrade: got %q", got)
	}
	if got := normalizeAWSSessionPolicyRecommendationFixtureState("success", connected, true); got != "success" {
		t.Fatalf("explicit success on live connection must stay success: got %q", got)
	}
	if got := normalizeAWSSessionPolicyRecommendationFixtureState("permission_denied", connected, true); got != "permission_denied" {
		t.Fatalf("explicit permission_denied must pass through: got %q", got)
	}
	if got := normalizeAWSSessionPolicyRecommendationFixtureState("bogus", connected, true); got != "" {
		t.Fatalf("unknown fixture state must return empty for invalid request: got %q", got)
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
