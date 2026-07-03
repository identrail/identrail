package api

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/telemetry"
	"go.uber.org/zap"
)

func newMachineIdentityDetailService(t *testing.T, project string, now time.Time) (*Service, string) {
	t.Helper()
	return newBlastRadiusService(t, project, now)
}

func TestGetAWSMachineIdentityDetailBuildsScopedContract(t *testing.T) {
	now := time.Date(2026, 7, 3, 13, 10, 0, 0, time.UTC)
	svc, ws := newMachineIdentityDetailService(t, "project-machine-identity-detail", now)
	identity := "arn:aws:iam::123456789012:role/payments-lambda-execution"

	result, err := svc.GetAWSMachineIdentityDetail(defaultScopeContext(), ws, "project-machine-identity-detail", AWSMachineIdentityDetailRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
		Identity:     identity,
	})
	if err != nil {
		t.Fatalf("get machine identity detail: %v", err)
	}
	if result.CurrentIssueRef != "#1549" || result.Version != awsMachineIdentityDetailVersion || result.PolicyVersion != awsMachineIdentityDetailPolicyID {
		t.Fatalf("unexpected detail metadata: %+v", result)
	}
	if result.Identity.IdentityNodeID != awsIdentityNodeIDForAPI(identity) || result.Identity.PrincipalARN != identity || result.Identity.EvidenceBoundary == "" {
		t.Fatalf("identity summary did not preserve ARN/node/evidence boundary: %+v", result.Identity)
	}
	if result.Status == "blocked" || result.Status == "empty" || result.Summary.WorkloadBindingCount != 1 || len(result.WorkloadBindings) != 1 {
		t.Fatalf("expected scoped detail with one workload binding: status=%s summary=%+v bindings=%+v", result.Status, result.Summary, result.WorkloadBindings)
	}
	if result.Summary.RelationshipCount != len(result.Relationships) || result.Summary.EvidenceLinkCount != len(result.EvidenceLinks) {
		t.Fatalf("summary counts must match payload: summary=%+v relationships=%d evidence=%d", result.Summary, len(result.Relationships), len(result.EvidenceLinks))
	}
	if len(result.Tabs) != 6 || result.Tabs[0].ID != "graph" {
		t.Fatalf("expected graph/runtime/permissions/secrets/fixes/governance tabs, got %+v", result.Tabs)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal detail: %v", err)
	}
	for _, forbidden := range []string{"secret_access_key", "\"secret_value\"", "password=", "rendered_policy", "policy_document_body", "payload_body"} {
		if strings.Contains(strings.ToLower(string(encoded)), forbidden) {
			t.Fatalf("machine identity detail leaked forbidden payload marker %q in %s", forbidden, string(encoded))
		}
	}
}

func TestGetAWSMachineIdentityDetailComposesRuntimePermissionsSecretsAndFixes(t *testing.T) {
	now := time.Date(2026, 7, 3, 13, 15, 0, 0, time.UTC)
	svc, ws := newMachineIdentityDetailService(t, "project-machine-identity-detail-compose", now)
	identity := "arn:aws:iam::123456789012:role/lambda-invoice-agent"

	result, err := svc.GetAWSMachineIdentityDetail(defaultScopeContext(), ws, "project-machine-identity-detail-compose", AWSMachineIdentityDetailRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
		Identity:     identity,
		Tab:          "governance",
	})
	if err != nil {
		t.Fatalf("get machine identity detail: %v", err)
	}
	if result.Summary.RuntimeEventCount == 0 || len(result.ResourcesReached) == 0 {
		t.Fatalf("expected runtime timeline and reached resources for %s: summary=%+v resources=%+v", identity, result.Summary, result.ResourcesReached)
	}
	if result.Summary.PermissionRecommendationCount == 0 || len(result.PermissionSummaries) == 0 {
		t.Fatalf("expected permission summaries for %s: summary=%+v permissions=%+v", identity, result.Summary, result.PermissionSummaries)
	}
	if result.Summary.SecretFindingCount == 0 || result.Summary.FindingCount == 0 {
		t.Fatalf("expected secret/finding summaries for %s: summary=%+v findings=%+v", identity, result.Summary, result.Findings)
	}
	if result.Summary.RemediationCaseCount == 0 {
		t.Fatalf("expected identity-scoped remediation cases: %+v", result.Summary)
	}
	if result.Summary.GovernanceDecisionCount == 0 || len(result.GovernanceDecisions) == 0 {
		t.Fatalf("detail tab selector must not filter governance categories: summary=%+v governance=%+v", result.Summary, result.Governance.Summary)
	}
	if category := result.Governance.AppliedFilters["category"]; category != "" {
		t.Fatalf("detail tab selector must not be forwarded as governance category filter: applied=%+v", result.Governance.AppliedFilters)
	}
	if result.Runtime.AppliedFilters["identity"] != identity || result.Permissions.AppliedFilters["identity"] != identity || result.RemediationCases.AppliedFilters["identity"] != identity {
		t.Fatalf("ARN detail requests must preserve exact ARN downstream scope: runtime=%+v permissions=%+v cases=%+v", result.Runtime.AppliedFilters, result.Permissions.AppliedFilters, result.RemediationCases.AppliedFilters)
	}
	if result.Governance.AppliedFilters["identity_id"] != awsIdentityNodeIDForAPI(identity) {
		t.Fatalf("governance must use normalized identity node id: %+v", result.Governance.AppliedFilters)
	}
}

func TestGetAWSMachineIdentityDetailNormalizesRoleNameForGovernance(t *testing.T) {
	now := time.Date(2026, 7, 3, 13, 18, 0, 0, time.UTC)
	svc, ws := newMachineIdentityDetailService(t, "project-machine-identity-detail-role-name", now)
	roleName := "lambda-invoice-agent"
	roleARN := "arn:aws:iam::123456789012:role/lambda-invoice-agent"
	roleNodeID := awsIdentityNodeIDForAPI(roleARN)

	result, err := svc.GetAWSMachineIdentityDetail(defaultScopeContext(), ws, "project-machine-identity-detail-role-name", AWSMachineIdentityDetailRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
		Identity:     roleName,
	})
	if err != nil {
		t.Fatalf("get machine identity detail by role name: %v", err)
	}
	if result.Identity.IdentityNodeID != roleNodeID || result.Identity.PrincipalARN != roleARN {
		t.Fatalf("role-name detail request did not normalize identity scope: %+v", result.Identity)
	}
	if result.Governance.AppliedFilters["identity_id"] != roleNodeID || result.Summary.GovernanceDecisionCount == 0 {
		t.Fatalf("role-name detail request must retain matching governance records: summary=%+v filters=%+v", result.Summary, result.Governance.AppliedFilters)
	}
	if result.Runtime.AppliedFilters["identity"] != roleARN || result.Permissions.AppliedFilters["identity"] != roleARN {
		t.Fatalf("role-name detail request must use exact ARN downstream scope: runtime=%+v permissions=%+v", result.Runtime.AppliedFilters, result.Permissions.AppliedFilters)
	}
}

func TestGetAWSMachineIdentityDetailFailureStates(t *testing.T) {
	now := time.Date(2026, 7, 3, 13, 20, 0, 0, time.UTC)
	svc, ws := newMachineIdentityDetailService(t, "project-machine-identity-detail-states", now)
	identity := "arn:aws:iam::123456789012:role/payments-lambda-execution"

	denied, err := svc.GetAWSMachineIdentityDetail(defaultScopeContext(), ws, "project-machine-identity-detail-states", AWSMachineIdentityDetailRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "permission_denied",
		Identity:     identity,
	})
	if err != nil {
		t.Fatalf("permission denied detail: %v", err)
	}
	if denied.Status != "blocked" || len(denied.Diagnostics) == 0 || len(denied.FailureReasons) == 0 {
		t.Fatalf("permission denied detail must be explicit: %+v", denied)
	}

	empty, err := svc.GetAWSMachineIdentityDetail(defaultScopeContext(), ws, "project-machine-identity-detail-states", AWSMachineIdentityDetailRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "empty",
		Identity:     identity,
	})
	if err != nil {
		t.Fatalf("empty detail: %v", err)
	}
	if empty.Status != "empty" || empty.Summary.WorkloadBindingCount != 0 || len(empty.FailureReasons) == 0 {
		t.Fatalf("empty detail should return an explicit empty payload: %+v", empty)
	}

	if _, err := svc.GetAWSMachineIdentityDetail(defaultScopeContext(), ws, "project-machine-identity-detail-states", AWSMachineIdentityDetailRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
	}); err == nil {
		t.Fatalf("missing identity should fail validation")
	}
	if _, err := svc.GetAWSMachineIdentityDetail(defaultScopeContext(), ws, "project-machine-identity-detail-states", AWSMachineIdentityDetailRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "garbage",
		Identity:     identity,
	}); err == nil {
		t.Fatalf("invalid fixture state should fail validation")
	}
}

func TestRouterAWSMachineIdentityDetail(t *testing.T) {
	now := time.Date(2026, 7, 3, 13, 25, 0, 0, time.UTC)
	svc, _ := newMachineIdentityDetailService(t, "project-machine-identity-detail-route", now)
	r := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{})
	identity := "arn:aws:iam::123456789012:role/lambda-invoice-agent"

	resp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-machine-identity-detail-route/aws/machine-identity-detail?connector_id=aws-prod&fixture_state=success&identity="+url.QueryEscape(identity)+"&tab=runtime", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	var body struct {
		Detail AWSMachineIdentityDetailResult `json:"detail"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode detail response: %v", err)
	}
	if body.Detail.CurrentIssueRef != "#1549" || body.Detail.AppliedFilters["tab"] != "runtime" {
		t.Fatalf("unexpected route payload: %+v", body.Detail)
	}
	if body.Detail.Summary.RuntimeEventCount == 0 {
		t.Fatalf("expected identity-scoped runtime events via route: %+v", body.Detail.Summary)
	}
}

func TestAWSMachineIdentityDetailMatchesExactIdentityScope(t *testing.T) {
	appARN := "arn:aws:iam::123456789012:role/app"
	appNodeID := awsIdentityNodeIDForAPI(appARN)
	appAdminARN := "arn:aws:iam::123456789012:role/app-admin"

	if !awsMachineIdentityMatches(appARN, appARN, appNodeID, "app") {
		t.Fatalf("exact ARN scope should match its ARN, node id, and role name")
	}
	if awsMachineIdentityMatches(appARN, appAdminARN, awsIdentityNodeIDForAPI(appAdminARN), "app-admin") {
		t.Fatalf("exact ARN scope must not match sibling role names by substring")
	}
	if !awsMachineIdentityMatches("app", "app") {
		t.Fatalf("role-name scope should match the exact role name")
	}
	if awsMachineIdentityMatches("app", "app-admin", appAdminARN, awsIdentityNodeIDForAPI(appAdminARN)) {
		t.Fatalf("role-name scope must not match sibling role names by substring")
	}
	if !awsMachineIdentityMatches(appNodeID, appARN) {
		t.Fatalf("identity node id scope should match its source ARN")
	}

	scope := awsMachineIdentityDetailScopeFor("app", nil)
	scope = awsMachineIdentityDetailScopeWithEvidence(scope, AWSRuntimeEventResult{Records: []AWSRuntimeEventRecord{{
		ActorPrincipalARN:   appAdminARN,
		ActorIdentityNodeID: awsIdentityNodeIDForAPI(appAdminARN),
	}}}, AWSLeastPrivilegeResult{}, AWSSecretPermissionEquivalenceResult{}, AWSBlastRadiusResult{}, AWSIdentitySprawlResult{}, AWSRemediationCaseResult{})
	if scope.PrincipalARN != "" || scope.NodeID != "" || scope.DownstreamIdentity == "app" {
		t.Fatalf("unresolved role-name scope must not absorb sibling-role evidence: %+v", scope)
	}
}
