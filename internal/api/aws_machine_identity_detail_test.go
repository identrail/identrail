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

func TestAWSMachineIdentityDetailBindingsApplyAccountRegionBeforeScope(t *testing.T) {
	targetAccount := "222222222222"
	targetRegion := "eu-west-1"
	targetARN := "arn:aws:iam::222222222222:role/app"
	targetNodeID := awsIdentityNodeIDForAPI(targetARN)
	otherAccount := "111111111111"
	otherRegion := "us-east-1"
	otherARN := "arn:aws:iam::111111111111:role/app"
	otherNodeID := awsIdentityNodeIDForAPI(otherARN)
	bindingScope := awsMachineIdentityDetailBindingScopeFor(AWSMachineIdentityDetailRequest{
		AccountID: targetAccount,
		Region:    targetRegion,
	})

	if !bindingScope.accepts(targetAccount, targetRegion) || bindingScope.accepts(otherAccount, targetRegion) || bindingScope.accepts(targetAccount, otherRegion) {
		t.Fatalf("binding scope must enforce both requested account and region: %+v", bindingScope)
	}
	if allScope := awsMachineIdentityDetailBindingScopeFor(AWSMachineIdentityDetailRequest{AccountID: "all", Region: "all"}); !allScope.accepts(otherAccount, otherRegion) {
		t.Fatalf("all scope should not filter bindings: %+v", allScope)
	}

	bindings := awsMachineIdentityDetailBindings("app", bindingScope,
		AWSEC2InstanceProfileInventoryResult{Records: []AWSEC2InstanceProfileRecord{{
			AccountID: otherAccount, Region: targetRegion, RoleARN: otherARN, RoleName: "app", WorkloadID: "ec2-other-account", WorkloadType: "ec2", WorkloadName: "ec2-other-account", FromNodeID: "aws:workload:ec2:other-account", ToNodeID: otherNodeID,
		}}},
		AWSECSTaskRoleInventoryResult{Records: []AWSECSTaskRoleRecord{{
			AccountID: targetAccount, Region: otherRegion, RoleARN: otherARN, RoleName: "app", WorkloadID: "ecs-other-region", WorkloadType: "ecs", WorkloadName: "ecs-other-region", FromNodeID: "aws:workload:ecs:other-region", ToNodeID: otherNodeID,
		}}},
		AWSLambdaExecutionRoleInventoryResult{Records: []AWSLambdaExecutionRoleRecord{{
			AccountID: targetAccount, Region: targetRegion, RoleARN: targetARN, RoleName: "app", FunctionName: "app", WorkloadID: "lambda-target", WorkloadType: "lambda", WorkloadName: "lambda-target", FromNodeID: "aws:workload:lambda:target", ToNodeID: targetNodeID,
		}}},
		AWSCodeBuildServiceRoleInventoryResult{Records: []AWSCodeBuildServiceRoleRecord{{
			AccountID: otherAccount, Region: targetRegion, RoleARN: otherARN, RoleName: "app", ProjectName: "codebuild-other-account", WorkloadID: "codebuild-other-account", WorkloadType: "codebuild", WorkloadName: "codebuild-other-account", FromNodeID: "aws:workload:codebuild:other-account", ToNodeID: otherNodeID,
		}}},
		AWSCodePipelineDeploymentRoleInventoryResult{Records: []AWSCodePipelineDeploymentRoleRecord{{
			AccountID: targetAccount, Region: otherRegion, RoleARN: otherARN, RoleName: "app", PipelineName: "pipeline-other-region", WorkloadID: "pipeline-other-region", WorkloadType: "codepipeline", WorkloadName: "pipeline-other-region", FromNodeID: "aws:workload:codepipeline:other-region", ToNodeID: otherNodeID,
		}}},
		AWSStepFunctionsStateMachineRoleInventoryResult{Records: []AWSStepFunctionsStateMachineRoleRecord{{
			AccountID: otherAccount, Region: targetRegion, RoleARN: otherARN, RoleName: "app", StateMachineName: "state-machine-other-account", WorkloadID: "sfn-other-account", WorkloadType: "stepfunctions", WorkloadName: "sfn-other-account", FromNodeID: "aws:workload:sfn:other-account", ToNodeID: otherNodeID,
		}}},
		AWSEventDrivenRoleInventoryResult{Records: []AWSEventDrivenRoleRecord{{
			AccountID: targetAccount, Region: otherRegion, RoleARN: otherARN, RoleName: "app", Service: "eventbridge", WorkloadID: "event-other-region", WorkloadType: "event_rule", WorkloadName: "event-other-region", FromNodeID: "aws:workload:event:other-region", ToNodeID: otherNodeID,
		}}},
		AWSManagedComputeRoleInventoryResult{Records: []AWSManagedComputeRoleRecord{{
			AccountID: otherAccount, Region: targetRegion, RoleARN: otherARN, RoleName: "app", Service: "batch", WorkloadID: "batch-other-account", WorkloadType: "batch_job", WorkloadName: "batch-other-account", FromNodeID: "aws:workload:batch:other-account", ToNodeID: otherNodeID,
		}}},
		AWSEKSWorkloadIdentityInventoryResult{Records: []AWSEKSWorkloadIdentityRecord{{
			AccountID: targetAccount, Region: otherRegion, RoleARN: otherARN, RoleName: "app", WorkloadID: "eks-other-region", WorkloadType: "service_account", WorkloadName: "eks-other-region", FromNodeID: "aws:workload:eks:other-region", ToNodeID: otherNodeID,
		}}},
	)

	if len(bindings) != 1 || bindings[0].RoleARN != targetARN || bindings[0].ToNodeID != targetNodeID {
		t.Fatalf("bindings must be scoped before identity canonicalization: %+v", bindings)
	}
	scope := awsMachineIdentityDetailScopeFor("app", bindings)
	if scope.PrincipalARN != targetARN || scope.NodeID != targetNodeID || scope.DownstreamIdentity != targetARN {
		t.Fatalf("identity scope must be seeded only from requested account/region bindings: %+v", scope)
	}
}

func TestGetAWSMachineIdentityDetailKeepsUnresolvedRoleNameGovernanceScoped(t *testing.T) {
	now := time.Date(2026, 7, 3, 13, 19, 0, 0, time.UTC)
	svc, ws := newMachineIdentityDetailService(t, "project-machine-identity-detail-unresolved-role", now)

	result, err := svc.GetAWSMachineIdentityDetail(defaultScopeContext(), ws, "project-machine-identity-detail-unresolved-role", AWSMachineIdentityDetailRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
		Identity:     "stale-role-name",
	})
	if err != nil {
		t.Fatalf("get machine identity detail for unresolved role name: %v", err)
	}
	if result.Status != "empty" || result.Summary.GovernanceDecisionCount != 0 || len(result.GovernanceDecisions) != 0 || len(result.Governance.Records) != 0 {
		t.Fatalf("unresolved role-name detail must stay empty and avoid connector-wide governance: status=%s summary=%+v governance=%+v", result.Status, result.Summary, result.Governance.Summary)
	}
	governanceIdentityID := result.Governance.AppliedFilters["identity_id"]
	if !strings.HasPrefix(governanceIdentityID, "aws:identity:unresolved:") {
		t.Fatalf("unresolved role-name governance must stay explicitly scoped: applied=%+v", result.Governance.AppliedFilters)
	}
	if result.Identity.IdentityNodeID != "" || result.Identity.PrincipalARN != "" {
		t.Fatalf("unresolved role-name identity should not synthesize a real ARN or node id: %+v", result.Identity)
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

func TestAWSMachineIdentityDetailPostFiltersDownstreamEvidenceByExactScope(t *testing.T) {
	appARN := "arn:aws:iam::123456789012:role/app"
	appNodeID := awsIdentityNodeIDForAPI(appARN)
	appAdminARN := "arn:aws:iam::123456789012:role/app-admin"
	appAdminNodeID := awsIdentityNodeIDForAPI(appAdminARN)
	scope := awsMachineIdentityDetailScopeFor(appARN, nil)

	runtime, permissions, secrets, blast, sprawl, cases := awsMachineIdentityDetailFilterDownstreamEvidence(scope,
		AWSRuntimeEventResult{FixtureState: "success", Records: []AWSRuntimeEventRecord{
			{EventID: "runtime-app", EventType: "api-call", ActorPrincipalARN: appARN, ActorIdentityNodeID: appNodeID, ResourceNodeID: "aws:resource:app", EvidenceRef: "evidence-runtime-app", Status: "allowed", Owner: "platform"},
			{EventID: "runtime-app-admin", EventType: "api-call", ActorPrincipalARN: appAdminARN, ActorIdentityNodeID: appAdminNodeID, ResourceNodeID: "aws:resource:app-admin", EvidenceRef: "evidence-runtime-admin", Status: "allowed", Owner: "platform"},
		}, Diagnostics: []AWSRuntimeEventDiagnostic{
			{Collector: "cloudtrail", SourceID: "runtime-app", Code: "late_delivery", Message: "app event arrived late", Retryable: true},
			{Collector: "cloudtrail", SourceID: "runtime-app-admin", Code: "late_delivery", Message: "admin event arrived late", Retryable: true},
			{Collector: "cloudtrail", Code: "collector_backfill", Message: "collector-wide runtime backfill", Retryable: true},
		}},
		AWSLeastPrivilegeResult{Recommendations: []AWSLeastPrivilegeRecommendation{
			{RecommendationID: "permission-app", PrincipalARN: appARN, IdentityNodeID: appNodeID, DisplayName: "app", ImpactedPath: []AWSLeastPrivilegePathStep{{NodeID: appNodeID, NodeType: "identity", Label: "app"}, {NodeID: "aws:resource:app", NodeType: "resource", Label: "app bucket"}}},
			{RecommendationID: "permission-app-admin", PrincipalARN: appAdminARN, IdentityNodeID: appAdminNodeID, DisplayName: "app-admin", ImpactedPath: []AWSLeastPrivilegePathStep{{NodeID: appAdminNodeID, NodeType: "identity", Label: "app-admin"}, {NodeID: "aws:resource:app-admin", NodeType: "resource", Label: "admin bucket"}}},
		}},
		AWSSecretPermissionEquivalenceResult{Findings: []AWSSecretPermissionEquivalenceFinding{
			{FindingID: "secret-app", PrincipalARN: appARN, IdentityNodeID: appNodeID, SecretNodeID: "aws:secret:app", SecretLabel: "app secret", ImpactedPath: []AWSSecretPermissionEquivalencePathStep{{NodeID: appNodeID, NodeType: "identity", Label: "app"}}},
			{FindingID: "secret-app-admin", PrincipalARN: appAdminARN, IdentityNodeID: appAdminNodeID, SecretNodeID: "aws:secret:app-admin", SecretLabel: "admin secret", ImpactedPath: []AWSSecretPermissionEquivalencePathStep{{NodeID: appAdminNodeID, NodeType: "identity", Label: "app-admin"}}},
		}},
		AWSBlastRadiusResult{Findings: []AWSBlastRadiusFinding{
			{FindingID: "blast-app", PrincipalARN: appARN, IdentityNodeID: appNodeID, DisplayName: "app", ImpactedPath: []AWSBlastRadiusPathStep{{NodeID: appNodeID, NodeType: "identity", Label: "app"}, {NodeID: "aws:data:app", NodeType: "data", Label: "app data"}}},
			{FindingID: "blast-app-admin", PrincipalARN: appAdminARN, IdentityNodeID: appAdminNodeID, DisplayName: "app-admin", ImpactedPath: []AWSBlastRadiusPathStep{{NodeID: appAdminNodeID, NodeType: "identity", Label: "app-admin"}, {NodeID: "aws:data:app-admin", NodeType: "data", Label: "admin data"}}},
		}},
		AWSIdentitySprawlResult{
			Findings: []AWSIdentitySprawlFinding{
				{FindingID: "sprawl-app", PrincipalARN: appARN, IdentityNodeID: appNodeID, RoleName: "app", DisplayName: "app", ClusterID: "cluster-app-family", WorkloadNodeIDs: []string{"aws:workload:app"}, WorkloadTypes: []string{"lambda"}, ImpactedPath: []AWSIdentitySprawlPathStep{{NodeID: appNodeID, NodeType: "identity", Label: "app"}, {NodeID: "aws:workload:app", NodeType: "workload", Label: "app workload"}}},
				{FindingID: "sprawl-app-admin", PrincipalARN: appAdminARN, IdentityNodeID: appAdminNodeID, RoleName: "app-admin", DisplayName: "app-admin", ClusterID: "cluster-app-family", WorkloadNodeIDs: []string{"aws:workload:app-admin"}, WorkloadTypes: []string{"lambda"}, ImpactedPath: []AWSIdentitySprawlPathStep{{NodeID: appAdminNodeID, NodeType: "identity", Label: "app-admin"}, {NodeID: "aws:workload:app-admin", NodeType: "workload", Label: "admin workload"}}},
			},
			Clusters: []AWSIdentitySprawlCluster{{ClusterID: "cluster-app-family", IdentityNodeIDs: []string{appNodeID, appAdminNodeID}, WorkloadTypes: []string{"lambda"}}},
		},
		AWSRemediationCaseResult{Cases: []AWSRemediationCase{
			{CaseID: "case-app", IdentityARN: appARN, IdentityNodeID: appNodeID, IdentityName: "app", ImpactedNodes: []string{appNodeID, "aws:resource:app"}, ImpactedPath: []AWSRemediationCasePathStep{{NodeID: appNodeID, NodeType: "identity", Label: "app"}}},
			{CaseID: "case-app-admin", IdentityARN: appAdminARN, IdentityNodeID: appAdminNodeID, IdentityName: "app-admin", ImpactedNodes: []string{appAdminNodeID, "aws:resource:app-admin"}, ImpactedPath: []AWSRemediationCasePathStep{{NodeID: appAdminNodeID, NodeType: "identity", Label: "app-admin"}}},
		}},
	)

	if len(runtime.Records) != 1 || runtime.Records[0].EventID != "runtime-app" || runtime.Summary.TotalEvents != 1 || runtime.Summary.FilteredEvents != 1 {
		t.Fatalf("runtime evidence should be exact-scoped: records=%+v summary=%+v", runtime.Records, runtime.Summary)
	}
	if len(runtime.Diagnostics) != 2 || runtime.Diagnostics[0].SourceID != "runtime-app" || runtime.Diagnostics[1].SourceID != "" {
		t.Fatalf("runtime diagnostics should keep exact event diagnostics and collector-level diagnostics only: %+v", runtime.Diagnostics)
	}
	if len(permissions.Recommendations) != 1 || permissions.Recommendations[0].RecommendationID != "permission-app" || permissions.Summary.TotalRecommendations != 1 || len(permissions.Relationships) != 1 {
		t.Fatalf("permission evidence should be exact-scoped: recommendations=%+v summary=%+v relationships=%+v", permissions.Recommendations, permissions.Summary, permissions.Relationships)
	}
	if len(secrets.Findings) != 1 || secrets.Findings[0].FindingID != "secret-app" || secrets.Summary.TotalFindings != 1 || len(secrets.Relationships) != 1 {
		t.Fatalf("secret evidence should be exact-scoped: findings=%+v summary=%+v relationships=%+v", secrets.Findings, secrets.Summary, secrets.Relationships)
	}
	if len(blast.Findings) != 1 || blast.Findings[0].FindingID != "blast-app" || blast.Summary.TotalFindings != 1 || len(blast.Relationships) != 1 {
		t.Fatalf("blast evidence should be exact-scoped: findings=%+v summary=%+v relationships=%+v", blast.Findings, blast.Summary, blast.Relationships)
	}
	if len(sprawl.Findings) != 1 || sprawl.Findings[0].FindingID != "sprawl-app" || sprawl.Summary.TotalFindings != 1 || len(sprawl.Clusters) != 1 || len(sprawl.Clusters[0].IdentityNodeIDs) != 1 || sprawl.Clusters[0].IdentityNodeIDs[0] != appNodeID {
		t.Fatalf("sprawl evidence should be exact-scoped: findings=%+v clusters=%+v summary=%+v", sprawl.Findings, sprawl.Clusters, sprawl.Summary)
	}
	if len(cases.Cases) != 1 || cases.Cases[0].CaseID != "case-app" || cases.Summary.TotalCases != 1 || len(cases.Relationships) != 1 {
		t.Fatalf("remediation cases should be exact-scoped: cases=%+v summary=%+v relationships=%+v", cases.Cases, cases.Summary, cases.Relationships)
	}
}
