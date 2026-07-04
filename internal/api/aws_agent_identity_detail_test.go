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

func newAgentIdentityDetailService(t *testing.T, project string, now time.Time) (*Service, string) {
	t.Helper()
	return newBlastRadiusService(t, project, now)
}

func TestGetAWSAgentIdentityDetailBuildsContract(t *testing.T) {
	now := time.Date(2026, 7, 3, 20, 0, 0, 0, time.UTC)
	svc, ws := newAgentIdentityDetailService(t, "project-agent-identity-detail", now)

	result, err := svc.GetAWSAgentIdentityDetail(defaultScopeContext(), ws, "project-agent-identity-detail", AWSAgentIdentityDetailRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
		Agent:        "AGENTPAY1",
	})
	if err != nil {
		t.Fatalf("get agent identity detail: %v", err)
	}
	if result.CurrentIssueRef != "#1550" || result.Version != awsAgentIdentityDetailVersion || result.PolicyVersion != awsAgentIdentityDetailPolicyID {
		t.Fatalf("unexpected contract metadata: %+v", result)
	}
	if !result.Agent.Resolved || result.Agent.AgentID != "AGENTPAY1" {
		t.Fatalf("expected fixture agent to resolve from inventory: %+v", result.Agent)
	}
	if result.Agent.Provider == "" || result.Agent.RuntimeRoleARN == "" {
		t.Fatalf("agent header must carry provider and backing role: %+v", result.Agent)
	}
	if result.RuntimeAccess.AppliedFilters["agent_id"] != result.Agent.AgentNodeID || result.Risk.AppliedFilters["agent_id"] != result.Agent.AgentNodeID {
		t.Fatalf("runtime/risk evidence must be scoped by unique agent node id: runtime=%+v risk=%+v agent=%+v", result.RuntimeAccess.AppliedFilters, result.Risk.AppliedFilters, result.Agent)
	}
	if result.Permissions.AppliedFilters["identity"] != result.Agent.RuntimeRoleNodeID {
		t.Fatalf("permission recommendations must be scoped by backing role identity, got filters=%+v agent=%+v", result.Permissions.AppliedFilters, result.Agent)
	}
	if result.RemediationCases.AppliedFilters["identity"] != result.Agent.RuntimeRoleNodeID {
		t.Fatalf("remediation cases must be scoped by backing role identity, got filters=%+v agent=%+v", result.RemediationCases.AppliedFilters, result.Agent)
	}
	if result.Governance.AppliedFilters["identity_id"] != result.Agent.RuntimeRoleNodeID || result.Summary.GovernanceDecisionCount == 0 {
		t.Fatalf("governance decisions must be scoped by backing role identity, got summary=%+v filters=%+v agent=%+v", result.Summary, result.Governance.AppliedFilters, result.Agent)
	}
	if result.Agent.EvidenceBoundary != awsAgentIdentityDetailEvidenceBoundary() {
		t.Fatalf("agent header crossed evidence boundary: %+v", result.Agent)
	}
	if len(result.Tools) == 0 {
		t.Fatalf("expected declared tools from the inventory record: %+v", result.Summary)
	}
	if len(result.Capabilities) != 3 {
		t.Fatalf("expected memory/browser/code-interpreter capability rows: %+v", result.Capabilities)
	}
	if len(result.Tabs) == 0 {
		t.Fatalf("expected detail tabs: %+v", result)
	}
	if result.Summary.ToolCount != len(result.Tools) || result.Summary.RuntimeCallCount != len(result.RuntimeCalls) {
		t.Fatalf("summary counts must match sections: %+v", result.Summary)
	}
	if result.Summary.FindingCount != len(result.Findings) || result.Summary.RecommendationCount != len(result.Recommendations) {
		t.Fatalf("summary finding/recommendation counts must match: %+v", result.Summary)
	}
	if len(result.EvidenceLinks) == 0 {
		t.Fatalf("expected evidence links: %+v", result)
	}
	for _, tool := range result.Tools {
		if tool.ToolName == "" || tool.Status == "" {
			t.Fatalf("tool row missing name/status: %+v", tool)
		}
	}

	serialized, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	lower := strings.ToLower(string(serialized))
	for _, forbidden := range []string{"\"secret_value\"", "\"prompt\"", "\"completion\"", "\"tool_payload\"", "\"secret_access_key\""} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("agent identity detail serialized forbidden sensitive payload marker %q", forbidden)
		}
	}
}

func TestGetAWSAgentIdentityDetailForwardsResourceToRecommendations(t *testing.T) {
	now := time.Date(2026, 7, 4, 11, 30, 0, 0, time.UTC)
	svc, ws := newAgentIdentityDetailService(t, "project-agent-identity-detail-resource", now)

	result, err := svc.GetAWSAgentIdentityDetail(defaultScopeContext(), ws, "project-agent-identity-detail-resource", AWSAgentIdentityDetailRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
		Agent:        "AGENTPAY1",
		Resource:     "prod/ai/openai-key",
	})
	if err != nil {
		t.Fatalf("get resource-filtered agent identity detail: %v", err)
	}
	if result.Permissions.AppliedFilters["resource"] != "prod/ai/openai-key" {
		t.Fatalf("permissions must receive the detail resource filter, got %+v", result.Permissions.AppliedFilters)
	}
	for _, recommendation := range result.Permissions.Recommendations {
		if !awsRuntimeEventMatchesAny("prod/ai/openai-key", awsLeastPrivilegeResourceMatchValues(recommendation)...) {
			t.Fatalf("resource-filtered permissions leaked unrelated recommendation: %+v", recommendation)
		}
	}
}

func TestGetAWSAgentIdentityDetailUnknownAgentIsExplicit(t *testing.T) {
	now := time.Date(2026, 7, 3, 20, 15, 0, 0, time.UTC)
	svc, ws := newAgentIdentityDetailService(t, "project-agent-identity-detail-unknown", now)

	result, err := svc.GetAWSAgentIdentityDetail(defaultScopeContext(), ws, "project-agent-identity-detail-unknown", AWSAgentIdentityDetailRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
		Agent:        "agent",
	})
	if err != nil {
		t.Fatalf("unknown agent must be an explicit state, not an error: %v", err)
	}
	if result.Status != "unknown" {
		t.Fatalf("unknown agent must surface status=unknown: %q", result.Status)
	}
	if result.Agent.Resolved || !result.Agent.Candidate || !result.Agent.LowConfidence {
		t.Fatalf("unknown agent header must be flagged candidate/low-confidence: %+v", result.Agent)
	}
	foundGap := false
	for _, gap := range result.CoverageGaps {
		if gap.Capability == "agent_inventory_resolution" {
			foundGap = true
			break
		}
	}
	if !foundGap {
		t.Fatalf("unknown agent must carry an explicit coverage gap: %+v", result.CoverageGaps)
	}
	if len(result.Relationships) != 0 {
		t.Fatalf("unknown agent must not inherit unrelated graph relationships: %+v", result.Relationships)
	}
	if len(result.Tools) != 0 || len(result.RuntimeCalls) != 0 || len(result.RuntimeAccess.Records) != 0 {
		t.Fatalf("unknown agent must not inherit runtime evidence: tools=%+v calls=%+v runtime=%+v", result.Tools, result.RuntimeCalls, result.RuntimeAccess.Records)
	}
	if len(result.Findings) != 0 || len(result.Risk.Findings) != 0 {
		t.Fatalf("unknown agent must not inherit risk findings: findings=%+v risk=%+v", result.Findings, result.Risk.Findings)
	}
	if len(result.Recommendations) != 0 || len(result.Permissions.Recommendations) != 0 {
		t.Fatalf("unknown agent must not inherit permission recommendations: recommendations=%+v permissions=%+v", result.Recommendations, result.Permissions.Recommendations)
	}
	if len(result.RemediationCases.Cases) != 0 || len(result.GovernanceDecisions) != 0 || len(result.Governance.Records) != 0 {
		t.Fatalf("unknown agent must not inherit remediation/governance evidence: cases=%+v decisions=%+v governance=%+v", result.RemediationCases.Cases, result.GovernanceDecisions, result.Governance.Records)
	}
	if len(result.FailureReasons) == 0 {
		t.Fatalf("unknown agent must carry a failure reason: %+v", result.FailureReasons)
	}
}

func TestGetAWSAgentIdentityDetailRequiresAgent(t *testing.T) {
	now := time.Date(2026, 7, 3, 20, 30, 0, 0, time.UTC)
	svc, ws := newAgentIdentityDetailService(t, "project-agent-identity-detail-required", now)

	if _, err := svc.GetAWSAgentIdentityDetail(defaultScopeContext(), ws, "project-agent-identity-detail-required", AWSAgentIdentityDetailRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
	}); err == nil {
		t.Fatalf("missing agent parameter must be rejected")
	}
}

func TestAWSAgentIdentityDetailToolsMergeDeclaredAndObserved(t *testing.T) {
	record := AWSAIAgentIdentityRecord{
		AgentID:        "agent-1",
		ToolNames:      []string{"search-tickets", "close-ticket"},
		ToolTargetRefs: []string{"api://tickets/search", "api://tickets/close"},
		EvidenceRef:    "evidence://inventory/agent-1",
	}
	runtime := []AWSAgentRuntimeAccessRecord{
		{
			CorrelationID:  "corr-1",
			ToolName:       "search-tickets",
			Status:         "confirmed",
			ObservedCount:  4,
			EvidenceRef:    "evidence://runtime/corr-1",
			LastObservedAt: time.Date(2026, 7, 2, 10, 0, 0, 0, time.UTC),
		},
		{
			CorrelationID: "corr-2",
			ToolName:      "delete-database",
			Status:        "observed_without_declaration",
			ObservedCount: 1,
			EvidenceRef:   "evidence://runtime/corr-2",
		},
		{
			CorrelationID: "corr-3",
			ToolName:      "close-ticket",
			Status:        "declared_unused",
			EvidenceRef:   "evidence://runtime/corr-3",
		},
	}

	tools := awsAgentIdentityDetailTools(record, runtime)
	if len(tools) != 3 {
		t.Fatalf("expected declared + observed union, got %+v", tools)
	}
	byName := map[string]AWSAgentIdentityToolSummary{}
	for _, tool := range tools {
		byName[tool.ToolName] = tool
	}
	confirmed := byName["search-tickets"]
	if !confirmed.Declared || !confirmed.Observed || confirmed.Status != "confirmed" || confirmed.ObservedCount != 4 {
		t.Fatalf("declared+observed tool must be confirmed with counts: %+v", confirmed)
	}
	unused := byName["close-ticket"]
	if !unused.Declared || unused.Observed || unused.Status != "declared_unused" {
		t.Fatalf("declared-only tool must stay declared_unused: %+v", unused)
	}
	undeclared := byName["delete-database"]
	if undeclared.Declared || !undeclared.Observed || undeclared.Status != "observed_without_declaration" {
		t.Fatalf("observed-only tool must carry the runtime status: %+v", undeclared)
	}
}

func TestAWSAgentIdentityDetailToolsApplyToolFilterToDeclaredRows(t *testing.T) {
	record := AWSAIAgentIdentityRecord{
		AgentID:        "agent-1",
		ToolNames:      []string{"search-tickets", "close-ticket"},
		ToolTargetRefs: []string{"api://tickets/search", "api://tickets/close"},
		EvidenceRef:    "evidence://inventory/agent-1",
	}
	runtime := []AWSAgentRuntimeAccessRecord{
		{
			CorrelationID: "corr-search",
			ToolName:      "search-tickets",
			ToolTargetRef: "api://tickets/search",
			Status:        "confirmed",
			ObservedCount: 2,
			EvidenceRef:   "evidence://runtime/search",
		},
		{
			CorrelationID: "corr-close",
			ToolName:      "close-ticket",
			ToolTargetRef: "api://tickets/close",
			Status:        "declared_unused",
			EvidenceRef:   "evidence://runtime/close",
		},
	}

	tools := awsAgentIdentityDetailTools(record, runtime, "api://tickets/search")
	if len(tools) != 1 {
		t.Fatalf("tool-filtered detail must only include matching declared/runtime tools, got %+v", tools)
	}
	if tools[0].ToolName != "search-tickets" || !tools[0].Declared || !tools[0].Observed {
		t.Fatalf("tool-filtered row must preserve the matching declared+observed tool: %+v", tools[0])
	}
}

func TestAWSAgentIdentityDetailPermissionIdentityPrefersBackingRole(t *testing.T) {
	roleARN := "arn:aws:iam::123456789012:role/agent-runtime"
	record := AWSAIAgentIdentityRecord{
		AgentID:           "agent-1",
		AgentNodeID:       "aws:agent:123456789012:us-east-1:bedrock_agent/agent-1",
		RuntimeRoleARN:    roleARN,
		RuntimeRoleNodeID: awsIdentityNodeIDForAPI(roleARN),
	}

	if got, want := awsAgentIdentityDetailPermissionIdentity(record, record.AgentID), record.RuntimeRoleNodeID; got != want {
		t.Fatalf("expected backing role node identity %q, got %q", want, got)
	}

	record.RuntimeRoleNodeID = ""
	if got, want := awsAgentIdentityDetailPermissionIdentity(record, record.AgentID), awsIdentityNodeIDForAPI(roleARN); got != want {
		t.Fatalf("expected role ARN-derived identity %q, got %q", want, got)
	}
}

func TestAWSAgentIdentityDetailMergesRuntimeAndRiskAgentKeys(t *testing.T) {
	record := AWSAIAgentIdentityRecord{
		AgentID:     "agent",
		AgentNodeID: "aws:agent:123456789012:us-east-1:custom_agent/agent-v1",
	}
	versionedNode := "aws:agent:123456789012:us-east-1:custom_agent/agent-v2"
	otherNode := "aws:agent:123456789012:us-east-1:custom_agent/agent-v20"
	runtimeByNode := AWSAgentRuntimeAccessResult{
		AppliedFilters: map[string]string{"agent_id": record.AgentNodeID},
	}
	runtimeByID := AWSAgentRuntimeAccessResult{
		AppliedFilters: map[string]string{"agent_id": record.AgentID},
		Records: []AWSAgentRuntimeAccessRecord{
			{
				CorrelationID: "corr-agent-id",
				AgentID:       record.AgentID,
				AgentNodeID:   versionedNode,
				ToolName:      "search",
				Status:        "confirmed",
				ObservedCount: 1,
			},
			{
				CorrelationID: "corr-sibling",
				AgentID:       "agent-v2",
				AgentNodeID:   otherNode,
				ToolName:      "archive",
				Status:        "confirmed",
				ObservedCount: 1,
			},
		},
	}
	mergedRuntime := awsAgentIdentityDetailMergeRuntimeAccessResults(runtimeByNode, runtimeByID, record.AgentNodeID, record.AgentID)
	scopedRuntime := awsAgentIdentityDetailScopeRuntimeAccess(mergedRuntime, record)
	if len(scopedRuntime.Records) != 1 || scopedRuntime.Records[0].CorrelationID != "corr-agent-id" {
		t.Fatalf("runtime evidence must merge alternate exact agent keys and still exact-filter siblings: %+v", scopedRuntime.Records)
	}
	if scopedRuntime.AppliedFilters["agent_id"] != record.AgentNodeID || scopedRuntime.AppliedFilters["agent_id_alternates"] != record.AgentID {
		t.Fatalf("merged runtime filters must expose primary and alternate agent keys: %+v", scopedRuntime.AppliedFilters)
	}

	riskByNode := AWSAIAgentRiskResult{
		AppliedFilters: map[string]string{"agent_id": record.AgentNodeID},
	}
	riskByID := AWSAIAgentRiskResult{
		AppliedFilters: map[string]string{"agent_id": record.AgentID},
		Findings: []AWSAIAgentRiskFinding{
			{FindingID: "risk-agent-id", AgentID: record.AgentID, AgentNodeID: versionedNode, RiskType: "broad_tool_access", Severity: "medium", Status: "open", Score: 70},
			{FindingID: "risk-sibling", AgentID: "agent-v2", AgentNodeID: otherNode, RiskType: "ownerless_agent", Severity: "medium", Status: "open", Score: 65},
		},
	}
	mergedRisk := awsAgentIdentityDetailMergeRiskResults(riskByNode, riskByID, record.AgentNodeID, record.AgentID)
	scopedRisk := awsAgentIdentityDetailScopeRisk(mergedRisk, record)
	if len(scopedRisk.Findings) != 1 || scopedRisk.Findings[0].FindingID != "risk-agent-id" {
		t.Fatalf("risk evidence must merge alternate exact agent keys and still exact-filter siblings: %+v", scopedRisk.Findings)
	}
	if scopedRisk.AppliedFilters["agent_id"] != record.AgentNodeID || scopedRisk.AppliedFilters["agent_id_alternates"] != record.AgentID {
		t.Fatalf("merged risk filters must expose primary and alternate agent keys: %+v", scopedRisk.AppliedFilters)
	}
}

func TestAWSAgentIdentityDetailScopesResolvedRuntimeAndRiskExactly(t *testing.T) {
	record := AWSAIAgentIdentityRecord{
		AgentID:     "agent",
		AgentNodeID: "aws:agent:123456789012:us-east-1:custom_agent/agent",
	}
	leakedAgentNode := "aws:agent:123456789012:us-east-1:custom_agent/agent-v2"
	runtime := AWSAgentRuntimeAccessResult{
		Records: []AWSAgentRuntimeAccessRecord{
			{
				CorrelationID:         "corr-agent",
				AgentID:               record.AgentID,
				AgentNodeID:           record.AgentNodeID,
				ToolName:              "search",
				Status:                "confirmed",
				ObservedCount:         2,
				DeclaredInInventory:   true,
				BackingRoleNodeIDs:    []string{"aws:identity:role/agent"},
				TargetResourceNodeIDs: []string{"aws:s3:bucket/tickets"},
			},
			{
				CorrelationID:         "corr-agent-v2",
				AgentID:               "agent-v2",
				AgentNodeID:           leakedAgentNode,
				ToolName:              "delete",
				Status:                "confirmed",
				ObservedCount:         1,
				BackingRoleNodeIDs:    []string{"aws:identity:role/agent-v2"},
				TargetResourceNodeIDs: []string{"aws:s3:bucket/archive"},
			},
		},
	}
	risk := AWSAIAgentRiskResult{
		Findings: []AWSAIAgentRiskFinding{
			{FindingID: "risk-agent", AgentID: record.AgentID, AgentNodeID: record.AgentNodeID, RiskType: "broad_tool_access", Severity: "high", Status: "open", Score: 90, ImpactedNodes: []string{record.AgentNodeID, "aws:identity:role/agent"}},
			{FindingID: "risk-agent-v2", AgentID: "agent-v2", AgentNodeID: leakedAgentNode, RiskType: "ownerless_agent", Severity: "medium", Status: "open", Score: 70, ImpactedNodes: []string{leakedAgentNode, "aws:identity:role/agent-v2"}},
		},
	}

	scopedRuntime := awsAgentIdentityDetailScopeRuntimeAccess(runtime, record)
	if len(scopedRuntime.Records) != 1 || scopedRuntime.Records[0].AgentNodeID != record.AgentNodeID {
		t.Fatalf("runtime evidence must be exact-scoped to the resolved agent: %+v", scopedRuntime.Records)
	}
	if scopedRuntime.Summary.FilteredCorrelations != 1 || scopedRuntime.Summary.ConfirmedCount != 1 || scopedRuntime.Summary.RelationshipCount != len(scopedRuntime.Relationships) {
		t.Fatalf("runtime summary must match exact-scoped records: summary=%+v relationships=%+v", scopedRuntime.Summary, scopedRuntime.Relationships)
	}
	for _, relation := range scopedRuntime.Relationships {
		if relation.FromNodeID == leakedAgentNode || relation.ToNodeID == leakedAgentNode {
			t.Fatalf("runtime relationships must not retain prefix-matched leaked agent: %+v", scopedRuntime.Relationships)
		}
	}

	scopedRisk := awsAgentIdentityDetailScopeRisk(risk, record)
	if len(scopedRisk.Findings) != 1 || scopedRisk.Findings[0].AgentNodeID != record.AgentNodeID {
		t.Fatalf("risk evidence must be exact-scoped to the resolved agent: %+v", scopedRisk.Findings)
	}
	if scopedRisk.Summary.FilteredFindings != 1 || scopedRisk.Summary.RelationshipCount != len(scopedRisk.Relationships) {
		t.Fatalf("risk summary must match exact-scoped findings: summary=%+v relationships=%+v", scopedRisk.Summary, scopedRisk.Relationships)
	}
	for _, relation := range scopedRisk.Relationships {
		if relation.FromNodeID == leakedAgentNode || relation.ToNodeID == leakedAgentNode {
			t.Fatalf("risk relationships must not retain prefix-matched leaked agent: %+v", scopedRisk.Relationships)
		}
	}
}

func TestAWSAgentIdentityDetailScopesPermissionsAndCasesExactly(t *testing.T) {
	roleARN := "arn:aws:iam::123456789012:role/agent"
	roleNode := awsIdentityNodeIDForAPI(roleARN)
	leakedRoleARN := "arn:aws:iam::123456789012:role/agent-v2"
	leakedRoleNode := awsIdentityNodeIDForAPI(leakedRoleARN)
	record := AWSAIAgentIdentityRecord{
		AgentID:           "agent",
		AgentNodeID:       "aws:agent:123456789012:us-east-1:custom_agent/agent",
		RuntimeRoleARN:    roleARN,
		RuntimeRoleNodeID: roleNode,
		RuntimeRoleName:   "agent",
	}
	permissions := AWSLeastPrivilegeResult{
		Recommendations: []AWSLeastPrivilegeRecommendation{
			{
				RecommendationID: "lp-agent",
				Decision:         "remove",
				Severity:         "high",
				Status:           "open",
				Service:          "s3",
				IdentityNodeID:   roleNode,
				PrincipalARN:     roleARN,
				DisplayName:      "agent",
				Score:            90,
				Confidence:       0.9,
				ImpactedPath: []AWSLeastPrivilegePathStep{
					{NodeID: roleNode, NodeType: "identity", Label: "agent"},
					{NodeID: "aws:s3:bucket/tickets", NodeType: "resource", Label: "tickets"},
				},
			},
			{
				RecommendationID: "lp-agent-v2",
				Decision:         "remove",
				Severity:         "high",
				Status:           "open",
				Service:          "s3",
				IdentityNodeID:   leakedRoleNode,
				PrincipalARN:     leakedRoleARN,
				DisplayName:      "agent-v2",
				Score:            80,
				Confidence:       0.8,
				ImpactedPath: []AWSLeastPrivilegePathStep{
					{NodeID: leakedRoleNode, NodeType: "identity", Label: "agent-v2"},
					{NodeID: "aws:s3:bucket/archive", NodeType: "resource", Label: "archive"},
				},
			},
		},
	}
	cases := AWSRemediationCaseResult{
		Cases: []AWSRemediationCase{
			{
				CaseID:         "case-agent",
				SourceType:     "least_privilege",
				Lifecycle:      "proposed",
				Severity:       "high",
				Status:         "open",
				ApprovalState:  "pending",
				IdentityNodeID: roleNode,
				IdentityARN:    roleARN,
				IdentityName:   "agent",
				Score:          90,
				Confidence:     0.9,
				ImpactedNodes:  []string{roleNode, "aws:s3:bucket/tickets"},
			},
			{
				CaseID:         "case-agent-v2",
				SourceType:     "least_privilege",
				Lifecycle:      "proposed",
				Severity:       "high",
				Status:         "open",
				ApprovalState:  "pending",
				IdentityNodeID: leakedRoleNode,
				IdentityARN:    leakedRoleARN,
				IdentityName:   "agent-v2",
				Score:          80,
				Confidence:     0.8,
				ImpactedNodes:  []string{leakedRoleNode, "aws:s3:bucket/archive"},
			},
		},
	}

	scopedPermissions := awsAgentIdentityDetailScopePermissions(permissions, record, roleNode)
	if len(scopedPermissions.Recommendations) != 1 || scopedPermissions.Recommendations[0].IdentityNodeID != roleNode {
		t.Fatalf("permissions must exact-scope to the selected runtime role: %+v", scopedPermissions.Recommendations)
	}
	if scopedPermissions.Summary.FilteredRecommendations != 1 || scopedPermissions.Summary.RelationshipCount != len(scopedPermissions.Relationships) {
		t.Fatalf("permission summary must match exact-scoped recommendations: summary=%+v relationships=%+v", scopedPermissions.Summary, scopedPermissions.Relationships)
	}
	for _, relation := range scopedPermissions.Relationships {
		if relation.FromNodeID == leakedRoleNode || relation.ToNodeID == leakedRoleNode {
			t.Fatalf("permission relationships must not retain prefix-matched leaked role: %+v", scopedPermissions.Relationships)
		}
	}

	scopedCases := awsAgentIdentityDetailScopeRemediationCases(cases, record, roleNode)
	if len(scopedCases.Cases) != 1 || scopedCases.Cases[0].IdentityNodeID != roleNode {
		t.Fatalf("remediation cases must exact-scope to the selected runtime role: %+v", scopedCases.Cases)
	}
	if scopedCases.Summary.FilteredCases != 1 || scopedCases.Summary.RelationshipCount != len(scopedCases.Relationships) {
		t.Fatalf("remediation summary must match exact-scoped cases: summary=%+v relationships=%+v", scopedCases.Summary, scopedCases.Relationships)
	}
	for _, relation := range scopedCases.Relationships {
		if relation.FromNodeID == leakedRoleNode || relation.ToNodeID == leakedRoleNode {
			t.Fatalf("remediation relationships must not retain prefix-matched leaked role: %+v", scopedCases.Relationships)
		}
	}
}

func TestAWSAgentIdentityDetailKeepsRoleWideButFiltersOtherAgentToolRecommendations(t *testing.T) {
	roleARN := "arn:aws:iam::123456789012:role/shared-agent-runtime"
	roleNode := awsIdentityNodeIDForAPI(roleARN)
	agentNode := "aws:agent:123456789012:us-east-1:custom_agent/agent"
	otherAgentNode := "aws:agent:123456789012:us-east-1:custom_agent/agent-v2"
	record := AWSAIAgentIdentityRecord{
		AgentID:           "agent",
		AgentNodeID:       agentNode,
		RuntimeRoleARN:    roleARN,
		RuntimeRoleNodeID: roleNode,
	}
	permissions := AWSLeastPrivilegeResult{
		Recommendations: []AWSLeastPrivilegeRecommendation{
			{
				RecommendationID:   "lp-selected-agent-tool",
				RecommendationType: "remove-unused-agent-tool",
				Decision:           "remove",
				Severity:           "medium",
				Status:             "open",
				Service:            "agent-runtime",
				IdentityNodeID:     roleNode,
				PrincipalARN:       roleARN,
				DisplayName:        "agent",
				Score:              70,
				Confidence:         0.8,
				ImpactedNodes:      []string{roleNode, agentNode, "aws:s3:bucket/tickets"},
				ImpactedPath: []AWSLeastPrivilegePathStep{
					{NodeID: roleNode, NodeType: "identity", Label: "shared-agent-runtime"},
					{NodeID: agentNode, NodeType: "ai_agent", Label: "agent"},
					{NodeID: "aws:s3:bucket/tickets", NodeType: "target_resource", Label: "tickets"},
				},
				Evidence: []AWSLeastPrivilegeEvidence{{Source: "agent_runtime_access", EvidenceRef: "evidence://runtime/agent"}},
			},
			{
				RecommendationID:   "lp-other-agent-tool",
				RecommendationType: "remove-unused-agent-tool",
				Decision:           "remove",
				Severity:           "medium",
				Status:             "open",
				Service:            "agent-runtime",
				IdentityNodeID:     roleNode,
				PrincipalARN:       roleARN,
				DisplayName:        "agent-v2",
				Score:              68,
				Confidence:         0.8,
				ImpactedNodes:      []string{roleNode, otherAgentNode, "aws:s3:bucket/archive"},
				ImpactedPath: []AWSLeastPrivilegePathStep{
					{NodeID: roleNode, NodeType: "identity", Label: "shared-agent-runtime"},
					{NodeID: otherAgentNode, NodeType: "ai_agent", Label: "agent-v2"},
					{NodeID: "aws:s3:bucket/archive", NodeType: "target_resource", Label: "archive"},
				},
				Evidence: []AWSLeastPrivilegeEvidence{{Source: "agent_runtime_access", EvidenceRef: "evidence://runtime/agent-v2"}},
			},
			{
				RecommendationID:   "lp-role-wide",
				RecommendationType: "remove-unused-iam-action",
				Decision:           "remove",
				Severity:           "high",
				Status:             "open",
				Service:            "s3",
				IdentityNodeID:     roleNode,
				PrincipalARN:       roleARN,
				DisplayName:        "shared-agent-runtime",
				Score:              80,
				Confidence:         0.85,
				ImpactedNodes:      []string{roleNode, "aws:s3:bucket/shared"},
				ImpactedPath: []AWSLeastPrivilegePathStep{
					{NodeID: roleNode, NodeType: "identity", Label: "shared-agent-runtime"},
					{NodeID: "aws:s3:bucket/shared", NodeType: "resource", Label: "shared"},
				},
				Evidence: []AWSLeastPrivilegeEvidence{{Source: "iam_last_used", EvidenceRef: "evidence://iam-last-used/shared-agent-runtime"}},
			},
		},
	}
	cases := AWSRemediationCaseResult{
		Cases: []AWSRemediationCase{
			{
				CaseID:         "case-selected-agent-tool",
				SourceType:     "least_privilege",
				Lifecycle:      "proposed",
				Severity:       "medium",
				Status:         "open",
				ApprovalState:  "pending",
				IdentityNodeID: roleNode,
				IdentityARN:    roleARN,
				IdentityName:   "agent",
				Score:          70,
				Confidence:     0.8,
				ImpactedNodes:  []string{roleNode, agentNode, "aws:s3:bucket/tickets"},
				ImpactedPath: []AWSLeastPrivilegePathStep{
					{NodeID: roleNode, NodeType: "identity", Label: "shared-agent-runtime"},
					{NodeID: agentNode, NodeType: "ai_agent", Label: "agent"},
					{NodeID: "aws:s3:bucket/tickets", NodeType: "target_resource", Label: "tickets"},
				},
			},
			{
				CaseID:         "case-other-agent-tool",
				SourceType:     "least_privilege",
				Lifecycle:      "proposed",
				Severity:       "medium",
				Status:         "open",
				ApprovalState:  "pending",
				IdentityNodeID: roleNode,
				IdentityARN:    roleARN,
				IdentityName:   "agent-v2",
				Score:          68,
				Confidence:     0.8,
				ImpactedNodes:  []string{roleNode, otherAgentNode, "aws:s3:bucket/archive"},
				ImpactedPath: []AWSLeastPrivilegePathStep{
					{NodeID: roleNode, NodeType: "identity", Label: "shared-agent-runtime"},
					{NodeID: otherAgentNode, NodeType: "ai_agent", Label: "agent-v2"},
					{NodeID: "aws:s3:bucket/archive", NodeType: "target_resource", Label: "archive"},
				},
			},
			{
				CaseID:         "case-role-wide",
				SourceType:     "least_privilege",
				Lifecycle:      "proposed",
				Severity:       "high",
				Status:         "open",
				ApprovalState:  "pending",
				IdentityNodeID: roleNode,
				IdentityARN:    roleARN,
				IdentityName:   "shared-agent-runtime",
				Score:          80,
				Confidence:     0.85,
				ImpactedNodes:  []string{roleNode, "aws:s3:bucket/shared"},
				ImpactedPath: []AWSLeastPrivilegePathStep{
					{NodeID: roleNode, NodeType: "identity", Label: "shared-agent-runtime"},
					{NodeID: "aws:s3:bucket/shared", NodeType: "resource", Label: "shared"},
				},
			},
		},
	}

	scopedPermissions := awsAgentIdentityDetailScopePermissions(permissions, record, roleNode)
	gotRecommendations := map[string]struct{}{}
	for _, recommendation := range scopedPermissions.Recommendations {
		gotRecommendations[recommendation.RecommendationID] = struct{}{}
	}
	if _, ok := gotRecommendations["lp-selected-agent-tool"]; !ok {
		t.Fatalf("selected agent tool recommendation must be retained: %+v", scopedPermissions.Recommendations)
	}
	if _, ok := gotRecommendations["lp-role-wide"]; !ok {
		t.Fatalf("role-wide IAM recommendation must be retained: %+v", scopedPermissions.Recommendations)
	}
	if _, ok := gotRecommendations["lp-other-agent-tool"]; ok {
		t.Fatalf("other agent tool recommendation must be filtered out: %+v", scopedPermissions.Recommendations)
	}

	scopedCases := awsAgentIdentityDetailScopeRemediationCases(cases, record, roleNode)
	gotCases := map[string]struct{}{}
	for _, c := range scopedCases.Cases {
		gotCases[c.CaseID] = struct{}{}
	}
	if _, ok := gotCases["case-selected-agent-tool"]; !ok {
		t.Fatalf("selected agent tool case must be retained: %+v", scopedCases.Cases)
	}
	if _, ok := gotCases["case-role-wide"]; !ok {
		t.Fatalf("role-wide IAM case must be retained: %+v", scopedCases.Cases)
	}
	if _, ok := gotCases["case-other-agent-tool"]; ok {
		t.Fatalf("other agent tool case must be filtered out: %+v", scopedCases.Cases)
	}
}

func TestAWSAgentIdentityDetailMergesAgentScopedRemediationCases(t *testing.T) {
	roleARN := "arn:aws:iam::123456789012:role/shared-agent-runtime"
	roleNode := awsIdentityNodeIDForAPI(roleARN)
	agentNode := "aws:agent:123456789012:us-east-1:custom_agent/agent"
	otherAgentNode := "aws:agent:123456789012:us-east-1:custom_agent/agent-v2"
	record := AWSAIAgentIdentityRecord{
		AgentID:           "agent",
		AgentNodeID:       agentNode,
		RuntimeRoleARN:    roleARN,
		RuntimeRoleNodeID: roleNode,
	}
	roleCases := AWSRemediationCaseResult{
		AppliedFilters: map[string]string{"identity": roleNode},
		Cases: []AWSRemediationCase{
			{
				CaseID:         "case-role-wide",
				SourceType:     "least_privilege",
				Lifecycle:      "proposed",
				Severity:       "high",
				Status:         "open",
				ApprovalState:  "pending",
				IdentityNodeID: roleNode,
				IdentityARN:    roleARN,
				IdentityName:   "shared-agent-runtime",
				Score:          80,
				Confidence:     0.85,
				ImpactedNodes:  []string{roleNode, "aws:s3:bucket/shared"},
			},
		},
	}
	agentCases := AWSRemediationCaseResult{
		AppliedFilters: map[string]string{"identity": agentNode},
		Cases: []AWSRemediationCase{
			{
				CaseID:          "case-selected-agent-risk",
				SourceType:      "ai_agent_risk",
				SourceFindingID: "risk-selected",
				Lifecycle:       "proposed",
				Severity:        "medium",
				Status:          "open",
				ApprovalState:   "pending",
				IdentityNodeID:  agentNode,
				IdentityName:    "agent",
				IdentityType:    "ai_agent",
				Score:           70,
				Confidence:      0.8,
				ImpactedNodes:   []string{agentNode, roleNode, "aws:s3:bucket/tickets"},
				ImpactedPath: []AWSLeastPrivilegePathStep{
					{NodeID: agentNode, NodeType: "ai_agent", Label: "agent"},
					{NodeID: roleNode, NodeType: "identity", Label: "shared-agent-runtime"},
					{NodeID: "aws:s3:bucket/tickets", NodeType: "target_resource", Label: "tickets"},
				},
			},
			{
				CaseID:          "case-other-agent-risk",
				SourceType:      "ai_agent_risk",
				SourceFindingID: "risk-other",
				Lifecycle:       "proposed",
				Severity:        "medium",
				Status:          "open",
				ApprovalState:   "pending",
				IdentityNodeID:  otherAgentNode,
				IdentityName:    "agent-v2",
				IdentityType:    "ai_agent",
				Score:           68,
				Confidence:      0.8,
				ImpactedNodes:   []string{otherAgentNode, roleNode, "aws:s3:bucket/archive"},
				ImpactedPath: []AWSLeastPrivilegePathStep{
					{NodeID: otherAgentNode, NodeType: "ai_agent", Label: "agent-v2"},
					{NodeID: roleNode, NodeType: "identity", Label: "shared-agent-runtime"},
					{NodeID: "aws:s3:bucket/archive", NodeType: "target_resource", Label: "archive"},
				},
			},
		},
	}

	merged := awsAgentIdentityDetailMergeRemediationCaseResults(roleCases, agentCases, roleNode, agentNode)
	scoped := awsAgentIdentityDetailScopeRemediationCases(merged, record, roleNode)
	got := map[string]struct{}{}
	for _, c := range scoped.Cases {
		got[c.CaseID] = struct{}{}
	}
	if _, ok := got["case-role-wide"]; !ok {
		t.Fatalf("role-wide remediation case must be retained: %+v", scoped.Cases)
	}
	if _, ok := got["case-selected-agent-risk"]; !ok {
		t.Fatalf("selected agent-scoped remediation case must be retained: %+v", scoped.Cases)
	}
	if _, ok := got["case-other-agent-risk"]; ok {
		t.Fatalf("other agent remediation case must be filtered out: %+v", scoped.Cases)
	}
	if scoped.AppliedFilters["identity"] != roleNode || scoped.AppliedFilters["agent_identity"] != agentNode {
		t.Fatalf("merged remediation filters must expose role and agent identities, got %+v", scoped.AppliedFilters)
	}
	if scoped.Summary.FilteredCases != len(scoped.Cases) || scoped.Summary.RelationshipCount != len(scoped.Relationships) {
		t.Fatalf("merged remediation summary must match scoped cases: summary=%+v relationships=%+v", scoped.Summary, scoped.Relationships)
	}
}

func TestAWSAgentIdentityDetailRelationshipsIncludeInventorySourceNodes(t *testing.T) {
	roleARN := "arn:aws:iam::123456789012:role/shared-agent-runtime"
	roleNode := awsIdentityNodeIDForAPI(roleARN)
	selected := AWSAIAgentIdentityRecord{
		AccountID:         "123456789012",
		Region:            "us-east-1",
		AgentType:         "custom_agent",
		AgentID:           "agent",
		AgentNodeID:       "aws:agent:123456789012:us-east-1:custom_agent/agent",
		RuntimeRoleARN:    roleARN,
		RuntimeRoleNodeID: roleNode,
		GatewayNodeID:     "aws:agent-gateway:123456789012:us-east-1:gateway/agent-gateway",
		ToolNames:         []string{"search-tickets"},
		EvidenceRef:       "evidence://inventory/agent",
	}
	other := AWSAIAgentIdentityRecord{
		AccountID:         "123456789012",
		Region:            "us-east-1",
		AgentType:         "custom_agent",
		AgentID:           "agent-v2",
		AgentNodeID:       "aws:agent:123456789012:us-east-1:custom_agent/agent-v2",
		RuntimeRoleARN:    roleARN,
		RuntimeRoleNodeID: roleNode,
		GatewayNodeID:     "aws:agent-gateway:123456789012:us-east-1:gateway/agent-v2-gateway",
		ToolNames:         []string{"archive-tickets"},
		EvidenceRef:       "evidence://inventory/agent-v2",
	}
	inventory := AWSAIAgentIdentityInventoryResult{
		Relationships: awsAIAgentIdentityRelationships([]AWSAIAgentIdentityRecord{selected, other}),
	}

	relationships := awsAgentIdentityDetailRelationships(selected, inventory, AWSAgentRuntimeAccessResult{})
	if len(relationships) == 0 {
		t.Fatal("expected selected inventory relationships")
	}
	workloadNode := awsAIAgentWorkloadNodeID(selected)
	toolNode := awsAIAgentToolNodeID(selected.GatewayNodeID, "search-tickets")
	foundRunsAs := false
	foundCallsTool := false
	for _, relationship := range relationships {
		if relationship.Type == "runs_as" && relationship.FromNodeID == workloadNode && relationship.ToNodeID == roleNode {
			foundRunsAs = true
		}
		if relationship.Type == "calls_tool" && relationship.FromNodeID == selected.GatewayNodeID && relationship.ToNodeID == toolNode {
			foundCallsTool = true
		}
		if relationship.FromNodeID == other.AgentNodeID || relationship.FromNodeID == other.GatewayNodeID || relationship.FromNodeID == awsAIAgentWorkloadNodeID(other) {
			t.Fatalf("detail relationships must not include sibling agent source edges: %+v", relationships)
		}
	}
	if !foundRunsAs {
		t.Fatalf("expected workload-sourced runs_as relationship, got %+v", relationships)
	}
	if !foundCallsTool {
		t.Fatalf("expected gateway-sourced calls_tool relationship, got %+v", relationships)
	}
}

func TestAWSAgentIdentityDetailGovernanceFiltersPreferRoleThenAgent(t *testing.T) {
	roleARN := "arn:aws:iam::123456789012:role/agent-runtime"
	roleRecord := AWSAIAgentIdentityRecord{
		AgentID:           "agent",
		AgentNodeID:       "aws:agent:123456789012:us-east-1:custom_agent/agent",
		RuntimeRoleARN:    roleARN,
		RuntimeRoleNodeID: awsIdentityNodeIDForAPI(roleARN),
	}
	identityID, agentID := awsAgentIdentityDetailGovernanceFilters(roleRecord, roleRecord.AgentNodeID)
	if identityID != roleRecord.RuntimeRoleNodeID || agentID != "" {
		t.Fatalf("role-backed governance must use identity_id only, got identity=%q agent=%q", identityID, agentID)
	}

	rolelessRecord := AWSAIAgentIdentityRecord{
		AgentID:     "custom-agent",
		AgentNodeID: "aws:agent:123456789012:us-east-1:custom_agent/custom-agent",
	}
	identityID, agentID = awsAgentIdentityDetailGovernanceFilters(rolelessRecord, rolelessRecord.AgentNodeID)
	if identityID != "" || agentID != rolelessRecord.AgentNodeID {
		t.Fatalf("roleless governance must use agent_id, got identity=%q agent=%q", identityID, agentID)
	}
}

func TestAWSAgentIdentityDetailGovernanceAlternateFiltersCoverExactKeys(t *testing.T) {
	roleARN := "arn:aws:iam::123456789012:role/shared-agent-runtime"
	roleNode := awsIdentityNodeIDForAPI(roleARN)
	roleRecord := AWSAIAgentIdentityRecord{
		AgentID:           "agent",
		AgentNodeID:       "aws:agent:123456789012:us-east-1:custom_agent/agent",
		RuntimeRoleARN:    roleARN,
		RuntimeRoleNodeID: roleNode,
	}
	alternates := awsAgentIdentityDetailGovernanceAlternateFilters(roleRecord, true, roleNode, "")
	gotIdentities := map[string]struct{}{}
	gotAgents := map[string]struct{}{}
	for _, alternate := range alternates {
		if alternate.IdentityID != "" {
			gotIdentities[alternate.IdentityID] = struct{}{}
		}
		if alternate.AgentID != "" {
			gotAgents[alternate.AgentID] = struct{}{}
		}
	}
	if _, ok := gotIdentities[roleNode]; ok {
		t.Fatalf("primary identity filter must not repeat as an alternate: %+v", alternates)
	}
	if _, ok := gotIdentities[roleARN]; !ok {
		t.Fatalf("raw role ARN identity must be queried as an alternate: %+v", alternates)
	}
	if _, ok := gotAgents[roleRecord.AgentNodeID]; !ok {
		t.Fatalf("agent node key must be queried as an alternate for role-backed agents: %+v", alternates)
	}
	if _, ok := gotAgents[roleRecord.AgentID]; !ok {
		t.Fatalf("agent id key must be queried as an alternate for role-backed agents: %+v", alternates)
	}

	rolelessRecord := AWSAIAgentIdentityRecord{
		AgentID:     "custom-agent",
		AgentNodeID: "aws:agent:123456789012:us-east-1:custom_agent/custom-agent",
	}
	rolelessAlternates := awsAgentIdentityDetailGovernanceAlternateFilters(rolelessRecord, true, "", rolelessRecord.AgentNodeID)
	if len(rolelessAlternates) != 1 || rolelessAlternates[0].AgentID != rolelessRecord.AgentID || rolelessAlternates[0].IdentityID != "" {
		t.Fatalf("roleless agents must query the alternate exact agent id only: %+v", rolelessAlternates)
	}

	if alternates := awsAgentIdentityDetailGovernanceAlternateFilters(AWSAIAgentIdentityRecord{}, false, "", "unresolved-sentinel"); len(alternates) != 0 {
		t.Fatalf("unresolved agents must not fan out governance queries: %+v", alternates)
	}
}

func TestAWSAgentIdentityDetailScopesGovernanceToSelectedAgent(t *testing.T) {
	roleARN := "arn:aws:iam::123456789012:role/shared-agent-runtime"
	roleNode := awsIdentityNodeIDForAPI(roleARN)
	record := AWSAIAgentIdentityRecord{
		AgentID:           "agent",
		AgentNodeID:       "aws:agent:123456789012:us-east-1:custom_agent/agent",
		RuntimeRoleARN:    roleARN,
		RuntimeRoleNodeID: roleNode,
	}
	otherAgentNode := "aws:agent:123456789012:us-east-1:custom_agent/agent-v2"
	occurred := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	governance := AWSGovernanceAuditReportingResult{
		Records: []AWSGovernanceAuditReportRecord{
			{ReportID: "report-role-wide", Category: "approval", SourceType: "least_privilege", DecisionType: "remediation_approval", State: "pending", IdentityNodeID: roleNode, OccurredAt: occurred},
			{ReportID: "report-selected-agent", Category: "decision", SourceType: "agentcore_gateway_policy_advisory", DecisionType: "agentcore_gateway_policy_advisory", State: "advisory", IdentityNodeID: roleNode, AgentID: record.AgentID, AgentNodeID: record.AgentNodeID, OccurredAt: occurred},
			{ReportID: "report-sibling-agent", Category: "decision", SourceType: "agentcore_gateway_policy_advisory", DecisionType: "agentcore_gateway_policy_advisory", State: "advisory", IdentityNodeID: roleNode, AgentID: "agent-v2", AgentNodeID: otherAgentNode, OccurredAt: occurred},
		},
	}

	scoped := awsAgentIdentityDetailScopeGovernance(governance, record)
	got := map[string]struct{}{}
	for _, candidate := range scoped.Records {
		got[candidate.ReportID] = struct{}{}
	}
	if _, ok := got["report-role-wide"]; !ok {
		t.Fatalf("role-wide governance rows must be retained: %+v", scoped.Records)
	}
	if _, ok := got["report-selected-agent"]; !ok {
		t.Fatalf("selected-agent governance rows must be retained: %+v", scoped.Records)
	}
	if _, ok := got["report-sibling-agent"]; ok {
		t.Fatalf("sibling-agent governance rows sharing the runtime role must be filtered out: %+v", scoped.Records)
	}
	if scoped.Summary.FilteredRecords != len(scoped.Records) || scoped.Summary.TotalRecords != len(scoped.Records) {
		t.Fatalf("governance summary must be recomputed from scoped records: %+v", scoped.Summary)
	}
}

func TestAWSAgentIdentityDetailMergesGovernanceResults(t *testing.T) {
	roleARN := "arn:aws:iam::123456789012:role/shared-agent-runtime"
	roleNode := awsIdentityNodeIDForAPI(roleARN)
	agentNode := "aws:agent:123456789012:us-east-1:custom_agent/agent"
	occurred := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	roleGovernance := AWSGovernanceAuditReportingResult{
		AppliedFilters: map[string]string{"identity_id": roleNode},
		Records: []AWSGovernanceAuditReportRecord{
			{ReportID: "report-role-wide", Category: "approval", SourceType: "least_privilege", DecisionType: "remediation_approval", State: "pending", IdentityNodeID: roleNode, OccurredAt: occurred},
			{ReportID: "report-shared", Category: "decision", SourceType: "agentcore_gateway_policy_advisory", DecisionType: "agentcore_gateway_policy_advisory", State: "advisory", IdentityNodeID: roleNode, AgentNodeID: agentNode, OccurredAt: occurred},
		},
	}
	agentGovernance := AWSGovernanceAuditReportingResult{
		AppliedFilters: map[string]string{"agent_id": agentNode},
		Records: []AWSGovernanceAuditReportRecord{
			{ReportID: "report-shared", Category: "decision", SourceType: "agentcore_gateway_policy_advisory", DecisionType: "agentcore_gateway_policy_advisory", State: "advisory", IdentityNodeID: roleNode, AgentNodeID: agentNode, OccurredAt: occurred},
			{ReportID: "report-agent-only", Category: "decision", SourceType: "agentcore_gateway_policy_advisory", DecisionType: "agentcore_gateway_policy_advisory", State: "advisory", AgentNodeID: agentNode, OccurredAt: occurred.Add(time.Hour)},
		},
	}

	merged := awsAgentIdentityDetailMergeGovernanceResults(roleGovernance, agentGovernance, []string{roleNode}, []string{"", agentNode})
	if len(merged.Records) != 3 {
		t.Fatalf("merged governance must dedupe shared report rows, got %+v", merged.Records)
	}
	if merged.Records[0].ReportID != "report-agent-only" {
		t.Fatalf("merged governance must stay sorted by occurred_at desc: %+v", merged.Records)
	}
	if merged.Summary.FilteredRecords != 3 || merged.Summary.TotalRecords != 3 {
		t.Fatalf("merged governance summary must be recomputed: %+v", merged.Summary)
	}
	if merged.AppliedFilters["identity_id"] != roleNode || merged.AppliedFilters["agent_id"] != agentNode {
		t.Fatalf("merged governance filters must expose the role identity and agent keys: %+v", merged.AppliedFilters)
	}
}

func TestAWSAgentIdentityDetailSecretReferencesAreMetadataOnly(t *testing.T) {
	record := AWSAIAgentIdentityRecord{
		AgentID: "agent-1",
		ProviderKeyReferences: []AWSAIAgentProviderKeyReference{
			{Reference: "arn:aws:secretsmanager:us-east-1:111111111111:secret:openai/api-key", ReferenceKind: "secretsmanager_secret", Provider: "openai", Sensitivity: "external_provider_key", Resolved: true, EvidenceRef: "evidence://keys/openai", Confidence: 0.9},
		},
		CredentialReferenceRefs: []string{"ssm://params/agent-1/token", "arn:aws:secretsmanager:us-east-1:111111111111:secret:openai/api-key"},
		EvidenceRef:             "evidence://inventory/agent-1",
		Confidence:              0.8,
	}
	references := awsAgentIdentityDetailSecretReferences(record)
	if len(references) != 2 {
		t.Fatalf("duplicate references must be deduped: %+v", references)
	}
	for _, reference := range references {
		if reference.Reference == "" || reference.ReferenceKind == "" {
			t.Fatalf("secret reference missing metadata: %+v", reference)
		}
	}
}

func TestAWSAgentIdentityDetailResolveMatchesAllTokens(t *testing.T) {
	records := []AWSAIAgentIdentityRecord{
		{AgentID: "AGENT1", AgentARN: "arn:aws:bedrock:us-east-1:1:agent/AGENT1", AgentNodeID: "aws:agent:1:us-east-1:bedrock_agent/AGENT1", AgentName: "payments-agent"},
	}
	for _, token := range []string{"AGENT1", "arn:aws:bedrock:us-east-1:1:agent/AGENT1", "aws:agent:1:us-east-1:bedrock_agent/AGENT1", "payments-agent", "agent1"} {
		if _, ok := awsAgentIdentityDetailResolve(token, records); !ok {
			t.Fatalf("token %q must resolve the agent record", token)
		}
	}
	if _, ok := awsAgentIdentityDetailResolve("other-agent", records); ok {
		t.Fatalf("unrelated token must not resolve")
	}
}

func TestGetAWSAgentIdentityDetailFixtureStates(t *testing.T) {
	now := time.Date(2026, 7, 3, 21, 0, 0, 0, time.UTC)
	svc, ws := newAgentIdentityDetailService(t, "project-agent-identity-detail-fixture", now)

	for _, state := range []string{"success", "empty", "degraded", "partial_failure", "permission_denied"} {
		result, err := svc.GetAWSAgentIdentityDetail(defaultScopeContext(), ws, "project-agent-identity-detail-fixture", AWSAgentIdentityDetailRequest{
			ConnectorID:  "aws-prod",
			FixtureState: state,
			Agent:        "AGENTPAY1",
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
		if state == "empty" && result.Status != "empty" {
			t.Fatalf("empty fixture must surface as explicit status, got %q", result.Status)
		}
		if state == "permission_denied" && result.Status != "permission_denied" {
			t.Fatalf("permission denied must surface as explicit status, got %q", result.Status)
		}
	}
}

func TestRouterAWSAgentIdentityDetail(t *testing.T) {
	now := time.Date(2026, 7, 3, 21, 30, 0, 0, time.UTC)
	svc, _ := newAgentIdentityDetailService(t, "project-agent-identity-detail-route", now)
	r := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{})

	resp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-agent-identity-detail-route/aws/agent-identity-detail?connector_id=aws-prod&fixture_state=success&agent=AGENTPAY1", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	var body struct {
		Detail AWSAgentIdentityDetailResult `json:"detail"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Detail.CurrentIssueRef != "#1550" || !body.Detail.Agent.Resolved {
		t.Fatalf("unexpected route payload: %+v", body.Detail.Agent)
	}

	missingAgent := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-agent-identity-detail-route/aws/agent-identity-detail?connector_id=aws-prod&fixture_state=success", "")
	if missingAgent.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 without agent, got %d body=%s", missingAgent.Code, missingAgent.Body.String())
	}
}
