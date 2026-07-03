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

func TestGetAWSAgentIdentityDetailUnknownAgentIsExplicit(t *testing.T) {
	now := time.Date(2026, 7, 3, 20, 15, 0, 0, time.UTC)
	svc, ws := newAgentIdentityDetailService(t, "project-agent-identity-detail-unknown", now)

	result, err := svc.GetAWSAgentIdentityDetail(defaultScopeContext(), ws, "project-agent-identity-detail-unknown", AWSAgentIdentityDetailRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
		Agent:        "agent-that-does-not-exist",
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
