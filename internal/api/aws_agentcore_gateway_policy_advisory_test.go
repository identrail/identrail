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

func newAgentCoreGatewayPolicyAdvisoryService(t *testing.T, project string, now time.Time) (*Service, string) {
	t.Helper()
	return newBlastRadiusService(t, project, now)
}

func TestGetAWSAgentCoreGatewayPolicyAdvisoryBuildsContract(t *testing.T) {
	now := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	svc, ws := newAgentCoreGatewayPolicyAdvisoryService(t, "project-agentcore-gateway-policy-advisory", now)

	result, err := svc.GetAWSAgentCoreGatewayPolicyAdvisory(defaultScopeContext(), ws, "project-agentcore-gateway-policy-advisory", AWSAgentCoreGatewayPolicyAdvisoryRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
	})
	if err != nil {
		t.Fatalf("get agentcore gateway policy advisory: %v", err)
	}
	if result.CurrentIssueRef != "#1545" || result.Version != awsAgentCoreGatewayPolicyAdvisoryVersion || result.Mode != awsAgentCoreGatewayPolicyAdvisoryModeAdvisory {
		t.Fatalf("unexpected contract metadata: %+v", result)
	}
	if result.PolicyVersion != awsAgentCoreGatewayPolicyAdvisoryPolicyID {
		t.Fatalf("expected stable policy version, got %q", result.PolicyVersion)
	}
	if result.PilotState == "" || result.EnforcementState != awsAgentCoreGatewayPolicyEnforcementAdvisory {
		t.Fatalf("expected explicit pilot/enforcement state, got pilot=%q enforcement=%q", result.PilotState, result.EnforcementState)
	}
	if len(result.Advisories) == 0 {
		t.Fatalf("expected advisories to be projected from AI agent risk source: %+v", result.Summary)
	}
	for _, advisory := range result.Advisories {
		if advisory.AdvisoryID == "" || advisory.CalculationVersion != awsAgentCoreGatewayPolicyAdvisoryVersion {
			t.Fatalf("advisory missing stable metadata: %+v", advisory)
		}
		if advisory.Mode != awsAgentCoreGatewayPolicyAdvisoryModeAdvisory {
			t.Fatalf("advisory must remain advisory: %+v", advisory)
		}
		if advisory.PilotState == "" || advisory.EnforcementState != awsAgentCoreGatewayPolicyEnforcementAdvisory {
			t.Fatalf("advisory missing explicit governance state: %+v", advisory)
		}
		switch advisory.Outcome {
		case awsAgentCoreGatewayPolicyOutcomeAllowTools, awsAgentCoreGatewayPolicyOutcomeWarn, awsAgentCoreGatewayPolicyOutcomeRequireApproval, awsAgentCoreGatewayPolicyOutcomeRestrictTools, awsAgentCoreGatewayPolicyOutcomeBlockTools:
		default:
			t.Fatalf("advisory has unknown outcome: %+v", advisory)
		}
		if advisory.AgentNodeID == "" {
			t.Fatalf("advisory must reference an agent_node_id: %+v", advisory)
		}
		if advisory.FindingID == "" {
			t.Fatalf("advisory must reference its source finding: %+v", advisory)
		}
		if advisory.EvidenceBoundary != awsAgentCoreGatewayPolicyAdvisoryEvidenceBoundary() {
			t.Fatalf("advisory crossed evidence boundary: %+v", advisory)
		}
		if !advisory.ReadOnlyProjection {
			t.Fatalf("advisory must remain read-only: %+v", advisory)
		}
		if advisory.Provenance.PolicyVersion == "" || advisory.Provenance.PolicyRule == "" {
			t.Fatalf("advisory missing provenance: %+v", advisory.Provenance)
		}
		if advisory.InputHash.Value == "" {
			t.Fatalf("advisory missing input hash: %+v", advisory.InputHash)
		}
	}

	serialized, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	lower := strings.ToLower(string(serialized))
	for _, forbidden := range []string{"\"prompt\"", "\"tool_payload\"", "\"completion\"", "\"secret_access_key\""} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("agentcore gateway policy advisory serialized forbidden sensitive payload marker %q", forbidden)
		}
	}
}

func TestAWSAgentCoreGatewayPolicyAdvisoryClassifyPolicyOrder(t *testing.T) {
	base := AWSAIAgentRiskFinding{FindingID: "f-1", AgentNodeID: "aws:agent:111111111111:us-east-1:agent/x", Severity: "medium", RiskType: "unknown"}

	critical := base
	critical.Severity = "critical"
	critical.SensitiveResources = []string{"arn:aws:secretsmanager:us-east-1:111111111111:secret:openai/api-key"}
	if out, rule, _, _ := awsAgentCoreGatewayPolicyAdvisoryClassify(critical); out != awsAgentCoreGatewayPolicyOutcomeBlockTools || rule != "critical_sensitive_reachability" {
		t.Fatalf("critical + sensitive reachability must classify as block_tools: %s / %s", out, rule)
	}

	externalCred := base
	externalCred.RiskType = "external_credential"
	if out, rule, _, _ := awsAgentCoreGatewayPolicyAdvisoryClassify(externalCred); out != awsAgentCoreGatewayPolicyOutcomeRequireApproval || rule != "external_credential_use" {
		t.Fatalf("external credential must classify as require_approval: %s / %s", out, rule)
	}

	externalCredExposure := base
	externalCredExposure.RiskType = "external_credential_exposure"
	if out, rule, _, _ := awsAgentCoreGatewayPolicyAdvisoryClassify(externalCredExposure); out != awsAgentCoreGatewayPolicyOutcomeRequireApproval || rule != "external_credential_use" {
		t.Fatalf("upstream external credential exposure must classify as require_approval: %s / %s", out, rule)
	}

	broad := base
	broad.RiskType = "broad_tool_access"
	if out, rule, _, _ := awsAgentCoreGatewayPolicyAdvisoryClassify(broad); out != awsAgentCoreGatewayPolicyOutcomeRestrictTools || rule != "broad_tool_access" {
		t.Fatalf("broad tool access must classify as restrict_tools: %s / %s", out, rule)
	}

	sensitiveDataReachability := base
	sensitiveDataReachability.RiskType = "sensitive_data_reachability"
	sensitiveDataReachability.ToolNames = []string{"tool-a"}
	sensitiveDataReachability.SensitiveResources = []string{"arn:aws:secretsmanager:us-east-1:111111111111:secret:openai/api-key"}
	if out, rule, _, _ := awsAgentCoreGatewayPolicyAdvisoryClassify(sensitiveDataReachability); out != awsAgentCoreGatewayPolicyOutcomeRestrictTools || rule != "sensitive_reachability" {
		t.Fatalf("upstream sensitive data reachability must classify as restrict_tools: %s / %s", out, rule)
	}

	for _, riskType := range []string{"undeclared_tool_runtime", "backing_role_mismatch"} {
		finding := base
		finding.RiskType = riskType
		finding.ToolNames = []string{"tool-a"}
		finding.SensitiveResources = []string{"arn:aws:s3:::sensitive-target"}
		if out, rule, _, _ := awsAgentCoreGatewayPolicyAdvisoryClassify(finding); out != awsAgentCoreGatewayPolicyOutcomeRequireApproval || rule != "runtime_governance_review" {
			t.Fatalf("%s must classify as require_approval: %s / %s", riskType, out, rule)
		}
	}

	for _, riskType := range []string{"runtime_tool_anomaly", "declared_unused_tool", "backing_role_scope"} {
		finding := base
		finding.RiskType = riskType
		finding.ToolNames = []string{"tool-a"}
		finding.SensitiveResources = []string{"arn:aws:s3:::sensitive-target"}
		if out, rule, _, _ := awsAgentCoreGatewayPolicyAdvisoryClassify(finding); out != awsAgentCoreGatewayPolicyOutcomeRestrictTools || rule != "runtime_tool_scope_review" {
			t.Fatalf("%s must classify as restrict_tools: %s / %s", riskType, out, rule)
		}
	}

	ownerless := base
	ownerless.RiskType = "ownerless_agent"
	if out, rule, _, _ := awsAgentCoreGatewayPolicyAdvisoryClassify(ownerless); out != awsAgentCoreGatewayPolicyOutcomeWarn || rule != "ownerless_agent" {
		t.Fatalf("ownerless agent must classify as warn: %s / %s", out, rule)
	}

	highGeneric := base
	highGeneric.Severity = "high"
	if out, rule, _, _ := awsAgentCoreGatewayPolicyAdvisoryClassify(highGeneric); out != awsAgentCoreGatewayPolicyOutcomeRequireApproval || rule != "high_severity_finding" {
		t.Fatalf("high severity without matching risk type must require approval: %s / %s", out, rule)
	}

	unknownTools := AWSAIAgentRiskFinding{FindingID: "f-2", AgentNodeID: "aws:agent:x", Severity: "medium", RiskType: "unknown"}
	if out, rule, _, _ := awsAgentCoreGatewayPolicyAdvisoryClassify(unknownTools); out != awsAgentCoreGatewayPolicyOutcomeWarn || rule != "unknown_tool_scope" {
		t.Fatalf("no tools must classify as warn: %s / %s", out, rule)
	}

	fine := AWSAIAgentRiskFinding{FindingID: "f-3", AgentNodeID: "aws:agent:x", Severity: "low", RiskType: "unknown", ToolNames: []string{"tool-a"}}
	if out, rule, _, _ := awsAgentCoreGatewayPolicyAdvisoryClassify(fine); out != awsAgentCoreGatewayPolicyOutcomeAllowTools || rule != "no_active_risk" {
		t.Fatalf("no active risk must allow tools: %s / %s", out, rule)
	}
}

func TestAWSAgentCoreGatewayPolicyAdvisoryToolPartition(t *testing.T) {
	tools := []string{"tool-a", "tool-b"}

	allow, restrict, block := awsAgentCoreGatewayPolicyAdvisoryToolPartition(awsAgentCoreGatewayPolicyOutcomeBlockTools, tools)
	if len(allow) != 0 || len(restrict) != 0 || len(block) != 2 {
		t.Fatalf("block_tools must put all tools in blocked bucket: allow=%+v restrict=%+v block=%+v", allow, restrict, block)
	}

	allow, restrict, block = awsAgentCoreGatewayPolicyAdvisoryToolPartition(awsAgentCoreGatewayPolicyOutcomeRestrictTools, tools)
	if len(allow) != 0 || len(restrict) != 2 || len(block) != 0 {
		t.Fatalf("restrict_tools must put all tools in restricted bucket: allow=%+v restrict=%+v block=%+v", allow, restrict, block)
	}

	allow, restrict, block = awsAgentCoreGatewayPolicyAdvisoryToolPartition(awsAgentCoreGatewayPolicyOutcomeAllowTools, tools)
	if len(allow) != 2 || len(restrict) != 0 || len(block) != 0 {
		t.Fatalf("allow_tools must put all tools in allowed bucket: allow=%+v restrict=%+v block=%+v", allow, restrict, block)
	}
}

func TestAWSAgentCoreGatewayPolicyAdvisoryPilotState(t *testing.T) {
	if got := awsAgentCoreGatewayPolicyAdvisoryPilotState(awsAgentCoreGatewayPolicyOutcomeAllowTools); got != awsAgentCoreGatewayPolicyPilotStateCandidate {
		t.Fatalf("allow_tools must be a pilot candidate, got %q", got)
	}
	if got := awsAgentCoreGatewayPolicyAdvisoryPilotState(awsAgentCoreGatewayPolicyOutcomeRestrictTools); got != awsAgentCoreGatewayPolicyPilotStateReview {
		t.Fatalf("restrict_tools must require operator review, got %q", got)
	}
	if got := awsAgentCoreGatewayPolicyAdvisoryPilotState(awsAgentCoreGatewayPolicyOutcomeBlockTools); got != awsAgentCoreGatewayPolicyPilotStateBlocked {
		t.Fatalf("block_tools must be blocked, got %q", got)
	}
}

func TestAWSAgentCoreGatewayPolicyAdvisoryAdmitsRequiresAgentNode(t *testing.T) {
	if awsAgentCoreGatewayPolicyAdvisoryAdmits(AWSAIAgentRiskFinding{FindingID: "f-1"}) {
		t.Fatalf("finding without agent_node_id must not be admitted")
	}
	if !awsAgentCoreGatewayPolicyAdvisoryAdmits(AWSAIAgentRiskFinding{FindingID: "f-1", AgentNodeID: "aws:agent:x"}) {
		t.Fatalf("finding with agent_node_id must be admitted")
	}
}

func TestFilterAWSAgentCoreGatewayPolicyAdvisories(t *testing.T) {
	entries := []AWSAgentCoreGatewayPolicyAdvisoryEntry{
		{
			AdvisoryID:  "adv-block",
			Outcome:     awsAgentCoreGatewayPolicyOutcomeBlockTools,
			Severity:    "critical",
			AccountID:   "111111111111",
			Region:      "us-east-1",
			AgentNodeID: "aws:agent:111111111111:us-east-1:agent/a",
			AgentID:     "agent-a",
			RiskType:    "sensitive_reachability",
			FindingID:   "aws-ai-agent-risk:a",
		},
		{
			AdvisoryID:  "adv-warn",
			Outcome:     awsAgentCoreGatewayPolicyOutcomeWarn,
			Severity:    "medium",
			AccountID:   "222222222222",
			Region:      "us-west-2",
			AgentNodeID: "aws:agent:222222222222:us-west-2:agent/b",
			AgentID:     "agent-b",
			RiskType:    "ownerless_agent",
			FindingID:   "aws-ai-agent-risk:b",
		},
	}

	filtered, applied := filterAWSAgentCoreGatewayPolicyAdvisories(entries, AWSAgentCoreGatewayPolicyAdvisoryRequest{Outcome: "block_tools"})
	if applied["outcome"] != normalizeAWSRuntimeEventFilterToken("block_tools") || len(filtered) != 1 || filtered[0].AdvisoryID != "adv-block" {
		t.Fatalf("outcome filter did not scope entries: applied=%+v filtered=%+v", applied, filtered)
	}

	filtered, applied = filterAWSAgentCoreGatewayPolicyAdvisories(entries, AWSAgentCoreGatewayPolicyAdvisoryRequest{AgentID: "agent-b"})
	if applied["agent_id"] != "agent-b" || len(filtered) != 1 || filtered[0].AdvisoryID != "adv-warn" {
		t.Fatalf("agent_id filter did not scope entries: applied=%+v filtered=%+v", applied, filtered)
	}

	filtered, applied = filterAWSAgentCoreGatewayPolicyAdvisories(entries, AWSAgentCoreGatewayPolicyAdvisoryRequest{RiskType: "sensitive_reachability"})
	if applied["risk_type"] != "sensitive_reachability" || len(filtered) != 1 || filtered[0].AdvisoryID != "adv-block" {
		t.Fatalf("risk_type filter did not scope entries: applied=%+v filtered=%+v", applied, filtered)
	}

	filtered, applied = filterAWSAgentCoreGatewayPolicyAdvisories(entries, AWSAgentCoreGatewayPolicyAdvisoryRequest{Search: "ownerless"})
	if applied["search"] != "ownerless" || len(filtered) != 1 || filtered[0].AdvisoryID != "adv-warn" {
		t.Fatalf("search must reach risk_type / rationale: applied=%+v filtered=%+v", applied, filtered)
	}
}

func TestAWSAgentCoreGatewayPolicyAdvisoryFixtureStates(t *testing.T) {
	now := time.Date(2026, 7, 3, 13, 0, 0, 0, time.UTC)
	svc, ws := newAgentCoreGatewayPolicyAdvisoryService(t, "project-agentcore-gateway-policy-advisory-fixture", now)

	for _, state := range []string{"success", "empty", "degraded", "partial_failure", "permission_denied"} {
		result, err := svc.GetAWSAgentCoreGatewayPolicyAdvisory(defaultScopeContext(), ws, "project-agentcore-gateway-policy-advisory-fixture", AWSAgentCoreGatewayPolicyAdvisoryRequest{
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

func TestAWSAgentCoreGatewayPolicyAdvisoryInputHashCoversAllInputs(t *testing.T) {
	base := AWSAIAgentRiskFinding{FindingID: "f-hash", AgentNodeID: "aws:agent:x", Severity: "medium", RiskType: "unknown", Status: "action_required", ToolNames: []string{"a"}, SensitiveResources: []string{"arn:aws:s3:::sensitive-a"}}
	baseHash := awsAgentCoreGatewayPolicyAdvisoryInputHash(base, awsAgentCoreGatewayPolicyOutcomeAllowTools).Value

	sevChanged := base
	sevChanged.Severity = "critical"
	if awsAgentCoreGatewayPolicyAdvisoryInputHash(sevChanged, awsAgentCoreGatewayPolicyOutcomeAllowTools).Value == baseHash {
		t.Fatalf("severity change must move input hash")
	}

	riskChanged := base
	riskChanged.RiskType = "external_credential"
	if awsAgentCoreGatewayPolicyAdvisoryInputHash(riskChanged, awsAgentCoreGatewayPolicyOutcomeAllowTools).Value == baseHash {
		t.Fatalf("risk_type change must move input hash")
	}

	if awsAgentCoreGatewayPolicyAdvisoryInputHash(base, awsAgentCoreGatewayPolicyOutcomeBlockTools).Value == baseHash {
		t.Fatalf("outcome change must move input hash")
	}

	extraSensitive := base
	extraSensitive.SensitiveResources = []string{"arn:aws:s3:::sensitive-a", "arn:aws:s3:::sensitive-b"}
	if awsAgentCoreGatewayPolicyAdvisoryInputHash(extraSensitive, awsAgentCoreGatewayPolicyOutcomeAllowTools).Value == baseHash {
		t.Fatalf("sensitive count change must move input hash")
	}

	toolScopeChanged := base
	toolScopeChanged.ToolNames = []string{"b"}
	if awsAgentCoreGatewayPolicyAdvisoryInputHash(toolScopeChanged, awsAgentCoreGatewayPolicyOutcomeAllowTools).Value == baseHash {
		t.Fatalf("same-count tool scope change must move input hash")
	}

	sensitiveScopeChanged := base
	sensitiveScopeChanged.SensitiveResources = []string{"arn:aws:s3:::sensitive-b"}
	if awsAgentCoreGatewayPolicyAdvisoryInputHash(sensitiveScopeChanged, awsAgentCoreGatewayPolicyOutcomeAllowTools).Value == baseHash {
		t.Fatalf("same-count sensitive resource scope change must move input hash")
	}
}

func TestRouterAWSAgentCoreGatewayPolicyAdvisory(t *testing.T) {
	now := time.Date(2026, 7, 3, 14, 0, 0, 0, time.UTC)
	svc, _ := newAgentCoreGatewayPolicyAdvisoryService(t, "project-agentcore-gateway-policy-advisory-route", now)
	r := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{})

	resp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-agentcore-gateway-policy-advisory-route/aws/agentcore-gateway-policy-advisory?connector_id=aws-prod&fixture_state=success", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	var body struct {
		Advisory AWSAgentCoreGatewayPolicyAdvisoryResult `json:"agentcore_gateway_policy_advisory"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Advisory.CurrentIssueRef != "#1545" || body.Advisory.PolicyVersion != awsAgentCoreGatewayPolicyAdvisoryPolicyID {
		t.Fatalf("unexpected route payload: %+v", body.Advisory)
	}
}
