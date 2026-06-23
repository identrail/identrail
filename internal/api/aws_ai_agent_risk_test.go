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

func newAIAgentRiskService(t *testing.T, project string, now time.Time) (*Service, string) {
	t.Helper()
	return newBlastRadiusService(t, project, now)
}

func TestGetAWSAIAgentRiskBuildsFindingContract(t *testing.T) {
	now := time.Date(2026, 6, 23, 9, 0, 0, 0, time.UTC)
	svc, ws := newAIAgentRiskService(t, "project-ai-agent-risk", now)

	result, err := svc.GetAWSAIAgentRisk(defaultScopeContext(), ws, "project-ai-agent-risk", AWSAIAgentRiskRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
	})
	if err != nil {
		t.Fatalf("get ai agent risk: %v", err)
	}
	if result.CurrentIssueRef != "#1528" || result.Version != awsAIAgentRiskVersion || result.Status != "ready" {
		t.Fatalf("unexpected contract metadata: %+v", result)
	}
	if len(result.Findings) == 0 || result.Summary.TotalFindings != len(result.Findings) {
		t.Fatalf("expected finding summary to match payload: %+v", result.Summary)
	}
	if result.Summary.ExternalCredentialCount == 0 || result.Summary.BroadToolAccessCount == 0 || result.Summary.SensitiveReachabilityCount == 0 {
		t.Fatalf("expected external credential, broad tool, and sensitive reachability findings: %+v", result.Summary)
	}
	if result.Summary.RuntimeObservedCount == 0 || result.Summary.RelationshipCount != len(result.Relationships) || len(result.Relationships) == 0 {
		t.Fatalf("expected runtime-backed counts and graph relationships: summary=%+v relationships=%+v", result.Summary, result.Relationships)
	}
	if result.Summary.RemediationPreviewCount == 0 || len(result.Caveats) == 0 || len(result.CoverageGaps) == 0 {
		t.Fatalf("expected remediation previews, caveats, and coverage gaps: summary=%+v caveats=%v gaps=%v", result.Summary, result.Caveats, result.CoverageGaps)
	}
	for i := 1; i < len(result.Findings); i++ {
		if result.Findings[i-1].Score < result.Findings[i].Score {
			t.Fatalf("findings are not ranked by descending score: %+v", result.Findings)
		}
	}
	for _, finding := range result.Findings {
		if finding.FindingID == "" || finding.CalculationVersion != awsAIAgentRiskVersion {
			t.Fatalf("finding missing stable metadata: %+v", finding)
		}
		if finding.RiskType == "" || finding.Severity == "" || finding.Status == "" || finding.Rationale == "" {
			t.Fatalf("finding missing classification fields: %+v", finding)
		}
		if finding.Score <= 0 || finding.Confidence <= 0 || finding.AgentNodeID == "" || len(finding.ImpactedPath) < 2 || len(finding.Evidence) == 0 {
			t.Fatalf("finding missing score, confidence, path, or evidence: %+v", finding)
		}
		if finding.EvidenceBoundary != "metadata_only_no_secret_values_no_prompts_no_completions_no_tool_payloads" {
			t.Fatalf("finding crossed evidence boundary: %+v", finding)
		}
		if strings.Contains(strings.ToLower(finding.Rationale), "secret value") && !strings.Contains(strings.ToLower(finding.Rationale), "not collected") {
			t.Fatalf("rationale must not imply secret value collection: %s", finding.Rationale)
		}
		if finding.RemediationCase.CaseID == "" || !finding.RemediationCase.ReadOnlyProjection {
			t.Fatalf("finding missing read-only remediation preview: %+v", finding.RemediationCase)
		}
	}
}

func TestGetAWSAIAgentRiskFilters(t *testing.T) {
	now := time.Date(2026, 6, 23, 9, 5, 0, 0, time.UTC)
	svc, ws := newAIAgentRiskService(t, "project-ai-agent-risk-filters", now)

	external, err := svc.GetAWSAIAgentRisk(defaultScopeContext(), ws, "project-ai-agent-risk-filters", AWSAIAgentRiskRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
		RiskType:     "external_credential_exposure",
		Search:       "support",
	})
	if err != nil {
		t.Fatalf("risk/search filter: %v", err)
	}
	if len(external.Findings) == 0 {
		t.Fatalf("expected external credential exposure findings")
	}
	for _, finding := range external.Findings {
		if finding.RiskType != "external_credential_exposure" || !strings.Contains(strings.ToLower(finding.AgentName+" "+finding.Rationale), "support") {
			t.Fatalf("risk/search filter leaked: %+v", finding)
		}
	}
	if external.AppliedFilters["risk_type"] != "external-credential-exposure" || external.AppliedFilters["search"] != "support" {
		t.Fatalf("expected applied filters, got %+v", external.AppliedFilters)
	}

	runtimeBacked, err := svc.GetAWSAIAgentRisk(defaultScopeContext(), ws, "project-ai-agent-risk-filters", AWSAIAgentRiskRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
		Evidence:     "runtime-backed",
	})
	if err != nil {
		t.Fatalf("runtime evidence filter: %v", err)
	}
	if len(runtimeBacked.Findings) == 0 {
		t.Fatalf("expected runtime-backed agent risk findings")
	}
	for _, finding := range runtimeBacked.Findings {
		if !awsStringSliceContains(finding.SourceSignals, "agent_runtime_access") && !awsStringSliceContains(finding.SourceSignals, "least_privilege") {
			t.Fatalf("runtime-backed filter leaked: %+v", finding)
		}
	}
}

func TestAWSAIAgentRiskIdentifiesOwnerlessAgent(t *testing.T) {
	now := time.Date(2026, 6, 23, 9, 10, 0, 0, time.UTC)
	agent := awsAIAgentFixtureRecord("123456789012", "us-east-1", "custom_agent", "ownerless-agent", "agent-ownerless", "arn:aws:lambda:us-east-1:123456789012:function:ownerless-agent", "arn:aws:iam::123456789012:role/ownerless-agent", now, func(r *AWSAIAgentIdentityRecord) {
		r.Tags = map[string]string{}
	})

	findings := awsAIAgentRiskFindingsFromAgent(agent, now)
	hasOwnerless := false
	for _, finding := range findings {
		if finding.RiskType == "ownerless_agent" {
			hasOwnerless = true
			if finding.Status != "review" || finding.RemediationCase.CaseID == "" {
				t.Fatalf("ownerless finding missing review/remediation metadata: %+v", finding)
			}
		}
	}
	if !hasOwnerless {
		t.Fatalf("expected ownerless agent finding, got %+v", findings)
	}
}

func TestGetAWSAIAgentRiskFailureStates(t *testing.T) {
	now := time.Date(2026, 6, 23, 9, 15, 0, 0, time.UTC)
	svc, ws := newAIAgentRiskService(t, "project-ai-agent-risk-states", now)

	denied, err := svc.GetAWSAIAgentRisk(defaultScopeContext(), ws, "project-ai-agent-risk-states", AWSAIAgentRiskRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "permission_denied",
	})
	if err != nil {
		t.Fatalf("permission denied: %v", err)
	}
	if denied.Status != "blocked" || len(denied.Findings) != 0 || len(denied.Diagnostics) == 0 || len(denied.FailureReasons) == 0 {
		t.Fatalf("permission denied must be explicit and suppress deterministic findings: %+v", denied)
	}

	empty, err := svc.GetAWSAIAgentRisk(defaultScopeContext(), ws, "project-ai-agent-risk-states", AWSAIAgentRiskRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "empty",
	})
	if err != nil {
		t.Fatalf("empty: %v", err)
	}
	if empty.Status != "degraded" || len(empty.Findings) != 0 || empty.Summary.TotalFindings != 0 || len(empty.FailureReasons) == 0 {
		t.Fatalf("empty fixture should be explicit degraded no-evidence state: %+v", empty)
	}
}

func TestRouterAWSAIAgentRisk(t *testing.T) {
	now := time.Date(2026, 6, 23, 9, 20, 0, 0, time.UTC)
	svc, _ := newAIAgentRiskService(t, "project-ai-agent-risk-route", now)
	r := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{})

	resp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-ai-agent-risk-route/aws/ai-agent-risk?connector_id=aws-prod&fixture_state=success&risk_type=external_credential_exposure", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	var body struct {
		Findings AWSAIAgentRiskResult `json:"findings"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Findings.CurrentIssueRef != "#1528" || body.Findings.AppliedFilters["risk_type"] != "external-credential-exposure" || len(body.Findings.Findings) == 0 {
		t.Fatalf("unexpected route payload: %+v", body.Findings)
	}
}
