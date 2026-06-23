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

func TestAWSAIAgentRiskFansOutBackingRoleScopeForSharedRoleAgents(t *testing.T) {
	now := time.Date(2026, 6, 23, 9, 12, 0, 0, time.UTC)
	roleARN := "arn:aws:iam::123456789012:role/shared-agent-runtime"
	agentA := awsAIAgentFixtureRecord("123456789012", "us-east-1", "custom_agent", "support-agent", "support-agent", "arn:aws:lambda:us-east-1:123456789012:function:support-agent", roleARN, now, nil)
	agentB := awsAIAgentFixtureRecord("123456789012", "us-east-1", "custom_agent", "billing-agent", "billing-agent", "arn:aws:lambda:us-east-1:123456789012:function:billing-agent", roleARN, now, nil)
	recommendation := AWSLeastPrivilegeRecommendation{
		RecommendationID:   "aws-least-privilege:shared-runtime-role",
		CalculationVersion: awsLeastPrivilegeVersion,
		RecommendationType: "static_grant_unused",
		Decision:           "review",
		Severity:           "high",
		Status:             "review",
		Score:              78,
		Confidence:         0.88,
		AccountID:          "123456789012",
		Region:             "us-east-1",
		Service:            "secretsmanager",
		IdentityNodeID:     awsIdentityNodeIDForAPI(roleARN),
		ResourceNodeID:     "aws:resource:secrets-manager-secret/shared-provider-key",
		ResourceARN:        "arn:aws:secretsmanager:us-east-1:123456789012:secret:shared-provider-key",
		DisplayName:        "shared-provider-key",
		Rationale:          "Shared runtime role can read a provider key.",
		ImpactedNodes:      []string{awsIdentityNodeIDForAPI(roleARN), "aws:resource:secrets-manager-secret/shared-provider-key"},
		ImpactedPath: []AWSLeastPrivilegePathStep{
			awsLeastPrivilegePathStep(awsIdentityNodeIDForAPI(roleARN), "identity", "shared-agent-runtime", "123456789012", "us-east-1"),
			awsLeastPrivilegePathStep("aws:resource:secrets-manager-secret/shared-provider-key", "secret", "shared-provider-key", "123456789012", "us-east-1"),
		},
		Evidence: []AWSLeastPrivilegeEvidence{{
			Source:      "least_privilege",
			EvidenceRef: "evidence://least-privilege/shared-runtime-role",
			Label:       "Least-privilege role-scope decision",
			Confidence:  0.88,
			ObservedAt:  now,
		}},
		NextAction: "Review the shared role before removing access.",
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	findings := awsAIAgentRiskFindings(awsAIAgentRiskSources{
		agents: AWSAIAgentIdentityInventoryResult{Records: []AWSAIAgentIdentityRecord{agentA, agentB}},
		least:  AWSLeastPrivilegeResult{Recommendations: []AWSLeastPrivilegeRecommendation{recommendation}},
	}, now)

	backingRoleScopeByAgent := map[string]bool{}
	for _, finding := range findings {
		if finding.RiskType == "backing_role_scope" {
			backingRoleScopeByAgent[finding.AgentID] = true
		}
	}
	if !backingRoleScopeByAgent["support-agent"] || !backingRoleScopeByAgent["billing-agent"] {
		t.Fatalf("expected backing role scope finding for each shared-role agent, got %+v", backingRoleScopeByAgent)
	}
}

func TestAWSAIAgentRiskDedupesExternalCredentialExposureAcrossSources(t *testing.T) {
	now := time.Date(2026, 6, 23, 9, 13, 0, 0, time.UTC)
	agent := awsAIAgentFixtureRecord(
		"123456789012",
		"us-east-1",
		"custom_agent",
		"support-agent",
		"support-agent",
		"arn:aws:ecs:us-east-1:123456789012:service/prod/support-agent",
		"arn:aws:iam::123456789012:role/support-agent",
		now,
		func(r *AWSAIAgentIdentityRecord) {
			r.CredentialReferenceRefs = []string{"OPENAI_API_KEY=secretsmanager:prod/support/openai-key"}
		},
	)
	if len(agent.ProviderKeyReferences) == 0 {
		t.Fatalf("fixture should derive ProviderKeyReferences from CredentialReferenceRefs: %+v", agent)
	}
	ref := agent.ProviderKeyReferences[0]
	providerFinding := AWSSecretPermissionEquivalenceFinding{
		FindingID:             "aws-secret-permission-equivalence:agent-provider-key-support-agent-openai",
		CalculationVersion:    awsSecretPermissionEquivalenceVersion,
		EquivalenceType:       "agent_provider_key_equivalence",
		Severity:              "high",
		Status:                "review",
		Score:                 84,
		Confidence:            0.94,
		AccountID:             "123456789012",
		Region:                "us-east-1",
		IdentityNodeID:        agent.RuntimeRoleNodeID,
		PrincipalARN:          agent.RuntimeRoleARN,
		AgentID:               agent.AgentID,
		AgentName:             agent.AgentName,
		SecretNodeID:          ref.TargetNodeID,
		SecretLabel:           ref.ReferenceName,
		Provider:              ref.Provider,
		ProviderKeyReference:  ref.ReferenceName,
		EquivalentPermissions: []string{"read"},
		SourceSignals:         []string{"secret_permission_equivalence"},
		Rationale:             "Agent has a provider key reference that can authorize OpenAI API access.",
		EvidenceBoundary:      awsSecretPermissionEvidenceBoundary(),
		ImpactedNodes:         []string{agent.RuntimeRoleNodeID, agent.AgentNodeID, ref.TargetNodeID},
		ImpactedPath: []AWSAIAgentRiskPathStep{
			awsLeastPrivilegePathStep(agent.RuntimeRoleNodeID, "identity", "support-agent-role", agent.AccountID, agent.Region),
			awsLeastPrivilegePathStep(agent.AgentNodeID, "ai_agent", "support-agent", agent.AccountID, agent.Region),
			awsLeastPrivilegePathStep(ref.TargetNodeID, "permission_bearing_secret", ref.ReferenceName, agent.AccountID, agent.Region),
		},
		Evidence:   []AWSSecretPermissionEquivalenceEvidence{{Source: "secret_permission_equivalence", EvidenceRef: "evidence://agent/support-agent/provider-key"}},
		NextAction: "Rotate or scope the provider key reference and role path.",
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	findings := awsAIAgentRiskFindings(awsAIAgentRiskSources{
		agents:      AWSAIAgentIdentityInventoryResult{Records: []AWSAIAgentIdentityRecord{agent}},
		equivalence: AWSSecretPermissionEquivalenceResult{Findings: []AWSSecretPermissionEquivalenceFinding{providerFinding}},
	}, now)

	externalCredentialFindings := []AWSAIAgentRiskFinding{}
	for _, finding := range findings {
		if finding.RiskType == "external_credential_exposure" {
			externalCredentialFindings = append(externalCredentialFindings, finding)
		}
	}
	if len(externalCredentialFindings) != 1 {
		t.Fatalf("expected one deduplicated external credential finding, got %d: %+v", len(externalCredentialFindings), externalCredentialFindings)
	}
	finding := externalCredentialFindings[0]
	if !awsStringSliceContains(finding.SourceSignals, "ai_agent_identities") {
		t.Fatalf("expected identity signal merged into external credential finding: %+v", finding.SourceSignals)
	}
	if !awsStringSliceContains(finding.SourceSignals, "secret_permission_equivalence") {
		t.Fatalf("expected secret-permission signal merged into external credential finding: %+v", finding.SourceSignals)
	}
	if len(finding.Evidence) < 2 {
		t.Fatalf("expected merged evidence from both sources, got %d: %+v", len(finding.Evidence), finding.Evidence)
	}
}

func TestAWSAIAgentRiskRuntimeFindingIncludesDeclaredBackingRole(t *testing.T) {
	now := time.Date(2026, 6, 23, 9, 16, 0, 0, time.UTC)
	record := AWSAgentRuntimeAccessRecord{
		CorrelationID:           "agent-declared-unused",
		AccountID:               "123456789012",
		Region:                  "us-east-1",
		AgentNodeID:             "aws:agent:123456789012:us-east-1:custom_agent/billing-agent",
		AgentName:               "billing-agent",
		AgentID:                 "billing-agent",
		ToolName:                "issue-refund",
		Status:                  "declared_unused",
		Confidence:              0.84,
		DeclaredBackingRoleNode: "aws:identity:role:declared-billing-agent",
		EvidenceRef:             "agent-evidence://billing-agent/declared-unused",
	}
	finding, ok := awsAIAgentRiskFindingFromRuntime(record, now)
	if !ok {
		t.Fatalf("expected runtime finding to be emitted for declared_unused status")
	}
	if !awsStringSliceContains(finding.ImpactedNodes, record.DeclaredBackingRoleNode) {
		t.Fatalf("declared backing role must appear in impacted nodes for graph edges: %+v", finding.ImpactedNodes)
	}
	var sawBackingRoleStep bool
	for _, step := range finding.ImpactedPath {
		if step.NodeType == "backing_role" && step.NodeID == record.DeclaredBackingRoleNode {
			sawBackingRoleStep = true
		}
	}
	if !sawBackingRoleStep {
		t.Fatalf("declared backing role must appear as a path step: %+v", finding.ImpactedPath)
	}
}

func TestAWSAIAgentRiskRuntimeFindingIncludesLineageOnlyCaveat(t *testing.T) {
	now := time.Date(2026, 6, 23, 9, 17, 0, 0, time.UTC)
	record := AWSAgentRuntimeAccessRecord{
		CorrelationID:         "agent-lineage-unresolved",
		AccountID:             "123456789012",
		Region:                "us-east-1",
		AgentNodeID:           "aws:agent:123456789012:us-east-1:custom_agent/support-agent",
		AgentName:             "support-agent",
		AgentID:               "support-agent",
		ToolName:              "lookup-case",
		Status:                "confirmed",
		Caveats:               []string{"session_lineage_unresolved"},
		Confidence:            0.82,
		TargetResourceNodeIDs: []string{"aws:resource:dynamodb-table/cases"},
		EvidenceRef:           "agent-evidence://support-agent/lineage-unresolved",
	}
	finding, ok := awsAIAgentRiskFindingFromRuntime(record, now)
	if !ok {
		t.Fatalf("expected confirmed runtime record with lineage caveat to emit a finding")
	}
	if finding.RiskType != "runtime_tool_anomaly" {
		t.Fatalf("expected lineage-only caveat to use runtime_tool_anomaly, got %q", finding.RiskType)
	}
}

func TestAWSAIAgentRiskRuntimeSecretEquivalenceRequiresAgentNode(t *testing.T) {
	now := time.Date(2026, 6, 23, 9, 14, 0, 0, time.UTC)
	agent := awsAIAgentFixtureRecord(
		"123456789012",
		"us-east-1",
		"custom_agent",
		"case-triage",
		"case-triage",
		"arn:aws:lambda:us-east-1:123456789012:function:case-triage",
		"arn:aws:iam::123456789012:role/case-triage",
		now,
		nil,
	)
	runtimeFinding := AWSSecretPermissionEquivalenceFinding{
		FindingID:          "aws-secret-permission-equivalence:runtime-case-triage-openai",
		CalculationVersion: awsSecretPermissionEquivalenceVersion,
		EquivalenceType:    "runtime_secret_access_equivalence",
		Severity:           "high",
		Status:             "review",
		Score:              78,
		Confidence:         0.88,
		AccountID:          "123456789012",
		Region:             "us-east-1",
		IdentityNodeID:     agent.RuntimeRoleNodeID,
		PrincipalARN:       agent.RuntimeRoleARN,
		AgentID:            agent.AgentID,
		SecretNodeID:       "aws:resource:secrets-manager-secret/case-triage-openai",
		SecretARN:          "arn:aws:secretsmanager:us-east-1:123456789012:secret:case-triage-openai",
		SecretLabel:        "case-triage-openai",
		Provider:           "openai",
		SourceSignals:      []string{"secrets_kms_runtime_access"},
		EvidenceBoundary:   awsSecretPermissionEvidenceBoundary(),
		ImpactedPath: []AWSSecretPermissionEquivalencePathStep{
			awsLeastPrivilegePathStep(agent.RuntimeRoleNodeID, "identity", "case-triage-role", agent.AccountID, agent.Region),
			awsLeastPrivilegePathStep("aws:resource:secrets-manager-secret/case-triage-openai", "permission_bearing_secret", "case-triage-openai", agent.AccountID, agent.Region),
		},
		CreatedAt: now,
		UpdatedAt: now,
	}

	resolved := awsAIAgentRiskFindings(awsAIAgentRiskSources{
		agents:      AWSAIAgentIdentityInventoryResult{Records: []AWSAIAgentIdentityRecord{agent}},
		equivalence: AWSSecretPermissionEquivalenceResult{Findings: []AWSSecretPermissionEquivalenceFinding{runtimeFinding}},
	}, now)
	var derived *AWSAIAgentRiskFinding
	for i, finding := range resolved {
		if finding.RiskType == "external_credential_exposure" {
			derived = &resolved[i]
		}
	}
	if derived == nil {
		t.Fatalf("expected external credential finding when agent inventory resolves the runtime AgentID, got %+v", resolved)
	}
	if derived.AgentNodeID != agent.AgentNodeID {
		t.Fatalf("expected AgentNodeID to be the inventory graph node %q, got %q", agent.AgentNodeID, derived.AgentNodeID)
	}
	if derived.AgentNodeID == runtimeFinding.AgentID {
		t.Fatalf("AgentNodeID must not be the raw runtime AgentID string %q", runtimeFinding.AgentID)
	}
	if len(derived.ImpactedPath) == 0 || derived.ImpactedPath[0].NodeType != "ai_agent" || derived.ImpactedPath[0].NodeID != agent.AgentNodeID {
		t.Fatalf("expected resolved AI agent to prefix impacted path, got %+v", derived.ImpactedPath)
	}

	orphaned := awsAIAgentRiskFindings(awsAIAgentRiskSources{
		equivalence: AWSSecretPermissionEquivalenceResult{Findings: []AWSSecretPermissionEquivalenceFinding{runtimeFinding}},
	}, now)
	for _, finding := range orphaned {
		if finding.RiskType == "external_credential_exposure" {
			t.Fatalf("expected runtime secret-equivalence without an ai_agent path or inventory match to be suppressed, got %+v", finding)
		}
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
