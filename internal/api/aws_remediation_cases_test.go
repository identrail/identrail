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

func newRemediationCaseService(t *testing.T, project string, now time.Time) (*Service, string) {
	t.Helper()
	return newBlastRadiusService(t, project, now)
}

func TestGetAWSRemediationCasesBuildsContract(t *testing.T) {
	now := time.Date(2026, 6, 23, 10, 0, 0, 0, time.UTC)
	svc, ws := newRemediationCaseService(t, "project-remediation-cases", now)

	result, err := svc.GetAWSRemediationCases(defaultScopeContext(), ws, "project-remediation-cases", AWSRemediationCaseRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
	})
	if err != nil {
		t.Fatalf("get remediation cases: %v", err)
	}
	if result.CurrentIssueRef != "#1529" || result.Version != awsRemediationCaseVersion || result.Status != "ready" {
		t.Fatalf("unexpected contract metadata: %+v", result)
	}
	if len(result.Cases) == 0 || result.Summary.TotalCases != len(result.Cases) {
		t.Fatalf("expected case summary to match payload: %+v", result.Summary)
	}
	if result.Summary.SourceTypeCounts["ai_agent_risk"] == 0 && result.Summary.SourceTypeCounts["least_privilege"] == 0 {
		t.Fatalf("expected at least one upstream source emitting cases: %+v", result.Summary.SourceTypeCounts)
	}
	if result.Summary.RelationshipCount != len(result.Relationships) || len(result.Relationships) == 0 {
		t.Fatalf("expected relationships and matching count: summary=%+v relationships=%+v", result.Summary, result.Relationships)
	}
	if len(result.Caveats) == 0 || len(result.CoverageGaps) == 0 {
		t.Fatalf("expected caveats and coverage gaps: %+v", result)
	}
	for i := 1; i < len(result.Cases); i++ {
		if result.Cases[i-1].Score < result.Cases[i].Score {
			t.Fatalf("cases are not ranked by descending score: %+v", result.Cases)
		}
	}
	for _, c := range result.Cases {
		if c.CaseID == "" || c.CalculationVersion != awsRemediationCaseVersion || c.SourceType == "" || c.SourceFindingID == "" {
			t.Fatalf("case missing stable metadata: %+v", c)
		}
		if c.Lifecycle == "" || c.Severity == "" || c.Status == "" || c.ApprovalState == "" || c.Title == "" {
			t.Fatalf("case missing classification fields: %+v", c)
		}
		if c.DiffIntent.Kind == "" || !c.DiffIntent.ReadOnlyProjection {
			t.Fatalf("case missing read-only diff intent: %+v", c.DiffIntent)
		}
		if len(c.RollbackPlan.Steps) == 0 || c.RollbackPlan.Strategy == "" {
			t.Fatalf("case missing rollback plan: %+v", c.RollbackPlan)
		}
		if len(c.VerificationPlan.Steps) == 0 || c.VerificationPlan.Strategy == "" {
			t.Fatalf("case missing verification plan: %+v", c.VerificationPlan)
		}
		if c.EvidenceBoundary != awsRemediationCaseEvidenceBoundary() {
			t.Fatalf("case crossed evidence boundary: %+v", c)
		}
		if len(c.AuditTrail) == 0 || c.AuditTrail[0].EventType != "proposed" {
			t.Fatalf("case missing proposed audit entry: %+v", c.AuditTrail)
		}
		if strings.Contains(strings.ToLower(c.Summary), "secret value") && !strings.Contains(strings.ToLower(c.Summary), "not collected") {
			t.Fatalf("summary must not imply secret value collection: %s", c.Summary)
		}
	}
}

func TestGetAWSRemediationCasesAppliesFilters(t *testing.T) {
	now := time.Date(2026, 6, 23, 10, 5, 0, 0, time.UTC)
	svc, ws := newRemediationCaseService(t, "project-remediation-case-filters", now)

	leastOnly, err := svc.GetAWSRemediationCases(defaultScopeContext(), ws, "project-remediation-case-filters", AWSRemediationCaseRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
		SourceType:   "least_privilege",
	})
	if err != nil {
		t.Fatalf("source filter: %v", err)
	}
	if len(leastOnly.Cases) == 0 {
		t.Fatalf("expected least-privilege cases in the success fixture")
	}
	for _, c := range leastOnly.Cases {
		if c.SourceType != "least_privilege" {
			t.Fatalf("source filter leaked %s case: %+v", c.SourceType, c)
		}
	}
	if leastOnly.AppliedFilters["source_type"] != "least-privilege" {
		t.Fatalf("expected applied source_type filter, got %+v", leastOnly.AppliedFilters)
	}

	highOnly, err := svc.GetAWSRemediationCases(defaultScopeContext(), ws, "project-remediation-case-filters", AWSRemediationCaseRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
		Severity:     "high",
	})
	if err != nil {
		t.Fatalf("severity filter: %v", err)
	}
	for _, c := range highOnly.Cases {
		if c.Severity != "high" {
			t.Fatalf("severity filter leaked %s case: %+v", c.Severity, c)
		}
	}

	owned, err := svc.GetAWSRemediationCases(defaultScopeContext(), ws, "project-remediation-case-filters", AWSRemediationCaseRequest{
		ConnectorID:   "aws-prod",
		FixtureState:  "success",
		OwnerAssigned: "true",
	})
	if err != nil {
		t.Fatalf("owner filter: %v", err)
	}
	for _, c := range owned.Cases {
		if !c.OwnerAssigned {
			t.Fatalf("owner filter leaked ownerless case: %+v", c)
		}
	}

	search, err := svc.GetAWSRemediationCases(defaultScopeContext(), ws, "project-remediation-case-filters", AWSRemediationCaseRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
		Search:       "rotation",
	})
	if err != nil {
		t.Fatalf("search filter: %v", err)
	}
	if len(search.Cases) == 0 {
		t.Fatalf("expected rotation cases in the success fixture")
	}
}

func TestAWSRemediationCaseDerivesLifecycleAndApproval(t *testing.T) {
	now := time.Date(2026, 6, 23, 10, 10, 0, 0, time.UTC)
	ownerless := AWSAIAgentRiskFinding{
		FindingID:        "aws-ai-agent-risk:ownerless-test",
		RiskType:         "ownerless_agent",
		Severity:         "high",
		Status:           "action_required",
		Score:            72,
		Confidence:       0.82,
		AccountID:        "123456789012",
		Region:           "us-east-1",
		AgentNodeID:      "aws:agent:123456789012:us-east-1:custom_agent/lonely-agent",
		AgentID:          "lonely-agent",
		AgentName:        "lonely-agent",
		AgentType:        "custom_agent",
		SourceSignals:    []string{"ai_agent_identities"},
		Rationale:        "lonely-agent has no owner tag.",
		EvidenceBoundary: awsAIAgentRiskEvidenceBoundary(),
		ImpactedNodes:    []string{"aws:agent:123456789012:us-east-1:custom_agent/lonely-agent"},
	}
	ownerCase, ok := awsRemediationCaseFromAIAgentRisk(ownerless, now)
	if !ok {
		t.Fatalf("expected ownerless agent to produce a case")
	}
	if ownerCase.OwnerAssigned {
		t.Fatalf("ownerless agent must not be owner-assigned")
	}
	if ownerCase.ApprovalState != "pending_owner" {
		t.Fatalf("ownerless high-severity case must wait on owner approval: %s", ownerCase.ApprovalState)
	}
	if ownerCase.Lifecycle != "in_review" {
		t.Fatalf("expected in_review lifecycle when owner is missing, got %s", ownerCase.Lifecycle)
	}
	if ownerCase.DiffIntent.Kind != "owner_assignment" {
		t.Fatalf("ownerless agent should propose owner_assignment diff, got %s", ownerCase.DiffIntent.Kind)
	}
	if !ownerCase.DiffIntent.NoOp {
		t.Fatalf("owner assignment diff should be a no-op AWS change: %+v", ownerCase.DiffIntent)
	}

	rotation := AWSAIAgentRiskFinding{
		FindingID:        "aws-ai-agent-risk:rotation-test",
		RiskType:         "external_credential_exposure",
		Severity:         "critical",
		Status:           "action_required",
		Score:            92,
		Confidence:       0.9,
		AccountID:        "123456789012",
		Region:           "us-east-1",
		AgentNodeID:      "aws:agent:123456789012:us-east-1:custom_agent/billing-agent",
		AgentID:          "billing-agent",
		AgentName:        "billing-agent",
		AgentType:        "custom_agent",
		Provider:         "openai",
		SourceSignals:    []string{"ai_agent_identities"},
		Rationale:        "billing-agent references an openai key.",
		EvidenceBoundary: awsAIAgentRiskEvidenceBoundary(),
	}
	rotationCase, ok := awsRemediationCaseFromAIAgentRisk(rotation, now)
	if !ok {
		t.Fatalf("expected rotation case")
	}
	if !rotationCase.ApprovalRequired {
		t.Fatalf("critical secret rotation must require approval: %+v", rotationCase)
	}
	if rotationCase.ApprovalState != "pending_approver" {
		t.Fatalf("owner-assigned critical case must enter pending_approver state, got %s", rotationCase.ApprovalState)
	}
	if rotationCase.Lifecycle != "approved" {
		t.Fatalf("owner-assigned critical action_required case should reach approved lifecycle, got %s", rotationCase.Lifecycle)
	}
	if rotationCase.DiffIntent.Kind != "secret_rotation" {
		t.Fatalf("rotation case should propose secret_rotation diff, got %s", rotationCase.DiffIntent.Kind)
	}
	if rotationCase.RollbackPlan.Strategy != "re_create_secret_reference" {
		t.Fatalf("secret_rotation must use re_create_secret_reference rollback, got %s", rotationCase.RollbackPlan.Strategy)
	}
	if rotationCase.VerificationPlan.Strategy != "secret_access_re_evaluate" {
		t.Fatalf("rotation must use secret_access_re_evaluate verification, got %s", rotationCase.VerificationPlan.Strategy)
	}

	lowConfidence := rotation
	lowConfidence.FindingID = "aws-ai-agent-risk:low-confidence"
	lowConfidence.Confidence = 0.4
	lowCase, ok := awsRemediationCaseFromAIAgentRisk(lowConfidence, now)
	if !ok {
		t.Fatalf("expected low-confidence case")
	}
	if lowCase.Lifecycle != "proposed" {
		t.Fatalf("low-confidence cases must stay proposed, got %s", lowCase.Lifecycle)
	}
}

func TestAWSRemediationCaseDedupesAcrossSources(t *testing.T) {
	now := time.Date(2026, 6, 23, 10, 15, 0, 0, time.UTC)
	base := AWSRemediationCase{
		CaseID:             "aws-remediation-case:duplicate-key",
		CalculationVersion: awsRemediationCaseVersion,
		SourceType:         "ai_agent_risk",
		Score:              70,
		Severity:           "high",
		Lifecycle:          "in_review",
		ApprovalState:      "pending_owner",
		DiffIntent:         AWSRemediationDiffIntent{Kind: "ai_agent_scope_change", ReadOnlyProjection: true},
		SourceSignals:      []string{"ai_agent_identities"},
		Evidence:           []AWSRemediationCaseEvidence{{Source: "ai_agent_identities", EvidenceRef: "evidence://agent/a"}},
		ImpactedNodes:      []string{"aws:agent:1", "aws:identity:role:a"},
		ResourceNodeIDs:    []string{"aws:agent:1"},
		AuditTrail:         []AWSRemediationAuditEntry{{EventID: "1", Actor: "system", EventType: "proposed", OccurredAt: now}},
		CreatedAt:          now,
		UpdatedAt:          now,
	}
	incoming := base
	incoming.SourceType = "least_privilege"
	incoming.Score = 88
	incoming.Severity = "critical"
	incoming.Lifecycle = "approved"
	incoming.DiffIntent = AWSRemediationDiffIntent{Kind: "iam_policy_diff", ReadOnlyProjection: true}
	incoming.SourceSignals = []string{"least_privilege"}
	incoming.Evidence = []AWSRemediationCaseEvidence{{Source: "least_privilege", EvidenceRef: "evidence://least/a"}}
	incoming.AuditTrail = []AWSRemediationAuditEntry{{EventID: "2", Actor: "system", EventType: "proposed", OccurredAt: now}}

	deduped := awsRemediationCaseDedupe([]AWSRemediationCase{base, incoming})
	if len(deduped) != 1 {
		t.Fatalf("expected dedupe to keep one case, got %d", len(deduped))
	}
	merged := deduped[0]
	if merged.Score != 88 || merged.Severity != "critical" || merged.Lifecycle != "approved" || merged.DiffIntent.Kind != "iam_policy_diff" {
		t.Fatalf("higher-score case must win the merge, got %+v", merged)
	}
	if !awsStringSliceContains(merged.SourceSignals, "ai_agent_identities") || !awsStringSliceContains(merged.SourceSignals, "least_privilege") {
		t.Fatalf("merged signals must include both sources: %+v", merged.SourceSignals)
	}
	if len(merged.Evidence) != 2 || len(merged.AuditTrail) != 2 {
		t.Fatalf("merged evidence and audit trail must compose both sources, got evidence=%d audit=%d", len(merged.Evidence), len(merged.AuditTrail))
	}
}

func TestGetAWSRemediationCasesFailureStates(t *testing.T) {
	now := time.Date(2026, 6, 23, 10, 20, 0, 0, time.UTC)
	svc, ws := newRemediationCaseService(t, "project-remediation-case-states", now)

	denied, err := svc.GetAWSRemediationCases(defaultScopeContext(), ws, "project-remediation-case-states", AWSRemediationCaseRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "permission_denied",
	})
	if err != nil {
		t.Fatalf("permission denied: %v", err)
	}
	if denied.Status != "blocked" || len(denied.Cases) != 0 || len(denied.Diagnostics) == 0 || len(denied.FailureReasons) == 0 {
		t.Fatalf("permission denied must be explicit and suppress deterministic cases: %+v", denied)
	}

	empty, err := svc.GetAWSRemediationCases(defaultScopeContext(), ws, "project-remediation-case-states", AWSRemediationCaseRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "empty",
	})
	if err != nil {
		t.Fatalf("empty: %v", err)
	}
	if empty.Status != "degraded" || empty.Summary.TotalCases != 0 || len(empty.FailureReasons) == 0 {
		t.Fatalf("empty fixture should be explicit degraded no-evidence state: %+v", empty)
	}

	if _, err := svc.GetAWSRemediationCases(defaultScopeContext(), ws, "project-remediation-case-states", AWSRemediationCaseRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "garbage",
	}); err == nil {
		t.Fatalf("invalid fixture state should fail validation")
	}
}

func TestRouterAWSRemediationCases(t *testing.T) {
	now := time.Date(2026, 6, 23, 10, 25, 0, 0, time.UTC)
	svc, _ := newRemediationCaseService(t, "project-remediation-case-route", now)
	r := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{})

	resp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-remediation-case-route/aws/remediation-cases?connector_id=aws-prod&fixture_state=success&source_type=ai_agent_risk", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	var body struct {
		Cases AWSRemediationCaseResult `json:"cases"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Cases.CurrentIssueRef != "#1529" || body.Cases.AppliedFilters["source_type"] != "ai-agent-risk" {
		t.Fatalf("unexpected route payload: %+v", body.Cases)
	}
	if len(body.Cases.Cases) == 0 {
		t.Fatalf("expected ai_agent_risk-sourced cases via the route: %+v", body.Cases)
	}
}
