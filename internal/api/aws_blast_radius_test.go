package api

import (
	"strings"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/domain"
	"github.com/identrail/identrail/internal/runtime/agentaccess"
)

func newBlastRadiusService(t *testing.T, project string, now time.Time) (*Service, string) {
	t.Helper()
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	seedDefaultProject(t, store, ctx, project)
	seedAWSConnectorForScanTest(t, store, ctx, project, "aws-prod", domain.ConnectorStatusActive, "healthy", now)
	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	return svc, "default"
}

func TestGetAWSBlastRadiusBuildsRankedIntelligenceContract(t *testing.T) {
	now := time.Date(2026, 6, 19, 20, 0, 0, 0, time.UTC)
	svc, ws := newBlastRadiusService(t, "project-blast-radius", now)

	result, err := svc.GetAWSBlastRadius(defaultScopeContext(), ws, "project-blast-radius", AWSBlastRadiusRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
	})
	if err != nil {
		t.Fatalf("get blast radius: %v", err)
	}
	if result.CurrentIssueRef != "#1521" || result.Version != awsBlastRadiusVersion || result.Status != "ready" {
		t.Fatalf("unexpected contract metadata: %+v", result)
	}
	if len(result.Findings) == 0 || result.Summary.TotalFindings != len(result.Findings) {
		t.Fatalf("expected findings summary to match payload: %+v", result.Summary)
	}
	if result.Findings[0].Score < result.Findings[len(result.Findings)-1].Score {
		t.Fatalf("findings are not ranked by descending score: %+v", result.Findings)
	}
	if result.Summary.RelationshipCount != len(result.Relationships) || len(result.Relationships) == 0 {
		t.Fatalf("expected graph relationships: %+v", result.Relationships)
	}
	if result.Summary.RemediationPreviewCount == 0 {
		t.Fatalf("expected remediation previews: %+v", result.Summary)
	}
	for _, finding := range result.Findings {
		if finding.FindingID == "" || finding.CalculationVersion != awsBlastRadiusVersion || finding.Rationale == "" {
			t.Fatalf("finding missing stable metadata: %+v", finding)
		}
		if finding.Score <= 0 || finding.Confidence <= 0 || len(finding.ImpactedPath) < 2 || len(finding.Evidence) == 0 {
			t.Fatalf("finding missing score/path/evidence: %+v", finding)
		}
		if finding.RemediationCase.CaseID == "" || !finding.RemediationCase.ReadOnlyProjection {
			t.Fatalf("finding missing read-only remediation preview: %+v", finding.RemediationCase)
		}
	}
}

func TestGetAWSBlastRadiusFiltersBySeverityStatusRiskAndIdentity(t *testing.T) {
	now := time.Date(2026, 6, 19, 20, 5, 0, 0, time.UTC)
	svc, ws := newBlastRadiusService(t, "project-blast-radius-filters", now)

	critical, err := svc.GetAWSBlastRadius(defaultScopeContext(), ws, "project-blast-radius-filters", AWSBlastRadiusRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
		Severity:     "critical",
	})
	if err != nil {
		t.Fatalf("critical filter: %v", err)
	}
	if len(critical.Findings) == 0 {
		t.Fatalf("expected critical findings")
	}
	for _, finding := range critical.Findings {
		if finding.Severity != "critical" {
			t.Fatalf("severity filter leaked %+v", finding)
		}
	}
	if critical.AppliedFilters["severity"] != "critical" {
		t.Fatalf("expected severity applied filter, got %+v", critical.AppliedFilters)
	}

	agent, err := svc.GetAWSBlastRadius(defaultScopeContext(), ws, "project-blast-radius-filters", AWSBlastRadiusRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
		RiskType:     "undeclared-agent-tool-path",
		Status:       "action_required",
	})
	if err != nil {
		t.Fatalf("agent filter: %v", err)
	}
	if len(agent.Findings) == 0 {
		all, allErr := svc.GetAWSBlastRadius(defaultScopeContext(), ws, "project-blast-radius-filters", AWSBlastRadiusRequest{ConnectorID: "aws-prod", FixtureState: "success"})
		if allErr != nil {
			t.Fatalf("expected undeclared agent tool finding; also failed to load unfiltered result: %v", allErr)
		}
		t.Fatalf("expected undeclared agent tool finding; risk counts=%+v status counts=%+v", all.Summary.RiskTypeCounts, all.Summary.StatusCounts)
	}
	for _, finding := range agent.Findings {
		if finding.RiskType != "undeclared-agent-tool-path" || finding.Status != "action_required" {
			t.Fatalf("risk/status filter leaked %+v", finding)
		}
	}

	identity, err := svc.GetAWSBlastRadius(defaultScopeContext(), ws, "project-blast-radius-filters", AWSBlastRadiusRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
		Identity:     "case-triage-runtime",
	})
	if err != nil {
		t.Fatalf("identity filter: %v", err)
	}
	if len(identity.Findings) == 0 {
		t.Fatalf("expected identity-matched findings")
	}
	for _, finding := range identity.Findings {
		if !awsRuntimeEventMatchesAny("case-triage-runtime", finding.IdentityNodeID, finding.PrincipalARN, finding.DisplayName) {
			t.Fatalf("identity filter leaked %+v", finding)
		}
	}
}

func TestFilterAWSBlastRadiusFindingsMatchesResourcePathLabels(t *testing.T) {
	findings := []AWSBlastRadiusFinding{
		{
			FindingID:      "finding-1",
			Severity:       "high",
			Status:         "action_required",
			RiskType:       "sensitive_resource",
			AccountID:      "111111111111",
			Region:         "us-east-1",
			IdentityNodeID: "iam-role/case-triage-runtime",
			PrincipalARN:   "arn:aws:iam::111111111111:role/case-triage-runtime",
			DisplayName:    "case-triage-runtime",
			ImpactedNodes:  []string{"aws:identity:iam:case-triage-runtime"},
			SensitiveNodes: []string{"aws:resource:secret:legacy-database"},
			ImpactedPath: []AWSBlastRadiusPathStep{
				{
					NodeID:   "aws:identity:iam:case-triage-runtime",
					NodeType: "identity",
					Label:    "case-triage-runtime",
				},
				{
					NodeID:   "aws:resource:secret:legacy-database",
					NodeType: "secret",
					Label:    "legacy-database-secret",
				},
			},
		},
		{
			FindingID:      "finding-2",
			Severity:       "medium",
			Status:         "action_required",
			RiskType:       "agent_tool_target",
			AccountID:      "222222222222",
			Region:         "us-west-2",
			IdentityNodeID: "iam-role/agent-worker",
			PrincipalARN:   "arn:aws:iam::222222222222:role/agent-worker",
			DisplayName:    "agent-worker",
			ImpactedNodes:  []string{"aws:identity:iam:agent-worker"},
			ImpactedPath: []AWSBlastRadiusPathStep{
				{
					NodeID:   "aws:identity:iam:agent-worker",
					NodeType: "identity",
					Label:    "agent-worker",
				},
				{
					NodeID:   "aws:resource:s3:payments-bucket",
					NodeType: "s3_bucket",
					Label:    "arn:aws:s3:::payments-bucket",
				},
			},
		},
	}

	filtered, _ := filterAWSBlastRadiusFindings(findings, AWSBlastRadiusRequest{Resource: "legacy-database-secret"})
	if len(filtered) != 1 || filtered[0].FindingID != "finding-1" {
		t.Fatalf("expected resource label filtering to match path labels, got %+v", filtered)
	}

	filtered, _ = filterAWSBlastRadiusFindings(findings, AWSBlastRadiusRequest{Resource: "arn:aws:s3:::payments-bucket"})
	if len(filtered) != 1 || filtered[0].FindingID != "finding-2" {
		t.Fatalf("expected resource ARN filtering to match path labels, got %+v", filtered)
	}
}

func TestAWSBlastRadiusFindingFromAgentUsesBackingRoleMismatchCaveatToken(t *testing.T) {
	record := AWSAgentRuntimeAccessRecord{
		CorrelationID:           "agent-1",
		AccountID:               "111111111111",
		Region:                  "us-east-1",
		AgentNodeID:             "aws:identity:agent:agent-a",
		AgentName:               "risk-agent",
		ToolName:                "query",
		Status:                  "confirmed",
		Confidence:              0.81,
		BackingRoleNodeIDs:      []string{"aws:identity:role:agent-role"},
		DeclaredBackingRoleNode: "aws:identity:role:declared",
		Caveats:                 []string{agentaccess.CaveatBackingRoleMismatch},
		EvidenceRef:             "agent-evidence://case-triage",
	}

	finding := awsBlastRadiusFindingFromAgent(record, time.Date(2026, 6, 19, 20, 30, 0, 0, time.UTC))
	if finding.Score != 72 {
		t.Fatalf("expected backing-role mismatch score bump to 72, got %d", finding.Score)
	}
}

func TestAWSBlastRadiusFindingFromAgentOmitsMissingTargetPathStep(t *testing.T) {
	record := AWSAgentRuntimeAccessRecord{
		CorrelationID:      "agent-2",
		AccountID:          "111111111111",
		Region:             "us-east-1",
		AgentNodeID:        "aws:identity:agent:agent-b",
		AgentName:          "background-agent",
		ToolName:           "ingest",
		Status:             "declared-unused",
		Confidence:         0.91,
		BackingRoleNodeIDs: []string{"aws:identity:role:declared"},
		EvidenceRef:        "agent-evidence://declared-unused",
	}

	finding := awsBlastRadiusFindingFromAgent(record, time.Date(2026, 6, 19, 20, 45, 0, 0, time.UTC))
	if len(finding.ImpactedPath) != 2 {
		t.Fatalf("expected identity-agent path only when target is missing, got %+v", finding.ImpactedPath)
	}
	for _, step := range finding.ImpactedPath {
		if step.NodeType == "target_resource" {
			t.Fatalf("expected no target_resource path when target is missing, got %+v", finding.ImpactedPath)
		}
	}
}

func TestAWSBlastRadiusFindingFromAgentPreservesAllBackingRolesAndTargets(t *testing.T) {
	record := AWSAgentRuntimeAccessRecord{
		CorrelationID:         "agent-3",
		AccountID:             "111111111111",
		Region:                "us-east-1",
		AgentNodeID:           "aws:identity:agent:agent-c",
		AgentName:             "search-agent",
		ToolName:              "scan",
		Status:                "confirmed",
		Confidence:            0.93,
		BackingRoleNodeIDs:    []string{"aws:identity:role:agent-role-b", "aws:identity:role:agent-role-a"},
		BackingRoleARNs:       []string{"arn:aws:iam::111111111111:role/agent-role-a", "arn:aws:iam::111111111111:role/agent-role-b"},
		TargetResourceNodeIDs: []string{"aws:resource:secret:api-key-a", "aws:resource:secret:api-key-b"},
		TargetResourceARNs:    []string{"arn:aws:secretsmanager:us-east-1:111111111111:secret:api-key-a", "arn:aws:secretsmanager:us-east-1:111111111111:secret:api-key-b"},
		EvidenceRef:           "agent-evidence://multi-role-target",
	}

	record.BackingRoleNodeIDs = dedupeStrings(record.BackingRoleNodeIDs)
	record.TargetResourceNodeIDs = dedupeStrings(record.TargetResourceNodeIDs)
	record.TargetResourceARNs = dedupeStrings(record.TargetResourceARNs)

	finding := awsBlastRadiusFindingFromAgent(record, time.Date(2026, 6, 19, 20, 50, 0, 0, time.UTC))

	expectedRoleNodes := map[string]bool{
		"aws:identity:role:agent-role-a": false,
		"aws:identity:role:agent-role-b": false,
	}
	expectedTargetNodes := map[string]bool{
		"aws:resource:secret:api-key-a":                                  false,
		"aws:resource:secret:api-key-b":                                  false,
		"arn:aws:secretsmanager:us-east-1:111111111111:secret:api-key-a": false,
		"arn:aws:secretsmanager:us-east-1:111111111111:secret:api-key-b": false,
	}
	foundImpactedNodes := map[string]bool{}
	for _, node := range finding.ImpactedNodes {
		foundImpactedNodes[node] = true
	}
	for node := range expectedRoleNodes {
		if !foundImpactedNodes[node] {
			t.Fatalf("missing backing role in impacted_nodes: %s", node)
		}
	}
	for node := range expectedTargetNodes {
		if !foundImpactedNodes[node] {
			t.Fatalf("missing target in impacted_nodes: %s", node)
		}
	}

	paths := finding.ImpactedPath
	hasEdge := func(fromNode, toNode string) bool {
		for i := 0; i+1 < len(paths); i++ {
			if strings.TrimSpace(paths[i].NodeID) == fromNode && strings.TrimSpace(paths[i+1].NodeID) == toNode {
				return true
			}
		}
		return false
	}
	for role := range expectedRoleNodes {
		if !hasEdge(role, record.AgentNodeID) {
			t.Fatalf("expected identity path edge for role %s to agent %s", role, record.AgentNodeID)
		}
	}
	for target := range expectedTargetNodes {
		if !hasEdge(record.AgentNodeID, target) {
			t.Fatalf("expected agent path edge for target %s", target)
		}
	}

	filtered, _ := filterAWSBlastRadiusFindings([]AWSBlastRadiusFinding{finding}, AWSBlastRadiusRequest{Identity: "agent-role-b"})
	if len(filtered) != 1 {
		t.Fatalf("expected second backing role to match identity filter, got %d findings", len(filtered))
	}
}

func TestGetAWSBlastRadiusPermissionDeniedAndEmptyStatesAreExplicit(t *testing.T) {
	now := time.Date(2026, 6, 19, 20, 10, 0, 0, time.UTC)
	svc, ws := newBlastRadiusService(t, "project-blast-radius-states", now)

	denied, err := svc.GetAWSBlastRadius(defaultScopeContext(), ws, "project-blast-radius-states", AWSBlastRadiusRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "permission_denied",
	})
	if err != nil {
		t.Fatalf("permission denied: %v", err)
	}
	if denied.Status != "blocked" || denied.Confidence != 0 || len(denied.Findings) != 0 {
		t.Fatalf("expected blocked permission-denied state, got %+v", denied)
	}
	if len(denied.Diagnostics) == 0 || len(denied.CoverageGaps) == 0 {
		t.Fatalf("expected diagnostics and coverage gaps for denied state")
	}

	empty, err := svc.GetAWSBlastRadius(defaultScopeContext(), ws, "project-blast-radius-states", AWSBlastRadiusRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "empty",
	})
	if err != nil {
		t.Fatalf("empty: %v", err)
	}
	if empty.Status != "degraded" || len(empty.Findings) != 0 || empty.Summary.TotalFindings != 0 {
		t.Fatalf("expected degraded empty state, got %+v", empty)
	}
}

func TestGetAWSBlastRadiusOmitsFixtureStateForLiveDefault(t *testing.T) {
	now := time.Date(2026, 6, 19, 20, 15, 0, 0, time.UTC)
	svc, ws := newBlastRadiusService(t, "project-blast-radius-live-default", now)

	result, err := svc.GetAWSBlastRadius(defaultScopeContext(), ws, "project-blast-radius-live-default", AWSBlastRadiusRequest{
		ConnectorID: "aws-prod",
	})
	if err != nil {
		t.Fatalf("live default: %v", err)
	}
	if result.FixtureState != "" {
		t.Fatalf("expected no fixture_state when caller did not request fixtures, got %q", result.FixtureState)
	}
	if result.Status != awsPlatformDependencyStatusDegraded {
		t.Fatalf("expected degraded live-unavailable state, got %q", result.Status)
	}
}

func TestNormalizeAWSBlastRadiusFixtureState(t *testing.T) {
	disconnected := AWSConnectionStatus{Connected: false}
	if got := normalizeAWSBlastRadiusFixtureState("", disconnected, true); got != "permission_denied" {
		t.Fatalf("expected denied for disconnected default, got %q", got)
	}
	if got := normalizeAWSBlastRadiusFixtureState("EMPTY", AWSConnectionStatus{}, false); got != "empty" {
		t.Fatalf("expected normalized empty, got %q", got)
	}
	if got := normalizeAWSBlastRadiusFixtureState("bogus", AWSConnectionStatus{}, false); got != "" {
		t.Fatalf("expected invalid fixture state to return empty token, got %q", got)
	}
}
