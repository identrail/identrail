package api

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/domain"
	"github.com/identrail/identrail/internal/runtime/agentaccess"
)

func newAgentRuntimeAccessService(t *testing.T, project string, now time.Time) (*Service, string) {
	t.Helper()
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	seedDefaultProject(t, store, ctx, project)
	seedAWSConnectorForScanTest(t, store, ctx, project, "aws-prod", domain.ConnectorStatusActive, "healthy", now)
	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	return svc, "default"
}

func agentRecordsByStatus(records []AWSAgentRuntimeAccessRecord) map[string]int {
	counts := map[string]int{}
	for _, record := range records {
		counts[record.Status]++
	}
	return counts
}

func hasAgentCaveat(caveats []string, want string) bool {
	for _, caveat := range caveats {
		if caveat == want {
			return true
		}
	}
	return false
}

func TestGetAWSAgentRuntimeAccessBuildsCorrelationContract(t *testing.T) {
	now := time.Date(2026, 6, 19, 18, 0, 0, 0, time.UTC)
	svc, ws := newAgentRuntimeAccessService(t, "project-agent-corr", now)

	result, err := svc.GetAWSAgentRuntimeAccess(defaultScopeContext(), ws, "project-agent-corr", AWSAgentRuntimeAccessRequest{ConnectorID: "aws-prod", FixtureState: "success"})
	if err != nil {
		t.Fatalf("get correlation: %v", err)
	}
	if result.CurrentIssueRef != "#1520" || result.Version != awsAgentRuntimeAccessVersion || result.Status != "ready" {
		t.Fatalf("unexpected contract metadata: %+v", result)
	}
	counts := agentRecordsByStatus(result.Records)
	if counts[agentaccess.StatusConfirmed] != 2 || counts[agentaccess.StatusObservedWithoutDeclaration] != 2 || counts[agentaccess.StatusDeclaredUnused] != 1 {
		t.Fatalf("unexpected status distribution: %+v (records=%+v)", counts, result.Records)
	}
	if result.Summary.ShadowAgentCount != 1 || result.Summary.UndeclaredToolCount != 1 {
		t.Fatalf("expected one shadow agent and one undeclared tool, got %+v", result.Summary)
	}
	if result.Summary.BackingRoleMismatchCount != 1 || result.Summary.FailedToolCallCount != 1 {
		t.Fatalf("expected one backing-role mismatch and one failed tool-call, got %+v", result.Summary)
	}
	if result.Summary.RelationshipCount != len(result.Relationships) || len(result.Relationships) == 0 {
		t.Fatalf("expected relationships: %+v", result.Relationships)
	}
	if len(result.Caveats) == 0 || len(result.CoverageGaps) == 0 {
		t.Fatalf("expected caveats and coverage gaps")
	}
	for _, record := range result.Records {
		if record.RedactionBoundary != agentaccess.RedactionBoundary {
			t.Fatalf("record leaked unsafe redaction boundary: %+v", record)
		}
		if record.EvidenceRef == "" || record.AgentNodeID == "" || record.Confidence <= 0 || record.NextAction == "" {
			t.Fatalf("record missing required fields: %+v", record)
		}
	}
}

func TestGetAWSAgentRuntimeAccessConfirmedFlagsMismatchAndFailure(t *testing.T) {
	now := time.Date(2026, 6, 19, 18, 0, 0, 0, time.UTC)
	svc, ws := newAgentRuntimeAccessService(t, "project-agent-mismatch", now)

	result, err := svc.GetAWSAgentRuntimeAccess(defaultScopeContext(), ws, "project-agent-mismatch", AWSAgentRuntimeAccessRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
		Tool:         "ticket-writer",
	})
	if err != nil {
		t.Fatalf("get correlation: %v", err)
	}
	if len(result.Records) != 1 {
		t.Fatalf("expected one ticket-writer correlation, got %+v", result.Records)
	}
	record := result.Records[0]
	if record.Status != agentaccess.StatusConfirmed {
		t.Fatalf("expected confirmed (tool declared), got %q", record.Status)
	}
	if !hasAgentCaveat(record.Caveats, agentaccess.CaveatBackingRoleMismatch) || !hasAgentCaveat(record.Caveats, agentaccess.CaveatToolCallFailed) {
		t.Fatalf("expected backing-role-mismatch + tool-call-failed caveats, got %+v", record.Caveats)
	}
}

func TestGetAWSAgentRuntimeAccessFiltersByStatusAndAgent(t *testing.T) {
	now := time.Date(2026, 6, 19, 18, 0, 0, 0, time.UTC)
	svc, ws := newAgentRuntimeAccessService(t, "project-agent-filter", now)

	shadow, err := svc.GetAWSAgentRuntimeAccess(defaultScopeContext(), ws, "project-agent-filter", AWSAgentRuntimeAccessRequest{ConnectorID: "aws-prod", FixtureState: "success", Status: "observed_without_declaration"})
	if err != nil {
		t.Fatalf("get correlation: %v", err)
	}
	if len(shadow.Records) != 2 {
		t.Fatalf("expected two observed_without_declaration records, got %+v", shadow.Records)
	}
	for _, record := range shadow.Records {
		if record.Status != agentaccess.StatusObservedWithoutDeclaration {
			t.Fatalf("status filter leaked: %+v", record)
		}
	}
	if shadow.AppliedFilters["status"] != "observed-without-declaration" {
		t.Fatalf("expected normalized applied status filter, got %+v", shadow.AppliedFilters)
	}

	triage, err := svc.GetAWSAgentRuntimeAccess(defaultScopeContext(), ws, "project-agent-filter", AWSAgentRuntimeAccessRequest{ConnectorID: "aws-prod", FixtureState: "success", AgentID: "case-triage"})
	if err != nil {
		t.Fatalf("get correlation: %v", err)
	}
	// case-triage: case-router (confirmed) + policy-checker (declared_unused) + bulk-export (undeclared tool).
	if len(triage.Records) != 3 {
		t.Fatalf("expected three case-triage correlations, got %+v", triage.Records)
	}
}

func TestGetAWSAgentRuntimeAccessIdentityFilterIncludesDeclaredUnusedRole(t *testing.T) {
	now := time.Date(2026, 6, 19, 18, 0, 0, 0, time.UTC)
	svc, ws := newAgentRuntimeAccessService(t, "project-agent-identity-filter", now)

	result, err := svc.GetAWSAgentRuntimeAccess(defaultScopeContext(), ws, "project-agent-identity-filter", AWSAgentRuntimeAccessRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
		Identity:     "case-triage-runtime",
	})
	if err != nil {
		t.Fatalf("get correlation: %v", err)
	}
	var policyChecker *AWSAgentRuntimeAccessRecord
	for i := range result.Records {
		if result.Records[i].ToolName == "policy-checker" {
			policyChecker = &result.Records[i]
			break
		}
	}
	if policyChecker == nil {
		t.Fatalf("identity filter dropped declared_unused tool for declared role: %+v", result.Records)
	}
	if policyChecker.Status != agentaccess.StatusDeclaredUnused {
		t.Fatalf("expected declared_unused policy-checker, got %+v", policyChecker)
	}
	if !strings.Contains(policyChecker.DeclaredBackingRole, "case-triage-runtime") || policyChecker.DeclaredBackingRoleNode == "" {
		t.Fatalf("expected declared backing role metadata projected, got %+v", policyChecker)
	}
}

func TestGetAWSAgentRuntimeAccessPermissionDeniedIsExplicit(t *testing.T) {
	now := time.Date(2026, 6, 19, 18, 0, 0, 0, time.UTC)
	svc, ws := newAgentRuntimeAccessService(t, "project-agent-denied", now)

	result, err := svc.GetAWSAgentRuntimeAccess(defaultScopeContext(), ws, "project-agent-denied", AWSAgentRuntimeAccessRequest{ConnectorID: "aws-prod", FixtureState: "permission_denied"})
	if err != nil {
		t.Fatalf("get correlation: %v", err)
	}
	if result.Status != "blocked" || result.Confidence != 0 {
		t.Fatalf("expected blocked permission-denied, got status=%q confidence=%v", result.Status, result.Confidence)
	}
	if len(result.Records) != 0 || len(result.Diagnostics) == 0 || len(result.CoverageGaps) == 0 {
		t.Fatalf("expected no records + diagnostics + coverage gaps, got %+v", result)
	}
}

func TestGetAWSAgentRuntimeAccessEmptyAndPartialFailure(t *testing.T) {
	now := time.Date(2026, 6, 19, 18, 0, 0, 0, time.UTC)
	svc, ws := newAgentRuntimeAccessService(t, "project-agent-states", now)

	empty, err := svc.GetAWSAgentRuntimeAccess(defaultScopeContext(), ws, "project-agent-states", AWSAgentRuntimeAccessRequest{ConnectorID: "aws-prod", FixtureState: "empty"})
	if err != nil {
		t.Fatalf("empty: %v", err)
	}
	if empty.Status != "degraded" || len(empty.Records) != 0 || len(empty.CoverageGaps) == 0 {
		t.Fatalf("unexpected empty state: %+v", empty)
	}

	partial, err := svc.GetAWSAgentRuntimeAccess(defaultScopeContext(), ws, "project-agent-states", AWSAgentRuntimeAccessRequest{ConnectorID: "aws-prod", FixtureState: "partial_failure"})
	if err != nil {
		t.Fatalf("partial: %v", err)
	}
	if partial.Status != "degraded" {
		t.Fatalf("expected degraded partial-failure, got %q", partial.Status)
	}
	// Inventory failed → no confirmed, and observed tool-calls carry the
	// inventory-unavailable caveat instead of shadow accusations.
	for _, record := range partial.Records {
		if record.Status == agentaccess.StatusConfirmed {
			t.Fatalf("partial-failure must not produce confirmed correlations: %+v", record)
		}
		if hasAgentCaveat(record.Caveats, agentaccess.CaveatAgentNotInInventory) {
			t.Fatalf("must not accuse shadow agent when inventory unavailable: %+v", record.Caveats)
		}
	}
	if partial.Summary.DeclaredUnusedCount != 0 {
		t.Fatalf("partial-failure has no declared tools, so no declared_unused expected: %+v", partial.Summary)
	}
}

func TestGetAWSAgentRuntimeAccessDefaultLiveRequiresDeliveryFactory(t *testing.T) {
	now := time.Date(2026, 6, 19, 18, 0, 0, 0, time.UTC)
	svc, ws := newAgentRuntimeAccessService(t, "project-agent-live-default", now)

	result, err := svc.GetAWSAgentRuntimeAccess(defaultScopeContext(), ws, "project-agent-live-default", AWSAgentRuntimeAccessRequest{ConnectorID: "aws-prod"})
	if err != nil {
		t.Fatalf("get correlation: %v", err)
	}
	if result.Status != awsPlatformDependencyStatusDegraded || len(result.Records) != 0 {
		t.Fatalf("expected degraded with no records when live delivery unavailable, got status=%q records=%d", result.Status, len(result.Records))
	}
}

func TestGetAWSAgentRuntimeAccessLiveRoutesThroughDeliveryAndInventoryUnavailable(t *testing.T) {
	now := time.Date(2026, 6, 19, 19, 0, 0, 0, time.UTC)
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	seedDefaultProject(t, store, ctx, "project-agent-live")
	seedAWSConnectorForScanTest(t, store, ctx, "project-agent-live", "aws-prod", domain.ConnectorStatusActive, "healthy", now)
	grantRuntimeEvidenceCapability(t, store, ctx, "project-agent-live", "aws-prod")

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }

	role := "arn:aws:iam::123456789012:role/agent-runtime"
	agentARN := "arn:aws:bedrock-agentcore:us-east-1:123456789012:agent-runtime-endpoint/live-agent/blue"
	deliveryRecord := liveRuntimeRecord(t, "evt-agent-live", "agent-tool", "InvokeTool", "bedrock-agentcore.amazonaws.com", "bedrock-agentcore:InvokeTool", "security", "agent-runtime", role, agentARN, "AWS::BedrockAgentCore::Runtime", now.Add(-2*time.Minute))
	deliveryRecord.AgentID = "live-agent"
	deliveryRecord.AgentNodeID = "aws:agent:123456789012:us-east-1:agentcore_runtime/live-agent/blue"
	deliveryRecord.ToolName = "live-tool"
	fake := &fakeDeliveryIngester{result: AWSCloudTrailIngestResult{Status: "ready", Records: []AWSRuntimeEventRecord{deliveryRecord}}}
	svc.AWSCloudTrailDeliveryFactory = func(_ context.Context, _ AWSConnectionStatus, _ AWSCloudTrailDeliverySource) (AWSCloudTrailRuntimeEventIngester, error) {
		return fake, nil
	}

	result, err := svc.GetAWSAgentRuntimeAccess(ctx, "default", "project-agent-live", AWSAgentRuntimeAccessRequest{ConnectorID: "aws-prod"})
	if err != nil {
		t.Fatalf("get correlation: %v", err)
	}
	if fake.calls == 0 {
		t.Fatalf("delivery factory was never used — agent tool-calls not routed through delivery")
	}
	var found *AWSAgentRuntimeAccessRecord
	for i := range result.Records {
		if result.Records[i].ToolName == "live-tool" {
			found = &result.Records[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("expected a correlation for the observed live tool-call, got %+v", result.Records)
	}
	// Inventory is forced empty in live mode → observed_without_declaration
	// with the neutral inventory-unavailable caveat, not a shadow accusation.
	if found.Status != agentaccess.StatusObservedWithoutDeclaration {
		t.Fatalf("expected observed_without_declaration, got %q", found.Status)
	}
	if !hasAgentCaveat(found.Caveats, agentaccess.CaveatInventoryUnavailable) {
		t.Fatalf("expected inventory-unavailable caveat, got %+v", found.Caveats)
	}
	if hasAgentCaveat(found.Caveats, agentaccess.CaveatAgentNotInInventory) {
		t.Fatalf("must not accuse shadow agent when inventory unavailable: %+v", found.Caveats)
	}
}

func TestGetAWSAgentRuntimeAccessBlockedRuntimeSuppressesDeclaredUnused(t *testing.T) {
	now := time.Date(2026, 6, 19, 19, 30, 0, 0, time.UTC)
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	seedDefaultProject(t, store, ctx, "project-agent-blocked")
	seedAWSConnectorForScanTest(t, store, ctx, "project-agent-blocked", "aws-prod", domain.ConnectorStatusActive, "healthy", now)
	grantRuntimeEvidenceCapability(t, store, ctx, "project-agent-blocked", "aws-prod")

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	svc.AWSCloudTrailDeliveryFactory = func(_ context.Context, _ AWSConnectionStatus, _ AWSCloudTrailDeliverySource) (AWSCloudTrailRuntimeEventIngester, error) {
		return &fakeDeliveryIngester{result: AWSCloudTrailIngestResult{Status: "blocked", FailureReasons: []string{"runtime event sources are not authorized for this connector"}}}, nil
	}

	result, err := svc.GetAWSAgentRuntimeAccess(ctx, "default", "project-agent-blocked", AWSAgentRuntimeAccessRequest{ConnectorID: "aws-prod"})
	if err != nil {
		t.Fatalf("get correlation: %v", err)
	}
	if result.Status != "blocked" || len(result.Records) != 0 || result.Summary.DeclaredUnusedCount != 0 {
		t.Fatalf("blocked runtime must not surface declared_unused: status=%q records=%d summary=%+v", result.Status, len(result.Records), result.Summary)
	}
}

func TestObservedAgentToolCallsFromRuntimeRecordsFiltersEventTypes(t *testing.T) {
	records := []AWSRuntimeEventRecord{
		{EventID: "tool", EventType: "agent-tool", AgentNodeID: "agent-1", AgentID: "a1", ToolName: "router", ActorIdentityNodeID: "role-1"},
		{EventID: "secret", EventType: "secret-read", AgentNodeID: "agent-x", ActorIdentityNodeID: "role-x"},
		{EventID: "no-agent", EventType: "agent-tool", ToolName: "router"},
	}
	observed := observedAgentToolCallsFromRuntimeRecords(records)
	if len(observed) != 1 || observed[0].EventID != "tool" {
		t.Fatalf("expected only the attributable agent-tool event, got %+v", observed)
	}
	if observed[0].Outcome != agentaccess.OutcomeUnknown {
		t.Fatalf("expected unknown outcome from live record, got %q", observed[0].Outcome)
	}
}

func TestDeclaredToolsFromAgentInventoryExpandsToolsAndKnownAgents(t *testing.T) {
	records := []AWSAIAgentIdentityRecord{
		{AgentID: "a", AgentNodeID: "node-a", RuntimeRoleARN: "arn:aws:iam::1:role/a", ToolNames: []string{"t1", "t2"}, ToolTargetRefs: []string{"ref1"}},
		{AgentID: "b", AgentNodeID: "node-b", ToolNames: nil},
	}
	declared, known := declaredToolsFromAgentInventory(records)
	// a expands to 2 tools; b contributes one empty-tool marker.
	if len(declared) != 3 {
		t.Fatalf("expected 3 declared entries (2 tools + 1 marker), got %+v", declared)
	}
	if len(known) != 2 || !strings.Contains(strings.Join(known, ","), "node-a") || !strings.Contains(strings.Join(known, ","), "node-b") {
		t.Fatalf("expected both agents known, got %+v", known)
	}
	// First tool of agent a carries its target ref.
	var t1 *agentaccess.DeclaredTool
	for i := range declared {
		if declared[i].ToolName == "t1" {
			t1 = &declared[i]
		}
	}
	if t1 == nil || t1.ToolTargetRef != "ref1" {
		t.Fatalf("expected t1 with target ref, got %+v", declared)
	}
}

func TestAWSAgentRuntimeAccessRelationshipsUseTargetResourceNodeIDs(t *testing.T) {
	agentNode := "aws:agent:123456789012:us-east-1:agentcore_runtime/case-triage/blue"
	resourceARN := "arn:aws:bedrock-agentcore:us-east-1:123456789012:agent-runtime-endpoint/case-triage/blue"
	resourceNode := "aws:resource:bedrock-agentcore:us-east-1:123456789012:agent-runtime-endpoint/case-triage/blue"
	relationships := awsAgentRuntimeAccessRelationships([]AWSAgentRuntimeAccessRecord{{
		AgentNodeID:           agentNode,
		Status:                agentaccess.StatusConfirmed,
		TargetResourceARNs:    []string{resourceARN},
		TargetResourceNodeIDs: []string{resourceNode},
		EvidenceRef:           "runtime-correlation://case-triage",
	}})

	foundTargetEdge := false
	for _, rel := range relationships {
		if rel.Type != "agent_tool_targeted_resource" {
			continue
		}
		foundTargetEdge = true
		if rel.FromNodeID != agentNode || rel.ToNodeID != resourceNode {
			t.Fatalf("expected target edge to graph resource node, got %+v", rel)
		}
		if rel.ToNodeID == resourceARN {
			t.Fatalf("target edge must not use raw ARN when graph node id is available: %+v", rel)
		}
	}
	if !foundTargetEdge {
		t.Fatalf("expected agent_tool_targeted_resource relationship, got %+v", relationships)
	}
}

func TestAWSAgentRuntimeAccessRelationshipsUseDeclaredRoleForUnusedTools(t *testing.T) {
	agentNode := "aws:agent:123456789012:us-east-1:agentcore_runtime/case-triage/blue"
	roleNode := "aws:identity:123456789012:role/case-triage-runtime"
	relationships := awsAgentRuntimeAccessRelationships([]AWSAgentRuntimeAccessRecord{{
		AgentNodeID:             agentNode,
		Status:                  agentaccess.StatusDeclaredUnused,
		DeclaredBackingRoleNode: roleNode,
		EvidenceRef:             "runtime-correlation://policy-checker",
	}})

	if len(relationships) != 1 {
		t.Fatalf("expected one declared role relationship, got %+v", relationships)
	}
	rel := relationships[0]
	if rel.Type != "unused_declared_tool" || rel.FromNodeID != roleNode || rel.ToNodeID != agentNode {
		t.Fatalf("expected declared role to agent unused edge, got %+v", rel)
	}
}
