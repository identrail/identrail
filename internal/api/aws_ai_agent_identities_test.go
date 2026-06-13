package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/domain"
	"github.com/identrail/identrail/internal/telemetry"
	"go.uber.org/zap"
)

func TestGetAWSAIAgentIdentityInventoryBuildsScopedRecords(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 12, 13, 0, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-a")
	seedAWSConnectorForScanTest(t, store, ctx, "project-a", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }

	result, err := svc.GetAWSAIAgentIdentityInventory(ctx, "default", "project-a", AWSAIAgentIdentityInventoryRequest{ConnectorID: "aws-prod"})
	if err != nil {
		t.Fatalf("get ai agent identity inventory: %v", err)
	}
	if result.Status != awsPlatformDependencyStatusReady || result.Confidence < 0.9 {
		t.Fatalf("expected ready inventory, got %+v", result)
	}
	if result.ParentIssueRef != "#1472" || result.CurrentIssueRef != "#1505" || result.Version != awsAIAgentIdentityVersion {
		t.Fatalf("unexpected parent/current/version metadata: %+v", result)
	}
	if result.BedrockAgentCount != 1 || result.AgentCoreRuntimeCount != 1 || result.CustomAgentCount != 1 || result.ExternalAgentCount != 1 || result.GatewayCount != 1 {
		t.Fatalf("expected one record per agent type, got %+v", result)
	}
	if result.RuntimeRoleCount == 0 || result.ToolCount == 0 || result.CapabilityCount == 0 || result.RelationshipCount == 0 {
		t.Fatalf("expected populated counts, got %+v", result)
	}
	var customAgentNodeID, externalAgentNodeID string
	foundRecordCredentialType := false
	for _, record := range result.Records {
		switch record.AgentType {
		case "custom_agent":
			customAgentNodeID = record.AgentNodeID
		case "external_provider_agent":
			externalAgentNodeID = record.AgentNodeID
		}
		for _, relationshipType := range record.RelationshipTypes {
			if relationshipType == "uses_credential" {
				t.Fatalf("expected supported graph relationship type uses_secret, got unsupported uses_credential in %+v", record)
			}
			if relationshipType == "uses_secret" {
				foundRecordCredentialType = true
			}
		}
	}
	if !foundRecordCredentialType {
		t.Fatalf("expected credential records to advertise uses_secret relationship type, got %+v", result.Records)
	}
	expectedCustomCredentialRefTarget := awsCredentialReferenceNodeID(customAgentNodeID, "secretsmanager:prod/ai/openai-key")
	expectedExternalCredentialRefTarget := awsCredentialReferenceNodeID(externalAgentNodeID, "ssm:/prod/support/ai-provider-key")
	matchedCustomCredentialRef := false
	matchedExternalCredentialRef := false
	foundCredentialEdge := false
	for _, relationship := range result.Relationships {
		if relationship.Type == "uses_credential" {
			t.Fatalf("expected supported graph relationship type uses_secret, got unsupported uses_credential in %+v", relationship)
		}
		if relationship.Type == "uses_secret" {
			foundCredentialEdge = true
			parts := strings.Split(strings.TrimPrefix(relationship.ToNodeID, awsAIAgentCredentialRefPrefix), "|")
			if len(parts) != 4 {
				t.Fatalf("expected uses_secret target to include workload/provider/name/source, got %+v", relationship)
			}
			if !strings.HasPrefix(relationship.ToNodeID, awsAIAgentCredentialRefPrefix) {
				t.Fatalf("expected uses_secret edge to target credential-reference resource node, got %+v", relationship)
			}
			if relationship.ToNodeID == expectedCustomCredentialRefTarget {
				matchedCustomCredentialRef = true
			}
			if relationship.ToNodeID == expectedExternalCredentialRefTarget {
				matchedExternalCredentialRef = true
			}
		}
	}
	if !foundCredentialEdge {
		t.Fatalf("expected credential references to emit uses_secret relationship, got %+v", result.Relationships)
	}
	if !matchedCustomCredentialRef {
		t.Fatalf("expected custom agent unresolved credential reference to emit uses_secret edge to %q, got %+v", expectedCustomCredentialRefTarget, result.Relationships)
	}
	if !matchedExternalCredentialRef {
		t.Fatalf("expected external-provider-agent unresolved credential reference to emit uses_secret edge to %q, got %+v", expectedExternalCredentialRefTarget, result.Relationships)
	}
	if len(result.CoverageGaps) == 0 {
		t.Fatalf("expected sensitive-boundary coverage gaps, got %+v", result.CoverageGaps)
	}
	for _, record := range result.Records {
		if record.SensitiveBoundary != "metadata_only" {
			t.Fatalf("expected metadata_only sensitive boundary, got %+v", record)
		}
		evidence := strings.ToLower(record.EvidenceRef + " " + record.Source + " " + strings.Join(record.ToolNames, " "))
		for _, forbidden := range []string{"prompt", "completion", "browser_page", "code_output", "secret_value", "payload_body"} {
			if strings.Contains(evidence, forbidden) {
				t.Fatalf("expected payload-safe evidence, got forbidden marker %q in %+v", forbidden, record)
			}
		}
	}
	if result.GeneratedAt != now || result.UpdatedAt != now {
		t.Fatalf("expected deterministic timestamps %v, got %v/%v", now, result.GeneratedAt, result.UpdatedAt)
	}
}

func TestRouterAWSAIAgentIdentityInventoryPartialFailure(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 12, 13, 30, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-1")
	seedAWSConnectorForScanTest(t, store, ctx, "project-1", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	r := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{})

	resp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-1/aws/ai-agent-identities?connector_id=aws-prod&fixture_state=partial_failure", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	var body struct {
		Inventory AWSAIAgentIdentityInventoryResult `json:"inventory"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Inventory.Status != awsPlatformDependencyStatusDegraded || body.Inventory.FixtureState != "partial_failure" {
		t.Fatalf("expected degraded partial_failure, got status=%q fixture=%q", body.Inventory.Status, body.Inventory.FixtureState)
	}
	if body.Inventory.RecordCount != 4 {
		t.Fatalf("expected partial failure to retain four records, got %d", body.Inventory.RecordCount)
	}
	foundGatewayDiag := false
	for _, diag := range body.Inventory.Diagnostics {
		if diag.Code == "ai_agent_gateway_list_failed" && diag.Retryable {
			foundGatewayDiag = true
		}
	}
	if !foundGatewayDiag {
		t.Fatalf("expected retryable gateway diagnostic, got %+v", body.Inventory.Diagnostics)
	}
}

func TestRouterAWSAIAgentIdentityInventoryEmptyStateReturnsArrayFields(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 12, 13, 45, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-empty")
	seedAWSConnectorForScanTest(t, store, ctx, "project-empty", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	r := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{})

	resp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-empty/aws/ai-agent-identities?connector_id=aws-prod&fixture_state=empty", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	assertAWSAIAgentIdentityInventoryArrayFields(t, resp.Body.Bytes(), []string{"records", "relationships", "failure_reasons", "remediation_hints", "diagnostics"})
}

func TestAIAgentFixtureRecordCallsToolRelationshipTypeOnlyForTrueGatewayCalls(t *testing.T) {
	record := awsAIAgentFixtureRecord("111111111111", "us-east-1", "agent_gateway", "payments-gateway", "payments-gateway", "arn:aws:bedrock:us-east-1:111111111111:agent-gateway/payments-gateway", "arn:aws:iam::111111111111:role/bedrock-agent-gateway-payments", time.Now(), func(r *AWSAIAgentIdentityRecord) {
		r.GatewayID = "payments-gateway"
		r.GatewayARN = "arn:aws:bedrock:us-east-1:111111111111:agent-gateway/payments-gateway"
	})
	found := false
	for _, relationshipType := range record.RelationshipTypes {
		if relationshipType == "calls_tool" {
			found = true
		}
	}
	if found {
		t.Fatalf("expected gateway self-record to omit calls_tool relationship type, got %v", record.RelationshipTypes)
	}
}

func TestAIAgentRelationshipsEmitCallsToolToToolNodes(t *testing.T) {
	record := awsAIAgentFixtureRecord("111111111111", "us-east-1", "custom_agent", "agent-with-gateway", "agent-1", "arn:aws:bedrock:us-east-1:111111111111:agent/agent-1", "arn:aws:iam::111111111111:role/agent-1", time.Now(), func(r *AWSAIAgentIdentityRecord) {
		r.GatewayID = "payments-gateway"
		r.GatewayARN = "arn:aws:bedrock:us-east-1:111111111111:agent-gateway/payments-gateway"
		r.ToolNames = []string{"payments-case-search", "fraud-review-action-group"}
	})

	relationships := awsAIAgentIdentityRelationships([]AWSAIAgentIdentityRecord{record})
	callsToolRelationships := make([]AWSAIAgentIdentityRelation, 0, len(relationships))
	for _, relationship := range relationships {
		if relationship.Type == "calls_tool" {
			callsToolRelationships = append(callsToolRelationships, relationship)
		}
	}
	if len(callsToolRelationships) != 2 {
		t.Fatalf("expected one calls_tool relationship per tool, got %d", len(callsToolRelationships))
	}
	gatewayToolNodeIDs := map[string]struct{}{
		awsAIAgentToolNodeID(record.GatewayNodeID, "payments-case-search"):      {},
		awsAIAgentToolNodeID(record.GatewayNodeID, "fraud-review-action-group"): {},
	}
	for _, relationship := range callsToolRelationships {
		if relationship.Type != "calls_tool" {
			t.Fatalf("expected calls_tool relationship, got %+v", relationship)
		}
		if relationship.FromNodeID != record.GatewayNodeID {
			t.Fatalf("expected calls_tool source %q, got %q", record.GatewayNodeID, relationship.FromNodeID)
		}
		if !strings.HasPrefix(relationship.ToNodeID, awsAIAgentToolNodePrefix) {
			t.Fatalf("expected tool node target with tool: prefix, got %q", relationship.ToNodeID)
		}
		if _, ok := gatewayToolNodeIDs[relationship.ToNodeID]; !ok {
			t.Fatalf("unexpected tool node target %q", relationship.ToNodeID)
		}
		delete(gatewayToolNodeIDs, relationship.ToNodeID)
	}
	if len(gatewayToolNodeIDs) != 0 {
		t.Fatalf("missing calls_tool edges for tools: %+v", gatewayToolNodeIDs)
	}
}

func TestAIAgentRelationshipsEmitCallsToolForGatewayRecord(t *testing.T) {
	record := awsAIAgentFixtureRecord("111111111111", "us-east-1", "agent_gateway", "payments-gateway", "payments-gateway", "arn:aws:bedrock:us-east-1:111111111111:agent-gateway/payments-gateway", "arn:aws:iam::111111111111:role/bedrock-agent-gateway-payments", time.Now(), func(r *AWSAIAgentIdentityRecord) {
		r.ToolNames = []string{"payments-case-search"}
	})

	relationships := awsAIAgentIdentityRelationships([]AWSAIAgentIdentityRecord{record})
	found := false
	for _, relationship := range relationships {
		if relationship.Type != "calls_tool" {
			continue
		}
		found = true
		if relationship.FromNodeID != record.AgentNodeID {
			t.Fatalf("expected calls_tool source %q, got %q", record.AgentNodeID, relationship.FromNodeID)
		}
		if relationship.ToNodeID != awsAIAgentToolNodeID(record.AgentNodeID, "payments-case-search") {
			t.Fatalf("expected calls_tool to target %q, got %q", awsAIAgentToolNodeID(record.AgentNodeID, "payments-case-search"), relationship.ToNodeID)
		}
	}
	if !found {
		t.Fatalf("expected gateway record to emit calls_tool relationship when tool names are present, got %+v", relationships)
	}
}

func TestAIAgentRelationshipsEmitRunsAsFromWorkloadNode(t *testing.T) {
	record := awsAIAgentFixtureRecord("111111111111", "us-east-1", "custom_agent", "invoice-reconciliation-agent", "custom-invoice-agent", "arn:aws:lambda:us-east-1:111111111111:function:invoice-reconciliation-agent", "arn:aws:iam::111111111111:role/invoice-agent", time.Now(), func(r *AWSAIAgentIdentityRecord) {
		r.ToolNames = nil
	})

	relationships := awsAIAgentIdentityRelationships([]AWSAIAgentIdentityRecord{record})
	var runsAs *AWSAIAgentIdentityRelation
	for _, relationship := range relationships {
		if relationship.Type == "runs_as" {
			rel := relationship
			runsAs = &rel
			break
		}
	}
	if runsAs == nil {
		t.Fatalf("expected runs_as relationship, got %+v", relationships)
	}
	expected := awsAIAgentWorkloadNodeID(record)
	if runsAs.FromNodeID != expected {
		t.Fatalf("expected runs_as source %q, got %q", expected, runsAs.FromNodeID)
	}
	if runsAs.ToNodeID != record.RuntimeRoleNodeID {
		t.Fatalf("expected runs_as target %q, got %q", record.RuntimeRoleNodeID, runsAs.ToNodeID)
	}
}

func TestRouterAWSAIAgentIdentityInventoryPermissionDenied(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 12, 14, 0, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-2")
	seedAWSConnectorForScanTest(t, store, ctx, "project-2", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	r := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{})

	resp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-2/aws/ai-agent-identities?connector_id=aws-prod&fixture_state=permission_denied", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	var body struct {
		Inventory AWSAIAgentIdentityInventoryResult `json:"inventory"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Inventory.Status != awsPlatformDependencyStatusBlocked {
		t.Fatalf("expected blocked status, got %q", body.Inventory.Status)
	}
	if len(body.Inventory.Records) != 0 {
		t.Fatalf("expected no records on permission_denied, got %d", len(body.Inventory.Records))
	}
	assertAWSAIAgentIdentityInventoryArrayFields(t, resp.Body.Bytes(), []string{"records", "relationships", "failure_reasons", "remediation_hints", "diagnostics"})
}

func TestRouterAWSAIAgentIdentityInventoryInvalidFixtureState(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 12, 14, 30, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-3")
	seedAWSConnectorForScanTest(t, store, ctx, "project-3", "aws-prod", domain.ConnectorStatusActive, "healthy", now)

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	r := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{})

	resp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-3/aws/ai-agent-identities?connector_id=aws-prod&fixture_state=invalid_state", "")
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid fixture state, got %d body=%s", resp.Code, resp.Body.String())
	}
}

func assertAWSAIAgentIdentityInventoryArrayFields(t *testing.T, payload []byte, fields []string) {
	t.Helper()
	var body struct {
		Inventory map[string]json.RawMessage `json:"inventory"`
	}
	if err := json.Unmarshal(payload, &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	for _, field := range fields {
		raw, ok := body.Inventory[field]
		if !ok {
			t.Fatalf("expected inventory.%s in response", field)
		}
		if string(raw) == "null" {
			t.Fatalf("expected inventory.%s to be an array, got null", field)
		}
		var values []json.RawMessage
		if err := json.Unmarshal(raw, &values); err != nil {
			t.Fatalf("expected inventory.%s to be an array, got %s: %v", field, string(raw), err)
		}
	}
}
