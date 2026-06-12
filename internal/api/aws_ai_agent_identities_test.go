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
	foundCredentialEdge := false
	for _, relationship := range result.Relationships {
		if relationship.Type == "uses_credential" {
			t.Fatalf("expected supported graph relationship type uses_secret, got unsupported uses_credential in %+v", relationship)
		}
		if relationship.Type == "uses_secret" {
			foundCredentialEdge = true
		}
	}
	if !foundCredentialEdge {
		t.Fatalf("expected credential references to emit uses_secret relationship, got %+v", result.Relationships)
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
