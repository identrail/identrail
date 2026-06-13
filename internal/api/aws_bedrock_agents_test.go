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

func newBedrockAgentsService(t *testing.T, store db.Store, now time.Time) *Service {
	t.Helper()
	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }
	return svc
}

func TestGetAWSBedrockAgentsInventorySuccess(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 13, 9, 0, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-a")
	seedAWSConnectorForScanTest(t, store, ctx, "project-a", "aws-prod", domain.ConnectorStatusActive, "healthy", now)
	svc := newBedrockAgentsService(t, store, now)

	result, err := svc.GetAWSBedrockAgentsInventory(ctx, "default", "project-a", AWSBedrockAgentsInventoryRequest{ConnectorID: "aws-prod"})
	if err != nil {
		t.Fatalf("get bedrock agents: %v", err)
	}
	if result.Status != awsPlatformDependencyStatusReady || result.Confidence < 0.9 {
		t.Fatalf("expected ready, got status=%q confidence=%v", result.Status, result.Confidence)
	}
	if result.CurrentIssueRef != "#1506" || result.Version != awsBedrockAgentsVersion {
		t.Fatalf("unexpected metadata: %+v", result)
	}
	if result.AgentCount != 2 || result.FilteredAgentCount != 2 {
		t.Fatalf("expected 2 agents, got count=%d filtered=%d", result.AgentCount, result.FilteredAgentCount)
	}
	if result.GuardrailCount == 0 || result.ToolCount == 0 || result.RuntimeRoleCount == 0 {
		t.Fatalf("expected derived counts, got %+v", result)
	}
	if result.RelationshipCount == 0 {
		t.Fatalf("expected relationships")
	}
	for _, record := range result.Records {
		if record.AgentType != awsBedrockAgentType {
			t.Fatalf("expected bedrock_agent type, got %q", record.AgentType)
		}
		if record.AgentNodeID == "" || record.EvidenceRef == "" || record.NextAction == "" {
			t.Fatalf("record missing required fields: %+v", record)
		}
		if record.Service != awsBedrockAgentsServiceName {
			t.Fatalf("expected service=%q, got %q", awsBedrockAgentsServiceName, record.Service)
		}
	}
}

func TestGetAWSBedrockAgentsInventoryFilters(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 13, 9, 30, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-a")
	seedAWSConnectorForScanTest(t, store, ctx, "project-a", "aws-prod", domain.ConnectorStatusActive, "healthy", now)
	svc := newBedrockAgentsService(t, store, now)

	byAgent, err := svc.GetAWSBedrockAgentsInventory(ctx, "default", "project-a", AWSBedrockAgentsInventoryRequest{ConnectorID: "aws-prod", AgentID: "PAYMENTSAGENT1"})
	if err != nil {
		t.Fatalf("filter by agent_id: %v", err)
	}
	if byAgent.FilteredAgentCount != 1 || byAgent.AgentCount != 2 {
		t.Fatalf("expected 1 filtered agent of 2 total, got %+v", byAgent)
	}

	byIdentity, err := svc.GetAWSBedrockAgentsInventory(ctx, "default", "project-a", AWSBedrockAgentsInventoryRequest{ConnectorID: "aws-prod", Identity: "support"})
	if err != nil {
		t.Fatalf("filter by identity: %v", err)
	}
	if byIdentity.FilteredAgentCount != 1 {
		t.Fatalf("expected 1 identity match, got %d", byIdentity.FilteredAgentCount)
	}

	byProvider, err := svc.GetAWSBedrockAgentsInventory(ctx, "default", "project-a", AWSBedrockAgentsInventoryRequest{ConnectorID: "aws-prod", Provider: "amazon-bedrock"})
	if err != nil {
		t.Fatalf("filter by provider: %v", err)
	}
	if byProvider.FilteredAgentCount != 2 {
		t.Fatalf("expected all 2 records to match amazon-bedrock provider, got %d", byProvider.FilteredAgentCount)
	}

	if _, err := svc.GetAWSBedrockAgentsInventory(ctx, "default", "project-a", AWSBedrockAgentsInventoryRequest{ConnectorID: "aws-prod", Provider: "bogus"}); err == nil {
		t.Fatalf("expected invalid provider error")
	}
}

func TestGetAWSBedrockAgentsInventoryFixtureStates(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 13, 10, 0, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-a")
	seedAWSConnectorForScanTest(t, store, ctx, "project-a", "aws-prod", domain.ConnectorStatusActive, "healthy", now)
	svc := newBedrockAgentsService(t, store, now)

	empty, err := svc.GetAWSBedrockAgentsInventory(ctx, "default", "project-a", AWSBedrockAgentsInventoryRequest{ConnectorID: "aws-prod", FixtureState: "empty"})
	if err != nil {
		t.Fatalf("empty: %v", err)
	}
	if empty.AgentCount != 0 || empty.Status != awsPlatformDependencyStatusReady {
		t.Fatalf("expected ready+empty, got %+v", empty)
	}
	if len(empty.Records) != 0 {
		t.Fatalf("expected zero records, got %+v", empty.Records)
	}

	degraded, err := svc.GetAWSBedrockAgentsInventory(ctx, "default", "project-a", AWSBedrockAgentsInventoryRequest{ConnectorID: "aws-prod", FixtureState: "degraded"})
	if err != nil {
		t.Fatalf("degraded: %v", err)
	}
	if degraded.Status != awsPlatformDependencyStatusDegraded || len(degraded.Diagnostics) == 0 {
		t.Fatalf("expected degraded with diagnostics, got %+v", degraded)
	}
	degradedRecord := false
	for _, rec := range degraded.Records {
		if rec.CoverageStatus == "degraded" {
			degradedRecord = true
			break
		}
	}
	if !degradedRecord {
		t.Fatalf("expected at least one degraded record")
	}

	partial, err := svc.GetAWSBedrockAgentsInventory(ctx, "default", "project-a", AWSBedrockAgentsInventoryRequest{ConnectorID: "aws-prod", FixtureState: "partial_failure"})
	if err != nil {
		t.Fatalf("partial_failure: %v", err)
	}
	if partial.Status != awsPlatformDependencyStatusDegraded {
		t.Fatalf("expected degraded for partial_failure, got %q", partial.Status)
	}
	if len(partial.Diagnostics) == 0 {
		t.Fatalf("expected partial failure diagnostics")
	}

	denied, err := svc.GetAWSBedrockAgentsInventory(ctx, "default", "project-a", AWSBedrockAgentsInventoryRequest{ConnectorID: "aws-prod", FixtureState: "permission_denied"})
	if err != nil {
		t.Fatalf("permission_denied: %v", err)
	}
	if denied.Status != awsPlatformDependencyStatusBlocked || denied.AgentCount != 0 {
		t.Fatalf("expected blocked + empty, got %+v", denied)
	}
}

func TestGetAWSBedrockAgentsInventoryNeverLeaksValues(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 13, 10, 30, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-a")
	seedAWSConnectorForScanTest(t, store, ctx, "project-a", "aws-prod", domain.ConnectorStatusActive, "healthy", now)
	svc := newBedrockAgentsService(t, store, now)

	result, err := svc.GetAWSBedrockAgentsInventory(ctx, "default", "project-a", AWSBedrockAgentsInventoryRequest{ConnectorID: "aws-prod"})
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	// Walk records + relationships only (the gap descriptions deliberately use
	// the word "prompt" to document what is intentionally not collected).
	recordsPayload, _ := json.Marshal(result.Records)
	relPayload, _ := json.Marshal(result.Relationships)
	combined := strings.ToLower(string(recordsPayload) + string(relPayload))
	for _, forbidden := range []string{"prompt_text", "instruction_text", "completion_text", "secret_value", "embedding_vector", "memory_content"} {
		if strings.Contains(combined, forbidden) {
			t.Fatalf("metadata-only contract violated: %q present in %s%s", forbidden, recordsPayload, relPayload)
		}
	}
}

func TestRouterAWSBedrockAgentsInventory(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := defaultScopeContext()
	now := time.Date(2026, 6, 13, 11, 0, 0, 0, time.UTC)
	seedDefaultProject(t, store, ctx, "project-1")
	seedAWSConnectorForScanTest(t, store, ctx, "project-1", "aws-prod", domain.ConnectorStatusActive, "healthy", now)
	svc := newBedrockAgentsService(t, store, now)
	r := NewRouter(zap.NewNop(), telemetry.NewMetrics(), svc, RouterOptions{})

	resp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-1/aws/bedrock-agents?connector_id=aws-prod&fixture_state=partial_failure", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	var body struct {
		Inventory AWSBedrockAgentsInventoryResult `json:"inventory"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Inventory.Status != awsPlatformDependencyStatusDegraded {
		t.Fatalf("expected degraded, got %+v", body.Inventory)
	}

	for _, query := range []string{"fixture_state=bogus", "provider=bogus"} {
		bad := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/default/projects/project-1/aws/bedrock-agents?connector_id=aws-prod&"+query, "")
		if bad.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for %q, got %d body=%s", query, bad.Code, bad.Body.String())
		}
	}
}
