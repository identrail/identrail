package aws

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/providers"
)

type fakeBedrockAgentsAPI struct {
	pages           []BedrockAgentsPage
	pageCalls       int
	details         map[string]BedrockAgentDetail
	detailIssues    map[string][]providers.SourceError
	detailErr       map[string]error
	listErr         map[int]error
	listCallCount   int
	detailCallCount int
	detailCallIDs   []string
}

func (f *fakeBedrockAgentsAPI) ListAgents(_ context.Context, _ string, _ int32) (BedrockAgentsPage, error) {
	if err, ok := f.listErr[f.listCallCount]; ok {
		f.listCallCount++
		return BedrockAgentsPage{}, err
	}
	if f.pageCalls >= len(f.pages) {
		f.listCallCount++
		return BedrockAgentsPage{}, nil
	}
	page := f.pages[f.pageCalls]
	f.pageCalls++
	f.listCallCount++
	return page, nil
}

func (f *fakeBedrockAgentsAPI) GetAgentDetail(_ context.Context, agentID string) (BedrockAgentDetail, []providers.SourceError, error) {
	f.detailCallCount++
	f.detailCallIDs = append(f.detailCallIDs, agentID)
	if err, ok := f.detailErr[agentID]; ok {
		return BedrockAgentDetail{}, nil, err
	}
	return f.details[agentID], f.detailIssues[agentID], nil
}

func bedrockSampleScope() AWSCollectorScope {
	return AWSCollectorScope{
		TenantID:    "tenant-1",
		WorkspaceID: "ws-1",
		ProjectID:   "proj-1",
		ConnectorID: "conn-1",
		ScanID:      "scan-1",
		AccountID:   "123456789012",
		Region:      "us-east-1",
	}
}

func TestBedrockAgentsCollectorCollectEmitsRecords(t *testing.T) {
	api := &fakeBedrockAgentsAPI{
		pages: []BedrockAgentsPage{{
			Agents: []BedrockAgentSummary{
				{
					AgentID:                     "AG1",
					AgentARN:                    "arn:aws:bedrock:us-east-1:123456789012:agent/AG1",
					AgentName:                   "support-agent",
					AgentStatus:                 "PREPARED",
					FoundationModel:             "anthropic.claude-3-5-sonnet-20240620-v1:0",
					RoleARN:                     "arn:aws:iam::123456789012:role/bedrock-support",
					GuardrailID:                 "guard-1",
					CustomerEncryptionKMSKeyARN: "arn:aws:kms:us-east-1:123456789012:key/cmk-1",
					Tags:                        map[string]string{"env": "prod"},
				},
			},
		}},
		details: map[string]BedrockAgentDetail{
			"AG1": {
				ActionGroupNames:        []string{"orders-tool", "refunds-tool"},
				ActionGroupExecutorARNs: []string{"arn:aws:lambda:us-east-1:123456789012:function:agent-exec"},
				KnowledgeBaseIDs:        []string{"KB1", "KB2"},
				AliasNames:              []string{"production"},
				HasInstruction:          true,
				HasPromptOverride:       true,
			},
		},
	}
	collector := NewBedrockAgentsCollector(api,
		WithBedrockAgentsClock(func() time.Time { return time.Date(2026, 6, 13, 0, 0, 0, 0, time.UTC) }),
	)
	assets, issues, err := collector.CollectWithDiagnostics(context.Background(), bedrockSampleScope())
	if err != nil {
		t.Fatalf("CollectWithDiagnostics: %v", err)
	}
	if len(issues) != 0 {
		t.Fatalf("expected no issues, got %v", issues)
	}
	if len(assets) != 1 {
		t.Fatalf("expected 1 asset, got %d", len(assets))
	}
	var record AIAgentIdentity
	if err := json.Unmarshal(assets[0].Payload, &record); err != nil {
		t.Fatalf("unmarshal asset: %v", err)
	}
	if record.AgentType != bedrockAgentType {
		t.Fatalf("expected bedrock_agent type, got %q", record.AgentType)
	}
	if record.Provider != "amazon-bedrock" || record.ModelID == "" {
		t.Fatalf("provider/model wrong: %+v", record)
	}
	if record.ToolCount != 2 {
		t.Fatalf("expected 2 tools, got %d", record.ToolCount)
	}
	if record.RuntimeRoleAccountID != "123456789012" {
		t.Fatalf("expected runtime role account id, got %q", record.RuntimeRoleAccountID)
	}
	wantCaps := map[string]bool{
		"tool_use": true, "knowledge_base": true, "guardrail": true,
		"aliases": true, "instruction_configured": true, "prompt_override_configured": true,
		"foundation_model": true, "customer_encryption_kms": true,
	}
	for _, cap := range record.CapabilityNames {
		delete(wantCaps, cap)
	}
	if len(wantCaps) != 0 {
		t.Fatalf("missing capabilities %v in %v", wantCaps, record.CapabilityNames)
	}
	joined := strings.Join(record.CredentialReferenceRefs, ",")
	if !strings.Contains(joined, "action_group_executor:") || !strings.Contains(joined, "kms:") {
		t.Fatalf("credential refs missing executor/kms markers: %v", record.CredentialReferenceRefs)
	}
	if record.SensitiveBoundary != "metadata_only" {
		t.Fatalf("sensitive boundary must be metadata_only, got %q", record.SensitiveBoundary)
	}
	if record.Status != "ready" || record.CoverageStatus != "covered" {
		t.Fatalf("status/coverage wrong: %+v", record)
	}
	if record.Confidence <= 0 {
		t.Fatalf("confidence not derived: %v", record.Confidence)
	}
}

func TestBedrockAgentsCollectorMetadataOnlyPayload(t *testing.T) {
	api := &fakeBedrockAgentsAPI{
		pages: []BedrockAgentsPage{{
			Agents: []BedrockAgentSummary{
				{AgentID: "AG1", AgentARN: "arn:aws:bedrock:us-east-1:123456789012:agent/AG1", AgentName: "agent", RoleARN: "arn:aws:iam::123456789012:role/r"},
			},
		}},
		details: map[string]BedrockAgentDetail{"AG1": {ActionGroupNames: []string{"tool-a"}}},
	}
	collector := NewBedrockAgentsCollector(api)
	assets, _, err := collector.CollectWithDiagnostics(context.Background(), bedrockSampleScope())
	if err != nil {
		t.Fatalf("CollectWithDiagnostics: %v", err)
	}
	payload := strings.ToLower(string(assets[0].Payload))
	for _, forbidden := range []string{"prompt_text", "instruction_text", "completion_text", "secret_value", "message_body", "embedding_vector"} {
		if strings.Contains(payload, forbidden) {
			t.Fatalf("metadata-only contract violated by %q in payload: %s", forbidden, payload)
		}
	}
}

func TestBedrockAgentsCollectorDefaultsScopeFieldsOnCollect(t *testing.T) {
	api := &fakeBedrockAgentsAPI{
		pages: []BedrockAgentsPage{{
			Agents: []BedrockAgentSummary{
				{AgentID: "AG1", AgentARN: "arn:aws:bedrock:us-east-1:123456789012:agent/AG1", AgentName: "agent", RoleARN: "arn:aws:iam::123456789012:role/r"},
			},
		}},
		details: map[string]BedrockAgentDetail{"AG1": {}},
	}
	collector := NewBedrockAgentsCollector(api)
	assets, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(assets) != 1 {
		t.Fatalf("expected one asset, got %d", len(assets))
	}
	var record AIAgentIdentity
	if err := json.Unmarshal(assets[0].Payload, &record); err != nil {
		t.Fatalf("unmarshal asset: %v", err)
	}
	if record.TenantID != "tenant" || record.WorkspaceID != "workspace" || record.ProjectID != "project" {
		t.Fatalf("expected default tenant/workspace/project scope, got %+v", record.ServiceCollectorRecord)
	}
	if record.ConnectorID != "aws-connector" || record.ScanID != "aws-ai-agent-identity-fixture" {
		t.Fatalf("expected default connector/scan scope, got %+v", record.ServiceCollectorRecord)
	}
}
func TestBedrockAgentsCollectorPartialFailureWhenDetailFails(t *testing.T) {
	api := &fakeBedrockAgentsAPI{
		pages: []BedrockAgentsPage{{
			Agents: []BedrockAgentSummary{
				{AgentID: "OK", AgentARN: "arn:aws:bedrock:us-east-1:123456789012:agent/OK", AgentName: "ok", RoleARN: "arn:aws:iam::123456789012:role/ok"},
				{AgentID: "BAD", AgentARN: "arn:aws:bedrock:us-east-1:123456789012:agent/BAD", AgentName: "bad", RoleARN: "arn:aws:iam::123456789012:role/bad"},
			},
		}},
		details:   map[string]BedrockAgentDetail{"OK": {ActionGroupNames: []string{"t"}}},
		detailErr: map[string]error{"BAD": errors.New("AccessDenied: GetAgent")},
	}
	collector := NewBedrockAgentsCollector(api, WithBedrockAgentsRetryPolicy(RetryPolicy{MaxRetries: 0, BaseDelay: 0, MaxDelay: 0}))
	assets, issues, err := collector.CollectWithDiagnostics(context.Background(), bedrockSampleScope())
	if err != nil {
		t.Fatalf("CollectWithDiagnostics: %v", err)
	}
	if len(assets) != 2 {
		t.Fatalf("expected 2 assets emitted, got %d", len(assets))
	}
	var badRecord AIAgentIdentity
	for _, asset := range assets {
		var record AIAgentIdentity
		if err := json.Unmarshal(asset.Payload, &record); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if record.AgentID == "BAD" {
			badRecord = record
		}
	}
	if badRecord.CoverageStatus != "degraded" {
		t.Fatalf("expected degraded coverage on detail failure, got %+v", badRecord)
	}
	if !hasIssueCode(issues, "bedrock_agent_detail_failed") {
		t.Fatalf("expected partial-failure diagnostic, got %v", issues)
	}
}

func TestBedrockAgentsCollectorDegradesWhenDetailIssuesReturned(t *testing.T) {
	api := &fakeBedrockAgentsAPI{
		pages: []BedrockAgentsPage{{
			Agents: []BedrockAgentSummary{
				{
					AgentID:                     "UNSEEDED",
					AgentARN:                    "arn:aws:bedrock:us-east-1:123456789012:agent/UNSEEDED",
					AgentName:                   "unseeded",
					RoleARN:                     "arn:aws:iam::123456789012:role/unseeded",
					FoundationModel:             "anthropic.claude-3-5-sonnet-20240620-v1:0",
					CustomerEncryptionKMSKeyARN: "arn:aws:kms:us-east-1:123456789012:key/cmk-1",
				},
			},
		}},
		detailIssues: map[string][]providers.SourceError{
			"UNSEEDED": {
				{
					Collector: bedrockAgentsCollectorName,
					SourceID:  "UNSEEDED",
					Code:      "bedrock_agent_detail_not_seeded",
					Message:   "no fixture detail seeded for agent",
					Retryable: true,
				},
			},
		},
	}
	collector := NewBedrockAgentsCollector(api)
	assets, issues, err := collector.CollectWithDiagnostics(context.Background(), bedrockSampleScope())
	if err != nil {
		t.Fatalf("CollectWithDiagnostics: %v", err)
	}
	if len(assets) != 1 {
		t.Fatalf("expected one asset, got %d", len(assets))
	}
	if !hasIssueCode(issues, "bedrock_agent_detail_not_seeded") {
		t.Fatalf("expected detail diagnostic, got %v", issues)
	}
	var record AIAgentIdentity
	if err := json.Unmarshal(assets[0].Payload, &record); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if record.CoverageStatus != "degraded" {
		t.Fatalf("expected degraded coverage when detail diagnostics are returned, got %+v", record)
	}
	if record.Status != "degraded" {
		t.Fatalf("expected degraded status when detail diagnostics are returned, got %+v", record)
	}
}

func TestBedrockAgentsCollectorPaginationDedup(t *testing.T) {
	api := &fakeBedrockAgentsAPI{
		pages: []BedrockAgentsPage{
			{
				Agents: []BedrockAgentSummary{
					{AgentID: "A", AgentARN: "arn:aws:bedrock:us-east-1:123456789012:agent/A", AgentName: "a", RoleARN: "arn:aws:iam::123456789012:role/a"},
				},
				NextToken: "tok",
			},
			{
				Agents: []BedrockAgentSummary{
					{AgentID: "A", AgentARN: "arn:aws:bedrock:us-east-1:123456789012:agent/A", AgentName: "a-dup", RoleARN: "arn:aws:iam::123456789012:role/a"},
					{AgentID: "B", AgentARN: "arn:aws:bedrock:us-east-1:123456789012:agent/B", AgentName: "b", RoleARN: "arn:aws:iam::123456789012:role/b"},
				},
			},
		},
		details: map[string]BedrockAgentDetail{
			"A": {},
			"B": {},
		},
	}
	collector := NewBedrockAgentsCollector(api)
	assets, _, err := collector.CollectWithDiagnostics(context.Background(), bedrockSampleScope())
	if err != nil {
		t.Fatalf("CollectWithDiagnostics: %v", err)
	}
	if len(assets) != 2 {
		t.Fatalf("expected 2 deduped assets, got %d", len(assets))
	}
}

func TestBedrockAgentsCollectorEmptyAuthorized(t *testing.T) {
	api := &fakeBedrockAgentsAPI{pages: []BedrockAgentsPage{{}}}
	collector := NewBedrockAgentsCollector(api)
	assets, issues, err := collector.CollectWithDiagnostics(context.Background(), bedrockSampleScope())
	if err != nil {
		t.Fatalf("CollectWithDiagnostics: %v", err)
	}
	if len(assets) != 0 {
		t.Fatalf("expected no assets, got %d", len(assets))
	}
	if len(issues) != 0 {
		t.Fatalf("expected no diagnostics, got %v", issues)
	}
}

func TestBedrockAgentsCollectorListFailureSurfaces(t *testing.T) {
	api := &fakeBedrockAgentsAPI{listErr: map[int]error{0: errors.New("AccessDenied: ListAgents")}}
	collector := NewBedrockAgentsCollector(api, WithBedrockAgentsRetryPolicy(RetryPolicy{MaxRetries: 0, BaseDelay: 0, MaxDelay: 0}))
	_, issues, err := collector.CollectWithDiagnostics(context.Background(), bedrockSampleScope())
	if err == nil {
		t.Fatalf("expected error on list failure")
	}
	if !hasIssueCode(issues, "bedrock_agents_list_failed") {
		t.Fatalf("expected list-failure diagnostic, got %v", issues)
	}
}

func TestBedrockAgentsCollectorDegradesOnDetailDiagnosticsWithoutError(t *testing.T) {
	// When the detail adapter returns soft diagnostics with a nil error (for
	// example a fixture flagging "not seeded" or a partial SDK response), the
	// emitted record must be degraded and the emitted diagnostic must use the
	// dedicated "incomplete" code so operators can distinguish it from a hard
	// detail fetch failure.
	api := &fakeBedrockAgentsAPI{
		pages: []BedrockAgentsPage{{
			Agents: []BedrockAgentSummary{
				{AgentID: "AG1", AgentARN: "arn:aws:bedrock:us-east-1:123456789012:agent/AG1", AgentName: "agent", RoleARN: "arn:aws:iam::123456789012:role/r"},
			},
		}},
		details: map[string]BedrockAgentDetail{},
		detailIssues: map[string][]providers.SourceError{
			"AG1": {{
				Collector: "bedrock_agents",
				SourceID:  "AG1",
				Code:      "bedrock_agent_detail_not_seeded",
				Message:   "fixture detail not seeded",
			}},
		},
	}
	collector := NewBedrockAgentsCollector(api)
	assets, issues, err := collector.CollectWithDiagnostics(context.Background(), bedrockSampleScope())
	if err != nil {
		t.Fatalf("CollectWithDiagnostics: %v", err)
	}
	if len(assets) != 1 {
		t.Fatalf("expected one degraded asset, got %d", len(assets))
	}
	var record AIAgentIdentity
	if err := json.Unmarshal(assets[0].Payload, &record); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if record.CoverageStatus != "degraded" || record.Status != "degraded" {
		t.Fatalf("expected degraded coverage when detail adapter returns soft diagnostics, got %+v", record)
	}
	if !hasIssueCode(issues, "bedrock_agent_detail_incomplete") {
		t.Fatalf("expected incomplete diagnostic, got %v", issues)
	}
	if hasIssueCode(issues, "bedrock_agent_detail_failed") {
		t.Fatalf("soft diagnostics must not be reported as detail_failed, got %v", issues)
	}
}

func TestBedrockAgentsCollectorARNOnlySummarySkipsDetailFetch(t *testing.T) {
	// An ARN-only summary must not trigger GetAgentDetail(""); doing so would
	// produce a misleading per-agent diagnostic. Instead the collector emits a
	// degraded record with an explicit "detail skipped" diagnostic.
	api := &fakeBedrockAgentsAPI{
		pages: []BedrockAgentsPage{{
			Agents: []BedrockAgentSummary{
				{AgentARN: "arn:aws:bedrock:us-east-1:123456789012:agent/ARNONLY", AgentName: "arn-only", RoleARN: "arn:aws:iam::123456789012:role/r"},
			},
		}},
	}
	collector := NewBedrockAgentsCollector(api)
	assets, issues, err := collector.CollectWithDiagnostics(context.Background(), bedrockSampleScope())
	if err != nil {
		t.Fatalf("CollectWithDiagnostics: %v", err)
	}
	if api.detailCallCount != 0 {
		t.Fatalf("GetAgentDetail must not be invoked for ARN-only summaries (empty AgentID), called %d time(s) with ids=%v", api.detailCallCount, api.detailCallIDs)
	}
	if len(assets) != 1 {
		t.Fatalf("expected one degraded asset, got %d", len(assets))
	}
	var record AIAgentIdentity
	if err := json.Unmarshal(assets[0].Payload, &record); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if record.CoverageStatus != "degraded" {
		t.Fatalf("expected degraded coverage for ARN-only summary, got %+v", record)
	}
	if !hasIssueCode(issues, "bedrock_agent_detail_skipped_missing_id") {
		t.Fatalf("expected detail-skipped diagnostic, got %v", issues)
	}
	// And the misleading "GetAgent() failed" diagnostic must not appear.
	if hasIssueCode(issues, "bedrock_agent_detail_failed") {
		t.Fatalf("ARN-only summary should not produce a generic detail_failed diagnostic, got %v", issues)
	}
}

func TestBedrockAgentsCollectorMalformedAgentSkipped(t *testing.T) {
	api := &fakeBedrockAgentsAPI{
		pages: []BedrockAgentsPage{{
			Agents: []BedrockAgentSummary{{AgentName: "no-id"}},
		}},
	}
	collector := NewBedrockAgentsCollector(api)
	assets, issues, err := collector.CollectWithDiagnostics(context.Background(), bedrockSampleScope())
	if err != nil {
		t.Fatalf("CollectWithDiagnostics: %v", err)
	}
	if len(assets) != 0 {
		t.Fatalf("expected malformed agent to be skipped, got %d", len(assets))
	}
	if !hasIssueCode(issues, "malformed_bedrock_agent") {
		t.Fatalf("expected malformed-agent diagnostic, got %v", issues)
	}
}

func TestBedrockAgentsCollectorPageLimitGuard(t *testing.T) {
	pages := []BedrockAgentsPage{}
	for i := 0; i < 3; i++ {
		pages = append(pages, BedrockAgentsPage{
			Agents:    []BedrockAgentSummary{{AgentID: "A", AgentARN: "arn:aws:bedrock:us-east-1:123456789012:agent/A", AgentName: "a", RoleARN: "arn:aws:iam::123456789012:role/a"}},
			NextToken: "more",
		})
	}
	api := &fakeBedrockAgentsAPI{pages: pages, details: map[string]BedrockAgentDetail{"A": {}}}
	collector := NewBedrockAgentsCollector(api, WithBedrockAgentsMaxPages(2))
	_, issues, err := collector.CollectWithDiagnostics(context.Background(), bedrockSampleScope())
	if err == nil {
		t.Fatalf("expected error when exceeding max pages")
	}
	if !hasIssueCode(issues, "bedrock_agents_page_limit_exceeded") {
		t.Fatalf("expected page-limit diagnostic, got %v", issues)
	}
}

func hasIssueCode(issues []providers.SourceError, code string) bool {
	for _, issue := range issues {
		if issue.Code == code {
			return true
		}
	}
	return false
}
