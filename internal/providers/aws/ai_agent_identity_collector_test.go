package aws

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/providers"
	"github.com/identrail/identrail/internal/providers/awscontract"
)

type fakeAIAgentIdentityAPI struct {
	pages     []AIAgentIdentityPage
	tokens    []string
	pageSizes []int32
}

func (f *fakeAIAgentIdentityAPI) ListAgentIdentities(ctx context.Context, nextToken string, pageSize int32) (AIAgentIdentityPage, error) {
	f.tokens = append(f.tokens, nextToken)
	f.pageSizes = append(f.pageSizes, pageSize)
	if len(f.pages) == 0 {
		return AIAgentIdentityPage{}, nil
	}
	page := f.pages[0]
	f.pages = f.pages[1:]
	return page, nil
}

func TestAIAgentIdentityCollectorEmitsNormalizedPayloadSafeAssets(t *testing.T) {
	collectedAt := time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC)
	roleARN := "arn:aws:iam::123456789012:role/bedrock-payments-agent"
	agentARN := "arn:aws:bedrock:us-east-1:123456789012:agent/AGENT123"
	api := &fakeAIAgentIdentityAPI{pages: []AIAgentIdentityPage{{
		Records: []AIAgentIdentity{{
			ServiceCollectorRecord: awscontract.ServiceCollectorRecord{
				AccountID:    "123456789012",
				Region:       "us-east-1",
				Service:      "bedrock",
				WorkloadID:   agentARN,
				WorkloadName: "payments-agent",
				WorkloadType: "bedrock",
				RoleARN:      roleARN,
			},
			AgentID:                 "AGENT123",
			AgentARN:                agentARN,
			AgentName:               "payments-agent",
			AgentType:               "bedrock",
			Provider:                "amazon-bedrock",
			ModelID:                 "anthropic.claude-3-5-sonnet-20240620-v1:0",
			RuntimeRoleARN:          roleARN,
			ToolNames:               []string{"payments-search", "case-router", "payments-search"},
			MemoryEnabled:           true,
			MemoryStoreRefs:         []string{"memory-store/payments"},
			BrowserEnabled:          true,
			CodeInterpreterEnabled:  true,
			CapabilityNames:         []string{"tool_use", "memory", "browser", "code_interpreter"},
			CredentialReferenceRefs: []string{"secretsmanager:prod/ai/provider-key"},
			SensitiveBoundary:       "metadata_only",
		}},
		NextToken: "page-2",
	}, {
		Diagnostics: []providers.SourceError{{
			Collector: aiAgentIdentityCollectorName,
			SourceID:  "gateway/payments",
			Code:      "ai_agent_gateway_describe_failed",
			Message:   "gateway metadata could not be described",
			Retryable: true,
		}},
	}}}
	collector := NewAIAgentIdentityCollector(api, WithAIAgentIdentityPageSize(50), WithAIAgentIdentityClock(func() time.Time { return collectedAt }))

	assets, diagnostics, err := collector.CollectWithDiagnostics(context.Background(), AWSCollectorScope{
		TenantID:    "tenant-a",
		WorkspaceID: "workspace-a",
		ProjectID:   "project-a",
		ConnectorID: "aws-prod",
		ScanID:      "scan-1",
	})
	if err != nil {
		t.Fatalf("collect failed: %v", err)
	}
	if len(assets) != 1 {
		t.Fatalf("expected one asset, got %d", len(assets))
	}
	if assets[0].Kind != rawKindAIAgentIdentity {
		t.Fatalf("unexpected asset kind %q", assets[0].Kind)
	}
	if len(diagnostics) != 1 || diagnostics[0].Code != "ai_agent_gateway_describe_failed" {
		t.Fatalf("expected retained diagnostic, got %+v", diagnostics)
	}
	if got, want := strings.Join(api.tokens, ","), ",page-2"; got != want {
		t.Fatalf("expected pagination tokens %q, got %q", want, got)
	}

	var record AIAgentIdentity
	if err := json.Unmarshal(assets[0].Payload, &record); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if record.AgentType != "bedrock_agent" || record.RuntimeRoleName != "bedrock-payments-agent" {
		t.Fatalf("expected normalized agent type and role name, got %+v", record)
	}
	if record.TenantID != "tenant-a" || record.WorkspaceID != "workspace-a" || record.ProjectID != "project-a" {
		t.Fatalf("expected scope inherited, got %+v", record)
	}
	if record.ToolCount != 2 || strings.Join(record.ToolNames, ",") != "payments-search,case-router" {
		t.Fatalf("expected tool names deduped without sorting away fixture order, got %+v", record.ToolNames)
	}
	payload := strings.ToLower(string(assets[0].Payload))
	for _, forbidden := range []string{"prompt", "completion", "browser_page", "code_output", "secret_value", "payload_body"} {
		if strings.Contains(payload, forbidden) {
			t.Fatalf("payload leaked forbidden field marker %q: %s", forbidden, payload)
		}
	}
}

func TestAIAgentIdentityCollectorDedupesAndSkipsMalformedRecords(t *testing.T) {
	collectedAt := time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC)
	record := AIAgentIdentity{
		ServiceCollectorRecord: awscontract.ServiceCollectorRecord{
			AccountID: "123456789012",
			Region:    "us-east-1",
			Service:   "agentcore",
		},
		AgentID:        "runtime-1",
		AgentName:      "payments-runtime",
		AgentType:      "agentcore",
		RuntimeRoleARN: "arn:aws:iam::123456789012:role/agentcore-payments-runtime",
	}
	api := &fakeAIAgentIdentityAPI{pages: []AIAgentIdentityPage{{
		Records: []AIAgentIdentity{
			record,
			record,
			{AgentType: "custom_agent"},
		},
	}}}
	collector := NewAIAgentIdentityCollector(api, WithAIAgentIdentityClock(func() time.Time { return collectedAt }))

	assets, diagnostics, err := collector.CollectWithDiagnostics(context.Background(), AWSCollectorScope{
		TenantID:    "tenant-a",
		WorkspaceID: "workspace-a",
		ProjectID:   "project-a",
		ConnectorID: "aws-prod",
		ScanID:      "scan-1",
	})
	if err != nil {
		t.Fatalf("collect failed: %v", err)
	}
	if len(assets) != 1 {
		t.Fatalf("expected duplicate and malformed records to collapse to one asset, got %d", len(assets))
	}
	if len(diagnostics) != 1 || diagnostics[0].Code != "malformed_ai_agent_identity" {
		t.Fatalf("expected malformed diagnostic, got %+v", diagnostics)
	}
}
