package aws

import (
	"context"
	"errors"
	"strings"
	"testing"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrockagentcorecontrol"
	agentcoretypes "github.com/aws/aws-sdk-go-v2/service/bedrockagentcorecontrol/types"
)

type fakeAgentCoreGatewaySDKClient struct {
	listOutput    *bedrockagentcorecontrol.ListGatewaysOutput
	listErr       error
	detailOutput  *bedrockagentcorecontrol.GetGatewayOutput
	detailErr     error
	targetsOutput *bedrockagentcorecontrol.ListGatewayTargetsOutput
	targetsErr    error
	targetOutput  *bedrockagentcorecontrol.GetGatewayTargetOutput
	targetErr     error
}

func (f *fakeAgentCoreGatewaySDKClient) ListGateways(_ context.Context, _ *bedrockagentcorecontrol.ListGatewaysInput, _ ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.ListGatewaysOutput, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	if f.listOutput == nil {
		return &bedrockagentcorecontrol.ListGatewaysOutput{}, nil
	}
	return f.listOutput, nil
}

func (f *fakeAgentCoreGatewaySDKClient) GetGateway(_ context.Context, _ *bedrockagentcorecontrol.GetGatewayInput, _ ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.GetGatewayOutput, error) {
	if f.detailErr != nil {
		return nil, f.detailErr
	}
	if f.detailOutput == nil {
		return &bedrockagentcorecontrol.GetGatewayOutput{}, nil
	}
	return f.detailOutput, nil
}

func (f *fakeAgentCoreGatewaySDKClient) ListGatewayTargets(_ context.Context, _ *bedrockagentcorecontrol.ListGatewayTargetsInput, _ ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.ListGatewayTargetsOutput, error) {
	if f.targetsErr != nil {
		return nil, f.targetsErr
	}
	if f.targetsOutput == nil {
		return &bedrockagentcorecontrol.ListGatewayTargetsOutput{}, nil
	}
	return f.targetsOutput, nil
}

func (f *fakeAgentCoreGatewaySDKClient) GetGatewayTarget(_ context.Context, _ *bedrockagentcorecontrol.GetGatewayTargetInput, _ ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.GetGatewayTargetOutput, error) {
	if f.targetErr != nil {
		return nil, f.targetErr
	}
	if f.targetOutput == nil {
		return &bedrockagentcorecontrol.GetGatewayTargetOutput{}, nil
	}
	return f.targetOutput, nil
}

func TestSDKAgentCoreGatewayAPIMapsMCPToolsAndAuthMetadata(t *testing.T) {
	client := &fakeAgentCoreGatewaySDKClient{
		listOutput: &bedrockagentcorecontrol.ListGatewaysOutput{
			Items: []agentcoretypes.GatewaySummary{{
				GatewayId:      awsv2.String("gw-payments"),
				Name:           awsv2.String("payments-gateway"),
				AuthorizerType: agentcoretypes.AuthorizerTypeCustomJwt,
				ProtocolType:   agentcoretypes.GatewayProtocolTypeMcp,
				Status:         agentcoretypes.GatewayStatusReady,
			}},
		},
		detailOutput: &bedrockagentcorecontrol.GetGatewayOutput{
			GatewayId:      awsv2.String("gw-payments"),
			GatewayArn:     awsv2.String("arn:aws:bedrock-agentcore:us-east-1:123456789012:gateway/gw-payments"),
			Name:           awsv2.String("payments-gateway"),
			RoleArn:        awsv2.String("arn:aws:iam::123456789012:role/agentcore-gateway-payments"),
			AuthorizerType: agentcoretypes.AuthorizerTypeCustomJwt,
			ProtocolType:   agentcoretypes.GatewayProtocolTypeMcp,
			Status:         agentcoretypes.GatewayStatusReady,
			GatewayUrl:     awsv2.String("https://gateway.example.test/mcp"),
			PolicyEngineConfiguration: &agentcoretypes.GatewayPolicyEngineConfiguration{
				Arn:  awsv2.String("arn:aws:bedrock-agentcore:us-east-1:123456789012:policy-engine/payments"),
				Mode: agentcoretypes.GatewayPolicyEngineModeEnforce,
			},
			WorkloadIdentityDetails: &agentcoretypes.WorkloadIdentityDetails{
				WorkloadIdentityArn: awsv2.String("arn:aws:bedrock-agentcore:us-east-1:123456789012:workload-identity/gw-payments"),
			},
		},
		targetsOutput: &bedrockagentcorecontrol.ListGatewayTargetsOutput{
			Items: []agentcoretypes.TargetSummary{{
				TargetId: awsv2.String("target-payments"),
				Name:     awsv2.String("payments-mcp"),
				Status:   agentcoretypes.TargetStatusReady,
			}},
		},
		targetOutput: &bedrockagentcorecontrol.GetGatewayTargetOutput{
			TargetId:     awsv2.String("target-payments"),
			Name:         awsv2.String("payments-mcp"),
			GatewayArn:   awsv2.String("arn:aws:bedrock-agentcore:us-east-1:123456789012:gateway/gw-payments"),
			Status:       agentcoretypes.TargetStatusReady,
			ProtocolType: agentcoretypes.TargetProtocolTypeMcp,
			CredentialProviderConfigurations: []agentcoretypes.CredentialProviderConfiguration{{
				CredentialProviderType: agentcoretypes.CredentialProviderTypeOauth,
				CredentialProvider: &agentcoretypes.CredentialProviderMemberOauthCredentialProvider{
					Value: agentcoretypes.OAuthCredentialProvider{ProviderArn: awsv2.String("arn:aws:bedrock-agentcore:us-east-1:123456789012:oauth/payments")},
				},
			}},
			TargetConfiguration: &agentcoretypes.TargetConfigurationMemberMcp{
				Value: &agentcoretypes.McpTargetConfigurationMemberLambda{
					Value: agentcoretypes.McpLambdaTargetConfiguration{
						LambdaArn: awsv2.String("arn:aws:lambda:us-east-1:123456789012:function:payments-tools"),
						ToolSchema: &agentcoretypes.ToolSchemaMemberInlinePayload{Value: []agentcoretypes.ToolDefinition{
							{Name: awsv2.String("payments-case-search")},
							{Name: awsv2.String("fraud-review-action-group")},
						}},
					},
				},
			},
		},
	}

	page, err := NewSDKAgentCoreGatewayAPIFromClient(client, "123456789012", "us-east-1").ListAgentIdentities(context.Background(), "", 10)
	if err != nil {
		t.Fatalf("ListAgentIdentities: %v", err)
	}
	if len(page.Records) != 1 {
		t.Fatalf("expected one gateway record, got %+v", page.Records)
	}
	record := page.Records[0]
	if record.AgentType != "agent_gateway" || record.GatewayID != "gw-payments" {
		t.Fatalf("expected gateway identity record, got %+v", record)
	}
	if record.AuthMode != "custom_jwt" {
		t.Fatalf("expected custom_jwt auth mode, got %q", record.AuthMode)
	}
	if !containsGatewayTestString(record.ToolNames, "payments-case-search") || !containsGatewayTestString(record.ToolNames, "fraud-review-action-group") {
		t.Fatalf("expected MCP tool names from inline schema, got %+v", record.ToolNames)
	}
	if len(record.ToolNames) != 2 || containsGatewayTestString(record.ToolNames, "payments-mcp") {
		t.Fatalf("expected only schema-derived MCP tool names, got %+v", record.ToolNames)
	}
	if !containsGatewayTestString(record.CredentialReferenceRefs, "arn:aws:bedrock-agentcore:us-east-1:123456789012:oauth/payments") {
		t.Fatalf("expected credential provider ARN reference, got %+v", record.CredentialReferenceRefs)
	}
	if !containsGatewayTestString(record.AllowedActions, "payments-case-search") {
		t.Fatalf("expected allowed actions derived from tool names, got %+v", record.AllowedActions)
	}
	if record.Status != "ready" || record.CoverageStatus != "covered" {
		t.Fatalf("expected covered ready gateway record, got status=%q coverage=%q", record.Status, record.CoverageStatus)
	}
}

func TestSDKAgentCoreGatewayAPIDegradesOnTargetDescribeFailure(t *testing.T) {
	client := &fakeAgentCoreGatewaySDKClient{
		listOutput: &bedrockagentcorecontrol.ListGatewaysOutput{
			Items: []agentcoretypes.GatewaySummary{{
				GatewayId: awsv2.String("gw-payments"),
				Name:      awsv2.String("payments-gateway"),
				Status:    agentcoretypes.GatewayStatusReady,
			}},
		},
		detailOutput: &bedrockagentcorecontrol.GetGatewayOutput{
			GatewayId:  awsv2.String("gw-payments"),
			GatewayArn: awsv2.String("arn:aws:bedrock-agentcore:us-east-1:123456789012:gateway/gw-payments"),
			Name:       awsv2.String("payments-gateway"),
			RoleArn:    awsv2.String("arn:aws:iam::123456789012:role/agentcore-gateway-payments"),
			Status:     agentcoretypes.GatewayStatusReady,
		},
		targetsOutput: &bedrockagentcorecontrol.ListGatewayTargetsOutput{
			Items: []agentcoretypes.TargetSummary{{
				TargetId: awsv2.String("target-payments"),
				Name:     awsv2.String("payments-mcp"),
				Status:   agentcoretypes.TargetStatusReady,
			}},
		},
		targetErr: errors.New("throttled"),
	}

	page, err := NewSDKAgentCoreGatewayAPIFromClient(client, "123456789012", "us-east-1").ListAgentIdentities(context.Background(), "", 10)
	if err != nil {
		t.Fatalf("ListAgentIdentities: %v", err)
	}
	if len(page.Records) != 1 {
		t.Fatalf("expected retained degraded gateway record, got %+v", page.Records)
	}
	if page.Records[0].Status != "degraded" || page.Records[0].CoverageStatus != "degraded" {
		t.Fatalf("expected degraded gateway record, got %+v", page.Records[0])
	}
	if len(page.Diagnostics) != 1 || page.Diagnostics[0].Code != "ai_agent_gateway_target_describe_failed" {
		t.Fatalf("expected target describe diagnostic, got %+v", page.Diagnostics)
	}
	if len(page.Records[0].ToolNames) != 0 || len(page.Records[0].AllowedActions) != 0 {
		t.Fatalf("expected no synthetic tools for undescribed target, got tools=%+v actions=%+v", page.Records[0].ToolNames, page.Records[0].AllowedActions)
	}
}

func TestAPIGatewayTargetMetadataKeepsFiltersOutOfToolNames(t *testing.T) {
	tools, refs, caps, actions := apiGatewayTargetMetadata(agentcoretypes.ApiGatewayTargetConfiguration{
		RestApiId: awsv2.String("api-123"),
		Stage:     awsv2.String("prod"),
		ApiGatewayToolConfiguration: &agentcoretypes.ApiGatewayToolConfiguration{
			ToolOverrides: []agentcoretypes.ApiGatewayToolOverride{{
				Name:   awsv2.String("getOrder"),
				Method: agentcoretypes.RestApiMethodGet,
				Path:   awsv2.String("/orders/{id}"),
			}, {
				Method: agentcoretypes.RestApiMethodDelete,
				Path:   awsv2.String("/orders/{id}"),
			}},
			ToolFilters: []agentcoretypes.ApiGatewayToolFilter{{
				Methods:    []agentcoretypes.RestApiMethod{agentcoretypes.RestApiMethodPost},
				FilterPath: awsv2.String("/orders"),
			}},
		},
	})

	if !containsGatewayTestString(tools, "getOrder") {
		t.Fatalf("expected override name as tool, got %+v", tools)
	}
	if !containsGatewayTestString(tools, "DELETE /orders/{id}") {
		t.Fatalf("expected unnamed override method/path fallback as tool, got %+v", tools)
	}
	if containsGatewayTestString(tools, "POST /orders") {
		t.Fatalf("expected filter actions to stay out of tool names, got %+v", tools)
	}
	if !containsGatewayTestString(actions, "GET /orders/{id}") ||
		!containsGatewayTestString(actions, "DELETE /orders/{id}") ||
		!containsGatewayTestString(actions, "POST /orders") {
		t.Fatalf("expected override and filter actions, got %+v", actions)
	}
	if !containsGatewayTestString(refs, "api-123") || !containsGatewayTestString(refs, "prod") {
		t.Fatalf("expected API Gateway refs, got %+v", refs)
	}
	if !containsGatewayTestString(caps, "mcp_api_gateway") {
		t.Fatalf("expected API Gateway capability, got %+v", caps)
	}
}

func TestToolNamesFromInlineJSONExtractsOpenAPIOperationIDs(t *testing.T) {
	tools := toolNamesFromInlineJSON(`{
		"openapi": "3.0.1",
		"paths": {
			"/orders": {
				"get": {"operationId": "listOrders"},
				"post": {"operationId": "createOrder"},
				"parameters": [{"name": "tenant_id", "in": "header"}]
			},
			"/orders/{id}": {
				"get": {"operationId": "getOrder"}
			}
		}
	}`)

	for _, want := range []string{"listOrders", "createOrder", "getOrder"} {
		if !containsGatewayTestString(tools, want) {
			t.Fatalf("expected OpenAPI operationId %q in tools, got %+v", want, tools)
		}
	}
	if containsGatewayTestString(tools, "tenant_id") {
		t.Fatalf("expected non-operation schema names to stay out of tools, got %+v", tools)
	}
}

func TestSmithyModelMetadataExtractsOperationShapes(t *testing.T) {
	tools := smithyModelMetadata(&agentcoretypes.ApiSchemaConfigurationMemberInlinePayload{Value: `{
		"smithy": "2.0",
		"shapes": {
			"com.example#ListOrders": {"type": "operation"},
			"com.example#CreateOrder": {"type": "operation"},
			"com.example#Order": {"type": "structure"}
		}
	}`})

	if !containsGatewayTestString(tools, "ListOrders") || !containsGatewayTestString(tools, "CreateOrder") {
		t.Fatalf("expected Smithy operation shapes as tools, got %+v", tools)
	}
	if containsGatewayTestString(tools, "Order") || containsGatewayTestString(tools, "com.example#ListOrders") {
		t.Fatalf("expected only local operation shape names, got %+v", tools)
	}
}

func containsGatewayTestString(values []string, want string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) == want {
			return true
		}
	}
	return false
}
