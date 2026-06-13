package aws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/bedrockagentcorecontrol"
	agentcoretypes "github.com/aws/aws-sdk-go-v2/service/bedrockagentcorecontrol/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/identrail/identrail/internal/providers"
	"github.com/identrail/identrail/internal/providers/awscontract"
	"github.com/identrail/identrail/internal/textutil"
)

type AgentCoreGatewaySDKClient interface {
	ListGateways(ctx context.Context, params *bedrockagentcorecontrol.ListGatewaysInput, optFns ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.ListGatewaysOutput, error)
	GetGateway(ctx context.Context, params *bedrockagentcorecontrol.GetGatewayInput, optFns ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.GetGatewayOutput, error)
	ListGatewayTargets(ctx context.Context, params *bedrockagentcorecontrol.ListGatewayTargetsInput, optFns ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.ListGatewayTargetsOutput, error)
	GetGatewayTarget(ctx context.Context, params *bedrockagentcorecontrol.GetGatewayTargetInput, optFns ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.GetGatewayTargetOutput, error)
}

type SDKAgentCoreGatewayAPI struct {
	client    AgentCoreGatewaySDKClient
	accountID string
	region    string
}

var _ AIAgentIdentityAPI = (*SDKAgentCoreGatewayAPI)(nil)

func NewSDKAgentCoreAIAgentIdentityAPI(region string, profile string, accountID string) (AIAgentIdentityAPI, error) {
	return NewSDKAgentCoreAIAgentIdentityAPIWithContext(context.Background(), region, profile, accountID)
}

func NewSDKAgentCoreAIAgentIdentityAPIWithContext(ctx context.Context, region string, profile string, accountID string) (AIAgentIdentityAPI, error) {
	cfg, err := loadSDKConfig(ctx, region, profile)
	if err != nil {
		return nil, err
	}
	resolvedAccountID, err := awsCallerAccountID(ctx, cfg, accountID)
	if err != nil {
		return nil, err
	}
	resolvedRegion := firstNonEmptyAWSValue(strings.TrimSpace(region), strings.TrimSpace(cfg.Region))
	client := bedrockagentcorecontrol.NewFromConfig(cfg)
	return NewSDKAgentCoreAIAgentIdentityAPIFromClient(client, client, client, resolvedAccountID, resolvedRegion), nil
}

func NewSDKAgentCoreAIAgentIdentityAPIFromAssumeRole(ctx context.Context, region string, profile string, roleARN string, externalID string, sessionName string, accountID string) (AIAgentIdentityAPI, error) {
	cfg, err := loadSDKConfig(ctx, region, profile)
	if err != nil {
		return nil, err
	}
	trimmedRoleARN := strings.TrimSpace(roleARN)
	if trimmedRoleARN == "" {
		return nil, fmt.Errorf("aws connector role arn is required")
	}
	options := []func(*stscreds.AssumeRoleOptions){
		func(options *stscreds.AssumeRoleOptions) {
			options.RoleSessionName = textutil.FirstNonEmpty(strings.TrimSpace(sessionName), "identrail-recurring-scan")
		},
	}
	if trimmedExternalID := strings.TrimSpace(externalID); trimmedExternalID != "" {
		options = append(options, func(options *stscreds.AssumeRoleOptions) {
			options.ExternalID = &trimmedExternalID
		})
	}
	cfg.Credentials = awsv2.NewCredentialsCache(stscreds.NewAssumeRoleProvider(sts.NewFromConfig(cfg), trimmedRoleARN, options...))
	resolvedAccountID, err := awsCallerAccountID(ctx, cfg, accountID)
	if err != nil {
		return nil, err
	}
	resolvedRegion := firstNonEmptyAWSValue(strings.TrimSpace(region), strings.TrimSpace(cfg.Region))
	client := bedrockagentcorecontrol.NewFromConfig(cfg)
	return NewSDKAgentCoreAIAgentIdentityAPIFromClient(client, client, client, resolvedAccountID, resolvedRegion), nil
}

func NewSDKAgentCoreAIAgentIdentityAPIFromClient(runtimeClient AgentCoreRuntimeSDKClient, gatewayClient AgentCoreGatewaySDKClient, capabilitiesClient AgentCoreCapabilitiesSDKClient, accountID string, region string) AIAgentIdentityAPI {
	return NewCompositeAIAgentIdentityAPI(
		NewSDKAgentCoreRuntimeAPIFromClient(runtimeClient, accountID, region),
		NewSDKAgentCoreGatewayAPIFromClient(gatewayClient, accountID, region),
		NewSDKAgentCoreCapabilitiesAPIFromClient(capabilitiesClient, accountID, region),
	)
}

func NewSDKAgentCoreGatewayAPIFromClient(client AgentCoreGatewaySDKClient, accountID string, region string) AIAgentIdentityAPI {
	return &SDKAgentCoreGatewayAPI{
		client:    client,
		accountID: strings.TrimSpace(accountID),
		region:    strings.TrimSpace(region),
	}
}

func (a *SDKAgentCoreGatewayAPI) ListAgentIdentities(ctx context.Context, nextToken string, pageSize int32) (AIAgentIdentityPage, error) {
	if a.client == nil {
		return AIAgentIdentityPage{}, fmt.Errorf("agentcore gateway sdk client is required")
	}
	input := &bedrockagentcorecontrol.ListGatewaysInput{
		MaxResults: awsv2.Int32(agentCoreSDKPageSize(pageSize)),
	}
	if token := strings.TrimSpace(nextToken); token != "" {
		input.NextToken = awsv2.String(token)
	}
	output, err := a.client.ListGateways(ctx, input)
	if err != nil {
		return AIAgentIdentityPage{}, err
	}
	records := make([]AIAgentIdentity, 0, len(output.Items))
	diagnostics := []providers.SourceError{}
	for _, summary := range output.Items {
		if err := ctx.Err(); err != nil {
			return AIAgentIdentityPage{}, err
		}
		record, gatewayDiagnostics, err := a.gatewayRecord(ctx, summary)
		if err != nil {
			return AIAgentIdentityPage{}, err
		}
		diagnostics = append(diagnostics, gatewayDiagnostics...)
		if strings.TrimSpace(record.GatewayID) == "" && strings.TrimSpace(record.GatewayARN) == "" {
			continue
		}
		records = append(records, record)
	}
	return AIAgentIdentityPage{
		Records:     records,
		NextToken:   strings.TrimSpace(awsv2.ToString(output.NextToken)),
		Diagnostics: diagnostics,
	}, nil
}

func (a *SDKAgentCoreGatewayAPI) gatewayRecord(ctx context.Context, summary agentcoretypes.GatewaySummary) (AIAgentIdentity, []providers.SourceError, error) {
	diagnostics := []providers.SourceError{}
	gatewayID := strings.TrimSpace(awsv2.ToString(summary.GatewayId))
	gatewayName := firstNonEmptyAWSValue(strings.TrimSpace(awsv2.ToString(summary.Name)), gatewayID)
	if gatewayID == "" {
		diagnostics = append(diagnostics, providers.SourceError{
			Collector: aiAgentIdentityCollectorName,
			Code:      "ai_agent_gateway_malformed",
			Message:   "skipped AgentCore gateway without a stable identifier",
			Retryable: false,
		})
		return AIAgentIdentity{}, diagnostics, nil
	}

	detail, detailErr := a.describeGateway(ctx, gatewayID)
	if errors.Is(detailErr, context.Canceled) || errors.Is(detailErr, context.DeadlineExceeded) {
		return AIAgentIdentity{}, diagnostics, detailErr
	}
	if detailErr != nil {
		diagnostics = append(diagnostics, providers.SourceError{
			Collector: aiAgentIdentityCollectorName,
			SourceID:  gatewayID,
			Code:      "ai_agent_gateway_describe_failed",
			Message:   fmt.Sprintf("AgentCore gateway %s could not be described: %v", gatewayID, detailErr),
			Retryable: isRetryable(detailErr),
		})
	}

	targets, targetDiagnostics, targetErr := a.gatewayTargets(ctx, gatewayID)
	diagnostics = append(diagnostics, targetDiagnostics...)
	if errors.Is(targetErr, context.Canceled) || errors.Is(targetErr, context.DeadlineExceeded) {
		return AIAgentIdentity{}, diagnostics, targetErr
	}
	if targetErr != nil {
		diagnostics = append(diagnostics, providers.SourceError{
			Collector: aiAgentIdentityCollectorName,
			SourceID:  gatewayID,
			Code:      "ai_agent_gateway_target_list_failed",
			Message:   fmt.Sprintf("AgentCore gateway %s targets could not be listed: %v", gatewayID, targetErr),
			Retryable: isRetryable(targetErr),
		})
	}

	gatewayARN := strings.TrimSpace(awsv2.ToString(detail.GatewayArn))
	roleARN := strings.TrimSpace(awsv2.ToString(detail.RoleArn))
	workloadIdentityARN := ""
	if detail.WorkloadIdentityDetails != nil {
		workloadIdentityARN = strings.TrimSpace(awsv2.ToString(detail.WorkloadIdentityDetails.WorkloadIdentityArn))
	}
	targetMetadata := summarizeGatewayTargets(targets)
	resourceRefs := normalizeStringList(append([]string{
		gatewayARN,
		strings.TrimSpace(awsv2.ToString(detail.GatewayUrl)),
		strings.TrimSpace(awsv2.ToString(detail.KmsKeyArn)),
		gatewayPolicyEngineARN(detail.PolicyEngineConfiguration),
		workloadIdentityARN,
	}, targetMetadata.resourceRefs...))
	capabilities := normalizeStringList(append([]string{
		"gateway",
		"tool_routing",
		gatewayProtocolCapability(firstNonEmptyAWSValue(string(detail.ProtocolType), string(summary.ProtocolType))),
		gatewayAuthCapability(firstNonEmptyAWSValue(string(detail.AuthorizerType), string(summary.AuthorizerType))),
		gatewayPolicyModeCapability(detail.PolicyEngineConfiguration),
	}, targetMetadata.capabilities...))
	record := AIAgentIdentity{
		ServiceCollectorRecord: awscontract.ServiceCollectorRecord{
			AccountID: strings.TrimSpace(a.accountID),
			Region:    strings.TrimSpace(a.region),
		},
		AgentID:                 gatewayID,
		AgentARN:                gatewayARN,
		AgentName:               gatewayName,
		AgentType:               "agent_gateway",
		Provider:                "amazon-bedrock-agentcore",
		RuntimeRoleARN:          roleARN,
		RuntimeRoleName:         roleNameFromARN(roleARN),
		RuntimeRoleAccountID:    roleAccountIDFromARN(roleARN),
		WorkloadIdentityARN:     workloadIdentityARN,
		GatewayID:               gatewayID,
		GatewayARN:              gatewayARN,
		ToolNames:               normalizeStringList(targetMetadata.toolNames),
		CapabilityNames:         capabilities,
		CredentialReferenceRefs: normalizeStringList(targetMetadata.credentialRefs),
		ResourceReferenceRefs:   resourceRefs,
		AuthMode:                strings.TrimSpace(strings.ToLower(firstNonEmptyAWSValue(string(detail.AuthorizerType), string(summary.AuthorizerType)))),
		AllowedActions:          normalizeStringList(targetMetadata.allowedActions),
		ToolTargetRefs:          normalizeStringList(targetMetadata.targetRefs),
		ServerProtocol:          strings.TrimSpace(strings.ToLower(firstNonEmptyAWSValue(string(detail.ProtocolType), string(summary.ProtocolType)))),
		SensitiveBoundary:       "metadata_only",
		CoverageStatus:          "covered",
		Status:                  gatewayStatus(firstNonEmptyAWSValue(string(detail.Status), string(summary.Status))),
	}
	if detailErr != nil || targetErr != nil || targetMetadata.degraded {
		record.CoverageStatus = "degraded"
		record.Status = "degraded"
		record.CoverageReason = firstNonEmptyAWSValue(
			strings.Join(normalizeStringList(detail.StatusReasons), "; "),
			"AgentCore gateway metadata was partially collected",
		)
	}
	record.Confidence = aiAgentIdentityConfidence(record)
	record.Source = "agentcore_gateway_metadata"
	record.Service = "agentcore"
	record.EvidenceRef = firstNonEmptyAWSValue(record.GatewayARN, record.AgentARN, record.GatewayID, record.AgentID)
	record.CollectorName = aiAgentIdentityCollectorName
	return record, diagnostics, nil
}

func (a *SDKAgentCoreGatewayAPI) describeGateway(ctx context.Context, gatewayID string) (bedrockagentcorecontrol.GetGatewayOutput, error) {
	output, err := a.client.GetGateway(ctx, &bedrockagentcorecontrol.GetGatewayInput{GatewayIdentifier: awsv2.String(gatewayID)})
	if err != nil {
		return bedrockagentcorecontrol.GetGatewayOutput{}, err
	}
	if output == nil {
		return bedrockagentcorecontrol.GetGatewayOutput{}, fmt.Errorf("gateway %s returned no metadata", gatewayID)
	}
	return *output, nil
}

func (a *SDKAgentCoreGatewayAPI) gatewayTargets(ctx context.Context, gatewayID string) ([]gatewayTargetMetadata, []providers.SourceError, error) {
	input := &bedrockagentcorecontrol.ListGatewayTargetsInput{
		GatewayIdentifier: awsv2.String(gatewayID),
		MaxResults:        awsv2.Int32(agentCoreSDKPageSize(defaultPageSize)),
	}
	targets := []gatewayTargetMetadata{}
	diagnostics := []providers.SourceError{}
	for {
		if err := ctx.Err(); err != nil {
			return targets, diagnostics, err
		}
		output, err := a.client.ListGatewayTargets(ctx, input)
		if err != nil {
			return targets, diagnostics, err
		}
		for _, summary := range output.Items {
			targetID := strings.TrimSpace(awsv2.ToString(summary.TargetId))
			if targetID == "" {
				continue
			}
			detail, err := a.client.GetGatewayTarget(ctx, &bedrockagentcorecontrol.GetGatewayTargetInput{
				GatewayIdentifier: awsv2.String(gatewayID),
				TargetId:          awsv2.String(targetID),
			})
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return targets, diagnostics, err
			}
			if err != nil {
				diagnostics = append(diagnostics, providers.SourceError{
					Collector: aiAgentIdentityCollectorName,
					SourceID:  gatewayID + "/" + targetID,
					Code:      "ai_agent_gateway_target_describe_failed",
					Message:   fmt.Sprintf("AgentCore gateway target %s/%s could not be described: %v", gatewayID, targetID, err),
					Retryable: isRetryable(err),
				})
				targets = append(targets, gatewayTargetMetadata{
					targetID:     targetID,
					targetName:   firstNonEmptyAWSValue(awsv2.ToString(summary.Name), targetID),
					status:       targetStatus(summary.Status),
					targetRefs:   []string{targetID},
					capabilities: []string{"gateway_target"},
					degraded:     true,
				})
				continue
			}
			if detail == nil {
				continue
			}
			targets = append(targets, gatewayTargetMetadataFromDetail(*detail))
		}
		nextToken := strings.TrimSpace(awsv2.ToString(output.NextToken))
		if nextToken == "" {
			break
		}
		input.NextToken = awsv2.String(nextToken)
	}
	return targets, diagnostics, nil
}

type gatewayTargetMetadata struct {
	targetID       string
	targetName     string
	status         string
	toolNames      []string
	capabilities   []string
	credentialRefs []string
	resourceRefs   []string
	allowedActions []string
	targetRefs     []string
	degraded       bool
}

func gatewayTargetMetadataFromDetail(detail bedrockagentcorecontrol.GetGatewayTargetOutput) gatewayTargetMetadata {
	targetID := strings.TrimSpace(awsv2.ToString(detail.TargetId))
	targetName := firstNonEmptyAWSValue(awsv2.ToString(detail.Name), targetID)
	metadata := gatewayTargetMetadata{
		targetID:     targetID,
		targetName:   targetName,
		status:       targetStatus(detail.Status),
		targetRefs:   []string{targetID},
		capabilities: []string{"gateway_target", "target_protocol_" + strings.ToLower(string(detail.ProtocolType))},
		resourceRefs: []string{awsv2.ToString(detail.GatewayArn)},
		degraded:     targetStatus(detail.Status) != "ready",
	}
	metadata.credentialRefs = append(metadata.credentialRefs, gatewayCredentialRefs(detail.CredentialProviderConfigurations)...)
	metadata.capabilities = append(metadata.capabilities, gatewayCredentialCapabilities(detail.CredentialProviderConfigurations)...)
	tools, refs, caps, actions := gatewayTargetConfigurationMetadata(detail.TargetConfiguration)
	metadata.toolNames = append(metadata.toolNames, tools...)
	metadata.resourceRefs = append(metadata.resourceRefs, refs...)
	metadata.capabilities = append(metadata.capabilities, caps...)
	metadata.allowedActions = append(metadata.allowedActions, actions...)
	if len(normalizeOrderedStringList(metadata.toolNames)) == 0 {
		metadata.toolNames = normalizeOrderedStringList([]string{targetName})
	}
	if len(normalizeOrderedStringList(metadata.allowedActions)) == 0 {
		metadata.allowedActions = normalizeOrderedStringList([]string{targetName})
	}
	return metadata
}

func summarizeGatewayTargets(targets []gatewayTargetMetadata) gatewayTargetMetadata {
	summary := gatewayTargetMetadata{}
	for _, target := range targets {
		summary.toolNames = append(summary.toolNames, target.toolNames...)
		summary.capabilities = append(summary.capabilities, target.capabilities...)
		summary.credentialRefs = append(summary.credentialRefs, target.credentialRefs...)
		summary.resourceRefs = append(summary.resourceRefs, target.resourceRefs...)
		summary.allowedActions = append(summary.allowedActions, target.allowedActions...)
		summary.targetRefs = append(summary.targetRefs, target.targetRefs...)
		summary.degraded = summary.degraded || target.degraded
	}
	return summary
}

func gatewayTargetConfigurationMetadata(config agentcoretypes.TargetConfiguration) ([]string, []string, []string, []string) {
	switch typed := config.(type) {
	case *agentcoretypes.TargetConfigurationMemberMcp:
		tools, refs, caps, actions := mcpTargetConfigurationMetadata(typed.Value)
		return tools, refs, append([]string{"mcp"}, caps...), actions
	case *agentcoretypes.TargetConfigurationMemberHttp:
		refs, caps := httpTargetConfigurationMetadata(typed.Value)
		return nil, refs, append([]string{"http_target"}, caps...), nil
	default:
		return nil, nil, nil, nil
	}
}

func mcpTargetConfigurationMetadata(config agentcoretypes.McpTargetConfiguration) ([]string, []string, []string, []string) {
	switch typed := config.(type) {
	case *agentcoretypes.McpTargetConfigurationMemberLambda:
		tools, refs := toolSchemaMetadata(typed.Value.ToolSchema)
		return tools, append(refs, awsv2.ToString(typed.Value.LambdaArn)), []string{"mcp_lambda"}, tools
	case *agentcoretypes.McpTargetConfigurationMemberMcpServer:
		tools, refs := mcpToolSchemaMetadata(typed.Value.McpToolSchema)
		return tools, append(refs, awsv2.ToString(typed.Value.Endpoint)), []string{"mcp_server", "mcp_listing_" + strings.ToLower(string(typed.Value.ListingMode))}, tools
	case *agentcoretypes.McpTargetConfigurationMemberApiGateway:
		return apiGatewayTargetMetadata(typed.Value)
	case *agentcoretypes.McpTargetConfigurationMemberOpenApiSchema:
		return apiSchemaMetadata(typed.Value), apiSchemaRefs(typed.Value), []string{"mcp_openapi_schema"}, apiSchemaMetadata(typed.Value)
	case *agentcoretypes.McpTargetConfigurationMemberSmithyModel:
		return smithyModelMetadata(typed.Value), apiSchemaRefs(typed.Value), []string{"mcp_smithy_model"}, smithyModelMetadata(typed.Value)
	default:
		return nil, nil, nil, nil
	}
}

func httpTargetConfigurationMetadata(config agentcoretypes.HttpTargetConfiguration) ([]string, []string) {
	switch typed := config.(type) {
	case *agentcoretypes.HttpTargetConfigurationMemberAgentcoreRuntime:
		_ = typed
		return nil, []string{"agentcore_runtime_target"}
	default:
		return nil, nil
	}
}

func apiGatewayTargetMetadata(config agentcoretypes.ApiGatewayTargetConfiguration) ([]string, []string, []string, []string) {
	refs := []string{awsv2.ToString(config.RestApiId), awsv2.ToString(config.Stage)}
	tools := []string{}
	actions := []string{}
	if config.ApiGatewayToolConfiguration != nil {
		for _, override := range config.ApiGatewayToolConfiguration.ToolOverrides {
			action := strings.TrimSpace(string(override.Method) + " " + awsv2.ToString(override.Path))
			if name := strings.TrimSpace(awsv2.ToString(override.Name)); name != "" {
				tools = append(tools, name)
			} else if action != "" {
				tools = append(tools, action)
			}
			actions = append(actions, action)
		}
		for _, filter := range config.ApiGatewayToolConfiguration.ToolFilters {
			for _, method := range filter.Methods {
				action := strings.TrimSpace(string(method) + " " + awsv2.ToString(filter.FilterPath))
				actions = append(actions, action)
			}
		}
	}
	return tools, refs, []string{"mcp_api_gateway"}, actions
}

func apiSchemaMetadata(config agentcoretypes.ApiSchemaConfiguration) []string {
	switch typed := config.(type) {
	case *agentcoretypes.ApiSchemaConfigurationMemberInlinePayload:
		return toolNamesFromInlineJSON(awsv2.ToString(&typed.Value))
	default:
		return nil
	}
}

func apiSchemaRefs(config agentcoretypes.ApiSchemaConfiguration) []string {
	switch typed := config.(type) {
	case *agentcoretypes.ApiSchemaConfigurationMemberS3:
		return []string{s3ConfigurationRef(typed.Value)}
	default:
		return nil
	}
}

func smithyModelMetadata(config agentcoretypes.ApiSchemaConfiguration) []string {
	switch typed := config.(type) {
	case *agentcoretypes.ApiSchemaConfigurationMemberInlinePayload:
		return smithyOperationNamesFromInlineJSON(awsv2.ToString(&typed.Value))
	default:
		return nil
	}
}

func toolSchemaMetadata(schema agentcoretypes.ToolSchema) ([]string, []string) {
	switch typed := schema.(type) {
	case *agentcoretypes.ToolSchemaMemberInlinePayload:
		tools := make([]string, 0, len(typed.Value))
		for _, tool := range typed.Value {
			tools = append(tools, awsv2.ToString(tool.Name))
		}
		return tools, nil
	case *agentcoretypes.ToolSchemaMemberS3:
		return nil, []string{s3ConfigurationRef(typed.Value)}
	default:
		return nil, nil
	}
}

func mcpToolSchemaMetadata(schema agentcoretypes.McpToolSchemaConfiguration) ([]string, []string) {
	switch typed := schema.(type) {
	case *agentcoretypes.McpToolSchemaConfigurationMemberInlinePayload:
		return toolNamesFromInlineJSON(typed.Value), nil
	case *agentcoretypes.McpToolSchemaConfigurationMemberS3:
		return nil, []string{s3ConfigurationRef(typed.Value)}
	default:
		return nil, nil
	}
}

func toolNamesFromInlineJSON(raw string) []string {
	var value any
	if strings.TrimSpace(raw) == "" || json.Unmarshal([]byte(raw), &value) != nil {
		return nil
	}
	names := []string{}
	names = append(names, openAPIOperationIDs(value)...)
	var visit func(any, string)
	visit = func(node any, parent string) {
		switch typed := node.(type) {
		case map[string]any:
			if strings.EqualFold(parent, "tools") {
				if name, ok := typed["name"].(string); ok {
					names = append(names, name)
				}
			}
			for key, child := range typed {
				visit(child, key)
			}
		case []any:
			for _, child := range typed {
				visit(child, parent)
			}
		}
	}
	visit(value, "")
	return normalizeStringList(names)
}

func smithyOperationNamesFromInlineJSON(raw string) []string {
	var value any
	if strings.TrimSpace(raw) == "" || json.Unmarshal([]byte(raw), &value) != nil {
		return nil
	}
	root, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	shapes, ok := root["shapes"].(map[string]any)
	if !ok {
		return nil
	}
	names := []string{}
	for shapeID, rawShape := range shapes {
		shape, ok := rawShape.(map[string]any)
		if !ok {
			continue
		}
		shapeType, _ := shape["type"].(string)
		if !strings.EqualFold(strings.TrimSpace(shapeType), "operation") {
			continue
		}
		names = append(names, smithyShapeName(shapeID))
	}
	return normalizeStringList(names)
}

func smithyShapeName(shapeID string) string {
	trimmed := strings.TrimSpace(shapeID)
	if trimmed == "" {
		return ""
	}
	if hash := strings.LastIndex(trimmed, "#"); hash >= 0 && hash < len(trimmed)-1 {
		return strings.TrimSpace(trimmed[hash+1:])
	}
	return trimmed
}

func openAPIOperationIDs(value any) []string {
	root, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	paths, ok := root["paths"].(map[string]any)
	if !ok {
		return nil
	}
	names := []string{}
	for _, rawPathItem := range paths {
		pathItem, ok := rawPathItem.(map[string]any)
		if !ok {
			continue
		}
		for method, rawOperation := range pathItem {
			if !isOpenAPIOperationMethod(method) {
				continue
			}
			operation, ok := rawOperation.(map[string]any)
			if !ok {
				continue
			}
			if operationID, ok := operation["operationId"].(string); ok {
				names = append(names, operationID)
			}
		}
	}
	return names
}

func isOpenAPIOperationMethod(method string) bool {
	switch strings.ToLower(strings.TrimSpace(method)) {
	case "get", "put", "post", "delete", "options", "head", "patch", "trace":
		return true
	default:
		return false
	}
}

func gatewayCredentialRefs(configs []agentcoretypes.CredentialProviderConfiguration) []string {
	refs := []string{}
	for _, config := range configs {
		switch provider := config.CredentialProvider.(type) {
		case *agentcoretypes.CredentialProviderMemberApiKeyCredentialProvider:
			refs = append(refs, awsv2.ToString(provider.Value.ProviderArn))
		case *agentcoretypes.CredentialProviderMemberOauthCredentialProvider:
			refs = append(refs, awsv2.ToString(provider.Value.ProviderArn))
		case *agentcoretypes.CredentialProviderMemberIamCredentialProvider:
			refs = append(refs, "iam:"+firstNonEmptyAWSValue(awsv2.ToString(provider.Value.Service), "service")+":"+firstNonEmptyAWSValue(awsv2.ToString(provider.Value.Region), "region"))
		}
	}
	return refs
}

func gatewayCredentialCapabilities(configs []agentcoretypes.CredentialProviderConfiguration) []string {
	capabilities := []string{}
	for _, config := range configs {
		if credentialType := strings.TrimSpace(strings.ToLower(string(config.CredentialProviderType))); credentialType != "" {
			capabilities = append(capabilities, "target_auth_"+credentialType)
		}
	}
	return capabilities
}

func s3ConfigurationRef(config agentcoretypes.S3Configuration) string {
	return firstNonEmptyAWSValue(awsv2.ToString(config.Uri), awsv2.ToString(config.BucketOwnerAccountId))
}

func gatewayPolicyEngineARN(config *agentcoretypes.GatewayPolicyEngineConfiguration) string {
	if config == nil {
		return ""
	}
	return awsv2.ToString(config.Arn)
}

func gatewayPolicyModeCapability(config *agentcoretypes.GatewayPolicyEngineConfiguration) string {
	if config == nil {
		return ""
	}
	mode := strings.TrimSpace(strings.ToLower(string(config.Mode)))
	if mode == "" {
		return ""
	}
	return "policy_engine_" + mode
}

func gatewayProtocolCapability(protocol string) string {
	if strings.TrimSpace(protocol) == "" {
		return ""
	}
	return "gateway_protocol_" + strings.ToLower(strings.TrimSpace(protocol))
}

func gatewayAuthCapability(authMode string) string {
	if strings.TrimSpace(authMode) == "" {
		return ""
	}
	return "gateway_auth_" + strings.ToLower(strings.TrimSpace(authMode))
}

func gatewayStatus(status string) string {
	switch strings.ToUpper(strings.TrimSpace(status)) {
	case "", "READY":
		return "ready"
	default:
		return "degraded"
	}
}

func targetStatus(status agentcoretypes.TargetStatus) string {
	switch strings.ToUpper(strings.TrimSpace(string(status))) {
	case "", "READY":
		return "ready"
	default:
		return "degraded"
	}
}
