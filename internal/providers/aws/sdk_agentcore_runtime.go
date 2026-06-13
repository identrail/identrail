package aws

import (
	"context"
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

// AgentCoreRuntimeSDKClient defines the AgentCore Control API calls required by
// the live runtime identity adapter.
type AgentCoreRuntimeSDKClient interface {
	ListAgentRuntimes(ctx context.Context, params *bedrockagentcorecontrol.ListAgentRuntimesInput, optFns ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.ListAgentRuntimesOutput, error)
	GetAgentRuntime(ctx context.Context, params *bedrockagentcorecontrol.GetAgentRuntimeInput, optFns ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.GetAgentRuntimeOutput, error)
	ListAgentRuntimeEndpoints(ctx context.Context, params *bedrockagentcorecontrol.ListAgentRuntimeEndpointsInput, optFns ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.ListAgentRuntimeEndpointsOutput, error)
}

// SDKAgentCoreRuntimeAPI adapts the AgentCore control plane into the generic
// AIAgentIdentity API contract.
type SDKAgentCoreRuntimeAPI struct {
	client    AgentCoreRuntimeSDKClient
	accountID string
	region    string
}

var _ AIAgentIdentityAPI = (*SDKAgentCoreRuntimeAPI)(nil)

// NewSDKAgentCoreRuntimeAPI constructs the runtime API using ambient AWS
// credentials.
func NewSDKAgentCoreRuntimeAPI(region string, profile string, accountID string) (AIAgentIdentityAPI, error) {
	return NewSDKAgentCoreRuntimeAPIWithContext(context.Background(), region, profile, accountID)
}

// NewSDKAgentCoreRuntimeAPIWithContext constructs the runtime API using the
// caller-provided context for AWS configuration loading.
func NewSDKAgentCoreRuntimeAPIWithContext(ctx context.Context, region string, profile string, accountID string) (AIAgentIdentityAPI, error) {
	cfg, err := loadSDKConfig(ctx, region, profile)
	if err != nil {
		return nil, err
	}
	resolvedAccountID, err := awsCallerAccountID(ctx, cfg, accountID)
	if err != nil {
		return nil, err
	}
	resolvedRegion := firstNonEmptyAWSValue(strings.TrimSpace(region), strings.TrimSpace(cfg.Region))
	return NewSDKAgentCoreRuntimeAPIFromClient(bedrockagentcorecontrol.NewFromConfig(cfg), resolvedAccountID, resolvedRegion), nil
}

// NewSDKAgentCoreRuntimeAPIFromAssumeRole constructs the runtime API after
// assuming the connector role.
func NewSDKAgentCoreRuntimeAPIFromAssumeRole(ctx context.Context, region string, profile string, roleARN string, externalID string, sessionName string, accountID string) (AIAgentIdentityAPI, error) {
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
	return NewSDKAgentCoreRuntimeAPIFromClient(bedrockagentcorecontrol.NewFromConfig(cfg), resolvedAccountID, resolvedRegion), nil
}

// NewSDKAgentCoreRuntimeAPIFromClient creates a test seam around a provided
// AgentCore client.
func NewSDKAgentCoreRuntimeAPIFromClient(client AgentCoreRuntimeSDKClient, accountID string, region string) AIAgentIdentityAPI {
	return &SDKAgentCoreRuntimeAPI{
		client:    client,
		accountID: strings.TrimSpace(accountID),
		region:    strings.TrimSpace(region),
	}
}

// ListAgentIdentities lists AgentCore runtimes and enriches each runtime with
// endpoint and workload-identity metadata while preserving partial-failure
// diagnostics for incomplete sub-calls.
func (a *SDKAgentCoreRuntimeAPI) ListAgentIdentities(ctx context.Context, nextToken string, pageSize int32) (AIAgentIdentityPage, error) {
	if a.client == nil {
		return AIAgentIdentityPage{}, fmt.Errorf("agentcore runtime sdk client is required")
	}
	input := &bedrockagentcorecontrol.ListAgentRuntimesInput{
		MaxResults: awsv2.Int32(agentCoreSDKPageSize(pageSize)),
	}
	if token := strings.TrimSpace(nextToken); token != "" {
		input.NextToken = awsv2.String(token)
	}
	output, err := a.client.ListAgentRuntimes(ctx, input)
	if err != nil {
		return AIAgentIdentityPage{}, err
	}

	records := make([]AIAgentIdentity, 0, len(output.AgentRuntimes))
	diagnostics := []providers.SourceError{}
	for _, summary := range output.AgentRuntimes {
		if err := ctx.Err(); err != nil {
			return AIAgentIdentityPage{}, err
		}
		record, runtimeDiagnostics, err := a.runtimeRecord(ctx, summary)
		if err != nil {
			return AIAgentIdentityPage{}, err
		}
		diagnostics = append(diagnostics, runtimeDiagnostics...)
		if strings.TrimSpace(record.AgentID) == "" && strings.TrimSpace(record.AgentARN) == "" {
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

func (a *SDKAgentCoreRuntimeAPI) runtimeRecord(ctx context.Context, summary agentcoretypes.AgentRuntime) (AIAgentIdentity, []providers.SourceError, error) {
	diagnostics := []providers.SourceError{}
	runtimeID := strings.TrimSpace(awsv2.ToString(summary.AgentRuntimeId))
	runtimeARN := strings.TrimSpace(awsv2.ToString(summary.AgentRuntimeArn))
	runtimeName := firstNonEmptyAWSValue(strings.TrimSpace(awsv2.ToString(summary.AgentRuntimeName)), runtimeID, runtimeARN)
	runtimeVersion := strings.TrimSpace(awsv2.ToString(summary.AgentRuntimeVersion))
	if runtimeID == "" && runtimeARN != "" {
		runtimeID = agentCoreRuntimeIDFromARN(runtimeARN)
	}
	if runtimeID == "" {
		diagnostics = append(diagnostics, providers.SourceError{
			Collector: aiAgentIdentityCollectorName,
			Code:      "agentcore_runtime_malformed",
			Message:   "skipped AgentCore runtime without a stable identifier",
			Retryable: false,
		})
		return AIAgentIdentity{}, diagnostics, nil
	}

	detail, detailErr := a.describeRuntime(ctx, runtimeID, runtimeVersion)
	if errors.Is(detailErr, context.Canceled) || errors.Is(detailErr, context.DeadlineExceeded) {
		return AIAgentIdentity{}, diagnostics, detailErr
	}
	if runtimeID != "" {
		// Keep the summary record visible even when a per-runtime describe
		// call fails. The record will be marked degraded below.
		if detailErr != nil {
			diagnostics = append(diagnostics, providers.SourceError{
				Collector: aiAgentIdentityCollectorName,
				SourceID:  runtimeID,
				Code:      "agentcore_runtime_describe_failed",
				Message:   fmt.Sprintf("AgentCore runtime %s could not be described: %v", runtimeID, detailErr),
				Retryable: isRetryable(detailErr),
			})
		}
	}

	endpointARNs, endpointNames, endpointStatuses, observabilityLinks, resourceRefs, endpointDiagnostics, endpointErr := a.listRuntimeEndpoints(ctx, runtimeID)
	diagnostics = append(diagnostics, endpointDiagnostics...)
	if errors.Is(endpointErr, context.Canceled) || errors.Is(endpointErr, context.DeadlineExceeded) {
		return AIAgentIdentity{}, diagnostics, endpointErr
	}
	if endpointErr != nil {
		diagnostics = append(diagnostics, providers.SourceError{
			Collector: aiAgentIdentityCollectorName,
			SourceID:  runtimeID,
			Code:      "agentcore_runtime_endpoint_list_failed",
			Message:   fmt.Sprintf("AgentCore runtime %s endpoints could not be listed: %v", runtimeID, endpointErr),
			Retryable: isRetryable(endpointErr),
		})
	}

	workloadIdentityARN := ""
	if detail.WorkloadIdentityDetails != nil {
		workloadIdentityARN = strings.TrimSpace(awsv2.ToString(detail.WorkloadIdentityDetails.WorkloadIdentityArn))
	}
	if workloadIdentityARN != "" {
		resourceRefs = append(resourceRefs, workloadIdentityARN)
	}

	record := AIAgentIdentity{
		ServiceCollectorRecord: awscontract.ServiceCollectorRecord{
			AccountID: strings.TrimSpace(a.accountID),
			Region:    strings.TrimSpace(a.region),
		},
		AgentID:                   runtimeID,
		AgentARN:                  firstNonEmptyAWSValue(runtimeARN, awsv2.ToString(detail.AgentRuntimeArn)),
		AgentName:                 runtimeName,
		AgentType:                 "agentcore_runtime",
		RuntimeVersion:            firstNonEmptyAWSValue(runtimeVersion, awsv2.ToString(detail.AgentRuntimeVersion)),
		Provider:                  "amazon-bedrock-agentcore",
		RuntimeRoleARN:            strings.TrimSpace(awsv2.ToString(detail.RoleArn)),
		RuntimeRoleName:           roleNameFromARN(strings.TrimSpace(awsv2.ToString(detail.RoleArn))),
		RuntimeRoleAccountID:      roleAccountIDFromARN(strings.TrimSpace(awsv2.ToString(detail.RoleArn))),
		WorkloadIdentityARN:       workloadIdentityARN,
		ToolNames:                 nil,
		BrowserEnabled:            false,
		CodeInterpreterEnabled:    false,
		CapabilityNames:           agentCoreRuntimeCapabilities(workloadIdentityARN, endpointARNs),
		CredentialReferenceRefs:   nil,
		ResourceReferenceRefs:     dedupeStrings(resourceRefs),
		ExecutionEndpointARNs:     endpointARNs,
		ExecutionEndpointNames:    endpointNames,
		ExecutionEndpointStatuses: endpointStatuses,
		ObservabilityLinks:        observabilityLinks,
		NetworkMode:               runtimeNetworkMode(detail.NetworkConfiguration),
		ServerProtocol:            runtimeServerProtocol(detail.ProtocolConfiguration),
		SensitiveBoundary:         "metadata_only",
		CoverageStatus:            "covered",
		Status:                    agentCoreRuntimeStatus(detail.Status),
	}
	if strings.TrimSpace(record.RuntimeVersion) == "" {
		record.RuntimeVersion = runtimeVersion
	}
	if strings.TrimSpace(record.AgentARN) == "" {
		record.AgentARN = runtimeARN
	}
	if strings.TrimSpace(record.RuntimeRoleARN) == "" {
		record.RuntimeRoleARN = strings.TrimSpace(awsv2.ToString(detail.RoleArn))
		record.RuntimeRoleName = roleNameFromARN(record.RuntimeRoleARN)
		record.RuntimeRoleAccountID = roleAccountIDFromARN(record.RuntimeRoleARN)
	}
	if detailErr != nil || endpointErr != nil {
		record.CoverageStatus = "degraded"
		record.Status = "degraded"
		record.CoverageReason = firstNonEmptyAWSValue(
			strings.TrimSpace(awsv2.ToString(detail.FailureReason)),
			"AgentCore runtime metadata was partially collected",
		)
	}
	record.Confidence = aiAgentIdentityConfidence(record)
	record.Source = "agentcore_runtime_metadata"
	record.Service = "agentcore"
	record.EvidenceRef = firstNonEmptyAWSValue(record.AgentARN, record.AgentID)
	record.CollectorName = aiAgentIdentityCollectorName
	record.SensitiveBoundary = firstNonEmptyAWSValue(record.SensitiveBoundary, "metadata_only")
	return record, diagnostics, nil
}

func agentCoreRuntimeCapabilities(workloadIdentityARN string, endpointARNs []string) []string {
	capabilities := []string{"runtime"}
	if strings.TrimSpace(workloadIdentityARN) != "" {
		capabilities = append(capabilities, "workload_identity")
	}
	if len(endpointARNs) > 0 {
		capabilities = append(capabilities, "execution_endpoint")
	}
	return capabilities
}

func (a *SDKAgentCoreRuntimeAPI) describeRuntime(ctx context.Context, runtimeID string, runtimeVersion string) (bedrockagentcorecontrol.GetAgentRuntimeOutput, error) {
	if strings.TrimSpace(runtimeID) == "" {
		return bedrockagentcorecontrol.GetAgentRuntimeOutput{}, fmt.Errorf("runtime id is required")
	}
	output, err := a.client.GetAgentRuntime(ctx, &bedrockagentcorecontrol.GetAgentRuntimeInput{
		AgentRuntimeId:      awsv2.String(runtimeID),
		AgentRuntimeVersion: stringPtrOrNil(strings.TrimSpace(runtimeVersion)),
	})
	if err != nil {
		return bedrockagentcorecontrol.GetAgentRuntimeOutput{}, err
	}
	if output == nil {
		return bedrockagentcorecontrol.GetAgentRuntimeOutput{}, fmt.Errorf("runtime %s returned no metadata", runtimeID)
	}
	return *output, nil
}

func (a *SDKAgentCoreRuntimeAPI) listRuntimeEndpoints(ctx context.Context, runtimeID string) ([]string, []string, []string, []string, []string, []providers.SourceError, error) {
	if strings.TrimSpace(runtimeID) == "" {
		return nil, nil, nil, nil, nil, nil, nil
	}
	input := &bedrockagentcorecontrol.ListAgentRuntimeEndpointsInput{
		AgentRuntimeId: awsv2.String(runtimeID),
		MaxResults:     awsv2.Int32(agentCoreSDKPageSize(defaultPageSize)),
	}
	endpointARNs := []string{}
	endpointNames := []string{}
	endpointStatuses := []string{}
	observabilityLinks := []string{}
	resourceRefs := []string{}
	for {
		if err := ctx.Err(); err != nil {
			return endpointARNs, endpointNames, endpointStatuses, observabilityLinks, resourceRefs, nil, err
		}
		output, err := a.client.ListAgentRuntimeEndpoints(ctx, input)
		if err != nil {
			return endpointARNs, endpointNames, endpointStatuses, observabilityLinks, resourceRefs, nil, err
		}
		if output != nil {
			for _, endpoint := range output.RuntimeEndpoints {
				endpointARN := strings.TrimSpace(awsv2.ToString(endpoint.AgentRuntimeEndpointArn))
				if endpointARN == "" {
					continue
				}
				endpointARNs = append(endpointARNs, endpointARN)
				endpointNames = append(endpointNames, firstNonEmptyAWSValue(strings.TrimSpace(awsv2.ToString(endpoint.Name)), agentCoreRuntimeEndpointNameFromARN(endpointARN)))
				endpointStatuses = append(endpointStatuses, agentCoreRuntimeEndpointStatus(endpoint.Status))
				observabilityLinks = append(observabilityLinks, agentCoreRuntimeObservabilityLink(runtimeID, endpoint))
				resourceRefs = append(resourceRefs, endpointARN)
			}
		}
		nextToken := ""
		if output != nil {
			nextToken = strings.TrimSpace(awsv2.ToString(output.NextToken))
		}
		if nextToken == "" {
			break
		}
		input.NextToken = awsv2.String(nextToken)
	}
	return normalizeOrderedStringList(endpointARNs), normalizeOrderedStringList(endpointNames), normalizeOrderedStringList(endpointStatuses), normalizeOrderedStringList(observabilityLinks), normalizeStringList(resourceRefs), nil, nil
}

func agentCoreSDKPageSize(pageSize int32) int32 {
	if pageSize <= 0 {
		return defaultPageSize
	}
	if pageSize > 100 {
		return 100
	}
	return pageSize
}

func agentCoreRuntimeIDFromARN(arn string) string {
	trimmed := strings.TrimSpace(arn)
	if trimmed == "" {
		return ""
	}
	if idx := strings.LastIndex(trimmed, "/"); idx >= 0 && idx < len(trimmed)-1 {
		return strings.TrimSpace(trimmed[idx+1:])
	}
	if idx := strings.LastIndex(trimmed, ":"); idx >= 0 && idx < len(trimmed)-1 {
		return strings.TrimSpace(trimmed[idx+1:])
	}
	return trimmed
}

func agentCoreRuntimeEndpointNameFromARN(arn string) string {
	trimmed := strings.TrimSpace(arn)
	if trimmed == "" {
		return ""
	}
	if idx := strings.LastIndex(trimmed, "/"); idx >= 0 && idx < len(trimmed)-1 {
		return strings.TrimSpace(trimmed[idx+1:])
	}
	return trimmed
}

func agentCoreRuntimeEndpointStatus(status agentcoretypes.AgentRuntimeEndpointStatus) string {
	switch strings.ToUpper(strings.TrimSpace(string(status))) {
	case "", "READY", "AVAILABLE", "ACTIVE":
		return "ready"
	default:
		return "degraded"
	}
}

func runtimeNetworkMode(network *agentcoretypes.NetworkConfiguration) string {
	if network == nil {
		return ""
	}
	return strings.TrimSpace(strings.ToLower(string(network.NetworkMode)))
}

func runtimeServerProtocol(protocol *agentcoretypes.ProtocolConfiguration) string {
	if protocol == nil {
		return ""
	}
	return strings.TrimSpace(strings.ToLower(string(protocol.ServerProtocol)))
}

func agentCoreRuntimeStatus(status agentcoretypes.AgentRuntimeStatus) string {
	switch strings.ToUpper(strings.TrimSpace(string(status))) {
	case "", "ACTIVE", "READY":
		return "ready"
	default:
		return "degraded"
	}
}

func agentCoreRuntimeObservabilityLink(runtimeID string, endpoint agentcoretypes.AgentRuntimeEndpoint) string {
	endpointName := firstNonEmptyAWSValue(strings.TrimSpace(awsv2.ToString(endpoint.Name)), agentCoreRuntimeEndpointNameFromARN(strings.TrimSpace(awsv2.ToString(endpoint.AgentRuntimeEndpointArn))))
	if endpointName == "" {
		endpointName = "endpoint"
	}
	return fmt.Sprintf("observability://agentcore/runtime/%s/endpoints/%s", normalizeName(runtimeID), normalizeName(endpointName))
}
