package aws

import (
	"context"
	"errors"
	"fmt"
	"strconv"
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

// AgentCoreCapabilitiesSDKClient defines the AgentCore Control API calls the
// capability adapter uses to map Memory, Browser, and Code Interpreter
// resources. Every call is read-only metadata: the adapter never reads memory
// records, browser pages, or code-interpreter output.
type AgentCoreCapabilitiesSDKClient interface {
	ListMemories(ctx context.Context, params *bedrockagentcorecontrol.ListMemoriesInput, optFns ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.ListMemoriesOutput, error)
	GetMemory(ctx context.Context, params *bedrockagentcorecontrol.GetMemoryInput, optFns ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.GetMemoryOutput, error)
	ListBrowsers(ctx context.Context, params *bedrockagentcorecontrol.ListBrowsersInput, optFns ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.ListBrowsersOutput, error)
	GetBrowser(ctx context.Context, params *bedrockagentcorecontrol.GetBrowserInput, optFns ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.GetBrowserOutput, error)
	ListCodeInterpreters(ctx context.Context, params *bedrockagentcorecontrol.ListCodeInterpretersInput, optFns ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.ListCodeInterpretersOutput, error)
	GetCodeInterpreter(ctx context.Context, params *bedrockagentcorecontrol.GetCodeInterpreterInput, optFns ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.GetCodeInterpreterOutput, error)
}

// SDKAgentCoreCapabilitiesAPI adapts AgentCore Memory/Browser/Code Interpreter
// resources into the generic AIAgentIdentity API contract as data/tool surfaces.
type SDKAgentCoreCapabilitiesAPI struct {
	client    AgentCoreCapabilitiesSDKClient
	accountID string
	region    string
}

var _ AIAgentIdentityAPI = (*SDKAgentCoreCapabilitiesAPI)(nil)

// NewSDKAgentCoreCapabilitiesAPI constructs the capability adapter using ambient
// AWS credentials.
func NewSDKAgentCoreCapabilitiesAPI(region string, profile string, accountID string) (AIAgentIdentityAPI, error) {
	return NewSDKAgentCoreCapabilitiesAPIWithContext(context.Background(), region, profile, accountID)
}

// NewSDKAgentCoreCapabilitiesAPIWithContext constructs the capability adapter
// using the caller-provided context for AWS configuration loading.
func NewSDKAgentCoreCapabilitiesAPIWithContext(ctx context.Context, region string, profile string, accountID string) (AIAgentIdentityAPI, error) {
	cfg, err := loadSDKConfig(ctx, region, profile)
	if err != nil {
		return nil, err
	}
	resolvedAccountID, err := awsCallerAccountID(ctx, cfg, accountID)
	if err != nil {
		return nil, err
	}
	resolvedRegion := firstNonEmptyAWSValue(strings.TrimSpace(region), strings.TrimSpace(cfg.Region))
	return NewSDKAgentCoreCapabilitiesAPIFromClient(bedrockagentcorecontrol.NewFromConfig(cfg), resolvedAccountID, resolvedRegion), nil
}

// NewSDKAgentCoreCapabilitiesAPIFromAssumeRole constructs the capability adapter
// after assuming the connector role.
func NewSDKAgentCoreCapabilitiesAPIFromAssumeRole(ctx context.Context, region string, profile string, roleARN string, externalID string, sessionName string, accountID string) (AIAgentIdentityAPI, error) {
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
	return NewSDKAgentCoreCapabilitiesAPIFromClient(bedrockagentcorecontrol.NewFromConfig(cfg), resolvedAccountID, resolvedRegion), nil
}

// NewSDKAgentCoreCapabilitiesAPIFromClient creates a test seam around a provided
// AgentCore client.
func NewSDKAgentCoreCapabilitiesAPIFromClient(client AgentCoreCapabilitiesSDKClient, accountID string, region string) AIAgentIdentityAPI {
	return &SDKAgentCoreCapabilitiesAPI{
		client:    client,
		accountID: strings.TrimSpace(accountID),
		region:    strings.TrimSpace(region),
	}
}

// agentCoreCapabilitySource indexes the three capability surfaces so pagination
// walks them deterministically (memory, then browser, then code interpreter).
type agentCoreCapabilitySource int

const (
	agentCoreCapabilitySourceMemory agentCoreCapabilitySource = iota
	agentCoreCapabilitySourceBrowser
	agentCoreCapabilitySourceCodeInterpreter
	agentCoreCapabilitySourceCount
)

// ListAgentIdentities lists AgentCore Memory, Browser, and Code Interpreter
// resources and maps each into a metadata-only capability identity. It walks the
// three surfaces in order using a composite "<source>:<token>" pagination token
// so a single agent collector can fan across all three without losing position.
func (a *SDKAgentCoreCapabilitiesAPI) ListAgentIdentities(ctx context.Context, nextToken string, pageSize int32) (AIAgentIdentityPage, error) {
	if a.client == nil {
		return AIAgentIdentityPage{}, fmt.Errorf("agentcore capabilities sdk client is required")
	}
	source, sourceToken, err := parseAgentCoreCapabilityToken(nextToken)
	if err != nil {
		return AIAgentIdentityPage{}, err
	}
	for source < agentCoreCapabilitySourceCount {
		if err := ctx.Err(); err != nil {
			return AIAgentIdentityPage{}, err
		}
		var (
			records     []AIAgentIdentity
			diagnostics []providers.SourceError
			next        string
		)
		switch source {
		case agentCoreCapabilitySourceMemory:
			records, next, diagnostics, err = a.listMemories(ctx, sourceToken, pageSize)
		case agentCoreCapabilitySourceBrowser:
			records, next, diagnostics, err = a.listBrowsers(ctx, sourceToken, pageSize)
		case agentCoreCapabilitySourceCodeInterpreter:
			records, next, diagnostics, err = a.listCodeInterpreters(ctx, sourceToken, pageSize)
		}
		if err != nil {
			// Cancellation/deadline aborts the whole adapter; any other list
			// failure (denied/throttled on one capability source) is recorded as
			// a diagnostic and we advance to the next source so an account that
			// still has ListBrowsers/ListCodeInterpreters permission does not
			// lose those records to a single ListMemories denial.
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || isRetryable(err) {
				return AIAgentIdentityPage{}, err
			}
			diagnostic := providers.SourceError{
				Collector: aiAgentIdentityCollectorName,
				SourceID:  agentCoreCapabilitySourceName(source),
				Code:      "agentcore_capability_list_failed",
				Message:   fmt.Sprintf("AgentCore %s list failed: %v", agentCoreCapabilitySourceName(source), err),
				Retryable: isRetryable(err),
			}
			page := AIAgentIdentityPage{Diagnostics: []providers.SourceError{diagnostic}}
			if source+1 < agentCoreCapabilitySourceCount {
				page.NextToken = formatAgentCoreCapabilityToken(source+1, "")
			}
			return page, nil
		}
		page := AIAgentIdentityPage{Records: records, Diagnostics: diagnostics}
		if strings.TrimSpace(next) != "" {
			page.NextToken = formatAgentCoreCapabilityToken(source, next)
			return page, nil
		}
		if source+1 < agentCoreCapabilitySourceCount {
			page.NextToken = formatAgentCoreCapabilityToken(source+1, "")
		}
		if len(page.Records) > 0 || len(page.Diagnostics) > 0 {
			return page, nil
		}
		source++
		sourceToken = ""
	}
	return AIAgentIdentityPage{}, nil
}

func (a *SDKAgentCoreCapabilitiesAPI) listMemories(ctx context.Context, token string, pageSize int32) ([]AIAgentIdentity, string, []providers.SourceError, error) {
	input := &bedrockagentcorecontrol.ListMemoriesInput{MaxResults: awsv2.Int32(agentCoreSDKPageSize(pageSize))}
	if trimmed := strings.TrimSpace(token); trimmed != "" {
		input.NextToken = awsv2.String(trimmed)
	}
	output, err := a.client.ListMemories(ctx, input)
	if err != nil {
		return nil, "", nil, err
	}
	records := make([]AIAgentIdentity, 0, len(output.Memories))
	diagnostics := []providers.SourceError{}
	for _, summary := range output.Memories {
		if err := ctx.Err(); err != nil {
			return records, "", diagnostics, err
		}
		record, recordDiagnostics, recordErr := a.memoryRecord(ctx, summary)
		if errors.Is(recordErr, context.Canceled) || errors.Is(recordErr, context.DeadlineExceeded) {
			return records, "", diagnostics, recordErr
		}
		diagnostics = append(diagnostics, recordDiagnostics...)
		if strings.TrimSpace(record.AgentID) == "" && strings.TrimSpace(record.AgentARN) == "" {
			continue
		}
		records = append(records, record)
	}
	return records, strings.TrimSpace(awsv2.ToString(output.NextToken)), diagnostics, nil
}

func (a *SDKAgentCoreCapabilitiesAPI) memoryRecord(ctx context.Context, summary agentcoretypes.MemorySummary) (AIAgentIdentity, []providers.SourceError, error) {
	diagnostics := []providers.SourceError{}
	memoryID := strings.TrimSpace(awsv2.ToString(summary.Id))
	memoryARN := strings.TrimSpace(awsv2.ToString(summary.Arn))
	if memoryID == "" && memoryARN == "" {
		diagnostics = append(diagnostics, providers.SourceError{
			Collector: aiAgentIdentityCollectorName,
			Code:      "agentcore_memory_malformed",
			Message:   "skipped AgentCore memory without a stable identifier",
			Retryable: false,
		})
		return AIAgentIdentity{}, diagnostics, nil
	}

	record := a.baseCapabilityRecord(agentCoreCapabilityKindMemory, memoryID, memoryARN, "")
	record.Status = agentCoreCapabilityStatus(string(summary.Status))

	// GetMemory keys on the short memory id. If the summary is ARN-only, skip the
	// describe call (it would query an empty id) and surface the summary as
	// degraded with an explicit reason instead of an avoidable describe failure.
	if memoryID == "" {
		diagnostics = append(diagnostics, providers.SourceError{
			Collector: aiAgentIdentityCollectorName,
			SourceID:  memoryARN,
			Code:      "agentcore_memory_id_missing",
			Message:   "AgentCore memory summary did not include an id; surfaced summary only",
			Retryable: true,
		})
		record.CoverageStatus = "degraded"
		record.Status = "degraded"
		record.CoverageReason = "AgentCore memory summary did not include an id"
		a.finalizeCapabilityRecord(&record)
		return record, diagnostics, nil
	}

	detail, detailErr := a.client.GetMemory(ctx, &bedrockagentcorecontrol.GetMemoryInput{MemoryId: awsv2.String(memoryID)})
	if errors.Is(detailErr, context.Canceled) || errors.Is(detailErr, context.DeadlineExceeded) {
		return AIAgentIdentity{}, diagnostics, detailErr
	}
	if detailErr != nil || detail == nil || detail.Memory == nil {
		diagnostics = append(diagnostics, providers.SourceError{
			Collector: aiAgentIdentityCollectorName,
			SourceID:  firstNonEmptyAWSValue(memoryID, memoryARN),
			Code:      "agentcore_memory_describe_failed",
			Message:   fmt.Sprintf("AgentCore memory %s could not be described: %v", firstNonEmptyAWSValue(memoryID, memoryARN), detailErr),
			Retryable: isRetryable(detailErr),
		})
		record.CoverageStatus = "degraded"
		record.Status = "degraded"
		record.CoverageReason = "AgentCore memory metadata was partially collected"
		a.finalizeCapabilityRecord(&record)
		return record, diagnostics, nil
	}

	memory := detail.Memory
	record.AgentARN = firstNonEmptyAWSValue(strings.TrimSpace(awsv2.ToString(memory.Arn)), memoryARN)
	record.AgentName = firstNonEmptyAWSValue(strings.TrimSpace(awsv2.ToString(memory.Name)), record.AgentName)
	roleARN := strings.TrimSpace(awsv2.ToString(memory.MemoryExecutionRoleArn))
	record.RuntimeRoleARN = roleARN
	record.RuntimeRoleName = roleNameFromARN(roleARN)
	record.RuntimeRoleAccountID = roleAccountIDFromARN(roleARN)
	record.EncryptionKeyARN = strings.TrimSpace(awsv2.ToString(memory.EncryptionKeyArn))
	record.Status = agentCoreCapabilityStatus(string(memory.Status))
	storageRefs := []string{}
	for _, strategy := range memory.Strategies {
		if name := strings.TrimSpace(awsv2.ToString(strategy.Name)); name != "" {
			record.CapabilityNames = appendUnique(record.CapabilityNames, "memory_strategy_"+normalizeName(name))
		}
		if kind := strings.TrimSpace(string(strategy.Type)); kind != "" {
			record.CapabilityNames = appendUnique(record.CapabilityNames, "memory_strategy_type_"+strings.ToLower(kind))
		}
	}
	if memory.EventExpiryDuration != nil {
		record.CapabilityNames = appendUnique(record.CapabilityNames, fmt.Sprintf("memory_event_expiry_days_%d", awsv2.ToInt32(memory.EventExpiryDuration)))
	}
	if memory.StreamDeliveryResources != nil {
		storageRefs = append(storageRefs, fmt.Sprintf("memory_stream_delivery_resources_%d", len(memory.StreamDeliveryResources.Resources)))
		record.CapabilityNames = appendUnique(record.CapabilityNames, "memory_stream_delivery")
	}
	record.StorageReferenceRefs = normalizeStringList(storageRefs)
	record.MemoryStoreRefs = normalizeStringList([]string{firstNonEmptyAWSValue(record.AgentARN, record.AgentID)})
	if reason := strings.TrimSpace(awsv2.ToString(memory.FailureReason)); reason != "" && record.CoverageStatus != "covered" {
		record.CoverageReason = reason
	}
	a.finalizeCapabilityRecord(&record)
	return record, diagnostics, nil
}

func (a *SDKAgentCoreCapabilitiesAPI) listBrowsers(ctx context.Context, token string, pageSize int32) ([]AIAgentIdentity, string, []providers.SourceError, error) {
	input := &bedrockagentcorecontrol.ListBrowsersInput{MaxResults: awsv2.Int32(agentCoreSDKPageSize(pageSize))}
	if trimmed := strings.TrimSpace(token); trimmed != "" {
		input.NextToken = awsv2.String(trimmed)
	}
	output, err := a.client.ListBrowsers(ctx, input)
	if err != nil {
		return nil, "", nil, err
	}
	records := make([]AIAgentIdentity, 0, len(output.BrowserSummaries))
	diagnostics := []providers.SourceError{}
	for _, summary := range output.BrowserSummaries {
		if err := ctx.Err(); err != nil {
			return records, "", diagnostics, err
		}
		record, recordDiagnostics, recordErr := a.browserRecord(ctx, summary)
		if errors.Is(recordErr, context.Canceled) || errors.Is(recordErr, context.DeadlineExceeded) {
			return records, "", diagnostics, recordErr
		}
		diagnostics = append(diagnostics, recordDiagnostics...)
		if strings.TrimSpace(record.AgentID) == "" && strings.TrimSpace(record.AgentARN) == "" {
			continue
		}
		records = append(records, record)
	}
	return records, strings.TrimSpace(awsv2.ToString(output.NextToken)), diagnostics, nil
}

func (a *SDKAgentCoreCapabilitiesAPI) browserRecord(ctx context.Context, summary agentcoretypes.BrowserSummary) (AIAgentIdentity, []providers.SourceError, error) {
	diagnostics := []providers.SourceError{}
	browserID := strings.TrimSpace(awsv2.ToString(summary.BrowserId))
	browserARN := strings.TrimSpace(awsv2.ToString(summary.BrowserArn))
	if browserID == "" && browserARN == "" {
		diagnostics = append(diagnostics, providers.SourceError{
			Collector: aiAgentIdentityCollectorName,
			Code:      "agentcore_browser_malformed",
			Message:   "skipped AgentCore browser without a stable identifier",
			Retryable: false,
		})
		return AIAgentIdentity{}, diagnostics, nil
	}

	record := a.baseCapabilityRecord(agentCoreCapabilityKindBrowser, browserID, browserARN, firstNonEmptyAWSValue(strings.TrimSpace(awsv2.ToString(summary.Name)), browserID))
	record.Status = agentCoreCapabilityStatus(string(summary.Status))

	// GetBrowser keys on the short browser id. Skip the describe call for an
	// ARN-only summary and surface it as degraded with an explicit reason
	// instead of an avoidable describe failure on an empty id.
	if browserID == "" {
		diagnostics = append(diagnostics, providers.SourceError{
			Collector: aiAgentIdentityCollectorName,
			SourceID:  browserARN,
			Code:      "agentcore_browser_id_missing",
			Message:   "AgentCore browser summary did not include an id; surfaced summary only",
			Retryable: true,
		})
		record.CoverageStatus = "degraded"
		record.Status = "degraded"
		record.CoverageReason = "AgentCore browser summary did not include an id"
		a.finalizeCapabilityRecord(&record)
		return record, diagnostics, nil
	}

	detail, detailErr := a.client.GetBrowser(ctx, &bedrockagentcorecontrol.GetBrowserInput{BrowserId: awsv2.String(browserID)})
	if errors.Is(detailErr, context.Canceled) || errors.Is(detailErr, context.DeadlineExceeded) {
		return AIAgentIdentity{}, diagnostics, detailErr
	}
	if detailErr != nil || detail == nil {
		diagnostics = append(diagnostics, providers.SourceError{
			Collector: aiAgentIdentityCollectorName,
			SourceID:  firstNonEmptyAWSValue(browserID, browserARN),
			Code:      "agentcore_browser_describe_failed",
			Message:   fmt.Sprintf("AgentCore browser %s could not be described: %v", firstNonEmptyAWSValue(browserID, browserARN), detailErr),
			Retryable: isRetryable(detailErr),
		})
		record.CoverageStatus = "degraded"
		record.Status = "degraded"
		record.CoverageReason = "AgentCore browser metadata was partially collected"
		a.finalizeCapabilityRecord(&record)
		return record, diagnostics, nil
	}

	record.AgentARN = firstNonEmptyAWSValue(strings.TrimSpace(awsv2.ToString(detail.BrowserArn)), browserARN)
	record.AgentName = firstNonEmptyAWSValue(strings.TrimSpace(awsv2.ToString(detail.Name)), record.AgentName)
	roleARN := strings.TrimSpace(awsv2.ToString(detail.ExecutionRoleArn))
	record.RuntimeRoleARN = roleARN
	record.RuntimeRoleName = roleNameFromARN(roleARN)
	record.RuntimeRoleAccountID = roleAccountIDFromARN(roleARN)
	record.Status = agentCoreCapabilityStatus(string(detail.Status))
	if detail.NetworkConfiguration != nil {
		record.NetworkMode = strings.ToLower(strings.TrimSpace(string(detail.NetworkConfiguration.NetworkMode)))
		record.CapabilityNames = append(record.CapabilityNames, vpcConfigCapabilities(detail.NetworkConfiguration.VpcConfig)...)
	}
	storageRefs := []string{}
	if detail.Recording != nil && detail.Recording.Enabled {
		record.CapabilityNames = appendUnique(record.CapabilityNames, "browser_recording")
		if ref := s3LocationRef(detail.Recording.S3Location); ref != "" {
			storageRefs = append(storageRefs, ref)
		}
	}
	if len(detail.EnterprisePolicies) > 0 {
		record.CapabilityNames = appendUnique(record.CapabilityNames, "browser_enterprise_policy")
	}
	record.StorageReferenceRefs = normalizeStringList(storageRefs)
	if reason := strings.TrimSpace(awsv2.ToString(detail.FailureReason)); reason != "" && record.CoverageStatus != "covered" {
		record.CoverageReason = reason
	}
	a.finalizeCapabilityRecord(&record)
	return record, diagnostics, nil
}

func (a *SDKAgentCoreCapabilitiesAPI) listCodeInterpreters(ctx context.Context, token string, pageSize int32) ([]AIAgentIdentity, string, []providers.SourceError, error) {
	input := &bedrockagentcorecontrol.ListCodeInterpretersInput{MaxResults: awsv2.Int32(agentCoreSDKPageSize(pageSize))}
	if trimmed := strings.TrimSpace(token); trimmed != "" {
		input.NextToken = awsv2.String(trimmed)
	}
	output, err := a.client.ListCodeInterpreters(ctx, input)
	if err != nil {
		return nil, "", nil, err
	}
	records := make([]AIAgentIdentity, 0, len(output.CodeInterpreterSummaries))
	diagnostics := []providers.SourceError{}
	for _, summary := range output.CodeInterpreterSummaries {
		if err := ctx.Err(); err != nil {
			return records, "", diagnostics, err
		}
		record, recordDiagnostics, recordErr := a.codeInterpreterRecord(ctx, summary)
		if errors.Is(recordErr, context.Canceled) || errors.Is(recordErr, context.DeadlineExceeded) {
			return records, "", diagnostics, recordErr
		}
		diagnostics = append(diagnostics, recordDiagnostics...)
		if strings.TrimSpace(record.AgentID) == "" && strings.TrimSpace(record.AgentARN) == "" {
			continue
		}
		records = append(records, record)
	}
	return records, strings.TrimSpace(awsv2.ToString(output.NextToken)), diagnostics, nil
}

func (a *SDKAgentCoreCapabilitiesAPI) codeInterpreterRecord(ctx context.Context, summary agentcoretypes.CodeInterpreterSummary) (AIAgentIdentity, []providers.SourceError, error) {
	diagnostics := []providers.SourceError{}
	interpreterID := strings.TrimSpace(awsv2.ToString(summary.CodeInterpreterId))
	interpreterARN := strings.TrimSpace(awsv2.ToString(summary.CodeInterpreterArn))
	if interpreterID == "" && interpreterARN == "" {
		diagnostics = append(diagnostics, providers.SourceError{
			Collector: aiAgentIdentityCollectorName,
			Code:      "agentcore_code_interpreter_malformed",
			Message:   "skipped AgentCore code interpreter without a stable identifier",
			Retryable: false,
		})
		return AIAgentIdentity{}, diagnostics, nil
	}

	record := a.baseCapabilityRecord(agentCoreCapabilityKindCodeInterpreter, interpreterID, interpreterARN, firstNonEmptyAWSValue(strings.TrimSpace(awsv2.ToString(summary.Name)), interpreterID))
	record.Status = agentCoreCapabilityStatus(string(summary.Status))

	// GetCodeInterpreter keys on the short id. Skip the describe call for an
	// ARN-only summary and surface it as degraded with an explicit reason
	// instead of an avoidable describe failure on an empty id.
	if interpreterID == "" {
		diagnostics = append(diagnostics, providers.SourceError{
			Collector: aiAgentIdentityCollectorName,
			SourceID:  interpreterARN,
			Code:      "agentcore_code_interpreter_id_missing",
			Message:   "AgentCore code interpreter summary did not include an id; surfaced summary only",
			Retryable: true,
		})
		record.CoverageStatus = "degraded"
		record.Status = "degraded"
		record.CoverageReason = "AgentCore code interpreter summary did not include an id"
		a.finalizeCapabilityRecord(&record)
		return record, diagnostics, nil
	}

	detail, detailErr := a.client.GetCodeInterpreter(ctx, &bedrockagentcorecontrol.GetCodeInterpreterInput{CodeInterpreterId: awsv2.String(interpreterID)})
	if errors.Is(detailErr, context.Canceled) || errors.Is(detailErr, context.DeadlineExceeded) {
		return AIAgentIdentity{}, diagnostics, detailErr
	}
	if detailErr != nil || detail == nil {
		diagnostics = append(diagnostics, providers.SourceError{
			Collector: aiAgentIdentityCollectorName,
			SourceID:  firstNonEmptyAWSValue(interpreterID, interpreterARN),
			Code:      "agentcore_code_interpreter_describe_failed",
			Message:   fmt.Sprintf("AgentCore code interpreter %s could not be described: %v", firstNonEmptyAWSValue(interpreterID, interpreterARN), detailErr),
			Retryable: isRetryable(detailErr),
		})
		record.CoverageStatus = "degraded"
		record.Status = "degraded"
		record.CoverageReason = "AgentCore code interpreter metadata was partially collected"
		a.finalizeCapabilityRecord(&record)
		return record, diagnostics, nil
	}

	record.AgentARN = firstNonEmptyAWSValue(strings.TrimSpace(awsv2.ToString(detail.CodeInterpreterArn)), interpreterARN)
	record.AgentName = firstNonEmptyAWSValue(strings.TrimSpace(awsv2.ToString(detail.Name)), record.AgentName)
	roleARN := strings.TrimSpace(awsv2.ToString(detail.ExecutionRoleArn))
	record.RuntimeRoleARN = roleARN
	record.RuntimeRoleName = roleNameFromARN(roleARN)
	record.RuntimeRoleAccountID = roleAccountIDFromARN(roleARN)
	record.Status = agentCoreCapabilityStatus(string(detail.Status))
	if detail.NetworkConfiguration != nil {
		record.NetworkMode = strings.ToLower(strings.TrimSpace(string(detail.NetworkConfiguration.NetworkMode)))
		record.CapabilityNames = append(record.CapabilityNames, vpcConfigCapabilities(detail.NetworkConfiguration.VpcConfig)...)
	}
	if reason := strings.TrimSpace(awsv2.ToString(detail.FailureReason)); reason != "" && record.CoverageStatus != "covered" {
		record.CoverageReason = reason
	}
	a.finalizeCapabilityRecord(&record)
	return record, diagnostics, nil
}

// baseCapabilityRecord seeds the common metadata-only fields shared by every
// capability surface.
func (a *SDKAgentCoreCapabilitiesAPI) baseCapabilityRecord(kind, id, arn, name string) AIAgentIdentity {
	return AIAgentIdentity{
		ServiceCollectorRecord: awscontract.ServiceCollectorRecord{
			AccountID: strings.TrimSpace(a.accountID),
			Region:    strings.TrimSpace(a.region),
		},
		AgentID:           id,
		AgentARN:          arn,
		AgentName:         firstNonEmptyAWSValue(name, id, arn),
		AgentType:         agentCoreCapabilityAgentType,
		CapabilityKind:    kind,
		Provider:          "amazon-bedrock-agentcore",
		CapabilityNames:   []string{"agentcore_" + kind},
		SensitiveBoundary: "metadata_only",
		CoverageStatus:    "covered",
		Status:            "ready",
	}
}

// finalizeCapabilityRecord fills in the derived collector envelope fields so the
// capability record validates against the shared service collector contract.
func (a *SDKAgentCoreCapabilitiesAPI) finalizeCapabilityRecord(record *AIAgentIdentity) {
	record.CapabilityNames = normalizeStringList(record.CapabilityNames)
	record.StorageReferenceRefs = normalizeStringList(record.StorageReferenceRefs)
	record.Service = "agentcore"
	record.Source = "agentcore_" + record.CapabilityKind + "_metadata"
	record.EvidenceRef = firstNonEmptyAWSValue(record.AgentARN, record.AgentID)
	record.CollectorName = aiAgentIdentityCollectorName
	record.Confidence = aiAgentIdentityConfidence(*record)
}

// agentCoreCapabilityStatus maps the AgentCore lifecycle status strings onto the
// constrained vocabulary used by every AI agent identity record.
func agentCoreCapabilityStatus(status string) string {
	normalized := strings.ToLower(strings.TrimSpace(status))
	switch normalized {
	case "", "active", "ready", "available":
		if normalized == "" {
			return "ready"
		}
		return "ready"
	case "creating", "create_in_progress", "updating", "update_in_progress":
		return "creating"
	case "deleting", "delete_in_progress":
		return "deleting"
	case "create_failed", "update_failed", "delete_failed", "failed":
		return "failed"
	default:
		return normalized
	}
}

// vpcConfigCapabilities returns metadata-only network posture tokens for a VPC
// configuration. It records only counts and the presence of the S3 endpoint
// requirement, never security-group or subnet identifiers as data.
func vpcConfigCapabilities(vpc *agentcoretypes.VpcConfig) []string {
	if vpc == nil {
		return nil
	}
	caps := []string{"vpc_attached"}
	if len(vpc.Subnets) > 0 {
		caps = append(caps, fmt.Sprintf("vpc_subnets_%d", len(vpc.Subnets)))
	}
	if len(vpc.SecurityGroups) > 0 {
		caps = append(caps, fmt.Sprintf("vpc_security_groups_%d", len(vpc.SecurityGroups)))
	}
	if awsv2.ToBool(vpc.RequireServiceS3Endpoint) {
		caps = append(caps, "vpc_require_s3_endpoint")
	}
	return caps
}

// s3LocationRef renders a metadata-only s3://bucket/prefix reference for a
// recording or storage destination, never the object contents.
func s3LocationRef(loc *agentcoretypes.S3Location) string {
	if loc == nil {
		return ""
	}
	bucket := strings.TrimSpace(awsv2.ToString(loc.Bucket))
	if bucket == "" {
		return ""
	}
	ref := "s3://" + bucket
	if prefix := strings.TrimSpace(awsv2.ToString(loc.Prefix)); prefix != "" {
		ref = ref + "/" + strings.TrimPrefix(prefix, "/")
	}
	return ref
}

func parseAgentCoreCapabilityToken(token string) (agentCoreCapabilitySource, string, error) {
	trimmed := strings.TrimSpace(token)
	if trimmed == "" {
		return agentCoreCapabilitySourceMemory, "", nil
	}
	indexPart, sourceToken, ok := strings.Cut(trimmed, ":")
	if !ok {
		return 0, "", fmt.Errorf("invalid agentcore capability pagination token")
	}
	// strconv.Atoi rejects malformed prefixes like "1abc" that fmt.Sscanf("%d")
	// would silently accept by stopping at the first non-digit.
	index, err := strconv.Atoi(indexPart)
	if err != nil {
		return 0, "", fmt.Errorf("invalid agentcore capability pagination token")
	}
	if index < 0 || agentCoreCapabilitySource(index) >= agentCoreCapabilitySourceCount {
		return 0, "", fmt.Errorf("invalid agentcore capability pagination token")
	}
	return agentCoreCapabilitySource(index), sourceToken, nil
}

func formatAgentCoreCapabilityToken(source agentCoreCapabilitySource, sourceToken string) string {
	return fmt.Sprintf("%d:%s", int(source), strings.TrimSpace(sourceToken))
}

func agentCoreCapabilitySourceName(source agentCoreCapabilitySource) string {
	switch source {
	case agentCoreCapabilitySourceMemory:
		return "memory"
	case agentCoreCapabilitySourceBrowser:
		return "browser"
	case agentCoreCapabilitySourceCodeInterpreter:
		return "code_interpreter"
	default:
		return "capability"
	}
}
