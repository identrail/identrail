package aws

import (
	"context"
	"fmt"
	"sort"
	"strings"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/identrail/identrail/internal/providers"
	"github.com/identrail/identrail/internal/providers/awscontract"
	"github.com/identrail/identrail/internal/textutil"
)

// LambdaSDKClient defines the Lambda SDK calls required by the execution-role adapter.
type LambdaSDKClient interface {
	ListFunctions(ctx context.Context, params *lambda.ListFunctionsInput, optFns ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error)
	ListEventSourceMappings(ctx context.Context, params *lambda.ListEventSourceMappingsInput, optFns ...func(*lambda.Options)) (*lambda.ListEventSourceMappingsOutput, error)
	ListAliases(ctx context.Context, params *lambda.ListAliasesInput, optFns ...func(*lambda.Options)) (*lambda.ListAliasesOutput, error)
	ListVersionsByFunction(ctx context.Context, params *lambda.ListVersionsByFunctionInput, optFns ...func(*lambda.Options)) (*lambda.ListVersionsByFunctionOutput, error)
	ListTags(ctx context.Context, params *lambda.ListTagsInput, optFns ...func(*lambda.Options)) (*lambda.ListTagsOutput, error)
}

// SDKLambdaExecutionRoleAPI adapts AWS SDK Lambda calls to LambdaExecutionRoleAPI.
type SDKLambdaExecutionRoleAPI struct {
	lambdaClient LambdaSDKClient
	accountID    string
	region       string
}

var _ LambdaExecutionRoleAPI = (*SDKLambdaExecutionRoleAPI)(nil)

// NewSDKLambdaExecutionRoleAPI constructs a Lambda execution-role API backed by the AWS SDK default credential chain.
func NewSDKLambdaExecutionRoleAPI(region string, profile string, accountID string) (LambdaExecutionRoleAPI, error) {
	return NewSDKLambdaExecutionRoleAPIWithContext(context.Background(), region, profile, accountID)
}

// NewSDKLambdaExecutionRoleAPIWithContext constructs a Lambda execution-role API using caller-provided context for config loading.
func NewSDKLambdaExecutionRoleAPIWithContext(ctx context.Context, region string, profile string, accountID string) (LambdaExecutionRoleAPI, error) {
	cfg, err := loadSDKConfig(ctx, region, profile)
	if err != nil {
		return nil, err
	}
	return NewSDKLambdaExecutionRoleAPIFromClient(lambda.NewFromConfig(cfg), accountID, region), nil
}

// NewSDKLambdaExecutionRoleAPIFromAssumeRole constructs a Lambda execution-role API for an onboarded connector role.
func NewSDKLambdaExecutionRoleAPIFromAssumeRole(ctx context.Context, region string, profile string, roleARN string, externalID string, sessionName string, accountID string) (LambdaExecutionRoleAPI, error) {
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
	return NewSDKLambdaExecutionRoleAPIFromClient(lambda.NewFromConfig(cfg), accountID, region), nil
}

// NewSDKLambdaExecutionRoleAPIFromClient creates a LambdaExecutionRoleAPI from a provided Lambda client.
func NewSDKLambdaExecutionRoleAPIFromClient(lambdaClient LambdaSDKClient, accountID string, region string) LambdaExecutionRoleAPI {
	return &SDKLambdaExecutionRoleAPI{
		lambdaClient: lambdaClient,
		accountID:    strings.TrimSpace(accountID),
		region:       strings.TrimSpace(region),
	}
}

// ListExecutionRoles returns a complete metadata-only Lambda scan. The SDK
// adapter handles AWS pagination internally; the collector-facing page contract
// remains reusable for fixture and unit-test APIs.
func (a *SDKLambdaExecutionRoleAPI) ListExecutionRoles(ctx context.Context, _ string, pageSize int32) (LambdaExecutionRolePage, error) {
	if a.lambdaClient == nil {
		return LambdaExecutionRolePage{}, fmt.Errorf("lambda sdk client is required")
	}

	pageSize = lambdaSDKPageSize(pageSize)
	functions, err := a.listFunctions(ctx, pageSize)
	if err != nil {
		return LambdaExecutionRolePage{}, err
	}

	records := make([]LambdaExecutionRole, 0, len(functions))
	diagnostics := []providers.SourceError{}
	for _, function := range functions {
		if err := ctx.Err(); err != nil {
			return LambdaExecutionRolePage{}, err
		}
		functionARN := strings.TrimSpace(awsv2.ToString(function.FunctionArn))
		functionName := firstNonEmptyAWSValue(awsv2.ToString(function.FunctionName), lambdaFunctionNameFromARN(functionARN))
		if functionARN == "" {
			diagnostics = append(diagnostics, lambdaSourceDiagnostic("missing_function_arn", functionName, "Lambda function did not report a function ARN", false))
			continue
		}

		tags, tagDiagnostics := a.tagsForFunction(ctx, functionARN)
		diagnostics = append(diagnostics, tagDiagnostics...)
		aliases, aliasDiagnostics := a.aliasesForFunction(ctx, firstNonEmptyAWSValue(functionARN, functionName), pageSize)
		diagnostics = append(diagnostics, aliasDiagnostics...)
		versions, versionDiagnostics := a.versionsForFunction(ctx, firstNonEmptyAWSValue(functionARN, functionName), pageSize)
		diagnostics = append(diagnostics, versionDiagnostics...)
		eventSources, eventSourceDiagnostics := a.eventSourcesForFunction(ctx, firstNonEmptyAWSValue(functionARN, functionName), pageSize)
		diagnostics = append(diagnostics, eventSourceDiagnostics...)

		records = append(records, a.recordsFromFunction(function, tags, aliases, versions, eventSources)...)
	}

	sort.SliceStable(records, func(i, j int) bool {
		return lambdaExecutionRoleSourceID(records[i]) < lambdaExecutionRoleSourceID(records[j])
	})
	return LambdaExecutionRolePage{Records: records, Diagnostics: diagnostics}, nil
}

func (a *SDKLambdaExecutionRoleAPI) listFunctions(ctx context.Context, pageSize int32) ([]lambdatypes.FunctionConfiguration, error) {
	input := &lambda.ListFunctionsInput{MaxItems: awsv2.Int32(pageSize)}
	functions := []lambdatypes.FunctionConfiguration{}
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		output, err := a.lambdaClient.ListFunctions(ctx, input)
		if err != nil {
			return nil, err
		}
		if output != nil {
			functions = append(functions, output.Functions...)
		}
		nextMarker := ""
		if output != nil {
			nextMarker = strings.TrimSpace(awsv2.ToString(output.NextMarker))
		}
		if nextMarker == "" {
			break
		}
		input.Marker = awsv2.String(nextMarker)
	}
	return functions, nil
}

func (a *SDKLambdaExecutionRoleAPI) tagsForFunction(ctx context.Context, functionARN string) (map[string]string, []providers.SourceError) {
	output, err := a.lambdaClient.ListTags(ctx, &lambda.ListTagsInput{Resource: awsv2.String(functionARN)})
	if err != nil {
		return nil, []providers.SourceError{lambdaSourceDiagnostic("tags_list_failed", functionARN, fmt.Sprintf("Lambda tags could not be listed: %v", err), true)}
	}
	if output == nil || len(output.Tags) == 0 {
		return nil, nil
	}
	return copyTags(output.Tags), nil
}

func (a *SDKLambdaExecutionRoleAPI) aliasesForFunction(ctx context.Context, functionName string, pageSize int32) ([]lambdatypes.AliasConfiguration, []providers.SourceError) {
	input := &lambda.ListAliasesInput{
		FunctionName: awsv2.String(functionName),
		MaxItems:     awsv2.Int32(pageSize),
	}
	aliases := []lambdatypes.AliasConfiguration{}
	for {
		if err := ctx.Err(); err != nil {
			return aliases, []providers.SourceError{lambdaSourceDiagnostic("alias_list_failed", functionName, err.Error(), true)}
		}
		output, err := a.lambdaClient.ListAliases(ctx, input)
		if err != nil {
			return aliases, []providers.SourceError{lambdaSourceDiagnostic("alias_list_failed", functionName, fmt.Sprintf("Lambda aliases could not be listed: %v", err), true)}
		}
		if output != nil {
			aliases = append(aliases, output.Aliases...)
		}
		nextMarker := ""
		if output != nil {
			nextMarker = strings.TrimSpace(awsv2.ToString(output.NextMarker))
		}
		if nextMarker == "" {
			break
		}
		input.Marker = awsv2.String(nextMarker)
	}
	return aliases, nil
}

func (a *SDKLambdaExecutionRoleAPI) versionsForFunction(ctx context.Context, functionName string, pageSize int32) ([]lambdatypes.FunctionConfiguration, []providers.SourceError) {
	input := &lambda.ListVersionsByFunctionInput{
		FunctionName: awsv2.String(functionName),
		MaxItems:     awsv2.Int32(pageSize),
	}
	versions := []lambdatypes.FunctionConfiguration{}
	for {
		if err := ctx.Err(); err != nil {
			return versions, []providers.SourceError{lambdaSourceDiagnostic("version_list_failed", functionName, err.Error(), true)}
		}
		output, err := a.lambdaClient.ListVersionsByFunction(ctx, input)
		if err != nil {
			return versions, []providers.SourceError{lambdaSourceDiagnostic("version_list_failed", functionName, fmt.Sprintf("Lambda versions could not be listed: %v", err), true)}
		}
		if output != nil {
			versions = append(versions, output.Versions...)
		}
		nextMarker := ""
		if output != nil {
			nextMarker = strings.TrimSpace(awsv2.ToString(output.NextMarker))
		}
		if nextMarker == "" {
			break
		}
		input.Marker = awsv2.String(nextMarker)
	}
	return versions, nil
}

func (a *SDKLambdaExecutionRoleAPI) eventSourcesForFunction(ctx context.Context, functionName string, pageSize int32) ([]lambdatypes.EventSourceMappingConfiguration, []providers.SourceError) {
	input := &lambda.ListEventSourceMappingsInput{
		FunctionName: awsv2.String(functionName),
		MaxItems:     awsv2.Int32(pageSize),
	}
	eventSources := []lambdatypes.EventSourceMappingConfiguration{}
	diagnostics := []providers.SourceError{}
	for {
		if err := ctx.Err(); err != nil {
			return eventSources, []providers.SourceError{lambdaSourceDiagnostic("event_source_mapping_list_failed", functionName, err.Error(), true)}
		}
		output, err := a.lambdaClient.ListEventSourceMappings(ctx, input)
		if err != nil {
			return eventSources, []providers.SourceError{lambdaSourceDiagnostic("event_source_mapping_list_failed", functionName, fmt.Sprintf("Lambda event source mappings could not be listed: %v", err), true)}
		}
		if output != nil {
			eventSources = append(eventSources, output.EventSourceMappings...)
		}
		nextMarker := ""
		if output != nil {
			nextMarker = strings.TrimSpace(awsv2.ToString(output.NextMarker))
		}
		if nextMarker == "" {
			break
		}
		input.Marker = awsv2.String(nextMarker)
	}
	for _, mapping := range eventSources {
		state := strings.TrimSpace(awsv2.ToString(mapping.State))
		if state == "" || strings.EqualFold(state, "Enabled") {
			continue
		}
		sourceID := firstNonEmptyAWSValue(awsv2.ToString(mapping.EventSourceMappingArn), awsv2.ToString(mapping.UUID), awsv2.ToString(mapping.EventSourceArn), functionName)
		message := "Lambda event source mapping is disabled or not fully enabled; role inventory remains visible but invocation coverage is degraded"
		if reason := strings.TrimSpace(awsv2.ToString(mapping.StateTransitionReason)); reason != "" {
			message += ": " + reason
		}
		diagnostics = append(diagnostics, lambdaSourceDiagnostic("disabled_event_source", sourceID, message, false))
	}
	return eventSources, diagnostics
}

func (a *SDKLambdaExecutionRoleAPI) recordsFromFunction(function lambdatypes.FunctionConfiguration, tags map[string]string, aliases []lambdatypes.AliasConfiguration, versions []lambdatypes.FunctionConfiguration, eventSources []lambdatypes.EventSourceMappingConfiguration) []LambdaExecutionRole {
	baseFunctionARN := strings.TrimSpace(awsv2.ToString(function.FunctionArn))
	baseFunctionName := firstNonEmptyAWSValue(awsv2.ToString(function.FunctionName), lambdaFunctionNameFromARN(baseFunctionARN))
	records := []LambdaExecutionRole{
		a.recordFromFunction(function, tags, aliases, versions, lambdaEventSourcesForBase(eventSources)),
	}
	seen := map[string]struct{}{
		lambdaExecutionRoleSourceID(records[0]): {},
	}

	for _, version := range versions {
		versionRef := strings.TrimSpace(awsv2.ToString(version.Version))
		if versionRef == "" || versionRef == "$LATEST" || strings.TrimSpace(awsv2.ToString(version.Role)) == "" {
			continue
		}
		versionAliases := lambdaAliasesForVersion(aliases, versionRef)
		versionRecord := a.recordFromFunction(
			normalizeLambdaVersionFunction(function, version, baseFunctionARN, baseFunctionName, versionRef),
			tags,
			versionAliases,
			[]lambdatypes.FunctionConfiguration{version},
			lambdaEventSourcesForVersion(eventSources, versionAliases, versionRef),
		)
		versionRecord.ServiceCollectorRecord.Source = "listversionsbyfunction"
		versionRecord.ServiceCollectorRecord.EvidenceRef = firstNonEmptyAWSValue(versionRecord.FunctionARN, baseFunctionARN, versionRecord.RoleARN)
		versionRecord.ServiceCollectorRecord.WorkloadID = firstNonEmptyAWSValue(versionRecord.FunctionARN, baseFunctionARN, baseFunctionName)
		versionRecord.ServiceCollectorRecord.WorkloadName = firstNonEmptyAWSValue(lambdaFunctionVersionName(versionRecord.FunctionName, versionRef), versionRecord.FunctionName, baseFunctionName)
		versionRecord.FunctionVersion = versionRef
		if _, exists := seen[lambdaExecutionRoleSourceID(versionRecord)]; exists {
			continue
		}
		records = append(records, versionRecord)
		seen[lambdaExecutionRoleSourceID(versionRecord)] = struct{}{}
	}
	return records
}

func (a *SDKLambdaExecutionRoleAPI) recordFromFunction(function lambdatypes.FunctionConfiguration, tags map[string]string, aliases []lambdatypes.AliasConfiguration, versions []lambdatypes.FunctionConfiguration, eventSources []lambdatypes.EventSourceMappingConfiguration) LambdaExecutionRole {
	functionARN := strings.TrimSpace(awsv2.ToString(function.FunctionArn))
	functionName := firstNonEmptyAWSValue(awsv2.ToString(function.FunctionName), lambdaFunctionNameFromARN(functionARN))
	roleARN := strings.TrimSpace(awsv2.ToString(function.Role))
	record := LambdaExecutionRole{
		ServiceCollectorRecord: awscontract.ServiceCollectorRecord{
			AccountID:     a.accountID,
			Region:        a.region,
			Service:       lambdaServiceName,
			WorkloadID:    firstNonEmptyAWSValue(functionARN, functionName),
			WorkloadType:  "lambda_function",
			WorkloadName:  firstNonEmptyAWSValue(functionName, lambdaFunctionNameFromARN(functionARN)),
			RoleARN:       roleARN,
			Source:        "listfunctions",
			EvidenceRef:   firstNonEmptyAWSValue(functionARN, roleARN),
			Confidence:    0.96,
			CollectorName: lambdaExecutionRoleCollectorName,
		},
		RoleName:         roleNameFromARN(roleARN),
		FunctionARN:      functionARN,
		FunctionName:     functionName,
		FunctionVersion:  strings.TrimSpace(awsv2.ToString(function.Version)),
		FunctionState:    string(function.State),
		LastUpdateStatus: string(function.LastUpdateStatus),
		Runtime:          string(function.Runtime),
		PackageType:      string(function.PackageType),
		Handler:          strings.TrimSpace(awsv2.ToString(function.Handler)),
		KMSKeyARN:        strings.TrimSpace(awsv2.ToString(function.KMSKeyArn)),
		MemorySize:       awsv2.ToInt32(function.MemorySize),
		Timeout:          awsv2.ToInt32(function.Timeout),
		Architectures:    lambdaArchitectures(function.Architectures),
		LayerARNs:        lambdaLayerARNs(function.Layers),
		AliasNames:       lambdaAliasNames(aliases),
		VersionRefs:      lambdaVersionRefs(versions),
		Tags:             copyTags(tags),
	}
	if function.VpcConfig != nil {
		record.VPCID = strings.TrimSpace(awsv2.ToString(function.VpcConfig.VpcId))
		record.SubnetIDs = normalizeStringList(function.VpcConfig.SubnetIds)
		record.SecurityGroupIDs = normalizeStringList(function.VpcConfig.SecurityGroupIds)
	}
	record.EnvironmentKeys = lambdaEnvironmentKeys(function.Environment)
	record.EventSourceARNs = lambdaEventSourceARNs(eventSources)
	record.EventSourceMappingUUIDs = lambdaEventSourceMappingUUIDs(eventSources)
	record.DisabledEventSourceARNs = lambdaDisabledEventSourceARNs(eventSources)
	record.DisabledEventSourceReasons = lambdaDisabledEventSourceReasons(eventSources)
	record.SecretRefs = lambdaEventSourceSecretRefs(eventSources)
	record.Confidence = lambdaExecutionRoleConfidence(record)
	return record
}

func normalizeLambdaVersionFunction(base lambdatypes.FunctionConfiguration, version lambdatypes.FunctionConfiguration, baseFunctionARN string, baseFunctionName string, versionRef string) lambdatypes.FunctionConfiguration {
	normalized := version
	if strings.TrimSpace(awsv2.ToString(normalized.FunctionArn)) == "" {
		normalized.FunctionArn = awsv2.String(lambdaQualifiedFunctionARN(baseFunctionARN, versionRef))
	}
	if strings.TrimSpace(awsv2.ToString(normalized.FunctionName)) == "" {
		normalized.FunctionName = awsv2.String(baseFunctionName)
	}
	if normalized.Runtime == "" {
		normalized.Runtime = base.Runtime
	}
	if normalized.PackageType == "" {
		normalized.PackageType = base.PackageType
	}
	if normalized.Handler == nil {
		normalized.Handler = base.Handler
	}
	if normalized.KMSKeyArn == nil {
		normalized.KMSKeyArn = base.KMSKeyArn
	}
	if normalized.MemorySize == nil {
		normalized.MemorySize = base.MemorySize
	}
	if normalized.Timeout == nil {
		normalized.Timeout = base.Timeout
	}
	if normalized.State == "" {
		normalized.State = base.State
	}
	if normalized.LastUpdateStatus == "" {
		normalized.LastUpdateStatus = base.LastUpdateStatus
	}
	if len(normalized.Architectures) == 0 {
		normalized.Architectures = append([]lambdatypes.Architecture(nil), base.Architectures...)
	}
	if normalized.Environment == nil {
		normalized.Environment = base.Environment
	}
	if normalized.VpcConfig == nil {
		normalized.VpcConfig = base.VpcConfig
	}
	if len(normalized.Layers) == 0 {
		normalized.Layers = append([]lambdatypes.Layer(nil), base.Layers...)
	}
	return normalized
}

func lambdaSDKPageSize(pageSize int32) int32 {
	if pageSize < 1 {
		return defaultPageSize
	}
	if pageSize > 50 {
		return 50
	}
	return pageSize
}

func lambdaSourceDiagnostic(code string, sourceID string, message string, retryable bool) providers.SourceError {
	return providers.SourceError{
		Collector: lambdaExecutionRoleCollectorName,
		SourceID:  strings.TrimSpace(sourceID),
		Code:      code,
		Message:   strings.TrimSpace(message),
		Retryable: retryable,
	}
}

func lambdaArchitectures(values []lambdatypes.Architecture) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, string(value))
	}
	return normalizeStringList(result)
}

func lambdaLayerARNs(layers []lambdatypes.Layer) []string {
	result := make([]string, 0, len(layers))
	for _, layer := range layers {
		if arn := strings.TrimSpace(awsv2.ToString(layer.Arn)); arn != "" {
			result = append(result, arn)
		}
	}
	return normalizeStringList(result)
}

func lambdaAliasNames(aliases []lambdatypes.AliasConfiguration) []string {
	result := make([]string, 0, len(aliases))
	for _, alias := range aliases {
		name := strings.TrimSpace(awsv2.ToString(alias.Name))
		version := strings.TrimSpace(awsv2.ToString(alias.FunctionVersion))
		switch {
		case name != "" && version != "":
			result = append(result, name+"="+version)
		case name != "":
			result = append(result, name)
		}
	}
	return normalizeStringList(result)
}

func lambdaEventSourcesForBase(eventSources []lambdatypes.EventSourceMappingConfiguration) []lambdatypes.EventSourceMappingConfiguration {
	result := []lambdatypes.EventSourceMappingConfiguration{}
	for _, mapping := range eventSources {
		if lambdaFunctionQualifierFromARN(awsv2.ToString(mapping.FunctionArn)) == "" {
			result = append(result, mapping)
		}
	}
	return result
}

func lambdaEventSourcesForVersion(eventSources []lambdatypes.EventSourceMappingConfiguration, aliases []lambdatypes.AliasConfiguration, versionRef string) []lambdatypes.EventSourceMappingConfiguration {
	trimmedVersion := strings.TrimSpace(versionRef)
	if trimmedVersion == "" {
		return nil
	}
	aliasTargets := map[string]struct{}{}
	for _, alias := range aliases {
		if name := strings.TrimSpace(awsv2.ToString(alias.Name)); name != "" {
			aliasTargets[name] = struct{}{}
		}
	}
	result := []lambdatypes.EventSourceMappingConfiguration{}
	for _, mapping := range eventSources {
		qualifier := lambdaFunctionQualifierFromARN(awsv2.ToString(mapping.FunctionArn))
		if qualifier == "" {
			continue
		}
		if qualifier == trimmedVersion {
			result = append(result, mapping)
			continue
		}
		if _, matchesAlias := aliasTargets[qualifier]; matchesAlias {
			result = append(result, mapping)
		}
	}
	return result
}

func lambdaAliasesForVersion(aliases []lambdatypes.AliasConfiguration, versionRef string) []lambdatypes.AliasConfiguration {
	trimmedVersion := strings.TrimSpace(versionRef)
	if trimmedVersion == "" {
		return nil
	}
	result := []lambdatypes.AliasConfiguration{}
	for _, alias := range aliases {
		if strings.TrimSpace(awsv2.ToString(alias.FunctionVersion)) == trimmedVersion {
			result = append(result, alias)
		}
	}
	return result
}

func lambdaVersionRefs(versions []lambdatypes.FunctionConfiguration) []string {
	result := make([]string, 0, len(versions))
	for _, version := range versions {
		if ref := strings.TrimSpace(awsv2.ToString(version.Version)); ref != "" {
			result = append(result, ref)
		}
	}
	return normalizeStringList(result)
}

func lambdaQualifiedFunctionARN(functionARN string, versionRef string) string {
	trimmedARN := strings.TrimSpace(functionARN)
	trimmedVersion := strings.TrimSpace(versionRef)
	if trimmedARN == "" || trimmedVersion == "" {
		return trimmedARN
	}
	marker := ":function:"
	idx := strings.Index(trimmedARN, marker)
	if idx < 0 {
		return trimmedARN
	}
	prefix := trimmedARN[:idx+len(marker)]
	name := trimmedARN[idx+len(marker):]
	if qualifierIdx := strings.Index(name, ":"); qualifierIdx >= 0 {
		name = name[:qualifierIdx]
	}
	if strings.TrimSpace(name) == "" {
		return trimmedARN
	}
	return prefix + name + ":" + trimmedVersion
}

func lambdaFunctionQualifierFromARN(functionARN string) string {
	trimmedARN := strings.TrimSpace(functionARN)
	if trimmedARN == "" {
		return ""
	}
	marker := ":function:"
	idx := strings.Index(trimmedARN, marker)
	if idx < 0 {
		return ""
	}
	rest := trimmedARN[idx+len(marker):]
	qualifierIdx := strings.Index(rest, ":")
	if qualifierIdx < 0 || qualifierIdx == len(rest)-1 {
		return ""
	}
	return strings.TrimSpace(rest[qualifierIdx+1:])
}

func lambdaFunctionVersionName(functionName string, versionRef string) string {
	trimmedName := strings.TrimSpace(functionName)
	trimmedVersion := strings.TrimSpace(versionRef)
	if trimmedName == "" || trimmedVersion == "" {
		return trimmedName
	}
	return trimmedName + ":" + trimmedVersion
}

func lambdaEnvironmentKeys(environment *lambdatypes.EnvironmentResponse) []string {
	if environment == nil || len(environment.Variables) == 0 {
		return nil
	}
	result := make([]string, 0, len(environment.Variables))
	for key := range environment.Variables {
		if trimmed := strings.TrimSpace(key); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return normalizeStringList(result)
}

func lambdaEventSourceARNs(eventSources []lambdatypes.EventSourceMappingConfiguration) []string {
	result := make([]string, 0, len(eventSources))
	for _, mapping := range eventSources {
		if arn := strings.TrimSpace(awsv2.ToString(mapping.EventSourceArn)); arn != "" {
			result = append(result, arn)
		}
	}
	return normalizeStringList(result)
}

func lambdaEventSourceMappingUUIDs(eventSources []lambdatypes.EventSourceMappingConfiguration) []string {
	result := make([]string, 0, len(eventSources))
	for _, mapping := range eventSources {
		if uuid := strings.TrimSpace(awsv2.ToString(mapping.UUID)); uuid != "" {
			result = append(result, uuid)
		}
	}
	return normalizeStringList(result)
}

func lambdaDisabledEventSourceARNs(eventSources []lambdatypes.EventSourceMappingConfiguration) []string {
	result := make([]string, 0, len(eventSources))
	for _, mapping := range eventSources {
		state := strings.TrimSpace(awsv2.ToString(mapping.State))
		if state == "" || strings.EqualFold(state, "Enabled") {
			continue
		}
		if arn := strings.TrimSpace(awsv2.ToString(mapping.EventSourceArn)); arn != "" {
			result = append(result, arn)
		}
	}
	return normalizeStringList(result)
}

func lambdaDisabledEventSourceReasons(eventSources []lambdatypes.EventSourceMappingConfiguration) []string {
	result := make([]string, 0, len(eventSources))
	for _, mapping := range eventSources {
		state := strings.TrimSpace(awsv2.ToString(mapping.State))
		if state == "" || strings.EqualFold(state, "Enabled") {
			continue
		}
		ref := firstNonEmptyAWSValue(awsv2.ToString(mapping.UUID), awsv2.ToString(mapping.EventSourceArn), awsv2.ToString(mapping.EventSourceMappingArn))
		reason := strings.TrimSpace(awsv2.ToString(mapping.StateTransitionReason))
		if ref != "" && reason != "" {
			result = append(result, ref+"="+reason)
			continue
		}
		if ref != "" {
			result = append(result, ref+"="+state)
		}
	}
	return normalizeStringList(result)
}

func lambdaEventSourceSecretRefs(eventSources []lambdatypes.EventSourceMappingConfiguration) []string {
	result := []string{}
	for _, mapping := range eventSources {
		for _, config := range mapping.SourceAccessConfigurations {
			refType := strings.TrimSpace(string(config.Type))
			uri := strings.TrimSpace(awsv2.ToString(config.URI))
			switch {
			case refType != "" && uri != "":
				result = append(result, refType+"="+uri)
			case uri != "":
				result = append(result, uri)
			}
		}
	}
	return normalizeStringList(result)
}
