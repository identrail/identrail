package aws

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sfn"
	sfntypes "github.com/aws/aws-sdk-go-v2/service/sfn/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"

	"github.com/identrail/identrail/internal/providers"
	"github.com/identrail/identrail/internal/providers/awscontract"
	"github.com/identrail/identrail/internal/textutil"
)

type StepFunctionsSDKClient interface {
	ListStateMachines(ctx context.Context, params *sfn.ListStateMachinesInput, optFns ...func(*sfn.Options)) (*sfn.ListStateMachinesOutput, error)
	DescribeStateMachine(ctx context.Context, params *sfn.DescribeStateMachineInput, optFns ...func(*sfn.Options)) (*sfn.DescribeStateMachineOutput, error)
	ListTagsForResource(ctx context.Context, params *sfn.ListTagsForResourceInput, optFns ...func(*sfn.Options)) (*sfn.ListTagsForResourceOutput, error)
}

type SDKStepFunctionsStateMachineRoleAPI struct {
	stepFunctionsClient StepFunctionsSDKClient
	accountID           string
	region              string
}

var _ StepFunctionsStateMachineRoleAPI = (*SDKStepFunctionsStateMachineRoleAPI)(nil)

func NewSDKStepFunctionsStateMachineRoleAPI(region string, profile string, accountID string) (StepFunctionsStateMachineRoleAPI, error) {
	return NewSDKStepFunctionsStateMachineRoleAPIWithContext(context.Background(), region, profile, accountID)
}

func NewSDKStepFunctionsStateMachineRoleAPIWithContext(ctx context.Context, region string, profile string, accountID string) (StepFunctionsStateMachineRoleAPI, error) {
	cfg, err := loadSDKConfig(ctx, region, profile)
	if err != nil {
		return nil, err
	}
	return NewSDKStepFunctionsStateMachineRoleAPIFromClient(sfn.NewFromConfig(cfg), accountID, region), nil
}

func NewSDKStepFunctionsStateMachineRoleAPIFromAssumeRole(ctx context.Context, region string, profile string, roleARN string, externalID string, sessionName string, accountID string) (StepFunctionsStateMachineRoleAPI, error) {
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
	return NewSDKStepFunctionsStateMachineRoleAPIFromClient(sfn.NewFromConfig(cfg), accountID, region), nil
}

func NewSDKStepFunctionsStateMachineRoleAPIFromClient(stepFunctionsClient StepFunctionsSDKClient, accountID string, region string) StepFunctionsStateMachineRoleAPI {
	return &SDKStepFunctionsStateMachineRoleAPI{
		stepFunctionsClient: stepFunctionsClient,
		accountID:           strings.TrimSpace(accountID),
		region:              strings.TrimSpace(region),
	}
}

func (a *SDKStepFunctionsStateMachineRoleAPI) ListServiceRoles(ctx context.Context, nextToken string, pageSize int32) (StepFunctionsStateMachineRolePage, error) {
	if a.stepFunctionsClient == nil {
		return StepFunctionsStateMachineRolePage{}, fmt.Errorf("stepfunctions sdk client is required")
	}
	input := &sfn.ListStateMachinesInput{MaxResults: pageSize}
	if token := strings.TrimSpace(nextToken); token != "" {
		input.NextToken = awsv2.String(token)
	}
	output, err := a.stepFunctionsClient.ListStateMachines(ctx, input)
	if err != nil {
		return StepFunctionsStateMachineRolePage{}, err
	}
	if output == nil || len(output.StateMachines) == 0 {
		return StepFunctionsStateMachineRolePage{NextToken: nextTokenFromStepFunctionsList(output)}, nil
	}

	records := []StepFunctionsStateMachineRole{}
	diagnostics := []providers.SourceError{}
	for _, summary := range output.StateMachines {
		if err := ctx.Err(); err != nil {
			return StepFunctionsStateMachineRolePage{}, err
		}
		stateMachineARN := strings.TrimSpace(awsv2.ToString(summary.StateMachineArn))
		if stateMachineARN == "" {
			diagnostics = append(diagnostics, stepFunctionsSourceDiagnostic("missing_state_machine_arn", "liststatemachines", "Step Functions list response included a state machine without an ARN", false))
			continue
		}
		describeOutput, definitionUnavailable, err := a.describeStateMachine(ctx, stateMachineARN)
		if err != nil {
			// Retryable AWS errors (throttling, KMS throttling, 5xx,
			// RequestLimitExceeded) must bubble back to retryAWSPage so
			// the whole page is retried under the existing backoff
			// policy. Anything else — non-retryable failures like
			// resource-not-found or contract violations — is reported as
			// a per-state-machine diagnostic so the rest of the page can
			// still be returned.
			if isRetryable(err) {
				return StepFunctionsStateMachineRolePage{}, fmt.Errorf("describe state machine %s: %w", stateMachineARN, err)
			}
			diagnostics = append(diagnostics, stepFunctionsSourceDiagnostic("state_machine_describe_failed", stateMachineARN, fmt.Sprintf("Step Functions state machine %s could not be described: %v", stateMachineARN, err), true))
			continue
		}
		if describeOutput == nil {
			diagnostics = append(diagnostics, stepFunctionsSourceDiagnostic("state_machine_not_found", stateMachineARN, "Step Functions state machine listed by ListStateMachines was not returned by DescribeStateMachine", true))
			continue
		}
		if definitionUnavailable != nil {
			diagnostics = append(diagnostics, stepFunctionsSourceDiagnostic("state_machine_definition_unavailable", stateMachineARN, fmt.Sprintf("Step Functions definition for state machine %s could not be read; retained metadata-only role evidence: %v", stateMachineARN, definitionUnavailable), true))
		}
		record := a.recordFromStateMachine(summary, describeOutput)
		tagsOutput, err := a.stepFunctionsClient.ListTagsForResource(ctx, &sfn.ListTagsForResourceInput{ResourceArn: awsv2.String(stateMachineARN)})
		if err != nil {
			diagnostics = append(diagnostics, stepFunctionsSourceDiagnostic("state_machine_tags_failed", stateMachineARN, fmt.Sprintf("Step Functions tags for state machine %s could not be read: %v", stateMachineARN, err), true))
		} else {
			record.Tags = stepFunctionsTags(tagsOutput)
		}
		records = append(records, record)
	}
	sort.SliceStable(records, func(i, j int) bool {
		return stepFunctionsStateMachineRoleSourceID(records[i]) < stepFunctionsStateMachineRoleSourceID(records[j])
	})
	return StepFunctionsStateMachineRolePage{Records: records, NextToken: nextTokenFromStepFunctionsList(output), Diagnostics: diagnostics}, nil
}

func (a *SDKStepFunctionsStateMachineRoleAPI) describeStateMachine(ctx context.Context, stateMachineARN string) (*sfn.DescribeStateMachineOutput, error, error) {
	allDataOutput, err := a.stepFunctionsClient.DescribeStateMachine(ctx, &sfn.DescribeStateMachineInput{
		StateMachineArn: awsv2.String(stateMachineARN),
		IncludedData:    sfntypes.IncludedDataAllData,
	})
	if err == nil {
		return allDataOutput, nil, nil
	}
	// Only fall back to the metadata-only describe when the all-data
	// describe failed because the definition could not be decrypted (the
	// KMS access denied / key-disabled cases, or a generic
	// AccessDeniedException on the definition action). Other failure
	// modes — throttling, KMS throttling, internal server errors,
	// timeouts — must propagate so the existing retryAWSPage policy can
	// run; silently downgrading them to `state_machine_definition_unavailable`
	// would swallow retryable signal and permanently drop the definition
	// hash, task resources, service integrations, and nested workflow
	// evidence for this state machine.
	if !isStepFunctionsDefinitionDecryptError(err) {
		return nil, nil, err
	}
	metadataOutput, metadataErr := a.stepFunctionsClient.DescribeStateMachine(ctx, &sfn.DescribeStateMachineInput{
		StateMachineArn: awsv2.String(stateMachineARN),
		IncludedData:    sfntypes.IncludedDataMetadataOnly,
	})
	if metadataErr != nil {
		return nil, nil, err
	}
	return metadataOutput, err, nil
}

// isStepFunctionsDefinitionDecryptError reports whether an error from
// DescribeStateMachine with IncludedData=ALL_DATA indicates that the
// state-machine definition could not be decrypted or read, so a
// metadata-only retry is a meaningful fallback. It deliberately excludes
// transient errors (throttling, KMS throttling, 5xx, timeout) which
// should propagate to the retry policy unchanged.
func isStepFunctionsDefinitionDecryptError(err error) bool {
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	switch strings.TrimSpace(apiErr.ErrorCode()) {
	case "KMSAccessDeniedException",
		"KmsAccessDeniedException",
		"KMSInvalidStateException",
		"KmsInvalidStateException",
		"AccessDeniedException",
		"AccessDenied":
		return true
	}
	return false
}

func (a *SDKStepFunctionsStateMachineRoleAPI) recordFromStateMachine(summary sfntypes.StateMachineListItem, describe *sfn.DescribeStateMachineOutput) StepFunctionsStateMachineRole {
	stateMachineARN := strings.TrimSpace(awsv2.ToString(describe.StateMachineArn))
	if stateMachineARN == "" {
		stateMachineARN = strings.TrimSpace(awsv2.ToString(summary.StateMachineArn))
	}
	stateMachineName := firstNonEmptyAWSValue(awsv2.ToString(describe.Name), awsv2.ToString(summary.Name), stepFunctionsStateMachineNameFromARN(stateMachineARN))
	roleARN := strings.TrimSpace(awsv2.ToString(describe.RoleArn))
	definition := stepFunctionsDefinitionMetadata(awsv2.ToString(describe.Definition))
	logLevel, includeExecutionData, logGroupARNs := stepFunctionsLoggingMetadata(describe.LoggingConfiguration)
	encryptionType, kmsKeyARN := stepFunctionsEncryptionMetadata(describe.EncryptionConfiguration)
	record := StepFunctionsStateMachineRole{
		ServiceCollectorRecord: awscontract.ServiceCollectorRecord{
			AccountID:     a.accountID,
			Region:        a.region,
			Service:       stepFunctionsServiceName,
			WorkloadID:    firstNonEmptyAWSValue(stateMachineARN, stateMachineName),
			WorkloadType:  "stepfunctions_state_machine",
			WorkloadName:  stateMachineName,
			RoleARN:       roleARN,
			Source:        "describestatemachine",
			EvidenceRef:   firstNonEmptyAWSValue(stateMachineARN, stateMachineName),
			Confidence:    0.96,
			CollectorName: stepFunctionsStateMachineRoleCollectorName,
		},
		RoleName:                    roleNameFromARN(roleARN),
		RoleAccountID:               roleAccountIDFromARN(roleARN),
		StateMachineARN:             stateMachineARN,
		StateMachineName:            stateMachineName,
		StateMachineType:            string(describe.Type),
		StateMachineStatus:          string(describe.Status),
		RevisionID:                  strings.TrimSpace(awsv2.ToString(describe.RevisionId)),
		Description:                 strings.TrimSpace(awsv2.ToString(describe.Description)),
		DefinitionSHA256:            definition.Hash,
		DefinitionResourceARNs:      definition.ResourceARNs,
		TaskResourceARNs:            definition.TaskResourceARNs,
		ServiceIntegrationResources: definition.ServiceIntegrations,
		NestedStateMachineARNs:      definition.NestedStateMachineARNs,
		LoggingLevel:                logLevel,
		LoggingIncludeExecutionData: includeExecutionData,
		LogGroupARNs:                logGroupARNs,
		TracingEnabled:              describe.TracingConfiguration != nil && describe.TracingConfiguration.Enabled,
		EncryptionType:              encryptionType,
		KMSKeyARN:                   kmsKeyARN,
	}
	record.Confidence = stepFunctionsStateMachineRoleConfidence(record)
	return record
}

func nextTokenFromStepFunctionsList(output *sfn.ListStateMachinesOutput) string {
	if output == nil {
		return ""
	}
	return strings.TrimSpace(awsv2.ToString(output.NextToken))
}

func stepFunctionsSourceDiagnostic(code string, sourceID string, message string, retryable bool) providers.SourceError {
	return providers.SourceError{
		Collector: stepFunctionsStateMachineRoleCollectorName,
		SourceID:  strings.TrimSpace(sourceID),
		Code:      strings.TrimSpace(code),
		Message:   strings.TrimSpace(message),
		Retryable: retryable,
	}
}

type stepFunctionsDefinitionSummary struct {
	Hash                   string
	ResourceARNs           []string
	TaskResourceARNs       []string
	ServiceIntegrations    []string
	NestedStateMachineARNs []string
}

func stepFunctionsDefinitionMetadata(definition string) stepFunctionsDefinitionSummary {
	trimmed := strings.TrimSpace(definition)
	if trimmed == "" || trimmed == "{}" {
		return stepFunctionsDefinitionSummary{}
	}
	summary := stepFunctionsDefinitionSummary{}
	hash := sha256.Sum256([]byte(trimmed))
	summary.Hash = hex.EncodeToString(hash[:])
	var parsed any
	if err := json.Unmarshal([]byte(trimmed), &parsed); err != nil {
		return summary
	}
	resourceARNs := map[string]struct{}{}
	taskARNs := map[string]struct{}{}
	integrations := map[string]struct{}{}
	nested := map[string]struct{}{}
	var walk func(value any, key string)
	walk = func(value any, key string) {
		if shouldSkipStepFunctionsDefinitionSubtree(key) {
			return
		}
		switch typed := value.(type) {
		case map[string]any:
			keys := make([]string, 0, len(typed))
			for childKey := range typed {
				keys = append(keys, childKey)
			}
			sort.Strings(keys)
			for _, childKey := range keys {
				walk(typed[childKey], childKey)
			}
		case []any:
			for _, child := range typed {
				walk(child, key)
			}
		case string:
			collectStepFunctionsDefinitionString(typed, key, resourceARNs, taskARNs, integrations, nested)
		}
	}
	walk(parsed, "")
	summary.ResourceARNs = sortedKeys(resourceARNs)
	summary.TaskResourceARNs = sortedKeys(taskARNs)
	summary.ServiceIntegrations = sortedKeys(integrations)
	summary.NestedStateMachineARNs = sortedKeys(nested)
	return summary
}

func collectStepFunctionsDefinitionString(value string, key string, resourceARNs map[string]struct{}, taskARNs map[string]struct{}, integrations map[string]struct{}, nested map[string]struct{}) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return
	}
	lowerKey := strings.ToLower(strings.TrimSpace(key))
	if strings.HasPrefix(trimmed, "arn:") {
		if !isStepFunctionsDefinitionReferenceKey(lowerKey) {
			return
		}
		resourceARNs[trimmed] = struct{}{}
		if lowerKey == "resource" {
			taskARNs[trimmed] = struct{}{}
		}
		if strings.Contains(trimmed, ":states:") && strings.Contains(trimmed, ":stateMachine:") {
			nested[trimmed] = struct{}{}
		}
		if integration := stepFunctionsServiceIntegration(trimmed); integration != "" {
			integrations[integration] = struct{}{}
		}
	}
}

func shouldSkipStepFunctionsDefinitionSubtree(key string) bool {
	switch strings.ToLower(strings.TrimSpace(key)) {
	case "payload", "result":
		return true
	default:
		return false
	}
}

func isStepFunctionsDefinitionReferenceKey(lowerKey string) bool {
	switch lowerKey {
	case "resource",
		"functionname",
		"statemachinearn",
		"rolearn",
		"topicarn",
		"queuearn",
		"streamarn",
		"tablearn",
		"kmskeyarn",
		"loggrouparn",
		"cluster",
		"taskdefinition",
		"eventbusname",
		"secretid":
		return true
	default:
		return false
	}
}

func stepFunctionsServiceIntegration(resource string) string {
	parts := strings.SplitN(resource, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || parts[2] != "states" || parts[3] != "" || parts[4] != "" {
		return ""
	}
	rest := parts[5]
	if strings.HasPrefix(rest, "aws-sdk:") {
		rest = strings.TrimPrefix(rest, "aws-sdk:")
	}
	end := len(rest)
	for _, sep := range []string{":", "."} {
		if idx := strings.Index(rest, sep); idx >= 0 && idx < end {
			end = idx
		}
	}
	return strings.TrimSpace(rest[:end])
}

func stepFunctionsLoggingMetadata(logging *sfntypes.LoggingConfiguration) (string, bool, []string) {
	if logging == nil {
		return "", false, nil
	}
	logGroups := []string{}
	for _, destination := range logging.Destinations {
		if destination.CloudWatchLogsLogGroup == nil {
			continue
		}
		if arn := strings.TrimSpace(awsv2.ToString(destination.CloudWatchLogsLogGroup.LogGroupArn)); arn != "" {
			logGroups = append(logGroups, arn)
		}
	}
	return string(logging.Level), logging.IncludeExecutionData, normalizeStringList(logGroups)
}

func stepFunctionsEncryptionMetadata(encryption *sfntypes.EncryptionConfiguration) (string, string) {
	if encryption == nil {
		return "", ""
	}
	return string(encryption.Type), strings.TrimSpace(awsv2.ToString(encryption.KmsKeyId))
}

func stepFunctionsTags(output *sfn.ListTagsForResourceOutput) map[string]string {
	if output == nil || len(output.Tags) == 0 {
		return nil
	}
	tags := map[string]string{}
	for _, tag := range output.Tags {
		key := strings.TrimSpace(awsv2.ToString(tag.Key))
		if key == "" {
			continue
		}
		tags[key] = strings.TrimSpace(awsv2.ToString(tag.Value))
	}
	return tags
}

func sortedKeys(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	sort.Strings(result)
	return normalizeStringList(result)
}
