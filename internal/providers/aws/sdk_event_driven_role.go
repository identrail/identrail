package aws

import (
	"context"
	"fmt"
	"sort"
	"strings"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	eventbridgetypes "github.com/aws/aws-sdk-go-v2/service/eventbridge/types"
	"github.com/aws/aws-sdk-go-v2/service/pipes"
	pipestypes "github.com/aws/aws-sdk-go-v2/service/pipes/types"
	"github.com/aws/aws-sdk-go-v2/service/scheduler"
	schedulertypes "github.com/aws/aws-sdk-go-v2/service/scheduler/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/identrail/identrail/internal/providers"
	"github.com/identrail/identrail/internal/providers/awscontract"
	"github.com/identrail/identrail/internal/textutil"
)

type EventBridgeSDKClient interface {
	ListEventBuses(ctx context.Context, params *eventbridge.ListEventBusesInput, optFns ...func(*eventbridge.Options)) (*eventbridge.ListEventBusesOutput, error)
	ListRules(ctx context.Context, params *eventbridge.ListRulesInput, optFns ...func(*eventbridge.Options)) (*eventbridge.ListRulesOutput, error)
	ListTargetsByRule(ctx context.Context, params *eventbridge.ListTargetsByRuleInput, optFns ...func(*eventbridge.Options)) (*eventbridge.ListTargetsByRuleOutput, error)
	ListTagsForResource(ctx context.Context, params *eventbridge.ListTagsForResourceInput, optFns ...func(*eventbridge.Options)) (*eventbridge.ListTagsForResourceOutput, error)
}

type SchedulerSDKClient interface {
	ListSchedules(ctx context.Context, params *scheduler.ListSchedulesInput, optFns ...func(*scheduler.Options)) (*scheduler.ListSchedulesOutput, error)
	GetSchedule(ctx context.Context, params *scheduler.GetScheduleInput, optFns ...func(*scheduler.Options)) (*scheduler.GetScheduleOutput, error)
}

type PipesSDKClient interface {
	ListPipes(ctx context.Context, params *pipes.ListPipesInput, optFns ...func(*pipes.Options)) (*pipes.ListPipesOutput, error)
	DescribePipe(ctx context.Context, params *pipes.DescribePipeInput, optFns ...func(*pipes.Options)) (*pipes.DescribePipeOutput, error)
}

type SDKEventDrivenRoleAPI struct {
	eventBridgeClient EventBridgeSDKClient
	schedulerClient   SchedulerSDKClient
	pipesClient       PipesSDKClient
	accountID         string
	region            string
}

var _ EventDrivenRoleAPI = (*SDKEventDrivenRoleAPI)(nil)

func NewSDKEventDrivenRoleAPI(region string, profile string, accountID string) (EventDrivenRoleAPI, error) {
	return NewSDKEventDrivenRoleAPIWithContext(context.Background(), region, profile, accountID)
}

func NewSDKEventDrivenRoleAPIWithContext(ctx context.Context, region string, profile string, accountID string) (EventDrivenRoleAPI, error) {
	cfg, err := loadSDKConfig(ctx, region, profile)
	if err != nil {
		return nil, err
	}
	return NewSDKEventDrivenRoleAPIFromClients(eventbridge.NewFromConfig(cfg), scheduler.NewFromConfig(cfg), pipes.NewFromConfig(cfg), accountID, region), nil
}

func NewSDKEventDrivenRoleAPIFromAssumeRole(ctx context.Context, region string, profile string, roleARN string, externalID string, sessionName string, accountID string) (EventDrivenRoleAPI, error) {
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
	return NewSDKEventDrivenRoleAPIFromClients(eventbridge.NewFromConfig(cfg), scheduler.NewFromConfig(cfg), pipes.NewFromConfig(cfg), accountID, region), nil
}

func NewSDKEventDrivenRoleAPIFromClients(eventBridgeClient EventBridgeSDKClient, schedulerClient SchedulerSDKClient, pipesClient PipesSDKClient, accountID string, region string) EventDrivenRoleAPI {
	return &SDKEventDrivenRoleAPI{
		eventBridgeClient: eventBridgeClient,
		schedulerClient:   schedulerClient,
		pipesClient:       pipesClient,
		accountID:         strings.TrimSpace(accountID),
		region:            strings.TrimSpace(region),
	}
}

func (a *SDKEventDrivenRoleAPI) ListServiceRoles(ctx context.Context, _ string, pageSize int32) (EventDrivenRolePage, error) {
	records := []EventDrivenRole{}
	diagnostics := []providers.SourceError{}
	if a.eventBridgeClient != nil {
		eventBridgeRecords, eventBridgeDiagnostics, err := a.listEventBridgeRuleRoles(ctx, pageSize)
		if err != nil {
			if isRetryable(err) {
				return EventDrivenRolePage{}, err
			}
			diagnostics = append(diagnostics, eventDrivenSourceDiagnostic("eventbridge_rules_failed", "eventbridge", fmt.Sprintf("EventBridge rules could not be listed: %v", err), true))
		}
		records = append(records, eventBridgeRecords...)
		diagnostics = append(diagnostics, eventBridgeDiagnostics...)
	}
	if a.schedulerClient != nil {
		scheduleRecords, scheduleDiagnostics, err := a.listSchedulerRoles(ctx, pageSize)
		if err != nil {
			if isRetryable(err) {
				return EventDrivenRolePage{}, err
			}
			diagnostics = append(diagnostics, eventDrivenSourceDiagnostic("scheduler_schedules_failed", "scheduler", fmt.Sprintf("EventBridge Scheduler schedules could not be listed: %v", err), true))
		}
		records = append(records, scheduleRecords...)
		diagnostics = append(diagnostics, scheduleDiagnostics...)
	}
	if a.pipesClient != nil {
		pipeRecords, pipeDiagnostics, err := a.listPipeRoles(ctx, pageSize)
		if err != nil {
			if isRetryable(err) {
				return EventDrivenRolePage{}, err
			}
			diagnostics = append(diagnostics, eventDrivenSourceDiagnostic("pipes_failed", "pipes", fmt.Sprintf("EventBridge Pipes could not be listed: %v", err), true))
		}
		records = append(records, pipeRecords...)
		diagnostics = append(diagnostics, pipeDiagnostics...)
	}
	sort.SliceStable(records, func(i, j int) bool {
		return eventDrivenRoleSourceID(records[i]) < eventDrivenRoleSourceID(records[j])
	})
	return EventDrivenRolePage{Records: records, Diagnostics: diagnostics}, nil
}

func (a *SDKEventDrivenRoleAPI) listEventBridgeRuleRoles(ctx context.Context, pageSize int32) ([]EventDrivenRole, []providers.SourceError, error) {
	eventBuses, err := a.listEventBuses(ctx, pageSize)
	if err != nil {
		return nil, nil, err
	}
	records := []EventDrivenRole{}
	diagnostics := []providers.SourceError{}
	for _, bus := range eventBuses {
		busName := strings.TrimSpace(awsv2.ToString(bus.Name))
		busARN := strings.TrimSpace(awsv2.ToString(bus.Arn))
		token := ""
		for {
			output, err := a.eventBridgeClient.ListRules(ctx, &eventbridge.ListRulesInput{
				EventBusName: awsv2.String(firstNonEmptyAWSValue(busName, busARN)),
				Limit:        awsv2.Int32(pageSize),
				NextToken:    stringPtrOrNil(token),
			})
			if err != nil {
				diagnostics = append(diagnostics, eventDrivenSourceDiagnostic("eventbridge_rule_list_failed", firstNonEmptyAWSValue(busARN, busName), fmt.Sprintf("EventBridge rules for bus %s could not be listed: %v", firstNonEmptyAWSValue(busName, busARN), err), true))
				break
			}
			if output == nil {
				break
			}
			for _, rule := range output.Rules {
				ruleRecords, ruleDiagnostics := a.recordsFromEventBridgeRule(ctx, busName, busARN, rule, pageSize)
				records = append(records, ruleRecords...)
				diagnostics = append(diagnostics, ruleDiagnostics...)
			}
			token = strings.TrimSpace(awsv2.ToString(output.NextToken))
			if token == "" {
				break
			}
		}
	}
	return records, diagnostics, nil
}

func (a *SDKEventDrivenRoleAPI) listEventBuses(ctx context.Context, pageSize int32) ([]eventbridgetypes.EventBus, error) {
	eventBuses := []eventbridgetypes.EventBus{}
	token := ""
	for {
		output, err := a.eventBridgeClient.ListEventBuses(ctx, &eventbridge.ListEventBusesInput{
			Limit:     awsv2.Int32(pageSize),
			NextToken: stringPtrOrNil(token),
		})
		if err != nil {
			return nil, err
		}
		if output == nil {
			break
		}
		eventBuses = append(eventBuses, output.EventBuses...)
		token = strings.TrimSpace(awsv2.ToString(output.NextToken))
		if token == "" {
			break
		}
	}
	if len(eventBuses) == 0 {
		eventBuses = append(eventBuses, eventbridgetypes.EventBus{Name: awsv2.String("default")})
	}
	return eventBuses, nil
}

func (a *SDKEventDrivenRoleAPI) recordsFromEventBridgeRule(ctx context.Context, busName string, busARN string, rule eventbridgetypes.Rule, pageSize int32) ([]EventDrivenRole, []providers.SourceError) {
	ruleARN := strings.TrimSpace(awsv2.ToString(rule.Arn))
	ruleName := strings.TrimSpace(awsv2.ToString(rule.Name))
	state := string(rule.State)
	base := EventDrivenRole{
		ServiceCollectorRecord: awscontract.ServiceCollectorRecord{
			AccountID:     a.accountID,
			Region:        a.region,
			Service:       "eventbridge",
			WorkloadID:    firstNonEmptyAWSValue(ruleARN, ruleName),
			WorkloadType:  "eventbridge_rule",
			WorkloadName:  ruleName,
			RoleARN:       strings.TrimSpace(awsv2.ToString(rule.RoleArn)),
			Source:        "listrules",
			EvidenceRef:   firstNonEmptyAWSValue(ruleARN, ruleName),
			Confidence:    0.9,
			CollectorName: eventDrivenRoleCollectorName,
		},
		RoleName:           roleNameFromARN(awsv2.ToString(rule.RoleArn)),
		RoleKind:           "eventbridge_rule_role",
		RoleAccountID:      roleAccountIDFromARN(awsv2.ToString(rule.RoleArn)),
		WorkloadARN:        ruleARN,
		EventBusName:       firstNonEmptyAWSValue(busName, awsv2.ToString(rule.EventBusName)),
		EventBusARN:        busARN,
		TargetService:      "eventbridge",
		EventPatternSHA256: sha256Hex(awsv2.ToString(rule.EventPattern)),
		Active:             strings.HasPrefix(state, "ENABLED"),
		Disabled:           strings.EqualFold(state, "DISABLED"),
	}
	base.Confidence = eventDrivenRoleConfidence(base)
	records := []EventDrivenRole{}
	if strings.TrimSpace(base.RoleARN) != "" {
		records = append(records, base)
	}
	diagnostics := []providers.SourceError{}
	targetToken := ""
	for {
		output, err := a.eventBridgeClient.ListTargetsByRule(ctx, &eventbridge.ListTargetsByRuleInput{
			EventBusName: awsv2.String(firstNonEmptyAWSValue(base.EventBusName, base.EventBusARN)),
			Rule:         awsv2.String(ruleName),
			Limit:        awsv2.Int32(pageSize),
			NextToken:    stringPtrOrNil(targetToken),
		})
		if err != nil {
			diagnostics = append(diagnostics, eventDrivenSourceDiagnostic("eventbridge_targets_failed", firstNonEmptyAWSValue(ruleARN, ruleName), fmt.Sprintf("EventBridge targets for rule %s could not be listed: %v", ruleName, err), true))
			break
		}
		if output == nil {
			break
		}
		for _, target := range output.Targets {
			targetRoleARN := strings.TrimSpace(awsv2.ToString(target.RoleArn))
			if targetRoleARN == "" {
				continue
			}
			record := base
			record.RoleARN = targetRoleARN
			record.RoleName = roleNameFromARN(targetRoleARN)
			record.RoleKind = "eventbridge_target_role"
			record.RoleAccountID = roleAccountIDFromARN(targetRoleARN)
			record.TargetARN = strings.TrimSpace(awsv2.ToString(target.Arn))
			record.TargetID = strings.TrimSpace(awsv2.ToString(target.Id))
			record.TargetService = awsServiceFromARN(record.TargetARN)
			record.Source = "listtargetsbyrule"
			record.EvidenceRef = firstNonEmptyAWSValue(ruleARN, ruleName) + "#target/" + record.TargetID
			record.DeadLetterARNs = eventBridgeTargetDLQs(target)
			record.InputPathConfigured = strings.TrimSpace(awsv2.ToString(target.InputPath)) != ""
			record.TargetInputConfigured = strings.TrimSpace(awsv2.ToString(target.Input)) != ""
			record.InputTransformerSHA256 = eventBridgeInputTransformerHash(target.InputTransformer)
			if target.RetryPolicy != nil {
				record.RetryMaximumAgeSeconds = awsv2.ToInt32(target.RetryPolicy.MaximumEventAgeInSeconds)
				record.RetryMaximumAttempts = awsv2.ToInt32(target.RetryPolicy.MaximumRetryAttempts)
			}
			record.Confidence = eventDrivenRoleConfidence(record)
			records = append(records, record)
		}
		targetToken = strings.TrimSpace(awsv2.ToString(output.NextToken))
		if targetToken == "" {
			break
		}
	}
	if ruleARN != "" {
		tagsOutput, err := a.eventBridgeClient.ListTagsForResource(ctx, &eventbridge.ListTagsForResourceInput{ResourceARN: awsv2.String(ruleARN)})
		if err == nil {
			tags := eventBridgeTags(tagsOutput)
			for idx := range records {
				records[idx].Tags = tags
			}
		}
	}
	return records, diagnostics
}

func (a *SDKEventDrivenRoleAPI) listSchedulerRoles(ctx context.Context, pageSize int32) ([]EventDrivenRole, []providers.SourceError, error) {
	records := []EventDrivenRole{}
	diagnostics := []providers.SourceError{}
	token := ""
	for {
		output, err := a.schedulerClient.ListSchedules(ctx, &scheduler.ListSchedulesInput{
			MaxResults: awsv2.Int32(pageSize),
			NextToken:  stringPtrOrNil(token),
		})
		if err != nil {
			return records, diagnostics, err
		}
		if output == nil {
			break
		}
		for _, summary := range output.Schedules {
			name := strings.TrimSpace(awsv2.ToString(summary.Name))
			group := strings.TrimSpace(awsv2.ToString(summary.GroupName))
			if name == "" {
				diagnostics = append(diagnostics, eventDrivenSourceDiagnostic("scheduler_schedule_name_missing", "listschedules", "EventBridge Scheduler list response included a schedule without a name", false))
				continue
			}
			describe, err := a.schedulerClient.GetSchedule(ctx, &scheduler.GetScheduleInput{Name: awsv2.String(name), GroupName: stringPtrOrNil(group)})
			if err != nil {
				diagnostics = append(diagnostics, eventDrivenSourceDiagnostic("scheduler_schedule_get_failed", firstNonEmptyAWSValue(group+"/"+name, name), fmt.Sprintf("EventBridge Scheduler schedule %s could not be described: %v", name, err), true))
				continue
			}
			if describe == nil || describe.Target == nil {
				diagnostics = append(diagnostics, eventDrivenSourceDiagnostic("scheduler_schedule_target_missing", firstNonEmptyAWSValue(group+"/"+name, name), "EventBridge Scheduler schedule did not include target metadata", false))
				continue
			}
			record := a.recordFromSchedule(describe)
			records = append(records, record)
		}
		token = strings.TrimSpace(awsv2.ToString(output.NextToken))
		if token == "" {
			break
		}
	}
	return records, diagnostics, nil
}

func (a *SDKEventDrivenRoleAPI) recordFromSchedule(schedule *scheduler.GetScheduleOutput) EventDrivenRole {
	target := schedule.Target
	roleARN := strings.TrimSpace(awsv2.ToString(target.RoleArn))
	scheduleARN := strings.TrimSpace(awsv2.ToString(schedule.Arn))
	targetARN := strings.TrimSpace(awsv2.ToString(target.Arn))
	record := EventDrivenRole{
		ServiceCollectorRecord: awscontract.ServiceCollectorRecord{
			AccountID:     a.accountID,
			Region:        a.region,
			Service:       "scheduler",
			WorkloadID:    firstNonEmptyAWSValue(scheduleARN, awsv2.ToString(schedule.Name)),
			WorkloadType:  "scheduler_schedule",
			WorkloadName:  strings.TrimSpace(awsv2.ToString(schedule.Name)),
			RoleARN:       roleARN,
			Source:        "getschedule",
			EvidenceRef:   firstNonEmptyAWSValue(scheduleARN, awsv2.ToString(schedule.Name)),
			Confidence:    0.94,
			CollectorName: eventDrivenRoleCollectorName,
		},
		RoleName:               roleNameFromARN(roleARN),
		RoleKind:               "scheduler_schedule_role",
		RoleAccountID:          roleAccountIDFromARN(roleARN),
		WorkloadARN:            scheduleARN,
		ScheduleGroupName:      strings.TrimSpace(awsv2.ToString(schedule.GroupName)),
		ScheduleExpression:     strings.TrimSpace(awsv2.ToString(schedule.ScheduleExpression)),
		ScheduleTimezone:       strings.TrimSpace(awsv2.ToString(schedule.ScheduleExpressionTimezone)),
		TargetARN:              targetARN,
		TargetService:          awsServiceFromARN(targetARN),
		DeadLetterARNs:         schedulerTargetDLQs(target),
		TargetInputConfigured:  strings.TrimSpace(awsv2.ToString(target.Input)) != "",
		KMSKeyARN:              strings.TrimSpace(awsv2.ToString(schedule.KmsKeyArn)),
		Active:                 schedule.State == schedulertypes.ScheduleStateEnabled,
		Disabled:               schedule.State == schedulertypes.ScheduleStateDisabled,
		RetryMaximumAgeSeconds: 0,
		RetryMaximumAttempts:   0,
	}
	if target.RetryPolicy != nil {
		record.RetryMaximumAgeSeconds = awsv2.ToInt32(target.RetryPolicy.MaximumEventAgeInSeconds)
		record.RetryMaximumAttempts = awsv2.ToInt32(target.RetryPolicy.MaximumRetryAttempts)
	}
	record.Confidence = eventDrivenRoleConfidence(record)
	return record
}

func (a *SDKEventDrivenRoleAPI) listPipeRoles(ctx context.Context, pageSize int32) ([]EventDrivenRole, []providers.SourceError, error) {
	records := []EventDrivenRole{}
	diagnostics := []providers.SourceError{}
	token := ""
	for {
		output, err := a.pipesClient.ListPipes(ctx, &pipes.ListPipesInput{
			Limit:     awsv2.Int32(pageSize),
			NextToken: stringPtrOrNil(token),
		})
		if err != nil {
			return records, diagnostics, err
		}
		if output == nil {
			break
		}
		for _, pipe := range output.Pipes {
			name := strings.TrimSpace(awsv2.ToString(pipe.Name))
			if name == "" {
				diagnostics = append(diagnostics, eventDrivenSourceDiagnostic("pipe_name_missing", "listpipes", "EventBridge Pipes list response included a pipe without a name", false))
				continue
			}
			describe, err := a.pipesClient.DescribePipe(ctx, &pipes.DescribePipeInput{Name: awsv2.String(name)})
			if err != nil {
				diagnostics = append(diagnostics, eventDrivenSourceDiagnostic("pipe_describe_failed", name, fmt.Sprintf("EventBridge Pipe %s could not be described: %v", name, err), true))
				continue
			}
			if describe == nil {
				continue
			}
			records = append(records, a.recordFromPipe(describe))
		}
		token = strings.TrimSpace(awsv2.ToString(output.NextToken))
		if token == "" {
			break
		}
	}
	return records, diagnostics, nil
}

func (a *SDKEventDrivenRoleAPI) recordFromPipe(pipe *pipes.DescribePipeOutput) EventDrivenRole {
	roleARN := strings.TrimSpace(awsv2.ToString(pipe.RoleArn))
	pipeARN := strings.TrimSpace(awsv2.ToString(pipe.Arn))
	targetARN := strings.TrimSpace(awsv2.ToString(pipe.Target))
	record := EventDrivenRole{
		ServiceCollectorRecord: awscontract.ServiceCollectorRecord{
			AccountID:     a.accountID,
			Region:        a.region,
			Service:       "pipes",
			WorkloadID:    firstNonEmptyAWSValue(pipeARN, awsv2.ToString(pipe.Name)),
			WorkloadType:  "eventbridge_pipe",
			WorkloadName:  strings.TrimSpace(awsv2.ToString(pipe.Name)),
			RoleARN:       roleARN,
			Source:        "describepipe",
			EvidenceRef:   firstNonEmptyAWSValue(pipeARN, awsv2.ToString(pipe.Name)),
			Confidence:    0.94,
			CollectorName: eventDrivenRoleCollectorName,
		},
		RoleName:             roleNameFromARN(roleARN),
		RoleKind:             "pipe_execution_role",
		RoleAccountID:        roleAccountIDFromARN(roleARN),
		WorkloadARN:          pipeARN,
		PipeSourceARN:        strings.TrimSpace(awsv2.ToString(pipe.Source)),
		PipeTargetARN:        targetARN,
		PipeEnrichmentARN:    strings.TrimSpace(awsv2.ToString(pipe.Enrichment)),
		TargetARN:            targetARN,
		TargetService:        awsServiceFromARN(targetARN),
		DeadLetterARNs:       pipeDLQs(pipe.SourceParameters, pipe.TargetParameters),
		ExecutionDataLogging: pipeExecutionDataLogging(pipe.LogConfiguration),
		LogDestinationARNs:   pipeLogDestinationARNs(pipe.LogConfiguration),
		KMSKeyARN:            strings.TrimSpace(awsv2.ToString(pipe.KmsKeyIdentifier)),
		Active:               pipe.CurrentState == pipestypes.PipeStateRunning,
		Disabled:             pipe.CurrentState == pipestypes.PipeStateStopped,
		StateReason:          strings.TrimSpace(awsv2.ToString(pipe.StateReason)),
		Tags:                 copyTags(pipe.Tags),
	}
	record.Confidence = eventDrivenRoleConfidence(record)
	return record
}

func eventDrivenSourceDiagnostic(code string, sourceID string, message string, retryable bool) providers.SourceError {
	return providers.SourceError{
		Collector: eventDrivenRoleCollectorName,
		SourceID:  strings.TrimSpace(sourceID),
		Code:      strings.TrimSpace(code),
		Message:   strings.TrimSpace(message),
		Retryable: retryable,
	}
}

func stringPtrOrNil(value string) *string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return awsv2.String(strings.TrimSpace(value))
}

func eventBridgeTargetDLQs(target eventbridgetypes.Target) []string {
	if target.DeadLetterConfig == nil {
		return nil
	}
	return normalizeStringList([]string{awsv2.ToString(target.DeadLetterConfig.Arn)})
}

func schedulerTargetDLQs(target *schedulertypes.Target) []string {
	if target == nil || target.DeadLetterConfig == nil {
		return nil
	}
	return normalizeStringList([]string{awsv2.ToString(target.DeadLetterConfig.Arn)})
}

func pipeDLQs(source *pipestypes.PipeSourceParameters, target *pipestypes.PipeTargetParameters) []string {
	values := []string{}
	if source != nil && source.KinesisStreamParameters != nil && source.KinesisStreamParameters.DeadLetterConfig != nil {
		values = append(values, awsv2.ToString(source.KinesisStreamParameters.DeadLetterConfig.Arn))
	}
	if target != nil && target.SqsQueueParameters != nil {
		// SQS target parameters do not define a DLQ. Keep this branch explicit
		// so future SDK fields do not tempt callers to read message bodies.
	}
	return normalizeStringList(values)
}

func eventBridgeInputTransformerHash(transformer *eventbridgetypes.InputTransformer) string {
	if transformer == nil {
		return ""
	}
	keys := make([]string, 0, len(transformer.InputPathsMap))
	for key := range transformer.InputPathsMap {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return sha256Hex(strings.Join(keys, ",") + "|" + awsv2.ToString(transformer.InputTemplate))
}

func eventBridgeTags(output *eventbridge.ListTagsForResourceOutput) map[string]string {
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

func pipeExecutionDataLogging(logging *pipestypes.PipeLogConfiguration) bool {
	if logging == nil {
		return false
	}
	return len(logging.IncludeExecutionData) > 0
}

func pipeLogDestinationARNs(logging *pipestypes.PipeLogConfiguration) []string {
	if logging == nil {
		return nil
	}
	values := []string{}
	if logging.CloudwatchLogsLogDestination != nil {
		values = append(values, awsv2.ToString(logging.CloudwatchLogsLogDestination.LogGroupArn))
	}
	if logging.FirehoseLogDestination != nil {
		values = append(values, awsv2.ToString(logging.FirehoseLogDestination.DeliveryStreamArn))
	}
	if logging.S3LogDestination != nil {
		values = append(values, awsv2.ToString(logging.S3LogDestination.BucketName))
	}
	return normalizeStringList(values)
}
