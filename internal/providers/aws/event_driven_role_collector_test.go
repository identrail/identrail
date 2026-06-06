package aws

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	eventbridgetypes "github.com/aws/aws-sdk-go-v2/service/eventbridge/types"
	"github.com/aws/aws-sdk-go-v2/service/pipes"
	pipestypes "github.com/aws/aws-sdk-go-v2/service/pipes/types"
	"github.com/aws/aws-sdk-go-v2/service/scheduler"
	schedulertypes "github.com/aws/aws-sdk-go-v2/service/scheduler/types"
	"github.com/identrail/identrail/internal/domain"
	"github.com/identrail/identrail/internal/providers"
	"github.com/identrail/identrail/internal/providers/awscontract"
)

type fakeEventDrivenRoleAPI struct {
	pages     []EventDrivenRolePage
	tokens    []string
	pageSizes []int32
}

func (f *fakeEventDrivenRoleAPI) ListServiceRoles(ctx context.Context, nextToken string, pageSize int32) (EventDrivenRolePage, error) {
	f.tokens = append(f.tokens, nextToken)
	f.pageSizes = append(f.pageSizes, pageSize)
	if len(f.pages) == 0 {
		return EventDrivenRolePage{}, nil
	}
	page := f.pages[0]
	f.pages = f.pages[1:]
	return page, nil
}

func TestEventDrivenRoleCollectorEmitsPayloadSafeDisabledAsset(t *testing.T) {
	collectedAt := time.Date(2026, 6, 6, 12, 0, 0, 0, time.UTC)
	roleARN := "arn:aws:iam::123456789012:role/scheduler-entitlement-refresh"
	scheduleARN := "arn:aws:scheduler:us-east-1:123456789012:schedule/default/daily-entitlement-refresh"
	api := &fakeEventDrivenRoleAPI{pages: []EventDrivenRolePage{{
		Records: []EventDrivenRole{{
			ServiceCollectorRecord: awscontract.ServiceCollectorRecord{
				AccountID:    "123456789012",
				Region:       "us-east-1",
				Service:      "scheduler",
				WorkloadID:   scheduleARN,
				WorkloadName: "daily-entitlement-refresh",
				WorkloadType: "scheduler_schedule",
				RoleARN:      roleARN,
			},
			WorkloadARN:           scheduleARN,
			ScheduleGroupName:     "default",
			ScheduleExpression:    "rate(1 day)",
			TargetARN:             "arn:aws:states:us-east-1:123456789012:stateMachine:refresh-entitlements",
			DeadLetterARNs:        []string{"arn:aws:sqs:us-east-1:123456789012:scheduler-dlq"},
			TargetInputConfigured: true,
			Disabled:              true,
			StateReason:           "operator disabled",
		}},
		NextToken: "page-2",
	}, {
		Diagnostics: []providers.SourceError{{
			Collector: eventDrivenRoleCollectorName,
			SourceID:  "pipes",
			Code:      "pipe_describe_failed",
			Message:   "one pipe failed",
			Retryable: true,
		}},
	}}}
	collector := NewEventDrivenRoleCollector(api, WithEventDrivenRolePageSize(31), WithEventDrivenRoleClock(func() time.Time { return collectedAt }))

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
	if len(assets) != 1 || len(diagnostics) != 1 || diagnostics[0].Code != "pipe_describe_failed" {
		t.Fatalf("expected one asset and retained diagnostic, assets=%d diagnostics=%+v", len(assets), diagnostics)
	}
	if got, want := strings.Join(api.tokens, ","), ",page-2"; got != want {
		t.Fatalf("expected next tokens %q, got %q", want, got)
	}
	if len(api.pageSizes) != 2 || api.pageSizes[0] != 31 || api.pageSizes[1] != 31 {
		t.Fatalf("expected page size on every call, got %+v", api.pageSizes)
	}
	if assets[0].Kind != rawKindEventDrivenRole {
		t.Fatalf("unexpected asset kind %q", assets[0].Kind)
	}
	payload := string(assets[0].Payload)
	if strings.Contains(payload, "do-not-store") || strings.Contains(payload, "secret") {
		t.Fatalf("payload unsafe data leaked: %s", payload)
	}
	var record EventDrivenRole
	if err := json.Unmarshal(assets[0].Payload, &record); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if record.Service != "scheduler" || !record.Disabled || record.Active {
		t.Fatalf("expected disabled scheduler record, got %+v", record)
	}
	if record.RoleName != "scheduler-entitlement-refresh" || record.RoleAccountID != "123456789012" {
		t.Fatalf("expected role fields derived from ARN, got %+v", record)
	}
}

func TestEventDrivenRoleNormalizerCreatesDistinctResourceTypes(t *testing.T) {
	roleARN := "arn:aws:iam::123456789012:role/pipes-audit-stream-reader"
	pipeARN := "arn:aws:pipes:us-east-1:123456789012:pipe/audit-stream-to-queue"
	payload, err := json.Marshal(EventDrivenRole{
		ServiceCollectorRecord: awscontract.ServiceCollectorRecord{
			AccountID:    "123456789012",
			Region:       "us-east-1",
			Service:      "pipes",
			WorkloadID:   pipeARN,
			WorkloadName: "audit-stream-to-queue",
			WorkloadType: "eventbridge_pipe",
			RoleARN:      roleARN,
		},
		WorkloadARN:          pipeARN,
		RoleName:             "pipes-audit-stream-reader",
		RoleKind:             "pipe_execution_role",
		PipeSourceARN:        "arn:aws:kinesis:us-east-1:123456789012:stream/audit-events",
		PipeTargetARN:        "arn:aws:sqs:us-east-1:123456789012:audit-enrichment",
		DeadLetterARNs:       []string{"arn:aws:sqs:us-east-1:123456789012:pipes-audit-dlq"},
		ExecutionDataLogging: true,
	})
	if err != nil {
		t.Fatalf("marshal record: %v", err)
	}
	bundle, err := NewRoleNormalizer().Normalize(context.Background(), []providers.RawAsset{{
		Kind:     rawKindEventDrivenRole,
		SourceID: "pipes|" + pipeARN,
		Payload:  payload,
	}})
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if len(bundle.Identities) != 1 || len(bundle.Workloads) != 1 || len(bundle.Resources) != 1 {
		t.Fatalf("expected identity/workload/resource nodes, got %+v", bundle)
	}
	if bundle.Resources[0].Type != domain.ResourceTypeEventBridgePipe {
		t.Fatalf("expected pipe resource type, got %+v", bundle.Resources[0])
	}
	if got := bundle.Resources[0].Metadata["execution_data_logging"]; got != true {
		t.Fatalf("expected execution data logging metadata, got %+v", bundle.Resources[0].Metadata)
	}
}

func TestEventDrivenRoleFixtureKindDetection(t *testing.T) {
	payload, err := json.Marshal(EventDrivenRole{
		ServiceCollectorRecord: awscontract.ServiceCollectorRecord{
			Service:      "scheduler",
			WorkloadType: "scheduler_schedule",
			RoleARN:      "arn:aws:iam::123456789012:role/scheduler-entitlement-refresh",
		},
		WorkloadARN:        "arn:aws:scheduler:us-east-1:123456789012:schedule/default/daily-entitlement-refresh",
		ScheduleExpression: "rate(1 day)",
	})
	if err != nil {
		t.Fatalf("marshal record: %v", err)
	}
	kind, sourceID := fixtureAssetKindAndSourceID(payload)
	if kind != rawKindEventDrivenRole || strings.TrimSpace(sourceID) == "" {
		t.Fatalf("expected event-driven fixture detection, kind=%q sourceID=%q", kind, sourceID)
	}
}

func TestEventDrivenRoleFixtureAliasesCanonicalizeBeforeNormalizing(t *testing.T) {
	for _, tc := range []struct {
		name         string
		workloadType string
		service      string
		workloadARN  string
		wantType     domain.ResourceType
	}{
		{
			name:         "schedule alias",
			workloadType: "schedule",
			service:      "eventbridge",
			workloadARN:  "arn:aws:scheduler:us-east-1:123456789012:schedule/default/daily-entitlement-refresh",
			wantType:     domain.ResourceTypeSchedulerSchedule,
		},
		{
			name:         "pipe alias",
			workloadType: "pipe",
			service:      "eventbridge",
			workloadARN:  "arn:aws:pipes:us-east-1:123456789012:pipe/audit-stream-to-queue",
			wantType:     domain.ResourceTypeEventBridgePipe,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload, err := json.Marshal(EventDrivenRole{
				ServiceCollectorRecord: awscontract.ServiceCollectorRecord{
					AccountID:    "123456789012",
					Region:       "us-east-1",
					Service:      tc.service,
					WorkloadID:   tc.workloadARN,
					WorkloadType: tc.workloadType,
					RoleARN:      "arn:aws:iam::123456789012:role/event-driven-role",
				},
				WorkloadARN: tc.workloadARN,
			})
			if err != nil {
				t.Fatalf("marshal record: %v", err)
			}
			bundle, err := NewRoleNormalizer().Normalize(context.Background(), []providers.RawAsset{{
				Kind:     rawKindEventDrivenRole,
				SourceID: tc.name,
				Payload:  payload,
			}})
			if err != nil {
				t.Fatalf("normalize: %v", err)
			}
			if len(bundle.Resources) != 1 || bundle.Resources[0].Type != tc.wantType {
				t.Fatalf("expected resource type %q, got %+v", tc.wantType, bundle.Resources)
			}
		})
	}
}

func TestEventDrivenSDKRecordHelpersRetainSafeMetadata(t *testing.T) {
	api := &SDKEventDrivenRoleAPI{accountID: "123456789012", region: "us-east-1"}
	scheduleRecord := api.recordFromSchedule(&scheduler.GetScheduleOutput{
		Arn:                        awsv2.String("arn:aws:scheduler:us-east-1:123456789012:schedule/default/daily-refresh"),
		Name:                       awsv2.String("daily-refresh"),
		GroupName:                  awsv2.String("default"),
		ScheduleExpression:         awsv2.String("rate(1 day)"),
		ScheduleExpressionTimezone: awsv2.String("UTC"),
		State:                      schedulertypes.ScheduleStateDisabled,
		Target: &schedulertypes.Target{
			Arn:     awsv2.String("arn:aws:states:us-east-1:123456789012:stateMachine:refresh"),
			RoleArn: awsv2.String("arn:aws:iam::123456789012:role/scheduler-refresh"),
			Input:   awsv2.String(`{"do":"not-store"}`),
			DeadLetterConfig: &schedulertypes.DeadLetterConfig{
				Arn: awsv2.String("arn:aws:sqs:us-east-1:123456789012:scheduler-dlq"),
			},
			RetryPolicy: &schedulertypes.RetryPolicy{
				MaximumEventAgeInSeconds: awsv2.Int32(3600),
				MaximumRetryAttempts:     awsv2.Int32(2),
			},
		},
	})
	if scheduleRecord.WorkloadType != "scheduler_schedule" || !scheduleRecord.Disabled || scheduleRecord.Active {
		t.Fatalf("expected disabled scheduler schedule, got %+v", scheduleRecord)
	}
	if !scheduleRecord.TargetInputConfigured || strings.Contains(scheduleRecord.WorkloadName, "not-store") {
		t.Fatalf("expected target input flag without retaining input payload, got %+v", scheduleRecord)
	}
	if len(scheduleRecord.DeadLetterARNs) != 1 || scheduleRecord.RetryMaximumAttempts != 2 {
		t.Fatalf("expected scheduler DLQ and retry metadata, got %+v", scheduleRecord)
	}

	pipeRecord := api.recordFromPipe(&pipes.DescribePipeOutput{
		Arn:              awsv2.String("arn:aws:pipes:us-east-1:123456789012:pipe/audit-stream-to-queue"),
		Name:             awsv2.String("audit-stream-to-queue"),
		RoleArn:          awsv2.String("arn:aws:iam::123456789012:role/pipes-audit"),
		Source:           awsv2.String("arn:aws:kinesis:us-east-1:123456789012:stream/audit"),
		Target:           awsv2.String("arn:aws:sqs:us-east-1:123456789012:audit-target"),
		Enrichment:       awsv2.String("arn:aws:lambda:us-east-1:123456789012:function:enrich-audit"),
		CurrentState:     pipestypes.PipeStateStopped,
		StateReason:      awsv2.String("disabled by operator"),
		KmsKeyIdentifier: awsv2.String("arn:aws:kms:us-east-1:123456789012:key/key-1"),
		Tags:             map[string]string{"owner": "security"},
	})
	if pipeRecord.WorkloadType != "eventbridge_pipe" || !pipeRecord.Disabled || pipeRecord.TargetService != "sqs" {
		t.Fatalf("expected stopped pipe metadata, got %+v", pipeRecord)
	}
	if pipeRecord.PipeSourceARN == "" || pipeRecord.PipeTargetARN == "" || pipeRecord.PipeEnrichmentARN == "" || pipeRecord.KMSKeyARN == "" {
		t.Fatalf("expected pipe references, got %+v", pipeRecord)
	}

	targetDLQs := eventBridgeTargetDLQs(eventbridgetypes.Target{DeadLetterConfig: &eventbridgetypes.DeadLetterConfig{Arn: awsv2.String("arn:aws:sqs:us-east-1:123456789012:target-dlq")}})
	if len(targetDLQs) != 1 {
		t.Fatalf("expected target DLQ extraction, got %+v", targetDLQs)
	}
}

type fakeEventBridgeSDKClient struct{}

func (f fakeEventBridgeSDKClient) ListEventBuses(ctx context.Context, params *eventbridge.ListEventBusesInput, optFns ...func(*eventbridge.Options)) (*eventbridge.ListEventBusesOutput, error) {
	return &eventbridge.ListEventBusesOutput{EventBuses: []eventbridgetypes.EventBus{{
		Name: awsv2.String("default"),
		Arn:  awsv2.String("arn:aws:events:us-east-1:123456789012:event-bus/default"),
	}}}, nil
}

func (f fakeEventBridgeSDKClient) ListRules(ctx context.Context, params *eventbridge.ListRulesInput, optFns ...func(*eventbridge.Options)) (*eventbridge.ListRulesOutput, error) {
	return &eventbridge.ListRulesOutput{Rules: []eventbridgetypes.Rule{{
		Name:         awsv2.String("customer-created"),
		Arn:          awsv2.String("arn:aws:events:us-east-1:123456789012:rule/default/customer-created"),
		RoleArn:      awsv2.String("arn:aws:iam::123456789012:role/eventbridge-rule-role"),
		EventBusName: awsv2.String("default"),
		EventPattern: awsv2.String(`{"source":["app.customer"]}`),
		State:        eventbridgetypes.RuleStateEnabled,
	}}}, nil
}

func (f fakeEventBridgeSDKClient) ListTargetsByRule(ctx context.Context, params *eventbridge.ListTargetsByRuleInput, optFns ...func(*eventbridge.Options)) (*eventbridge.ListTargetsByRuleOutput, error) {
	return &eventbridge.ListTargetsByRuleOutput{Targets: []eventbridgetypes.Target{{
		Id:      awsv2.String("sync-customer"),
		Arn:     awsv2.String("arn:aws:lambda:us-east-1:123456789012:function:sync-customer"),
		RoleArn: awsv2.String("arn:aws:iam::123456789012:role/eventbridge-target-role"),
		Input:   awsv2.String(`{"do":"not-store"}`),
		DeadLetterConfig: &eventbridgetypes.DeadLetterConfig{
			Arn: awsv2.String("arn:aws:sqs:us-east-1:123456789012:eventbridge-dlq"),
		},
		InputTransformer: &eventbridgetypes.InputTransformer{
			InputPathsMap: map[string]string{"id": "$.detail.id"},
			InputTemplate: awsv2.String(`{"id":"<id>"}`),
		},
		RetryPolicy: &eventbridgetypes.RetryPolicy{
			MaximumEventAgeInSeconds: awsv2.Int32(3600),
			MaximumRetryAttempts:     awsv2.Int32(3),
		},
	}}}, nil
}

func (f fakeEventBridgeSDKClient) ListTagsForResource(ctx context.Context, params *eventbridge.ListTagsForResourceInput, optFns ...func(*eventbridge.Options)) (*eventbridge.ListTagsForResourceOutput, error) {
	return &eventbridge.ListTagsForResourceOutput{Tags: []eventbridgetypes.Tag{{Key: awsv2.String("owner"), Value: awsv2.String("platform")}}}, nil
}

type fakeSchedulerSDKClient struct{}

func (f fakeSchedulerSDKClient) ListSchedules(ctx context.Context, params *scheduler.ListSchedulesInput, optFns ...func(*scheduler.Options)) (*scheduler.ListSchedulesOutput, error) {
	return &scheduler.ListSchedulesOutput{Schedules: []schedulertypes.ScheduleSummary{
		{},
		{Name: awsv2.String("daily-refresh"), GroupName: awsv2.String("default")},
	}}, nil
}

func (f fakeSchedulerSDKClient) GetSchedule(ctx context.Context, params *scheduler.GetScheduleInput, optFns ...func(*scheduler.Options)) (*scheduler.GetScheduleOutput, error) {
	return &scheduler.GetScheduleOutput{
		Arn:                awsv2.String("arn:aws:scheduler:us-east-1:123456789012:schedule/default/daily-refresh"),
		Name:               awsv2.String("daily-refresh"),
		GroupName:          awsv2.String("default"),
		ScheduleExpression: awsv2.String("rate(1 day)"),
		State:              schedulertypes.ScheduleStateEnabled,
		Target: &schedulertypes.Target{
			Arn:     awsv2.String("arn:aws:lambda:us-east-1:123456789012:function:refresh"),
			RoleArn: awsv2.String("arn:aws:iam::123456789012:role/scheduler-refresh"),
		},
	}, nil
}

type fakePipesSDKClient struct{}

func (f fakePipesSDKClient) ListPipes(ctx context.Context, params *pipes.ListPipesInput, optFns ...func(*pipes.Options)) (*pipes.ListPipesOutput, error) {
	return &pipes.ListPipesOutput{Pipes: []pipestypes.Pipe{
		{},
		{Name: awsv2.String("audit-stream-to-queue")},
	}}, nil
}

func (f fakePipesSDKClient) DescribePipe(ctx context.Context, params *pipes.DescribePipeInput, optFns ...func(*pipes.Options)) (*pipes.DescribePipeOutput, error) {
	return &pipes.DescribePipeOutput{
		Arn:          awsv2.String("arn:aws:pipes:us-east-1:123456789012:pipe/audit-stream-to-queue"),
		Name:         awsv2.String("audit-stream-to-queue"),
		RoleArn:      awsv2.String("arn:aws:iam::123456789012:role/pipes-audit"),
		Source:       awsv2.String("arn:aws:kinesis:us-east-1:123456789012:stream/audit"),
		Target:       awsv2.String("arn:aws:sqs:us-east-1:123456789012:audit-target"),
		CurrentState: pipestypes.PipeStateRunning,
	}, nil
}

func TestSDKEventDrivenRoleAPIListsAllServices(t *testing.T) {
	api := NewSDKEventDrivenRoleAPIFromClients(fakeEventBridgeSDKClient{}, fakeSchedulerSDKClient{}, fakePipesSDKClient{}, "123456789012", "us-east-1")
	page, err := api.ListServiceRoles(context.Background(), "", 25)
	if err != nil {
		t.Fatalf("list service roles: %v", err)
	}
	if len(page.Records) != 4 {
		t.Fatalf("expected rule, target, schedule, and pipe records, got %+v", page.Records)
	}
	codes := map[string]bool{}
	for _, diagnostic := range page.Diagnostics {
		codes[diagnostic.Code] = true
	}
	if !codes["scheduler_schedule_name_missing"] || !codes["pipe_name_missing"] {
		t.Fatalf("expected missing-name diagnostics, got %+v", page.Diagnostics)
	}
	seen := map[string]bool{}
	for _, record := range page.Records {
		seen[record.RoleKind] = true
		if record.RoleKind == "eventbridge_target_role" {
			if !record.TargetInputConfigured || record.InputTransformerSHA256 == "" || len(record.DeadLetterARNs) != 1 || record.RetryMaximumAttempts != 3 {
				t.Fatalf("expected payload-safe target metadata, got %+v", record)
			}
			if record.Tags["owner"] != "platform" {
				t.Fatalf("expected eventbridge tags on target record, got %+v", record.Tags)
			}
		}
	}
	for _, want := range []string{"eventbridge_rule_role", "eventbridge_target_role", "scheduler_schedule_role", "pipe_execution_role"} {
		if !seen[want] {
			t.Fatalf("missing role kind %q in %+v", want, page.Records)
		}
	}
}
