package aws

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

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
