package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/domain"
	"github.com/identrail/identrail/internal/providers"
	"github.com/identrail/identrail/internal/providers/awscontract"
)

type fakeECSTaskRoleAPI struct {
	pages []ECSTaskRolePage
	calls int
}

func (f *fakeECSTaskRoleAPI) ListTaskRoles(_ context.Context, nextToken string, pageSize int32) (ECSTaskRolePage, error) {
	f.calls++
	if pageSize != 2 {
		return ECSTaskRolePage{}, fakeRetryableError{message: "unexpected page size"}
	}
	switch f.calls {
	case 1:
		if nextToken != "" {
			return ECSTaskRolePage{}, fakeRetryableError{message: "unexpected first token"}
		}
	case 2:
		if nextToken != "page-2" {
			return ECSTaskRolePage{}, fakeRetryableError{message: "unexpected second token"}
		}
	}
	if f.calls > len(f.pages) {
		return ECSTaskRolePage{}, nil
	}
	return f.pages[f.calls-1], nil
}

func TestECSTaskRoleCollectorEmitsContractRecordsAndDiagnostics(t *testing.T) {
	fixedNow := time.Date(2026, 6, 4, 17, 0, 0, 0, time.UTC)
	api := &fakeECSTaskRoleAPI{
		pages: []ECSTaskRolePage{
			{
				Records: []ECSTaskRole{
					{
						ServiceCollectorRecord: awscontract.ServiceCollectorRecord{
							WorkloadID:   "arn:aws:ecs:us-east-1:123456789012:service/prod/payments",
							WorkloadType: "ecs_service",
							WorkloadName: "payments",
							RoleARN:      "arn:aws:iam::123456789012:role/payments-task",
							Source:       "describeservices",
							EvidenceRef:  "arn:aws:ecs:us-east-1:123456789012:service/prod/payments",
						},
						RoleKind:               ecsRoleKindTask,
						RoleName:               "payments-task",
						ClusterARN:             "arn:aws:ecs:us-east-1:123456789012:cluster/prod",
						ServiceARN:             "arn:aws:ecs:us-east-1:123456789012:service/prod/payments",
						ServiceName:            "payments",
						TaskDefinitionARN:      "arn:aws:ecs:us-east-1:123456789012:task-definition/payments:4",
						TaskDefinitionFamily:   "payments",
						TaskDefinitionRevision: "4",
						TaskDefinitionStatus:   "ACTIVE",
						TaskRoleARN:            "arn:aws:iam::123456789012:role/payments-task",
						ExecutionRoleARN:       "arn:aws:iam::123456789012:role/payments-execution",
						LaunchType:             "FARGATE",
						ContainerImages:        []string{"repo/payments:2026-06-04"},
						SecretRefs:             []string{"DATABASE_PASSWORD=arn:aws:secretsmanager:us-east-1:123456789012:secret:payments/db"},
						EnvironmentKeys:        []string{"APP_ENV"},
						Tags:                   map[string]string{"owner": "payments"},
					},
				},
				NextToken: "page-2",
			},
			{
				Records: []ECSTaskRole{
					{
						ServiceCollectorRecord: awscontract.ServiceCollectorRecord{
							WorkloadID:   "arn:aws:ecs:us-east-1:123456789012:service/prod/payments",
							WorkloadType: "ecs_service",
							WorkloadName: "payments",
							RoleARN:      "arn:aws:iam::123456789012:role/payments-execution",
							Source:       "describeservices",
							EvidenceRef:  "arn:aws:ecs:us-east-1:123456789012:service/prod/payments",
						},
						RoleKind:          ecsRoleKindExecution,
						RoleName:          "payments-execution",
						TaskDefinitionARN: "arn:aws:ecs:us-east-1:123456789012:task-definition/payments:4",
						ExecutionRoleARN:  "arn:aws:iam::123456789012:role/payments-execution",
					},
					{
						ServiceCollectorRecord: awscontract.ServiceCollectorRecord{
							WorkloadID:   "arn:aws:ecs:us-east-1:123456789012:task-definition/worker:2",
							WorkloadType: "ecs_task_definition",
							WorkloadName: "worker",
							Source:       "describetaskdefinition",
							EvidenceRef:  "arn:aws:ecs:us-east-1:123456789012:task-definition/worker:2",
						},
						RoleKind:          ecsRoleKindTask,
						TaskDefinitionARN: "arn:aws:ecs:us-east-1:123456789012:task-definition/worker:2",
					},
				},
			},
		},
	}
	collector := NewECSTaskRoleCollector(api, WithECSTaskRolePageSize(2), WithECSTaskRoleClock(func() time.Time {
		return fixedNow
	}))

	assets, diagnostics, err := collector.CollectWithDiagnostics(context.Background(), AWSCollectorScope{
		TenantID:    "tenant-a",
		WorkspaceID: "workspace-a",
		ProjectID:   "project-a",
		ConnectorID: "aws-prod",
		ScanID:      "scan-ecs",
		AccountID:   "123456789012",
		Region:      "us-east-1",
	})
	if err != nil {
		t.Fatalf("collect failed: %v", err)
	}
	if len(assets) != 2 {
		t.Fatalf("expected two valid raw assets, got %d", len(assets))
	}
	if len(diagnostics) != 1 || diagnostics[0].Code != "missing_ecs_role" {
		t.Fatalf("expected missing role diagnostic, got %+v", diagnostics)
	}

	var payload ECSTaskRole
	if err := json.Unmarshal(assets[0].Payload, &payload); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if payload.CollectedAt != fixedNow {
		t.Fatalf("expected collected_at %s, got %s", fixedNow, payload.CollectedAt)
	}
	if payload.Service != "ecs" || payload.CollectorName != ecsTaskRoleCollectorName || payload.RoleKind == "" {
		t.Fatalf("expected normalized ECS metadata, got %+v", payload)
	}
	if _, err := awscontract.NormalizeServiceCollectorRecord(payload.ServiceCollectorRecord); err != nil {
		t.Fatalf("expected payload to satisfy service collector contract: %v", err)
	}
}

func TestRoleNormalizerAddsECSTaskAndExecutionRoleEdges(t *testing.T) {
	taskRecord := ECSTaskRole{
		ServiceCollectorRecord: awscontract.ServiceCollectorRecord{
			AccountID:     "123456789012",
			Region:        "us-east-1",
			Service:       "ecs",
			WorkloadID:    "arn:aws:ecs:us-east-1:123456789012:service/prod/payments",
			WorkloadType:  "ecs_service",
			WorkloadName:  "payments",
			RoleARN:       "arn:aws:iam::123456789012:role/payments-task",
			Source:        "describeservices",
			EvidenceRef:   "arn:aws:ecs:us-east-1:123456789012:service/prod/payments",
			Confidence:    0.96,
			ScanID:        "scan-ecs",
			CollectorName: ecsTaskRoleCollectorName,
			CollectedAt:   time.Date(2026, 6, 4, 17, 0, 0, 0, time.UTC),
		},
		RoleKind:          ecsRoleKindTask,
		RoleName:          "payments-task",
		ServiceARN:        "arn:aws:ecs:us-east-1:123456789012:service/prod/payments",
		ServiceName:       "payments",
		TaskDefinitionARN: "arn:aws:ecs:us-east-1:123456789012:task-definition/payments:4",
		TaskRoleARN:       "arn:aws:iam::123456789012:role/payments-task",
		ExecutionRoleARN:  "arn:aws:iam::123456789012:role/payments-execution",
		ContainerImages:   []string{"repo/payments:4"},
		SecretRefs:        []string{"DATABASE_PASSWORD=arn:aws:secretsmanager:us-east-1:123456789012:secret:payments/db"},
		EnvironmentKeys:   []string{"APP_ENV"},
		Tags:              map[string]string{"owner": "payments"},
	}
	executionRecord := taskRecord
	executionRecord.RoleKind = ecsRoleKindExecution
	executionRecord.RoleARN = "arn:aws:iam::123456789012:role/payments-execution"
	executionRecord.RoleName = "payments-execution"
	executionRecord.Confidence = 0.9

	taskPayload, err := json.Marshal(taskRecord)
	if err != nil {
		t.Fatalf("marshal task record: %v", err)
	}
	executionPayload, err := json.Marshal(executionRecord)
	if err != nil {
		t.Fatalf("marshal execution record: %v", err)
	}
	bundle, err := NewRoleNormalizer().Normalize(context.Background(), []providers.RawAsset{
		{Kind: rawKindECSTaskRole, SourceID: "ecs-task", Payload: taskPayload},
		{Kind: rawKindECSTaskRole, SourceID: "ecs-execution", Payload: executionPayload},
	})
	if err != nil {
		t.Fatalf("normalize failed: %v", err)
	}
	if err := providers.ValidateNormalizedBundle(bundle); err != nil {
		t.Fatalf("normalized bundle invalid: %v", err)
	}
	if len(bundle.Identities) != 2 || len(bundle.Workloads) != 2 {
		t.Fatalf("expected task and execution role identities/workloads, got identities=%+v workloads=%+v", bundle.Identities, bundle.Workloads)
	}
	if len(bundle.Resources) != 2 {
		t.Fatalf("expected service and task definition resources, got %+v", bundle.Resources)
	}
	for _, resource := range bundle.Resources {
		if strings.Contains(fmtAny(resource.Metadata["environment_keys"]), "APP_ENV=value") {
			t.Fatalf("environment values must not be normalized, got %+v", resource.Metadata)
		}
	}

	relationships, err := NewRelationshipBuilder().ResolveRelationships(context.Background(), bundle, nil)
	if err != nil {
		t.Fatalf("resolve relationships: %v", err)
	}
	if err := providers.ValidateGraphContract(bundle, relationships); err != nil {
		t.Fatalf("graph contract invalid: %v", err)
	}
	if !hasRelationshipType(relationships, domain.RelationshipRunsAs) {
		t.Fatalf("expected task role runs_as edge, got %+v", relationships)
	}
	if !hasRelationshipType(relationships, domain.RelationshipAttachedTo) {
		t.Fatalf("expected execution role attached_to edge, got %+v", relationships)
	}
}

func TestRoleNormalizerUsesNormalizedECSRoleKindInWorkloadName(t *testing.T) {
	record := ECSTaskRole{
		ServiceCollectorRecord: awscontract.ServiceCollectorRecord{
			AccountID:     "123456789012",
			Region:        "us-east-1",
			Service:       "ecs",
			WorkloadID:    "arn:aws:ecs:us-east-1:123456789012:service/prod/payments",
			WorkloadType:  "ecs_service",
			RoleARN:       "arn:aws:iam::123456789012:role/payments-execution",
			Source:        "describeservices",
			EvidenceRef:   "arn:aws:ecs:us-east-1:123456789012:service/prod/payments",
			Confidence:    0.9,
			ScanID:        "scan-ecs",
			CollectorName: ecsTaskRoleCollectorName,
			CollectedAt:   time.Date(2026, 6, 4, 17, 0, 0, 0, time.UTC),
		},
		RoleKind:         "execution",
		RoleName:         "payments-execution",
		ServiceARN:       "arn:aws:ecs:us-east-1:123456789012:service/prod/payments",
		ServiceName:      "payments",
		ExecutionRoleARN: "arn:aws:iam::123456789012:role/payments-execution",
	}
	payload, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("marshal execution record: %v", err)
	}

	bundle, err := NewRoleNormalizer().Normalize(context.Background(), []providers.RawAsset{
		{Kind: rawKindECSTaskRole, SourceID: "ecs-execution", Payload: payload},
	})
	if err != nil {
		t.Fatalf("normalize failed: %v", err)
	}
	if len(bundle.Workloads) != 1 {
		t.Fatalf("expected one workload, got %+v", bundle.Workloads)
	}
	if !strings.Contains(bundle.Workloads[0].Name, "execution role") {
		t.Fatalf("expected normalized execution role workload label, got %q", bundle.Workloads[0].Name)
	}
}

func fmtAny(value any) string {
	if value == nil {
		return ""
	}
	return strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(strings.TrimPrefix(strings.TrimSuffix(fmt.Sprintf("%v", value), "]"), "["), "\n", " "), "\t", " "))
}
