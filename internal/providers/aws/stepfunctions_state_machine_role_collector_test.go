package aws

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/providers"
	"github.com/identrail/identrail/internal/providers/awscontract"
)

type fakeStepFunctionsRoleAPI struct {
	pages     []StepFunctionsStateMachineRolePage
	err       error
	tokens    []string
	pageSizes []int32
	calls     int
}

func (f *fakeStepFunctionsRoleAPI) ListServiceRoles(ctx context.Context, nextToken string, pageSize int32) (StepFunctionsStateMachineRolePage, error) {
	f.calls++
	f.tokens = append(f.tokens, nextToken)
	f.pageSizes = append(f.pageSizes, pageSize)
	if len(f.pages) == 0 {
		if f.err != nil {
			return StepFunctionsStateMachineRolePage{}, f.err
		}
		return StepFunctionsStateMachineRolePage{}, nil
	}
	page := f.pages[0]
	f.pages = f.pages[1:]
	return page, nil
}

func TestStepFunctionsStateMachineRoleCollectorEmitsSafeDefinitionAsset(t *testing.T) {
	collectedAt := time.Date(2026, 6, 6, 12, 0, 0, 0, time.UTC)
	roleARN := "arn:aws:iam::123456789012:role/payments-stepfunctions-execution"
	stateMachineARN := "arn:aws:states:us-east-1:123456789012:stateMachine:payments-orchestrator"
	api := &fakeStepFunctionsRoleAPI{pages: []StepFunctionsStateMachineRolePage{{
		Records: []StepFunctionsStateMachineRole{{
			ServiceCollectorRecord: awscontract.ServiceCollectorRecord{
				AccountID:    "123456789012",
				Region:       "us-east-1",
				WorkloadID:   stateMachineARN,
				WorkloadName: "payments-orchestrator",
				RoleARN:      roleARN,
			},
			StateMachineARN:             stateMachineARN,
			DefinitionSHA256:            "hash-only",
			DefinitionResourceARNs:      []string{"arn:aws:lambda:us-east-1:123456789012:function:charge-card"},
			ServiceIntegrationResources: []string{"lambda"},
		}},
	}}}
	collector := NewStepFunctionsStateMachineRoleCollector(api, WithStepFunctionsStateMachineRoleClock(func() time.Time { return collectedAt }))

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
	if len(diagnostics) != 0 {
		t.Fatalf("expected no diagnostics, got %+v", diagnostics)
	}
	if len(assets) != 1 {
		t.Fatalf("expected one asset, got %d", len(assets))
	}
	if assets[0].Kind != rawKindStepFunctionsStateMachineRole {
		t.Fatalf("unexpected kind %q", assets[0].Kind)
	}
	var record StepFunctionsStateMachineRole
	if err := json.Unmarshal(assets[0].Payload, &record); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if record.Service != stepFunctionsServiceName || record.CollectorName != stepFunctionsStateMachineRoleCollectorName {
		t.Fatalf("unexpected contract fields: %+v", record.ServiceCollectorRecord)
	}
	if record.RoleName != "payments-stepfunctions-execution" {
		t.Fatalf("expected role name from ARN, got %q", record.RoleName)
	}
	if record.DefinitionSHA256 != "hash-only" || strings.Contains(string(assets[0].Payload), "Payload") {
		t.Fatalf("expected hash-only definition evidence, got %s", string(assets[0].Payload))
	}
}

func TestStepFunctionsStateMachineRoleCollectorPassesPaginationInputs(t *testing.T) {
	api := &fakeStepFunctionsRoleAPI{pages: []StepFunctionsStateMachineRolePage{
		{NextToken: "page-2"},
		{},
	}}
	collector := NewStepFunctionsStateMachineRoleCollector(api, WithStepFunctionsStateMachineRolePageSize(37))
	_, _, err := collector.CollectWithDiagnostics(context.Background(), AWSCollectorScope{})
	if err != nil {
		t.Fatalf("collect failed: %v", err)
	}
	if got, want := strings.Join(api.tokens, ","), ",page-2"; got != want {
		t.Fatalf("expected next tokens %q, got %q", want, got)
	}
	if len(api.pageSizes) != 2 || api.pageSizes[0] != 37 || api.pageSizes[1] != 37 {
		t.Fatalf("expected page size to be passed on every call, got %+v", api.pageSizes)
	}
}

func TestStepFunctionsStateMachineRoleCollectorKeepsPartialPageEvidence(t *testing.T) {
	api := &fakeStepFunctionsRoleAPI{
		pages: []StepFunctionsStateMachineRolePage{{
			Records: []StepFunctionsStateMachineRole{{
				ServiceCollectorRecord: awscontract.ServiceCollectorRecord{
					AccountID:  "123456789012",
					Region:     "us-east-1",
					WorkloadID: "arn:aws:states:us-east-1:123456789012:stateMachine:payments",
					RoleARN:    "arn:aws:iam::123456789012:role/payments-stepfunctions",
				},
				StateMachineARN: "arn:aws:states:us-east-1:123456789012:stateMachine:payments",
			}},
			NextToken: "page-2",
		}},
	}
	collector := NewStepFunctionsStateMachineRoleCollector(api, WithStepFunctionsStateMachineRoleMaxPages(1))
	assets, diagnostics, err := collector.CollectWithDiagnostics(context.Background(), AWSCollectorScope{})
	if err == nil {
		t.Fatal("expected max page error")
	}
	if len(assets) != 0 {
		t.Fatalf("expected max-page guard to discard partial assets, got %d", len(assets))
	}
	if diagnostics != nil {
		t.Fatalf("expected no diagnostics before max-page guard, got %+v", diagnostics)
	}
}

func TestStepFunctionsStateMachineRoleCollectorPageFailureAfterEvidence(t *testing.T) {
	api := &fakeStepFunctionsRoleAPI{
		pages: []StepFunctionsStateMachineRolePage{{
			Records: []StepFunctionsStateMachineRole{{
				ServiceCollectorRecord: awscontract.ServiceCollectorRecord{
					AccountID:  "123456789012",
					Region:     "us-east-1",
					WorkloadID: "arn:aws:states:us-east-1:123456789012:stateMachine:payments",
					RoleARN:    "arn:aws:iam::123456789012:role/payments-stepfunctions",
				},
				StateMachineARN: "arn:aws:states:us-east-1:123456789012:stateMachine:payments",
			}},
			NextToken: "page-2",
		}},
		err: errors.New("throttle"),
	}
	collector := NewStepFunctionsStateMachineRoleCollector(api, WithStepFunctionsStateMachineRoleRetryPolicy(RetryPolicy{MaxRetries: 0}))
	_, _, err := collector.CollectWithDiagnostics(context.Background(), AWSCollectorScope{})
	if err == nil {
		t.Fatal("expected second page error")
	}

	api = &fakeStepFunctionsRoleAPI{pages: []StepFunctionsStateMachineRolePage{{
		Records: []StepFunctionsStateMachineRole{{
			ServiceCollectorRecord: awscontract.ServiceCollectorRecord{
				AccountID:  "123456789012",
				Region:     "us-east-1",
				WorkloadID: "arn:aws:states:us-east-1:123456789012:stateMachine:payments",
				RoleARN:    "arn:aws:iam::123456789012:role/payments-stepfunctions",
			},
			StateMachineARN: "arn:aws:states:us-east-1:123456789012:stateMachine:payments",
		}},
		NextToken: "page-2",
	}}, err: errors.New("throttle")}
	collector = NewStepFunctionsStateMachineRoleCollector(api, WithStepFunctionsStateMachineRoleMaxPages(3), WithStepFunctionsStateMachineRoleRetryPolicy(RetryPolicy{MaxRetries: 0}))
	assets, diagnostics, err := collector.CollectWithDiagnostics(context.Background(), AWSCollectorScope{})
	if err == nil || len(assets) != 1 {
		t.Fatalf("expected partial max-page evidence and error, assets=%d err=%v", len(assets), err)
	}
	if len(diagnostics) != 1 || diagnostics[0].Code != "stepfunctions_state_machine_role_page_failed" || !diagnostics[0].Retryable {
		t.Fatalf("expected retryable page diagnostic, got %+v", diagnostics)
	}
}

func TestStepFunctionsDefinitionMetadataExtractsOnlySafeReferences(t *testing.T) {
	definition := `{"StartAt":"Charge","States":{"Charge":{"Type":"Task","Resource":"arn:aws:states:::lambda:invoke","Parameters":{"FunctionName":"arn:aws:lambda:us-east-1:123456789012:function:charge-card","CustomerRoleArn":"arn:aws:iam::123456789012:role/customer-parameter","Payload":{"card":"do-not-store","ExampleRoleArn":"arn:aws:iam::123456789012:role/customer-example"}},"Result":{"ExampleTopicArn":"arn:aws:sns:us-east-1:123456789012:customer-topic"},"Next":"Nested"},"Nested":{"Type":"Task","Resource":"arn:aws:states:::states:startExecution","Parameters":{"StateMachineArn":"arn:aws:states:us-east-1:123456789012:stateMachine:risk-check"},"End":true}}}`
	summary := stepFunctionsDefinitionMetadata(definition)
	if summary.Hash == "" {
		t.Fatal("expected hash")
	}
	resourceARNs := strings.Join(summary.ResourceARNs, ",")
	if strings.Contains(resourceARNs, "do-not-store") || strings.Contains(resourceARNs, "customer-example") || strings.Contains(resourceARNs, "customer-topic") || strings.Contains(resourceARNs, "customer-parameter") {
		t.Fatalf("payload leaked into resource refs: %+v", summary.ResourceARNs)
	}
	if len(summary.ServiceIntegrations) != 2 || summary.ServiceIntegrations[0] != "lambda" || summary.ServiceIntegrations[1] != "states" {
		t.Fatalf("unexpected integrations: %+v", summary.ServiceIntegrations)
	}
	if len(summary.NestedStateMachineARNs) != 1 {
		t.Fatalf("expected nested state machine ARN, got %+v", summary.NestedStateMachineARNs)
	}
}

func TestStepFunctionsDefinitionMetadataSupportsAWSPartitions(t *testing.T) {
	definition := `{"States":{"Gov":{"Type":"Task","Resource":"arn:aws-us-gov:lambda:us-gov-west-1:123456789012:function:charge-card","Next":"China"},"China":{"Type":"Task","Resource":"arn:aws-cn:states:::lambda:invoke","End":true}}}`
	summary := stepFunctionsDefinitionMetadata(definition)
	if !strings.Contains(strings.Join(summary.TaskResourceARNs, ","), "arn:aws-us-gov:lambda:us-gov-west-1:123456789012:function:charge-card") {
		t.Fatalf("expected aws-us-gov ARN extraction, got %+v", summary.TaskResourceARNs)
	}
	if len(summary.ServiceIntegrations) != 1 || summary.ServiceIntegrations[0] != "lambda" {
		t.Fatalf("expected aws-cn Step Functions integration extraction, got %+v", summary.ServiceIntegrations)
	}
}

func TestStepFunctionsDefinitionMetadataReportsAWSSDKIntegrationTargets(t *testing.T) {
	definition := `{"States":{"ReadItem":{"Type":"Task","Resource":"arn:aws:states:::aws-sdk:dynamodb:getItem","Next":"Send"},"Send":{"Type":"Task","Resource":"arn:aws:states:::aws-sdk:sqs:sendMessage","End":true}}}`
	summary := stepFunctionsDefinitionMetadata(definition)
	if len(summary.ServiceIntegrations) != 2 || summary.ServiceIntegrations[0] != "dynamodb" || summary.ServiceIntegrations[1] != "sqs" {
		t.Fatalf("expected AWS SDK target services, got %+v", summary.ServiceIntegrations)
	}
}

func TestStepFunctionsRoleNormalizerCreatesGraphNodes(t *testing.T) {
	roleARN := "arn:aws:iam::123456789012:role/payments-stepfunctions"
	stateMachineARN := "arn:aws:states:us-east-1:123456789012:stateMachine:payments"
	record := StepFunctionsStateMachineRole{
		ServiceCollectorRecord: awscontract.ServiceCollectorRecord{
			AccountID:    "123456789012",
			Region:       "us-east-1",
			WorkloadID:   stateMachineARN,
			WorkloadName: "payments",
			RoleARN:      roleARN,
		},
		StateMachineARN:             stateMachineARN,
		StateMachineName:            "payments",
		DefinitionSHA256:            "hash-only",
		ServiceIntegrationResources: []string{"lambda"},
	}
	payload, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	bundle, err := NewRoleNormalizer().Normalize(context.Background(), []providers.RawAsset{{
		Kind:     rawKindStepFunctionsStateMachineRole,
		SourceID: "stepfunctions",
		Payload:  payload,
	}})
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if len(bundle.Identities) != 1 || len(bundle.Workloads) != 1 || len(bundle.Resources) != 1 {
		t.Fatalf("unexpected normalized counts: %+v", bundle)
	}
	if got := bundle.Resources[0].Metadata["definition_sha256"]; got != "hash-only" {
		t.Fatalf("expected definition hash metadata, got %v", got)
	}
}
