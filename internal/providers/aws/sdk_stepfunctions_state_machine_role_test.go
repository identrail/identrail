package aws

import (
	"context"
	"errors"
	"testing"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sfn"
	sfntypes "github.com/aws/aws-sdk-go-v2/service/sfn/types"
)

type fakeStepFunctionsSDKClient struct {
	listOutput        *sfn.ListStateMachinesOutput
	listErr           error
	describeOutputs   map[string]*sfn.DescribeStateMachineOutput
	describeErrs      map[string]error
	tagsOutput        *sfn.ListTagsForResourceOutput
	describeInputs    []*sfn.DescribeStateMachineInput
	listTagsCallCount int
}

func (f *fakeStepFunctionsSDKClient) ListStateMachines(ctx context.Context, params *sfn.ListStateMachinesInput, optFns ...func(*sfn.Options)) (*sfn.ListStateMachinesOutput, error) {
	return f.listOutput, f.listErr
}

func (f *fakeStepFunctionsSDKClient) DescribeStateMachine(ctx context.Context, params *sfn.DescribeStateMachineInput, optFns ...func(*sfn.Options)) (*sfn.DescribeStateMachineOutput, error) {
	f.describeInputs = append(f.describeInputs, params)
	arn := awsv2.ToString(params.StateMachineArn)
	if err := f.describeErrs[arn+"|"+string(params.IncludedData)]; err != nil {
		return nil, err
	}
	if err := f.describeErrs[arn]; err != nil {
		return nil, err
	}
	if output := f.describeOutputs[arn+"|"+string(params.IncludedData)]; output != nil {
		return output, nil
	}
	return f.describeOutputs[arn], nil
}

func (f *fakeStepFunctionsSDKClient) ListTagsForResource(ctx context.Context, params *sfn.ListTagsForResourceInput, optFns ...func(*sfn.Options)) (*sfn.ListTagsForResourceOutput, error) {
	f.listTagsCallCount++
	return f.tagsOutput, nil
}

func TestSDKStepFunctionsStateMachineRoleAPIListsDefinitionReferenceRecords(t *testing.T) {
	stateMachineARN := "arn:aws:states:us-east-1:123456789012:stateMachine:payments"
	roleARN := "arn:aws:iam::123456789012:role/payments-stepfunctions"
	client := &fakeStepFunctionsSDKClient{
		listOutput: &sfn.ListStateMachinesOutput{
			StateMachines: []sfntypes.StateMachineListItem{{
				Name:            awsv2.String("payments"),
				StateMachineArn: awsv2.String(stateMachineARN),
				Type:            sfntypes.StateMachineTypeStandard,
			}},
		},
		describeOutputs: map[string]*sfn.DescribeStateMachineOutput{
			stateMachineARN: {
				Name:            awsv2.String("payments"),
				StateMachineArn: awsv2.String(stateMachineARN),
				RoleArn:         awsv2.String(roleARN),
				Type:            sfntypes.StateMachineTypeStandard,
				Status:          sfntypes.StateMachineStatusActive,
				Definition:      awsv2.String(`{"States":{"Charge":{"Type":"Task","Resource":"arn:aws:states:::lambda:invoke","Parameters":{"FunctionName":"arn:aws:lambda:us-east-1:123456789012:function:charge-card","Payload":{"secret":"never-store"}},"End":true}}}`),
				LoggingConfiguration: &sfntypes.LoggingConfiguration{
					Level:                sfntypes.LogLevelAll,
					IncludeExecutionData: false,
					Destinations: []sfntypes.LogDestination{{
						CloudWatchLogsLogGroup: &sfntypes.CloudWatchLogsLogGroup{LogGroupArn: awsv2.String("arn:aws:logs:us-east-1:123456789012:log-group:/aws/vendedlogs/states/payments:*")},
					}},
				},
				TracingConfiguration: &sfntypes.TracingConfiguration{Enabled: true},
			},
		},
		tagsOutput: &sfn.ListTagsForResourceOutput{Tags: []sfntypes.Tag{{Key: awsv2.String("owner"), Value: awsv2.String("platform")}}},
	}
	api := NewSDKStepFunctionsStateMachineRoleAPIFromClient(client, "123456789012", "us-east-1")
	page, err := api.ListServiceRoles(context.Background(), "", 25)
	if err != nil {
		t.Fatalf("list failed: %v", err)
	}
	if len(page.Records) != 1 {
		t.Fatalf("expected one record, got %+v", page.Records)
	}
	if len(client.describeInputs) != 1 || client.describeInputs[0].IncludedData != sfntypes.IncludedDataAllData {
		t.Fatalf("DescribeStateMachine must request definition data for reference extraction, got %+v", client.describeInputs)
	}
	record := page.Records[0]
	if record.RoleARN != roleARN || record.RoleName != "payments-stepfunctions" {
		t.Fatalf("unexpected role mapping: %+v", record)
	}
	if record.DefinitionSHA256 == "" || len(record.ServiceIntegrationResources) != 1 || record.ServiceIntegrationResources[0] != "lambda" {
		t.Fatalf("unexpected definition summary: %+v", record)
	}
	if record.Tags["owner"] != "platform" || len(record.LogGroupARNs) != 1 || !record.TracingEnabled {
		t.Fatalf("unexpected metadata: %+v", record)
	}
}

func TestSDKStepFunctionsStateMachineRoleAPIPartialDescribeFailure(t *testing.T) {
	stateMachineARN := "arn:aws:states:us-east-1:123456789012:stateMachine:payments"
	client := &fakeStepFunctionsSDKClient{
		listOutput: &sfn.ListStateMachinesOutput{
			StateMachines: []sfntypes.StateMachineListItem{{Name: awsv2.String("payments"), StateMachineArn: awsv2.String(stateMachineARN)}},
		},
		describeErrs: map[string]error{stateMachineARN: errors.New("access denied")},
	}
	api := NewSDKStepFunctionsStateMachineRoleAPIFromClient(client, "123456789012", "us-east-1")
	page, err := api.ListServiceRoles(context.Background(), "", 25)
	if err != nil {
		t.Fatalf("list failed: %v", err)
	}
	if len(page.Records) != 0 || len(page.Diagnostics) != 1 || page.Diagnostics[0].Code != "state_machine_describe_failed" {
		t.Fatalf("expected describe diagnostic, got %+v", page)
	}
}

func TestSDKStepFunctionsStateMachineRoleAPIFallsBackToMetadataOnlyDescribe(t *testing.T) {
	stateMachineARN := "arn:aws:states:us-east-1:123456789012:stateMachine:encrypted"
	roleARN := "arn:aws:iam::123456789012:role/encrypted-stepfunctions"
	client := &fakeStepFunctionsSDKClient{
		listOutput: &sfn.ListStateMachinesOutput{
			StateMachines: []sfntypes.StateMachineListItem{{Name: awsv2.String("encrypted"), StateMachineArn: awsv2.String(stateMachineARN)}},
		},
		describeOutputs: map[string]*sfn.DescribeStateMachineOutput{
			stateMachineARN + "|" + string(sfntypes.IncludedDataMetadataOnly): {
				Name:            awsv2.String("encrypted"),
				StateMachineArn: awsv2.String(stateMachineARN),
				RoleArn:         awsv2.String(roleARN),
				Type:            sfntypes.StateMachineTypeStandard,
				Status:          sfntypes.StateMachineStatusActive,
				Definition:      awsv2.String("{}"),
			},
		},
		describeErrs: map[string]error{
			stateMachineARN + "|" + string(sfntypes.IncludedDataAllData): errors.New("kms decrypt denied"),
		},
	}
	api := NewSDKStepFunctionsStateMachineRoleAPIFromClient(client, "123456789012", "us-east-1")
	page, err := api.ListServiceRoles(context.Background(), "", 25)
	if err != nil {
		t.Fatalf("list failed: %v", err)
	}
	if len(page.Records) != 1 || page.Records[0].RoleARN != roleARN {
		t.Fatalf("expected metadata-only fallback record, got %+v", page.Records)
	}
	if len(page.Diagnostics) != 1 || page.Diagnostics[0].Code != "state_machine_definition_unavailable" {
		t.Fatalf("expected definition unavailable diagnostic, got %+v", page.Diagnostics)
	}
	if len(client.describeInputs) != 2 ||
		client.describeInputs[0].IncludedData != sfntypes.IncludedDataAllData ||
		client.describeInputs[1].IncludedData != sfntypes.IncludedDataMetadataOnly {
		t.Fatalf("expected ALL_DATA then METADATA_ONLY describe calls, got %+v", client.describeInputs)
	}
}
