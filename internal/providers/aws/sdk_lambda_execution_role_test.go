package aws

import (
	"context"
	"errors"
	"strings"
	"testing"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
)

type fakeLambdaSDKClient struct {
	listFunctionsInputs           []*lambda.ListFunctionsInput
	listEventSourceMappingsInputs []*lambda.ListEventSourceMappingsInput
	listAliasesInputs             []*lambda.ListAliasesInput
	listVersionsInputs            []*lambda.ListVersionsByFunctionInput
	listTagsInputs                []*lambda.ListTagsInput

	listFunctionsOutputs []*lambda.ListFunctionsOutput
	aliasesByFunction    map[string]*lambda.ListAliasesOutput
	versionsByFunction   map[string]*lambda.ListVersionsByFunctionOutput
	eventSourcesByFunc   map[string]*lambda.ListEventSourceMappingsOutput
	tagsByResource       map[string]*lambda.ListTagsOutput

	listFunctionsErr    error
	listEventSourcesErr map[string]error
}

func (f *fakeLambdaSDKClient) ListFunctions(_ context.Context, params *lambda.ListFunctionsInput, _ ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error) {
	f.listFunctionsInputs = append(f.listFunctionsInputs, params)
	if f.listFunctionsErr != nil {
		return nil, f.listFunctionsErr
	}
	idx := len(f.listFunctionsInputs) - 1
	if idx >= len(f.listFunctionsOutputs) {
		return &lambda.ListFunctionsOutput{}, nil
	}
	return f.listFunctionsOutputs[idx], nil
}

func (f *fakeLambdaSDKClient) ListEventSourceMappings(_ context.Context, params *lambda.ListEventSourceMappingsInput, _ ...func(*lambda.Options)) (*lambda.ListEventSourceMappingsOutput, error) {
	f.listEventSourceMappingsInputs = append(f.listEventSourceMappingsInputs, params)
	functionName := awsv2.ToString(params.FunctionName)
	if err := f.listEventSourcesErr[functionName]; err != nil {
		return nil, err
	}
	if output := f.eventSourcesByFunc[functionName]; output != nil {
		return output, nil
	}
	return &lambda.ListEventSourceMappingsOutput{}, nil
}

func (f *fakeLambdaSDKClient) ListAliases(_ context.Context, params *lambda.ListAliasesInput, _ ...func(*lambda.Options)) (*lambda.ListAliasesOutput, error) {
	f.listAliasesInputs = append(f.listAliasesInputs, params)
	if output := f.aliasesByFunction[awsv2.ToString(params.FunctionName)]; output != nil {
		return output, nil
	}
	return &lambda.ListAliasesOutput{}, nil
}

func (f *fakeLambdaSDKClient) ListVersionsByFunction(_ context.Context, params *lambda.ListVersionsByFunctionInput, _ ...func(*lambda.Options)) (*lambda.ListVersionsByFunctionOutput, error) {
	f.listVersionsInputs = append(f.listVersionsInputs, params)
	if output := f.versionsByFunction[awsv2.ToString(params.FunctionName)]; output != nil {
		return output, nil
	}
	return &lambda.ListVersionsByFunctionOutput{}, nil
}

func (f *fakeLambdaSDKClient) ListTags(_ context.Context, params *lambda.ListTagsInput, _ ...func(*lambda.Options)) (*lambda.ListTagsOutput, error) {
	f.listTagsInputs = append(f.listTagsInputs, params)
	if output := f.tagsByResource[awsv2.ToString(params.Resource)]; output != nil {
		return output, nil
	}
	return &lambda.ListTagsOutput{}, nil
}

func TestSDKLambdaExecutionRoleAPIMapsFunctionRoleAndMetadata(t *testing.T) {
	functionARN := "arn:aws:lambda:us-east-1:123456789012:function:payments-worker"
	roleARN := "arn:aws:iam::123456789012:role/payments-lambda-execution"
	queueARN := "arn:aws:sqs:us-east-1:123456789012:payments"
	disabledStreamARN := "arn:aws:dynamodb:us-east-1:123456789012:table/legacy/stream/2026"
	secretARN := "arn:aws:secretsmanager:us-east-1:123456789012:secret:lambda/kafka"
	client := &fakeLambdaSDKClient{
		listFunctionsOutputs: []*lambda.ListFunctionsOutput{
			{
				Functions: []lambdatypes.FunctionConfiguration{
					{
						FunctionArn:      awsv2.String(functionARN),
						FunctionName:     awsv2.String("payments-worker"),
						Version:          awsv2.String("$LATEST"),
						Role:             awsv2.String(roleARN),
						Runtime:          lambdatypes.Runtime("nodejs20.x"),
						PackageType:      lambdatypes.PackageType("Zip"),
						Handler:          awsv2.String("index.handler"),
						KMSKeyArn:        awsv2.String("arn:aws:kms:us-east-1:123456789012:key/lambda-env"),
						MemorySize:       awsv2.Int32(512),
						Timeout:          awsv2.Int32(30),
						State:            lambdatypes.State("Active"),
						LastUpdateStatus: lambdatypes.LastUpdateStatus("Successful"),
						Architectures:    []lambdatypes.Architecture{lambdatypes.Architecture("x86_64")},
						Environment: &lambdatypes.EnvironmentResponse{
							Variables: map[string]string{
								"APP_ENV":           "prod",
								"DATABASE_PASSWORD": "must-not-appear",
							},
						},
						VpcConfig: &lambdatypes.VpcConfigResponse{
							VpcId:            awsv2.String("vpc-123"),
							SubnetIds:        []string{"subnet-a", "subnet-b"},
							SecurityGroupIds: []string{"sg-123"},
						},
						Layers: []lambdatypes.Layer{
							{Arn: awsv2.String("arn:aws:lambda:us-east-1:123456789012:layer:shared:3")},
						},
					},
				},
			},
		},
		aliasesByFunction: map[string]*lambda.ListAliasesOutput{
			functionARN: {Aliases: []lambdatypes.AliasConfiguration{
				{Name: awsv2.String("prod"), FunctionVersion: awsv2.String("3")},
			}},
		},
		versionsByFunction: map[string]*lambda.ListVersionsByFunctionOutput{
			functionARN: {Versions: []lambdatypes.FunctionConfiguration{
				{Version: awsv2.String("$LATEST")},
				{Version: awsv2.String("3")},
			}},
		},
		eventSourcesByFunc: map[string]*lambda.ListEventSourceMappingsOutput{
			functionARN: {EventSourceMappings: []lambdatypes.EventSourceMappingConfiguration{
				{
					UUID:           awsv2.String("mapping-enabled"),
					EventSourceArn: awsv2.String(queueARN),
					FunctionArn:    awsv2.String(functionARN),
					State:          awsv2.String("Enabled"),
				},
				{
					UUID:                  awsv2.String("mapping-disabled"),
					EventSourceArn:        awsv2.String(disabledStreamARN),
					EventSourceMappingArn: awsv2.String("arn:aws:lambda:us-east-1:123456789012:event-source-mapping:mapping-disabled"),
					FunctionArn:           awsv2.String(functionARN),
					State:                 awsv2.String("Disabled"),
					StateTransitionReason: awsv2.String("Disabled by operator"),
					SourceAccessConfigurations: []lambdatypes.SourceAccessConfiguration{
						{Type: lambdatypes.SourceAccessType("BASIC_AUTH"), URI: awsv2.String(secretARN)},
					},
				},
			}},
		},
		tagsByResource: map[string]*lambda.ListTagsOutput{
			functionARN: {Tags: map[string]string{"owner": "payments"}},
		},
		listEventSourcesErr: map[string]error{},
	}
	api := NewSDKLambdaExecutionRoleAPIFromClient(client, "123456789012", "us-east-1")

	page, err := api.ListExecutionRoles(context.Background(), "", 25)
	if err != nil {
		t.Fatalf("list execution roles: %v", err)
	}
	if len(page.Records) != 1 {
		t.Fatalf("expected one lambda role record, got %+v", page.Records)
	}
	if len(page.Diagnostics) != 1 || page.Diagnostics[0].Code != "disabled_event_source" || page.Diagnostics[0].Retryable {
		t.Fatalf("expected disabled event-source diagnostic, got %+v", page.Diagnostics)
	}
	if got := awsv2.ToInt32(client.listFunctionsInputs[0].MaxItems); got != 25 {
		t.Fatalf("ListFunctions MaxItems = %d, want 25", got)
	}
	if len(client.listTagsInputs) != 1 || awsv2.ToString(client.listTagsInputs[0].Resource) != functionARN {
		t.Fatalf("expected ListTags by function arn, got %+v", client.listTagsInputs)
	}

	record := page.Records[0]
	if record.RoleARN != roleARN || record.RoleName != "payments-lambda-execution" || record.FunctionName != "payments-worker" {
		t.Fatalf("expected function execution role metadata, got %+v", record)
	}
	if record.Runtime != "nodejs20.x" || record.PackageType != "Zip" || record.Handler != "index.handler" || record.VPCID != "vpc-123" {
		t.Fatalf("expected Lambda runtime/package/vpc metadata, got %+v", record)
	}
	if len(record.EventSourceARNs) != 2 || len(record.DisabledEventSourceARNs) != 1 || record.DisabledEventSourceARNs[0] != disabledStreamARN {
		t.Fatalf("expected enabled and disabled event-source metadata, got %+v", record)
	}
	if len(record.SecretRefs) != 1 || !strings.Contains(record.SecretRefs[0], secretARN) {
		t.Fatalf("expected metadata-only source access secret reference, got %+v", record.SecretRefs)
	}
	if strings.Contains(strings.Join(record.EnvironmentKeys, ","), "must-not-appear") || strings.Contains(strings.Join(record.SecretRefs, ","), "must-not-appear") {
		t.Fatalf("environment values must not be collected, got record=%+v", record)
	}
	if len(record.AliasNames) != 1 || record.AliasNames[0] != "prod=3" || len(record.VersionRefs) != 2 {
		t.Fatalf("expected alias and version refs, got %+v", record)
	}
}

func TestSDKLambdaExecutionRoleAPIFailsWhenFunctionListingFails(t *testing.T) {
	client := &fakeLambdaSDKClient{
		listFunctionsErr:    errors.New("lambda unavailable"),
		listEventSourcesErr: map[string]error{},
	}
	api := NewSDKLambdaExecutionRoleAPIFromClient(client, "123456789012", "us-east-1")

	if _, err := api.ListExecutionRoles(context.Background(), "", 10); err == nil {
		t.Fatal("expected list functions failure")
	}
}

func TestSDKLambdaExecutionRoleAPIRetainsFunctionOnEventSourcePartialFailure(t *testing.T) {
	functionARN := "arn:aws:lambda:us-east-1:123456789012:function:payments-worker"
	client := &fakeLambdaSDKClient{
		listFunctionsOutputs: []*lambda.ListFunctionsOutput{
			{Functions: []lambdatypes.FunctionConfiguration{
				{
					FunctionArn:  awsv2.String(functionARN),
					FunctionName: awsv2.String("payments-worker"),
					Role:         awsv2.String("arn:aws:iam::123456789012:role/payments-lambda-execution"),
				},
			}},
		},
		aliasesByFunction:  map[string]*lambda.ListAliasesOutput{},
		versionsByFunction: map[string]*lambda.ListVersionsByFunctionOutput{},
		eventSourcesByFunc: map[string]*lambda.ListEventSourceMappingsOutput{},
		tagsByResource:     map[string]*lambda.ListTagsOutput{},
		listEventSourcesErr: map[string]error{
			functionARN: errors.New("lambda event source API unavailable"),
		},
	}
	api := NewSDKLambdaExecutionRoleAPIFromClient(client, "123456789012", "us-east-1")

	page, err := api.ListExecutionRoles(context.Background(), "", 10)
	if err != nil {
		t.Fatalf("list execution roles should tolerate event-source partial failure: %v", err)
	}
	if len(page.Records) != 1 {
		t.Fatalf("expected retained function role evidence, got %+v", page.Records)
	}
	if len(page.Diagnostics) != 1 || page.Diagnostics[0].Code != "event_source_mapping_list_failed" || !page.Diagnostics[0].Retryable {
		t.Fatalf("expected retryable event-source partial-failure diagnostic, got %+v", page.Diagnostics)
	}
}

func TestSDKLambdaExecutionRoleAPIEmitsPublishedVersionRoleRecords(t *testing.T) {
	functionARN := "arn:aws:lambda:us-east-1:123456789012:function:payments-worker"
	latestRoleARN := "arn:aws:iam::123456789012:role/payments-lambda-latest"
	versionRoleARN := "arn:aws:iam::123456789012:role/payments-lambda-prod"
	queueARN := "arn:aws:sqs:us-east-1:123456789012:payments-latest"
	prodQueueARN := "arn:aws:sqs:us-east-1:123456789012:payments-prod"
	client := &fakeLambdaSDKClient{
		listFunctionsOutputs: []*lambda.ListFunctionsOutput{
			{Functions: []lambdatypes.FunctionConfiguration{
				{
					FunctionArn:  awsv2.String(functionARN),
					FunctionName: awsv2.String("payments-worker"),
					Version:      awsv2.String("$LATEST"),
					Role:         awsv2.String(latestRoleARN),
					Runtime:      lambdatypes.Runtime("nodejs20.x"),
					PackageType:  lambdatypes.PackageType("Zip"),
				},
			}},
		},
		aliasesByFunction: map[string]*lambda.ListAliasesOutput{
			functionARN: {Aliases: []lambdatypes.AliasConfiguration{
				{Name: awsv2.String("prod"), FunctionVersion: awsv2.String("3")},
				{Name: awsv2.String("canary"), FunctionVersion: awsv2.String("4")},
			}},
		},
		versionsByFunction: map[string]*lambda.ListVersionsByFunctionOutput{
			functionARN: {Versions: []lambdatypes.FunctionConfiguration{
				{Version: awsv2.String("$LATEST"), Role: awsv2.String(latestRoleARN)},
				{Version: awsv2.String("3"), Role: awsv2.String(versionRoleARN)},
			}},
		},
		eventSourcesByFunc: map[string]*lambda.ListEventSourceMappingsOutput{
			functionARN: {EventSourceMappings: []lambdatypes.EventSourceMappingConfiguration{
				{
					UUID:           awsv2.String("mapping-latest"),
					EventSourceArn: awsv2.String(queueARN),
					FunctionArn:    awsv2.String(functionARN),
					State:          awsv2.String("Enabled"),
				},
				{
					UUID:           awsv2.String("mapping-prod"),
					EventSourceArn: awsv2.String(prodQueueARN),
					FunctionArn:    awsv2.String(functionARN + ":prod"),
					State:          awsv2.String("Enabled"),
				},
			}},
		},
		tagsByResource:      map[string]*lambda.ListTagsOutput{},
		listEventSourcesErr: map[string]error{},
	}
	api := NewSDKLambdaExecutionRoleAPIFromClient(client, "123456789012", "us-east-1")

	page, err := api.ListExecutionRoles(context.Background(), "", 10)
	if err != nil {
		t.Fatalf("list execution roles: %v", err)
	}
	if len(page.Records) != 2 {
		t.Fatalf("expected latest and published-version role records, got %+v", page.Records)
	}

	var latestRecord, versionRecord LambdaExecutionRole
	for _, record := range page.Records {
		switch record.FunctionVersion {
		case "$LATEST":
			latestRecord = record
		case "3":
			versionRecord = record
		}
	}
	if latestRecord.RoleARN != latestRoleARN {
		t.Fatalf("expected latest role %q, got %+v", latestRoleARN, latestRecord)
	}
	if len(latestRecord.EventSourceARNs) != 1 || latestRecord.EventSourceARNs[0] != queueARN {
		t.Fatalf("expected only unqualified event source on latest record, got %+v", latestRecord.EventSourceARNs)
	}
	if versionRecord.RoleARN != versionRoleARN || versionRecord.Source != "listversionsbyfunction" {
		t.Fatalf("expected version-specific role evidence, got %+v", versionRecord)
	}
	if versionRecord.FunctionARN != functionARN+":3" || versionRecord.WorkloadName != "payments-worker:3" {
		t.Fatalf("expected qualified version workload, got %+v", versionRecord)
	}
	if len(versionRecord.AliasNames) != 1 || versionRecord.AliasNames[0] != "prod=3" {
		t.Fatalf("expected only aliases targeting version 3, got %+v", versionRecord.AliasNames)
	}
	if len(versionRecord.EventSourceARNs) != 1 || versionRecord.EventSourceARNs[0] != prodQueueARN {
		t.Fatalf("expected alias-qualified event source on version record, got %+v", versionRecord.EventSourceARNs)
	}
	if got := lambdaQualifiedFunctionARN(functionARN+":old", "3"); got != functionARN+":3" {
		t.Fatalf("expected qualifier replacement, got %q", got)
	}
	if got := lambdaFunctionQualifierFromARN(functionARN + ":prod"); got != "prod" {
		t.Fatalf("expected qualifier extraction, got %q", got)
	}
}
