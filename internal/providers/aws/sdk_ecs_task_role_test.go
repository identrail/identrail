package aws

import (
	"context"
	"errors"
	"strings"
	"testing"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
)

type fakeECSSDKClient struct {
	listClustersInputs          []*ecs.ListClustersInput
	listServicesInputs          []*ecs.ListServicesInput
	describeServicesInputs      []*ecs.DescribeServicesInput
	listTaskDefinitionsInputs   []*ecs.ListTaskDefinitionsInput
	describeTaskDefinitionInput []*ecs.DescribeTaskDefinitionInput

	listClustersOutputs         []*ecs.ListClustersOutput
	listServicesOutputByCluster map[string]*ecs.ListServicesOutput
	servicesByCluster           map[string][]ecstypes.Service
	taskDefinitions             map[string]ecstypes.TaskDefinition
	taskDefinitionTags          map[string][]ecstypes.Tag
	listTaskDefinitionsByState  map[ecstypes.TaskDefinitionStatus]*ecs.ListTaskDefinitionsOutput

	listClustersErr error
	listServicesErr map[string]error
}

func (f *fakeECSSDKClient) ListClusters(_ context.Context, params *ecs.ListClustersInput, _ ...func(*ecs.Options)) (*ecs.ListClustersOutput, error) {
	f.listClustersInputs = append(f.listClustersInputs, params)
	if f.listClustersErr != nil {
		return nil, f.listClustersErr
	}
	idx := len(f.listClustersInputs) - 1
	if idx >= len(f.listClustersOutputs) {
		return &ecs.ListClustersOutput{}, nil
	}
	return f.listClustersOutputs[idx], nil
}

func (f *fakeECSSDKClient) ListServices(_ context.Context, params *ecs.ListServicesInput, _ ...func(*ecs.Options)) (*ecs.ListServicesOutput, error) {
	f.listServicesInputs = append(f.listServicesInputs, params)
	cluster := awsv2.ToString(params.Cluster)
	if err := f.listServicesErr[cluster]; err != nil {
		return nil, err
	}
	if output := f.listServicesOutputByCluster[cluster]; output != nil {
		return output, nil
	}
	return &ecs.ListServicesOutput{}, nil
}

func (f *fakeECSSDKClient) DescribeServices(_ context.Context, params *ecs.DescribeServicesInput, _ ...func(*ecs.Options)) (*ecs.DescribeServicesOutput, error) {
	f.describeServicesInputs = append(f.describeServicesInputs, params)
	cluster := awsv2.ToString(params.Cluster)
	return &ecs.DescribeServicesOutput{Services: append([]ecstypes.Service(nil), f.servicesByCluster[cluster]...)}, nil
}

func (f *fakeECSSDKClient) ListTaskDefinitions(_ context.Context, params *ecs.ListTaskDefinitionsInput, _ ...func(*ecs.Options)) (*ecs.ListTaskDefinitionsOutput, error) {
	f.listTaskDefinitionsInputs = append(f.listTaskDefinitionsInputs, params)
	if output := f.listTaskDefinitionsByState[params.Status]; output != nil {
		return output, nil
	}
	return &ecs.ListTaskDefinitionsOutput{}, nil
}

func (f *fakeECSSDKClient) DescribeTaskDefinition(_ context.Context, params *ecs.DescribeTaskDefinitionInput, _ ...func(*ecs.Options)) (*ecs.DescribeTaskDefinitionOutput, error) {
	f.describeTaskDefinitionInput = append(f.describeTaskDefinitionInput, params)
	arn := awsv2.ToString(params.TaskDefinition)
	taskDefinition, ok := f.taskDefinitions[arn]
	if !ok {
		return nil, errors.New("missing task definition")
	}
	return &ecs.DescribeTaskDefinitionOutput{
		TaskDefinition: &taskDefinition,
		Tags:           append([]ecstypes.Tag(nil), f.taskDefinitionTags[arn]...),
	}, nil
}

func TestSDKECSTaskRoleAPIMapsServicesAndInactiveTaskDefinitions(t *testing.T) {
	clusterARN := "arn:aws:ecs:us-east-1:123456789012:cluster/prod"
	serviceARN := "arn:aws:ecs:us-east-1:123456789012:service/prod/payments"
	taskDefinitionARN := "arn:aws:ecs:us-east-1:123456789012:task-definition/payments:42"
	inactiveTaskDefinitionARN := "arn:aws:ecs:us-east-1:123456789012:task-definition/legacy:7"
	client := &fakeECSSDKClient{
		listClustersOutputs: []*ecs.ListClustersOutput{
			{ClusterArns: []string{clusterARN}},
		},
		listServicesOutputByCluster: map[string]*ecs.ListServicesOutput{
			clusterARN: {ServiceArns: []string{serviceARN}},
		},
		servicesByCluster: map[string][]ecstypes.Service{
			clusterARN: {
				{
					ClusterArn:         awsv2.String(clusterARN),
					ServiceArn:         awsv2.String(serviceARN),
					ServiceName:        awsv2.String("payments"),
					Status:             awsv2.String("ACTIVE"),
					TaskDefinition:     awsv2.String(taskDefinitionARN),
					LaunchType:         ecstypes.LaunchTypeFargate,
					SchedulingStrategy: ecstypes.SchedulingStrategyReplica,
					DesiredCount:       2,
					RunningCount:       2,
					Tags: []ecstypes.Tag{
						{Key: awsv2.String("owner"), Value: awsv2.String("payments")},
					},
				},
			},
		},
		taskDefinitions: map[string]ecstypes.TaskDefinition{
			taskDefinitionARN: {
				TaskDefinitionArn:       awsv2.String(taskDefinitionARN),
				Family:                  awsv2.String("payments"),
				Revision:                42,
				Status:                  ecstypes.TaskDefinitionStatusActive,
				TaskRoleArn:             awsv2.String("arn:aws:iam::123456789012:role/payments-task"),
				ExecutionRoleArn:        awsv2.String("arn:aws:iam::123456789012:role/payments-execution"),
				RequiresCompatibilities: []ecstypes.Compatibility{ecstypes.CompatibilityFargate},
				ContainerDefinitions: []ecstypes.ContainerDefinition{
					{
						Image: awsv2.String("123456789012.dkr.ecr.us-east-1.amazonaws.com/payments:42"),
						Environment: []ecstypes.KeyValuePair{
							{Name: awsv2.String("APP_ENV"), Value: awsv2.String("prod")},
							{Name: awsv2.String("DATABASE_PASSWORD"), Value: awsv2.String("must-not-appear")},
						},
						Secrets: []ecstypes.Secret{
							{Name: awsv2.String("DATABASE_PASSWORD"), ValueFrom: awsv2.String("arn:aws:secretsmanager:us-east-1:123456789012:secret:payments/db")},
						},
					},
				},
			},
			inactiveTaskDefinitionARN: {
				TaskDefinitionArn: awsv2.String(inactiveTaskDefinitionARN),
				Family:            awsv2.String("legacy"),
				Revision:          7,
				Status:            ecstypes.TaskDefinitionStatusInactive,
				TaskRoleArn:       awsv2.String("arn:aws:iam::123456789012:role/legacy-task"),
				ContainerDefinitions: []ecstypes.ContainerDefinition{
					{Image: awsv2.String("legacy:7")},
				},
			},
		},
		listTaskDefinitionsByState: map[ecstypes.TaskDefinitionStatus]*ecs.ListTaskDefinitionsOutput{
			ecstypes.TaskDefinitionStatusActive:   {},
			ecstypes.TaskDefinitionStatusInactive: {TaskDefinitionArns: []string{inactiveTaskDefinitionARN}},
		},
		listServicesErr: map[string]error{},
	}
	api := NewSDKECSTaskRoleAPIFromClient(client, "123456789012", "us-east-1")

	page, err := api.ListTaskRoles(context.Background(), "", 25)
	if err != nil {
		t.Fatalf("list task roles: %v", err)
	}
	if len(page.Diagnostics) != 0 {
		t.Fatalf("expected no diagnostics, got %+v", page.Diagnostics)
	}
	if len(page.Records) != 3 {
		t.Fatalf("expected service task/execution plus inactive task role records, got %+v", page.Records)
	}
	if got := awsv2.ToInt32(client.listClustersInputs[0].MaxResults); got != 25 {
		t.Fatalf("ListClusters MaxResults = %d, want 25", got)
	}
	if len(client.describeServicesInputs) != 1 || len(client.describeServicesInputs[0].Include) != 1 || client.describeServicesInputs[0].Include[0] != ecstypes.ServiceFieldTags {
		t.Fatalf("expected DescribeServices to request tags, got %+v", client.describeServicesInputs)
	}
	if len(client.listTaskDefinitionsInputs) != 2 ||
		client.listTaskDefinitionsInputs[0].Status != ecstypes.TaskDefinitionStatusActive ||
		client.listTaskDefinitionsInputs[1].Status != ecstypes.TaskDefinitionStatusInactive {
		t.Fatalf("expected active and inactive task definition scans, got %+v", client.listTaskDefinitionsInputs)
	}

	var serviceTaskRole, serviceExecutionRole, inactiveTaskRole *ECSTaskRole
	for idx := range page.Records {
		record := &page.Records[idx]
		switch {
		case record.WorkloadType == "ecs_service" && record.RoleKind == ecsRoleKindTask:
			serviceTaskRole = record
		case record.WorkloadType == "ecs_service" && record.RoleKind == ecsRoleKindExecution:
			serviceExecutionRole = record
		case record.WorkloadType == "ecs_task_definition" && record.TaskDefinitionStatus == "INACTIVE":
			inactiveTaskRole = record
		}
		if strings.Contains(strings.Join(record.EnvironmentKeys, ","), "must-not-appear") {
			t.Fatalf("environment values must not be collected, got %+v", record.EnvironmentKeys)
		}
	}
	if serviceTaskRole == nil || serviceTaskRole.RoleARN != "arn:aws:iam::123456789012:role/payments-task" || serviceTaskRole.LaunchType != "FARGATE" {
		t.Fatalf("expected service task role with launch metadata, got %+v", page.Records)
	}
	if serviceExecutionRole == nil || serviceExecutionRole.Confidence != 0.9 || serviceExecutionRole.RoleARN != "arn:aws:iam::123456789012:role/payments-execution" {
		t.Fatalf("expected service execution role with lower confidence, got %+v", page.Records)
	}
	if inactiveTaskRole == nil || inactiveTaskRole.TaskDefinitionFamily != "legacy" || inactiveTaskRole.RoleName != "legacy-task" {
		t.Fatalf("expected inactive task definition task role, got %+v", page.Records)
	}
	if len(serviceTaskRole.SecretRefs) != 1 || !strings.Contains(serviceTaskRole.SecretRefs[0], "arn:aws:secretsmanager") {
		t.Fatalf("expected metadata-only secret reference, got %+v", serviceTaskRole.SecretRefs)
	}
}

func TestSDKECSTaskRoleAPIReportsClusterPartialFailure(t *testing.T) {
	clusterARN := "arn:aws:ecs:us-east-1:123456789012:cluster/prod"
	client := &fakeECSSDKClient{
		listClustersOutputs:         []*ecs.ListClustersOutput{{ClusterArns: []string{clusterARN}}},
		listServicesErr:             map[string]error{clusterARN: errors.New("ecs unavailable")},
		listServicesOutputByCluster: map[string]*ecs.ListServicesOutput{},
		servicesByCluster:           map[string][]ecstypes.Service{},
		taskDefinitions:             map[string]ecstypes.TaskDefinition{},
		listTaskDefinitionsByState: map[ecstypes.TaskDefinitionStatus]*ecs.ListTaskDefinitionsOutput{
			ecstypes.TaskDefinitionStatusActive:   {},
			ecstypes.TaskDefinitionStatusInactive: {},
		},
	}
	api := NewSDKECSTaskRoleAPIFromClient(client, "123456789012", "us-east-1")

	page, err := api.ListTaskRoles(context.Background(), "", 10)
	if err != nil {
		t.Fatalf("list task roles should tolerate cluster-level service listing failure: %v", err)
	}
	if len(page.Diagnostics) != 1 || page.Diagnostics[0].Code != "cluster_service_list_failed" || !page.Diagnostics[0].Retryable {
		t.Fatalf("expected retryable cluster partial-failure diagnostic, got %+v", page.Diagnostics)
	}
}
