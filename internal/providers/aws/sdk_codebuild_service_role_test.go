package aws

import (
	"context"
	"errors"
	"strings"
	"testing"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/codebuild"
	codebuildtypes "github.com/aws/aws-sdk-go-v2/service/codebuild/types"
)

type fakeCodeBuildSDKClient struct {
	listProjectsInputs    []*codebuild.ListProjectsInput
	batchGetProjectsInput []*codebuild.BatchGetProjectsInput

	listProjectsOutputs []*codebuild.ListProjectsOutput
	projectsByName      map[string]codebuildtypes.Project

	listProjectsErr     error
	batchGetProjectsErr error
	projectsNotFound    []string
}

func (f *fakeCodeBuildSDKClient) ListProjects(_ context.Context, params *codebuild.ListProjectsInput, _ ...func(*codebuild.Options)) (*codebuild.ListProjectsOutput, error) {
	f.listProjectsInputs = append(f.listProjectsInputs, params)
	if f.listProjectsErr != nil {
		return nil, f.listProjectsErr
	}
	idx := len(f.listProjectsInputs) - 1
	if idx >= len(f.listProjectsOutputs) {
		return &codebuild.ListProjectsOutput{}, nil
	}
	return f.listProjectsOutputs[idx], nil
}

func (f *fakeCodeBuildSDKClient) BatchGetProjects(_ context.Context, params *codebuild.BatchGetProjectsInput, _ ...func(*codebuild.Options)) (*codebuild.BatchGetProjectsOutput, error) {
	f.batchGetProjectsInput = append(f.batchGetProjectsInput, params)
	if f.batchGetProjectsErr != nil {
		return nil, f.batchGetProjectsErr
	}
	output := &codebuild.BatchGetProjectsOutput{ProjectsNotFound: append([]string(nil), f.projectsNotFound...)}
	for _, name := range params.Names {
		if project, ok := f.projectsByName[name]; ok {
			output.Projects = append(output.Projects, project)
		}
	}
	return output, nil
}

func TestSDKCodeBuildServiceRoleAPIMapsProjectRoleAndMetadata(t *testing.T) {
	projectARN := "arn:aws:codebuild:us-east-1:123456789012:project/payments-build"
	roleARN := "arn:aws:iam::123456789012:role/payments-codebuild-service"
	secretARN := "arn:aws:secretsmanager:us-east-1:123456789012:secret:codebuild/payments-db"
	client := &fakeCodeBuildSDKClient{
		listProjectsOutputs: []*codebuild.ListProjectsOutput{
			{Projects: []string{"payments-build"}},
		},
		projectsByName: map[string]codebuildtypes.Project{
			"payments-build": {
				Arn:               awsv2.String(projectARN),
				Name:              awsv2.String("payments-build"),
				ServiceRole:       awsv2.String(roleARN),
				Description:       awsv2.String("payments ci"),
				ProjectVisibility: codebuildtypes.ProjectVisibilityTypePrivate,
				SourceVersion:     awsv2.String("main"),
				EncryptionKey:     awsv2.String("arn:aws:kms:us-east-1:123456789012:key/codebuild"),
				Source: &codebuildtypes.ProjectSource{
					Type:             codebuildtypes.SourceTypeGithub,
					Location:         awsv2.String("https://github.com/example/payments"),
					SourceIdentifier: awsv2.String("primary"),
					Auth:             &codebuildtypes.SourceAuth{Type: codebuildtypes.SourceAuthTypeCodeconnections},
				},
				Artifacts: &codebuildtypes.ProjectArtifacts{
					Type:     codebuildtypes.ArtifactsTypeS3,
					Location: awsv2.String("payments-artifacts"),
				},
				Environment: &codebuildtypes.ProjectEnvironment{
					Type:                     codebuildtypes.EnvironmentTypeLinuxContainer,
					ComputeType:              codebuildtypes.ComputeTypeBuildGeneral1Small,
					Image:                    awsv2.String("aws/codebuild/standard:7.0"),
					ImagePullCredentialsType: codebuildtypes.ImagePullCredentialsTypeCodebuild,
					PrivilegedMode:           awsv2.Bool(true),
					EnvironmentVariables: []codebuildtypes.EnvironmentVariable{
						{Name: awsv2.String("APP_ENV"), Value: awsv2.String("prod"), Type: codebuildtypes.EnvironmentVariableTypePlaintext},
						{Name: awsv2.String("DATABASE_PASSWORD"), Value: awsv2.String(secretARN), Type: codebuildtypes.EnvironmentVariableTypeSecretsManager},
						{Name: awsv2.String("NPM_TOKEN"), Value: awsv2.String("/ci/npm/token"), Type: codebuildtypes.EnvironmentVariableTypeParameterStore},
					},
				},
				VpcConfig: &codebuildtypes.VpcConfig{
					VpcId:            awsv2.String("vpc-123"),
					Subnets:          []string{"subnet-a", "subnet-b"},
					SecurityGroupIds: []string{"sg-123"},
				},
				Cache: &codebuildtypes.ProjectCache{
					Type:     codebuildtypes.CacheTypeLocal,
					Location: awsv2.String("local-cache"),
				},
				LogsConfig: &codebuildtypes.LogsConfig{
					CloudWatchLogs: &codebuildtypes.CloudWatchLogsConfig{},
					S3Logs:         &codebuildtypes.S3LogsConfig{},
				},
				Tags: []codebuildtypes.Tag{{Key: awsv2.String("owner"), Value: awsv2.String("payments")}},
			},
		},
	}
	api := NewSDKCodeBuildServiceRoleAPIFromClient(client, "123456789012", "us-east-1")

	page, err := api.ListServiceRoles(context.Background(), "", 25)
	if err != nil {
		t.Fatalf("list service roles: %v", err)
	}
	if len(page.Records) != 1 {
		t.Fatalf("expected one codebuild role record, got %+v", page.Records)
	}
	if len(client.listProjectsInputs) != 1 || client.listProjectsInputs[0].NextToken != nil {
		t.Fatalf("expected one ListProjects call, got %+v", client.listProjectsInputs)
	}
	if len(client.batchGetProjectsInput) != 1 || len(client.batchGetProjectsInput[0].Names) != 1 || client.batchGetProjectsInput[0].Names[0] != "payments-build" {
		t.Fatalf("expected BatchGetProjects by project name, got %+v", client.batchGetProjectsInput)
	}

	record := page.Records[0]
	if record.RoleARN != roleARN || record.RoleName != "payments-codebuild-service" || record.ProjectName != "payments-build" {
		t.Fatalf("expected project service role metadata, got %+v", record)
	}
	if record.SourceType != "GITHUB" || record.SourceAuthType != "CODECONNECTIONS" || record.SourceLocation == "" {
		t.Fatalf("expected source metadata, got %+v", record)
	}
	if record.EnvironmentType != "LINUX_CONTAINER" || record.ComputeType != "BUILD_GENERAL1_SMALL" || !record.PrivilegedMode {
		t.Fatalf("expected environment metadata, got %+v", record)
	}
	if record.VPCID != "vpc-123" || len(record.SubnetIDs) != 2 || len(record.SecurityGroupIDs) != 1 {
		t.Fatalf("expected vpc metadata, got %+v", record)
	}
	if len(record.SecretRefs) != 2 || !strings.Contains(record.SecretRefs[0]+record.SecretRefs[1], secretARN) {
		t.Fatalf("expected secret reference metadata, got %+v", record.SecretRefs)
	}
	if strings.Contains(strings.Join(record.EnvironmentKeys, ","), "prod") || strings.Contains(strings.Join(record.SecretRefs, ","), "must-not-appear") {
		t.Fatalf("environment values must not be collected, got record=%+v", record)
	}
	if len(record.LogTypes) != 2 || record.CacheType != "LOCAL" {
		t.Fatalf("expected log/cache metadata, got %+v", record)
	}
}

func TestSDKCodeBuildServiceRoleAPIFailsWhenProjectListingFails(t *testing.T) {
	client := &fakeCodeBuildSDKClient{listProjectsErr: errors.New("codebuild unavailable")}
	api := NewSDKCodeBuildServiceRoleAPIFromClient(client, "123456789012", "us-east-1")

	if _, err := api.ListServiceRoles(context.Background(), "", 10); err == nil {
		t.Fatal("expected list projects failure")
	}
}

func TestSDKCodeBuildServiceRoleAPIEmitsProjectNotFoundDiagnostic(t *testing.T) {
	client := &fakeCodeBuildSDKClient{
		listProjectsOutputs: []*codebuild.ListProjectsOutput{{Projects: []string{"missing-project"}}},
		projectsByName:      map[string]codebuildtypes.Project{},
		projectsNotFound:    []string{"missing-project"},
	}
	api := NewSDKCodeBuildServiceRoleAPIFromClient(client, "123456789012", "us-east-1")

	page, err := api.ListServiceRoles(context.Background(), "", 10)
	if err != nil {
		t.Fatalf("list service roles: %v", err)
	}
	if len(page.Records) != 0 || len(page.Diagnostics) != 1 || page.Diagnostics[0].Code != "project_not_found" || !page.Diagnostics[0].Retryable {
		t.Fatalf("expected project_not_found diagnostic, got page=%+v", page)
	}
}

func TestSDKCodeBuildServiceRoleAPIBatchesFullListProjectsPage(t *testing.T) {
	client := &fakeCodeBuildSDKClient{
		listProjectsOutputs: []*codebuild.ListProjectsOutput{{Projects: []string{"project-a", "project-b", "project-c"}, NextToken: awsv2.String("page-2")}},
		projectsByName: map[string]codebuildtypes.Project{
			"project-a": codeBuildSDKTestProject("project-a"),
			"project-b": codeBuildSDKTestProject("project-b"),
			"project-c": codeBuildSDKTestProject("project-c"),
		},
	}
	api := NewSDKCodeBuildServiceRoleAPIFromClient(client, "123456789012", "us-east-1")

	page, err := api.ListServiceRoles(context.Background(), "", 1)
	if err != nil {
		t.Fatalf("list service roles: %v", err)
	}
	if len(page.Records) != 3 {
		t.Fatalf("expected every listed project to be resolved despite smaller public page size, got %+v", page.Records)
	}
	if page.NextToken != "page-2" {
		t.Fatalf("expected AWS next token to be preserved, got %q", page.NextToken)
	}
	if len(client.batchGetProjectsInput) != 1 || len(client.batchGetProjectsInput[0].Names) != 3 {
		t.Fatalf("expected full ListProjects page to be batched, got %+v", client.batchGetProjectsInput)
	}
}

func TestSDKCodeBuildServiceRoleAPIHandlesNextTokenAndBatchErrors(t *testing.T) {
	client := &fakeCodeBuildSDKClient{
		listProjectsOutputs: []*codebuild.ListProjectsOutput{{Projects: []string{"payments-build"}, NextToken: awsv2.String("page-2")}},
		projectsByName:      map[string]codebuildtypes.Project{},
		batchGetProjectsErr: errors.New("batch failed"),
	}
	api := NewSDKCodeBuildServiceRoleAPIFromClient(client, "123456789012", "us-east-1")

	if _, err := api.ListServiceRoles(context.Background(), "page-1", 10); err == nil || !strings.Contains(err.Error(), "batch failed") {
		t.Fatalf("expected batch failure, got %v", err)
	}
	if got := awsv2.ToString(client.listProjectsInputs[0].NextToken); got != "page-1" {
		t.Fatalf("expected forwarded next token, got %q", got)
	}
}

func codeBuildSDKTestProject(name string) codebuildtypes.Project {
	return codebuildtypes.Project{
		Arn:         awsv2.String("arn:aws:codebuild:us-east-1:123456789012:project/" + name),
		Name:        awsv2.String(name),
		ServiceRole: awsv2.String("arn:aws:iam::123456789012:role/" + name + "-service"),
	}
}
