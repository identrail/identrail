package aws

import (
	"context"
	"errors"
	"strings"
	"testing"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/codepipeline"
	codepipelinetypes "github.com/aws/aws-sdk-go-v2/service/codepipeline/types"
)

type fakeCodePipelineSDKClient struct {
	listInputs  []*codepipeline.ListPipelinesInput
	getInputs   []*codepipeline.GetPipelineInput
	stateInputs []*codepipeline.GetPipelineStateInput

	listOutputs []*codepipeline.ListPipelinesOutput
	pipelines   map[string]*codepipeline.GetPipelineOutput
	states      map[string]*codepipeline.GetPipelineStateOutput

	listErr  error
	getErr   error
	stateErr error
}

func (f *fakeCodePipelineSDKClient) ListPipelines(_ context.Context, params *codepipeline.ListPipelinesInput, _ ...func(*codepipeline.Options)) (*codepipeline.ListPipelinesOutput, error) {
	f.listInputs = append(f.listInputs, params)
	if f.listErr != nil {
		return nil, f.listErr
	}
	idx := len(f.listInputs) - 1
	if idx >= len(f.listOutputs) {
		return &codepipeline.ListPipelinesOutput{}, nil
	}
	return f.listOutputs[idx], nil
}

func (f *fakeCodePipelineSDKClient) GetPipeline(_ context.Context, params *codepipeline.GetPipelineInput, _ ...func(*codepipeline.Options)) (*codepipeline.GetPipelineOutput, error) {
	f.getInputs = append(f.getInputs, params)
	if f.getErr != nil {
		return nil, f.getErr
	}
	return f.pipelines[awsv2.ToString(params.Name)], nil
}

func (f *fakeCodePipelineSDKClient) GetPipelineState(_ context.Context, params *codepipeline.GetPipelineStateInput, _ ...func(*codepipeline.Options)) (*codepipeline.GetPipelineStateOutput, error) {
	f.stateInputs = append(f.stateInputs, params)
	if f.stateErr != nil {
		return nil, f.stateErr
	}
	return f.states[awsv2.ToString(params.Name)], nil
}

func TestSDKCodePipelineDeploymentRoleAPIMapsPipelineAndActionRoles(t *testing.T) {
	pipelineName := "payments-release"
	pipelineARN := "arn:aws:codepipeline:us-east-1:123456789012:payments-release"
	pipelineRoleARN := "arn:aws:iam::123456789012:role/payments-codepipeline-service"
	actionRoleARN := "arn:aws:iam::210987654321:role/payments-prod-deploy-action"
	client := &fakeCodePipelineSDKClient{
		listOutputs: []*codepipeline.ListPipelinesOutput{{
			Pipelines: []codepipelinetypes.PipelineSummary{{Name: awsv2.String(pipelineName)}},
		}},
		pipelines: map[string]*codepipeline.GetPipelineOutput{
			pipelineName: codePipelineSDKTestPipeline(pipelineName, pipelineARN, pipelineRoleARN, actionRoleARN),
		},
		states: map[string]*codepipeline.GetPipelineStateOutput{
			pipelineName: {
				StageStates: []codepipelinetypes.StageState{{
					StageName: awsv2.String("Deploy"),
					InboundTransitionState: &codepipelinetypes.TransitionState{
						Enabled:        false,
						DisabledReason: awsv2.String("freeze window"),
					},
				}},
			},
		},
	}
	api := NewSDKCodePipelineDeploymentRoleAPIFromClient(client, "123456789012", "us-east-1")

	page, err := api.ListServiceRoles(context.Background(), "", 25)
	if err != nil {
		t.Fatalf("list deployment roles: %v", err)
	}
	if len(page.Records) != 2 {
		t.Fatalf("expected pipeline and action role records, got %+v", page.Records)
	}
	if len(client.listInputs) != 1 || client.listInputs[0].NextToken != nil || awsv2.ToInt32(client.listInputs[0].MaxResults) != 25 {
		t.Fatalf("expected one ListPipelines call with page size, got %+v", client.listInputs)
	}
	if len(client.getInputs) != 1 || len(client.stateInputs) != 1 {
		t.Fatalf("expected GetPipeline and GetPipelineState calls, got get=%+v state=%+v", client.getInputs, client.stateInputs)
	}

	var pipelineRecord, actionRecord CodePipelineDeploymentRole
	for _, record := range page.Records {
		switch record.RoleKind {
		case "pipeline_service_role":
			pipelineRecord = record
		case "action_role":
			actionRecord = record
		}
	}
	if pipelineRecord.RoleARN != pipelineRoleARN || pipelineRecord.RoleKind != "pipeline_service_role" || pipelineRecord.PipelineARN != pipelineARN {
		t.Fatalf("expected pipeline service role metadata, got %+v", pipelineRecord)
	}
	if actionRecord.RoleARN != actionRoleARN || actionRecord.RoleKind != "action_role" || !actionRecord.CrossAccountRole || !actionRecord.CrossRegionAction {
		t.Fatalf("expected cross-account cross-region action role metadata, got %+v", actionRecord)
	}
	if actionRecord.AccountID != "123456789012" || actionRecord.RoleAccountID != "210987654321" {
		t.Fatalf("expected action workload account and role account to remain separate, got %+v", actionRecord)
	}
	if actionRecord.ActionProvider != "CodeDeploy" || actionRecord.ActionCategory != "Deploy" || len(actionRecord.InputArtifactNames) != 1 {
		t.Fatalf("expected action provider/artifact metadata, got %+v", actionRecord)
	}
	if len(actionRecord.ConfigurationKeys) != 2 || strings.Contains(strings.Join(actionRecord.ConfigurationKeys, ","), "must-not-appear") {
		t.Fatalf("expected configuration keys without values, got %+v", actionRecord.ConfigurationKeys)
	}
	if len(actionRecord.ArtifactStoreRegions) != 2 || !pipelineRecord.CrossRegionArtifactStores {
		t.Fatalf("expected cross-region artifact stores, got pipeline=%+v action=%+v", pipelineRecord, actionRecord)
	}
	if got := strings.Join(actionRecord.ArtifactStoreRegions, ","); got != "us-east-1,us-west-2" {
		t.Fatalf("expected stable artifact store region ordering, got %q", got)
	}
	if got := strings.Join(actionRecord.ArtifactStoreLocations, ","); got != "payments-pipeline-artifacts-east,payments-pipeline-artifacts-west" {
		t.Fatalf("expected stable artifact store location ordering, got %q", got)
	}
	if got := strings.Join(actionRecord.ConfigurationKeys, ","); got != "ApplicationName,DeploymentGroupName" {
		t.Fatalf("expected stable configuration key ordering, got %q", got)
	}
	if len(pipelineRecord.DisabledStageTransitions) != 1 || !strings.Contains(pipelineRecord.DisabledStageTransitions[0], "freeze window") {
		t.Fatalf("expected disabled transition evidence, got %+v", pipelineRecord.DisabledStageTransitions)
	}
	if len(actionRecord.DisabledStageTransitions) != 0 {
		t.Fatalf("expected disabled transition evidence to stay pipeline-scoped, got action=%+v", actionRecord.DisabledStageTransitions)
	}
}

func TestSDKCodePipelineDeploymentRoleAPISurfacesPartialPipelineFailures(t *testing.T) {
	client := &fakeCodePipelineSDKClient{
		listOutputs: []*codepipeline.ListPipelinesOutput{{
			Pipelines: []codepipelinetypes.PipelineSummary{{Name: awsv2.String("missing")}},
		}},
		pipelines: map[string]*codepipeline.GetPipelineOutput{},
	}
	api := NewSDKCodePipelineDeploymentRoleAPIFromClient(client, "123456789012", "us-east-1")

	page, err := api.ListServiceRoles(context.Background(), "", 10)
	if err != nil {
		t.Fatalf("list deployment roles: %v", err)
	}
	if len(page.Records) != 0 || len(page.Diagnostics) != 1 || page.Diagnostics[0].Code != "pipeline_not_found" {
		t.Fatalf("expected pipeline_not_found diagnostic, got %+v", page)
	}
}

func TestSDKCodePipelineDeploymentRoleAPIHandlesNextTokenAndListErrors(t *testing.T) {
	client := &fakeCodePipelineSDKClient{listErr: errors.New("codepipeline unavailable")}
	api := NewSDKCodePipelineDeploymentRoleAPIFromClient(client, "123456789012", "us-east-1")

	if _, err := api.ListServiceRoles(context.Background(), "page-1", 10); err == nil || !strings.Contains(err.Error(), "codepipeline unavailable") {
		t.Fatalf("expected list failure, got %v", err)
	}
	if got := awsv2.ToString(client.listInputs[0].NextToken); got != "page-1" {
		t.Fatalf("expected forwarded next token, got %q", got)
	}
}

func codePipelineSDKTestPipeline(name string, arn string, pipelineRoleARN string, actionRoleARN string) *codepipeline.GetPipelineOutput {
	return &codepipeline.GetPipelineOutput{
		Metadata: &codepipelinetypes.PipelineMetadata{PipelineArn: awsv2.String(arn)},
		Pipeline: &codepipelinetypes.PipelineDeclaration{
			Name:          awsv2.String(name),
			RoleArn:       awsv2.String(pipelineRoleARN),
			Version:       awsv2.Int32(3),
			PipelineType:  codepipelinetypes.PipelineTypeV2,
			ExecutionMode: codepipelinetypes.ExecutionModeQueued,
			ArtifactStores: map[string]codepipelinetypes.ArtifactStore{
				"us-east-1": {
					Type:     codepipelinetypes.ArtifactStoreTypeS3,
					Location: awsv2.String("payments-pipeline-artifacts-east"),
					EncryptionKey: &codepipelinetypes.EncryptionKey{
						Id:   awsv2.String("arn:aws:kms:us-east-1:123456789012:key/pipeline-east"),
						Type: codepipelinetypes.EncryptionKeyTypeKms,
					},
				},
				"us-west-2": {
					Type:     codepipelinetypes.ArtifactStoreTypeS3,
					Location: awsv2.String("payments-pipeline-artifacts-west"),
				},
			},
			Stages: []codepipelinetypes.StageDeclaration{{
				Name: awsv2.String("Deploy"),
				Actions: []codepipelinetypes.ActionDeclaration{{
					Name:    awsv2.String("Prod"),
					RoleArn: awsv2.String(actionRoleARN),
					Region:  awsv2.String("us-west-2"),
					ActionTypeId: &codepipelinetypes.ActionTypeId{
						Category: codepipelinetypes.ActionCategoryDeploy,
						Owner:    codepipelinetypes.ActionOwnerAws,
						Provider: awsv2.String("CodeDeploy"),
						Version:  awsv2.String("1"),
					},
					InputArtifacts: []codepipelinetypes.InputArtifact{{Name: awsv2.String("BuildArtifact")}},
					Configuration: map[string]string{
						"ApplicationName":     "must-not-appear",
						"DeploymentGroupName": "must-not-appear",
					},
				}},
			}},
		},
	}
}
