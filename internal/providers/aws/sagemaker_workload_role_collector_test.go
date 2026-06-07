package aws

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sagemaker"
	sagemakertypes "github.com/aws/aws-sdk-go-v2/service/sagemaker/types"

	"github.com/identrail/identrail/internal/providers"
	"github.com/identrail/identrail/internal/providers/awscontract"
)

type fakeSageMakerWorkloadRoleAPI struct {
	pages     []SageMakerWorkloadRolePage
	tokens    []string
	pageSizes []int32
}

func (f *fakeSageMakerWorkloadRoleAPI) ListServiceRoles(ctx context.Context, nextToken string, pageSize int32) (SageMakerWorkloadRolePage, error) {
	f.tokens = append(f.tokens, nextToken)
	f.pageSizes = append(f.pageSizes, pageSize)
	if len(f.pages) == 0 {
		return SageMakerWorkloadRolePage{}, nil
	}
	page := f.pages[0]
	f.pages = f.pages[1:]
	return page, nil
}

func TestSageMakerWorkloadRoleCollectorEmitsNormalizedAssets(t *testing.T) {
	collectedAt := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	roleARN := "arn:aws:iam::123456789012:role/sagemaker-payments-training"
	workloadARN := "arn:aws:sagemaker:us-east-1:123456789012:training-job/payments-train-2026"
	api := &fakeSageMakerWorkloadRoleAPI{pages: []SageMakerWorkloadRolePage{{
		Records: []SageMakerWorkloadRole{{
			ServiceCollectorRecord: awscontract.ServiceCollectorRecord{
				AccountID:    "123456789012",
				Region:       "us-east-1",
				Service:      "sagemaker",
				WorkloadID:   workloadARN,
				WorkloadName: "payments-train-2026",
				WorkloadType: "sagemaker_training_job",
				RoleARN:      roleARN,
			},
			RoleKind:       "sagemaker_training_execution_role",
			WorkloadARN:    workloadARN,
			ResourceStatus: "InProgress",
			ImageURIs:      []string{"123456789012.dkr.ecr.us-east-1.amazonaws.com/payments-training:2026-04"},
			S3References:   []string{"s3://payments-feature-store/train/123456789012/"},
			KMSKeyARNs:     []string{"arn:aws:kms:us-east-1:123456789012:key/payments-train-out"},
			Active:         true,
		}},
		NextToken: "page-2",
	}, {
		Diagnostics: []providers.SourceError{{
			Collector: sageMakerWorkloadRoleCollectorName,
			SourceID:  "sagemaker",
			Code:      "sagemaker_pipelines_failed",
			Message:   "one sagemaker pipeline page failed",
			Retryable: true,
		}},
	}}}
	collector := NewSageMakerWorkloadRoleCollector(api, WithSageMakerWorkloadRolePageSize(25), WithSageMakerWorkloadRoleClock(func() time.Time { return collectedAt }))

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
	if len(assets) != 1 {
		t.Fatalf("expected one asset, got %d", len(assets))
	}
	if assets[0].Kind != rawKindSageMakerWorkloadRole {
		t.Fatalf("unexpected asset kind %q", assets[0].Kind)
	}
	if len(diagnostics) != 1 || diagnostics[0].Code != "sagemaker_pipelines_failed" {
		t.Fatalf("expected retained diagnostic, got %+v", diagnostics)
	}
	if got, want := strings.Join(api.tokens, ","), ",page-2"; got != want {
		t.Fatalf("expected tokens %q, got %q", want, got)
	}

	var record SageMakerWorkloadRole
	if err := json.Unmarshal(assets[0].Payload, &record); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if record.RoleARN != roleARN || record.RoleKind != "sagemaker_training_execution_role" {
		t.Fatalf("unexpected normalized record: %+v", record)
	}
	if record.RoleName != "sagemaker-payments-training" {
		t.Fatalf("expected role name normalized from arn, got %q", record.RoleName)
	}
	if record.TenantID != "tenant-a" || record.WorkspaceID != "workspace-a" || record.ProjectID != "project-a" {
		t.Fatalf("expected scope inherited, got %+v", record)
	}
	if got, want := strings.Join(record.ImageURIs, ","), "123456789012.dkr.ecr.us-east-1.amazonaws.com/payments-training:2026-04"; got != want {
		t.Fatalf("expected image uris %q, got %q", want, got)
	}
}

func TestSageMakerWorkloadRoleCollectorSkipsRecordsMissingRole(t *testing.T) {
	collectedAt := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	api := &fakeSageMakerWorkloadRoleAPI{pages: []SageMakerWorkloadRolePage{{
		Records: []SageMakerWorkloadRole{{
			ServiceCollectorRecord: awscontract.ServiceCollectorRecord{
				AccountID:    "123456789012",
				Region:       "us-east-1",
				Service:      "sagemaker",
				WorkloadID:   "arn:aws:sagemaker:us-east-1:123456789012:notebook-instance/no-role",
				WorkloadName: "no-role",
				WorkloadType: "sagemaker_notebook_instance",
				RoleARN:      "",
			},
			RoleKind:    "sagemaker_notebook_execution_role",
			WorkloadARN: "arn:aws:sagemaker:us-east-1:123456789012:notebook-instance/no-role",
		}},
	}}}
	collector := NewSageMakerWorkloadRoleCollector(api, WithSageMakerWorkloadRoleClock(func() time.Time { return collectedAt }))
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
	if len(assets) != 0 {
		t.Fatalf("expected role-less records dropped, got %+v", assets)
	}
	if len(diagnostics) != 1 || diagnostics[0].Code != "missing_sagemaker_role" {
		t.Fatalf("expected missing_sagemaker_role diagnostic, got %+v", diagnostics)
	}
}

func TestSageMakerWorkloadRoleSourceIDDedupesAcrossPages(t *testing.T) {
	collectedAt := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	roleARN := "arn:aws:iam::123456789012:role/sagemaker-payments-model"
	workloadARN := "arn:aws:sagemaker:us-east-1:123456789012:model/payments-risk-classifier"
	record := SageMakerWorkloadRole{
		ServiceCollectorRecord: awscontract.ServiceCollectorRecord{
			AccountID:    "123456789012",
			Region:       "us-east-1",
			Service:      "sagemaker",
			WorkloadID:   workloadARN,
			WorkloadName: "payments-risk-classifier",
			WorkloadType: "sagemaker_model",
			RoleARN:      roleARN,
		},
		RoleKind:    "sagemaker_model_execution_role",
		WorkloadARN: workloadARN,
	}
	api := &fakeSageMakerWorkloadRoleAPI{pages: []SageMakerWorkloadRolePage{
		{Records: []SageMakerWorkloadRole{record}, NextToken: "page-2"},
		{Records: []SageMakerWorkloadRole{record}},
	}}
	collector := NewSageMakerWorkloadRoleCollector(api, WithSageMakerWorkloadRoleClock(func() time.Time { return collectedAt }))
	assets, _, err := collector.CollectWithDiagnostics(context.Background(), AWSCollectorScope{
		TenantID:    "tenant-a",
		WorkspaceID: "workspace-a",
		ProjectID:   "project-a",
		ConnectorID: "aws-prod",
		ScanID:      "scan-1",
	})
	if err != nil {
		t.Fatalf("collect failed: %v", err)
	}
	if len(assets) != 1 {
		t.Fatalf("expected duplicate dedupe, got %d assets", len(assets))
	}
}

type fakeSageMakerSDKClient struct {
	notebooks   []sagemakertypes.NotebookInstanceSummary
	notebook    *sagemaker.DescribeNotebookInstanceOutput
	pipelines   []sagemakertypes.PipelineSummary
	pipeline    *sagemaker.DescribePipelineOutput
	pipelineErr error
}

func (f *fakeSageMakerSDKClient) ListNotebookInstances(ctx context.Context, params *sagemaker.ListNotebookInstancesInput, optFns ...func(*sagemaker.Options)) (*sagemaker.ListNotebookInstancesOutput, error) {
	return &sagemaker.ListNotebookInstancesOutput{NotebookInstances: f.notebooks}, nil
}

func (f *fakeSageMakerSDKClient) DescribeNotebookInstance(ctx context.Context, params *sagemaker.DescribeNotebookInstanceInput, optFns ...func(*sagemaker.Options)) (*sagemaker.DescribeNotebookInstanceOutput, error) {
	return f.notebook, nil
}

func (f *fakeSageMakerSDKClient) ListTrainingJobs(ctx context.Context, params *sagemaker.ListTrainingJobsInput, optFns ...func(*sagemaker.Options)) (*sagemaker.ListTrainingJobsOutput, error) {
	return &sagemaker.ListTrainingJobsOutput{}, nil
}
func (f *fakeSageMakerSDKClient) DescribeTrainingJob(ctx context.Context, params *sagemaker.DescribeTrainingJobInput, optFns ...func(*sagemaker.Options)) (*sagemaker.DescribeTrainingJobOutput, error) {
	return nil, nil
}
func (f *fakeSageMakerSDKClient) ListProcessingJobs(ctx context.Context, params *sagemaker.ListProcessingJobsInput, optFns ...func(*sagemaker.Options)) (*sagemaker.ListProcessingJobsOutput, error) {
	return &sagemaker.ListProcessingJobsOutput{}, nil
}
func (f *fakeSageMakerSDKClient) DescribeProcessingJob(ctx context.Context, params *sagemaker.DescribeProcessingJobInput, optFns ...func(*sagemaker.Options)) (*sagemaker.DescribeProcessingJobOutput, error) {
	return nil, nil
}
func (f *fakeSageMakerSDKClient) ListTransformJobs(ctx context.Context, params *sagemaker.ListTransformJobsInput, optFns ...func(*sagemaker.Options)) (*sagemaker.ListTransformJobsOutput, error) {
	return &sagemaker.ListTransformJobsOutput{}, nil
}
func (f *fakeSageMakerSDKClient) DescribeTransformJob(ctx context.Context, params *sagemaker.DescribeTransformJobInput, optFns ...func(*sagemaker.Options)) (*sagemaker.DescribeTransformJobOutput, error) {
	return nil, nil
}
func (f *fakeSageMakerSDKClient) ListModels(ctx context.Context, params *sagemaker.ListModelsInput, optFns ...func(*sagemaker.Options)) (*sagemaker.ListModelsOutput, error) {
	return &sagemaker.ListModelsOutput{}, nil
}
func (f *fakeSageMakerSDKClient) DescribeModel(ctx context.Context, params *sagemaker.DescribeModelInput, optFns ...func(*sagemaker.Options)) (*sagemaker.DescribeModelOutput, error) {
	return nil, nil
}
func (f *fakeSageMakerSDKClient) ListEndpoints(ctx context.Context, params *sagemaker.ListEndpointsInput, optFns ...func(*sagemaker.Options)) (*sagemaker.ListEndpointsOutput, error) {
	return &sagemaker.ListEndpointsOutput{}, nil
}
func (f *fakeSageMakerSDKClient) DescribeEndpoint(ctx context.Context, params *sagemaker.DescribeEndpointInput, optFns ...func(*sagemaker.Options)) (*sagemaker.DescribeEndpointOutput, error) {
	return nil, nil
}
func (f *fakeSageMakerSDKClient) DescribeEndpointConfig(ctx context.Context, params *sagemaker.DescribeEndpointConfigInput, optFns ...func(*sagemaker.Options)) (*sagemaker.DescribeEndpointConfigOutput, error) {
	return nil, nil
}
func (f *fakeSageMakerSDKClient) ListPipelines(ctx context.Context, params *sagemaker.ListPipelinesInput, optFns ...func(*sagemaker.Options)) (*sagemaker.ListPipelinesOutput, error) {
	if f.pipelineErr != nil {
		return nil, f.pipelineErr
	}
	return &sagemaker.ListPipelinesOutput{PipelineSummaries: f.pipelines}, nil
}
func (f *fakeSageMakerSDKClient) DescribePipeline(ctx context.Context, params *sagemaker.DescribePipelineInput, optFns ...func(*sagemaker.Options)) (*sagemaker.DescribePipelineOutput, error) {
	return f.pipeline, nil
}
func (f *fakeSageMakerSDKClient) ListDomains(ctx context.Context, params *sagemaker.ListDomainsInput, optFns ...func(*sagemaker.Options)) (*sagemaker.ListDomainsOutput, error) {
	return &sagemaker.ListDomainsOutput{}, nil
}
func (f *fakeSageMakerSDKClient) DescribeDomain(ctx context.Context, params *sagemaker.DescribeDomainInput, optFns ...func(*sagemaker.Options)) (*sagemaker.DescribeDomainOutput, error) {
	return nil, nil
}
func (f *fakeSageMakerSDKClient) ListTags(ctx context.Context, params *sagemaker.ListTagsInput, optFns ...func(*sagemaker.Options)) (*sagemaker.ListTagsOutput, error) {
	return &sagemaker.ListTagsOutput{}, nil
}

func TestSDKSageMakerWorkloadRoleEmitsNotebookAndPipelineRecords(t *testing.T) {
	client := &fakeSageMakerSDKClient{
		notebooks: []sagemakertypes.NotebookInstanceSummary{{
			NotebookInstanceName: awsv2.String("payments-eval"),
			NotebookInstanceArn:  awsv2.String("arn:aws:sagemaker:us-east-1:123456789012:notebook-instance/payments-eval"),
		}},
		notebook: &sagemaker.DescribeNotebookInstanceOutput{
			NotebookInstanceName:   awsv2.String("payments-eval"),
			NotebookInstanceArn:    awsv2.String("arn:aws:sagemaker:us-east-1:123456789012:notebook-instance/payments-eval"),
			NotebookInstanceStatus: sagemakertypes.NotebookInstanceStatusInService,
			RoleArn:                awsv2.String("arn:aws:iam::123456789012:role/sagemaker-payments-notebook"),
			KmsKeyId:               awsv2.String("arn:aws:kms:us-east-1:123456789012:key/payments-notebook"),
		},
		pipelines: []sagemakertypes.PipelineSummary{{
			PipelineName: awsv2.String("payments-mlops"),
			PipelineArn:  awsv2.String("arn:aws:sagemaker:us-east-1:123456789012:pipeline/payments-mlops"),
		}},
		pipeline: &sagemaker.DescribePipelineOutput{
			PipelineName:   awsv2.String("payments-mlops"),
			PipelineArn:    awsv2.String("arn:aws:sagemaker:us-east-1:123456789012:pipeline/payments-mlops"),
			PipelineStatus: sagemakertypes.PipelineStatusActive,
			RoleArn:        awsv2.String("arn:aws:iam::123456789012:role/sagemaker-payments-pipeline"),
		},
	}
	api := &SDKSageMakerWorkloadRoleAPI{client: client, accountID: "123456789012", region: "us-east-1"}
	page, err := api.ListServiceRoles(context.Background(), "", 100)
	if err != nil {
		t.Fatalf("list service roles: %v", err)
	}
	if len(page.Records) != 2 {
		t.Fatalf("expected notebook and pipeline records, got %+v", page.Records)
	}
	var roleKinds []string
	for _, record := range page.Records {
		roleKinds = append(roleKinds, record.RoleKind)
	}
	gotKinds := strings.Join(roleKinds, ",")
	if !strings.Contains(gotKinds, "sagemaker_notebook_execution_role") || !strings.Contains(gotKinds, "sagemaker_pipeline_execution_role") {
		t.Fatalf("expected both execution role kinds, got %s", gotKinds)
	}
}

func TestSDKSageMakerWorkloadRoleDegradesOnSubListingFailure(t *testing.T) {
	client := &fakeSageMakerSDKClient{
		notebooks: []sagemakertypes.NotebookInstanceSummary{{
			NotebookInstanceName: awsv2.String("payments-eval"),
			NotebookInstanceArn:  awsv2.String("arn:aws:sagemaker:us-east-1:123456789012:notebook-instance/payments-eval"),
		}},
		notebook: &sagemaker.DescribeNotebookInstanceOutput{
			NotebookInstanceName:   awsv2.String("payments-eval"),
			NotebookInstanceArn:    awsv2.String("arn:aws:sagemaker:us-east-1:123456789012:notebook-instance/payments-eval"),
			NotebookInstanceStatus: sagemakertypes.NotebookInstanceStatusInService,
			RoleArn:                awsv2.String("arn:aws:iam::123456789012:role/sagemaker-payments-notebook"),
		},
		pipelineErr: errors.New("throttled by SageMaker"),
	}
	api := &SDKSageMakerWorkloadRoleAPI{client: client, accountID: "123456789012", region: "us-east-1"}
	page, err := api.ListServiceRoles(context.Background(), "", 100)
	if err != nil {
		t.Fatalf("expected sub-listing failure to degrade, got err %v", err)
	}
	if len(page.Records) != 1 || page.Records[0].RoleKind != "sagemaker_notebook_execution_role" {
		t.Fatalf("expected notebook record retained, got %+v", page.Records)
	}
	foundPipelineDiag := false
	for _, diag := range page.Diagnostics {
		if diag.Code == "sagemaker_pipelines_failed" && diag.Retryable {
			foundPipelineDiag = true
		}
	}
	if !foundPipelineDiag {
		t.Fatalf("expected sagemaker_pipelines_failed diagnostic, got %+v", page.Diagnostics)
	}
}

func TestSDKSageMakerIAMRoleARNUsesRegionPartition(t *testing.T) {
	api := &SDKSageMakerWorkloadRoleAPI{accountID: "123456789012", region: "us-gov-west-1"}
	got := api.iamRoleARNForSageMaker("SageMakerExecutionRole", "arn:aws-us-gov:sagemaker:us-gov-west-1:123456789012:model/payments")
	if !strings.HasPrefix(got, "arn:aws-us-gov:iam::") {
		t.Fatalf("expected GovCloud partition in expanded role arn, got %q", got)
	}
}
