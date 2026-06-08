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

	"github.com/identrail/identrail/internal/domain"
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

func TestSDKSageMakerWorkloadRoleEmitsNotebookAndPipelineRecords(t *testing.T) {
	client := &fullSageMakerSDKClient{
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
	client := &fullSageMakerSDKClient{
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

// fullSageMakerSDKClient is the canonical SageMaker SDK fake for collector
// tests. Tests populate only the fields they care about; every other List/
// Describe call returns an empty output. Set pipelineErr to simulate a
// retryable sub-listing failure.
type fullSageMakerSDKClient struct {
	notebooks      []sagemakertypes.NotebookInstanceSummary
	notebook       *sagemaker.DescribeNotebookInstanceOutput
	trainings      []sagemakertypes.TrainingJobSummary
	training       *sagemaker.DescribeTrainingJobOutput
	processings    []sagemakertypes.ProcessingJobSummary
	processing     *sagemaker.DescribeProcessingJobOutput
	transforms     []sagemakertypes.TransformJobSummary
	transform      *sagemaker.DescribeTransformJobOutput
	transformModel *sagemaker.DescribeModelOutput
	models         []sagemakertypes.ModelSummary
	model          *sagemaker.DescribeModelOutput
	endpoints      []sagemakertypes.EndpointSummary
	endpoint       *sagemaker.DescribeEndpointOutput
	endpointConfig *sagemaker.DescribeEndpointConfigOutput
	endpointModel  *sagemaker.DescribeModelOutput
	pipelines      []sagemakertypes.PipelineSummary
	pipeline       *sagemaker.DescribePipelineOutput
	pipelineErr    error
	domains        []sagemakertypes.DomainDetails
	domain         *sagemaker.DescribeDomainOutput
}

// All Describe* methods follow the same empty-output contract: when the
// matching configured field is nil we return a zero-valued non-nil output
// rather than nil. This matches what the real SDK returns for "no item" and
// keeps the collector free of brittle nil-pointer guards.

func (f *fullSageMakerSDKClient) ListNotebookInstances(ctx context.Context, params *sagemaker.ListNotebookInstancesInput, optFns ...func(*sagemaker.Options)) (*sagemaker.ListNotebookInstancesOutput, error) {
	return &sagemaker.ListNotebookInstancesOutput{NotebookInstances: f.notebooks}, nil
}
func (f *fullSageMakerSDKClient) DescribeNotebookInstance(ctx context.Context, params *sagemaker.DescribeNotebookInstanceInput, optFns ...func(*sagemaker.Options)) (*sagemaker.DescribeNotebookInstanceOutput, error) {
	if f.notebook != nil {
		return f.notebook, nil
	}
	return &sagemaker.DescribeNotebookInstanceOutput{}, nil
}
func (f *fullSageMakerSDKClient) ListTrainingJobs(ctx context.Context, params *sagemaker.ListTrainingJobsInput, optFns ...func(*sagemaker.Options)) (*sagemaker.ListTrainingJobsOutput, error) {
	return &sagemaker.ListTrainingJobsOutput{TrainingJobSummaries: f.trainings}, nil
}
func (f *fullSageMakerSDKClient) DescribeTrainingJob(ctx context.Context, params *sagemaker.DescribeTrainingJobInput, optFns ...func(*sagemaker.Options)) (*sagemaker.DescribeTrainingJobOutput, error) {
	if f.training != nil {
		return f.training, nil
	}
	return &sagemaker.DescribeTrainingJobOutput{}, nil
}
func (f *fullSageMakerSDKClient) ListProcessingJobs(ctx context.Context, params *sagemaker.ListProcessingJobsInput, optFns ...func(*sagemaker.Options)) (*sagemaker.ListProcessingJobsOutput, error) {
	return &sagemaker.ListProcessingJobsOutput{ProcessingJobSummaries: f.processings}, nil
}
func (f *fullSageMakerSDKClient) DescribeProcessingJob(ctx context.Context, params *sagemaker.DescribeProcessingJobInput, optFns ...func(*sagemaker.Options)) (*sagemaker.DescribeProcessingJobOutput, error) {
	if f.processing != nil {
		return f.processing, nil
	}
	return &sagemaker.DescribeProcessingJobOutput{}, nil
}
func (f *fullSageMakerSDKClient) ListTransformJobs(ctx context.Context, params *sagemaker.ListTransformJobsInput, optFns ...func(*sagemaker.Options)) (*sagemaker.ListTransformJobsOutput, error) {
	return &sagemaker.ListTransformJobsOutput{TransformJobSummaries: f.transforms}, nil
}
func (f *fullSageMakerSDKClient) DescribeTransformJob(ctx context.Context, params *sagemaker.DescribeTransformJobInput, optFns ...func(*sagemaker.Options)) (*sagemaker.DescribeTransformJobOutput, error) {
	if f.transform != nil {
		return f.transform, nil
	}
	return &sagemaker.DescribeTransformJobOutput{}, nil
}
func (f *fullSageMakerSDKClient) ListModels(ctx context.Context, params *sagemaker.ListModelsInput, optFns ...func(*sagemaker.Options)) (*sagemaker.ListModelsOutput, error) {
	return &sagemaker.ListModelsOutput{Models: f.models}, nil
}
func (f *fullSageMakerSDKClient) DescribeModel(ctx context.Context, params *sagemaker.DescribeModelInput, optFns ...func(*sagemaker.Options)) (*sagemaker.DescribeModelOutput, error) {
	name := awsv2.ToString(params.ModelName)
	if f.endpoint != nil && f.endpointModel != nil && name == awsv2.ToString(f.endpointModel.ModelName) {
		return f.endpointModel, nil
	}
	if f.transform != nil && f.transformModel != nil && name == awsv2.ToString(f.transformModel.ModelName) {
		return f.transformModel, nil
	}
	if f.model != nil {
		return f.model, nil
	}
	return &sagemaker.DescribeModelOutput{}, nil
}
func (f *fullSageMakerSDKClient) ListEndpoints(ctx context.Context, params *sagemaker.ListEndpointsInput, optFns ...func(*sagemaker.Options)) (*sagemaker.ListEndpointsOutput, error) {
	return &sagemaker.ListEndpointsOutput{Endpoints: f.endpoints}, nil
}
func (f *fullSageMakerSDKClient) DescribeEndpoint(ctx context.Context, params *sagemaker.DescribeEndpointInput, optFns ...func(*sagemaker.Options)) (*sagemaker.DescribeEndpointOutput, error) {
	if f.endpoint != nil {
		return f.endpoint, nil
	}
	return &sagemaker.DescribeEndpointOutput{}, nil
}
func (f *fullSageMakerSDKClient) DescribeEndpointConfig(ctx context.Context, params *sagemaker.DescribeEndpointConfigInput, optFns ...func(*sagemaker.Options)) (*sagemaker.DescribeEndpointConfigOutput, error) {
	if f.endpointConfig != nil {
		return f.endpointConfig, nil
	}
	return &sagemaker.DescribeEndpointConfigOutput{}, nil
}
func (f *fullSageMakerSDKClient) ListPipelines(ctx context.Context, params *sagemaker.ListPipelinesInput, optFns ...func(*sagemaker.Options)) (*sagemaker.ListPipelinesOutput, error) {
	if f.pipelineErr != nil {
		return nil, f.pipelineErr
	}
	return &sagemaker.ListPipelinesOutput{PipelineSummaries: f.pipelines}, nil
}
func (f *fullSageMakerSDKClient) DescribePipeline(ctx context.Context, params *sagemaker.DescribePipelineInput, optFns ...func(*sagemaker.Options)) (*sagemaker.DescribePipelineOutput, error) {
	if f.pipeline != nil {
		return f.pipeline, nil
	}
	return &sagemaker.DescribePipelineOutput{}, nil
}
func (f *fullSageMakerSDKClient) ListDomains(ctx context.Context, params *sagemaker.ListDomainsInput, optFns ...func(*sagemaker.Options)) (*sagemaker.ListDomainsOutput, error) {
	return &sagemaker.ListDomainsOutput{Domains: f.domains}, nil
}
func (f *fullSageMakerSDKClient) DescribeDomain(ctx context.Context, params *sagemaker.DescribeDomainInput, optFns ...func(*sagemaker.Options)) (*sagemaker.DescribeDomainOutput, error) {
	if f.domain != nil {
		return f.domain, nil
	}
	return &sagemaker.DescribeDomainOutput{}, nil
}

func TestSDKSageMakerWorkloadRoleEnumeratesEveryWorkloadType(t *testing.T) {
	region := "us-east-1"
	account := "123456789012"
	trainingARN := "arn:aws:sagemaker:us-east-1:123456789012:training-job/train"
	processingARN := "arn:aws:sagemaker:us-east-1:123456789012:processing-job/process"
	transformARN := "arn:aws:sagemaker:us-east-1:123456789012:transform-job/score"
	modelARN := "arn:aws:sagemaker:us-east-1:123456789012:model/payments"
	endpointARN := "arn:aws:sagemaker:us-east-1:123456789012:endpoint/payments"
	pipelineARN := "arn:aws:sagemaker:us-east-1:123456789012:pipeline/mlops"
	domainARN := "arn:aws:sagemaker:us-east-1:123456789012:domain/d-1"
	endpointModel := &sagemaker.DescribeModelOutput{
		ModelName:        awsv2.String("payments"),
		ModelArn:         awsv2.String(modelARN),
		ExecutionRoleArn: awsv2.String("arn:aws:iam::123456789012:role/model"),
	}
	client := &fullSageMakerSDKClient{
		trainings: []sagemakertypes.TrainingJobSummary{{TrainingJobName: awsv2.String("train")}},
		training: &sagemaker.DescribeTrainingJobOutput{
			TrainingJobArn:         awsv2.String(trainingARN),
			TrainingJobStatus:      sagemakertypes.TrainingJobStatusInProgress,
			RoleArn:                awsv2.String("arn:aws:iam::" + account + ":role/train"),
			AlgorithmSpecification: &sagemakertypes.AlgorithmSpecification{TrainingImage: awsv2.String(account + ".dkr.ecr." + region + ".amazonaws.com/train:1")},
			OutputDataConfig:       &sagemakertypes.OutputDataConfig{S3OutputPath: awsv2.String("s3://train/out/"), KmsKeyId: awsv2.String("arn:aws:kms:" + region + ":" + account + ":key/out")},
			ResourceConfig:         &sagemakertypes.ResourceConfig{VolumeKmsKeyId: awsv2.String("arn:aws:kms:" + region + ":" + account + ":key/vol")},
			InputDataConfig: []sagemakertypes.Channel{{
				DataSource: &sagemakertypes.DataSource{S3DataSource: &sagemakertypes.S3DataSource{S3Uri: awsv2.String("s3://train/in/")}},
			}},
			VpcConfig: &sagemakertypes.VpcConfig{},
		},
		processings: []sagemakertypes.ProcessingJobSummary{{ProcessingJobName: awsv2.String("process")}},
		processing: &sagemaker.DescribeProcessingJobOutput{
			ProcessingJobArn:    awsv2.String(processingARN),
			ProcessingJobStatus: sagemakertypes.ProcessingJobStatusInProgress,
			RoleArn:             awsv2.String("arn:aws:iam::" + account + ":role/process"),
			AppSpecification:    &sagemakertypes.AppSpecification{ImageUri: awsv2.String(account + ".dkr.ecr." + region + ".amazonaws.com/process:1")},
			ProcessingResources: &sagemakertypes.ProcessingResources{ClusterConfig: &sagemakertypes.ProcessingClusterConfig{VolumeKmsKeyId: awsv2.String("arn:aws:kms:" + region + ":" + account + ":key/proc-vol")}},
			ProcessingInputs:    []sagemakertypes.ProcessingInput{{S3Input: &sagemakertypes.ProcessingS3Input{S3Uri: awsv2.String("s3://process/in/")}}},
			ProcessingOutputConfig: &sagemakertypes.ProcessingOutputConfig{
				KmsKeyId: awsv2.String("arn:aws:kms:" + region + ":" + account + ":key/proc-out"),
				Outputs:  []sagemakertypes.ProcessingOutput{{S3Output: &sagemakertypes.ProcessingS3Output{S3Uri: awsv2.String("s3://process/out/")}}},
			},
			NetworkConfig: &sagemakertypes.NetworkConfig{VpcConfig: &sagemakertypes.VpcConfig{}},
		},
		transforms: []sagemakertypes.TransformJobSummary{{TransformJobName: awsv2.String("score")}},
		transform: &sagemaker.DescribeTransformJobOutput{
			TransformJobArn:    awsv2.String(transformARN),
			TransformJobStatus: sagemakertypes.TransformJobStatusInProgress,
			ModelName:          awsv2.String("score-model"),
			TransformInput:     &sagemakertypes.TransformInput{DataSource: &sagemakertypes.TransformDataSource{S3DataSource: &sagemakertypes.TransformS3DataSource{S3Uri: awsv2.String("s3://score/in/")}}},
			TransformOutput:    &sagemakertypes.TransformOutput{S3OutputPath: awsv2.String("s3://score/out/"), KmsKeyId: awsv2.String("arn:aws:kms:" + region + ":" + account + ":key/score-out")},
			TransformResources: &sagemakertypes.TransformResources{VolumeKmsKeyId: awsv2.String("arn:aws:kms:" + region + ":" + account + ":key/score-vol")},
		},
		transformModel: &sagemaker.DescribeModelOutput{
			ModelName:        awsv2.String("score-model"),
			ModelArn:         awsv2.String("arn:aws:sagemaker:us-east-1:123456789012:model/score-model"),
			ExecutionRoleArn: awsv2.String("arn:aws:iam::" + account + ":role/score-model"),
		},
		models: []sagemakertypes.ModelSummary{{ModelName: awsv2.String("payments")}},
		model: &sagemaker.DescribeModelOutput{
			ModelName:        awsv2.String("payments"),
			ModelArn:         awsv2.String(modelARN),
			ExecutionRoleArn: awsv2.String("arn:aws:iam::" + account + ":role/model"),
			PrimaryContainer: &sagemakertypes.ContainerDefinition{
				Image:        awsv2.String(account + ".dkr.ecr." + region + ".amazonaws.com/model:1"),
				ModelDataUrl: awsv2.String("s3://models/payments/"),
			},
			Containers: []sagemakertypes.ContainerDefinition{{
				Image:        awsv2.String(account + ".dkr.ecr." + region + ".amazonaws.com/secondary:1"),
				ModelDataUrl: awsv2.String("s3://models/payments-secondary/"),
			}},
			VpcConfig: &sagemakertypes.VpcConfig{},
		},
		endpoints: []sagemakertypes.EndpointSummary{{EndpointName: awsv2.String("payments")}},
		endpoint: &sagemaker.DescribeEndpointOutput{
			EndpointArn:        awsv2.String(endpointARN),
			EndpointStatus:     sagemakertypes.EndpointStatusInService,
			EndpointConfigName: awsv2.String("payments-config"),
		},
		endpointConfig: &sagemaker.DescribeEndpointConfigOutput{
			KmsKeyId: awsv2.String("arn:aws:kms:" + region + ":" + account + ":key/endpoint"),
			ProductionVariants: []sagemakertypes.ProductionVariant{
				{ModelName: awsv2.String("payments")},
				// duplicate variant pointing at the same model — must dedupe
				{ModelName: awsv2.String("payments")},
				// empty name — must be skipped
				{ModelName: awsv2.String("")},
			},
		},
		endpointModel: endpointModel,
		pipelines:     []sagemakertypes.PipelineSummary{{PipelineName: awsv2.String("mlops"), PipelineArn: awsv2.String(pipelineARN)}},
		pipeline: &sagemaker.DescribePipelineOutput{
			PipelineName:   awsv2.String("mlops"),
			PipelineArn:    awsv2.String(pipelineARN),
			PipelineStatus: sagemakertypes.PipelineStatusActive,
			RoleArn:        awsv2.String("arn:aws:iam::" + account + ":role/pipeline"),
		},
		domains: []sagemakertypes.DomainDetails{{DomainId: awsv2.String("d-1"), DomainName: awsv2.String("payments")}},
		domain: &sagemaker.DescribeDomainOutput{
			DomainArn:           awsv2.String(domainARN),
			Status:              sagemakertypes.DomainStatusInService,
			KmsKeyId:            awsv2.String("arn:aws:kms:" + region + ":" + account + ":key/domain"),
			DefaultUserSettings: &sagemakertypes.UserSettings{ExecutionRole: awsv2.String("arn:aws:iam::" + account + ":role/domain")},
		},
	}
	api := &SDKSageMakerWorkloadRoleAPI{client: client, accountID: account, region: region}
	page, err := api.ListServiceRoles(context.Background(), "", 100)
	if err != nil {
		t.Fatalf("list service roles: %v", err)
	}
	// Should produce one record per non-notebook workload type, including a
	// single endpoint record (deduped) and a single transform record (its
	// role comes from the model describe call).
	want := map[string]bool{
		"sagemaker_training_execution_role":        false,
		"sagemaker_processing_execution_role":      false,
		"sagemaker_batch_transform_execution_role": false,
		"sagemaker_model_execution_role":           false,
		"sagemaker_endpoint_execution_role":        false,
		"sagemaker_pipeline_execution_role":        false,
		"sagemaker_domain_execution_role":          false,
	}
	endpointCount := 0
	for _, record := range page.Records {
		if record.RoleKind == "sagemaker_endpoint_execution_role" {
			endpointCount++
		}
		if _, ok := want[record.RoleKind]; ok {
			want[record.RoleKind] = true
		}
	}
	for kind, seen := range want {
		if !seen {
			t.Fatalf("missing %q record, got %+v", kind, page.Records)
		}
	}
	if endpointCount != 1 {
		t.Fatalf("expected one endpoint record after dedupe, got %d", endpointCount)
	}
}

func TestSageMakerDedupeStringSliceTrimsAndSorts(t *testing.T) {
	got := dedupeStringSlice([]string{"b", "  a  ", "a", "", "b"})
	if strings.Join(got, ",") != "a,b" {
		t.Fatalf("expected sorted unique slice, got %v", got)
	}
}

func TestSageMakerWorkloadRoleConfidenceBranches(t *testing.T) {
	cases := []struct {
		record SageMakerWorkloadRole
		want   float64
	}{
		{SageMakerWorkloadRole{CoverageStatus: "unsupported"}, 0.4},
		{SageMakerWorkloadRole{Disabled: true}, 0.72},
		{SageMakerWorkloadRole{}, 0.86},
		{SageMakerWorkloadRole{ResourceStatus: "InService"}, 0.93},
	}
	for i, tc := range cases {
		if got := sageMakerWorkloadRoleConfidence(tc.record); got != tc.want {
			t.Fatalf("case %d: confidence = %v, want %v", i, got, tc.want)
		}
	}
}

func TestSageMakerDefaultRoleKindFallsBackToWorkloadType(t *testing.T) {
	got := sageMakerDefaultRoleKind(SageMakerWorkloadRole{
		ServiceCollectorRecord: awscontract.ServiceCollectorRecord{WorkloadType: "sagemaker_training_job"},
	})
	if got != "sagemaker_training_execution_role" {
		t.Fatalf("expected workload-type fallback, got %q", got)
	}
}

func TestSDKSageMakerWorkloadRoleRequiresClient(t *testing.T) {
	api := &SDKSageMakerWorkloadRoleAPI{}
	if _, err := api.ListServiceRoles(context.Background(), "", 100); err == nil {
		t.Fatalf("expected error when client missing")
	}
}

func TestSageMakerNormalizerProjectsAssetIntoBundle(t *testing.T) {
	collectedAt := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	roleARN := "arn:aws:iam::123456789012:role/sagemaker-payments-training"
	workloadARN := "arn:aws:sagemaker:us-east-1:123456789012:training-job/payments-train"
	record := SageMakerWorkloadRole{
		ServiceCollectorRecord: awscontract.ServiceCollectorRecord{
			AccountID:    "123456789012",
			Region:       "us-east-1",
			Service:      "sagemaker",
			WorkloadID:   workloadARN,
			WorkloadName: "payments-train",
			WorkloadType: "sagemaker_training_job",
			RoleARN:      roleARN,
		},
		RoleKind:       "sagemaker_training_execution_role",
		WorkloadARN:    workloadARN,
		ResourceType:   "sagemaker_training_job",
		ResourceStatus: "InProgress",
		ImageURIs:      []string{"123456789012.dkr.ecr.us-east-1.amazonaws.com/train:1"},
		S3References:   []string{"s3://train/in/"},
		KMSKeyARNs:     []string{"arn:aws:kms:us-east-1:123456789012:key/train"},
		Active:         true,
	}
	payload, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	asset := providers.RawAsset{
		Kind:      rawKindSageMakerWorkloadRole,
		SourceID:  "sagemaker|" + workloadARN + "|sagemaker_training_execution_role|" + roleARN,
		Payload:   payload,
		Collected: collectedAt.Format(time.RFC3339Nano),
	}
	bundle := providers.NormalizedBundle{}
	identitySeen := map[string]struct{}{}
	workloadSeen := map[string]struct{}{}
	resourceSeen := map[string]struct{}{}
	if err := normalizeSageMakerWorkloadRoleAsset(asset, 0, &bundle, identitySeen, workloadSeen, resourceSeen); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if len(bundle.Identities) != 1 || bundle.Identities[0].ARN != roleARN {
		t.Fatalf("expected identity from role arn, got %+v", bundle.Identities)
	}
	if len(bundle.Workloads) != 1 || bundle.Workloads[0].Type != "sagemaker_training_job_execution_role" {
		t.Fatalf("expected suffixed workload type, got %+v", bundle.Workloads)
	}
	if len(bundle.Resources) != 1 {
		t.Fatalf("expected one resource, got %+v", bundle.Resources)
	}
	res := bundle.Resources[0]
	if res.Type != domain.ResourceTypeSageMakerTraining {
		t.Fatalf("expected training resource type, got %q", res.Type)
	}
	images, _ := res.Metadata["image_uris"].([]string)
	if len(images) != 1 || images[0] == "" {
		t.Fatalf("expected image uris carried into resource metadata, got %v", images)
	}

	// Second asset with the same workload but a different role ARN should
	// merge into the existing resource's role list, not create a duplicate
	// resource entry.
	second := record
	second.RoleARN = "arn:aws:iam::123456789012:role/sagemaker-payments-other"
	second.RoleKind = "sagemaker_training_execution_role"
	secondPayload, err := json.Marshal(second)
	if err != nil {
		t.Fatalf("marshal second: %v", err)
	}
	secondAsset := asset
	secondAsset.Payload = secondPayload
	if err := normalizeSageMakerWorkloadRoleAsset(secondAsset, 1, &bundle, identitySeen, workloadSeen, resourceSeen); err != nil {
		t.Fatalf("normalize second: %v", err)
	}
	if len(bundle.Resources) != 1 {
		t.Fatalf("expected resource merged, got %d", len(bundle.Resources))
	}
	roles, _ := bundle.Resources[0].Metadata["roles"].([]map[string]any)
	if len(roles) != 2 {
		t.Fatalf("expected two role entries on resource metadata, got %d (%+v)", len(roles), roles)
	}
}

func TestSageMakerResourceIDClassifiesEveryType(t *testing.T) {
	cases := []struct {
		workloadType string
		want         string
	}{
		{"sagemaker_notebook_instance", "aws:resource:sagemaker-notebook:"},
		{"sagemaker_training_job", "aws:resource:sagemaker-training-job:"},
		{"sagemaker_processing_job", "aws:resource:sagemaker-processing-job:"},
		{"sagemaker_transform_job", "aws:resource:sagemaker-transform-job:"},
		{"sagemaker_model", "aws:resource:sagemaker-model:"},
		{"sagemaker_endpoint", "aws:resource:sagemaker-endpoint:"},
		{"sagemaker_pipeline", "aws:resource:sagemaker-pipeline:"},
		{"sagemaker_domain", "aws:resource:sagemaker-domain:"},
		{"sagemaker_workload", "aws:resource:sagemaker-workload:"},
	}
	for _, tc := range cases {
		got := sageMakerResourceID(SageMakerWorkloadRole{
			ResourceType: tc.workloadType,
			WorkloadARN:  "arn:aws:sagemaker:us-east-1:123456789012:" + tc.workloadType,
		})
		if !strings.HasPrefix(got, tc.want) {
			t.Fatalf("workload %q resource id = %q, want prefix %q", tc.workloadType, got, tc.want)
		}
	}
}

func TestIsSageMakerWorkloadRoleFixtureDiscriminatesByARN(t *testing.T) {
	// A CodePipeline-style record whose PipelineARN is *not* a SageMaker ARN
	// must not be misclassified.
	codePipelineRecord := SageMakerWorkloadRole{PipelineARN: "arn:aws:codepipeline:us-east-1:123456789012:pipeline/myapp"}
	if isSageMakerWorkloadRoleFixture(codePipelineRecord) {
		t.Fatalf("CodePipeline pipeline ARN should not be classified as SageMaker")
	}
	// A SageMaker pipeline ARN should be classified.
	sageRecord := SageMakerWorkloadRole{PipelineARN: "arn:aws:sagemaker:us-east-1:123456789012:pipeline/mlops"}
	if !isSageMakerWorkloadRoleFixture(sageRecord) {
		t.Fatalf("SageMaker pipeline ARN should be classified")
	}
}

func TestSageMakerWorkloadRoleSourceIDDistinguishesEndpointModels(t *testing.T) {
	endpointARN := "arn:aws:sagemaker:us-east-1:123456789012:endpoint/payments"
	roleARN := "arn:aws:iam::123456789012:role/shared-execution"
	baseline := SageMakerWorkloadRole{
		ServiceCollectorRecord: awscontract.ServiceCollectorRecord{
			Service:      "sagemaker",
			WorkloadType: "sagemaker_endpoint",
			RoleARN:      roleARN,
		},
		WorkloadARN:  endpointARN,
		ResourceType: "sagemaker_endpoint",
		RoleKind:     "sagemaker_endpoint_execution_role",
	}
	variantA := baseline
	variantA.ModelARN = "arn:aws:sagemaker:us-east-1:123456789012:model/payments-a"
	variantB := baseline
	variantB.ModelARN = "arn:aws:sagemaker:us-east-1:123456789012:model/payments-b"
	if sageMakerWorkloadRoleSourceID(variantA) == sageMakerWorkloadRoleSourceID(variantB) {
		t.Fatalf("endpoint records for different backing models must produce distinct source IDs")
	}

	// Non-endpoint records continue to ignore ModelARN so older callers
	// keep their stable source IDs.
	nonEndpoint := SageMakerWorkloadRole{
		ServiceCollectorRecord: awscontract.ServiceCollectorRecord{
			Service:      "sagemaker",
			WorkloadType: "sagemaker_training_job",
			RoleARN:      roleARN,
		},
		WorkloadARN: "arn:aws:sagemaker:us-east-1:123456789012:training-job/train",
		RoleKind:    "sagemaker_training_execution_role",
		ModelARN:    "arn:aws:sagemaker:us-east-1:123456789012:model/different",
	}
	nonEndpointTwin := nonEndpoint
	nonEndpointTwin.ModelARN = "arn:aws:sagemaker:us-east-1:123456789012:model/another"
	if sageMakerWorkloadRoleSourceID(nonEndpoint) != sageMakerWorkloadRoleSourceID(nonEndpointTwin) {
		t.Fatalf("non-endpoint records must keep deterministic source ids regardless of ModelARN")
	}
}

func TestSageMakerNormalizerMergesAdditionalEndpointModelEvidence(t *testing.T) {
	collectedAt := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	roleARN := "arn:aws:iam::123456789012:role/shared-execution"
	endpointARN := "arn:aws:sagemaker:us-east-1:123456789012:endpoint/payments"
	modelA := "arn:aws:sagemaker:us-east-1:123456789012:model/payments-a"
	modelB := "arn:aws:sagemaker:us-east-1:123456789012:model/payments-b"
	baseline := SageMakerWorkloadRole{
		ServiceCollectorRecord: awscontract.ServiceCollectorRecord{
			AccountID:    "123456789012",
			Region:       "us-east-1",
			Service:      "sagemaker",
			WorkloadID:   endpointARN,
			WorkloadName: "payments",
			WorkloadType: "sagemaker_endpoint",
			RoleARN:      roleARN,
		},
		RoleKind:       "sagemaker_endpoint_execution_role",
		WorkloadARN:    endpointARN,
		ResourceType:   "sagemaker_endpoint",
		ResourceStatus: "InService",
		Active:         true,
	}
	first := baseline
	first.ModelARN = modelA
	first.ImageURIs = []string{"123456789012.dkr.ecr.us-east-1.amazonaws.com/payments-a:1"}
	first.S3References = []string{"s3://payments-a/"}
	first.KMSKeyARNs = []string{"arn:aws:kms:us-east-1:123456789012:key/payments-a"}
	second := baseline
	second.ModelARN = modelB
	second.ImageURIs = []string{"123456789012.dkr.ecr.us-east-1.amazonaws.com/payments-b:1"}
	second.S3References = []string{"s3://payments-b/"}
	second.KMSKeyARNs = []string{"arn:aws:kms:us-east-1:123456789012:key/payments-b"}

	bundle := providers.NormalizedBundle{}
	identitySeen := map[string]struct{}{}
	workloadSeen := map[string]struct{}{}
	resourceSeen := map[string]struct{}{}
	for i, record := range []SageMakerWorkloadRole{first, second} {
		payload, err := json.Marshal(record)
		if err != nil {
			t.Fatalf("marshal %d: %v", i, err)
		}
		asset := providers.RawAsset{
			Kind:      rawKindSageMakerWorkloadRole,
			SourceID:  sageMakerWorkloadRoleSourceID(record),
			Payload:   payload,
			Collected: collectedAt.Format(time.RFC3339Nano),
		}
		if err := normalizeSageMakerWorkloadRoleAsset(asset, i, &bundle, identitySeen, workloadSeen, resourceSeen); err != nil {
			t.Fatalf("normalize %d: %v", i, err)
		}
	}
	if len(bundle.Resources) != 1 {
		t.Fatalf("expected one endpoint resource, got %d", len(bundle.Resources))
	}
	meta := bundle.Resources[0].Metadata
	models, _ := meta["model_arns"].([]string)
	if len(models) != 2 || models[0] != modelA || models[1] != modelB {
		t.Fatalf("expected both backing models on the endpoint resource, got %v", models)
	}
	images, _ := meta["image_uris"].([]string)
	if len(images) != 2 {
		t.Fatalf("expected both backing model image uris, got %v", images)
	}
	s3refs, _ := meta["s3_references"].([]string)
	if len(s3refs) != 2 {
		t.Fatalf("expected both backing model s3 references, got %v", s3refs)
	}
	kms, _ := meta["kms_key_arns"].([]string)
	if len(kms) != 2 {
		t.Fatalf("expected both backing model kms key arns, got %v", kms)
	}
	roles, _ := meta["roles"].([]map[string]any)
	if len(roles) != 1 {
		t.Fatalf("expected one role entry when both models share the execution role, got %d", len(roles))
	}
}

func TestSageMakerNormalizerEmitsWorkloadPerEndpointModelRole(t *testing.T) {
	collectedAt := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	endpointARN := "arn:aws:sagemaker:us-east-1:123456789012:endpoint/payments"
	modelA := "arn:aws:sagemaker:us-east-1:123456789012:model/payments-a"
	modelB := "arn:aws:sagemaker:us-east-1:123456789012:model/payments-b"
	baseline := SageMakerWorkloadRole{
		ServiceCollectorRecord: awscontract.ServiceCollectorRecord{
			AccountID:    "123456789012",
			Region:       "us-east-1",
			Service:      "sagemaker",
			WorkloadID:   endpointARN,
			WorkloadName: "payments",
			WorkloadType: "sagemaker_endpoint",
		},
		RoleKind:       "sagemaker_endpoint_execution_role",
		WorkloadARN:    endpointARN,
		ResourceType:   "sagemaker_endpoint",
		ResourceStatus: "InService",
		Active:         true,
	}
	first := baseline
	first.ModelARN = modelA
	first.RoleARN = "arn:aws:iam::123456789012:role/model-a"
	second := baseline
	second.ModelARN = modelB
	second.RoleARN = "arn:aws:iam::123456789012:role/model-b"

	bundle := providers.NormalizedBundle{}
	identitySeen := map[string]struct{}{}
	workloadSeen := map[string]struct{}{}
	resourceSeen := map[string]struct{}{}
	for i, record := range []SageMakerWorkloadRole{first, second} {
		payload, err := json.Marshal(record)
		if err != nil {
			t.Fatalf("marshal %d: %v", i, err)
		}
		asset := providers.RawAsset{
			Kind:      rawKindSageMakerWorkloadRole,
			SourceID:  sageMakerWorkloadRoleSourceID(record),
			Payload:   payload,
			Collected: collectedAt.Format(time.RFC3339Nano),
		}
		if err := normalizeSageMakerWorkloadRoleAsset(asset, i, &bundle, identitySeen, workloadSeen, resourceSeen); err != nil {
			t.Fatalf("normalize %d: %v", i, err)
		}
	}
	if len(bundle.Identities) != 2 {
		t.Fatalf("expected an identity per execution role, got %d", len(bundle.Identities))
	}
	if len(bundle.Workloads) != 2 {
		t.Fatalf("expected a workload entry per backing model role, got %d", len(bundle.Workloads))
	}
	seenRefs := map[string]struct{}{}
	for _, workload := range bundle.Workloads {
		if workload.Type != "sagemaker_endpoint_execution_role" {
			t.Fatalf("expected endpoint execution role workload type, got %q", workload.Type)
		}
		seenRefs[workload.RawRef] = struct{}{}
	}
	if len(seenRefs) != 2 {
		t.Fatalf("expected distinct RawRef (identity) on each workload, got %v", seenRefs)
	}
}

func TestSDKSageMakerTransformJobPullsModelEvidence(t *testing.T) {
	region := "us-east-1"
	account := "123456789012"
	transformARN := "arn:aws:sagemaker:us-east-1:123456789012:transform-job/score"
	modelARN := "arn:aws:sagemaker:us-east-1:123456789012:model/score-model"
	client := &fullSageMakerSDKClient{
		transforms: []sagemakertypes.TransformJobSummary{{TransformJobName: awsv2.String("score")}},
		transform: &sagemaker.DescribeTransformJobOutput{
			TransformJobArn:    awsv2.String(transformARN),
			TransformJobStatus: sagemakertypes.TransformJobStatusInProgress,
			ModelName:          awsv2.String("score-model"),
			TransformInput:     &sagemakertypes.TransformInput{DataSource: &sagemakertypes.TransformDataSource{S3DataSource: &sagemakertypes.TransformS3DataSource{S3Uri: awsv2.String("s3://score/in/")}}},
			TransformOutput:    &sagemakertypes.TransformOutput{S3OutputPath: awsv2.String("s3://score/out/"), KmsKeyId: awsv2.String("arn:aws:kms:" + region + ":" + account + ":key/score-out")},
			TransformResources: &sagemakertypes.TransformResources{VolumeKmsKeyId: awsv2.String("arn:aws:kms:" + region + ":" + account + ":key/score-vol")},
		},
		transformModel: &sagemaker.DescribeModelOutput{
			ModelName:        awsv2.String("score-model"),
			ModelArn:         awsv2.String(modelARN),
			ExecutionRoleArn: awsv2.String("arn:aws:iam::" + account + ":role/score-model"),
			PrimaryContainer: &sagemakertypes.ContainerDefinition{
				Image:        awsv2.String(account + ".dkr.ecr." + region + ".amazonaws.com/score-model:1"),
				ModelDataUrl: awsv2.String("s3://score-models/score-model/"),
			},
			VpcConfig: &sagemakertypes.VpcConfig{},
		},
	}
	api := &SDKSageMakerWorkloadRoleAPI{client: client, accountID: account, region: region}
	records, _, err := api.listTransformJobs(context.Background(), 100)
	if err != nil {
		t.Fatalf("list transform jobs: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected one transform record, got %d", len(records))
	}
	record := records[0]
	if record.ModelARN != modelARN {
		t.Fatalf("expected model ARN copied from DescribeModel, got %q", record.ModelARN)
	}
	if record.NetworkMode != "vpc" {
		t.Fatalf("expected vpc network mode inherited from model vpc config, got %q", record.NetworkMode)
	}
	hasImage := false
	for _, image := range record.ImageURIs {
		if image == account+".dkr.ecr."+region+".amazonaws.com/score-model:1" {
			hasImage = true
		}
	}
	if !hasImage {
		t.Fatalf("expected model container image URI, got %v", record.ImageURIs)
	}
	hasModelArtifact := false
	for _, ref := range record.S3References {
		if ref == "s3://score-models/score-model/" {
			hasModelArtifact = true
		}
	}
	if !hasModelArtifact {
		t.Fatalf("expected model artifact S3 prefix, got %v", record.S3References)
	}
}

func TestIsActiveSageMakerStatus(t *testing.T) {
	cases := map[string]bool{
		"InService":    true,
		"InProgress":   true,
		"Active":       true,
		"RUNNING":      true,
		"Running":      true,
		"Completed":    false,
		"Failed":       false,
		"Stopping":     false,
		"Stopped":      false,
		"Deleting":     false,
		"Updating":     false,
		"OutOfService": false,
		"":             false,
	}
	for status, want := range cases {
		if got := isActiveSageMakerStatus(status); got != want {
			t.Fatalf("status %q: got Active=%v, want Active=%v", status, got, want)
		}
	}
}

func TestSDKSageMakerEndpointCopiesModelEvidence(t *testing.T) {
	region := "us-east-1"
	account := "123456789012"
	endpointARN := "arn:aws:sagemaker:us-east-1:123456789012:endpoint/payments"
	client := &fullSageMakerSDKClient{
		endpoints: []sagemakertypes.EndpointSummary{{EndpointName: awsv2.String("payments")}},
		endpoint: &sagemaker.DescribeEndpointOutput{
			EndpointArn:        awsv2.String(endpointARN),
			EndpointStatus:     sagemakertypes.EndpointStatusInService,
			EndpointConfigName: awsv2.String("payments-config"),
		},
		endpointConfig: &sagemaker.DescribeEndpointConfigOutput{
			ProductionVariants: []sagemakertypes.ProductionVariant{{ModelName: awsv2.String("payments")}},
		},
		endpointModel: &sagemaker.DescribeModelOutput{
			ModelName:        awsv2.String("payments"),
			ModelArn:         awsv2.String("arn:aws:sagemaker:us-east-1:123456789012:model/payments"),
			ExecutionRoleArn: awsv2.String("arn:aws:iam::" + account + ":role/payments-model"),
			PrimaryContainer: &sagemakertypes.ContainerDefinition{
				Image:        awsv2.String(account + ".dkr.ecr." + region + ".amazonaws.com/payments-model:1"),
				ModelDataUrl: awsv2.String("s3://payments-models/payments/"),
			},
			VpcConfig: &sagemakertypes.VpcConfig{},
		},
	}
	api := &SDKSageMakerWorkloadRoleAPI{client: client, accountID: account, region: region}
	records, _, err := api.listEndpoints(context.Background(), 100)
	if err != nil {
		t.Fatalf("list endpoints: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected one endpoint record, got %d", len(records))
	}
	record := records[0]
	if record.NetworkMode != "vpc" {
		t.Fatalf("expected vpc network mode from model vpc config, got %q", record.NetworkMode)
	}
	hasImage := false
	for _, image := range record.ImageURIs {
		if image == account+".dkr.ecr."+region+".amazonaws.com/payments-model:1" {
			hasImage = true
		}
	}
	if !hasImage {
		t.Fatalf("expected endpoint model image URI, got %v", record.ImageURIs)
	}
	hasArtifact := false
	for _, ref := range record.S3References {
		if ref == "s3://payments-models/payments/" {
			hasArtifact = true
		}
	}
	if !hasArtifact {
		t.Fatalf("expected endpoint model artifact S3 prefix, got %v", record.S3References)
	}
}

func TestSDKSageMakerCompletedJobIsNotActive(t *testing.T) {
	api := &SDKSageMakerWorkloadRoleAPI{accountID: "123456789012", region: "us-east-1"}
	record := api.recordForRole(
		"sagemaker_training_job",
		"completed-job",
		"arn:aws:sagemaker:us-east-1:123456789012:training-job/completed-job",
		"Completed",
		"arn:aws:iam::123456789012:role/training",
		"sagemaker_training_execution_role",
		sageMakerRecordOptions{},
		nil,
	)
	if record.Active {
		t.Fatalf("expected a Completed training job to be inactive, got Active=true")
	}
}

func TestSDKSageMakerPropagatesContextCancellation(t *testing.T) {
	client := &fullSageMakerSDKClient{
		notebooks: []sagemakertypes.NotebookInstanceSummary{{
			NotebookInstanceName: awsv2.String("payments-eval"),
		}},
	}
	// Wrap the SDK client so DescribeNotebookInstance returns context.Canceled.
	cancelClient := &cancelDescribeNotebookClient{SageMakerSDKClient: client}
	api := &SDKSageMakerWorkloadRoleAPI{client: cancelClient, accountID: "123456789012", region: "us-east-1"}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := api.ListServiceRoles(ctx, "", 100)
	if err == nil {
		t.Fatalf("expected canceled context to propagate from describe call, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

type cancelDescribeNotebookClient struct {
	SageMakerSDKClient
}

func (c *cancelDescribeNotebookClient) DescribeNotebookInstance(ctx context.Context, params *sagemaker.DescribeNotebookInstanceInput, optFns ...func(*sagemaker.Options)) (*sagemaker.DescribeNotebookInstanceOutput, error) {
	// Honour the context so the test fails if the collector ever stops
	// threading the caller's context through the describe call. Returning
	// context.Canceled unconditionally would let a broken implementation
	// (e.g. one that swapped in context.Background) pass.
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &sagemaker.DescribeNotebookInstanceOutput{}, nil
}

func TestSDKSageMakerModelStatusIsNotForcedActive(t *testing.T) {
	region := "us-east-1"
	account := "123456789012"
	client := &fullSageMakerSDKClient{
		models: []sagemakertypes.ModelSummary{{ModelName: awsv2.String("payments")}},
		model: &sagemaker.DescribeModelOutput{
			ModelName:        awsv2.String("payments"),
			ModelArn:         awsv2.String("arn:aws:sagemaker:" + region + ":" + account + ":model/payments"),
			ExecutionRoleArn: awsv2.String("arn:aws:iam::" + account + ":role/model"),
		},
	}
	api := &SDKSageMakerWorkloadRoleAPI{client: client, accountID: account, region: region}
	records, _, err := api.listModels(context.Background(), 100)
	if err != nil {
		t.Fatalf("list models: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected one model record, got %d", len(records))
	}
	if records[0].Active {
		t.Fatalf("expected model record to not be force-active since DescribeModel has no status, got Active=true")
	}
}

func TestSageMakerResourceTypeFallsBackToWorkloadType(t *testing.T) {
	cases := map[string]domain.ResourceType{
		"sagemaker_notebook_instance": domain.ResourceTypeSageMakerNotebook,
		"sagemaker_training_job":      domain.ResourceTypeSageMakerTraining,
		"sagemaker_processing_job":    domain.ResourceTypeSageMakerProcessing,
		"sagemaker_transform_job":     domain.ResourceTypeSageMakerTransform,
		"sagemaker_model":             domain.ResourceTypeSageMakerModel,
		"sagemaker_endpoint":          domain.ResourceTypeSageMakerEndpoint,
		"sagemaker_pipeline":          domain.ResourceTypeSageMakerPipeline,
		"sagemaker_domain":            domain.ResourceTypeSageMakerDomain,
	}
	for workloadType, want := range cases {
		got := sageMakerResourceType(SageMakerWorkloadRole{
			ServiceCollectorRecord: awscontract.ServiceCollectorRecord{WorkloadType: workloadType},
		})
		if got != want {
			t.Fatalf("workload-type fallback %q: got %q, want %q", workloadType, got, want)
		}
	}
}

func TestSageMakerCollectorReturnsPartialAssetsOnMaxPagesExceeded(t *testing.T) {
	collectedAt := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	roleARN := "arn:aws:iam::123456789012:role/sagemaker-payments-training"
	workloadARN := "arn:aws:sagemaker:us-east-1:123456789012:training-job/payments-train-2026"
	// Two pages: first returns a record (so an asset exists), then both pages
	// keep advancing NextToken so the collector hits the max-pages guard.
	record := SageMakerWorkloadRole{
		ServiceCollectorRecord: awscontract.ServiceCollectorRecord{
			AccountID:    "123456789012",
			Region:       "us-east-1",
			Service:      "sagemaker",
			WorkloadID:   workloadARN,
			WorkloadName: "payments-train-2026",
			WorkloadType: "sagemaker_training_job",
			RoleARN:      roleARN,
		},
		RoleKind:    "sagemaker_training_execution_role",
		WorkloadARN: workloadARN,
	}
	api := &fakeSageMakerWorkloadRoleAPI{pages: []SageMakerWorkloadRolePage{
		{Records: []SageMakerWorkloadRole{record}, NextToken: "page-2"},
		{Records: []SageMakerWorkloadRole{record}, NextToken: "page-3"},
		{Records: []SageMakerWorkloadRole{record}, NextToken: "page-4"},
	}}
	collector := NewSageMakerWorkloadRoleCollector(api,
		WithSageMakerWorkloadRoleMaxPages(2),
		WithSageMakerWorkloadRoleClock(func() time.Time { return collectedAt }),
	)
	assets, diagnostics, err := collector.CollectWithDiagnostics(context.Background(), AWSCollectorScope{
		TenantID:    "tenant-a",
		WorkspaceID: "workspace-a",
		ProjectID:   "project-a",
		ConnectorID: "aws-prod",
		ScanID:      "scan-1",
	})
	if err == nil {
		t.Fatalf("expected max-pages error, got nil")
	}
	if len(assets) == 0 {
		t.Fatalf("expected partial assets returned with the overflow error, got none")
	}
	foundOverflowDiag := false
	for _, diag := range diagnostics {
		if diag.Code == "sagemaker_workload_role_page_limit_exceeded" {
			foundOverflowDiag = true
		}
	}
	if !foundOverflowDiag {
		t.Fatalf("expected page-limit diagnostic among returned diagnostics, got %+v", diagnostics)
	}
}

func TestSageMakerResourceTypeIsCaseInsensitive(t *testing.T) {
	for _, raw := range []string{"sagemaker_endpoint", "SAGEMAKER_ENDPOINT", "SageMaker_Endpoint", "  sagemaker_endpoint  "} {
		got := sageMakerResourceType(SageMakerWorkloadRole{
			ServiceCollectorRecord: awscontract.ServiceCollectorRecord{WorkloadType: raw},
		})
		if got != domain.ResourceTypeSageMakerEndpoint {
			t.Fatalf("workload_type %q should classify as endpoint regardless of case, got %q", raw, got)
		}
	}
}

func TestIsSageMakerARNHonorsServiceSegment(t *testing.T) {
	// Genuine SageMaker ARN — must match.
	if !isSageMakerARN("arn:aws:sagemaker:us-east-1:123456789012:endpoint/payments") {
		t.Fatalf("expected real SageMaker ARN to match")
	}
	// Tag value or unrelated resource path that mentions ":sagemaker:" — must
	// not false-positive.
	if isSageMakerARN("arn:aws:s3:::audit-bucket/path:sagemaker:notes/object") {
		t.Fatalf("unrelated ARN containing :sagemaker: in the resource path must not match")
	}
	if isSageMakerARN("arn:aws:codepipeline:us-east-1:123456789012:pipeline/myapp") {
		t.Fatalf("CodePipeline ARN must not match")
	}
	// Empty / malformed inputs return false.
	if isSageMakerARN("") || isSageMakerARN("not-an-arn") {
		t.Fatalf("empty/malformed input must not match")
	}
}

func TestSageMakerCollectorIsSafeForConcurrentCollect(t *testing.T) {
	collectedAt := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	roleARN := "arn:aws:iam::123456789012:role/sagemaker-payments-training"
	workloadARN := "arn:aws:sagemaker:us-east-1:123456789012:training-job/payments-train"
	build := func() *fakeSageMakerWorkloadRoleAPI {
		return &fakeSageMakerWorkloadRoleAPI{pages: []SageMakerWorkloadRolePage{{
			Records: []SageMakerWorkloadRole{{
				ServiceCollectorRecord: awscontract.ServiceCollectorRecord{
					AccountID: "123456789012", Region: "us-east-1", Service: "sagemaker",
					WorkloadID: workloadARN, WorkloadName: "payments-train",
					WorkloadType: "sagemaker_training_job", RoleARN: roleARN,
				},
				RoleKind: "sagemaker_training_execution_role", WorkloadARN: workloadARN,
			}},
			Diagnostics: []providers.SourceError{{
				Collector: sageMakerWorkloadRoleCollectorName,
				Code:      "sagemaker_pipelines_failed",
				Message:   "concurrent pipeline diagnostic",
				Retryable: true,
			}},
		}}}
	}
	// Two collectors sharing nothing but the same definition pattern, run
	// concurrently. Diagnostics from one call must not bleed into the other.
	collectorA := NewSageMakerWorkloadRoleCollector(build(), WithSageMakerWorkloadRoleClock(func() time.Time { return collectedAt }))
	collectorB := NewSageMakerWorkloadRoleCollector(build(), WithSageMakerWorkloadRoleClock(func() time.Time { return collectedAt }))
	scope := AWSCollectorScope{TenantID: "tenant-a", WorkspaceID: "workspace-a", ProjectID: "project-a", ConnectorID: "aws-prod", ScanID: "scan-1"}
	type result struct {
		diagnostics []providers.SourceError
		err         error
	}
	done := make(chan result, 2)
	for _, collector := range []*SageMakerWorkloadRoleCollector{collectorA, collectorB} {
		go func(c *SageMakerWorkloadRoleCollector) {
			_, diags, err := c.CollectWithDiagnostics(context.Background(), scope)
			done <- result{diags, err}
		}(collector)
	}
	for i := 0; i < 2; i++ {
		res := <-done
		if res.err != nil {
			t.Fatalf("concurrent collect failed: %v", res.err)
		}
		if len(res.diagnostics) != 1 || res.diagnostics[0].Code != "sagemaker_pipelines_failed" {
			t.Fatalf("expected exactly one diagnostic per collector, got %+v", res.diagnostics)
		}
	}
}

func TestFixtureClassifierResolvesSageMakerBeforeManagedCompute(t *testing.T) {
	// A SageMaker fixture record carries a SageMaker workload ARN under
	// ResourceARN. ManagedComputeRole's matcher would also claim a record
	// with a non-empty ResourceARN, so the classifier must check SageMaker
	// first. Without that ordering the fixture would be misrouted into the
	// managed-compute raw asset kind and never normalized.
	record := SageMakerWorkloadRole{
		ServiceCollectorRecord: awscontract.ServiceCollectorRecord{
			AccountID:    "123456789012",
			Region:       "us-east-1",
			Service:      "sagemaker",
			WorkloadID:   "arn:aws:sagemaker:us-east-1:123456789012:endpoint/payments",
			WorkloadName: "payments",
			WorkloadType: "sagemaker_endpoint",
			RoleARN:      "arn:aws:iam::123456789012:role/sagemaker-payments-model",
		},
		RoleKind:    "sagemaker_endpoint_execution_role",
		WorkloadARN: "arn:aws:sagemaker:us-east-1:123456789012:endpoint/payments",
		ResourceARN: "arn:aws:sagemaker:us-east-1:123456789012:endpoint/payments",
	}
	payload, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	kind, sourceID := fixtureAssetKindAndSourceID(payload)
	if kind != rawKindSageMakerWorkloadRole {
		t.Fatalf("expected SageMaker classification, got %q", kind)
	}
	if sourceID == "" {
		t.Fatalf("expected a non-empty source ID for the classified SageMaker fixture")
	}
}

func TestSDKSageMakerEndpointCollectsShadowProductionVariants(t *testing.T) {
	region := "us-east-1"
	account := "123456789012"
	endpointARN := "arn:aws:sagemaker:us-east-1:123456789012:endpoint/payments"
	primaryModel := "arn:aws:sagemaker:us-east-1:123456789012:model/payments-primary"
	shadowModel := "arn:aws:sagemaker:us-east-1:123456789012:model/payments-shadow"
	primaryDescribe := &sagemaker.DescribeModelOutput{
		ModelName:        awsv2.String("payments-primary"),
		ModelArn:         awsv2.String(primaryModel),
		ExecutionRoleArn: awsv2.String("arn:aws:iam::" + account + ":role/payments-primary"),
	}
	shadowDescribe := &sagemaker.DescribeModelOutput{
		ModelName:        awsv2.String("payments-shadow"),
		ModelArn:         awsv2.String(shadowModel),
		ExecutionRoleArn: awsv2.String("arn:aws:iam::" + account + ":role/payments-shadow"),
	}
	client := &shadowEndpointSDKClient{
		fullSageMakerSDKClient: fullSageMakerSDKClient{
			endpoints: []sagemakertypes.EndpointSummary{{EndpointName: awsv2.String("payments")}},
			endpoint: &sagemaker.DescribeEndpointOutput{
				EndpointArn:        awsv2.String(endpointARN),
				EndpointStatus:     sagemakertypes.EndpointStatusInService,
				EndpointConfigName: awsv2.String("payments-config"),
			},
			endpointConfig: &sagemaker.DescribeEndpointConfigOutput{
				ProductionVariants: []sagemakertypes.ProductionVariant{
					{ModelName: awsv2.String("payments-primary")},
				},
				ShadowProductionVariants: []sagemakertypes.ProductionVariant{
					{ModelName: awsv2.String("payments-shadow")},
					// Duplicate shadow variant must dedupe with the same
					// model-name guard as the primary variants.
					{ModelName: awsv2.String("payments-shadow")},
					{ModelName: awsv2.String("")},
				},
			},
		},
		primaryDescribe: primaryDescribe,
		shadowDescribe:  shadowDescribe,
	}
	api := &SDKSageMakerWorkloadRoleAPI{client: client, accountID: account, region: region}
	records, _, err := api.listEndpoints(context.Background(), 100)
	if err != nil {
		t.Fatalf("list endpoints: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("expected one record per backing model (primary + shadow), got %d", len(records))
	}
	hasPrimary, hasShadow := false, false
	for _, record := range records {
		switch record.ModelARN {
		case primaryModel:
			hasPrimary = true
		case shadowModel:
			hasShadow = true
		}
	}
	if !hasPrimary || !hasShadow {
		t.Fatalf("expected both ProductionVariants and ShadowProductionVariants models to surface, got %+v", records)
	}
}

// shadowEndpointSDKClient routes DescribeModel back to the configured
// primary/shadow describe outputs based on the model name, so the endpoint
// test can assert both variants surface.
type shadowEndpointSDKClient struct {
	fullSageMakerSDKClient
	primaryDescribe *sagemaker.DescribeModelOutput
	shadowDescribe  *sagemaker.DescribeModelOutput
}

func (s *shadowEndpointSDKClient) DescribeModel(ctx context.Context, params *sagemaker.DescribeModelInput, optFns ...func(*sagemaker.Options)) (*sagemaker.DescribeModelOutput, error) {
	name := awsv2.ToString(params.ModelName)
	if s.primaryDescribe != nil && name == awsv2.ToString(s.primaryDescribe.ModelName) {
		return s.primaryDescribe, nil
	}
	if s.shadowDescribe != nil && name == awsv2.ToString(s.shadowDescribe.ModelName) {
		return s.shadowDescribe, nil
	}
	return &sagemaker.DescribeModelOutput{}, nil
}
