package aws

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sagemaker"
	sagemakertypes "github.com/aws/aws-sdk-go-v2/service/sagemaker/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/identrail/identrail/internal/providers"
	"github.com/identrail/identrail/internal/providers/awscontract"
	"github.com/identrail/identrail/internal/textutil"
)

// SageMakerSDKClient is the narrow seam between the SDK SageMaker client and
// the workload role collector. It deliberately exposes only the metadata-only
// describe/list calls the collector needs so notebook, training payload, and
// model object reads remain impossible from this surface.
type SageMakerSDKClient interface {
	ListNotebookInstances(ctx context.Context, params *sagemaker.ListNotebookInstancesInput, optFns ...func(*sagemaker.Options)) (*sagemaker.ListNotebookInstancesOutput, error)
	DescribeNotebookInstance(ctx context.Context, params *sagemaker.DescribeNotebookInstanceInput, optFns ...func(*sagemaker.Options)) (*sagemaker.DescribeNotebookInstanceOutput, error)
	ListTrainingJobs(ctx context.Context, params *sagemaker.ListTrainingJobsInput, optFns ...func(*sagemaker.Options)) (*sagemaker.ListTrainingJobsOutput, error)
	DescribeTrainingJob(ctx context.Context, params *sagemaker.DescribeTrainingJobInput, optFns ...func(*sagemaker.Options)) (*sagemaker.DescribeTrainingJobOutput, error)
	ListProcessingJobs(ctx context.Context, params *sagemaker.ListProcessingJobsInput, optFns ...func(*sagemaker.Options)) (*sagemaker.ListProcessingJobsOutput, error)
	DescribeProcessingJob(ctx context.Context, params *sagemaker.DescribeProcessingJobInput, optFns ...func(*sagemaker.Options)) (*sagemaker.DescribeProcessingJobOutput, error)
	ListTransformJobs(ctx context.Context, params *sagemaker.ListTransformJobsInput, optFns ...func(*sagemaker.Options)) (*sagemaker.ListTransformJobsOutput, error)
	DescribeTransformJob(ctx context.Context, params *sagemaker.DescribeTransformJobInput, optFns ...func(*sagemaker.Options)) (*sagemaker.DescribeTransformJobOutput, error)
	ListModels(ctx context.Context, params *sagemaker.ListModelsInput, optFns ...func(*sagemaker.Options)) (*sagemaker.ListModelsOutput, error)
	DescribeModel(ctx context.Context, params *sagemaker.DescribeModelInput, optFns ...func(*sagemaker.Options)) (*sagemaker.DescribeModelOutput, error)
	ListEndpoints(ctx context.Context, params *sagemaker.ListEndpointsInput, optFns ...func(*sagemaker.Options)) (*sagemaker.ListEndpointsOutput, error)
	DescribeEndpoint(ctx context.Context, params *sagemaker.DescribeEndpointInput, optFns ...func(*sagemaker.Options)) (*sagemaker.DescribeEndpointOutput, error)
	DescribeEndpointConfig(ctx context.Context, params *sagemaker.DescribeEndpointConfigInput, optFns ...func(*sagemaker.Options)) (*sagemaker.DescribeEndpointConfigOutput, error)
	ListPipelines(ctx context.Context, params *sagemaker.ListPipelinesInput, optFns ...func(*sagemaker.Options)) (*sagemaker.ListPipelinesOutput, error)
	DescribePipeline(ctx context.Context, params *sagemaker.DescribePipelineInput, optFns ...func(*sagemaker.Options)) (*sagemaker.DescribePipelineOutput, error)
	ListDomains(ctx context.Context, params *sagemaker.ListDomainsInput, optFns ...func(*sagemaker.Options)) (*sagemaker.ListDomainsOutput, error)
	DescribeDomain(ctx context.Context, params *sagemaker.DescribeDomainInput, optFns ...func(*sagemaker.Options)) (*sagemaker.DescribeDomainOutput, error)
}

// SDKSageMakerWorkloadRoleAPI is the SDK-backed implementation of the
// SageMaker workload role API. It enumerates every supported workload type
// (notebooks, training, processing, transform, model, endpoint, pipeline,
// domain) and produces normalized role records without ever fetching notebook
// contents, training data payloads, or model artifacts.
type SDKSageMakerWorkloadRoleAPI struct {
	client    SageMakerSDKClient
	accountID string
	region    string
}

var _ SageMakerWorkloadRoleAPI = (*SDKSageMakerWorkloadRoleAPI)(nil)

// NewSDKSageMakerWorkloadRoleAPI constructs the SDK-backed API using ambient
// AWS credentials.
func NewSDKSageMakerWorkloadRoleAPI(region string, profile string, accountID string) (SageMakerWorkloadRoleAPI, error) {
	return NewSDKSageMakerWorkloadRoleAPIWithContext(context.Background(), region, profile, accountID)
}

// NewSDKSageMakerWorkloadRoleAPIWithContext constructs the SDK-backed API
// using the supplied context for AWS configuration loading.
func NewSDKSageMakerWorkloadRoleAPIWithContext(ctx context.Context, region string, profile string, accountID string) (SageMakerWorkloadRoleAPI, error) {
	cfg, err := loadSDKConfig(ctx, region, profile)
	if err != nil {
		return nil, err
	}
	resolved, err := sageMakerAccountID(ctx, cfg, accountID)
	if err != nil {
		return nil, err
	}
	resolvedRegion := firstNonEmptyAWSValue(strings.TrimSpace(region), strings.TrimSpace(cfg.Region))
	return NewSDKSageMakerWorkloadRoleAPIFromClient(sagemaker.NewFromConfig(cfg), resolved, resolvedRegion), nil
}

// NewSDKSageMakerWorkloadRoleAPIFromAssumeRole constructs the SDK-backed API
// after assuming the supplied connector role.
func NewSDKSageMakerWorkloadRoleAPIFromAssumeRole(ctx context.Context, region string, profile string, roleARN string, externalID string, sessionName string, accountID string) (SageMakerWorkloadRoleAPI, error) {
	cfg, err := loadSDKConfig(ctx, region, profile)
	if err != nil {
		return nil, err
	}
	trimmedRoleARN := strings.TrimSpace(roleARN)
	if trimmedRoleARN == "" {
		return nil, fmt.Errorf("aws connector role arn is required")
	}
	options := []func(*stscreds.AssumeRoleOptions){
		func(options *stscreds.AssumeRoleOptions) {
			options.RoleSessionName = textutil.FirstNonEmpty(strings.TrimSpace(sessionName), "identrail-recurring-scan")
		},
	}
	if trimmedExternalID := strings.TrimSpace(externalID); trimmedExternalID != "" {
		options = append(options, func(options *stscreds.AssumeRoleOptions) {
			options.ExternalID = &trimmedExternalID
		})
	}
	cfg.Credentials = awsv2.NewCredentialsCache(stscreds.NewAssumeRoleProvider(sts.NewFromConfig(cfg), trimmedRoleARN, options...))
	resolved, err := sageMakerAccountID(ctx, cfg, accountID)
	if err != nil {
		return nil, err
	}
	resolvedRegion := firstNonEmptyAWSValue(strings.TrimSpace(region), strings.TrimSpace(cfg.Region))
	return NewSDKSageMakerWorkloadRoleAPIFromClient(sagemaker.NewFromConfig(cfg), resolved, resolvedRegion), nil
}

// NewSDKSageMakerWorkloadRoleAPIFromClient is the seam tests use to inject a
// fake SageMakerSDKClient.
func NewSDKSageMakerWorkloadRoleAPIFromClient(client SageMakerSDKClient, accountID string, region string) SageMakerWorkloadRoleAPI {
	return &SDKSageMakerWorkloadRoleAPI{
		client:    client,
		accountID: strings.TrimSpace(accountID),
		region:    strings.TrimSpace(region),
	}
}

// ListServiceRoles enumerates every supported SageMaker workload type and
// returns normalized role records plus per-sub-call diagnostics. Sub-call
// failures degrade gracefully so one denied or throttled API never hides the
// evidence collected by the other sub-calls in the same scan.
func (a *SDKSageMakerWorkloadRoleAPI) ListServiceRoles(ctx context.Context, _ string, pageSize int32) (SageMakerWorkloadRolePage, error) {
	if a.client == nil {
		return SageMakerWorkloadRolePage{}, errors.New("sagemaker SDK client is required")
	}
	records := []SageMakerWorkloadRole{}
	diagnostics := []providers.SourceError{}

	type subListing struct {
		code string
		fn   func(context.Context, int32) ([]SageMakerWorkloadRole, []providers.SourceError, error)
	}
	listings := []subListing{
		{code: "notebooks", fn: a.listNotebookInstances},
		{code: "training_jobs", fn: a.listTrainingJobs},
		{code: "processing_jobs", fn: a.listProcessingJobs},
		{code: "transform_jobs", fn: a.listTransformJobs},
		{code: "models", fn: a.listModels},
		{code: "endpoints", fn: a.listEndpoints},
		{code: "pipelines", fn: a.listPipelines},
		{code: "domains", fn: a.listDomains},
	}
	for _, listing := range listings {
		next, issues, err := listing.fn(ctx, pageSize)
		if err != nil {
			if sageMakerShouldReturnError(err) {
				return SageMakerWorkloadRolePage{}, err
			}
			diagnostics = append(diagnostics, sageMakerDiagnostic(fmt.Sprintf("sagemaker_%s_failed", listing.code), listing.code, fmt.Sprintf("SageMaker %s could not be listed: %v", strings.ReplaceAll(listing.code, "_", " "), err), true))
		}
		records = append(records, next...)
		diagnostics = append(diagnostics, issues...)
	}
	sort.SliceStable(records, func(i, j int) bool {
		return sageMakerWorkloadRoleSourceID(records[i]) < sageMakerWorkloadRoleSourceID(records[j])
	})
	return SageMakerWorkloadRolePage{Records: records, Diagnostics: diagnostics}, nil
}

func (a *SDKSageMakerWorkloadRoleAPI) listNotebookInstances(ctx context.Context, pageSize int32) ([]SageMakerWorkloadRole, []providers.SourceError, error) {
	records := []SageMakerWorkloadRole{}
	diagnostics := []providers.SourceError{}
	token := ""
	for {
		output, err := a.client.ListNotebookInstances(ctx, &sagemaker.ListNotebookInstancesInput{
			MaxResults: awsv2.Int32(sageMakerSDKPageSize(pageSize, 100)),
			NextToken:  stringPtrOrNil(token),
		})
		if err != nil {
			return records, diagnostics, err
		}
		if output == nil {
			break
		}
		for _, summary := range output.NotebookInstances {
			name := strings.TrimSpace(awsv2.ToString(summary.NotebookInstanceName))
			arn := strings.TrimSpace(awsv2.ToString(summary.NotebookInstanceArn))
			if name == "" {
				diagnostics = append(diagnostics, sageMakerDiagnostic("sagemaker_notebook_name_missing", "listnotebookinstances", "SageMaker notebook summary did not include a name", false))
				continue
			}
			describe, err := a.client.DescribeNotebookInstance(ctx, &sagemaker.DescribeNotebookInstanceInput{NotebookInstanceName: awsv2.String(name)})
			if err != nil {
				if sageMakerShouldReturnError(err) {
					return records, diagnostics, err
				}
				diagnostics = append(diagnostics, sageMakerDiagnostic("sagemaker_notebook_describe_failed", firstNonEmptyAWSValue(arn, name), fmt.Sprintf("SageMaker notebook %q could not be described: %v", name, err), true))
				continue
			}
			if describe == nil {
				continue
			}
			arn = firstNonEmptyAWSValue(strings.TrimSpace(awsv2.ToString(describe.NotebookInstanceArn)), arn)
			status := string(describe.NotebookInstanceStatus)
			kms := []string{strings.TrimSpace(awsv2.ToString(describe.KmsKeyId))}
			records = append(records, a.recordForRole(
				"sagemaker_notebook_instance", name, arn, status,
				strings.TrimSpace(awsv2.ToString(describe.RoleArn)),
				"sagemaker_notebook_execution_role",
				sageMakerRecordOptions{KMSKeyARNs: kms},
				nil,
			))
		}
		token = strings.TrimSpace(awsv2.ToString(output.NextToken))
		if token == "" {
			break
		}
	}
	return records, diagnostics, nil
}

func (a *SDKSageMakerWorkloadRoleAPI) listTrainingJobs(ctx context.Context, pageSize int32) ([]SageMakerWorkloadRole, []providers.SourceError, error) {
	records := []SageMakerWorkloadRole{}
	diagnostics := []providers.SourceError{}
	token := ""
	for {
		output, err := a.client.ListTrainingJobs(ctx, &sagemaker.ListTrainingJobsInput{
			MaxResults: awsv2.Int32(sageMakerSDKPageSize(pageSize, 100)),
			NextToken:  stringPtrOrNil(token),
		})
		if err != nil {
			return records, diagnostics, err
		}
		if output == nil {
			break
		}
		for _, summary := range output.TrainingJobSummaries {
			name := strings.TrimSpace(awsv2.ToString(summary.TrainingJobName))
			if name == "" {
				diagnostics = append(diagnostics, sageMakerDiagnostic("sagemaker_training_job_name_missing", "listtrainingjobs", "SageMaker training job summary did not include a name", false))
				continue
			}
			describe, err := a.client.DescribeTrainingJob(ctx, &sagemaker.DescribeTrainingJobInput{TrainingJobName: awsv2.String(name)})
			if err != nil {
				if sageMakerShouldReturnError(err) {
					return records, diagnostics, err
				}
				diagnostics = append(diagnostics, sageMakerDiagnostic("sagemaker_training_job_describe_failed", name, fmt.Sprintf("SageMaker training job %q could not be described: %v", name, err), true))
				continue
			}
			if describe == nil {
				continue
			}
			arn := strings.TrimSpace(awsv2.ToString(describe.TrainingJobArn))
			status := string(describe.TrainingJobStatus)
			opts := sageMakerRecordOptions{}
			if describe.AlgorithmSpecification != nil {
				opts.ImageURIs = append(opts.ImageURIs, strings.TrimSpace(awsv2.ToString(describe.AlgorithmSpecification.TrainingImage)))
			}
			if describe.OutputDataConfig != nil {
				opts.S3References = append(opts.S3References, strings.TrimSpace(awsv2.ToString(describe.OutputDataConfig.S3OutputPath)))
				opts.KMSKeyARNs = append(opts.KMSKeyARNs, strings.TrimSpace(awsv2.ToString(describe.OutputDataConfig.KmsKeyId)))
			}
			if describe.ResourceConfig != nil {
				opts.KMSKeyARNs = append(opts.KMSKeyARNs, strings.TrimSpace(awsv2.ToString(describe.ResourceConfig.VolumeKmsKeyId)))
			}
			for _, channel := range describe.InputDataConfig {
				if channel.DataSource != nil && channel.DataSource.S3DataSource != nil {
					opts.S3References = append(opts.S3References, strings.TrimSpace(awsv2.ToString(channel.DataSource.S3DataSource.S3Uri)))
				}
			}
			if describe.VpcConfig != nil {
				opts.NetworkMode = "vpc"
			}
			records = append(records, a.recordForRole(
				"sagemaker_training_job", name, arn, status,
				strings.TrimSpace(awsv2.ToString(describe.RoleArn)),
				"sagemaker_training_execution_role",
				opts, nil,
			))
		}
		token = strings.TrimSpace(awsv2.ToString(output.NextToken))
		if token == "" {
			break
		}
	}
	return records, diagnostics, nil
}

func (a *SDKSageMakerWorkloadRoleAPI) listProcessingJobs(ctx context.Context, pageSize int32) ([]SageMakerWorkloadRole, []providers.SourceError, error) {
	records := []SageMakerWorkloadRole{}
	diagnostics := []providers.SourceError{}
	token := ""
	for {
		output, err := a.client.ListProcessingJobs(ctx, &sagemaker.ListProcessingJobsInput{
			MaxResults: awsv2.Int32(sageMakerSDKPageSize(pageSize, 100)),
			NextToken:  stringPtrOrNil(token),
		})
		if err != nil {
			return records, diagnostics, err
		}
		if output == nil {
			break
		}
		for _, summary := range output.ProcessingJobSummaries {
			name := strings.TrimSpace(awsv2.ToString(summary.ProcessingJobName))
			if name == "" {
				diagnostics = append(diagnostics, sageMakerDiagnostic("sagemaker_processing_job_name_missing", "listprocessingjobs", "SageMaker processing job summary did not include a name", false))
				continue
			}
			describe, err := a.client.DescribeProcessingJob(ctx, &sagemaker.DescribeProcessingJobInput{ProcessingJobName: awsv2.String(name)})
			if err != nil {
				if sageMakerShouldReturnError(err) {
					return records, diagnostics, err
				}
				diagnostics = append(diagnostics, sageMakerDiagnostic("sagemaker_processing_job_describe_failed", name, fmt.Sprintf("SageMaker processing job %q could not be described: %v", name, err), true))
				continue
			}
			if describe == nil {
				continue
			}
			arn := strings.TrimSpace(awsv2.ToString(describe.ProcessingJobArn))
			status := string(describe.ProcessingJobStatus)
			opts := sageMakerRecordOptions{}
			if describe.AppSpecification != nil {
				opts.ImageURIs = append(opts.ImageURIs, strings.TrimSpace(awsv2.ToString(describe.AppSpecification.ImageUri)))
			}
			if describe.ProcessingResources != nil && describe.ProcessingResources.ClusterConfig != nil {
				opts.KMSKeyARNs = append(opts.KMSKeyARNs, strings.TrimSpace(awsv2.ToString(describe.ProcessingResources.ClusterConfig.VolumeKmsKeyId)))
			}
			for _, input := range describe.ProcessingInputs {
				if input.S3Input != nil {
					opts.S3References = append(opts.S3References, strings.TrimSpace(awsv2.ToString(input.S3Input.S3Uri)))
				}
			}
			if describe.ProcessingOutputConfig != nil {
				opts.KMSKeyARNs = append(opts.KMSKeyARNs, strings.TrimSpace(awsv2.ToString(describe.ProcessingOutputConfig.KmsKeyId)))
				for _, output := range describe.ProcessingOutputConfig.Outputs {
					if output.S3Output != nil {
						opts.S3References = append(opts.S3References, strings.TrimSpace(awsv2.ToString(output.S3Output.S3Uri)))
					}
				}
			}
			if describe.NetworkConfig != nil && describe.NetworkConfig.VpcConfig != nil {
				opts.NetworkMode = "vpc"
			}
			records = append(records, a.recordForRole(
				"sagemaker_processing_job", name, arn, status,
				strings.TrimSpace(awsv2.ToString(describe.RoleArn)),
				"sagemaker_processing_execution_role",
				opts, nil,
			))
		}
		token = strings.TrimSpace(awsv2.ToString(output.NextToken))
		if token == "" {
			break
		}
	}
	return records, diagnostics, nil
}

func (a *SDKSageMakerWorkloadRoleAPI) listTransformJobs(ctx context.Context, pageSize int32) ([]SageMakerWorkloadRole, []providers.SourceError, error) {
	records := []SageMakerWorkloadRole{}
	diagnostics := []providers.SourceError{}
	token := ""
	for {
		output, err := a.client.ListTransformJobs(ctx, &sagemaker.ListTransformJobsInput{
			MaxResults: awsv2.Int32(sageMakerSDKPageSize(pageSize, 100)),
			NextToken:  stringPtrOrNil(token),
		})
		if err != nil {
			return records, diagnostics, err
		}
		if output == nil {
			break
		}
		for _, summary := range output.TransformJobSummaries {
			name := strings.TrimSpace(awsv2.ToString(summary.TransformJobName))
			if name == "" {
				diagnostics = append(diagnostics, sageMakerDiagnostic("sagemaker_transform_job_name_missing", "listtransformjobs", "SageMaker transform job summary did not include a name", false))
				continue
			}
			describe, err := a.client.DescribeTransformJob(ctx, &sagemaker.DescribeTransformJobInput{TransformJobName: awsv2.String(name)})
			if err != nil {
				if sageMakerShouldReturnError(err) {
					return records, diagnostics, err
				}
				diagnostics = append(diagnostics, sageMakerDiagnostic("sagemaker_transform_job_describe_failed", name, fmt.Sprintf("SageMaker transform job %q could not be described: %v", name, err), true))
				continue
			}
			if describe == nil {
				continue
			}
			arn := strings.TrimSpace(awsv2.ToString(describe.TransformJobArn))
			modelName := strings.TrimSpace(awsv2.ToString(describe.ModelName))
			opts := sageMakerRecordOptions{}
			roleARN := ""
			if modelName != "" {
				if modelDescribe, modelErr := a.client.DescribeModel(ctx, &sagemaker.DescribeModelInput{ModelName: awsv2.String(modelName)}); modelErr == nil && modelDescribe != nil {
					roleARN = strings.TrimSpace(awsv2.ToString(modelDescribe.ExecutionRoleArn))
					// DescribeTransformJob does not expose the model ARN,
					// container image, or model artifact S3 URI directly, so
					// fold the related model evidence onto the transform job
					// record before emitting it. This keeps the execution
					// role's S3/ECR reach visible for blast-radius reasoning
					// on real transform jobs (the fixture/API already shows
					// this context for parity).
					opts.ModelARN = strings.TrimSpace(awsv2.ToString(modelDescribe.ModelArn))
					if modelDescribe.PrimaryContainer != nil {
						opts.ImageURIs = append(opts.ImageURIs, strings.TrimSpace(awsv2.ToString(modelDescribe.PrimaryContainer.Image)))
						opts.S3References = append(opts.S3References, strings.TrimSpace(awsv2.ToString(modelDescribe.PrimaryContainer.ModelDataUrl)))
					}
					for _, container := range modelDescribe.Containers {
						opts.ImageURIs = append(opts.ImageURIs, strings.TrimSpace(awsv2.ToString(container.Image)))
						opts.S3References = append(opts.S3References, strings.TrimSpace(awsv2.ToString(container.ModelDataUrl)))
					}
					if modelDescribe.VpcConfig != nil {
						opts.NetworkMode = "vpc"
					}
				} else if modelErr != nil {
					if sageMakerShouldReturnError(modelErr) {
						return records, diagnostics, modelErr
					}
					diagnostics = append(diagnostics, sageMakerDiagnostic("sagemaker_transform_model_describe_failed", modelName, fmt.Sprintf("SageMaker transform job %q model %q could not be described: %v", name, modelName, modelErr), true))
				}
			}
			if describe.TransformInput != nil && describe.TransformInput.DataSource != nil && describe.TransformInput.DataSource.S3DataSource != nil {
				opts.S3References = append(opts.S3References, strings.TrimSpace(awsv2.ToString(describe.TransformInput.DataSource.S3DataSource.S3Uri)))
			}
			if describe.TransformOutput != nil {
				opts.S3References = append(opts.S3References, strings.TrimSpace(awsv2.ToString(describe.TransformOutput.S3OutputPath)))
				opts.KMSKeyARNs = append(opts.KMSKeyARNs, strings.TrimSpace(awsv2.ToString(describe.TransformOutput.KmsKeyId)))
			}
			if describe.TransformResources != nil {
				opts.KMSKeyARNs = append(opts.KMSKeyARNs, strings.TrimSpace(awsv2.ToString(describe.TransformResources.VolumeKmsKeyId)))
			}
			records = append(records, a.recordForRole(
				"sagemaker_transform_job", name, arn, string(describe.TransformJobStatus),
				roleARN,
				"sagemaker_batch_transform_execution_role",
				opts, nil,
			))
		}
		token = strings.TrimSpace(awsv2.ToString(output.NextToken))
		if token == "" {
			break
		}
	}
	return records, diagnostics, nil
}

func (a *SDKSageMakerWorkloadRoleAPI) listModels(ctx context.Context, pageSize int32) ([]SageMakerWorkloadRole, []providers.SourceError, error) {
	records := []SageMakerWorkloadRole{}
	diagnostics := []providers.SourceError{}
	token := ""
	for {
		output, err := a.client.ListModels(ctx, &sagemaker.ListModelsInput{
			MaxResults: awsv2.Int32(sageMakerSDKPageSize(pageSize, 100)),
			NextToken:  stringPtrOrNil(token),
		})
		if err != nil {
			return records, diagnostics, err
		}
		if output == nil {
			break
		}
		for _, summary := range output.Models {
			name := strings.TrimSpace(awsv2.ToString(summary.ModelName))
			if name == "" {
				diagnostics = append(diagnostics, sageMakerDiagnostic("sagemaker_model_name_missing", "listmodels", "SageMaker model summary did not include a name", false))
				continue
			}
			describe, err := a.client.DescribeModel(ctx, &sagemaker.DescribeModelInput{ModelName: awsv2.String(name)})
			if err != nil {
				if sageMakerShouldReturnError(err) {
					return records, diagnostics, err
				}
				diagnostics = append(diagnostics, sageMakerDiagnostic("sagemaker_model_describe_failed", name, fmt.Sprintf("SageMaker model %q could not be described: %v", name, err), true))
				continue
			}
			if describe == nil {
				continue
			}
			arn := strings.TrimSpace(awsv2.ToString(describe.ModelArn))
			opts := sageMakerRecordOptions{ModelARN: arn}
			if describe.PrimaryContainer != nil {
				opts.ImageURIs = append(opts.ImageURIs, strings.TrimSpace(awsv2.ToString(describe.PrimaryContainer.Image)))
				opts.S3References = append(opts.S3References, strings.TrimSpace(awsv2.ToString(describe.PrimaryContainer.ModelDataUrl)))
			}
			for _, container := range describe.Containers {
				opts.ImageURIs = append(opts.ImageURIs, strings.TrimSpace(awsv2.ToString(container.Image)))
				opts.S3References = append(opts.S3References, strings.TrimSpace(awsv2.ToString(container.ModelDataUrl)))
			}
			if describe.VpcConfig != nil {
				opts.NetworkMode = "vpc"
			}
			// SageMaker models are registry entries — DescribeModel does not
			// return a lifecycle status, so we emit the record without a
			// status string instead of hardcoding "InService" (which would
			// otherwise always mark every model as active).
			records = append(records, a.recordForRole(
				"sagemaker_model", name, arn, "",
				strings.TrimSpace(awsv2.ToString(describe.ExecutionRoleArn)),
				"sagemaker_model_execution_role",
				opts, nil,
			))
		}
		token = strings.TrimSpace(awsv2.ToString(output.NextToken))
		if token == "" {
			break
		}
	}
	return records, diagnostics, nil
}

func (a *SDKSageMakerWorkloadRoleAPI) listEndpoints(ctx context.Context, pageSize int32) ([]SageMakerWorkloadRole, []providers.SourceError, error) {
	records := []SageMakerWorkloadRole{}
	diagnostics := []providers.SourceError{}
	token := ""
	for {
		output, err := a.client.ListEndpoints(ctx, &sagemaker.ListEndpointsInput{
			MaxResults: awsv2.Int32(sageMakerSDKPageSize(pageSize, 100)),
			NextToken:  stringPtrOrNil(token),
		})
		if err != nil {
			return records, diagnostics, err
		}
		if output == nil {
			break
		}
		for _, summary := range output.Endpoints {
			name := strings.TrimSpace(awsv2.ToString(summary.EndpointName))
			if name == "" {
				diagnostics = append(diagnostics, sageMakerDiagnostic("sagemaker_endpoint_name_missing", "listendpoints", "SageMaker endpoint summary did not include a name", false))
				continue
			}
			describe, err := a.client.DescribeEndpoint(ctx, &sagemaker.DescribeEndpointInput{EndpointName: awsv2.String(name)})
			if err != nil {
				if sageMakerShouldReturnError(err) {
					return records, diagnostics, err
				}
				diagnostics = append(diagnostics, sageMakerDiagnostic("sagemaker_endpoint_describe_failed", name, fmt.Sprintf("SageMaker endpoint %q could not be described: %v", name, err), true))
				continue
			}
			if describe == nil {
				continue
			}
			arn := strings.TrimSpace(awsv2.ToString(describe.EndpointArn))
			configName := strings.TrimSpace(awsv2.ToString(describe.EndpointConfigName))
			opts := sageMakerRecordOptions{EndpointConfig: configName}
			var modelNames []string
			seenModel := map[string]struct{}{}
			if configName != "" {
				configDescribe, configErr := a.client.DescribeEndpointConfig(ctx, &sagemaker.DescribeEndpointConfigInput{EndpointConfigName: awsv2.String(configName)})
				if configErr != nil {
					if sageMakerShouldReturnError(configErr) {
						return records, diagnostics, configErr
					}
					diagnostics = append(diagnostics, sageMakerDiagnostic("sagemaker_endpoint_config_describe_failed", configName, fmt.Sprintf("SageMaker endpoint config %q could not be described: %v", configName, configErr), true))
				} else if configDescribe != nil {
					opts.KMSKeyARNs = append(opts.KMSKeyARNs, strings.TrimSpace(awsv2.ToString(configDescribe.KmsKeyId)))
					// SageMaker endpoints can route a fraction of inference
					// traffic to ShadowProductionVariants in addition to the
					// primary ProductionVariants (used for A/B testing and
					// shadow testing of new model versions). Both variant
					// lists can reference distinct models with distinct
					// execution roles, so the collector must enumerate both
					// or it would silently undercount the endpoint's
					// role/S3/ECR/KMS reach.
					collectVariantModel := func(variant sagemakertypes.ProductionVariant) {
						modelName := strings.TrimSpace(awsv2.ToString(variant.ModelName))
						if modelName == "" {
							return
						}
						if _, exists := seenModel[modelName]; exists {
							return
						}
						seenModel[modelName] = struct{}{}
						modelNames = append(modelNames, modelName)
					}
					for _, variant := range configDescribe.ProductionVariants {
						collectVariantModel(variant)
					}
					for _, variant := range configDescribe.ShadowProductionVariants {
						collectVariantModel(variant)
					}
				}
			}
			// Endpoints carry no role of their own; they inherit the model
			// execution role. Emit one record per unique backing model so the
			// graph shows the endpoint→model→role relationship without
			// duplicate DescribeModel calls or duplicate records when an
			// endpoint config has multiple variants pointing at the same model.
			for _, modelName := range modelNames {
				modelDescribe, modelErr := a.client.DescribeModel(ctx, &sagemaker.DescribeModelInput{ModelName: awsv2.String(modelName)})
				if modelErr != nil {
					if sageMakerShouldReturnError(modelErr) {
						return records, diagnostics, modelErr
					}
					diagnostics = append(diagnostics, sageMakerDiagnostic("sagemaker_endpoint_model_describe_failed", modelName, fmt.Sprintf("SageMaker endpoint %q model %q could not be described: %v", name, modelName, modelErr), true))
					continue
				}
				if modelDescribe == nil {
					continue
				}
				modelOpts := opts
				modelOpts.ModelARN = strings.TrimSpace(awsv2.ToString(modelDescribe.ModelArn))
				// DescribeEndpoint/DescribeEndpointConfig do not expose the
				// model's container image or model artifact S3 URI, so fold
				// the model describe payload onto the endpoint record before
				// emitting it. This keeps the endpoint execution role's
				// S3/ECR reach visible for blast-radius reasoning.
				if modelDescribe.PrimaryContainer != nil {
					modelOpts.ImageURIs = append(modelOpts.ImageURIs, strings.TrimSpace(awsv2.ToString(modelDescribe.PrimaryContainer.Image)))
					modelOpts.S3References = append(modelOpts.S3References, strings.TrimSpace(awsv2.ToString(modelDescribe.PrimaryContainer.ModelDataUrl)))
				}
				for _, container := range modelDescribe.Containers {
					modelOpts.ImageURIs = append(modelOpts.ImageURIs, strings.TrimSpace(awsv2.ToString(container.Image)))
					modelOpts.S3References = append(modelOpts.S3References, strings.TrimSpace(awsv2.ToString(container.ModelDataUrl)))
				}
				if modelDescribe.VpcConfig != nil {
					modelOpts.NetworkMode = "vpc"
				}
				records = append(records, a.recordForRole(
					"sagemaker_endpoint", name, arn, string(describe.EndpointStatus),
					strings.TrimSpace(awsv2.ToString(modelDescribe.ExecutionRoleArn)),
					"sagemaker_endpoint_execution_role",
					modelOpts, nil,
				))
			}
		}
		token = strings.TrimSpace(awsv2.ToString(output.NextToken))
		if token == "" {
			break
		}
	}
	return records, diagnostics, nil
}

func (a *SDKSageMakerWorkloadRoleAPI) listPipelines(ctx context.Context, pageSize int32) ([]SageMakerWorkloadRole, []providers.SourceError, error) {
	records := []SageMakerWorkloadRole{}
	diagnostics := []providers.SourceError{}
	token := ""
	for {
		output, err := a.client.ListPipelines(ctx, &sagemaker.ListPipelinesInput{
			MaxResults: awsv2.Int32(sageMakerSDKPageSize(pageSize, 100)),
			NextToken:  stringPtrOrNil(token),
		})
		if err != nil {
			return records, diagnostics, err
		}
		if output == nil {
			break
		}
		for _, summary := range output.PipelineSummaries {
			name := strings.TrimSpace(awsv2.ToString(summary.PipelineName))
			arn := strings.TrimSpace(awsv2.ToString(summary.PipelineArn))
			if name == "" {
				diagnostics = append(diagnostics, sageMakerDiagnostic("sagemaker_pipeline_name_missing", "listpipelines", "SageMaker pipeline summary did not include a name", false))
				continue
			}
			describe, err := a.client.DescribePipeline(ctx, &sagemaker.DescribePipelineInput{PipelineName: awsv2.String(name)})
			if err != nil {
				if sageMakerShouldReturnError(err) {
					return records, diagnostics, err
				}
				diagnostics = append(diagnostics, sageMakerDiagnostic("sagemaker_pipeline_describe_failed", firstNonEmptyAWSValue(arn, name), fmt.Sprintf("SageMaker pipeline %q could not be described: %v", name, err), true))
				continue
			}
			if describe == nil {
				continue
			}
			arn = firstNonEmptyAWSValue(strings.TrimSpace(awsv2.ToString(describe.PipelineArn)), arn)
			records = append(records, a.recordForRole(
				"sagemaker_pipeline", name, arn, string(describe.PipelineStatus),
				strings.TrimSpace(awsv2.ToString(describe.RoleArn)),
				"sagemaker_pipeline_execution_role",
				sageMakerRecordOptions{PipelineARN: arn}, nil,
			))
		}
		token = strings.TrimSpace(awsv2.ToString(output.NextToken))
		if token == "" {
			break
		}
	}
	return records, diagnostics, nil
}

func (a *SDKSageMakerWorkloadRoleAPI) listDomains(ctx context.Context, pageSize int32) ([]SageMakerWorkloadRole, []providers.SourceError, error) {
	records := []SageMakerWorkloadRole{}
	diagnostics := []providers.SourceError{}
	token := ""
	for {
		output, err := a.client.ListDomains(ctx, &sagemaker.ListDomainsInput{
			MaxResults: awsv2.Int32(sageMakerSDKPageSize(pageSize, 100)),
			NextToken:  stringPtrOrNil(token),
		})
		if err != nil {
			return records, diagnostics, err
		}
		if output == nil {
			break
		}
		for _, summary := range output.Domains {
			domainID := strings.TrimSpace(awsv2.ToString(summary.DomainId))
			name := strings.TrimSpace(awsv2.ToString(summary.DomainName))
			if domainID == "" {
				diagnostics = append(diagnostics, sageMakerDiagnostic("sagemaker_domain_id_missing", "listdomains", "SageMaker domain summary did not include a domain id", false))
				continue
			}
			describe, err := a.client.DescribeDomain(ctx, &sagemaker.DescribeDomainInput{DomainId: awsv2.String(domainID)})
			if err != nil {
				if sageMakerShouldReturnError(err) {
					return records, diagnostics, err
				}
				diagnostics = append(diagnostics, sageMakerDiagnostic("sagemaker_domain_describe_failed", domainID, fmt.Sprintf("SageMaker domain %q could not be described: %v", domainID, err), true))
				continue
			}
			if describe == nil {
				continue
			}
			arn := strings.TrimSpace(awsv2.ToString(describe.DomainArn))
			opts := sageMakerRecordOptions{DomainID: domainID, DomainARN: arn}
			opts.KMSKeyARNs = append(opts.KMSKeyARNs, strings.TrimSpace(awsv2.ToString(describe.KmsKeyId)))
			roleARN := ""
			if describe.DefaultUserSettings != nil {
				roleARN = strings.TrimSpace(awsv2.ToString(describe.DefaultUserSettings.ExecutionRole))
			}
			records = append(records, a.recordForRole(
				"sagemaker_domain", firstNonEmptyAWSValue(name, domainID), arn, string(describe.Status),
				roleARN,
				"sagemaker_domain_execution_role",
				opts, nil,
			))
		}
		token = strings.TrimSpace(awsv2.ToString(output.NextToken))
		if token == "" {
			break
		}
	}
	return records, diagnostics, nil
}

type sageMakerRecordOptions struct {
	DomainID       string
	DomainARN      string
	UserProfile    string
	SpaceName      string
	PipelineARN    string
	ModelARN       string
	EndpointConfig string
	NetworkMode    string
	ImageURIs      []string
	S3References   []string
	KMSKeyARNs     []string
}

func (a *SDKSageMakerWorkloadRoleAPI) recordForRole(workloadType string, workloadName string, workloadARN string, status string, roleARN string, roleKind string, opts sageMakerRecordOptions, tags map[string]string) SageMakerWorkloadRole {
	roleARN = a.iamRoleARNForSageMaker(roleARN, workloadARN)
	record := SageMakerWorkloadRole{
		ServiceCollectorRecord: awscontract.ServiceCollectorRecord{
			AccountID:     a.accountID,
			Region:        a.region,
			Service:       sageMakerServiceName,
			WorkloadID:    firstNonEmptyAWSValue(workloadARN, workloadName),
			WorkloadType:  workloadType,
			WorkloadName:  strings.TrimSpace(workloadName),
			RoleARN:       roleARN,
			Source:        "sagemaker_metadata",
			EvidenceRef:   firstNonEmptyAWSValue(workloadARN, workloadName),
			Confidence:    0.93,
			CollectorName: sageMakerWorkloadRoleCollectorName,
		},
		RoleName:       roleNameFromARN(roleARN),
		RoleKind:       roleKind,
		RoleAccountID:  roleAccountIDFromARN(roleARN),
		WorkloadARN:    strings.TrimSpace(workloadARN),
		ResourceARN:    strings.TrimSpace(workloadARN),
		ResourceType:   workloadType,
		ResourceStatus: strings.TrimSpace(status),
		DomainID:       strings.TrimSpace(opts.DomainID),
		DomainARN:      strings.TrimSpace(opts.DomainARN),
		UserProfile:    strings.TrimSpace(opts.UserProfile),
		SpaceName:      strings.TrimSpace(opts.SpaceName),
		PipelineARN:    strings.TrimSpace(opts.PipelineARN),
		ModelARN:       strings.TrimSpace(opts.ModelARN),
		EndpointConfig: strings.TrimSpace(opts.EndpointConfig),
		NetworkMode:    strings.TrimSpace(opts.NetworkMode),
		ImageURIs:      dedupeStringSlice(opts.ImageURIs),
		S3References:   dedupeStringSlice(opts.S3References),
		KMSKeyARNs:     dedupeStringSlice(opts.KMSKeyARNs),
		CoverageStatus: "covered",
		Active:         isActiveSageMakerStatus(status),
		Disabled:       strings.EqualFold(status, "Disabled") || strings.EqualFold(status, "Stopped"),
		Tags:           copyTags(tags),
	}
	record.Confidence = sageMakerWorkloadRoleConfidence(record)
	return record
}

func (a *SDKSageMakerWorkloadRoleAPI) iamRoleARNForSageMaker(value string, workloadARN string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	if strings.HasPrefix(trimmed, "arn:") {
		return trimmed
	}
	accountID := strings.TrimSpace(a.accountID)
	if accountID == "" {
		accountID = accountIDFromARN(workloadARN)
	}
	if accountID == "" {
		return ""
	}
	return fmt.Sprintf("arn:%s:iam::%s:role/%s", arnPartitionFromARN(workloadARN), accountID, strings.TrimPrefix(trimmed, "/"))
}

func sageMakerDiagnostic(code string, sourceID string, message string, retryable bool) providers.SourceError {
	return providers.SourceError{
		Collector: sageMakerWorkloadRoleCollectorName,
		SourceID:  strings.TrimSpace(sourceID),
		Code:      strings.TrimSpace(code),
		Message:   strings.TrimSpace(message),
		Retryable: retryable,
	}
}

func sageMakerShouldReturnError(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// isActiveSageMakerStatus returns true only for statuses AWS uses to mark a
// SageMaker workload as currently running. SageMaker job statuses
// (Completed, Failed, Stopping, Stopped) and endpoint/domain failure modes
// (OutOfService, Failed, Updating, Deleting) must not be reported as
// active so downstream consumers do not treat finished or failed workloads
// as live evidence.
func isActiveSageMakerStatus(status string) bool {
	switch strings.TrimSpace(status) {
	case "InService", "InProgress", "Active", "RUNNING", "Running":
		return true
	default:
		return false
	}
}

func sageMakerSDKPageSize(pageSize int32, max int32) int32 {
	if pageSize <= 0 {
		pageSize = defaultPageSize
	}
	if max > 0 && pageSize > max {
		return max
	}
	return pageSize
}

func sageMakerAccountID(ctx context.Context, cfg awsv2.Config, accountID string) (string, error) {
	trimmed := strings.TrimSpace(accountID)
	if trimmed != "" {
		return trimmed, nil
	}
	identity, err := sts.NewFromConfig(cfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", fmt.Errorf("read AWS caller identity for sagemaker account id: %w", err)
	}
	resolved := strings.TrimSpace(awsv2.ToString(identity.Account))
	if resolved == "" {
		return "", fmt.Errorf("read AWS caller identity for sagemaker account id: empty account id")
	}
	return resolved, nil
}
