package aws

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/apprunner"
	apprunnertypes "github.com/aws/aws-sdk-go-v2/service/apprunner/types"
	"github.com/aws/aws-sdk-go-v2/service/batch"
	batchtypes "github.com/aws/aws-sdk-go-v2/service/batch/types"
	"github.com/aws/aws-sdk-go-v2/service/emr"
	emrtypes "github.com/aws/aws-sdk-go-v2/service/emr/types"
	"github.com/aws/aws-sdk-go-v2/service/glue"
	gluetypes "github.com/aws/aws-sdk-go-v2/service/glue/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/identrail/identrail/internal/providers"
	"github.com/identrail/identrail/internal/providers/awscontract"
	"github.com/identrail/identrail/internal/textutil"
)

type AppRunnerSDKClient interface {
	ListServices(ctx context.Context, params *apprunner.ListServicesInput, optFns ...func(*apprunner.Options)) (*apprunner.ListServicesOutput, error)
	DescribeService(ctx context.Context, params *apprunner.DescribeServiceInput, optFns ...func(*apprunner.Options)) (*apprunner.DescribeServiceOutput, error)
}

type BatchSDKClient interface {
	DescribeComputeEnvironments(ctx context.Context, params *batch.DescribeComputeEnvironmentsInput, optFns ...func(*batch.Options)) (*batch.DescribeComputeEnvironmentsOutput, error)
	DescribeJobDefinitions(ctx context.Context, params *batch.DescribeJobDefinitionsInput, optFns ...func(*batch.Options)) (*batch.DescribeJobDefinitionsOutput, error)
}

type GlueSDKClient interface {
	GetJobs(ctx context.Context, params *glue.GetJobsInput, optFns ...func(*glue.Options)) (*glue.GetJobsOutput, error)
	GetCrawlers(ctx context.Context, params *glue.GetCrawlersInput, optFns ...func(*glue.Options)) (*glue.GetCrawlersOutput, error)
}

type EMRSDKClient interface {
	ListClusters(ctx context.Context, params *emr.ListClustersInput, optFns ...func(*emr.Options)) (*emr.ListClustersOutput, error)
	DescribeCluster(ctx context.Context, params *emr.DescribeClusterInput, optFns ...func(*emr.Options)) (*emr.DescribeClusterOutput, error)
}

type SDKManagedComputeRoleAPI struct {
	appRunnerClient AppRunnerSDKClient
	batchClient     BatchSDKClient
	glueClient      GlueSDKClient
	emrClient       EMRSDKClient
	accountID       string
	region          string
}

var _ ManagedComputeRoleAPI = (*SDKManagedComputeRoleAPI)(nil)

func NewSDKManagedComputeRoleAPI(region string, profile string, accountID string) (ManagedComputeRoleAPI, error) {
	return NewSDKManagedComputeRoleAPIWithContext(context.Background(), region, profile, accountID)
}

func NewSDKManagedComputeRoleAPIWithContext(ctx context.Context, region string, profile string, accountID string) (ManagedComputeRoleAPI, error) {
	cfg, err := loadSDKConfig(ctx, region, profile)
	if err != nil {
		return nil, err
	}
	resolvedAccountID, err := managedComputeAccountID(ctx, cfg, accountID)
	if err != nil {
		return nil, err
	}
	return NewSDKManagedComputeRoleAPIFromClients(apprunner.NewFromConfig(cfg), batch.NewFromConfig(cfg), glue.NewFromConfig(cfg), emr.NewFromConfig(cfg), resolvedAccountID, region), nil
}

func NewSDKManagedComputeRoleAPIFromAssumeRole(ctx context.Context, region string, profile string, roleARN string, externalID string, sessionName string, accountID string) (ManagedComputeRoleAPI, error) {
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
	resolvedAccountID, err := managedComputeAccountID(ctx, cfg, accountID)
	if err != nil {
		return nil, err
	}
	return NewSDKManagedComputeRoleAPIFromClients(apprunner.NewFromConfig(cfg), batch.NewFromConfig(cfg), glue.NewFromConfig(cfg), emr.NewFromConfig(cfg), resolvedAccountID, region), nil
}

func NewSDKManagedComputeRoleAPIFromClients(appRunnerClient AppRunnerSDKClient, batchClient BatchSDKClient, glueClient GlueSDKClient, emrClient EMRSDKClient, accountID string, region string) ManagedComputeRoleAPI {
	return &SDKManagedComputeRoleAPI{
		appRunnerClient: appRunnerClient,
		batchClient:     batchClient,
		glueClient:      glueClient,
		emrClient:       emrClient,
		accountID:       strings.TrimSpace(accountID),
		region:          strings.TrimSpace(region),
	}
}

func (a *SDKManagedComputeRoleAPI) ListServiceRoles(ctx context.Context, _ string, pageSize int32) (ManagedComputeRolePage, error) {
	records := []ManagedComputeRole{}
	diagnostics := []providers.SourceError{}
	if a.appRunnerClient != nil {
		next, issues, err := a.listAppRunnerRoles(ctx, pageSize)
		if err != nil {
			if managedComputeShouldReturnError(err) {
				return ManagedComputeRolePage{}, err
			}
			diagnostics = append(diagnostics, managedComputeDiagnostic("apprunner_services_failed", "apprunner", fmt.Sprintf("App Runner services could not be listed: %v", err), true))
		}
		records = append(records, next...)
		diagnostics = append(diagnostics, issues...)
	}
	if a.batchClient != nil {
		next, issues, err := a.listBatchRoles(ctx, pageSize)
		if err != nil {
			if managedComputeShouldReturnError(err) {
				return ManagedComputeRolePage{}, err
			}
			diagnostics = append(diagnostics, managedComputeDiagnostic("batch_failed", "batch", fmt.Sprintf("Batch metadata could not be listed: %v", err), true))
		}
		records = append(records, next...)
		diagnostics = append(diagnostics, issues...)
	}
	if a.glueClient != nil {
		next, issues, err := a.listGlueRoles(ctx, pageSize)
		if err != nil {
			if managedComputeShouldReturnError(err) {
				return ManagedComputeRolePage{}, err
			}
			diagnostics = append(diagnostics, managedComputeDiagnostic("glue_failed", "glue", fmt.Sprintf("Glue metadata could not be listed: %v", err), true))
		}
		records = append(records, next...)
		diagnostics = append(diagnostics, issues...)
	}
	if a.emrClient != nil {
		next, issues, err := a.listEMRRoles(ctx, pageSize)
		if err != nil {
			if managedComputeShouldReturnError(err) {
				return ManagedComputeRolePage{}, err
			}
			diagnostics = append(diagnostics, managedComputeDiagnostic("emr_failed", "emr", fmt.Sprintf("EMR metadata could not be listed: %v", err), true))
		}
		records = append(records, next...)
		diagnostics = append(diagnostics, issues...)
	}
	diagnostics = append(diagnostics, managedComputeDiagnostic("managed_compute_unsupported_service", "mwaa", "Managed compute coverage gap: MWAA role discovery is not implemented in this issue", false))
	sort.SliceStable(records, func(i, j int) bool {
		return managedComputeRoleSourceID(records[i]) < managedComputeRoleSourceID(records[j])
	})
	return ManagedComputeRolePage{Records: records, Diagnostics: diagnostics}, nil
}

func (a *SDKManagedComputeRoleAPI) listAppRunnerRoles(ctx context.Context, pageSize int32) ([]ManagedComputeRole, []providers.SourceError, error) {
	records := []ManagedComputeRole{}
	diagnostics := []providers.SourceError{}
	token := ""
	maxResults := managedComputeSDKPageSize(pageSize, 20)
	for {
		output, err := a.appRunnerClient.ListServices(ctx, &apprunner.ListServicesInput{MaxResults: awsv2.Int32(maxResults), NextToken: stringPtrOrNil(token)})
		if err != nil {
			return records, diagnostics, err
		}
		if output == nil {
			break
		}
		for _, summary := range output.ServiceSummaryList {
			serviceARN := strings.TrimSpace(awsv2.ToString(summary.ServiceArn))
			if serviceARN == "" {
				diagnostics = append(diagnostics, managedComputeDiagnostic("apprunner_service_arn_missing", "listservices", "App Runner service summary did not include an ARN", false))
				continue
			}
			describe, err := a.appRunnerClient.DescribeService(ctx, &apprunner.DescribeServiceInput{ServiceArn: awsv2.String(serviceARN)})
			if err != nil {
				diagnostics = append(diagnostics, managedComputeDiagnostic("apprunner_service_describe_failed", serviceARN, fmt.Sprintf("App Runner service could not be described: %v", err), true))
				continue
			}
			if describe == nil || describe.Service == nil {
				continue
			}
			records = append(records, a.recordsFromAppRunnerService(describe.Service)...)
		}
		token = strings.TrimSpace(awsv2.ToString(output.NextToken))
		if token == "" {
			break
		}
	}
	return records, diagnostics, nil
}

func (a *SDKManagedComputeRoleAPI) recordsFromAppRunnerService(service *apprunnertypes.Service) []ManagedComputeRole {
	if service == nil {
		return nil
	}
	arn := strings.TrimSpace(awsv2.ToString(service.ServiceArn))
	name := strings.TrimSpace(awsv2.ToString(service.ServiceName))
	status := string(service.Status)
	roles := []struct {
		arn  string
		kind string
	}{}
	if service.InstanceConfiguration != nil {
		roles = append(roles, struct {
			arn  string
			kind string
		}{arn: awsv2.ToString(service.InstanceConfiguration.InstanceRoleArn), kind: "apprunner_instance_role"})
	}
	if service.SourceConfiguration != nil && service.SourceConfiguration.AuthenticationConfiguration != nil {
		roles = append(roles, struct {
			arn  string
			kind string
		}{arn: awsv2.ToString(service.SourceConfiguration.AuthenticationConfiguration.AccessRoleArn), kind: "apprunner_access_role"})
	}
	return a.recordsForRoles("apprunner", "apprunner_service", name, arn, status, "", "", roles, copyTags(nil))
}

func (a *SDKManagedComputeRoleAPI) listBatchRoles(ctx context.Context, pageSize int32) ([]ManagedComputeRole, []providers.SourceError, error) {
	records := []ManagedComputeRole{}
	diagnostics := []providers.SourceError{}
	envToken := ""
	for {
		envs, err := a.batchClient.DescribeComputeEnvironments(ctx, &batch.DescribeComputeEnvironmentsInput{MaxResults: awsv2.Int32(pageSize), NextToken: stringPtrOrNil(envToken)})
		if err != nil {
			if managedComputeShouldReturnError(err) {
				return records, diagnostics, err
			}
			diagnostics = append(diagnostics, managedComputeDiagnostic("batch_compute_environments_failed", "describecomputeenvironments", fmt.Sprintf("Batch compute environments could not be described: %v", err), true))
			break
		}
		if envs == nil {
			break
		}
		for _, env := range envs.ComputeEnvironments {
			arn := strings.TrimSpace(awsv2.ToString(env.ComputeEnvironmentArn))
			name := strings.TrimSpace(awsv2.ToString(env.ComputeEnvironmentName))
			status := string(env.Status)
			roles := []struct {
				arn  string
				kind string
			}{{arn: awsv2.ToString(env.ServiceRole), kind: "batch_service_role"}}
			if env.ComputeResources != nil {
				roles = append(roles,
					struct{ arn, kind string }{arn: awsv2.ToString(env.ComputeResources.SpotIamFleetRole), kind: "batch_spot_fleet_role"},
				)
			}
			next := a.recordsForRoles("batch", "batch_compute_environment", name, arn, status, string(env.ContainerOrchestrationType), "", roles, nil)
			for idx := range next {
				next[idx].ClusterARN = strings.TrimSpace(awsv2.ToString(env.EcsClusterArn))
				next[idx].Active = env.State == batchtypes.CEStateEnabled
				next[idx].Disabled = env.State == batchtypes.CEStateDisabled
			}
			records = append(records, next...)
		}
		envToken = strings.TrimSpace(awsv2.ToString(envs.NextToken))
		if envToken == "" {
			break
		}
	}
	jobToken := ""
	for {
		jobs, err := a.batchClient.DescribeJobDefinitions(ctx, &batch.DescribeJobDefinitionsInput{MaxResults: awsv2.Int32(pageSize), NextToken: stringPtrOrNil(jobToken), Status: awsv2.String("ACTIVE")})
		if err != nil {
			diagnostics = append(diagnostics, managedComputeDiagnostic("batch_job_definitions_failed", "describejobdefinitions", fmt.Sprintf("Batch job definitions could not be described: %v", err), true))
			return records, diagnostics, nil
		}
		if jobs == nil {
			break
		}
		for _, job := range jobs.JobDefinitions {
			records = append(records, a.recordsFromBatchJobDefinition(job)...)
		}
		jobToken = strings.TrimSpace(awsv2.ToString(jobs.NextToken))
		if jobToken == "" {
			break
		}
	}
	return records, diagnostics, nil
}

func (a *SDKManagedComputeRoleAPI) recordsFromBatchJobDefinition(job batchtypes.JobDefinition) []ManagedComputeRole {
	arn := strings.TrimSpace(awsv2.ToString(job.JobDefinitionArn))
	name := strings.TrimSpace(awsv2.ToString(job.JobDefinitionName))
	roles := []struct {
		arn  string
		kind string
	}{}
	if job.ContainerProperties != nil {
		roles = append(roles,
			struct{ arn, kind string }{arn: a.iamRoleARNFromNameOrARN(awsv2.ToString(job.ContainerProperties.JobRoleArn), arn), kind: "batch_job_role"},
			struct{ arn, kind string }{arn: a.iamRoleARNFromNameOrARN(awsv2.ToString(job.ContainerProperties.ExecutionRoleArn), arn), kind: "batch_execution_role"},
		)
	}
	if job.EcsProperties != nil {
		for _, task := range job.EcsProperties.TaskProperties {
			roles = append(roles,
				struct{ arn, kind string }{arn: a.iamRoleARNFromNameOrARN(awsv2.ToString(task.TaskRoleArn), arn), kind: "batch_job_role"},
				struct{ arn, kind string }{arn: a.iamRoleARNFromNameOrARN(awsv2.ToString(task.ExecutionRoleArn), arn), kind: "batch_execution_role"},
			)
		}
	}
	if job.NodeProperties != nil {
		for _, nodeRange := range job.NodeProperties.NodeRangeProperties {
			if nodeRange.Container == nil {
				continue
			}
			roles = append(roles,
				struct{ arn, kind string }{arn: a.iamRoleARNFromNameOrARN(awsv2.ToString(nodeRange.Container.JobRoleArn), arn), kind: "batch_job_role"},
				struct{ arn, kind string }{arn: a.iamRoleARNFromNameOrARN(awsv2.ToString(nodeRange.Container.ExecutionRoleArn), arn), kind: "batch_execution_role"},
			)
		}
	}
	next := a.recordsForRoles("batch", "batch_job_definition", name, arn, "ACTIVE", string(job.ContainerOrchestrationType), "", roles, nil)
	for idx := range next {
		next[idx].JobDefinitionARN = arn
		next[idx].Revision = awsv2.ToInt32(job.Revision)
	}
	return next
}

func (a *SDKManagedComputeRoleAPI) listGlueRoles(ctx context.Context, pageSize int32) ([]ManagedComputeRole, []providers.SourceError, error) {
	records := []ManagedComputeRole{}
	diagnostics := []providers.SourceError{}
	token := ""
	for {
		output, err := a.glueClient.GetJobs(ctx, &glue.GetJobsInput{MaxResults: awsv2.Int32(pageSize), NextToken: stringPtrOrNil(token)})
		if err != nil {
			if managedComputeShouldReturnError(err) {
				return records, diagnostics, err
			}
			diagnostics = append(diagnostics, managedComputeDiagnostic("glue_jobs_failed", "getjobs", fmt.Sprintf("Glue jobs could not be listed: %v", err), true))
			break
		}
		if output == nil {
			break
		}
		for _, job := range output.Jobs {
			arn := glueResourceARN(a.region, a.accountID, "job", awsv2.ToString(job.Name))
			engine := ""
			if job.Command != nil {
				engine = awsv2.ToString(job.Command.Name)
			}
			records = append(records, a.recordsForRoles("glue", "glue_job", awsv2.ToString(job.Name), arn, "", engine, "", []struct {
				arn  string
				kind string
			}{{arn: a.iamRoleARNFromNameOrARN(awsv2.ToString(job.Role), arn), kind: "glue_job_role"}}, nil)...)
		}
		token = strings.TrimSpace(awsv2.ToString(output.NextToken))
		if token == "" {
			break
		}
	}
	token = ""
	for {
		output, err := a.glueClient.GetCrawlers(ctx, &glue.GetCrawlersInput{MaxResults: awsv2.Int32(pageSize), NextToken: stringPtrOrNil(token)})
		if err != nil {
			diagnostics = append(diagnostics, managedComputeDiagnostic("glue_crawlers_failed", "getcrawlers", fmt.Sprintf("Glue crawlers could not be listed: %v", err), true))
			break
		}
		if output == nil {
			break
		}
		for _, crawler := range output.Crawlers {
			arn := glueResourceARN(a.region, a.accountID, "crawler", awsv2.ToString(crawler.Name))
			records = append(records, a.recordsForRoles("glue", "glue_crawler", awsv2.ToString(crawler.Name), arn, string(crawler.State), "", "", []struct {
				arn  string
				kind string
			}{{arn: a.iamRoleARNFromNameOrARN(awsv2.ToString(crawler.Role), arn), kind: "glue_crawler_role"}}, nil)...)
		}
		token = strings.TrimSpace(awsv2.ToString(output.NextToken))
		if token == "" {
			break
		}
	}
	return records, diagnostics, nil
}

func (a *SDKManagedComputeRoleAPI) listEMRRoles(ctx context.Context, pageSize int32) ([]ManagedComputeRole, []providers.SourceError, error) {
	records := []ManagedComputeRole{}
	diagnostics := []providers.SourceError{}
	token := ""
	for {
		output, err := a.emrClient.ListClusters(ctx, &emr.ListClustersInput{Marker: stringPtrOrNil(token)})
		if err != nil {
			return records, diagnostics, err
		}
		if output == nil {
			break
		}
		for _, summary := range output.Clusters {
			clusterID := strings.TrimSpace(awsv2.ToString(summary.Id))
			if clusterID == "" {
				diagnostics = append(diagnostics, managedComputeDiagnostic("emr_cluster_id_missing", "listclusters", "EMR cluster summary did not include an ID", false))
				continue
			}
			describe, err := a.emrClient.DescribeCluster(ctx, &emr.DescribeClusterInput{ClusterId: awsv2.String(clusterID)})
			if err != nil {
				diagnostics = append(diagnostics, managedComputeDiagnostic("emr_cluster_describe_failed", clusterID, fmt.Sprintf("EMR cluster could not be described: %v", err), true))
				continue
			}
			if describe == nil || describe.Cluster == nil {
				continue
			}
			records = append(records, a.recordsFromEMRCluster(describe.Cluster)...)
		}
		token = strings.TrimSpace(awsv2.ToString(output.Marker))
		if token == "" {
			break
		}
	}
	_ = pageSize
	return records, diagnostics, nil
}

func (a *SDKManagedComputeRoleAPI) recordsFromEMRCluster(cluster *emrtypes.Cluster) []ManagedComputeRole {
	if cluster == nil {
		return nil
	}
	arn := strings.TrimSpace(awsv2.ToString(cluster.ClusterArn))
	if arn == "" {
		arn = fmt.Sprintf("arn:%s:elasticmapreduce:%s:%s:cluster/%s", awsPartitionForRegion(a.region), a.region, a.accountID, awsv2.ToString(cluster.Id))
	}
	status := ""
	if cluster.Status != nil {
		status = string(cluster.Status.State)
	}
	return a.recordsForRoles("emr", "emr_cluster", awsv2.ToString(cluster.Name), arn, status, "", "", []struct {
		arn  string
		kind string
	}{
		{arn: a.iamRoleARNFromNameOrARN(awsv2.ToString(cluster.ServiceRole), arn), kind: "emr_service_role"},
		{arn: a.iamRoleARNFromNameOrARN(awsv2.ToString(cluster.AutoScalingRole), arn), kind: "emr_autoscaling_role"},
	}, nil)
}

func (a *SDKManagedComputeRoleAPI) recordsForRoles(service string, workloadType string, workloadName string, workloadARN string, status string, engine string, queueARN string, roles []struct {
	arn  string
	kind string
}, tags map[string]string) []ManagedComputeRole {
	records := []ManagedComputeRole{}
	for _, role := range roles {
		roleARN := strings.TrimSpace(role.arn)
		if roleARN == "" {
			continue
		}
		record := ManagedComputeRole{
			ServiceCollectorRecord: awscontract.ServiceCollectorRecord{
				AccountID:     a.accountID,
				Region:        a.region,
				Service:       service,
				WorkloadID:    firstNonEmptyAWSValue(workloadARN, workloadName),
				WorkloadType:  workloadType,
				WorkloadName:  strings.TrimSpace(workloadName),
				RoleARN:       roleARN,
				Source:        service + "_metadata",
				EvidenceRef:   firstNonEmptyAWSValue(workloadARN, workloadName),
				Confidence:    0.93,
				CollectorName: managedComputeRoleCollectorName,
			},
			RoleName:       roleNameFromARN(roleARN),
			RoleKind:       role.kind,
			RoleAccountID:  roleAccountIDFromARN(roleARN),
			WorkloadARN:    strings.TrimSpace(workloadARN),
			ResourceARN:    strings.TrimSpace(workloadARN),
			ResourceType:   workloadType,
			ResourceStatus: strings.TrimSpace(status),
			ComputeEngine:  strings.TrimSpace(engine),
			QueueARN:       strings.TrimSpace(queueARN),
			CoverageStatus: "covered",
			Active:         !strings.EqualFold(status, "DISABLED") && !strings.EqualFold(status, "TERMINATED"),
			Disabled:       strings.EqualFold(status, "DISABLED"),
			Tags:           copyTags(tags),
		}
		record.Confidence = managedComputeRoleConfidence(record)
		records = append(records, record)
	}
	return records
}

func managedComputeDiagnostic(code string, sourceID string, message string, retryable bool) providers.SourceError {
	return providers.SourceError{
		Collector: managedComputeRoleCollectorName,
		SourceID:  strings.TrimSpace(sourceID),
		Code:      strings.TrimSpace(code),
		Message:   strings.TrimSpace(message),
		Retryable: retryable,
	}
}

func managedComputeShouldReturnError(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

func glueResourceARN(region string, accountID string, kind string, name string) string {
	if strings.TrimSpace(name) == "" {
		return ""
	}
	return fmt.Sprintf("arn:%s:glue:%s:%s:%s/%s", awsPartitionForRegion(region), normalizeName(region), normalizeName(accountID), normalizeName(kind), strings.TrimSpace(name))
}

func awsPartitionForRegion(region string) string {
	trimmed := strings.TrimSpace(region)
	switch {
	case strings.HasPrefix(trimmed, "us-gov-"):
		return "aws-us-gov"
	case strings.HasPrefix(trimmed, "cn-"):
		return "aws-cn"
	default:
		return "aws"
	}
}

func managedComputeAccountID(ctx context.Context, cfg awsv2.Config, accountID string) (string, error) {
	trimmed := strings.TrimSpace(accountID)
	if trimmed != "" {
		return trimmed, nil
	}
	identity, err := sts.NewFromConfig(cfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", fmt.Errorf("read AWS caller identity for managed compute account id: %w", err)
	}
	resolved := strings.TrimSpace(awsv2.ToString(identity.Account))
	if resolved == "" {
		return "", fmt.Errorf("read AWS caller identity for managed compute account id: empty account id")
	}
	return resolved, nil
}

func (a *SDKManagedComputeRoleAPI) iamRoleARNFromNameOrARN(value string, workloadARN string) string {
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

func arnPartitionFromARN(arn string) string {
	parts := strings.Split(strings.TrimSpace(arn), ":")
	if len(parts) >= 2 && parts[0] == "arn" && strings.TrimSpace(parts[1]) != "" {
		return strings.TrimSpace(parts[1])
	}
	return "aws"
}

func managedComputeSDKPageSize(pageSize int32, max int32) int32 {
	if pageSize <= 0 {
		pageSize = defaultPageSize
	}
	if max > 0 && pageSize > max {
		return max
	}
	return pageSize
}

var _ = gluetypes.Job{}
