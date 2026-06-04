package aws

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/identrail/identrail/internal/providers"
	"github.com/identrail/identrail/internal/providers/awscontract"
	"github.com/identrail/identrail/internal/textutil"
)

// ECSSDKClient defines the ECS SDK calls required by the task-role adapter.
type ECSSDKClient interface {
	ListClusters(ctx context.Context, params *ecs.ListClustersInput, optFns ...func(*ecs.Options)) (*ecs.ListClustersOutput, error)
	ListServices(ctx context.Context, params *ecs.ListServicesInput, optFns ...func(*ecs.Options)) (*ecs.ListServicesOutput, error)
	DescribeServices(ctx context.Context, params *ecs.DescribeServicesInput, optFns ...func(*ecs.Options)) (*ecs.DescribeServicesOutput, error)
	ListTaskDefinitions(ctx context.Context, params *ecs.ListTaskDefinitionsInput, optFns ...func(*ecs.Options)) (*ecs.ListTaskDefinitionsOutput, error)
	DescribeTaskDefinition(ctx context.Context, params *ecs.DescribeTaskDefinitionInput, optFns ...func(*ecs.Options)) (*ecs.DescribeTaskDefinitionOutput, error)
}

// SDKECSTaskRoleAPI adapts AWS SDK ECS calls to ECSTaskRoleAPI.
type SDKECSTaskRoleAPI struct {
	ecsClient ECSSDKClient
	accountID string
	region    string
}

var _ ECSTaskRoleAPI = (*SDKECSTaskRoleAPI)(nil)

// NewSDKECSTaskRoleAPI constructs an ECS task-role API backed by the AWS SDK default credential chain.
func NewSDKECSTaskRoleAPI(region string, profile string, accountID string) (ECSTaskRoleAPI, error) {
	return NewSDKECSTaskRoleAPIWithContext(context.Background(), region, profile, accountID)
}

// NewSDKECSTaskRoleAPIWithContext constructs an ECS task-role API using caller-provided context for config loading.
func NewSDKECSTaskRoleAPIWithContext(ctx context.Context, region string, profile string, accountID string) (ECSTaskRoleAPI, error) {
	cfg, err := loadSDKConfig(ctx, region, profile)
	if err != nil {
		return nil, err
	}
	return NewSDKECSTaskRoleAPIFromClient(ecs.NewFromConfig(cfg), accountID, region), nil
}

// NewSDKECSTaskRoleAPIFromAssumeRole constructs an ECS task-role API for an onboarded connector role.
func NewSDKECSTaskRoleAPIFromAssumeRole(ctx context.Context, region string, profile string, roleARN string, externalID string, sessionName string, accountID string) (ECSTaskRoleAPI, error) {
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
	return NewSDKECSTaskRoleAPIFromClient(ecs.NewFromConfig(cfg), accountID, region), nil
}

// NewSDKECSTaskRoleAPIFromClient creates an ECSTaskRoleAPI from a provided ECS client.
func NewSDKECSTaskRoleAPIFromClient(ecsClient ECSSDKClient, accountID string, region string) ECSTaskRoleAPI {
	return &SDKECSTaskRoleAPI{
		ecsClient: ecsClient,
		accountID: strings.TrimSpace(accountID),
		region:    strings.TrimSpace(region),
	}
}

// ListTaskRoles returns a complete metadata-only ECS scan. The SDK adapter
// handles AWS pagination internally; the collector-facing page contract remains
// reusable for fixture and unit-test APIs.
func (a *SDKECSTaskRoleAPI) ListTaskRoles(ctx context.Context, _ string, pageSize int32) (ECSTaskRolePage, error) {
	if a.ecsClient == nil {
		return ECSTaskRolePage{}, fmt.Errorf("ecs sdk client is required")
	}

	pageSize = ecsSDKPageSize(pageSize)
	records := []ECSTaskRole{}
	diagnostics := []providers.SourceError{}
	seenTaskDefinitionARNs := map[string]struct{}{}

	clusterARNs, err := a.listClusters(ctx, pageSize)
	if err != nil {
		return ECSTaskRolePage{}, err
	}
	for _, clusterARN := range clusterARNs {
		if err := ctx.Err(); err != nil {
			return ECSTaskRolePage{}, err
		}
		serviceARNs, err := a.listServices(ctx, clusterARN, pageSize)
		if err != nil {
			diagnostics = append(diagnostics, ecsSourceDiagnostic("cluster_service_list_failed", clusterARN, fmt.Sprintf("ECS services could not be listed for cluster %s: %v", clusterARN, err), true))
			continue
		}
		for _, batch := range batchStrings(serviceARNs, 10) {
			output, err := a.ecsClient.DescribeServices(ctx, &ecs.DescribeServicesInput{
				Cluster:  awsv2.String(clusterARN),
				Services: batch,
				Include:  []ecstypes.ServiceField{ecstypes.ServiceFieldTags},
			})
			if err != nil {
				diagnostics = append(diagnostics, ecsSourceDiagnostic("cluster_services_describe_failed", clusterARN, fmt.Sprintf("ECS services could not be described for cluster %s: %v", clusterARN, err), true))
				continue
			}
			for _, failure := range output.Failures {
				diagnostics = append(diagnostics, ecsSourceDiagnostic("service_describe_failed", awsv2.ToString(failure.Arn), firstNonEmptyAWSValue(awsv2.ToString(failure.Detail), awsv2.ToString(failure.Reason), "ECS service could not be described"), true))
			}
			for _, service := range output.Services {
				taskDefinitionARN := strings.TrimSpace(awsv2.ToString(service.TaskDefinition))
				if taskDefinitionARN == "" {
					diagnostics = append(diagnostics, ecsSourceDiagnostic("missing_task_definition", awsv2.ToString(service.ServiceArn), "ECS service did not report a task definition ARN", false))
					continue
				}
				taskDefinition, taskDefinitionTags, err := a.describeTaskDefinition(ctx, taskDefinitionARN)
				if err != nil {
					diagnostics = append(diagnostics, ecsSourceDiagnostic("task_definition_describe_failed", taskDefinitionARN, fmt.Sprintf("ECS service task definition could not be described: %v", err), true))
					continue
				}
				serviceRecords := a.recordsFromTaskDefinition(taskDefinition, taskDefinitionTags, &service)
				if len(serviceRecords) == 0 {
					diagnostics = append(diagnostics, ecsSourceDiagnostic("missing_ecs_task_roles", taskDefinitionARN, "ECS task definition did not include task or execution role ARNs", false))
					continue
				}
				records = append(records, serviceRecords...)
				seenTaskDefinitionARNs[taskDefinitionARN] = struct{}{}
			}
		}
	}

	taskDefinitionARNs, taskDefinitionDiagnostics := a.listTaskDefinitions(ctx, pageSize)
	diagnostics = append(diagnostics, taskDefinitionDiagnostics...)
	for _, taskDefinitionARN := range taskDefinitionARNs {
		if err := ctx.Err(); err != nil {
			return ECSTaskRolePage{}, err
		}
		taskDefinition, tags, err := a.describeTaskDefinition(ctx, taskDefinitionARN)
		if err != nil {
			diagnostics = append(diagnostics, ecsSourceDiagnostic("task_definition_describe_failed", taskDefinitionARN, fmt.Sprintf("ECS task definition could not be described: %v", err), true))
			continue
		}
		taskDefinitionRecords := a.recordsFromTaskDefinition(taskDefinition, tags, nil)
		if len(taskDefinitionRecords) == 0 {
			if _, serviceSeen := seenTaskDefinitionARNs[taskDefinitionARN]; !serviceSeen {
				diagnostics = append(diagnostics, ecsSourceDiagnostic("missing_ecs_task_roles", taskDefinitionARN, "ECS task definition did not include task or execution role ARNs", false))
			}
			continue
		}
		records = append(records, taskDefinitionRecords...)
	}

	sort.SliceStable(records, func(i, j int) bool {
		return ecsTaskRoleSourceID(records[i]) < ecsTaskRoleSourceID(records[j])
	})
	return ECSTaskRolePage{Records: records, Diagnostics: diagnostics}, nil
}

func (a *SDKECSTaskRoleAPI) listClusters(ctx context.Context, pageSize int32) ([]string, error) {
	input := &ecs.ListClustersInput{MaxResults: awsv2.Int32(pageSize)}
	clusters := []string{}
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		output, err := a.ecsClient.ListClusters(ctx, input)
		if err != nil {
			return nil, err
		}
		if output != nil {
			clusters = append(clusters, normalizeStringList(output.ClusterArns)...)
		}
		nextToken := ""
		if output != nil {
			nextToken = strings.TrimSpace(awsv2.ToString(output.NextToken))
		}
		if nextToken == "" {
			break
		}
		input.NextToken = awsv2.String(nextToken)
	}
	sort.Strings(clusters)
	return clusters, nil
}

func (a *SDKECSTaskRoleAPI) listServices(ctx context.Context, clusterARN string, pageSize int32) ([]string, error) {
	input := &ecs.ListServicesInput{
		Cluster:    awsv2.String(clusterARN),
		MaxResults: awsv2.Int32(pageSize),
	}
	services := []string{}
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		output, err := a.ecsClient.ListServices(ctx, input)
		if err != nil {
			return nil, err
		}
		if output != nil {
			services = append(services, normalizeStringList(output.ServiceArns)...)
		}
		nextToken := ""
		if output != nil {
			nextToken = strings.TrimSpace(awsv2.ToString(output.NextToken))
		}
		if nextToken == "" {
			break
		}
		input.NextToken = awsv2.String(nextToken)
	}
	sort.Strings(services)
	return services, nil
}

func (a *SDKECSTaskRoleAPI) listTaskDefinitions(ctx context.Context, pageSize int32) ([]string, []providers.SourceError) {
	taskDefinitions := []string{}
	diagnostics := []providers.SourceError{}
	for _, status := range []ecstypes.TaskDefinitionStatus{ecstypes.TaskDefinitionStatusActive, ecstypes.TaskDefinitionStatusInactive} {
		input := &ecs.ListTaskDefinitionsInput{
			MaxResults: awsv2.Int32(pageSize),
			Status:     status,
		}
		for {
			if err := ctx.Err(); err != nil {
				return taskDefinitions, append(diagnostics, ecsSourceDiagnostic("task_definition_list_failed", string(status), err.Error(), true))
			}
			output, err := a.ecsClient.ListTaskDefinitions(ctx, input)
			if err != nil {
				diagnostics = append(diagnostics, ecsSourceDiagnostic("task_definition_list_failed", string(status), fmt.Sprintf("ECS %s task definitions could not be listed: %v", status, err), true))
				break
			}
			if output != nil {
				taskDefinitions = append(taskDefinitions, normalizeStringList(output.TaskDefinitionArns)...)
			}
			nextToken := ""
			if output != nil {
				nextToken = strings.TrimSpace(awsv2.ToString(output.NextToken))
			}
			if nextToken == "" {
				break
			}
			input.NextToken = awsv2.String(nextToken)
		}
	}
	taskDefinitions = normalizeStringList(taskDefinitions)
	sort.Strings(taskDefinitions)
	return taskDefinitions, diagnostics
}

func (a *SDKECSTaskRoleAPI) describeTaskDefinition(ctx context.Context, taskDefinitionARN string) (ecstypes.TaskDefinition, []ecstypes.Tag, error) {
	output, err := a.ecsClient.DescribeTaskDefinition(ctx, &ecs.DescribeTaskDefinitionInput{
		TaskDefinition: awsv2.String(taskDefinitionARN),
		Include:        []ecstypes.TaskDefinitionField{ecstypes.TaskDefinitionFieldTags},
	})
	if err != nil {
		return ecstypes.TaskDefinition{}, nil, err
	}
	if output == nil || output.TaskDefinition == nil {
		return ecstypes.TaskDefinition{}, nil, fmt.Errorf("task definition response was empty")
	}
	return *output.TaskDefinition, append([]ecstypes.Tag(nil), output.Tags...), nil
}

func (a *SDKECSTaskRoleAPI) recordsFromTaskDefinition(taskDefinition ecstypes.TaskDefinition, taskDefinitionTags []ecstypes.Tag, service *ecstypes.Service) []ECSTaskRole {
	taskDefinitionARN := strings.TrimSpace(awsv2.ToString(taskDefinition.TaskDefinitionArn))
	if taskDefinitionARN == "" {
		return nil
	}

	compatibilities := compatibilityStrings(taskDefinition.RequiresCompatibilities)
	base := ECSTaskRole{
		ServiceCollectorRecord: awscontract.ServiceCollectorRecord{
			AccountID:     a.accountID,
			Region:        a.region,
			Service:       ecsServiceName,
			WorkloadID:    taskDefinitionARN,
			WorkloadType:  "ecs_task_definition",
			WorkloadName:  firstNonEmptyAWSValue(awsv2.ToString(taskDefinition.Family), ecsNameFromARN(taskDefinitionARN)),
			Source:        "describetaskdefinition",
			EvidenceRef:   taskDefinitionARN,
			Confidence:    0.96,
			CollectorName: ecsTaskRoleCollectorName,
		},
		TaskDefinitionARN:      taskDefinitionARN,
		TaskDefinitionFamily:   strings.TrimSpace(awsv2.ToString(taskDefinition.Family)),
		TaskDefinitionRevision: strconv.FormatInt(int64(taskDefinition.Revision), 10),
		TaskDefinitionStatus:   string(taskDefinition.Status),
		TaskRoleARN:            strings.TrimSpace(awsv2.ToString(taskDefinition.TaskRoleArn)),
		ExecutionRoleARN:       strings.TrimSpace(awsv2.ToString(taskDefinition.ExecutionRoleArn)),
		Compatibilities:        compatibilities,
		ContainerImages:        containerImages(taskDefinition.ContainerDefinitions),
		SecretRefs:             containerSecretRefs(taskDefinition.ContainerDefinitions),
		EnvironmentKeys:        containerEnvironmentKeys(taskDefinition.ContainerDefinitions),
		Tags:                   copyECSTags(taskDefinitionTags),
	}

	if service != nil {
		serviceARN := strings.TrimSpace(awsv2.ToString(service.ServiceArn))
		serviceName := firstNonEmptyAWSValue(awsv2.ToString(service.ServiceName), ecsNameFromARN(serviceARN))
		base.WorkloadID = firstNonEmptyAWSValue(serviceARN, serviceName, taskDefinitionARN)
		base.WorkloadType = "ecs_service"
		base.WorkloadName = firstNonEmptyAWSValue(serviceName, base.TaskDefinitionFamily, ecsNameFromARN(taskDefinitionARN))
		base.Source = "describeservices"
		base.EvidenceRef = firstNonEmptyAWSValue(serviceARN, taskDefinitionARN)
		base.ClusterARN = strings.TrimSpace(awsv2.ToString(service.ClusterArn))
		base.ClusterName = ecsNameFromARN(base.ClusterARN)
		base.ServiceARN = serviceARN
		base.ServiceName = serviceName
		base.ServiceStatus = strings.TrimSpace(awsv2.ToString(service.Status))
		base.LaunchType = string(service.LaunchType)
		base.SchedulingStrategy = string(service.SchedulingStrategy)
		base.DesiredCount = service.DesiredCount
		base.RunningCount = service.RunningCount
		base.PendingCount = service.PendingCount
		base.Tags = copyECSTags(service.Tags)
	}

	records := []ECSTaskRole{}
	if taskRoleARN := strings.TrimSpace(awsv2.ToString(taskDefinition.TaskRoleArn)); taskRoleARN != "" {
		record := base
		record.RoleKind = ecsRoleKindTask
		record.RoleARN = taskRoleARN
		record.RoleName = roleNameFromARN(taskRoleARN)
		record.Confidence = 0.96
		records = append(records, record)
	}
	if executionRoleARN := strings.TrimSpace(awsv2.ToString(taskDefinition.ExecutionRoleArn)); executionRoleARN != "" {
		record := base
		record.RoleKind = ecsRoleKindExecution
		record.RoleARN = executionRoleARN
		record.RoleName = roleNameFromARN(executionRoleARN)
		record.Confidence = 0.9
		records = append(records, record)
	}
	return records
}

func ecsSDKPageSize(pageSize int32) int32 {
	if pageSize < 1 {
		return defaultPageSize
	}
	if pageSize > 100 {
		return 100
	}
	return pageSize
}

func ecsSourceDiagnostic(code string, sourceID string, message string, retryable bool) providers.SourceError {
	return providers.SourceError{
		Collector: ecsTaskRoleCollectorName,
		SourceID:  strings.TrimSpace(sourceID),
		Code:      code,
		Message:   strings.TrimSpace(message),
		Retryable: retryable,
	}
}

func batchStrings(values []string, batchSize int) [][]string {
	if batchSize <= 0 || len(values) == 0 {
		return nil
	}
	batches := make([][]string, 0, (len(values)+batchSize-1)/batchSize)
	for start := 0; start < len(values); start += batchSize {
		end := start + batchSize
		if end > len(values) {
			end = len(values)
		}
		batches = append(batches, append([]string(nil), values[start:end]...))
	}
	return batches
}

func compatibilityStrings(values []ecstypes.Compatibility) []string {
	if len(values) == 0 {
		return nil
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, string(value))
	}
	return normalizeStringList(result)
}

func containerImages(containers []ecstypes.ContainerDefinition) []string {
	result := make([]string, 0, len(containers))
	for _, container := range containers {
		if image := strings.TrimSpace(awsv2.ToString(container.Image)); image != "" {
			result = append(result, image)
		}
	}
	return normalizeStringList(result)
}

func containerSecretRefs(containers []ecstypes.ContainerDefinition) []string {
	result := []string{}
	for _, container := range containers {
		for _, secret := range container.Secrets {
			name := strings.TrimSpace(awsv2.ToString(secret.Name))
			valueFrom := strings.TrimSpace(awsv2.ToString(secret.ValueFrom))
			if name != "" && valueFrom != "" {
				result = append(result, name+"="+valueFrom)
				continue
			}
			if ref := firstNonEmptyAWSValue(name, valueFrom); ref != "" {
				result = append(result, ref)
			}
		}
		if container.RepositoryCredentials != nil {
			if credentials := strings.TrimSpace(awsv2.ToString(container.RepositoryCredentials.CredentialsParameter)); credentials != "" {
				result = append(result, "repository_credentials="+credentials)
			}
		}
	}
	return normalizeStringList(result)
}

func containerEnvironmentKeys(containers []ecstypes.ContainerDefinition) []string {
	result := []string{}
	for _, container := range containers {
		for _, env := range container.Environment {
			if name := strings.TrimSpace(awsv2.ToString(env.Name)); name != "" {
				result = append(result, name)
			}
		}
	}
	return normalizeStringList(result)
}

func copyECSTags(tags []ecstypes.Tag) map[string]string {
	if len(tags) == 0 {
		return nil
	}
	result := make(map[string]string, len(tags))
	for _, tag := range tags {
		key := strings.TrimSpace(awsv2.ToString(tag.Key))
		if key == "" {
			continue
		}
		result[key] = strings.TrimSpace(awsv2.ToString(tag.Value))
	}
	if len(result) == 0 {
		return nil
	}
	return result
}
