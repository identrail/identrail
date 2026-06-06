package aws

import (
	"context"
	"fmt"
	"sort"
	"strings"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/codebuild"
	codebuildtypes "github.com/aws/aws-sdk-go-v2/service/codebuild/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/identrail/identrail/internal/providers"
	"github.com/identrail/identrail/internal/providers/awscontract"
	"github.com/identrail/identrail/internal/textutil"
)

// CodeBuildSDKClient defines the CodeBuild SDK calls required by the service-role adapter.
type CodeBuildSDKClient interface {
	ListProjects(ctx context.Context, params *codebuild.ListProjectsInput, optFns ...func(*codebuild.Options)) (*codebuild.ListProjectsOutput, error)
	BatchGetProjects(ctx context.Context, params *codebuild.BatchGetProjectsInput, optFns ...func(*codebuild.Options)) (*codebuild.BatchGetProjectsOutput, error)
}

// SDKCodeBuildServiceRoleAPI adapts AWS SDK CodeBuild calls to CodeBuildServiceRoleAPI.
type SDKCodeBuildServiceRoleAPI struct {
	codeBuildClient CodeBuildSDKClient
	accountID       string
	region          string
}

var _ CodeBuildServiceRoleAPI = (*SDKCodeBuildServiceRoleAPI)(nil)

// NewSDKCodeBuildServiceRoleAPI constructs a CodeBuild service-role API backed by the AWS SDK default credential chain.
func NewSDKCodeBuildServiceRoleAPI(region string, profile string, accountID string) (CodeBuildServiceRoleAPI, error) {
	return NewSDKCodeBuildServiceRoleAPIWithContext(context.Background(), region, profile, accountID)
}

// NewSDKCodeBuildServiceRoleAPIWithContext constructs a CodeBuild service-role API using caller-provided context for config loading.
func NewSDKCodeBuildServiceRoleAPIWithContext(ctx context.Context, region string, profile string, accountID string) (CodeBuildServiceRoleAPI, error) {
	cfg, err := loadSDKConfig(ctx, region, profile)
	if err != nil {
		return nil, err
	}
	return NewSDKCodeBuildServiceRoleAPIFromClient(codebuild.NewFromConfig(cfg), accountID, region), nil
}

// NewSDKCodeBuildServiceRoleAPIFromAssumeRole constructs a CodeBuild service-role API for an onboarded connector role.
func NewSDKCodeBuildServiceRoleAPIFromAssumeRole(ctx context.Context, region string, profile string, roleARN string, externalID string, sessionName string, accountID string) (CodeBuildServiceRoleAPI, error) {
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
	return NewSDKCodeBuildServiceRoleAPIFromClient(codebuild.NewFromConfig(cfg), accountID, region), nil
}

// NewSDKCodeBuildServiceRoleAPIFromClient creates a CodeBuildServiceRoleAPI from a provided CodeBuild client.
func NewSDKCodeBuildServiceRoleAPIFromClient(codeBuildClient CodeBuildSDKClient, accountID string, region string) CodeBuildServiceRoleAPI {
	return &SDKCodeBuildServiceRoleAPI{
		codeBuildClient: codeBuildClient,
		accountID:       strings.TrimSpace(accountID),
		region:          strings.TrimSpace(region),
	}
}

// ListServiceRoles returns one CodeBuild project-name page resolved to project metadata.
func (a *SDKCodeBuildServiceRoleAPI) ListServiceRoles(ctx context.Context, nextToken string, pageSize int32) (CodeBuildServiceRolePage, error) {
	if a.codeBuildClient == nil {
		return CodeBuildServiceRolePage{}, fmt.Errorf("codebuild sdk client is required")
	}

	output, err := a.codeBuildClient.ListProjects(ctx, &codebuild.ListProjectsInput{
		NextToken: codeBuildListProjectsNextToken(nextToken),
		SortBy:    codebuildtypes.ProjectSortByTypeName,
		SortOrder: codebuildtypes.SortOrderTypeAscending,
	})
	if err != nil {
		return CodeBuildServiceRolePage{}, err
	}
	if output == nil || len(output.Projects) == 0 {
		return CodeBuildServiceRolePage{NextToken: nextTokenFromCodeBuildListProjects(output)}, nil
	}

	names := normalizeStringList(output.Projects)
	records, diagnostics, err := a.batchGetProjectRecords(ctx, names)
	if err != nil {
		return CodeBuildServiceRolePage{}, err
	}
	sort.SliceStable(records, func(i, j int) bool {
		return codeBuildServiceRoleSourceID(records[i]) < codeBuildServiceRoleSourceID(records[j])
	})
	return CodeBuildServiceRolePage{Records: records, NextToken: nextTokenFromCodeBuildListProjects(output), Diagnostics: diagnostics}, nil
}

func codeBuildListProjectsNextToken(nextToken string) *string {
	trimmed := strings.TrimSpace(nextToken)
	if trimmed == "" {
		return nil
	}
	return awsv2.String(trimmed)
}

func (a *SDKCodeBuildServiceRoleAPI) batchGetProjectRecords(ctx context.Context, names []string) ([]CodeBuildServiceRole, []providers.SourceError, error) {
	records := []CodeBuildServiceRole{}
	diagnostics := []providers.SourceError{}
	const batchSize = 100
	for start := 0; start < len(names); start += batchSize {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		end := start + batchSize
		if end > len(names) {
			end = len(names)
		}
		batch := names[start:end]
		output, err := a.codeBuildClient.BatchGetProjects(ctx, &codebuild.BatchGetProjectsInput{Names: batch})
		if err != nil {
			return nil, nil, err
		}
		if output == nil {
			continue
		}
		for _, missing := range output.ProjectsNotFound {
			diagnostics = append(diagnostics, codeBuildSourceDiagnostic("project_not_found", missing, "CodeBuild project listed by ListProjects was not returned by BatchGetProjects", true))
		}
		for _, project := range output.Projects {
			if err := ctx.Err(); err != nil {
				return nil, nil, err
			}
			record := a.recordFromProject(project)
			if strings.TrimSpace(record.ProjectARN) == "" {
				diagnostics = append(diagnostics, codeBuildSourceDiagnostic("missing_project_arn", record.ProjectName, "CodeBuild project did not report a project ARN", false))
				continue
			}
			records = append(records, record)
		}
	}
	return records, diagnostics, nil
}

func (a *SDKCodeBuildServiceRoleAPI) recordFromProject(project codebuildtypes.Project) CodeBuildServiceRole {
	projectARN := strings.TrimSpace(awsv2.ToString(project.Arn))
	projectName := firstNonEmptyAWSValue(awsv2.ToString(project.Name), codeBuildProjectNameFromARN(projectARN))
	roleARN := strings.TrimSpace(awsv2.ToString(project.ServiceRole))
	record := CodeBuildServiceRole{
		ServiceCollectorRecord: awscontract.ServiceCollectorRecord{
			AccountID:     a.accountID,
			Region:        a.region,
			Service:       codeBuildServiceName,
			WorkloadID:    firstNonEmptyAWSValue(projectARN, projectName),
			WorkloadType:  "codebuild_project",
			WorkloadName:  firstNonEmptyAWSValue(projectName, codeBuildProjectNameFromARN(projectARN)),
			RoleARN:       roleARN,
			Source:        "batchgetprojects",
			EvidenceRef:   firstNonEmptyAWSValue(projectARN, roleARN),
			Confidence:    0.96,
			CollectorName: codeBuildServiceRoleCollectorName,
		},
		RoleName:           roleNameFromARN(roleARN),
		ProjectARN:         projectARN,
		ProjectName:        projectName,
		ProjectDescription: strings.TrimSpace(awsv2.ToString(project.Description)),
		ProjectVisibility:  string(project.ProjectVisibility),
		SourceVersion:      strings.TrimSpace(awsv2.ToString(project.SourceVersion)),
		KMSKeyARN:          strings.TrimSpace(awsv2.ToString(project.EncryptionKey)),
		Tags:               codeBuildTags(project.Tags),
	}
	if project.Source != nil {
		record.SourceType = string(project.Source.Type)
		record.SourceLocation = strings.TrimSpace(awsv2.ToString(project.Source.Location))
		if project.Source.Auth != nil {
			record.SourceAuthType = string(project.Source.Auth.Type)
		}
	}
	record.SourceIdentifiers = codeBuildSourceIdentifiers(project)
	record.ArtifactTypes, record.ArtifactLocations = codeBuildArtifacts(project)
	if project.Environment != nil {
		record.EnvironmentType = string(project.Environment.Type)
		record.ComputeType = string(project.Environment.ComputeType)
		record.Image = strings.TrimSpace(awsv2.ToString(project.Environment.Image))
		record.ImagePullCredentialsType = string(project.Environment.ImagePullCredentialsType)
		record.PrivilegedMode = awsv2.ToBool(project.Environment.PrivilegedMode)
		record.EnvironmentKeys, record.SecretRefs = codeBuildEnvironmentMetadata(project.Environment.EnvironmentVariables)
	}
	if project.VpcConfig != nil {
		record.VPCID = strings.TrimSpace(awsv2.ToString(project.VpcConfig.VpcId))
		record.SubnetIDs = normalizeStringList(project.VpcConfig.Subnets)
		record.SecurityGroupIDs = normalizeStringList(project.VpcConfig.SecurityGroupIds)
	}
	if project.Cache != nil {
		record.CacheType = string(project.Cache.Type)
		record.CacheLocation = strings.TrimSpace(awsv2.ToString(project.Cache.Location))
	}
	record.LogTypes = codeBuildLogTypes(project.LogsConfig)
	record.Confidence = codeBuildServiceRoleConfidence(record)
	return record
}

func nextTokenFromCodeBuildListProjects(output *codebuild.ListProjectsOutput) string {
	if output == nil {
		return ""
	}
	return strings.TrimSpace(awsv2.ToString(output.NextToken))
}

func codeBuildSourceDiagnostic(code string, sourceID string, message string, retryable bool) providers.SourceError {
	return providers.SourceError{
		Collector: codeBuildServiceRoleCollectorName,
		SourceID:  strings.TrimSpace(sourceID),
		Code:      code,
		Message:   strings.TrimSpace(message),
		Retryable: retryable,
	}
}

func codeBuildTags(tags []codebuildtypes.Tag) map[string]string {
	if len(tags) == 0 {
		return nil
	}
	result := map[string]string{}
	for _, tag := range tags {
		key := strings.TrimSpace(awsv2.ToString(tag.Key))
		value := strings.TrimSpace(awsv2.ToString(tag.Value))
		if key != "" {
			result[key] = value
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

func codeBuildSourceIdentifiers(project codebuildtypes.Project) []string {
	result := []string{}
	if project.Source != nil {
		result = append(result, codeBuildSourceIdentifier(*project.Source))
	}
	for _, source := range project.SecondarySources {
		result = append(result, codeBuildSourceIdentifier(source))
	}
	return normalizeStringList(result)
}

func codeBuildSourceIdentifier(source codebuildtypes.ProjectSource) string {
	sourceType := strings.TrimSpace(string(source.Type))
	identifier := strings.TrimSpace(awsv2.ToString(source.SourceIdentifier))
	location := strings.TrimSpace(awsv2.ToString(source.Location))
	switch {
	case sourceType != "" && identifier != "":
		return sourceType + "=" + identifier
	case sourceType != "" && location != "":
		return sourceType + "=" + location
	case sourceType != "":
		return sourceType
	default:
		return location
	}
}

func codeBuildArtifacts(project codebuildtypes.Project) ([]string, []string) {
	types := []string{}
	locations := []string{}
	addArtifact := func(artifact codebuildtypes.ProjectArtifacts) {
		if artifact.Type != "" {
			types = append(types, string(artifact.Type))
		}
		location := strings.TrimSpace(awsv2.ToString(artifact.Location))
		if location != "" {
			locations = append(locations, location)
		}
	}
	if project.Artifacts != nil {
		addArtifact(*project.Artifacts)
	}
	for _, artifact := range project.SecondaryArtifacts {
		addArtifact(artifact)
	}
	return normalizeStringList(types), normalizeStringList(locations)
}

func codeBuildEnvironmentMetadata(vars []codebuildtypes.EnvironmentVariable) ([]string, []string) {
	keys := []string{}
	secretRefs := []string{}
	for _, variable := range vars {
		name := strings.TrimSpace(awsv2.ToString(variable.Name))
		if name != "" {
			keys = append(keys, name)
		}
		valueRef := strings.TrimSpace(awsv2.ToString(variable.Value))
		varType := strings.TrimSpace(string(variable.Type))
		if valueRef == "" {
			continue
		}
		switch variable.Type {
		case codebuildtypes.EnvironmentVariableTypeParameterStore, codebuildtypes.EnvironmentVariableTypeSecretsManager:
			if name != "" && varType != "" {
				secretRefs = append(secretRefs, name+"="+varType+":"+valueRef)
			} else if varType != "" {
				secretRefs = append(secretRefs, varType+":"+valueRef)
			}
		}
	}
	return normalizeStringList(keys), normalizeStringList(secretRefs)
}

func codeBuildLogTypes(config *codebuildtypes.LogsConfig) []string {
	if config == nil {
		return nil
	}
	result := []string{}
	if config.CloudWatchLogs != nil {
		result = append(result, "cloudwatch")
	}
	if config.S3Logs != nil {
		result = append(result, "s3")
	}
	return normalizeStringList(result)
}
