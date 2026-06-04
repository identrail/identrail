package aws

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/identrail/identrail/internal/providers/awscontract"
	"github.com/identrail/identrail/internal/textutil"
)

const launchTemplatePageTokenPrefix = "launch-templates:"

// EC2SDKClient defines the EC2 SDK calls required by the instance-profile adapter.
type EC2SDKClient interface {
	DescribeInstances(ctx context.Context, params *ec2.DescribeInstancesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error)
	DescribeLaunchTemplates(ctx context.Context, params *ec2.DescribeLaunchTemplatesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeLaunchTemplatesOutput, error)
	DescribeLaunchTemplateVersions(ctx context.Context, params *ec2.DescribeLaunchTemplateVersionsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeLaunchTemplateVersionsOutput, error)
}

// IAMInstanceProfileSDKClient defines the IAM SDK calls needed to resolve instance-profile roles.
type IAMInstanceProfileSDKClient interface {
	GetInstanceProfile(ctx context.Context, params *iam.GetInstanceProfileInput, optFns ...func(*iam.Options)) (*iam.GetInstanceProfileOutput, error)
}

// SDKEC2InstanceProfileAPI adapts AWS SDK EC2/IAM calls to EC2InstanceProfileAPI.
type SDKEC2InstanceProfileAPI struct {
	ec2Client EC2SDKClient
	iamClient IAMInstanceProfileSDKClient
	accountID string
	region    string
	roleCache map[string][]iamtypes.Role
}

var _ EC2InstanceProfileAPI = (*SDKEC2InstanceProfileAPI)(nil)

// NewSDKEC2InstanceProfileAPI constructs an EC2 instance-profile API backed by the AWS SDK default credential chain.
func NewSDKEC2InstanceProfileAPI(region string, profile string, accountID string) (EC2InstanceProfileAPI, error) {
	return NewSDKEC2InstanceProfileAPIWithContext(context.Background(), region, profile, accountID)
}

// NewSDKEC2InstanceProfileAPIWithContext constructs an EC2 instance-profile API using caller-provided context for config loading.
func NewSDKEC2InstanceProfileAPIWithContext(ctx context.Context, region string, profile string, accountID string) (EC2InstanceProfileAPI, error) {
	cfg, err := loadSDKConfig(ctx, region, profile)
	if err != nil {
		return nil, err
	}
	return NewSDKEC2InstanceProfileAPIFromClients(ec2.NewFromConfig(cfg), iam.NewFromConfig(cfg), accountID, region), nil
}

// NewSDKEC2InstanceProfileAPIFromAssumeRole constructs an EC2 instance-profile API for an onboarded connector role.
func NewSDKEC2InstanceProfileAPIFromAssumeRole(ctx context.Context, region string, profile string, roleARN string, externalID string, sessionName string, accountID string) (EC2InstanceProfileAPI, error) {
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
	return NewSDKEC2InstanceProfileAPIFromClients(ec2.NewFromConfig(cfg), iam.NewFromConfig(cfg), accountID, region), nil
}

// NewSDKEC2InstanceProfileAPIFromClients creates an EC2InstanceProfileAPI from provided SDK clients.
func NewSDKEC2InstanceProfileAPIFromClients(ec2Client EC2SDKClient, iamClient IAMInstanceProfileSDKClient, accountID string, region string) EC2InstanceProfileAPI {
	return &SDKEC2InstanceProfileAPI{
		ec2Client: ec2Client,
		iamClient: iamClient,
		accountID: strings.TrimSpace(accountID),
		region:    strings.TrimSpace(region),
		roleCache: map[string][]iamtypes.Role{},
	}
}

// ListInstanceProfiles returns one page of EC2 instances followed by launch-template role references.
func (a *SDKEC2InstanceProfileAPI) ListInstanceProfiles(ctx context.Context, nextToken string, pageSize int32) (EC2InstanceProfilePage, error) {
	if a.ec2Client == nil {
		return EC2InstanceProfilePage{}, fmt.Errorf("ec2 sdk client is required")
	}
	if strings.HasPrefix(nextToken, launchTemplatePageTokenPrefix) {
		return a.listLaunchTemplateProfiles(ctx, strings.TrimPrefix(nextToken, launchTemplatePageTokenPrefix), pageSize)
	}
	return a.listInstanceProfiles(ctx, nextToken, pageSize)
}

func (a *SDKEC2InstanceProfileAPI) listInstanceProfiles(ctx context.Context, nextToken string, pageSize int32) (EC2InstanceProfilePage, error) {
	input := &ec2.DescribeInstancesInput{
		MaxResults: awsv2.Int32(pageSize),
	}
	if token := strings.TrimSpace(nextToken); token != "" {
		input.NextToken = awsv2.String(token)
	}
	output, err := a.ec2Client.DescribeInstances(ctx, input)
	if err != nil {
		return EC2InstanceProfilePage{}, err
	}

	records := []EC2InstanceProfile{}
	for _, reservation := range output.Reservations {
		for _, instance := range reservation.Instances {
			if err := ctx.Err(); err != nil {
				return EC2InstanceProfilePage{}, err
			}
			record, err := a.recordFromInstance(ctx, instance)
			if err != nil {
				return EC2InstanceProfilePage{}, err
			}
			if strings.TrimSpace(record.WorkloadID) == "" && strings.TrimSpace(record.InstanceID) == "" {
				continue
			}
			records = append(records, record)
		}
	}

	page := EC2InstanceProfilePage{Records: records}
	if output.NextToken != nil && strings.TrimSpace(*output.NextToken) != "" {
		page.NextToken = strings.TrimSpace(*output.NextToken)
	} else {
		page.NextToken = launchTemplatePageTokenPrefix
	}
	return page, nil
}

func (a *SDKEC2InstanceProfileAPI) listLaunchTemplateProfiles(ctx context.Context, nextToken string, pageSize int32) (EC2InstanceProfilePage, error) {
	input := &ec2.DescribeLaunchTemplatesInput{MaxResults: awsv2.Int32(pageSize)}
	if token := strings.TrimSpace(nextToken); token != "" {
		input.NextToken = awsv2.String(token)
	}
	output, err := a.ec2Client.DescribeLaunchTemplates(ctx, input)
	if err != nil {
		return EC2InstanceProfilePage{}, err
	}

	records := []EC2InstanceProfile{}
	for _, template := range output.LaunchTemplates {
		templateRecords, err := a.recordsFromLaunchTemplate(ctx, template)
		if err != nil {
			return EC2InstanceProfilePage{}, err
		}
		records = append(records, templateRecords...)
	}

	page := EC2InstanceProfilePage{Records: records}
	if output.NextToken != nil && strings.TrimSpace(*output.NextToken) != "" {
		page.NextToken = launchTemplatePageTokenPrefix + strings.TrimSpace(*output.NextToken)
	}
	return page, nil
}

func (a *SDKEC2InstanceProfileAPI) recordFromInstance(ctx context.Context, instance ec2types.Instance) (EC2InstanceProfile, error) {
	instanceID := strings.TrimSpace(awsv2.ToString(instance.InstanceId))
	instanceARN := a.instanceARN(instanceID)
	profileARN := ""
	profileID := ""
	profileName := ""
	if instance.IamInstanceProfile != nil {
		profileARN = strings.TrimSpace(awsv2.ToString(instance.IamInstanceProfile.Arn))
		profileID = strings.TrimSpace(awsv2.ToString(instance.IamInstanceProfile.Id))
		profileName = instanceProfileNameFromARN(profileARN)
	}
	roles, err := a.rolesForInstanceProfile(ctx, profileARN, profileName)
	if err != nil {
		return EC2InstanceProfile{}, err
	}
	roleARN, roleName := firstRoleIdentity(roles)

	record := EC2InstanceProfile{
		ServiceCollectorRecord: awsServiceCollectorRecordSeed(a.accountID, a.region, "ec2_instance", instanceID, instanceName(instance.Tags, instanceID), roleARN, "describeinstances", instanceARN),
		InstanceID:             instanceID,
		InstanceARN:            instanceARN,
		InstanceName:           instanceName(instance.Tags, instanceID),
		InstanceState:          string(instanceStateName(instance.State)),
		InstanceProfileARN:     profileARN,
		InstanceProfileID:      profileID,
		InstanceProfileName:    profileName,
		RoleName:               roleName,
		Tags:                   copyEC2Tags(instance.Tags),
	}
	if instance.MetadataOptions != nil {
		record.IMDSEndpoint = string(instance.MetadataOptions.HttpEndpoint)
		record.IMDSHTTPTokens = string(instance.MetadataOptions.HttpTokens)
		record.IMDSHopLimit = awsv2.ToInt32(instance.MetadataOptions.HttpPutResponseHopLimit)
	}
	return record, nil
}

func (a *SDKEC2InstanceProfileAPI) recordsFromLaunchTemplate(ctx context.Context, template ec2types.LaunchTemplate) ([]EC2InstanceProfile, error) {
	templateID := strings.TrimSpace(awsv2.ToString(template.LaunchTemplateId))
	templateName := strings.TrimSpace(awsv2.ToString(template.LaunchTemplateName))
	versions := launchTemplateVersions(template.DefaultVersionNumber, template.LatestVersionNumber)
	if templateID == "" || len(versions) == 0 {
		return nil, nil
	}

	output, err := a.ec2Client.DescribeLaunchTemplateVersions(ctx, &ec2.DescribeLaunchTemplateVersionsInput{
		LaunchTemplateId: awsv2.String(templateID),
		Versions:         versions,
		MaxResults:       awsv2.Int32(defaultPageSize),
	})
	if err != nil {
		return nil, fmt.Errorf("describe launch template versions %s: %w", templateID, err)
	}

	records := []EC2InstanceProfile{}
	for _, version := range output.LaunchTemplateVersions {
		if version.LaunchTemplateData == nil || version.LaunchTemplateData.IamInstanceProfile == nil {
			continue
		}
		profileSpec := version.LaunchTemplateData.IamInstanceProfile
		profileARN := strings.TrimSpace(awsv2.ToString(profileSpec.Arn))
		profileName := firstNonEmptyAWSValue(strings.TrimSpace(awsv2.ToString(profileSpec.Name)), instanceProfileNameFromARN(profileARN))
		roles, err := a.rolesForInstanceProfile(ctx, profileARN, profileName)
		if err != nil {
			return nil, err
		}
		roleARN, roleName := firstRoleIdentity(roles)
		versionNumber := strconv.FormatInt(awsv2.ToInt64(version.VersionNumber), 10)
		workloadID := templateID + ":" + versionNumber
		seed := awsServiceCollectorRecordSeed(a.accountID, a.region, "ec2_launch_template", workloadID, firstNonEmptyAWSValue(templateName, templateID), roleARN, "describelaunchtemplateversions", templateID)
		seed.Confidence = 0.9
		records = append(records, EC2InstanceProfile{
			ServiceCollectorRecord: seed,
			InstanceProfileARN:     profileARN,
			InstanceProfileName:    profileName,
			RoleName:               roleName,
			LaunchTemplateID:       templateID,
			LaunchTemplateName:     templateName,
			LaunchTemplateVersion:  versionNumber,
		})
	}
	return records, nil
}

func (a *SDKEC2InstanceProfileAPI) rolesForInstanceProfile(ctx context.Context, profileARN string, profileName string) ([]iamtypes.Role, error) {
	name := firstNonEmptyAWSValue(profileName, instanceProfileNameFromARN(profileARN))
	if name == "" {
		return nil, nil
	}
	if cached, ok := a.roleCache[name]; ok {
		return cached, nil
	}
	if a.iamClient == nil {
		return nil, fmt.Errorf("iam sdk client is required to resolve instance profile %s", name)
	}
	output, err := a.iamClient.GetInstanceProfile(ctx, &iam.GetInstanceProfileInput{InstanceProfileName: awsv2.String(name)})
	if err != nil {
		return nil, fmt.Errorf("get instance profile %s: %w", name, err)
	}
	if output.InstanceProfile == nil {
		a.roleCache[name] = nil
		return nil, nil
	}
	roles := append([]iamtypes.Role(nil), output.InstanceProfile.Roles...)
	a.roleCache[name] = roles
	return roles, nil
}

func awsServiceCollectorRecordSeed(accountID, region, workloadType, workloadID, workloadName, roleARN, source, evidenceRef string) awscontract.ServiceCollectorRecord {
	return awscontract.ServiceCollectorRecord{
		AccountID:     strings.TrimSpace(accountID),
		Region:        strings.TrimSpace(region),
		Service:       ec2ServiceName,
		WorkloadID:    strings.TrimSpace(workloadID),
		WorkloadType:  strings.TrimSpace(workloadType),
		WorkloadName:  strings.TrimSpace(workloadName),
		RoleARN:       strings.TrimSpace(roleARN),
		Source:        strings.TrimSpace(source),
		EvidenceRef:   strings.TrimSpace(evidenceRef),
		Confidence:    0.95,
		CollectorName: ec2InstanceProfileCollectorName,
	}
}

func (a *SDKEC2InstanceProfileAPI) instanceARN(instanceID string) string {
	trimmed := strings.TrimSpace(instanceID)
	if trimmed == "" || strings.TrimSpace(a.accountID) == "" || strings.TrimSpace(a.region) == "" {
		return trimmed
	}
	return fmt.Sprintf("arn:aws:ec2:%s:%s:instance/%s", strings.TrimSpace(a.region), strings.TrimSpace(a.accountID), trimmed)
}

func launchTemplateVersions(defaultVersion *int64, latestVersion *int64) []string {
	seen := map[int64]struct{}{}
	versions := []string{}
	for _, value := range []*int64{defaultVersion, latestVersion} {
		if value == nil || *value <= 0 {
			continue
		}
		if _, exists := seen[*value]; exists {
			continue
		}
		seen[*value] = struct{}{}
		versions = append(versions, strconv.FormatInt(*value, 10))
	}
	return versions
}

func firstRoleIdentity(roles []iamtypes.Role) (string, string) {
	for _, role := range roles {
		arn := strings.TrimSpace(awsv2.ToString(role.Arn))
		if arn == "" {
			continue
		}
		name := strings.TrimSpace(awsv2.ToString(role.RoleName))
		if name == "" {
			name = roleNameFromARN(arn)
		}
		return arn, name
	}
	return "", ""
}

func instanceProfileNameFromARN(profileARN string) string {
	trimmed := strings.TrimSpace(profileARN)
	if trimmed == "" {
		return ""
	}
	const marker = ":instance-profile/"
	idx := strings.Index(trimmed, marker)
	if idx < 0 {
		return roleNameFromARN(trimmed)
	}
	name := trimmed[idx+len(marker):]
	if slash := strings.LastIndex(name, "/"); slash >= 0 && slash < len(name)-1 {
		name = name[slash+1:]
	}
	return strings.TrimSpace(name)
}

func instanceName(tags []ec2types.Tag, fallback string) string {
	for _, tag := range tags {
		if strings.EqualFold(strings.TrimSpace(awsv2.ToString(tag.Key)), "Name") {
			if value := strings.TrimSpace(awsv2.ToString(tag.Value)); value != "" {
				return value
			}
		}
	}
	return strings.TrimSpace(fallback)
}

func instanceStateName(state *ec2types.InstanceState) ec2types.InstanceStateName {
	if state == nil {
		return ""
	}
	return state.Name
}

func copyEC2Tags(tags []ec2types.Tag) map[string]string {
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
