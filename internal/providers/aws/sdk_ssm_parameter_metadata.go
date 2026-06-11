package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/identrail/identrail/internal/providers"
	"github.com/identrail/identrail/internal/providers/awscontract"
	"github.com/identrail/identrail/internal/textutil"
)

// SSMSDKClient is the metadata-only surface of the AWS SSM SDK this collector
// is allowed to call. GetParameter, GetParameters, GetParametersByPath, and
// GetParameterHistory are intentionally absent because they return values.
type SSMSDKClient interface {
	DescribeParameters(ctx context.Context, params *ssm.DescribeParametersInput, optFns ...func(*ssm.Options)) (*ssm.DescribeParametersOutput, error)
	ListTagsForResource(ctx context.Context, params *ssm.ListTagsForResourceInput, optFns ...func(*ssm.Options)) (*ssm.ListTagsForResourceOutput, error)
}

type SDKSSMParameterMetadataAPI struct {
	client    SSMSDKClient
	accountID string
	region    string
}

func NewSDKSSMParameterMetadataAPI(region string, profile string, accountID string) (SSMParameterMetadataAPI, error) {
	return NewSDKSSMParameterMetadataAPIWithContext(context.Background(), region, profile, accountID)
}

func NewSDKSSMParameterMetadataAPIWithContext(ctx context.Context, region string, profile string, accountID string) (SSMParameterMetadataAPI, error) {
	cfg, err := loadSDKConfig(ctx, region, profile)
	if err != nil {
		return nil, err
	}
	resolvedAccountID, err := awsCallerAccountID(ctx, cfg, accountID)
	if err != nil {
		return nil, err
	}
	resolvedRegion := firstNonEmptyAWSValue(strings.TrimSpace(region), strings.TrimSpace(cfg.Region))
	return NewSDKSSMParameterMetadataAPIFromClient(ssm.NewFromConfig(cfg), resolvedAccountID, resolvedRegion), nil
}

func NewSDKSSMParameterMetadataAPIFromAssumeRole(ctx context.Context, region string, profile string, roleARN string, externalID string, sessionName string, accountID string) (SSMParameterMetadataAPI, error) {
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
	resolvedAccountID, err := awsCallerAccountID(ctx, cfg, accountID)
	if err != nil {
		return nil, err
	}
	resolvedRegion := firstNonEmptyAWSValue(strings.TrimSpace(region), strings.TrimSpace(cfg.Region))
	return NewSDKSSMParameterMetadataAPIFromClient(ssm.NewFromConfig(cfg), resolvedAccountID, resolvedRegion), nil
}

func NewSDKSSMParameterMetadataAPIFromClient(client SSMSDKClient, accountID string, region string) SSMParameterMetadataAPI {
	return &SDKSSMParameterMetadataAPI{
		client:    client,
		accountID: strings.TrimSpace(accountID),
		region:    strings.TrimSpace(region),
	}
}

// ssmDescribeParametersMaxResults is the hard ceiling AWS enforces on
// DescribeParameters MaxResults. The shared scanner default page size (100)
// exceeds it, so requests must be clamped or AWS rejects them with a
// ValidationException before any parameters are inventoried.
const ssmDescribeParametersMaxResults int32 = 50

func (a *SDKSSMParameterMetadataAPI) ListParameterMetadata(ctx context.Context, nextToken string, pageSize int32) (SSMParameterMetadataPage, error) {
	if a.client == nil {
		return SSMParameterMetadataPage{}, fmt.Errorf("ssm parameter metadata api requires client")
	}
	if pageSize <= 0 {
		pageSize = defaultPageSize
	}
	if pageSize > ssmDescribeParametersMaxResults {
		pageSize = ssmDescribeParametersMaxResults
	}
	input := &ssm.DescribeParametersInput{
		NextToken:  stringPtrOrNil(nextToken),
		MaxResults: awsv2.Int32(pageSize),
	}
	output, err := a.client.DescribeParameters(ctx, input)
	if err != nil {
		return SSMParameterMetadataPage{}, err
	}
	if output == nil {
		return SSMParameterMetadataPage{}, nil
	}
	page := SSMParameterMetadataPage{
		Records:   make([]SSMParameterMetadata, 0, len(output.Parameters)),
		NextToken: strings.TrimSpace(awsv2.ToString(output.NextToken)),
	}
	for _, entry := range output.Parameters {
		record := ssmParameterMetadataFromEntry(entry, a.accountID, a.region)
		if record.ParameterARN == "" && record.ParameterName == "" {
			page.Diagnostics = append(page.Diagnostics, ssmParameterMetadataDiagnostic("ssm_parameter_id_missing", "describeparameters", "skipped SSM parameter record without ARN or name", false))
			continue
		}
		a.enrichParameterTags(ctx, &record, &page.Diagnostics)
		page.Records = append(page.Records, record)
	}
	return page, nil
}

func (a *SDKSSMParameterMetadataAPI) enrichParameterTags(ctx context.Context, record *SSMParameterMetadata, diagnostics *[]providers.SourceError) {
	name := strings.TrimSpace(record.ParameterName)
	if name == "" {
		return
	}
	output, err := a.client.ListTagsForResource(ctx, &ssm.ListTagsForResourceInput{
		ResourceType: ssmtypes.ResourceTypeForTaggingParameter,
		ResourceId:   awsv2.String(name),
	})
	if err != nil {
		*diagnostics = append(*diagnostics, ssmParameterMetadataDiagnostic("ssm_parameter_tags_failed", name, fmt.Sprintf("ListTagsForResource failed: %v", err), true))
		return
	}
	if output == nil {
		return
	}
	record.Tags = ssmParameterTags(output.TagList)
}

func ssmParameterMetadataFromEntry(entry ssmtypes.ParameterMetadata, accountID string, region string) SSMParameterMetadata {
	record := SSMParameterMetadata{
		ParameterARN:          strings.TrimSpace(awsv2.ToString(entry.ARN)),
		ParameterName:         strings.TrimSpace(awsv2.ToString(entry.Name)),
		ParameterType:         string(entry.Type),
		Tier:                  string(entry.Tier),
		DataType:              strings.TrimSpace(awsv2.ToString(entry.DataType)),
		Version:               entry.Version,
		DescriptionPresent:    strings.TrimSpace(awsv2.ToString(entry.Description)) != "",
		AllowedPatternPresent: strings.TrimSpace(awsv2.ToString(entry.AllowedPattern)) != "",
		KMSKeyID:              strings.TrimSpace(awsv2.ToString(entry.KeyId)),
		LastModifiedAt:        awsTimeString(entry.LastModifiedDate),
		LastModifiedBy:        strings.TrimSpace(awsv2.ToString(entry.LastModifiedUser)),
		Policies:              ssmParameterPoliciesFromInline(entry.Policies),
		ServiceCollectorRecord: awscontract.ServiceCollectorRecord{
			AccountID: strings.TrimSpace(accountID),
			Region:    strings.TrimSpace(region),
			Service:   ssmServiceName,
		},
	}
	return record
}

// ssmParameterPoliciesFromInline converts the policy summaries returned by
// DescribeParameters into the metadata-only envelope. Only the policy type,
// status, and expiration timestamp survive; raw policy text is dropped.
func ssmParameterPoliciesFromInline(policies []ssmtypes.ParameterInlinePolicy) []SSMParameterPolicy {
	if len(policies) == 0 {
		return nil
	}
	out := make([]SSMParameterPolicy, 0, len(policies))
	for _, policy := range policies {
		summary := SSMParameterPolicy{
			PolicyType:   strings.TrimSpace(awsv2.ToString(policy.PolicyType)),
			PolicyStatus: strings.TrimSpace(awsv2.ToString(policy.PolicyStatus)),
		}
		text := strings.TrimSpace(awsv2.ToString(policy.PolicyText))
		if summary.PolicyType == "" || strings.EqualFold(summary.PolicyType, "Expiration") {
			parsedType, expiresAt := parseSSMParameterPolicyText(text)
			if summary.PolicyType == "" {
				summary.PolicyType = parsedType
			}
			if strings.EqualFold(summary.PolicyType, "Expiration") {
				summary.ExpiresAt = expiresAt
			}
		}
		if summary.PolicyType == "" && summary.PolicyStatus == "" {
			continue
		}
		out = append(out, summary)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseSSMParameterPolicyText extracts the policy type and the expiration
// timestamp attribute from a parameter policy document. Expiration timestamps
// are lifecycle metadata; no other attribute is persisted.
func parseSSMParameterPolicyText(text string) (string, string) {
	if strings.TrimSpace(text) == "" {
		return "", ""
	}
	var doc struct {
		Type       string `json:"Type"`
		Attributes struct {
			Timestamp string `json:"Timestamp"`
		} `json:"Attributes"`
	}
	if err := json.Unmarshal([]byte(text), &doc); err != nil {
		return "", ""
	}
	return strings.TrimSpace(doc.Type), strings.TrimSpace(doc.Attributes.Timestamp)
}

func ssmParameterTags(tags []ssmtypes.Tag) map[string]string {
	out := map[string]string{}
	for _, tag := range tags {
		key := strings.TrimSpace(awsv2.ToString(tag.Key))
		if key == "" {
			continue
		}
		out[key] = strings.TrimSpace(awsv2.ToString(tag.Value))
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
