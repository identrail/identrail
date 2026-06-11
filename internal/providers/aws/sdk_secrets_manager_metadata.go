package aws

import (
	"context"
	"fmt"
	"strings"
	"time"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	smtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/identrail/identrail/internal/providers"
	"github.com/identrail/identrail/internal/providers/awscontract"
	"github.com/identrail/identrail/internal/textutil"
)

type SecretsManagerSDKClient interface {
	ListSecrets(ctx context.Context, params *secretsmanager.ListSecretsInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.ListSecretsOutput, error)
	DescribeSecret(ctx context.Context, params *secretsmanager.DescribeSecretInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.DescribeSecretOutput, error)
	GetResourcePolicy(ctx context.Context, params *secretsmanager.GetResourcePolicyInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetResourcePolicyOutput, error)
	ListSecretVersionIds(ctx context.Context, params *secretsmanager.ListSecretVersionIdsInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.ListSecretVersionIdsOutput, error)
}

type SDKSecretsManagerMetadataAPI struct {
	client    SecretsManagerSDKClient
	accountID string
	region    string
}

func NewSDKSecretsManagerMetadataAPI(region string, profile string, accountID string) (SecretsManagerMetadataAPI, error) {
	return NewSDKSecretsManagerMetadataAPIWithContext(context.Background(), region, profile, accountID)
}

func NewSDKSecretsManagerMetadataAPIWithContext(ctx context.Context, region string, profile string, accountID string) (SecretsManagerMetadataAPI, error) {
	cfg, err := loadSDKConfig(ctx, region, profile)
	if err != nil {
		return nil, err
	}
	resolvedAccountID, err := awsCallerAccountID(ctx, cfg, accountID)
	if err != nil {
		return nil, err
	}
	resolvedRegion := firstNonEmptyAWSValue(strings.TrimSpace(region), strings.TrimSpace(cfg.Region))
	return NewSDKSecretsManagerMetadataAPIFromClient(secretsmanager.NewFromConfig(cfg), resolvedAccountID, resolvedRegion), nil
}

func NewSDKSecretsManagerMetadataAPIFromAssumeRole(ctx context.Context, region string, profile string, roleARN string, externalID string, sessionName string, accountID string) (SecretsManagerMetadataAPI, error) {
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
	return NewSDKSecretsManagerMetadataAPIFromClient(secretsmanager.NewFromConfig(cfg), resolvedAccountID, resolvedRegion), nil
}

func NewSDKSecretsManagerMetadataAPIFromClient(client SecretsManagerSDKClient, accountID string, region string) SecretsManagerMetadataAPI {
	return &SDKSecretsManagerMetadataAPI{
		client:    client,
		accountID: strings.TrimSpace(accountID),
		region:    strings.TrimSpace(region),
	}
}

func (a *SDKSecretsManagerMetadataAPI) ListSecretMetadata(ctx context.Context, nextToken string, pageSize int32) (SecretsManagerMetadataPage, error) {
	if a.client == nil {
		return SecretsManagerMetadataPage{}, fmt.Errorf("secrets manager metadata api requires client")
	}
	input := &secretsmanager.ListSecretsInput{
		NextToken:  stringPtrOrNil(nextToken),
		MaxResults: awsv2.Int32(pageSize),
	}
	if pageSize <= 0 {
		input.MaxResults = awsv2.Int32(defaultPageSize)
	}
	output, err := a.client.ListSecrets(ctx, input)
	if err != nil {
		return SecretsManagerMetadataPage{}, err
	}
	if output == nil {
		return SecretsManagerMetadataPage{}, nil
	}
	page := SecretsManagerMetadataPage{
		Records:   make([]SecretsManagerSecretMetadata, 0, len(output.SecretList)),
		NextToken: strings.TrimSpace(awsv2.ToString(output.NextToken)),
	}
	for _, entry := range output.SecretList {
		record := secretMetadataFromListEntry(entry, a.accountID, a.region)
		secretID := firstNonEmptyAWSValue(record.SecretARN, record.SecretName)
		if secretID == "" {
			page.Diagnostics = append(page.Diagnostics, secretsManagerMetadataDiagnostic("secrets_manager_secret_id_missing", "listsecrets", "skipped Secrets Manager record without ARN or name", false))
			continue
		}
		a.enrichSecretMetadata(ctx, secretID, &record, &page.Diagnostics)
		page.Records = append(page.Records, record)
	}
	return page, nil
}

func (a *SDKSecretsManagerMetadataAPI) enrichSecretMetadata(ctx context.Context, secretID string, record *SecretsManagerSecretMetadata, diagnostics *[]providers.SourceError) {
	describe, err := a.client.DescribeSecret(ctx, &secretsmanager.DescribeSecretInput{SecretId: awsv2.String(secretID)})
	if err != nil {
		*diagnostics = append(*diagnostics, secretsManagerMetadataDiagnostic("secrets_manager_describe_secret_failed", secretID, fmt.Sprintf("DescribeSecret failed: %v", err), true))
	} else if describe != nil {
		mergeSecretDescribe(record, describe, a.accountID, a.region)
	}
	policy, err := a.client.GetResourcePolicy(ctx, &secretsmanager.GetResourcePolicyInput{SecretId: awsv2.String(secretID)})
	if err != nil {
		if !secretsManagerNoResourcePolicy(err) {
			*diagnostics = append(*diagnostics, secretsManagerMetadataDiagnostic("secrets_manager_resource_policy_failed", secretID, fmt.Sprintf("GetResourcePolicy failed: %v", err), true))
		}
	} else if policy != nil && strings.TrimSpace(awsv2.ToString(policy.ResourcePolicy)) != "" {
		grants, count, parseErr := parseSecretsManagerResourcePolicyGrants(awsv2.ToString(policy.ResourcePolicy), record.AccountID)
		if parseErr != nil {
			*diagnostics = append(*diagnostics, secretsManagerMetadataDiagnostic("secrets_manager_resource_policy_parse_failed", secretID, fmt.Sprintf("parse resource policy failed: %v", parseErr), false))
		} else {
			record.HasResourcePolicy = true
			record.ResourcePolicyStatementCount = count
			record.IdentityGrants = grants
		}
	}
	versionStages, versionDiagnostics := a.secretVersionStages(ctx, secretID)
	*diagnostics = append(*diagnostics, versionDiagnostics...)
	record.VersionStages = versionStages
}

func secretMetadataFromListEntry(entry smtypes.SecretListEntry, accountID string, region string) SecretsManagerSecretMetadata {
	record := SecretsManagerSecretMetadata{
		SecretARN:          strings.TrimSpace(awsv2.ToString(entry.ARN)),
		SecretName:         strings.TrimSpace(awsv2.ToString(entry.Name)),
		DescriptionPresent: strings.TrimSpace(awsv2.ToString(entry.Description)) != "",
		KMSKeyID:           strings.TrimSpace(awsv2.ToString(entry.KmsKeyId)),
		RotationEnabled:    awsv2.ToBool(entry.RotationEnabled),
		RotationLambdaARN:  strings.TrimSpace(awsv2.ToString(entry.RotationLambdaARN)),
		OwningService:      strings.TrimSpace(awsv2.ToString(entry.OwningService)),
		PrimaryRegion:      strings.TrimSpace(awsv2.ToString(entry.PrimaryRegion)),
		Tags:               secretsManagerTags(entry.Tags),
		ServiceCollectorRecord: awscontract.ServiceCollectorRecord{
			AccountID: strings.TrimSpace(accountID),
			Region:    strings.TrimSpace(region),
			Service:   secretsManagerServiceName,
		},
	}
	if entry.RotationRules != nil {
		record.AutomaticallyAfterDays = awsv2.ToInt64(entry.RotationRules.AutomaticallyAfterDays)
		record.RotationInterval = awsv2.ToInt64(entry.RotationRules.AutomaticallyAfterDays)
	}
	record.CreatedAt = awsTimeString(entry.CreatedDate)
	record.LastChangedAt = awsTimeString(entry.LastChangedDate)
	record.LastAccessedAt = awsDateString(entry.LastAccessedDate)
	record.LastRotatedAt = awsTimeString(entry.LastRotatedDate)
	record.DeletedAt = awsTimeString(entry.DeletedDate)
	for versionID, stages := range entry.SecretVersionsToStages {
		record.VersionStages = append(record.VersionStages, SecretsManagerVersionStage{
			VersionID: strings.TrimSpace(versionID),
			Stages:    normalizeStringList(stages),
		})
	}
	return record
}

func mergeSecretDescribe(record *SecretsManagerSecretMetadata, describe *secretsmanager.DescribeSecretOutput, accountID string, region string) {
	record.SecretARN = firstNonEmptyAWSValue(awsv2.ToString(describe.ARN), record.SecretARN)
	record.SecretName = firstNonEmptyAWSValue(awsv2.ToString(describe.Name), record.SecretName)
	record.DescriptionPresent = record.DescriptionPresent || strings.TrimSpace(awsv2.ToString(describe.Description)) != ""
	record.KMSKeyID = firstNonEmptyAWSValue(awsv2.ToString(describe.KmsKeyId), record.KMSKeyID)
	record.RotationEnabled = awsv2.ToBool(describe.RotationEnabled)
	record.RotationLambdaARN = firstNonEmptyAWSValue(awsv2.ToString(describe.RotationLambdaARN), record.RotationLambdaARN)
	record.OwningService = firstNonEmptyAWSValue(awsv2.ToString(describe.OwningService), record.OwningService)
	record.PrimaryRegion = firstNonEmptyAWSValue(awsv2.ToString(describe.PrimaryRegion), record.PrimaryRegion)
	record.AccountID = firstNonEmptyAWSValue(accountID, record.AccountID, accountIDFromARN(record.SecretARN))
	record.Region = firstNonEmptyAWSValue(region, record.Region, regionFromARN(record.SecretARN))
	if tags := secretsManagerTags(describe.Tags); len(tags) > 0 {
		record.Tags = tags
	}
	if describe.RotationRules != nil {
		record.AutomaticallyAfterDays = awsv2.ToInt64(describe.RotationRules.AutomaticallyAfterDays)
		record.RotationInterval = awsv2.ToInt64(describe.RotationRules.AutomaticallyAfterDays)
	}
	record.CreatedAt = firstNonEmptyAWSValue(awsTimeString(describe.CreatedDate), record.CreatedAt)
	record.LastChangedAt = firstNonEmptyAWSValue(awsTimeString(describe.LastChangedDate), record.LastChangedAt)
	record.LastAccessedAt = firstNonEmptyAWSValue(awsDateString(describe.LastAccessedDate), record.LastAccessedAt)
	record.LastRotatedAt = firstNonEmptyAWSValue(awsTimeString(describe.LastRotatedDate), record.LastRotatedAt)
	record.DeletedAt = firstNonEmptyAWSValue(awsTimeString(describe.DeletedDate), record.DeletedAt)
	record.ReplicaRegions = secretReplicaRegions(describe.ReplicationStatus)
}

func (a *SDKSecretsManagerMetadataAPI) secretVersionStages(ctx context.Context, secretID string) ([]SecretsManagerVersionStage, []providers.SourceError) {
	diagnostics := []providers.SourceError{}
	stages := []SecretsManagerVersionStage{}
	nextToken := ""
	for page := 1; ; page++ {
		if page > defaultMaxPages {
			diagnostics = append(diagnostics, secretsManagerMetadataDiagnostic("secrets_manager_versions_page_limit_exceeded", secretID, "ListSecretVersionIds paginated beyond max pages", false))
			break
		}
		output, err := a.client.ListSecretVersionIds(ctx, &secretsmanager.ListSecretVersionIdsInput{
			SecretId:  awsv2.String(secretID),
			NextToken: stringPtrOrNil(nextToken),
		})
		if err != nil {
			diagnostics = append(diagnostics, secretsManagerMetadataDiagnostic("secrets_manager_versions_failed", secretID, fmt.Sprintf("ListSecretVersionIds failed: %v", err), true))
			break
		}
		if output == nil {
			break
		}
		for _, version := range output.Versions {
			stages = append(stages, SecretsManagerVersionStage{
				VersionID:    strings.TrimSpace(awsv2.ToString(version.VersionId)),
				Stages:       normalizeStringList(version.VersionStages),
				CreatedAt:    awsTimeString(version.CreatedDate),
				LastAccessed: awsDateString(version.LastAccessedDate),
				KMSKeyIDs:    normalizeStringList(version.KmsKeyIds),
			})
		}
		nextToken = strings.TrimSpace(awsv2.ToString(output.NextToken))
		if nextToken == "" {
			break
		}
	}
	return normalizeSecretsManagerVersionStages(stages), diagnostics
}

func secretsManagerTags(tags []smtypes.Tag) map[string]string {
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

func secretReplicaRegions(replicas []smtypes.ReplicationStatusType) []SecretsManagerReplicaRegion {
	if len(replicas) == 0 {
		return nil
	}
	out := make([]SecretsManagerReplicaRegion, 0, len(replicas))
	for _, replica := range replicas {
		out = append(out, SecretsManagerReplicaRegion{
			Region:         strings.TrimSpace(awsv2.ToString(replica.Region)),
			KMSKeyID:       strings.TrimSpace(awsv2.ToString(replica.KmsKeyId)),
			Status:         string(replica.Status),
			StatusMessage:  strings.TrimSpace(awsv2.ToString(replica.StatusMessage)),
			LastAccessedAt: awsDateString(replica.LastAccessedDate),
		})
	}
	return normalizeSecretsManagerReplicaRegions(out)
}

func awsTimeString(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format("2006-01-02T15:04:05Z")
}

func awsDateString(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format("2006-01-02")
}

func secretsManagerNoResourcePolicy(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "resourcenotfoundexception") || strings.Contains(msg, "resource policy") && strings.Contains(msg, "not found")
}

// awsCallerAccountID resolves the effective AWS account id, preferring the
// configured value and falling back to STS GetCallerIdentity.
func awsCallerAccountID(ctx context.Context, cfg awsv2.Config, accountID string) (string, error) {
	trimmed := strings.TrimSpace(accountID)
	if trimmed != "" {
		return trimmed, nil
	}
	identity, err := sts.NewFromConfig(cfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", fmt.Errorf("read AWS caller identity for account id: %w", err)
	}
	resolved := strings.TrimSpace(awsv2.ToString(identity.Account))
	if resolved == "" {
		return "", fmt.Errorf("read AWS caller identity for account id: empty account id")
	}
	return resolved, nil
}
