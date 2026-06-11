package aws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/identrail/identrail/internal/providers"
	"github.com/identrail/identrail/internal/providers/awscontract"
	"github.com/identrail/identrail/internal/textutil"
)

// ECRSDKClient is the metadata-only subset of the ECR SDK. BatchGetImage,
// GetDownloadUrlForLayer, image manifest APIs, and scan finding detail APIs are
// intentionally absent.
type ECRSDKClient interface {
	DescribeRepositories(ctx context.Context, params *ecr.DescribeRepositoriesInput, optFns ...func(*ecr.Options)) (*ecr.DescribeRepositoriesOutput, error)
	DescribeImages(ctx context.Context, params *ecr.DescribeImagesInput, optFns ...func(*ecr.Options)) (*ecr.DescribeImagesOutput, error)
	GetRepositoryPolicy(ctx context.Context, params *ecr.GetRepositoryPolicyInput, optFns ...func(*ecr.Options)) (*ecr.GetRepositoryPolicyOutput, error)
	GetLifecyclePolicy(ctx context.Context, params *ecr.GetLifecyclePolicyInput, optFns ...func(*ecr.Options)) (*ecr.GetLifecyclePolicyOutput, error)
	GetRegistryScanningConfiguration(ctx context.Context, params *ecr.GetRegistryScanningConfigurationInput, optFns ...func(*ecr.Options)) (*ecr.GetRegistryScanningConfigurationOutput, error)
	ListTagsForResource(ctx context.Context, params *ecr.ListTagsForResourceInput, optFns ...func(*ecr.Options)) (*ecr.ListTagsForResourceOutput, error)
}

type SDKECRRepositoryMetadataAPI struct {
	client    ECRSDKClient
	accountID string
	region    string
}

var ecrRepositoryScanningFilterRegexes sync.Map

func NewSDKECRRepositoryMetadataAPI(region string, profile string, accountID string) (ECRRepositoryMetadataAPI, error) {
	return NewSDKECRRepositoryMetadataAPIWithContext(context.Background(), region, profile, accountID)
}

func NewSDKECRRepositoryMetadataAPIWithContext(ctx context.Context, region string, profile string, accountID string) (ECRRepositoryMetadataAPI, error) {
	cfg, err := loadSDKConfig(ctx, region, profile)
	if err != nil {
		return nil, err
	}
	resolvedAccountID, err := awsCallerAccountID(ctx, cfg, accountID)
	if err != nil {
		return nil, err
	}
	resolvedRegion := firstNonEmptyAWSValue(strings.TrimSpace(region), strings.TrimSpace(cfg.Region))
	return NewSDKECRRepositoryMetadataAPIFromClient(ecr.NewFromConfig(cfg), resolvedAccountID, resolvedRegion), nil
}

func NewSDKECRRepositoryMetadataAPIFromAssumeRole(ctx context.Context, region string, profile string, roleARN string, externalID string, sessionName string, accountID string) (ECRRepositoryMetadataAPI, error) {
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
	return NewSDKECRRepositoryMetadataAPIFromClient(ecr.NewFromConfig(cfg), resolvedAccountID, resolvedRegion), nil
}

func NewSDKECRRepositoryMetadataAPIFromClient(client ECRSDKClient, accountID string, region string) ECRRepositoryMetadataAPI {
	return &SDKECRRepositoryMetadataAPI{
		client:    client,
		accountID: strings.TrimSpace(accountID),
		region:    strings.TrimSpace(region),
	}
}

func (a *SDKECRRepositoryMetadataAPI) ListRepositoryMetadata(ctx context.Context, nextToken string, pageSize int32) (ECRRepositoryMetadataPage, error) {
	if a.client == nil {
		return ECRRepositoryMetadataPage{}, fmt.Errorf("ecr repository metadata api requires client")
	}
	if pageSize <= 0 {
		pageSize = defaultPageSize
	}
	output, err := a.client.DescribeRepositories(ctx, &ecr.DescribeRepositoriesInput{
		NextToken:  stringPtrOrNil(nextToken),
		MaxResults: awsv2.Int32(pageSize),
	})
	if err != nil {
		return ECRRepositoryMetadataPage{}, err
	}
	if output == nil {
		return ECRRepositoryMetadataPage{}, nil
	}
	page := ECRRepositoryMetadataPage{
		Records:   make([]ECRRepositoryMetadata, 0, len(output.Repositories)),
		NextToken: strings.TrimSpace(awsv2.ToString(output.NextToken)),
	}
	scanningEnabled := false
	scanningKnown := false
	var scanningRules []ecrtypes.RegistryScanningRule
	if scan, scanErr := a.client.GetRegistryScanningConfiguration(ctx, &ecr.GetRegistryScanningConfigurationInput{}); scanErr == nil && scan != nil && scan.ScanningConfiguration != nil {
		scanningKnown = true
		scanningEnabled = scan.ScanningConfiguration.ScanType == ecrtypes.ScanTypeEnhanced
		scanningRules = scan.ScanningConfiguration.Rules
	} else if scanErr != nil {
		page.Diagnostics = append(page.Diagnostics, ecrRepositoryMetadataDiagnostic("ecr_registry_scanning_failed", "registry", fmt.Sprintf("GetRegistryScanningConfiguration failed: %v", scanErr), true))
	}
	for _, repository := range output.Repositories {
		record := ecrRepositoryMetadataFromRepository(repository, a.accountID, a.region)
		record.EnhancedScanningKnown = scanningKnown
		record.EnhancedScanningEnabled = ecrRepositoryEnhancedScanningEnabled(record.RepositoryName, scanningEnabled, scanningRules)
		a.enrichRepository(ctx, &record, &page.Diagnostics)
		page.Records = append(page.Records, record)
	}
	return page, nil
}

func (a *SDKECRRepositoryMetadataAPI) enrichRepository(ctx context.Context, record *ECRRepositoryMetadata, diagnostics *[]providers.SourceError) {
	name := strings.TrimSpace(record.RepositoryName)
	if name == "" {
		return
	}
	if output, err := a.client.GetRepositoryPolicy(ctx, &ecr.GetRepositoryPolicyInput{RepositoryName: awsv2.String(name)}); err == nil && output != nil {
		record.HasRepositoryPolicy = strings.TrimSpace(awsv2.ToString(output.PolicyText)) != ""
		record.RepositoryPolicyStatement = countJSONPolicyStatements(awsv2.ToString(output.PolicyText))
	} else if err != nil && !isRepositoryPolicyNotFound(err) {
		*diagnostics = append(*diagnostics, ecrRepositoryMetadataDiagnostic("ecr_repository_policy_failed", name, fmt.Sprintf("GetRepositoryPolicy failed: %v", err), true))
	}
	if output, err := a.client.GetLifecyclePolicy(ctx, &ecr.GetLifecyclePolicyInput{RepositoryName: awsv2.String(name)}); err == nil && output != nil {
		record.HasLifecyclePolicy = strings.TrimSpace(awsv2.ToString(output.LifecyclePolicyText)) != ""
		record.LifecycleRuleCount = countECRLifecycleRules(awsv2.ToString(output.LifecyclePolicyText))
	} else if err != nil && !isLifecyclePolicyNotFound(err) {
		*diagnostics = append(*diagnostics, ecrRepositoryMetadataDiagnostic("ecr_lifecycle_policy_failed", name, fmt.Sprintf("GetLifecyclePolicy failed: %v", err), true))
	}
	nextToken := ""
	for {
		output, err := a.client.DescribeImages(ctx, &ecr.DescribeImagesInput{
			RepositoryName: awsv2.String(name),
			MaxResults:     awsv2.Int32(100),
			NextToken:      stringPtrOrNil(nextToken),
		})
		if err != nil {
			*diagnostics = append(*diagnostics, ecrRepositoryMetadataDiagnostic("ecr_describe_images_failed", name, fmt.Sprintf("DescribeImages failed: %v", err), true))
			break
		}
		if output != nil {
			for _, detail := range output.ImageDetails {
				record.ImageCount++
				if len(detail.ImageTags) > 0 {
					record.TaggedImageCount++
				} else {
					record.UntaggedImageCount++
				}
				if pushed := awsTimeString(detail.ImagePushedAt); pushed > record.LastPushedAt {
					record.LastPushedAt = pushed
				}
			}
			nextToken = strings.TrimSpace(awsv2.ToString(output.NextToken))
			if nextToken == "" {
				break
			}
		}
		if output == nil {
			break
		}
	}
	if output, err := a.client.ListTagsForResource(ctx, &ecr.ListTagsForResourceInput{ResourceArn: awsv2.String(record.RepositoryARN)}); err == nil && output != nil {
		record.Tags = ecrTags(output.Tags)
	} else if err != nil {
		*diagnostics = append(*diagnostics, ecrRepositoryMetadataDiagnostic("ecr_tags_failed", name, fmt.Sprintf("ListTagsForResource failed: %v", err), true))
	}
}

func isRepositoryPolicyNotFound(err error) bool {
	var policyErr *ecrtypes.RepositoryPolicyNotFoundException
	return errors.As(err, &policyErr)
}

func isLifecyclePolicyNotFound(err error) bool {
	var lifecycleErr *ecrtypes.LifecyclePolicyNotFoundException
	return errors.As(err, &lifecycleErr)
}

func ecrRepositoryEnhancedScanningEnabled(repositoryName string, scanningEnabled bool, scanningRules []ecrtypes.RegistryScanningRule) bool {
	if !scanningEnabled || strings.TrimSpace(repositoryName) == "" {
		return false
	}
	repoName := strings.TrimSpace(repositoryName)
	if len(scanningRules) == 0 {
		return true
	}
	for _, rule := range scanningRules {
		for _, filter := range rule.RepositoryFilters {
			if filter.FilterType != ecrtypes.ScanningRepositoryFilterTypeWildcard {
				continue
			}
			pattern := strings.TrimSpace(awsv2.ToString(filter.Filter))
			if pattern == "" {
				continue
			}
			if ecrRepositoryScanningFilterMatchesAWS(pattern, repoName) {
				return true
			}
		}
	}
	return false
}

func ecrRepositoryScanningFilterMatchesAWS(pattern, repositoryName string) bool {
	filter := strings.TrimSpace(strings.ToLower(pattern))
	repo := strings.TrimSpace(strings.ToLower(repositoryName))
	if filter == "" || repo == "" {
		return false
	}
	if !strings.Contains(filter, "*") {
		return strings.Contains(repo, filter)
	}

	patternRe := regexp.QuoteMeta(filter)
	patternRe = strings.ReplaceAll(patternRe, "\\*", ".*")
	if cached, ok := ecrRepositoryScanningFilterRegexes.Load(patternRe); ok {
		if compiled, ok := cached.(*regexp.Regexp); ok {
			return compiled.MatchString(repo)
		}
	}
	compiled, err := regexp.Compile("^" + patternRe + "$")
	if err != nil {
		return false
	}
	cached, loaded := ecrRepositoryScanningFilterRegexes.LoadOrStore(patternRe, compiled)
	if loaded {
		if compiledCached, ok := cached.(*regexp.Regexp); ok {
			return compiledCached.MatchString(repo)
		}
	}
	return compiled.MatchString(repo)
}

func ecrRepositoryMetadataFromRepository(repository ecrtypes.Repository, accountID string, region string) ECRRepositoryMetadata {
	encryptionType := ""
	kmsKey := ""
	if repository.EncryptionConfiguration != nil {
		encryptionType = string(repository.EncryptionConfiguration.EncryptionType)
		kmsKey = awsv2.ToString(repository.EncryptionConfiguration.KmsKey)
	}
	scanOnPush := false
	if repository.ImageScanningConfiguration != nil {
		scanOnPush = repository.ImageScanningConfiguration.ScanOnPush
	}
	return ECRRepositoryMetadata{
		RepositoryARN:      strings.TrimSpace(awsv2.ToString(repository.RepositoryArn)),
		RepositoryName:     strings.TrimSpace(awsv2.ToString(repository.RepositoryName)),
		RegistryID:         firstNonEmptyAWSValue(awsv2.ToString(repository.RegistryId), accountID),
		RepositoryURI:      strings.TrimSpace(awsv2.ToString(repository.RepositoryUri)),
		ImageTagMutability: string(repository.ImageTagMutability),
		EncryptionType:     encryptionType,
		KMSKeyID:           strings.TrimSpace(kmsKey),
		ScanOnPush:         scanOnPush,
		CreatedAt:          awsTimeString(repository.CreatedAt),
		ServiceCollectorRecord: awscontract.ServiceCollectorRecord{
			AccountID: strings.TrimSpace(accountID),
			Region:    strings.TrimSpace(region),
			Service:   ecrServiceName,
		},
	}
}

func countJSONPolicyStatements(raw string) int {
	if strings.TrimSpace(raw) == "" {
		return 0
	}
	var doc struct {
		Statement json.RawMessage `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(raw), &doc); err != nil || len(doc.Statement) == 0 {
		return 0
	}
	var statements []json.RawMessage
	if err := json.Unmarshal(doc.Statement, &statements); err == nil {
		return len(statements)
	}
	var statement map[string]any
	if err := json.Unmarshal(doc.Statement, &statement); err == nil && len(statement) > 0 {
		return 1
	}
	return 0
}

func countECRLifecycleRules(raw string) int {
	if strings.TrimSpace(raw) == "" {
		return 0
	}
	var doc struct {
		Rules []any `json:"rules"`
	}
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		return 0
	}
	return len(doc.Rules)
}

func ecrTags(tags []ecrtypes.Tag) map[string]string {
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
