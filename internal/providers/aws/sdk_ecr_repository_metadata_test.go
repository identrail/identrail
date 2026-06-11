package aws

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
)

type fakeECRSDKClient struct {
	repositoriesErr error
	repositories    []ecrtypes.Repository
	policyErr       error
	lifecycleErr    error
	imagesErr       error
	tagsErr         error
	scanningErr     error
	scanningConfig  *ecrtypes.RegistryScanningConfiguration
}

func (f fakeECRSDKClient) DescribeRepositories(ctx context.Context, params *ecr.DescribeRepositoriesInput, optFns ...func(*ecr.Options)) (*ecr.DescribeRepositoriesOutput, error) {
	if f.repositoriesErr != nil {
		return nil, f.repositoriesErr
	}
	createdAt := time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)
	repositories := f.repositories
	if repositories == nil {
		repositories = []ecrtypes.Repository{{
			RepositoryArn:      awsv2.String("arn:aws:ecr:us-east-1:123456789012:repository/payments/api"),
			RepositoryName:     awsv2.String("payments/api"),
			RepositoryUri:      awsv2.String("123456789012.dkr.ecr.us-east-1.amazonaws.com/payments/api"),
			RegistryId:         awsv2.String("123456789012"),
			ImageTagMutability: ecrtypes.ImageTagMutabilityMutable,
			EncryptionConfiguration: &ecrtypes.EncryptionConfiguration{
				EncryptionType: ecrtypes.EncryptionTypeKms,
				KmsKey:         awsv2.String("alias/payments-images"),
			},
			ImageScanningConfiguration: &ecrtypes.ImageScanningConfiguration{ScanOnPush: true},
			CreatedAt:                  &createdAt,
		}}
	}
	return &ecr.DescribeRepositoriesOutput{
		NextToken:    awsv2.String("next-page"),
		Repositories: repositories,
	}, nil
}

func (f fakeECRSDKClient) DescribeImages(ctx context.Context, params *ecr.DescribeImagesInput, optFns ...func(*ecr.Options)) (*ecr.DescribeImagesOutput, error) {
	if f.imagesErr != nil {
		return nil, f.imagesErr
	}
	first := time.Date(2026, 6, 10, 14, 0, 0, 0, time.UTC)
	second := time.Date(2026, 6, 11, 14, 0, 0, 0, time.UTC)
	return &ecr.DescribeImagesOutput{ImageDetails: []ecrtypes.ImageDetail{
		{ImageTags: []string{"prod"}, ImagePushedAt: &first},
		{ImagePushedAt: &second},
	}}, nil
}

func (f fakeECRSDKClient) GetRepositoryPolicy(ctx context.Context, params *ecr.GetRepositoryPolicyInput, optFns ...func(*ecr.Options)) (*ecr.GetRepositoryPolicyOutput, error) {
	if f.policyErr != nil {
		return nil, f.policyErr
	}
	return &ecr.GetRepositoryPolicyOutput{PolicyText: awsv2.String(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow"},{"Effect":"Deny"}]}`)}, nil
}

func (f fakeECRSDKClient) GetLifecyclePolicy(ctx context.Context, params *ecr.GetLifecyclePolicyInput, optFns ...func(*ecr.Options)) (*ecr.GetLifecyclePolicyOutput, error) {
	if f.lifecycleErr != nil {
		return nil, f.lifecycleErr
	}
	return &ecr.GetLifecyclePolicyOutput{LifecyclePolicyText: awsv2.String(`{"rules":[{"rulePriority":1},{"rulePriority":2}]}`)}, nil
}

func (f fakeECRSDKClient) GetRegistryScanningConfiguration(ctx context.Context, params *ecr.GetRegistryScanningConfigurationInput, optFns ...func(*ecr.Options)) (*ecr.GetRegistryScanningConfigurationOutput, error) {
	if f.scanningErr != nil {
		return nil, f.scanningErr
	}
	if f.scanningConfig != nil {
		return &ecr.GetRegistryScanningConfigurationOutput{ScanningConfiguration: f.scanningConfig}, nil
	}
	return &ecr.GetRegistryScanningConfigurationOutput{ScanningConfiguration: &ecrtypes.RegistryScanningConfiguration{ScanType: ecrtypes.ScanTypeEnhanced}}, nil
}

func TestECRRepositoryEnhancedScanningFiltersOnlyMatchedRepositories(t *testing.T) {
	repositories := []ecrtypes.Repository{
		{
			RepositoryName: awsv2.String("prod-app"),
			RepositoryArn:  awsv2.String("arn:aws:ecr:us-east-1:123456789012:repository/prod-app"),
			RepositoryUri:  awsv2.String("123456789012.dkr.ecr.us-east-1.amazonaws.com/prod-app"),
			RegistryId:     awsv2.String("123456789012"),
			CreatedAt:      &time.Time{},
		},
		{
			RepositoryName: awsv2.String("legacy-app"),
			RepositoryArn:  awsv2.String("arn:aws:ecr:us-east-1:123456789012:repository/legacy-app"),
			RepositoryUri:  awsv2.String("123456789012.dkr.ecr.us-east-1.amazonaws.com/legacy-app"),
			RegistryId:     awsv2.String("123456789012"),
			CreatedAt:      &time.Time{},
		},
	}
	api := NewSDKECRRepositoryMetadataAPIFromClient(fakeECRSDKClient{
		repositories: repositories,
		scanningConfig: &ecrtypes.RegistryScanningConfiguration{
			ScanType: ecrtypes.ScanTypeEnhanced,
			Rules: []ecrtypes.RegistryScanningRule{{
				RepositoryFilters: []ecrtypes.ScanningRepositoryFilter{{
					FilterType: ecrtypes.ScanningRepositoryFilterTypeWildcard,
					Filter:     awsv2.String("prod-*"),
				}},
			}},
		},
	}, "123456789012", "us-east-1")

	page, err := api.ListRepositoryMetadata(context.Background(), "", 50)
	if err != nil {
		t.Fatalf("list repository metadata: %v", err)
	}
	if len(page.Records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(page.Records))
	}
	if !page.Records[0].EnhancedScanningEnabled || !page.Records[0].EnhancedScanningKnown {
		t.Fatalf("expected enhanced scanning enabled and known for matched repo, got %+v", page.Records[0])
	}
	if page.Records[1].EnhancedScanningEnabled || !page.Records[1].EnhancedScanningKnown {
		t.Fatalf("expected enhanced scanning disabled for non-matched repo, got %+v", page.Records[1])
	}
}

func TestECRRepositoryEnhancedScanningFilterMatchesWithoutWildcard(t *testing.T) {
	repositories := []ecrtypes.Repository{
		{
			RepositoryName: awsv2.String("prod-api"),
			RepositoryArn:  awsv2.String("arn:aws:ecr:us-east-1:123456789012:repository/prod-api"),
			RepositoryUri:  awsv2.String("123456789012.dkr.ecr.us-east-1.amazonaws.com/prod-api"),
			RegistryId:     awsv2.String("123456789012"),
			CreatedAt:      &time.Time{},
		},
		{
			RepositoryName: awsv2.String("repo-prod"),
			RepositoryArn:  awsv2.String("arn:aws:ecr:us-east-1:123456789012:repository/repo-prod"),
			RepositoryUri:  awsv2.String("123456789012.dkr.ecr.us-east-1.amazonaws.com/repo-prod"),
			RegistryId:     awsv2.String("123456789012"),
			CreatedAt:      &time.Time{},
		},
		{
			RepositoryName: awsv2.String("legacy"),
			RepositoryArn:  awsv2.String("arn:aws:ecr:us-east-1:123456789012:repository/legacy"),
			RepositoryUri:  awsv2.String("123456789012.dkr.ecr.us-east-1.amazonaws.com/legacy"),
			RegistryId:     awsv2.String("123456789012"),
			CreatedAt:      &time.Time{},
		},
	}
	api := NewSDKECRRepositoryMetadataAPIFromClient(fakeECRSDKClient{
		repositories: repositories,
		scanningConfig: &ecrtypes.RegistryScanningConfiguration{
			ScanType: ecrtypes.ScanTypeEnhanced,
			Rules: []ecrtypes.RegistryScanningRule{{
				RepositoryFilters: []ecrtypes.ScanningRepositoryFilter{{
					FilterType: ecrtypes.ScanningRepositoryFilterTypeWildcard,
					Filter:     awsv2.String("prod"),
				}},
			}},
		},
	}, "123456789012", "us-east-1")

	page, err := api.ListRepositoryMetadata(context.Background(), "", 50)
	if err != nil {
		t.Fatalf("list repository metadata: %v", err)
	}
	if len(page.Records) != 3 {
		t.Fatalf("expected 3 records, got %d", len(page.Records))
	}
	if !page.Records[0].EnhancedScanningEnabled {
		t.Fatalf("expected first repo enhanced scanning match for substring filter, got %+v", page.Records[0])
	}
	if !page.Records[1].EnhancedScanningEnabled {
		t.Fatalf("expected second repo enhanced scanning match for substring filter, got %+v", page.Records[1])
	}
	if page.Records[2].EnhancedScanningEnabled {
		t.Fatalf("expected third repo to skip enhanced scanning filter, got %+v", page.Records[2])
	}
}

func TestECRRepositoryEnhancedScanningFilterMatchesWildcardAcrossSlash(t *testing.T) {
	repositories := []ecrtypes.Repository{{
		RepositoryName: awsv2.String("payments/api"),
		RepositoryArn:  awsv2.String("arn:aws:ecr:us-east-1:123456789012:repository/payments/api"),
		RepositoryUri:  awsv2.String("123456789012.dkr.ecr.us-east-1.amazonaws.com/payments/api"),
		RegistryId:     awsv2.String("123456789012"),
		CreatedAt:      &time.Time{},
	}}
	api := NewSDKECRRepositoryMetadataAPIFromClient(fakeECRSDKClient{
		repositories: repositories,
		scanningConfig: &ecrtypes.RegistryScanningConfiguration{
			ScanType: ecrtypes.ScanTypeEnhanced,
			Rules: []ecrtypes.RegistryScanningRule{{
				RepositoryFilters: []ecrtypes.ScanningRepositoryFilter{{
					FilterType: ecrtypes.ScanningRepositoryFilterTypeWildcard,
					Filter:     awsv2.String("*"),
				}},
			}},
		},
	}, "123456789012", "us-east-1")

	page, err := api.ListRepositoryMetadata(context.Background(), "", 50)
	if err != nil {
		t.Fatalf("list repository metadata: %v", err)
	}
	if len(page.Records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(page.Records))
	}
	if !page.Records[0].EnhancedScanningEnabled {
		t.Fatalf("expected wildcard filter to match repository with slash path, got %+v", page.Records[0])
	}
}

func TestECRRepositoryEnhancedScanningFilterRegexesAreCached(t *testing.T) {
	ecrRepositoryScanningFilterRegexes = sync.Map{}

	if !ecrRepositoryScanningFilterMatchesAWS("prod*", "prod-api") {
		t.Fatalf("expected wildcard filter to match repository with prefix")
	}
	cached, ok := ecrRepositoryScanningFilterRegexes.Load("prod.*")
	if !ok {
		t.Fatalf("expected compiled regex cached for prod* pattern")
	}
	if !ecrRepositoryScanningFilterMatchesAWS("prod*", "prod-service") {
		t.Fatalf("expected wildcard filter to match repository with same prefix")
	}
	cachedTwice, ok := ecrRepositoryScanningFilterRegexes.Load("prod.*")
	if !ok {
		t.Fatalf("expected compiled regex still cached on repeated calls")
	}
	if cached != cachedTwice {
		t.Fatalf("expected regex cache to be reused for identical pattern")
	}
}

func TestECRRepositoryEnhancedScanningEnabledForAllWithoutRules(t *testing.T) {
	api := NewSDKECRRepositoryMetadataAPIFromClient(fakeECRSDKClient{
		scanningConfig: &ecrtypes.RegistryScanningConfiguration{
			ScanType: ecrtypes.ScanTypeEnhanced,
		},
	}, "123456789012", "us-east-1")

	page, err := api.ListRepositoryMetadata(context.Background(), "", 50)
	if err != nil {
		t.Fatalf("list repository metadata: %v", err)
	}
	if len(page.Records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(page.Records))
	}
	if !page.Records[0].EnhancedScanningEnabled || !page.Records[0].EnhancedScanningKnown {
		t.Fatalf("expected enhanced scanning enabled and known when enhanced type configured without filters, got %+v", page.Records[0])
	}
}

func TestECRRepositoryEnhancedScanningDisabledWhenScanTypeBasic(t *testing.T) {
	api := NewSDKECRRepositoryMetadataAPIFromClient(fakeECRSDKClient{
		scanningConfig: &ecrtypes.RegistryScanningConfiguration{
			ScanType: ecrtypes.ScanTypeBasic,
			Rules: []ecrtypes.RegistryScanningRule{{
				RepositoryFilters: []ecrtypes.ScanningRepositoryFilter{{
					FilterType: ecrtypes.ScanningRepositoryFilterTypeWildcard,
					Filter:     awsv2.String("*"),
				}},
			}},
		},
	}, "123456789012", "us-east-1")

	page, err := api.ListRepositoryMetadata(context.Background(), "", 50)
	if err != nil {
		t.Fatalf("list repository metadata: %v", err)
	}
	if len(page.Records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(page.Records))
	}
	if page.Records[0].EnhancedScanningEnabled {
		t.Fatalf("expected enhanced scanning disabled for basic scan type, got %+v", page.Records[0])
	}
}

func (f fakeECRSDKClient) ListTagsForResource(ctx context.Context, params *ecr.ListTagsForResourceInput, optFns ...func(*ecr.Options)) (*ecr.ListTagsForResourceOutput, error) {
	if f.tagsErr != nil {
		return nil, f.tagsErr
	}
	return &ecr.ListTagsForResourceOutput{Tags: []ecrtypes.Tag{{Key: awsv2.String("owner"), Value: awsv2.String("payments")}}}, nil
}

func TestSDKECRRepositoryMetadataAPIListRepositoryMetadata(t *testing.T) {
	api := NewSDKECRRepositoryMetadataAPIFromClient(fakeECRSDKClient{}, "123456789012", "us-east-1")

	page, err := api.ListRepositoryMetadata(context.Background(), "", 50)
	if err != nil {
		t.Fatalf("list repository metadata: %v", err)
	}
	if page.NextToken != "next-page" || len(page.Diagnostics) != 0 || len(page.Records) != 1 {
		t.Fatalf("unexpected page: %+v", page)
	}
	record := page.Records[0]
	if record.RepositoryName != "payments/api" || record.ImageCount != 2 || record.TaggedImageCount != 1 || record.UntaggedImageCount != 1 {
		t.Fatalf("unexpected repository/image summary: %+v", record)
	}
	if !record.HasRepositoryPolicy || record.RepositoryPolicyStatement != 2 || !record.HasLifecyclePolicy || record.LifecycleRuleCount != 2 {
		t.Fatalf("expected policy and lifecycle summaries, got %+v", record)
	}
	if !record.EnhancedScanningKnown || !record.EnhancedScanningEnabled || !record.ScanOnPush {
		t.Fatalf("expected scan metadata, got %+v", record)
	}
	if record.Tags["owner"] != "payments" || record.LastPushedAt != "2026-06-11T14:00:00Z" {
		t.Fatalf("unexpected tags or push time: %+v", record)
	}
}

func TestSDKECRRepositoryMetadataAPIDiagnosticsForOptionalMetadata(t *testing.T) {
	api := NewSDKECRRepositoryMetadataAPIFromClient(fakeECRSDKClient{
		policyErr:    errors.New("access denied policy"),
		lifecycleErr: errors.New("access denied lifecycle"),
		imagesErr:    errors.New("throttled images"),
		tagsErr:      errors.New("access denied tags"),
		scanningErr:  errors.New("access denied scanning"),
	}, "123456789012", "us-east-1")

	page, err := api.ListRepositoryMetadata(context.Background(), "", 50)
	if err != nil {
		t.Fatalf("list repository metadata: %v", err)
	}
	if len(page.Records) != 1 || len(page.Diagnostics) != 5 {
		t.Fatalf("expected record plus optional metadata diagnostics, got %+v", page)
	}
}

func TestSDKECRRepositoryMetadataAPIErrors(t *testing.T) {
	nilAPI := NewSDKECRRepositoryMetadataAPIFromClient(nil, "123456789012", "us-east-1")
	if _, err := nilAPI.ListRepositoryMetadata(context.Background(), "", 50); err == nil {
		t.Fatalf("expected nil client error")
	}
	api := NewSDKECRRepositoryMetadataAPIFromClient(fakeECRSDKClient{repositoriesErr: errors.New("describe failed")}, "123456789012", "us-east-1")
	if _, err := api.ListRepositoryMetadata(context.Background(), "", 50); err == nil {
		t.Fatalf("expected describe repositories error")
	}
}

func TestCountJSONPolicyStatements(t *testing.T) {
	if got := countJSONPolicyStatements(`{"Statement":{"Effect":"Allow"}}`); got != 1 {
		t.Fatalf("single statement count = %d, want 1", got)
	}
	if got := countJSONPolicyStatements(`{"Statement":[{"Effect":"Allow"},{"Effect":"Deny"}]}`); got != 2 {
		t.Fatalf("array statement count = %d, want 2", got)
	}
	if got := countJSONPolicyStatements(`{"Statement":"bogus"}`); got != 0 {
		t.Fatalf("invalid statement count = %d, want 0", got)
	}
}
