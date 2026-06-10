package aws

import (
	"context"
	"errors"
	"fmt"
	"strings"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3control"
	s3controltypes "github.com/aws/aws-sdk-go-v2/service/s3control/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/identrail/identrail/internal/providers"
	"github.com/identrail/identrail/internal/textutil"
)

// S3SDKClient is the narrow seam between the AWS SDK S3 client and the
// reachability collector. It deliberately exposes only metadata-only calls so
// the collector cannot accidentally list, read, or write object contents.
type S3SDKClient interface {
	ListBuckets(ctx context.Context, params *s3.ListBucketsInput, optFns ...func(*s3.Options)) (*s3.ListBucketsOutput, error)
	GetBucketLocation(ctx context.Context, params *s3.GetBucketLocationInput, optFns ...func(*s3.Options)) (*s3.GetBucketLocationOutput, error)
	GetBucketPolicy(ctx context.Context, params *s3.GetBucketPolicyInput, optFns ...func(*s3.Options)) (*s3.GetBucketPolicyOutput, error)
	GetPublicAccessBlock(ctx context.Context, params *s3.GetPublicAccessBlockInput, optFns ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error)
	GetBucketOwnershipControls(ctx context.Context, params *s3.GetBucketOwnershipControlsInput, optFns ...func(*s3.Options)) (*s3.GetBucketOwnershipControlsOutput, error)
	GetBucketEncryption(ctx context.Context, params *s3.GetBucketEncryptionInput, optFns ...func(*s3.Options)) (*s3.GetBucketEncryptionOutput, error)
	GetBucketTagging(ctx context.Context, params *s3.GetBucketTaggingInput, optFns ...func(*s3.Options)) (*s3.GetBucketTaggingOutput, error)
}

// S3ControlSDKClient is the SDK seam for the account-level S3 Access Points
// listing. It is kept on its own interface because s3control is a separate
// service endpoint and some accounts do not use access points.
type S3ControlSDKClient interface {
	ListAccessPoints(ctx context.Context, params *s3control.ListAccessPointsInput, optFns ...func(*s3control.Options)) (*s3control.ListAccessPointsOutput, error)
}

// SDKS3BucketReachabilityAPI implements the collector seam against the AWS
// SDK. Every read is metadata-only: ListBuckets and per-bucket Get* calls.
// Bucket policies are captured for *parsing*, not for storing the raw
// document — only inferred grant tuples flow into the normalized record.
type SDKS3BucketReachabilityAPI struct {
	client        S3SDKClient
	controlClient S3ControlSDKClient
	accountID     string
	region        string
}

var _ S3BucketReachabilityAPI = (*SDKS3BucketReachabilityAPI)(nil)

// NewSDKS3BucketReachabilityAPI constructs the SDK-backed API using ambient
// AWS credentials.
func NewSDKS3BucketReachabilityAPI(region string, profile string, accountID string) (S3BucketReachabilityAPI, error) {
	return NewSDKS3BucketReachabilityAPIWithContext(context.Background(), region, profile, accountID)
}

// NewSDKS3BucketReachabilityAPIWithContext constructs the SDK-backed API
// using the supplied context for config loading.
func NewSDKS3BucketReachabilityAPIWithContext(ctx context.Context, region string, profile string, accountID string) (S3BucketReachabilityAPI, error) {
	cfg, err := loadSDKConfig(ctx, region, profile)
	if err != nil {
		return nil, err
	}
	resolved, err := s3BucketReachabilityAccountID(ctx, cfg, accountID)
	if err != nil {
		return nil, err
	}
	resolvedRegion := firstNonEmptyAWSValue(strings.TrimSpace(region), strings.TrimSpace(cfg.Region))
	return NewSDKS3BucketReachabilityAPIFromClients(s3.NewFromConfig(cfg), s3control.NewFromConfig(cfg), resolved, resolvedRegion), nil
}

// NewSDKS3BucketReachabilityAPIFromAssumeRole constructs the SDK-backed API
// after assuming the supplied connector role.
func NewSDKS3BucketReachabilityAPIFromAssumeRole(ctx context.Context, region string, profile string, roleARN string, externalID string, sessionName string, accountID string) (S3BucketReachabilityAPI, error) {
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
	resolved, err := s3BucketReachabilityAccountID(ctx, cfg, accountID)
	if err != nil {
		return nil, err
	}
	resolvedRegion := firstNonEmptyAWSValue(strings.TrimSpace(region), strings.TrimSpace(cfg.Region))
	return NewSDKS3BucketReachabilityAPIFromClients(s3.NewFromConfig(cfg), s3control.NewFromConfig(cfg), resolved, resolvedRegion), nil
}

// NewSDKS3BucketReachabilityAPIFromClients is the seam tests use to inject
// fake S3 and s3control clients.
func NewSDKS3BucketReachabilityAPIFromClients(client S3SDKClient, controlClient S3ControlSDKClient, accountID string, region string) S3BucketReachabilityAPI {
	return &SDKS3BucketReachabilityAPI{
		client:        client,
		controlClient: controlClient,
		accountID:     strings.TrimSpace(accountID),
		region:        strings.TrimSpace(region),
	}
}

// ListBucketReachability enumerates every bucket and folds the per-bucket
// metadata into a single page. S3 has no native pagination for ListBuckets,
// so this implementation returns one page only.
func (a *SDKS3BucketReachabilityAPI) ListBucketReachability(ctx context.Context, _ string, _ int32) (S3BucketReachabilityPage, error) {
	if a.client == nil {
		return S3BucketReachabilityPage{}, errors.New("s3 SDK client is required")
	}
	listOutput, err := a.client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return S3BucketReachabilityPage{}, err
	}
	if listOutput == nil {
		return S3BucketReachabilityPage{}, nil
	}
	// One pre-fetched access-point map per account keyed by bucket name. We
	// fetch it once outside the bucket loop because s3control returns access
	// points across all buckets in the account.
	accessPoints, accessPointDiagnostics := a.fetchAccessPointsByBucket(ctx)
	diagnostics := append([]providers.SourceError(nil), accessPointDiagnostics...)
	records := []S3BucketReachability{}
	for _, summary := range listOutput.Buckets {
		name := strings.TrimSpace(awsv2.ToString(summary.Name))
		if name == "" {
			diagnostics = append(diagnostics, s3BucketReachabilityDiagnostic("s3_bucket_name_missing", "listbuckets", "S3 bucket summary did not include a name", false))
			continue
		}
		record := S3BucketReachability{
			BucketName: name,
		}
		if summary.CreationDate != nil {
			record.CreatedAt = summary.CreationDate.UTC().Format("2006-01-02T15:04:05Z")
		}
		region := a.bucketRegion(ctx, name, &diagnostics)
		record.BucketRegion = region
		record.BucketARN = s3BucketARNFromName(name, a.accountID, region)
		a.enrichBucketPolicy(ctx, name, &record, &diagnostics)
		a.enrichPublicAccessBlock(ctx, name, &record, &diagnostics)
		a.enrichOwnershipControls(ctx, name, &record, &diagnostics)
		a.enrichEncryption(ctx, name, &record, &diagnostics)
		a.enrichTags(ctx, name, &record, &diagnostics)
		record.AccessPoints = accessPoints[name]
		records = append(records, record)
	}
	return S3BucketReachabilityPage{Records: records, Diagnostics: diagnostics}, nil
}

func (a *SDKS3BucketReachabilityAPI) bucketRegion(ctx context.Context, name string, diagnostics *[]providers.SourceError) string {
	output, err := a.client.GetBucketLocation(ctx, &s3.GetBucketLocationInput{Bucket: awsv2.String(name)})
	if err != nil {
		*diagnostics = append(*diagnostics, s3BucketReachabilityDiagnostic("s3_bucket_location_failed", name, fmt.Sprintf("GetBucketLocation %q failed: %v", name, err), true))
		return a.region
	}
	if output == nil {
		return a.region
	}
	region := string(output.LocationConstraint)
	switch region {
	case "":
		// us-east-1 has empty LocationConstraint
		return "us-east-1"
	case "EU":
		// Legacy LocationConstraint returned for buckets created in the
		// original EU region — aliases to eu-west-1.
		return "eu-west-1"
	default:
		return region
	}
}

func (a *SDKS3BucketReachabilityAPI) enrichBucketPolicy(ctx context.Context, name string, record *S3BucketReachability, diagnostics *[]providers.SourceError) {
	output, err := a.client.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{Bucket: awsv2.String(name)})
	if err != nil {
		if s3IsNoSuchBucketPolicy(err) {
			return
		}
		*diagnostics = append(*diagnostics, s3BucketReachabilityDiagnostic("s3_bucket_policy_failed", name, fmt.Sprintf("GetBucketPolicy %q failed: %v", name, err), true))
		return
	}
	if output == nil || output.Policy == nil {
		return
	}
	record.HasBucketPolicy = true
	grants, statementCount, parseErr := parseS3BucketPolicyGrants(awsv2.ToString(output.Policy))
	if parseErr != nil {
		*diagnostics = append(*diagnostics, s3BucketReachabilityDiagnostic("s3_bucket_policy_parse_failed", name, fmt.Sprintf("parse bucket policy %q: %v", name, parseErr), false))
		return
	}
	record.BucketPolicyStatementCount = statementCount
	record.IdentityGrants = grants
}

func (a *SDKS3BucketReachabilityAPI) enrichPublicAccessBlock(ctx context.Context, name string, record *S3BucketReachability, diagnostics *[]providers.SourceError) {
	output, err := a.client.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{Bucket: awsv2.String(name)})
	if err != nil {
		if s3IsNoSuchPublicAccessBlockConfiguration(err) {
			return
		}
		*diagnostics = append(*diagnostics, s3BucketReachabilityDiagnostic("s3_public_access_block_failed", name, fmt.Sprintf("GetPublicAccessBlock %q failed: %v", name, err), true))
		return
	}
	if output == nil || output.PublicAccessBlockConfiguration == nil {
		return
	}
	cfg := output.PublicAccessBlockConfiguration
	pab := &S3PublicAccessBlock{
		BlockPublicACLs:       awsv2.ToBool(cfg.BlockPublicAcls),
		IgnorePublicACLs:      awsv2.ToBool(cfg.IgnorePublicAcls),
		BlockPublicPolicy:     awsv2.ToBool(cfg.BlockPublicPolicy),
		RestrictPublicBuckets: awsv2.ToBool(cfg.RestrictPublicBuckets),
	}
	record.PublicAccessBlock = pab
	record.BlockPublicACLs = pab.BlockPublicACLs
	record.IgnorePublicACLs = pab.IgnorePublicACLs
	record.BlockPublicPolicy = pab.BlockPublicPolicy
	record.RestrictPublicBuckets = pab.RestrictPublicBuckets
}

func (a *SDKS3BucketReachabilityAPI) enrichOwnershipControls(ctx context.Context, name string, record *S3BucketReachability, diagnostics *[]providers.SourceError) {
	output, err := a.client.GetBucketOwnershipControls(ctx, &s3.GetBucketOwnershipControlsInput{Bucket: awsv2.String(name)})
	if err != nil {
		if s3IsNoSuchOwnershipControls(err) {
			return
		}
		*diagnostics = append(*diagnostics, s3BucketReachabilityDiagnostic("s3_ownership_controls_failed", name, fmt.Sprintf("GetBucketOwnershipControls %q failed: %v", name, err), true))
		return
	}
	if output == nil || output.OwnershipControls == nil || len(output.OwnershipControls.Rules) == 0 {
		return
	}
	rule := output.OwnershipControls.Rules[0]
	record.OwnershipControls = string(rule.ObjectOwnership)
}

func (a *SDKS3BucketReachabilityAPI) enrichEncryption(ctx context.Context, name string, record *S3BucketReachability, diagnostics *[]providers.SourceError) {
	output, err := a.client.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{Bucket: awsv2.String(name)})
	if err != nil {
		if s3IsNoSuchEncryption(err) {
			return
		}
		*diagnostics = append(*diagnostics, s3BucketReachabilityDiagnostic("s3_bucket_encryption_failed", name, fmt.Sprintf("GetBucketEncryption %q failed: %v", name, err), true))
		return
	}
	if output == nil || output.ServerSideEncryptionConfiguration == nil {
		return
	}
	rules := output.ServerSideEncryptionConfiguration.Rules
	if len(rules) == 0 {
		return
	}
	rule := rules[0]
	if rule.ApplyServerSideEncryptionByDefault != nil {
		record.DefaultEncryptionAlgorithm = string(rule.ApplyServerSideEncryptionByDefault.SSEAlgorithm)
		record.DefaultEncryptionKMSKeyARN = strings.TrimSpace(awsv2.ToString(rule.ApplyServerSideEncryptionByDefault.KMSMasterKeyID))
	}
	record.BucketKeyEnabled = awsv2.ToBool(rule.BucketKeyEnabled)
}

func (a *SDKS3BucketReachabilityAPI) enrichTags(ctx context.Context, name string, record *S3BucketReachability, diagnostics *[]providers.SourceError) {
	output, err := a.client.GetBucketTagging(ctx, &s3.GetBucketTaggingInput{Bucket: awsv2.String(name)})
	if err != nil {
		if s3IsNoSuchTagSet(err) {
			return
		}
		*diagnostics = append(*diagnostics, s3BucketReachabilityDiagnostic("s3_bucket_tagging_failed", name, fmt.Sprintf("GetBucketTagging %q failed: %v", name, err), true))
		return
	}
	if output == nil || len(output.TagSet) == 0 {
		return
	}
	tags := map[string]string{}
	for _, tag := range output.TagSet {
		key := strings.TrimSpace(awsv2.ToString(tag.Key))
		if key == "" {
			continue
		}
		tags[key] = strings.TrimSpace(awsv2.ToString(tag.Value))
	}
	if len(tags) > 0 {
		record.Tags = tags
	}
}

// fetchAccessPointsByBucket pulls every access point in the account once and
// indexes them by bucket. Returns a map suitable for direct lookup in the
// per-bucket loop.
func (a *SDKS3BucketReachabilityAPI) fetchAccessPointsByBucket(ctx context.Context) (map[string][]S3AccessPointReference, []providers.SourceError) {
	if a.controlClient == nil || strings.TrimSpace(a.accountID) == "" {
		return map[string][]S3AccessPointReference{}, nil
	}
	out := map[string][]S3AccessPointReference{}
	diagnostics := []providers.SourceError{}
	nextToken := ""
	for {
		output, err := a.controlClient.ListAccessPoints(ctx, &s3control.ListAccessPointsInput{
			AccountId: awsv2.String(a.accountID),
			NextToken: stringPtrOrNil(nextToken),
		})
		if err != nil {
			diagnostics = append(diagnostics, s3BucketReachabilityDiagnostic("s3_access_points_failed", "listaccesspoints", fmt.Sprintf("ListAccessPoints failed: %v", err), true))
			break
		}
		if output == nil {
			break
		}
		for _, point := range output.AccessPointList {
			ref := S3AccessPointReference{
				Name:          strings.TrimSpace(awsv2.ToString(point.Name)),
				ARN:           strings.TrimSpace(awsv2.ToString(point.AccessPointArn)),
				NetworkOrigin: string(point.NetworkOrigin),
			}
			if point.VpcConfiguration != nil {
				ref.VPCID = strings.TrimSpace(awsv2.ToString(point.VpcConfiguration.VpcId))
			}
			bucket := strings.TrimSpace(awsv2.ToString(point.Bucket))
			if bucket == "" {
				continue
			}
			out[bucket] = append(out[bucket], ref)
		}
		nextToken = strings.TrimSpace(awsv2.ToString(output.NextToken))
		if nextToken == "" {
			break
		}
	}
	return out, diagnostics
}

func s3BucketReachabilityDiagnostic(code string, sourceID string, message string, retryable bool) providers.SourceError {
	return providers.SourceError{
		Collector: s3BucketReachabilityCollectorName,
		SourceID:  strings.TrimSpace(sourceID),
		Code:      strings.TrimSpace(code),
		Message:   strings.TrimSpace(message),
		Retryable: retryable,
	}
}

func s3BucketReachabilityAccountID(ctx context.Context, cfg awsv2.Config, accountID string) (string, error) {
	trimmed := strings.TrimSpace(accountID)
	if trimmed != "" {
		return trimmed, nil
	}
	identity, err := sts.NewFromConfig(cfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", fmt.Errorf("read AWS caller identity for s3 account id: %w", err)
	}
	resolved := strings.TrimSpace(awsv2.ToString(identity.Account))
	if resolved == "" {
		return "", fmt.Errorf("read AWS caller identity for s3 account id: empty account id")
	}
	return resolved, nil
}

// Sentinel error helpers — AWS returns typed errors for "no policy" / "no
// PAB" / "no encryption" / "no tags" which we treat as "absent" rather than
// failure diagnostics.

// s3IsNoSuchBucketPolicy returns true only for the "no bucket policy
// configured" case. AWS's NoSuchBucket (the bucket itself does not exist)
// is a real error and must not be swallowed — we deliberately do not match
// the parent typed error here.
func s3IsNoSuchBucketPolicy(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "nosuchbucketpolicy")
}

func s3IsNoSuchPublicAccessBlockConfiguration(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "nosuchpublicaccessblockconfiguration")
}

func s3IsNoSuchOwnershipControls(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "ownershipcontrolsnotfound")
}

func s3IsNoSuchEncryption(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "serversideencryptionconfigurationnotfounderror")
}

func s3IsNoSuchTagSet(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "nosuchtagset")
}

// silence unused import lint for s3controltypes when the build only references
// the package indirectly through interface methods.
var _ s3controltypes.AccessPoint
