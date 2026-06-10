package aws

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/s3control"
	s3controltypes "github.com/aws/aws-sdk-go-v2/service/s3control/types"
)

type fakeS3SDKClient struct {
	listOutput    *s3.ListBucketsOutput
	listErr       error
	location      map[string]*s3.GetBucketLocationOutput
	locationErr   map[string]error
	policy        map[string]*s3.GetBucketPolicyOutput
	policyErr     map[string]error
	pab           map[string]*s3.GetPublicAccessBlockOutput
	pabErr        map[string]error
	ownership     map[string]*s3.GetBucketOwnershipControlsOutput
	ownershipErr  map[string]error
	encryption    map[string]*s3.GetBucketEncryptionOutput
	encryptionErr map[string]error
	tagging       map[string]*s3.GetBucketTaggingOutput
	taggingErr    map[string]error
}

func (f *fakeS3SDKClient) ListBuckets(ctx context.Context, _ *s3.ListBucketsInput, _ ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
	return f.listOutput, f.listErr
}

func (f *fakeS3SDKClient) GetBucketLocation(ctx context.Context, in *s3.GetBucketLocationInput, _ ...func(*s3.Options)) (*s3.GetBucketLocationOutput, error) {
	name := awsv2.ToString(in.Bucket)
	if err, ok := f.locationErr[name]; ok {
		return nil, err
	}
	return f.location[name], nil
}

func (f *fakeS3SDKClient) GetBucketPolicy(ctx context.Context, in *s3.GetBucketPolicyInput, _ ...func(*s3.Options)) (*s3.GetBucketPolicyOutput, error) {
	name := awsv2.ToString(in.Bucket)
	if err, ok := f.policyErr[name]; ok {
		return nil, err
	}
	return f.policy[name], nil
}

func (f *fakeS3SDKClient) GetPublicAccessBlock(ctx context.Context, in *s3.GetPublicAccessBlockInput, _ ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error) {
	name := awsv2.ToString(in.Bucket)
	if err, ok := f.pabErr[name]; ok {
		return nil, err
	}
	return f.pab[name], nil
}

func (f *fakeS3SDKClient) GetBucketOwnershipControls(ctx context.Context, in *s3.GetBucketOwnershipControlsInput, _ ...func(*s3.Options)) (*s3.GetBucketOwnershipControlsOutput, error) {
	name := awsv2.ToString(in.Bucket)
	if err, ok := f.ownershipErr[name]; ok {
		return nil, err
	}
	return f.ownership[name], nil
}

func (f *fakeS3SDKClient) GetBucketEncryption(ctx context.Context, in *s3.GetBucketEncryptionInput, _ ...func(*s3.Options)) (*s3.GetBucketEncryptionOutput, error) {
	name := awsv2.ToString(in.Bucket)
	if err, ok := f.encryptionErr[name]; ok {
		return nil, err
	}
	return f.encryption[name], nil
}

func (f *fakeS3SDKClient) GetBucketTagging(ctx context.Context, in *s3.GetBucketTaggingInput, _ ...func(*s3.Options)) (*s3.GetBucketTaggingOutput, error) {
	name := awsv2.ToString(in.Bucket)
	if err, ok := f.taggingErr[name]; ok {
		return nil, err
	}
	return f.tagging[name], nil
}

type fakeS3ControlSDKClient struct {
	pages []*s3control.ListAccessPointsOutput
	err   error
	calls int
}

func (f *fakeS3ControlSDKClient) ListAccessPoints(ctx context.Context, in *s3control.ListAccessPointsInput, _ ...func(*s3control.Options)) (*s3control.ListAccessPointsOutput, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	if f.calls > len(f.pages) {
		return &s3control.ListAccessPointsOutput{}, nil
	}
	return f.pages[f.calls-1], nil
}

func TestSDKS3BucketReachabilityAPI_NilClient(t *testing.T) {
	api := &SDKS3BucketReachabilityAPI{}
	if _, err := api.ListBucketReachability(context.Background(), "", 0); err == nil {
		t.Fatalf("expected error with nil client")
	}
}

func TestSDKS3BucketReachabilityAPI_ListBucketsError(t *testing.T) {
	api := NewSDKS3BucketReachabilityAPIFromClients(
		&fakeS3SDKClient{listErr: errors.New("boom")},
		&fakeS3ControlSDKClient{},
		"123456789012",
		"us-east-1",
	)
	if _, err := api.ListBucketReachability(context.Background(), "", 0); err == nil {
		t.Fatalf("expected error from ListBuckets")
	}
}

func TestSDKS3BucketReachabilityAPI_FullEnrichment(t *testing.T) {
	created := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	fake := &fakeS3SDKClient{
		listOutput: &s3.ListBucketsOutput{
			Buckets: []s3types.Bucket{
				{Name: awsv2.String("ok-bucket"), CreationDate: &created},
				{Name: awsv2.String("eu-bucket"), CreationDate: &created},
				{Name: awsv2.String("no-policy"), CreationDate: &created},
				{Name: awsv2.String("error-policy"), CreationDate: &created},
				{Name: awsv2.String(""), CreationDate: &created},
			},
		},
		location: map[string]*s3.GetBucketLocationOutput{
			"ok-bucket":    {LocationConstraint: s3types.BucketLocationConstraint("us-west-2")},
			"eu-bucket":    {LocationConstraint: s3types.BucketLocationConstraint("EU")},
			"no-policy":    {LocationConstraint: s3types.BucketLocationConstraint("")},
			"error-policy": {LocationConstraint: s3types.BucketLocationConstraint("us-east-1")},
		},
		policy: map[string]*s3.GetBucketPolicyOutput{
			"ok-bucket": {Policy: awsv2.String(`{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:role/x"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::ok-bucket/*"}]}`)},
		},
		policyErr: map[string]error{
			"no-policy":    errors.New("NoSuchBucketPolicy: missing"),
			"error-policy": errors.New("AccessDenied: denied"),
		},
		pab: map[string]*s3.GetPublicAccessBlockOutput{
			"ok-bucket": {PublicAccessBlockConfiguration: &s3types.PublicAccessBlockConfiguration{
				BlockPublicAcls:       awsv2.Bool(true),
				IgnorePublicAcls:      awsv2.Bool(true),
				BlockPublicPolicy:     awsv2.Bool(true),
				RestrictPublicBuckets: awsv2.Bool(true),
			}},
		},
		pabErr: map[string]error{
			"no-policy":    errors.New("NoSuchPublicAccessBlockConfiguration: missing"),
			"error-policy": errors.New("AccessDenied: pab"),
		},
		ownership: map[string]*s3.GetBucketOwnershipControlsOutput{
			"ok-bucket": {OwnershipControls: &s3types.OwnershipControls{Rules: []s3types.OwnershipControlsRule{{ObjectOwnership: s3types.ObjectOwnershipBucketOwnerEnforced}}}},
		},
		ownershipErr: map[string]error{
			"no-policy":    errors.New("OwnershipControlsNotFoundError: missing"),
			"error-policy": errors.New("AccessDenied: ownership"),
		},
		encryption: map[string]*s3.GetBucketEncryptionOutput{
			"ok-bucket": {ServerSideEncryptionConfiguration: &s3types.ServerSideEncryptionConfiguration{Rules: []s3types.ServerSideEncryptionRule{{
				ApplyServerSideEncryptionByDefault: &s3types.ServerSideEncryptionByDefault{
					SSEAlgorithm:   s3types.ServerSideEncryptionAwsKms,
					KMSMasterKeyID: awsv2.String("arn:aws:kms:us-west-2:123456789012:key/abc"),
				},
				BucketKeyEnabled: awsv2.Bool(true),
			}}}},
		},
		encryptionErr: map[string]error{
			"no-policy":    errors.New("ServerSideEncryptionConfigurationNotFoundError: missing"),
			"error-policy": errors.New("AccessDenied: enc"),
		},
		tagging: map[string]*s3.GetBucketTaggingOutput{
			"ok-bucket": {TagSet: []s3types.Tag{{Key: awsv2.String("owner"), Value: awsv2.String("payments")}, {Key: awsv2.String(""), Value: awsv2.String("ignored")}}},
		},
		taggingErr: map[string]error{
			"no-policy":    errors.New("NoSuchTagSet: missing"),
			"error-policy": errors.New("AccessDenied: tags"),
		},
	}
	control := &fakeS3ControlSDKClient{
		pages: []*s3control.ListAccessPointsOutput{
			{
				AccessPointList: []s3controltypes.AccessPoint{
					{Name: awsv2.String("ap-1"), AccessPointArn: awsv2.String("arn:aws:s3:us-west-2:123456789012:accesspoint/ap-1"), Bucket: awsv2.String("ok-bucket"), NetworkOrigin: s3controltypes.NetworkOriginVpc, VpcConfiguration: &s3controltypes.VpcConfiguration{VpcId: awsv2.String("vpc-1")}},
					{Name: awsv2.String("ap-orphan"), Bucket: awsv2.String("")},
				},
				NextToken: awsv2.String("p2"),
			},
			{AccessPointList: []s3controltypes.AccessPoint{}},
		},
	}
	api := NewSDKS3BucketReachabilityAPIFromClients(fake, control, "123456789012", "us-west-2")

	page, err := api.ListBucketReachability(context.Background(), "", 0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	byName := map[string]S3BucketReachability{}
	for _, r := range page.Records {
		byName[r.BucketName] = r
	}
	if len(byName) != 4 {
		t.Fatalf("expected 4 named records (empty bucket skipped), got %d", len(byName))
	}

	ok := byName["ok-bucket"]
	if ok.BucketRegion != "us-west-2" {
		t.Fatalf("expected us-west-2, got %q", ok.BucketRegion)
	}
	if !ok.HasBucketPolicy || len(ok.IdentityGrants) != 1 {
		t.Fatalf("expected one parsed grant, got %+v", ok.IdentityGrants)
	}
	if ok.PublicAccessBlock == nil || !ok.PublicAccessBlock.BlockPublicACLs {
		t.Fatalf("expected PAB populated, got %+v", ok.PublicAccessBlock)
	}
	if ok.OwnershipControls != string(s3types.ObjectOwnershipBucketOwnerEnforced) {
		t.Fatalf("expected ownership controls, got %q", ok.OwnershipControls)
	}
	if ok.DefaultEncryptionAlgorithm != string(s3types.ServerSideEncryptionAwsKms) || ok.DefaultEncryptionKMSKeyARN == "" || !ok.BucketKeyEnabled {
		t.Fatalf("expected KMS encryption fields, got %+v", ok)
	}
	if v, exists := ok.Tags["owner"]; !exists || v != "payments" {
		t.Fatalf("expected owner tag, got %+v", ok.Tags)
	}
	if len(ok.AccessPoints) != 1 || ok.AccessPoints[0].Name != "ap-1" || ok.AccessPoints[0].VPCID != "vpc-1" {
		t.Fatalf("expected one access point, got %+v", ok.AccessPoints)
	}
	if ok.CreatedAt == "" {
		t.Fatalf("expected creation date populated")
	}

	if got := byName["eu-bucket"].BucketRegion; got != "eu-west-1" {
		t.Fatalf("expected EU legacy region to map to eu-west-1, got %q", got)
	}

	noPolicy := byName["no-policy"]
	if noPolicy.HasBucketPolicy {
		t.Fatalf("no-policy bucket should not be flagged as having a policy")
	}
	if noPolicy.BucketRegion != "us-east-1" {
		t.Fatalf("expected empty LocationConstraint to map to us-east-1, got %q", noPolicy.BucketRegion)
	}

	// Errors should produce diagnostics, not be silently dropped.
	codes := map[string]int{}
	for _, d := range page.Diagnostics {
		codes[d.Code]++
	}
	for _, code := range []string{"s3_bucket_policy_failed", "s3_public_access_block_failed", "s3_ownership_controls_failed", "s3_bucket_encryption_failed", "s3_bucket_tagging_failed"} {
		if codes[code] == 0 {
			t.Fatalf("expected %q diagnostic for error-policy bucket; got %+v", code, codes)
		}
	}
	if codes["s3_bucket_name_missing"] == 0 {
		t.Fatalf("expected missing-name diagnostic")
	}
}

func TestSDKS3BucketReachabilityAPI_BucketLocationFailureFallsBackToScopeRegion(t *testing.T) {
	created := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	fake := &fakeS3SDKClient{
		listOutput: &s3.ListBucketsOutput{Buckets: []s3types.Bucket{{Name: awsv2.String("denied-region"), CreationDate: &created}}},
		locationErr: map[string]error{
			"denied-region": errors.New("AccessDenied: GetBucketLocation"),
		},
		policyErr: map[string]error{
			"denied-region": errors.New("NoSuchBucketPolicy: missing"),
		},
		pabErr: map[string]error{
			"denied-region": errors.New("NoSuchPublicAccessBlockConfiguration: missing"),
		},
		ownershipErr: map[string]error{
			"denied-region": errors.New("OwnershipControlsNotFoundError: missing"),
		},
		encryptionErr: map[string]error{
			"denied-region": errors.New("ServerSideEncryptionConfigurationNotFoundError: missing"),
		},
		taggingErr: map[string]error{
			"denied-region": errors.New("NoSuchTagSet: missing"),
		},
	}
	api := NewSDKS3BucketReachabilityAPIFromClients(fake, &fakeS3ControlSDKClient{}, "123456789012", "eu-central-1")
	page, err := api.ListBucketReachability(context.Background(), "", 0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(page.Records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(page.Records))
	}
	if page.Records[0].BucketRegion != "eu-central-1" {
		t.Fatalf("expected fallback to scope region, got %q", page.Records[0].BucketRegion)
	}
	foundLocDiag := false
	for _, d := range page.Diagnostics {
		if d.Code == "s3_bucket_location_failed" {
			foundLocDiag = true
		}
	}
	if !foundLocDiag {
		t.Fatalf("expected s3_bucket_location_failed diagnostic")
	}
}

func TestSDKS3BucketReachabilityAPI_AccessPointsError(t *testing.T) {
	fake := &fakeS3SDKClient{listOutput: &s3.ListBucketsOutput{}}
	control := &fakeS3ControlSDKClient{err: errors.New("AccessDenied: ListAccessPoints")}
	api := NewSDKS3BucketReachabilityAPIFromClients(fake, control, "123456789012", "us-east-1")
	page, err := api.ListBucketReachability(context.Background(), "", 0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	foundDiag := false
	for _, d := range page.Diagnostics {
		if d.Code == "s3_access_points_failed" {
			foundDiag = true
		}
	}
	if !foundDiag {
		t.Fatalf("expected s3_access_points_failed diagnostic")
	}
}

func TestSDKS3BucketReachabilityAPI_AccessPointsSkippedWithoutAccount(t *testing.T) {
	fake := &fakeS3SDKClient{listOutput: &s3.ListBucketsOutput{}}
	api := NewSDKS3BucketReachabilityAPIFromClients(fake, &fakeS3ControlSDKClient{}, "", "us-east-1")
	page, err := api.ListBucketReachability(context.Background(), "", 0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(page.Diagnostics) != 0 {
		t.Fatalf("expected no diagnostics when access-point fetch is skipped, got %+v", page.Diagnostics)
	}
}

func TestSDKS3BucketReachabilityAPI_PolicyParseFailure(t *testing.T) {
	created := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	fake := &fakeS3SDKClient{
		listOutput: &s3.ListBucketsOutput{Buckets: []s3types.Bucket{{Name: awsv2.String("bad-policy"), CreationDate: &created}}},
		location: map[string]*s3.GetBucketLocationOutput{
			"bad-policy": {LocationConstraint: s3types.BucketLocationConstraint("us-east-1")},
		},
		policy: map[string]*s3.GetBucketPolicyOutput{
			"bad-policy": {Policy: awsv2.String("not json")},
		},
		pabErr:        map[string]error{"bad-policy": errors.New("NoSuchPublicAccessBlockConfiguration: missing")},
		ownershipErr:  map[string]error{"bad-policy": errors.New("OwnershipControlsNotFoundError: missing")},
		encryptionErr: map[string]error{"bad-policy": errors.New("ServerSideEncryptionConfigurationNotFoundError: missing")},
		taggingErr:    map[string]error{"bad-policy": errors.New("NoSuchTagSet: missing")},
	}
	api := NewSDKS3BucketReachabilityAPIFromClients(fake, &fakeS3ControlSDKClient{}, "123456789012", "us-east-1")
	page, err := api.ListBucketReachability(context.Background(), "", 0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	foundDiag := false
	for _, d := range page.Diagnostics {
		if d.Code == "s3_bucket_policy_parse_failed" {
			foundDiag = true
		}
	}
	if !foundDiag {
		t.Fatalf("expected s3_bucket_policy_parse_failed diagnostic")
	}
}

func TestS3BucketReachabilityCollector_CollectWithoutScope(t *testing.T) {
	api := &fakeS3BucketReachabilityAPI{pages: []S3BucketReachabilityPage{{Records: []S3BucketReachability{{BucketName: "bucket", BucketRegion: "us-east-1"}}}}}
	c := NewS3BucketReachabilityCollector(api)
	assets, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(assets) != 1 {
		t.Fatalf("expected 1 asset, got %d", len(assets))
	}
}

func TestS3BucketReachabilityCollector_OptionsPageSize(t *testing.T) {
	api := &fakeS3BucketReachabilityAPI{}
	c := NewS3BucketReachabilityCollector(api, WithS3BucketReachabilityPageSize(50))
	if c.pageSize != 50 {
		t.Fatalf("expected pageSize 50, got %d", c.pageSize)
	}
}

func TestS3BucketReachabilityCollector_PartitionForUnknownRegion(t *testing.T) {
	if got := awsPartitionForRegion("not-a-region"); got != "aws" {
		t.Fatalf("expected aws default partition, got %q", got)
	}
}

func TestSortedAccessPoints(t *testing.T) {
	in := []S3AccessPointReference{{Name: "b"}, {Name: "a"}, {Name: "c"}}
	out := sortedAccessPoints(in)
	if !strings.EqualFold(out[0].Name, "a") || out[1].Name != "b" || out[2].Name != "c" {
		t.Fatalf("expected sorted access points, got %+v", out)
	}
}

func TestCanonicalS3GrantEffect(t *testing.T) {
	cases := map[string]string{
		"allow": "Allow",
		"DENY":  "Deny",
		"Other": "Other",
		"":      "",
	}
	for in, want := range cases {
		if got := canonicalS3GrantEffect(in); got != want {
			t.Fatalf("canonicalS3GrantEffect(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestS3BucketReachabilityConfidence_DefaultUnknown(t *testing.T) {
	record := S3BucketReachability{ExposureClassification: ""}
	if got := s3BucketReachabilityConfidence(record); got != 0.7 {
		t.Fatalf("expected 0.7 for unknown classification, got %v", got)
	}
	record.ExposureClassification = "private"
	if got := s3BucketReachabilityConfidence(record); got != 0.86 {
		t.Fatalf("expected 0.86 for private, got %v", got)
	}
}
