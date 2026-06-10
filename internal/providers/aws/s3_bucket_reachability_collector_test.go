package aws

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/providers"
)

type fakeS3BucketReachabilityAPI struct {
	pages []S3BucketReachabilityPage
	calls int
	err   error
}

func (f *fakeS3BucketReachabilityAPI) ListBucketReachability(ctx context.Context, nextToken string, pageSize int32) (S3BucketReachabilityPage, error) {
	f.calls++
	if f.err != nil {
		return S3BucketReachabilityPage{}, f.err
	}
	if len(f.pages) == 0 {
		return S3BucketReachabilityPage{}, nil
	}
	page := f.pages[0]
	f.pages = f.pages[1:]
	return page, nil
}

func TestParseS3BucketPolicyGrants_AllowWildcardWithoutCondition(t *testing.T) {
	grants, count, err := parseS3BucketPolicyGrants(`{
		"Version": "2012-10-17",
		"Statement": [{
			"Sid": "PublicRead",
			"Effect": "Allow",
			"Principal": "*",
			"Action": ["s3:GetObject"],
			"Resource": "arn:aws:s3:::payments-public/*"
		}]
	}`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 statement, got %d", count)
	}
	if len(grants) != 1 {
		t.Fatalf("expected 1 grant, got %d", len(grants))
	}
	g := grants[0]
	if g.Effect != "Allow" {
		t.Fatalf("expected Allow effect, got %q", g.Effect)
	}
	if !g.WildcardPrincipal || g.PrincipalARN != "*" {
		t.Fatalf("expected wildcard principal, got %+v", g)
	}
	if g.HasCondition {
		t.Fatalf("expected no condition, got %+v", g)
	}
}

func TestParseS3BucketPolicyGrants_DenyAndConditions(t *testing.T) {
	grants, _, err := parseS3BucketPolicyGrants(`{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Sid": "RequireTLS",
				"Effect": "Deny",
				"Principal": "*",
				"Action": "s3:*",
				"Resource": "arn:aws:s3:::payments-internal/*",
				"Condition": { "Bool": { "aws:SecureTransport": "false" } }
			},
			{
				"Sid": "CrossAccountWrite",
				"Effect": "Allow",
				"Principal": { "AWS": "arn:aws:iam::999999999999:role/external-role" },
				"Action": ["s3:PutObject"],
				"Resource": "arn:aws:s3:::payments-cross-account/*",
				"Condition": { "StringEquals": { "aws:PrincipalOrgID": "o-123" } }
			}
		]
	}`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(grants) != 2 {
		t.Fatalf("expected 2 grants, got %d", len(grants))
	}
	denyFound, crossFound := false, false
	for _, g := range grants {
		if g.Effect == "Deny" && g.PrincipalARN == "*" {
			denyFound = true
			if !g.HasCondition {
				t.Fatalf("deny should report condition")
			}
			if len(g.ConditionKeys) == 0 || g.ConditionKeys[0] != "aws:SecureTransport" {
				t.Fatalf("expected SecureTransport condition key, got %+v", g.ConditionKeys)
			}
		}
		if g.Effect == "Allow" && strings.Contains(g.PrincipalARN, "999999999999") {
			crossFound = true
			if !g.HasCondition {
				t.Fatalf("cross-account allow should carry condition")
			}
		}
	}
	if !denyFound || !crossFound {
		t.Fatalf("missing grants: deny=%v cross=%v", denyFound, crossFound)
	}
}

func TestParseS3BucketPolicyGrants_NotPrincipalIsSkipped(t *testing.T) {
	// NotPrincipal has inverse semantics, so the listed principal is the one
	// the statement *excludes*. The parser must skip the entire statement
	// rather than emit a grant that would be interpreted as inclusion.
	grants, _, err := parseS3BucketPolicyGrants(`{
		"Version": "2012-10-17",
		"Statement": [{
			"Sid": "AllowExceptOne",
			"Effect": "Allow",
			"NotPrincipal": { "AWS": "arn:aws:iam::111111111111:role/admin" },
			"Action": "s3:GetObject",
			"Resource": "arn:aws:s3:::payments-internal/*"
		}]
	}`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(grants) != 0 {
		t.Fatalf("expected NotPrincipal to be skipped, got %+v", grants)
	}
}

func TestParseS3BucketPolicyGrants_MalformedStatement(t *testing.T) {
	if _, _, err := parseS3BucketPolicyGrants(`{"Statement": 42}`); err == nil {
		t.Fatalf("expected error on malformed statement shape")
	}
}

func TestClassifyS3BucketExposure_Public(t *testing.T) {
	got, reasons := classifyS3BucketExposure(S3BucketReachability{
		HasBucketPolicy: true,
		IdentityGrants: []S3IdentityGrant{{
			Effect:            "Allow",
			IsPublic:          true,
			WildcardPrincipal: true,
		}},
	})
	if got != "public" {
		t.Fatalf("expected public, got %q reasons=%v", got, reasons)
	}
	if len(reasons) == 0 {
		t.Fatalf("expected reasons populated")
	}
}

func TestClassifyS3BucketExposure_PABClampsPublic(t *testing.T) {
	got, _ := classifyS3BucketExposure(S3BucketReachability{
		HasBucketPolicy: true,
		IdentityGrants: []S3IdentityGrant{{
			Effect:            "Allow",
			IsPublic:          true,
			WildcardPrincipal: true,
		}},
		PublicAccessBlock: &S3PublicAccessBlock{
			BlockPublicACLs:       true,
			BlockPublicPolicy:     true,
			IgnorePublicACLs:      true,
			RestrictPublicBuckets: true,
		},
	})
	if got == "public" {
		t.Fatalf("PAB should suppress public classification")
	}
}

func TestClassifyS3BucketExposure_CrossAccount(t *testing.T) {
	got, _ := classifyS3BucketExposure(S3BucketReachability{
		HasBucketPolicy: true,
		IdentityGrants: []S3IdentityGrant{{
			Effect:         "Allow",
			IsCrossAccount: true,
			PrincipalARN:   "arn:aws:iam::222222222222:role/other",
		}},
	})
	if got != "cross_account" {
		t.Fatalf("expected cross_account, got %q", got)
	}
}

func TestClassifyS3BucketExposure_Restricted(t *testing.T) {
	got, _ := classifyS3BucketExposure(S3BucketReachability{
		HasBucketPolicy: true,
		IdentityGrants: []S3IdentityGrant{{
			Effect:            "Deny",
			WildcardPrincipal: true,
			PrincipalARN:      "*",
		}},
	})
	if got != "restricted" {
		t.Fatalf("expected restricted, got %q", got)
	}
}

func TestClassifyS3BucketExposure_PrivateWithGrants(t *testing.T) {
	got, _ := classifyS3BucketExposure(S3BucketReachability{
		HasBucketPolicy: true,
		IdentityGrants: []S3IdentityGrant{{
			Effect:       "Allow",
			PrincipalARN: "arn:aws:iam::123456789012:role/internal",
		}},
	})
	if got != "private_with_grants" {
		t.Fatalf("expected private_with_grants, got %q", got)
	}
}

func TestClassifyS3BucketExposure_PrivateDefault(t *testing.T) {
	got, _ := classifyS3BucketExposure(S3BucketReachability{})
	if got != "private" {
		t.Fatalf("expected private default, got %q", got)
	}
}

func TestS3BucketReachabilityCollector_NormalizesScopeAndDedupes(t *testing.T) {
	api := &fakeS3BucketReachabilityAPI{
		pages: []S3BucketReachabilityPage{
			{
				Records: []S3BucketReachability{
					{BucketName: "payments-public", BucketRegion: "us-east-1"},
					{BucketName: "payments-public", BucketRegion: "us-east-1"}, // dup
					{BucketName: "payments-cross", BucketRegion: "us-east-1"},
				},
				NextToken: "next",
			},
			{
				Records: []S3BucketReachability{
					{BucketName: "payments-internal", BucketRegion: "us-west-2"},
				},
			},
		},
	}
	c := NewS3BucketReachabilityCollector(api, WithS3BucketReachabilityClock(func() time.Time {
		return time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	}))
	assets, diags, err := c.CollectWithDiagnostics(context.Background(), AWSCollectorScope{
		Service:   "s3",
		AccountID: "123456789012",
		Region:    "us-east-1",
		TenantID:  "tenant-1",
	})
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(assets) != 3 {
		t.Fatalf("expected 3 deduped assets, got %d", len(assets))
	}
	if len(diags) != 0 {
		t.Fatalf("unexpected diagnostics: %+v", diags)
	}
	var first S3BucketReachability
	if err := json.Unmarshal(assets[0].Payload, &first); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if first.AccountID != "123456789012" || first.TenantID != "tenant-1" {
		t.Fatalf("scope not propagated: %+v", first)
	}
	if first.BucketARN == "" || !strings.HasPrefix(first.BucketARN, "arn:aws:s3:::") {
		t.Fatalf("expected synthesized bucket ARN, got %q", first.BucketARN)
	}
	if assets[0].Kind != rawKindS3BucketReachability {
		t.Fatalf("unexpected raw kind: %s", assets[0].Kind)
	}
}

func TestS3BucketReachabilityCollector_PartitionAwareARN(t *testing.T) {
	api := &fakeS3BucketReachabilityAPI{
		pages: []S3BucketReachabilityPage{
			{Records: []S3BucketReachability{{BucketName: "gov-bucket", BucketRegion: "us-gov-west-1"}}},
		},
	}
	c := NewS3BucketReachabilityCollector(api)
	assets, _, err := c.CollectWithDiagnostics(context.Background(), AWSCollectorScope{
		Service: "s3", Region: "us-gov-west-1", AccountID: "123456789012",
	})
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	var rec S3BucketReachability
	if err := json.Unmarshal(assets[0].Payload, &rec); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !strings.HasPrefix(rec.BucketARN, "arn:aws-us-gov:s3:::") {
		t.Fatalf("expected GovCloud partition ARN, got %q", rec.BucketARN)
	}
}

func TestS3BucketReachabilityCollector_PageLimitDiagnostic(t *testing.T) {
	api := &fakeS3BucketReachabilityAPI{
		pages: []S3BucketReachabilityPage{
			{Records: []S3BucketReachability{{BucketName: "a", BucketRegion: "us-east-1"}}, NextToken: "p2"},
			{Records: []S3BucketReachability{{BucketName: "b", BucketRegion: "us-east-1"}}, NextToken: "p3"},
		},
	}
	c := NewS3BucketReachabilityCollector(api,
		WithS3BucketReachabilityMaxPages(1),
	)
	_, diags, err := c.CollectWithDiagnostics(context.Background(), AWSCollectorScope{Service: "s3", AccountID: "123456789012", Region: "us-east-1"})
	if err == nil {
		t.Fatalf("expected page-limit error")
	}
	found := false
	for _, d := range diags {
		if d.Code == "s3_bucket_reachability_page_limit_exceeded" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected page-limit diagnostic, got %+v", diags)
	}
}

func TestS3BucketReachabilityCollector_ListErrorPropagates(t *testing.T) {
	api := &fakeS3BucketReachabilityAPI{err: errors.New("boom")}
	c := NewS3BucketReachabilityCollector(api,
		WithS3BucketReachabilityRetryPolicy(RetryPolicy{MaxRetries: 0, BaseDelay: time.Microsecond, MaxDelay: time.Microsecond}),
		WithS3BucketReachabilitySleeper(func(ctx context.Context, _ time.Duration) error { return nil }),
	)
	assets, diags, err := c.CollectWithDiagnostics(context.Background(), AWSCollectorScope{Service: "s3"})
	if err == nil {
		t.Fatalf("expected error")
	}
	if len(assets) != 0 {
		t.Fatalf("expected no assets on first-page error, got %d", len(assets))
	}
	if len(diags) == 0 {
		t.Fatalf("expected diagnostic on list failure")
	}
}

func TestAnnotateS3Grants_CrossAccountFromARN(t *testing.T) {
	grants := annotateS3Grants([]S3IdentityGrant{{
		PrincipalARN: "arn:aws:iam::999999999999:role/external",
		Effect:       "Allow",
	}}, "123456789012")
	if len(grants) != 1 || !grants[0].IsCrossAccount {
		t.Fatalf("expected cross-account flag, got %+v", grants)
	}
}

func TestS3BucketReachabilityCollector_NilClient(t *testing.T) {
	c := NewS3BucketReachabilityCollector(nil)
	_, _, err := c.CollectWithDiagnostics(context.Background(), AWSCollectorScope{Service: "s3"})
	if err == nil {
		t.Fatalf("expected error when client nil")
	}
}

func TestS3BucketReachabilityCollector_ServiceName(t *testing.T) {
	c := NewS3BucketReachabilityCollector(&fakeS3BucketReachabilityAPI{})
	if c.ServiceName() != "s3" {
		t.Fatalf("expected service name s3, got %q", c.ServiceName())
	}
}

func TestS3BucketReachabilityCollector_SkipsMalformedRecord(t *testing.T) {
	api := &fakeS3BucketReachabilityAPI{
		pages: []S3BucketReachabilityPage{{
			Records: []S3BucketReachability{{}},
		}},
	}
	c := NewS3BucketReachabilityCollector(api)
	assets, diags, err := c.CollectWithDiagnostics(context.Background(), AWSCollectorScope{Service: "s3"})
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(assets) != 0 {
		t.Fatalf("expected no assets, got %d", len(assets))
	}
	found := false
	for _, d := range diags {
		if d.Code == "malformed_s3_bucket_record" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected malformed diagnostic, got %+v", diags)
	}
}

func TestS3BucketReachabilityCollector_AcceptsCollectorDiagnostics(t *testing.T) {
	api := &fakeS3BucketReachabilityAPI{
		pages: []S3BucketReachabilityPage{{
			Records: []S3BucketReachability{{BucketName: "ok-bucket", BucketRegion: "us-east-1"}},
			Diagnostics: []providers.SourceError{{
				Collector: s3BucketReachabilityCollectorName,
				SourceID:  "ok-bucket",
				Code:      "s3_bucket_policy_failed",
				Message:   "denied",
				Retryable: false,
			}},
		}},
	}
	c := NewS3BucketReachabilityCollector(api)
	_, diags, err := c.CollectWithDiagnostics(context.Background(), AWSCollectorScope{Service: "s3", AccountID: "123456789012", Region: "us-east-1"})
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(diags) != 1 || diags[0].Code != "s3_bucket_policy_failed" {
		t.Fatalf("expected collector diagnostic, got %+v", diags)
	}
}

func TestIsIAMUserARN(t *testing.T) {
	cases := map[string]bool{
		"arn:aws:iam::123456789012:user/alice":      true,
		"arn:aws-us-gov:iam::123456789012:user/bob": true,
		"arn:aws:iam::123456789012:role/r":          false,
		"arn:aws:iam::abc:user/x":                   false,
		"arn:aws:iam::123456789012:user/":           false,
	}
	for arn, want := range cases {
		if got := isIAMUserARN(arn); got != want {
			t.Fatalf("isIAMUserARN(%q) = %v, want %v", arn, got, want)
		}
	}
}

func TestClassifyS3BucketExposure_DenyAllShadowsPublic(t *testing.T) {
	// Cubic review P1: deny-all with no condition must shadow an unconditional
	// public Allow rather than be hidden behind the public branch.
	got, _ := classifyS3BucketExposure(S3BucketReachability{
		HasBucketPolicy: true,
		IdentityGrants: []S3IdentityGrant{
			{Effect: "Allow", IsPublic: true, WildcardPrincipal: true},
			{Effect: "Deny", WildcardPrincipal: true, PrincipalARN: "*"},
		},
	})
	if got != "restricted" {
		t.Fatalf("expected restricted (deny-all shadows public), got %q", got)
	}
}

func TestClassifyS3BucketExposure_DenyAllShadowsCrossAccount(t *testing.T) {
	got, _ := classifyS3BucketExposure(S3BucketReachability{
		HasBucketPolicy: true,
		IdentityGrants: []S3IdentityGrant{
			{Effect: "Allow", IsCrossAccount: true, PrincipalARN: "arn:aws:iam::999999999999:role/x"},
			{Effect: "Deny", WildcardPrincipal: true, PrincipalARN: "*"},
		},
	})
	if got != "restricted" {
		t.Fatalf("expected restricted (deny-all shadows cross_account), got %q", got)
	}
}

func TestNormalizeS3BucketReachabilityScope_PrefersBucketRegion(t *testing.T) {
	scope := AWSCollectorScope{Service: "s3", AccountID: "123456789012", Region: "us-east-1"}
	record := S3BucketReachability{
		BucketName:   "cross-region-bucket",
		BucketRegion: "eu-west-1",
	}
	normalized := normalizeS3BucketReachabilityScope(scope, record, time.Now().UTC())
	if normalized.Region != "eu-west-1" {
		t.Fatalf("expected normalized Region to follow the bucket region (eu-west-1), got %q", normalized.Region)
	}
	if normalized.BucketRegion != "eu-west-1" {
		t.Fatalf("expected BucketRegion preserved, got %q", normalized.BucketRegion)
	}
}

func TestS3ExtractPrincipals_NilReturnsNothing(t *testing.T) {
	principals, principalType, wildcard := s3ExtractPrincipals(nil)
	if len(principals) != 0 || principalType != "" || wildcard {
		t.Fatalf("expected zero values for nil principal, got %v %q %v", principals, principalType, wildcard)
	}
}

func TestS3PrincipalsFromAny_VariantsAndUnknownShape(t *testing.T) {
	ps, pt, wc := s3PrincipalsFromAny("*")
	if len(ps) != 1 || ps[0] != "*" || pt != "*" || !wc {
		t.Fatalf("wildcard string: got %v %q %v", ps, pt, wc)
	}
	ps, pt, wc = s3PrincipalsFromAny("arn:aws:iam::123456789012:role/x")
	if len(ps) != 1 || pt != "aws" || wc {
		t.Fatalf("plain string: got %v %q %v", ps, pt, wc)
	}
	ps, pt, wc = s3PrincipalsFromAny(map[string]any{"Service": "lambda.amazonaws.com"})
	if len(ps) != 1 || pt != "service" || wc {
		t.Fatalf("service map: got %v %q %v", ps, pt, wc)
	}
	ps, pt, wc = s3PrincipalsFromAny(map[string]any{"AWS": []any{"arn:aws:iam::123456789012:role/r", "*"}})
	if len(ps) != 2 || pt != "aws" || !wc {
		t.Fatalf("aws list with wildcard: got %v %q %v", ps, pt, wc)
	}
	ps, pt, wc = s3PrincipalsFromAny(123)
	if len(ps) != 0 || pt != "" || wc {
		t.Fatalf("unknown shape: got %v %q %v", ps, pt, wc)
	}
}

func TestParseS3BucketPolicyGrants_BlankAndInvalid(t *testing.T) {
	grants, count, err := parseS3BucketPolicyGrants("   ")
	if err != nil || count != 0 || len(grants) != 0 {
		t.Fatalf("blank policy: got grants=%v count=%d err=%v", grants, count, err)
	}
	if _, _, err := parseS3BucketPolicyGrants("not json"); err == nil {
		t.Fatalf("expected error on invalid json")
	}
	// URL-encoded policy body must be tolerated.
	grants, _, err = parseS3BucketPolicyGrants("%7B%22Statement%22%3A%5B%5D%7D")
	if err != nil || len(grants) != 0 {
		t.Fatalf("url-encoded empty policy: got grants=%v err=%v", grants, err)
	}
}

func TestS3IsNoSuchBucketPolicy_DoesNotSwallowNoSuchBucket(t *testing.T) {
	// Cubic review P1: NoSuchBucket (bucket doesn't exist) must NOT be
	// classified as "no bucket policy" — that would hide real errors.
	if s3IsNoSuchBucketPolicy(errors.New("NoSuchBucket: The specified bucket does not exist")) {
		t.Fatalf("NoSuchBucket must not be treated as NoSuchBucketPolicy")
	}
	if !s3IsNoSuchBucketPolicy(errors.New("NoSuchBucketPolicy: The bucket policy does not exist")) {
		t.Fatalf("NoSuchBucketPolicy should be recognised")
	}
	if s3IsNoSuchBucketPolicy(nil) {
		t.Fatalf("nil error should return false")
	}
}

func TestS3IsNoSuchSentinels(t *testing.T) {
	if !s3IsNoSuchPublicAccessBlockConfiguration(errors.New("NoSuchPublicAccessBlockConfiguration")) {
		t.Fatalf("expected PAB sentinel match")
	}
	if !s3IsNoSuchOwnershipControls(errors.New("OwnershipControlsNotFoundError")) {
		t.Fatalf("expected ownership sentinel match")
	}
	if !s3IsNoSuchEncryption(errors.New("ServerSideEncryptionConfigurationNotFoundError")) {
		t.Fatalf("expected encryption sentinel match")
	}
	if !s3IsNoSuchTagSet(errors.New("NoSuchTagSet")) {
		t.Fatalf("expected tag sentinel match")
	}
	for _, fn := range []func(error) bool{
		s3IsNoSuchPublicAccessBlockConfiguration,
		s3IsNoSuchOwnershipControls,
		s3IsNoSuchEncryption,
		s3IsNoSuchTagSet,
	} {
		if fn(nil) {
			t.Fatalf("sentinel should return false for nil error")
		}
	}
}
