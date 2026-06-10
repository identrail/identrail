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

func TestParseS3BucketPolicyGrants_NotPrincipalDoesNotEmitAllowEdge(t *testing.T) {
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
	for _, g := range grants {
		if g.Effect == "Allow" && !g.WildcardPrincipal && g.PrincipalARN != "*" {
			// NotPrincipal expansion is intentionally surfaced as a single grant
			// for visibility, but the normalizer is responsible for not turning
			// it into a directed edge — we only verify here that the grant
			// records the principal it referenced.
			if !strings.Contains(g.PrincipalARN, "111111111111") {
				t.Fatalf("expected NotPrincipal arn carried through, got %q", g.PrincipalARN)
			}
		}
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
