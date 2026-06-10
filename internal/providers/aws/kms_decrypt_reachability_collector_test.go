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

type fakeKMSDecryptReachabilityAPI struct {
	pages []KMSDecryptReachabilityPage
	calls int
	err   error
}

func (f *fakeKMSDecryptReachabilityAPI) ListKMSKeyReachability(ctx context.Context, nextToken string, pageSize int32) (KMSDecryptReachabilityPage, error) {
	f.calls++
	if f.err != nil {
		return KMSDecryptReachabilityPage{}, f.err
	}
	if len(f.pages) == 0 {
		return KMSDecryptReachabilityPage{}, nil
	}
	page := f.pages[0]
	f.pages = f.pages[1:]
	return page, nil
}

func TestParseKMSKeyPolicyGrants_DelegationAndAppGrant(t *testing.T) {
	owner := "123456789012"
	grants, count, iam, err := parseKMSKeyPolicyGrants(`{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Sid": "EnableIAMUserPermissions",
				"Effect": "Allow",
				"Principal": {"AWS": "arn:aws:iam::123456789012:root"},
				"Action": "kms:*",
				"Resource": "*"
			},
			{
				"Sid": "AppDecrypt",
				"Effect": "Allow",
				"Principal": {"AWS": "arn:aws:iam::123456789012:role/payments-app"},
				"Action": ["kms:Decrypt", "kms:GenerateDataKey"],
				"Resource": "*"
			}
		]
	}`, owner)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if count != 2 {
		t.Fatalf("expected 2 statements, got %d", count)
	}
	if !iam {
		t.Fatalf("expected EnableIAMUserPermissions to be detected")
	}
	if len(grants) != 2 {
		t.Fatalf("expected 2 grants, got %d", len(grants))
	}
}

func TestParseKMSKeyPolicyGrants_PublicWildcardWithoutCondition(t *testing.T) {
	grants, _, iam, err := parseKMSKeyPolicyGrants(`{
		"Version": "2012-10-17",
		"Statement": [{
			"Sid": "PublicDecrypt",
			"Effect": "Allow",
			"Principal": "*",
			"Action": "kms:Decrypt",
			"Resource": "*"
		}]
	}`, "123456789012")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if iam {
		t.Fatalf("wildcard principal must not be detected as IAM delegation")
	}
	if len(grants) != 1 || !grants[0].WildcardPrincipal || grants[0].PrincipalARN != "*" {
		t.Fatalf("expected wildcard principal grant, got %+v", grants)
	}
}

func TestParseKMSKeyPolicyGrants_NotPrincipalIsSkipped(t *testing.T) {
	grants, _, _, err := parseKMSKeyPolicyGrants(`{
		"Statement": [{
			"Effect": "Allow",
			"NotPrincipal": {"AWS": "arn:aws:iam::123456789012:role/admin"},
			"Action": "kms:Decrypt",
			"Resource": "*"
		}]
	}`, "123456789012")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(grants) != 0 {
		t.Fatalf("expected NotPrincipal to be skipped, got %+v", grants)
	}
}

func TestParseKMSKeyPolicyGrants_NotActionIsSkipped(t *testing.T) {
	grants, _, _, err := parseKMSKeyPolicyGrants(`{
		"Statement": [{
			"Effect": "Allow",
			"Principal": {"AWS": "arn:aws:iam::123456789012:role/app"},
			"NotAction": "kms:Encrypt",
			"Resource": "*"
		}]
	}`, "123456789012")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(grants) != 0 {
		t.Fatalf("expected NotAction to be skipped, got %+v", grants)
	}
}

func TestParseKMSKeyPolicyGrants_PreservesAllPrincipalEntries(t *testing.T) {
	grants, _, _, err := parseKMSKeyPolicyGrants(`{
		"Statement": [{
			"Effect": "Allow",
			"Principal": {
				"AWS": ["arn:aws:iam::123456789012:role/app", "arn:aws:iam::123456789012:user/alice"],
				"Service": "lambda.amazonaws.com"
			},
			"Action": "kms:Decrypt",
			"Resource": "*"
		}]
	}`, "123456789012")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(grants) != 3 {
		t.Fatalf("expected all principal entries, got %+v", grants)
	}
	want := map[string]string{
		"arn:aws:iam::123456789012:role/app":   "aws",
		"arn:aws:iam::123456789012:user/alice": "aws",
		"lambda.amazonaws.com":                 "service",
	}
	for _, grant := range grants {
		wantType, ok := want[grant.PrincipalARN]
		if !ok {
			t.Fatalf("unexpected principal %q in %+v", grant.PrincipalARN, grants)
		}
		if grant.PrincipalType != wantType {
			t.Fatalf("expected principal %q type %q, got %q", grant.PrincipalARN, wantType, grant.PrincipalType)
		}
		delete(want, grant.PrincipalARN)
	}
	for principal := range want {
		t.Fatalf("expected principal %q in %+v", principal, grants)
	}
}

func TestParseKMSKeyPolicyGrants_MalformedShape(t *testing.T) {
	if _, _, _, err := parseKMSKeyPolicyGrants(`{"Statement": 42}`, ""); err == nil {
		t.Fatalf("expected error on malformed statement shape")
	}
}

func TestParseKMSKeyPolicyGrants_BlankAndURLEncoded(t *testing.T) {
	if grants, count, iam, err := parseKMSKeyPolicyGrants("  ", ""); err != nil || count != 0 || iam || len(grants) != 0 {
		t.Fatalf("blank policy: grants=%v count=%d iam=%v err=%v", grants, count, iam, err)
	}
	encoded := "%7B%22Statement%22%3A%5B%5D%7D"
	if _, count, _, err := parseKMSKeyPolicyGrants(encoded, ""); err != nil || count != 0 {
		t.Fatalf("url-encoded empty policy: count=%d err=%v", count, err)
	}
}

func TestKMSCapabilitiesForActions_BucketsByClass(t *testing.T) {
	cases := []struct {
		actions []string
		want    []string
	}{
		{[]string{"kms:Decrypt"}, []string{"decrypt"}},
		{[]string{"kms:GenerateDataKeyWithoutPlaintext"}, []string{"decrypt", "encrypt"}},
		{[]string{"kms:ReEncryptFrom", "kms:ReEncryptTo"}, []string{"decrypt", "encrypt"}},
		{[]string{"kms:Sign", "kms:Verify"}, []string{"sign"}},
		{[]string{"kms:CreateGrant", "kms:ListGrants"}, []string{"grant"}},
		{[]string{"kms:PutKeyPolicy", "kms:ScheduleKeyDeletion"}, []string{"admin"}},
		{[]string{"kms:*"}, []string{"admin", "decrypt", "encrypt", "grant", "sign"}},
		{nil, nil},
		{[]string{"unknown:action"}, nil},
	}
	for _, tc := range cases {
		got := kmsCapabilitiesForActions(tc.actions)
		if !equalStringSlices(got, tc.want) {
			t.Fatalf("kmsCapabilitiesForActions(%v) = %v, want %v", tc.actions, got, tc.want)
		}
	}
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestClassifyKMSKeyExposure_DenyAllShadowsPublic(t *testing.T) {
	got, _ := classifyKMSKeyExposure(KMSDecryptReachability{
		HasKeyPolicy: true,
		KeyManager:   "CUSTOMER",
		IdentityGrants: []KMSIdentityGrant{
			{Effect: "Allow", IsPublic: true, WildcardPrincipal: true, PrincipalARN: "*"},
			{Effect: "Deny", WildcardPrincipal: true, PrincipalARN: "*"},
		},
	})
	if got != "restricted" {
		t.Fatalf("expected restricted, got %q", got)
	}
}

func TestClassifyKMSKeyExposure_Public(t *testing.T) {
	got, _ := classifyKMSKeyExposure(KMSDecryptReachability{
		HasKeyPolicy: true,
		KeyManager:   "CUSTOMER",
		IdentityGrants: []KMSIdentityGrant{
			{Effect: "Allow", IsPublic: true, WildcardPrincipal: true, PrincipalARN: "*"},
		},
	})
	if got != "public" {
		t.Fatalf("expected public, got %q", got)
	}
}

func TestClassifyKMSKeyExposure_CrossAccountFromLiveGrant(t *testing.T) {
	got, _ := classifyKMSKeyExposure(KMSDecryptReachability{
		HasKeyPolicy: true,
		KeyManager:   "CUSTOMER",
		Grants: []KMSGrant{{
			GranteePrincipal: "arn:aws:iam::999999999999:role/partner",
			IsCrossAccount:   true,
		}},
	})
	if got != "cross_account" {
		t.Fatalf("expected cross_account, got %q", got)
	}
}

func TestClassifyKMSKeyExposure_ManagedByIAM(t *testing.T) {
	rec := KMSDecryptReachability{
		HasKeyPolicy:         true,
		KeyManager:           "CUSTOMER",
		IAMDelegationEnabled: true,
		IdentityGrants: []KMSIdentityGrant{
			{
				Effect:       "Allow",
				PrincipalARN: "arn:aws:iam::123456789012:root",
				Actions:      []string{"kms:*"},
			},
		},
	}
	rec.AccountID = "123456789012"
	got, _ := classifyKMSKeyExposure(rec)
	if got != "managed_by_iam" {
		t.Fatalf("expected managed_by_iam, got %q", got)
	}
}

func TestClassifyKMSKeyExposure_ManagedByAWS(t *testing.T) {
	got, _ := classifyKMSKeyExposure(KMSDecryptReachability{KeyManager: "AWS"})
	if got != "managed_by_aws" {
		t.Fatalf("expected managed_by_aws, got %q", got)
	}
}

func TestClassifyKMSKeyExposure_PrivateWithGrants(t *testing.T) {
	rec := KMSDecryptReachability{
		HasKeyPolicy: true,
		KeyManager:   "CUSTOMER",
		IdentityGrants: []KMSIdentityGrant{{
			Effect:       "Allow",
			PrincipalARN: "arn:aws:iam::123456789012:role/payments",
			Actions:      []string{"kms:Decrypt"},
		}},
	}
	rec.AccountID = "123456789012"
	got, _ := classifyKMSKeyExposure(rec)
	if got != "private_with_grants" {
		t.Fatalf("expected private_with_grants, got %q", got)
	}
}

func TestClassifyKMSKeyExposure_PrivateDefault(t *testing.T) {
	got, _ := classifyKMSKeyExposure(KMSDecryptReachability{KeyManager: "CUSTOMER"})
	if got != "private" {
		t.Fatalf("expected private, got %q", got)
	}
}

func TestIsIAMDelegationGrant(t *testing.T) {
	owner := "123456789012"
	yes := KMSIdentityGrant{
		Effect:       "Allow",
		PrincipalARN: "arn:aws:iam::123456789012:root",
		Actions:      []string{"kms:*"},
	}
	if !isIAMDelegationGrant(yes, owner) {
		t.Fatalf("expected delegation grant to match")
	}
	wrongAccount := yes
	wrongAccount.PrincipalARN = "arn:aws:iam::999999999999:root"
	if isIAMDelegationGrant(wrongAccount, owner) {
		t.Fatalf("delegation must be account-scoped")
	}
	conditioned := yes
	conditioned.HasCondition = true
	if isIAMDelegationGrant(conditioned, owner) {
		t.Fatalf("conditional grants must not be delegation")
	}
	wildcard := yes
	wildcard.WildcardPrincipal = true
	if isIAMDelegationGrant(wildcard, owner) {
		t.Fatalf("wildcard principal must not be delegation")
	}
	narrow := yes
	narrow.Actions = []string{"kms:Decrypt"}
	if isIAMDelegationGrant(narrow, owner) {
		t.Fatalf("narrow actions must not be delegation")
	}
}

func TestAnnotateKMSGrants_CrossAccountAndCapabilities(t *testing.T) {
	out := annotateKMSGrants([]KMSIdentityGrant{{
		PrincipalARN: "arn:aws:iam::999999999999:role/partner",
		Effect:       "Allow",
		Actions:      []string{"kms:Decrypt"},
	}}, "123456789012")
	if len(out) != 1 || !out[0].IsCrossAccount {
		t.Fatalf("expected cross-account flag, got %+v", out)
	}
	if len(out[0].Capabilities) != 1 || out[0].Capabilities[0] != "decrypt" {
		t.Fatalf("expected decrypt capability, got %+v", out[0].Capabilities)
	}
}

func TestAnnotateKMSLiveGrants_CrossAccount(t *testing.T) {
	out := annotateKMSLiveGrants([]KMSGrant{{
		GranteePrincipal: "arn:aws:iam::999999999999:role/partner",
		Operations:       []string{"Decrypt"},
	}}, "123456789012")
	if len(out) != 1 || !out[0].IsCrossAccount {
		t.Fatalf("expected cross-account live grant, got %+v", out)
	}
	if len(out[0].Capabilities) != 1 || out[0].Capabilities[0] != "decrypt" {
		t.Fatalf("expected decrypt capability, got %+v", out[0].Capabilities)
	}
}

func TestKMSDecryptReachabilityCollector_NormalizesAndDedupes(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	api := &fakeKMSDecryptReachabilityAPI{pages: []KMSDecryptReachabilityPage{
		{Records: []KMSDecryptReachability{
			{KeyID: "k1", KeyARN: "arn:aws:kms:us-east-1:123456789012:key/k1"},
			{KeyID: "k1", KeyARN: "arn:aws:kms:us-east-1:123456789012:key/k1"}, // dup
			{KeyID: "k2", KeyARN: "arn:aws:kms:us-east-1:123456789012:key/k2"},
		}, NextToken: "next"},
		{Records: []KMSDecryptReachability{
			{KeyID: "k3", KeyARN: "arn:aws:kms:us-east-1:123456789012:key/k3"},
		}},
	}}
	c := NewKMSDecryptReachabilityCollector(api, WithKMSDecryptReachabilityClock(func() time.Time { return now }))
	assets, diags, err := c.CollectWithDiagnostics(context.Background(), AWSCollectorScope{
		Service:   "kms",
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
	var first KMSDecryptReachability
	if err := json.Unmarshal(assets[0].Payload, &first); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if first.TenantID != "tenant-1" || first.AccountID != "123456789012" {
		t.Fatalf("scope not propagated: %+v", first)
	}
	if assets[0].Kind != rawKindKMSDecryptReachability {
		t.Fatalf("unexpected raw kind: %s", assets[0].Kind)
	}
}

func TestKMSDecryptReachabilityCollector_PageLimitDiagnostic(t *testing.T) {
	api := &fakeKMSDecryptReachabilityAPI{pages: []KMSDecryptReachabilityPage{
		{Records: []KMSDecryptReachability{{KeyID: "a", KeyARN: "arn:aws:kms:us-east-1:123456789012:key/a"}}, NextToken: "p2"},
		{Records: []KMSDecryptReachability{{KeyID: "b", KeyARN: "arn:aws:kms:us-east-1:123456789012:key/b"}}, NextToken: "p3"},
	}}
	c := NewKMSDecryptReachabilityCollector(api, WithKMSDecryptReachabilityMaxPages(1))
	_, diags, err := c.CollectWithDiagnostics(context.Background(), AWSCollectorScope{Service: "kms", AccountID: "123456789012", Region: "us-east-1"})
	if err == nil {
		t.Fatalf("expected page-limit error")
	}
	found := false
	for _, d := range diags {
		if d.Code == "kms_decrypt_reachability_page_limit_exceeded" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected page-limit diagnostic, got %+v", diags)
	}
}

func TestKMSDecryptReachabilityCollector_ListErrorPropagates(t *testing.T) {
	api := &fakeKMSDecryptReachabilityAPI{err: errors.New("boom")}
	c := NewKMSDecryptReachabilityCollector(api,
		WithKMSDecryptReachabilityRetryPolicy(RetryPolicy{MaxRetries: 0, BaseDelay: time.Microsecond, MaxDelay: time.Microsecond}),
		WithKMSDecryptReachabilitySleeper(func(ctx context.Context, _ time.Duration) error { return nil }),
	)
	assets, diags, err := c.CollectWithDiagnostics(context.Background(), AWSCollectorScope{Service: "kms"})
	if err == nil {
		t.Fatalf("expected error")
	}
	if len(assets) != 0 {
		t.Fatalf("expected no assets, got %d", len(assets))
	}
	if len(diags) == 0 {
		t.Fatalf("expected diagnostic on list failure")
	}
}

func TestKMSDecryptReachabilityCollector_SkipsMalformedRecord(t *testing.T) {
	api := &fakeKMSDecryptReachabilityAPI{pages: []KMSDecryptReachabilityPage{{Records: []KMSDecryptReachability{{}}}}}
	c := NewKMSDecryptReachabilityCollector(api)
	assets, diags, err := c.CollectWithDiagnostics(context.Background(), AWSCollectorScope{Service: "kms"})
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(assets) != 0 {
		t.Fatalf("expected no assets, got %d", len(assets))
	}
	found := false
	for _, d := range diags {
		if d.Code == "malformed_kms_decrypt_reachability_record" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected malformed diagnostic, got %+v", diags)
	}
}

func TestKMSDecryptReachabilityCollector_NilClient(t *testing.T) {
	c := NewKMSDecryptReachabilityCollector(nil)
	if _, _, err := c.CollectWithDiagnostics(context.Background(), AWSCollectorScope{Service: "kms"}); err == nil {
		t.Fatalf("expected error when client nil")
	}
}

func TestKMSDecryptReachabilityCollector_ServiceName(t *testing.T) {
	c := NewKMSDecryptReachabilityCollector(&fakeKMSDecryptReachabilityAPI{})
	if c.ServiceName() != "kms" {
		t.Fatalf("expected service name kms, got %q", c.ServiceName())
	}
}

func TestKMSDecryptReachabilityCollector_AcceptsDiagnostics(t *testing.T) {
	api := &fakeKMSDecryptReachabilityAPI{pages: []KMSDecryptReachabilityPage{{
		Records: []KMSDecryptReachability{{KeyID: "k1", KeyARN: "arn:aws:kms:us-east-1:123456789012:key/k1"}},
		Diagnostics: []providers.SourceError{{
			Collector: kmsDecryptReachabilityCollectorName,
			SourceID:  "k1",
			Code:      "kms_list_grants_failed",
			Message:   "denied",
		}},
	}}}
	c := NewKMSDecryptReachabilityCollector(api)
	_, diags, err := c.CollectWithDiagnostics(context.Background(), AWSCollectorScope{Service: "kms", AccountID: "123456789012", Region: "us-east-1"})
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(diags) != 1 || diags[0].Code != "kms_list_grants_failed" {
		t.Fatalf("expected collector diagnostic, got %+v", diags)
	}
}

func TestKMSKeyARNFromIDPartitionAware(t *testing.T) {
	cases := []struct {
		region, partition string
	}{
		{"us-east-1", "aws"},
		{"us-gov-west-1", "aws-us-gov"},
		{"cn-north-1", "aws-cn"},
	}
	for _, tc := range cases {
		arn := kmsKeyARNFromID("key123", "123456789012", tc.region)
		if !strings.HasPrefix(arn, "arn:"+tc.partition+":kms:"+tc.region+":") {
			t.Fatalf("region %q: expected partition %q, got %q", tc.region, tc.partition, arn)
		}
	}
	if got := kmsKeyARNFromID("", "123456789012", "us-east-1"); got != "" {
		t.Fatalf("expected empty ARN for empty id, got %q", got)
	}
}

func TestKMSDecryptReachabilityConfidenceFallback(t *testing.T) {
	if got := kmsDecryptReachabilityConfidence(KMSDecryptReachability{ExposureClassification: ""}); got != 0.7 {
		t.Fatalf("expected 0.7 for unknown classification, got %v", got)
	}
	if got := kmsDecryptReachabilityConfidence(KMSDecryptReachability{ExposureClassification: "public"}); got != 0.95 {
		t.Fatalf("expected 0.95 for public, got %v", got)
	}
}

func TestCanonicalKMSGrantEffect(t *testing.T) {
	for in, want := range map[string]string{"allow": "Allow", "DENY": "Deny", "Other": "Other", "": ""} {
		if got := canonicalKMSGrantEffect(in); got != want {
			t.Fatalf("canonicalKMSGrantEffect(%q)=%q want %q", in, got, want)
		}
	}
}
