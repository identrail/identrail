package aws

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
)

type fakeKMSSDKClient struct {
	listKeys     []*kms.ListKeysOutput
	listKeysErr  error
	listKeysCall int
	describe     map[string]*kms.DescribeKeyOutput
	describeErr  map[string]error
	policy       map[string]*kms.GetKeyPolicyOutput
	policyErr    map[string]error
	rotation     map[string]*kms.GetKeyRotationStatusOutput
	rotationErr  map[string]error
	aliases      []*kms.ListAliasesOutput
	aliasesErr   error
	aliasesCall  int
	grants       map[string]*kms.ListGrantsOutput
	grantsErr    map[string]error
	tags         map[string]*kms.ListResourceTagsOutput
	tagsErr      map[string]error
}

func (f *fakeKMSSDKClient) ListKeys(ctx context.Context, _ *kms.ListKeysInput, _ ...func(*kms.Options)) (*kms.ListKeysOutput, error) {
	f.listKeysCall++
	if f.listKeysErr != nil {
		return nil, f.listKeysErr
	}
	if f.listKeysCall > len(f.listKeys) {
		return &kms.ListKeysOutput{}, nil
	}
	return f.listKeys[f.listKeysCall-1], nil
}

func (f *fakeKMSSDKClient) DescribeKey(ctx context.Context, in *kms.DescribeKeyInput, _ ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
	id := awsv2.ToString(in.KeyId)
	if err, ok := f.describeErr[id]; ok {
		return nil, err
	}
	if out, ok := f.describe[id]; ok {
		return out, nil
	}
	// DescribeKey accepts either a key id or an ARN; check both.
	for k, out := range f.describe {
		if out != nil && out.KeyMetadata != nil && awsv2.ToString(out.KeyMetadata.Arn) == id {
			return f.describe[k], nil
		}
	}
	return nil, nil
}

func (f *fakeKMSSDKClient) GetKeyPolicy(ctx context.Context, in *kms.GetKeyPolicyInput, _ ...func(*kms.Options)) (*kms.GetKeyPolicyOutput, error) {
	id := awsv2.ToString(in.KeyId)
	if err, ok := f.policyErr[id]; ok {
		return nil, err
	}
	return f.policy[id], nil
}

func (f *fakeKMSSDKClient) GetKeyRotationStatus(ctx context.Context, in *kms.GetKeyRotationStatusInput, _ ...func(*kms.Options)) (*kms.GetKeyRotationStatusOutput, error) {
	id := awsv2.ToString(in.KeyId)
	if err, ok := f.rotationErr[id]; ok {
		return nil, err
	}
	return f.rotation[id], nil
}

func (f *fakeKMSSDKClient) ListAliases(ctx context.Context, _ *kms.ListAliasesInput, _ ...func(*kms.Options)) (*kms.ListAliasesOutput, error) {
	f.aliasesCall++
	if f.aliasesErr != nil {
		return nil, f.aliasesErr
	}
	if f.aliasesCall > len(f.aliases) {
		return &kms.ListAliasesOutput{}, nil
	}
	return f.aliases[f.aliasesCall-1], nil
}

func (f *fakeKMSSDKClient) ListGrants(ctx context.Context, in *kms.ListGrantsInput, _ ...func(*kms.Options)) (*kms.ListGrantsOutput, error) {
	id := awsv2.ToString(in.KeyId)
	if err, ok := f.grantsErr[id]; ok {
		return nil, err
	}
	if out, ok := f.grants[id]; ok {
		return out, nil
	}
	return &kms.ListGrantsOutput{}, nil
}

func (f *fakeKMSSDKClient) ListResourceTags(ctx context.Context, in *kms.ListResourceTagsInput, _ ...func(*kms.Options)) (*kms.ListResourceTagsOutput, error) {
	id := awsv2.ToString(in.KeyId)
	if err, ok := f.tagsErr[id]; ok {
		return nil, err
	}
	if out, ok := f.tags[id]; ok {
		return out, nil
	}
	return &kms.ListResourceTagsOutput{}, nil
}

func TestSDKKMSDecryptReachabilityAPI_NilClient(t *testing.T) {
	api := &SDKKMSDecryptReachabilityAPI{}
	if _, err := api.ListKMSKeyReachability(context.Background(), "", 0); err == nil {
		t.Fatalf("expected error with nil client")
	}
}

func TestSDKKMSDecryptReachabilityAPI_ListKeysError(t *testing.T) {
	api := NewSDKKMSDecryptReachabilityAPIFromClient(&fakeKMSSDKClient{listKeysErr: errors.New("boom")}, "123456789012", "us-east-1")
	if _, err := api.ListKMSKeyReachability(context.Background(), "", 0); err == nil {
		t.Fatalf("expected error")
	}
}

func TestSDKKMSDecryptReachabilityAPI_FullEnrichment(t *testing.T) {
	created := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cmkID := "aaaa1111-2222-3333-4444-555566667777"
	awsManagedID := "bbbb1111-2222-3333-4444-555566667777"
	asymmetricID := "cccc1111-2222-3333-4444-555566667777"
	externalID := "dddd1111-2222-3333-4444-555566667777"
	fake := &fakeKMSSDKClient{
		listKeys: []*kms.ListKeysOutput{{
			Keys: []kmstypes.KeyListEntry{
				{KeyId: awsv2.String(cmkID), KeyArn: awsv2.String("arn:aws:kms:us-east-1:123456789012:key/" + cmkID)},
				{KeyId: awsv2.String(awsManagedID), KeyArn: awsv2.String("arn:aws:kms:us-east-1:123456789012:key/" + awsManagedID)},
				{KeyId: awsv2.String(asymmetricID), KeyArn: awsv2.String("arn:aws:kms:us-east-1:123456789012:key/" + asymmetricID)},
				{KeyId: awsv2.String(externalID), KeyArn: awsv2.String("arn:aws:kms:us-east-1:123456789012:key/" + externalID)},
				{KeyId: awsv2.String(""), KeyArn: awsv2.String("")},
			},
		}},
		describe: map[string]*kms.DescribeKeyOutput{
			cmkID: {KeyMetadata: &kmstypes.KeyMetadata{
				KeyId:        awsv2.String(cmkID),
				Arn:          awsv2.String("arn:aws:kms:us-east-1:123456789012:key/" + cmkID),
				AWSAccountId: awsv2.String("123456789012"),
				KeyManager:   kmstypes.KeyManagerTypeCustomer,
				KeyState:     kmstypes.KeyStateEnabled,
				KeyUsage:     kmstypes.KeyUsageTypeEncryptDecrypt,
				KeySpec:      kmstypes.KeySpecSymmetricDefault,
				Origin:       kmstypes.OriginTypeAwsKms,
				CreationDate: &created,
				Enabled:      true,
				MultiRegion:  awsv2.Bool(true),
				MultiRegionConfiguration: &kmstypes.MultiRegionConfiguration{
					MultiRegionKeyType: kmstypes.MultiRegionKeyTypePrimary,
					PrimaryKey:         &kmstypes.MultiRegionKey{Arn: awsv2.String("arn:aws:kms:us-east-1:123456789012:key/" + cmkID)},
					ReplicaKeys:        []kmstypes.MultiRegionKey{{Arn: awsv2.String("arn:aws:kms:eu-west-1:123456789012:key/replica")}},
				},
			}},
			awsManagedID: {KeyMetadata: &kmstypes.KeyMetadata{
				KeyId:      awsv2.String(awsManagedID),
				Arn:        awsv2.String("arn:aws:kms:us-east-1:123456789012:key/" + awsManagedID),
				KeyManager: kmstypes.KeyManagerTypeAws,
				KeyState:   kmstypes.KeyStateEnabled,
			}},
			asymmetricID: {KeyMetadata: &kmstypes.KeyMetadata{
				KeyId:      awsv2.String(asymmetricID),
				Arn:        awsv2.String("arn:aws:kms:us-east-1:123456789012:key/" + asymmetricID),
				KeyManager: kmstypes.KeyManagerTypeCustomer,
				KeyState:   kmstypes.KeyStateEnabled,
				KeyUsage:   kmstypes.KeyUsageTypeSignVerify,
				KeySpec:    kmstypes.KeySpec("RSA_4096"),
				Origin:     kmstypes.OriginTypeAwsKms,
			}},
			externalID: {KeyMetadata: &kmstypes.KeyMetadata{
				KeyId:      awsv2.String(externalID),
				Arn:        awsv2.String("arn:aws:kms:us-east-1:123456789012:key/" + externalID),
				KeyManager: kmstypes.KeyManagerTypeCustomer,
				KeyState:   kmstypes.KeyStateEnabled,
				KeyUsage:   kmstypes.KeyUsageTypeEncryptDecrypt,
				KeySpec:    kmstypes.KeySpecSymmetricDefault,
				Origin:     kmstypes.OriginTypeExternal,
			}},
		},
		policy: map[string]*kms.GetKeyPolicyOutput{
			cmkID: {Policy: awsv2.String(`{"Statement":[{"Sid":"EnableIAMUserPermissions","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"kms:*","Resource":"*"}]}`)},
		},
		policyErr: map[string]error{
			asymmetricID: errors.New("AccessDenied: policy"),
		},
		rotation: map[string]*kms.GetKeyRotationStatusOutput{
			cmkID: {KeyRotationEnabled: true},
		},
		rotationErr: map[string]error{
			asymmetricID: errors.New("UnsupportedOperationException: KMS key with arn does not support rotation"),
		},
		aliases: []*kms.ListAliasesOutput{{
			Aliases: []kmstypes.AliasListEntry{
				{AliasName: awsv2.String("alias/payments"), TargetKeyId: awsv2.String(cmkID)},
				{AliasName: awsv2.String("alias/aws/s3"), TargetKeyId: awsv2.String(awsManagedID)},
				{AliasName: awsv2.String(""), TargetKeyId: awsv2.String(cmkID)},
			},
		}},
		grants: map[string]*kms.ListGrantsOutput{
			cmkID: {Grants: []kmstypes.GrantListEntry{{
				GrantId:          awsv2.String("grant-1"),
				Name:             awsv2.String("lambda-decrypt"),
				GranteePrincipal: awsv2.String("arn:aws:iam::123456789012:role/lambda-decrypt"),
				Operations:       []kmstypes.GrantOperation{kmstypes.GrantOperationDecrypt},
				Constraints: &kmstypes.GrantConstraints{
					EncryptionContextEquals: map[string]string{
						"tenant_id": "secret-value-we-dont-keep",
						"app":       "billing",
					},
					EncryptionContextSubset: map[string]string{
						"region": "us-east-1",
						"env":    "prod",
					},
				},
				CreationDate: &created,
			}}},
		},
		tags: map[string]*kms.ListResourceTagsOutput{
			cmkID: {Tags: []kmstypes.Tag{{TagKey: awsv2.String("owner"), TagValue: awsv2.String("payments")}, {TagKey: awsv2.String(""), TagValue: awsv2.String("ignored")}}},
		},
	}
	api := NewSDKKMSDecryptReachabilityAPIFromClient(fake, "123456789012", "us-east-1")
	page, err := api.ListKMSKeyReachability(context.Background(), "", 0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	byID := map[string]KMSDecryptReachability{}
	for _, r := range page.Records {
		byID[r.KeyID] = r
	}
	if len(byID) != 4 {
		t.Fatalf("expected 4 named records, got %d", len(byID))
	}
	cmk := byID[cmkID]
	if cmk.KeyManager != string(kmstypes.KeyManagerTypeCustomer) {
		t.Fatalf("expected customer manager, got %q", cmk.KeyManager)
	}
	if !cmk.HasKeyPolicy || !cmk.IAMDelegationEnabled {
		t.Fatalf("expected policy + IAM delegation, got %+v", cmk)
	}
	if !cmk.RotationSupported || !cmk.RotationEnabled {
		t.Fatalf("expected rotation supported + enabled, got %+v", cmk)
	}
	if !cmk.MultiRegion || !cmk.MultiRegionPrimary || len(cmk.ReplicaKeyARNs) != 1 {
		t.Fatalf("expected multi-region primary with replica, got %+v", cmk)
	}
	if len(cmk.Aliases) != 1 || cmk.Aliases[0] != "alias/payments" {
		t.Fatalf("expected single alias/payments, got %+v", cmk.Aliases)
	}
	if len(cmk.Grants) != 1 || cmk.Grants[0].GranteePrincipal == "" {
		t.Fatalf("expected one live grant, got %+v", cmk.Grants)
	}
	// Encryption context VALUES must never reach the record.
	if got, want := cmk.Grants[0].EncryptionContextKeys, []string{"app", "tenant_id"}; !slices.Equal(got, want) {
		t.Fatalf("expected sorted encryption-context keys %+v, got %+v", want, got)
	}
	if got, want := cmk.Grants[0].EncryptionContextSubsetKeys, []string{"env", "region"}; !slices.Equal(got, want) {
		t.Fatalf("expected sorted encryption-context subset keys %+v, got %+v", want, got)
	}
	for _, key := range cmk.Grants[0].EncryptionContextKeys {
		if key == "secret-value-we-dont-keep" {
			t.Fatalf("encryption context VALUES leaked into record")
		}
	}
	if v, ok := cmk.Tags["owner"]; !ok || v != "payments" {
		t.Fatalf("expected owner tag, got %+v", cmk.Tags)
	}

	awsManaged := byID[awsManagedID]
	if awsManaged.KeyManager != string(kmstypes.KeyManagerTypeAws) {
		t.Fatalf("expected AWS-managed, got %+v", awsManaged.KeyManager)
	}

	asym := byID[asymmetricID]
	if asym.RotationSupported {
		t.Fatalf("asymmetric keys must not be rotation-supported, got %+v", asym)
	}
	external := byID[externalID]
	if external.RotationSupported {
		t.Fatalf("external-origin imported keys must not be rotation-supported, got %+v", external)
	}
	// UnsupportedOperationException must NOT produce a rotation diagnostic.
	codes := map[string]int{}
	for _, d := range page.Diagnostics {
		codes[d.Code]++
	}
	if codes["kms_key_rotation_failed"] > 0 {
		t.Fatalf("unsupported rotation must not produce a diagnostic, got codes=%+v", codes)
	}
	if codes["kms_key_policy_failed"] == 0 {
		t.Fatalf("expected kms_key_policy_failed for asymmetric AccessDenied")
	}
	if codes["kms_key_id_missing"] == 0 {
		t.Fatalf("expected kms_key_id_missing for empty key in summary")
	}
}

func TestSDKKMSDecryptReachabilityAPI_AliasesError(t *testing.T) {
	api := NewSDKKMSDecryptReachabilityAPIFromClient(&fakeKMSSDKClient{
		listKeys:   []*kms.ListKeysOutput{{}},
		aliasesErr: errors.New("AccessDenied: ListAliases"),
	}, "123456789012", "us-east-1")
	page, err := api.ListKMSKeyReachability(context.Background(), "", 0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	found := false
	for _, d := range page.Diagnostics {
		if d.Code == "kms_list_aliases_failed" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected aliases diagnostic")
	}
}

func TestSDKKMSDecryptReachabilityAPI_GrantsError(t *testing.T) {
	cmkID := "aaaa1111-2222-3333-4444-555566667777"
	fake := &fakeKMSSDKClient{
		listKeys: []*kms.ListKeysOutput{{
			Keys: []kmstypes.KeyListEntry{{KeyId: awsv2.String(cmkID), KeyArn: awsv2.String("arn:aws:kms:us-east-1:123456789012:key/" + cmkID)}},
		}},
		describe: map[string]*kms.DescribeKeyOutput{
			cmkID: {KeyMetadata: &kmstypes.KeyMetadata{
				KeyId:      awsv2.String(cmkID),
				Arn:        awsv2.String("arn:aws:kms:us-east-1:123456789012:key/" + cmkID),
				KeyManager: kmstypes.KeyManagerTypeCustomer,
			}},
		},
		grantsErr: map[string]error{cmkID: errors.New("AccessDenied: ListGrants")},
	}
	api := NewSDKKMSDecryptReachabilityAPIFromClient(fake, "123456789012", "us-east-1")
	page, err := api.ListKMSKeyReachability(context.Background(), "", 0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	found := false
	for _, d := range page.Diagnostics {
		if d.Code == "kms_list_grants_failed" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected list_grants diagnostic")
	}
}

func TestKMSIsRotationUnsupported(t *testing.T) {
	cases := map[string]bool{
		"UnsupportedOperationException: KMS key spec does not support rotation": true,
		"KMS key with arn does not support rotation":                            true,
		"GenerateDataKey is not supported for asymmetric keys":                  true,
		"AccessDenied: rotation":                                                false,
		"":                                                                      false,
	}
	for in, want := range cases {
		var err error
		if in != "" {
			err = errors.New(in)
		}
		if got := kmsIsRotationUnsupported(err); got != want {
			t.Fatalf("kmsIsRotationUnsupported(%q)=%v want %v", in, got, want)
		}
	}
}
