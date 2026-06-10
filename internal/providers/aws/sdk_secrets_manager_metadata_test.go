package aws

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	smtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
)

type fakeSecretsManagerSDKClient struct {
	listSecrets       *secretsmanager.ListSecretsOutput
	listSecretsErr    error
	describe          map[string]*secretsmanager.DescribeSecretOutput
	describeErr       map[string]error
	resourcePolicy    map[string]*secretsmanager.GetResourcePolicyOutput
	resourcePolicyErr map[string]error
	versions          map[string]*secretsmanager.ListSecretVersionIdsOutput
	versionsErr       map[string]error
}

func (f *fakeSecretsManagerSDKClient) ListSecrets(ctx context.Context, input *secretsmanager.ListSecretsInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.ListSecretsOutput, error) {
	if f.listSecretsErr != nil {
		return nil, f.listSecretsErr
	}
	return f.listSecrets, nil
}

func (f *fakeSecretsManagerSDKClient) DescribeSecret(ctx context.Context, input *secretsmanager.DescribeSecretInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.DescribeSecretOutput, error) {
	id := awsv2.ToString(input.SecretId)
	if err, ok := f.describeErr[id]; ok {
		return nil, err
	}
	return f.describe[id], nil
}

func (f *fakeSecretsManagerSDKClient) GetResourcePolicy(ctx context.Context, input *secretsmanager.GetResourcePolicyInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetResourcePolicyOutput, error) {
	id := awsv2.ToString(input.SecretId)
	if err, ok := f.resourcePolicyErr[id]; ok {
		return nil, err
	}
	return f.resourcePolicy[id], nil
}

func (f *fakeSecretsManagerSDKClient) ListSecretVersionIds(ctx context.Context, input *secretsmanager.ListSecretVersionIdsInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.ListSecretVersionIdsOutput, error) {
	id := awsv2.ToString(input.SecretId)
	if err, ok := f.versionsErr[id]; ok {
		return nil, err
	}
	return f.versions[id], nil
}

func TestSDKSecretsManagerMetadataAPI_ListSecretMetadataEnrichesRecord(t *testing.T) {
	arn := "arn:aws:secretsmanager:us-east-1:123456789012:secret:payments/db-AbCdEf"
	now := time.Date(2026, 6, 10, 10, 0, 0, 0, time.UTC)
	fake := &fakeSecretsManagerSDKClient{
		listSecrets: &secretsmanager.ListSecretsOutput{
			SecretList: []smtypes.SecretListEntry{{
				ARN:             awsv2.String(arn),
				Name:            awsv2.String("payments/db"),
				Description:     awsv2.String("sensitive operator note do not persist"),
				RotationEnabled: awsv2.Bool(true),
				KmsKeyId:        awsv2.String("alias/payments"),
				Tags:            []smtypes.Tag{{Key: awsv2.String("owner"), Value: awsv2.String("payments")}},
			}},
		},
		describe: map[string]*secretsmanager.DescribeSecretOutput{
			arn: {
				ARN:             awsv2.String(arn),
				Name:            awsv2.String("payments/db"),
				Description:     awsv2.String("another sensitive note"),
				RotationEnabled: awsv2.Bool(true),
				RotationRules:   &smtypes.RotationRulesType{AutomaticallyAfterDays: awsv2.Int64(30)},
				CreatedDate:     &now,
				Tags:            []smtypes.Tag{{Key: awsv2.String("env"), Value: awsv2.String("prod")}},
			},
		},
		resourcePolicy: map[string]*secretsmanager.GetResourcePolicyOutput{
			arn: {ResourcePolicy: awsv2.String(`{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::999999999999:role/partner"},"Action":"secretsmanager:DescribeSecret","Resource":"*"}]}`)},
		},
		versions: map[string]*secretsmanager.ListSecretVersionIdsOutput{
			arn: {Versions: []smtypes.SecretVersionsListEntry{{
				VersionId:     awsv2.String("version-current"),
				VersionStages: []string{"AWSCURRENT"},
				CreatedDate:   &now,
			}}},
		},
	}
	api := NewSDKSecretsManagerMetadataAPIFromClient(fake, "123456789012", "us-east-1")

	page, err := api.ListSecretMetadata(context.Background(), "", 25)
	if err != nil {
		t.Fatalf("list metadata: %v", err)
	}
	if len(page.Diagnostics) != 0 || len(page.Records) != 1 {
		t.Fatalf("expected one clean record, records=%d diagnostics=%+v", len(page.Records), page.Diagnostics)
	}
	record := page.Records[0]
	if !record.RotationEnabled || record.RotationInterval != 30 {
		t.Fatalf("rotation metadata not enriched: %+v", record)
	}
	if !record.DescriptionPresent {
		t.Fatalf("expected description presence flag")
	}
	payload, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("marshal record: %v", err)
	}
	if strings.Contains(string(payload), "sensitive operator note") || strings.Contains(string(payload), "another sensitive note") {
		t.Fatalf("description text leaked into metadata payload: %s", payload)
	}
	if len(record.IdentityGrants) != 1 || !record.IdentityGrants[0].IsCrossAccount {
		t.Fatalf("expected cross-account resource policy grant, got %+v", record.IdentityGrants)
	}
	if got := record.Tags["env"]; got != "prod" {
		t.Fatalf("expected describe tags to win, got tags=%+v", record.Tags)
	}
	if len(record.VersionStages) != 1 || record.VersionStages[0].VersionID != "version-current" {
		t.Fatalf("expected version metadata, got %+v", record.VersionStages)
	}
}

func TestSDKSecretsManagerMetadataAPI_ListSecretsError(t *testing.T) {
	api := NewSDKSecretsManagerMetadataAPIFromClient(&fakeSecretsManagerSDKClient{listSecretsErr: errors.New("denied")}, "123456789012", "us-east-1")
	if _, err := api.ListSecretMetadata(context.Background(), "", 25); err == nil {
		t.Fatalf("expected ListSecrets error")
	}
}
