package aws

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/domain"
	"github.com/identrail/identrail/internal/providers"
	"github.com/identrail/identrail/internal/providers/awscontract"
)

type fakeSecretsManagerMetadataAPI struct {
	pages     []SecretsManagerMetadataPage
	calls     int
	err       error
	errOnCall int
}

func (f *fakeSecretsManagerMetadataAPI) ListSecretMetadata(ctx context.Context, nextToken string, pageSize int32) (SecretsManagerMetadataPage, error) {
	f.calls++
	if f.err != nil && (f.errOnCall == 0 || f.calls >= f.errOnCall) {
		return SecretsManagerMetadataPage{}, f.err
	}
	if len(f.pages) == 0 {
		return SecretsManagerMetadataPage{}, nil
	}
	page := f.pages[0]
	f.pages = f.pages[1:]
	return page, nil
}

func TestSecretsManagerMetadataCollectorCollectsMetadataOnly(t *testing.T) {
	now := time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)
	api := &fakeSecretsManagerMetadataAPI{pages: []SecretsManagerMetadataPage{{
		Records: []SecretsManagerSecretMetadata{{
			SecretARN:       "arn:aws:secretsmanager:us-east-1:123456789012:secret:payments/db-AbCdEf",
			SecretName:      "payments/db",
			KMSKeyID:        "alias/payments",
			RotationEnabled: true,
			Tags:            map[string]string{"owner": "payments"},
		}},
	}}}
	collector := NewSecretsManagerMetadataCollector(api, WithSecretsManagerMetadataClock(func() time.Time { return now }))

	assets, diagnostics, err := collector.CollectWithDiagnostics(context.Background(), AWSCollectorScope{
		ConnectorID: "aws-prod",
		AccountID:   "123456789012",
		Region:      "us-east-1",
	})
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(diagnostics) != 0 || len(assets) != 1 {
		t.Fatalf("expected one clean asset, assets=%d diagnostics=%+v", len(assets), diagnostics)
	}
	var record SecretsManagerSecretMetadata
	if err := json.Unmarshal(assets[0].Payload, &record); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if record.ConnectorID != "aws-prod" || record.AccountID != "123456789012" || record.Region != "us-east-1" {
		t.Fatalf("scope not applied: %+v", record.ServiceCollectorRecord)
	}
	if record.KMSKeyARN != "arn:aws:kms:us-east-1:123456789012:alias/payments" {
		t.Fatalf("unexpected KMS key ARN: %s", record.KMSKeyARN)
	}
	payload := strings.ToLower(string(assets[0].Payload))
	if strings.Contains(payload, "secretstring") || strings.Contains(payload, "secretbinary") || strings.Contains(payload, "getsecretvalue") {
		t.Fatalf("secret value material leaked into collector payload: %s", payload)
	}
}

func TestSecretsManagerMetadataCollectorPartialFailureReturnsDiagnostics(t *testing.T) {
	api := &fakeSecretsManagerMetadataAPI{
		pages: []SecretsManagerMetadataPage{{
			Records: []SecretsManagerSecretMetadata{{
				SecretARN:  "arn:aws:secretsmanager:us-east-1:123456789012:secret:payments/db-AbCdEf",
				SecretName: "payments/db",
			}},
			NextToken: "next",
		}},
		err:       errors.New("throttled"),
		errOnCall: 2,
	}
	collector := NewSecretsManagerMetadataCollector(api, WithSecretsManagerMetadataMaxPages(3))

	assets, diagnostics, err := collector.CollectWithDiagnostics(context.Background(), AWSCollectorScope{AccountID: "123456789012", Region: "us-east-1"})
	if err == nil {
		t.Fatalf("expected second-page error")
	}
	if len(assets) != 1 || len(diagnostics) == 0 {
		t.Fatalf("expected partial asset plus diagnostics, assets=%d diagnostics=%+v", len(assets), diagnostics)
	}
	if diagnostics[0].Code != "secrets_manager_metadata_page_failed" {
		t.Fatalf("unexpected diagnostic: %+v", diagnostics)
	}
}

func TestParseSecretsManagerResourcePolicyGrantsPublicAndCrossAccount(t *testing.T) {
	grants, count, err := parseSecretsManagerResourcePolicyGrants(`{
		"Statement": [
			{"Sid":"PublicDescribe","Effect":"Allow","Principal":"*","Action":"secretsmanager:DescribeSecret","Resource":"*"},
			{"Sid":"Partner","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::999999999999:role/partner"},"Action":["secretsmanager:GetResourcePolicy"],"Resource":"*"},
			{"Sid":"PartnerAccount","Effect":"Allow","Principal":{"AWS":"999999999999"},"Action":["secretsmanager:DescribeSecret"],"Resource":"*"},
			{"Sid":"SameAccount","Effect":"Allow","Principal":{"AWS":"123456789012"},"Action":["secretsmanager:DescribeSecret"],"Resource":"*"}
		]
	}`, "123456789012")
	if err != nil {
		t.Fatalf("parse policy: %v", err)
	}
	if count != 4 || len(grants) != 4 {
		t.Fatalf("expected four grants, count=%d grants=%+v", count, grants)
	}
	if !grants[0].IsPublic || !grants[0].WildcardPrincipal {
		t.Fatalf("expected public wildcard grant, got %+v", grants[0])
	}
	if !grants[1].IsCrossAccount {
		t.Fatalf("expected cross-account grant, got %+v", grants[1])
	}
	if !grants[2].IsCrossAccount {
		t.Fatalf("expected bare account-id principal to be cross-account, got %+v", grants[2])
	}
	if grants[3].IsCrossAccount {
		t.Fatalf("expected same-account bare principal to stay in-account, got %+v", grants[3])
	}
}

func TestSecretsManagerKMSKeyARN(t *testing.T) {
	tests := []struct {
		name  string
		keyID string
		want  string
	}{
		{name: "empty", keyID: "", want: ""},
		{name: "bare key id", keyID: "key123", want: "arn:aws:kms:us-east-1:123456789012:key/key123"},
		{name: "alias", keyID: "alias/payments", want: "arn:aws:kms:us-east-1:123456789012:alias/payments"},
		{name: "full arn passthrough", keyID: "arn:aws:kms:eu-west-1:999999999999:key/key123", want: "arn:aws:kms:eu-west-1:999999999999:key/key123"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := secretsManagerKMSKeyARN(tc.keyID, "123456789012", "us-east-1"); got != tc.want {
				t.Fatalf("secretsManagerKMSKeyARN(%q) = %q, want %q", tc.keyID, got, tc.want)
			}
		})
	}
}

func TestSecretsManagerMetadataNormalizeAndGraphUsesSecret(t *testing.T) {
	secret := SecretsManagerSecretMetadata{
		SecretARN:              "arn:aws:secretsmanager:us-east-1:123456789012:secret:payments/db-AbCdEf",
		SecretName:             "payments/db",
		ServiceCollectorRecord: awscontract.ServiceCollectorRecord{},
	}
	secret.AccountID = "123456789012"
	secret.Region = "us-east-1"
	secret.Service = secretsManagerServiceName
	payload, err := json.Marshal(secret)
	if err != nil {
		t.Fatalf("marshal secret: %v", err)
	}
	bundle, err := NewRoleNormalizer().Normalize(context.Background(), []providers.RawAsset{{
		Kind:     rawKindSecretsManagerMetadata,
		SourceID: secretsManagerMetadataSourceID(secret),
		Payload:  payload,
	}, {
		Kind:     rawKindECSTaskRole,
		SourceID: "ecs-service",
		Payload: []byte(`{
			"account_id":"123456789012",
			"region":"us-east-1",
			"service":"ecs",
			"cluster_arn":"arn:aws:ecs:us-east-1:123456789012:cluster/prod",
			"service_arn":"arn:aws:ecs:us-east-1:123456789012:service/prod/payments",
			"workload_id":"arn:aws:ecs:us-east-1:123456789012:service/prod/payments",
			"workload_type":"ecs_service",
			"workload_name":"payments",
			"task_definition_arn":"arn:aws:ecs:us-east-1:123456789012:task-definition/payments:4",
			"role_arn":"arn:aws:iam::123456789012:role/payments-task",
			"secret_refs":["DATABASE_PASSWORD=arn:aws:secretsmanager:us-east-1:123456789012:secret:payments/db-AbCdEf:password"]
		}`),
	}})
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if len(bundle.Resources) == 0 {
		t.Fatalf("expected normalized resources")
	}
	relationships, err := NewRelationshipBuilder().ResolveRelationships(context.Background(), bundle, nil)
	if err != nil {
		t.Fatalf("relationships: %v", err)
	}
	for _, relationship := range relationships {
		if relationship.Type == domain.RelationshipUsesSecret {
			if relationship.ToNodeID != secretsManagerSecretResourceID(secret.SecretARN) {
				t.Fatalf("unexpected target: %+v", relationship)
			}
			return
		}
	}
	t.Fatalf("expected uses_secret relationship, got %+v", relationships)
}

func TestSecretsManagerReferenceKeysFromRefStripsValueSuffixes(t *testing.T) {
	tests := []struct {
		name string
		ref  string
		want []string
		not  []string
	}{
		{
			name: "arn json key suffix",
			ref:  "DATABASE_PASSWORD=arn:aws:secretsmanager:us-east-1:123456789012:secret:payments/db-AbCdEf:password",
			want: []string{
				"DATABASE_PASSWORD=arn:aws:secretsmanager:us-east-1:123456789012:secret:payments/db-AbCdEf:password",
				"arn:aws:secretsmanager:us-east-1:123456789012:secret:payments/db-AbCdEf:password",
				"arn:aws:secretsmanager:us-east-1:123456789012:secret:payments/db-AbCdEf",
				"payments/db",
			},
		},
		{
			name: "name json key suffix",
			ref:  "SECRETS_MANAGER:payments/db:password",
			want: []string{
				"SECRETS_MANAGER:payments/db:password",
				"payments/db:password",
				"payments/db",
			},
		},
		{
			name: "prefixed ref is not stripped before prefix removal",
			ref:  "SECRETS_MANAGER:payments:password",
			want: []string{
				"SECRETS_MANAGER:payments:password",
				"payments:password",
				"payments",
			},
			not: []string{"SECRETS_MANAGER"},
		},
		{
			name: "arbitrary colon ref is not stripped",
			ref:  "not-a-secret:maybe",
			want: []string{"not-a-secret:maybe"},
			not:  []string{"not-a-secret"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			keys := secretsManagerReferenceKeysFromRef(tc.ref)
			for _, want := range tc.want {
				if !containsString(keys, want) {
					t.Fatalf("expected key %q in %+v", want, keys)
				}
			}
			for _, not := range tc.not {
				if containsString(keys, not) {
					t.Fatalf("did not expect key %q in %+v", not, keys)
				}
			}
		})
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
