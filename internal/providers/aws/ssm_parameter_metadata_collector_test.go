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

type fakeSSMParameterMetadataAPI struct {
	pages     []SSMParameterMetadataPage
	calls     int
	err       error
	errOnCall int
}

func (f *fakeSSMParameterMetadataAPI) ListParameterMetadata(ctx context.Context, nextToken string, pageSize int32) (SSMParameterMetadataPage, error) {
	f.calls++
	if f.err != nil && (f.errOnCall == 0 || f.calls >= f.errOnCall) {
		return SSMParameterMetadataPage{}, f.err
	}
	if len(f.pages) == 0 {
		return SSMParameterMetadataPage{}, nil
	}
	page := f.pages[0]
	f.pages = f.pages[1:]
	return page, nil
}

func TestSSMParameterMetadataCollectorCollectsMetadataOnly(t *testing.T) {
	now := time.Date(2026, 6, 11, 12, 0, 0, 0, time.UTC)
	api := &fakeSSMParameterMetadataAPI{pages: []SSMParameterMetadataPage{{
		Records: []SSMParameterMetadata{{
			ParameterARN:  "arn:aws:ssm:us-east-1:123456789012:parameter/payments/db/password",
			ParameterName: "/payments/db/password",
			ParameterType: "SecureString",
			Tier:          "Advanced",
			KMSKeyID:      "alias/payments",
			Version:       4,
			Tags:          map[string]string{"owner": "payments"},
		}},
	}}}
	collector := NewSSMParameterMetadataCollector(api, WithSSMParameterMetadataClock(func() time.Time { return now }))

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
	var record SSMParameterMetadata
	if err := json.Unmarshal(assets[0].Payload, &record); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if record.ConnectorID != "aws-prod" || record.AccountID != "123456789012" || record.Region != "us-east-1" {
		t.Fatalf("scope not applied: %+v", record.ServiceCollectorRecord)
	}
	if record.ParameterType != "secure_string" || record.Tier != "advanced" {
		t.Fatalf("expected canonical type and tier, got %q %q", record.ParameterType, record.Tier)
	}
	if record.ParameterPath != "/payments/db" || record.PathDepth != 3 {
		t.Fatalf("unexpected path context: %q depth=%d", record.ParameterPath, record.PathDepth)
	}
	if record.KMSKeyARN != "arn:aws:kms:us-east-1:123456789012:alias/payments" {
		t.Fatalf("unexpected KMS key ARN: %s", record.KMSKeyARN)
	}
	if !record.Sensitive || record.SensitivityClassification != "secure_string_customer_kms" {
		t.Fatalf("expected sensitive customer-kms classification, got %+v", record)
	}
	payload := strings.ToLower(string(assets[0].Payload))
	for _, forbidden := range []string{"parameter_value", "getparameter", "secretstring"} {
		if strings.Contains(payload, forbidden) {
			t.Fatalf("value material leaked into collector payload: %s", payload)
		}
	}
}

func TestSSMParameterMetadataCollectorPageBudgetCoversAdvancedTierCeiling(t *testing.T) {
	// DescribeParameters returns at most 50 items per page and an Advanced-tier
	// account can hold up to 100,000 parameters, so the default page budget must
	// be able to reach the full inventory rather than aborting at 25,000.
	collector := NewSSMParameterMetadataCollector(&fakeSSMParameterMetadataAPI{})
	const advancedTierCeiling = 100_000
	if got := int64(collector.maxPages) * int64(ssmDescribeParametersMaxResults); got < advancedTierCeiling {
		t.Fatalf("page budget covers %d parameters, want >= %d (maxPages=%d, pageSize=%d)", got, advancedTierCeiling, collector.maxPages, ssmDescribeParametersMaxResults)
	}
}

func TestSSMParameterMetadataCollectorPartialFailureReturnsDiagnostics(t *testing.T) {
	api := &fakeSSMParameterMetadataAPI{
		pages: []SSMParameterMetadataPage{{
			Records: []SSMParameterMetadata{{
				ParameterARN:  "arn:aws:ssm:us-east-1:123456789012:parameter/payments/db/password",
				ParameterName: "/payments/db/password",
				ParameterType: "SecureString",
			}},
			NextToken: "next",
		}},
		err:       errors.New("throttled"),
		errOnCall: 2,
	}
	collector := NewSSMParameterMetadataCollector(api, WithSSMParameterMetadataMaxPages(3))

	assets, diagnostics, err := collector.CollectWithDiagnostics(context.Background(), AWSCollectorScope{AccountID: "123456789012", Region: "us-east-1"})
	if err == nil {
		t.Fatalf("expected second-page error")
	}
	if len(assets) != 1 || len(diagnostics) == 0 {
		t.Fatalf("expected partial asset plus diagnostics, assets=%d diagnostics=%+v", len(assets), diagnostics)
	}
	if diagnostics[0].Code != "ssm_parameter_metadata_page_failed" {
		t.Fatalf("unexpected diagnostic: %+v", diagnostics)
	}
}

func TestSSMParameterMetadataCollectorSkipsMalformedRecords(t *testing.T) {
	api := &fakeSSMParameterMetadataAPI{pages: []SSMParameterMetadataPage{{
		Records: []SSMParameterMetadata{{ParameterType: "String"}},
	}}}
	collector := NewSSMParameterMetadataCollector(api)

	assets, diagnostics, err := collector.CollectWithDiagnostics(context.Background(), AWSCollectorScope{AccountID: "123456789012", Region: "us-east-1"})
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(assets) != 0 || len(diagnostics) != 1 || diagnostics[0].Code != "malformed_ssm_parameter_record" {
		t.Fatalf("expected one malformed-record diagnostic, assets=%d diagnostics=%+v", len(assets), diagnostics)
	}
}

func TestClassifySSMParameterSensitivityAndExposure(t *testing.T) {
	tests := []struct {
		name            string
		record          SSMParameterMetadata
		wantSensitive   bool
		wantSensitivity string
		wantExposure    string
		wantReason      string
	}{
		{
			name:            "secure string customer kms",
			record:          SSMParameterMetadata{ParameterType: "secure_string", KMSKeyID: "alias/payments"},
			wantSensitive:   true,
			wantSensitivity: "secure_string_customer_kms",
			wantExposure:    "private",
			wantReason:      "customer_kms_key_referenced",
		},
		{
			name:            "secure string aws managed kms",
			record:          SSMParameterMetadata{ParameterType: "secure_string", KMSKeyID: "alias/aws/ssm"},
			wantSensitive:   true,
			wantSensitivity: "secure_string_aws_managed_kms",
			wantExposure:    "private",
			wantReason:      "secure_string_kms_encrypted",
		},
		{
			name: "plain text referenced by workload",
			record: SSMParameterMetadata{ParameterType: "string", ReferenceCount: 1, ReferencedBy: []SecretWorkloadReference{{
				Reference: "DB_HOST=/payments/db/host", ReferenceKind: "name", Confidence: 0.8,
			}}},
			wantSensitivity: "plain_text",
			wantExposure:    "referenced_by_workload",
			wantReason:      "plain_text_parameter_referenced_as_secret",
		},
		{
			name: "expiring parameter",
			record: SSMParameterMetadata{ParameterType: "string", Policies: []SSMParameterPolicy{{
				PolicyType: "Expiration", PolicyStatus: "pending", ExpiresAt: "2026-12-02T21:34:33Z",
			}}},
			wantSensitivity: "plain_text",
			wantExposure:    "scheduled_expiration",
			wantReason:      "expiration_policy_present",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sensitive, sensitivity := classifySSMParameterSensitivity(tc.record)
			if sensitive != tc.wantSensitive || sensitivity != tc.wantSensitivity {
				t.Fatalf("sensitivity = (%t, %q), want (%t, %q)", sensitive, sensitivity, tc.wantSensitive, tc.wantSensitivity)
			}
			exposure, reasons := classifySSMParameterExposure(tc.record)
			if exposure != tc.wantExposure {
				t.Fatalf("exposure = %q, want %q (reasons %+v)", exposure, tc.wantExposure, reasons)
			}
			if !containsString(reasons, tc.wantReason) {
				t.Fatalf("expected reason %q in %+v", tc.wantReason, reasons)
			}
		})
	}
}

func TestSSMParameterPathContext(t *testing.T) {
	tests := []struct {
		name      string
		wantPath  string
		wantDepth int
	}{
		{name: "/payments/db/password", wantPath: "/payments/db", wantDepth: 3},
		{name: "/payments", wantPath: "", wantDepth: 1},
		{name: "db-password", wantPath: "", wantDepth: 1},
		{name: "", wantPath: "", wantDepth: 0},
	}
	for _, tc := range tests {
		path, depth := ssmParameterPathContext(tc.name)
		if path != tc.wantPath || depth != tc.wantDepth {
			t.Fatalf("ssmParameterPathContext(%q) = (%q, %d), want (%q, %d)", tc.name, path, depth, tc.wantPath, tc.wantDepth)
		}
	}
}

func TestSSMParameterNameFromARN(t *testing.T) {
	tests := []struct {
		arn  string
		want string
	}{
		{arn: "arn:aws:ssm:us-east-1:123456789012:parameter/payments/db/password", want: "/payments/db/password"},
		{arn: "arn:aws:ssm:us-east-1:123456789012:parameter/db-password", want: "db-password"},
		{arn: "arn:aws:secretsmanager:us-east-1:123456789012:secret:payments/db-AbCdEf", want: ""},
		{arn: "not-an-arn", want: ""},
	}
	for _, tc := range tests {
		if got := ssmParameterNameFromARN(tc.arn); got != tc.want {
			t.Fatalf("ssmParameterNameFromARN(%q) = %q, want %q", tc.arn, got, tc.want)
		}
	}
}

func TestSSMParameterMetadataSourceIDDistinguishesNameOnlyRecords(t *testing.T) {
	first := ssmParameterMetadataSourceID(SSMParameterMetadata{ParameterName: "/payments/db/password"})
	second := ssmParameterMetadataSourceID(SSMParameterMetadata{ParameterName: "/payments/db/host"})
	if first == second {
		t.Fatalf("expected distinct source IDs for name-only records, both were %q", first)
	}
	if !strings.Contains(first, "/payments/db/password") {
		t.Fatalf("expected parameter name in source ID, got %q", first)
	}
}

func TestSSMParameterReferenceKeysFromRefStripsPrefixesAndSuffixes(t *testing.T) {
	tests := []struct {
		name string
		ref  string
		want []string
	}{
		{
			name: "ecs valuefrom arn with version",
			ref:  "DATABASE_PASSWORD=arn:aws:ssm:us-east-1:123456789012:parameter/payments/db/password:3",
			want: []string{
				"arn:aws:ssm:us-east-1:123456789012:parameter/payments/db/password",
				"/payments/db/password",
				"payments/db/password",
			},
		},
		{
			name: "codebuild parameter store prefix",
			ref:  "DB_HOST=PARAMETER_STORE:/payments/db/host",
			want: []string{
				"/payments/db/host",
				"payments/db/host",
			},
		},
		{
			name: "bare name with label suffix",
			ref:  "db-password:prod",
			want: []string{
				"db-password:prod",
				"/db-password:prod",
			},
		},
		{
			name: "env assignment with label suffix",
			ref:  "DB_PASSWORD=db-password:prod",
			want: []string{
				"db-password",
				"/db-password",
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			keys := ssmParameterReferenceKeysFromRef(tc.ref)
			for _, want := range tc.want {
				if !containsString(keys, want) {
					t.Fatalf("expected key %q in %+v", want, keys)
				}
			}
		})
	}
}

func TestSSMParameterMetadataNormalizeAndGraphUsesParameter(t *testing.T) {
	parameter := SSMParameterMetadata{
		ParameterARN:           "arn:aws:ssm:us-east-1:123456789012:parameter/payments/db/password",
		ParameterName:          "/payments/db/password",
		ParameterType:          "secure_string",
		ServiceCollectorRecord: awscontract.ServiceCollectorRecord{},
	}
	parameter.AccountID = "123456789012"
	parameter.Region = "us-east-1"
	parameter.Service = ssmServiceName
	payload, err := json.Marshal(parameter)
	if err != nil {
		t.Fatalf("marshal parameter: %v", err)
	}
	bundle, err := NewRoleNormalizer().Normalize(context.Background(), []providers.RawAsset{{
		Kind:     rawKindSSMParameterMetadata,
		SourceID: ssmParameterMetadataSourceID(parameter),
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
			"secret_refs":["DATABASE_PASSWORD=arn:aws:ssm:us-east-1:123456789012:parameter/payments/db/password:3"]
		}`),
	}})
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	foundResource := false
	for _, resource := range bundle.Resources {
		if resource.Type == domain.ResourceTypeSSMParameter {
			foundResource = true
			if resource.ID != ssmParameterResourceID(parameter.ParameterARN) {
				t.Fatalf("unexpected resource id: %+v", resource)
			}
		}
	}
	if !foundResource {
		t.Fatalf("expected normalized ssm parameter resource, got %+v", bundle.Resources)
	}
	relationships, err := NewRelationshipBuilder().ResolveRelationships(context.Background(), bundle, nil)
	if err != nil {
		t.Fatalf("relationships: %v", err)
	}
	for _, relationship := range relationships {
		if relationship.Type == domain.RelationshipUsesSecret {
			if relationship.ToNodeID != ssmParameterResourceID(parameter.ParameterARN) {
				t.Fatalf("unexpected target: %+v", relationship)
			}
			return
		}
	}
	t.Fatalf("expected uses_secret relationship to ssm parameter, got %+v", relationships)
}

func TestResolveKMSKeyARNSharedHelper(t *testing.T) {
	if got := resolveKMSKeyARN("alias/payments", "123456789012", "us-east-1"); got != "arn:aws:kms:us-east-1:123456789012:alias/payments" {
		t.Fatalf("unexpected alias resolution: %q", got)
	}
	if got := resolveKMSKeyARN("arn:aws:kms:eu-west-1:999999999999:key/key123", "123456789012", "us-east-1"); got != "arn:aws:kms:eu-west-1:999999999999:key/key123" {
		t.Fatalf("expected ARN passthrough, got %q", got)
	}
}
