package aws

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

type fakeSSMSDKClient struct {
	describeParameters    *ssm.DescribeParametersOutput
	describeParametersErr error
	lastMaxResults        int32
	tags                  map[string]*ssm.ListTagsForResourceOutput
	tagsErr               map[string]error
}

func (f *fakeSSMSDKClient) DescribeParameters(ctx context.Context, input *ssm.DescribeParametersInput, _ ...func(*ssm.Options)) (*ssm.DescribeParametersOutput, error) {
	if input != nil && input.MaxResults != nil {
		f.lastMaxResults = *input.MaxResults
	}
	if f.describeParametersErr != nil {
		return nil, f.describeParametersErr
	}
	return f.describeParameters, nil
}

func (f *fakeSSMSDKClient) ListTagsForResource(ctx context.Context, input *ssm.ListTagsForResourceInput, _ ...func(*ssm.Options)) (*ssm.ListTagsForResourceOutput, error) {
	id := awsv2.ToString(input.ResourceId)
	if err, ok := f.tagsErr[id]; ok {
		return nil, err
	}
	return f.tags[id], nil
}

func TestSDKSSMParameterMetadataAPI_ListParameterMetadataEnrichesRecord(t *testing.T) {
	arn := "arn:aws:ssm:us-east-1:123456789012:parameter/payments/db/password"
	name := "/payments/db/password"
	now := time.Date(2026, 6, 11, 10, 0, 0, 0, time.UTC)
	fake := &fakeSSMSDKClient{
		describeParameters: &ssm.DescribeParametersOutput{
			Parameters: []ssmtypes.ParameterMetadata{{
				ARN:              awsv2.String(arn),
				Name:             awsv2.String(name),
				Type:             ssmtypes.ParameterTypeSecureString,
				Tier:             ssmtypes.ParameterTierAdvanced,
				KeyId:            awsv2.String("alias/payments"),
				Description:      awsv2.String("sensitive operator note do not persist"),
				AllowedPattern:   awsv2.String("^[a-z]+$"),
				Version:          4,
				LastModifiedDate: &now,
				LastModifiedUser: awsv2.String("arn:aws:iam::123456789012:role/payments-deployer"),
				Policies: []ssmtypes.ParameterInlinePolicy{{
					PolicyType:   awsv2.String("Expiration"),
					PolicyStatus: awsv2.String("Pending"),
					PolicyText:   awsv2.String(`{"Type":"Expiration","Version":"1.0","Attributes":{"Timestamp":"2026-12-02T21:34:33.000Z"}}`),
				}},
			}},
		},
		tags: map[string]*ssm.ListTagsForResourceOutput{
			name: {TagList: []ssmtypes.Tag{{Key: awsv2.String("owner"), Value: awsv2.String("payments")}}},
		},
	}
	api := NewSDKSSMParameterMetadataAPIFromClient(fake, "123456789012", "us-east-1")

	page, err := api.ListParameterMetadata(context.Background(), "", 25)
	if err != nil {
		t.Fatalf("list metadata: %v", err)
	}
	if len(page.Diagnostics) != 0 || len(page.Records) != 1 {
		t.Fatalf("expected one clean record, records=%d diagnostics=%+v", len(page.Records), page.Diagnostics)
	}
	record := page.Records[0]
	if record.ParameterARN != arn || record.ParameterName != name {
		t.Fatalf("identity fields not mapped: %+v", record)
	}
	if !record.DescriptionPresent || !record.AllowedPatternPresent {
		t.Fatalf("expected presence flags, got %+v", record)
	}
	if record.LastModifiedBy != "arn:aws:iam::123456789012:role/payments-deployer" {
		t.Fatalf("expected last-modified identity context, got %q", record.LastModifiedBy)
	}
	if len(record.Policies) != 1 || record.Policies[0].PolicyType != "Expiration" || record.Policies[0].ExpiresAt != "2026-12-02T21:34:33.000Z" {
		t.Fatalf("expected expiration policy summary, got %+v", record.Policies)
	}
	if got := record.Tags["owner"]; got != "payments" {
		t.Fatalf("expected tags enrichment, got %+v", record.Tags)
	}
	payload, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("marshal record: %v", err)
	}
	if strings.Contains(string(payload), "sensitive operator note") {
		t.Fatalf("description text leaked into metadata payload: %s", payload)
	}
	if strings.Contains(string(payload), "^[a-z]+$") {
		t.Fatalf("allowed pattern text leaked into metadata payload: %s", payload)
	}
}

func TestSDKSSMParameterMetadataAPI_TagFailureIsDiagnosticNotFatal(t *testing.T) {
	name := "/payments/db/password"
	fake := &fakeSSMSDKClient{
		describeParameters: &ssm.DescribeParametersOutput{
			Parameters: []ssmtypes.ParameterMetadata{{
				ARN:  awsv2.String("arn:aws:ssm:us-east-1:123456789012:parameter/payments/db/password"),
				Name: awsv2.String(name),
				Type: ssmtypes.ParameterTypeString,
			}},
		},
		tagsErr: map[string]error{name: errors.New("AccessDenied: ssm:ListTagsForResource")},
	}
	api := NewSDKSSMParameterMetadataAPIFromClient(fake, "123456789012", "us-east-1")

	page, err := api.ListParameterMetadata(context.Background(), "", 25)
	if err != nil {
		t.Fatalf("list metadata: %v", err)
	}
	if len(page.Records) != 1 {
		t.Fatalf("expected record despite tag failure, got %+v", page.Records)
	}
	if len(page.Diagnostics) != 1 || page.Diagnostics[0].Code != "ssm_parameter_tags_failed" || !page.Diagnostics[0].Retryable {
		t.Fatalf("expected retryable tag diagnostic, got %+v", page.Diagnostics)
	}
}

func TestSDKSSMParameterMetadataAPI_DescribeParametersError(t *testing.T) {
	api := NewSDKSSMParameterMetadataAPIFromClient(&fakeSSMSDKClient{describeParametersErr: errors.New("denied")}, "123456789012", "us-east-1")
	if _, err := api.ListParameterMetadata(context.Background(), "", 25); err == nil {
		t.Fatalf("expected DescribeParameters error")
	}
}

func TestSDKSSMParameterMetadataAPI_ClampsMaxResultsToAPILimit(t *testing.T) {
	tests := []struct {
		name     string
		pageSize int32
		want     int32
	}{
		{name: "scanner default exceeds api limit", pageSize: defaultPageSize, want: ssmDescribeParametersMaxResults},
		{name: "non-positive falls back then clamps", pageSize: 0, want: ssmDescribeParametersMaxResults},
		{name: "within limit is preserved", pageSize: 25, want: 25},
		{name: "exactly at limit is preserved", pageSize: ssmDescribeParametersMaxResults, want: ssmDescribeParametersMaxResults},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeSSMSDKClient{describeParameters: &ssm.DescribeParametersOutput{}}
			api := NewSDKSSMParameterMetadataAPIFromClient(fake, "123456789012", "us-east-1")
			if _, err := api.ListParameterMetadata(context.Background(), "", tc.pageSize); err != nil {
				t.Fatalf("list metadata: %v", err)
			}
			if fake.lastMaxResults != tc.want {
				t.Fatalf("MaxResults = %d, want %d", fake.lastMaxResults, tc.want)
			}
			if fake.lastMaxResults > ssmDescribeParametersMaxResults {
				t.Fatalf("MaxResults %d exceeds AWS DescribeParameters limit %d", fake.lastMaxResults, ssmDescribeParametersMaxResults)
			}
		})
	}
}

func TestParseSSMParameterPolicyText(t *testing.T) {
	policyType, expiresAt := parseSSMParameterPolicyText(`{"Type":"Expiration","Version":"1.0","Attributes":{"Timestamp":"2026-12-02T21:34:33.000Z"}}`)
	if policyType != "Expiration" || expiresAt != "2026-12-02T21:34:33.000Z" {
		t.Fatalf("unexpected parse result: %q %q", policyType, expiresAt)
	}
	if policyType, expiresAt := parseSSMParameterPolicyText("not json"); policyType != "" || expiresAt != "" {
		t.Fatalf("expected empty result for malformed text, got %q %q", policyType, expiresAt)
	}
}
