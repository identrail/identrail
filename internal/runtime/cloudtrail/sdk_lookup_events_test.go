package cloudtrail

import (
	"context"
	"testing"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
)

type fakeCloudTrailClient struct {
	got *cloudtrail.LookupEventsInput
}

func (f *fakeCloudTrailClient) LookupEvents(_ context.Context, params *cloudtrail.LookupEventsInput, _ ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error) {
	f.got = params
	return &cloudtrail.LookupEventsOutput{}, nil
}

func TestSDKLookupEventsAPIOmitsAttributeWhenValueIsEmpty(t *testing.T) {
	// CloudTrail rejects LookupAttributes with an empty AttributeValue
	// (`InvalidLookupAttributesException`). When the engine asks for a
	// key-only attribute (e.g. MutationOnly with no source filter
	// configured), the adapter must omit the attribute entirely so
	// CloudTrail returns the full window instead of erroring.
	fake := &fakeCloudTrailClient{}
	adapter := NewSDKLookupEventsAPIFromClient(fake)

	if _, err := adapter.LookupEvents(context.Background(), LookupEventsInput{
		MaxResults: 50,
		Attributes: LookupAttribute{Key: "EventSource", Value: "  "},
	}); err != nil {
		t.Fatalf("LookupEvents: %v", err)
	}
	if fake.got == nil {
		t.Fatalf("expected LookupEvents to be invoked")
	}
	if len(fake.got.LookupAttributes) != 0 {
		t.Fatalf("empty-value attribute must not be pushed to CloudTrail, got %+v", fake.got.LookupAttributes)
	}

	// Sanity check: non-empty value still pushes.
	fake = &fakeCloudTrailClient{}
	adapter = NewSDKLookupEventsAPIFromClient(fake)
	if _, err := adapter.LookupEvents(context.Background(), LookupEventsInput{
		MaxResults: 50,
		Attributes: LookupAttribute{Key: "EventSource", Value: "kms.amazonaws.com"},
	}); err != nil {
		t.Fatalf("LookupEvents: %v", err)
	}
	if len(fake.got.LookupAttributes) != 1 || awsv2.ToString(fake.got.LookupAttributes[0].AttributeValue) != "kms.amazonaws.com" {
		t.Fatalf("expected non-empty attribute to be pushed, got %+v", fake.got.LookupAttributes)
	}
}
