package cloudtrail

import (
	"context"
	"errors"
	"fmt"
	"strings"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cloudtrailtypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// CloudTrailClient is the minimal seam from the AWS SDK CloudTrail
// client this package depends on. Defining it here lets the adapter
// be swapped for a fake in tests of the SDK wrapper itself, though
// the ingester tests already use the higher-level LookupEventsAPI.
type CloudTrailClient interface {
	LookupEvents(ctx context.Context, params *cloudtrail.LookupEventsInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error)
}

// SDKLookupEventsAPI implements LookupEventsAPI against the AWS SDK.
// It only exposes the LookupEvents operation; PutEvents and the
// CloudTrail Lake read APIs are deliberately absent so the adapter
// cannot accidentally invoke a mutation.
type SDKLookupEventsAPI struct {
	client CloudTrailClient
}

var _ LookupEventsAPI = (*SDKLookupEventsAPI)(nil)

// NewSDKLookupEventsAPIFromClient wraps a pre-built CloudTrail
// client. Used both by production wiring and by SDK-layer tests.
func NewSDKLookupEventsAPIFromClient(client CloudTrailClient) *SDKLookupEventsAPI {
	return &SDKLookupEventsAPI{client: client}
}

// NewSDKLookupEventsAPIWithContext builds the SDK-backed adapter using
// ambient AWS credentials and the supplied region/profile.
func NewSDKLookupEventsAPIWithContext(ctx context.Context, region string, profile string) (LookupEventsAPI, error) {
	cfg, err := loadSDKConfig(ctx, region, profile)
	if err != nil {
		return nil, err
	}
	return NewSDKLookupEventsAPIFromClient(cloudtrail.NewFromConfig(cfg)), nil
}

// NewSDKLookupEventsAPIFromAssumeRole builds the SDK-backed adapter
// after assuming a connector role with the supplied external ID. This
// is the production code path: Identrail never embeds long-lived
// CloudTrail credentials and always reaches CloudTrail through a
// short-lived assumed role.
func NewSDKLookupEventsAPIFromAssumeRole(ctx context.Context, region string, profile string, roleARN string, externalID string, sessionName string) (LookupEventsAPI, error) {
	cfg, err := loadSDKConfig(ctx, region, profile)
	if err != nil {
		return nil, err
	}
	trimmedRoleARN := strings.TrimSpace(roleARN)
	if trimmedRoleARN == "" {
		return nil, errors.New("cloudtrail: aws connector role arn is required")
	}
	options := []func(*stscreds.AssumeRoleOptions){
		func(options *stscreds.AssumeRoleOptions) {
			name := strings.TrimSpace(sessionName)
			if name == "" {
				name = "identrail-cloudtrail-lookup-events"
			}
			options.RoleSessionName = name
		},
	}
	if trimmedExternalID := strings.TrimSpace(externalID); trimmedExternalID != "" {
		options = append(options, func(options *stscreds.AssumeRoleOptions) {
			options.ExternalID = &trimmedExternalID
		})
	}
	cfg.Credentials = awsv2.NewCredentialsCache(stscreds.NewAssumeRoleProvider(sts.NewFromConfig(cfg), trimmedRoleARN, options...))
	return NewSDKLookupEventsAPIFromClient(cloudtrail.NewFromConfig(cfg)), nil
}

// LookupEvents calls the SDK and converts the response into the
// engine-facing LookupEventsPage type. Mapping is one-to-one and never
// touches request parameters or response elements from the
// CloudTrailEvent JSON; the engine performs allow-listed extraction
// after this returns.
func (a *SDKLookupEventsAPI) LookupEvents(ctx context.Context, input LookupEventsInput) (LookupEventsPage, error) {
	if a == nil || a.client == nil {
		return LookupEventsPage{}, errors.New("cloudtrail: SDK client is required")
	}
	params := &cloudtrail.LookupEventsInput{}
	if !input.StartTime.IsZero() {
		t := input.StartTime
		params.StartTime = &t
	}
	if !input.EndTime.IsZero() {
		t := input.EndTime
		params.EndTime = &t
	}
	if next := strings.TrimSpace(input.NextToken); next != "" {
		params.NextToken = &next
	}
	if input.MaxResults > 0 {
		max := input.MaxResults
		params.MaxResults = &max
	}
	// CloudTrail rejects a LookupAttribute whose AttributeValue is
	// empty (`InvalidLookupAttributesException`), so only push the
	// attribute when both key and trimmed value are non-empty. A
	// key-only attribute is treated as "no pushdown" and falls back to
	// the full window scan.
	attrKey := strings.TrimSpace(input.Attributes.Key)
	attrValue := strings.TrimSpace(input.Attributes.Value)
	if attrKey != "" && attrValue != "" {
		params.LookupAttributes = []cloudtrailtypes.LookupAttribute{{
			AttributeKey:   cloudtrailtypes.LookupAttributeKey(attrKey),
			AttributeValue: awsv2.String(attrValue),
		}}
	}
	out, err := a.client.LookupEvents(ctx, params)
	if err != nil {
		return LookupEventsPage{}, err
	}
	if out == nil {
		return LookupEventsPage{}, nil
	}
	page := LookupEventsPage{NextToken: strings.TrimSpace(awsv2.ToString(out.NextToken))}
	for _, raw := range out.Events {
		event := Event{
			EventID:     strings.TrimSpace(awsv2.ToString(raw.EventId)),
			EventName:   strings.TrimSpace(awsv2.ToString(raw.EventName)),
			EventSource: strings.TrimSpace(awsv2.ToString(raw.EventSource)),
			AccessKeyID: strings.TrimSpace(awsv2.ToString(raw.AccessKeyId)),
			Username:    strings.TrimSpace(awsv2.ToString(raw.Username)),
			ReadOnly:    strings.TrimSpace(awsv2.ToString(raw.ReadOnly)),
			RawEvent:    awsv2.ToString(raw.CloudTrailEvent),
		}
		if raw.EventTime != nil {
			event.EventTime = raw.EventTime.UTC()
		}
		for _, r := range raw.Resources {
			event.Resources = append(event.Resources, EventResource{
				ResourceType: strings.TrimSpace(awsv2.ToString(r.ResourceType)),
				ResourceName: strings.TrimSpace(awsv2.ToString(r.ResourceName)),
			})
		}
		page.Events = append(page.Events, event)
	}
	return page, nil
}

func loadSDKConfig(ctx context.Context, region string, profile string) (awsv2.Config, error) {
	options := []func(*awsconfig.LoadOptions) error{}
	if trimmedRegion := strings.TrimSpace(region); trimmedRegion != "" {
		options = append(options, awsconfig.WithRegion(trimmedRegion))
	}
	if trimmedProfile := strings.TrimSpace(profile); trimmedProfile != "" {
		options = append(options, awsconfig.WithSharedConfigProfile(trimmedProfile))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, options...)
	if err != nil {
		return awsv2.Config{}, fmt.Errorf("cloudtrail: load aws config: %w", err)
	}
	return cfg, nil
}
