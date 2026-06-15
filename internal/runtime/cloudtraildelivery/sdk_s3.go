package cloudtraildelivery

import (
	"context"
	"errors"
	"fmt"
	"strings"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// S3Client is the minimal seam from the AWS SDK S3 client this
// package depends on. Defining it here lets the adapter swap in a
// fake for SDK-layer tests without taking a hard dep on the SDK.
type S3Client interface {
	ListObjectsV2(ctx context.Context, params *s3.ListObjectsV2Input, optFns ...func(*s3.Options)) (*s3.ListObjectsV2Output, error)
	GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error)
}

// SDKS3API implements S3API against the AWS SDK. Only the read-side
// operations are exposed; PutObject, DeleteObject, and any mutating
// API are deliberately absent so the adapter cannot accidentally
// invoke a write.
type SDKS3API struct {
	client S3Client
}

// NewSDKS3APIFromClient wraps a pre-built S3 client.
func NewSDKS3APIFromClient(client S3Client) *SDKS3API {
	return &SDKS3API{client: client}
}

// NewSDKS3APIFromAssumeRole builds the SDK-backed adapter after
// assuming the supplied connector role with the supplied external ID.
func NewSDKS3APIFromAssumeRole(ctx context.Context, region, profile, roleARN, externalID, sessionName string) (S3API, error) {
	cfg, err := loadSDKConfig(ctx, region, profile)
	if err != nil {
		return nil, err
	}
	trimmedRoleARN := strings.TrimSpace(roleARN)
	if trimmedRoleARN == "" {
		return nil, errors.New("cloudtraildelivery: aws connector role arn is required")
	}
	options := []func(*stscreds.AssumeRoleOptions){
		func(o *stscreds.AssumeRoleOptions) {
			name := strings.TrimSpace(sessionName)
			if name == "" {
				name = "identrail-cloudtrail-s3-delivery"
			}
			o.RoleSessionName = name
		},
	}
	if trimmedExternalID := strings.TrimSpace(externalID); trimmedExternalID != "" {
		options = append(options, func(o *stscreds.AssumeRoleOptions) {
			o.ExternalID = &trimmedExternalID
		})
	}
	cfg.Credentials = awsv2.NewCredentialsCache(stscreds.NewAssumeRoleProvider(sts.NewFromConfig(cfg), trimmedRoleARN, options...))
	return NewSDKS3APIFromClient(s3.NewFromConfig(cfg)), nil
}

// ListObjectsV2 maps the engine input onto the SDK shape and trims
// the response down to the metadata the ingester actually uses.
func (a *SDKS3API) ListObjectsV2(ctx context.Context, input ListObjectsV2Input) (ListObjectsV2Output, error) {
	if a == nil || a.client == nil {
		return ListObjectsV2Output{}, errors.New("cloudtraildelivery: SDK S3 client is required")
	}
	params := &s3.ListObjectsV2Input{Bucket: awsv2.String(input.Bucket)}
	if prefix := strings.TrimSpace(input.Prefix); prefix != "" {
		params.Prefix = awsv2.String(prefix)
	}
	if next := strings.TrimSpace(input.ContinuationToken); next != "" {
		params.ContinuationToken = awsv2.String(next)
	}
	if input.MaxKeys > 0 {
		params.MaxKeys = awsv2.Int32(input.MaxKeys)
	}
	if start := strings.TrimSpace(input.StartAfter); start != "" {
		params.StartAfter = awsv2.String(start)
	}
	out, err := a.client.ListObjectsV2(ctx, params)
	if err != nil {
		return ListObjectsV2Output{}, err
	}
	if out == nil {
		return ListObjectsV2Output{}, nil
	}
	resp := ListObjectsV2Output{NextToken: strings.TrimSpace(awsv2.ToString(out.NextContinuationToken))}
	if out.IsTruncated != nil {
		resp.IsTruncated = *out.IsTruncated
	}
	for _, item := range out.Contents {
		entry := S3Object{
			Key: strings.TrimSpace(awsv2.ToString(item.Key)),
		}
		if item.Size != nil {
			entry.Size = *item.Size
		}
		if item.LastModified != nil {
			entry.LastModified = item.LastModified.UTC()
		}
		resp.Objects = append(resp.Objects, entry)
	}
	return resp, nil
}

// GetObject maps the engine input onto the SDK shape. The caller
// owns closing the response body.
func (a *SDKS3API) GetObject(ctx context.Context, input GetObjectInput) (GetObjectOutput, error) {
	if a == nil || a.client == nil {
		return GetObjectOutput{}, errors.New("cloudtraildelivery: SDK S3 client is required")
	}
	out, err := a.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: awsv2.String(input.Bucket),
		Key:    awsv2.String(input.Key),
	})
	if err != nil {
		return GetObjectOutput{}, err
	}
	if out == nil {
		return GetObjectOutput{}, errors.New("cloudtraildelivery: SDK GetObject returned nil")
	}
	resp := GetObjectOutput{Body: out.Body}
	if out.ContentLength != nil {
		resp.ContentLength = *out.ContentLength
	}
	return resp, nil
}

func loadSDKConfig(ctx context.Context, region, profile string) (awsv2.Config, error) {
	options := []func(*awsconfig.LoadOptions) error{}
	if trimmedRegion := strings.TrimSpace(region); trimmedRegion != "" {
		options = append(options, awsconfig.WithRegion(trimmedRegion))
	}
	if trimmedProfile := strings.TrimSpace(profile); trimmedProfile != "" {
		options = append(options, awsconfig.WithSharedConfigProfile(trimmedProfile))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, options...)
	if err != nil {
		return awsv2.Config{}, fmt.Errorf("cloudtraildelivery: load aws config: %w", err)
	}
	return cfg, nil
}
