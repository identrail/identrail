package cloudtraildelivery

import (
	"context"
	"errors"
	"strings"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// SQSClient is the minimal seam from the AWS SDK SQS client.
type SQSClient interface {
	ReceiveMessage(ctx context.Context, params *sqs.ReceiveMessageInput, optFns ...func(*sqs.Options)) (*sqs.ReceiveMessageOutput, error)
	DeleteMessageBatch(ctx context.Context, params *sqs.DeleteMessageBatchInput, optFns ...func(*sqs.Options)) (*sqs.DeleteMessageBatchOutput, error)
}

// SDKSQSAPI implements SQSAPI against the AWS SDK. Only the
// read-and-acknowledge operations are exposed; SendMessage,
// PurgeQueue, and any mutating producer API are deliberately absent
// so the adapter cannot accidentally produce or destroy queue
// content.
type SDKSQSAPI struct {
	client SQSClient
}

// NewSDKSQSAPIFromClient wraps a pre-built SQS client.
func NewSDKSQSAPIFromClient(client SQSClient) *SDKSQSAPI {
	return &SDKSQSAPI{client: client}
}

// NewSDKSQSAPIFromAssumeRole builds the SDK-backed adapter after
// assuming the supplied connector role.
func NewSDKSQSAPIFromAssumeRole(ctx context.Context, region, profile, roleARN, externalID, sessionName string) (SQSAPI, error) {
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
				name = "identrail-cloudtrail-eventbridge-delivery"
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
	return NewSDKSQSAPIFromClient(sqs.NewFromConfig(cfg)), nil
}

// ReceiveMessage maps the engine input onto the SDK shape and trims
// the response down to the metadata the ingester actually uses.
func (a *SDKSQSAPI) ReceiveMessage(ctx context.Context, input ReceiveMessageInput) (ReceiveMessageOutput, error) {
	if a == nil || a.client == nil {
		return ReceiveMessageOutput{}, errors.New("cloudtraildelivery: SDK SQS client is required")
	}
	params := &sqs.ReceiveMessageInput{QueueUrl: awsv2.String(input.QueueURL)}
	if input.MaxNumberOfMessages > 0 {
		params.MaxNumberOfMessages = input.MaxNumberOfMessages
	}
	if input.WaitTimeSeconds > 0 {
		params.WaitTimeSeconds = input.WaitTimeSeconds
	}
	if input.VisibilityTimeout > 0 {
		params.VisibilityTimeout = input.VisibilityTimeout
	}
	out, err := a.client.ReceiveMessage(ctx, params)
	if err != nil {
		return ReceiveMessageOutput{}, err
	}
	if out == nil {
		return ReceiveMessageOutput{}, nil
	}
	resp := ReceiveMessageOutput{}
	for _, msg := range out.Messages {
		resp.Messages = append(resp.Messages, SQSMessage{
			MessageID:     strings.TrimSpace(awsv2.ToString(msg.MessageId)),
			ReceiptHandle: strings.TrimSpace(awsv2.ToString(msg.ReceiptHandle)),
			Body:          awsv2.ToString(msg.Body),
		})
	}
	return resp, nil
}

// DeleteMessageBatch acks one or more successfully-processed messages.
func (a *SDKSQSAPI) DeleteMessageBatch(ctx context.Context, input DeleteMessageBatchInput) (DeleteMessageBatchOutput, error) {
	if a == nil || a.client == nil {
		return DeleteMessageBatchOutput{}, errors.New("cloudtraildelivery: SDK SQS client is required")
	}
	entries := make([]sqstypes.DeleteMessageBatchRequestEntry, 0, len(input.Entries))
	for _, e := range input.Entries {
		entries = append(entries, sqstypes.DeleteMessageBatchRequestEntry{
			Id:            awsv2.String(e.ID),
			ReceiptHandle: awsv2.String(e.ReceiptHandle),
		})
	}
	out, err := a.client.DeleteMessageBatch(ctx, &sqs.DeleteMessageBatchInput{
		QueueUrl: awsv2.String(input.QueueURL),
		Entries:  entries,
	})
	if err != nil {
		return DeleteMessageBatchOutput{}, err
	}
	if out == nil {
		return DeleteMessageBatchOutput{}, nil
	}
	resp := DeleteMessageBatchOutput{}
	for _, ok := range out.Successful {
		resp.Successful = append(resp.Successful, strings.TrimSpace(awsv2.ToString(ok.Id)))
	}
	for _, failure := range out.Failed {
		resp.Failed = append(resp.Failed, DeleteMessageBatchFailure{
			ID:      strings.TrimSpace(awsv2.ToString(failure.Id)),
			Code:    strings.TrimSpace(awsv2.ToString(failure.Code)),
			Message: strings.TrimSpace(awsv2.ToString(failure.Message)),
		})
	}
	return resp, nil
}
