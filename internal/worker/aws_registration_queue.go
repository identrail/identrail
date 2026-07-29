package worker

import (
	"context"
	"fmt"
	"strings"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/identrail/identrail/internal/api"
)

type awsRegistrationQueueClient interface {
	ReceiveMessage(context.Context, *sqs.ReceiveMessageInput, ...func(*sqs.Options)) (*sqs.ReceiveMessageOutput, error)
	DeleteMessage(context.Context, *sqs.DeleteMessageInput, ...func(*sqs.Options)) (*sqs.DeleteMessageOutput, error)
}

type awsRegistrationQueueRunner struct {
	client   awsRegistrationQueueClient
	queueURL string
	service  *api.Service
	process  func(context.Context, string) error
}

func newAWSRegistrationQueueRunner(ctx context.Context, service *api.Service, queueURL string, region string, profile string) (*awsRegistrationQueueRunner, error) {
	if service == nil {
		return nil, fmt.Errorf("aws registration service is not configured")
	}
	options := []func(*awsconfig.LoadOptions) error{awsconfig.WithRegion(strings.TrimSpace(region))}
	if strings.TrimSpace(profile) != "" {
		options = append(options, awsconfig.WithSharedConfigProfile(strings.TrimSpace(profile)))
	}
	configuration, err := awsconfig.LoadDefaultConfig(ctx, options...)
	if err != nil {
		return nil, fmt.Errorf("load aws registration queue config: %w", err)
	}
	return &awsRegistrationQueueRunner{
		client:   sqs.NewFromConfig(configuration),
		queueURL: strings.TrimSpace(queueURL),
		service:  service,
		process:  service.ProcessAWSConnectorRegistrationMessage,
	}, nil
}

func (r *awsRegistrationQueueRunner) RunOnce(ctx context.Context) error {
	if r == nil || r.client == nil || r.queueURL == "" || r.process == nil {
		return fmt.Errorf("aws registration queue is not configured")
	}
	// Fetch a small batch. Each message may run STS + read-only permission
	// checks, so keeping the batch small ensures serial processing completes
	// within the queue's visibility timeout even under network jitter — a
	// redelivery mid-processing would race the original attempt and could
	// send an otherwise valid registration to the DLQ.
	result, err := r.client.ReceiveMessage(ctx, &sqs.ReceiveMessageInput{
		QueueUrl:            &r.queueURL,
		MaxNumberOfMessages: 3,
		WaitTimeSeconds:     10,
	})
	if err != nil {
		return fmt.Errorf("receive aws registration messages: %w", err)
	}
	failures := 0
	for _, message := range result.Messages {
		if message.Body == nil || message.ReceiptHandle == nil {
			failures++
			continue
		}
		if processErr := r.process(ctx, *message.Body); processErr != nil {
			failures++
			continue
		}
		if _, deleteErr := r.client.DeleteMessage(ctx, &sqs.DeleteMessageInput{QueueUrl: &r.queueURL, ReceiptHandle: message.ReceiptHandle}); deleteErr != nil {
			failures++
		}
	}
	if failures > 0 {
		return fmt.Errorf("aws registration queue left %d message(s) for retry", failures)
	}
	return nil
}
