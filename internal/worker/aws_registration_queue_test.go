package worker

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
)

type fakeAWSRegistrationQueueClient struct {
	messages      []types.Message
	receiveErr    error
	deleteErr     error
	deletedHandle []string
}

func (f *fakeAWSRegistrationQueueClient) ReceiveMessage(_ context.Context, _ *sqs.ReceiveMessageInput, _ ...func(*sqs.Options)) (*sqs.ReceiveMessageOutput, error) {
	if f.receiveErr != nil {
		return nil, f.receiveErr
	}
	return &sqs.ReceiveMessageOutput{Messages: f.messages}, nil
}

func (f *fakeAWSRegistrationQueueClient) DeleteMessage(_ context.Context, input *sqs.DeleteMessageInput, _ ...func(*sqs.Options)) (*sqs.DeleteMessageOutput, error) {
	if f.deleteErr != nil {
		return nil, f.deleteErr
	}
	if input.ReceiptHandle != nil {
		f.deletedHandle = append(f.deletedHandle, *input.ReceiptHandle)
	}
	return &sqs.DeleteMessageOutput{}, nil
}

func TestAWSRegistrationQueueDeletesOnlySuccessfulMessages(t *testing.T) {
	body := "registration-event"
	receipt := "receipt-1"
	client := &fakeAWSRegistrationQueueClient{messages: []types.Message{{Body: &body, ReceiptHandle: &receipt}}}
	runner := &awsRegistrationQueueRunner{
		client:   client,
		queueURL: "https://sqs.us-east-1.amazonaws.com/123456789012/registration",
		process: func(_ context.Context, got string) error {
			if got != body {
				t.Fatalf("unexpected registration body: %q", got)
			}
			return nil
		},
	}
	if err := runner.RunOnce(context.Background()); err != nil {
		t.Fatalf("run registration queue: %v", err)
	}
	if len(client.deletedHandle) != 1 || client.deletedHandle[0] != receipt {
		t.Fatalf("expected successful message deletion, got %+v", client.deletedHandle)
	}
}

func TestAWSRegistrationQueueRetainsFailedMessageWithoutLeakingBody(t *testing.T) {
	body := "RegistrationToken=do-not-log"
	receipt := "receipt-2"
	client := &fakeAWSRegistrationQueueClient{messages: []types.Message{{Body: &body, ReceiptHandle: &receipt}}}
	runner := &awsRegistrationQueueRunner{
		client:   client,
		queueURL: "https://sqs.us-east-1.amazonaws.com/123456789012/registration",
		process:  func(context.Context, string) error { return errors.New("invalid registration") },
	}
	err := runner.RunOnce(context.Background())
	if err == nil || strings.Contains(err.Error(), body) || strings.Contains(err.Error(), "do-not-log") {
		t.Fatalf("expected a payload-safe retry error, got %v", err)
	}
	if len(client.deletedHandle) != 0 {
		t.Fatalf("failed message must remain for SQS retry, deleted %+v", client.deletedHandle)
	}
}
