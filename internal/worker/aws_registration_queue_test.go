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

func TestAWSRegistrationQueueEmptyBatchIsNoop(t *testing.T) {
	client := &fakeAWSRegistrationQueueClient{}
	processed := 0
	runner := &awsRegistrationQueueRunner{
		client:   client,
		queueURL: "https://sqs.us-east-1.amazonaws.com/123456789012/registration",
		process: func(context.Context, string) error {
			processed++
			return nil
		},
	}
	if err := runner.RunOnce(context.Background()); err != nil {
		t.Fatalf("empty batch should succeed, got %v", err)
	}
	if processed != 0 || len(client.deletedHandle) != 0 {
		t.Fatalf("empty batch should not process or delete anything")
	}
}

func TestAWSRegistrationQueueReceiveErrorReturnsError(t *testing.T) {
	client := &fakeAWSRegistrationQueueClient{receiveErr: errors.New("network")}
	runner := &awsRegistrationQueueRunner{
		client:   client,
		queueURL: "https://sqs.us-east-1.amazonaws.com/123456789012/registration",
		process:  func(context.Context, string) error { return nil },
	}
	err := runner.RunOnce(context.Background())
	if err == nil || !strings.Contains(err.Error(), "receive aws registration messages") {
		t.Fatalf("expected receive error to propagate, got %v", err)
	}
}

func TestAWSRegistrationQueueSkipsMessagesWithNilBodyOrReceipt(t *testing.T) {
	goodBody := "good"
	goodReceipt := "receipt-good"
	nilReceipt := "receipt-body-missing"
	nilBody := "nil-receipt-body"
	client := &fakeAWSRegistrationQueueClient{messages: []types.Message{
		{Body: nil, ReceiptHandle: &nilReceipt},
		{Body: &nilBody, ReceiptHandle: nil},
		{Body: &goodBody, ReceiptHandle: &goodReceipt},
	}}
	processed := 0
	runner := &awsRegistrationQueueRunner{
		client:   client,
		queueURL: "https://sqs.us-east-1.amazonaws.com/123456789012/registration",
		process: func(_ context.Context, body string) error {
			processed++
			if body != goodBody {
				t.Fatalf("only the well-formed message should be processed, got %q", body)
			}
			return nil
		},
	}
	err := runner.RunOnce(context.Background())
	if err == nil || !strings.Contains(err.Error(), "left 2 message") {
		t.Fatalf("nil body/receipt messages should be counted as failures, got %v", err)
	}
	if processed != 1 {
		t.Fatalf("expected only one successful process call, got %d", processed)
	}
	if len(client.deletedHandle) != 1 || client.deletedHandle[0] != goodReceipt {
		t.Fatalf("only the well-formed message should be deleted, got %+v", client.deletedHandle)
	}
}

func TestAWSRegistrationQueueDeleteErrorReportsFailure(t *testing.T) {
	body := "registration-event"
	receipt := "receipt-3"
	client := &fakeAWSRegistrationQueueClient{
		messages:  []types.Message{{Body: &body, ReceiptHandle: &receipt}},
		deleteErr: errors.New("delete throttled"),
	}
	runner := &awsRegistrationQueueRunner{
		client:   client,
		queueURL: "https://sqs.us-east-1.amazonaws.com/123456789012/registration",
		process:  func(context.Context, string) error { return nil },
	}
	err := runner.RunOnce(context.Background())
	if err == nil || !strings.Contains(err.Error(), "left 1 message") {
		t.Fatalf("delete failure should be counted as a retryable failure, got %v", err)
	}
}

func TestAWSRegistrationQueueMixedSuccessAndFailure(t *testing.T) {
	okBody := "ok"
	okReceipt := "receipt-ok"
	failBody := "fail"
	failReceipt := "receipt-fail"
	client := &fakeAWSRegistrationQueueClient{messages: []types.Message{
		{Body: &okBody, ReceiptHandle: &okReceipt},
		{Body: &failBody, ReceiptHandle: &failReceipt},
	}}
	runner := &awsRegistrationQueueRunner{
		client:   client,
		queueURL: "https://sqs.us-east-1.amazonaws.com/123456789012/registration",
		process: func(_ context.Context, body string) error {
			if body == failBody {
				return errors.New("process failed")
			}
			return nil
		},
	}
	err := runner.RunOnce(context.Background())
	if err == nil || !strings.Contains(err.Error(), "left 1 message") {
		t.Fatalf("mixed batch should report the failed count, got %v", err)
	}
	if len(client.deletedHandle) != 1 || client.deletedHandle[0] != okReceipt {
		t.Fatalf("only the successful message should be deleted, got %+v", client.deletedHandle)
	}
}
