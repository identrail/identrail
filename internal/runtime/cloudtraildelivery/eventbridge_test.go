package cloudtraildelivery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/runtime/cloudtrail"
)

func TestDeliveryFilterMatchesSessionDerivedIdentityCandidates(t *testing.T) {
	event := cloudtrail.NormalizedEvent{
		EventID:            "evt-identity",
		AccountID:          "123456789012",
		Region:             "us-east-1",
		EventSource:        "sts.amazonaws.com",
		EventName:          "AssumeRole",
		ActorPrincipalARN:  "arn:aws:sts::123456789012:assumed-role/payments/payments-job-42",
		ActorPrincipalType: "assumed_role",
		SessionID:          "sess-123",
		AssumedRoleARN:     "arn:aws:iam::123456789012:role/payments",
		SessionIssuerARN:   "arn:aws:iam::123456789012:role/payments",
		SourceIdentity:     "alice@example.com",
		RoleSessionName:    "payments-job-42",
		OriginalActorARN:   "arn:aws:iam::123456789012:role/original",
		ChainedFromARN:     "arn:aws:iam::123456789012:role/chained",
		LineageStatus:      "resolved",
	}
	for _, identity := range []string{
		"aws:identity:arn:aws:iam::123456789012:role/payments",
		"alice@example.com",
		"payments-job-42",
		"arn:aws:iam::123456789012:role/original",
		"arn:aws:iam::123456789012:role/chained",
		deliveryRuntimeSessionNodeID(event),
	} {
		if got := filterRuntimeEventRecordsForDelivery([]cloudtrail.NormalizedEvent{event}, map[string]string{"identity": identity}, DeliverySourceEventBridge); len(got) != 1 {
			t.Fatalf("expected identity filter %q to match delivery event, got %+v", identity, got)
		}
	}
}

func TestDeliveryFilterMatchesAgentNodeID(t *testing.T) {
	event := cloudtrail.NormalizedEvent{
		EventID:             "evt-agent",
		AccountID:           "123456789012",
		Region:              "us-east-1",
		AgentID:             "runtime-case-triage",
		AgentType:           "agentcore_runtime",
		AgentRuntimeVersion: "blue",
	}
	agentNodeID := deliveryAgentNodeID(event)
	if got := filterRuntimeEventRecordsForDelivery([]cloudtrail.NormalizedEvent{event}, map[string]string{"agent_id": agentNodeID}, DeliverySourceEventBridge); len(got) != 1 {
		t.Fatalf("expected agent node filter %q to match delivery event, got %+v", agentNodeID, got)
	}
}

type fakeSQS struct {
	receiveOut    ReceiveMessageOutput
	receivePages  []ReceiveMessageOutput
	receiveErr    error
	receiveInputs []ReceiveMessageInput
	deletedIDs    []string
	deleteFailure []DeleteMessageBatchFailure
	deleteErr     error
}

func (f *fakeSQS) ReceiveMessage(ctx context.Context, input ReceiveMessageInput) (ReceiveMessageOutput, error) {
	if err := ctx.Err(); err != nil {
		return ReceiveMessageOutput{}, err
	}
	f.receiveInputs = append(f.receiveInputs, input)
	if len(f.receivePages) > 0 {
		idx := len(f.receiveInputs) - 1
		if idx >= len(f.receivePages) {
			return ReceiveMessageOutput{}, nil
		}
		return f.receivePages[idx], f.receiveErr
	}
	return f.receiveOut, f.receiveErr
}

func (f *fakeSQS) DeleteMessageBatch(ctx context.Context, input DeleteMessageBatchInput) (DeleteMessageBatchOutput, error) {
	if err := ctx.Err(); err != nil {
		return DeleteMessageBatchOutput{}, err
	}
	if f.deleteErr != nil {
		return DeleteMessageBatchOutput{}, f.deleteErr
	}
	out := DeleteMessageBatchOutput{Failed: f.deleteFailure}
	for _, e := range input.Entries {
		out.Successful = append(out.Successful, e.ID)
		f.deletedIDs = append(f.deletedIDs, e.ID)
	}
	return out, nil
}

func eventBridgeMessageBody(t *testing.T, eventID, eventName, eventSource string, eventTime time.Time) string {
	t.Helper()
	detail := map[string]any{
		"eventID":            eventID,
		"eventName":          eventName,
		"eventSource":        eventSource,
		"eventTime":          eventTime.UTC().Format(time.RFC3339),
		"awsRegion":          "us-east-1",
		"recipientAccountId": "123456789012",
		"userIdentity": map[string]any{
			"type": "AssumedRole",
			"arn":  "arn:aws:sts::123456789012:assumed-role/role/sess",
		},
	}
	envelope := map[string]any{
		"id":          "eb-id-" + eventID,
		"source":      "aws.cloudtrail",
		"detail-type": "AWS API Call via CloudTrail",
		"account":     "123456789012",
		"region":      "us-east-1",
		"time":        eventTime.UTC().Format(time.RFC3339),
		"detail":      detail,
	}
	body, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("encode envelope: %v", err)
	}
	return string(body)
}

func eventBridgeMessageBodyWithResources(t *testing.T, eventID, eventName, eventSource string, eventTime time.Time, resources []map[string]any) string {
	t.Helper()
	detail := map[string]any{
		"eventID":            eventID,
		"eventName":          eventName,
		"eventSource":        eventSource,
		"eventTime":          eventTime.UTC().Format(time.RFC3339),
		"awsRegion":          "us-east-1",
		"recipientAccountId": "123456789012",
		"resources":          resources,
		"userIdentity": map[string]any{
			"type": "AssumedRole",
			"arn":  "arn:aws:sts::123456789012:assumed-role/role/sess",
		},
	}
	envelope := map[string]any{
		"id":          "eb-id-" + eventID,
		"source":      "aws.cloudtrail",
		"detail-type": "AWS API Call via CloudTrail",
		"account":     "123456789012",
		"region":      "us-east-1",
		"time":        eventTime.UTC().Format(time.RFC3339),
		"detail":      detail,
	}
	body, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("encode envelope: %v", err)
	}
	return string(body)
}

func TestEventBridgeIngesterNormalizesAndDeletesProcessedMessages(t *testing.T) {
	now := time.Date(2026, 6, 15, 18, 0, 0, 0, time.UTC)
	fake := &fakeSQS{receiveOut: ReceiveMessageOutput{Messages: []SQSMessage{
		{MessageID: "msg-1", ReceiptHandle: "rh-1", Body: eventBridgeMessageBody(t, "evt-secret", "GetSecretValue", "secretsmanager.amazonaws.com", now.Add(-2*time.Minute))},
		{MessageID: "msg-2", ReceiptHandle: "rh-2", Body: eventBridgeMessageBody(t, "evt-kms", "Decrypt", "kms.amazonaws.com", now.Add(-1*time.Minute))},
	}}}
	ing := NewEventBridgeIngester(fake, "https://sqs.us-east-1.amazonaws.com/123456789012/cloudtrail-events")
	ing.Now = func() time.Time { return now }
	result, err := ing.Ingest(context.Background(), IngestRequest{AccountID: "123456789012", Region: "us-east-1"})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if result.Source != DeliverySourceEventBridge || result.Status != "ready" {
		t.Fatalf("expected source=eventbridge ready, got %+v", result)
	}
	if len(result.Events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(result.Events))
	}
	if len(fake.deletedIDs) != 2 {
		t.Fatalf("expected both messages deleted, got %+v", fake.deletedIDs)
	}
}

func TestEventBridgeIngesterDedupesAndStillDeletesDuplicates(t *testing.T) {
	now := time.Date(2026, 6, 15, 18, 0, 0, 0, time.UTC)
	body := eventBridgeMessageBody(t, "evt-dupe", "AssumeRole", "sts.amazonaws.com", now)
	fake := &fakeSQS{receiveOut: ReceiveMessageOutput{Messages: []SQSMessage{
		{MessageID: "msg-1", ReceiptHandle: "rh-1", Body: body},
		{MessageID: "msg-2", ReceiptHandle: "rh-2", Body: body},
	}}}
	ing := NewEventBridgeIngester(fake, "https://sqs/queue")
	ing.Now = func() time.Time { return now }
	result, err := ing.Ingest(context.Background(), IngestRequest{AccountID: "123456789012", Region: "us-east-1"})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if len(result.Events) != 1 {
		t.Fatalf("expected one event after dedupe, got %d", len(result.Events))
	}
	if len(fake.deletedIDs) != 2 {
		t.Fatalf("expected both duplicate messages deleted, got %+v", fake.deletedIDs)
	}
}

func TestEventBridgeIngesterLeavesUnparseableMessagesInQueueForRedrive(t *testing.T) {
	now := time.Date(2026, 6, 15, 18, 0, 0, 0, time.UTC)
	fake := &fakeSQS{receiveOut: ReceiveMessageOutput{Messages: []SQSMessage{
		{MessageID: "msg-bad", ReceiptHandle: "rh-bad", Body: "{not-json"},
		{MessageID: "msg-good", ReceiptHandle: "rh-good", Body: eventBridgeMessageBody(t, "evt-good", "AssumeRole", "sts.amazonaws.com", now)},
	}}}
	ing := NewEventBridgeIngester(fake, "https://sqs/queue")
	ing.Now = func() time.Time { return now }
	result, err := ing.Ingest(context.Background(), IngestRequest{AccountID: "123456789012", Region: "us-east-1"})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if len(result.Events) != 1 || result.Events[0].EventID != "evt-good" {
		t.Fatalf("expected the good event preserved, got %+v", result.Events)
	}
	if len(fake.deletedIDs) != 1 || fake.deletedIDs[0] != "msg-good" {
		t.Fatalf("malformed message must remain in queue for redrive, got deleted=%+v", fake.deletedIDs)
	}
	if result.Status != "degraded" {
		t.Fatalf("expected degraded status when an envelope is unparseable, got %q", result.Status)
	}
}

func TestEventBridgeIngesterReportsPermissionDeniedAsBlocked(t *testing.T) {
	fake := &fakeSQS{receiveErr: codedErr{code: "AccessDeniedException", msg: "User is not authorized (AccessDeniedException)"}}
	ing := NewEventBridgeIngester(fake, "https://sqs/queue")
	ing.Now = func() time.Time { return time.Now().UTC() }
	result, err := ing.Ingest(context.Background(), IngestRequest{AccountID: "123456789012", Region: "us-east-1"})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if result.Status != "blocked" {
		t.Fatalf("expected blocked, got %q", result.Status)
	}
	if len(result.CoverageGaps) == 0 || result.CoverageGaps[0].Status != "permission_denied" {
		t.Fatalf("expected permission_denied coverage gap, got %+v", result.CoverageGaps)
	}
}

func TestEventBridgeIngesterPropagatesContextCancellation(t *testing.T) {
	fake := &fakeSQS{receiveErr: context.Canceled}
	ing := NewEventBridgeIngester(fake, "https://sqs/queue")
	ing.Now = func() time.Time { return time.Now().UTC() }
	if _, err := ing.Ingest(context.Background(), IngestRequest{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled propagation, got %v", err)
	}
}

func TestEventBridgeIngesterPropagatesDeleteContextCancellation(t *testing.T) {
	now := time.Date(2026, 6, 15, 18, 0, 0, 0, time.UTC)
	fake := &fakeSQS{
		receiveOut: ReceiveMessageOutput{Messages: []SQSMessage{
			{MessageID: "msg-1", ReceiptHandle: "rh-1", Body: eventBridgeMessageBody(t, "evt-1", "AssumeRole", "sts.amazonaws.com", now)},
		}},
		deleteErr: context.Canceled,
	}
	ing := NewEventBridgeIngester(fake, "https://sqs/queue")
	ing.Now = func() time.Time { return now }
	if _, err := ing.Ingest(context.Background(), IngestRequest{AccountID: "123456789012", Region: "us-east-1"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled propagation from delete, got %v", err)
	}
}

func TestEventBridgeIngesterRespectsMaxEventsBudget(t *testing.T) {
	now := time.Date(2026, 6, 15, 18, 0, 0, 0, time.UTC)
	fake := &fakeSQS{receiveOut: ReceiveMessageOutput{Messages: []SQSMessage{
		{MessageID: "msg-1", ReceiptHandle: "rh-1", Body: eventBridgeMessageBody(t, "evt-1", "AssumeRole", "sts.amazonaws.com", now.Add(-3*time.Minute))},
		{MessageID: "msg-2", ReceiptHandle: "rh-2", Body: eventBridgeMessageBody(t, "evt-2", "AssumeRole", "sts.amazonaws.com", now.Add(-2*time.Minute))},
		{MessageID: "msg-3", ReceiptHandle: "rh-3", Body: eventBridgeMessageBody(t, "evt-3", "AssumeRole", "sts.amazonaws.com", now.Add(-1*time.Minute))},
	}}}
	ing := NewEventBridgeIngester(fake, "https://sqs/queue")
	ing.Now = func() time.Time { return now }
	result, err := ing.Ingest(context.Background(), IngestRequest{AccountID: "123456789012", Region: "us-east-1", MaxEvents: 2})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if len(result.Events) != 2 {
		t.Fatalf("expected MaxEvents=2 cap, got %d", len(result.Events))
	}
	if !result.HistoryTruncated {
		t.Fatalf("expected HistoryTruncated when budget capped")
	}
}

func TestEventBridgeIngesterReceivesBatchesUpToMaxMessages(t *testing.T) {
	now := time.Date(2026, 6, 15, 18, 0, 0, 0, time.UTC)
	page := func(start int) ReceiveMessageOutput {
		out := ReceiveMessageOutput{}
		for idx := 0; idx < 10; idx++ {
			n := start + idx
			out.Messages = append(out.Messages, SQSMessage{
				MessageID:     fmt.Sprintf("msg-%02d", n),
				ReceiptHandle: fmt.Sprintf("rh-%02d", n),
				Body:          eventBridgeMessageBody(t, fmt.Sprintf("evt-%02d", n), "AssumeRole", "sts.amazonaws.com", now),
			})
		}
		return out
	}
	fake := &fakeSQS{receivePages: []ReceiveMessageOutput{page(0), page(10), ReceiveMessageOutput{}}}
	ing := NewEventBridgeIngester(fake, "https://sqs/queue")
	ing.Now = func() time.Time { return now }
	result, err := ing.Ingest(context.Background(), IngestRequest{AccountID: "123456789012", Region: "us-east-1", MaxMessages: 20})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if len(result.Events) != 20 || len(fake.deletedIDs) != 20 {
		t.Fatalf("expected 20 events/deletes, got events=%d deletes=%d", len(result.Events), len(fake.deletedIDs))
	}
	if len(fake.receiveInputs) != 2 || fake.receiveInputs[0].MaxNumberOfMessages != 10 || fake.receiveInputs[1].MaxNumberOfMessages != 10 {
		t.Fatalf("expected two 10-message receives, got %+v", fake.receiveInputs)
	}
}

func TestEventBridgeIngesterDoesNotDeleteMessageTruncatedMidFanout(t *testing.T) {
	now := time.Date(2026, 6, 15, 18, 0, 0, 0, time.UTC)
	body := eventBridgeMessageBodyWithResources(t, "evt-many", "BatchGetSecretValue", "secretsmanager.amazonaws.com", now, []map[string]any{
		{"type": "AWS::SecretsManager::Secret", "ARN": "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/one"},
		{"type": "AWS::SecretsManager::Secret", "ARN": "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/two"},
	})
	fake := &fakeSQS{receiveOut: ReceiveMessageOutput{Messages: []SQSMessage{
		{MessageID: "msg-many", ReceiptHandle: "rh-many", Body: body},
	}}}
	ing := NewEventBridgeIngester(fake, "https://sqs/queue")
	ing.Now = func() time.Time { return now }
	result, err := ing.Ingest(context.Background(), IngestRequest{AccountID: "123456789012", Region: "us-east-1", MaxEvents: 1})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if !result.HistoryTruncated || len(result.Events) != 1 {
		t.Fatalf("expected one truncated event, got %+v", result)
	}
	if len(fake.deletedIDs) != 0 {
		t.Fatalf("truncated message must remain for redelivery, deleted=%+v", fake.deletedIDs)
	}
}

func TestEventBridgeIngesterDoesNotDeleteFilteredOutMessages(t *testing.T) {
	now := time.Date(2026, 6, 15, 18, 0, 0, 0, time.UTC)
	fake := &fakeSQS{receiveOut: ReceiveMessageOutput{Messages: []SQSMessage{
		{MessageID: "msg-1", ReceiptHandle: "rh-1", Body: eventBridgeMessageBody(t, "evt-secret", "GetSecretValue", "secretsmanager.amazonaws.com", now.Add(-2*time.Minute))},
		{MessageID: "msg-2", ReceiptHandle: "rh-2", Body: eventBridgeMessageBody(t, "evt-kms", "Decrypt", "kms.amazonaws.com", now.Add(-1*time.Minute))},
	}}}
	ing := NewEventBridgeIngester(fake, "https://sqs/queue")
	ing.Now = func() time.Time { return now }
	result, err := ing.Ingest(context.Background(), IngestRequest{AccountID: "123456789012", Region: "us-east-1", AppliedFilters: map[string]string{"event_type": "secret-read"}})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if len(result.Events) != 1 || result.Events[0].EventID != "evt-secret" {
		t.Fatalf("expected only filtered event to be returned, got %+v", result.Events)
	}
	if len(fake.deletedIDs) != 1 {
		t.Fatalf("expected only matching message to delete, got %+v", fake.deletedIDs)
	}
	if fake.deletedIDs[0] != "msg-1" {
		t.Fatalf("expected secret message deleted, got %+v", fake.deletedIDs)
	}
}

func TestEventBridgeIngesterDoesNotDeletePartiallyFilteredFanoutMessage(t *testing.T) {
	now := time.Date(2026, 6, 15, 18, 0, 0, 0, time.UTC)
	body := eventBridgeMessageBodyWithResources(t, "evt-many", "BatchGetSecretValue", "secretsmanager.amazonaws.com", now, []map[string]any{
		{"type": "AWS::SecretsManager::Secret", "ARN": "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/one"},
		{"type": "AWS::SecretsManager::Secret", "ARN": "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/two"},
	})
	fake := &fakeSQS{receiveOut: ReceiveMessageOutput{Messages: []SQSMessage{
		{MessageID: "msg-many", ReceiptHandle: "rh-many", Body: body},
	}}}
	ing := NewEventBridgeIngester(fake, "https://sqs/queue")
	ing.Now = func() time.Time { return now }

	result, err := ing.Ingest(context.Background(), IngestRequest{
		AccountID:      "123456789012",
		Region:         "us-east-1",
		AppliedFilters: map[string]string{"resource": "prod/one"},
	})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if len(result.Events) != 1 || !strings.Contains(result.Events[0].TargetResourceARN, "prod/one") {
		t.Fatalf("expected only matching fan-out record, got %+v", result.Events)
	}
	if len(fake.deletedIDs) != 0 {
		t.Fatalf("partially filtered fan-out message must remain for broader queries, deleted=%+v", fake.deletedIDs)
	}
}

func TestEventBridgeIngesterMatchesResourceNodeFilter(t *testing.T) {
	now := time.Date(2026, 6, 15, 18, 0, 0, 0, time.UTC)
	resourceARN := "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/one"
	body := eventBridgeMessageBodyWithResources(t, "evt-node", "GetSecretValue", "secretsmanager.amazonaws.com", now, []map[string]any{
		{"type": "AWS::SecretsManager::Secret", "ARN": resourceARN},
	})
	fake := &fakeSQS{receiveOut: ReceiveMessageOutput{Messages: []SQSMessage{
		{MessageID: "msg-node", ReceiptHandle: "rh-node", Body: body},
	}}}
	ing := NewEventBridgeIngester(fake, "https://sqs/queue")
	ing.Now = func() time.Time { return now }
	resourceNodeID := deliveryRuntimeResourceNodeID(resourceARN, "AWS::SecretsManager::Secret")

	result, err := ing.Ingest(context.Background(), IngestRequest{
		AccountID:      "123456789012",
		Region:         "us-east-1",
		AppliedFilters: map[string]string{"resource": resourceNodeID},
	})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if len(result.Events) != 1 || result.Events[0].EventID != "evt-node" {
		t.Fatalf("expected resource-node filtered event, got %+v", result.Events)
	}
	if len(fake.deletedIDs) != 1 || fake.deletedIDs[0] != "msg-node" {
		t.Fatalf("expected fully retained resource-node match to delete, got %+v", fake.deletedIDs)
	}
}

func TestEventBridgeIngesterIgnoresDeliveryEvidenceFilterBeforeAdapterStamping(t *testing.T) {
	now := time.Date(2026, 6, 15, 18, 0, 0, 0, time.UTC)
	fake := &fakeSQS{receiveOut: ReceiveMessageOutput{Messages: []SQSMessage{
		{MessageID: "msg-1", ReceiptHandle: "rh-1", Body: eventBridgeMessageBody(t, "evt-secret", "GetSecretValue", "secretsmanager.amazonaws.com", now.Add(-time.Minute))},
	}}}
	ing := NewEventBridgeIngester(fake, "https://sqs/queue")
	ing.Now = func() time.Time { return now }

	result, err := ing.Ingest(context.Background(), IngestRequest{
		AccountID:      "123456789012",
		Region:         "us-east-1",
		AppliedFilters: map[string]string{"evidence": "eventbridge-delivery"},
	})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if len(result.Events) != 1 || result.Events[0].EventID != "evt-secret" {
		t.Fatalf("expected delivery evidence filter to be left for API stamping, got %+v", result.Events)
	}
	if len(fake.deletedIDs) != 1 || fake.deletedIDs[0] != "msg-1" {
		t.Fatalf("expected fully retained message to delete, got %+v", fake.deletedIDs)
	}
}

func TestEventBridgeIngesterDoesNotDeleteMessagesExcludedByAccountRegionFilters(t *testing.T) {
	now := time.Date(2026, 6, 15, 18, 0, 0, 0, time.UTC)
	fake := &fakeSQS{receiveOut: ReceiveMessageOutput{Messages: []SQSMessage{
		{MessageID: "msg-1", ReceiptHandle: "rh-1", Body: eventBridgeMessageBody(t, "evt-secret", "GetSecretValue", "secretsmanager.amazonaws.com", now.Add(-time.Minute))},
	}}}
	ing := NewEventBridgeIngester(fake, "https://sqs/queue")
	ing.Now = func() time.Time { return now }

	result, err := ing.Ingest(context.Background(), IngestRequest{
		AccountID:      "123456789012",
		Region:         "us-east-1",
		AppliedFilters: map[string]string{"region": "us-west-2"},
	})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if len(result.Events) != 0 {
		t.Fatalf("expected region-filtered message to return no events, got %+v", result.Events)
	}
	if len(fake.deletedIDs) != 0 {
		t.Fatalf("region-filtered message must remain for broader queries, deleted=%+v", fake.deletedIDs)
	}
}

func TestEventBridgeIngesterKeepsMessagesForOtherDeliveryEvidenceFilter(t *testing.T) {
	now := time.Date(2026, 6, 15, 18, 0, 0, 0, time.UTC)
	fake := &fakeSQS{receiveOut: ReceiveMessageOutput{Messages: []SQSMessage{
		{MessageID: "msg-1", ReceiptHandle: "rh-1", Body: eventBridgeMessageBody(t, "evt-secret", "GetSecretValue", "secretsmanager.amazonaws.com", now.Add(-time.Minute))},
	}}}
	ing := NewEventBridgeIngester(fake, "https://sqs/queue")
	ing.Now = func() time.Time { return now }

	result, err := ing.Ingest(context.Background(), IngestRequest{
		AccountID:      "123456789012",
		Region:         "us-east-1",
		AppliedFilters: map[string]string{"evidence": "s3-delivery"},
	})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if len(result.Events) != 0 {
		t.Fatalf("expected nonmatching delivery evidence filter to return no events, got %+v", result.Events)
	}
	if result.Status != "ready" || len(result.CoverageGaps) != 0 {
		t.Fatalf("expected nonmatching delivery source to be neutral, got %+v", result)
	}
	if len(fake.receiveInputs) != 0 {
		t.Fatalf("nonmatching delivery evidence filter must not receive SQS messages, inputs=%+v", fake.receiveInputs)
	}
	if len(fake.deletedIDs) != 0 {
		t.Fatalf("nonmatching delivery evidence filter must not delete message, deleted=%+v", fake.deletedIDs)
	}
}

func TestEventBridgeIngesterKeepsMessagesForRawEvidenceFilter(t *testing.T) {
	now := time.Date(2026, 6, 15, 18, 0, 0, 0, time.UTC)
	fake := &fakeSQS{receiveOut: ReceiveMessageOutput{Messages: []SQSMessage{
		{MessageID: "msg-1", ReceiptHandle: "rh-1", Body: eventBridgeMessageBody(t, "evt-secret", "GetSecretValue", "secretsmanager.amazonaws.com", now.Add(-time.Minute))},
	}}}
	ing := NewEventBridgeIngester(fake, "https://sqs/queue")
	ing.Now = func() time.Time { return now }

	result, err := ing.Ingest(context.Background(), IngestRequest{
		AccountID:      "123456789012",
		Region:         "us-east-1",
		AppliedFilters: map[string]string{"evidence": "cloudtrail"},
	})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if len(result.Events) != 0 {
		t.Fatalf("expected raw evidence filter to exclude delivery event before stamping, got %+v", result.Events)
	}
	if len(fake.deletedIDs) != 0 {
		t.Fatalf("raw evidence filter must not delete delivery message, deleted=%+v", fake.deletedIDs)
	}
}
