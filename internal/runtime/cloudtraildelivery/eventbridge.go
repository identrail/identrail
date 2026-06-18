package cloudtraildelivery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/identrail/identrail/internal/runtime/cloudtrail"
)

// SQSAPI is the narrow seam for the EventBridge → SQS delivery
// channel. EventBridge fans CloudTrail events out to subscribers; the
// most common fan-out target in production is an SQS queue, and the
// ingester pulls a bounded batch of messages, normalizes the
// CloudTrail `detail` payload, and deletes successfully-ingested
// messages so they are not re-delivered. Messages whose normalization
// fails are left in the queue so the queue's redrive policy applies.
type SQSAPI interface {
	ReceiveMessage(ctx context.Context, input ReceiveMessageInput) (ReceiveMessageOutput, error)
	DeleteMessageBatch(ctx context.Context, input DeleteMessageBatchInput) (DeleteMessageBatchOutput, error)
}

// ReceiveMessageInput mirrors the SDK input.
type ReceiveMessageInput struct {
	QueueURL            string
	MaxNumberOfMessages int32
	WaitTimeSeconds     int32
	VisibilityTimeout   int32
}

// ReceiveMessageOutput holds the messages pulled from the queue.
type ReceiveMessageOutput struct {
	Messages []SQSMessage
}

// SQSMessage is the trimmed SDK message shape.
type SQSMessage struct {
	MessageID     string
	ReceiptHandle string
	Body          string
}

// DeleteMessageBatchInput requests deletion of one or more processed
// messages.
type DeleteMessageBatchInput struct {
	QueueURL string
	Entries  []DeleteMessageBatchEntry
}

// DeleteMessageBatchEntry pairs a message id with its receipt handle.
type DeleteMessageBatchEntry struct {
	ID            string
	ReceiptHandle string
}

// DeleteMessageBatchOutput surfaces the partial-failure structure
// SQS uses (some deletes can succeed while others fail in one
// request).
type DeleteMessageBatchOutput struct {
	Successful []string
	Failed     []DeleteMessageBatchFailure
}

// DeleteMessageBatchFailure carries the SQS error code per failed
// entry so the ingester can attach a per-message diagnostic.
type DeleteMessageBatchFailure struct {
	ID      string
	Code    string
	Message string
}

// EventBridgeIngester drives one bounded EventBridge ingestion run by
// consuming the SQS queue an EventBridge rule targets.
type EventBridgeIngester struct {
	API      SQSAPI
	QueueURL string
	Now      func() time.Time
	Sleep    func(time.Duration)
}

// NewEventBridgeIngester returns an EventBridgeIngester with sensible
// defaults for the Now and Sleep hooks.
func NewEventBridgeIngester(api SQSAPI, queueURL string) *EventBridgeIngester {
	return &EventBridgeIngester{
		API:      api,
		QueueURL: strings.TrimSpace(queueURL),
		Now:      func() time.Time { return time.Now().UTC() },
		Sleep:    time.Sleep,
	}
}

// eventBridgeEnvelope is the metadata-only projection of the
// EventBridge event envelope CloudTrail publishes. The `detail` field
// is the CloudTrail record itself; everything outside `detail` is
// envelope metadata the ingester does not need.
type eventBridgeEnvelope struct {
	ID         string          `json:"id"`
	Source     string          `json:"source"`
	DetailType string          `json:"detail-type"`
	Account    string          `json:"account"`
	Region     string          `json:"region"`
	Time       string          `json:"time"`
	Detail     json.RawMessage `json:"detail"`
}

// Ingest runs one bounded EventBridge ingestion pass.
func (i *EventBridgeIngester) Ingest(ctx context.Context, request IngestRequest) (IngestResult, error) {
	if i == nil {
		return IngestResult{}, errors.New("cloudtraildelivery: EventBridgeIngester is nil")
	}
	if i.API == nil {
		return IngestResult{}, errors.New("cloudtraildelivery: SQS API is required")
	}
	if strings.TrimSpace(i.QueueURL) == "" {
		return IngestResult{}, errors.New("cloudtraildelivery: queue url is required")
	}
	now := i.callerNow()
	request = request.withDefaults()
	result := IngestResult{Source: DeliverySourceEventBridge, Status: "ready"}

	receiveOut, moreAvailable, recvErr := i.receiveWithRetry(ctx, request)
	if recvErr != nil {
		if errors.Is(recvErr, context.Canceled) || errors.Is(recvErr, context.DeadlineExceeded) {
			return IngestResult{}, recvErr
		}
		if isPermissionDenied(recvErr) {
			return finalizeBlocked(result, recvErr, "CloudTrail EventBridge SQS receive is not authorized."), nil
		}
		result.Diagnostics = append(result.Diagnostics, cloudtrail.Diagnostic{
			SourceID:    "sqs-receive",
			Code:        diagnosticCodeFor(recvErr),
			Message:     fmt.Sprintf("SQS ReceiveMessage failed: %v", recvErr),
			Remediation: "Retry SQS receive; no messages were consumed.",
			Retryable:   isRetryable(recvErr),
		})
		result.Status = "degraded"
		result.FailureReasons = append(result.FailureReasons, "CloudTrail EventBridge SQS receive failed")
		result.RemediationHints = append(result.RemediationHints, "Confirm the connector role can sqs:ReceiveMessage on the configured queue.")
		finalizeEmptyOrTruncated(&result)
		return result, nil
	}
	if moreAvailable {
		result.HistoryTruncated = true
	}

	seen := map[string]struct{}{}
	toDelete := make([]DeleteMessageBatchEntry, 0, len(receiveOut.Messages))
	for _, msg := range receiveOut.Messages {
		result.MessagesProcessed++
		if result.MessagesProcessed > request.MaxMessages {
			result.HistoryTruncated = true
			break
		}
		record, raw, parseErr := decodeEventBridgeMessage(msg.Body)
		if parseErr != nil {
			// Malformed envelope: emit a diagnostic and leave the
			// message in-queue so the queue's redrive policy applies.
			result.Diagnostics = append(result.Diagnostics, cloudtrail.Diagnostic{
				SourceID:    msg.MessageID,
				Code:        "cloudtrail_eventbridge_envelope_unparseable",
				Message:     fmt.Sprintf("EventBridge envelope unparseable for message %s: %v", msg.MessageID, parseErr),
				Remediation: "Inspect the dead-letter queue; the message is preserved for redelivery.",
				Retryable:   false,
			})
			continue
		}
		eventID := strings.TrimSpace(record.EventID)
		if eventID == "" {
			result.Diagnostics = append(result.Diagnostics, cloudtrail.Diagnostic{
				SourceID:  msg.MessageID,
				Code:      "cloudtrail_eventbridge_record_missing_id",
				Message:   fmt.Sprintf("EventBridge message %s has no eventID; skipping.", msg.MessageID),
				Retryable: false,
			})
			// Even without an event id we can safely delete: the
			// message has no future value.
			toDelete = append(toDelete, DeleteMessageBatchEntry{ID: msg.MessageID, ReceiptHandle: msg.ReceiptHandle})
			continue
		}
		if _, dupe := seen[eventID]; dupe {
			toDelete = append(toDelete, DeleteMessageBatchEntry{ID: msg.MessageID, ReceiptHandle: msg.ReceiptHandle})
			continue
		}
		seen[eventID] = struct{}{}
		event := record.toCloudTrailEvent(raw)
		normalized, mapDiag, ok := cloudtrail.NormalizeEvent(event, request.AccountID, request.Region, now)
		if mapDiag != nil {
			mapDiag.SourceID = eventID
			result.Diagnostics = append(result.Diagnostics, *mapDiag)
		}
		if !ok {
			// Engine rejected the record (missing core fields, etc.).
			// Delete so the queue does not keep re-delivering it.
			toDelete = append(toDelete, DeleteMessageBatchEntry{ID: msg.MessageID, ReceiptHandle: msg.ReceiptHandle})
			continue
		}
		if !isWithinScope(request.AccountID, request.Region, record.RecipientAccount, record.AWSRegion) {
			continue
		}
		remaining := request.MaxEvents - len(result.Events)
		if remaining <= 0 {
			result.HistoryTruncated = true
			break
		}
		if len(normalized) > remaining {
			normalized = normalized[:remaining]
			result.HistoryTruncated = true
			result.Events = append(result.Events, normalized...)
			result.EventsConsidered++
			break
		}
		result.Events = append(result.Events, normalized...)
		toDelete = append(toDelete, DeleteMessageBatchEntry{ID: msg.MessageID, ReceiptHandle: msg.ReceiptHandle})
		result.EventsConsidered++
	}

	if len(toDelete) > 0 {
		if err := i.deleteBatch(ctx, toDelete, &result); err != nil {
			return IngestResult{}, err
		}
	}
	finalizeEmptyOrTruncated(&result)
	finalizeDiagnosticDegrade(&result)
	return result, nil
}

func isWithinScope(requestedAccount string, requestedRegion string, recordAccount string, recordRegion string) bool {
	account := strings.TrimSpace(requestedAccount)
	region := strings.TrimSpace(requestedRegion)
	if account != "" && strings.TrimSpace(recordAccount) != account {
		return false
	}
	if region != "" && strings.TrimSpace(recordRegion) != region {
		return false
	}
	return true
}

func (i *EventBridgeIngester) receiveWithRetry(ctx context.Context, request IngestRequest) (ReceiveMessageOutput, bool, error) {
	var combined ReceiveMessageOutput
	lastBatchFull := false
	for len(combined.Messages) < request.MaxMessages {
		max := request.MaxMessages - len(combined.Messages)
		// SQS caps ReceiveMessage at 10 entries per request; loop so
		// one ingestion run can consume the caller's MaxMessages budget.
		if max > 10 {
			max = 10
		}
		out, err := i.receiveOneWithRetry(ctx, request, max)
		if err != nil {
			return ReceiveMessageOutput{}, false, err
		}
		if len(out.Messages) == 0 {
			lastBatchFull = false
			break
		}
		combined.Messages = append(combined.Messages, out.Messages...)
		lastBatchFull = len(out.Messages) >= max
		if len(out.Messages) < max {
			break
		}
	}
	// If the budget is filled and the last batch was full, the queue
	// likely has more messages the caller could not consume.
	moreAvailable := lastBatchFull && len(combined.Messages) >= request.MaxMessages
	return combined, moreAvailable, nil
}

func (i *EventBridgeIngester) receiveOneWithRetry(ctx context.Context, request IngestRequest, max int) (ReceiveMessageOutput, error) {
	input := ReceiveMessageInput{
		QueueURL:            i.QueueURL,
		MaxNumberOfMessages: int32(max),
		// Long-poll with a 5-second wait so the ingester does not hot-
		// loop on an empty queue, but stays well below typical worker
		// tick budgets.
		WaitTimeSeconds:   5,
		VisibilityTimeout: int32(DefaultSQSVisibilityBuffer / time.Second),
	}
	var lastErr error
	for attempt := 0; attempt <= request.MaxThrottleRetries; attempt++ {
		if err := ctx.Err(); err != nil {
			return ReceiveMessageOutput{}, err
		}
		out, err := i.API.ReceiveMessage(ctx, input)
		if err == nil {
			return out, nil
		}
		lastErr = err
		if !isThrottling(err) {
			return ReceiveMessageOutput{}, err
		}
		if attempt == request.MaxThrottleRetries {
			break
		}
		i.sleep(request.ThrottleBackoff * time.Duration(attempt+1))
	}
	return ReceiveMessageOutput{}, lastErr
}

func (i *EventBridgeIngester) deleteBatch(ctx context.Context, entries []DeleteMessageBatchEntry, result *IngestResult) error {
	// SQS DeleteMessageBatch caps at 10 entries per request. Chunk to
	// stay within the cap and accumulate per-failure diagnostics.
	const batchCap = 10
	for start := 0; start < len(entries); start += batchCap {
		if err := ctx.Err(); err != nil {
			return err
		}
		end := start + batchCap
		if end > len(entries) {
			end = len(entries)
		}
		out, err := i.API.DeleteMessageBatch(ctx, DeleteMessageBatchInput{
			QueueURL: i.QueueURL,
			Entries:  entries[start:end],
		})
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			result.Diagnostics = append(result.Diagnostics, cloudtrail.Diagnostic{
				SourceID:    "sqs-delete-batch",
				Code:        diagnosticCodeFor(err),
				Message:     fmt.Sprintf("SQS DeleteMessageBatch failed: %v", err),
				Remediation: "Retry: messages re-appear after the visibility timeout and the next run will reprocess them.",
				Retryable:   isRetryable(err),
			})
			continue
		}
		for _, failure := range out.Failed {
			result.Diagnostics = append(result.Diagnostics, cloudtrail.Diagnostic{
				SourceID:    failure.ID,
				Code:        "cloudtrail_eventbridge_delete_failed",
				Message:     fmt.Sprintf("SQS DeleteMessageBatch failed for message %s: %s (%s)", failure.ID, failure.Message, failure.Code),
				Remediation: "Message re-appears after the visibility timeout; the next run dedupes by eventID and re-deletes.",
				Retryable:   true,
			})
		}
	}
	return nil
}

// decodeEventBridgeMessage parses an SQS message body produced by an
// EventBridge rule targeting an SQS queue. The body is the
// EventBridge envelope JSON; `detail` is the CloudTrail record. The
// raw `detail` JSON is returned so cloudtrail.NormalizeEvent can use
// its allow-listed metadata extraction on the full payload.
func decodeEventBridgeMessage(body string) (CloudTrailRecord, string, error) {
	trimmed := strings.TrimSpace(body)
	if trimmed == "" {
		return CloudTrailRecord{}, "", errors.New("empty SQS body")
	}
	var envelope eventBridgeEnvelope
	if err := json.Unmarshal([]byte(trimmed), &envelope); err != nil {
		return CloudTrailRecord{}, "", fmt.Errorf("decode EventBridge envelope: %w", err)
	}
	if len(envelope.Detail) == 0 {
		return CloudTrailRecord{}, "", errors.New("EventBridge envelope has empty detail")
	}
	var record CloudTrailRecord
	if err := json.Unmarshal(envelope.Detail, &record); err != nil {
		return CloudTrailRecord{}, "", fmt.Errorf("decode CloudTrail detail: %w", err)
	}
	return record, string(envelope.Detail), nil
}

func (i *EventBridgeIngester) callerNow() time.Time {
	if i == nil || i.Now == nil {
		return time.Now().UTC()
	}
	return i.Now().UTC()
}

func (i *EventBridgeIngester) sleep(d time.Duration) {
	if i == nil || i.Sleep == nil || d <= 0 {
		return
	}
	i.Sleep(d)
}
