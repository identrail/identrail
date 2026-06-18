package cloudtraildelivery

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/identrail/identrail/internal/runtime/cloudtrail"
)

// S3API is the narrow seam every S3 backend implements. The SDK
// adapter wraps s3.Client; tests use a fake to exercise the ingester
// deterministically without network access.
type S3API interface {
	ListObjectsV2(ctx context.Context, input ListObjectsV2Input) (ListObjectsV2Output, error)
	GetObject(ctx context.Context, input GetObjectInput) (GetObjectOutput, error)
}

// ListObjectsV2Input is the S3 ListObjectsV2 request, expressed
// independently of the SDK so the ingester layer never imports the
// SDK types directly.
type ListObjectsV2Input struct {
	Bucket            string
	Prefix            string
	ContinuationToken string
	MaxKeys           int32
	// StartAfter scopes the listing to keys strictly greater than the
	// supplied key. CloudTrail object keys embed an ISO-8601 timestamp,
	// so passing the last processed key gives the next run an
	// efficient resume marker without re-listing the entire window.
	StartAfter string
}

// ListObjectsV2Output is the trimmed S3 response shape.
type ListObjectsV2Output struct {
	Objects     []S3Object
	NextToken   string
	IsTruncated bool
}

// S3Object is the per-object metadata the ingester needs from
// ListObjectsV2.
type S3Object struct {
	Key          string
	Size         int64
	LastModified time.Time
}

// GetObjectInput is the S3 GetObject request shape.
type GetObjectInput struct {
	Bucket string
	Key    string
}

// GetObjectOutput is the trimmed S3 response shape. The Body field is
// the caller's responsibility to close.
type GetObjectOutput struct {
	Body          io.ReadCloser
	ContentLength int64
}

// S3Ingester drives one bounded CloudTrail S3 ingestion run.
type S3Ingester struct {
	API S3API
	// Bucket and Prefix locate the CloudTrail trail's S3 destination.
	// CloudTrail keys look like
	// AWSLogs/<account>/CloudTrail/<region>/YYYY/MM/DD/<account>_CloudTrail_<region>_<timestamp>_<uuid>.json.gz
	// so a prefix scoped to one account+region greatly reduces the
	// number of objects listed per run.
	Bucket string
	Prefix string
	Now    func() time.Time
	Sleep  func(time.Duration)
}

// NewS3Ingester returns an S3Ingester with sensible defaults for the
// Now and Sleep hooks.
func NewS3Ingester(api S3API, bucket, prefix string) *S3Ingester {
	return &S3Ingester{
		API:    api,
		Bucket: strings.TrimSpace(bucket),
		Prefix: strings.TrimSpace(prefix),
		Now:    func() time.Time { return time.Now().UTC() },
		Sleep:  time.Sleep,
	}
}

// Ingest runs one bounded S3 ingestion pass. Documented failure modes
// (permission denied, throttling exhaustion, partial-file failures,
// empty window) are surfaced through IngestResult.Status and
// Diagnostics rather than the error return so the API layer can serve
// a stable 200 response. A returned error means a programmer bug or
// context cancellation.
func (i *S3Ingester) Ingest(ctx context.Context, request IngestRequest) (IngestResult, error) {
	if i == nil {
		return IngestResult{}, errors.New("cloudtraildelivery: S3Ingester is nil")
	}
	if i.API == nil {
		return IngestResult{}, errors.New("cloudtraildelivery: S3 API is required")
	}
	if strings.TrimSpace(i.Bucket) == "" {
		return IngestResult{}, errors.New("cloudtraildelivery: bucket is required")
	}
	now := i.callerNow()
	request = request.withDefaults()
	result := IngestResult{Source: DeliverySourceS3, Status: "ready"}

	objects, listTruncated, listErr := i.listObjects(ctx, request, now)
	if listErr != nil {
		if errors.Is(listErr, context.Canceled) || errors.Is(listErr, context.DeadlineExceeded) {
			return IngestResult{}, listErr
		}
		if isPermissionDenied(listErr) {
			return finalizeBlocked(result, listErr, "CloudTrail S3 log listing is not authorized."), nil
		}
		result.Diagnostics = append(result.Diagnostics, cloudtrail.Diagnostic{
			SourceID:    "s3-list",
			Code:        diagnosticCodeFor(listErr),
			Message:     fmt.Sprintf("CloudTrail S3 ListObjectsV2 failed: %v", listErr),
			Remediation: "Retry CloudTrail S3 listing; partial coverage from any objects already downloaded is preserved.",
			Retryable:   isRetryable(listErr),
		})
		result.Status = "degraded"
		result.FailureReasons = append(result.FailureReasons, "CloudTrail S3 trail listing failed")
		result.RemediationHints = append(result.RemediationHints, "Confirm the connector role can s3:ListBucket on the CloudTrail bucket and retry.")
		finalizeEmptyOrTruncated(&result)
		return result, nil
	}

	// The checkpoint is an S3 key fed back through StartAfter, so keep
	// processing order key-sorted to match S3 resume semantics.
	sort.SliceStable(objects, func(a, b int) bool {
		return objects[a].Key < objects[b].Key
	})

	seen := map[string]struct{}{}
	checkpoint := strings.TrimSpace(request.Checkpoint)
	checkpointBlocked := false
	if listTruncated {
		result.HistoryTruncated = true
	}
	for idx, obj := range objects {
		result.FilesProcessed++
		if result.FilesProcessed > request.MaxFiles {
			result.HistoryTruncated = true
			break
		}
		if obj.Size > request.MaxFileBytes {
			result.Diagnostics = append(result.Diagnostics, cloudtrail.Diagnostic{
				SourceID:    obj.Key,
				Code:        "cloudtrail_s3_object_too_large",
				Message:     fmt.Sprintf("CloudTrail S3 object %q is %d bytes; exceeds MaxFileBytes=%d and was skipped.", obj.Key, obj.Size, request.MaxFileBytes),
				Remediation: "Raise the MaxFileBytes budget or split the trail's destination so each file is smaller.",
				Retryable:   false,
			})
			checkpointBlocked = true
			continue
		}
		records, recordErr := i.downloadAndParse(ctx, obj.Key, request.MaxFileBytes)
		if recordErr != nil {
			if errors.Is(recordErr, context.Canceled) || errors.Is(recordErr, context.DeadlineExceeded) {
				return IngestResult{}, recordErr
			}
			if isPermissionDenied(recordErr) {
				return finalizeBlocked(result, recordErr, "CloudTrail S3 object read is not authorized."), nil
			}
			result.Diagnostics = append(result.Diagnostics, cloudtrail.Diagnostic{
				SourceID:    obj.Key,
				Code:        diagnosticCodeFor(recordErr),
				Message:     fmt.Sprintf("CloudTrail S3 object %q failed to parse: %v", obj.Key, recordErr),
				Remediation: "Retry the failed object; events from other objects in this run are preserved.",
				Retryable:   isRetryable(recordErr),
			})
			result.Status = "degraded"
			checkpointBlocked = true
			continue
		}
		fileComplete := true
		for _, raw := range records {
			result.EventsConsidered++
			eventID := strings.TrimSpace(raw.Event.EventID)
			if eventID == "" {
				result.Diagnostics = append(result.Diagnostics, cloudtrail.Diagnostic{
					SourceID:  obj.Key,
					Code:      "cloudtrail_s3_record_missing_id",
					Message:   "CloudTrail S3 record had no eventID; skipping.",
					Retryable: false,
				})
				continue
			}
			if _, dupe := seen[eventID]; dupe {
				continue
			}
			seen[eventID] = struct{}{}
			normalized, mapDiag, ok := cloudtrail.NormalizeEvent(raw.Event, request.AccountID, request.Region, now)
			if mapDiag != nil {
				mapDiag.SourceID = eventID
				result.Diagnostics = append(result.Diagnostics, *mapDiag)
			}
			if !ok {
				continue
			}
			if !isWithinScope(request.AccountID, request.Region, raw.Record.RecipientAccount, raw.Record.AWSRegion) {
				continue
			}
			remaining := request.MaxEvents - len(result.Events)
			if remaining <= 0 {
				result.HistoryTruncated = true
				fileComplete = false
				break
			}
			if len(normalized) > remaining {
				normalized = normalized[:remaining]
				result.HistoryTruncated = true
				fileComplete = false
			}
			result.Events = append(result.Events, normalized...)
		}
		if len(result.Events) >= request.MaxEvents {
			// More files may exist past the current index → truncated.
			if idx+1 < len(objects) {
				result.HistoryTruncated = true
			}
			if !checkpointBlocked && fileComplete {
				checkpoint = obj.Key
			}
			break
		}
		if !checkpointBlocked && fileComplete {
			checkpoint = obj.Key
		}
	}
	result.Checkpoint = checkpoint
	finalizeEmptyOrTruncated(&result)
	finalizeDiagnosticDegrade(&result)
	return result, nil
}

// listObjects pulls one page worth of CloudTrail trail files. The
// caller-supplied Checkpoint is the previous run's last-processed key
// (already strictly greater than any earlier key for the same trail).
// When the checkpoint is empty the lookback window scopes the listing
// to the last LookbackWindow worth of activity.
func (i *S3Ingester) listObjects(ctx context.Context, request IngestRequest, now time.Time) ([]S3Object, bool, error) {
	startAfter := strings.TrimSpace(request.Checkpoint)
	prefix := strings.TrimSpace(i.Prefix)
	filtered := make([]S3Object, 0, request.MaxFiles)
	cutoff := now.Add(-request.LookbackWindow)
	nextToken := ""
	// maxListPages caps how many S3 list pages we fetch so an
	// unbounded prefix with many old objects doesn't cause us to
	// traverse the entire bucket. One page returns up to MaxFiles
	// keys, so MaxFiles pages is a generous upper bound.
	maxListPages := request.MaxFiles
	if maxListPages < 1 {
		maxListPages = DefaultMaxFiles
	}
	for page := 0; page < maxListPages; page++ {
		out, err := i.listWithRetry(ctx, ListObjectsV2Input{
			Bucket:            i.Bucket,
			Prefix:            prefix,
			MaxKeys:           int32(request.MaxFiles),
			StartAfter:        startAfter,
			ContinuationToken: nextToken,
		}, request)
		if err != nil {
			return nil, false, err
		}
		for _, obj := range out.Objects {
			if startAfter == "" && !obj.LastModified.IsZero() && obj.LastModified.Before(cutoff) {
				continue
			}
			filtered = append(filtered, obj)
			if len(filtered) >= request.MaxFiles {
				return filtered, out.IsTruncated || strings.TrimSpace(out.NextToken) != "", nil
			}
		}
		nextToken = strings.TrimSpace(out.NextToken)
		if !out.IsTruncated || nextToken == "" {
			break
		}
	}
	// If we exhausted the page budget without filling the file budget
	// and there are still more pages, report truncation.
	if nextToken != "" && len(filtered) < request.MaxFiles {
		return filtered, true, nil
	}
	return filtered, false, nil
}

func (i *S3Ingester) listWithRetry(ctx context.Context, input ListObjectsV2Input, request IngestRequest) (ListObjectsV2Output, error) {
	var lastErr error
	for attempt := 0; attempt <= request.MaxThrottleRetries; attempt++ {
		if err := ctx.Err(); err != nil {
			return ListObjectsV2Output{}, err
		}
		out, err := i.API.ListObjectsV2(ctx, input)
		if err == nil {
			return out, nil
		}
		lastErr = err
		if !isThrottling(err) {
			return ListObjectsV2Output{}, err
		}
		if attempt == request.MaxThrottleRetries {
			break
		}
		i.sleep(request.ThrottleBackoff * time.Duration(attempt+1))
	}
	return ListObjectsV2Output{}, lastErr
}

// s3RawRecord pairs a parsed CloudTrailRecord with the raw JSON of
// that single record. The raw JSON is fed back into the cloudtrail
// engine's NormalizeEvent so the allow-listed metadata extraction
// (sessionContext attributes etc.) sees the full payload.
type s3RawRecord struct {
	Record CloudTrailRecord
	Event  cloudtrail.Event
}

func (i *S3Ingester) downloadAndParse(ctx context.Context, key string, maxBytes int64) ([]s3RawRecord, error) {
	resp, err := i.API.GetObject(ctx, GetObjectInput{Bucket: i.Bucket, Key: key})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	gzReader, err := gzip.NewReader(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("open gzip stream for %s: %w", key, err)
	}
	defer gzReader.Close()
	payload, err := readAllLimited(gzReader, maxBytes)
	if err != nil {
		return nil, fmt.Errorf("read gzip stream for %s: %w", key, err)
	}
	return parseCloudTrailLogFile(payload)
}

func readAllLimited(reader io.Reader, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		return io.ReadAll(reader)
	}
	limited := io.LimitReader(reader, maxBytes+1)
	payload, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if int64(len(payload)) > maxBytes {
		return nil, fmt.Errorf("decompressed CloudTrail S3 object exceeds MaxFileBytes=%d", maxBytes)
	}
	return payload, nil
}

// parseCloudTrailLogFile decodes a CloudTrail S3 log file
// `{ "Records": [...] }` and returns each record alongside its raw
// per-record JSON so cloudtrail.NormalizeEvent can re-extract the
// allow-listed metadata.
func parseCloudTrailLogFile(payload []byte) ([]s3RawRecord, error) {
	var envelope struct {
		Records []json.RawMessage `json:"Records"`
	}
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return nil, fmt.Errorf("decode CloudTrail log envelope: %w", err)
	}
	out := make([]s3RawRecord, 0, len(envelope.Records))
	for _, raw := range envelope.Records {
		var record CloudTrailRecord
		if err := json.Unmarshal(raw, &record); err != nil {
			// Skip malformed records but keep the rest of the file.
			continue
		}
		out = append(out, s3RawRecord{Record: record, Event: record.toCloudTrailEvent(string(raw))})
	}
	return out, nil
}

func (i *S3Ingester) callerNow() time.Time {
	if i == nil || i.Now == nil {
		return time.Now().UTC()
	}
	return i.Now().UTC()
}

func (i *S3Ingester) sleep(d time.Duration) {
	if i == nil || i.Sleep == nil || d <= 0 {
		return
	}
	i.Sleep(d)
}

func finalizeBlocked(result IngestResult, err error, reason string) IngestResult {
	result.Status = "blocked"
	result.Events = nil
	result.HistoryTruncated = false
	result.Diagnostics = append([]cloudtrail.Diagnostic{}, cloudtrail.Diagnostic{
		SourceID:    string(result.Source),
		Code:        "permission_denied",
		Message:     fmt.Sprintf("%s: %v", reason, err),
		Remediation: "Grant the connector role metadata-only access to the CloudTrail S3 bucket or EventBridge target.",
		Retryable:   true,
	})
	result.FailureReasons = []string{reason}
	result.RemediationHints = []string{"Grant the connector role metadata-only access to the configured CloudTrail delivery channel."}
	result.CoverageGaps = []cloudtrail.CoverageGap{{
		Capability:  "cloudtrail_" + string(result.Source) + "_delivery",
		Status:      "permission_denied",
		Reason:      reason,
		Remediation: "Add the required IAM permissions and retry.",
	}}
	return result
}

func finalizeEmptyOrTruncated(result *IngestResult) {
	if result.HistoryTruncated {
		result.FailureReasons = append(result.FailureReasons, "CloudTrail delivery ingestion stopped at a bounded budget")
		result.RemediationHints = append(result.RemediationHints, "Narrow the lookback window or raise the per-run budget; partial coverage is preserved.")
		result.CoverageGaps = append(result.CoverageGaps, cloudtrail.CoverageGap{
			Capability:  "cloudtrail_" + string(result.Source) + "_delivery",
			Status:      "history_truncated",
			Reason:      "Delivery ingestion stopped at the configured MaxFiles/MaxMessages/MaxEvents budget; more records were available.",
			Remediation: "Narrow the lookback window or raise the per-run budget so the trail tail is covered.",
		})
		if result.Status == "ready" {
			result.Status = "degraded"
		}
	}
	if len(result.Events) == 0 && result.Status == "ready" {
		result.Status = "degraded"
		result.FailureReasons = append(result.FailureReasons, "no CloudTrail delivery records matched the scoped window")
		result.RemediationHints = append(result.RemediationHints, "Confirm CloudTrail trail/EventBridge delivery is enabled and the connector can read it.")
		result.CoverageGaps = append(result.CoverageGaps, cloudtrail.CoverageGap{
			Capability:  "cloudtrail_" + string(result.Source) + "_delivery",
			Status:      "empty",
			Reason:      "CloudTrail delivery returned no records in the scanned window.",
			Remediation: "Widen the lookback window or confirm the trail is actively writing.",
		})
	}
}

func finalizeDiagnosticDegrade(result *IngestResult) {
	if result.Status == "ready" && len(result.Diagnostics) > 0 {
		result.Status = "degraded"
		result.FailureReasons = append(result.FailureReasons, "CloudTrail delivery ingestion returned diagnostics")
		result.RemediationHints = append(result.RemediationHints, "Review diagnostics before treating runtime coverage as complete.")
	}
}
