package cloudtraildelivery

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"
)

type fakeS3 struct {
	objects     []S3Object
	bodyByKey   map[string][]byte
	listErr     error
	getErrByKey map[string]error
	listCalls   int
	getCalls    int
}

func (f *fakeS3) ListObjectsV2(_ context.Context, _ ListObjectsV2Input) (ListObjectsV2Output, error) {
	f.listCalls++
	if f.listErr != nil {
		return ListObjectsV2Output{}, f.listErr
	}
	return ListObjectsV2Output{Objects: f.objects}, nil
}

func (f *fakeS3) GetObject(_ context.Context, input GetObjectInput) (GetObjectOutput, error) {
	f.getCalls++
	if err, ok := f.getErrByKey[input.Key]; ok {
		return GetObjectOutput{}, err
	}
	body, ok := f.bodyByKey[input.Key]
	if !ok {
		return GetObjectOutput{}, fmt.Errorf("fake: missing body for %s", input.Key)
	}
	return GetObjectOutput{Body: io.NopCloser(bytes.NewReader(body)), ContentLength: int64(len(body))}, nil
}

type codedErr struct {
	code, msg string
}

func (e codedErr) Error() string     { return e.msg }
func (e codedErr) ErrorCode() string { return e.code }

func cloudTrailRecord(id, name, source string, eventTime time.Time, resources []map[string]string) map[string]any {
	rs := []map[string]any{}
	for _, r := range resources {
		rs = append(rs, map[string]any{"type": r["type"], "ARN": r["arn"]})
	}
	return map[string]any{
		"eventID":            id,
		"eventName":          name,
		"eventSource":        source,
		"eventTime":          eventTime.UTC().Format(time.RFC3339),
		"awsRegion":          "us-east-1",
		"recipientAccountId": "123456789012",
		"resources":          rs,
		"userIdentity": map[string]any{
			"type": "AssumedRole",
			"arn":  "arn:aws:sts::123456789012:assumed-role/identrail-runtime-reader/sess-runtime-reader",
		},
	}
}

func gzipLogFile(t *testing.T, records ...map[string]any) []byte {
	t.Helper()
	envelope := map[string]any{"Records": records}
	payload, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("encode envelope: %v", err)
	}
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(payload); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

func TestS3IngesterDownloadsAndNormalizesRecords(t *testing.T) {
	now := time.Date(2026, 6, 15, 18, 0, 0, 0, time.UTC)
	key := "AWSLogs/123456789012/CloudTrail/us-east-1/2026/06/15/123456789012_CloudTrail_us-east-1_20260615T1800Z_aaa.json.gz"
	body := gzipLogFile(t,
		cloudTrailRecord("evt-secret", "GetSecretValue", "secretsmanager.amazonaws.com", now.Add(-3*time.Minute), []map[string]string{
			{"type": "AWS::SecretsManager::Secret", "arn": "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/openai"},
		}),
		cloudTrailRecord("evt-kms", "Decrypt", "kms.amazonaws.com", now.Add(-2*time.Minute), []map[string]string{
			{"type": "AWS::KMS::Key", "arn": "arn:aws:kms:us-east-1:123456789012:key/abc"},
		}),
	)
	fake := &fakeS3{
		objects:   []S3Object{{Key: key, Size: int64(len(body)), LastModified: now.Add(-1 * time.Minute)}},
		bodyByKey: map[string][]byte{key: body},
	}
	ing := NewS3Ingester(fake, "bucket", "AWSLogs/123456789012/CloudTrail/us-east-1/")
	ing.Now = func() time.Time { return now }

	result, err := ing.Ingest(context.Background(), IngestRequest{AccountID: "123456789012", Region: "us-east-1"})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if result.Source != DeliverySourceS3 {
		t.Fatalf("expected source=s3, got %q", result.Source)
	}
	if result.Status != "ready" {
		t.Fatalf("expected status=ready, got %q (%+v)", result.Status, result)
	}
	if len(result.Events) != 2 {
		t.Fatalf("expected 2 events, got %d (%+v)", len(result.Events), result.Events)
	}
	if result.Checkpoint != key {
		t.Fatalf("expected checkpoint to advance to %q, got %q", key, result.Checkpoint)
	}
	if result.FilesProcessed != 1 {
		t.Fatalf("expected 1 file processed, got %d", result.FilesProcessed)
	}
}

func TestS3IngesterDedupesEventIDAcrossFiles(t *testing.T) {
	now := time.Date(2026, 6, 15, 18, 0, 0, 0, time.UTC)
	dupeRecord := cloudTrailRecord("evt-dupe", "AssumeRole", "sts.amazonaws.com", now.Add(-2*time.Minute), nil)
	file1 := gzipLogFile(t, dupeRecord)
	file2 := gzipLogFile(t,
		dupeRecord,
		cloudTrailRecord("evt-new", "Decrypt", "kms.amazonaws.com", now.Add(-1*time.Minute), nil),
	)
	key1, key2 := "log-1.json.gz", "log-2.json.gz"
	fake := &fakeS3{
		objects: []S3Object{
			{Key: key1, Size: int64(len(file1)), LastModified: now.Add(-3 * time.Minute)},
			{Key: key2, Size: int64(len(file2)), LastModified: now.Add(-2 * time.Minute)},
		},
		bodyByKey: map[string][]byte{key1: file1, key2: file2},
	}
	ing := NewS3Ingester(fake, "bucket", "")
	ing.Now = func() time.Time { return now }
	result, err := ing.Ingest(context.Background(), IngestRequest{AccountID: "123456789012", Region: "us-east-1"})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if len(result.Events) != 2 {
		t.Fatalf("expected 2 events after dedupe, got %d", len(result.Events))
	}
	ids := map[string]bool{}
	for _, ev := range result.Events {
		ids[ev.EventID] = true
	}
	if !ids["evt-dupe"] || !ids["evt-new"] {
		t.Fatalf("expected evt-dupe + evt-new, got %v", ids)
	}
}

func TestS3IngesterReportsPermissionDeniedAsBlocked(t *testing.T) {
	now := time.Date(2026, 6, 15, 18, 0, 0, 0, time.UTC)
	fake := &fakeS3{listErr: codedErr{code: "AccessDeniedException", msg: "User is not authorized to perform s3:ListBucket (AccessDeniedException)"}}
	ing := NewS3Ingester(fake, "bucket", "")
	ing.Now = func() time.Time { return now }
	result, err := ing.Ingest(context.Background(), IngestRequest{AccountID: "123456789012", Region: "us-east-1"})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if result.Status != "blocked" || len(result.Events) != 0 {
		t.Fatalf("expected blocked status with no records, got %+v", result)
	}
	if len(result.CoverageGaps) == 0 || result.CoverageGaps[0].Status != "permission_denied" {
		t.Fatalf("expected permission_denied coverage gap, got %+v", result.CoverageGaps)
	}
}

func TestS3IngesterEmptyWindowReportsDegradedNotBlocked(t *testing.T) {
	now := time.Date(2026, 6, 15, 18, 0, 0, 0, time.UTC)
	fake := &fakeS3{}
	ing := NewS3Ingester(fake, "bucket", "")
	ing.Now = func() time.Time { return now }
	result, err := ing.Ingest(context.Background(), IngestRequest{AccountID: "123456789012", Region: "us-east-1"})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if result.Status != "degraded" {
		t.Fatalf("expected degraded for empty window, got %q", result.Status)
	}
	if len(result.CoverageGaps) != 1 || result.CoverageGaps[0].Status != "empty" {
		t.Fatalf("expected empty coverage gap, got %+v", result.CoverageGaps)
	}
}

func TestS3IngesterRespectsMaxEventsBudgetAndMarksTruncated(t *testing.T) {
	now := time.Date(2026, 6, 15, 18, 0, 0, 0, time.UTC)
	body := gzipLogFile(t,
		cloudTrailRecord("evt-1", "AssumeRole", "sts.amazonaws.com", now.Add(-3*time.Minute), nil),
		cloudTrailRecord("evt-2", "AssumeRole", "sts.amazonaws.com", now.Add(-2*time.Minute), nil),
		cloudTrailRecord("evt-3", "AssumeRole", "sts.amazonaws.com", now.Add(-1*time.Minute), nil),
	)
	key := "log.json.gz"
	fake := &fakeS3{
		objects:   []S3Object{{Key: key, Size: int64(len(body)), LastModified: now}},
		bodyByKey: map[string][]byte{key: body},
	}
	ing := NewS3Ingester(fake, "bucket", "")
	ing.Now = func() time.Time { return now }
	result, err := ing.Ingest(context.Background(), IngestRequest{AccountID: "123456789012", Region: "us-east-1", MaxEvents: 2})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if len(result.Events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(result.Events))
	}
	if !result.HistoryTruncated {
		t.Fatalf("expected HistoryTruncated when budget caps fan-in")
	}
}

func TestS3IngesterPartialFileFailureKeepsOtherFiles(t *testing.T) {
	now := time.Date(2026, 6, 15, 18, 0, 0, 0, time.UTC)
	good := gzipLogFile(t, cloudTrailRecord("evt-good", "AssumeRole", "sts.amazonaws.com", now.Add(-1*time.Minute), nil))
	badKey, goodKey := "bad.json.gz", "good.json.gz"
	fake := &fakeS3{
		objects: []S3Object{
			{Key: badKey, Size: 32, LastModified: now.Add(-2 * time.Minute)},
			{Key: goodKey, Size: int64(len(good)), LastModified: now.Add(-1 * time.Minute)},
		},
		bodyByKey:   map[string][]byte{badKey: []byte("not a gzip"), goodKey: good},
		getErrByKey: map[string]error{},
	}
	ing := NewS3Ingester(fake, "bucket", "")
	ing.Now = func() time.Time { return now }
	result, err := ing.Ingest(context.Background(), IngestRequest{AccountID: "123456789012", Region: "us-east-1"})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if len(result.Events) != 1 || result.Events[0].EventID != "evt-good" {
		t.Fatalf("expected the good file's record preserved, got %+v", result.Events)
	}
	if result.Status != "degraded" {
		t.Fatalf("expected degraded after partial file failure, got %q", result.Status)
	}
	foundDiag := false
	for _, diag := range result.Diagnostics {
		if strings.Contains(diag.Message, "bad.json.gz") {
			foundDiag = true
		}
	}
	if !foundDiag {
		t.Fatalf("expected a diagnostic naming the failed file, got %+v", result.Diagnostics)
	}
}

func TestS3IngesterPropagatesContextCancellation(t *testing.T) {
	fake := &fakeS3{listErr: context.Canceled}
	ing := NewS3Ingester(fake, "bucket", "")
	ing.Now = func() time.Time { return time.Now().UTC() }
	if _, err := ing.Ingest(context.Background(), IngestRequest{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled propagation, got %v", err)
	}
}
