package audit

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type testRecordingAuditSink struct {
	events []AuditEvent
}

func (s *testRecordingAuditSink) Write(_ context.Context, event AuditEvent) error {
	s.events = append(s.events, event)
	return nil
}

func (*testRecordingAuditSink) Close() error { return nil }

type testErrorAuditSink struct {
	writeErr error
	closeErr error
	events   []AuditEvent
}

func (s *testErrorAuditSink) Write(_ context.Context, event AuditEvent) error {
	s.events = append(s.events, event)
	return s.writeErr
}

func (s *testErrorAuditSink) Close() error {
	return s.closeErr
}

func TestFileAuditSinkWritesJSONL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	sink, err := NewFileAuditSink(path)
	if err != nil {
		t.Fatalf("new file audit sink: %v", err)
	}
	defer sink.Close()

	event := AuditEvent{
		Timestamp: time.Now().UTC(),
		Kind:      "api_request",
		Method:    "GET",
		Path:      "/v1/scans",
		Status:    200,
	}
	if err := sink.Write(context.Background(), event); err != nil {
		t.Fatalf("write event: %v", err)
	}

	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read audit file: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(payload)), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected one line, got %d", len(lines))
	}
	var got AuditEvent
	if err := json.Unmarshal([]byte(lines[0]), &got); err != nil {
		t.Fatalf("unmarshal event: %v", err)
	}
	if got.Method != "GET" || got.Path != "/v1/scans" || got.Status != 200 {
		t.Fatalf("unexpected event: %+v", got)
	}
}

func TestFileAuditSinkConstructorError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "audit.jsonl")
	if _, err := NewFileAuditSink(path); err == nil {
		t.Fatal("expected constructor error")
	}
}

func TestHTTPAuditSinkWritesEvent(t *testing.T) {
	var gotBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		gotBody = body
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	sink, err := NewHTTPAuditSink(server.URL, 2*time.Second, "secret", 1, 10*time.Millisecond)
	if err != nil {
		t.Fatalf("new http audit sink: %v", err)
	}
	if err := sink.Write(context.Background(), AuditEvent{Method: "GET", Path: "/v1/scans", Timestamp: time.Now().UTC()}); err != nil {
		t.Fatalf("write: %v", err)
	}
	if len(gotBody) == 0 {
		t.Fatal("expected request body")
	}
}

func TestHTTPAuditSinkRejectsInsecureURL(t *testing.T) {
	if _, err := NewHTTPAuditSink("http://example.com/audit", 2*time.Second, "", 1, 10*time.Millisecond); err == nil {
		t.Fatal("expected insecure url error")
	}
}

func TestMultiAuditSinkFanout(t *testing.T) {
	record := &testRecordingAuditSink{}
	multi := NewMultiAuditSink(record, NopAuditSink{})
	if err := multi.Write(context.Background(), AuditEvent{Method: "GET", Path: "/v1/scans"}); err != nil {
		t.Fatalf("write: %v", err)
	}
	if len(record.events) != 1 {
		t.Fatalf("expected one event, got %d", len(record.events))
	}
}

func TestAsyncAuditSinkFlushesAndCloses(t *testing.T) {
	record := &testRecordingAuditSink{}
	sink := NewAsyncAuditSink(record, 2)

	if err := sink.Write(context.Background(), AuditEvent{Method: "GET", Path: "/v1/scans"}); err != nil {
		t.Fatalf("queue first event: %v", err)
	}
	if err := sink.Write(context.Background(), AuditEvent{Method: "POST", Path: "/v1/findings"}); err != nil {
		t.Fatalf("queue second event: %v", err)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("close async audit sink: %v", err)
	}
	if len(record.events) != 2 {
		t.Fatalf("expected flushed events, got %+v", record.events)
	}
	if err := sink.Write(context.Background(), AuditEvent{}); err == nil {
		t.Fatal("expected write after close to fail")
	}
}

func TestAsyncAuditSinkPropagatesWriteAndCloseErrors(t *testing.T) {
	writeErr := errors.New("write failed")
	closeErr := errors.New("close failed")
	sink := NewAsyncAuditSink(&testErrorAuditSink{writeErr: writeErr, closeErr: closeErr}, 0)

	if err := sink.Write(context.Background(), AuditEvent{Method: "GET", Path: "/v1/scans"}); err != nil {
		t.Fatalf("queue event: %v", err)
	}
	if err := sink.Close(); !errors.Is(err, writeErr) {
		t.Fatalf("expected write error precedence, got %v", err)
	}

	closeOnly := NewAsyncAuditSink(&testErrorAuditSink{closeErr: closeErr}, 1)
	if err := closeOnly.Close(); !errors.Is(err, closeErr) {
		t.Fatalf("expected close error, got %v", err)
	}
}

func TestFingerprinterIdentifierProducesHMAC(t *testing.T) {
	fp := NewFingerprinter("test-secret-key")
	result := fp.Identifier("user-123")
	if result == "" {
		t.Fatal("expected non-empty fingerprint")
	}
	if !strings.HasPrefix(result, "hmac256:") {
		t.Fatalf("expected hmac256 prefix, got %q", result)
	}
	if len(result) != len("hmac256:")+24 {
		t.Fatalf("unexpected fingerprint length: %d", len(result))
	}
}

func TestFingerprinterIdentifierIsDeterministic(t *testing.T) {
	fp := NewFingerprinter("test-secret-key")
	a := fp.Identifier("user-123")
	b := fp.Identifier("user-123")
	if a != b {
		t.Fatalf("expected deterministic output, got %q and %q", a, b)
	}
}

func TestFingerprinterDifferentKeysProduceDifferentOutput(t *testing.T) {
	fp1 := NewFingerprinter("key-one")
	fp2 := NewFingerprinter("key-two")
	result1 := fp1.Identifier("user-123")
	result2 := fp2.Identifier("user-123")
	if result1 == result2 {
		t.Fatal("different keys should produce different fingerprints")
	}
}

func TestFingerprinterEmptyInputReturnsEmpty(t *testing.T) {
	fp := NewFingerprinter("test-secret-key")
	if fp.Identifier("") != "" {
		t.Fatal("expected empty string for empty input")
	}
	if fp.Identifier("   ") != "" {
		t.Fatal("expected empty string for whitespace-only input")
	}
}

func TestFingerprinterAPIKeyMatchesIdentifier(t *testing.T) {
	fp := NewFingerprinter("test-secret-key")
	apiResult := fp.APIKey("my-api-key")
	idResult := fp.Identifier("my-api-key")
	if apiResult != idResult {
		t.Fatalf("APIKey and Identifier should produce same output for same input, got %q and %q", apiResult, idResult)
	}
}

func TestNewFingerprinterPanicsOnEmptySecret(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on empty secret")
		}
	}()
	NewFingerprinter("")
}

func TestLegacyFingerprintIdentifierStillWorks(t *testing.T) {
	result := FingerprintIdentifier("user-123")
	if result == "" {
		t.Fatal("expected non-empty legacy fingerprint")
	}
	if !strings.HasPrefix(result, "fnv64a:") {
		t.Fatalf("expected fnv64a prefix, got %q", result)
	}
}

func TestLegacyFingerprintAPIKeyStillWorks(t *testing.T) {
	result := FingerprintAPIKey("my-api-key")
	if result == "" {
		t.Fatal("expected non-empty legacy fingerprint")
	}
	if !strings.HasPrefix(result, "fnv64a:") {
		t.Fatalf("expected fnv64a prefix, got %q", result)
	}
}

func TestLegacyFingerprintIdentifierEmptyReturnsEmpty(t *testing.T) {
	if FingerprintIdentifier("") != "" {
		t.Fatal("expected empty for empty input")
	}
	if FingerprintIdentifier("   ") != "" {
		t.Fatal("expected empty for whitespace input")
	}
}

func TestNopAuditSinkClose(t *testing.T) {
	sink := NopAuditSink{}
	if err := sink.Close(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestHTTPAuditSinkClose(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	sink, err := NewHTTPAuditSink(server.URL, 2*time.Second, "", 0, 10*time.Millisecond)
	if err != nil {
		t.Fatalf("new http audit sink: %v", err)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("unexpected close error: %v", err)
	}
}

func TestMultiAuditSinkClose(t *testing.T) {
	record := &testRecordingAuditSink{}
	multi := NewMultiAuditSink(record, NopAuditSink{})
	if err := multi.Close(); err != nil {
		t.Fatalf("unexpected close error: %v", err)
	}
}

func TestHTTPAuditSinkRetryOnServerError(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts++
		if attempts < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	sink, err := NewHTTPAuditSink(server.URL, 2*time.Second, "", 3, 1*time.Millisecond)
	if err != nil {
		t.Fatalf("new http audit sink: %v", err)
	}
	if err := sink.Write(context.Background(), AuditEvent{Method: "POST", Path: "/audit"}); err != nil {
		t.Fatalf("expected success after retries: %v", err)
	}
	if attempts < 3 {
		t.Fatalf("expected at least 3 attempts, got %d", attempts)
	}
}

func TestHTTPAuditSinkNonRetryableError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()

	sink, err := NewHTTPAuditSink(server.URL, 2*time.Second, "", 3, 1*time.Millisecond)
	if err != nil {
		t.Fatalf("new http audit sink: %v", err)
	}
	if err := sink.Write(context.Background(), AuditEvent{Method: "POST"}); err == nil {
		t.Fatal("expected error for 400 response")
	}
}

func TestHTTPAuditSinkContextCancelDuringRetry(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	sink, err := NewHTTPAuditSink(server.URL, 2*time.Second, "", 5, 50*time.Millisecond)
	if err != nil {
		t.Fatalf("new http audit sink: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = sink.Write(ctx, AuditEvent{Method: "POST"})
	if err == nil {
		t.Fatal("expected error on cancelled context")
	}
}

func TestHTTPAuditSinkNilContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	sink, err := NewHTTPAuditSink(server.URL, 2*time.Second, "", 0, 10*time.Millisecond)
	if err != nil {
		t.Fatalf("new http audit sink: %v", err)
	}
	if err := sink.Write(nil, AuditEvent{Method: "GET"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestHTTPAuditSinkWithHMACSignature(t *testing.T) {
	var gotSignature string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSignature = r.Header.Get("X-Identrail-Signature")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	sink, err := NewHTTPAuditSink(server.URL, 2*time.Second, "my-secret", 0, 10*time.Millisecond)
	if err != nil {
		t.Fatalf("new http audit sink: %v", err)
	}
	if err := sink.Write(context.Background(), AuditEvent{Method: "GET"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotSignature == "" {
		t.Fatal("expected HMAC signature header")
	}
}

func TestHTTPAuditSinkEmptyURL(t *testing.T) {
	if _, err := NewHTTPAuditSink("", 2*time.Second, "", 0, 10*time.Millisecond); err == nil {
		t.Fatal("expected error for empty URL")
	}
}

func TestHTTPAuditSinkDefaultTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	sink, err := NewHTTPAuditSink(server.URL, 0, "", 0, 0)
	if err != nil {
		t.Fatalf("new http audit sink: %v", err)
	}
	if err := sink.Write(context.Background(), AuditEvent{Method: "GET"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateAuditForwardURLVariousSchemes(t *testing.T) {
	tests := []struct {
		url     string
		wantErr bool
	}{
		{"https://example.com/audit", false},
		{"http://localhost/audit", false},
		{"http://127.0.0.1/audit", false},
		{"http://[::1]/audit", false},
		{"http://example.com/audit", true},
		{"ftp://example.com/audit", true},
	}
	for _, tt := range tests {
		err := validateAuditForwardURL(tt.url)
		if (err != nil) != tt.wantErr {
			t.Errorf("validateAuditForwardURL(%q) error=%v, wantErr=%v", tt.url, err, tt.wantErr)
		}
	}
}

func TestBackoffDuration(t *testing.T) {
	base := 100 * time.Millisecond
	if got := backoffDuration(base, 0); got != base {
		t.Fatalf("expected %v for attempt 0, got %v", base, got)
	}
	if got := backoffDuration(base, 1); got != 200*time.Millisecond {
		t.Fatalf("expected 200ms for attempt 1, got %v", got)
	}
	if got := backoffDuration(base, 2); got != 400*time.Millisecond {
		t.Fatalf("expected 400ms for attempt 2, got %v", got)
	}
	if got := backoffDuration(base, 20); got != 10*time.Second {
		t.Fatalf("expected cap at 10s, got %v", got)
	}
}

func TestWaitForRetryCompletes(t *testing.T) {
	err := waitForRetry(context.Background(), 1*time.Millisecond)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestWaitForRetryCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := waitForRetry(ctx, 1*time.Hour)
	if err == nil {
		t.Fatal("expected error on cancelled context")
	}
}
