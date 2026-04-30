package audit

import (
	"context"
	"encoding/json"
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
