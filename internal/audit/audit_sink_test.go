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
