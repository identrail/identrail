package workflow

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/domain"
)

func sampleEvent(kind EventKind) Event {
	return Event{
		Kind: kind,
		Finding: domain.Finding{
			ID:           "finding-42",
			Type:         domain.FindingOverPrivileged,
			Severity:     domain.SeverityHigh,
			Title:        "Overprivileged role: WorkerRole",
			HumanSummary: "This role grants wildcard actions.",
		},
		Actor:     "alice@example.com",
		EmittedAt: time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC),
	}
}

type recordingDestination struct {
	name    string
	calls   int
	lastCtx context.Context
	lastEv  Event
	err     error
}

func (r *recordingDestination) Name() string { return r.name }
func (r *recordingDestination) Send(ctx context.Context, event Event) error {
	r.calls++
	r.lastCtx = ctx
	r.lastEv = event
	return r.err
}

// ---------- Event / AlertPolicy ----------

func TestEvent_Validate(t *testing.T) {
	if err := sampleEvent(EventFindingCreated).Validate(); err != nil {
		t.Errorf("valid event rejected: %v", err)
	}
	if err := (Event{Kind: EventFindingCreated}).Validate(); err == nil {
		t.Error("expected error for missing finding id")
	}
	if err := (Event{Finding: domain.Finding{ID: "x"}}).Validate(); err == nil {
		t.Error("expected error for missing kind")
	}
}

func TestAlertPolicy_FiltersBySeverityKindAndType(t *testing.T) {
	base := sampleEvent(EventFindingCreated)
	cases := []struct {
		name   string
		policy AlertPolicy
		event  Event
		want   bool
	}{
		{"empty_policy_allows", AlertPolicy{}, base, true},
		{"severity_floor_high_allows_high", AlertPolicy{MinSeverity: domain.SeverityHigh}, base, true},
		{"severity_floor_critical_blocks_high", AlertPolicy{MinSeverity: domain.SeverityCritical}, base, false},
		{"kind_allowlist_blocks_others", AlertPolicy{AllowKinds: []EventKind{EventFindingResolved}}, base, false},
		{"kind_allowlist_matches", AlertPolicy{AllowKinds: []EventKind{EventFindingCreated}}, base, true},
		{"type_allowlist_blocks_others", AlertPolicy{AllowTypes: []domain.FindingType{domain.FindingStaleIdentity}}, base, false},
		{"type_allowlist_matches", AlertPolicy{AllowTypes: []domain.FindingType{domain.FindingOverPrivileged}}, base, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.policy.Allow(tc.event); got != tc.want {
				t.Errorf("Allow: want %v, got %v", tc.want, got)
			}
		})
	}
}

// ---------- Router ----------

func TestRouter_DispatchFansOutByPolicy(t *testing.T) {
	slackDest := &recordingDestination{name: "slack"}
	jiraDest := &recordingDestination{name: "jira"}
	auditBuf := &bytes.Buffer{}
	router := Router{
		Destinations: []RoutedDestination{
			{Destination: slackDest, Policy: AlertPolicy{}},
			{Destination: jiraDest, Policy: AlertPolicy{MinSeverity: domain.SeverityCritical}},
		},
		Audit: &JSONLineAuditSink{Writer: auditBuf},
		Now:   func() time.Time { return time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC) },
	}

	records, err := router.Dispatch(context.Background(), sampleEvent(EventFindingCreated))
	if err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	if slackDest.calls != 1 {
		t.Errorf("slack calls: want 1, got %d", slackDest.calls)
	}
	if jiraDest.calls != 0 {
		t.Errorf("jira should be filtered out by severity floor, got %d calls", jiraDest.calls)
	}
	if len(records) != 1 {
		t.Fatalf("records: want 1, got %d", len(records))
	}
	if !records[0].Success || records[0].Destination != "slack" {
		t.Errorf("unexpected record: %+v", records[0])
	}

	// Audit sink should have one line for the slack dispatch.
	lines := strings.Split(strings.TrimSpace(auditBuf.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("audit lines: want 1, got %d (%q)", len(lines), auditBuf.String())
	}
	var rec DispatchRecord
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
		t.Fatalf("decode audit line: %v", err)
	}
	if rec.Destination != "slack" || !rec.Success {
		t.Errorf("unexpected audit record: %+v", rec)
	}
}

func TestRouter_DispatchRecordsFailureButContinues(t *testing.T) {
	failing := &recordingDestination{name: "slack", err: errors.New("network down")}
	ok := &recordingDestination{name: "jira"}
	router := Router{
		Destinations: []RoutedDestination{
			{Destination: failing, Policy: AlertPolicy{}},
			{Destination: ok, Policy: AlertPolicy{}},
		},
	}
	records, err := router.Dispatch(context.Background(), sampleEvent(EventFindingResolved))
	if err == nil {
		t.Fatal("expected wrapped error from first failure")
	}
	if !strings.Contains(err.Error(), "slack") || !strings.Contains(err.Error(), "network down") {
		t.Errorf("expected slack failure in error, got: %v", err)
	}
	if ok.calls != 1 {
		t.Errorf("second destination should still receive event, got %d calls", ok.calls)
	}
	if len(records) != 2 {
		t.Fatalf("records: want 2, got %d", len(records))
	}
	if records[0].Success {
		t.Errorf("first record should be failure")
	}
	if records[0].Error == "" {
		t.Errorf("first record missing error message")
	}
	if !records[1].Success {
		t.Errorf("second record should be success")
	}
}

func TestRouter_RejectsInvalidEvent(t *testing.T) {
	router := Router{}
	_, err := router.Dispatch(context.Background(), Event{})
	if err == nil {
		t.Error("expected error for invalid event")
	}
}

func TestRouter_SkipsNilDestinationsAndSurfacesMisconfig(t *testing.T) {
	ok := &recordingDestination{name: "slack"}
	router := Router{
		Destinations: []RoutedDestination{
			{Destination: nil, Policy: AlertPolicy{}},
			{Destination: ok, Policy: AlertPolicy{}},
		},
	}
	records, err := router.Dispatch(context.Background(), sampleEvent(EventFindingCreated))
	if err == nil {
		t.Fatal("expected error for nil destination")
	}
	if ok.calls != 1 {
		t.Errorf("subsequent valid destination should still be reached, got %d calls", ok.calls)
	}
	if len(records) != 2 {
		t.Fatalf("expected 2 records (nil + valid), got %d", len(records))
	}
	if records[0].Success {
		t.Errorf("nil destination record should be failure")
	}
	if !strings.Contains(records[0].Error, "nil destination") {
		t.Errorf("expected nil destination error message, got: %q", records[0].Error)
	}
}

type failingAuditSink struct {
	err error
}

func (f failingAuditSink) Record(context.Context, DispatchRecord) error { return f.err }

func TestRouter_SurfacesAuditSinkFailure(t *testing.T) {
	ok := &recordingDestination{name: "slack"}
	router := Router{
		Destinations: []RoutedDestination{
			{Destination: ok, Policy: AlertPolicy{}},
		},
		Audit: failingAuditSink{err: errors.New("disk full")},
	}
	_, err := router.Dispatch(context.Background(), sampleEvent(EventFindingCreated))
	if err == nil {
		t.Fatal("expected dispatch error when audit sink fails")
	}
	if !strings.Contains(err.Error(), "audit sink") || !strings.Contains(err.Error(), "disk full") {
		t.Errorf("expected wrapped audit-sink error, got: %v", err)
	}
	if ok.calls != 1 {
		t.Errorf("destination should still receive event even if audit fails, got %d calls", ok.calls)
	}
}

func TestRouter_DestinationErrorTakesPrecedenceOverAuditError(t *testing.T) {
	failing := &recordingDestination{name: "slack", err: errors.New("network down")}
	router := Router{
		Destinations: []RoutedDestination{
			{Destination: failing, Policy: AlertPolicy{}},
		},
		Audit: failingAuditSink{err: errors.New("audit failed too")},
	}
	_, err := router.Dispatch(context.Background(), sampleEvent(EventFindingCreated))
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "network down") {
		t.Errorf("expected destination error to be returned first, got: %v", err)
	}
}

func TestAlertPolicy_UnknownSeverityFailsClosed(t *testing.T) {
	policy := AlertPolicy{MinSeverity: domain.FindingSeverity("not-a-real-severity")}
	if policy.Allow(sampleEvent(EventFindingCreated)) {
		t.Error("policy with unknown MinSeverity should reject all events")
	}
}

func TestAlertPolicy_Validate(t *testing.T) {
	if err := (AlertPolicy{}).Validate(); err != nil {
		t.Errorf("empty policy should validate, got: %v", err)
	}
	if err := (AlertPolicy{MinSeverity: domain.SeverityHigh}).Validate(); err != nil {
		t.Errorf("valid severity should validate, got: %v", err)
	}
	if err := (AlertPolicy{MinSeverity: "bogus"}).Validate(); err == nil {
		t.Error("expected validation error for unrecognized severity")
	}
}

func TestLinearDestination_Send_TrimsAPIKeyWhitespace(t *testing.T) {
	srv, captured := captureTLSRequest(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"issueCreate":{"success":true,"issue":{"id":"i1","identifier":"OPS-1","url":"https://linear.app/x"}}}}`))
	})
	dest := LinearDestination{APIURL: srv.URL, APIKey: "  lin_xxx  \n", TeamID: "team-1", HTTPClient: srv.Client()}
	if err := dest.Send(context.Background(), sampleEvent(EventFindingCreated)); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if got := captured.Headers.Get("Authorization"); got != "lin_xxx" {
		t.Errorf("authorization header should be trimmed: %q", got)
	}
}

// ---------- Audit ----------

func TestJSONLineAuditSink_ConcurrentWritesAreLineSafe(t *testing.T) {
	buf := &bytes.Buffer{}
	sink := &JSONLineAuditSink{Writer: buf}
	var wg sync.WaitGroup
	for i := 0; i < 25; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_ = sink.Record(context.Background(), DispatchRecord{
				EventKind:   EventFindingCreated,
				FindingID:   "f",
				Destination: "slack",
				Success:     true,
				AttemptedAt: time.Unix(int64(i), 0).UTC(),
			})
		}(i)
	}
	wg.Wait()
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 25 {
		t.Fatalf("expected 25 audit lines, got %d", len(lines))
	}
	for i, l := range lines {
		var rec DispatchRecord
		if err := json.Unmarshal([]byte(l), &rec); err != nil {
			t.Errorf("line %d not valid JSON: %v", i, err)
		}
	}
}

func TestJSONLineAuditSink_NilWriterReturnsError(t *testing.T) {
	sink := &JSONLineAuditSink{}
	if err := sink.Record(context.Background(), DispatchRecord{}); err == nil {
		t.Error("expected error for nil writer")
	}
}

// ---------- Slack ----------

func captureRequest(t *testing.T, handler func(w http.ResponseWriter, r *http.Request)) (*httptest.Server, *recordedHTTPRequest) {
	t.Helper()
	var captured recordedHTTPRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured.Method = r.Method
		captured.Path = r.URL.Path
		captured.Headers = r.Header.Clone()
		captured.Body, _ = io.ReadAll(r.Body)
		_ = r.Body.Close()
		handler(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv, &captured
}

type recordedHTTPRequest struct {
	Method  string
	Path    string
	Headers http.Header
	Body    []byte
}

func captureTLSRequest(t *testing.T, handler func(w http.ResponseWriter, r *http.Request)) (*httptest.Server, *recordedHTTPRequest) {
	t.Helper()
	var captured recordedHTTPRequest
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured.Method = r.Method
		captured.Path = r.URL.Path
		captured.Headers = r.Header.Clone()
		captured.Body, _ = io.ReadAll(r.Body)
		_ = r.Body.Close()
		handler(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv, &captured
}

func TestSlackDestination_Send_HappyPath(t *testing.T) {
	srv, captured := captureTLSRequest(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	dest := SlackDestination{WebhookURL: srv.URL, HTTPClient: srv.Client()}
	if err := dest.Send(context.Background(), sampleEvent(EventFindingCreated)); err != nil {
		t.Fatalf("Send: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(captured.Body, &payload); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	text, _ := payload["text"].(string)
	if !strings.Contains(text, "finding.created") {
		t.Errorf("expected event kind in slack text, got %q", text)
	}
	if _, ok := payload["blocks"]; !ok {
		t.Error("expected blocks field in slack payload")
	}
	if captured.Headers.Get("Content-Type") != "application/json" {
		t.Errorf("missing/wrong content-type: %s", captured.Headers.Get("Content-Type"))
	}
}

func TestSlackDestination_Send_ErrorsOn5xx(t *testing.T) {
	srv, _ := captureTLSRequest(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	dest := SlackDestination{WebhookURL: srv.URL, HTTPClient: srv.Client()}
	err := dest.Send(context.Background(), sampleEvent(EventFindingCreated))
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Errorf("expected 500 error, got: %v", err)
	}
}

func TestSlackDestination_Send_RejectsEmptyURL(t *testing.T) {
	dest := SlackDestination{}
	err := dest.Send(context.Background(), sampleEvent(EventFindingCreated))
	if err == nil {
		t.Error("expected error for empty webhook URL")
	}
}

func TestSlackDestination_Send_RejectsHTTPWebhookURL(t *testing.T) {
	dest := SlackDestination{WebhookURL: "http://hooks.slack.example.com/services/T/B/secret"}
	err := dest.Send(context.Background(), sampleEvent(EventFindingCreated))
	if err == nil {
		t.Fatal("expected http:// webhook URL to be rejected")
	}
	if !strings.Contains(err.Error(), "https") {
		t.Errorf("expected https requirement in error, got: %v", err)
	}
}

// ---------- Jira ----------

func TestJiraDestination_Send_HappyPath(t *testing.T) {
	srv, captured := captureTLSRequest(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"10001","key":"OPS-1"}`))
	})
	dest := JiraDestination{
		BaseURL:    srv.URL, // https:// from httptest.NewTLSServer
		Email:      "ops@example.com",
		APIToken:   "tok",
		ProjectKey: "OPS",
		HTTPClient: srv.Client(),
	}
	if err := dest.Send(context.Background(), sampleEvent(EventFindingCreated)); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if captured.Path != "/rest/api/3/issue" {
		t.Errorf("path: want /rest/api/3/issue, got %s", captured.Path)
	}
	auth := captured.Headers.Get("Authorization")
	if !strings.HasPrefix(auth, "Basic ") {
		t.Errorf("expected basic auth, got %q", auth)
	}
	var body struct {
		Fields struct {
			Project   map[string]string `json:"project"`
			Summary   string            `json:"summary"`
			IssueType map[string]string `json:"issuetype"`
			Labels    []string          `json:"labels"`
		} `json:"fields"`
	}
	if err := json.Unmarshal(captured.Body, &body); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if body.Fields.Project["key"] != "OPS" {
		t.Errorf("project key: want OPS, got %s", body.Fields.Project["key"])
	}
	if !strings.Contains(body.Fields.Summary, "HIGH") {
		t.Errorf("summary missing severity prefix: %s", body.Fields.Summary)
	}
	if body.Fields.IssueType["name"] != "Task" {
		t.Errorf("expected default issue type Task, got %s", body.Fields.IssueType["name"])
	}
	wantLabel := "identrail"
	found := false
	for _, l := range body.Fields.Labels {
		if l == wantLabel {
			found = true
		}
	}
	if !found {
		t.Errorf("expected identrail label, got %v", body.Fields.Labels)
	}
}

func TestJiraDestination_Send_ValidatesConfig(t *testing.T) {
	cases := []struct {
		name string
		dest JiraDestination
	}{
		{"missing_url", JiraDestination{Email: "e", APIToken: "t", ProjectKey: "P"}},
		{"missing_email", JiraDestination{BaseURL: "https://x", APIToken: "t", ProjectKey: "P"}},
		{"missing_token", JiraDestination{BaseURL: "https://x", Email: "e", ProjectKey: "P"}},
		{"missing_project", JiraDestination{BaseURL: "https://x", Email: "e", APIToken: "t"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.dest.Send(context.Background(), sampleEvent(EventFindingCreated))
			if err == nil {
				t.Error("expected error")
			}
		})
	}
}

func TestJiraDestination_Send_RejectsHTTPBaseURL(t *testing.T) {
	dest := JiraDestination{
		BaseURL:    "http://acme.atlassian.net",
		Email:      "ops@example.com",
		APIToken:   "tok",
		ProjectKey: "OPS",
	}
	err := dest.Send(context.Background(), sampleEvent(EventFindingCreated))
	if err == nil {
		t.Fatal("expected http:// base URL to be rejected")
	}
	if !strings.Contains(err.Error(), "https") {
		t.Errorf("expected https requirement in error, got: %v", err)
	}
}

// ---------- Linear ----------

func TestLinearDestination_Send_HappyPath(t *testing.T) {
	srv, captured := captureTLSRequest(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"issueCreate":{"success":true,"issue":{"id":"i1","identifier":"OPS-1","url":"https://linear.app/x"}}}}`))
	})
	dest := LinearDestination{APIURL: srv.URL, APIKey: "lin_xxx", TeamID: "team-1", HTTPClient: srv.Client()}
	if err := dest.Send(context.Background(), sampleEvent(EventFindingCreated)); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if captured.Headers.Get("Authorization") != "lin_xxx" {
		t.Errorf("authorization header: %q", captured.Headers.Get("Authorization"))
	}
	var body struct {
		Query     string         `json:"query"`
		Variables map[string]any `json:"variables"`
	}
	if err := json.Unmarshal(captured.Body, &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !strings.Contains(body.Query, "issueCreate") {
		t.Errorf("query does not include issueCreate: %s", body.Query)
	}
	input, _ := body.Variables["input"].(map[string]any)
	if input["teamId"] != "team-1" {
		t.Errorf("teamId: want team-1, got %v", input["teamId"])
	}
}

func TestLinearDestination_Send_PropagatesGraphQLErrors(t *testing.T) {
	srv, _ := captureTLSRequest(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"errors":[{"message":"unauthenticated"}]}`))
	})
	dest := LinearDestination{APIURL: srv.URL, APIKey: "lin", TeamID: "t", HTTPClient: srv.Client()}
	err := dest.Send(context.Background(), sampleEvent(EventFindingCreated))
	if err == nil || !strings.Contains(err.Error(), "unauthenticated") {
		t.Errorf("expected graphql error propagated, got: %v", err)
	}
}

func TestLinearDestination_Send_ErrorsOnSuccessFalse(t *testing.T) {
	srv, _ := captureTLSRequest(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"issueCreate":{"success":false}}}`))
	})
	dest := LinearDestination{APIURL: srv.URL, APIKey: "k", TeamID: "t", HTTPClient: srv.Client()}
	err := dest.Send(context.Background(), sampleEvent(EventFindingCreated))
	if err == nil || !strings.Contains(err.Error(), "success=false") {
		t.Errorf("expected success=false error, got: %v", err)
	}
}

func TestLinearDestination_Send_ValidatesConfig(t *testing.T) {
	if err := (LinearDestination{TeamID: "t"}).Send(context.Background(), sampleEvent(EventFindingCreated)); err == nil {
		t.Error("expected error for missing API key")
	}
	if err := (LinearDestination{APIKey: "k"}).Send(context.Background(), sampleEvent(EventFindingCreated)); err == nil {
		t.Error("expected error for missing team id")
	}
}

func TestLinearDestination_Send_RejectsHTTPAPIURL(t *testing.T) {
	dest := LinearDestination{
		APIURL: "http://api.linear.app/graphql",
		APIKey: "lin",
		TeamID: "t",
	}
	err := dest.Send(context.Background(), sampleEvent(EventFindingCreated))
	if err == nil {
		t.Fatal("expected http:// API URL to be rejected")
	}
	if !strings.Contains(err.Error(), "https") {
		t.Errorf("expected https requirement in error, got: %v", err)
	}
}
