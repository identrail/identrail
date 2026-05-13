package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestEnvHelpers(t *testing.T) {
	t.Setenv("IDENTRAIL_TEST_STRING", " value ")
	if got := env("IDENTRAIL_TEST_STRING", "fallback"); got != "value" {
		t.Fatalf("env() = %q, want value", got)
	}
	if got := env("IDENTRAIL_TEST_MISSING", "fallback"); got != "fallback" {
		t.Fatalf("env() fallback = %q", got)
	}

	t.Setenv("IDENTRAIL_TEST_DURATION", "45s")
	if got := envDuration("IDENTRAIL_TEST_DURATION", time.Second); got != 45*time.Second {
		t.Fatalf("envDuration() = %s", got)
	}
	t.Setenv("IDENTRAIL_TEST_DURATION", "not-a-duration")
	if got := envDuration("IDENTRAIL_TEST_DURATION", time.Second); got != time.Second {
		t.Fatalf("envDuration() invalid fallback = %s", got)
	}

	for _, value := range []string{"1", "true", "YES", "on"} {
		t.Setenv("IDENTRAIL_TEST_BOOL", value)
		if !envBool("IDENTRAIL_TEST_BOOL", false) {
			t.Fatalf("envBool(%q) = false, want true", value)
		}
	}
	for _, value := range []string{"0", "false", "NO", "off"} {
		t.Setenv("IDENTRAIL_TEST_BOOL", value)
		if envBool("IDENTRAIL_TEST_BOOL", true) {
			t.Fatalf("envBool(%q) = true, want false", value)
		}
	}
	t.Setenv("IDENTRAIL_TEST_BOOL", "unknown")
	if !envBool("IDENTRAIL_TEST_BOOL", true) {
		t.Fatal("envBool() should return fallback for unknown value")
	}
}

func TestPostJSONAddsHeadersAndDecodesResponse(t *testing.T) {
	var gotAuth string
	var gotPayload enrollRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s, want POST", r.Method)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Fatalf("content-type = %q", got)
		}
		gotAuth = r.Header.Get("Authorization")
		if err := json.NewDecoder(r.Body).Decode(&gotPayload); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"connector_id":"connector-1","agent_id":"agent-1","agent_token":"agent-token","heartbeat_url":"/heartbeat"}`))
	}))
	defer server.Close()

	var response enrollResponse
	err := postJSON(context.Background(), server.Client(), server.URL, " bearer-token ", enrollRequest{
		EnrollmentToken: "enroll-token",
		AgentID:         "agent-1",
	}, &response)
	if err != nil {
		t.Fatalf("postJSON(): %v", err)
	}
	if gotAuth != "Bearer bearer-token" {
		t.Fatalf("authorization = %q", gotAuth)
	}
	if gotPayload.EnrollmentToken != "enroll-token" || gotPayload.AgentID != "agent-1" {
		t.Fatalf("unexpected request payload: %+v", gotPayload)
	}
	if response.AgentToken != "agent-token" || response.ConnectorID != "connector-1" {
		t.Fatalf("unexpected response: %+v", response)
	}
}

func TestPostJSONReportsAPIErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "invalid enrollment", http.StatusUnauthorized)
	}))
	defer server.Close()

	err := heartbeat(context.Background(), server.Client(), server.URL, "agent-token", heartbeatRequest{AgentID: "agent-1"})
	if err == nil {
		t.Fatal("expected heartbeat error")
	}
	if !strings.Contains(err.Error(), "401 Unauthorized") || !strings.Contains(err.Error(), "invalid enrollment") {
		t.Fatalf("error did not include status and body: %v", err)
	}
}

func TestPostJSONHandlesEmptyAndInvalidResponses(t *testing.T) {
	emptyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer emptyServer.Close()
	if err := postJSON(context.Background(), emptyServer.Client(), emptyServer.URL, "", heartbeatRequest{}, &map[string]any{}); err != nil {
		t.Fatalf("postJSON() empty response: %v", err)
	}

	invalidServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{`))
	}))
	defer invalidServer.Close()
	err := postJSON(context.Background(), invalidServer.Client(), invalidServer.URL, "", heartbeatRequest{}, &map[string]any{})
	if err == nil || !strings.Contains(err.Error(), "decode identrail API response") {
		t.Fatalf("expected decode error, got %v", err)
	}
}

func TestEnrollAndHeartbeatUseExpectedEndpoints(t *testing.T) {
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		switch r.URL.Path {
		case "/v1/connectors/k8s/enroll":
			_, _ = w.Write([]byte(`{"connector_id":"connector-1","agent_id":"agent-1","agent_token":"agent-token","heartbeat_url":"/v1/connectors/k8s/heartbeat"}`))
		case "/v1/connectors/k8s/heartbeat":
			if got := r.Header.Get("Authorization"); got != "Bearer agent-token" {
				t.Fatalf("authorization = %q", got)
			}
			_, _ = w.Write([]byte(`{"ok":true}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	response, err := enroll(context.Background(), server.Client(), server.URL, enrollRequest{EnrollmentToken: "enroll-token"})
	if err != nil {
		t.Fatalf("enroll(): %v", err)
	}
	if response.AgentToken != "agent-token" {
		t.Fatalf("unexpected enroll response: %+v", response)
	}
	if err := heartbeat(context.Background(), server.Client(), server.URL, response.AgentToken, heartbeatRequest{AgentID: response.AgentID}); err != nil {
		t.Fatalf("heartbeat(): %v", err)
	}
	if strings.Join(paths, ",") != "/v1/connectors/k8s/enroll,/v1/connectors/k8s/heartbeat" {
		t.Fatalf("paths = %v", paths)
	}
}

func TestMainSendsOneHeartbeatWithExistingAgentToken(t *testing.T) {
	var heartbeatCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/connectors/k8s/heartbeat" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer agent-token" {
			t.Fatalf("authorization = %q", got)
		}
		var payload heartbeatRequest
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode heartbeat: %v", err)
		}
		if payload.ConnectorID != "connector-1" || payload.AgentID != "agent-1" {
			t.Fatalf("unexpected heartbeat payload: %+v", payload)
		}
		atomic.AddInt32(&heartbeatCount, 1)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	t.Setenv("IDENTRAIL_API_URL", server.URL)
	t.Setenv("IDENTRAIL_AGENT_TOKEN", "agent-token")
	t.Setenv("IDENTRAIL_CONNECTOR_ID", "connector-1")
	t.Setenv("IDENTRAIL_AGENT_ID", "agent-1")
	t.Setenv("IDENTRAIL_AGENT_ONCE", "true")

	previousArgs := os.Args
	previousFlagSet := flag.CommandLine
	os.Args = []string{previousArgs[0]}
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	flag.CommandLine.SetOutput(io.Discard)
	defer func() {
		os.Args = previousArgs
		flag.CommandLine = previousFlagSet
	}()

	main()

	if got := atomic.LoadInt32(&heartbeatCount); got != 1 {
		t.Fatalf("heartbeat count = %d, want 1", got)
	}
}

func TestMainEnrollsBeforeHeartbeat(t *testing.T) {
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		switch r.URL.Path {
		case "/v1/connectors/k8s/enroll":
			var payload enrollRequest
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatalf("decode enrollment: %v", err)
			}
			if payload.EnrollmentToken != "enrollment-token" || payload.AgentID != "agent-1" {
				t.Fatalf("unexpected enrollment payload: %+v", payload)
			}
			_, _ = w.Write([]byte(`{"connector_id":"connector-1","agent_id":"agent-1","agent_token":"issued-agent-token","heartbeat_url":"/v1/connectors/k8s/heartbeat"}`))
		case "/v1/connectors/k8s/heartbeat":
			if got := r.Header.Get("Authorization"); got != "Bearer issued-agent-token" {
				t.Fatalf("authorization = %q", got)
			}
			_, _ = w.Write([]byte(`{"ok":true}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	t.Setenv("IDENTRAIL_API_URL", server.URL)
	t.Setenv("IDENTRAIL_ENROLLMENT_TOKEN", "enrollment-token")
	t.Setenv("IDENTRAIL_AGENT_ID", "agent-1")
	t.Setenv("IDENTRAIL_AGENT_ONCE", "true")
	t.Setenv("IDENTRAIL_SCAN_SECRET_VALUES", "true")

	previousArgs := os.Args
	previousFlagSet := flag.CommandLine
	os.Args = []string{previousArgs[0]}
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	flag.CommandLine.SetOutput(io.Discard)
	defer func() {
		os.Args = previousArgs
		flag.CommandLine = previousFlagSet
	}()

	main()

	if got := strings.Join(paths, ","); got != "/v1/connectors/k8s/enroll,/v1/connectors/k8s/heartbeat" {
		t.Fatalf("paths = %s", got)
	}
}

func TestRunAgentRetriesEnrollmentAfterStartupFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var enrollAttempts int32
	var heartbeatAttempts int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/connectors/k8s/enroll":
			attempt := atomic.AddInt32(&enrollAttempts, 1)
			if attempt == 1 {
				http.Error(w, "api temporarily unavailable", http.StatusServiceUnavailable)
				return
			}
			_, _ = w.Write([]byte(`{"connector_id":"connector-1","agent_id":"agent-1","agent_token":"issued-agent-token","heartbeat_url":"/v1/connectors/k8s/heartbeat"}`))
		case "/v1/connectors/k8s/heartbeat":
			attempt := atomic.AddInt32(&heartbeatAttempts, 1)
			switch r.Header.Get("Authorization") {
			case "Bearer enrollment-token":
				http.Error(w, "not enrolled yet", http.StatusUnauthorized)
			case "Bearer issued-agent-token":
				_, _ = w.Write([]byte(`{"ok":true}`))
				cancel()
			default:
				t.Fatalf("unexpected authorization header on heartbeat %d: %q", attempt, r.Header.Get("Authorization"))
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	err := runAgent(ctx, server.Client(), server.URL, "enrollment-token", "", "connector-1", "agent-1", false, time.Millisecond)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("runAgent() error = %v, want context.Canceled", err)
	}
	if got := atomic.LoadInt32(&enrollAttempts); got != 2 {
		t.Fatalf("enroll attempts = %d, want 2", got)
	}
	if got := atomic.LoadInt32(&heartbeatAttempts); got != 2 {
		t.Fatalf("heartbeat attempts = %d, want 2", got)
	}
}
