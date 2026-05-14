package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
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

func useTestKubernetesProbe(t *testing.T, probe kubernetesProbe) {
	t.Helper()
	previous := collectKubernetesProbe
	collectKubernetesProbe = func(context.Context) kubernetesProbe {
		return probe
	}
	t.Cleanup(func() {
		collectKubernetesProbe = previous
	})
}

func healthyTestKubernetesProbe() kubernetesProbe {
	return kubernetesProbe{
		Cluster:    "prod-cluster",
		Server:     "https://kubernetes.default.svc",
		GitVersion: "v1.30.4",
		Platform:   "linux/amd64",
		PermissionChecks: []agentPermissionCheck{{
			Verb:     "list",
			Resource: "pods",
			Scope:    "cluster",
			Allowed:  true,
		}},
	}
}

func useTestServiceAccountFiles(t *testing.T, token string, caPEM []byte) {
	t.Helper()
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token")
	caPath := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(tokenPath, []byte(token), 0o600); err != nil {
		t.Fatalf("write service account token: %v", err)
	}
	if err := os.WriteFile(caPath, caPEM, 0o600); err != nil {
		t.Fatalf("write service account CA: %v", err)
	}
	previousTokenPath := kubernetesServiceAccountTokenPath
	previousCAPath := kubernetesServiceAccountCAPath
	kubernetesServiceAccountTokenPath = tokenPath
	kubernetesServiceAccountCAPath = caPath
	t.Cleanup(func() {
		kubernetesServiceAccountTokenPath = previousTokenPath
		kubernetesServiceAccountCAPath = previousCAPath
	})
}

func useTestKubernetesService(t *testing.T, rawURL string) {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse Kubernetes service URL: %v", err)
	}
	t.Setenv("KUBERNETES_SERVICE_HOST", parsed.Hostname())
	t.Setenv("KUBERNETES_SERVICE_PORT", parsed.Port())
}

func useTestKubernetesServiceHostPort(t *testing.T, host string, port string) {
	t.Helper()
	t.Setenv("KUBERNETES_SERVICE_HOST", host)
	t.Setenv("KUBERNETES_SERVICE_PORT", port)
}

func testKubernetesServerCA(t *testing.T, server *httptest.Server) []byte {
	t.Helper()
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
}

func TestDiscoverInClusterKubernetesReportsHealthyProbe(t *testing.T) {
	allowedPaths := map[string]bool{
		"/api/v1/serviceaccounts":                                true,
		"/apis/rbac.authorization.k8s.io/v1/rolebindings":        true,
		"/apis/rbac.authorization.k8s.io/v1/clusterrolebindings": true,
		"/apis/rbac.authorization.k8s.io/v1/roles":               true,
		"/apis/rbac.authorization.k8s.io/v1/clusterroles":        true,
		"/api/v1/pods": true,
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer service-token" {
			t.Fatalf("authorization = %q", got)
		}
		switch {
		case r.URL.Path == "/version":
			_, _ = w.Write([]byte(`{"gitVersion":"v1.30.4","platform":"linux/amd64"}`))
		case allowedPaths[r.URL.Path] && r.URL.Query().Get("limit") == "1":
			_, _ = w.Write([]byte(`{"items":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	useTestKubernetesService(t, server.URL)
	useTestServiceAccountFiles(t, "service-token", testKubernetesServerCA(t, server))
	t.Setenv("IDENTRAIL_K8S_CLUSTER_NAME", "prod-cluster")

	probe := discoverInClusterKubernetes(context.Background())
	if probe.Cluster != "prod-cluster" || probe.Server == "" || probe.GitVersion != "v1.30.4" || probe.Platform != "linux/amd64" {
		t.Fatalf("unexpected probe identity: %+v", probe)
	}
	if len(probe.Diagnostics) != 0 {
		t.Fatalf("expected no diagnostics, got %+v", probe.Diagnostics)
	}
	if len(probe.PermissionChecks) != len(allowedPaths) {
		t.Fatalf("permission checks = %d, want %d", len(probe.PermissionChecks), len(allowedPaths))
	}
	for _, check := range probe.PermissionChecks {
		if !check.Allowed {
			t.Fatalf("expected %s to be allowed: %+v", check.Resource, check)
		}
	}
}

func TestDiscoverInClusterKubernetesReportsRBACDenial(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/version" {
			_, _ = w.Write([]byte(`{"gitVersion":"v1.30.4"}`))
			return
		}
		if r.URL.Path == "/api/v1/pods" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		_, _ = w.Write([]byte(`{"items":[]}`))
	}))
	defer server.Close()

	useTestKubernetesService(t, server.URL)
	useTestServiceAccountFiles(t, "service-token", testKubernetesServerCA(t, server))

	probe := discoverInClusterKubernetes(context.Background())
	var podsCheck agentPermissionCheck
	for _, check := range probe.PermissionChecks {
		if check.Resource == "pods" {
			podsCheck = check
			break
		}
	}
	if podsCheck.Allowed || !strings.Contains(podsCheck.Diagnostic, "HTTP 403") {
		t.Fatalf("expected pods denial diagnostic, got %+v", podsCheck)
	}
}

func TestDiscoverInClusterKubernetesRequiresClusterEnvironment(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	t.Setenv("KUBERNETES_SERVICE_PORT", "")

	probe := discoverInClusterKubernetes(context.Background())
	if len(probe.Diagnostics) != 1 || probe.Diagnostics[0].Code != "kubernetes_agent_not_in_cluster" {
		t.Fatalf("expected not-in-cluster diagnostic, got %+v", probe.Diagnostics)
	}
}

func TestKubernetesAPIBaseURLBracketsIPv6Hosts(t *testing.T) {
	if got := kubernetesAPIBaseURL("fd00::1", "443"); got != "https://[fd00::1]:443" {
		t.Fatalf("kubernetesAPIBaseURL() = %q", got)
	}
	if got := kubernetesAPIBaseURL("10.0.0.1", "443"); got != "https://10.0.0.1:443" {
		t.Fatalf("kubernetesAPIBaseURL() IPv4 = %q", got)
	}
}

func TestDiscoverInClusterKubernetesUsesBracketedIPv6ServerOnTokenError(t *testing.T) {
	useTestKubernetesServiceHostPort(t, "fd00::1", "443")
	previousTokenPath := kubernetesServiceAccountTokenPath
	kubernetesServiceAccountTokenPath = filepath.Join(t.TempDir(), "missing-token")
	t.Cleanup(func() {
		kubernetesServiceAccountTokenPath = previousTokenPath
	})

	probe := discoverInClusterKubernetes(context.Background())
	if probe.Server != "https://[fd00::1]:443" {
		t.Fatalf("server = %q", probe.Server)
	}
}

func TestPersistKubernetesAgentTokenPatchesConfiguredSecret(t *testing.T) {
	var patchedToken string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch {
			t.Fatalf("method = %s, want PATCH", r.Method)
		}
		if r.URL.Path != "/api/v1/namespaces/identrail/secrets/identrail-agent-enrollment" {
			t.Fatalf("unexpected secret path: %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer service-token" {
			t.Fatalf("authorization = %q", got)
		}
		if got := r.Header.Get("Content-Type"); got != "application/merge-patch+json" {
			t.Fatalf("content-type = %q", got)
		}
		var payload struct {
			Data map[string]string `json:"data"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode patch: %v", err)
		}
		decoded, err := base64.StdEncoding.DecodeString(payload.Data["agent-token"])
		if err != nil {
			t.Fatalf("decode token: %v", err)
		}
		patchedToken = string(decoded)
		_, _ = w.Write([]byte(`{"kind":"Secret"}`))
	}))
	defer server.Close()

	useTestKubernetesService(t, server.URL)
	useTestServiceAccountFiles(t, "service-token", testKubernetesServerCA(t, server))
	t.Setenv("IDENTRAIL_AGENT_NAMESPACE", "identrail")
	t.Setenv("IDENTRAIL_AGENT_TOKEN_SECRET_NAME", "identrail-agent-enrollment")
	t.Setenv("IDENTRAIL_AGENT_TOKEN_SECRET_KEY", "agent-token")

	if err := persistKubernetesAgentToken(context.Background(), "issued-agent-token"); err != nil {
		t.Fatalf("persistKubernetesAgentToken(): %v", err)
	}
	if patchedToken != "issued-agent-token" {
		t.Fatalf("patched token = %q", patchedToken)
	}
}

func TestPersistKubernetesAgentTokenSkipsWhenSecretConfigMissing(t *testing.T) {
	if err := persistKubernetesAgentToken(context.Background(), "issued-agent-token"); err != nil {
		t.Fatalf("persistKubernetesAgentToken() with no secret config: %v", err)
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
	useTestKubernetesProbe(t, healthyTestKubernetesProbe())
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
		if payload.Cluster != "prod-cluster" || payload.Server == "" || len(payload.PermissionChecks) == 0 {
			t.Fatalf("expected heartbeat to include Kubernetes probe proof, got %+v", payload)
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
	useTestKubernetesProbe(t, healthyTestKubernetesProbe())
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
			if payload.Cluster != "prod-cluster" || payload.Server == "" || len(payload.PermissionChecks) == 0 {
				t.Fatalf("expected enrollment to include Kubernetes probe proof, got %+v", payload)
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

func TestRunAgentPrefersFreshEnrollmentOverPersistedAgentToken(t *testing.T) {
	useTestKubernetesProbe(t, healthyTestKubernetesProbe())
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		switch r.URL.Path {
		case "/v1/connectors/k8s/enroll":
			var payload enrollRequest
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatalf("decode enrollment: %v", err)
			}
			if payload.EnrollmentToken != "fresh-enrollment-token" {
				t.Fatalf("enrollment token = %q", payload.EnrollmentToken)
			}
			_, _ = w.Write([]byte(`{"connector_id":"connector-2","agent_id":"agent-2","agent_token":"fresh-agent-token","heartbeat_url":"/v1/connectors/k8s/heartbeat"}`))
		case "/v1/connectors/k8s/heartbeat":
			if got := r.Header.Get("Authorization"); got != "Bearer fresh-agent-token" {
				t.Fatalf("authorization = %q, want fresh agent token", got)
			}
			_, _ = w.Write([]byte(`{"ok":true}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	err := runAgent(context.Background(), server.Client(), server.URL, "fresh-enrollment-token", "stale-agent-token", "connector-1", "agent-1", true, time.Second)
	if err != nil {
		t.Fatalf("runAgent(): %v", err)
	}
	if got := strings.Join(paths, ","); got != "/v1/connectors/k8s/enroll,/v1/connectors/k8s/heartbeat" {
		t.Fatalf("paths = %s", got)
	}
}

func TestRunAgentFallsBackToPersistedAgentTokenWhenEnrollmentAlreadyUsed(t *testing.T) {
	useTestKubernetesProbe(t, healthyTestKubernetesProbe())
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		switch r.URL.Path {
		case "/v1/connectors/k8s/enroll":
			http.Error(w, "kubernetes enrollment token is no longer usable", http.StatusGone)
		case "/v1/connectors/k8s/heartbeat":
			if got := r.Header.Get("Authorization"); got != "Bearer persisted-agent-token" {
				t.Fatalf("authorization = %q, want persisted agent token", got)
			}
			_, _ = w.Write([]byte(`{"ok":true}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	err := runAgent(context.Background(), server.Client(), server.URL, "already-used-enrollment-token", "persisted-agent-token", "connector-1", "agent-1", true, time.Second)
	if err != nil {
		t.Fatalf("runAgent(): %v", err)
	}
	if got := strings.Join(paths, ","); got != "/v1/connectors/k8s/enroll,/v1/connectors/k8s/heartbeat" {
		t.Fatalf("paths = %s", got)
	}
}

func TestRunAgentRetriesEnrollmentAfterStartupFailure(t *testing.T) {
	useTestKubernetesProbe(t, healthyTestKubernetesProbe())
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

func TestRunAgentReturnsOneShotFailure(t *testing.T) {
	useTestKubernetesProbe(t, healthyTestKubernetesProbe())
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/connectors/k8s/heartbeat" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		http.Error(w, "heartbeat rejected", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	err := runAgent(context.Background(), server.Client(), server.URL, "", "agent-token", "connector-1", "agent-1", true, time.Second)
	if err == nil {
		t.Fatal("expected one-shot heartbeat failure to be returned")
	}
	if !strings.Contains(err.Error(), "send kubernetes agent heartbeat") || !strings.Contains(err.Error(), "heartbeat rejected") {
		t.Fatalf("unexpected error: %v", err)
	}
}
