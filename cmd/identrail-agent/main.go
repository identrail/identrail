package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

var (
	kubernetesServiceAccountTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	kubernetesServiceAccountCAPath    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	kubernetesAPITimeout              = 8 * time.Second
)

type enrollRequest struct {
	EnrollmentToken  string                 `json:"enrollment_token"`
	ConnectorID      string                 `json:"connector_id,omitempty"`
	AgentID          string                 `json:"agent_id,omitempty"`
	Cluster          string                 `json:"cluster,omitempty"`
	Server           string                 `json:"server,omitempty"`
	GitVersion       string                 `json:"git_version,omitempty"`
	Platform         string                 `json:"platform,omitempty"`
	PermissionChecks []agentPermissionCheck `json:"permission_checks,omitempty"`
	Diagnostics      []agentDiagnostic      `json:"diagnostics,omitempty"`
}

type enrollResponse struct {
	ConnectorID  string `json:"connector_id"`
	AgentID      string `json:"agent_id"`
	AgentToken   string `json:"agent_token"`
	HeartbeatURL string `json:"heartbeat_url"`
}

type heartbeatRequest struct {
	ConnectorID      string                 `json:"connector_id,omitempty"`
	AgentID          string                 `json:"agent_id,omitempty"`
	Cluster          string                 `json:"cluster,omitempty"`
	Server           string                 `json:"server,omitempty"`
	GitVersion       string                 `json:"git_version,omitempty"`
	Platform         string                 `json:"platform,omitempty"`
	PermissionChecks []agentPermissionCheck `json:"permission_checks,omitempty"`
	Diagnostics      []agentDiagnostic      `json:"diagnostics,omitempty"`
}

type agentPermissionCheck struct {
	Verb        string `json:"verb"`
	Resource    string `json:"resource"`
	Scope       string `json:"scope"`
	Allowed     bool   `json:"allowed"`
	Diagnostic  string `json:"diagnostic,omitempty"`
	Remediation string `json:"remediation,omitempty"`
}

type agentDiagnostic struct {
	Code        string `json:"code"`
	Severity    string `json:"severity"`
	Message     string `json:"message"`
	Remediation string `json:"remediation,omitempty"`
}

type kubernetesProbe struct {
	Cluster          string
	Server           string
	GitVersion       string
	Platform         string
	PermissionChecks []agentPermissionCheck
	Diagnostics      []agentDiagnostic
}

var collectKubernetesProbe = discoverInClusterKubernetes

func main() {
	var apiURL string
	var enrollmentToken string
	var agentToken string
	var connectorID string
	var agentID string
	var heartbeatInterval time.Duration
	var once bool
	var scanSecretValues bool

	flag.StringVar(&apiURL, "api-url", env("IDENTRAIL_API_URL", "https://api.identrail.com"), "Identrail API base URL")
	flag.StringVar(&enrollmentToken, "enrollment-token", env("IDENTRAIL_ENROLLMENT_TOKEN", ""), "single-use enrollment token")
	flag.StringVar(&agentToken, "agent-token", env("IDENTRAIL_AGENT_TOKEN", ""), "agent bearer token returned by enrollment")
	flag.StringVar(&connectorID, "connector-id", env("IDENTRAIL_CONNECTOR_ID", ""), "Kubernetes connector ID")
	flag.StringVar(&agentID, "agent-id", env("IDENTRAIL_AGENT_ID", hostnameAgentID()), "stable agent ID")
	flag.DurationVar(&heartbeatInterval, "heartbeat-interval", envDuration("IDENTRAIL_HEARTBEAT_INTERVAL", 30*time.Second), "heartbeat interval")
	flag.BoolVar(&once, "once", envBool("IDENTRAIL_AGENT_ONCE", false), "send one heartbeat and exit")
	flag.BoolVar(&scanSecretValues, "scan-secret-values", envBool("IDENTRAIL_SCAN_SECRET_VALUES", false), "allow scanning Kubernetes Secret values")
	flag.Parse()

	if scanSecretValues {
		log.Print("secret value scanning is enabled for this agent")
	}
	ctx := context.Background()
	client := &http.Client{Timeout: 15 * time.Second}
	if err := runAgent(ctx, client, apiURL, enrollmentToken, agentToken, connectorID, agentID, once, heartbeatInterval); err != nil {
		log.Fatal(err)
	}
}

func runAgent(ctx context.Context, client *http.Client, apiURL string, enrollmentToken string, agentToken string, connectorID string, agentID string, once bool, heartbeatInterval time.Duration) error {
	apiURL = strings.TrimRight(strings.TrimSpace(apiURL), "/")
	if apiURL == "" {
		return errors.New("api-url is required")
	}

	credential := strings.TrimSpace(agentToken)
	enrollmentToken = strings.TrimSpace(enrollmentToken)
	if credential == "" && enrollmentToken == "" {
		return errors.New("enrollment-token or agent-token is required")
	}

	enrollmentAttempted := false
	for {
		var lastErr error
		usingEnrollmentRecoveryCredential := false
		if enrollmentToken != "" && !enrollmentAttempted {
			enrollmentAttempted = true
			probe := collectKubernetesProbe(ctx)
			response, err := enroll(ctx, client, apiURL, enrollRequest{
				EnrollmentToken:  enrollmentToken,
				ConnectorID:      connectorID,
				AgentID:          agentID,
				Cluster:          probe.Cluster,
				Server:           probe.Server,
				GitVersion:       probe.GitVersion,
				Platform:         probe.Platform,
				PermissionChecks: probe.PermissionChecks,
				Diagnostics:      probe.Diagnostics,
			})
			if err != nil {
				if credential == "" {
					log.Printf("enroll failed; trying enrollment credential for heartbeat recovery: %v", err)
					credential = enrollmentToken
					usingEnrollmentRecoveryCredential = true
				} else {
					log.Printf("enroll failed; using existing agent credential: %v", err)
				}
			} else {
				if err := persistKubernetesAgentToken(ctx, response.AgentToken); err != nil {
					log.Printf("persist kubernetes agent token failed; continuing with in-memory credential: %v", err)
				}
				credential = response.AgentToken
				connectorID = response.ConnectorID
				agentID = response.AgentID
				log.Printf("enrolled connector %s as %s", connectorID, agentID)
			}
		}
		if credential == "" {
			return errors.New("agent credential is required")
		}

		probe := collectKubernetesProbe(ctx)
		payload := heartbeatRequest{
			ConnectorID:      connectorID,
			AgentID:          agentID,
			Cluster:          probe.Cluster,
			Server:           probe.Server,
			GitVersion:       probe.GitVersion,
			Platform:         probe.Platform,
			PermissionChecks: probe.PermissionChecks,
			Diagnostics:      probe.Diagnostics,
		}
		if err := heartbeat(ctx, client, apiURL, credential, payload); err != nil {
			log.Printf("heartbeat failed: %v", err)
			lastErr = fmt.Errorf("send kubernetes agent heartbeat: %w", err)
			if usingEnrollmentRecoveryCredential {
				credential = ""
				enrollmentAttempted = false
			}
		} else {
			log.Printf("heartbeat sent for connector %s", connectorID)
			lastErr = nil
		}
		if once {
			return lastErr
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(heartbeatInterval):
		}
	}
}

func enroll(ctx context.Context, client *http.Client, apiURL string, payload enrollRequest) (enrollResponse, error) {
	var response enrollResponse
	if err := postJSON(ctx, client, apiURL+"/v1/connectors/k8s/enroll", "", payload, &response); err != nil {
		return enrollResponse{}, err
	}
	return response, nil
}

func heartbeat(ctx context.Context, client *http.Client, apiURL string, token string, payload heartbeatRequest) error {
	var response map[string]any
	return postJSON(ctx, client, apiURL+"/v1/connectors/k8s/heartbeat", token, payload, &response)
}

func postJSON(ctx context.Context, client *http.Client, url string, bearer string, payload any, response any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if strings.TrimSpace(bearer) != "" {
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(bearer))
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	payloadBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("identrail API returned %s: %s", resp.Status, strings.TrimSpace(string(payloadBytes)))
	}
	if len(payloadBytes) == 0 {
		return nil
	}
	if err := json.Unmarshal(payloadBytes, response); err != nil {
		return fmt.Errorf("decode identrail API response: %w", err)
	}
	return nil
}

func discoverInClusterKubernetes(ctx context.Context) kubernetesProbe {
	host := strings.TrimSpace(os.Getenv("KUBERNETES_SERVICE_HOST"))
	port := strings.TrimSpace(os.Getenv("KUBERNETES_SERVICE_PORT"))
	if host == "" || port == "" {
		return kubernetesProbe{
			Diagnostics: []agentDiagnostic{{
				Code:        "kubernetes_agent_not_in_cluster",
				Severity:    "error",
				Message:     "Kubernetes service discovery environment variables are not available.",
				Remediation: "Run identrail-agent inside the target Kubernetes cluster using the Helm chart.",
			}},
		}
	}
	if _, err := strconv.Atoi(port); err != nil {
		return kubernetesProbe{
			Diagnostics: []agentDiagnostic{{
				Code:        "kubernetes_agent_service_port_invalid",
				Severity:    "error",
				Message:     fmt.Sprintf("KUBERNETES_SERVICE_PORT is invalid: %s", port),
				Remediation: "Run identrail-agent with the standard Kubernetes service environment injected by the cluster.",
			}},
		}
	}
	baseURL := kubernetesAPIBaseURL(host, port)
	tokenBytes, err := os.ReadFile(kubernetesServiceAccountTokenPath)
	if err != nil {
		return kubernetesProbe{
			Server: baseURL,
			Diagnostics: []agentDiagnostic{{
				Code:        "kubernetes_agent_service_account_token_missing",
				Severity:    "error",
				Message:     fmt.Sprintf("read Kubernetes service account token: %v", err),
				Remediation: "Mount the Kubernetes service account token into the identrail-agent pod.",
			}},
		}
	}
	client, err := kubernetesAPIClient()
	if err != nil {
		return kubernetesProbe{
			Server: baseURL,
			Diagnostics: []agentDiagnostic{{
				Code:        "kubernetes_agent_tls_config_invalid",
				Severity:    "error",
				Message:     err.Error(),
				Remediation: "Mount the Kubernetes service account CA bundle into the identrail-agent pod.",
			}},
		}
	}

	token := strings.TrimSpace(string(tokenBytes))
	probe := kubernetesProbe{
		Cluster: strings.TrimSpace(os.Getenv("IDENTRAIL_K8S_CLUSTER_NAME")),
		Server:  baseURL,
	}
	if probe.Cluster == "" {
		probe.Cluster = host
	}

	var version struct {
		GitVersion string `json:"gitVersion"`
		Platform   string `json:"platform"`
	}
	if status, body, err := kubernetesGetJSON(ctx, client, baseURL+"/version", token, &version); err != nil {
		probe.Diagnostics = append(probe.Diagnostics, agentDiagnostic{
			Code:        "kubernetes_agent_version_unavailable",
			Severity:    "warning",
			Message:     fmt.Sprintf("read Kubernetes server version: %v", err),
			Remediation: "Verify the agent service account can reach the Kubernetes API server.",
		})
	} else if status < 200 || status >= 300 {
		probe.Diagnostics = append(probe.Diagnostics, agentDiagnostic{
			Code:        "kubernetes_agent_version_unavailable",
			Severity:    "warning",
			Message:     fmt.Sprintf("read Kubernetes server version returned HTTP %d: %s", status, body),
			Remediation: "Verify the Kubernetes API server is reachable from the agent pod.",
		})
	} else {
		probe.GitVersion = strings.TrimSpace(version.GitVersion)
		probe.Platform = strings.TrimSpace(version.Platform)
	}

	for _, check := range requiredAgentPermissionChecks() {
		probe.PermissionChecks = append(probe.PermissionChecks, runAgentPermissionCheck(ctx, client, baseURL, token, check))
	}
	return probe
}

func kubernetesAPIBaseURL(host string, port string) string {
	return "https://" + net.JoinHostPort(strings.TrimSpace(host), strings.TrimSpace(port))
}

func kubernetesAPIClient() (*http.Client, error) {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if caBytes, err := os.ReadFile(kubernetesServiceAccountCAPath); err == nil {
		if ok := pool.AppendCertsFromPEM(caBytes); !ok {
			return nil, errors.New("service account CA bundle did not contain a valid PEM certificate")
		}
	} else {
		return nil, fmt.Errorf("read Kubernetes service account CA bundle: %w", err)
	}
	return &http.Client{
		Timeout: kubernetesAPITimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		},
	}, nil
}

func requiredAgentPermissionChecks() []agentPermissionCheck {
	return []agentPermissionCheck{
		{Verb: "list", Resource: "serviceaccounts", Scope: "cluster", Remediation: "Grant the identrail-agent service account list access to serviceaccounts."},
		{Verb: "list", Resource: "rolebindings", Scope: "cluster", Remediation: "Grant the identrail-agent service account list access to rolebindings."},
		{Verb: "list", Resource: "clusterrolebindings", Scope: "cluster", Remediation: "Grant the identrail-agent service account list access to clusterrolebindings."},
		{Verb: "list", Resource: "roles", Scope: "cluster", Remediation: "Grant the identrail-agent service account list access to roles."},
		{Verb: "list", Resource: "clusterroles", Scope: "cluster", Remediation: "Grant the identrail-agent service account list access to clusterroles."},
		{Verb: "list", Resource: "pods", Scope: "cluster", Remediation: "Grant the identrail-agent service account list access to pods."},
	}
}

func runAgentPermissionCheck(ctx context.Context, client *http.Client, baseURL string, token string, check agentPermissionCheck) agentPermissionCheck {
	path := kubernetesResourceListPath(check.Resource)
	if path == "" {
		check.Diagnostic = "unsupported Kubernetes resource check"
		return check
	}
	status, body, err := kubernetesGet(ctx, client, baseURL+path+"?limit=1", token)
	if err != nil {
		check.Diagnostic = fmt.Sprintf("list Kubernetes %s: %v", check.Resource, err)
		return check
	}
	if status >= 200 && status < 300 {
		check.Allowed = true
		return check
	}
	check.Diagnostic = fmt.Sprintf("list Kubernetes %s returned HTTP %d: %s", check.Resource, status, body)
	return check
}

func kubernetesResourceListPath(resource string) string {
	switch strings.TrimSpace(resource) {
	case "serviceaccounts":
		return "/api/v1/serviceaccounts"
	case "pods":
		return "/api/v1/pods"
	case "rolebindings":
		return "/apis/rbac.authorization.k8s.io/v1/rolebindings"
	case "roles":
		return "/apis/rbac.authorization.k8s.io/v1/roles"
	case "clusterrolebindings":
		return "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings"
	case "clusterroles":
		return "/apis/rbac.authorization.k8s.io/v1/clusterroles"
	default:
		return ""
	}
}

func kubernetesGetJSON(ctx context.Context, client *http.Client, url string, token string, target any) (int, string, error) {
	status, body, err := kubernetesGet(ctx, client, url, token)
	if err != nil || status < 200 || status >= 300 || len(body) == 0 {
		return status, body, err
	}
	if err := json.Unmarshal([]byte(body), target); err != nil {
		return status, body, fmt.Errorf("decode Kubernetes API response: %w", err)
	}
	return status, body, nil
}

func kubernetesGet(ctx context.Context, client *http.Client, url string, token string) (int, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(token))
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return resp.StatusCode, strings.TrimSpace(string(body)), nil
}

func persistKubernetesAgentToken(ctx context.Context, agentToken string) error {
	agentToken = strings.TrimSpace(agentToken)
	namespace := strings.TrimSpace(os.Getenv("IDENTRAIL_AGENT_NAMESPACE"))
	secretName := strings.TrimSpace(os.Getenv("IDENTRAIL_AGENT_TOKEN_SECRET_NAME"))
	secretKey := strings.TrimSpace(os.Getenv("IDENTRAIL_AGENT_TOKEN_SECRET_KEY"))
	if agentToken == "" || namespace == "" || secretName == "" {
		return nil
	}
	if secretKey == "" {
		secretKey = "agent-token"
	}
	host := strings.TrimSpace(os.Getenv("KUBERNETES_SERVICE_HOST"))
	port := strings.TrimSpace(os.Getenv("KUBERNETES_SERVICE_PORT"))
	if host == "" || port == "" {
		return errors.New("Kubernetes service discovery environment variables are not available")
	}
	baseURL := kubernetesAPIBaseURL(host, port)
	serviceAccountToken, err := os.ReadFile(kubernetesServiceAccountTokenPath)
	if err != nil {
		return fmt.Errorf("read Kubernetes service account token: %w", err)
	}
	client, err := kubernetesAPIClient()
	if err != nil {
		return err
	}
	patchBody, err := json.Marshal(map[string]any{
		"data": map[string]string{
			secretKey: base64.StdEncoding.EncodeToString([]byte(agentToken)),
		},
	})
	if err != nil {
		return err
	}
	secretURL := baseURL + "/api/v1/namespaces/" + url.PathEscape(namespace) + "/secrets/" + url.PathEscape(secretName)
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, secretURL, bytes.NewReader(patchBody))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(serviceAccountToken)))
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/merge-patch+json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("patch Kubernetes agent token secret returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

func env(key string, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func envDuration(key string, fallback time.Duration) time.Duration {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func envBool(key string, fallback bool) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}

func hostnameAgentID() string {
	name, err := os.Hostname()
	if err != nil || strings.TrimSpace(name) == "" {
		return "identrail-agent"
	}
	return "identrail-agent-" + strings.TrimSpace(name)
}
