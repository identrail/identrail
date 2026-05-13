package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

type enrollRequest struct {
	EnrollmentToken string `json:"enrollment_token"`
	ConnectorID     string `json:"connector_id,omitempty"`
	AgentID         string `json:"agent_id,omitempty"`
	Cluster         string `json:"cluster,omitempty"`
	Server          string `json:"server,omitempty"`
	GitVersion      string `json:"git_version,omitempty"`
	Platform        string `json:"platform,omitempty"`
}

type enrollResponse struct {
	ConnectorID  string `json:"connector_id"`
	AgentID      string `json:"agent_id"`
	AgentToken   string `json:"agent_token"`
	HeartbeatURL string `json:"heartbeat_url"`
}

type heartbeatRequest struct {
	ConnectorID string `json:"connector_id,omitempty"`
	AgentID     string `json:"agent_id,omitempty"`
	Cluster     string `json:"cluster,omitempty"`
	Server      string `json:"server,omitempty"`
	GitVersion  string `json:"git_version,omitempty"`
	Platform    string `json:"platform,omitempty"`
}

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
	apiURL = strings.TrimRight(strings.TrimSpace(apiURL), "/")
	if apiURL == "" {
		log.Fatal("api-url is required")
	}

	credential := strings.TrimSpace(agentToken)
	if credential == "" {
		if strings.TrimSpace(enrollmentToken) == "" {
			log.Fatal("enrollment-token or agent-token is required")
		}
		response, err := enroll(ctx, client, apiURL, enrollRequest{
			EnrollmentToken: enrollmentToken,
			ConnectorID:     connectorID,
			AgentID:         agentID,
		})
		if err != nil {
			log.Printf("enroll failed; continuing with existing enrollment credential for heartbeat: %v", err)
			credential = enrollmentToken
		} else {
			credential = response.AgentToken
			connectorID = response.ConnectorID
			agentID = response.AgentID
			log.Printf("enrolled connector %s as %s", connectorID, agentID)
		}
	}

	for {
		if err := heartbeat(ctx, client, apiURL, credential, heartbeatRequest{
			ConnectorID: connectorID,
			AgentID:     agentID,
		}); err != nil {
			log.Printf("heartbeat failed: %v", err)
		} else {
			log.Printf("heartbeat sent for connector %s", connectorID)
		}
		if once {
			return
		}
		time.Sleep(heartbeatInterval)
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
