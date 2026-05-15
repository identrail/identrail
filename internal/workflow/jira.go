package workflow

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const jiraDestinationName = "jira"

// JiraDestination creates issues in a Jira Cloud project via the v3 REST API.
type JiraDestination struct {
	BaseURL    string // e.g. https://acme.atlassian.net
	Email      string
	APIToken   string
	ProjectKey string
	IssueType  string // defaults to "Task"
	HTTPClient *http.Client
}

// Name implements Destination.
func (j JiraDestination) Name() string { return jiraDestinationName }

// Send creates one Jira issue per event.
func (j JiraDestination) Send(ctx context.Context, event Event) error {
	if err := j.validate(); err != nil {
		return err
	}
	body, err := json.Marshal(j.payload(event))
	if err != nil {
		return err
	}
	issueURL := strings.TrimRight(j.BaseURL, "/") + "/rest/api/3/issue"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, issueURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(j.Email+":"+j.APIToken)))

	res, err := j.client().Do(req)
	if err != nil {
		return fmt.Errorf("jira POST: %w", err)
	}
	defer res.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(res.Body, 1<<14))
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return fmt.Errorf("jira issue create responded %d: %s", res.StatusCode, strings.TrimSpace(string(respBody)))
	}
	return nil
}

func (j JiraDestination) validate() error {
	base := strings.TrimSpace(j.BaseURL)
	if base == "" {
		return fmt.Errorf("jira base URL is required")
	}
	// Refuse to send Basic-auth credentials over plaintext transport. The
	// only acceptable scheme is HTTPS so the email + API token cannot leak.
	if !strings.HasPrefix(strings.ToLower(base), "https://") {
		return fmt.Errorf("jira base URL must use https:// to protect basic-auth credentials")
	}
	if strings.TrimSpace(j.Email) == "" || strings.TrimSpace(j.APIToken) == "" {
		return fmt.Errorf("jira email and api token are required")
	}
	if strings.TrimSpace(j.ProjectKey) == "" {
		return fmt.Errorf("jira project key is required")
	}
	return nil
}

func (j JiraDestination) payload(event Event) map[string]any {
	issueType := valueOrFallback(j.IssueType, "Task")
	title := valueOrFallback(event.Finding.Title, fmt.Sprintf("Identrail finding %s", event.Finding.ID))
	summary := fmt.Sprintf("[%s] %s", strings.ToUpper(string(event.Finding.Severity)), title)
	return map[string]any{
		"fields": map[string]any{
			"project":     map[string]any{"key": j.ProjectKey},
			"summary":     summary,
			"description": j.buildADFDescription(event),
			"issuetype":   map[string]any{"name": issueType},
			"labels":      []string{"identrail", string(event.Finding.Type), strings.ToLower(string(event.Finding.Severity))},
		},
	}
}

// buildADFDescription returns an Atlassian Document Format description, the
// only body format accepted by Jira Cloud REST API v3.
func (j JiraDestination) buildADFDescription(event Event) map[string]any {
	paragraphs := []map[string]any{
		paragraph(fmt.Sprintf("Event: %s", event.Kind)),
		paragraph(fmt.Sprintf("Finding ID: %s", event.Finding.ID)),
		paragraph(fmt.Sprintf("Severity: %s", event.Finding.Severity)),
		paragraph(fmt.Sprintf("Type: %s", event.Finding.Type)),
		paragraph(valueOrFallback(event.Finding.HumanSummary, "No human summary available.")),
	}
	if event.RelatedURL != "" {
		paragraphs = append(paragraphs, paragraph("Related: "+event.RelatedURL))
	}
	return map[string]any{
		"type":    "doc",
		"version": 1,
		"content": paragraphs,
	}
}

func paragraph(text string) map[string]any {
	return map[string]any{
		"type":    "paragraph",
		"content": []map[string]any{{"type": "text", "text": text}},
	}
}

func (j JiraDestination) client() *http.Client {
	if j.HTTPClient != nil {
		return j.HTTPClient
	}
	return &http.Client{Timeout: 10 * time.Second}
}
