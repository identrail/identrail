package workflow

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	linearDestinationName = "linear"
	defaultLinearAPIURL   = "https://api.linear.app/graphql"
)

// LinearDestination creates issues in a Linear team via GraphQL.
type LinearDestination struct {
	APIURL     string // defaults to https://api.linear.app/graphql
	APIKey     string
	TeamID     string
	HTTPClient *http.Client
}

// Name implements Destination.
func (l LinearDestination) Name() string { return linearDestinationName }

// Send creates one Linear issue per event.
func (l LinearDestination) Send(ctx context.Context, event Event) error {
	apiKey := strings.TrimSpace(l.APIKey)
	if apiKey == "" {
		return fmt.Errorf("linear API key is required")
	}
	if strings.TrimSpace(l.TeamID) == "" {
		return fmt.Errorf("linear team id is required")
	}

	title := valueOrFallback(event.Finding.Title, fmt.Sprintf("Identrail finding %s", event.Finding.ID))
	if event.Kind == EventSCIMProvisioned && event.SCIMProvisioning != nil {
		title = fmt.Sprintf("[SCIM] %s user %s", strings.ToUpper(event.SCIMProvisioning.Operation), valueOrFallback(event.SCIMProvisioning.UserName, event.SCIMProvisioning.UserID))
	} else {
		title = fmt.Sprintf("[%s] %s", strings.ToUpper(string(event.Finding.Severity)), title)
	}

	payload := map[string]any{
		"query": `mutation IssueCreate($input: IssueCreateInput!) {
  issueCreate(input: $input) {
    success
    issue { id identifier url }
  }
}`,
		"variables": map[string]any{
			"input": map[string]any{
				"teamId":      l.TeamID,
				"title":       title,
				"description": l.buildDescription(event),
			},
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	apiURL := strings.TrimSpace(valueOrFallback(l.APIURL, defaultLinearAPIURL))
	// Refuse to send the API key over plaintext transport. The default Linear
	// endpoint is HTTPS; a custom override must keep that property.
	if !strings.HasPrefix(strings.ToLower(apiURL), "https://") {
		return fmt.Errorf("linear API URL must use https:// to protect the API key")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", apiKey)

	res, err := l.client().Do(req)
	if err != nil {
		return fmt.Errorf("linear POST: %w", err)
	}
	defer res.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(res.Body, 1<<14))
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return fmt.Errorf("linear API responded %d: %s", res.StatusCode, strings.TrimSpace(string(respBody)))
	}

	var parsed struct {
		Data struct {
			IssueCreate struct {
				Success bool `json:"success"`
			} `json:"issueCreate"`
		} `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return fmt.Errorf("decode linear response: %w", err)
	}
	if len(parsed.Errors) > 0 {
		return fmt.Errorf("linear graphql error: %s", parsed.Errors[0].Message)
	}
	if !parsed.Data.IssueCreate.Success {
		return fmt.Errorf("linear issueCreate returned success=false")
	}
	return nil
}

func (l LinearDestination) buildDescription(event Event) string {
	var b strings.Builder
	fmt.Fprintf(&b, "**Event:** `%s`\n\n", event.Kind)
	if event.Kind == EventSCIMProvisioned && event.SCIMProvisioning != nil {
		scim := event.SCIMProvisioning
		fmt.Fprintf(&b, "**User ID:** `%s`\n\n", scim.UserID)
		fmt.Fprintf(&b, "**User name:** `%s`\n\n", scim.UserName)
		fmt.Fprintf(&b, "**Connection:** `%s`\n\n", scim.ConnectionID)
		fmt.Fprintf(&b, "**Operation:** `%s`\n\n", scim.Operation)
		fmt.Fprintf(&b, "**Active:** %t\n\n", scim.Active)
		if event.RelatedURL != "" {
			fmt.Fprintf(&b, "Related: %s\n", event.RelatedURL)
		}
		return b.String()
	}
	fmt.Fprintf(&b, "**Finding ID:** `%s`\n\n", event.Finding.ID)
	fmt.Fprintf(&b, "**Severity:** %s\n\n", event.Finding.Severity)
	fmt.Fprintf(&b, "**Type:** `%s`\n\n", event.Finding.Type)
	if event.Finding.HumanSummary != "" {
		fmt.Fprintf(&b, "%s\n\n", event.Finding.HumanSummary)
	}
	if event.RelatedURL != "" {
		fmt.Fprintf(&b, "Related: %s\n", event.RelatedURL)
	}
	return b.String()
}

func (l LinearDestination) client() *http.Client {
	if l.HTTPClient != nil {
		return l.HTTPClient
	}
	return &http.Client{Timeout: 10 * time.Second}
}
