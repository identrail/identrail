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

const slackDestinationName = "slack"

// SlackDestination posts events to a Slack incoming webhook URL.
type SlackDestination struct {
	WebhookURL string
	HTTPClient *http.Client
}

// Name implements Destination.
func (s SlackDestination) Name() string { return slackDestinationName }

// Send delivers the event as a formatted Slack message.
func (s SlackDestination) Send(ctx context.Context, event Event) error {
	webhookURL := strings.TrimSpace(s.WebhookURL)
	if webhookURL == "" {
		return fmt.Errorf("slack webhook URL is empty")
	}
	// Slack incoming webhook URLs embed a secret token in the path itself.
	// Refuse to send the request — and the finding payload — over plaintext
	// transport, matching the Jira/Linear https-only posture.
	if !strings.HasPrefix(strings.ToLower(webhookURL), "https://") {
		return fmt.Errorf("slack webhook URL must use https:// to protect the embedded webhook secret")
	}
	body, err := json.Marshal(s.payload(event))
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	res, err := s.client().Do(req)
	if err != nil {
		return fmt.Errorf("slack POST: %w", err)
	}
	defer res.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(res.Body, 1<<14))
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return fmt.Errorf("slack webhook responded %d: %s", res.StatusCode, strings.TrimSpace(string(respBody)))
	}
	return nil
}

func (s SlackDestination) payload(event Event) map[string]any {
	if event.Kind == EventSCIMProvisioned && event.SCIMProvisioning != nil {
		scim := event.SCIMProvisioning
		title := valueOrFallback(scim.UserName, scim.UserID)
		summary := fmt.Sprintf("*%s* — %s user `%s`", event.Kind, scim.Operation, title)
		fields := []map[string]any{
			{"type": "mrkdwn", "text": fmt.Sprintf("*User ID*\n`%s`", scim.UserID)},
			{"type": "mrkdwn", "text": fmt.Sprintf("*Connection*\n`%s`", scim.ConnectionID)},
			{"type": "mrkdwn", "text": fmt.Sprintf("*Operation*\n`%s`", scim.Operation)},
			{"type": "mrkdwn", "text": fmt.Sprintf("*Active*\n%t", scim.Active)},
		}
		blocks := []map[string]any{
			{"type": "section", "text": map[string]any{"type": "mrkdwn", "text": summary}},
			{"type": "section", "fields": fields},
		}
		if event.RelatedURL != "" {
			blocks = append(blocks, map[string]any{
				"type": "section",
				"text": map[string]any{"type": "mrkdwn", "text": fmt.Sprintf("<%s|Open SCIM resource>", event.RelatedURL)},
			})
		}
		return map[string]any{"text": summary, "blocks": blocks}
	}
	title := valueOrFallback(event.Finding.Title, fmt.Sprintf("Finding %s", event.Finding.ID))
	summary := fmt.Sprintf("*%s* — %s (%s)", event.Kind, title, event.Finding.Severity)
	fields := []map[string]any{
		{"type": "mrkdwn", "text": fmt.Sprintf("*Finding ID*\n`%s`", event.Finding.ID)},
		{"type": "mrkdwn", "text": fmt.Sprintf("*Type*\n`%s`", event.Finding.Type)},
		{"type": "mrkdwn", "text": fmt.Sprintf("*Severity*\n%s", event.Finding.Severity)},
		{"type": "mrkdwn", "text": fmt.Sprintf("*Actor*\n%s", valueOrFallback(event.Actor, "—"))},
	}
	blocks := []map[string]any{
		{"type": "section", "text": map[string]any{"type": "mrkdwn", "text": summary}},
		{"type": "section", "fields": fields},
	}
	if event.RelatedURL != "" {
		blocks = append(blocks, map[string]any{
			"type": "section",
			"text": map[string]any{"type": "mrkdwn", "text": fmt.Sprintf("<%s|Open related context>", event.RelatedURL)},
		})
	}
	return map[string]any{"text": summary, "blocks": blocks}
}

func (s SlackDestination) client() *http.Client {
	if s.HTTPClient != nil {
		return s.HTTPClient
	}
	return &http.Client{Timeout: 10 * time.Second}
}
