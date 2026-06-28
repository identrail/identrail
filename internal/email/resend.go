package email

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	defaultResendEmailsEndpoint = "https://api.resend.com/emails"
	defaultResendTimeout        = 3 * time.Second
)

// ResendSender sends transactional email through Resend's HTTP API.
type ResendSender struct {
	client   *http.Client
	endpoint string
	apiKey   string
}

// ResendSenderOption customizes the Resend sender.
type ResendSenderOption func(*ResendSender)

// WithResendEndpoint points the sender at a non-default endpoint. It is used by tests.
func WithResendEndpoint(endpoint string) ResendSenderOption {
	return func(sender *ResendSender) {
		sender.endpoint = strings.TrimSpace(endpoint)
	}
}

// WithHTTPClient overrides the HTTP client.
func WithHTTPClient(client *http.Client) ResendSenderOption {
	return func(sender *ResendSender) {
		if client != nil {
			sender.client = client
		}
	}
}

// NewResendSender builds a Resend-backed transactional email sender.
func NewResendSender(apiKey string, timeout time.Duration, opts ...ResendSenderOption) (*ResendSender, error) {
	trimmedKey := strings.TrimSpace(apiKey)
	if trimmedKey == "" {
		return nil, fmt.Errorf("resend api key is required")
	}
	if timeout <= 0 {
		timeout = defaultResendTimeout
	}
	sender := &ResendSender{
		client:   &http.Client{Timeout: timeout},
		endpoint: defaultResendEmailsEndpoint,
		apiKey:   trimmedKey,
	}
	for _, opt := range opts {
		opt(sender)
	}
	if err := validateResendEndpoint(sender.endpoint); err != nil {
		return nil, err
	}
	return sender, nil
}

func (s *ResendSender) Send(ctx context.Context, message Message) error {
	if s == nil || s.client == nil {
		return fmt.Errorf("resend sender is not configured")
	}
	payload, err := resendPayloadFromMessage(message)
	if err != nil {
		return err
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal resend email: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build resend email request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+safeHeaderValue(s.apiKey))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "identrail-email/1.0")
	if key := safeHeaderValue(message.IdempotencyKey); key != "" {
		req.Header.Set("Idempotency-Key", key)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("send resend email: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("resend email status %d: %s", resp.StatusCode, readResendError(resp.Body))
	}
	return nil
}

type resendEmailPayload struct {
	From    string   `json:"from"`
	To      []string `json:"to"`
	ReplyTo string   `json:"reply_to,omitempty"`
	Subject string   `json:"subject"`
	Text    string   `json:"text,omitempty"`
	HTML    string   `json:"html,omitempty"`
}

func resendPayloadFromMessage(message Message) (resendEmailPayload, error) {
	from := strings.TrimSpace(message.From)
	if from == "" {
		return resendEmailPayload{}, fmt.Errorf("email from address is required")
	}
	to := make([]string, 0, len(message.To))
	for _, address := range message.To {
		if trimmed := strings.TrimSpace(address); trimmed != "" {
			to = append(to, trimmed)
		}
	}
	if len(to) == 0 {
		return resendEmailPayload{}, fmt.Errorf("email recipient is required")
	}
	subject := strings.TrimSpace(message.Subject)
	if subject == "" {
		return resendEmailPayload{}, fmt.Errorf("email subject is required")
	}
	if strings.TrimSpace(message.Text) == "" && strings.TrimSpace(message.HTML) == "" {
		return resendEmailPayload{}, fmt.Errorf("email text or html body is required")
	}
	return resendEmailPayload{
		From:    from,
		To:      to,
		ReplyTo: strings.TrimSpace(message.ReplyTo),
		Subject: subject,
		Text:    strings.TrimSpace(message.Text),
		HTML:    strings.TrimSpace(message.HTML),
	}, nil
}

func validateResendEndpoint(raw string) error {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("resend endpoint must be an absolute URL")
	}
	switch strings.ToLower(parsed.Scheme) {
	case "https":
		return nil
	case "http":
		if parsed.Hostname() == "127.0.0.1" || parsed.Hostname() == "localhost" || parsed.Hostname() == "::1" {
			return nil
		}
	}
	return fmt.Errorf("resend endpoint must use https outside local testing")
}

func readResendError(body io.Reader) string {
	raw, _ := io.ReadAll(io.LimitReader(body, 512))
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return "empty response body"
	}
	var apiErr struct {
		Name    string `json:"name"`
		Message string `json:"message"`
	}
	if json.Unmarshal(raw, &apiErr) == nil && strings.TrimSpace(apiErr.Message) != "" {
		if strings.TrimSpace(apiErr.Name) != "" {
			return strings.TrimSpace(apiErr.Name) + ": " + strings.TrimSpace(apiErr.Message)
		}
		return strings.TrimSpace(apiErr.Message)
	}
	return trimmed
}

func safeHeaderValue(raw string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case '\r', '\n':
			return -1
		default:
			return r
		}
	}, strings.TrimSpace(raw))
}
