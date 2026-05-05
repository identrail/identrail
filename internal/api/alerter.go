package api

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/domain"
)

const (
	defaultAlertTimeout     = 5 * time.Second
	defaultAlertMaxFindings = 25
	defaultAlertMaxRetries  = 2
	defaultAlertBackoff     = 1 * time.Second
)

var severityRank = map[domain.FindingSeverity]int{
	domain.SeverityInfo:     1,
	domain.SeverityLow:      2,
	domain.SeverityMedium:   3,
	domain.SeverityHigh:     4,
	domain.SeverityCritical: 5,
}

// FindingAlerter emits structured scan alerts to external systems.
type FindingAlerter interface {
	NotifyScan(ctx context.Context, provider string, scan db.ScanRecord, findings []domain.Finding) error
}

// NopFindingAlerter is used when alerting is not configured.
type NopFindingAlerter struct{}

func (NopFindingAlerter) NotifyScan(context.Context, string, db.ScanRecord, []domain.Finding) error {
	return nil
}

// WebhookAlerter posts high-signal findings to one webhook endpoint.
type WebhookAlerter struct {
	client       *http.Client
	webhookURL   string
	minSeverity  domain.FindingSeverity
	hmacSecret   string
	maxFindings  int
	maxRetries   int
	retryBackoff time.Duration
}

// AlertPayload is the external webhook contract for scan alerts.
type AlertPayload struct {
	Version         string         `json:"version"`
	Provider        string         `json:"provider"`
	ScanID          string         `json:"scan_id"`
	Status          string         `json:"status"`
	StartedAt       time.Time      `json:"started_at"`
	FinishedAt      *time.Time     `json:"finished_at,omitempty"`
	TotalFindings   int            `json:"total_findings"`
	MatchedFindings int            `json:"matched_findings"`
	MinSeverity     string         `json:"min_severity"`
	Findings        []AlertFinding `json:"findings"`
}

// AlertFinding keeps alert payloads concise and operator-focused.
type AlertFinding struct {
	ID           string                 `json:"id"`
	Type         domain.FindingType     `json:"type"`
	Severity     domain.FindingSeverity `json:"severity"`
	Title        string                 `json:"title"`
	HumanSummary string                 `json:"human_summary"`
	Remediation  string                 `json:"remediation"`
	Path         []string               `json:"path,omitempty"`
}

// NewWebhookAlerter creates a webhook notifier with URL safety checks.
func NewWebhookAlerter(
	webhookURL string,
	timeout time.Duration,
	minSeverity string,
	hmacSecret string,
	maxFindings int,
	maxRetries int,
	retryBackoff time.Duration,
) (*WebhookAlerter, error) {
	trimmedURL := strings.TrimSpace(webhookURL)
	if trimmedURL == "" {
		return nil, fmt.Errorf("webhook url is required")
	}
	if err := validateWebhookURL(trimmedURL); err != nil {
		return nil, err
	}

	parsedSeverity, err := parseFindingSeverity(minSeverity)
	if err != nil {
		return nil, err
	}
	if timeout <= 0 {
		timeout = defaultAlertTimeout
	}
	if maxFindings <= 0 {
		maxFindings = defaultAlertMaxFindings
	}
	if maxRetries < 0 {
		maxRetries = defaultAlertMaxRetries
	}
	if retryBackoff <= 0 {
		retryBackoff = defaultAlertBackoff
	}

	return &WebhookAlerter{
		client:       &http.Client{Timeout: timeout},
		webhookURL:   trimmedURL,
		minSeverity:  parsedSeverity,
		hmacSecret:   strings.TrimSpace(hmacSecret),
		maxFindings:  maxFindings,
		maxRetries:   maxRetries,
		retryBackoff: retryBackoff,
	}, nil
}

func (a *WebhookAlerter) NotifyScan(ctx context.Context, provider string, scan db.ScanRecord, findings []domain.Finding) error {
	matched := filterFindingsBySeverity(findings, a.minSeverity, a.maxFindings)
	if len(matched) == 0 {
		return nil
	}

	payload := AlertPayload{
		Version:         "1",
		Provider:        provider,
		ScanID:          scan.ID,
		Status:          scan.Status,
		StartedAt:       scan.StartedAt,
		FinishedAt:      scan.FinishedAt,
		TotalFindings:   len(findings),
		MatchedFindings: len(matched),
		MinSeverity:     string(a.minSeverity),
		Findings:        matched,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal alert payload: %w", err)
	}

	var lastErr error
	attempts := a.maxRetries + 1
	for attempt := 0; attempt < attempts; attempt++ {
		retryable, sendErr := a.sendWebhook(ctx, body)
		if sendErr == nil {
			return nil
		}
		lastErr = sendErr
		if !retryable || attempt == attempts-1 {
			break
		}
		wait := backoffDuration(a.retryBackoff, attempt)
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return fmt.Errorf("send alert webhook: %w", ctx.Err())
		case <-timer.C:
		}
	}
	return lastErr
}

func (a *WebhookAlerter) sendWebhook(ctx context.Context, body []byte) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.webhookURL, bytes.NewReader(body))
	if err != nil {
		return false, fmt.Errorf("build alert request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "identrail-alert/1.0")
	if a.hmacSecret != "" {
		req.Header.Set("X-Identrail-Signature", computeHMAC(body, a.hmacSecret))
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return true, fmt.Errorf("send alert webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		retryable := resp.StatusCode >= http.StatusInternalServerError
		return retryable, fmt.Errorf("alert webhook status %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	return false, nil
}

func filterFindingsBySeverity(findings []domain.Finding, min domain.FindingSeverity, max int) []AlertFinding {
	result := make([]AlertFinding, 0, len(findings))
	minRank := severityRank[min]
	for _, finding := range findings {
		rank, ok := severityRank[finding.Severity]
		if !ok || rank < minRank {
			continue
		}
		result = append(result, AlertFinding{
			ID:           finding.ID,
			Type:         finding.Type,
			Severity:     finding.Severity,
			Title:        finding.Title,
			HumanSummary: finding.HumanSummary,
			Remediation:  finding.Remediation,
			Path:         finding.Path,
		})
		if len(result) >= max {
			break
		}
	}
	return result
}

func parseFindingSeverity(raw string) (domain.FindingSeverity, error) {
	if strings.TrimSpace(raw) == "" {
		return domain.SeverityHigh, nil
	}
	normalized := domain.FindingSeverity(strings.ToLower(strings.TrimSpace(raw)))
	if _, ok := severityRank[normalized]; !ok {
		return "", fmt.Errorf("invalid alert min severity %q", raw)
	}
	return normalized, nil
}

func validateWebhookURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("parse webhook url: %w", err)
	}
	host := strings.ToLower(parsed.Hostname())
	switch strings.ToLower(parsed.Scheme) {
	case "https":
		return nil
	case "http":
		if host == "localhost" || host == "127.0.0.1" || host == "::1" {
			return nil
		}
		return fmt.Errorf("insecure webhook url scheme http is only allowed for localhost")
	default:
		return fmt.Errorf("unsupported webhook url scheme %q", parsed.Scheme)
	}
}

func computeHMAC(body []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

func backoffDuration(base time.Duration, attempt int) time.Duration {
	wait := base
	for i := 0; i < attempt; i++ {
		wait *= 2
	}
	if wait > 10*time.Second {
		return 10 * time.Second
	}
	return wait
}
