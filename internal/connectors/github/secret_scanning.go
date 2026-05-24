package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
)

// SecretScanningAlert is the GitHub API shape needed for repository finding
// ingestion. The raw `secret` value GitHub returns is intentionally omitted so
// the credential material is never deserialized, stored, logged, or returned.
type SecretScanningAlert struct {
	Number                int    `json:"number"`
	State                 string `json:"state"`
	SecretType            string `json:"secret_type"`
	SecretTypeDisplayName string `json:"secret_type_display_name"`
	Validity              string `json:"validity"`
	Resolution            string `json:"resolution"`
	PushProtectionBypass  bool   `json:"push_protection_bypassed"`
	HTMLURL               string `json:"html_url"`
}

// ListSecretScanningAlerts returns all open GitHub secret-scanning alerts for a
// repository. It follows GitHub pagination using the installation token.
func (c RepositoryClient) ListSecretScanningAlerts(ctx context.Context, installationID int64, repository string) ([]SecretScanningAlert, error) {
	if c.TokenClient == nil {
		return nil, fmt.Errorf("github installation token client is required")
	}
	normalizedRepository, err := normalizeRepositoryName(repository)
	if err != nil {
		return nil, err
	}
	token, err := c.TokenClient.Mint(ctx, installationID)
	if err != nil {
		return nil, err
	}
	alerts := []SecretScanningAlert{}
	endpoint := c.repositoryEndpoint(normalizedRepository, "/secret-scanning/alerts?state=open&per_page="+strconv.Itoa(defaultRepoPageLimit)+"&hide_secret=true")
	_, err = c.getSecretScanningAlertsPages(ctx, token.Token, endpoint, func(body []byte) error {
		var page []SecretScanningAlert
		if err := json.Unmarshal(body, &page); err != nil {
			return err
		}
		alerts = append(alerts, page...)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("list github secret scanning alerts: %w", err)
	}
	return alerts, nil
}

func (c RepositoryClient) getSecretScanningAlertsPages(ctx context.Context, token string, endpoint string, decode func([]byte) error) (*GitHubRateLimitState, error) {
	nextURL := endpoint
	var lastRateLimit *GitHubRateLimitState
	for nextURL != "" {
		body, rateLimit, link, err := c.doGitHubRequestRaw(ctx, token, http.MethodGet, nextURL)
		if rateLimit != nil {
			lastRateLimit = rateLimit
		}
		if err != nil {
			return lastRateLimit, err
		}
		if err := decode(body); err != nil {
			return lastRateLimit, fmt.Errorf("decode github posture page: %w", err)
		}
		nextURL = nextLink(link)
		if nextURL == "" {
			return lastRateLimit, nil
		}
		nextURL, err = ensureHideSecretQuery(nextURL)
		if err != nil {
			return lastRateLimit, err
		}
	}
	return lastRateLimit, nil
}

func ensureHideSecretQuery(rawURL string) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	query := parsed.Query()
	query.Set("hide_secret", "true")
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}
