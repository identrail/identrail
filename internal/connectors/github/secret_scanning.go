package github

import (
	"context"
	"encoding/json"
	"fmt"
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
	_, err = c.getJSONPages(ctx, token.Token, endpoint, func(body []byte) error {
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
