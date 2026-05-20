package github

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
)

// CodeScanningAlert is the GitHub API shape needed for repository finding ingestion.
type CodeScanningAlert struct {
	Number             int                       `json:"number"`
	State              string                    `json:"state"`
	Rule               CodeScanningRule          `json:"rule"`
	Tool               CodeScanningTool          `json:"tool"`
	MostRecentInstance CodeScanningAlertInstance `json:"most_recent_instance"`
	HTMLURL            string                    `json:"html_url"`
}

type CodeScanningRule struct {
	ID                    string   `json:"id"`
	Name                  string   `json:"name"`
	Severity              string   `json:"severity"`
	Description           string   `json:"description"`
	SecuritySeverityLevel string   `json:"security_severity_level"`
	Tags                  []string `json:"tags"`
}

type CodeScanningTool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type CodeScanningAlertInstance struct {
	Ref         string               `json:"ref"`
	AnalysisKey string               `json:"analysis_key"`
	Category    string               `json:"category"`
	State       string               `json:"state"`
	CommitSHA   string               `json:"commit_sha"`
	Message     CodeScanningMessage  `json:"message"`
	Location    CodeScanningLocation `json:"location"`
}

type CodeScanningMessage struct {
	Text string `json:"text"`
}

type CodeScanningLocation struct {
	Path        string `json:"path"`
	StartLine   int    `json:"start_line"`
	EndLine     int    `json:"end_line"`
	StartColumn int    `json:"start_column"`
	EndColumn   int    `json:"end_column"`
}

// ListCodeScanningAlerts returns all open GitHub code-scanning alerts for a repository.
func (c RepositoryClient) ListCodeScanningAlerts(ctx context.Context, installationID int64, repository string) ([]CodeScanningAlert, error) {
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
	alerts := []CodeScanningAlert{}
	endpoint := c.repositoryEndpoint(normalizedRepository, "/code-scanning/alerts?state=open&per_page="+strconv.Itoa(defaultRepoPageLimit))
	_, err = c.getJSONPages(ctx, token.Token, endpoint, func(body []byte) error {
		var page []CodeScanningAlert
		if err := json.Unmarshal(body, &page); err != nil {
			return err
		}
		alerts = append(alerts, page...)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("list github code scanning alerts: %w", err)
	}
	return alerts, nil
}
