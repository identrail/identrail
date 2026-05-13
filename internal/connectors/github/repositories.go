package github

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const defaultRepoPageLimit = 100

// Repository describes the GitHub repository metadata Identrail needs for
// selection and scan target storage.
type Repository struct {
	FullName string `json:"full_name"`
	Private  bool   `json:"private"`
}

// RepositoryClient lists repositories visible to one GitHub App installation.
type RepositoryClient struct {
	TokenClient InstallationTokenMinter
	HTTPClient  *http.Client
	APIBaseURL  string
}

// InstallationTokenMinter mints GitHub App installation access tokens.
type InstallationTokenMinter interface {
	Mint(ctx context.Context, installationID int64) (InstallationToken, error)
}

// ListInstallationRepositories returns all repositories available to the
// installation, following GitHub pagination.
func (c RepositoryClient) ListInstallationRepositories(ctx context.Context, installationID int64) ([]Repository, error) {
	if c.TokenClient == nil {
		return nil, fmt.Errorf("github installation token client is required")
	}
	token, err := c.TokenClient.Mint(ctx, installationID)
	if err != nil {
		return nil, err
	}
	nextURL := strings.TrimRight(c.apiBaseURL(), "/") + "/installation/repositories?per_page=" + strconv.Itoa(defaultRepoPageLimit)
	repositories := []Repository{}
	for nextURL != "" {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, nextURL, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("Authorization", "Bearer "+token.Token)
		res, err := c.httpClient().Do(req)
		if err != nil {
			return nil, fmt.Errorf("list github repositories: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
		_ = res.Body.Close()
		if res.StatusCode < 200 || res.StatusCode >= 300 {
			return nil, fmt.Errorf("list github repositories: status %d", res.StatusCode)
		}
		var page struct {
			Repositories []Repository `json:"repositories"`
		}
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, fmt.Errorf("decode github repositories: %w", err)
		}
		for _, repository := range page.Repositories {
			repository.FullName = strings.TrimSpace(repository.FullName)
			if repository.FullName != "" {
				repositories = append(repositories, repository)
			}
		}
		nextURL = nextLink(res.Header.Get("Link"))
	}
	return repositories, nil
}

func (c RepositoryClient) apiBaseURL() string {
	if c.APIBaseURL != "" {
		return c.APIBaseURL
	}
	return defaultGitHubAPIBaseURL
}

func (c RepositoryClient) httpClient() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return &http.Client{Timeout: 10 * time.Second}
}

func nextLink(header string) string {
	for _, part := range strings.Split(header, ",") {
		segments := strings.Split(strings.TrimSpace(part), ";")
		if len(segments) < 2 {
			continue
		}
		linkURL := strings.Trim(strings.TrimSpace(segments[0]), "<>")
		for _, segment := range segments[1:] {
			if strings.TrimSpace(segment) == `rel="next"` {
				if parsed, err := url.Parse(linkURL); err == nil && parsed.Scheme != "" && parsed.Host != "" {
					return parsed.String()
				}
			}
		}
	}
	return ""
}
