package github

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

var classicPATPattern = regexp.MustCompile(`^(ghp|github_pat)_[A-Za-z0-9_]{20,}$`)

// PATValidationResult captures the minimum identity and scope proof for a PAT.
type PATValidationResult struct {
	Login  string
	Scopes []string
}

// PATValidator validates classic GitHub PATs against GitHub.com or GHES.
type PATValidator struct {
	HTTPClient      *http.Client
	AllowedBaseURLs []string
}

// ValidateGitHubPAT adapts PATValidator to the API service dependency.
func (v PATValidator) ValidateGitHubPAT(ctx context.Context, baseURL string, token string) (PATValidationResult, error) {
	return v.Validate(ctx, baseURL, token)
}

// NormalizeBaseURL validates and canonicalizes the GitHub Enterprise base URL.
func NormalizeBaseURL(value string) (string, error) {
	trimmed := strings.TrimRight(strings.TrimSpace(value), "/")
	if trimmed == "" {
		return "https://github.com", nil
	}
	parsed, err := url.Parse(trimmed)
	if err != nil || parsed == nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("github base url must be absolute")
	}
	if parsed.Scheme != "https" && parsed.Hostname() != "localhost" && parsed.Hostname() != "127.0.0.1" {
		return "", fmt.Errorf("github base url must use https unless it points at localhost")
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String(), nil
}

// ValidatePATShape checks whether a token looks like a GitHub classic PAT.
func ValidatePATShape(token string) error {
	if !classicPATPattern.MatchString(strings.TrimSpace(token)) {
		return fmt.Errorf("github pat must look like a GitHub personal access token")
	}
	return nil
}

// Validate confirms the token is accepted and has read-oriented repository scope.
func (v PATValidator) Validate(ctx context.Context, baseURL string, token string) (PATValidationResult, error) {
	allowedBaseURL, err := v.allowedBaseURL(baseURL)
	if err != nil {
		return PATValidationResult{}, err
	}
	if err := ValidatePATShape(token); err != nil {
		return PATValidationResult{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, userEndpoint(allowedBaseURL), nil)
	if err != nil {
		return PATValidationResult{}, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(token))
	res, err := v.httpClient().Do(req)
	if err != nil {
		return PATValidationResult{}, fmt.Errorf("validate github pat: %w", err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return PATValidationResult{}, fmt.Errorf("validate github pat: status %d", res.StatusCode)
	}
	var payload struct {
		Login string `json:"login"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return PATValidationResult{}, fmt.Errorf("decode github pat validation response: %w", err)
	}
	scopes := normalizeScopes(res.Header.Get("X-OAuth-Scopes"))
	if !hasAcceptablePATScopes(scopes) {
		return PATValidationResult{}, fmt.Errorf("github pat requires repo or public_repo scope")
	}
	return PATValidationResult{Login: strings.TrimSpace(payload.Login), Scopes: scopes}, nil
}

func (v PATValidator) httpClient() *http.Client {
	if v.HTTPClient != nil {
		return v.HTTPClient
	}
	return &http.Client{Timeout: 10 * time.Second}
}

func (v PATValidator) allowedBaseURL(baseURL string) (string, error) {
	normalizedBaseURL, err := NormalizeBaseURL(baseURL)
	if err != nil {
		return "", err
	}
	allowedBaseURLs := v.AllowedBaseURLs
	if len(allowedBaseURLs) == 0 {
		allowedBaseURLs = []string{"https://github.com"}
	}
	for _, allowedValue := range allowedBaseURLs {
		normalizedAllowedURL, err := NormalizeBaseURL(allowedValue)
		if err != nil {
			return "", fmt.Errorf("invalid allowed github base url: %w", err)
		}
		if normalizedAllowedURL == normalizedBaseURL {
			return normalizedAllowedURL, nil
		}
	}
	return "", fmt.Errorf("github base url is not allowed")
}

func userEndpoint(baseURL string) string {
	if strings.EqualFold(strings.TrimRight(baseURL, "/"), "https://github.com") {
		return defaultGitHubAPIBaseURL + "/user"
	}
	return strings.TrimRight(baseURL, "/") + "/api/v3/user"
}

func normalizeScopes(raw string) []string {
	parts := strings.Split(raw, ",")
	scopes := make([]string, 0, len(parts))
	seen := map[string]struct{}{}
	for _, part := range parts {
		scope := strings.ToLower(strings.TrimSpace(part))
		if scope == "" {
			continue
		}
		if _, exists := seen[scope]; exists {
			continue
		}
		seen[scope] = struct{}{}
		scopes = append(scopes, scope)
	}
	sort.Strings(scopes)
	return scopes
}

func hasAcceptablePATScopes(scopes []string) bool {
	for _, scope := range scopes {
		if scope == "repo" || scope == "public_repo" {
			return true
		}
	}
	return false
}
