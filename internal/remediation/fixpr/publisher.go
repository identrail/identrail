package fixpr

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
	defaultGitHubAPIBaseURL = "https://api.github.com"
	publisherHTTPTimeout    = 15 * time.Second
)

// PublishResult is the outcome of a successful PR publish.
type PublishResult struct {
	PRNumber   int    `json:"pr_number"`
	PRURL      string `json:"pr_url"`
	BranchName string `json:"branch_name"`
	CommitSHA  string `json:"commit_sha"`
}

// GitHubPublisher publishes a FixPRPlan to a GitHub repository using the Git
// Data API: it reads the base ref, builds blobs + tree + commit, creates the
// branch, then opens a pull request. Authentication uses a short-lived bearer
// token supplied per call so callers can mint installation tokens for the
// target installation.
type GitHubPublisher struct {
	HTTPClient *http.Client
	APIBaseURL string
}

// Publish creates the branch, commit, and PR for the plan in repo {owner}/{name}
// using token as the bearer credential. Returns the created PR metadata.
func (p GitHubPublisher) Publish(ctx context.Context, owner, repo, token string, plan FixPRPlan) (PublishResult, error) {
	if strings.TrimSpace(owner) == "" || strings.TrimSpace(repo) == "" {
		return PublishResult{}, fmt.Errorf("owner and repo are required")
	}
	if strings.TrimSpace(token) == "" {
		return PublishResult{}, fmt.Errorf("github token is required")
	}
	if len(plan.Files) == 0 {
		return PublishResult{}, fmt.Errorf("plan has no files")
	}

	baseRefSHA, baseTreeSHA, err := p.getBaseRef(ctx, owner, repo, token, plan.BaseBranch)
	if err != nil {
		return PublishResult{}, fmt.Errorf("read base branch %q: %w", plan.BaseBranch, err)
	}

	treeEntries := make([]map[string]any, 0, len(plan.Files))
	for _, file := range plan.Files {
		blobSHA, err := p.createBlob(ctx, owner, repo, token, file.Content)
		if err != nil {
			return PublishResult{}, fmt.Errorf("create blob for %s: %w", file.Path, err)
		}
		treeEntries = append(treeEntries, map[string]any{
			"path": file.Path,
			"mode": "100644",
			"type": "blob",
			"sha":  blobSHA,
		})
	}

	treeSHA, err := p.createTree(ctx, owner, repo, token, baseTreeSHA, treeEntries)
	if err != nil {
		return PublishResult{}, fmt.Errorf("create tree: %w", err)
	}
	commitSHA, err := p.createCommit(ctx, owner, repo, token, plan.CommitMessage, treeSHA, baseRefSHA)
	if err != nil {
		return PublishResult{}, fmt.Errorf("create commit: %w", err)
	}
	if err := p.createBranch(ctx, owner, repo, token, plan.BranchName, commitSHA); err != nil {
		return PublishResult{}, fmt.Errorf("create branch %s: %w", plan.BranchName, err)
	}
	prNumber, prURL, err := p.openPullRequest(ctx, owner, repo, token, plan)
	if err != nil {
		return PublishResult{}, fmt.Errorf("open pull request: %w", err)
	}

	return PublishResult{
		PRNumber:   prNumber,
		PRURL:      prURL,
		BranchName: plan.BranchName,
		CommitSHA:  commitSHA,
	}, nil
}

func (p GitHubPublisher) getBaseRef(ctx context.Context, owner, repo, token, base string) (string, string, error) {
	var refBody struct {
		Object struct {
			SHA string `json:"sha"`
		} `json:"object"`
	}
	// GitHub's git refs endpoint expects the branch portion of the path to
	// preserve "/" separators (e.g. "release/2026.05"); escape each segment
	// individually instead of treating the whole ref as one component.
	refPath := fmt.Sprintf("/repos/%s/%s/git/ref/heads/%s", url.PathEscape(owner), url.PathEscape(repo), escapeRefPath(base))
	if err := p.doJSON(ctx, http.MethodGet, refPath, token, nil, &refBody); err != nil {
		return "", "", err
	}
	var commitBody struct {
		Tree struct {
			SHA string `json:"sha"`
		} `json:"tree"`
	}
	commitPath := fmt.Sprintf("/repos/%s/%s/git/commits/%s", url.PathEscape(owner), url.PathEscape(repo), refBody.Object.SHA)
	if err := p.doJSON(ctx, http.MethodGet, commitPath, token, nil, &commitBody); err != nil {
		return "", "", err
	}
	return refBody.Object.SHA, commitBody.Tree.SHA, nil
}

func (p GitHubPublisher) createBlob(ctx context.Context, owner, repo, token, content string) (string, error) {
	var resp struct {
		SHA string `json:"sha"`
	}
	body := map[string]any{"content": content, "encoding": "utf-8"}
	path := fmt.Sprintf("/repos/%s/%s/git/blobs", url.PathEscape(owner), url.PathEscape(repo))
	if err := p.doJSON(ctx, http.MethodPost, path, token, body, &resp); err != nil {
		return "", err
	}
	return resp.SHA, nil
}

func (p GitHubPublisher) createTree(ctx context.Context, owner, repo, token, baseTree string, entries []map[string]any) (string, error) {
	var resp struct {
		SHA string `json:"sha"`
	}
	body := map[string]any{"base_tree": baseTree, "tree": entries}
	path := fmt.Sprintf("/repos/%s/%s/git/trees", url.PathEscape(owner), url.PathEscape(repo))
	if err := p.doJSON(ctx, http.MethodPost, path, token, body, &resp); err != nil {
		return "", err
	}
	return resp.SHA, nil
}

func (p GitHubPublisher) createCommit(ctx context.Context, owner, repo, token, message, tree, parent string) (string, error) {
	var resp struct {
		SHA string `json:"sha"`
	}
	body := map[string]any{
		"message": message,
		"tree":    tree,
		"parents": []string{parent},
	}
	path := fmt.Sprintf("/repos/%s/%s/git/commits", url.PathEscape(owner), url.PathEscape(repo))
	if err := p.doJSON(ctx, http.MethodPost, path, token, body, &resp); err != nil {
		return "", err
	}
	return resp.SHA, nil
}

func (p GitHubPublisher) createBranch(ctx context.Context, owner, repo, token, branch, sha string) error {
	body := map[string]any{
		"ref": "refs/heads/" + branch,
		"sha": sha,
	}
	path := fmt.Sprintf("/repos/%s/%s/git/refs", url.PathEscape(owner), url.PathEscape(repo))
	return p.doJSON(ctx, http.MethodPost, path, token, body, nil)
}

func (p GitHubPublisher) openPullRequest(ctx context.Context, owner, repo, token string, plan FixPRPlan) (int, string, error) {
	var resp struct {
		Number  int    `json:"number"`
		HTMLURL string `json:"html_url"`
	}
	body := map[string]any{
		"title": plan.PRTitle,
		"head":  plan.BranchName,
		"base":  plan.BaseBranch,
		"body":  plan.PRBody,
	}
	path := fmt.Sprintf("/repos/%s/%s/pulls", url.PathEscape(owner), url.PathEscape(repo))
	if err := p.doJSON(ctx, http.MethodPost, path, token, body, &resp); err != nil {
		return 0, "", err
	}
	return resp.Number, resp.HTMLURL, nil
}

func (p GitHubPublisher) doJSON(ctx context.Context, method, path, token string, payload any, out any) error {
	var reqBody io.Reader
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("encode request: %w", err)
		}
		reqBody = bytes.NewReader(raw)
	}
	full := strings.TrimRight(p.apiBaseURL(), "/") + path
	req, err := http.NewRequestWithContext(ctx, method, full, reqBody)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+token)
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	res, err := p.httpClient().Do(req)
	if err != nil {
		return fmt.Errorf("github request: %w", err)
	}
	defer res.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		snippet := strings.TrimSpace(string(body))
		if len(snippet) > 200 {
			snippet = snippet[:200] + "..."
		}
		return fmt.Errorf("github %s %s: status %d: %s", method, path, res.StatusCode, snippet)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("decode github response: %w", err)
	}
	return nil
}

// escapeRefPath escapes a git ref so it can be safely interpolated into a URL
// path while preserving the "/" separators that GitHub's ref endpoints require.
func escapeRefPath(ref string) string {
	parts := strings.Split(ref, "/")
	for i, segment := range parts {
		parts[i] = url.PathEscape(segment)
	}
	return strings.Join(parts, "/")
}

func (p GitHubPublisher) apiBaseURL() string {
	if p.APIBaseURL != "" {
		return p.APIBaseURL
	}
	return defaultGitHubAPIBaseURL
}

func (p GitHubPublisher) httpClient() *http.Client {
	if p.HTTPClient != nil {
		return p.HTTPClient
	}
	return &http.Client{Timeout: publisherHTTPTimeout}
}
