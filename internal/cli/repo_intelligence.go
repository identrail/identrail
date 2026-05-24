package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/identrail/identrail/internal/api"
	"github.com/identrail/identrail/internal/config"
	githubconnector "github.com/identrail/identrail/internal/connectors/github"
	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/domain"
	"github.com/spf13/cobra"
)

type cliAPIOptions struct {
	APIURL      string
	APIKey      string
	TenantID    string
	WorkspaceID string
	Timeout     time.Duration
}

const defaultCLIAPITimeout = 10 * time.Second

type cliAPIErrorResponse struct {
	Error string `json:"error"`
}

type repoScanCLIResponse struct {
	RepoScan db.RepoScanRecord `json:"repo_scan"`
}

type repoScanPageCLIResponse struct {
	Items      []db.RepoScanRecord `json:"items"`
	NextCursor string              `json:"next_cursor,omitempty"`
}

type repoFindingPageCLIResponse struct {
	Items      []domain.Finding         `json:"items"`
	Summary    *api.RepoFindingsSummary `json:"summary,omitempty"`
	NextCursor string                   `json:"next_cursor,omitempty"`
}

func defaultCLIAPIOptions(cfg config.Config) cliAPIOptions {
	return cliAPIOptions{
		APIURL:      defaultCLIAPIURL(),
		APIKey:      strings.TrimSpace(os.Getenv("IDENTRAIL_API_KEY")),
		TenantID:    strings.TrimSpace(cfg.DefaultTenantID),
		WorkspaceID: strings.TrimSpace(cfg.DefaultWorkspaceID),
		Timeout:     defaultCLIAPITimeout,
	}
}

func bindCLIAPIFlags(cmd *cobra.Command, options *cliAPIOptions, apiKeyUse string) {
	cmd.Flags().StringVar(&options.APIURL, "api-url", options.APIURL, "Identrail API base URL")
	cmd.Flags().StringVar(&options.APIKey, "api-key", options.APIKey, apiKeyUse)
	cmd.Flags().StringVar(&options.TenantID, "tenant-id", options.TenantID, "Tenant scope header")
	cmd.Flags().StringVar(&options.WorkspaceID, "workspace-id", options.WorkspaceID, "Workspace scope header")
	cmd.Flags().DurationVar(&options.Timeout, "timeout", options.Timeout, "HTTP timeout")
}

func normalizeCLIAPITimeout(timeout time.Duration) time.Duration {
	if timeout <= 0 {
		return defaultCLIAPITimeout
	}
	return timeout
}

func newCLIAPIRequestContext(options cliAPIOptions) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), normalizeCLIAPITimeout(options.Timeout))
}

func doCLIAPIRequest(ctx context.Context, options cliAPIOptions, method string, path string, query url.Values, payload any, response any) error {
	apiURL := strings.TrimRight(strings.TrimSpace(options.APIURL), "/")
	if apiURL == "" {
		return fmt.Errorf("--api-url is required")
	}
	fullURL := apiURL + path
	if len(query) > 0 {
		fullURL += "?" + query.Encode()
	}

	var body io.Reader
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("encode request: %w", err)
		}
		body = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, fullURL, body)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if normalizedKey := strings.TrimSpace(options.APIKey); normalizedKey != "" {
		req.Header.Set("X-API-Key", normalizedKey)
	}
	if normalizedTenant := strings.TrimSpace(options.TenantID); normalizedTenant != "" {
		req.Header.Set("X-Identrail-Tenant-ID", normalizedTenant)
	}
	if normalizedWorkspace := strings.TrimSpace(options.WorkspaceID); normalizedWorkspace != "" {
		req.Header.Set("X-Identrail-Workspace-ID", normalizedWorkspace)
	}

	resp, err := (&http.Client{Timeout: normalizeCLIAPITimeout(options.Timeout)}).Do(req)
	if err != nil {
		return fmt.Errorf("api request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var apiErr cliAPIErrorResponse
		if err := json.NewDecoder(resp.Body).Decode(&apiErr); err == nil && strings.TrimSpace(apiErr.Error) != "" {
			return fmt.Errorf("api request failed: %s (status %d)", strings.TrimSpace(apiErr.Error), resp.StatusCode)
		}
		return fmt.Errorf("api request failed with status %d", resp.StatusCode)
	}

	if response == nil {
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(response); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

func buildRepoScanQueueCmd(cfg config.Config, out io.Writer) *cobra.Command {
	options := defaultCLIAPIOptions(cfg)
	var (
		repository   string
		projectID    string
		connectorID  string
		scanMode     string
		baseRevision string
		headRevision string
		changedPaths []string
		historyLimit int
		maxFindings  int
		outputFormat string
	)

	cmd := &cobra.Command{
		Use:   "queue",
		Short: "Queue an API-backed repository intelligence scan",
		RunE: func(_ *cobra.Command, _ []string) error {
			if strings.TrimSpace(repository) == "" {
				return fmt.Errorf("--repo is required")
			}
			if strings.TrimSpace(connectorID) != "" && strings.TrimSpace(projectID) == "" {
				return fmt.Errorf("--project-id is required when --connector-id is set")
			}
			if historyLimit < 0 {
				return fmt.Errorf("--history-limit must be zero or greater")
			}
			if maxFindings < 0 {
				return fmt.Errorf("--max-findings must be zero or greater")
			}
			if err := validateRepoScanMode(scanMode); err != nil {
				return err
			}
			formatter, err := parseOutputFormat(outputFormat)
			if err != nil {
				return err
			}

			request := api.RepoScanRequest{
				Repository:   strings.TrimSpace(repository),
				ProjectID:    strings.TrimSpace(projectID),
				ConnectorID:  strings.TrimSpace(connectorID),
				ScanMode:     strings.TrimSpace(scanMode),
				BaseRevision: strings.TrimSpace(baseRevision),
				HeadRevision: strings.TrimSpace(headRevision),
				ChangedPaths: normalizeCLIStringSlice(changedPaths),
				HistoryLimit: historyLimit,
				MaxFindings:  maxFindings,
			}
			var response repoScanCLIResponse
			ctx, cancel := newCLIAPIRequestContext(options)
			defer cancel()
			if err := doCLIAPIRequest(ctx, options, http.MethodPost, "/v1/repo-scans", nil, request, &response); err != nil {
				return err
			}
			switch formatter {
			case outputJSON:
				return writeJSON(out, response)
			default:
				return renderRepoScanQueuedOutput(out, response.RepoScan)
			}
		},
	}

	bindCLIAPIFlags(cmd, &options, "API key used to queue repository scans")
	cmd.Flags().StringVar(&repository, "repo", "", "Repository target (owner/repo)")
	cmd.Flags().StringVar(&projectID, "project-id", "", "Project ID for GitHub App private repository scans")
	cmd.Flags().StringVar(&connectorID, "connector-id", "", "Connector ID for GitHub App private repository scans")
	cmd.Flags().StringVar(&scanMode, "scan-mode", "", "Scan mode: quick|delta|deep (empty uses server default)")
	cmd.Flags().StringVar(&baseRevision, "base-revision", "", "Base revision for delta scans")
	cmd.Flags().StringVar(&headRevision, "head-revision", "", "Head revision for delta scans")
	cmd.Flags().StringSliceVar(&changedPaths, "changed-path", nil, "Changed path for quick or delta scans (repeatable or comma-separated)")
	cmd.Flags().IntVar(&historyLimit, "history-limit", 0, "Maximum commits to inspect (0 uses server default)")
	cmd.Flags().IntVar(&maxFindings, "max-findings", 0, "Maximum findings to emit (0 uses server default)")
	cmd.Flags().StringVar(&outputFormat, "output", formatTable, "Output format: table|json")
	return cmd
}

func buildRepoScanListCmd(cfg config.Config, out io.Writer) *cobra.Command {
	options := defaultCLIAPIOptions(cfg)
	var (
		limit        int
		cursor       string
		sortBy       string
		sortOrder    string
		outputFormat string
	)
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List API-backed repository scans",
		RunE: func(_ *cobra.Command, _ []string) error {
			if limit < 1 {
				return fmt.Errorf("--limit must be at least 1")
			}
			formatter, err := parseOutputFormat(outputFormat)
			if err != nil {
				return err
			}
			query := url.Values{}
			addCLIQueryInt(query, "limit", limit)
			addCLIQuery(query, "cursor", cursor)
			addCLIQuery(query, "sort_by", sortBy)
			addCLIQuery(query, "sort_order", sortOrder)

			var response repoScanPageCLIResponse
			ctx, cancel := newCLIAPIRequestContext(options)
			defer cancel()
			if err := doCLIAPIRequest(ctx, options, http.MethodGet, "/v1/repo-scans", query, nil, &response); err != nil {
				return err
			}
			switch formatter {
			case outputJSON:
				return writeJSON(out, response)
			default:
				return renderRepoScanListOutput(out, response)
			}
		},
	}
	bindCLIAPIFlags(cmd, &options, "API key used to list repository scans")
	cmd.Flags().IntVar(&limit, "limit", 20, "Maximum repository scans to list")
	cmd.Flags().StringVar(&cursor, "cursor", "", "Pagination cursor")
	cmd.Flags().StringVar(&sortBy, "sort-by", "started_at", "Sort field")
	cmd.Flags().StringVar(&sortOrder, "sort-order", "desc", "Sort order: asc|desc")
	cmd.Flags().StringVar(&outputFormat, "output", formatTable, "Output format: table|json")
	return cmd
}

func buildRepoScanShowCmd(cfg config.Config, out io.Writer) *cobra.Command {
	options := defaultCLIAPIOptions(cfg)
	var outputFormat string
	cmd := &cobra.Command{
		Use:   "show <repo-scan-id>",
		Short: "Show one API-backed repository scan",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			formatter, err := parseOutputFormat(outputFormat)
			if err != nil {
				return err
			}
			var response db.RepoScanRecord
			ctx, cancel := newCLIAPIRequestContext(options)
			defer cancel()
			path := "/v1/repo-scans/" + url.PathEscape(strings.TrimSpace(args[0]))
			if err := doCLIAPIRequest(ctx, options, http.MethodGet, path, nil, nil, &response); err != nil {
				return err
			}
			switch formatter {
			case outputJSON:
				return writeJSON(out, response)
			default:
				return renderRepoScanRecordOutput(out, response)
			}
		},
	}
	bindCLIAPIFlags(cmd, &options, "API key used to read repository scans")
	cmd.Flags().StringVar(&outputFormat, "output", formatTable, "Output format: table|json")
	return cmd
}

func buildRepoScanCancelCmd(cfg config.Config, out io.Writer) *cobra.Command {
	options := defaultCLIAPIOptions(cfg)
	var outputFormat string
	cmd := &cobra.Command{
		Use:   "cancel <repo-scan-id>",
		Short: "Cancel a queued or running API-backed repository scan",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			formatter, err := parseOutputFormat(outputFormat)
			if err != nil {
				return err
			}
			var response repoScanCLIResponse
			ctx, cancel := newCLIAPIRequestContext(options)
			defer cancel()
			path := "/v1/repo-scans/" + url.PathEscape(strings.TrimSpace(args[0])) + "/cancel"
			if err := doCLIAPIRequest(ctx, options, http.MethodPost, path, nil, nil, &response); err != nil {
				return err
			}
			switch formatter {
			case outputJSON:
				return writeJSON(out, response)
			default:
				return renderRepoScanCanceledOutput(out, response.RepoScan)
			}
		},
	}
	bindCLIAPIFlags(cmd, &options, "API key used to cancel repository scans")
	cmd.Flags().StringVar(&outputFormat, "output", formatTable, "Output format: table|json")
	return cmd
}

func buildRepoFindingsCmd(cfg config.Config, out io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "repo-findings",
		Short: "Repository finding intelligence",
	}
	cmd.AddCommand(buildRepoFindingsListCmd(cfg, out))
	return cmd
}

func buildRepoFindingsListCmd(cfg config.Config, out io.Writer) *cobra.Command {
	options := defaultCLIAPIOptions(cfg)
	var (
		limit           int
		cursor          string
		repoScanID      string
		repository      string
		severity        string
		findingType     string
		lifecycleStatus string
		detector        string
		owner           string
		minConfidence   float64
		minAgeDays      int
		sortBy          string
		sortOrder       string
		outputFormat    string
	)
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List repository findings with lifecycle and confidence filters",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if limit < 1 {
				return fmt.Errorf("--limit must be at least 1")
			}
			if cmd.Flags().Changed("min-confidence") && (minConfidence < 0 || minConfidence > 1) {
				return fmt.Errorf("--min-confidence must be between 0 and 1")
			}
			if minAgeDays < 0 {
				return fmt.Errorf("--min-age-days must be zero or greater")
			}
			formatter, err := parseOutputFormat(outputFormat)
			if err != nil {
				return err
			}
			query := url.Values{}
			addCLIQueryInt(query, "limit", limit)
			addCLIQuery(query, "cursor", cursor)
			addCLIQuery(query, "repo_scan_id", repoScanID)
			addCLIQuery(query, "repository", repository)
			addCLIQuery(query, "severity", severity)
			addCLIQuery(query, "type", findingType)
			addCLIQuery(query, "repo_lifecycle_status", lifecycleStatus)
			addCLIQuery(query, "detector", detector)
			addCLIQuery(query, "owner", owner)
			if minConfidence >= 0 {
				query.Set("min_confidence", fmt.Sprintf("%.4f", minConfidence))
			}
			if minAgeDays > 0 {
				addCLIQueryInt(query, "min_age_days", minAgeDays)
			}
			addCLIQuery(query, "sort_by", sortBy)
			addCLIQuery(query, "sort_order", sortOrder)

			var response repoFindingPageCLIResponse
			ctx, cancel := newCLIAPIRequestContext(options)
			defer cancel()
			if err := doCLIAPIRequest(ctx, options, http.MethodGet, "/v1/repo-findings", query, nil, &response); err != nil {
				return err
			}
			switch formatter {
			case outputJSON:
				return writeJSON(out, response)
			default:
				return renderRepoFindingsListOutput(out, response)
			}
		},
	}
	bindCLIAPIFlags(cmd, &options, "API key used to list repository findings")
	cmd.Flags().IntVar(&limit, "limit", 25, "Maximum repository findings to list")
	cmd.Flags().StringVar(&cursor, "cursor", "", "Pagination cursor")
	cmd.Flags().StringVar(&repoScanID, "repo-scan-id", "", "Filter by repository scan ID")
	cmd.Flags().StringVar(&repository, "repo", "", "Filter by repository")
	cmd.Flags().StringVar(&severity, "severity", "", "Filter by severity")
	cmd.Flags().StringVar(&findingType, "type", "", "Filter by finding type")
	cmd.Flags().StringVar(&lifecycleStatus, "status", "", "Filter by repository finding lifecycle status")
	cmd.Flags().StringVar(&detector, "detector", "", "Filter by detector")
	cmd.Flags().StringVar(&owner, "owner", "", "Filter by owner")
	cmd.Flags().Float64Var(&minConfidence, "min-confidence", -1, "Minimum confidence score from 0 to 1")
	cmd.Flags().IntVar(&minAgeDays, "min-age-days", 0, "Minimum finding age in days")
	cmd.Flags().StringVar(&sortBy, "sort-by", "created_at", "Sort field")
	cmd.Flags().StringVar(&sortOrder, "sort-order", "desc", "Sort order: asc|desc")
	cmd.Flags().StringVar(&outputFormat, "output", formatTable, "Output format: table|json")
	return cmd
}

func buildRepoRiskGraphCmd(cfg config.Config, out io.Writer) *cobra.Command {
	options := defaultCLIAPIOptions(cfg)
	var (
		repoScanID    string
		repository    string
		defaultBranch string
		severity      string
		findingType   string
		outputFormat  string
	)
	cmd := &cobra.Command{
		Use:   "repo-risk-graph",
		Short: "Fetch the repository-to-machine-identity risk graph",
		RunE: func(_ *cobra.Command, _ []string) error {
			formatter, err := parseOutputFormat(outputFormat)
			if err != nil {
				return err
			}
			query := url.Values{}
			addCLIQuery(query, "repo_scan_id", repoScanID)
			addCLIQuery(query, "repository", repository)
			addCLIQuery(query, "default_branch", defaultBranch)
			addCLIQuery(query, "severity", severity)
			addCLIQuery(query, "type", findingType)

			var graph domain.RepoRiskGraph
			ctx, cancel := newCLIAPIRequestContext(options)
			defer cancel()
			if err := doCLIAPIRequest(ctx, options, http.MethodGet, "/v1/repo-risk-graph", query, nil, &graph); err != nil {
				return err
			}
			switch formatter {
			case outputJSON:
				return writeJSON(out, graph)
			default:
				return renderRepoRiskGraphOutput(out, graph)
			}
		},
	}
	bindCLIAPIFlags(cmd, &options, "API key used to read repository risk graphs")
	cmd.Flags().StringVar(&repoScanID, "repo-scan-id", "", "Filter by repository scan ID")
	cmd.Flags().StringVar(&repository, "repo", "", "Filter by repository")
	cmd.Flags().StringVar(&defaultBranch, "default-branch", "", "Default branch used when graph evidence omits branch context")
	cmd.Flags().StringVar(&severity, "severity", "", "Filter graph findings by severity")
	cmd.Flags().StringVar(&findingType, "type", "", "Filter graph findings by type")
	cmd.Flags().StringVar(&outputFormat, "output", formatTable, "Output format: table|json")
	return cmd
}

func buildRepoPostureCmd(cfg config.Config, out io.Writer) *cobra.Command {
	options := defaultCLIAPIOptions(cfg)
	var (
		connectorID  string
		projectID    string
		repository   string
		outputFormat string
	)
	cmd := &cobra.Command{
		Use:   "repo-posture",
		Short: "Collect GitHub repository posture through a GitHub App connector",
		RunE: func(_ *cobra.Command, _ []string) error {
			if strings.TrimSpace(connectorID) == "" {
				return fmt.Errorf("--connector-id is required")
			}
			if strings.TrimSpace(projectID) == "" {
				return fmt.Errorf("--project-id is required")
			}
			if strings.TrimSpace(repository) == "" {
				return fmt.Errorf("--repo is required")
			}
			formatter, err := parseOutputFormat(outputFormat)
			if err != nil {
				return err
			}
			query := url.Values{}
			addCLIQuery(query, "workspace_id", options.WorkspaceID)
			addCLIQuery(query, "project_id", projectID)
			addCLIQuery(query, "repository", repository)
			path := "/v1/connectors/github/" + url.PathEscape(strings.TrimSpace(connectorID)) + "/posture"

			var response api.GitHubRepositoryPostureResponse
			ctx, cancel := newCLIAPIRequestContext(options)
			defer cancel()
			if err := doCLIAPIRequest(ctx, options, http.MethodGet, path, query, nil, &response); err != nil {
				return err
			}
			switch formatter {
			case outputJSON:
				return writeJSON(out, response)
			default:
				return renderRepoPostureOutput(out, response)
			}
		},
	}
	bindCLIAPIFlags(cmd, &options, "API key used to collect GitHub repository posture")
	cmd.Flags().StringVar(&connectorID, "connector-id", "", "GitHub connector ID")
	cmd.Flags().StringVar(&projectID, "project-id", "", "Project ID that owns the GitHub connector")
	cmd.Flags().StringVar(&repository, "repo", "", "Repository target (owner/repo)")
	cmd.Flags().StringVar(&outputFormat, "output", formatTable, "Output format: table|json")
	return cmd
}

func buildRepoRemediationCmd(cfg config.Config, out io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "repo-remediation",
		Short: "Repository finding remediation intelligence",
	}
	cmd.AddCommand(buildRepoRemediationPreviewCmd(cfg, out))
	return cmd
}

func buildRepoRemediationPreviewCmd(cfg config.Config, out io.Writer) *cobra.Command {
	options := defaultCLIAPIOptions(cfg)
	var (
		repoScanID     string
		sourceFile     string
		sourceContent  string
		baseBranch     string
		branchPrefix   string
		findingURL     string
		requireFixPlan bool
		outputFormat   string
	)
	cmd := &cobra.Command{
		Use:   "preview <finding-id>",
		Short: "Preview safe remediation for one repository finding",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if strings.TrimSpace(sourceFile) != "" && strings.TrimSpace(sourceContent) != "" {
				return fmt.Errorf("use either --source-file or --source-content, not both")
			}
			formatter, err := parseOutputFormat(outputFormat)
			if err != nil {
				return err
			}
			content := sourceContent
			if strings.TrimSpace(sourceFile) != "" {
				data, err := os.ReadFile(strings.TrimSpace(sourceFile))
				if err != nil {
					return fmt.Errorf("read source file: %w", err)
				}
				content = string(data)
			}
			request := api.RepoFindingRemediationPreviewRequest{
				RepoScanID:     strings.TrimSpace(repoScanID),
				SourceContent:  content,
				BaseBranch:     strings.TrimSpace(baseBranch),
				BranchPrefix:   strings.TrimSpace(branchPrefix),
				FindingURL:     strings.TrimSpace(findingURL),
				RequireFixPlan: requireFixPlan,
			}
			query := url.Values{}
			addCLIQuery(query, "repo_scan_id", repoScanID)
			path := "/v1/repo-findings/" + url.PathEscape(strings.TrimSpace(args[0])) + "/remediation/preview"

			var response api.RepoFindingRemediationPreview
			ctx, cancel := newCLIAPIRequestContext(options)
			defer cancel()
			if err := doCLIAPIRequest(ctx, options, http.MethodPost, path, query, request, &response); err != nil {
				return err
			}
			switch formatter {
			case outputJSON:
				return writeJSON(out, response)
			default:
				return renderRepoRemediationPreviewOutput(out, response)
			}
		},
	}
	bindCLIAPIFlags(cmd, &options, "API key used to preview repository remediation")
	cmd.Flags().StringVar(&repoScanID, "repo-scan-id", "", "Repository scan ID for finding lookup")
	cmd.Flags().StringVar(&sourceFile, "source-file", "", "Path to source file content for deterministic patch preview")
	cmd.Flags().StringVar(&sourceContent, "source-content", "", "Inline source content for deterministic patch preview")
	cmd.Flags().StringVar(&baseBranch, "base-branch", "", "Base branch for generated fix PR plan")
	cmd.Flags().StringVar(&branchPrefix, "branch-prefix", "", "Branch prefix for generated fix PR plan")
	cmd.Flags().StringVar(&findingURL, "finding-url", "", "URL to include in generated remediation context")
	cmd.Flags().BoolVar(&requireFixPlan, "require-fix-plan", false, "Fail unless a deterministic fix PR plan can be produced")
	cmd.Flags().StringVar(&outputFormat, "output", formatTable, "Output format: table|json")
	return cmd
}

func validateRepoScanMode(mode string) error {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", "quick", "delta", "deep":
		return nil
	default:
		return fmt.Errorf("--scan-mode must be quick, delta, or deep")
	}
}

func normalizeCLIStringSlice(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			trimmed := strings.TrimSpace(part)
			if trimmed != "" {
				normalized = append(normalized, trimmed)
			}
		}
	}
	return normalized
}

func addCLIQuery(query url.Values, key string, value string) {
	if normalized := strings.TrimSpace(value); normalized != "" {
		query.Set(key, normalized)
	}
}

func addCLIQueryInt(query url.Values, key string, value int) {
	if value > 0 {
		query.Set(key, fmt.Sprintf("%d", value))
	}
}

func renderRepoScanQueuedOutput(out io.Writer, scan db.RepoScanRecord) error {
	_, err := fmt.Fprintf(
		out,
		"Repo scan queued: id=%s repo=%s status=%s mode=%s\n",
		scan.ID,
		scan.Repository,
		scan.Status,
		formatOptionalString(scan.ScanMode, "deep"),
	)
	return err
}

func renderRepoScanCanceledOutput(out io.Writer, scan db.RepoScanRecord) error {
	_, err := fmt.Fprintf(
		out,
		"Repo scan canceled: id=%s repo=%s status=%s\n",
		scan.ID,
		scan.Repository,
		scan.Status,
	)
	return err
}

func renderRepoScanListOutput(out io.Writer, response repoScanPageCLIResponse) error {
	if _, err := fmt.Fprintf(out, "Repo scans: %d\n", len(response.Items)); err != nil {
		return err
	}
	if len(response.Items) == 0 {
		if _, err := fmt.Fprintln(out, "No repository scans."); err != nil {
			return err
		}
	} else {
		for i, scan := range response.Items {
			if err := renderRepoScanRecordLine(out, i+1, scan); err != nil {
				return err
			}
		}
	}
	if response.NextCursor != "" {
		_, err := fmt.Fprintf(out, "Next cursor: %s\n", response.NextCursor)
		return err
	}
	return nil
}

func renderRepoScanRecordOutput(out io.Writer, scan db.RepoScanRecord) error {
	if err := renderRepoScanRecordLine(out, 1, scan); err != nil {
		return err
	}
	if scan.ErrorMessage != "" {
		_, err := fmt.Fprintf(out, "   error=%s\n", scan.ErrorMessage)
		return err
	}
	return nil
}

func renderRepoScanRecordLine(out io.Writer, index int, scan db.RepoScanRecord) error {
	finished := "running"
	if scan.FinishedAt != nil {
		finished = scan.FinishedAt.Format(time.RFC3339)
	}
	_, err := fmt.Fprintf(
		out,
		"%d. %s repo=%s status=%s mode=%s findings=%d files=%d commits=%d finished=%s\n",
		index,
		scan.ID,
		scan.Repository,
		scan.Status,
		formatOptionalString(scan.ScanMode, "deep"),
		scan.FindingCount,
		scan.FilesScanned,
		scan.CommitsScanned,
		finished,
	)
	return err
}

func renderRepoFindingsListOutput(out io.Writer, response repoFindingPageCLIResponse) error {
	if response.Summary != nil {
		if _, err := fmt.Fprintf(
			out,
			"Repo findings: %d listed | open=%d fixed=%d reopened=%d suppressed=%d sla_aged=%d\n",
			len(response.Items),
			response.Summary.TotalOpen,
			response.Summary.FixedCount,
			response.Summary.ReopenedCount,
			response.Summary.SuppressedCount,
			response.Summary.SLAAgedCount,
		); err != nil {
			return err
		}
	} else if _, err := fmt.Fprintf(out, "Repo findings: %d\n", len(response.Items)); err != nil {
		return err
	}
	if len(response.Items) == 0 {
		if _, err := fmt.Fprintln(out, "No repository findings."); err != nil {
			return err
		}
	} else {
		for i, finding := range response.Items {
			if err := renderRepoFindingLine(out, i+1, finding); err != nil {
				return err
			}
		}
	}
	if response.NextCursor != "" {
		_, err := fmt.Fprintf(out, "Next cursor: %s\n", response.NextCursor)
		return err
	}
	return nil
}

func renderRepoFindingLine(out io.Writer, index int, finding domain.Finding) error {
	location := finding.Repository
	if finding.FilePath != "" {
		location = strings.Trim(strings.Join([]string{finding.Repository, finding.FilePath}, " "), " ")
		if finding.LineNumber > 0 {
			location = fmt.Sprintf("%s:%d", location, finding.LineNumber)
		}
	}
	if strings.TrimSpace(location) == "" {
		location = "unknown location"
	}
	if _, err := fmt.Fprintf(
		out,
		"%d. [%s] %s (%s)\n",
		index,
		strings.ToUpper(string(finding.Severity)),
		finding.Title,
		finding.Type,
	); err != nil {
		return err
	}
	_, err := fmt.Fprintf(
		out,
		"   %s detector=%s status=%s confidence=%.2f owner=%s\n   %s\n",
		location,
		formatOptionalString(finding.Detector, "unknown"),
		formatOptionalString(string(finding.LifecycleStatus), "open"),
		finding.ConfidenceScore,
		formatOptionalString(finding.Owner, "unassigned"),
		finding.HumanSummary,
	)
	return err
}

func renderRepoRiskGraphOutput(out io.Writer, graph domain.RepoRiskGraph) error {
	if _, err := fmt.Fprintf(
		out,
		"Repo risk graph: repo=%s findings=%d nodes=%d edges=%d high_risk=%d critical=%d unknown_nodes=%d unknown_edges=%d\n",
		formatOptionalString(graph.Repository, "all"),
		graph.Summary.FindingCount,
		graph.Summary.NodeCount,
		graph.Summary.EdgeCount,
		graph.Summary.HighRiskFindings,
		graph.Summary.CriticalFindings,
		graph.Summary.UnknownNodeCount,
		graph.Summary.UnknownEdgeCount,
	); err != nil {
		return err
	}
	if len(graph.Scores) == 0 {
		_, err := fmt.Fprintln(out, "No scored findings.")
		return err
	}
	scores := append([]domain.RepoRiskGraphFindingScore(nil), graph.Scores...)
	sort.SliceStable(scores, func(i, j int) bool {
		return scores[i].Score > scores[j].Score
	})
	limit := len(scores)
	if limit > 5 {
		limit = 5
	}
	for i := 0; i < limit; i++ {
		score := scores[i]
		unknowns := "none"
		if len(score.Unknowns) > 0 {
			unknowns = strings.Join(score.Unknowns, ",")
		}
		if _, err := fmt.Fprintf(
			out,
			"%d. finding=%s score=%d severity=%s confidence=%.2f unknowns=%s\n",
			i+1,
			score.FindingID,
			score.Score,
			score.Severity,
			score.Confidence,
			unknowns,
		); err != nil {
			return err
		}
	}
	return nil
}

func renderRepoPostureOutput(out io.Writer, response api.GitHubRepositoryPostureResponse) error {
	posture := response.Posture
	counts := countPostureStates(posture.Checks)
	if _, err := fmt.Fprintf(
		out,
		"GitHub posture: repo=%s connector=%s provider=%s checks=%d insecure=%d permission_limited=%d unavailable=%d unsupported=%d unknown=%d collected_at=%s\n",
		posture.Repository,
		response.ConnectorID,
		response.Provider,
		len(posture.Checks),
		counts.insecure,
		counts.limited,
		counts.unavailable,
		counts.unsupported,
		counts.unknown,
		posture.CollectedAt.Format(time.RFC3339),
	); err != nil {
		return err
	}
	if len(posture.Checks) == 0 {
		if _, err := fmt.Fprintln(out, "No posture checks."); err != nil {
			return err
		}
	}
	if err := renderPostureChecks(out, posture.Checks); err != nil {
		return err
	}
	return renderOrgPostureSection(out, response.OrganizationPosture)
}

func renderOrgPostureSection(out io.Writer, posture *githubconnector.OrganizationPosture) error {
	if posture == nil {
		_, err := fmt.Fprintln(out, "Organization posture: not collected (repository owner is not an accessible organization).")
		return err
	}
	counts := countPostureStates(posture.Checks)
	if _, err := fmt.Fprintf(
		out,
		"Organization posture (inherited): org=%s checks=%d insecure=%d permission_limited=%d unavailable=%d unsupported=%d unknown=%d collected_at=%s\n",
		posture.Organization,
		len(posture.Checks),
		counts.insecure,
		counts.limited,
		counts.unavailable,
		counts.unsupported,
		counts.unknown,
		posture.CollectedAt.Format(time.RFC3339),
	); err != nil {
		return err
	}
	return renderPostureChecks(out, posture.Checks)
}

func renderPostureChecks(out io.Writer, checks []githubconnector.RepositoryPostureCheck) error {
	for i, check := range checks {
		if _, err := fmt.Fprintf(
			out,
			"%d. [%s] %s/%s - %s\n",
			i+1,
			strings.ToUpper(string(check.State)),
			check.Category,
			check.ID,
			check.Summary,
		); err != nil {
			return err
		}
		if strings.TrimSpace(check.Reason) != "" {
			if _, err := fmt.Fprintf(out, "   reason=%s\n", check.Reason); err != nil {
				return err
			}
		}
	}
	return nil
}

type postureStateCounts struct {
	insecure    int
	limited     int
	unavailable int
	unsupported int
	unknown     int
}

func countPostureStates(checks []githubconnector.RepositoryPostureCheck) postureStateCounts {
	var counts postureStateCounts
	for _, check := range checks {
		switch check.State {
		case githubconnector.RepositoryPostureStateInsecure:
			counts.insecure++
		case githubconnector.RepositoryPostureStatePermissionLimited:
			counts.limited++
		case githubconnector.RepositoryPostureStateUnavailable:
			counts.unavailable++
		case githubconnector.RepositoryPostureStateUnsupported:
			counts.unsupported++
		case githubconnector.RepositoryPostureStateUnknown:
			counts.unknown++
		}
	}
	return counts
}

func renderRepoRemediationPreviewOutput(out io.Writer, response api.RepoFindingRemediationPreview) error {
	remediation := response.Remediation
	if _, err := fmt.Fprintf(
		out,
		"Repo remediation: finding=%s detector=%s publishable=%t fix_plan=%t\n",
		response.Finding.ID,
		remediation.Detector,
		remediation.Publishable,
		response.FixPRPlan != nil,
	); err != nil {
		return err
	}
	if strings.TrimSpace(remediation.RiskSummary) != "" {
		if _, err := fmt.Fprintf(out, "Risk: %s\n", remediation.RiskSummary); err != nil {
			return err
		}
	}
	if len(remediation.Steps) > 0 {
		if _, err := fmt.Fprintln(out, "Steps:"); err != nil {
			return err
		}
		for _, step := range remediation.Steps {
			if _, err := fmt.Fprintf(out, "- %s\n", step); err != nil {
				return err
			}
		}
	}
	if len(remediation.SafetyNotes) > 0 {
		if _, err := fmt.Fprintln(out, "Safety notes:"); err != nil {
			return err
		}
		for _, note := range remediation.SafetyNotes {
			if _, err := fmt.Fprintf(out, "- %s\n", note); err != nil {
				return err
			}
		}
	}
	if response.FixPRPlan != nil {
		_, err := fmt.Fprintf(
			out,
			"Fix PR plan: branch=%s base=%s files=%d title=%s\n",
			response.FixPRPlan.BranchName,
			response.FixPRPlan.BaseBranch,
			len(response.FixPRPlan.Files),
			response.FixPRPlan.PRTitle,
		)
		return err
	}
	if remediation.PublishBlockedReason != "" {
		_, err := fmt.Fprintf(out, "Publish blocked: %s\n", remediation.PublishBlockedReason)
		return err
	}
	return nil
}

func formatOptionalString(value string, fallback string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return fallback
	}
	return trimmed
}
