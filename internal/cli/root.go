package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/identrail/identrail/internal/app"
	"github.com/identrail/identrail/internal/config"
	"github.com/identrail/identrail/internal/domain"
	awsprovider "github.com/identrail/identrail/internal/providers/aws"
	k8sprovider "github.com/identrail/identrail/internal/providers/kubernetes"
	"github.com/identrail/identrail/internal/repoexposure"
	"github.com/spf13/cobra"
)

const (
	defaultStateFile = ".identrail/last-findings.json"
	formatTable      = "table"
	formatJSON       = "json"
	defaultAPIURL    = "http://127.0.0.1:8080"
	defaultPolicySet = "central_authorization"
)

var defaultAWSFixturePaths = []string{
	"testdata/aws/role_with_policies.json",
	"testdata/aws/role_with_urlencoded_trust.json",
}

var defaultKubernetesFixturePaths = []string{
	"testdata/kubernetes/service_account_payments.json",
	"testdata/kubernetes/cluster_role_cluster_admin.json",
	"testdata/kubernetes/role_binding_cluster_admin.json",
	"testdata/kubernetes/pod_payments.json",
}

// BuildRootCmd creates the command tree with injected config and output writer.
func BuildRootCmd(cfg config.Config, out io.Writer) *cobra.Command {
	var stateFile string

	root := &cobra.Command{
		Use:   "identrail",
		Short: "Machine identity security scanner",
		Long:  "Identrail scans machine identities and reports typed cloud identity risks.",
	}

	root.SetOut(out)
	root.SetErr(out)
	root.PersistentFlags().StringVar(&stateFile, "state-file", defaultStateFile, "Path to local findings state file")

	root.AddCommand(buildScanCmd(cfg, out, &stateFile))
	root.AddCommand(buildScanReplayCmd(cfg, out))
	root.AddCommand(buildFindingsCmd(out, &stateFile))
	root.AddCommand(buildRepoScanCmd(cfg, out))
	root.AddCommand(buildRepoFindingsCmd(cfg, out))
	root.AddCommand(buildRepoRiskGraphCmd(cfg, out))
	root.AddCommand(buildRepoPostureCmd(cfg, out))
	root.AddCommand(buildRepoRemediationCmd(cfg, out))
	root.AddCommand(buildAuthzCmd(cfg, out))

	return root
}

func buildScanCmd(cfg config.Config, out io.Writer, stateFile *string) *cobra.Command {
	var fixtures []string
	var outputFormat string
	var staleAfterDays int
	var skipSave bool
	var repoHistoryLimit int
	var repoMaxFindings int

	defaultFixtures := defaultFixturesForProvider(cfg)

	cmd := &cobra.Command{
		Use:   "scan [repository]",
		Short: "Run a read-only scan",
		Long:  "Runs the provider scan pipeline with no arguments, or scans repository exposure when a repository target is provided.",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 1 {
				if cmd.Flags().Changed("fixture") || cmd.Flags().Changed("stale-after-days") || cmd.Flags().Changed("no-save") {
					return fmt.Errorf("provider scan flags cannot be used with a repository target")
				}
				return runRepoScan(out, repoScanCLIOptions{
					Repository:   args[0],
					OutputFormat: outputFormat,
					HistoryLimit: repoHistoryLimit,
					MaxFindings:  repoMaxFindings,
				})
			}
			if cmd.Flags().Changed("history-limit") || cmd.Flags().Changed("max-findings") {
				return fmt.Errorf("--history-limit and --max-findings require a repository target")
			}
			if staleAfterDays < 1 {
				return fmt.Errorf("--stale-after-days must be at least 1")
			}

			formatter, err := parseOutputFormat(outputFormat)
			if err != nil {
				return err
			}

			scanner, err := buildScannerForProvider(cfg, fixtures, staleAfterDays)
			if err != nil {
				return err
			}

			result, err := scanner.Run(context.Background())
			if err != nil {
				return fmt.Errorf("scan failed: %w", err)
			}

			snapshot := findingsSnapshot{
				GeneratedAt: result.Completed,
				Assets:      result.Assets,
				Findings:    result.Findings,
			}
			if !skipSave {
				if err := saveSnapshot(*stateFile, snapshot); err != nil {
					return err
				}
			}

			if err := renderScanOutput(out, snapshot, formatter); err != nil {
				return err
			}

			if !skipSave {
				_, err = fmt.Fprintf(out, "Saved findings state to %s\n", *stateFile)
				if err != nil {
					return err
				}
			}
			return nil
		},
	}

	cmd.Flags().StringSliceVar(&fixtures, "fixture", append([]string(nil), defaultFixtures...), "Fixture JSON path(s) or directories for local scan")
	cmd.Flags().StringVar(&outputFormat, "output", formatTable, "Output format: table|json")
	cmd.Flags().IntVar(&staleAfterDays, "stale-after-days", 90, "Staleness threshold in days")
	cmd.Flags().BoolVar(&skipSave, "no-save", false, "Skip writing local findings state")
	cmd.Flags().IntVar(&repoHistoryLimit, "history-limit", 500, "Maximum number of repository commits to inspect when a repository target is supplied")
	cmd.Flags().IntVar(&repoMaxFindings, "max-findings", 200, "Maximum repository findings to emit when a repository target is supplied")

	return cmd
}

func buildFindingsCmd(out io.Writer, stateFile *string) *cobra.Command {
	var outputFormat string
	cmd := &cobra.Command{
		Use:   "findings",
		Short: "List findings from the most recent scan",
		RunE: func(_ *cobra.Command, _ []string) error {
			formatter, err := parseOutputFormat(outputFormat)
			if err != nil {
				return err
			}

			snapshot, err := loadSnapshot(*stateFile)
			if err != nil {
				if errors.Is(err, os.ErrNotExist) {
					_, writeErr := fmt.Fprintf(out, "No findings state found at %s. Run `identrail scan` first.\n", *stateFile)
					return writeErr
				}
				return err
			}
			return renderFindingsOutput(out, snapshot, formatter)
		},
	}

	cmd.Flags().StringVar(&outputFormat, "output", formatTable, "Output format: table|json")
	return cmd
}

func buildScanReplayCmd(cfg config.Config, out io.Writer) *cobra.Command {
	var (
		apiURL       string
		apiKey       string
		tenantID     string
		workspaceID  string
		scanID       string
		timeout      time.Duration
		outputFormat string
	)

	cmd := &cobra.Command{
		Use:   "scan-replay",
		Short: "Replay one failed or dead-lettered scan through the API queue",
		RunE: func(_ *cobra.Command, _ []string) error {
			if strings.TrimSpace(scanID) == "" {
				return fmt.Errorf("--scan-id is required")
			}
			formatter, err := parseOutputFormat(outputFormat)
			if err != nil {
				return err
			}
			replayURL := strings.TrimRight(strings.TrimSpace(apiURL), "/") + "/v1/scans/" + url.PathEscape(strings.TrimSpace(scanID)) + "/replay"
			if strings.TrimSpace(apiURL) == "" {
				return fmt.Errorf("--api-url is required")
			}

			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			req, err := http.NewRequestWithContext(ctx, http.MethodPost, replayURL, nil)
			if err != nil {
				return fmt.Errorf("build replay request: %w", err)
			}
			if normalizedKey := strings.TrimSpace(apiKey); normalizedKey != "" {
				req.Header.Set("X-API-Key", normalizedKey)
			}
			if normalizedTenant := strings.TrimSpace(tenantID); normalizedTenant != "" {
				req.Header.Set("X-Identrail-Tenant-ID", normalizedTenant)
			}
			if normalizedWorkspace := strings.TrimSpace(workspaceID); normalizedWorkspace != "" {
				req.Header.Set("X-Identrail-Workspace-ID", normalizedWorkspace)
			}

			resp, err := (&http.Client{Timeout: timeout}).Do(req)
			if err != nil {
				return fmt.Errorf("replay request failed: %w", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				var apiErr scanReplayCLIErrorResponse
				if err := json.NewDecoder(resp.Body).Decode(&apiErr); err == nil && strings.TrimSpace(apiErr.Error) != "" {
					return fmt.Errorf("replay request failed: %s (status %d)", strings.TrimSpace(apiErr.Error), resp.StatusCode)
				}
				return fmt.Errorf("replay request failed with status %d", resp.StatusCode)
			}

			var response scanReplayCLIResponse
			if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
				return fmt.Errorf("decode replay response: %w", err)
			}

			switch formatter {
			case outputJSON:
				return writeJSON(out, response)
			default:
				return renderScanReplayOutput(out, strings.TrimSpace(scanID), response)
			}
		},
	}

	cmd.Flags().StringVar(&apiURL, "api-url", defaultCLIAPIURL(), "Identrail API base URL")
	cmd.Flags().StringVar(&apiKey, "api-key", strings.TrimSpace(os.Getenv("IDENTRAIL_API_KEY")), "API key used for replay request")
	cmd.Flags().StringVar(&tenantID, "tenant-id", strings.TrimSpace(cfg.DefaultTenantID), "Tenant scope header for replay request")
	cmd.Flags().StringVar(&workspaceID, "workspace-id", strings.TrimSpace(cfg.DefaultWorkspaceID), "Workspace scope header for replay request")
	cmd.Flags().StringVar(&scanID, "scan-id", "", "Failed or dead-lettered scan ID to replay")
	cmd.Flags().DurationVar(&timeout, "timeout", 10*time.Second, "HTTP timeout for replay request")
	cmd.Flags().StringVar(&outputFormat, "output", formatTable, "Output format: table|json")
	return cmd
}

func buildRepoScanCmd(cfg config.Config, out io.Writer) *cobra.Command {
	options := repoScanCLIOptions{}

	cmd := &cobra.Command{
		Use:     "repo-scan [repository]",
		Aliases: []string{"repo"},
		Short:   "Scan repository history for secret exposures and misconfigurations",
		Long:    "Scans all reachable commits for added secret material and scans HEAD configuration files for high-signal misconfigurations.",
		Args:    cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			repository, err := resolveRepoScanTarget(options.Repository, args)
			if err != nil {
				return err
			}
			options.Repository = repository
			return runRepoScan(out, options)
		},
	}

	cmd.Flags().StringVar(&options.Repository, "repo", "", "Repository target (owner/repo, URL, or local git path)")
	cmd.Flags().StringVar(&options.OutputFormat, "output", formatTable, "Output format: table|json")
	cmd.Flags().IntVar(&options.HistoryLimit, "history-limit", 500, "Maximum number of commits to inspect for history secret exposure")
	cmd.Flags().IntVar(&options.MaxFindings, "max-findings", 200, "Maximum findings to emit before truncating scan output")
	cmd.AddCommand(buildRepoScanQueueCmd(cfg, out))
	cmd.AddCommand(buildRepoScanListCmd(cfg, out))
	cmd.AddCommand(buildRepoScanShowCmd(cfg, out))
	cmd.AddCommand(buildRepoScanCancelCmd(cfg, out))
	return cmd
}

type repoScanCLIOptions struct {
	Repository   string
	OutputFormat string
	HistoryLimit int
	MaxFindings  int
}

func resolveRepoScanTarget(flagValue string, args []string) (string, error) {
	flagTarget := strings.TrimSpace(flagValue)
	argTarget := ""
	if len(args) > 0 {
		argTarget = strings.TrimSpace(args[0])
	}
	if flagTarget != "" && argTarget != "" && flagTarget != argTarget {
		return "", fmt.Errorf("repository argument %q does not match --repo %q", argTarget, flagTarget)
	}
	switch {
	case argTarget != "":
		return argTarget, nil
	case flagTarget != "":
		return flagTarget, nil
	default:
		return "", fmt.Errorf("repository argument or --repo is required")
	}
}

func runRepoScan(out io.Writer, options repoScanCLIOptions) error {
	repository := strings.TrimSpace(options.Repository)
	if repository == "" {
		return fmt.Errorf("repository argument or --repo is required")
	}
	if options.HistoryLimit < 1 {
		return fmt.Errorf("--history-limit must be at least 1")
	}
	if options.MaxFindings < 1 {
		return fmt.Errorf("--max-findings must be at least 1")
	}
	formatter, err := parseOutputFormat(options.OutputFormat)
	if err != nil {
		return err
	}

	scanner := repoexposure.NewScanner(
		nil,
		repoexposure.WithHistoryLimit(options.HistoryLimit),
		repoexposure.WithMaxFindings(options.MaxFindings),
	)
	result, err := scanner.ScanRepository(context.Background(), repository)
	if err != nil {
		return fmt.Errorf("repo scan failed: %w", err)
	}

	switch formatter {
	case outputJSON:
		return writeJSON(out, result)
	default:
		if _, err := fmt.Fprintf(
			out,
			"Repo scan completed: repo=%s commits=%d files=%d findings=%d truncated=%t\n",
			result.Repository,
			result.CommitsScanned,
			result.FilesScanned,
			len(result.Findings),
			result.Truncated,
		); err != nil {
			return err
		}
		return renderFindingsTable(out, result.Findings)
	}
}

func buildAuthzCmd(cfg config.Config, out io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "authz",
		Short: "Authorization policy lifecycle operations",
	}
	cmd.AddCommand(buildAuthzRollbackCmd(cfg, out))
	return cmd
}

func buildAuthzRollbackCmd(cfg config.Config, out io.Writer) *cobra.Command {
	var (
		apiURL        string
		apiKey        string
		tenantID      string
		workspaceID   string
		policySetID   string
		targetVersion int
		actor         string
		timeout       time.Duration
		outputFormat  string
	)

	cmd := &cobra.Command{
		Use:   "rollback",
		Short: "Rollback active authorization policy version immediately",
		Long:  "Issues one rollback API request that resets rollout mode to disabled and switches active policy version immediately.",
		RunE: func(_ *cobra.Command, _ []string) error {
			if targetVersion <= 0 {
				return fmt.Errorf("--target-version must be greater than zero")
			}
			formatter, err := parseOutputFormat(outputFormat)
			if err != nil {
				return err
			}
			rollbackURL := strings.TrimRight(strings.TrimSpace(apiURL), "/") + "/v1/authz/policies/rollback"
			if strings.TrimSpace(apiURL) == "" {
				return fmt.Errorf("--api-url is required")
			}
			requestBody := authzPolicyRollbackCLIRequest{
				PolicySetID:   strings.TrimSpace(policySetID),
				TargetVersion: targetVersion,
				Actor:         strings.TrimSpace(actor),
			}
			payload, err := json.Marshal(requestBody)
			if err != nil {
				return fmt.Errorf("encode rollback request: %w", err)
			}

			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			req, err := http.NewRequestWithContext(ctx, http.MethodPost, rollbackURL, bytes.NewReader(payload))
			if err != nil {
				return fmt.Errorf("build rollback request: %w", err)
			}
			req.Header.Set("Content-Type", "application/json")
			if normalizedKey := strings.TrimSpace(apiKey); normalizedKey != "" {
				req.Header.Set("X-API-Key", normalizedKey)
			}
			if normalizedTenant := strings.TrimSpace(tenantID); normalizedTenant != "" {
				req.Header.Set("X-Identrail-Tenant-ID", normalizedTenant)
			}
			if normalizedWorkspace := strings.TrimSpace(workspaceID); normalizedWorkspace != "" {
				req.Header.Set("X-Identrail-Workspace-ID", normalizedWorkspace)
			}

			resp, err := (&http.Client{Timeout: timeout}).Do(req)
			if err != nil {
				return fmt.Errorf("rollback request failed: %w", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				var apiErr authzPolicyRollbackCLIErrorResponse
				if err := json.NewDecoder(resp.Body).Decode(&apiErr); err == nil && strings.TrimSpace(apiErr.Error) != "" {
					return fmt.Errorf("rollback request failed: %s (status %d)", strings.TrimSpace(apiErr.Error), resp.StatusCode)
				}
				return fmt.Errorf("rollback request failed with status %d", resp.StatusCode)
			}

			var response authzPolicyRollbackCLIResponse
			if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
				return fmt.Errorf("decode rollback response: %w", err)
			}
			switch formatter {
			case outputJSON:
				return writeJSON(out, response)
			default:
				return renderAuthzRollbackOutput(out, response)
			}
		},
	}

	cmd.Flags().StringVar(&apiURL, "api-url", defaultCLIAPIURL(), "Identrail API base URL")
	cmd.Flags().StringVar(&apiKey, "api-key", strings.TrimSpace(os.Getenv("IDENTRAIL_API_KEY")), "API key used for rollback request")
	cmd.Flags().StringVar(&tenantID, "tenant-id", strings.TrimSpace(cfg.DefaultTenantID), "Tenant scope header for rollback request")
	cmd.Flags().StringVar(&workspaceID, "workspace-id", strings.TrimSpace(cfg.DefaultWorkspaceID), "Workspace scope header for rollback request")
	cmd.Flags().StringVar(&policySetID, "policy-set-id", defaultPolicySet, "Policy set to rollback")
	cmd.Flags().IntVar(&targetVersion, "target-version", 0, "Target policy version to make active")
	cmd.Flags().StringVar(&actor, "actor", "", "Actor identifier recorded in rollback lifecycle event")
	cmd.Flags().DurationVar(&timeout, "timeout", 10*time.Second, "HTTP timeout for rollback request")
	cmd.Flags().StringVar(&outputFormat, "output", formatTable, "Output format: table|json")
	return cmd
}

func defaultCLIAPIURL() string {
	if configured := strings.TrimSpace(os.Getenv("IDENTRAIL_API_URL")); configured != "" {
		return configured
	}
	return defaultAPIURL
}

func renderAuthzRollbackOutput(out io.Writer, response authzPolicyRollbackCLIResponse) error {
	_, err := fmt.Fprintf(
		out,
		"Rollback applied: policy_set=%s active_version=%d mode=%s previous_effective=%s\n",
		strings.TrimSpace(response.PolicySetID),
		response.ActiveVersion,
		strings.TrimSpace(response.RolloutMode),
		formatOptionalInt(response.PreviousEffective),
	)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(
		out,
		"Previous active=%s candidate=%s updated_at=%s\n",
		formatOptionalInt(response.PreviousActiveVersion),
		formatOptionalInt(response.PreviousCandidateVersion),
		response.UpdatedAt.Format(time.RFC3339),
	)
	return err
}

func renderScanReplayOutput(out io.Writer, sourceScanID string, response scanReplayCLIResponse) error {
	_, err := fmt.Fprintf(
		out,
		"Replay queued: source_scan=%s replay_scan=%s provider=%s status=%s retry_count=%d\n",
		sourceScanID,
		strings.TrimSpace(response.Scan.ID),
		strings.TrimSpace(response.Scan.Provider),
		strings.TrimSpace(response.Scan.Status),
		response.Scan.RetryCount,
	)
	return err
}

type authzPolicyRollbackCLIRequest struct {
	PolicySetID   string `json:"policy_set_id"`
	TargetVersion int    `json:"target_version"`
	Actor         string `json:"actor,omitempty"`
}

type authzPolicyRollbackCLIResponse struct {
	PolicySetID              string    `json:"policy_set_id"`
	PreviousEffective        *int      `json:"previous_effective_version,omitempty"`
	PreviousActiveVersion    *int      `json:"previous_active_version,omitempty"`
	PreviousCandidateVersion *int      `json:"previous_candidate_version,omitempty"`
	ActiveVersion            int       `json:"active_version"`
	RolloutMode              string    `json:"rollout_mode"`
	UpdatedAt                time.Time `json:"updated_at"`
}

type authzPolicyRollbackCLIErrorResponse struct {
	Error string `json:"error"`
}

type scanReplayCLIResponse struct {
	Scan scanReplayCLIRecord `json:"scan"`
}

type scanReplayCLIRecord struct {
	ID           string `json:"id"`
	Provider     string `json:"provider"`
	Status       string `json:"status"`
	RetryCount   int    `json:"retry_count"`
	DeadLettered bool   `json:"dead_lettered"`
}

type scanReplayCLIErrorResponse struct {
	Error string `json:"error"`
}

func formatOptionalInt(value *int) string {
	if value == nil {
		return "none"
	}
	return fmt.Sprintf("%d", *value)
}

// Execute runs the root command with externalized args for testability.
func Execute(cfg config.Config, args []string, out io.Writer) error {
	cmd := BuildRootCmd(cfg, out)
	cmd.SetArgs(args)
	return cmd.Execute()
}

func defaultFixturesForProvider(cfg config.Config) []string {
	switch strings.ToLower(strings.TrimSpace(cfg.Provider)) {
	case "kubernetes":
		if len(cfg.KubernetesFixturePath) > 0 {
			return cfg.KubernetesFixturePath
		}
		return defaultKubernetesFixturePaths
	default:
		if len(cfg.AWSFixturePath) > 0 {
			return cfg.AWSFixturePath
		}
		return defaultAWSFixturePaths
	}
}

func buildScannerForProvider(cfg config.Config, fixtures []string, staleAfterDays int) (app.Scanner, error) {
	switch strings.ToLower(strings.TrimSpace(cfg.Provider)) {
	case "aws":
		switch strings.ToLower(strings.TrimSpace(cfg.AWSSource)) {
		case "", "fixture":
			return app.Scanner{
				Collector:            awsprovider.NewFixtureCollector(fixtures),
				Normalizer:           awsprovider.NewRoleNormalizer(),
				PermissionResolver:   awsprovider.NewPolicyPermissionResolver(),
				RelationshipResolver: awsprovider.NewRelationshipBuilder(),
				RiskRuleSet:          awsprovider.NewRuleSet(awsprovider.WithStaleAfter(time.Duration(staleAfterDays) * 24 * time.Hour)),
			}, nil
		case "sdk":
			iamAPI, err := awsprovider.NewSDKIAMAPI(cfg.AWSRegion, cfg.AWSProfile)
			if err != nil {
				return app.Scanner{}, fmt.Errorf("initialize aws sdk collector: %w", err)
			}
			ec2API, err := awsprovider.NewSDKEC2InstanceProfileAPI(cfg.AWSRegion, cfg.AWSProfile, cfg.AWSAccountID)
			if err != nil {
				return app.Scanner{}, fmt.Errorf("initialize aws ec2 instance profile collector: %w", err)
			}
			ecsAPI, err := awsprovider.NewSDKECSTaskRoleAPI(cfg.AWSRegion, cfg.AWSProfile, cfg.AWSAccountID)
			if err != nil {
				return app.Scanner{}, fmt.Errorf("initialize aws ecs task role collector: %w", err)
			}
			lambdaAPI, err := awsprovider.NewSDKLambdaExecutionRoleAPI(cfg.AWSRegion, cfg.AWSProfile, cfg.AWSAccountID)
			if err != nil {
				return app.Scanner{}, fmt.Errorf("initialize aws lambda execution role collector: %w", err)
			}
			codeBuildAPI, err := awsprovider.NewSDKCodeBuildServiceRoleAPI(cfg.AWSRegion, cfg.AWSProfile, cfg.AWSAccountID)
			if err != nil {
				return app.Scanner{}, fmt.Errorf("initialize aws codebuild service role collector: %w", err)
			}
			codePipelineAPI, err := awsprovider.NewSDKCodePipelineDeploymentRoleAPI(cfg.AWSRegion, cfg.AWSProfile, cfg.AWSAccountID)
			if err != nil {
				return app.Scanner{}, fmt.Errorf("initialize aws codepipeline deployment role collector: %w", err)
			}
			stepFunctionsAPI, err := awsprovider.NewSDKStepFunctionsStateMachineRoleAPI(cfg.AWSRegion, cfg.AWSProfile, cfg.AWSAccountID)
			if err != nil {
				return app.Scanner{}, fmt.Errorf("initialize aws stepfunctions state machine role collector: %w", err)
			}
			eventDrivenAPI, err := awsprovider.NewSDKEventDrivenRoleAPI(cfg.AWSRegion, cfg.AWSProfile, cfg.AWSAccountID)
			if err != nil {
				return app.Scanner{}, fmt.Errorf("initialize aws event-driven role collector: %w", err)
			}
			eksAPI, err := awsprovider.NewSDKEKSWorkloadIdentityAPI(cfg.AWSRegion, cfg.AWSProfile, cfg.AWSAccountID)
			if err != nil {
				return app.Scanner{}, fmt.Errorf("initialize aws eks workload identity collector: %w", err)
			}
			return awsprovider.NewAWSScannerWithServices(iamAPI, cfg.AWSAccountID, cfg.AWSRegion, []awsprovider.AWSServiceCollector{
				awsprovider.NewEC2InstanceProfileCollector(ec2API),
				awsprovider.NewECSTaskRoleCollector(ecsAPI),
				awsprovider.NewLambdaExecutionRoleCollector(lambdaAPI),
				awsprovider.NewCodeBuildServiceRoleCollector(codeBuildAPI),
				awsprovider.NewCodePipelineDeploymentRoleCollector(codePipelineAPI),
				awsprovider.NewStepFunctionsStateMachineRoleCollector(stepFunctionsAPI),
				awsprovider.NewEventDrivenRoleCollector(eventDrivenAPI),
				awsprovider.NewEKSWorkloadIdentityCollector(eksAPI),
			}, awsprovider.NewRuleSet(
				awsprovider.WithStaleAfter(time.Duration(staleAfterDays)*24*time.Hour),
			)), nil
		default:
			return app.Scanner{}, fmt.Errorf("unsupported aws source %q", cfg.AWSSource)
		}
	case "kubernetes":
		switch strings.ToLower(strings.TrimSpace(cfg.KubernetesSource)) {
		case "", "fixture":
			return app.Scanner{
				Collector:            k8sprovider.NewFixtureCollector(fixtures),
				Normalizer:           k8sprovider.NewNormalizer(),
				PermissionResolver:   k8sprovider.NewPermissionResolver(),
				RelationshipResolver: k8sprovider.NewRelationshipResolver(),
				RiskRuleSet:          k8sprovider.NewRuleSet(),
			}, nil
		case "kubectl":
			return app.Scanner{
				Collector:            k8sprovider.NewKubectlCollector(cfg.KubectlPath, cfg.KubeContext, nil),
				Normalizer:           k8sprovider.NewNormalizer(),
				PermissionResolver:   k8sprovider.NewPermissionResolver(),
				RelationshipResolver: k8sprovider.NewRelationshipResolver(),
				RiskRuleSet:          k8sprovider.NewRuleSet(),
			}, nil
		default:
			return app.Scanner{}, fmt.Errorf("unsupported kubernetes source %q", cfg.KubernetesSource)
		}
	default:
		return app.Scanner{}, fmt.Errorf("unsupported provider %q", cfg.Provider)
	}
}

type outputFormat int

const (
	outputTable outputFormat = iota
	outputJSON
)

func parseOutputFormat(raw string) (outputFormat, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case formatTable:
		return outputTable, nil
	case formatJSON:
		return outputJSON, nil
	default:
		return outputTable, fmt.Errorf("invalid --output %q (expected table|json)", raw)
	}
}

type findingsSnapshot struct {
	GeneratedAt time.Time        `json:"generated_at"`
	Assets      int              `json:"assets"`
	Findings    []domain.Finding `json:"findings"`
}

func saveSnapshot(path string, snapshot findingsSnapshot) error {
	absolute := normalizeStatePath(path)
	if err := os.MkdirAll(filepath.Dir(absolute), 0o755); err != nil {
		return fmt.Errorf("create state directory: %w", err)
	}

	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return fmt.Errorf("encode findings snapshot: %w", err)
	}
	if err := os.WriteFile(absolute, data, 0o600); err != nil {
		return fmt.Errorf("write findings snapshot: %w", err)
	}
	return nil
}

func loadSnapshot(path string) (findingsSnapshot, error) {
	absolute := normalizeStatePath(path)
	data, err := os.ReadFile(absolute)
	if err != nil {
		return findingsSnapshot{}, err
	}

	var snapshot findingsSnapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return findingsSnapshot{}, fmt.Errorf("decode findings snapshot: %w", err)
	}
	return snapshot, nil
}

func normalizeStatePath(path string) string {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return defaultStateFile
	}
	return trimmed
}

func renderScanOutput(out io.Writer, snapshot findingsSnapshot, format outputFormat) error {
	switch format {
	case outputJSON:
		return writeJSON(out, snapshot)
	default:
		_, err := fmt.Fprintf(out, "Scan completed: %d assets, %d findings\n", snapshot.Assets, len(snapshot.Findings))
		if err != nil {
			return err
		}
		return renderFindingsTable(out, snapshot.Findings)
	}
}

func renderFindingsOutput(out io.Writer, snapshot findingsSnapshot, format outputFormat) error {
	switch format {
	case outputJSON:
		return writeJSON(out, snapshot)
	default:
		_, err := fmt.Fprintf(out, "Last scan: %s | assets: %d | findings: %d\n", snapshot.GeneratedAt.Format(time.RFC3339), snapshot.Assets, len(snapshot.Findings))
		if err != nil {
			return err
		}
		return renderFindingsTable(out, snapshot.Findings)
	}
}

func writeJSON(out io.Writer, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "%s\n", data)
	return err
}

func renderFindingsTable(out io.Writer, findings []domain.Finding) error {
	if len(findings) == 0 {
		_, err := fmt.Fprintln(out, "No findings.")
		return err
	}

	sorted := make([]domain.Finding, len(findings))
	copy(sorted, findings)
	sort.Slice(sorted, func(i, j int) bool {
		leftSeverity := severitySortRank(sorted[i].Severity)
		rightSeverity := severitySortRank(sorted[j].Severity)
		if leftSeverity == rightSeverity {
			if sorted[i].Type == sorted[j].Type {
				return sorted[i].Title < sorted[j].Title
			}
			return sorted[i].Type < sorted[j].Type
		}
		return leftSeverity > rightSeverity
	})

	for i, finding := range sorted {
		_, err := fmt.Fprintf(
			out,
			"%d. [%s] %s (%s)\n   %s\n",
			i+1,
			strings.ToUpper(string(finding.Severity)),
			finding.Title,
			finding.Type,
			finding.HumanSummary,
		)
		if err != nil {
			return err
		}
	}
	return nil
}

func severitySortRank(severity domain.FindingSeverity) int {
	switch severity {
	case domain.SeverityCritical:
		return 5
	case domain.SeverityHigh:
		return 4
	case domain.SeverityMedium:
		return 3
	case domain.SeverityLow:
		return 2
	case domain.SeverityInfo:
		return 1
	default:
		return 0
	}
}
