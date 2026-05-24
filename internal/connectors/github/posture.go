package github

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// RepositoryPostureState is a normalized posture state for one GitHub control.
type RepositoryPostureState string

const (
	RepositoryPostureStateSecure            RepositoryPostureState = "secure"
	RepositoryPostureStateInsecure          RepositoryPostureState = "insecure"
	RepositoryPostureStateUnavailable       RepositoryPostureState = "unavailable"
	RepositoryPostureStatePermissionLimited RepositoryPostureState = "permission_limited"
)

// RepositoryPosture describes GitHub-hosted repository security settings that
// are not visible from git content alone.
type RepositoryPosture struct {
	Repository     string                   `json:"repository"`
	InstallationID int64                    `json:"installation_id,omitempty"`
	CollectedAt    time.Time                `json:"collected_at"`
	Checks         []RepositoryPostureCheck `json:"checks"`
	RateLimit      *GitHubRateLimitState    `json:"rate_limit,omitempty"`
}

// RepositoryPostureCheck is one normalized GitHub repository posture signal.
type RepositoryPostureCheck struct {
	ID       string                 `json:"id"`
	Category string                 `json:"category"`
	State    RepositoryPostureState `json:"state"`
	Reason   string                 `json:"reason,omitempty"`
	Summary  string                 `json:"summary"`
	Evidence map[string]any         `json:"evidence,omitempty"`
}

// GitHubRateLimitState captures the latest observed GitHub REST rate-limit
// headers for posture calls.
type GitHubRateLimitState struct {
	Limit     int        `json:"limit,omitempty"`
	Remaining int        `json:"remaining,omitempty"`
	ResetAt   *time.Time `json:"reset_at,omitempty"`
}

type githubAPIRequestError struct {
	StatusCode   int
	Message      string
	RateLimited  bool
	RetryAfter   string
	RateLimit    *GitHubRateLimitState
	ResponsePath string
}

func (e githubAPIRequestError) Error() string {
	message := strings.TrimSpace(e.Message)
	if message == "" {
		message = http.StatusText(e.StatusCode)
	}
	if message == "" {
		message = "github api request failed"
	}
	return fmt.Sprintf("github api %s: status %d: %s", e.ResponsePath, e.StatusCode, message)
}

type repositoryMetadata struct {
	FullName            string                            `json:"full_name"`
	Private             bool                              `json:"private"`
	Visibility          string                            `json:"visibility"`
	DefaultBranch       string                            `json:"default_branch"`
	Archived            bool                              `json:"archived"`
	Disabled            bool                              `json:"disabled"`
	Fork                bool                              `json:"fork"`
	Topics              []string                          `json:"topics"`
	HasSecurityPolicy   bool                              `json:"has_security_policy"`
	SecurityAndAnalysis map[string]repositoryFeatureState `json:"security_and_analysis"`
}

type repositoryFeatureState struct {
	Status string `json:"status"`
}

type branchProtection struct {
	RequiredPullRequestReviews *struct {
		RequiredApprovingReviewCount int  `json:"required_approving_review_count"`
		DismissStaleReviews          bool `json:"dismiss_stale_reviews"`
		RequireCodeOwnerReviews      bool `json:"require_code_owner_reviews"`
	} `json:"required_pull_request_reviews"`
	RequiredStatusChecks *struct {
		Strict   bool     `json:"strict"`
		Contexts []string `json:"contexts"`
		Checks   []struct {
			Context string `json:"context"`
		} `json:"checks"`
	} `json:"required_status_checks"`
	EnforceAdmins *struct {
		Enabled bool `json:"enabled"`
	} `json:"enforce_admins"`
	AllowForcePushes *struct {
		Enabled bool `json:"enabled"`
	} `json:"allow_force_pushes"`
	AllowDeletions *struct {
		Enabled bool `json:"enabled"`
	} `json:"allow_deletions"`
}

type repositoryRuleset struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Target      string `json:"target"`
	Enforcement string `json:"enforcement"`
	Rules       []struct {
		Type string `json:"type"`
	} `json:"rules"`
}

type actionsPermissions struct {
	Enabled                      bool   `json:"enabled"`
	AllowedActions               string `json:"allowed_actions"`
	DefaultWorkflowPermissions   string `json:"default_workflow_permissions"`
	CanApprovePullRequestReviews bool   `json:"can_approve_pull_request_reviews"`
	EnabledRepositories          string `json:"enabled_repositories"`
	SelectedActionsURL           string `json:"selected_actions_url"`
	AllowedActionsConfigURL      string `json:"allowed_actions_config_url"`
}

type deployKey struct {
	ID       int64  `json:"id"`
	Title    string `json:"title"`
	ReadOnly bool   `json:"read_only"`
}

type repositoryHook struct {
	ID       int64          `json:"id"`
	Name     string         `json:"name"`
	Active   bool           `json:"active"`
	Events   []string       `json:"events"`
	Config   map[string]any `json:"config"`
	LastResp *struct {
		Code    int    `json:"code"`
		Status  string `json:"status"`
		Message string `json:"message"`
	} `json:"last_response"`
}

type repositoryEnvironmentPage struct {
	TotalCount   int                     `json:"total_count"`
	Environments []repositoryEnvironment `json:"environments"`
}

type repositoryEnvironment struct {
	Name            string `json:"name"`
	ProtectionRules []struct {
		Type string `json:"type"`
	} `json:"protection_rules"`
}

type actionsRunnerPage struct {
	TotalCount int             `json:"total_count"`
	Runners    []actionsRunner `json:"runners"`
}

type actionsRunner struct {
	ID     int64                `json:"id"`
	Name   string               `json:"name"`
	OS     string               `json:"os"`
	Status string               `json:"status"`
	Busy   bool                 `json:"busy"`
	Labels []actionsRunnerLabel `json:"labels"`
}

type actionsRunnerLabel struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type orgRunnerGroupPage struct {
	TotalCount   int              `json:"total_count"`
	RunnerGroups []orgRunnerGroup `json:"runner_groups"`
}

type orgRunnerGroupRepositoryPage struct {
	TotalCount   int                        `json:"total_count"`
	Repositories []orgRunnerGroupRepository `json:"repositories"`
}

type orgRunnerGroupRepository struct {
	FullName string `json:"full_name"`
}

type orgRunnerGroup struct {
	ID                       int64  `json:"id"`
	Name                     string `json:"name"`
	Visibility               string `json:"visibility"`
	AllowsPublicRepositories bool   `json:"allows_public_repositories"`
	Default                  bool   `json:"default"`
	RestrictedToWorkflows    bool   `json:"restricted_to_workflows"`
}

// CollectRepositoryPosture collects normalized security posture from GitHub API
// endpoints that require an installation token. Each endpoint contributes a
// check even when the setting is unavailable or permission-limited.
func (c RepositoryClient) CollectRepositoryPosture(ctx context.Context, installationID int64, repository string) (RepositoryPosture, error) {
	if c.TokenClient == nil {
		return RepositoryPosture{}, fmt.Errorf("github installation token client is required")
	}
	normalizedRepository, err := normalizeRepositoryName(repository)
	if err != nil {
		return RepositoryPosture{}, err
	}
	token, err := c.TokenClient.Mint(ctx, installationID)
	if err != nil {
		return RepositoryPosture{}, err
	}

	posture := RepositoryPosture{
		Repository:     normalizedRepository,
		InstallationID: installationID,
		CollectedAt:    c.now().UTC(),
		Checks:         make([]RepositoryPostureCheck, 0, 11),
	}
	updateRate := func(limit *GitHubRateLimitState) {
		if limit != nil {
			posture.RateLimit = limit
		}
	}

	var metadata repositoryMetadata
	rateLimit, err := c.getJSON(ctx, token.Token, c.repositoryEndpoint(normalizedRepository, ""), &metadata)
	updateRate(rateLimit)
	if err != nil {
		posture.Checks = append(posture.Checks, checkFromAPIError("repository_metadata", "repository", err, RepositoryPostureStateUnavailable, "api_unavailable", "Repository metadata could not be collected."))
	} else {
		posture.Checks = append(posture.Checks, repositoryMetadataCheck(normalizedRepository, metadata))
	}

	defaultBranch := strings.TrimSpace(metadata.DefaultBranch)
	if defaultBranch == "" {
		posture.Checks = append(posture.Checks, RepositoryPostureCheck{
			ID:       "default_branch_protection",
			Category: "branch_protection",
			State:    RepositoryPostureStateUnavailable,
			Reason:   "default_branch_unknown",
			Summary:  "Repository metadata did not include a default branch, so branch protection posture could not be collected.",
			Evidence: map[string]any{
				"repository": normalizedRepository,
			},
		})
	} else {
		posture.Checks = append(posture.Checks, c.collectBranchProtection(ctx, token.Token, normalizedRepository, defaultBranch, updateRate))
	}
	posture.Checks = append(posture.Checks, c.collectRulesets(ctx, token.Token, normalizedRepository, updateRate))
	posture.Checks = append(posture.Checks, c.collectActionsPermissions(ctx, token.Token, normalizedRepository, updateRate))
	posture.Checks = append(posture.Checks, c.collectDependabot(ctx, token.Token, normalizedRepository, updateRate))
	posture.Checks = append(posture.Checks, c.collectAlertEndpoint(ctx, token.Token, normalizedRepository, "code_scanning", "security", c.repositoryEndpoint(normalizedRepository, "/code-scanning/alerts?state=open&per_page=1"), updateRate))
	posture.Checks = append(posture.Checks, c.collectAlertEndpoint(ctx, token.Token, normalizedRepository, "secret_scanning", "security", c.repositoryEndpoint(normalizedRepository, "/secret-scanning/alerts?state=open&per_page=1"), updateRate))
	posture.Checks = append(posture.Checks, c.collectDeployKeys(ctx, token.Token, normalizedRepository, updateRate))
	posture.Checks = append(posture.Checks, c.collectWebhooks(ctx, token.Token, normalizedRepository, updateRate))
	posture.Checks = append(posture.Checks, c.collectEnvironments(ctx, token.Token, normalizedRepository, updateRate))
	posture.Checks = append(posture.Checks, c.collectSelfHostedRunners(ctx, token.Token, normalizedRepository, updateRate))

	return posture, nil
}

func repositoryMetadataCheck(repository string, metadata repositoryMetadata) RepositoryPostureCheck {
	evidence := map[string]any{
		"repository":          repository,
		"full_name":           strings.TrimSpace(metadata.FullName),
		"private":             metadata.Private,
		"visibility":          strings.TrimSpace(metadata.Visibility),
		"default_branch":      strings.TrimSpace(metadata.DefaultBranch),
		"archived":            metadata.Archived,
		"disabled":            metadata.Disabled,
		"fork":                metadata.Fork,
		"has_security_policy": metadata.HasSecurityPolicy,
	}
	if len(metadata.Topics) > 0 {
		evidence["topics"] = metadata.Topics
	}
	if len(metadata.SecurityAndAnalysis) > 0 {
		summary := map[string]string{}
		for key, feature := range metadata.SecurityAndAnalysis {
			summary[key] = strings.TrimSpace(feature.Status)
		}
		evidence["security_and_analysis"] = summary
	}
	if metadata.Archived || metadata.Disabled {
		return RepositoryPostureCheck{
			ID:       "repository_metadata",
			Category: "repository",
			State:    RepositoryPostureStateInsecure,
			Reason:   "repository_inactive",
			Summary:  "Repository is archived or disabled.",
			Evidence: evidence,
		}
	}
	if !metadata.HasSecurityPolicy {
		return RepositoryPostureCheck{
			ID:       "repository_metadata",
			Category: "repository",
			State:    RepositoryPostureStateInsecure,
			Reason:   "security_policy_missing",
			Summary:  "Repository metadata is available, but no security policy is advertised.",
			Evidence: evidence,
		}
	}
	return RepositoryPostureCheck{
		ID:       "repository_metadata",
		Category: "repository",
		State:    RepositoryPostureStateSecure,
		Reason:   "metadata_available",
		Summary:  "Repository metadata and security policy are available.",
		Evidence: evidence,
	}
}

func (c RepositoryClient) collectBranchProtection(ctx context.Context, token string, repository string, branch string, updateRate func(*GitHubRateLimitState)) RepositoryPostureCheck {
	var protection branchProtection
	rateLimit, err := c.getJSON(ctx, token, c.repositoryEndpoint(repository, "/branches/"+url.PathEscape(branch)+"/protection"), &protection)
	updateRate(rateLimit)
	if err != nil {
		if apiErr, ok := asGitHubAPIError(err); ok && apiErr.StatusCode == http.StatusNotFound {
			return RepositoryPostureCheck{
				ID:       "default_branch_protection",
				Category: "branch_protection",
				State:    RepositoryPostureStateInsecure,
				Reason:   "not_configured",
				Summary:  "Default branch protection is not configured or not visible.",
				Evidence: map[string]any{"repository": repository, "default_branch": branch},
			}
		}
		return checkFromAPIError("default_branch_protection", "branch_protection", err, RepositoryPostureStateUnavailable, "api_unavailable", "Default branch protection could not be collected.")
	}

	requiredReviewCount := 0
	if protection.RequiredPullRequestReviews != nil {
		requiredReviewCount = protection.RequiredPullRequestReviews.RequiredApprovingReviewCount
	}
	statusCheckCount := 0
	if protection.RequiredStatusChecks != nil {
		statusCheckCount = len(protection.RequiredStatusChecks.Contexts) + len(protection.RequiredStatusChecks.Checks)
	}
	forcePushesAllowed := protection.AllowForcePushes != nil && protection.AllowForcePushes.Enabled
	deletionsAllowed := protection.AllowDeletions != nil && protection.AllowDeletions.Enabled
	adminsEnforced := protection.EnforceAdmins != nil && protection.EnforceAdmins.Enabled
	evidence := map[string]any{
		"repository":               repository,
		"default_branch":           branch,
		"required_reviews":         requiredReviewCount,
		"required_status_checks":   statusCheckCount,
		"admins_enforced":          adminsEnforced,
		"force_pushes_allowed":     forcePushesAllowed,
		"branch_deletions_allowed": deletionsAllowed,
	}
	if requiredReviewCount == 0 || statusCheckCount == 0 || !adminsEnforced || forcePushesAllowed || deletionsAllowed {
		return RepositoryPostureCheck{
			ID:       "default_branch_protection",
			Category: "branch_protection",
			State:    RepositoryPostureStateInsecure,
			Reason:   "weak_protection",
			Summary:  "Default branch protection is present but missing required reviews, status checks, admin enforcement, or destructive-change safeguards.",
			Evidence: evidence,
		}
	}
	return RepositoryPostureCheck{
		ID:       "default_branch_protection",
		Category: "branch_protection",
		State:    RepositoryPostureStateSecure,
		Reason:   "protection_enforced",
		Summary:  "Default branch protection requires reviews and status checks.",
		Evidence: evidence,
	}
}

func (c RepositoryClient) collectRulesets(ctx context.Context, token string, repository string, updateRate func(*GitHubRateLimitState)) RepositoryPostureCheck {
	var rulesets []repositoryRuleset
	rateLimit, err := c.getJSONPages(ctx, token, c.repositoryEndpoint(repository, "/rulesets?targets=branch&per_page=100"), func(body []byte) error {
		var page []repositoryRuleset
		if err := json.Unmarshal(body, &page); err != nil {
			return err
		}
		rulesets = append(rulesets, page...)
		return nil
	})
	updateRate(rateLimit)
	if err != nil {
		if apiErr, ok := asGitHubAPIError(err); ok && apiErr.StatusCode == http.StatusNotFound {
			return RepositoryPostureCheck{
				ID:       "repository_rulesets",
				Category: "branch_protection",
				State:    RepositoryPostureStateInsecure,
				Reason:   "not_configured",
				Summary:  "Repository branch rulesets are not configured or not visible.",
				Evidence: map[string]any{"repository": repository},
			}
		}
		return checkFromAPIError("repository_rulesets", "branch_protection", err, RepositoryPostureStateUnavailable, "api_unavailable", "Repository rulesets could not be collected.")
	}
	active := 0
	evaluate := 0
	for _, ruleset := range rulesets {
		switch strings.ToLower(strings.TrimSpace(ruleset.Enforcement)) {
		case "active":
			active++
		case "evaluate":
			evaluate++
		}
	}
	evidence := map[string]any{
		"repository":        repository,
		"ruleset_count":     len(rulesets),
		"active_rulesets":   active,
		"evaluate_rulesets": evaluate,
	}
	if active == 0 {
		return RepositoryPostureCheck{
			ID:       "repository_rulesets",
			Category: "branch_protection",
			State:    RepositoryPostureStateInsecure,
			Reason:   "no_active_rulesets",
			Summary:  "No active branch rulesets are configured.",
			Evidence: evidence,
		}
	}
	return RepositoryPostureCheck{
		ID:       "repository_rulesets",
		Category: "branch_protection",
		State:    RepositoryPostureStateSecure,
		Reason:   "active_rulesets_present",
		Summary:  "Repository has active branch rulesets.",
		Evidence: evidence,
	}
}

func (c RepositoryClient) collectActionsPermissions(ctx context.Context, token string, repository string, updateRate func(*GitHubRateLimitState)) RepositoryPostureCheck {
	var permissions actionsPermissions
	rateLimit, err := c.getJSON(ctx, token, c.repositoryEndpoint(repository, "/actions/permissions"), &permissions)
	updateRate(rateLimit)
	if err != nil {
		return checkFromAPIError("actions_permissions", "actions", err, RepositoryPostureStateUnavailable, "api_unavailable", "GitHub Actions permissions could not be collected.")
	}
	evidence := map[string]any{
		"repository":                       repository,
		"enabled":                          permissions.Enabled,
		"allowed_actions":                  strings.TrimSpace(permissions.AllowedActions),
		"default_workflow_permissions":     strings.TrimSpace(permissions.DefaultWorkflowPermissions),
		"can_approve_pull_request_reviews": permissions.CanApprovePullRequestReviews,
		"enabled_repositories":             strings.TrimSpace(permissions.EnabledRepositories),
	}
	broadActionsAllowed := permissions.Enabled && strings.EqualFold(permissions.AllowedActions, "all")
	writeWorkflowToken := permissions.Enabled && strings.EqualFold(permissions.DefaultWorkflowPermissions, "write")
	prApprovalEnabled := permissions.Enabled && permissions.CanApprovePullRequestReviews
	if broadActionsAllowed || writeWorkflowToken || prApprovalEnabled {
		return RepositoryPostureCheck{
			ID:       "actions_permissions",
			Category: "actions",
			State:    RepositoryPostureStateInsecure,
			Reason:   "broad_actions_or_write_privileges",
			Summary:  "GitHub Actions is enabled with broad action sources, write-token permissions, or pull-request approval privileges.",
			Evidence: evidence,
		}
	}
	return RepositoryPostureCheck{
		ID:       "actions_permissions",
		Category: "actions",
		State:    RepositoryPostureStateSecure,
		Reason:   "least_privilege_actions",
		Summary:  "GitHub Actions permissions do not grant default write-token or PR approval privileges.",
		Evidence: evidence,
	}
}

func (c RepositoryClient) collectDependabot(ctx context.Context, token string, repository string, updateRate func(*GitHubRateLimitState)) RepositoryPostureCheck {
	alertsEnabled, alertsRate, alertsErr := c.featureStatus(ctx, token, c.repositoryEndpoint(repository, "/vulnerability-alerts"))
	updateRate(alertsRate)
	fixesEnabled, fixesRate, fixesErr := c.featureStatus(ctx, token, c.repositoryEndpoint(repository, "/automated-security-fixes"))
	updateRate(fixesRate)
	if alertsErr != nil {
		return checkFromAPIError("dependabot_security", "security", alertsErr, RepositoryPostureStateInsecure, "not_configured", "Dependabot alerts are not configured or could not be collected.")
	}
	if fixesErr != nil {
		return checkFromAPIError("dependabot_security", "security", fixesErr, RepositoryPostureStateInsecure, "not_configured", "Dependabot security updates are not configured or could not be collected.")
	}
	evidence := map[string]any{
		"repository":                          repository,
		"dependabot_alerts_enabled":           alertsEnabled,
		"dependabot_security_updates_enabled": fixesEnabled,
	}
	if !alertsEnabled || !fixesEnabled {
		return RepositoryPostureCheck{
			ID:       "dependabot_security",
			Category: "security",
			State:    RepositoryPostureStateInsecure,
			Reason:   "dependabot_security_disabled",
			Summary:  "Dependabot alerts or security updates are disabled.",
			Evidence: evidence,
		}
	}
	return RepositoryPostureCheck{
		ID:       "dependabot_security",
		Category: "security",
		State:    RepositoryPostureStateSecure,
		Reason:   "dependabot_security_enabled",
		Summary:  "Dependabot alerts and security updates are enabled.",
		Evidence: evidence,
	}
}

func (c RepositoryClient) collectAlertEndpoint(ctx context.Context, token string, repository string, id string, category string, endpoint string, updateRate func(*GitHubRateLimitState)) RepositoryPostureCheck {
	var alerts []map[string]any
	rateLimit, err := c.getJSON(ctx, token, endpoint, &alerts)
	updateRate(rateLimit)
	if err != nil {
		return checkFromAPIError(id, category, err, RepositoryPostureStateInsecure, "not_configured", id+" alerts are not configured or could not be collected.")
	}
	evidence := map[string]any{
		"repository":          repository,
		"open_alerts_sampled": len(alerts),
	}
	if len(alerts) > 0 {
		return RepositoryPostureCheck{
			ID:       id,
			Category: category,
			State:    RepositoryPostureStateInsecure,
			Reason:   "open_alerts_present",
			Summary:  "Open " + strings.ReplaceAll(id, "_", " ") + " alerts are present.",
			Evidence: evidence,
		}
	}
	return RepositoryPostureCheck{
		ID:       id,
		Category: category,
		State:    RepositoryPostureStateSecure,
		Reason:   "enabled_no_open_alerts",
		Summary:  strings.ReplaceAll(id, "_", " ") + " is enabled and no open alerts were returned.",
		Evidence: evidence,
	}
}

func (c RepositoryClient) collectDeployKeys(ctx context.Context, token string, repository string, updateRate func(*GitHubRateLimitState)) RepositoryPostureCheck {
	keys := []deployKey{}
	rateLimit, err := c.getJSONPages(ctx, token, c.repositoryEndpoint(repository, "/keys?per_page=100"), func(body []byte) error {
		var page []deployKey
		if err := json.Unmarshal(body, &page); err != nil {
			return err
		}
		keys = append(keys, page...)
		return nil
	})
	updateRate(rateLimit)
	if err != nil {
		return checkFromAPIError("deploy_keys", "access", err, RepositoryPostureStateUnavailable, "api_unavailable", "Deploy keys could not be collected.")
	}
	writable := 0
	for _, key := range keys {
		if !key.ReadOnly {
			writable++
		}
	}
	evidence := map[string]any{
		"repository":           repository,
		"deploy_key_count":     len(keys),
		"writable_deploy_keys": writable,
		"readonly_deploy_keys": len(keys) - writable,
	}
	if writable > 0 {
		return RepositoryPostureCheck{
			ID:       "deploy_keys",
			Category: "access",
			State:    RepositoryPostureStateInsecure,
			Reason:   "writable_deploy_keys_present",
			Summary:  "Repository has deploy keys with write access.",
			Evidence: evidence,
		}
	}
	return RepositoryPostureCheck{
		ID:       "deploy_keys",
		Category: "access",
		State:    RepositoryPostureStateSecure,
		Reason:   "no_writable_deploy_keys",
		Summary:  "No writable deploy keys were returned.",
		Evidence: evidence,
	}
}

func (c RepositoryClient) collectWebhooks(ctx context.Context, token string, repository string, updateRate func(*GitHubRateLimitState)) RepositoryPostureCheck {
	hooks := []repositoryHook{}
	rateLimit, err := c.getJSONPages(ctx, token, c.repositoryEndpoint(repository, "/hooks?per_page=100"), func(body []byte) error {
		var page []repositoryHook
		if err := json.Unmarshal(body, &page); err != nil {
			return err
		}
		hooks = append(hooks, page...)
		return nil
	})
	updateRate(rateLimit)
	if err != nil {
		return checkFromAPIError("webhooks", "webhooks", err, RepositoryPostureStateUnavailable, "api_unavailable", "Repository webhooks could not be collected.")
	}
	active := 0
	insecureSSL := 0
	failing := 0
	for _, hook := range hooks {
		if hook.Active {
			active++
		}
		if strings.TrimSpace(fmt.Sprint(hook.Config["insecure_ssl"])) == "1" {
			insecureSSL++
		}
		if hook.LastResp != nil && hook.LastResp.Code >= 400 {
			failing++
		}
	}
	evidence := map[string]any{
		"repository":         repository,
		"webhook_count":      len(hooks),
		"active_webhooks":    active,
		"insecure_ssl_hooks": insecureSSL,
		"failing_webhooks":   failing,
	}
	if insecureSSL > 0 || failing > 0 {
		return RepositoryPostureCheck{
			ID:       "webhooks",
			Category: "webhooks",
			State:    RepositoryPostureStateInsecure,
			Reason:   "risky_webhooks_present",
			Summary:  "Repository has webhooks with insecure SSL or failing delivery status.",
			Evidence: evidence,
		}
	}
	return RepositoryPostureCheck{
		ID:       "webhooks",
		Category: "webhooks",
		State:    RepositoryPostureStateSecure,
		Reason:   "no_risky_webhooks",
		Summary:  "No insecure or failing repository webhooks were returned.",
		Evidence: evidence,
	}
}

func (c RepositoryClient) collectEnvironments(ctx context.Context, token string, repository string, updateRate func(*GitHubRateLimitState)) RepositoryPostureCheck {
	totalCount := 0
	environments := []repositoryEnvironment{}
	rateLimit, err := c.getJSONPages(ctx, token, c.repositoryEndpoint(repository, "/environments?per_page=100"), func(body []byte) error {
		var page repositoryEnvironmentPage
		if err := json.Unmarshal(body, &page); err != nil {
			return err
		}
		if page.TotalCount > totalCount {
			totalCount = page.TotalCount
		}
		environments = append(environments, page.Environments...)
		return nil
	})
	updateRate(rateLimit)
	if err != nil {
		return checkFromAPIError("deployment_environments", "deployments", err, RepositoryPostureStateUnavailable, "api_unavailable", "Deployment environments could not be collected.")
	}
	unprotected := 0
	for _, environment := range environments {
		if len(environment.ProtectionRules) == 0 {
			unprotected++
		}
	}
	if totalCount < len(environments) {
		totalCount = len(environments)
	}
	evidence := map[string]any{
		"repository":               repository,
		"environment_count":        totalCount,
		"unprotected_environments": unprotected,
	}
	if totalCount > 0 && unprotected > 0 {
		return RepositoryPostureCheck{
			ID:       "deployment_environments",
			Category: "deployments",
			State:    RepositoryPostureStateInsecure,
			Reason:   "unprotected_environments",
			Summary:  "One or more deployment environments do not report protection rules.",
			Evidence: evidence,
		}
	}
	return RepositoryPostureCheck{
		ID:       "deployment_environments",
		Category: "deployments",
		State:    RepositoryPostureStateSecure,
		Reason:   "environments_protected_or_absent",
		Summary:  "Deployment environments are protected or none were returned.",
		Evidence: evidence,
	}
}

// collectSelfHostedRunners reports whether the repository can run jobs on
// self-hosted GitHub Actions runners. Self-hosted runners are a machine-identity
// risk boundary because they can hold persistent cloud, deployment, registry, or
// internal-network credentials. The repository runner list is the authoritative
// repo-scope signal; organization runner-group breadth is collected best-effort
// and recorded as evidence rather than failing the whole check when the App
// lacks organization permission. Evidence is summary-shaped: it never includes
// runner registration tokens, runner host names, or other secret-bearing values.
func (c RepositoryClient) collectSelfHostedRunners(ctx context.Context, token string, repository string, updateRate func(*GitHubRateLimitState)) RepositoryPostureCheck {
	runners := []actionsRunner{}
	rateLimit, err := c.getJSONPages(ctx, token, c.repositoryEndpoint(repository, "/actions/runners?per_page=100"), func(body []byte) error {
		var page actionsRunnerPage
		if err := json.Unmarshal(body, &page); err != nil {
			return err
		}
		runners = append(runners, page.Runners...)
		return nil
	})
	updateRate(rateLimit)
	if err != nil {
		return checkFromAPIError("self_hosted_runners", "runners", err, RepositoryPostureStateUnavailable, "api_unavailable", "Self-hosted runner posture could not be collected.")
	}

	online, offline, busy := 0, 0, 0
	labelSet := map[string]struct{}{}
	osSet := map[string]struct{}{}
	for _, runner := range runners {
		switch strings.ToLower(strings.TrimSpace(runner.Status)) {
		case "online":
			online++
		case "offline":
			offline++
		}
		if runner.Busy {
			busy++
		}
		for _, label := range runner.Labels {
			if name := strings.TrimSpace(label.Name); name != "" {
				labelSet[name] = struct{}{}
			}
		}
		if os := strings.TrimSpace(runner.OS); os != "" {
			osSet[os] = struct{}{}
		}
	}

	evidence := map[string]any{
		"repository":               repository,
		"self_hosted_runner_count": len(runners),
		"online_runners":           online,
		"offline_runners":          offline,
		"busy_runners":             busy,
	}
	if len(labelSet) > 0 {
		evidence["runner_labels"] = sortedStringSet(labelSet)
	}
	if len(osSet) > 0 {
		evidence["runner_os"] = sortedStringSet(osSet)
	}

	groupsState, broadGroups, publicRepoGroups, groupCount := c.collectOrgRunnerGroupBreadth(ctx, token, repository, updateRate)
	evidence["runner_groups_state"] = string(groupsState)
	if groupsState == RepositoryPostureStateSecure || groupsState == RepositoryPostureStateInsecure {
		evidence["org_runner_groups"] = groupCount
		evidence["broadly_available_runner_groups"] = broadGroups
		evidence["public_repository_runner_groups"] = publicRepoGroups
	}

	if len(runners) > 0 || broadGroups > 0 || publicRepoGroups > 0 {
		reason := "self_hosted_runners_present"
		summary := "Repository can use self-hosted GitHub Actions runners, which hold persistent credentials and require isolation from untrusted workflows."
		if len(runners) == 0 {
			reason = "broad_runner_groups_available"
			summary = "Organization runner groups available to this repository are broadly shared or allow public repositories."
		}
		return RepositoryPostureCheck{
			ID:       "self_hosted_runners",
			Category: "runners",
			State:    RepositoryPostureStateInsecure,
			Reason:   reason,
			Summary:  summary,
			Evidence: evidence,
		}
	}
	if groupsState != RepositoryPostureStateSecure {
		summary := "Self-hosted runner group visibility is not fully observable, so repository runner posture could not be fully verified."
		return RepositoryPostureCheck{
			ID:       "self_hosted_runners",
			Category: "runners",
			State:    groupsState,
			Reason:   "runner_group_visibility_unknown",
			Summary:  summary,
			Evidence: evidence,
		}
	}
	return RepositoryPostureCheck{
		ID:       "self_hosted_runners",
		Category: "runners",
		State:    RepositoryPostureStateSecure,
		Reason:   "no_self_hosted_runners",
		Summary:  "No self-hosted runners or broadly shared runner groups were visible to the installation.",
		Evidence: evidence,
	}
}

// collectOrgRunnerGroupBreadth inspects organization runner groups available to
// the repository. It returns a normalized state plus broad/public/total counts.
// Personal repositories and installations without organization permission return
// permission_limited; rate limits and other failures return unavailable.
func (c RepositoryClient) collectOrgRunnerGroupBreadth(ctx context.Context, token string, repository string, updateRate func(*GitHubRateLimitState)) (RepositoryPostureState, int, int, int) {
	normalizedRepository, err := normalizeRepositoryName(repository)
	if err != nil {
		return RepositoryPostureStateUnavailable, 0, 0, 0
	}
	groupEndpoint := c.repositoryEndpoint(normalizedRepository, "/actions/runner-groups?per_page=100")
	org := strings.SplitN(normalizedRepository, "/", 2)[0]
	fallbackToOrg := false
	groups := []orgRunnerGroup{}
	fetchGroups := func(endpoint string) (*GitHubRateLimitState, error) {
		groups = []orgRunnerGroup{}
		rateLimit, err := c.getJSONPages(ctx, token, endpoint, func(body []byte) error {
			var page orgRunnerGroupPage
			if err := json.Unmarshal(body, &page); err != nil {
				return err
			}
			groups = append(groups, page.RunnerGroups...)
			return nil
		})
		updateRate(rateLimit)
		return rateLimit, err
	}

	_, err = fetchGroups(groupEndpoint)
	if err != nil {
		apiErr, ok := asGitHubAPIError(err)
		if !ok {
			return RepositoryPostureStateUnavailable, 0, 0, 0
		}
		if apiErr.StatusCode == http.StatusNotFound {
			_, err = fetchGroups(c.orgEndpoint(org, "/actions/runner-groups?per_page=100"))
			fallbackToOrg = true
		} else {
			if apiErr.RateLimited {
				return RepositoryPostureStateUnavailable, 0, 0, 0
			}
			switch apiErr.StatusCode {
			case http.StatusForbidden, http.StatusUnauthorized:
				return RepositoryPostureStatePermissionLimited, 0, 0, 0
			case http.StatusNotFound:
				return RepositoryPostureStateUnavailable, 0, 0, 0
			default:
				return RepositoryPostureStateUnavailable, 0, 0, 0
			}
		}
	}
	if err != nil {
		apiErr, ok := asGitHubAPIError(err)
		if !ok {
			return RepositoryPostureStateUnavailable, 0, 0, 0
		}
		if apiErr.RateLimited {
			return RepositoryPostureStateUnavailable, 0, 0, 0
		}
		switch apiErr.StatusCode {
		case http.StatusForbidden, http.StatusUnauthorized:
			return RepositoryPostureStatePermissionLimited, 0, 0, 0
		case http.StatusNotFound:
			return RepositoryPostureStateUnavailable, 0, 0, 0
		default:
			return RepositoryPostureStateUnavailable, 0, 0, 0
		}
	}
	broad := 0
	publicRepoGroups := 0
	for _, group := range groups {
		if fallbackToOrg && strings.EqualFold(strings.TrimSpace(group.Visibility), "selected") {
			hasAccess, accessErr := c.repositoryInOrgRunnerGroup(ctx, token, org, group.ID, normalizedRepository, updateRate)
			if accessErr != nil {
				if apiErr, ok := asGitHubAPIError(accessErr); ok {
					if apiErr.RateLimited {
						return RepositoryPostureStateUnavailable, 0, 0, 0
					}
					switch apiErr.StatusCode {
					case http.StatusForbidden, http.StatusUnauthorized:
						return RepositoryPostureStatePermissionLimited, 0, 0, 0
					case http.StatusNotFound:
						return RepositoryPostureStateUnavailable, 0, 0, 0
					default:
						return RepositoryPostureStateUnavailable, 0, 0, 0
					}
				}
				return RepositoryPostureStateUnavailable, 0, 0, 0
			}
			if !hasAccess {
				continue
			}
		}

		if strings.EqualFold(strings.TrimSpace(group.Visibility), "all") {
			broad++
		}
		if group.AllowsPublicRepositories {
			publicRepoGroups++
		}
	}
	state := RepositoryPostureStateSecure
	if broad > 0 || publicRepoGroups > 0 {
		state = RepositoryPostureStateInsecure
	}
	return state, broad, publicRepoGroups, len(groups)
}

func (c RepositoryClient) repositoryInOrgRunnerGroup(
	ctx context.Context,
	token string,
	org string,
	groupID int64,
	repository string,
	updateRate func(*GitHubRateLimitState),
) (bool, error) {
	repository = strings.ToLower(strings.TrimSpace(repository))
	groupReposEndpoint := c.orgEndpoint(org, fmt.Sprintf("/actions/runner-groups/%d/repositories?per_page=100", groupID))
	groupHasRepo := false
	rateLimit, err := c.getJSONPages(ctx, token, groupReposEndpoint, func(body []byte) error {
		var page orgRunnerGroupRepositoryPage
		if err := json.Unmarshal(body, &page); err != nil {
			return err
		}
		if groupHasRepo {
			return nil
		}
		for _, repo := range page.Repositories {
			if strings.EqualFold(strings.TrimSpace(repo.FullName), repository) {
				groupHasRepo = true
				return nil
			}
		}
		return nil
	})
	updateRate(rateLimit)
	if err != nil {
		return false, err
	}
	return groupHasRepo, nil
}

func (c RepositoryClient) featureStatus(ctx context.Context, token string, endpoint string) (bool, *GitHubRateLimitState, error) {
	rateLimit, err := c.doGitHubRequest(ctx, token, http.MethodGet, endpoint, nil)
	if err != nil {
		if apiErr, ok := asGitHubAPIError(err); ok && apiErr.StatusCode == http.StatusNotFound {
			return false, apiErr.RateLimit, nil
		}
		return false, rateLimit, err
	}
	return true, rateLimit, nil
}

func checkFromAPIError(id string, category string, err error, notFoundState RepositoryPostureState, notFoundReason string, notFoundSummary string) RepositoryPostureCheck {
	evidence := map[string]any{}
	if apiErr, ok := asGitHubAPIError(err); ok {
		state := RepositoryPostureStateUnavailable
		reason := "api_unavailable"
		summary := "GitHub API did not return this posture signal."
		switch {
		case apiErr.StatusCode == http.StatusNotFound:
			state = notFoundState
			reason = notFoundReason
			summary = notFoundSummary
		case apiErr.StatusCode == http.StatusForbidden || apiErr.StatusCode == http.StatusUnauthorized:
			if apiErr.RateLimited {
				state = RepositoryPostureStateUnavailable
				reason = "rate_limited"
				summary = "GitHub rate limit prevented this posture signal from being collected."
			} else {
				state = RepositoryPostureStatePermissionLimited
				reason = "permission_limited"
				summary = "GitHub App permissions do not allow this posture signal to be collected."
			}
		case apiErr.RateLimited:
			state = RepositoryPostureStateUnavailable
			reason = "rate_limited"
			summary = "GitHub rate limit prevented this posture signal from being collected."
		}
		evidence["status_code"] = apiErr.StatusCode
		if apiErr.Message != "" {
			evidence["message"] = apiErr.Message
		}
		if apiErr.RetryAfter != "" {
			evidence["retry_after"] = apiErr.RetryAfter
		}
		return RepositoryPostureCheck{
			ID:       id,
			Category: category,
			State:    state,
			Reason:   reason,
			Summary:  summary,
			Evidence: evidence,
		}
	}
	evidence["error"] = err.Error()
	return RepositoryPostureCheck{
		ID:       id,
		Category: category,
		State:    RepositoryPostureStateUnavailable,
		Reason:   "api_unavailable",
		Summary:  "GitHub API did not return this posture signal.",
		Evidence: evidence,
	}
}

func asGitHubAPIError(err error) (githubAPIRequestError, bool) {
	apiErr, ok := err.(githubAPIRequestError)
	return apiErr, ok
}

func (c RepositoryClient) getJSON(ctx context.Context, token string, endpoint string, out any) (*GitHubRateLimitState, error) {
	return c.doGitHubRequest(ctx, token, http.MethodGet, endpoint, out)
}

func (c RepositoryClient) getJSONPages(ctx context.Context, token string, endpoint string, decode func([]byte) error) (*GitHubRateLimitState, error) {
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
	}
	return lastRateLimit, nil
}

func (c RepositoryClient) doGitHubRequest(ctx context.Context, token string, method string, endpoint string, out any) (*GitHubRateLimitState, error) {
	body, rateLimit, _, err := c.doGitHubRequestRaw(ctx, token, method, endpoint)
	if err != nil {
		return rateLimit, err
	}
	if out == nil {
		return rateLimit, nil
	}
	if err := json.Unmarshal(body, out); err != nil {
		return rateLimit, fmt.Errorf("decode github posture response: %w", err)
	}
	return rateLimit, nil
}

func (c RepositoryClient) doGitHubRequestRaw(ctx context.Context, token string, method string, endpoint string) ([]byte, *GitHubRateLimitState, string, error) {
	req, err := http.NewRequestWithContext(ctx, method, endpoint, nil)
	if err != nil {
		return nil, nil, "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	res, err := c.httpClient().Do(req)
	if err != nil {
		return nil, nil, "", fmt.Errorf("call github posture api: %w", err)
	}
	body, bodyErr := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	closeErr := res.Body.Close()
	if bodyErr != nil {
		return nil, nil, "", fmt.Errorf("read github posture response body: %w", bodyErr)
	}
	if closeErr != nil {
		return nil, nil, "", fmt.Errorf("close github posture response body: %w", closeErr)
	}
	rateLimit := rateLimitStateFromHeaders(res.Header)
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		message := githubAPIErrorMessage(body)
		return nil, rateLimit, "", githubAPIRequestError{
			StatusCode:   res.StatusCode,
			Message:      message,
			RateLimited:  githubRateLimited(res.StatusCode, res.Header, message),
			RetryAfter:   strings.TrimSpace(res.Header.Get("Retry-After")),
			RateLimit:    rateLimit,
			ResponsePath: req.URL.Path,
		}
	}
	return body, rateLimit, res.Header.Get("Link"), nil
}

func githubAPIErrorMessage(body []byte) string {
	var payload struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &payload); err == nil {
		return strings.TrimSpace(payload.Message)
	}
	return strings.TrimSpace(string(body))
}

func githubRateLimited(statusCode int, header http.Header, message string) bool {
	if statusCode == http.StatusTooManyRequests {
		return true
	}
	if statusCode != http.StatusForbidden {
		return false
	}
	if strings.TrimSpace(header.Get("X-RateLimit-Remaining")) == "0" {
		return true
	}
	if strings.TrimSpace(header.Get("Retry-After")) != "" {
		return true
	}
	return strings.Contains(strings.ToLower(message), "rate limit")
}

func rateLimitStateFromHeaders(header http.Header) *GitHubRateLimitState {
	limit, hasLimit := parseHeaderInt(header.Get("X-RateLimit-Limit"))
	remaining, hasRemaining := parseHeaderInt(header.Get("X-RateLimit-Remaining"))
	resetUnix, hasReset := parseHeaderInt(header.Get("X-RateLimit-Reset"))
	if !hasLimit && !hasRemaining && !hasReset {
		return nil
	}
	var resetAt *time.Time
	if hasReset && resetUnix > 0 {
		reset := time.Unix(int64(resetUnix), 0).UTC()
		resetAt = &reset
	}
	return &GitHubRateLimitState{
		Limit:     limit,
		Remaining: remaining,
		ResetAt:   resetAt,
	}
}

func parseHeaderInt(value string) (int, bool) {
	parsed, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		return 0, false
	}
	return parsed, true
}

func (c RepositoryClient) repositoryEndpoint(repository string, suffix string) string {
	parts := strings.Split(repository, "/")
	return strings.TrimRight(c.apiBaseURL(), "/") + "/repos/" + url.PathEscape(parts[0]) + "/" + url.PathEscape(parts[1]) + suffix
}

func (c RepositoryClient) orgEndpoint(org string, suffix string) string {
	return strings.TrimRight(c.apiBaseURL(), "/") + "/orgs/" + url.PathEscape(org) + suffix
}

func sortedStringSet(set map[string]struct{}) []string {
	keys := make([]string, 0, len(set))
	for key := range set {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func normalizeRepositoryName(repository string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(repository))
	if normalized == "" || strings.Count(normalized, "/") != 1 {
		return "", fmt.Errorf("github repository must be owner/name")
	}
	parts := strings.Split(normalized, "/")
	if strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
		return "", fmt.Errorf("github repository must be owner/name")
	}
	return normalized, nil
}

func (c RepositoryClient) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}
