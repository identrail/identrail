package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// OrganizationPosture describes organization-level GitHub security policy that
// is inherited by every repository in the organization. It is collected
// separately from RepositoryPosture so consumers can distinguish risk that is
// local to a repository from risk inherited from the organization policy plane.
type OrganizationPosture struct {
	Organization   string                   `json:"organization"`
	InstallationID int64                    `json:"installation_id,omitempty"`
	CollectedAt    time.Time                `json:"collected_at"`
	Checks         []RepositoryPostureCheck `json:"checks"`
	RateLimit      *GitHubRateLimitState    `json:"rate_limit,omitempty"`
}

type organizationActionsPermissions struct {
	EnabledRepositories string `json:"enabled_repositories"`
	AllowedActions      string `json:"allowed_actions"`
}

type organizationWorkflowPermissions struct {
	DefaultWorkflowPermissions   string `json:"default_workflow_permissions"`
	CanApprovePullRequestReviews bool   `json:"can_approve_pull_request_reviews"`
}

type organizationActionsRepositoryPage struct {
	TotalCount   int `json:"total_count"`
	Repositories []struct {
		FullName string `json:"full_name"`
	} `json:"repositories"`
}

var errStopOrgActionsRepositoryPaging = errors.New("stop org actions repository paging")

type organizationSelectedActions struct {
	GitHubOwnedAllowed *bool    `json:"github_owned_allowed"`
	VerifiedAllowed    *bool    `json:"verified_allowed"`
	PatternsAllowed    []string `json:"patterns_allowed"`
}

type organizationCodeSecurityConfiguration struct {
	ID                           int64  `json:"id"`
	Name                         string `json:"name"`
	TargetType                   string `json:"target_type"`
	Enforcement                  string `json:"enforcement"`
	SecretScanning               string `json:"secret_scanning"`
	SecretScanningPushProtection string `json:"secret_scanning_push_protection"`
	DependabotAlerts             string `json:"dependabot_alerts"`
	CodeScanningDefaultSetup     string `json:"code_scanning_default_setup"`
}

type organizationCodeSecurityConfigurationItem struct {
	organizationCodeSecurityConfiguration
	Configuration organizationCodeSecurityConfiguration `json:"configuration"`
}

type repositoryCodeSecurityConfiguration struct {
	Status        string                                `json:"status"`
	Configuration organizationCodeSecurityConfiguration `json:"configuration"`
}

// CollectOrganizationPosture collects normalized organization-level security
// posture for the organization that owns a scanned repository. Each endpoint
// contributes one check; permission-limited, unavailable, unsupported, and
// unknown states are reported explicitly and never collapse into "secure".
func (c RepositoryClient) CollectOrganizationPosture(ctx context.Context, installationID int64, organization string, repository string) (OrganizationPosture, error) {
	if c.TokenClient == nil {
		return OrganizationPosture{}, fmt.Errorf("github installation token client is required")
	}
	org, err := normalizeOrganizationName(organization)
	if err != nil {
		return OrganizationPosture{}, err
	}
	normalizedRepository, err := normalizeRepositoryName(repository)
	if err != nil {
		return OrganizationPosture{}, err
	}
	if owner, _, ok := strings.Cut(normalizedRepository, "/"); !ok || owner != org {
		return OrganizationPosture{}, fmt.Errorf("github repository must belong to organization %q", org)
	}
	token, err := c.TokenClient.Mint(ctx, installationID)
	if err != nil {
		return OrganizationPosture{}, err
	}

	posture := OrganizationPosture{
		Organization:   org,
		InstallationID: installationID,
		CollectedAt:    c.now().UTC(),
		Checks:         make([]RepositoryPostureCheck, 0, 5),
	}
	updateRate := func(limit *GitHubRateLimitState) {
		if limit != nil {
			posture.RateLimit = limit
		}
	}

	codeSecurityConfigurations, codeSecurityErr := c.collectOrgCodeSecurityConfigurations(ctx, token.Token, org, updateRate)
	var repositoryCodeSecurity *repositoryCodeSecurityConfiguration
	var repositoryCodeSecurityErr error
	if codeSecurityErr == nil && shouldCollectRepositoryCodeSecurityConfiguration(codeSecurityConfigurations) {
		repositoryCodeSecurity, repositoryCodeSecurityErr = c.collectRepositoryCodeSecurityConfiguration(ctx, token.Token, normalizedRepository, updateRate)
	}
	posture.Checks = append(posture.Checks, collectOrgSecretScanningPolicy(org, normalizedRepository, codeSecurityConfigurations, codeSecurityErr, repositoryCodeSecurity, repositoryCodeSecurityErr))
	actionsPolicy := c.collectOrgActionsPolicy(ctx, token.Token, org, normalizedRepository, updateRate)
	posture.Checks = append(posture.Checks, actionsPolicy)
	posture.Checks = append(posture.Checks, c.collectOrgWorkflowPermissions(ctx, token.Token, org, actionsPolicy, updateRate))
	posture.Checks = append(posture.Checks, c.collectOrgReusableWorkflowPolicy(ctx, token.Token, org, actionsPolicy, updateRate))
	posture.Checks = append(posture.Checks, collectOrgCodeSecurityConfiguration(org, normalizedRepository, codeSecurityConfigurations, codeSecurityErr, repositoryCodeSecurity, repositoryCodeSecurityErr))

	if organizationPostureMayBeUserOwner(posture) {
		exists, existsErr := c.githubOrganizationExists(ctx, token.Token, org, updateRate)
		if existsErr == nil && !exists {
			return organizationPostureNotAnOrganization(posture), nil
		}
	}

	return posture, nil
}

func collectOrgSecretScanningPolicy(org string, repository string, configurations []organizationCodeSecurityConfiguration, err error, repositoryConfiguration *repositoryCodeSecurityConfiguration, repositoryErr error) RepositoryPostureCheck {
	if err != nil {
		return checkFromAPIError(
			"org_secret_scanning_policy",
			"secret_scanning",
			err,
			RepositoryPostureStateUnsupported,
			"plan_unavailable",
			"Organization code security configurations are not available for this account or plan.",
		)
	}
	evidence := orgCodeSecurityConfigurationEvidence(org, configurations)
	if enforcedSecretScanningPolicyCount(configurations) == 0 {
		return RepositoryPostureCheck{
			ID:       "org_secret_scanning_policy",
			Category: "secret_scanning",
			State:    RepositoryPostureStateInsecure,
			Reason:   "secret_scanning_policy_weak",
			Summary:  "Organization does not enforce secret scanning and push protection through an organization code security configuration.",
			Evidence: evidence,
		}
	}
	if repositoryErr != nil {
		return checkFromAPIError(
			"org_secret_scanning_policy",
			"secret_scanning",
			repositoryErr,
			RepositoryPostureStateInsecure,
			"secret_scanning_policy_weak",
			"GitHub did not report an organization code security configuration for this repository.",
		)
	}
	evidence = addRepositoryCodeSecurityConfigurationEvidence(evidence, repository, repositoryConfiguration)
	if !repositoryCodeSecurityConfigurationApplies(repositoryConfiguration) || !organizationSecretScanningConfigurationProtective(repositoryConfiguration.Configuration) {
		return RepositoryPostureCheck{
			ID:       "org_secret_scanning_policy",
			Category: "secret_scanning",
			State:    RepositoryPostureStateInsecure,
			Reason:   "secret_scanning_policy_weak",
			Summary:  "Scanned repository is not attached to an enforced organization code security configuration with secret scanning and push protection.",
			Evidence: evidence,
		}
	}
	return RepositoryPostureCheck{
		ID:       "org_secret_scanning_policy",
		Category: "secret_scanning",
		State:    RepositoryPostureStateSecure,
		Reason:   "secret_scanning_policy_enforced",
		Summary:  "Scanned repository inherits secret scanning and push protection from an enforced organization code security configuration.",
		Evidence: evidence,
	}
}

func (c RepositoryClient) collectOrgActionsPolicy(ctx context.Context, token string, org string, repository string, updateRate func(*GitHubRateLimitState)) RepositoryPostureCheck {
	var permissions organizationActionsPermissions
	rateLimit, err := c.getJSON(ctx, token, c.orgEndpoint(org, "/actions/permissions"), &permissions)
	updateRate(rateLimit)
	if err != nil {
		return checkFromAPIError(
			"org_actions_policy",
			"actions",
			err,
			RepositoryPostureStateUnsupported,
			"organization_policy_unavailable",
			"GitHub did not expose an organization Actions policy for this account.",
		)
	}
	allowed := strings.ToLower(strings.TrimSpace(permissions.AllowedActions))
	enabledRepos := strings.ToLower(strings.TrimSpace(permissions.EnabledRepositories))
	evidence := map[string]any{
		"organization":         org,
		"repository":           repository,
		"allowed_actions":      allowed,
		"enabled_repositories": enabledRepos,
	}
	if enabledRepos == "none" {
		return RepositoryPostureCheck{
			ID:       "org_actions_policy",
			Category: "actions",
			State:    RepositoryPostureStateSecure,
			Reason:   "actions_disabled",
			Summary:  "Organization disables GitHub Actions for all repositories.",
			Evidence: evidence,
		}
	}
	if enabledRepos == "selected" {
		selected, err := c.orgActionsRepositorySelected(ctx, token, org, repository, updateRate)
		if err != nil {
			return checkFromAPIError(
				"org_actions_policy",
				"actions",
				err,
				RepositoryPostureStateUnsupported,
				"organization_selected_repositories_unavailable",
				"GitHub did not expose the organization Actions selected-repository list for this account.",
			)
		}
		evidence["repository_selected"] = selected
		if !selected {
			return RepositoryPostureCheck{
				ID:       "org_actions_policy",
				Category: "actions",
				State:    RepositoryPostureStateSecure,
				Reason:   "actions_not_enabled_for_repository",
				Summary:  "Organization enables GitHub Actions only for selected repositories, and this repository is not selected.",
				Evidence: evidence,
			}
		}
	}
	if allowed == "" {
		return RepositoryPostureCheck{
			ID:       "org_actions_policy",
			Category: "actions",
			State:    RepositoryPostureStateUnknown,
			Reason:   "policy_unclassified",
			Summary:  "Organization Actions policy did not report an allowed-actions setting.",
			Evidence: evidence,
		}
	}
	if allowed == "all" {
		return RepositoryPostureCheck{
			ID:       "org_actions_policy",
			Category: "actions",
			State:    RepositoryPostureStateInsecure,
			Reason:   "broad_actions_policy",
			Summary:  "Organization allows any action, including untrusted third-party actions.",
			Evidence: evidence,
		}
	}
	return RepositoryPostureCheck{
		ID:       "org_actions_policy",
		Category: "actions",
		State:    RepositoryPostureStateSecure,
		Reason:   "restricted_actions_policy",
		Summary:  "Organization restricts which actions may run.",
		Evidence: evidence,
	}
}

func (c RepositoryClient) collectOrgWorkflowPermissions(ctx context.Context, token string, org string, actionsPolicy RepositoryPostureCheck, updateRate func(*GitHubRateLimitState)) RepositoryPostureCheck {
	if orgActionsUnavailable(actionsPolicy) {
		return RepositoryPostureCheck{
			ID:       "org_workflow_permissions",
			Category: "actions",
			State:    RepositoryPostureStateSecure,
			Reason:   actionsPolicy.Reason,
			Summary:  "Organization Actions policy does not enable Actions for this repository, so workflow token permissions cannot be exercised.",
			Evidence: orgActionsEvidence(org, actionsPolicy),
		}
	}
	var workflow organizationWorkflowPermissions
	rateLimit, err := c.getJSON(ctx, token, c.orgEndpoint(org, "/actions/permissions/workflow"), &workflow)
	updateRate(rateLimit)
	if err != nil {
		return checkFromAPIError(
			"org_workflow_permissions",
			"actions",
			err,
			RepositoryPostureStateUnsupported,
			"organization_policy_unavailable",
			"GitHub did not expose organization default workflow permissions for this account.",
		)
	}
	defaultPermissions := strings.ToLower(strings.TrimSpace(workflow.DefaultWorkflowPermissions))
	evidence := map[string]any{
		"organization":                     org,
		"default_workflow_permissions":     defaultPermissions,
		"can_approve_pull_request_reviews": workflow.CanApprovePullRequestReviews,
	}
	if defaultPermissions == "" {
		return RepositoryPostureCheck{
			ID:       "org_workflow_permissions",
			Category: "actions",
			State:    RepositoryPostureStateUnknown,
			Reason:   "policy_unclassified",
			Summary:  "Organization workflow policy did not report a default token permission.",
			Evidence: evidence,
		}
	}
	if defaultPermissions == "write" || workflow.CanApprovePullRequestReviews {
		return RepositoryPostureCheck{
			ID:       "org_workflow_permissions",
			Category: "actions",
			State:    RepositoryPostureStateInsecure,
			Reason:   "write_token_or_pr_approval",
			Summary:  "Organization grants write-scoped default workflow tokens or lets Actions approve pull requests.",
			Evidence: evidence,
		}
	}
	return RepositoryPostureCheck{
		ID:       "org_workflow_permissions",
		Category: "actions",
		State:    RepositoryPostureStateSecure,
		Reason:   "least_privilege_workflows",
		Summary:  "Organization default workflow tokens are read-only and cannot approve pull requests.",
		Evidence: evidence,
	}
}

func (c RepositoryClient) orgActionsRepositorySelected(ctx context.Context, token string, org string, repository string, updateRate func(*GitHubRateLimitState)) (bool, error) {
	repository = strings.ToLower(strings.TrimSpace(repository))
	selected := false
	endpoint := c.orgEndpoint(org, "/actions/permissions/repositories?per_page=100")
	rateLimit, err := c.getJSONPages(ctx, token, endpoint, func(body []byte) error {
		var page organizationActionsRepositoryPage
		if err := json.Unmarshal(body, &page); err != nil {
			return err
		}
		if selected {
			return nil
		}
		for _, repo := range page.Repositories {
			if strings.EqualFold(strings.TrimSpace(repo.FullName), repository) {
				selected = true
				return errStopOrgActionsRepositoryPaging
			}
		}
		return nil
	})
	updateRate(rateLimit)
	if errors.Is(err, errStopOrgActionsRepositoryPaging) {
		err = nil
	}
	if err != nil {
		return false, err
	}
	return selected, nil
}

func orgActionsUnavailable(actionsPolicy RepositoryPostureCheck) bool {
	return actionsPolicy.ID == "org_actions_policy" && (actionsPolicy.Reason == "actions_disabled" || actionsPolicy.Reason == "actions_not_enabled_for_repository")
}

func orgActionsEvidence(org string, actionsPolicy RepositoryPostureCheck) map[string]any {
	evidence := map[string]any{"organization": org}
	for _, key := range []string{"repository", "enabled_repositories", "allowed_actions", "repository_selected"} {
		if value, ok := actionsPolicy.Evidence[key]; ok {
			evidence[key] = value
		}
	}
	return evidence
}

func (c RepositoryClient) collectOrgReusableWorkflowPolicy(ctx context.Context, token string, org string, actionsPolicy RepositoryPostureCheck, updateRate func(*GitHubRateLimitState)) RepositoryPostureCheck {
	if selectedActionsApplicable, known := orgSelectedActionsPolicyApplicable(actionsPolicy); known && !selectedActionsApplicable {
		return orgReusableWorkflowPolicyNotApplicable(org, actionsPolicy)
	}
	var selected organizationSelectedActions
	rateLimit, err := c.getJSON(ctx, token, c.orgEndpoint(org, "/actions/permissions/selected-actions"), &selected)
	updateRate(rateLimit)
	if err != nil {
		if apiErr, ok := asGitHubAPIError(err); ok && apiErr.StatusCode == http.StatusConflict {
			return orgReusableWorkflowPolicyNotApplicable(org, actionsPolicy)
		}
		return checkFromAPIError(
			"org_reusable_workflow_policy",
			"actions",
			err,
			RepositoryPostureStateUnsupported,
			"organization_policy_unavailable",
			"GitHub did not expose an organization reusable workflow allowlist for this account.",
		)
	}
	if selected.GitHubOwnedAllowed == nil && selected.VerifiedAllowed == nil {
		return RepositoryPostureCheck{
			ID:       "org_reusable_workflow_policy",
			Category: "actions",
			State:    RepositoryPostureStateUnknown,
			Reason:   "policy_unclassified",
			Summary:  "Organization selected-actions policy did not report allowlist settings.",
			Evidence: map[string]any{"organization": org},
		}
	}
	verified := boolValue(selected.VerifiedAllowed)
	evidence := map[string]any{
		"organization":          org,
		"github_owned_allowed":  boolValue(selected.GitHubOwnedAllowed),
		"verified_allowed":      verified,
		"allowed_pattern_count": len(selected.PatternsAllowed),
	}
	if verified {
		return RepositoryPostureCheck{
			ID:       "org_reusable_workflow_policy",
			Category: "actions",
			State:    RepositoryPostureStateInsecure,
			Reason:   "verified_creators_allowed",
			Summary:  "Organization allows all verified-creator actions instead of an explicit pinned allowlist.",
			Evidence: evidence,
		}
	}
	if riskyPatterns := riskySelectedActionPatterns(selected.PatternsAllowed); len(riskyPatterns) > 0 {
		evidence["risky_pattern_count"] = len(riskyPatterns)
		evidence["risky_pattern_examples"] = sampleStrings(riskyPatterns, 3)
		return RepositoryPostureCheck{
			ID:       "org_reusable_workflow_policy",
			Category: "actions",
			State:    RepositoryPostureStateInsecure,
			Reason:   "broad_action_allowlist",
			Summary:  "Organization selected-actions allowlist includes broad or unpinned patterns.",
			Evidence: evidence,
		}
	}
	return RepositoryPostureCheck{
		ID:       "org_reusable_workflow_policy",
		Category: "actions",
		State:    RepositoryPostureStateSecure,
		Reason:   "restricted_action_sources",
		Summary:  "Organization restricts actions to GitHub-owned actions and an explicit allowlist.",
		Evidence: evidence,
	}
}

func orgSelectedActionsPolicyApplicable(actionsPolicy RepositoryPostureCheck) (bool, bool) {
	if actionsPolicy.ID != "org_actions_policy" {
		return true, false
	}
	enabledRepos, hasEnabledRepos := stringEvidence(actionsPolicy.Evidence, "enabled_repositories")
	if hasEnabledRepos && enabledRepos == "none" {
		return false, true
	}
	if hasEnabledRepos && enabledRepos == "selected" {
		if selected, ok := boolEvidence(actionsPolicy.Evidence, "repository_selected"); ok && !selected {
			return false, true
		}
	}
	allowedActions, hasAllowedActions := stringEvidence(actionsPolicy.Evidence, "allowed_actions")
	if hasAllowedActions {
		if allowedActions == "" {
			return true, false
		}
		return allowedActions == "selected", true
	}
	return true, false
}

func orgReusableWorkflowPolicyNotApplicable(org string, actionsPolicy RepositoryPostureCheck) RepositoryPostureCheck {
	evidence := map[string]any{"organization": org}
	for _, key := range []string{"repository", "enabled_repositories", "allowed_actions", "repository_selected"} {
		if value, ok := actionsPolicy.Evidence[key]; ok {
			evidence[key] = value
		}
	}
	return RepositoryPostureCheck{
		ID:       "org_reusable_workflow_policy",
		Category: "actions",
		State:    RepositoryPostureStateSecure,
		Reason:   "not_applicable",
		Summary:  "Reusable workflow allowlist applies only when the organization Actions policy is set to selected actions.",
		Evidence: evidence,
	}
}

func stringEvidence(evidence map[string]any, key string) (string, bool) {
	value, ok := evidence[key]
	if !ok {
		return "", false
	}
	text, ok := value.(string)
	if !ok {
		return "", false
	}
	return strings.ToLower(strings.TrimSpace(text)), true
}

func boolEvidence(evidence map[string]any, key string) (bool, bool) {
	value, ok := evidence[key]
	if !ok {
		return false, false
	}
	enabled, ok := value.(bool)
	return enabled, ok
}

func riskySelectedActionPatterns(patterns []string) []string {
	risky := make([]string, 0)
	for _, pattern := range patterns {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			continue
		}
		if selectedActionPatternRisky(pattern) {
			risky = append(risky, pattern)
		}
	}
	return risky
}

func selectedActionPatternRisky(pattern string) bool {
	if strings.Contains(pattern, "*") {
		return true
	}
	_, ref, ok := strings.Cut(pattern, "@")
	if !ok || strings.TrimSpace(ref) == "" {
		return true
	}
	return !isFullCommitSHA(ref)
}

func isFullCommitSHA(ref string) bool {
	ref = strings.TrimSpace(ref)
	if len(ref) != 40 && len(ref) != 64 {
		return false
	}
	for _, char := range ref {
		if (char >= '0' && char <= '9') || (char >= 'a' && char <= 'f') || (char >= 'A' && char <= 'F') {
			continue
		}
		return false
	}
	return true
}

func sampleStrings(values []string, limit int) []string {
	if len(values) <= limit {
		return values
	}
	return values[:limit]
}

func collectOrgCodeSecurityConfiguration(org string, repository string, configurations []organizationCodeSecurityConfiguration, err error, repositoryConfiguration *repositoryCodeSecurityConfiguration, repositoryErr error) RepositoryPostureCheck {
	if err != nil {
		return checkFromAPIError(
			"org_code_security_configuration",
			"code_security",
			err,
			RepositoryPostureStateUnsupported,
			"plan_unavailable",
			"Organization code security configurations are not available for this account or plan.",
		)
	}
	evidence := orgCodeSecurityConfigurationEvidence(org, configurations)
	orgScoped := intEvidence(evidence, "organization_configuration_count")
	enforced := intEvidence(evidence, "enforced_configuration_count")
	protective := intEvidence(evidence, "protective_configurations")
	if len(configurations) == 0 {
		return RepositoryPostureCheck{
			ID:       "org_code_security_configuration",
			Category: "code_security",
			State:    RepositoryPostureStateInsecure,
			Reason:   "no_central_configuration",
			Summary:  "Organization has no central code security configuration to enforce repository controls.",
			Evidence: evidence,
		}
	}
	if orgScoped == 0 {
		return RepositoryPostureCheck{
			ID:       "org_code_security_configuration",
			Category: "code_security",
			State:    RepositoryPostureStateInsecure,
			Reason:   "no_central_configuration",
			Summary:  "Organization has no organization-scoped code security configuration to enforce repository controls.",
			Evidence: evidence,
		}
	}
	if enforced == 0 {
		return RepositoryPostureCheck{
			ID:       "org_code_security_configuration",
			Category: "code_security",
			State:    RepositoryPostureStateInsecure,
			Reason:   "configuration_not_enforced",
			Summary:  "Organization code security configurations are present but not enforced.",
			Evidence: evidence,
		}
	}
	if protective == 0 {
		return RepositoryPostureCheck{
			ID:       "org_code_security_configuration",
			Category: "code_security",
			State:    RepositoryPostureStateInsecure,
			Reason:   "configuration_not_protective",
			Summary:  "Organization code security configurations do not enable secret scanning or push protection.",
			Evidence: evidence,
		}
	}
	if repositoryErr != nil {
		return checkFromAPIError(
			"org_code_security_configuration",
			"code_security",
			repositoryErr,
			RepositoryPostureStateInsecure,
			"configuration_not_applied",
			"GitHub did not report an organization code security configuration for this repository.",
		)
	}
	evidence = addRepositoryCodeSecurityConfigurationEvidence(evidence, repository, repositoryConfiguration)
	if !repositoryCodeSecurityConfigurationApplies(repositoryConfiguration) {
		return RepositoryPostureCheck{
			ID:       "org_code_security_configuration",
			Category: "code_security",
			State:    RepositoryPostureStateInsecure,
			Reason:   "configuration_not_applied",
			Summary:  "Scanned repository is not attached to an enforced organization code security configuration.",
			Evidence: evidence,
		}
	}
	if !organizationCodeSecurityConfigurationEnforced(repositoryConfiguration.Configuration) {
		return RepositoryPostureCheck{
			ID:       "org_code_security_configuration",
			Category: "code_security",
			State:    RepositoryPostureStateInsecure,
			Reason:   "configuration_not_enforced",
			Summary:  "Scanned repository is attached to an organization code security configuration that is not enforced.",
			Evidence: evidence,
		}
	}
	if !organizationCodeSecurityConfigurationProtective(repositoryConfiguration.Configuration) {
		return RepositoryPostureCheck{
			ID:       "org_code_security_configuration",
			Category: "code_security",
			State:    RepositoryPostureStateInsecure,
			Reason:   "configuration_not_protective",
			Summary:  "Scanned repository's organization code security configuration does not enable secret scanning or push protection.",
			Evidence: evidence,
		}
	}
	return RepositoryPostureCheck{
		ID:       "org_code_security_configuration",
		Category: "code_security",
		State:    RepositoryPostureStateSecure,
		Reason:   "central_configuration_present",
		Summary:  "Scanned repository is attached to an enforced organization code security configuration.",
		Evidence: evidence,
	}
}

func organizationPostureMayBeUserOwner(posture OrganizationPosture) bool {
	if len(posture.Checks) == 0 {
		return false
	}
	for _, check := range posture.Checks {
		if check.State != RepositoryPostureStateUnsupported {
			return false
		}
		switch check.Reason {
		case "plan_unavailable", "organization_policy_unavailable":
		default:
			return false
		}
	}
	return true
}

func (c RepositoryClient) githubOrganizationExists(ctx context.Context, token string, org string, updateRate func(*GitHubRateLimitState)) (bool, error) {
	rateLimit, err := c.getJSON(ctx, token, c.orgEndpoint(org, ""), nil)
	updateRate(rateLimit)
	if err == nil {
		return true, nil
	}
	if apiErr, ok := asGitHubAPIError(err); ok && apiErr.StatusCode == http.StatusNotFound {
		return false, nil
	}
	return false, err
}

func organizationPostureNotAnOrganization(posture OrganizationPosture) OrganizationPosture {
	for index := range posture.Checks {
		check := &posture.Checks[index]
		check.State = RepositoryPostureStateUnsupported
		check.Reason = "not_an_organization"
		check.Summary = "Repository owner is a user account, so organization-level GitHub policy does not apply."
		if check.Evidence == nil {
			check.Evidence = map[string]any{}
		}
		check.Evidence["organization"] = posture.Organization
	}
	return posture
}

func shouldCollectRepositoryCodeSecurityConfiguration(configurations []organizationCodeSecurityConfiguration) bool {
	for _, configuration := range configurations {
		if !organizationCodeSecurityConfigurationScoped(configuration) {
			continue
		}
		if organizationCodeSecurityConfigurationEnforced(configuration) && organizationCodeSecurityConfigurationProtective(configuration) {
			return true
		}
	}
	return false
}

func (c RepositoryClient) collectRepositoryCodeSecurityConfiguration(ctx context.Context, token string, repository string, updateRate func(*GitHubRateLimitState)) (*repositoryCodeSecurityConfiguration, error) {
	body, rateLimit, _, err := c.doGitHubRequestRaw(ctx, token, http.MethodGet, c.repositoryEndpoint(repository, "/code-security-configuration"))
	updateRate(rateLimit)
	if err != nil {
		return nil, err
	}
	if len(strings.TrimSpace(string(body))) == 0 {
		return nil, nil
	}
	var configuration repositoryCodeSecurityConfiguration
	if err := json.Unmarshal(body, &configuration); err != nil {
		return nil, fmt.Errorf("decode github repository code security configuration: %w", err)
	}
	return &configuration, nil
}

func (c RepositoryClient) collectOrgCodeSecurityConfigurations(ctx context.Context, token string, org string, updateRate func(*GitHubRateLimitState)) ([]organizationCodeSecurityConfiguration, error) {
	configurations := []organizationCodeSecurityConfiguration{}
	rateLimit, err := c.getJSONPages(ctx, token, c.orgEndpoint(org, "/code-security/configurations?per_page=100"), func(body []byte) error {
		var page []organizationCodeSecurityConfigurationItem
		if err := json.Unmarshal(body, &page); err != nil {
			return err
		}
		for _, item := range page {
			configurations = append(configurations, item.configuration())
		}
		return nil
	})
	updateRate(rateLimit)
	return configurations, err
}

func (item organizationCodeSecurityConfigurationItem) configuration() organizationCodeSecurityConfiguration {
	configuration := item.organizationCodeSecurityConfiguration
	nested := item.Configuration
	if configuration.ID == 0 {
		configuration.ID = nested.ID
	}
	if configuration.Name == "" {
		configuration.Name = nested.Name
	}
	if configuration.TargetType == "" {
		configuration.TargetType = nested.TargetType
	}
	if configuration.Enforcement == "" {
		configuration.Enforcement = nested.Enforcement
	}
	if configuration.SecretScanning == "" {
		configuration.SecretScanning = nested.SecretScanning
	}
	if configuration.SecretScanningPushProtection == "" {
		configuration.SecretScanningPushProtection = nested.SecretScanningPushProtection
	}
	if configuration.DependabotAlerts == "" {
		configuration.DependabotAlerts = nested.DependabotAlerts
	}
	if configuration.CodeScanningDefaultSetup == "" {
		configuration.CodeScanningDefaultSetup = nested.CodeScanningDefaultSetup
	}
	return configuration
}

func addRepositoryCodeSecurityConfigurationEvidence(evidence map[string]any, repository string, repositoryConfiguration *repositoryCodeSecurityConfiguration) map[string]any {
	evidence["repository"] = repository
	if repositoryConfiguration == nil {
		evidence["repository_configuration_applied"] = false
		return evidence
	}
	evidence["repository_configuration_applied"] = true
	evidence["repository_configuration_status"] = strings.ToLower(strings.TrimSpace(repositoryConfiguration.Status))
	evidence["repository_configuration_id"] = repositoryConfiguration.Configuration.ID
	evidence["repository_configuration_target_type"] = strings.ToLower(strings.TrimSpace(repositoryConfiguration.Configuration.TargetType))
	return evidence
}

func repositoryCodeSecurityConfigurationApplies(repositoryConfiguration *repositoryCodeSecurityConfiguration) bool {
	if repositoryConfiguration == nil {
		return false
	}
	status := strings.ToLower(strings.TrimSpace(repositoryConfiguration.Status))
	if status != "" && status != "attached" && status != "enforced" {
		return false
	}
	return organizationCodeSecurityConfigurationScoped(repositoryConfiguration.Configuration)
}

func organizationCodeSecurityConfigurationScoped(configuration organizationCodeSecurityConfiguration) bool {
	return strings.EqualFold(strings.TrimSpace(configuration.TargetType), "organization")
}

func organizationCodeSecurityConfigurationEnforced(configuration organizationCodeSecurityConfiguration) bool {
	return strings.EqualFold(strings.TrimSpace(configuration.Enforcement), "enforced")
}

func organizationCodeSecurityConfigurationProtective(configuration organizationCodeSecurityConfiguration) bool {
	secretScanning := strings.EqualFold(strings.TrimSpace(configuration.SecretScanning), "enabled")
	pushProtection := strings.EqualFold(strings.TrimSpace(configuration.SecretScanningPushProtection), "enabled")
	return secretScanning || pushProtection
}

func organizationSecretScanningConfigurationProtective(configuration organizationCodeSecurityConfiguration) bool {
	secretScanning := strings.EqualFold(strings.TrimSpace(configuration.SecretScanning), "enabled")
	pushProtection := strings.EqualFold(strings.TrimSpace(configuration.SecretScanningPushProtection), "enabled")
	return secretScanning && pushProtection
}

func orgCodeSecurityConfigurationEvidence(org string, configurations []organizationCodeSecurityConfiguration) map[string]any {
	global := 0
	orgScoped := 0
	enforced := 0
	unenforced := 0
	protective := 0
	secretScanningPolicy := 0
	for _, configuration := range configurations {
		targetType := strings.ToLower(strings.TrimSpace(configuration.TargetType))
		if targetType == "global" {
			global++
			continue
		}
		if !organizationCodeSecurityConfigurationScoped(configuration) {
			continue
		}
		orgScoped++
		if !organizationCodeSecurityConfigurationEnforced(configuration) {
			unenforced++
			continue
		}
		enforced++
		if organizationCodeSecurityConfigurationProtective(configuration) {
			protective++
		}
		if organizationSecretScanningConfigurationProtective(configuration) {
			secretScanningPolicy++
		}
	}
	return map[string]any{
		"organization":                                   org,
		"configuration_count":                            len(configurations),
		"global_template_count":                          global,
		"organization_configuration_count":               orgScoped,
		"enforced_configuration_count":                   enforced,
		"unenforced_configuration_count":                 unenforced,
		"protective_configurations":                      protective,
		"secret_scanning_push_protection_configurations": secretScanningPolicy,
	}
}

func enforcedSecretScanningPolicyCount(configurations []organizationCodeSecurityConfiguration) int {
	return intEvidence(orgCodeSecurityConfigurationEvidence("", configurations), "secret_scanning_push_protection_configurations")
}

func intEvidence(evidence map[string]any, key string) int {
	value, _ := evidence[key].(int)
	return value
}

func normalizeOrganizationName(organization string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(organization))
	if normalized == "" || strings.ContainsAny(normalized, "/ ") {
		return "", fmt.Errorf("github organization must be a single login")
	}
	return normalized, nil
}

func boolValue(value *bool) bool {
	return value != nil && *value
}
