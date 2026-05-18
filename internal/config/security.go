package config

import (
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	githubconnector "github.com/identrail/identrail/internal/connectors/github"
	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/repoallowlist"
	"github.com/identrail/identrail/internal/secretstore"
	"github.com/identrail/identrail/internal/urlpolicy"
)

const (
	maxAlertFindingsLimit       = 500
	maxAlertRetriesLimit        = 10
	maxAlertBackoffLimit        = 30
	maxAuditForwardRetriesLimit = 10
	maxAuditForwardBackoffLimit = 30
	maxRepoScanHistoryLimitMax  = 20000
	maxRepoScanFindingsLimitMax = 5000
	maxScanQueueMaxPending      = 20000
	maxRepoQueueMaxPending      = 50000
	maxWorkerQueueBatchSize     = 500
	minAPIKeyLength             = 24
	maxScopeIdentifierLength    = 64
	maxOIDCClaimNameLength      = 128
	maxAppModeCanaryPercent     = 100
)

var allowedKeyScopes = map[string]struct{}{
	"read":  {},
	"write": {},
	"admin": {},
}

const (
	apiKeyScopeTenantPrefix    = "tenant:"
	apiKeyScopeWorkspacePrefix = "workspace:"
)

var allowedAlertSeverities = map[string]struct{}{
	"info":     {},
	"low":      {},
	"medium":   {},
	"high":     {},
	"critical": {},
}

var allowedKubernetesSources = map[string]struct{}{
	"fixture": {},
	"kubectl": {},
}

var allowedAWSSources = map[string]struct{}{
	"fixture": {},
	"sdk":     {},
}

var allowedLockBackends = map[string]struct{}{
	"auto":     {},
	"inmemory": {},
	"postgres": {},
}

var allowedProviders = map[string]struct{}{
	"aws":        {},
	"kubernetes": {},
}

var placeholderAPIKeys = map[string]struct{}{
	"replace-read-key":              {},
	"replace-write-key":             {},
	"replace-with-strong-read-key":  {},
	"replace-with-strong-write-key": {},
}

var placeholderDefaultScopeIDs = map[string]struct{}{
	"replace-tenant-id":    {},
	"replace-workspace-id": {},
}

var scopeIdentifierPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,63}$`)
var oidcClaimNamePattern = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9._:-]{0,127}$`)

// ValidateSecurity checks hard-fail security misconfigurations.
func ValidateSecurity(cfg Config) error {
	if len(cfg.parseErrors) > 0 {
		return fmt.Errorf("invalid environment configuration: %s", strings.Join(cfg.parseErrors, "; "))
	}
	provider := strings.ToLower(strings.TrimSpace(cfg.Provider))
	if provider == "" {
		provider = defaultProvider
	}
	if _, ok := allowedProviders[provider]; !ok {
		return fmt.Errorf("invalid IDENTRAIL_PROVIDER %q: v1 supports aws or kubernetes", cfg.Provider)
	}
	if cfg.requireLiveSourcesInvalid {
		return fmt.Errorf("invalid IDENTRAIL_REQUIRE_LIVE_SOURCES %q: must be true or false", cfg.requireLiveSourcesRaw)
	}
	defaultTenant := strings.TrimSpace(cfg.DefaultTenantID)
	if defaultTenant == "" {
		defaultTenant = defaultTenantID
	}
	if err := validateScopeIdentifier("IDENTRAIL_DEFAULT_TENANT_ID", defaultTenant); err != nil {
		return err
	}
	if err := validateNotPlaceholderScopeIdentifier("IDENTRAIL_DEFAULT_TENANT_ID", defaultTenant); err != nil {
		return err
	}
	defaultWorkspace := strings.TrimSpace(cfg.DefaultWorkspaceID)
	if defaultWorkspace == "" {
		defaultWorkspace = defaultWorkspaceID
	}
	if err := validateScopeIdentifier("IDENTRAIL_DEFAULT_WORKSPACE_ID", defaultWorkspace); err != nil {
		return err
	}
	if err := validateNotPlaceholderScopeIdentifier("IDENTRAIL_DEFAULT_WORKSPACE_ID", defaultWorkspace); err != nil {
		return err
	}
	if cfg.AppModeConnectorsEnabled && !cfg.AppModeEnabled {
		return fmt.Errorf("IDENTRAIL_APP_MODE_CONNECTORS_ENABLED requires IDENTRAIL_APP_MODE_ENABLED=true")
	}
	if cfg.AppModeConnectorsEnabled &&
		strings.TrimSpace(cfg.DatabaseURL) != "" &&
		strings.TrimSpace(cfg.ConnectorSecretKeys) == "" {
		return fmt.Errorf("IDENTRAIL_CONNECTOR_SECRET_KEYS must be set when IDENTRAIL_APP_MODE_CONNECTORS_ENABLED=true and IDENTRAIL_DATABASE_URL is configured")
	}
	if cfg.AppModeSchedulerEnabled && !cfg.AppModeEnabled {
		return fmt.Errorf("IDENTRAIL_APP_MODE_SCHEDULER_ENABLED requires IDENTRAIL_APP_MODE_ENABLED=true")
	}
	if cfg.AppModeRemediationEnabled && !cfg.AppModeEnabled {
		return fmt.Errorf("IDENTRAIL_APP_MODE_REMEDIATION_ENABLED requires IDENTRAIL_APP_MODE_ENABLED=true")
	}
	if cfg.AppModePremiumEnabled && !cfg.AppModeEnabled {
		return fmt.Errorf("IDENTRAIL_APP_MODE_PREMIUM_ENABLED requires IDENTRAIL_APP_MODE_ENABLED=true")
	}
	if cfg.AppModePremiumReports && !cfg.AppModePremiumEnabled {
		return fmt.Errorf("IDENTRAIL_APP_MODE_PREMIUM_REPORTS_ENABLED requires IDENTRAIL_APP_MODE_PREMIUM_ENABLED=true")
	}
	if cfg.AppModePremiumAutofix && !cfg.AppModePremiumEnabled {
		return fmt.Errorf("IDENTRAIL_APP_MODE_PREMIUM_AUTOFIX_ENABLED requires IDENTRAIL_APP_MODE_PREMIUM_ENABLED=true")
	}
	if cfg.AppModeRolloutEnabled && !cfg.AppModeEnabled {
		return fmt.Errorf("IDENTRAIL_APP_MODE_ROLLOUT_ENABLED requires IDENTRAIL_APP_MODE_ENABLED=true")
	}
	if !cfg.AppModeRolloutEnabled {
		if cfg.AppModeRolloutCanary > 0 {
			return fmt.Errorf("IDENTRAIL_APP_MODE_ROLLOUT_CANARY_PERCENT requires IDENTRAIL_APP_MODE_ROLLOUT_ENABLED=true")
		}
		if len(cfg.AppModeTenantAllowlist) > 0 {
			return fmt.Errorf("IDENTRAIL_APP_MODE_ROLLOUT_TENANT_ALLOWLIST requires IDENTRAIL_APP_MODE_ROLLOUT_ENABLED=true")
		}
		if len(cfg.AppModeWorkspaceAllowlist) > 0 {
			return fmt.Errorf("IDENTRAIL_APP_MODE_ROLLOUT_WORKSPACE_ALLOWLIST requires IDENTRAIL_APP_MODE_ROLLOUT_ENABLED=true")
		}
	}
	if cfg.AppModeRolloutCanary < 0 || cfg.AppModeRolloutCanary > maxAppModeCanaryPercent {
		return fmt.Errorf("IDENTRAIL_APP_MODE_ROLLOUT_CANARY_PERCENT must be between 0 and %d", maxAppModeCanaryPercent)
	}
	for _, tenantID := range cfg.AppModeTenantAllowlist {
		if err := validateScopeIdentifier("IDENTRAIL_APP_MODE_ROLLOUT_TENANT_ALLOWLIST", tenantID); err != nil {
			return err
		}
	}
	for _, workspaceID := range cfg.AppModeWorkspaceAllowlist {
		if err := validateScopeIdentifier("IDENTRAIL_APP_MODE_ROLLOUT_WORKSPACE_ALLOWLIST", workspaceID); err != nil {
			return err
		}
	}

	oidcIssuer := strings.TrimSpace(cfg.OIDCIssuerURL)
	oidcAudience := strings.TrimSpace(cfg.OIDCAudience)
	if oidcIssuer != "" && oidcAudience == "" {
		return fmt.Errorf("IDENTRAIL_OIDC_AUDIENCE must be set when IDENTRAIL_OIDC_ISSUER_URL is configured")
	}
	if oidcAudience != "" && oidcIssuer == "" {
		return fmt.Errorf("IDENTRAIL_OIDC_ISSUER_URL must be set when IDENTRAIL_OIDC_AUDIENCE is configured")
	}
	if oidcIssuer != "" {
		tenantClaim := strings.TrimSpace(cfg.OIDCTenantClaim)
		if tenantClaim == "" {
			tenantClaim = defaultOIDCTenantClaim
		}
		if err := validateOIDCClaimName("IDENTRAIL_OIDC_TENANT_CLAIM", tenantClaim); err != nil {
			return err
		}
		workspaceClaim := strings.TrimSpace(cfg.OIDCWorkspaceClaim)
		if workspaceClaim == "" {
			workspaceClaim = defaultOIDCWorkspaceClaim
		}
		if err := validateOIDCClaimName("IDENTRAIL_OIDC_WORKSPACE_CLAIM", workspaceClaim); err != nil {
			return err
		}
		groupsClaim := strings.TrimSpace(cfg.OIDCGroupsClaim)
		if groupsClaim == "" {
			groupsClaim = defaultOIDCGroupsClaim
		}
		if err := validateOIDCClaimName("IDENTRAIL_OIDC_GROUPS_CLAIM", groupsClaim); err != nil {
			return err
		}
		rolesClaim := strings.TrimSpace(cfg.OIDCRolesClaim)
		if rolesClaim == "" {
			rolesClaim = defaultOIDCRolesClaim
		}
		if err := validateOIDCClaimName("IDENTRAIL_OIDC_ROLES_CLAIM", rolesClaim); err != nil {
			return err
		}
	}
	if cfg.AuthManualMode && strings.TrimSpace(cfg.WorkOSClientID) != "" {
		return fmt.Errorf("IDENTRAIL_AUTH_MANUAL_MODE=true cannot be combined with IDENTRAIL_WORKOS_CLIENT_ID")
	}
	if cfg.FeatureWorkOSLogin && cfg.AuthManualMode {
		return fmt.Errorf("IDENTRAIL_FEATURE_WORKOS_LOGIN=true cannot be combined with IDENTRAIL_AUTH_MANUAL_MODE=true")
	}
	if cfg.AuthManualMode && !cfg.AuthManualModeAllowUnsafe {
		// /auth/manual mints a browser session from request-supplied tenant
		// and identity fields, so it must be unreachable from anywhere but
		// the local machine. A loopback IDENTRAIL_PUBLIC_BASE_URL alone is
		// not sufficient: it only declares intent. The server must also bind
		// a loopback IDENTRAIL_HTTP_ADDR, otherwise it can listen on
		// 0.0.0.0 / sit behind an ingress while still advertising
		// http://localhost and remain remotely reachable.
		if !isLoopbackBaseURL(cfg.PublicBaseURL) || !isLoopbackListenAddr(cfg.HTTPAddr) {
			return fmt.Errorf("IDENTRAIL_AUTH_MANUAL_MODE=true is a local-development-only feature: /auth/manual mints a browser session from request-supplied tenant and identity fields. It requires a loopback IDENTRAIL_PUBLIC_BASE_URL (http://localhost, http://127.0.0.1, or http://[::1]) and a loopback IDENTRAIL_HTTP_ADDR (e.g. 127.0.0.1:8080), so the endpoint cannot be reached remotely. For a deliberately non-production test deployment whose reachability is constrained another way, set IDENTRAIL_AUTH_MANUAL_MODE_ALLOW_UNSAFE=true to override this guard")
		}
	}
	if cfg.FeatureWorkOSLogin && !cfg.FeatureNewAuth {
		return fmt.Errorf("IDENTRAIL_FEATURE_WORKOS_LOGIN=true requires IDENTRAIL_FEATURE_NEW_AUTH=true")
	}
	if cfg.FeatureOnboardingWizard && !cfg.FeatureNewAuth {
		return fmt.Errorf("IDENTRAIL_FEATURE_ONBOARDING_WIZARD=true requires IDENTRAIL_FEATURE_NEW_AUTH=true")
	}
	if cfg.FeatureNewAuth {
		if err := validatePublicBaseURL(cfg.PublicBaseURL); err != nil {
			return err
		}
		if err := validateSessionKey("IDENTRAIL_SESSION_KEY", cfg.SessionKey); err != nil {
			return err
		}
		if strings.TrimSpace(cfg.SessionKeyPrevious) != "" {
			if err := validateSessionKey("IDENTRAIL_SESSION_KEY_PREVIOUS", cfg.SessionKeyPrevious); err != nil {
				return err
			}
		}
	}
	if cfg.FeatureWorkOSLogin {
		if strings.TrimSpace(cfg.WorkOSClientID) == "" {
			return fmt.Errorf("IDENTRAIL_WORKOS_CLIENT_ID is required when IDENTRAIL_FEATURE_WORKOS_LOGIN=true")
		}
		if strings.TrimSpace(cfg.WorkOSAPIKey) == "" {
			return fmt.Errorf("IDENTRAIL_WORKOS_API_KEY is required when IDENTRAIL_FEATURE_WORKOS_LOGIN=true")
		}
		if strings.TrimSpace(cfg.WorkOSWebhookSecret) == "" {
			return fmt.Errorf("IDENTRAIL_WORKOS_WEBHOOK_SECRET is required when IDENTRAIL_FEATURE_WORKOS_LOGIN=true")
		}
		if strings.TrimSpace(cfg.WorkOSEnvironmentID) == "" {
			return fmt.Errorf("IDENTRAIL_WORKOS_ENVIRONMENT_ID is required when IDENTRAIL_FEATURE_WORKOS_LOGIN=true")
		}
	}
	if cfg.FeatureConnectorAWS {
		if strings.TrimSpace(cfg.AWSCloudFormationTemplateURL) == "" {
			return fmt.Errorf("IDENTRAIL_AWS_CFN_TEMPLATE_URL is required when IDENTRAIL_FEATURE_CONNECTOR_AWS=true")
		}
		parsedTemplateURL, err := url.Parse(strings.TrimSpace(cfg.AWSCloudFormationTemplateURL))
		if err != nil || parsedTemplateURL == nil || parsedTemplateURL.Scheme == "" || parsedTemplateURL.Host == "" {
			return fmt.Errorf("IDENTRAIL_AWS_CFN_TEMPLATE_URL must be an absolute URL")
		}
		if parsedTemplateURL.Scheme != "https" && parsedTemplateURL.Hostname() != "localhost" {
			return fmt.Errorf("IDENTRAIL_AWS_CFN_TEMPLATE_URL must use HTTPS unless it points at localhost")
		}
		if !regexp.MustCompile(`^[0-9]{12}$`).MatchString(strings.TrimSpace(cfg.AWSAccountID)) {
			return fmt.Errorf("IDENTRAIL_AWS_ACCOUNT_ID must be a 12 digit AWS account ID when IDENTRAIL_FEATURE_CONNECTOR_AWS=true")
		}
		if strings.TrimSpace(cfg.DatabaseURL) != "" && strings.TrimSpace(cfg.ConnectorSecretKeys) == "" {
			return fmt.Errorf("IDENTRAIL_CONNECTOR_SECRET_KEYS must be set when IDENTRAIL_FEATURE_CONNECTOR_AWS=true and IDENTRAIL_DATABASE_URL is configured")
		}
	}
	if cfg.FeatureConnectorGitHubV2 {
		for _, allowedBaseURL := range cfg.GitHubPATAllowedBaseURLs {
			if _, err := githubconnector.NormalizeBaseURL(allowedBaseURL); err != nil {
				return fmt.Errorf("IDENTRAIL_GITHUB_PAT_ALLOWED_BASE_URLS contains an invalid GitHub base URL")
			}
		}
		if hasGitHubAppConfig(cfg) {
			appID, err := strconv.ParseInt(strings.TrimSpace(cfg.GitHubAppID), 10, 64)
			if err != nil || appID <= 0 {
				return fmt.Errorf("IDENTRAIL_GITHUB_APP_ID must be a positive integer when the GitHub App flow is configured")
			}
			if _, err := githubconnector.NormalizeAppSlug(cfg.GitHubAppName); err != nil {
				return fmt.Errorf("IDENTRAIL_GITHUB_APP_NAME must be a valid GitHub App slug when the GitHub App flow is configured")
			}
			if _, err := githubconnector.ParsePrivateKey(cfg.GitHubAppPrivateKey); err != nil {
				return fmt.Errorf("IDENTRAIL_GITHUB_APP_PRIVATE_KEY must be a PEM encoded RSA private key when the GitHub App flow is configured")
			}
			if strings.TrimSpace(cfg.GitHubAppWebhookSecret) == "" {
				return fmt.Errorf("IDENTRAIL_GITHUB_APP_WEBHOOK_SECRET is required when the GitHub App flow is configured")
			}
		}
		if strings.TrimSpace(cfg.DatabaseURL) != "" && strings.TrimSpace(cfg.ConnectorSecretKeys) == "" {
			return fmt.Errorf("IDENTRAIL_CONNECTOR_SECRET_KEYS must be set when IDENTRAIL_FEATURE_CONNECTOR_GITHUB_V2=true and IDENTRAIL_DATABASE_URL is configured")
		}
	}
	if cfg.FeatureConnectorK8S && strings.TrimSpace(cfg.DatabaseURL) != "" && strings.TrimSpace(cfg.ConnectorSecretKeys) == "" {
		return fmt.Errorf("IDENTRAIL_CONNECTOR_SECRET_KEYS must be set when IDENTRAIL_FEATURE_CONNECTOR_K8S=true and IDENTRAIL_DATABASE_URL is configured")
	}

	if cfg.apiKeyScopesError != "" {
		return fmt.Errorf("invalid IDENTRAIL_API_KEY_SCOPES: %s", cfg.apiKeyScopesError)
	}
	if cfg.apiKeyScopeBindingsError != "" {
		return fmt.Errorf("invalid IDENTRAIL_API_KEY_SCOPE_BINDINGS: %s", cfg.apiKeyScopeBindingsError)
	}
	apiKeyScopeLegacyBindings := map[string]db.Scope{}
	if len(cfg.APIKeyScopes) > 0 {
		for key, scopes := range cfg.APIKeyScopes {
			trimmedKey := strings.TrimSpace(key)
			if trimmedKey == "" {
				return fmt.Errorf("scoped api key cannot be empty")
			}
			validScopeCount := 0
			tenantBinding := ""
			workspaceBinding := ""
			for _, scope := range scopes {
				normalizedScope := strings.ToLower(strings.TrimSpace(scope))
				if normalizedScope == "" {
					continue
				}
				if strings.HasPrefix(normalizedScope, apiKeyScopeTenantPrefix) {
					tenantID := strings.TrimSpace(scope[len(apiKeyScopeTenantPrefix):])
					if tenantID == "" {
						return fmt.Errorf("invalid API key scope configured")
					}
					if err := validateScopeIdentifier("IDENTRAIL_API_KEY_SCOPES tenant binding", tenantID); err != nil {
						return err
					}
					if tenantBinding != "" && tenantBinding != tenantID {
						return fmt.Errorf("invalid API key scope configured")
					}
					tenantBinding = tenantID
					continue
				}
				if strings.HasPrefix(normalizedScope, apiKeyScopeWorkspacePrefix) {
					workspaceID := strings.TrimSpace(scope[len(apiKeyScopeWorkspacePrefix):])
					if workspaceID == "" {
						return fmt.Errorf("invalid API key scope configured")
					}
					if err := validateScopeIdentifier("IDENTRAIL_API_KEY_SCOPES workspace binding", workspaceID); err != nil {
						return err
					}
					if workspaceBinding != "" && workspaceBinding != workspaceID {
						return fmt.Errorf("invalid API key scope configured")
					}
					workspaceBinding = workspaceID
					continue
				}
				if _, ok := allowedKeyScopes[normalizedScope]; !ok {
					// Do not include sensitive API key material or scope values in the error.
					return fmt.Errorf("invalid API key scope configured")
				}
				validScopeCount++
			}
			if validScopeCount == 0 {
				// Do not include the API key itself in the error to avoid leaking secrets.
				return fmt.Errorf("API key configured without any valid scopes")
			}
			if tenantBinding != "" || workspaceBinding != "" {
				apiKeyScopeLegacyBindings[trimmedKey] = db.Scope{
					TenantID:    tenantBinding,
					WorkspaceID: workspaceBinding,
				}
			}
		}
	}
	if len(cfg.APIKeyScopeBindings) > 0 {
		if len(cfg.APIKeyScopes) == 0 {
			return fmt.Errorf("IDENTRAIL_API_KEY_SCOPE_BINDINGS requires IDENTRAIL_API_KEY_SCOPES")
		}
		for key, scope := range cfg.APIKeyScopeBindings {
			trimmedKey := strings.TrimSpace(key)
			if trimmedKey == "" {
				return fmt.Errorf("IDENTRAIL_API_KEY_SCOPE_BINDINGS includes an empty key")
			}
			if _, ok := cfg.APIKeyScopes[trimmedKey]; !ok {
				return fmt.Errorf("IDENTRAIL_API_KEY_SCOPE_BINDINGS includes a key not present in IDENTRAIL_API_KEY_SCOPES")
			}
			if err := validateScopeIdentifier("IDENTRAIL_API_KEY_SCOPE_BINDINGS tenant", scope.TenantID); err != nil {
				return err
			}
			if err := validateScopeIdentifier("IDENTRAIL_API_KEY_SCOPE_BINDINGS workspace", scope.WorkspaceID); err != nil {
				return err
			}
			if legacyBinding, ok := apiKeyScopeLegacyBindings[strings.TrimSpace(key)]; ok {
				if legacyBinding.TenantID != "" && legacyBinding.TenantID != scope.TenantID {
					return fmt.Errorf("IDENTRAIL_API_KEY_SCOPE_BINDINGS conflicts with IDENTRAIL_API_KEY_SCOPES tenant binding")
				}
				if legacyBinding.WorkspaceID != "" && legacyBinding.WorkspaceID != scope.WorkspaceID {
					return fmt.Errorf("IDENTRAIL_API_KEY_SCOPE_BINDINGS conflicts with IDENTRAIL_API_KEY_SCOPES workspace binding")
				}
			}
		}
		for key := range cfg.APIKeyScopes {
			if _, ok := cfg.APIKeyScopeBindings[strings.TrimSpace(key)]; !ok {
				return fmt.Errorf("IDENTRAIL_API_KEY_SCOPES keys must also be configured in IDENTRAIL_API_KEY_SCOPE_BINDINGS")
			}
		}
	}

	if len(cfg.APIKeyScopes) == 0 && len(cfg.WriteAPIKeys) > 0 {
		allowed := map[string]struct{}{}
		for _, key := range cfg.APIKeys {
			trimmed := strings.TrimSpace(key)
			if trimmed == "" {
				continue
			}
			allowed[trimmed] = struct{}{}
		}
		for _, writeKey := range cfg.WriteAPIKeys {
			trimmed := strings.TrimSpace(writeKey)
			if trimmed == "" {
				continue
			}
			if _, ok := allowed[trimmed]; !ok {
				// Avoid including the specific write API key value in the error.
				return fmt.Errorf("configured write API key must also exist in IDENTRAIL_API_KEYS")
			}
		}
	}
	if len(cfg.APIKeyScopes) == 0 && len(cfg.APIKeys) > 0 && len(cfg.WriteAPIKeys) == 0 {
		return fmt.Errorf("IDENTRAIL_WRITE_API_KEYS must include at least one key when using IDENTRAIL_API_KEYS without scoped keys")
	}

	if cfg.AlertMaxFindings > maxAlertFindingsLimit {
		return fmt.Errorf("IDENTRAIL_ALERT_MAX_FINDINGS must be <= %d", maxAlertFindingsLimit)
	}
	if cfg.AlertMaxRetries > maxAlertRetriesLimit {
		return fmt.Errorf("IDENTRAIL_ALERT_MAX_RETRIES must be <= %d", maxAlertRetriesLimit)
	}
	if cfg.AlertRetryBackoff > time.Duration(maxAlertBackoffLimit)*time.Second {
		return fmt.Errorf("IDENTRAIL_ALERT_RETRY_BACKOFF must be <= %ds", maxAlertBackoffLimit)
	}
	if cfg.AuditForwardTimeout > 30*time.Second {
		return fmt.Errorf("IDENTRAIL_AUDIT_FORWARD_TIMEOUT must be <= 30s")
	}
	if cfg.AuditForwardMaxRetries > maxAuditForwardRetriesLimit {
		return fmt.Errorf("IDENTRAIL_AUDIT_FORWARD_MAX_RETRIES must be <= %d", maxAuditForwardRetriesLimit)
	}
	if cfg.AuditForwardRetryBackoff > time.Duration(maxAuditForwardBackoffLimit)*time.Second {
		return fmt.Errorf("IDENTRAIL_AUDIT_FORWARD_RETRY_BACKOFF must be <= %ds", maxAuditForwardBackoffLimit)
	}
	if strings.TrimSpace(cfg.AuditForwardURL) != "" {
		if err := validateForwardURL(cfg.AuditForwardURL); err != nil {
			return err
		}
	}
	if strings.TrimSpace(cfg.ConnectorSecretKeys) == "" && cfg.ConnectorSecretKeysRequired {
		return fmt.Errorf("IDENTRAIL_CONNECTOR_SECRET_KEYS is required when IDENTRAIL_CONNECTOR_SECRET_KEYS_REQUIRED=true")
	}
	if strings.TrimSpace(cfg.ConnectorSecretKeys) != "" {
		materials, err := secretstore.ParseKeySet(cfg.ConnectorSecretKeys)
		if err != nil {
			return fmt.Errorf("invalid IDENTRAIL_CONNECTOR_SECRET_KEYS: %w", err)
		}
		if _, err := secretstore.NewManager(materials); err != nil {
			return fmt.Errorf("invalid IDENTRAIL_CONNECTOR_SECRET_KEYS: %w", err)
		}
	}

	if strings.TrimSpace(cfg.AlertWebhookURL) != "" {
		severity := strings.ToLower(strings.TrimSpace(cfg.AlertMinSeverity))
		if _, ok := allowedAlertSeverities[severity]; !ok {
			return fmt.Errorf("invalid IDENTRAIL_ALERT_MIN_SEVERITY %q", cfg.AlertMinSeverity)
		}
	}
	if provider == "kubernetes" {
		source := strings.ToLower(strings.TrimSpace(cfg.KubernetesSource))
		if source == "" {
			source = "fixture"
		}
		if _, ok := allowedKubernetesSources[source]; !ok {
			return fmt.Errorf("invalid IDENTRAIL_K8S_SOURCE %q", cfg.KubernetesSource)
		}
		if cfg.RequireLiveSources && source == "fixture" {
			return fmt.Errorf("IDENTRAIL_REQUIRE_LIVE_SOURCES=true requires IDENTRAIL_K8S_SOURCE=kubectl")
		}
		if source == "kubectl" && strings.TrimSpace(cfg.KubectlPath) == "" {
			return fmt.Errorf("IDENTRAIL_KUBECTL_PATH must be set when IDENTRAIL_K8S_SOURCE=kubectl")
		}
	}
	if provider == "aws" {
		source := strings.ToLower(strings.TrimSpace(cfg.AWSSource))
		if source == "" {
			source = "fixture"
		}
		if _, ok := allowedAWSSources[source]; !ok {
			return fmt.Errorf("invalid IDENTRAIL_AWS_SOURCE %q", cfg.AWSSource)
		}
		if cfg.RequireLiveSources && source == "fixture" {
			return fmt.Errorf("IDENTRAIL_REQUIRE_LIVE_SOURCES=true requires IDENTRAIL_AWS_SOURCE=sdk")
		}
		if source == "sdk" && strings.TrimSpace(cfg.AWSRegion) == "" {
			return fmt.Errorf("IDENTRAIL_AWS_REGION must be set when IDENTRAIL_AWS_SOURCE=sdk")
		}
	}
	historyLimit := cfg.RepoScanHistoryLimit
	if historyLimit == 0 {
		historyLimit = defaultRepoScanHistoryLimit
	}
	maxFindings := cfg.RepoScanMaxFindings
	if maxFindings == 0 {
		maxFindings = defaultRepoScanMaxFindings
	}
	historyLimitMax := cfg.RepoScanHistoryLimitMax
	if historyLimitMax == 0 {
		historyLimitMax = defaultRepoScanHistoryLimitMax
	}
	maxFindingsMax := cfg.RepoScanMaxFindingsMax
	if maxFindingsMax == 0 {
		maxFindingsMax = defaultRepoScanMaxFindingsLimitMax
	}
	if historyLimit <= 0 {
		return fmt.Errorf("IDENTRAIL_REPO_SCAN_HISTORY_LIMIT must be > 0")
	}
	if maxFindings <= 0 {
		return fmt.Errorf("IDENTRAIL_REPO_SCAN_MAX_FINDINGS must be > 0")
	}
	if historyLimitMax <= 0 || historyLimitMax > maxRepoScanHistoryLimitMax {
		return fmt.Errorf("IDENTRAIL_REPO_SCAN_HISTORY_LIMIT_MAX must be > 0 and <= %d", maxRepoScanHistoryLimitMax)
	}
	if maxFindingsMax <= 0 || maxFindingsMax > maxRepoScanFindingsLimitMax {
		return fmt.Errorf("IDENTRAIL_REPO_SCAN_MAX_FINDINGS_MAX must be > 0 and <= %d", maxRepoScanFindingsLimitMax)
	}
	if historyLimit > historyLimitMax {
		return fmt.Errorf("IDENTRAIL_REPO_SCAN_HISTORY_LIMIT must be <= IDENTRAIL_REPO_SCAN_HISTORY_LIMIT_MAX")
	}
	if maxFindings > maxFindingsMax {
		return fmt.Errorf("IDENTRAIL_REPO_SCAN_MAX_FINDINGS must be <= IDENTRAIL_REPO_SCAN_MAX_FINDINGS_MAX")
	}
	scanQueueMaxPending := cfg.ScanQueueMaxPending
	if scanQueueMaxPending == 0 {
		scanQueueMaxPending = defaultScanQueueMaxPending
	}
	if scanQueueMaxPending <= 0 || scanQueueMaxPending > maxScanQueueMaxPending {
		return fmt.Errorf("IDENTRAIL_SCAN_QUEUE_MAX_PENDING must be > 0 and <= %d", maxScanQueueMaxPending)
	}
	repoQueueMaxPending := cfg.RepoQueueMaxPending
	if repoQueueMaxPending == 0 {
		repoQueueMaxPending = defaultRepoQueueMaxPending
	}
	if repoQueueMaxPending <= 0 || repoQueueMaxPending > maxRepoQueueMaxPending {
		return fmt.Errorf("IDENTRAIL_REPO_SCAN_QUEUE_MAX_PENDING must be > 0 and <= %d", maxRepoQueueMaxPending)
	}
	workerAPIJobQueueInterval := cfg.WorkerAPIJobQueueInterval
	if workerAPIJobQueueInterval == 0 {
		workerAPIJobQueueInterval = defaultWorkerAPIJobQueueInterval
	}
	if workerAPIJobQueueInterval <= 0 {
		return fmt.Errorf("IDENTRAIL_WORKER_API_JOB_QUEUE_INTERVAL must be > 0")
	}
	workerAPIJobQueueBatchSize := cfg.WorkerAPIJobQueueBatchSize
	if workerAPIJobQueueBatchSize == 0 {
		workerAPIJobQueueBatchSize = defaultWorkerAPIJobQueueBatchSize
	}
	if workerAPIJobQueueBatchSize <= 0 || workerAPIJobQueueBatchSize > maxWorkerQueueBatchSize {
		return fmt.Errorf("IDENTRAIL_WORKER_API_JOB_QUEUE_BATCH_SIZE must be > 0 and <= %d", maxWorkerQueueBatchSize)
	}
	if cfg.RepoScanEnabled && len(cfg.RepoScanAllowlist) == 0 {
		return fmt.Errorf("IDENTRAIL_REPO_SCAN_ALLOWLIST must include at least one target pattern when IDENTRAIL_REPO_SCAN_ENABLED=true")
	}
	if cfg.WorkerRepoScanEnabled {
		if !cfg.RepoScanEnabled {
			return fmt.Errorf("IDENTRAIL_WORKER_REPO_SCAN_ENABLED requires IDENTRAIL_REPO_SCAN_ENABLED=true")
		}
		if cfg.WorkerRepoScanInterval <= 0 {
			return fmt.Errorf("IDENTRAIL_WORKER_REPO_SCAN_INTERVAL must be > 0")
		}
		if len(cfg.WorkerRepoScanTargets) == 0 {
			return fmt.Errorf("IDENTRAIL_WORKER_REPO_SCAN_TARGETS must include at least one repository when worker repo scans are enabled")
		}
		for _, target := range cfg.WorkerRepoScanTargets {
			normalized := strings.TrimSpace(target)
			if normalized == "" {
				continue
			}
			if !configRepoTargetAllowed(normalized, cfg.RepoScanAllowlist) {
				return fmt.Errorf("worker repo scan target %q is outside IDENTRAIL_REPO_SCAN_ALLOWLIST", normalized)
			}
		}
		if cfg.WorkerRepoScanHistory > 0 && cfg.WorkerRepoScanHistory > historyLimitMax {
			return fmt.Errorf("IDENTRAIL_WORKER_REPO_SCAN_HISTORY_LIMIT must be <= IDENTRAIL_REPO_SCAN_HISTORY_LIMIT_MAX")
		}
		if cfg.WorkerRepoScanFindings > 0 && cfg.WorkerRepoScanFindings > maxFindingsMax {
			return fmt.Errorf("IDENTRAIL_WORKER_REPO_SCAN_MAX_FINDINGS must be <= IDENTRAIL_REPO_SCAN_MAX_FINDINGS_MAX")
		}
	}
	lockBackend := strings.ToLower(strings.TrimSpace(cfg.LockBackend))
	if lockBackend == "" {
		lockBackend = defaultLockBackend
	}
	if _, ok := allowedLockBackends[lockBackend]; !ok {
		return fmt.Errorf("invalid IDENTRAIL_LOCK_BACKEND %q", cfg.LockBackend)
	}
	if lockBackend == "postgres" && strings.TrimSpace(cfg.DatabaseURL) == "" {
		return fmt.Errorf("IDENTRAIL_LOCK_BACKEND=postgres requires IDENTRAIL_DATABASE_URL")
	}
	if len(cfg.APIKeys) == 0 && len(cfg.APIKeyScopes) == 0 && oidcIssuer == "" && !cfg.FeatureNewAuth {
		return fmt.Errorf("no authentication configured: set API keys or OIDC configuration")
	}
	// Placeholder validation follows the active API key mode.
	// Scoped keys take precedence over legacy API_KEYS/WRITE_API_KEYS.
	if len(cfg.APIKeyScopes) > 0 {
		if _, found := findPlaceholderAPIKey(nil, nil, cfg.APIKeyScopes); found {
			// Do not echo the placeholder key value; just indicate that placeholders are not allowed.
			return fmt.Errorf("placeholder API key is not allowed in runtime configuration; provision real secrets")
		}
	} else {
		if _, found := findPlaceholderAPIKey(cfg.APIKeys, cfg.WriteAPIKeys, nil); found {
			// Do not echo the placeholder key value; just indicate that placeholders are not allowed.
			return fmt.Errorf("placeholder API key is not allowed in runtime configuration; provision real secrets")
		}
	}
	for _, trustedProxy := range cfg.TrustedProxies {
		normalized := strings.TrimSpace(trustedProxy)
		if normalized == "" {
			continue
		}
		if strings.Contains(normalized, "/") {
			if _, err := netip.ParsePrefix(normalized); err != nil {
				return fmt.Errorf("invalid IDENTRAIL_TRUSTED_PROXIES entry %q: %w", normalized, err)
			}
			continue
		}
		if _, err := netip.ParseAddr(normalized); err != nil {
			return fmt.Errorf("invalid IDENTRAIL_TRUSTED_PROXIES entry %q: %w", normalized, err)
		}
	}
	return nil
}

func hasGitHubAppConfig(cfg Config) bool {
	return strings.TrimSpace(cfg.GitHubAppID) != "" ||
		strings.TrimSpace(cfg.GitHubAppName) != "" ||
		strings.TrimSpace(cfg.GitHubAppPrivateKey) != "" ||
		strings.TrimSpace(cfg.GitHubAppWebhookSecret) != ""
}

func validatePublicBaseURL(raw string) error {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return fmt.Errorf("IDENTRAIL_PUBLIC_BASE_URL is required when IDENTRAIL_FEATURE_NEW_AUTH=true")
	}
	parsed, err := url.Parse(trimmed)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("IDENTRAIL_PUBLIC_BASE_URL must be an absolute URL")
	}
	switch strings.ToLower(parsed.Scheme) {
	case "https":
		return nil
	case "http":
		if isLoopbackHost(parsed.Hostname()) {
			return nil
		}
	}
	return fmt.Errorf("IDENTRAIL_PUBLIC_BASE_URL must use https outside local development")
}

// isLoopbackHost reports whether host is a loopback address that only the
// local machine can reach.
func isLoopbackHost(host string) bool {
	switch strings.ToLower(strings.TrimSpace(host)) {
	case "localhost", "127.0.0.1", "::1":
		return true
	default:
		return false
	}
}

// isLoopbackBaseURL reports whether raw is an absolute URL whose host is a
// loopback address. Manual auth mode is gated on this so /auth/manual can
// never be reached from anywhere but the local machine.
func isLoopbackBaseURL(raw string) bool {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return false
	}
	switch strings.ToLower(parsed.Scheme) {
	case "http", "https":
		return isLoopbackHost(parsed.Hostname())
	default:
		return false
	}
}

// isLoopbackListenAddr reports whether addr binds only the loopback
// interface. An empty addr, a port-only form (":8080"), or an explicit
// all-interfaces host ("0.0.0.0", "::") all bind every interface and are not
// loopback, so manual mode fails closed for them. A bare loopback IP literal
// (e.g. 127.0.0.5) is honored via netip.IsLoopback.
func isLoopbackListenAddr(addr string) bool {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return false
	}
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.IsLoopback()
	}
	return false
}

func validateSessionKey(envName string, raw string) error {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return fmt.Errorf("%s is required when IDENTRAIL_FEATURE_NEW_AUTH=true", envName)
	}
	if decoded, err := hex.DecodeString(trimmed); err == nil {
		if len(decoded) < 32 {
			return fmt.Errorf("%s must contain at least 32 bytes of key material", envName)
		}
		return nil
	}
	if len([]byte(trimmed)) < 32 {
		return fmt.Errorf("%s must contain at least 32 bytes of key material", envName)
	}
	return nil
}

func validateScopeIdentifier(envName string, value string) error {
	normalized := strings.TrimSpace(value)
	if normalized == "" {
		return fmt.Errorf("%s must be non-empty", envName)
	}
	if len(normalized) > maxScopeIdentifierLength {
		return fmt.Errorf("%s must be <= %d characters", envName, maxScopeIdentifierLength)
	}
	if !scopeIdentifierPattern.MatchString(normalized) {
		return fmt.Errorf("%s must match %s", envName, scopeIdentifierPattern.String())
	}
	return nil
}

func validateNotPlaceholderScopeIdentifier(envName string, value string) error {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if _, ok := placeholderDefaultScopeIDs[normalized]; ok {
		return fmt.Errorf("%s cannot use a placeholder value", envName)
	}
	return nil
}

func validateOIDCClaimName(envName string, value string) error {
	normalized := strings.TrimSpace(value)
	if normalized == "" {
		return fmt.Errorf("%s must be non-empty", envName)
	}
	if len(normalized) > maxOIDCClaimNameLength {
		return fmt.Errorf("%s must be <= %d characters", envName, maxOIDCClaimNameLength)
	}
	if !oidcClaimNamePattern.MatchString(normalized) {
		return fmt.Errorf("%s must match %s", envName, oidcClaimNamePattern.String())
	}
	return nil
}

// SecurityWarnings returns non-fatal security posture warnings.
func SecurityWarnings(cfg Config) []string {
	warnings := []string{}
	if len(cfg.APIKeys) > 0 && len(cfg.APIKeyScopes) > 0 {
		warnings = append(warnings, "IDENTRAIL_API_KEYS is ignored when IDENTRAIL_API_KEY_SCOPES is configured")
	}
	if hasShortAPIKey(cfg.APIKeys, cfg.APIKeyScopes) {
		warnings = append(warnings, fmt.Sprintf("one or more API keys are shorter than %d characters; rotate to high-entropy keys", minAPIKeyLength))
	}
	if strings.TrimSpace(cfg.OIDCIssuerURL) != "" && (len(cfg.APIKeys) > 0 || len(cfg.APIKeyScopes) > 0) {
		warnings = append(warnings, "both API key auth and OIDC are enabled; verify expected precedence in clients and automation")
	}
	if len(cfg.APIKeyScopes) > 0 && len(cfg.APIKeyScopeBindings) == 0 {
		warnings = append(warnings, "scoped API keys are not tenant/workspace bound; set IDENTRAIL_API_KEY_SCOPE_BINDINGS to enforce scope isolation")
	}
	if !cfg.PostgresRLSEnforced {
		warnings = append(warnings, "postgres row-level scope enforcement is disabled; set IDENTRAIL_POSTGRES_RLS_ENFORCED=true for deployment environments")
	}
	if cfg.AuthManualMode {
		if cfg.AuthManualModeAllowUnsafe && (!isLoopbackBaseURL(cfg.PublicBaseURL) || !isLoopbackListenAddr(cfg.HTTPAddr)) {
			warnings = append(warnings, "IDENTRAIL_AUTH_MANUAL_MODE is enabled with IDENTRAIL_AUTH_MANUAL_MODE_ALLOW_UNSAFE on a non-loopback IDENTRAIL_PUBLIC_BASE_URL or IDENTRAIL_HTTP_ADDR; /auth/manual can mint a session from request-supplied identity and must never be exposed to production or internet-accessible deployments")
		} else {
			warnings = append(warnings, "IDENTRAIL_AUTH_MANUAL_MODE is enabled; /auth/manual is a local-development-only login and must never be enabled outside local development")
		}
	}
	if strings.TrimSpace(cfg.AuditLogFile) == "" {
		warnings = append(warnings, "audit file sink is disabled; configure IDENTRAIL_AUDIT_LOG_FILE for durable local audit records")
	}
	if strings.TrimSpace(cfg.AuditForwardURL) != "" && strings.TrimSpace(cfg.AuditForwardHMACSecret) == "" {
		warnings = append(warnings, "audit forward signing is disabled; set IDENTRAIL_AUDIT_FORWARD_HMAC_SECRET to enable receiver signature verification")
	}
	if strings.TrimSpace(cfg.AuditFingerprintSecret) == "" {
		warnings = append(warnings, "audit fingerprinting uses legacy unkeyed hash; set IDENTRAIL_AUDIT_FINGERPRINT_SECRET for HMAC-SHA256 pseudonymization")
	}
	if !cfg.RequireExplicitScope {
		warnings = append(warnings, "tenant/workspace scope may fall back to defaults; set IDENTRAIL_REQUIRE_EXPLICIT_SCOPE=true in production")
	}
	if strings.TrimSpace(cfg.ConnectorSecretKeys) == "" {
		warnings = append(warnings, "connector secrets use an ephemeral in-memory encryption key; set IDENTRAIL_CONNECTOR_SECRET_KEYS before persisting connector credentials")
	}
	if strings.TrimSpace(cfg.AlertWebhookURL) != "" && strings.TrimSpace(cfg.AlertHMACSecret) == "" {
		warnings = append(warnings, "alert webhook signing is disabled; set IDENTRAIL_ALERT_HMAC_SECRET to enable request signature verification")
	}
	if cfg.RepoScanEnabled && len(cfg.RepoScanAllowlist) == 0 {
		warnings = append(warnings, "repo scan allowlist is open; set IDENTRAIL_REPO_SCAN_ALLOWLIST to restrict allowed repository targets")
	}
	lockBackend := strings.ToLower(strings.TrimSpace(cfg.LockBackend))
	if lockBackend == "" {
		lockBackend = defaultLockBackend
	}
	if strings.TrimSpace(cfg.DatabaseURL) != "" && lockBackend == "inmemory" {
		warnings = append(warnings, "IDENTRAIL_LOCK_BACKEND is inmemory in database mode; use postgres lock backend for multi-instance deployments")
	}
	return warnings
}

// StartupDiagnostics returns startup-safe key runtime mode summaries.
func StartupDiagnostics(cfg Config) []string {
	diagnostics := []string{
		fmt.Sprintf("app_mode.enabled=%t", cfg.AppModeEnabled),
		fmt.Sprintf("app_mode.connectors.enabled=%t", cfg.AppModeConnectorsEnabled),
		fmt.Sprintf("app_mode.scheduler.enabled=%t", cfg.AppModeSchedulerEnabled),
		fmt.Sprintf("app_mode.remediation.enabled=%t", cfg.AppModeRemediationEnabled),
		fmt.Sprintf("app_mode.premium.enabled=%t", cfg.AppModePremiumEnabled),
		fmt.Sprintf("app_mode.premium.reports.enabled=%t", cfg.AppModePremiumReports),
		fmt.Sprintf("app_mode.premium.autofix.enabled=%t", cfg.AppModePremiumAutofix),
		fmt.Sprintf("app_mode.rollout.enabled=%t", cfg.AppModeRolloutEnabled),
		fmt.Sprintf("app_mode.rollout.canary_percent=%d", cfg.AppModeRolloutCanary),
		fmt.Sprintf("app_mode.rollout.tenant_allowlist_count=%d", len(cfg.AppModeTenantAllowlist)),
		fmt.Sprintf("app_mode.rollout.workspace_allowlist_count=%d", len(cfg.AppModeWorkspaceAllowlist)),
	}
	return diagnostics
}

func hasShortAPIKey(keys []string, scoped map[string][]string) bool {
	for _, key := range keys {
		if len(strings.TrimSpace(key)) > 0 && len(strings.TrimSpace(key)) < minAPIKeyLength {
			return true
		}
	}
	for key := range scoped {
		if len(strings.TrimSpace(key)) > 0 && len(strings.TrimSpace(key)) < minAPIKeyLength {
			return true
		}
	}
	return false
}

func findPlaceholderAPIKey(keys []string, writeKeys []string, scoped map[string][]string) (string, bool) {
	for _, key := range keys {
		normalized := strings.ToLower(strings.TrimSpace(key))
		if normalized == "" {
			continue
		}
		if _, exists := placeholderAPIKeys[normalized]; exists {
			return key, true
		}
	}
	for _, key := range writeKeys {
		normalized := strings.ToLower(strings.TrimSpace(key))
		if normalized == "" {
			continue
		}
		if _, exists := placeholderAPIKeys[normalized]; exists {
			return key, true
		}
	}
	for key := range scoped {
		normalized := strings.ToLower(strings.TrimSpace(key))
		if normalized == "" {
			continue
		}
		if _, exists := placeholderAPIKeys[normalized]; exists {
			return key, true
		}
	}
	return "", false
}

func validateForwardURL(raw string) error {
	return urlpolicy.ValidateAuditForwardURL(raw)
}

func configRepoTargetAllowed(target string, allowlist []string) bool {
	return repoallowlist.TargetAllowed(target, allowlist, true)
}
