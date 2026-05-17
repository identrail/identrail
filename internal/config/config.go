package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/identrail/identrail/internal/db"
)

const (
	defaultHTTPAddr                    = ":8080"
	defaultLogLevel                    = "info"
	defaultProvider                    = "aws"
	defaultServiceName                 = "identrail"
	defaultAWSSource                   = "fixture"
	defaultAWSRegion                   = "us-east-1"
	defaultAWSFixtures                 = "testdata/aws/role_with_policies.json,testdata/aws/role_with_urlencoded_trust.json"
	defaultK8sFixtures                 = "testdata/kubernetes/service_account_payments.json,testdata/kubernetes/cluster_role_cluster_admin.json,testdata/kubernetes/role_binding_cluster_admin.json,testdata/kubernetes/pod_payments.json"
	defaultK8sSource                   = "fixture"
	defaultKubectlPath                 = "kubectl"
	defaultScanInterval                = 15 * time.Minute
	defaultRepoScanEnabled             = false
	defaultRepoScanHistoryLimit        = 500
	defaultRepoScanMaxFindings         = 200
	defaultRepoScanHistoryLimitMax     = 5000
	defaultRepoScanMaxFindingsLimitMax = 1000
	defaultScanQueueMaxPending         = 25
	defaultRepoQueueMaxPending         = 100
	defaultWorkerRepoScanEnabled       = false
	defaultWorkerRepoScanRunNow        = false
	defaultWorkerRepoScanInterval      = 1 * time.Hour
	defaultWorkerScanPolicyEnabled     = true
	defaultWorkerScanPolicyInterval    = 1 * time.Minute
	defaultWorkerAPIJobQueueEnabled    = true
	defaultWorkerAPIJobQueueInterval   = 2 * time.Second
	defaultWorkerAPIJobQueueBatchSize  = 5
	defaultLockBackend                 = "auto"
	defaultLockNamespace               = "identrail"
	defaultPostgresRLSEnforced         = false
	defaultTenantID                    = "default"
	defaultWorkspaceID                 = "default"
	defaultOIDCWriteScopes             = "identrail.write,identrail.admin,write,admin"
	defaultOIDCTenantClaim             = OIDCDefaultTenantClaim
	defaultOIDCWorkspaceClaim          = OIDCDefaultWorkspaceClaim
	defaultOIDCGroupsClaim             = OIDCDefaultGroupsClaim
	defaultOIDCRolesClaim              = OIDCDefaultRolesClaim
	defaultFeatureNewAuth              = false
	defaultFeatureWorkOSLogin          = false
	defaultFeatureConnectorAWS         = false
	defaultFeatureConnectorGitHubV2    = false
	defaultFeatureConnectorK8S         = false
	defaultFeatureOnboardingWizard     = false
	defaultFeatureNativeSSO            = false
	defaultAuthManualMode              = false
	defaultAppModeEnabled              = false
	defaultAppModeConnectorsEnabled    = false
	defaultAppModeSchedulerEnabled     = false
	defaultAppModeRemediationEnabled   = false
	defaultAppModePremiumEnabled       = false
	defaultAppModePremiumReports       = false
	defaultAppModePremiumAutofix       = false
	defaultAppModeRolloutEnabled       = false
	defaultAppModeRolloutCanaryPercent = 0
)

const (
	OIDCDefaultTenantClaim    = "tenant_id"
	OIDCDefaultWorkspaceClaim = "workspace_id"
	OIDCDefaultGroupsClaim    = "groups"
	OIDCDefaultRolesClaim     = "roles"
)

// Config centralizes process-level configuration. It keeps module wiring simple
// and deterministic for API, worker, and CLI binaries.
type Config struct {
	HTTPAddr                     string
	LogLevel                     string
	Provider                     string
	ServiceName                  string
	TrustedProxies               []string
	CORSAllowedOrigins           []string
	DatabaseURL                  string
	AllowMemoryStore             bool
	AWSSource                    string
	AWSRegion                    string
	AWSProfile                   string
	AWSCloudFormationTemplateURL string
	AWSAccountID                 string
	AWSFixturePath               []string
	KubernetesFixturePath        []string
	KubernetesSource             string
	KubectlPath                  string
	KubeContext                  string
	RequireLiveSources           bool
	requireLiveSourcesRaw        string
	requireLiveSourcesInvalid    bool
	parseErrors                  []string
	ScanInterval                 time.Duration
	WorkerRunNow                 bool
	APIKeys                      []string
	WriteAPIKeys                 []string
	APIKeyScopes                 map[string][]string
	APIKeyScopeBindings          map[string]db.Scope
	apiKeyScopesError            string
	apiKeyScopeBindingsError     string
	RateLimitRPM                 int
	RateLimitBurst               int
	RunMigrations                bool
	RunMigrationsOnly            bool
	MigrationsDir                string
	PostgresRLSEnforced          bool
	AuditLogFile                 string
	AuditForwardURL              string
	AuditForwardTimeout          time.Duration
	AuditForwardMaxRetries       int
	AuditForwardRetryBackoff     time.Duration
	AuditForwardHMACSecret       string
	AuditFingerprintSecret       string
	ConnectorSecretKeys          string
	ConnectorSecretKeysRequired  bool
	AlertWebhookURL              string
	AlertMinSeverity             string
	AlertTimeout                 time.Duration
	AlertHMACSecret              string
	AlertMaxFindings             int
	AlertMaxRetries              int
	AlertRetryBackoff            time.Duration
	RepoScanEnabled              bool
	RepoScanHistoryLimit         int
	RepoScanMaxFindings          int
	RepoScanHistoryLimitMax      int
	RepoScanMaxFindingsMax       int
	RepoScanAllowlist            []string
	ScanQueueMaxPending          int
	RepoQueueMaxPending          int
	WorkerRepoScanEnabled        bool
	WorkerRepoScanRunNow         bool
	WorkerRepoScanInterval       time.Duration
	WorkerRepoScanTargets        []string
	WorkerRepoScanHistory        int
	WorkerRepoScanFindings       int
	WorkerScanPolicyEnabled      bool
	WorkerScanPolicyInterval     time.Duration
	WorkerAPIJobQueueEnabled     bool
	WorkerAPIJobQueueInterval    time.Duration
	WorkerAPIJobQueueBatchSize   int
	LockBackend                  string
	LockNamespace                string
	DefaultTenantID              string
	DefaultWorkspaceID           string
	RequireExplicitScope         bool
	OIDCIssuerURL                string
	OIDCAudience                 string
	OIDCWriteScopes              []string
	OIDCTenantClaim              string
	OIDCWorkspaceClaim           string
	OIDCGroupsClaim              string
	OIDCRolesClaim               string
	FeatureNewAuth               bool
	FeatureWorkOSLogin           bool
	FeatureConnectorAWS          bool
	FeatureConnectorGitHubV2     bool
	FeatureConnectorK8S          bool
	FeatureOnboardingWizard      bool
	FeatureNativeSSO             bool
	GitHubAppID                  string
	GitHubAppName                string
	GitHubAppPrivateKey          string
	GitHubAppWebhookSecret       string
	GitHubPATAllowedBaseURLs     []string
	PublicBaseURL                string
	SessionKey                   string
	SessionKeyPrevious           string
	AuthManualMode               bool
	WorkOSClientID               string
	WorkOSAPIKey                 string
	WorkOSWebhookSecret          string
	WorkOSEnvironmentID          string
	AppModeEnabled               bool
	AppModeConnectorsEnabled     bool
	AppModeSchedulerEnabled      bool
	AppModeRemediationEnabled    bool
	AppModePremiumEnabled        bool
	AppModePremiumReports        bool
	AppModePremiumAutofix        bool
	AppModeRolloutEnabled        bool
	AppModeRolloutCanary         int
	AppModeTenantAllowlist       []string
	AppModeWorkspaceAllowlist    []string
	WorkerHeartbeatPath          string
}

// Load reads environment variables and applies safe defaults for local and CI use.
func Load() Config {
	parseErrors := []string{}
	boolEnv := func(key string, fallback bool) bool {
		value, parseErr := parseBoolEnv(key, fallback)
		if parseErr != "" {
			parseErrors = append(parseErrors, parseErr)
		}
		return value
	}
	durationEnv := func(key string, fallback time.Duration) time.Duration {
		value, parseErr := parseDurationEnv(key, fallback)
		if parseErr != "" {
			parseErrors = append(parseErrors, parseErr)
		}
		return value
	}
	requireLiveSourcesRaw := getEnv("IDENTRAIL_REQUIRE_LIVE_SOURCES", "false")
	requireLiveSources, requireLiveSourcesInvalid := parseBoolWithValidity(requireLiveSourcesRaw, false)
	apiKeyScopes, apiKeyScopesError := parseKeyScopes(getEnv("IDENTRAIL_API_KEY_SCOPES", ""))
	if apiKeyScopesError != "" {
		parseErrors = append(parseErrors, "invalid IDENTRAIL_API_KEY_SCOPES: "+apiKeyScopesError)
	}
	apiKeyScopeBindings, apiKeyScopeBindingsError := parseKeyScopeBindings(getEnv("IDENTRAIL_API_KEY_SCOPE_BINDINGS", ""))
	if apiKeyScopeBindingsError != "" {
		parseErrors = append(parseErrors, "invalid IDENTRAIL_API_KEY_SCOPE_BINDINGS: "+apiKeyScopeBindingsError)
	}
	featureNativeSSO := boolEnv("IDENTRAIL_FEATURE_NATIVE_SSO", defaultFeatureNativeSSO)
	if strings.TrimSpace(os.Getenv("IDENTRAIL_ENABLE_NATIVE_SSO")) != "" {
		featureNativeSSO = boolEnv("IDENTRAIL_ENABLE_NATIVE_SSO", featureNativeSSO)
	}

	return Config{
		HTTPAddr:                     getEnv("IDENTRAIL_HTTP_ADDR", defaultHTTPAddr),
		LogLevel:                     strings.ToLower(getEnv("IDENTRAIL_LOG_LEVEL", defaultLogLevel)),
		Provider:                     strings.ToLower(getEnv("IDENTRAIL_PROVIDER", defaultProvider)),
		ServiceName:                  getEnv("IDENTRAIL_SERVICE_NAME", defaultServiceName),
		TrustedProxies:               parseCommaSeparated(getEnv("IDENTRAIL_TRUSTED_PROXIES", "")),
		CORSAllowedOrigins:           parseCommaSeparated(getEnv("IDENTRAIL_CORS_ALLOWED_ORIGINS", "")),
		DatabaseURL:                  getEnv("IDENTRAIL_DATABASE_URL", ""),
		AllowMemoryStore:             boolEnv("IDENTRAIL_ALLOW_MEMORY_STORE", false),
		AWSSource:                    strings.ToLower(getEnv("IDENTRAIL_AWS_SOURCE", defaultAWSSource)),
		AWSRegion:                    getEnv("IDENTRAIL_AWS_REGION", defaultAWSRegion),
		AWSProfile:                   getEnv("IDENTRAIL_AWS_PROFILE", ""),
		AWSCloudFormationTemplateURL: getEnv("IDENTRAIL_AWS_CFN_TEMPLATE_URL", ""),
		AWSAccountID:                 getEnv("IDENTRAIL_AWS_ACCOUNT_ID", ""),
		AWSFixturePath:               parseCommaSeparated(getEnv("IDENTRAIL_AWS_FIXTURES", defaultAWSFixtures)),
		KubernetesFixturePath:        parseCommaSeparated(getEnv("IDENTRAIL_K8S_FIXTURES", defaultK8sFixtures)),
		KubernetesSource:             strings.ToLower(getEnv("IDENTRAIL_K8S_SOURCE", defaultK8sSource)),
		KubectlPath:                  getEnv("IDENTRAIL_KUBECTL_PATH", defaultKubectlPath),
		KubeContext:                  getEnv("IDENTRAIL_KUBE_CONTEXT", ""),
		RequireLiveSources:           requireLiveSources,
		requireLiveSourcesRaw:        requireLiveSourcesRaw,
		requireLiveSourcesInvalid:    requireLiveSourcesInvalid,
		ScanInterval:                 durationEnv("IDENTRAIL_SCAN_INTERVAL", defaultScanInterval),
		WorkerRunNow:                 boolEnv("IDENTRAIL_WORKER_RUN_NOW", true),
		APIKeys:                      parseCommaSeparated(getEnv("IDENTRAIL_API_KEYS", "")),
		WriteAPIKeys:                 parseCommaSeparated(getEnv("IDENTRAIL_WRITE_API_KEYS", "")),
		APIKeyScopes:                 apiKeyScopes,
		APIKeyScopeBindings:          apiKeyScopeBindings,
		apiKeyScopeBindingsError:     apiKeyScopeBindingsError,
		apiKeyScopesError:            apiKeyScopesError,
		RateLimitRPM:                 parseInt(getEnv("IDENTRAIL_RATE_LIMIT_RPM", "120"), 120),
		RateLimitBurst:               parseInt(getEnv("IDENTRAIL_RATE_LIMIT_BURST", "20"), 20),
		RunMigrations:                boolEnv("IDENTRAIL_RUN_MIGRATIONS", true),
		RunMigrationsOnly:            boolEnv("IDENTRAIL_RUN_MIGRATIONS_ONLY", false),
		MigrationsDir:                getEnv("IDENTRAIL_MIGRATIONS_DIR", "migrations"),
		PostgresRLSEnforced:          boolEnv("IDENTRAIL_POSTGRES_RLS_ENFORCED", defaultPostgresRLSEnforced),
		AuditLogFile:                 getEnv("IDENTRAIL_AUDIT_LOG_FILE", ""),
		AuditForwardURL:              getEnv("IDENTRAIL_AUDIT_FORWARD_URL", ""),
		AuditForwardTimeout:          durationEnv("IDENTRAIL_AUDIT_FORWARD_TIMEOUT", 3*time.Second),
		AuditForwardMaxRetries:       parseInt(getEnv("IDENTRAIL_AUDIT_FORWARD_MAX_RETRIES", "1"), 1),
		AuditForwardRetryBackoff:     durationEnv("IDENTRAIL_AUDIT_FORWARD_RETRY_BACKOFF", 1*time.Second),
		AuditForwardHMACSecret:       getEnv("IDENTRAIL_AUDIT_FORWARD_HMAC_SECRET", ""),
		AuditFingerprintSecret:       getEnv("IDENTRAIL_AUDIT_FINGERPRINT_SECRET", ""),
		ConnectorSecretKeys:          getEnv("IDENTRAIL_CONNECTOR_SECRET_KEYS", ""),
		ConnectorSecretKeysRequired:  boolEnv("IDENTRAIL_CONNECTOR_SECRET_KEYS_REQUIRED", false),
		AlertWebhookURL:              getEnv("IDENTRAIL_ALERT_WEBHOOK_URL", ""),
		AlertMinSeverity:             strings.ToLower(getEnv("IDENTRAIL_ALERT_MIN_SEVERITY", "high")),
		AlertTimeout:                 durationEnv("IDENTRAIL_ALERT_TIMEOUT", 5*time.Second),
		AlertHMACSecret:              getEnv("IDENTRAIL_ALERT_HMAC_SECRET", ""),
		AlertMaxFindings:             parseInt(getEnv("IDENTRAIL_ALERT_MAX_FINDINGS", "25"), 25),
		AlertMaxRetries:              parseInt(getEnv("IDENTRAIL_ALERT_MAX_RETRIES", "2"), 2),
		AlertRetryBackoff:            durationEnv("IDENTRAIL_ALERT_RETRY_BACKOFF", 1*time.Second),
		RepoScanEnabled:              boolEnv("IDENTRAIL_REPO_SCAN_ENABLED", defaultRepoScanEnabled),
		RepoScanHistoryLimit:         parseInt(getEnv("IDENTRAIL_REPO_SCAN_HISTORY_LIMIT", "500"), defaultRepoScanHistoryLimit),
		RepoScanMaxFindings:          parseInt(getEnv("IDENTRAIL_REPO_SCAN_MAX_FINDINGS", "200"), defaultRepoScanMaxFindings),
		RepoScanHistoryLimitMax:      parseInt(getEnv("IDENTRAIL_REPO_SCAN_HISTORY_LIMIT_MAX", "5000"), defaultRepoScanHistoryLimitMax),
		RepoScanMaxFindingsMax:       parseInt(getEnv("IDENTRAIL_REPO_SCAN_MAX_FINDINGS_MAX", "1000"), defaultRepoScanMaxFindingsLimitMax),
		RepoScanAllowlist:            parseCommaSeparated(getEnv("IDENTRAIL_REPO_SCAN_ALLOWLIST", "")),
		ScanQueueMaxPending:          parseInt(getEnv("IDENTRAIL_SCAN_QUEUE_MAX_PENDING", "25"), defaultScanQueueMaxPending),
		RepoQueueMaxPending:          parseInt(getEnv("IDENTRAIL_REPO_SCAN_QUEUE_MAX_PENDING", "100"), defaultRepoQueueMaxPending),
		WorkerRepoScanEnabled:        boolEnv("IDENTRAIL_WORKER_REPO_SCAN_ENABLED", defaultWorkerRepoScanEnabled),
		WorkerRepoScanRunNow:         boolEnv("IDENTRAIL_WORKER_REPO_SCAN_RUN_NOW", defaultWorkerRepoScanRunNow),
		WorkerRepoScanInterval:       durationEnv("IDENTRAIL_WORKER_REPO_SCAN_INTERVAL", defaultWorkerRepoScanInterval),
		WorkerRepoScanTargets:        parseCommaSeparated(getEnv("IDENTRAIL_WORKER_REPO_SCAN_TARGETS", "")),
		WorkerRepoScanHistory:        parseInt(getEnv("IDENTRAIL_WORKER_REPO_SCAN_HISTORY_LIMIT", "0"), 0),
		WorkerRepoScanFindings:       parseInt(getEnv("IDENTRAIL_WORKER_REPO_SCAN_MAX_FINDINGS", "0"), 0),
		WorkerScanPolicyEnabled:      boolEnv("IDENTRAIL_WORKER_SCAN_POLICY_SCHEDULER_ENABLED", defaultWorkerScanPolicyEnabled),
		WorkerScanPolicyInterval:     durationEnv("IDENTRAIL_WORKER_SCAN_POLICY_SCHEDULER_INTERVAL", defaultWorkerScanPolicyInterval),
		WorkerAPIJobQueueEnabled:     boolEnv("IDENTRAIL_WORKER_API_JOB_QUEUE_ENABLED", defaultWorkerAPIJobQueueEnabled),
		WorkerAPIJobQueueInterval:    durationEnv("IDENTRAIL_WORKER_API_JOB_QUEUE_INTERVAL", defaultWorkerAPIJobQueueInterval),
		WorkerAPIJobQueueBatchSize:   parseInt(getEnv("IDENTRAIL_WORKER_API_JOB_QUEUE_BATCH_SIZE", "5"), defaultWorkerAPIJobQueueBatchSize),
		WorkerHeartbeatPath:          strings.TrimSpace(getEnv("IDENTRAIL_WORKER_HEARTBEAT_PATH", "")),
		LockBackend:                  strings.ToLower(getEnv("IDENTRAIL_LOCK_BACKEND", defaultLockBackend)),
		LockNamespace:                getEnv("IDENTRAIL_LOCK_NAMESPACE", defaultLockNamespace),
		DefaultTenantID:              getEnv("IDENTRAIL_DEFAULT_TENANT_ID", defaultTenantID),
		DefaultWorkspaceID:           getEnv("IDENTRAIL_DEFAULT_WORKSPACE_ID", defaultWorkspaceID),
		RequireExplicitScope:         boolEnv("IDENTRAIL_REQUIRE_EXPLICIT_SCOPE", false),
		OIDCIssuerURL:                getEnv("IDENTRAIL_OIDC_ISSUER_URL", ""),
		OIDCAudience:                 getEnv("IDENTRAIL_OIDC_AUDIENCE", ""),
		OIDCWriteScopes:              parseCommaSeparated(getEnv("IDENTRAIL_OIDC_WRITE_SCOPES", defaultOIDCWriteScopes)),
		OIDCTenantClaim:              getEnv("IDENTRAIL_OIDC_TENANT_CLAIM", defaultOIDCTenantClaim),
		OIDCWorkspaceClaim:           getEnv("IDENTRAIL_OIDC_WORKSPACE_CLAIM", defaultOIDCWorkspaceClaim),
		OIDCGroupsClaim:              getEnv("IDENTRAIL_OIDC_GROUPS_CLAIM", defaultOIDCGroupsClaim),
		OIDCRolesClaim:               getEnv("IDENTRAIL_OIDC_ROLES_CLAIM", defaultOIDCRolesClaim),
		FeatureNewAuth:               boolEnv("IDENTRAIL_FEATURE_NEW_AUTH", defaultFeatureNewAuth),
		FeatureWorkOSLogin:           boolEnv("IDENTRAIL_FEATURE_WORKOS_LOGIN", defaultFeatureWorkOSLogin),
		FeatureConnectorAWS:          boolEnv("IDENTRAIL_FEATURE_CONNECTOR_AWS", defaultFeatureConnectorAWS),
		FeatureConnectorGitHubV2:     boolEnv("IDENTRAIL_FEATURE_CONNECTOR_GITHUB_V2", defaultFeatureConnectorGitHubV2),
		FeatureConnectorK8S:          boolEnv("IDENTRAIL_FEATURE_CONNECTOR_K8S", defaultFeatureConnectorK8S),
		FeatureOnboardingWizard:      boolEnv("IDENTRAIL_FEATURE_ONBOARDING_WIZARD", defaultFeatureOnboardingWizard),
		FeatureNativeSSO:             featureNativeSSO,
		GitHubAppID:                  getEnv("IDENTRAIL_GITHUB_APP_ID", ""),
		GitHubAppName:                getEnv("IDENTRAIL_GITHUB_APP_NAME", ""),
		GitHubAppPrivateKey:          getEnv("IDENTRAIL_GITHUB_APP_PRIVATE_KEY", ""),
		GitHubAppWebhookSecret:       getEnv("IDENTRAIL_GITHUB_APP_WEBHOOK_SECRET", ""),
		GitHubPATAllowedBaseURLs:     parseCommaSeparated(getEnv("IDENTRAIL_GITHUB_PAT_ALLOWED_BASE_URLS", "https://github.com")),
		PublicBaseURL:                getEnv("IDENTRAIL_PUBLIC_BASE_URL", ""),
		SessionKey:                   getEnv("IDENTRAIL_SESSION_KEY", ""),
		SessionKeyPrevious:           getEnv("IDENTRAIL_SESSION_KEY_PREVIOUS", ""),
		AuthManualMode:               boolEnv("IDENTRAIL_AUTH_MANUAL_MODE", defaultAuthManualMode),
		WorkOSClientID:               getEnv("IDENTRAIL_WORKOS_CLIENT_ID", ""),
		WorkOSAPIKey:                 getEnv("IDENTRAIL_WORKOS_API_KEY", ""),
		WorkOSWebhookSecret:          getEnv("IDENTRAIL_WORKOS_WEBHOOK_SECRET", ""),
		WorkOSEnvironmentID:          getEnv("IDENTRAIL_WORKOS_ENVIRONMENT_ID", ""),
		AppModeEnabled:               boolEnv("IDENTRAIL_APP_MODE_ENABLED", defaultAppModeEnabled),
		AppModeConnectorsEnabled:     boolEnv("IDENTRAIL_APP_MODE_CONNECTORS_ENABLED", defaultAppModeConnectorsEnabled),
		AppModeSchedulerEnabled:      boolEnv("IDENTRAIL_APP_MODE_SCHEDULER_ENABLED", defaultAppModeSchedulerEnabled),
		AppModeRemediationEnabled:    boolEnv("IDENTRAIL_APP_MODE_REMEDIATION_ENABLED", defaultAppModeRemediationEnabled),
		AppModePremiumEnabled:        boolEnv("IDENTRAIL_APP_MODE_PREMIUM_ENABLED", defaultAppModePremiumEnabled),
		AppModePremiumReports:        boolEnv("IDENTRAIL_APP_MODE_PREMIUM_REPORTS_ENABLED", defaultAppModePremiumReports),
		AppModePremiumAutofix:        boolEnv("IDENTRAIL_APP_MODE_PREMIUM_AUTOFIX_ENABLED", defaultAppModePremiumAutofix),
		AppModeRolloutEnabled:        boolEnv("IDENTRAIL_APP_MODE_ROLLOUT_ENABLED", defaultAppModeRolloutEnabled),
		AppModeRolloutCanary:         parseIntAllowZero(getEnv("IDENTRAIL_APP_MODE_ROLLOUT_CANARY_PERCENT", "0"), defaultAppModeRolloutCanaryPercent),
		AppModeTenantAllowlist:       parseCommaSeparated(getEnv("IDENTRAIL_APP_MODE_ROLLOUT_TENANT_ALLOWLIST", "")),
		AppModeWorkspaceAllowlist:    parseCommaSeparated(getEnv("IDENTRAIL_APP_MODE_ROLLOUT_WORKSPACE_ALLOWLIST", "")),
		parseErrors:                  parseErrors,
	}
}

func getEnv(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}

func parseCommaSeparated(value string) []string {
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		result = append(result, trimmed)
	}
	return result
}

func parseDuration(value string, fallback time.Duration) time.Duration {
	parsed, err := time.ParseDuration(strings.TrimSpace(value))
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}

func parseDurationEnv(key string, fallback time.Duration) (time.Duration, string) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback, ""
	}
	parsed, err := time.ParseDuration(raw)
	if err != nil || parsed <= 0 {
		return fallback, fmt.Sprintf("invalid %s %q: must be a positive duration such as 5s or 15m", key, raw)
	}
	return parsed, ""
}

func parseBool(value string, fallback bool) bool {
	parsed, err := strconv.ParseBool(strings.TrimSpace(value))
	if err != nil {
		return fallback
	}
	return parsed
}

func parseBoolEnv(key string, fallback bool) (bool, string) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback, ""
	}
	parsed, err := strconv.ParseBool(raw)
	if err != nil {
		return fallback, fmt.Sprintf("invalid %s %q: must be true or false", key, raw)
	}
	return parsed, ""
}

func parseBoolWithValidity(value string, fallback bool) (bool, bool) {
	trimmed := strings.TrimSpace(value)
	parsed, err := strconv.ParseBool(trimmed)
	if err != nil {
		return fallback, trimmed != ""
	}
	return parsed, false
}

func parseInt(value string, fallback int) int {
	parsed, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}

func parseIntAllowZero(value string, fallback int) int {
	parsed, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || parsed < 0 {
		return fallback
	}
	return parsed
}

func parseKeyScopes(value string) (map[string][]string, string) {
	result := map[string][]string{}
	for index, entry := range strings.Split(value, ";") {
		trimmed := strings.TrimSpace(entry)
		if trimmed == "" {
			continue
		}
		parts := strings.SplitN(trimmed, ":", 2)
		if len(parts) != 2 {
			return result, "entry " + strconv.Itoa(index+1) + " must use key:scope1,scope2 format"
		}
		key := strings.TrimSpace(parts[0])
		if key == "" {
			return result, "entry " + strconv.Itoa(index+1) + " has an empty key"
		}
		scopes := parseCommaSeparated(parts[1])
		if len(scopes) == 0 {
			return result, "entry " + strconv.Itoa(index+1) + " has no scopes"
		}
		if _, exists := result[key]; exists {
			return result, "entry " + strconv.Itoa(index+1) + " duplicates a key"
		}
		result[key] = scopes
	}
	return result, ""
}

func parseKeyScopeBindings(value string) (map[string]db.Scope, string) {
	result := map[string]db.Scope{}
	for index, entry := range strings.Split(value, ";") {
		trimmed := strings.TrimSpace(entry)
		if trimmed == "" {
			continue
		}
		parts := strings.SplitN(trimmed, ":", 2)
		if len(parts) != 2 {
			return result, "entry " + strconv.Itoa(index+1) + " must use key:tenant-id/workspace-id format"
		}
		key := strings.TrimSpace(parts[0])
		if key == "" {
			return result, "entry " + strconv.Itoa(index+1) + " has an empty key"
		}
		if _, exists := result[key]; exists {
			return result, "entry " + strconv.Itoa(index+1) + " duplicates a key"
		}
		scopeParts := strings.SplitN(strings.TrimSpace(parts[1]), "/", 2)
		if len(scopeParts) != 2 {
			return result, "entry " + strconv.Itoa(index+1) + " must use tenant-id/workspace-id format"
		}
		tenantID := strings.TrimSpace(scopeParts[0])
		workspaceID := strings.TrimSpace(scopeParts[1])
		if tenantID == "" || workspaceID == "" {
			return result, "entry " + strconv.Itoa(index+1) + " must include non-empty tenant and workspace"
		}
		scope := db.Scope{
			TenantID:    tenantID,
			WorkspaceID: workspaceID,
		}.Normalize()
		result[key] = scope
	}
	return result, ""
}
