# Configuration Reference

This page is the canonical runtime configuration surface for API and worker processes.

Boolean values must parse as Go booleans (`true`, `false`, `1`, `0`, `t`, `f`) and duration values must be positive Go durations such as `5s`, `15m`, or `1h`. Invalid boolean or duration values are startup errors.

## Core Runtime

- `IDENTRAIL_SERVICE_NAME` (default: `identrail`)
- `IDENTRAIL_LOG_LEVEL` (default: `info`)
- `IDENTRAIL_HTTP_ADDR` (default: `:8080`)
- `IDENTRAIL_PROVIDER` (`aws|kubernetes`)
- `IDENTRAIL_DATABASE_URL` (required for API and worker persistence)
- `IDENTRAIL_ALLOW_MEMORY_STORE` (default: `false`; set `true` only for local tests or disposable demos without persisted state)
- `IDENTRAIL_RUN_MIGRATIONS` (default: `true`)
- `IDENTRAIL_RUN_MIGRATIONS_ONLY` (default: `false`)
- `IDENTRAIL_MIGRATIONS_DIR` (default: `migrations`)

## Auth and Scope

- `IDENTRAIL_API_KEYS`
- `IDENTRAIL_WRITE_API_KEYS`
- `IDENTRAIL_API_KEY_SCOPES` (takes precedence over legacy key lists; semicolon-separated `key:scope1,scope2` entries)
- `IDENTRAIL_API_KEY_SCOPE_BINDINGS` (optional tenant/workspace binding for scoped keys, format: `<api-key>:<tenant-id>/<workspace-id>;...`)
- `IDENTRAIL_OIDC_ISSUER_URL`
- `IDENTRAIL_OIDC_AUDIENCE`
- `IDENTRAIL_OIDC_WRITE_SCOPES`
- `IDENTRAIL_OIDC_TENANT_CLAIM`
- `IDENTRAIL_OIDC_WORKSPACE_CLAIM`
- `IDENTRAIL_OIDC_GROUPS_CLAIM`
- `IDENTRAIL_OIDC_ROLES_CLAIM`
- `IDENTRAIL_DEFAULT_TENANT_ID`
- `IDENTRAIL_DEFAULT_WORKSPACE_ID`
- `IDENTRAIL_REQUIRE_EXPLICIT_SCOPE` (default: `false`; set `true` in production to require tenant/workspace claims or headers instead of default fallback)

Notes:
- `IDENTRAIL_OIDC_ISSUER_URL` and `IDENTRAIL_OIDC_AUDIENCE` must be configured together.
- OIDC bearer auth enforces issuer/audience plus token validity (`exp`) via provider verification.
- Use either scoped API keys (`IDENTRAIL_API_KEY_SCOPES`) or legacy key lists (`IDENTRAIL_API_KEYS` plus `IDENTRAIL_WRITE_API_KEYS`). Scoped keys take precedence when both are set; overlap should be limited to planned migrations.
- `IDENTRAIL_API_KEY_SCOPE_BINDINGS` can optionally bind scoped keys to a tenant/workspace pair: `<api-key>:<tenant-id>/<workspace-id>;...`.
- API key callers can send `X-Identrail-Tenant-ID` and `X-Identrail-Workspace-ID` only when those headers match the configured binding for that scoped key.
- Malformed `IDENTRAIL_API_KEY_SCOPES` entries are startup errors. Do not include bare keys, empty keys, empty scope lists, or duplicate key entries.

## Provider Collection

AWS:
- `IDENTRAIL_AWS_SOURCE` (`fixture|sdk`)
- `IDENTRAIL_AWS_REGION`
- `IDENTRAIL_AWS_PROFILE`
- `IDENTRAIL_AWS_FIXTURES`

Kubernetes:
- `IDENTRAIL_K8S_SOURCE` (`fixture|kubectl`)
- `IDENTRAIL_K8S_FIXTURES`
- `IDENTRAIL_KUBECTL_PATH`
- `IDENTRAIL_KUBE_CONTEXT`

Kubernetes connector onboarding uses the same kubectl path and context to run a non-mutating preflight before activation. The runtime identity must be able to list `serviceaccounts`, `rolebindings`, `clusterrolebindings`, `roles`, `clusterroles`, and `pods`; missing permissions are reported as connector health diagnostics instead of starting unsafe automation.

Cross-provider:
- `IDENTRAIL_REQUIRE_LIVE_SOURCES`

Production deployment templates set `IDENTRAIL_REQUIRE_LIVE_SOURCES=true` with `IDENTRAIL_AWS_SOURCE=sdk` and `IDENTRAIL_K8S_SOURCE=kubectl`. Keep fixture sources for local smoke tests only, and set `IDENTRAIL_REQUIRE_LIVE_SOURCES=false` when using them intentionally.

## Queue, Worker, and Locking

- `IDENTRAIL_SCAN_INTERVAL`
- `IDENTRAIL_WORKER_RUN_NOW`
- `IDENTRAIL_WORKER_API_JOB_QUEUE_ENABLED`
- `IDENTRAIL_WORKER_API_JOB_QUEUE_INTERVAL`
- `IDENTRAIL_WORKER_API_JOB_QUEUE_BATCH_SIZE`
- `IDENTRAIL_SCAN_QUEUE_MAX_PENDING`
- `IDENTRAIL_REPO_SCAN_QUEUE_MAX_PENDING`
- `IDENTRAIL_LOCK_BACKEND` (`auto|inmemory|postgres`)
- `IDENTRAIL_LOCK_NAMESPACE`

## App-Mode Feature Flags

App-mode feature flags are supported runtime configuration for API and worker processes. They are disabled by default and must be explicitly enabled; dependent feature flags fail validation unless their parent flag is enabled.

- `IDENTRAIL_APP_MODE_ENABLED` (default: `false`)
- `IDENTRAIL_APP_MODE_CONNECTORS_ENABLED` (default: `false`)
- `IDENTRAIL_APP_MODE_SCHEDULER_ENABLED` (default: `false`)
- `IDENTRAIL_APP_MODE_REMEDIATION_ENABLED` (default: `false`)
- `IDENTRAIL_APP_MODE_PREMIUM_ENABLED` (default: `false`)
- `IDENTRAIL_APP_MODE_PREMIUM_REPORTS_ENABLED` (default: `false`)
- `IDENTRAIL_APP_MODE_PREMIUM_AUTOFIX_ENABLED` (default: `false`)
- `IDENTRAIL_APP_MODE_ROLLOUT_ENABLED` (default: `false`)
- `IDENTRAIL_APP_MODE_ROLLOUT_CANARY_PERCENT` (`0..100`, default: `0`)
- `IDENTRAIL_APP_MODE_ROLLOUT_TENANT_ALLOWLIST` (CSV tenant ids)
- `IDENTRAIL_APP_MODE_ROLLOUT_WORKSPACE_ALLOWLIST` (CSV workspace ids)

## Repository Exposure

- `IDENTRAIL_REPO_SCAN_ENABLED`
- `IDENTRAIL_REPO_SCAN_HISTORY_LIMIT`
- `IDENTRAIL_REPO_SCAN_MAX_FINDINGS`
- `IDENTRAIL_REPO_SCAN_HISTORY_LIMIT_MAX`
- `IDENTRAIL_REPO_SCAN_MAX_FINDINGS_MAX`
- `IDENTRAIL_REPO_SCAN_ALLOWLIST`
- `IDENTRAIL_WORKER_REPO_SCAN_ENABLED`
- `IDENTRAIL_WORKER_REPO_SCAN_RUN_NOW`
- `IDENTRAIL_WORKER_REPO_SCAN_INTERVAL`
- `IDENTRAIL_WORKER_REPO_SCAN_TARGETS`
- `IDENTRAIL_WORKER_REPO_SCAN_HISTORY_LIMIT`
- `IDENTRAIL_WORKER_REPO_SCAN_MAX_FINDINGS`

## Security and Networking

- `IDENTRAIL_RATE_LIMIT_RPM`
- `IDENTRAIL_RATE_LIMIT_BURST`
- `IDENTRAIL_TRUSTED_PROXIES`
- `IDENTRAIL_CORS_ALLOWED_ORIGINS`
- `IDENTRAIL_POSTGRES_RLS_ENFORCED`
- `IDENTRAIL_CONNECTOR_SECRET_KEYS`
  - Format: `version:base64-encoded-32-byte-key`, separated by commas or semicolons for rotation keysets.
  - The last key in the list is used for new connector secret envelopes; earlier versions remain available for decrypting existing envelopes during rotation.
  - If unset, the API uses an ephemeral in-memory key intended only for local/test connector state.
- `IDENTRAIL_CONNECTOR_SECRET_KEYS_REQUIRED` (default: `false`; set `true` in durable connector deployments so startup fails if `IDENTRAIL_CONNECTOR_SECRET_KEYS` is missing)

## Audit and Alerts

Audit:
- `IDENTRAIL_AUDIT_LOG_FILE`
- `IDENTRAIL_AUDIT_FINGERPRINT_SECRET`
  - Enables keyed HMAC-SHA256 pseudonymization for audit identifiers and API-key fingerprints.
  - Optional HMAC-SHA256 secret used to pseudonymize audit subject/resource identifiers.
  - If unset, audit fingerprinting falls back to a legacy unkeyed hash intended only for local or transitional setups.
- `IDENTRAIL_AUDIT_FORWARD_URL`
- `IDENTRAIL_AUDIT_FORWARD_TIMEOUT`
- `IDENTRAIL_AUDIT_FORWARD_MAX_RETRIES`
- `IDENTRAIL_AUDIT_FORWARD_RETRY_BACKOFF`
- `IDENTRAIL_AUDIT_FORWARD_HMAC_SECRET`

Alerts:
- `IDENTRAIL_ALERT_WEBHOOK_URL`
- `IDENTRAIL_ALERT_MIN_SEVERITY`
- `IDENTRAIL_ALERT_TIMEOUT`
- `IDENTRAIL_ALERT_HMAC_SECRET`
- `IDENTRAIL_ALERT_MAX_FINDINGS`
- `IDENTRAIL_ALERT_MAX_RETRIES`
- `IDENTRAIL_ALERT_RETRY_BACKOFF`

## Web App OIDC Session Lifecycle

The web app supports OIDC login/callback/refresh/logout flows when these Vite env vars are set at build time:

- `VITE_OIDC_ISSUER_URL`
- `VITE_OIDC_CLIENT_ID`
- `VITE_OIDC_SCOPE` (default: `openid profile email offline_access`)
- `VITE_OIDC_REDIRECT_URI` (default: `${origin}/app/callback`)
- `VITE_OIDC_POST_LOGOUT_REDIRECT_URI` (default: `${origin}/app/login?signed_out=1`)
- `VITE_OIDC_TENANT_CLAIM` (default: `tenant_id`)
- `VITE_OIDC_WORKSPACE_CLAIM` (default: `workspace_id`)
- `VITE_OIDC_ROLES_CLAIM` (default: `roles`)

## Web Lead Capture Forwarding

Server-side `/api/leads` forwarding uses these optional runtime environment variables:

- `LEAD_WEBHOOK_URL` (required to enable forwarding; must use `https`, or `http` only for localhost targets)
- `LEAD_WEBHOOK_TIMEOUT_MS` (default: `3000`, bounded to `500..10000`)
- `LEAD_CAPTURE_RATE_LIMIT_PER_MIN` (default: `15`, bounded to `1..120`, applied per client IP window)
- `LEAD_WEBHOOK_HMAC_SECRET` (optional; when set, emits `X-Identrail-Signature: sha256=<digest>` for receiver-side verification)

## Validation and Limits

Security validation and bounds are enforced at startup in:
- `internal/config/security.go`

Parsing defaults are defined in:
- `internal/config/config.go`
