# Auth Environment Variables Reference

A flat list of every environment variable the auth and connector work introduces, with default, validation rule, and the PR that adds it.

The rule that drives every example below: domain references are always config-driven. The doc never hardcodes `app.identrail.com` outside of an example value column.

## Core Session and Identity

The two variables marked `Required` in the table below apply regardless of which auth driver is active (WorkOS, generic OIDC, or manual). Self-hosted operators set them just as cloud deployments do. The other two are optional knobs covered in the same table for completeness: `IDENTRAIL_SESSION_KEY_PREVIOUS` is only set during a key rotation, and `IDENTRAIL_AUTH_MANUAL_MODE` defaults to `false`.

| Variable | Default | Validation | Adds in |
| --- | --- | --- | --- |
| `IDENTRAIL_PUBLIC_BASE_URL` | none | Required for any auth driver (WorkOS, OIDC, or manual). Must parse as an absolute URL. Must be `https://` in any non-development build. Refuses to start if missing. | PR 2 |
| `IDENTRAIL_SESSION_KEY` | none | Required for any auth driver. 32 bytes minimum (64 hex chars). Refuses to start if missing or shorter. | PR 2 |
| `IDENTRAIL_SESSION_KEY_PREVIOUS` | empty | Optional. Same format as `IDENTRAIL_SESSION_KEY`. Used during key rotation. | PR 2 |
| `IDENTRAIL_AUTH_MANUAL_MODE` | `false` | Boolean. Mutually exclusive with `IDENTRAIL_WORKOS_CLIENT_ID`; setting both refuses to start. | PR 2 |

Production example values:

```
IDENTRAIL_PUBLIC_BASE_URL=https://app.identrail.com
IDENTRAIL_SESSION_KEY=<64 hex chars from openssl rand -hex 32>
```

## WorkOS Hosted Login

| Variable | Default | Validation | Adds in |
| --- | --- | --- | --- |
| `IDENTRAIL_WORKOS_CLIENT_ID` | empty | Required when `IDENTRAIL_FEATURE_WORKOS_LOGIN=true`. Refuses to start if `IDENTRAIL_AUTH_MANUAL_MODE=true` and this is set. | PR 4 |
| `IDENTRAIL_WORKOS_API_KEY` | empty | Required when `IDENTRAIL_FEATURE_WORKOS_LOGIN=true`. Treated as a secret. | PR 4 |
| `IDENTRAIL_WORKOS_WEBHOOK_SECRET` | empty | Required when `IDENTRAIL_FEATURE_WORKOS_LOGIN=true`. Used to verify webhook HMAC. | PR 4 |
| `IDENTRAIL_WORKOS_ENVIRONMENT_ID` | empty | Required when `IDENTRAIL_FEATURE_WORKOS_LOGIN=true`. Picks the WorkOS environment (test, staging, production). | PR 4 |

Self-hosted operators leave all four WorkOS variables in this section empty. They still set the two required core variables in the previous section (`IDENTRAIL_PUBLIC_BASE_URL` and `IDENTRAIL_SESSION_KEY`), set the two optional ones if they need them (`IDENTRAIL_SESSION_KEY_PREVIOUS` during a key rotation, `IDENTRAIL_AUTH_MANUAL_MODE` for local dev), and configure their OIDC issuer via the existing `IDENTRAIL_OIDC_*` variables.

## Email

| Variable | Default | Validation | Adds in |
| --- | --- | --- | --- |
| `IDENTRAIL_EMAIL_PROVIDER` | empty | One of `resend`, `postmark`, `ses`, or empty. Empty disables outgoing email and refuses to send invitations. | PR 11 |
| `IDENTRAIL_EMAIL_API_KEY` | empty | Required when `IDENTRAIL_EMAIL_PROVIDER` is set. Treated as a secret. | PR 11 |
| `IDENTRAIL_EMAIL_FROM_ADDRESS` | empty | Required when `IDENTRAIL_EMAIL_PROVIDER` is set. Must be a valid email under a domain owned by the operator. | PR 11 |

## Connector Providers

### AWS Connector

| Variable | Default | Validation | Adds in |
| --- | --- | --- | --- |
| `IDENTRAIL_AWS_CFN_TEMPLATE_URL` | empty | Required for the CFN one-click flow. Points at the CDN-hosted template. | PR 7 |
| `IDENTRAIL_AWS_ACCOUNT_ID` | empty | Required. The Identrail-side AWS account that the customer's role trusts. | PR 7 |

### GitHub Connector

| Variable | Default | Validation | Adds in |
| --- | --- | --- | --- |
| `IDENTRAIL_GITHUB_APP_ID` | empty | Required only when the hosted GitHub App flow is configured. | PR 8 |
| `IDENTRAIL_GITHUB_APP_PRIVATE_KEY` | empty | Required only when the hosted GitHub App flow is configured. PEM-formatted RSA private key. Treated as a secret. | PR 8 |
| `IDENTRAIL_GITHUB_APP_WEBHOOK_SECRET` | empty | Required only when the hosted GitHub App flow is configured. Used to verify webhook HMAC. | PR 8 |
| `IDENTRAIL_GITHUB_APP_NAME` | empty | Required only when the hosted GitHub App flow is configured. The GitHub App slug used in install URLs. | PR 8 |
| `IDENTRAIL_GITHUB_PAT_ALLOWED_BASE_URLS` | `https://github.com` | Comma-separated allowlist of GitHub.com or GitHub Enterprise base URLs accepted by the PAT fallback. | PR 8 |

### Kubernetes Connector

| Variable | Default | Validation | Adds in |
| --- | --- | --- | --- |
| `IDENTRAIL_K8S_AGENT_HELM_REPO` | `oci://registry.identrail.com/charts` | The Helm OCI registry the operator references when installing the agent. Self-hosters can override. | PR 9 |
| `IDENTRAIL_K8S_AGENT_VERSION` | empty | Optional. Pins a specific agent version. Empty means latest stable. | PR 9 |

The PR 9 implementation ships the chart in `deploy/connectors/k8s/identrail-agent`. The API response generates a Helm command against that checked-in chart path; self-hosted operators can publish it to their own OCI registry later without changing the connector API.

## Feature Flags

Feature flags follow the existing `IDENTRAIL_FEATURE_*` and `VITE_FEATURE_*` patterns. Backend flags use `IDENTRAIL_FEATURE_*` and frontend flags use `VITE_FEATURE_*`. Defaults are conservative; every new feature ships off and gets turned on after the PR is reviewed and verified.

| Variable | Default | Adds in |
| --- | --- | --- |
| `IDENTRAIL_FEATURE_NEW_AUTH` | `false` | PR 2 |
| `IDENTRAIL_FEATURE_WORKOS_LOGIN` | `false` | PR 4 |
| `IDENTRAIL_FEATURE_CONNECTORS_V2` | `false` | PR 6 |
| `IDENTRAIL_FEATURE_CONNECTOR_AWS` | `false` | PR 7 |
| `IDENTRAIL_FEATURE_CONNECTOR_GITHUB_V2` | `false` | PR 8 |
| `IDENTRAIL_FEATURE_CONNECTOR_K8S` | `false` | PR 9 |
| `IDENTRAIL_FEATURE_ONBOARDING_WIZARD` | `false` | PR 10 |
| `IDENTRAIL_FEATURE_SSO_ADMIN` | `false` | PR 11 |
| `IDENTRAIL_FEATURE_SCIM` | `false` | PR 12 |
| `IDENTRAIL_FEATURE_ENTITLEMENTS` | `false` | PR 12 |
| `VITE_FEATURE_NEW_AUTH_UI` | `false` | PR 5 |
| `VITE_FEATURE_CONNECTORS_V2` | `false` | PR 6 |
| `VITE_FEATURE_CONNECTOR_AWS` | `false` | PR 7 |
| `VITE_FEATURE_CONNECTOR_GITHUB_V2` | `false` | PR 8 |
| `VITE_FEATURE_CONNECTOR_K8S` | `false` | PR 9 |
| `VITE_FEATURE_ONBOARDING_WIZARD` | `false` | PR 10 |

The common pattern is paired flags for UI-backed features: the backend flag (`IDENTRAIL_FEATURE_*`) gates API endpoints and the frontend flag (`VITE_FEATURE_*`) gates the UI surface. Both default off, and turning them on activates the PR's behavior. Backend-only capabilities may expose only an `IDENTRAIL_FEATURE_*` flag.

Identrail Cloud production intentionally enables the onboarding pair during
deployment: `IDENTRAIL_FEATURE_ONBOARDING_WIZARD=true` on the API and
`VITE_FEATURE_ONBOARDING_WIZARD=true` on the web build. Production-oriented
self-hosted examples keep the default off until operators opt in and have new
auth/session configuration ready.

## Existing Variables (Not Touched)

For reference, the variables that already exist and stay unchanged:

- `IDENTRAIL_DATABASE_URL`
- `IDENTRAIL_API_KEYS`, `IDENTRAIL_WRITE_API_KEYS`, scoped key variants
- `IDENTRAIL_OIDC_ISSUER_URL`, `IDENTRAIL_OIDC_AUDIENCE`, claim mappings
- `IDENTRAIL_DEFAULT_TENANT_ID`, `IDENTRAIL_DEFAULT_WORKSPACE_ID`
- `IDENTRAIL_AUDIT_LOG_FILE`, `IDENTRAIL_AUDIT_FORWARD_*`
- `IDENTRAIL_RATE_LIMIT_RPM`, `IDENTRAIL_RATE_LIMIT_BURST`
- `IDENTRAIL_LOCK_BACKEND`, `IDENTRAIL_LOCK_NAMESPACE`
- All scan scheduling and worker variables

The contract: every variable above continues to mean exactly what it means today.

## Validation at Startup

`internal/config` runs validation in three passes:

1. Required variables are present and parse as the expected type.
2. Mutual-exclusion checks (manual mode + WorkOS, missing WorkOS secrets when `IDENTRAIL_FEATURE_WORKOS_LOGIN=true`, etc.).
3. URL reachability checks (where appropriate; WorkOS API health, OIDC discovery endpoint).

Failure in any pass refuses to start the server. The error message names the variable, the rule that failed, and an example correct value.

## Vercel and Deployment Notes

Production secrets (`IDENTRAIL_SESSION_KEY`, all WorkOS keys, the email provider key, GitHub App private key) live in Vercel's environment variable storage scoped to the Production environment. Preview and Development environments have their own values pointing at WorkOS test environments and a sandbox database.

Self-hosted operators set the same variables in `deploy/docker/.env` or their Helm `values.yaml`. The implementation PRs (4, 7, 8, 9, 11) add each new variable to `deploy/docker/.env.example` and `deploy/helm/identrail/values.yaml` in the same commit that introduces it, with the definitions used here. PR 1 does not modify those files; it only documents the contract they will follow.
