# GitHub Connector

PR 8 adds the standard GitHub connector surface behind:

- Backend: `IDENTRAIL_FEATURE_CONNECTOR_GITHUB_V2=true`
- Frontend: `VITE_FEATURE_CONNECTOR_GITHUB_V2=true`

The product UI should use only the standard connector endpoints:

```text
POST /v1/connectors/github
GET  /v1/connectors/github
POST /v1/connectors/github/complete
POST /v1/connectors/github/pat
GET  /v1/connectors/github/{connector_id}/repos
POST /auth/webhooks/github
```

Older project-scoped GitHub routes are not the product path. They remain internal compatibility code while the connector surface is finalized, but new UI, docs, and automation should not depend on them.

## Hosted GitHub.com Flow

`POST /v1/connectors/github` creates a pending connector and returns a GitHub App install URL. The product sends GitHub back to `/app/github/callback`, and that callback calls `POST /v1/connectors/github/complete` with the returned state and installation ID. The backend owns the GitHub App slug and webhook secret through environment variables, so users do not paste app credentials into the browser.

Required runtime configuration for the hosted GitHub App flow:

- `IDENTRAIL_GITHUB_APP_ID`
- `IDENTRAIL_GITHUB_APP_NAME`
- `IDENTRAIL_GITHUB_APP_PRIVATE_KEY`
- `IDENTRAIL_GITHUB_APP_WEBHOOK_SECRET`
- `IDENTRAIL_CONNECTOR_SECRET_KEYS` with
  `IDENTRAIL_CONNECTOR_SECRET_KEYS_REQUIRED=true` for durable connector
  credential storage

The GitHub App manifest lives at `deploy/connectors/github/app-manifest.json`. It requests read-only permissions: metadata, contents, pull requests, and code scanning alerts.

For Identrail Cloud, the AWS API manual deploy workflow exposes first-class
inputs for this path:

- `API_FEATURE_CONNECTOR_GITHUB_V2` defaults to `true`; set it to `false` only
  for rollback.
- `API_GITHUB_APP_ID` and `API_GITHUB_APP_NAME` are repository variables.
- `API_GITHUB_APP_PRIVATE_KEY_SECRET_ARN`,
  `API_GITHUB_APP_WEBHOOK_SECRET_ARN`, and
  `API_CONNECTOR_SECRET_KEYS_SECRET_ARN` are repository secrets that reference
  Secrets Manager ARNs.

The versioned release web build enables `VITE_FEATURE_CONNECTOR_GITHUB_V2=true`
and still honors the backend feature availability contract. If the API reports
that the GitHub connector route is disabled, the product source screen marks the
GitHub source unavailable instead of calling the connector route and showing a
raw framework 404. If the route is enabled but the GitHub App runtime settings
are missing, the start request returns the API's configuration message so the
operator sees a specific setup problem.

## GitHub Enterprise Fallback

`POST /v1/connectors/github/pat` accepts an allowlisted GitHub Enterprise base URL and a personal access token. The API validates the token against `/api/v3/user`, requires `repo` or `public_repo` scope, encrypts the token into the connector secret envelope table, and stores only non-secret metadata on the connector state.

Set `IDENTRAIL_GITHUB_PAT_ALLOWED_BASE_URLS` to the comma-separated list of GitHub.com or GitHub Enterprise origins that PAT validation may call. The default is `https://github.com`. This keeps the fallback usable without letting user input choose arbitrary outbound hosts.

This fallback is for self-hosted GitHub Enterprise and development environments. Hosted Identrail should prefer the GitHub App path.

## Webhooks

`POST /auth/webhooks/github` verifies the global GitHub App HMAC secret before processing events.

Installation lifecycle events can mark matching connectors disconnected. Repository events are matched by installation ID and repository allowlist before queueing scans.

Webhook-triggered scans still honor the repo scan allowlist and queue controls.
Before enabling `IDENTRAIL_REPO_SCAN_ENABLED=true` for hosted production, set an
explicit `IDENTRAIL_REPO_SCAN_ALLOWLIST` or equivalent scoped target guard so a
GitHub webhook cannot enqueue scans outside approved repositories.
For the AWS-hosted API workflow, use the first-class repository variables
`API_REPO_SCAN_ENABLED=true` and `API_REPO_SCAN_ALLOWLIST=<owner/repo>` instead
of hiding the same runtime values inside `API_EXTRA_ENVIRONMENT_JSON`.

## Rollback

Set `IDENTRAIL_FEATURE_CONNECTOR_GITHUB_V2=false` to return the standard GitHub connector API to 404. Set `VITE_FEATURE_CONNECTOR_GITHUB_V2=false` to hide the frontend path.
