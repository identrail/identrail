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

The GitHub App manifest lives at `deploy/connectors/github/app-manifest.json`. It requests read-only permissions: metadata, contents, pull requests, and code scanning alerts.

## GitHub Enterprise Fallback

`POST /v1/connectors/github/pat` accepts an allowlisted GitHub Enterprise base URL and a personal access token. The API validates the token against `/api/v3/user`, requires `repo` or `public_repo` scope, encrypts the token into the connector secret envelope table, and stores only non-secret metadata on the connector state.

Set `IDENTRAIL_GITHUB_PAT_ALLOWED_BASE_URLS` to the comma-separated list of GitHub.com or GitHub Enterprise origins that PAT validation may call. The default is `https://github.com`. This keeps the fallback usable without letting user input choose arbitrary outbound hosts.

This fallback is for self-hosted GitHub Enterprise and development environments. Hosted Identrail should prefer the GitHub App path.

## Webhooks

`POST /auth/webhooks/github` verifies the global GitHub App HMAC secret before processing events.

Installation lifecycle events can mark matching connectors disconnected. Repository events are matched by installation ID and repository allowlist before queueing scans.

## Rollback

Set `IDENTRAIL_FEATURE_CONNECTOR_GITHUB_V2=false` to return the standard GitHub connector API to 404. Set `VITE_FEATURE_CONNECTOR_GITHUB_V2=false` to hide the frontend path.
