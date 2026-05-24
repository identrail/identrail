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
GET  /v1/connectors/github/{connector_id}/posture
POST /auth/webhooks/github
```

Older project-scoped GitHub routes are not the product path. They remain internal compatibility code while the connector surface is finalized, but new UI, docs, and automation should not depend on them.

## Hosted GitHub.com Flow

`POST /v1/connectors/github` creates a pending connector and returns a GitHub
App target-picker URL. The product opens GitHub in a new tab and keeps a
fallback button visible if the browser blocks navigation. The URL starts at
GitHub's account selector (`/installations/select_target`) so GitHub, not
Identrail, shows the personal-account or organization choice before the
selected-repository screen. The product sends GitHub back to
`/app/github/callback`, and that callback calls
`POST /v1/connectors/github/complete` with the returned state and installation
ID. The backend owns the GitHub App slug and webhook secret through environment
variables, so users do not paste app credentials into the browser.

Required runtime configuration for the hosted GitHub App flow:

- `IDENTRAIL_GITHUB_APP_ID`
- `IDENTRAIL_GITHUB_APP_NAME`
- `IDENTRAIL_GITHUB_APP_PRIVATE_KEY`
- `IDENTRAIL_GITHUB_APP_WEBHOOK_SECRET`
- `IDENTRAIL_CONNECTOR_SECRET_KEYS` with
  `IDENTRAIL_CONNECTOR_SECRET_KEYS_REQUIRED=true` for durable connector
  credential storage

The GitHub App manifest lives at `deploy/connectors/github/app-manifest.json`.
It requests read-only permissions for repository metadata, contents, pull
requests, administration settings, Actions settings, repository environments,
code scanning alerts, secret scanning alerts, Dependabot alerts, and repository
webhooks. The manifest is public so GitHub can offer both personal-account and
organization installation targets; production app settings should keep "Where
can this GitHub App be installed?" on "Any account" rather than "Only on this
account." If the production app remains private, GitHub may still only offer the
app owner account even when Identrail starts at the account selector.

Before launching or after changing GitHub App settings, compare the public app
registration against the manifest:

```bash
python3 scripts/check_github_app_manifest.py --slug identrail
```

This check intentionally uses GitHub's public app endpoint. A private app or
wrong slug should fail even if a maintainer can view the app while signed in.
GitHub does not expose every setting through that public endpoint, so operators
must also confirm in the GitHub App settings that:

- Setup URL is `https://app.identrail.com/app/github/callback`.
- Redirect on update is disabled; repository-access changes sync through the
  `installation_repositories` webhook.
- "Where can this GitHub App be installed?" is set to Any account.

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

Personal repositories and organization repositories follow the same completion
path. After callback, Identrail lists repositories selected for that
installation and accepts any `owner/repo` in the selected list, subject to the
hosted repo scan allowlist described below. A repository that was not selected
during installation or was not allowlisted should produce a targeted product
message instead of a generic 404.

## GitHub Enterprise Fallback

`POST /v1/connectors/github/pat` accepts an allowlisted GitHub Enterprise base URL and a personal access token. The API validates the token against `/api/v3/user`, requires `repo` or `public_repo` scope, encrypts the token into the connector secret envelope table, and stores only non-secret metadata on the connector state.

Set `IDENTRAIL_GITHUB_PAT_ALLOWED_BASE_URLS` to the comma-separated list of GitHub.com or GitHub Enterprise origins that PAT validation may call. The default is `https://github.com`. This keeps the fallback usable without letting user input choose arbitrary outbound hosts.

This fallback is for self-hosted GitHub Enterprise and development environments. Hosted Identrail should prefer the GitHub App path.

## Webhooks

`POST /auth/webhooks/github` verifies the global GitHub App HMAC secret before processing events.

Installation lifecycle events can mark matching connectors disconnected. Repository events are matched by installation ID and repository allowlist before queueing scans.

Webhook-triggered scans still honor the repo scan allowlist, per-repository
cursor, and queue controls. Push and pull-request events enqueue `delta` scans
when GitHub supplies a usable head revision. Push events use `before` and
`after` as the base/head revisions and fold commit `added`, `modified`, and
`removed` paths into the scan request. Duplicate delivery IDs, burst-window
repeats, queue pressure, disabled scanning, target-deny decisions, and
already-current cursors are recorded as skipped work instead of creating
unbounded duplicate queue entries.
Before enabling `IDENTRAIL_REPO_SCAN_ENABLED=true` for hosted production, set an
explicit `IDENTRAIL_REPO_SCAN_ALLOWLIST` or equivalent scoped target guard so a
GitHub webhook cannot enqueue scans outside approved repositories.
For the AWS-hosted API workflow, use the first-class repository variables
`API_REPO_SCAN_ENABLED=true` and `API_REPO_SCAN_ALLOWLIST=<owner/repo>` instead
of hiding the same runtime values inside `API_EXTRA_ENVIRONMENT_JSON`.

## Private Repository Scans

GitHub App connections can now back private repository exposure scans. When a
repo scan request includes `project_id`, Identrail verifies that the scoped
project has an active GitHub App connection, that the requested repository is in
the selected repository list, and that the normal repo-scan allowlist still
permits the target.

Queued scans store only non-secret source metadata: provider, project id,
connector id, and installation id. The API and worker never store the raw
installation token in `repo_scans`, `repo_findings`, logs, traces, errors, or
API responses. The worker mints a short-lived installation token immediately
before cloning and passes it to git through an askpass helper so the token does
not appear in clone URLs or command-line arguments.

Scheduled policy scans enqueue `deep` scans, while GitHub webhook-triggered
scans attach the project/connector source context and enqueue `delta` or
`quick` scans depending on event metadata. Private repositories use the same
short-lived GitHub App path as manually queued connector-backed scans.

## Repository Posture Collection

`GET /v1/connectors/github/{connector_id}/posture` collects security posture for
one selected repository through the GitHub App connector. The request must
include `workspace_id`, `project_id`, and a `repository` query value in
`owner/name` form. The API normalizes the repository name, verifies that the
connector belongs to the scoped project, requires an active GitHub App
installation, and denies repositories outside the connector's selected
repository list.

The response is a normalized posture record with one check per control. Check
states are:

- `secure`: the setting was collected and matches Identrail's expected posture.
- `insecure`: the setting was collected and is missing or weak.
- `permission_limited`: GitHub returned a permission/authz response for that
  signal, so the App needs more read permission or the repository/plan does not
  expose it to the installation.
- `unavailable`: GitHub returned an API or rate-limit failure that prevents
  Identrail from making a posture decision for that signal.

The collector currently evaluates repository metadata, default branch
protection, branch rulesets, Actions repository permissions, Dependabot alerts
and security updates, code scanning alerts, secret scanning alerts, deploy keys,
repository webhooks, and deployment environments. Evidence is intentionally
summary-shaped: webhook URLs, credentials, tokens, and other secret-bearing
values are not persisted or returned.

The manifest permissions that support this collection are read-only:

- `metadata`: repository identity and ruleset metadata.
- `administration`: branch protection, deploy keys, security feature toggles,
  and repository administration settings that GitHub exposes as read APIs.
- `actions`: Actions repository permissions.
- `environments`: repository deployment environments and protection metadata.
- `security_events`: code scanning alerts.
- `secret_scanning_alerts`: secret scanning alerts.
- `vulnerability_alerts`: Dependabot alerts.
- `repository_hooks`: repository webhook status.

If one of these permissions is missing, the corresponding posture check should
return `permission_limited` instead of failing the whole collection.

## Rollback

Set `IDENTRAIL_FEATURE_CONNECTOR_GITHUB_V2=false` to return the standard GitHub connector API to 404. Set `VITE_FEATURE_CONNECTOR_GITHUB_V2=false` to hide the frontend path.
