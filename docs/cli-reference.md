# CLI Reference

## Root command

- `identrail`

Global flag:
- `--state-file` (default `.identrail/last-findings.json`)

## `identrail scan`

Runs provider scan pipeline and prints findings when no repository argument is
provided.

Key flags:
- `--fixture` (repeatable)
- `--output table|json`
- `--stale-after-days` (default `90`)
- `--no-save`

## `identrail scan <repository>`

Runs repository exposure scanner using the short command form.

Examples:
- `identrail scan identrail/identrail`
- `identrail scan owner/repo --history-limit 50 --max-findings 20`
- `identrail scan https://github.com/owner/repo.git --output json`

Key flags:
- `--history-limit` (default `500`)
- `--max-findings` (default `200`)
- `--output table|json`

## `identrail findings`

Reads persisted findings state and prints output.

Key flags:
- `--output table|json`

## `identrail aws-status`

Fetches hosted AWS connector status for one project or environment. Table output
summarizes connection state, health, declared scope, account coverage, region
coverage, permission checks, next action, connector ID, and diagnostic count.
JSON output returns the API response envelope. The command never prints the
connector External ID.

Example:
```bash
identrail aws-status \
  --api-url "$IDENTRAIL_API_URL" \
  --api-key "$IDENTRAIL_API_KEY" \
  --tenant-id tenant-a \
  --workspace-id workspace-a \
  --project-id production
```

Key flags:
- `--api-url`
- `--api-key`
- `--tenant-id`
- `--workspace-id` (required unless configured as the default workspace)
- `--project-id` (required)
- `--connector-id` (optional, uses the connector-specific poll route)
- `--timeout`
- `--output table|json`

## AWS connector lifecycle

The hosted lifecycle commands use the same scoped API operations as the app:

```bash
identrail aws-disable --workspace-id workspace-a --project-id production --connector-id aws-prod
identrail aws-enable --workspace-id workspace-a --project-id production --connector-id aws-prod
identrail aws-disconnect --workspace-id workspace-a --project-id production --connector-id aws-prod --confirm aws-prod
```

All commands accept `--api-url`, `--api-key`, `--tenant-id`, `--timeout`, and
`--output table|json`. They never print the connector External ID.

Refresh a live organization rollout after an AWS-side repair:

```bash
identrail aws-rollout-reconcile \
  --workspace-id workspace-a \
  --project-id production \
  --rollout-id rollout-id
```

## `identrail repo-scan`

Runs the local repository exposure scanner. This is the backward-compatible long
form of `identrail scan <repository>`.

Aliases:
- `identrail repo`

Key flags:
- positional repository target or `--repo`
- `--history-limit` (default `500`)
- `--max-findings` (default `200`)
- `--output table|json`

## `identrail repo-scan queue`

Queues an API-backed repository intelligence scan. Use this for hosted scans,
private repositories, GitHub App installation credentials, and incremental scan
metadata.

Key flags:
- `--api-url`
- `--api-key`
- `--tenant-id`
- `--workspace-id`
- `--repo` (required)
- `--project-id` (required for GitHub App private repo scans)
- `--connector-id`
- `--scan-mode quick|delta|deep`
- `--base-revision`
- `--head-revision`
- `--changed-path` (repeatable or comma-separated)
- `--history-limit` (default `0`, server default)
- `--max-findings` (default `0`, server default)
- `--timeout`
- `--output table|json`

## `identrail repo-scan list|show|cancel`

Reads or cancels API-backed repository scans.

Examples:
```bash
identrail repo-scan list --limit 20
identrail repo-scan show <repo-scan-id>
identrail repo-scan cancel <repo-scan-id>
```

Common flags:
- `--api-url`
- `--api-key`
- `--tenant-id`
- `--workspace-id`
- `--timeout`
- `--output table|json`

## `identrail repo-findings list`

Lists repository findings with lifecycle, ownership, detector, confidence, and
age filters.

Key flags:
- `--api-url`
- `--api-key`
- `--tenant-id`
- `--workspace-id`
- `--repo-scan-id`
- `--repo`
- `--severity`
- `--type`
- `--status`
- `--detector`
- `--owner`
- `--min-confidence`
- `--min-age-days`
- `--limit`
- `--cursor`
- `--sort-by`
- `--sort-order`
- `--timeout`
- `--output table|json`

## `identrail repo-risk-graph`

Fetches the repository-to-machine-identity risk graph from the API.

Key flags:
- `--api-url`
- `--api-key`
- `--tenant-id`
- `--workspace-id`
- `--repo-scan-id`
- `--repo`
- `--default-branch`
- `--severity`
- `--type`
- `--timeout`
- `--output table|json`

## `identrail repo-posture`

Collects GitHub repository posture through a connected GitHub App.

Key flags:
- `--api-url`
- `--api-key`
- `--tenant-id`
- `--workspace-id`
- `--connector-id` (required)
- `--project-id` (required)
- `--repo` (required)
- `--timeout`
- `--output table|json`

## `identrail repo-remediation preview`

Previews detector-specific remediation for one repository finding and can return
a safe fix-PR plan when source content is supplied.

Key flags:
- `--api-url`
- `--api-key`
- `--tenant-id`
- `--workspace-id`
- `--repo-scan-id`
- `--source-file`
- `--source-content`
- `--base-branch`
- `--branch-prefix`
- `--finding-url`
- `--require-fix-plan`
- `--timeout`
- `--output table|json`

## `identrail repo-remediation publish`

Publishes an approved deterministic remediation branch and GitHub pull request
for one repository finding. Publication requires current source content, an
explicit approval flag, explicit confirmation that write permissions are
configured, and a short-lived GitHub token.

Key flags:
- `--api-url`
- `--api-key`
- `--tenant-id`
- `--workspace-id`
- `--repo-scan-id`
- `--source-file`
- `--source-content`
- `--base-branch`
- `--branch-prefix`
- `--finding-url`
- `--github-token`
- `--github-token-env`
- `--approve`
- `--write-permissions-configured`
- `--timeout`
- `--output table|json`

## `identrail authz rollback`

Calls rollback endpoint for active policy version switch.

Key flags:
- `--api-url`
- `--api-key`
- `--tenant-id`
- `--workspace-id`
- `--policy-set-id` (default `central_authorization`)
- `--target-version` (required)
- `--actor`
- `--timeout`
- `--output table|json`

## Environment variables used by CLI

- `IDENTRAIL_API_URL` (default API base URL)
- `IDENTRAIL_API_KEY` (default API auth key for API-backed CLI commands)
- `IDENTRAIL_PROVIDER` (affects default fixtures for `scan`)
