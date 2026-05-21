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

## `identrail repo-scan`

Runs repository exposure scanner. This is the backward-compatible long form of
`identrail scan <repository>`.

Aliases:
- `identrail repo`

Key flags:
- positional repository target or `--repo`
- `--history-limit` (default `500`)
- `--max-findings` (default `200`)
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
- `IDENTRAIL_API_KEY` (default rollback auth key)
- `IDENTRAIL_PROVIDER` (affects default fixtures for `scan`)
