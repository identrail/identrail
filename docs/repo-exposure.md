# Repository Exposure Scanner

## Goal

Detect leaked secrets and high-signal misconfigurations in authorized repository history, without storing raw secret values.

## Command

```bash
identrail repo-scan --repo owner/repo
```

CLI also supports full URLs and local git paths:

```bash
identrail repo-scan --repo https://github.com/owner/repo.git
identrail repo-scan --repo /path/to/local/repo
```

## API

You can trigger the same scanner through API:

```bash
curl -X POST http://localhost:8080/v1/repo-scans \
  -H "Content-Type: application/json" \
  -H "X-API-Key: <write-enabled-key>" \
  -d '{
    "repository": "owner/repo",
    "history_limit": 500,
    "max_findings": 200
  }'
```

API/worker repository target forms:
- `owner/repo`
- `https://...`
- `ssh://...`
- `git@...`

Local filesystem repository paths are CLI-only and are not valid API/worker targets.

For private GitHub repositories, pass the owning project id for a connected
GitHub App installation:

```bash
curl -X POST http://localhost:8080/v1/repo-scans \
  -H "Content-Type: application/json" \
  -H "X-API-Key: <write-enabled-key>" \
  -d '{
    "repository": "owner/private-repo",
    "project_id": "project-1",
    "history_limit": 500,
    "max_findings": 200
  }'
```

Connector-backed scans require the repository to be selected on the project's
GitHub App connection and still honor `IDENTRAIL_REPO_SCAN_ALLOWLIST`, queue
capacity, and per-repository concurrency controls.

Read APIs:

- `GET /v1/repo-scans`
- `GET /v1/repo-scans/:repo_scan_id`
- `GET /v1/repo-findings?repo_scan_id=&severity=&type=`
- `GET /v1/repo-finding-clusters?repo_scan_id=&severity=&type=`
- list endpoints support cursor pagination (`?limit=...&cursor=...`) and return `next_cursor` when more results exist
- repo finding responses expose stable repository and location fields when available: `repository`, `file_path`, `line_number`, `commit`, `detector`, `line_snippet`, `line_snippet_redacted`, and `source_url`
- `source_url` is a direct GitHub blob link pinned to the detected commit when Identrail can derive one
- grouped cluster responses roll duplicate repo findings into cluster counts with `first_seen_at`, `last_seen_at`, `spread`, and a per-occurrence `members` list

## What It Scans

1. Commit history (all reachable commits, bounded by `--history-limit`):
- Added diff lines are scanned for token/key material.
2. HEAD snapshot:
- IaC/CI/runtime config files are scanned for high-signal misconfig patterns.

## Current Detections

The scanner uses a versioned secret detector registry for commit-history secret detection.

- Secret detector families (history):
  - AWS: access key IDs and secret keys
  - GitHub: `ghp_`, `gho_`, `ghu_`, `ghr_`, `ghs_`, `github_pat_` and app tokens
  - GitLab: `glpat-...`
  - Slack: `xox*` tokens
  - Azure: `AZURE_CLIENT_SECRET`
  - GCP: `AIza...` API keys
  - Stripe: `sk_*` / `pk_*` keys
  - OpenAI: `sk-...` / `sk-proj-...`
  - WorkOS: `workos_live_...` / `workos_test_...`
  - Vercel: `vercel_pat_...`
  - npm: registry token fields
  - Docker Hub: `dckr_pat_...`
  - TLS/PKI: private key and certificate headers
  - JWT-like bearer material
  - Database connection URLs with embedded credentials
  - OAuth client secrets
  - Webhook signing secrets
  - CI/CD platform tokens
- Misconfiguration detectors (HEAD):
  - GitHub Actions `permissions: write-all`
  - GitHub Actions `pull_request_target` trigger
  - Kubernetes `privileged: true`
  - Terraform public S3 ACL
  - Terraform SSH/RDP open to world (`0.0.0.0/0`)
  - Docker `FROM ...:latest`

## Registry model

- The detector list is centrally maintained as a Go-structured registry in `internal/repoexposure/rules.go`.
- Each detector includes:
  - Stable detector ID
  - Detector version
  - Provider + category metadata
  - Severity, summary, and remediation guidance
  - One or more matcher patterns
  - Optional entropy thresholds
- Detection metadata includes registry details in each finding evidence:
  - `detector`
  - `detector_version`
  - `detector_category`
  - `detector_provider`
  - `confidence_score`
  - `confidence_state`
  - `confidence_reasons`

To add a new secret detector, add a new entry to the registry with a unique ID, a new version if needed for compatibility, and test fixtures.

## Secret Confidence Classification

Secret findings are not silently dropped when they look like examples or test
fixtures. Instead, the scanner emits confidence metadata so API clients and
analysts can triage the result without losing auditability.

Current `confidence_state` values for repo secret findings:

- `high_confidence`: provider-shaped secret material in a production-like path.
- `medium_confidence`: matched secret material with weaker detector confidence or generic shape.
- `sample_or_placeholder`: sample, docs, `.env.example`, obvious placeholder, sequential, repeated, or low-entropy values.
- `test_fixture`: findings under test, fixture, or `testdata` paths.
- `allowlisted`: the secret fingerprint is listed in the repository's local `.identrailignore` file.

Confidence is evidence metadata and also populates the top-level
`confidence_score` field in finding API responses. Scores are deterministic and
bounded from `0.01` to `0.99`; allowlisted fingerprints are emitted at `0.05`.

The first suppression mechanism is repository-local and fingerprint based. Add a
`.identrailignore` file at repository HEAD with one fingerprint per line:

```text
# Comments are ignored.
secret-fingerprint: <sha256-secret-fingerprint>
sha256=<sha256-secret-fingerprint>
```

The scanner still emits allowlisted findings by default, but marks them as
`allowlisted` and includes `secret_allowlisted: true` in evidence. Organization
or dashboard-managed suppression policies are intentionally left to a later
workflow layer.

## Security Guardrails

- Read-only git operations only (`clone --mirror`, `rev-list`, `show`, `ls-tree`).
- Secret values are never stored in findings.
- Evidence keeps only:
  - detector name
  - commit/path/line context
  - line snippet (redacted for secret findings)
  - secret fingerprint (SHA-256)
  - redacted line snippets
- Findings are deterministic and deduplicated by stable IDs/fingerprints.
- Output is capped by `--max-findings` to prevent runaway payloads.
- Repo scan metadata/findings are persisted in dedicated storage (`repo_scans`, `repo_findings`) to avoid changing existing cloud scan APIs.
- GitHub App private-repo scans persist only non-secret connector context
  (`source_provider`, project id, connector id, installation id). The worker
  mints the short-lived installation token at execution time and passes it to
  git through `GIT_ASKPASS`, not through clone URLs, process arguments,
  findings, scan rows, logs, or API responses.
- Snapshot-based repo misconfiguration findings now persist the resolved HEAD commit SHA on new scans so GitHub links stay pinned to the scanned revision.

## Useful Flags

- `--history-limit` (default: `500`): max commits to inspect.
- `--max-findings` (default: `200`): hard cap on findings.
- `--output table|json`.

## Runtime Configuration

- Hosted API/worker images must include `git` at runtime. The scanner performs
  read-only clone and history commands inside the running worker, not only
  during image build.
- `IDENTRAIL_REPO_SCAN_ENABLED` (default: `false`)
- `IDENTRAIL_REPO_SCAN_HISTORY_LIMIT` (default: `500`)
- `IDENTRAIL_REPO_SCAN_MAX_FINDINGS` (default: `200`)
- `IDENTRAIL_REPO_SCAN_HISTORY_LIMIT_MAX` (default: `5000`)
- `IDENTRAIL_REPO_SCAN_MAX_FINDINGS_MAX` (default: `1000`)
- `IDENTRAIL_REPO_SCAN_ALLOWLIST`:
  - required when `IDENTRAIL_REPO_SCAN_ENABLED=true`
  - comma-separated list of allowed target patterns
  - supports prefix wildcard with `*` (example: `trusted-org/*`)
  - set `*` only if you intentionally want open target scope
- Optional worker scheduling:
  - `IDENTRAIL_WORKER_REPO_SCAN_ENABLED` (`false` by default)
  - `IDENTRAIL_WORKER_REPO_SCAN_RUN_NOW` (`false` by default)
  - `IDENTRAIL_WORKER_REPO_SCAN_INTERVAL` (`1h` by default)
  - `IDENTRAIL_WORKER_REPO_SCAN_TARGETS` (required when enabled)
  - `IDENTRAIL_WORKER_REPO_SCAN_HISTORY_LIMIT` (`0` means use service default)
  - `IDENTRAIL_WORKER_REPO_SCAN_MAX_FINDINGS` (`0` means use service default)

## Concurrency Behavior

- Cloud scan lock key: `scan:<provider>`
- Repo scan lock key: `repo-scan:<target>`
- If a repo target is already running, API returns `409` and worker logs skip for that target.

## Known Limits

- Focused on high-signal patterns, not exhaustive secret taxonomy.
- Full-history scanning on very large repositories can be expensive; tune `--history-limit`.
- Private remote scans are supported for GitHub App connectors. Other private
  git hosts still need an explicit connector-backed credential flow before API
  or worker scans can authenticate to them.
- CLI scans support public remotes and local repository paths, but do not use
  saved Identrail connector credentials.
