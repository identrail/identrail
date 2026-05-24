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

The terminal also exposes the hosted/API-backed GitHub intelligence surface:

```bash
identrail repo-scan queue \
  --repo owner/private-repo \
  --project-id project-1 \
  --connector-id github-app

identrail repo-scan list
identrail repo-findings list --repo owner/private-repo --status open --min-confidence 0.8
identrail repo-risk-graph --repo owner/private-repo
identrail repo-posture --connector-id github-app --project-id project-1 --repo owner/private-repo
identrail repo-remediation preview <finding-id> --repo-scan-id <repo-scan-id>
```

API-backed CLI commands use `IDENTRAIL_API_URL`, `IDENTRAIL_API_KEY`,
`--tenant-id`, and `--workspace-id` the same way other API CLI commands do.

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
GitHub App connection and still honor queue capacity and per-repository
concurrency controls. Direct non-connector scans continue to use
`IDENTRAIL_REPO_SCAN_ALLOWLIST` for their target guard.

Read APIs:

- `GET /v1/repo-scans`
- `GET /v1/repo-scans/:repo_scan_id`
- `GET /v1/repo-findings?repo_scan_id=&repository=&status=&severity=&type=&detector=&owner=&confidence=&age_days=`
- `POST /v1/repo-findings/:finding_id/remediation/preview?repo_scan_id=`
- `GET /v1/repo-finding-clusters?repo_scan_id=&severity=&type=`
- `GET /v1/repo-risk-graph?repo_scan_id=&repository=&default_branch=&severity=&type=`
- list endpoints support cursor pagination (`?limit=...&cursor=...`) and return `next_cursor` when more results exist
- repo finding responses expose stable repository, lifecycle, and location fields when available: `repository`, `file_path`, `line_number`, `commit`, `detector`, `line_snippet`, `line_snippet_redacted`, `source_url`, `lifecycle_key`, `lifecycle_status`, `owner`, `first_seen_at`, `last_seen_at`, `fixed_at`, `reopened_at`, `dismissed_at`, and `suppression_expires_at`
- `source_url` is a direct GitHub blob link pinned to the detected commit when Identrail can derive one
- repo finding pages include a `summary` object with open, fixed, reopened, suppressed, SLA-aged, and MTTR-ready counts plus owner, detector, and severity rollups
- grouped cluster responses roll duplicate repo findings into cluster counts with `first_seen_at`, `last_seen_at`, `spread`, and a per-occurrence `members` list

## Finding Lifecycle

Repository finding lifecycle is computed from a stable `lifecycle_key`, not only
from the per-scan row id. This lets Identrail connect the same secret,
misconfiguration, or external scanner alert across repeated scans even when a
commit-scoped finding id changes.

Lifecycle semantics:

- `open`: first observed in the current repository state or still present after a later scan
- `fixed`: previously open/reopened finding was absent from a completed, non-truncated deep scan
- `reopened`: previously fixed finding appeared again in a later scan
- `suppressed`: operator suppression is active; a suppression reason is required and expiry is optional
- `risk_accepted` / `false_positive`: reserved lifecycle states for ownership workflows that need durable dismissal semantics

Identrail preserves `first_seen_at` when a finding persists, updates
`last_seen_at` when it is observed again, sets `fixed_at` when a full deep scan
no longer sees it, and sets `reopened_at` when a fixed finding returns. Delta,
quick, changed-path, and truncated scans do not close missing findings because
they did not inspect the whole repository.

Operational guidance:

- Use `repo_lifecycle_status=open&age_days=7&severity=high` to find high-risk findings that are aging beyond the default SLA window.
- Use `owner=` and `detector=` filters to route queues to repository owners or detector specialists.
- Treat `mean_time_to_resolve_seconds` as MTTR-ready only for findings with both `first_seen_at` and `fixed_at`.
- Prefer suppression comments that explain the business reason; leave `suppression_expires_at` empty only for durable, reviewed exceptions.

## Safe Remediation Previews

Repository findings can be converted into rule-specific remediation previews
without publishing a branch:

```bash
curl -X POST http://localhost:8080/v1/repo-findings/:finding_id/remediation/preview \
  -H "Content-Type: application/json" \
  -H "X-API-Key: <read-enabled-key>" \
  -d '{
    "repo_scan_id": "<repo-scan-id>",
    "base_branch": "main",
    "source_content": "name: ci\npermissions: write-all\n"
  }'
```

Preview mode returns:

- detector-specific risk summary, remediation steps, safety notes, and validation notes
- non-secret traceability fields such as finding ID, scan ID, repository, commit, path, and line
- an optional `fix_pr_plan` only when the detector has a deterministic patch and the caller supplies current affected-file content

Generated fix-PR plans are intentionally constrained:

- they modify only the affected repository file, never a default branch directly
- they include finding ID, scan ID, detector, risk summary, validation notes, and safety notes in the PR body
- they are preview-only until an operator explicitly approves publication and supplies write-capable GitHub credentials
- read-only scanner installations can request previews but cannot publish PRs by default

Secret findings are handled differently. Identrail returns rotation and
revocation guidance, but does not generate source patches or PR plans for
secret exposure findings. This prevents raw secret values from being copied
into generated branches, commits, PR descriptions, logs, or review comments.

Deterministic publishable templates currently cover:

- GitHub Actions `permissions: write-all`
- GitHub Actions `pull_request_target` trigger replacement when the workflow owner approves moving to `pull_request`
- Kubernetes `privileged: true`
- Terraform S3 `public-read` / `public-read-write` ACLs

Guidance-only templates cover workflow attack-path findings that need owner
review, Docker `latest` image pinning where the correct version/digest must be
chosen, and open SSH/RDP Terraform ingress where approved administrative CIDRs
are environment-specific.
Management APIs:

- `POST /v1/repo-scans/:repo_scan_id/cancel` marks a queued or running scan
  terminal with `repository scan canceled by user`, freeing the repository for
  a fresh scan.

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
  - GitHub Actions workflow attack paths:
    - `pull_request_target` checking out untrusted PR head code
    - privileged `pull_request_target` jobs with write-token scopes or secrets
    - workflow/job-level broad token write scopes
    - unpinned third-party actions that use mutable refs
    - shell interpolation of PR or issue-controlled GitHub context
    - unsafe `workflow_run` privilege chains
    - broad OIDC credential-minting context
    - cache keys or restore paths influenced by untrusted PR context
    - artifact or release publishing reachable from untrusted inputs
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

GitHub Actions workflow findings also include contextual evidence such as:

- `workflow_events`
- `workflow_job`
- `workflow_step_index`
- `workflow_action`
- `permission_summary`
- `write_scopes`
- detector-specific evidence such as `checkout_ref`, `untrusted_context`,
  `cache_key`, `cache_restore_keys`, or `publishes_release`

This lets Identrail report the dangerous combination instead of only reporting
that a keyword exists. For example, a hardened `pull_request_target` metadata
workflow can remain a lower-context signal, while a `pull_request_target`
workflow that checks out `${{ github.event.pull_request.head.sha }}` and grants
write permissions is emitted as a critical workflow attack path.

### GitHub Actions Workflow Detectors

| Detector | Signal | Typical severity | Recommended remediation |
| --- | --- | --- | --- |
| `workflow_broad_token_permissions` | Workflow or job `GITHUB_TOKEN` permissions grant write-capable scopes beyond `id-token: write`. | High | Default to read-only workflow permissions and move write scopes to the smallest job that needs them. |
| `workflow_pull_request_target_privileged_context` | `pull_request_target` runs with write-token permissions or secret access. | Critical | Keep `pull_request_target` metadata-only, remove secrets, and move untrusted code execution to `pull_request`. |
| `workflow_pull_request_target_untrusted_checkout` | `pull_request_target` checks out PR head ref, SHA, or fork repository. | Critical | Checkout only trusted base code in privileged workflows, or split the untrusted build into an unprivileged workflow. |
| `workflow_unpinned_third_party_action` | A non-local action outside `actions/*` uses a mutable tag or branch instead of a full commit SHA. | Medium | Pin third-party actions to audited commit SHAs and update them through reviewed dependency changes. |
| `workflow_shell_injection_user_context` | A shell step interpolates PR title/body/branch, issue text, or comment body directly. | High | Pass user-controlled context through quoted environment variables or avoid shell interpolation entirely. |
| `workflow_run_privilege_chain` | `workflow_run` reaches write permissions, secrets, cloud login, or release behavior. | High | Treat upstream artifacts as untrusted, validate them before privileged use, and gate deploy jobs with environments. |
| `workflow_oidc_broad_trust` | `id-token: write` is available from untrusted events, `workflow_run`, or broad all-branch push deploys. | High | Restrict cloud trust policies to protected branches and environments, and avoid OIDC on untrusted workflow paths. |
| `workflow_cache_poisoning` | Cache keys or restore paths are influenced by PR-controlled context, or broad restore keys are used on untrusted events. | Medium | Separate untrusted PR caches from trusted build caches and avoid broad restore keys in privileged jobs. |
| `workflow_artifact_poisoning` | PR or `workflow_run` context can upload artifacts or release assets consumed later. | Medium to high | Keep untrusted artifacts isolated, verify provenance before reuse, and publish releases only from protected contexts. |

To add a new secret detector, add a new entry to the registry with a unique ID, a new version if needed for compatibility, and test fixtures.

## External Scanner Adapters

The scanner can import findings from explicit, caller-provided adapters. No
external scanner binaries are executed by default. This keeps hosted scans
read-only and deterministic unless a future caller deliberately wires a scanner
runner with its own allowlist, timeout, filesystem, and network controls.

Supported ingestion surfaces:

- SARIF 2.1.0 results, including tools such as Semgrep, Gitleaks, CodeQL, and
  other scanners that emit SARIF.
- GitHub code-scanning alerts fetched through the GitHub App connector's
  `security_events: read` permission.
- GitHub secret-scanning alerts fetched through the GitHub App connector's
  `secret_scanning_alerts: read` permission.
- GitHub Dependabot vulnerability alerts fetched through the GitHub App
  connector's `vulnerability_alerts: read` permission.

Connector-backed GitHub App repository scans collect open code-scanning,
secret-scanning, and Dependabot alerts for selected repositories when the
installation permission allows it. Each source is independent: if the
installation cannot read one of these alert APIs, or GitHub returns a
permission-limited, unavailable, or rate-limited response, the native Identrail
scan and the other imports still complete. Adapter findings are simply absent
for the source that could not be read.

### Posture checks vs imported alert findings

These imports are distinct from the repository posture collection exposed by
`GET /v1/connectors/github/{connector_id}/posture`:

- Posture checks answer "is this security feature configured?" They return a
  per-control state (`secure`, `insecure`, `permission_limited`, `unavailable`)
  for code scanning, secret scanning, and Dependabot, without enumerating the
  individual alerts.
- Imported alert findings answer "what open problems exist right now?" They turn
  each open GitHub-native alert into a first-class `domain.Finding` that
  participates in the same findings workflow, lifecycle, dedupe, and risk
  scoring as native scanner results.

A repository can therefore show a `secure` posture for "secret scanning enabled"
while still surfacing individual imported secret-scanning findings for the open
alerts GitHub reports.

GitHub-native alert findings carry source metadata so they are distinguishable
from native scanner output:

- secret-scanning alerts: `adapter_source_type: github_secret_scanning`,
  `adapter_secret_type`, `adapter_secret_validity`, and the GitHub
  `adapter_alert_url`. They are normalized as `secret_exposure` findings.
- Dependabot alerts: `adapter_source_type: github_dependabot`,
  `adapter_ecosystem`, `adapter_package`, `adapter_advisory_ghsa`,
  `adapter_advisory_cve`, `adapter_advisory_identifiers`,
  `adapter_vulnerable_range`, `adapter_first_patched_version`, and the GitHub
  `adapter_alert_url`. They are normalized as repository findings
  (`repo_misconfiguration`).

Imported secret-scanning alerts never store the raw secret value. Identrail does
not fetch or deserialize the GitHub `secret` field; it keeps only the secret type
label, validity, and alert metadata, stores a redacted snippet marker, and sets
`line_snippet_redacted: true`, `raw_secret_stored: false`, and
`secret_value_masked: true`. Severity is mapped from alert validity (active
secrets are treated as critical; otherwise high). Dependabot severity is mapped
from the advisory severity (`critical`/`high`/`medium`/`moderate`/`low`).

Adapter findings are normalized into the same `domain.Finding` shape as native
repository findings, and include adapter-specific evidence metadata:

- `adapter_name`
- `adapter_version`
- `adapter_source_type`
- `adapter_rule_id`
- `adapter_rule_name`
- `adapter_confidence`
- `adapter_severity_source`
- `adapter_location_path`
- `adapter_location_line`
- `adapter_location_column`

Secret-like adapter findings are treated as secret exposure findings and do not
store raw messages or snippets. Identrail stores a redacted snippet marker,
sets `line_snippet_redacted: true`, and records `raw_secret_stored: false`,
`secret_value_masked: true`, and `raw_adapter_result_stored: false` evidence.

External findings are deduplicated by stable IDs, adapter dedupe keys, detector
location, and same-line snippet fingerprints. This prevents a native detector
and an external scanner from flooding the same path/line with repeated copies
of the same underlying issue.

## GitHub-to-Machine-Identity Risk Graph

Repository findings can be projected into a deterministic risk graph through
`GET /v1/repo-risk-graph` or `domain.BuildRepoRiskGraph`. The graph is built
from existing finding fields and evidence metadata; it does not execute extra
scanners or infer cloud state that was not observed.

Supported node concepts:

- Repository and default branch.
- Repository finding.
- GitHub Actions workflow and workflow job.
- GitHub environment.
- GitHub secret reference or exposed token/credential fingerprint.
- GitHub Actions OIDC subject.
- Cloud role or service-account reference when evidence names one.
- Kubernetes service account when evidence names one.
- GitHub App and deploy-key references when evidence names them.
- Unknown node for missing blast-radius evidence that should not be guessed.

Supported edge concepts:

- Finding belongs to repository.
- Repository contains workflow.
- Finding affects workflow.
- Workflow runs job.
- Job uses secret.
- Finding exposes token or credential material.
- Workflow or job can mint an OIDC token.
- OIDC subject can assume a named role when evidence identifies the role.
- Repository deploys to an environment.
- Finding references an identity such as a role, service account, GitHub App,
  or deploy key.
- Reachability is unknown when evidence proves a risky path exists but does not
  name the downstream identity.

Risk scoring is graph-aware and inspectable. Each finding score includes
separate factors for severity, confidence, exploitability, privilege, exposure,
environment criticality, and freshness. For example, a high-severity workflow
finding with `id-token:write`, a cloud-auth action, a production environment,
and a named role scores higher than a low-severity repository hygiene issue.
An OIDC finding without a named cloud role still receives an OIDC privilege
factor, but the missing role is recorded in `unknowns` and represented by an
unknown reachability edge.

Evidence limits are intentional:

- Identrail links workflow, secret, OIDC, role, environment, and service-account
  nodes only when fields or finding evidence provide those names.
- A broad OIDC finding without `aws_role_arn`, `cloud_role_arn`,
  `cloud_role`, `azure_client_id`, or `gcp_service_account` evidence gets an
  unknown downstream identity instead of a guessed provider role.
- Secret findings create token or secret nodes using fingerprints, detector
  IDs, or non-secret labels. Raw secret values are not required and should not
  be stored for graph construction.
- The graph is a repo-finding evidence model. Full cloud-provider posture
  collection, cross-account trust expansion, UI visualization, and
  auto-remediation remain separate layers.

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
- External adapters are opt-in. Identrail imports already-produced SARIF or
  GitHub alert data; it does not execute Gitleaks, Semgrep, CodeQL, or other
  third-party scanner binaries by default.
- External adapter evidence stores normalized metadata only and explicitly
  records `raw_adapter_result_stored: false`.
- Repo scan metadata/findings are persisted in dedicated storage (`repo_scans`, `repo_findings`) to avoid changing existing cloud scan APIs.
- Repo scan records now include `scan_mode`, base/head revision, cursor before
  and after values, changed paths, and truncation status. Successful scans also
  update a scoped `repo_scan_cursors` row so repeated delta requests at the
  same head revision can be skipped before worker time is spent.
- GitHub App private-repo scans persist only non-secret connector context
  (`source_provider`, project id, connector id, installation id). The worker
  mints the short-lived installation token at execution time and passes it to
  git through `GIT_ASKPASS`, not through clone URLs, process arguments,
  findings, scan rows, logs, or API responses.
- Snapshot-based repo misconfiguration findings now persist the resolved HEAD commit SHA on new scans so GitHub links stay pinned to the scanned revision.

## Scan Modes

- `deep`: full bounded history scan plus HEAD configuration inspection. Manual
  API requests and scheduled scan policies use this mode unless a request
  explicitly asks for another mode.
- `delta`: commit-range scan for `base_revision..head_revision`, with optional
  `changed_paths` used as a git pathspec and as the HEAD file-inspection scope.
  Push and pull-request webhooks enqueue this mode only when the webhook payload
  includes enough revision metadata.
- `quick`: HEAD/configuration-focused scan mode for event types that should
  refresh repository posture without replaying commit history.

Delta scans require `head_revision`. If the stored cursor already matches the
requested head revision, the API returns a conflict and the webhook path records
the scan as skipped instead of queueing duplicate work.

## Useful Flags

- `--history-limit` (default: `500`): max commits to inspect.
- `--max-findings` (default: `200`): hard cap on findings.
- `--output table|json`.
- API-backed terminal commands also accept `--api-url`, `--api-key`,
  `--tenant-id`, `--workspace-id`, `--timeout`, and `--output table|json`.

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
- External scanner execution is intentionally not enabled as a runtime feature
  in this release. Add execution only behind explicit operator-controlled
  allowlists, resource limits, and sandboxing.
