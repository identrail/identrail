# AWS remediation dry-run executor

Issue #1537 adds a metadata-only dry-run projection for approved AWS
remediation cases. It turns each approval-queue entry into an explicit dry-run
record with the intended AWS API calls, affected resources, satisfied/failed
prerequisites, verification checks, rollback plan, idempotency key, audit
trail, and a deterministic outcome so operators can see exactly what would
happen before any controlled live apply runs.

The endpoint is read-only. It never calls IAM, STS, Secrets Manager, KMS, or
Organizations write APIs, never opens external PRs, and never reads, exposes,
logs, or persists rendered policies, secret values, customer payloads,
prompts, completions, browser pages, code-interpreter output, database rows,
or object contents. Live apply is reserved for the wave 8 executors
(#1538–#1542) and intentionally out of scope here.

## API

`GET /v1/workspaces/{workspace_id}/projects/{project_id}/aws/remediation-dry-run`

| Query param | Purpose |
|---|---|
| `connector_id` | scope to one AWS connector |
| `fixture_state` | `success` / `empty` / `degraded` / `partial_failure` / `permission_denied` for deterministic demos and tests |
| `account_id`, `region` | account and region filters |
| `approval_id` | source approval entry filter |
| `case_id` | source remediation case filter |
| `source_type` | `least_privilege`, `trust_policy_hardening`, `aws_iac_remediation`, `aws_permission_boundary_scp`, `aws_secret_key_rotation`, `aws_access_key_quarantine`, `secret_permission_equivalence`, `ai_agent_risk`, `blast_radius`, … |
| `outcome` | `would_succeed`, `would_fail`, `requires_review`, `blocked`, or `kill_switch_engaged` |
| `risk_tier` | `critical`, `high`, `medium`, or `low` |
| `severity` | `critical`, `high`, `medium`, or `low` |
| `search` | free-text search across dry-run, intended-call, prerequisite, verification, evidence, and audit fields |

Response shape: `{ "dry_run": AWSRemediationDryRunResult }` with
tenant/workspace/project metadata, summary counts, ranked entries,
relationships, caveats, failure reasons, remediation hints, evidence links,
coverage gaps, diagnostics, and generated timestamps.

## Entry shape

Each `AWSRemediationDryRunEntry` includes:

- stable `dry_run_id`, calculation version, source `approval_id`/`case_id`,
  source artifact ID, issue refs, score, confidence, severity, and risk tier
- the deterministic `outcome` (`would_succeed` / `would_fail` /
  `requires_review` / `blocked` / `kill_switch_engaged`) plus a matching
  next-action hint
- `intended_api_calls` (service + operation + target + idempotency-key/refs)
  derived from the source type — for example IAM `PutRolePolicy` for
  least-privilege diffs, IAM `UpdateAssumeRolePolicy` for trust hardening,
  Secrets Manager `RotateSecret` for secret rotation, IAM `UpdateAccessKey`
  for quarantine, and `bedrock-agent:UpdateAgent` for AI-agent risk
- `affected_resources` with change kind and before/after metadata refs
- `satisfied_prerequisites` and `failed_prerequisites` covering approval
  state, kill switch, ready-for-execution, every RBAC gate, and every
  feature flag (including the `live_aws_mutation` gate that must remain off
  at this layer)
- `verification_checks` (CloudTrail, IAM policy simulator, Access Analyzer,
  IAM last-used) tuned by source type
- rollback plan, verification plan, tradeoffs from the source approval, and
  an audit trail that copies the source approval entries plus a
  `dry_run_simulated` row with the projected outcome
- deterministic `idempotency_key` and `dry_run_ref` so later wave apply
  executors can re-use the same keys without re-deriving them
- `ready_for_apply` is true only when the outcome is `would_succeed`, the
  upstream approval is `ready_for_execution`, and no kill switch is engaged

## Failure handling

- **Ready**: upstream approval evidence is available and at least one dry-run
  entry can be composed.
- **Degraded**: partial or degraded upstream evidence is visible with explicit
  diagnostics; composed entries stay visible when safe.
- **Blocked**: permission-denied upstream evidence emits zero entries plus
  failure reasons, remediation hints, diagnostics, and coverage gaps.

Unsupported, empty, partial, degraded, and permission-denied states stay
explicit. The endpoint does not convert absence of upstream evidence into
deterministic dry-run output.

## App surface

The AWS Runtime page renders an **AWS remediation dry-run executor** panel
with dry-run title, source type, intended calls, satisfied/failed
prerequisites, outcome, and severity/outcome pill. Loading, empty, degraded,
blocked, and error states are explicit.

## Validation

1. Confirm blocker #1536 is closed.
2. Run the upstream approval queue with `fixture_state=success`.
3. Call the dry-run endpoint with `fixture_state=success` and verify at least
   one entry includes intended API calls, satisfied/failed prerequisites,
   verification checks, rollback plan, idempotency key, and `dry_run_ref`.
4. Filter by `outcome=would_succeed`, `source_type=trust_policy_hardening`,
   and `risk_tier=high`.
5. Run `fixture_state=empty`, `degraded`, `partial_failure`, and
   `permission_denied` and confirm the status, diagnostics, and failure
   reasons stay explicit.

## What is intentionally out of scope

- Live IAM/STS/Secrets Manager/KMS/Organizations write APIs (wave 8 executors
  #1538–#1542 own controlled apply).
- Persisting dry-run mutations server-side; the endpoint projects
  deterministically from the upstream approval queue and is safe to re-query.
- Rendering policy bodies, IaC bodies, secret values, or workload payloads.
- Opening, pushing, or merging operator source-control PRs.
