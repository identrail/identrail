# AWS low-risk live remediation

Issue #1538 adds a metadata-only projection of allowlisted low-risk AWS
remediations derived from the upstream dry-run executor (#1537). Each entry
pairs a dry-run record with one code-managed allowlist rule (approved
detach/disable), captures the idempotency key, intended mutation, preflight
checks, verification records, rollback plan, and audit trail so the
wave-8.04+ live-apply executors can replay the change idempotently.

The endpoint is read-only. It never calls IAM, STS, Secrets Manager, KMS, or
Organizations write APIs, never opens external PRs, and never reads,
exposes, logs, or persists rendered policies, secret values, customer
payloads, prompts, completions, browser pages, code-interpreter output,
database rows, or object contents.

## Allowlist

The allowlist is defined in code (`awsLowRiskRemediationAllowlist`) and any
change is a code review under the wave-8 safety controls. Every rule
declares `MaxBlastRadius`; the projection rejects any upstream dry-run whose
`risk_tier` or `severity` exceeds that ceiling, so high/critical entries
never appear in the low-risk projection even if their action and source
match.

| Rule | Category | Action | Match sources | Max blast radius | Rationale |
|---|---|---|---|---|---|
| `iam_update_access_key_quarantine` | `approved_disable` | `iam:UpdateAccessKey` | aws_access_key_quarantine | low | Mark a stale access key Inactive once the quarantine planner approved disable. |
| `iam_detach_role_policy_orphaned` | `approved_detach` | `iam:DetachRolePolicy` | least_privilege, blast_radius | low | Detach an orphaned role-managed policy with no observed runtime use. |

Tagging and stale-metadata-cleanup categories are reserved in the contract
(`action_category` enum) for future rules, but no rule is admitted until the
dry-run executor emits the corresponding AWS action — advertising a rule
that the dry-run can't produce would mislead operators and the UI.

## API

`GET /v1/workspaces/{workspace_id}/projects/{project_id}/aws/low-risk-live-remediation`

| Query param | Purpose |
|---|---|
| `connector_id` | scope to one AWS connector |
| `fixture_state` | `success` / `empty` / `degraded` / `partial_failure` / `permission_denied` |
| `account_id`, `region` | account and region filters |
| `dry_run_id`, `case_id` | source filters |
| `action` | allowlist action filter (e.g. `iam:UpdateAccessKey`) |
| `action_category` | `tagging`, `stale_metadata_cleanup`, `approved_disable`, `approved_detach` |
| `state` | `projected`, `skipped`, or `blocked` |
| `severity` | `critical`, `high`, `medium`, or `low` |
| `search` | free-text search across execution, allowlist, mutation, preflight, verification, audit, and evidence fields |

Response shape: `{ "low_risk_live_remediation": AWSLowRiskRemediationResult }`
with tenant/workspace/project metadata, the allowlist, summary counts, ranked
entries, relationships, caveats, failure reasons, remediation hints, evidence
links, coverage gaps, diagnostics, and generated timestamps.

## Entry shape

Each `AWSLowRiskRemediationEntry` includes:

- stable `execution_id`, calculation version, source `dry_run_id`/
  `approval_id`/`case_id`, issue refs, score, confidence, severity, and state
- the matched `allowlist_rule` (name, category, action, match-sources,
  max blast radius, rationale)
- a deterministic `mutation` record (service, operation, target resource,
  before/after refs, parameter refs)
- `preflights` (allowlist-admitted, dry-run-would-succeed, ready-for-apply,
  kill-switch-off, idempotency-key-present, upstream-prereq) plus per-source
  `verifications` carried over from the dry-run
- rollback plan, verification plan, tradeoffs from the source dry-run, and an
  audit trail that copies the upstream entries plus a
  `low_risk_execution_projected` row
- `ready_for_live_apply` is true only when state is `projected`, the upstream
  dry-run is itself `ready_for_apply`, and no kill switch is engaged

## State semantics

- **projected**: allowlist matched, every safety preflight passes, upstream
  dry-run is `would_succeed` and `ready_for_apply`. Eligible for wave-8.04+
  live apply when the apply executor's feature flag opens.
- **skipped**: allowlist matched, but the upstream dry-run is not yet
  `would_succeed` or `ready_for_apply` (no safety violation — just not ready
  yet).
- **blocked**: kill switch engaged or a safety preflight (allowlist,
  idempotency, kill switch, upstream prerequisites) failed.

## Failure handling

- **Ready**: upstream dry-run evidence is available and at least one entry
  matches the allowlist.
- **Degraded**: partial or degraded upstream evidence; composed entries stay
  visible when safe.
- **Blocked**: permission-denied upstream evidence emits zero entries plus
  failure reasons, remediation hints, diagnostics, and coverage gaps.

## App surface

The AWS Runtime page renders an **AWS low-risk live remediation** panel with
execution title, allowlist rule, action + category, preflight pass/blocked
count, readiness, and severity/state pill. Loading, empty, degraded, blocked,
and error states are explicit.

## Validation

1. Confirm blocker #1537 is closed.
2. Run upstream dry-run with `fixture_state=success`.
3. Call the low-risk endpoint with `fixture_state=success` and verify at
   least one entry includes mutation, preflights, verifications, allowlist
   rule, idempotency key, and audit trail.
4. Filter by `state=projected`, `action_category=approved_disable`,
   `action=iam:UpdateAccessKey`.
5. Run `fixture_state=empty`, `degraded`, `partial_failure`, and
   `permission_denied` and confirm the status, diagnostics, and failure
   reasons stay explicit.

## What is intentionally out of scope

- Live IAM/STS/Secrets Manager/KMS/Organizations write APIs (wave-8.04+
  executors own controlled apply).
- Persisting execution-state mutations server-side; the endpoint projects
  deterministically from the upstream dry-run and is safe to re-query.
- Allowlist extensions outside the four rules above; expanding the allowlist
  is a code change reviewed under wave-8 safety controls.
- Rendering policy bodies, IaC bodies, secret values, or workload payloads.
