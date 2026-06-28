# AWS approved trust-policy hardening executor

Issue #1539 adds a metadata-only projection of approved AWS trust-policy
hardening execution records. Each entry joins the dry-run executor (#1537)
with the trust-policy hardening planner (#1531) for cases whose
`source_type` is `trust_policy_hardening` and whose dry-run diff kind targets
an IAM trust-policy mutation (`iam_trust_diff` or `iac_trust_policy_pr`).

The endpoint is read-only. It never calls IAM, STS, or Organizations write
APIs, never opens external PRs, and never reads, exposes, logs, or persists
rendered policy documents, secret values, customer payloads, prompts,
completions, browser pages, code-interpreter output, database rows, or
object contents. Controlled live `iam:UpdateAssumeRolePolicy` belongs to the
wave-8 apply runtime and its own feature flags.

## API

`GET /v1/workspaces/{workspace_id}/projects/{project_id}/aws/trust-policy-hardening-executor`

| Query param | Purpose |
|---|---|
| `connector_id` | scope to one AWS connector |
| `fixture_state` | `success` / `empty` / `degraded` / `partial_failure` / `permission_denied` |
| `account_id`, `region` | account and region filters |
| `dry_run_id`, `case_id`, `plan_id` | source filters |
| `hardening_direction` | trust-policy hardening direction filter |
| `state` | `projected`, `precondition_failed`, or `blocked` |
| `severity` | `critical`, `high`, `medium`, or `low` |
| `search` | free-text search across execution, precondition, simulation, verification, audit, and evidence fields |

Response shape: `{ "trust_policy_hardening_executor": AWSTrustPolicyHardeningExecutorResult }`
with tenant/workspace/project metadata, summary counts, ranked entries,
relationships, caveats, failure reasons, remediation hints, evidence links,
coverage gaps, diagnostics, and generated timestamps.

## Entry shape

Each `AWSTrustPolicyHardeningExecutorEntry` includes:

- stable `execution_id`, calculation version, source `dry_run_id` /
  `approval_id` / `case_id` / `plan_id`, score, confidence, severity, and
  state
- structured trust-policy hardening fields from the planner: `hardening_direction`,
  `principal_change`, `condition_recommendations`, `statement_snippets`,
  `affected_callers`, `breakage_projection`, and `public_principal`
- the projected `intended_api_call` (`iam:UpdateAssumeRolePolicy`) plus the
  deterministic idempotency key carried from the dry-run
- `preconditions` (dry-run-would-succeed, ready-for-apply, kill-switch-off,
  idempotency-key-present, plan-ready-for-apply,
  no-public-principal-after-change, breakage-level-low)
- `policy_simulation` metadata (`simulation_ref`, outcome, before/after
  refs, allowed/denied counts, signals such as `runtime_observed` or
  `access_analyzer_backed`)
- `verifications` (CloudTrail observation, Access Analyzer re-check, and —
  for condition-hardening directions — policy simulator confirmation) plus any
  verification checks carried from the dry-run
- rollback plan and verification plan copied from the planner
- audit trail copying upstream entries plus a
  `trust_policy_hardening_execution_projected` row
- `ready_for_live_apply` is true only when state is `projected`, the
  upstream dry-run is itself `ready_for_apply`, and no kill switch is
  engaged

## State semantics

- **projected**: every precondition passed, the dry-run is `would_succeed`
  and `ready_for_apply`, the planner says ready, the trust policy retains
  no public principal, and breakage is `low`. Eligible for the wave-8 apply
  runtime when its feature flag opens.
- **precondition_failed**: the planner is not yet ready, the breakage
  projection is above `low`, or the dry-run is not yet `would_succeed` —
  not a safety violation, just not ready.
- **blocked**: a safety precondition failed (kill switch engaged, public
  principal would remain, idempotency key missing, upstream prereq
  blocked) or the dry-run is itself blocked.

## Failure handling

- **Ready**: upstream dry-run and planner evidence are available and at
  least one matching entry is composed.
- **Degraded**: partial or degraded upstream evidence; composed entries
  stay visible when safe.
- **Blocked**: permission-denied upstream evidence emits zero entries plus
  failure reasons, remediation hints, diagnostics, and coverage gaps.

## App surface

The AWS Runtime page renders an **AWS approved trust-policy hardening
executor** panel with execution title, hardening direction, precondition
pass/blocked counts, simulation outcome plus allow/condition counts,
readiness label, and severity/state pill. Loading, empty, degraded,
blocked, and error states are explicit.

## Validation

1. Confirm blockers #1531 and #1537 are closed.
2. Run upstream dry-run + trust-hardening planner with `fixture_state=success`.
3. Call the executor endpoint with `fixture_state=success` and verify at
   least one entry includes intended API call, preconditions, policy
   simulation, verifications, structured planner data, idempotency key,
   and audit trail.
4. Filter by `hardening_direction=add_org_or_source_condition`, `state=projected`, and
   `plan_id=<plan-id>`.
5. Run `fixture_state=empty`, `degraded`, `partial_failure`, and
   `permission_denied` and confirm the status, diagnostics, and failure
   reasons stay explicit.

## What is intentionally out of scope

- Live `iam:UpdateAssumeRolePolicy` calls (wave-8 apply runtime owns
  controlled execution).
- Persisting execution-state mutations server-side; the endpoint projects
  deterministically from the upstream dry-run + planner and is safe to
  re-query.
- Rendering policy bodies, IaC bodies, secret values, or workload
  payloads.
- Trust-policy mutations whose dry-run diff kind is not
  `iam_trust_diff`/`iac_trust_policy_pr` — those are out of scope for this
  executor.
