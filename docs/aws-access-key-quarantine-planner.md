# AWS access key disable and quarantine planner

Issue #1534 adds a metadata-only planner for stale, risky, or unused IAM
access keys. It converts dormant-access findings, IAM last-used evidence, and
runtime signals into owner-notified disable/quarantine plans with grace periods,
rollback, verification, and readiness gates.

The planner is read-only. It never calls AWS IAM write APIs, never disables an
access key, and never reads, exposes, logs, or persists secret access key
values, rendered policies, prompts, completions, browser pages,
code-interpreter output, database rows, object contents, customer payloads, or
workload payloads.

## API

`GET /v1/workspaces/{workspace_id}/projects/{project_id}/aws/access-key-quarantine`

| Query param | Purpose |
|---|---|
| `connector_id` | scope to one AWS connector |
| `fixture_state` | `success` / `empty` / `degraded` / `partial_failure` / `permission_denied` for deterministic demos and tests |
| `account_id`, `region` | account and region filters |
| `identity` | access key ID, IAM principal, node ID, or target label match |
| `quarantine_state` | `disable_candidate`, `quarantine_candidate`, `grace_period_required`, or `needs_review` |
| `owner` | owner notification target |
| `severity` | `critical`, `high`, `medium`, or `low` |
| `status` | `ready_for_quarantine`, `pending_owner`, or `review` |
| `ready_for_apply` | `true` / `false` |
| `search` | free-text search across plan, target, owner, order, rollback, verification, evidence, and readiness fields |

Response shape: `{ "plans": AWSAccessKeyQuarantineResult }` with
tenant/workspace/project metadata, summary counts, ranked plans,
relationships, caveats, failure reasons, remediation hints, evidence links,
coverage gaps, diagnostics, and generated timestamps.

## Plan shape

Each `AWSAccessKeyQuarantinePlan` includes:

- stable `plan_id`, calculation version, issue refs, score, confidence, status,
  and severity
- `quarantine_state`, target access key metadata refs, affected principal refs,
  last-used timestamp, dormant days, and grace-period days
- `owner_notice` with assigned owner, notification state, required actors, and
  instructions
- ordered `notify`, `grace_period`, `dry_run`, `apply`, and `verify` steps
- before/after intent, tradeoffs, rollback plan, verification plan, readiness
  gates, impacted graph nodes, and evidence refs
- `ready_for_apply`, which is only a planning signal for a future approved
  executor or human operator

`ready_for_apply` is true only when the owner is assigned, evidence confidence
is high enough, the dormant access state is explicit, and all readiness gates
pass. Plans with unknown evidence, low confidence, missing owner notice, or
permission-denied upstream data remain review-only or blocked.

## Failure handling

- **Ready**: upstream dormant-access evidence is available and qualifying access
  key findings can be planned.
- **Degraded**: partial or degraded upstream evidence is visible with explicit
  diagnostics; composed plans remain available when safe.
- **Blocked**: permission-denied upstream evidence emits zero plans plus failure
  reasons, remediation hints, diagnostics, and coverage gaps.

Unsupported, empty, partial, degraded, and permission-denied states remain
visible. The planner does not convert absence of evidence into proof that a key
is safe to disable.

## App surface

The AWS Runtime page renders an **AWS access key quarantine plans** panel with
plan state, owner notice, target key/principal, quarantine order, readiness,
severity/status, and verification strategy. Loading, empty, degraded, blocked,
and error states are explicit.

## Validation

1. Confirm blockers #1524 and #1529 are closed.
2. Run dormant-access evidence with `fixture_state=success`.
3. Call the planner endpoint with `fixture_state=success` and verify at least
   one access-key plan includes owner notice, grace period, rollback, and
   verification.
4. Filter by `identity`, `quarantine_state`, `owner`, `ready_for_apply`, and
   `search=quarantine_re_evaluate`.
5. Run `fixture_state=empty`, `degraded`, `partial_failure`, and
   `permission_denied` and confirm the status, diagnostics, and failure reasons
   stay explicit.
