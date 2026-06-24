# AWS IAM policy least-privilege diff generator

Issue #1530 (Wave 7.02) adds a metadata-only engine that turns upstream
least-privilege recommendations (#1522) into ranked, read-only IAM policy
least-privilege diffs. Each diff carries the projected before/after IAM
statement, removed/kept actions, resource scope, expected breakage,
rollback, and verification — so a remediation case (#1529) and a future
executor wave have the concrete payload they need to plan, approve, and
apply safely.

This issue is the **diff projection** capability of the Identrail
remediation loop. It does not mutate AWS, does not call any IAM write
API, and does not read rendered policy bodies, secret values, workload
payloads, prompts, completions, browser pages, code-interpreter output,
database rows, object contents, or customer payloads. Approve, execute,
verify, rollback, and govern transitions belong to later wave issues.

## What it produces

The engine emits `AWSIAMPolicyDiff` records, one per upstream
least-privilege recommendation that is not a `keep` decision. Every
diff carries:

- **Identifiers**: stable `diff_id`, `calculation_version`, and the
  `source_recommendation_id` it was generated from.
- **Decision / severity / status / score / confidence**: inherited
  from the upstream recommendation.
- **Identity context**: account, region, service, identity node id,
  ARN, name, plus optional resource node id and ARN.
- **`statement_changes`**: one or more `AWSIAMPolicyStatementDiff`
  entries with `change_kind` ∈ {`scope_removed`, `statement_removed`,
  `manual_review`}, removed/kept actions, resource and condition
  before/after, and a rationale.
- **Aggregated action sets**: top-level `removed_actions`,
  `kept_actions`, `observed_actions`, `granted_actions`.
- **`resource_scope_before` / `resource_scope_after`**: metadata
  refs only — empty `resource_scope_after` indicates the statement
  is removed entirely.
- **`breakage_projection`** with `level` ∈ {`low`, `medium`, `high`,
  `unknown`}, rationale, and signal counts. Review-decision diffs
  always project `unknown`.
- **`rollback_plan`** (`re_attach_policy` or `manual_review`) and
  **`verification_plan`** (`policy_simulate` or `manual_review`).
- **`ready_for_apply`**: `true` only when `decision = remove`,
  `breakage_projection.level = low`, and `confidence >= 0.75`.
- **`read_only_projection`: true** on every diff.
- **Evidence refs / source signals / impacted nodes / impacted path /
  next action** carried from the upstream recommendation.

## API

`GET /v1/workspaces/{workspace_id}/projects/{project_id}/aws/iam-policy-diffs`

| Query param | Purpose |
|---|---|
| `connector_id` | scope to one AWS connector |
| `fixture_state` | `success` / `empty` / `degraded` / `partial_failure` / `permission_denied` for deterministic demos and tests |
| `account_id`, `region` | account and region filters |
| `identity` | substring search across identity node, ARN, or name |
| `service` | exact match on the upstream AWS service token |
| `decision` | `remove` or `review` (`keep` is suppressed by the engine) |
| `severity` | `critical`, `high`, `medium`, or `low` |
| `status` | `action_required`, `review`, or `monitor` |
| `breakage_level` | `low`, `medium`, `high`, or `unknown` |
| `ready_for_apply` | `true` / `false` |
| `search` | free-text search across diff, statement, action, resource, evidence, and plan fields |

Response shape: `{ "diffs": AWSIAMPolicyDiffResult }` with summary,
ranked diffs, graph relationships, caveats, failure reasons,
remediation hints, evidence links, coverage gaps, diagnostics, and the
standard tenant/workspace/project metadata.

## Evidence boundary

The engine never reads, stores, logs, or displays rendered IAM policy
bodies, secret values, prompts, completions, tool inputs/outputs,
browser pages, code-interpreter output, database rows, object
contents, customer payloads, or workload payloads. It composes only
the upstream least-privilege recommendation refs and counts.

Statement-level `condition_before` and `condition_after` carry
identifiers (e.g. condition keys / labels) only — never rendered JSON
condition bodies.

## AWS permissions

This capability adds no live mutation and requires no additional AWS
permissions beyond what the least-privilege engine (#1522) already
needs. It reuses that engine's read-only metadata access.

Do not grant IAM write permissions for this issue.

## Ready-for-apply derivation

A diff is marked `ready_for_apply: true` only when *all* of the
following hold:

1. `decision == "remove"`, and
2. `breakage_projection.level == "low"`, and
3. `confidence >= 0.75`.

Any other combination (`review` decisions, medium/high/unknown
breakage, or sub-0.75 confidence) keeps `ready_for_apply: false` so
downstream consumers cannot queue uncertain diffs for execution.

## Failure handling

- **Ready**: least-privilege was available and emitted no blocking
  diagnostics.
- **Degraded**: least-privilege returned partial / degraded / empty
  evidence, or produced retryable diagnostics. Diffs already
  composed remain visible.
- **Blocked**: least-privilege is permission denied. The response has
  zero diffs plus diagnostics and failure reasons.

Unknown, unsupported, partial, degraded, and permission-denied
evidence stays explicit and is not treated as proof that a diff is
safe to apply.

## App surface

The AWS Runtime app surface renders the **AWS IAM policy
least-privilege diff** panel with each diff's identity, decision,
statement change kind, removed/kept action counts, breakage level,
ready-for-apply flag, verification strategy, and evidence refs.
Loading, empty, error, degraded, and permission-denied states are
explicit.

## Live validation

1. Confirm blocker #1529 is closed.
2. Run least-privilege with `fixture_state=success`.
3. Run the diff endpoint with `fixture_state=success` and confirm
   `remove` and `review` diffs appear.
4. Filter by `decision=remove`, `breakage_level=low`,
   `ready_for_apply=true`, and `search` to verify deterministic
   drill-down.
5. Run `fixture_state=permission_denied`, `empty`, `degraded`, and
   `partial_failure` and confirm blocked/degraded states are
   explicit.
6. Confirm the AWS Runtime app panel renders success, empty,
   degraded, permission-denied, and partial-failure states without
   exposing rendered policy bodies or secret values.

## Safety gates

- Read-only. No IAM write API is called by this issue.
- All diffs include `read_only_projection: true`.
- All diffs include rollback and verification plans, so a future
  executor has the safety scaffolding the moment it can land
  approved changes.
- `ready_for_apply` is derived deterministically — it is a hint to
  consumers, not an instruction to execute.
