# AWS permission boundary and SCP recommendation planner

Issue #1532 (Wave 7.04) adds a metadata-only engine that turns upstream
least-privilege (#1522), cross-account-trust (#1526), and AWS
Organizations topology (#1498) evidence into ranked, read-only IAM
permission boundary and Service Control Policy (SCP) recommendations.
Each plan carries target scope, OU/account impact, statement snippet
refs, prevented behavior, breakage projection, rollback plan, and
verification plan — so a remediation case (#1529) and a future executor
wave have the concrete payload they need to plan, approve, and apply
safely.

This issue is the **boundary/SCP projection** capability of the
Identrail remediation loop. It does not mutate AWS, does not call any
IAM or Organizations write API, and does not read rendered policy
bodies, secret values, workload payloads, prompts, completions,
browser pages, code-interpreter output, database rows, object
contents, or customer payloads. Approve / execute / verify / rollback
/ govern transitions belong to later wave issues.

## What it produces

The engine emits `AWSPermissionBoundarySCPPlan` records with two
kinds:

- **`permission_boundary`** — generated when at least two identities
  have a least-privilege `remove` recommendation for the same action.
  The boundary denies that action so the recommendation cannot
  silently reappear across the affected identities.
- **`scp`** — generated per cross-account-trust finding that should
  be blocked at the org/OU level (public principals, missing
  conditions, Access Analyzer external access, cross-account graph
  paths). The SCP denies the action pattern that re-introduces the
  flagged trust.

Every plan carries:

- **Identifiers**: stable `plan_id`, `calculation_version`,
  `source_finding_ids` (the upstream recommendation or finding IDs
  the plan was derived from), `kind` ∈
  `permission_boundary` / `scp`, `target_scope` ∈
  `identity` / `account` / `ou` / `org_root`.
- **Targets**: `target_account_ids`, `target_ou_paths`,
  `target_identity_node_ids`.
- **Severity / status / score / confidence**: aggregated from the
  upstream sources.
- **`prevented_behavior`**: a short string describing what the plan
  denies.
- **`statement_snippets`**: one or more
  `AWSPermissionBoundarySCPStatementSnippet` entries with
  `change_kind` ∈ `deny_repeated_action`,
  `deny_public_principal_creation`, `require_org_condition`,
  `deny_org_unsafe_pattern`, `manual_review`. Snippets carry
  `before_ref` / `after_ref` metadata pointers, deny/allow action
  lists, condition-key labels, and resource scope — never rendered
  JSON policy bodies.
- **`breakage_projection`** with `level` ∈ `low` / `medium` / `high` /
  `unknown`, rationale, `affected_identities`, `affected_accounts`,
  `affected_ous`, plus signal counts.
- **`rollback_plan`** (`detach_permission_boundary` or `detach_scp`)
  and **`verification_plan`** (`policy_simulate` or `scp_simulate`).
- **`ready_for_apply: true`** only when `breakage_level == "low"`,
  `confidence >= 0.75`, and the plan has non-empty targets for its
  kind.
- **`read_only_projection: true`** on every plan.
- Evidence refs, source signals, impacted graph nodes/path, next
  action.

## API

`GET /v1/workspaces/{workspace_id}/projects/{project_id}/aws/permission-boundary-scp`

| Query param | Purpose |
|---|---|
| `connector_id` | scope to one AWS connector |
| `fixture_state` | `success` / `empty` / `degraded` / `partial_failure` / `permission_denied` for deterministic demos and tests |
| `account_id`, `region` | account and region filters (matches the plan's anchor account or any `target_account_ids` entry) |
| `service` | exact match on the upstream AWS service token |
| `kind` | `permission_boundary` or `scp` |
| `target_scope` | `identity`, `account`, `ou`, or `org_root` |
| `severity` | `critical`, `high`, `medium`, or `low` |
| `status` | `action_required`, `review`, or `monitor` |
| `breakage_level` | `low`, `medium`, `high`, or `unknown` |
| `ready_for_apply` | `true` / `false` |
| `search` | free-text search across plan, statement snippet (denied/allowed actions, condition keys, resource scope), breakage projection, rollback, and verification fields |

Response shape: `{ "plans": AWSPermissionBoundarySCPResult }` with
summary, ranked plans, graph relationships, caveats, failure reasons,
remediation hints, evidence links, coverage gaps, diagnostics, and
the standard tenant/workspace/project metadata.

## Evidence boundary

The engine never reads, stores, logs, or displays rendered IAM/SCP
policy bodies, secret values, prompts, completions, tool
inputs/outputs, browser pages, code-interpreter output, database
rows, object contents, customer payloads, or workload payloads. It
composes only the upstream finding refs, action and condition-key
labels, and account/OU topology pointers.

`before_ref` / `after_ref` on each statement snippet carry projection
URIs (e.g. `permission-boundary://repeated-action/<action>`,
`scp://<finding>/scoped-projection`) — never rendered JSON.

## AWS permissions

This capability adds no live mutation and requires no additional AWS
permissions beyond what the least-privilege (#1522),
cross-account-trust (#1526), and AWS Organizations topology (#1498)
engines already need. It reuses their read-only metadata access.

Do not grant IAM or Organizations write permissions for this issue.

## Ready-for-apply derivation

A plan is marked `ready_for_apply: true` only when *all* of the
following hold:

1. `breakage_projection.level == "low"`, **and**
2. `confidence >= 0.75`, **and**
3. for `permission_boundary`: `breakage_projection.affected_identities >= 2`, **or**
   for `scp`: `breakage_projection.affected_accounts >= 1`.

Public SCPs always project `high` breakage and therefore stay
non-executable; unknown breakage stays non-executable; plans that
target zero identities or accounts stay non-executable.

## Failure handling

- **Ready**: all three upstream sources were available and emitted
  no blocking diagnostics.
- **Degraded**: at least one upstream source returned partial,
  degraded, or retryable diagnostics. Plans already composed remain
  visible.
- **Blocked**: at least one upstream source is permission denied. The
  response has zero plans plus diagnostics and failure reasons.

Unknown, unsupported, partial, degraded, and permission-denied
evidence stays explicit and is not treated as proof that a plan is
safe to apply.

## App surface

The AWS Runtime app surface renders the **AWS permission boundary /
SCP planner** panel with each plan's kind, target scope, denied
action / condition key summary, prevented behavior, breakage level,
ready-for-apply badge, severity/status, and verification strategy.
Loading, empty, error, degraded, and permission-denied states are
explicit.

## Live validation

1. Confirm blockers #1498 and #1529 are closed.
2. Run least-privilege, cross-account-trust, and Organizations
   topology with `fixture_state=success`.
3. Run the planner endpoint with `fixture_state=success` and confirm
   permission boundary plans (only when >= 2 identities share a
   removed action) and SCP plans (per qualifying trust finding) both
   appear.
4. Filter by `kind=permission_boundary`, `kind=scp`,
   `target_scope=org_root`, `breakage_level=low`,
   `ready_for_apply=true`, and `search` to verify deterministic
   drill-down.
5. Run `fixture_state=permission_denied`, `empty`, `degraded`, and
   `partial_failure` and confirm blocked/degraded states are
   explicit.
6. Confirm the AWS Runtime app panel renders success, empty,
   degraded, permission-denied, and partial-failure states without
   exposing rendered policy bodies or secret values.

## Safety gates

- Read-only. No IAM or Organizations write API is called by this
  issue.
- All plans include `read_only_projection: true`.
- All plans include rollback and verification plans, so a future
  executor has the safety scaffolding the moment it can land
  approved changes.
- `ready_for_apply` is derived deterministically — it is a hint to
  consumers, not an instruction to execute.
- Public-principal SCPs always stay non-executable so the engine
  cannot accidentally suggest applying an org-wide deny without
  owner sign-off.
- Permission boundaries require at least two identities to share a
  removed action, so single-identity findings never get hoisted to
  org-level boundaries.
