# AWS remediation case model

Issue #1529 (Wave 7.01) adds a metadata-only engine that turns AWS AI agent
risk, least-privilege, secret-permission equivalence, and blast-radius findings
into ranked, explainable remediation cases. Cases pair every finding with a
read-only diff intent, tradeoffs, rollback plan, verification plan, owner and
approval state, and a deterministic audit trail.

This issue is the **planning** capability of the Identrail remediation loop.
It does not mutate AWS state, does not call any AWS write API, and does not
collect prompts, completions, browser pages, code-interpreter output, database
rows, object contents, secret values, or rendered policy bodies. Approve,
execute, verify, rollback, and govern transitions belong to later wave
issues.

## What it produces

The engine emits `AWSRemediationCase` records sourced from four upstream
intelligence engines:

- `ai_agent_risk` (#1528) - AI agent risk findings
- `least_privilege` (#1522) - IAM scope recommendations
- `secret_permission_equivalence` (#1527) - secret/KMS equivalence findings
- `blast_radius` (#1521) - cross-account / sensitive reachability findings

Every case carries:

- **Identifiers**: stable `case_id`, `calculation_version`, originating
  `source_type`, and `source_finding_id` for back-reference.
- **Lifecycle**: one of `proposed`, `in_review`, `approved`, `executed`,
  `verified`, `closed`, or `rolled_back`. Cases produced by this issue never
  enter `executed`, `verified`, `closed`, or `rolled_back` - those require a
  future remediation-executor wave to land.
- **Severity / status / score / confidence**: inherited from the upstream
  finding so dashboards stay consistent.
- **Identity context**: account, region, identity node id, ARN, name, type,
  provider, owner metadata, and impacted resource node ids.
- **Approval state**: `not_required`, `pending_owner`, `pending_owner_review`,
  `pending_approver`, `approved`, or `rejected`. Derivation is deterministic:
  critical / high severity or risky diff kinds (secret rotation, IAM trust
  edit, KMS grant edit) require approval; if the upstream finding lacks owner
  metadata the case is held in `pending_owner` until ownership is assigned.
- **Diff intent**: one of `iam_policy_diff`, `iam_trust_diff`,
  `role_scope_diff`, `secret_rotation`, `kms_grant_diff`,
  `ai_agent_scope_change`, `owner_assignment`, or `manual_review`. The intent
  carries `before_ref` and `after_ref` metadata pointers but never inlines a
  rendered policy body, secret value, or workload payload.
- **Tradeoffs**: one or more operator-visible entries across `breakage_risk`,
  `observability_impact`, `downstream_blast_radius`, and `rotation_risk` with
  direction (`improves`, `worsens`, `neutral`) and severity.
- **Rollback plan**: strategy plus the steps an operator would follow to
  revert if a future executor lands the diff.
- **Verification plan**: strategy plus success/failure signals that a future
  executor or operator would check after applying the diff.
- **Evidence / source signals**: refs only, never payloads.
- **Audit trail**: deterministic system-emitted `proposed` event with the
  case's first evidence ref. Future wave issues append `reviewed`, `approved`,
  `executed`, `verified`, `closed`, and `rolled_back` rows.

## API

`GET /v1/workspaces/{workspace_id}/projects/{project_id}/aws/remediation-cases`

| Query param | Purpose |
|---|---|
| `connector_id` | scope to one AWS connector |
| `fixture_state` | `success` / `empty` / `degraded` / `partial_failure` / `permission_denied` for deterministic demos and tests |
| `account_id`, `region` | account and region filters |
| `identity` | substring search across identity node, ARN, name, type, or owner |
| `source_type` | `ai_agent_risk`, `least_privilege`, `secret_permission_equivalence`, or `blast_radius` |
| `lifecycle` | one of the lifecycle states above |
| `severity` | `critical`, `high`, `medium`, or `low` |
| `status` | `action_required`, `review`, or `monitor` |
| `approval_state` | one of the approval states above |
| `owner_assigned` | `true`/`false` to restrict to owner-assigned or ownerless cases |
| `search` | free-text search across case, diff, tradeoff, rollback, verification, evidence, and audit-trail fields |

Response shape: `{ "cases": AWSRemediationCaseResult }` with summary, ranked
cases, graph relationships, caveats, failure reasons, remediation hints,
evidence links, coverage gaps, diagnostics, and the standard
tenant/workspace/project issue metadata.

## Evidence boundary

The engine never reads, stores, logs, or displays secret values, prompt text,
completions, tool inputs or outputs, browser pages, code-interpreter output,
database rows, object contents, customer payloads, or rendered policy bodies.
It only composes:

- AI agent risk findings (already metadata-only)
- least-privilege recommendations (already metadata-only)
- secret-permission equivalence findings (already metadata-only)
- blast-radius findings (already metadata-only)

`before_ref` and `after_ref` on the diff intent are metadata pointers (issue
URLs, evidence URIs, projection URIs). They never carry rendered diffs.

## AWS permissions

This capability adds no live mutation and requires no additional AWS
permissions beyond what the upstream intelligence engines already need. It
reuses their read-only metadata access.

Do not grant permissions that read prompts, invocations, memory records,
browser pages, code-interpreter output, database rows, object contents, or
secret values for this issue.

## Lifecycle and approval derivation

Lifecycle is derived deterministically:

| Upstream signal | Lifecycle |
|---|---|
| confidence < 0.55 | `proposed` |
| status = `action_required` AND owner missing | `in_review` |
| status = `action_required` AND owner assigned AND approval pending | `approved` |
| status = `review` | `in_review` |
| status = `monitor` (or anything else) | `proposed` |

Approval is required for `critical`/`high` severity or any of the destructive
diff kinds (`secret_rotation`, `iam_trust_diff`, `kms_grant_diff`). When
required but no owner is assigned, the case sits at `pending_owner`;
otherwise it advances to `pending_approver`.

## Failure handling

- **Ready**: every upstream source was available and emitted no blocking
  diagnostics.
- **Degraded**: at least one upstream source was partial, capability-limited,
  empty because live evidence is unavailable, or produced retryable
  diagnostics. The cases already composed remain visible.
- **Blocked**: at least one upstream source is permission denied. The response
  has zero deterministic cases plus diagnostics and failure reasons.

Unknown, unsupported, partial, degraded, and permission-denied evidence stays
explicit and is not treated as proof that a case is safe to execute.

## App surface

The AWS Runtime app surface renders the **AWS remediation case model** panel
with ranked cases, identity / resource context, lifecycle, owner / approval
state, diff intent, tradeoffs, rollback and verification plans, evidence refs,
and next actions. Operators can inspect the planned remediation without
reading logs or database rows.

## Live validation

1. Confirm blockers #1522 and #1528 are closed.
2. Run AI agent risk, least privilege, secret-permission equivalence, and
   blast radius with `fixture_state=success`.
3. Run the remediation case endpoint with `fixture_state=success` and confirm
   AI agent, least-privilege, secret, and blast-radius source cases are
   ranked.
4. Filter by `source_type=least_privilege`, `severity=high`, `owner_assigned`,
   and `search` to verify deterministic drill-down.
5. Run `fixture_state=permission_denied`, `empty`, `degraded`, and
   `partial_failure` and confirm blocked/degraded states are explicit.
6. Confirm the AWS Runtime app panel renders success, empty, degraded,
   permission-denied, and partial-failure states without exposing payloads or
   secret values.

## Safety gates

- Read-only. No AWS write API is called by this issue.
- All cases include `read_only_projection: true` on the diff intent.
- All cases include rollback and verification plans, so a future executor has
  the safety scaffolding the moment it can land approved changes.
- The deterministic `proposed` audit entry captures the evidence ref that
  justified case creation so the audit trail begins at the moment of
  planning, not at execution.
