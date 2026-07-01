# AWS approved permission boundary executor

Issue #1540 adds a metadata-only projection of approved AWS permission
boundary execution records. Each entry joins the dry-run executor (#1537)
with the permission boundary planner (#1532) for cases whose `source_type` is
`aws_permission_boundary_scp`, whose planner kind is `permission_boundary`,
and whose dry-run diff kind is `permission_boundary_diff`.

The endpoint is read-only. It never calls IAM or Organizations write APIs and
never reads, exposes, logs, or persists rendered policy documents, secret
values, customer payloads, prompts, completions, browser pages,
code-interpreter output, database rows, or object contents.

## API

`GET /v1/workspaces/{workspace_id}/projects/{project_id}/aws/permission-boundary-executor`

Response shape: `{ "permission_boundary_executor": AWSPermissionBoundaryExecutorResult }`.

Supported filters: `connector_id`, `fixture_state`, `account_id`, `region`,
`dry_run_id`, `case_id`, `plan_id`, `operation`, `state`, `severity`, and
`search`.

## Entry Shape

Each entry includes stable source IDs, target identity/account/OU scope,
the projected IAM `PutRolePermissionsBoundary` or `PutUserPermissionsBoundary`
call, idempotency key, statement snippets, breakage projection,
preconditions, policy-simulator refs, rollback and verification plans,
audit trail, relationships, and `ready_for_live_apply`.

`ready_for_live_apply` is true only when every safety precondition passes,
the upstream dry-run is `would_succeed` and `ready_for_apply`, the planner is
ready, breakage is `low`, scope is captured, and no kill switch is engaged.

## States

- `projected`: ready for the wave-8 apply runtime when its feature flag opens.
- `precondition_failed`: upstream evidence exists but is not ready, such as
  non-low breakage or a planner/dry-run readiness gate.
- `blocked`: a safety gate failed, the tenant kill switch is engaged, the
  operation is unsupported, or the dry-run is blocked.

SCP plans are intentionally excluded; org-level SCP execution is projected by
the dedicated SCP guardrail executor.

## App Surface

The AWS Runtime page renders an **AWS approved permission boundary executor**
panel with execution title, IAM operation, target counts, precondition counts,
simulation outcome, readiness, and severity/state pill.
