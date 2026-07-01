# AWS approved SCP guardrail executor

Issue #1541 adds a metadata-only projection of approved AWS Organizations SCP
guardrail execution records. Each entry joins the dry-run executor (#1537) with
the permission boundary/SCP planner (#1532) for cases whose `source_type` is
`aws_permission_boundary_scp`, whose planner kind is `scp`, and whose dry-run
diff kind is `scp_diff`.

The endpoint is read-only. It never calls IAM or Organizations write APIs and
never reads, exposes, logs, or persists rendered policy documents, secret
values, customer payloads, prompts, completions, browser pages,
code-interpreter output, database rows, or object contents.

## API

`GET /v1/workspaces/{workspace_id}/projects/{project_id}/aws/scp-guardrail-executor`

Response shape: `{ "scp_guardrail_executor": AWSScpGuardrailExecutorResult }`.

Supported filters: `connector_id`, `fixture_state`, `account_id`, `region`,
`dry_run_id`, `case_id`, `plan_id`, `operation`, `target_scope`, `state`,
`severity`, and `search`. `target_scope` accepts `account`, `ou`, or `root`.

## Entry Shape

Each entry includes stable source IDs, one target account/OU/root scope, projected AWS
Organizations `AttachPolicy` or `CreatePolicy` intent, idempotency key,
statement snippets, breakage projection, preconditions, SCP simulation refs,
rollback and verification plans, audit trail, relationships, and
`ready_for_live_apply`.

`ready_for_live_apply` is true only when every safety precondition passes, the
upstream dry-run is `would_succeed` and `ready_for_apply`, the planner is ready,
breakage is `low`, account or OU target scope is captured, and no kill switch is
engaged.

## States

- `projected`: ready for the wave-8 apply runtime when its feature flag opens.
- `precondition_failed`: upstream evidence exists but is not ready, such as
  non-low breakage or a planner/dry-run readiness gate.
- `blocked`: a safety gate failed, the tenant kill switch is engaged, the
  operation is unsupported, or the dry-run is blocked.

Permission boundary plans are intentionally excluded; identity-level IAM
permission-boundary execution is projected by the permission boundary executor.

## App Surface

The AWS Runtime page renders an **AWS approved SCP guardrail executor** panel
with execution title, Organizations operation, account/OU target counts,
precondition counts, simulation outcome, readiness, and severity/state pill.
