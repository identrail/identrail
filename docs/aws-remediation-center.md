# AWS Remediation Center unified experience

Issue #1552 adds the read-only operator center that unifies the AWS remediation
lifecycle into one scoped surface. It stitches remediation cases, the approval
queue, dry-run projections, low-risk live actions, and post-remediation
verification and rollback into case-keyed rollups that back the app route
`/app/{tenant_id}/{workspace_id}/aws/remediation/center`.

## API

`GET /v1/workspaces/{workspace_id}/projects/{project_id}/aws/remediation-center`

Supported optional filters:

- `connector_id`
- `fixture_state`: `success`, `empty`, `degraded`, `partial_failure`, or `permission_denied`
- `account_id`
- `region`
- `severity`
- `confidence`: `high`, `medium`, `low`, or a `0..1` floor value
- `identity_type`
- `action_type`
- `status`
- `stage`: `case`, `approval`, `dry_run`, `live_action`, `verification`, or `rollback`
- `case_id`
- `tab`: `overview`, `cases`, `approvals`, `dry_runs`, `live_actions`, `verification`, or `audit`
- `search`

The response is returned as `{ "remediation_center": ... }` and includes:

- tenant, workspace, project, connector, account, region, parent/current issue, version, status, confidence, policy version, and applied filters
- a summary with total and filtered case counts, per-stage/severity/status/action-type/identity-type counts, and lifecycle rollups (pending approvals, dry-runs, live actions, verification, rollbacks, ready-for-apply, kill-switch, and blocked safety-gate counts)
- tab counts for overview, cases, approvals, dry-runs, live actions, verification, and audit
- case rollups that carry the case spine id, lifecycle stage, severity, confidence, owner, approval/dry-run/execution/verification/rollback linkage, tradeoffs, safety gates, and the next action
- the underlying remediation case, approval queue, dry-run, live-action, and verification/rollback source results
- diagnostics, coverage gaps, failure reasons, remediation hints, and evidence links

Each case is keyed by its remediation `case_id`, which is the spine that joins the
approval, dry-run, live-action, and verification stages. The most safety-critical
verification state is retained per case so kill-switch, failed, and rollback
states are never masked by a later `verified` record.

## App behavior

The AWS remediation surface links operators into the center with the selected
environment. The page keeps the environment selector active and reloads when the
environment, connector, or tab changes.

The UI exposes seven tabs:

- `overview`: pre-action safety review — per-case tradeoffs, safety-gate status, apply readiness, kill-switch state, and severity/confidence
- `cases`: case lifecycle rollup with stage, safety gates, next action, and severity/confidence
- `approvals`: approval-queue entries with state, readiness, and severity
- `dry_runs`: dry-run projections with outcome, apply readiness, and severity
- `live_actions`: low-risk live actions with state and next action
- `verification`: post-remediation verification and rollback state
- `audit`: the consolidated immutable audit trail across every lifecycle stage (case, approval, dry-run, live action, and verification), tagged with the owning case and stage

Key metrics, safety-gate status, ready-for-apply, kill-switch, and rollback
counts surface above the tabs, and the page links back to the broader AWS
remediation and governance surfaces.

Filters are driven by URL query parameters (`account_id`, `region`, `severity`,
`confidence`, `identity_type`, `action_type`, `status`, `stage`, `case_id`, and
`search`). They are forwarded to the API and preserved across tab navigation, so
deep links with filters fetch and keep the expected subset. When filters narrow
the case set, the embedded approval, dry-run, live-action, verification, and
audit payloads are reconciled to the filtered cases so a tab never renders rows
from cases outside the current filter. The consolidated `audit_trail` is scoped
the same way, so its entries always match the audit tab count.

## Safety boundaries

The contract is read-only and metadata-only. It must not read, expose, log, or
persist rendered policy bodies, secret values, workload payloads, prompt text,
completions, database rows, or customer object contents.

The response evidence boundary is
`metadata_only_no_rendered_policy_bodies_no_secret_values_no_workload_payloads_tenant_workspace_project_connector_account_region_scoped`.
Downstream sources may contribute ARNs, names, ids, hashes, timestamps, action
names, safety-gate status, and safe reference identifiers, but not sensitive
values or document bodies.

## Failure states

- `empty`: the selected scope has no matching remediation evidence after sources run.
- `degraded`: evidence exists, but one or more sources returned partial or low-confidence data.
- `partial_failure`: at least one downstream source failed while retained evidence remains visible.
- `permission_denied`: the selected connector lacks required read-only metadata permissions.

These states remain visible in the center through status panels, diagnostics,
coverage gaps, and remediation hints rather than being collapsed into a
successful view.
