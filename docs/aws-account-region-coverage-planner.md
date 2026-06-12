# AWS Account and Region Coverage Planner

Issues #1499, #1501, #1502, and #1503 add a deterministic, metadata-only planner and public coverage API that expands
an AWS connector's configured accounts, regions, service partitions, and
persisted scan cursors into explicit scan targets.

It also models per-account, per-region, and per-service availability outcomes
(`blocked`, `unsupported`, `disabled`, and `permission_denied`) so operators can
see exactly where and why scanning cannot proceed.

## What It Plans

The planner creates one target per account, region, and service combination.
Global services such as IAM are planned once per account in a home region so the
plan reflects where the scan runs instead of pretending IAM is regional.

Each target records:

- account, region, service, and whether the service is global
- enabled or disabled status
- priority and the reason for the target
- prerequisites such as member-account onboarding or opt-in region enablement
- lifecycle state: `planned`, `pending`, `in_progress`, `covered`, `partial`,
  `failed`, `permission_denied`, `unsupported`, `blocked`, or `disabled`
- cursor, failure reason, attempts, resumability, and evidence reference
- collector name when a service checkpoint is owned by a specific collector
- the next operator action

The planner is deterministic: the same connector configuration and checkpoints
produce the same ordered plan.

## Scan Cursor Shape

Live planning reads `aws_account_region_coverages.scan_cursor` as a metadata
envelope scoped by tenant, workspace, project, connector, account, and region.
Service cursors are keyed below `services`, `service_cursors`, `checkpoints`, or
`cursors`:

```json
{
  "services": {
    "lambda": {
      "collector": "lambda_execution_roles",
      "state": "in_progress",
      "cursor": "lambda-page-2",
      "attempts": 1,
      "observed_at": "2026-06-12T12:00:00Z"
    }
  }
}
```

Supported states are `planned`, `pending`, `in_progress`, `covered`, `partial`,
`failed`, `permission_denied`, `unsupported`, `blocked`, and `disabled`.
Malformed cursor entries are ignored and surfaced as diagnostics instead of
failing the whole plan.

Resumable cursors in `pending`, `in_progress`, `partial`, or `failed` expire
after 24 hours. Expired cursors are not replayed; operators see a degraded
diagnostic and can refresh the target with a new read-only scan.

## API

```http
GET /v1/workspaces/{workspace_id}/projects/{project_id}/aws/coverage-plan
```

Optional query parameters:

- `connector_id`: scope the response to one AWS connector.
- `fixture_state`: one of `success`, `empty`, `degraded`, `partial_failure`, or
  `permission_denied` for UI and contract validation.
- `account`: filter to one 12-digit AWS account.
- `region`: filter to one region.
- `service`: filter to one service partition.
- `state`: filter to one coverage lifecycle state.

The response includes tenant, workspace, project, issue metadata, summary
counts, filtered targets, normalized `partial_failure_reports`, diagnostics,
coverage gaps, remediation hints, and evidence links.

## Public Account/Region Coverage API

```http
GET /v1/workspaces/{workspace_id}/projects/{project_id}/aws/account-region-coverage
```

This endpoint returns row-oriented coverage records for dashboards, recovery,
and rerun workflows. It reuses the planner contract but normalizes each target
into a public `coverage_status`:

- `covered`
- `missing`
- `degraded`
- `unreachable`
- `suspended`
- `disabled`
- `stale`
- `permission_denied`

Optional query parameters are `connector_id`, `fixture_state`, `account`,
`region`, `service`, `collector`, `state`, and `status`.

Each record includes account, region, service, collector, lifecycle state,
public coverage status, cursor/checkpoint, attempts, failure reason,
retryability, stale flag, evidence reference, timestamps, and next action. The
summary includes total and filtered record counts plus status, state, and
collector breakdowns.

Use the planner endpoint when you need target expansion and prerequisites. Use
the public coverage API when an operator or dashboard needs filterable coverage
state without reading logs or internal tables.

## Partial Failure Reports

`partial_failure_reports` is a normalized dashboard and rerun contract. Each
entry is scoped to one account, region, and service and includes:

- target key, account, region, service, and collector
- lifecycle state and reason code
- failure reason, retryability, attempts, and cursor/checkpoint when available
- evidence reference, timestamp, and next operator action

Reports are emitted for `partial`, `failed`, and `permission_denied` target
states. Blocked and unsupported targets stay visible as target states and
diagnostics, but are not included in the retry-focused partial failure queue.
Successful targets remain in the response, so operators can see what was
preserved while recovering only the degraded target.

When using fixture input or external planner input, `region_availability` and
`service_availability` constraints are applied after checkpoint replay, so explicit
blocked/unsupported/permission-denied/disabled states are preserved as
first-class outcomes.

## Safety Boundary

The planner performs no AWS mutations and reads no customer payloads. It does
not read or persist secret values, prompts, completions, object contents,
database rows, environment variable values, or code-interpreter output.

The planner does not call live AWS APIs during planning. Default API calls use
persisted account/region rows and their scan cursors; explicit `fixture_state`
queries use deterministic fixtures for validation.

## Failure States

Denied, unsupported, partial, failed, blocked, and disabled targets are explicit
states. They are never counted as successful coverage.

Use `partial_failure_reports`, diagnostics, and target-level `next_action`
values to decide whether to deploy missing read-only roles, enable an opt-in
region, remove unsupported targets, or rerun resumable targets from their
checkpoint.

## Validation

Run fixture validation before merging:

```sh
go test ./internal/providers/awscontract ./internal/api
```

For live validation, use only an authorized test account and record account,
region, service, state, and evidence references. Do not capture customer
payloads or secret values.
