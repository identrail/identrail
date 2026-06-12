# AWS Account and Region Coverage Planner

Issue #1497 adds a deterministic, metadata-only planner that expands an AWS
connector's configured accounts, regions, and service partitions into explicit
scan targets.

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
- the next operator action

The planner is deterministic: the same connector configuration and checkpoints
produce the same ordered plan.

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
counts, filtered targets, diagnostics, coverage gaps, remediation hints, and
evidence links.

## Safety Boundary

The planner performs no AWS mutations and reads no customer payloads. It does
not read or persist secret values, prompts, completions, object contents,
database rows, environment variable values, or code-interpreter output.

AWS Organizations account discovery and live region availability discovery are
outside this issue. This PR plans from configured connector scope and explicit
checkpoints only.

## Failure States

Denied, unsupported, partial, failed, blocked, and disabled targets are explicit
states. They are never counted as successful coverage.

Use diagnostics and target-level `next_action` values to decide whether to
deploy missing read-only roles, enable an opt-in region, remove unsupported
targets, or rerun resumable targets from their checkpoint.

## Validation

Run fixture validation before merging:

```sh
go test ./internal/providers/awscontract ./internal/api
```

For live validation, use only an authorized test account and record account,
region, service, state, and evidence references. Do not capture customer
payloads or secret values.
