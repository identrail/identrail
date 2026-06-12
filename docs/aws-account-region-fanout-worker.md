# AWS Account and Region Fan-Out Worker

Issues #1500 and #1501 add a deterministic, metadata-only execution view for
bounded AWS account/region/service fan-out. It builds on the coverage planner
and makes worker state, persisted scan cursors, and downstream recovery state
explicit for operators.

## What It Executes

The fan-out executor consumes an `awscontract.CoveragePlan` and produces one
worker target for each planned account, region, and service target. It records:

- target account, region, service, priority, coverage state, and worker state
- collector name when the checkpoint is owned by a specific service collector
- bounded concurrency slot and queue state
- attempts, maximum attempts, retryability, retry-after, and checkpoints
- failure reason, evidence reference, timestamp, and next operator action

Targets that are `disabled`, `unsupported`, or `blocked` are skipped instead of
being queued. `permission_denied`, `partial`, and `failed` remain explicit
states and never count as successful coverage.

## API

```http
GET /v1/workspaces/{workspace_id}/projects/{project_id}/aws/fanout-execution
```

Optional query parameters:

- `connector_id`: scope the response to one AWS connector.
- `fixture_state`: one of `success`, `empty`, `degraded`, `partial_failure`, or
  `permission_denied` for UI and contract validation.
- `account`: filter to one 12-digit AWS account.
- `region`: filter to one region.
- `service`: filter to one service partition.
- `state`: filter by lifecycle or worker state.
- `max_concurrency`: deterministic worker concurrency limit from 1 to 64.

The response includes issue metadata, summary counts, filtered targets,
diagnostics, coverage gaps, remediation hints, and evidence links.

## Failure And Retry Behavior

One account/region/service failure does not fail the whole execution view.
Throttled, partial, pending, and in-progress targets preserve their checkpoint
and retry metadata so a future worker run can resume from the last safe cursor.
Permission-denied targets are non-retryable until the read-only collector role is
repaired.

Default API calls replay persisted `scan_cursor` service checkpoints from
account/region coverage rows. Explicit `fixture_state` calls keep using
deterministic fixture outcomes for CI and app validation. Resumable cursors older
than 24 hours are treated as stale and are not reused for continuation.

## Safety Boundary

This issue does not mutate AWS state and does not collect customer payloads,
secret values, prompts, completions, browser output, database rows, object
contents, or code-interpreter output. The deterministic fixture path is safe for
CI and UI validation.

## Validation

Run:

```sh
go test ./internal/providers/awscontract ./internal/api
cd web && npm run build
```

For live validation, use only an authorized test account and record
account/region/service coverage, worker state, retry status, and evidence
references without exposing sensitive payloads.
