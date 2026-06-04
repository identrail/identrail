# AWS Platform Baseline Gate

The AWS platform baseline gate is the required readiness check before
project-scoped AWS scans, remediation jobs, or governance actions start. It is
scoped by tenant, workspace, project, and optional connector ID, and persists
its latest result in `aws_platform_baseline_results`.

## Checks

The verifier runs these checks and records each check name, status, timestamp,
confidence, failure reason, remediation hint, and evidence link:

- `aws_connector_health`: required. Confirms the selected AWS connector is
  active, healthy, and not failing permission diagnostics.
- `graph_contract_version`: required. Confirms the graph relationship contract
  registry is present and stamps the supported contract version.
- `worker_queue_availability`: required. Confirms the AWS scan queue can accept
  work under `IDENTRAIL_SCAN_QUEUE_MAX_PENDING`; the default single-slot gate
  treats queued and running scans for the same source as capacity blockers.
- `fixture_availability`: required only when `IDENTRAIL_AWS_SOURCE=fixture`.
  Confirms at least one configured fixture JSON file is readable.
- `app_validation_prerequisites`: required. Confirms the project scope and AWS
  app routes are valid and the project is not archived.

Fixture-only execution does not require live AWS credentials. Set
`IDENTRAIL_AWS_SOURCE=fixture` and point `IDENTRAIL_AWS_FIXTURES` at readable
JSON fixture files or directories.

## API

```text
GET  /v1/workspaces/{workspace_id}/projects/{project_id}/aws/baseline
POST /v1/workspaces/{workspace_id}/projects/{project_id}/aws/baseline
```

`POST` accepts optional `connector_id` and `git_sha`, verifies the baseline,
persists the result, and returns `{ "baseline": ... }`. When `git_sha` is not
provided, the service uses `IDENTRAIL_BASELINE_GIT_SHA` and then
`IDENTRAIL_GIT_SHA`.

Project-scoped AWS scan enqueue and replay call the verifier before writing to
the queue. If any required check fails, the API returns:

```json
{
  "error_code": "aws_platform_baseline_not_ready",
  "failure_reasons": ["aws connector is missing"],
  "baseline": {
    "status": "blocked",
    "required_checks_passed": false
  }
}
```

This response uses HTTP `412 Precondition Failed` so clients can distinguish a
readiness failure from queue contention, validation errors, or server failures.

## UI

The AWS Control Center shows the gate as a KPI and detailed baseline panel with
per-check diagnostics. Connect AWS also shows the gate beside permission
diagnostics and can run the baseline after connector validation.
