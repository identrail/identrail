# AWS Platform Observability

Issue #1556 adds a metadata-only platform observability view for AWS machine-identity operations. It composes existing Identrail source contracts so operators can see scan throughput, queue lag, throttling, collector failures, runtime lag, remediation state, verification outcomes, enforcement health, and governance exceptions without reading logs or database rows.

## API

`GET /v1/workspaces/{workspace_id}/projects/{project_id}/aws/platform-observability`

Response shape: `{ "platform_observability": AWSPlatformObservabilityResult }`.

Supported filters:

- `connector_id`
- `fixture_state`: `success`, `empty`, `degraded`, `partial_failure`, `permission_denied`
- `account_id`
- `region`
- `service`
- `component`: `collector`, `queue`, `runtime`, `remediation`, `verification`, `enforcement`, `governance`
- `status`: `ready`, `degraded`, `blocked`
- `search`

The payload includes:

- `summary`: dashboard counters for metrics, traces, alerts, scan throughput, queue lag, runtime lag, collector failures, throttling, remediation pending work, verification failures, and governance exceptions.
- `metrics`: bounded platform health metrics with status, severity, confidence, account/region/service context, trace IDs, evidence refs, and next actions.
- `traces`: operator-debuggable trace rows for fan-out targets, runtime evidence, and verification entries.
- `alerts`: degraded or blocked metric alerts.
- `coverage_gaps` and `diagnostics`: explicit source limits and retry guidance.

## App Surface

The AWS app adds `/app/:tenantID/:workspaceID/aws/observability`. The page includes summary cards, metric rows, trace rows, filters, loading state, empty state, degraded state, and permission-denied state using the existing AWS environment selector and scoped auth headers.

## Evidence Boundary

The observability view is read-only. It links to existing evidence refs and docs, and it does not collect or expose secret values, prompts, completions, browser output, code-interpreter output, database rows, object contents, policy bodies, or customer payloads.

## Troubleshooting

- `blocked` usually means the selected connector cannot read a required metadata source or an upstream source returned permission denied.
- `degraded` means at least one source is partial, stale, throttled, failed, or verification/enforcement evidence needs operator attention.
- Queue and runtime lag are derived from bounded source contracts. Use trace rows for account, region, service, retry, and evidence-ref drill-down.
- Fixture states keep local validation deterministic; live AWS validation should use only authorized test accounts and should record account/region/service coverage without sensitive payloads.
