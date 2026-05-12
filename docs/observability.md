# Observability Baseline

Identrail exposes logs, metrics, and tracing hooks from day one.

## Logs

- Structured logs via Zap across API, worker, scheduler, and providers.
- Scan lifecycle errors are persisted as scan events and also logged.

## Metrics

Scrape `GET /metrics`.

Production deployments should protect or isolate this endpoint. Set `IDENTRAIL_METRICS_API_KEY` and configure Prometheus to send the value as either `Authorization: Bearer <key>` or `X-Metrics-Key: <key>`. If the key is empty, `/metrics` remains unauthenticated for local development or network-isolated deployments only.

Core scan metrics:
- `identrail_scan_runs_total`
- `identrail_scan_success_total`
- `identrail_scan_failure_total`
- `identrail_scan_partial_total`
- `identrail_scan_in_flight`
- `identrail_scan_duration_milliseconds`

Risk output metric:
- `identrail_analysis_findings_generated_total`

Repository scan metrics:
- `identrail_repo_scan_runs_total`
- `identrail_repo_scan_success_total`
- `identrail_repo_scan_failure_total`
- `identrail_repo_scan_truncated_total`
- `identrail_repo_scan_duration_milliseconds`

Automation reliability metrics:
- `identrail_queue_depth{queue="scan|repo_scan"}`: current API/worker queue backlog.
- `identrail_worker_jobs_total{queue="scan|repo_scan",outcome="success|failure|requeued"}`: queue worker processing results.
- `identrail_worker_requeues_total{queue="scan|repo_scan"}`: jobs put back on a queue because work could not safely run yet.
- `identrail_worker_dead_letters_total{runner="cloud|repo|api_queue|scan_policy|scan|repo_scan"}`: scheduled or queued work that exhausted retries.
- `identrail_worker_retries_total{runner="cloud|repo|api_queue|scan_policy"}`: retryable scheduled runner failures.
- `identrail_automation_runs_total{source="scheduled|event|api_queue",connector="aws|github|kubernetes|repo_scan",outcome="queued|succeeded|failed|partial|skipped|requeued"}`: bounded automation reliability counter for scheduled scans, GitHub webhook-triggered scans, and API queue processing.
- `identrail_automation_lag_milliseconds{source="scheduled|api_queue",queue="scan|repo_scan"}`: scheduler catch-up or queue wait lag before work is enqueued or claimed.

Authorization policy lifecycle metrics:
- `identrail_authz_policy_decisions_by_version_total`
- `identrail_authz_policy_rollout_shadow_evaluations_total`
- `identrail_authz_policy_rollout_shadow_divergences_total`
- `identrail_authz_policy_rollout_shadow_divergence_rate`
- `identrail_authz_policy_rollout_shadow_evaluation_errors_total`
- `identrail_authz_policy_rollout_rollbacks_total`

### Metric Cardinality Rules

Prometheus labels must stay bounded and operationally meaningful.

Allowed label examples:
- Decision labels with small, controlled value sets: `allowed`, `outcome`, `reason`, `kind`.
- Rollout labels controlled by configuration or code: `policy_source`, `policy_version`, `rollout_mode`.
- Worker labels controlled by code constants: `queue`, `runner`, `source`.
- Automation labels controlled by code constants: `connector`, `outcome`.

Forbidden label examples:
- Request-scoped identifiers: `request_id`, trace IDs, correlation IDs.
- Actor or credential identifiers: API keys, tokens, email addresses, user IDs, principals.
- Tenant or workspace identifiers: `tenant_id`, `workspace_id`, workspace slugs.
- Scan or repository identifiers: `scan_id`, repository names, repo URLs, commit SHAs.

If a value is useful for incident triage but has unbounded cardinality, put it in structured logs or audit events instead of a Prometheus label. New metric vectors should call or test `telemetry.ValidateMetricLabels` for every label name before they are registered.

## Tracing

- Scanner pipeline emits OpenTelemetry spans:
  - `scanner.run`
  - `scanner.collect`
  - `scanner.normalize`
  - `scanner.permissions`
  - `scanner.relationships`
  - `scanner.risk`
- Automation orchestration emits OpenTelemetry spans:
  - `automation.scan_policy_scheduler`
  - `automation.github_webhook`

## V1 SLOs

- Scan success rate: >= 99% over rolling 24h (excluding known provider outages).
- API p95 latency for list endpoints: <= 300ms under normal load (enforced by `internal/api/slo_smoke_test.go`).
- Worker scheduled run reliability: >= 99% successful schedule executions per day.
- Backlog recovery: queue drains to steady state within 30 minutes after outage.

## Alert Triggers (Recommended)

- `identrail_scan_failure_total` increase > 3 in 10 minutes.
- `identrail_scan_partial_total` increase > 5 in 30 minutes.
- `identrail_scan_in_flight` stuck > 1 for 10 minutes.
- `identrail_automation_runs_total{outcome="failed"}` increase > 0 in 10 minutes for source `scheduled` or `event`.
- `identrail_automation_runs_total{outcome="skipped"}` increase > 5 in 10 minutes for source `scheduled` or `event`.
- `histogram_quantile(0.95, sum by (le, source, queue) (rate(identrail_automation_lag_milliseconds_bucket[10m]))) > 300000` for queued scan recovery lag.
- `identrail_queue_depth{queue="repo_scan"}` remains above 0 for 30 minutes.
- `identrail_worker_dead_letters_total` increase > 0 in 10 minutes.
- API p95 latency above SLO for 15 minutes.

Route alert descriptions to this runbook section first, then to `docs/deploy-runbook.md` for process-level recovery and `docs/authz-operator-runbook.md` when authorization policy metrics are involved.

## Dashboard Panels

Recommended operator dashboard panels:

- Automation success rate by source: `sum by (source, connector, outcome) (rate(identrail_automation_runs_total[5m]))`.
- Scheduled scan SLA: `sum by (connector, outcome) (increase(identrail_automation_runs_total{source="scheduled"}[24h]))`.
- Event-driven scan SLA: `sum by (connector, outcome) (increase(identrail_automation_runs_total{source="event"}[24h]))`.
- Queue depth by queue: `identrail_queue_depth`.
- Queue lag p95: `histogram_quantile(0.95, sum by (le, source, queue) (rate(identrail_automation_lag_milliseconds_bucket[10m])))`.
- Worker dead letters by runner: `sum by (runner) (increase(identrail_worker_dead_letters_total[24h]))`.

Use structured logs and scan events for high-cardinality drill-down such as repository name, scan id, tenant, workspace, request id, or trace id.
