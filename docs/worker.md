# Worker

## What it does

The worker runs scans on a schedule and drains API-enqueued jobs.

- Binary: `cmd/worker`
- Loop: `internal/scheduler/runner.go`
- Scan call: `api.Service.RunScan`
- Optional repo scan call: `api.Service.RunRepoScanPersisted`
- Scan policy scheduler call: `api.Service.EnqueueDueScanPolicies`
- API queue drain call: `api.Service.ProcessNextQueuedScan` + `api.Service.ProcessNextQueuedRepoScan`

## Config

- `IDENTRAIL_SCAN_INTERVAL` (default `15m`)
- `IDENTRAIL_WORKER_SCAN_ENABLED` (default `true`)
- `IDENTRAIL_WORKER_RUN_NOW` (default `true`)
- `IDENTRAIL_AWS_FIXTURES`
- `IDENTRAIL_DATABASE_URL`
- `IDENTRAIL_LOCK_BACKEND` (`auto|postgres|inmemory`, default `auto`)
- `IDENTRAIL_LOCK_NAMESPACE` (default `identrail`)
- `IDENTRAIL_WORKER_REPO_SCAN_ENABLED` (default `false`)
- `IDENTRAIL_WORKER_REPO_SCAN_RUN_NOW` (default `false`)
- `IDENTRAIL_WORKER_REPO_SCAN_INTERVAL` (default `1h`)
- `IDENTRAIL_WORKER_REPO_SCAN_TARGETS` (comma-separated repos, required when enabled)
- `IDENTRAIL_WORKER_REPO_SCAN_HISTORY_LIMIT` (optional override; `0` uses service default)
- `IDENTRAIL_WORKER_REPO_SCAN_MAX_FINDINGS` (optional override; `0` uses service default)
- `IDENTRAIL_WORKER_SCAN_POLICY_SCHEDULER_ENABLED` (default `true`)
- `IDENTRAIL_WORKER_SCAN_POLICY_SCHEDULER_INTERVAL` (default `1m`)
- `IDENTRAIL_WORKER_API_JOB_QUEUE_ENABLED` (default `true`)
- `IDENTRAIL_WORKER_API_JOB_QUEUE_INTERVAL` (default `2s`)
- `IDENTRAIL_WORKER_API_JOB_QUEUE_BATCH_SIZE` (default `5`)
- `IDENTRAIL_WORKER_HEARTBEAT_PATH` (optional path for a timestamp heartbeat file)

## Behavior

- Optional cloud scan on startup (`IDENTRAIL_WORKER_SCAN_ENABLED=true` and `IDENTRAIL_WORKER_RUN_NOW=true`)
- Repeats cloud scans every interval when `IDENTRAIL_WORKER_SCAN_ENABLED=true`
- Uses same persistence flow as API-triggered scan
- Skips overlapping runs via existing service lock
- Optional repo scan scheduler is additive and disabled by default
- Project scan policies with `scheduled` or `hybrid` trigger mode are checked periodically. The worker claims each due cron tick before enqueueing selected GitHub repositories, so missed ticks recover on the next worker pass and concurrent workers do not duplicate the same policy run.
- API `POST /v1/scans` and `POST /v1/repo-scans` enqueue work; worker queue runner executes queued jobs asynchronously
- Queue runner applies bounded batch processing per tick (`IDENTRAIL_WORKER_API_JOB_QUEUE_BATCH_SIZE`)
- Heartbeat files are written at worker startup and before each configured runner tick when `IDENTRAIL_WORKER_HEARTBEAT_PATH` is set. Supervisors can alert when the file timestamp stops advancing.
- Repo scans use per-target lock key (`repo-scan:<target>`) to avoid overlap between API and worker triggers
- In database mode, `IDENTRAIL_LOCK_BACKEND=auto` uses PostgreSQL advisory locks for multi-instance safety
