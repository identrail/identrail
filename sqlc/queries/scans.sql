-- name: GetScan :one
SELECT id, provider, status, started_at, finished_at, asset_count, finding_count, COALESCE(error_message, '') AS error_message,
       retry_count, max_retry_count, COALESCE(failure_category, '') AS failure_category, next_retry_at, dead_lettered, dead_lettered_at
FROM scans
WHERE id = $1;

-- name: ListScans :many
SELECT id, provider, status, started_at, finished_at, asset_count, finding_count, COALESCE(error_message, '') AS error_message,
       retry_count, max_retry_count, COALESCE(failure_category, '') AS failure_category, next_retry_at, dead_lettered, dead_lettered_at
FROM scans
ORDER BY started_at DESC
LIMIT $1;
