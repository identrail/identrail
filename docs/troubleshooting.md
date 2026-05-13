# Troubleshooting Playbook

## Scan Fails Immediately

Checks:
1. `IDENTRAIL_PROVIDER` is `aws` or `kubernetes`.
2. Auth exists (API keys/scoped keys or OIDC).
3. For AWS SDK mode, credentials and region are valid.
4. For Kubernetes kubectl mode, context and cluster access are valid.

## Frequent Partial Runs

Checks:
1. Inspect `GET /v1/scans/{scan_id}/events` for source errors.
2. Check provider rate limits and transient API failures.
3. Confirm collector retry/backoff settings are active.

## API scan trigger rejected (`429 scan queue is full`)

Checks:
1. Confirm worker is running and draining queued jobs.
2. Check queue settings:
   - `IDENTRAIL_SCAN_QUEUE_MAX_PENDING`
   - `IDENTRAIL_WORKER_API_JOB_QUEUE_ENABLED`
   - `IDENTRAIL_WORKER_API_JOB_QUEUE_INTERVAL`
   - `IDENTRAIL_WORKER_API_JOB_QUEUE_BATCH_SIZE`
3. Confirm no prolonged downstream scanner failures are stalling queue drain.

Note:
- `POST /v1/scans` is asynchronous and returns `202` when accepted into queue.

## No Findings Returned

Checks:
1. Confirm scan completed and not failed.
2. Validate filters (`severity`, `type`, `scan_id`) are not too strict.
3. Run without filters and inspect findings summary.

## Repo Scan Rejected

Checks:
1. `IDENTRAIL_REPO_SCAN_ENABLED=true`.
2. `IDENTRAIL_REPO_SCAN_ALLOWLIST` is set and includes the target.
3. API target is remote (`owner/repo`, `https://...`, or `ssh://...`) and not a local filesystem path.
4. Request uses write-authorized API key/scope.

## GitHub Action says missing `VITE_IDENTRAIL_API_URL`

Symptoms:
1. Older `Vercel Production Deploy` workflow logs show missing `vars.VITE_IDENTRAIL_API_URL`.
2. The browser sign-in page shows `Identrail API URL is not configured`.
3. Vercel dashboard still shows successful deployments.

Why this happens:
1. Vite bakes `VITE_IDENTRAIL_API_URL` into the production web bundle at build time.
2. Token-based GitHub deploys now default Identrail Cloud to `https://api.identrail.com` and upsert that value into Vercel when the GitHub variable is missing.
3. Hook-only fallback deploys use the env already configured in Vercel and cannot upsert or inspect that value from GitHub Actions, so canonical Identrail Cloud domains rely on the runtime default while custom domains still need an explicit value.

Checks:
1. In GitHub: `Settings` -> `Secrets and variables` -> `Actions` -> `Variables`, confirm `VITE_IDENTRAIL_API_URL` exists if using a custom API origin.
2. In Vercel: `Project` -> `Settings` -> `Environment Variables`, confirm `VITE_IDENTRAIL_API_URL` exists for custom domains or non-hook deploys that must avoid the Identrail Cloud default.
3. Ensure the value points to the public API URL (not the web frontend URL).

For Identrail Cloud, the intended value is:

```text
VITE_IDENTRAIL_API_URL=https://api.identrail.com
```

Do not use `https://identrail.com`, `https://www.identrail.com`, or `https://app.identrail.com` for this value. Those are frontend origins. Validate the value with:

```bash
VITE_IDENTRAIL_API_URL=https://api.identrail.com make production-api-url-check
```

After `api.identrail.com` is live, run the full probe:

```bash
VITE_IDENTRAIL_API_URL=https://api.identrail.com make production-api-preflight
```
