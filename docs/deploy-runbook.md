# Deploy Runbook

Simple operational runbook for Identrail API/worker deploys.

Portable deployment profiles:
- Docker: `deploy/docker/`
- Kubernetes: `deploy/kubernetes/`
- Linux VM/systemd: `deploy/systemd/`
- Guide: `docs/deployment-anywhere.md`
- AWS OIDC deployment role: `docs/aws-oidc-deployment.md`
- AWS deployment foundation: `docs/aws-deployment-foundation.md`
- AWS API hosting: `docs/aws-api-hosting.md`
- AWS connector onboarding: `docs/auth/aws-connector.md`
- Operator readiness: `docs/operator-readiness.md`
- Troubleshooting playbook: `docs/troubleshooting.md`
- Incident workflow: `docs/incident-response.md`
- Security baseline: `docs/security-hardening.md`
- Observability baseline: `docs/observability.md`
- API contract: `docs/openapi-v1.yaml`
- Migration policy: `docs/migrations.md`
- V1 release qualification: `docs/v1_release_qualification.md`

## 1) Pre-Deploy Checklist

- Confirm `IDENTRAIL_DATABASE_URL` points to target environment.
- Confirm `IDENTRAIL_ALLOW_MEMORY_STORE=false`; only disposable local runs should opt into in-memory persistence.
- Confirm production collectors use live sources:
  - `IDENTRAIL_REQUIRE_LIVE_SOURCES=true`
  - AWS: `IDENTRAIL_AWS_SOURCE=sdk`
  - Kubernetes: `IDENTRAIL_K8S_SOURCE=kubectl`
- Confirm migrations path is correct (`IDENTRAIL_MIGRATIONS_DIR`).
- Confirm shared API/worker config keeps `IDENTRAIL_RUN_MIGRATIONS=false`.
- Confirm lock backend for deployment shape:
  - single instance: `IDENTRAIL_LOCK_BACKEND=inmemory` or `auto`
  - multi-instance: `IDENTRAIL_LOCK_BACKEND=postgres`
  - set `IDENTRAIL_LOCK_NAMESPACE` to isolate lock domains between environments
- Confirm API auth is configured (OIDC or API keys); if using API keys, configure exactly one mode unless a deliberate migration requires overlap:
  - scoped mode: `IDENTRAIL_API_KEY_SCOPES`
  - legacy mode: `IDENTRAIL_API_KEYS` plus `IDENTRAIL_WRITE_API_KEYS`
- Confirm default request scope values for non-claim/non-header contexts:
  - `IDENTRAIL_DEFAULT_TENANT_ID`
  - `IDENTRAIL_DEFAULT_WORKSPACE_ID`
- Confirm production APIs reject fallback scope:
  - `IDENTRAIL_REQUIRE_EXPLICIT_SCOPE=true`
- Confirm durable connector secret storage:
  - `IDENTRAIL_CONNECTOR_SECRET_KEYS`
  - `IDENTRAIL_CONNECTOR_SECRET_KEYS_REQUIRED=true`
- Confirm OIDC claim mapping when OIDC is enabled:
  - `IDENTRAIL_OIDC_TENANT_CLAIM`
  - `IDENTRAIL_OIDC_WORKSPACE_CLAIM`
  - `IDENTRAIL_OIDC_GROUPS_CLAIM`
  - `IDENTRAIL_OIDC_ROLES_CLAIM`
- Confirm Postgres RLS enforcement mode for scoped read paths:
  - `IDENTRAIL_POSTGRES_RLS_ENFORCED`
- Confirm alert config:
  - `IDENTRAIL_ALERT_WEBHOOK_URL`
  - `IDENTRAIL_ALERT_MIN_SEVERITY`
  - optional `IDENTRAIL_ALERT_HMAC_SECRET`
  - `IDENTRAIL_ALERT_MAX_RETRIES`
  - `IDENTRAIL_ALERT_RETRY_BACKOFF`
- Confirm audit forwarding config (if enabled):
  - `IDENTRAIL_AUDIT_FORWARD_URL`
  - `IDENTRAIL_AUDIT_FORWARD_TIMEOUT`
  - `IDENTRAIL_AUDIT_FORWARD_MAX_RETRIES`
  - `IDENTRAIL_AUDIT_FORWARD_RETRY_BACKOFF`
  - optional `IDENTRAIL_AUDIT_FORWARD_HMAC_SECRET`
- Confirm audit pseudonymization uses a keyed fingerprint:
  - `IDENTRAIL_AUDIT_FINGERPRINT_SECRET`
- If worker repo scans are enabled, confirm:
  - `IDENTRAIL_WORKER_REPO_SCAN_ENABLED=true`
  - `IDENTRAIL_WORKER_REPO_SCAN_TARGETS` has intended repositories
  - targets are covered by `IDENTRAIL_REPO_SCAN_ALLOWLIST` when allowlist is set
- Confirm API queue controls:
  - `IDENTRAIL_SCAN_QUEUE_MAX_PENDING`
  - `IDENTRAIL_REPO_SCAN_QUEUE_MAX_PENDING`
  - `IDENTRAIL_WORKER_API_JOB_QUEUE_ENABLED=true`
  - `IDENTRAIL_WORKER_API_JOB_QUEUE_INTERVAL`
  - `IDENTRAIL_WORKER_API_JOB_QUEUE_BATCH_SIZE`

## 2) Deploy Sequence

1. Ensure CI is green on `dev` (`Go Quality`, `Go Tests`, `Go Integration (Postgres)`, `Web Build`).
2. Run migrations once using the dedicated migration job:
   - Kubernetes manifests: apply `deploy/kubernetes/migration-job.yaml` and wait for job completion.
   - Helm: pre-install/pre-upgrade hook job runs automatically when `migrations.enabled=true`.
3. Deploy API service with `IDENTRAIL_RUN_MIGRATIONS=false`.
4. Verify health endpoint: `GET /healthz`.
5. Deploy worker with same DB + provider config (`IDENTRAIL_RUN_MIGRATIONS=false`).
6. Trigger one scan (`POST /v1/scans`) with write-authorized key.
7. Verify:
  - scan is accepted as queued (`202`) then completed by worker
  - findings list (`GET /v1/findings`)
  - findings summary (`GET /v1/findings/summary`)
  - findings trends (`GET /v1/findings/trends`)
  - scan diff (`GET /v1/scans/:scan_id/diff`)
  - scan events (`GET /v1/scans/:scan_id/events`)
8. If repo scan is enabled:
   - trigger `POST /v1/repo-scans`
   - verify `GET /v1/repo-scans`
   - verify `GET /v1/repo-findings?repo_scan_id=<id>`

### AWS API Hosting Notes

For AWS-hosted API rollout, keep `create_api_hosting_resources=false` until the
VPC, subnets, ACM certificate, immutable API image, database, and Secrets
Manager references are ready. Plan the stack first, verify the load balancer
health endpoint, and only then point `api.identrail.com` at the load balancer.
Keep `app.identrail.com` on Vercel.

Use the `AWS API Manual Deploy` GitHub Actions workflow for controlled API
cutover preparation. Run `plan` first. Use `apply` only after reviewing the plan; the
workflow requires the explicit confirmation string `apply-api.identrail.com` and
persists Terraform state in the configured S3 state bucket.

For the first cost-controlled Identrail Cloud cutover, prefer the documented
public-task bootstrap mode instead of creating NAT Gateways. Set
`api_task_subnet_ids` to two public subnets and `api_task_assign_public_ip=true`
so ECS tasks can pull images, read Secrets Manager, and write logs without NAT
hourly charges. The service security group still accepts inbound traffic only
from the ALB security group. Revisit private task subnets plus NAT/VPC endpoints
after the API is live and traffic or customer requirements justify the added
cost.

## 3) Rollback Sequence

Before any migration or rollback, capture a fresh Postgres backup or managed database
snapshot for the target environment and record where the artifact can be restored from.

1. Stop worker to avoid new writes during rollback.
2. Roll back API to previous image.
3. If schema rollback is required, apply matching down migration manually.
4. Re-run health checks and one scan smoke test.

## 4) Postgres Backup and Restore

1. Configure recurring managed Postgres backups or scheduled `pg_dump` jobs for every
   non-local environment.
2. Before deploys that include migrations, run an explicit backup:
   - `pg_dump --format=custom --file identrail-$(date +%Y%m%d%H%M%S).dump "$IDENTRAIL_DATABASE_URL"`
3. Store backup artifacts in encrypted storage with access limited to operators who can
   restore production data.
4. Test restore drills on a non-production database at least once per release cycle:
   - `createdb identrail_restore_test`
   - `pg_restore --clean --if-exists --dbname identrail_restore_test identrail-<timestamp>.dump`
5. After restore, verify:
   - migrations table is present and at the expected version
   - `GET /healthz` succeeds against the restored database
   - one read-only findings query returns expected data
6. Document recovery objectives for each environment:
   - RPO: maximum acceptable data loss window
   - RTO: maximum acceptable time to restore service

## 5) Key Rotation

1. Add new keys/scoped keys to environment.
2. Deploy services.
3. Validate new key access.
4. Remove old keys.
5. Deploy again.

## 6) Alert Webhook Verification

1. Trigger a scan that emits `high` or `critical` finding.
2. Confirm webhook receiver gets payload.
3. Confirm `X-Identrail-Signature` validation if secret is configured.
4. If receiver is temporarily failing, confirm retries are visible in receiver logs.

## 7) Incident Clues

- For API activity trace: check audit log sink (`IDENTRAIL_AUDIT_LOG_FILE`).
- For scan lifecycle: check `/v1/scans/:scan_id/events`.
- For alert delivery issues: check API/worker warning logs for alert delivery failures.
