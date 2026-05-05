# Helm Deployment

This chart is the Kubernetes deployment baseline for Identrail.

## Location

- Chart: `deploy/helm/identrail`

## Quick Start

1. Copy default values:
   - `cp deploy/helm/identrail/values.yaml /tmp/identrail-values.yaml`
2. Create the runtime secret referenced by default (`identrail-secrets`):
   - `READ_KEY=$(openssl rand -hex 24); WRITE_KEY=$(openssl rand -hex 24); DB_PASSWORD=$(openssl rand -hex 24); kubectl -n identrail create secret generic identrail-secrets --from-literal=IDENTRAIL_API_KEYS="${READ_KEY},${WRITE_KEY}" --from-literal=IDENTRAIL_WRITE_API_KEYS="${WRITE_KEY}" --from-literal=IDENTRAIL_DATABASE_URL="postgres://identrail:${DB_PASSWORD}@postgres:5432/identrail?sslmode=require"`
3. (Optional) If you want Helm to create the secret instead, set `secret.create=true` and provide `secret.data`.
4. Install or upgrade:
   - `helm upgrade --install identrail deploy/helm/identrail -n identrail --create-namespace -f /tmp/identrail-values.yaml`
5. Verify:
   - `kubectl -n identrail get pods`
   - `kubectl -n identrail get svc`

## Notes

- Default mode uses `secret.existingSecret=identrail-secrets` with `secret.create=false`.
- Migrations run as a pre-install/pre-upgrade Helm hook job (`templates/migration-job.yaml`).
- API and worker deployments force `IDENTRAIL_RUN_MIGRATIONS=false` to avoid DDL races.
- Disable hook jobs only if migrations are handled externally: set `migrations.enabled=false`.
- Values default to `IDENTRAIL_AWS_SOURCE=sdk` and enforce `IDENTRAIL_REQUIRE_LIVE_SOURCES=true`.
- `IDENTRAIL_K8S_SOURCE` defaults to `kubectl` for production profiles. Use an image that includes `kubectl` before switching `IDENTRAIL_PROVIDER=kubernetes`.
- Enable web deployment by setting `web.enabled=true` and set public Vite build/runtime config under `web.viteEnv`. These values are exposed to browsers, so do not put secrets there.
- Enable ingress by setting `ingress.enabled=true`.
- `IDENTRAIL_AUDIT_LOG_FILE` is empty by default. If you enable it, mount a writable path for the container user.
