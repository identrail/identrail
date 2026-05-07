# Kubernetes Deployment

## Files

- `namespace.yaml`
- `configmap.yaml`
- `secret.example.yaml`
- `migration-job.yaml`
- `api-deployment.yaml`
- `api-service.yaml`
- `worker-deployment.yaml`
- `ingress.example.yaml`

## Quick Start

1. Apply namespace and config:
   - `kubectl apply -f deploy/kubernetes/namespace.yaml`
   - `kubectl apply -f deploy/kubernetes/configmap.yaml`
2. Create and apply a real secret from `secret.example.yaml`.
3. Run migrations once and wait for completion:
   - `kubectl apply -f deploy/kubernetes/migration-job.yaml`
   - `kubectl -n identrail wait --for=condition=complete --timeout=300s job/identrail-migrations`
4. Apply API + worker:
   - `kubectl apply -f deploy/kubernetes/api-deployment.yaml`
   - `kubectl apply -f deploy/kubernetes/api-service.yaml`
   - `kubectl apply -f deploy/kubernetes/worker-deployment.yaml`
5. Optional ingress:
   - `kubectl apply -f deploy/kubernetes/ingress.example.yaml`

Notes:
- Default manifest profile is production-oriented and fails fast on fixture collectors (`IDENTRAIL_REQUIRE_LIVE_SOURCES=true`).
- Replace the bootstrap `IDENTRAIL_DEFAULT_TENANT_ID` and `IDENTRAIL_DEFAULT_WORKSPACE_ID` values with real tenant/workspace IDs before production use. OIDC claims apply only to API request scoping; workers and background jobs still rely on fallback defaults and must not run with shared sample values.
- The production manifest profile enables `IDENTRAIL_POSTGRES_RLS_ENFORCED=true`; confirm migrations and scoped policies before rollout.
- Keep `IDENTRAIL_AWS_SOURCE=sdk` for production AWS runs.
- For Kubernetes provider runs, set `IDENTRAIL_K8S_SOURCE=kubectl` and use an image that includes `kubectl`.
- The default manifests disable service account token automounting. If Kubernetes provider mode needs in-cluster API credentials, explicitly enable token mounting for that workload and bind a least-privilege service account.
- For upgrade-safe deployment at scale, prefer Helm (`deploy/helm/identrail`).
- Worker probes use `identrail --healthcheck`, which verifies the worker binary can execute inside the container.
- Update the API, worker, and migration manifests to the same release tag or digest before applying them in production; avoid mutable `latest` tags.
