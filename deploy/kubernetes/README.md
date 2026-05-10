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
- `rbac-scanner-readonly.example.yaml`
- `network-policy.example.yaml`

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
6. Optional least-privilege hardening examples:
   - `kubectl apply -f deploy/kubernetes/network-policy.example.yaml`
7. Optional: enable in-cluster Kubernetes scan collection:
   - `kubectl apply -f deploy/kubernetes/rbac-scanner-readonly.example.yaml`
   - `kubectl -n identrail patch configmap identrail-config --type merge -p '{"data":{"IDENTRAIL_PROVIDER":"kubernetes","IDENTRAIL_K8S_SOURCE":"kubectl"}}'`
   - `kubectl -n identrail patch deployment identrail-api --type merge -p '{"spec":{"template":{"spec":{"serviceAccountName":"identrail-scanner","automountServiceAccountToken":true}}}}'`
   - `kubectl -n identrail patch deployment identrail-worker --type merge -p '{"spec":{"template":{"spec":{"serviceAccountName":"identrail-scanner","automountServiceAccountToken":true}}}}'`
   - `kubectl -n identrail rollout restart deployment/identrail-api deployment/identrail-worker`

Notes:
- Default manifest profile is production-oriented and fails fast on fixture collectors (`IDENTRAIL_REQUIRE_LIVE_SOURCES=true`).
- Replace the bootstrap `IDENTRAIL_DEFAULT_TENANT_ID` and `IDENTRAIL_DEFAULT_WORKSPACE_ID` values with real tenant/workspace IDs before production use. OIDC claims apply only to API request scoping; workers and background jobs still rely on fallback defaults and must not run with shared sample values.
- The production manifest profile enables `IDENTRAIL_POSTGRES_RLS_ENFORCED=true`; confirm migrations and scoped policies before rollout.
- Keep `IDENTRAIL_AWS_SOURCE=sdk` for production AWS runs.
- Default API/worker manifests set `automountServiceAccountToken: false`; only enable service-account token mounts when you intentionally run in-cluster Kubernetes collection.
- For Kubernetes provider runs, set `IDENTRAIL_PROVIDER=kubernetes` (and `IDENTRAIL_K8S_SOURCE=kubectl`), apply `rbac-scanner-readonly.example.yaml`, patch API/worker to use `identrail-scanner`, restart those deployments, and use an image that includes `kubectl`.
- For upgrade-safe deployment at scale, prefer Helm (`deploy/helm/identrail`).
- Worker probes use `identrail --healthcheck`, which verifies the worker binary can execute inside the container.
- Update the API, worker, and migration manifests to the same release tag or digest before applying them in production; avoid mutable `latest` tags.
