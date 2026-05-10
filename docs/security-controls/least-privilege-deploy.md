# Least-Privilege Production Deployment Examples

This guide publishes concrete production examples for issue #901 so operators can deploy Identrail with tightly scoped privileges and verify the control end to end.

## Scope

The examples cover:

- Kubernetes baseline with restricted pod/container security settings.
- Optional Kubernetes read-only RBAC for cluster scanning.
- NetworkPolicy and TLS examples.
- Helm values overrides for least-privilege defaults.
- Docker Compose hardening for single-host deployments.
- Postgres role separation for migration vs runtime workloads.
- Smoke tests that prove the deployment is functioning without ad-hoc privilege grants.

## 1) Kubernetes Baseline (Manifest Deployment)

The shipped manifests already enforce key container-level controls in:

- `deploy/kubernetes/api-deployment.yaml`
- `deploy/kubernetes/worker-deployment.yaml`
- `deploy/kubernetes/migration-job.yaml`

Those files set:

- `automountServiceAccountToken: false`
- `runAsNonRoot: true`
- `allowPrivilegeEscalation: false`
- `readOnlyRootFilesystem: true`
- `capabilities.drop: ["ALL"]`

### Optional RBAC for Kubernetes Scan Collection

If you run with `IDENTRAIL_K8S_SOURCE=kubectl`, attach read-only RBAC and then opt API/worker into scanner service-account token usage:

```bash
kubectl apply -f deploy/kubernetes/rbac-scanner-readonly.example.yaml
kubectl -n identrail patch deployment identrail-api --type merge -p '{"spec":{"template":{"spec":{"serviceAccountName":"identrail-scanner","automountServiceAccountToken":true}}}}'
kubectl -n identrail patch deployment identrail-worker --type merge -p '{"spec":{"template":{"spec":{"serviceAccountName":"identrail-scanner","automountServiceAccountToken":true}}}}'
```

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: identrail-scanner
  namespace: identrail
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: identrail-scanner-readonly
rules:
  - apiGroups: [""]
    resources: ["pods", "services", "serviceaccounts", "namespaces"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["rbac.authorization.k8s.io"]
    resources: ["roles", "rolebindings", "clusterroles", "clusterrolebindings"]
    verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: identrail-scanner-readonly
subjects:
  - kind: ServiceAccount
    name: identrail-scanner
    namespace: identrail
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: identrail-scanner-readonly
```

### NetworkPolicy Example (Default-Deny + Explicit Allows)

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: identrail-default-deny
  namespace: identrail
spec:
  podSelector: {}
  policyTypes: ["Ingress", "Egress"]
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: identrail-api-ingress
  namespace: identrail
spec:
  podSelector:
    matchLabels:
      app: identrail-api
  policyTypes: ["Ingress"]
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: ingress-nginx
      ports:
        - protocol: TCP
          port: 8080
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: identrail-postgres-ingress
  namespace: identrail
spec:
  podSelector:
    matchLabels:
      app: postgres
  policyTypes: ["Ingress"]
  ingress:
    - from:
        - podSelector:
            matchExpressions:
              - key: app
                operator: In
                values:
                  - identrail-api
                  - identrail-worker
                  - identrail-migrations
      ports:
        - protocol: TCP
          port: 5432
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: identrail-egress-db-and-dns
  namespace: identrail
spec:
  podSelector: {}
  policyTypes: ["Egress"]
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: identrail
      ports:
        - protocol: TCP
          port: 5432
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
      ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: default
        - ipBlock:
            cidr: 203.0.113.0/24
      ports:
        - protocol: TCP
          port: 443
```

If Postgres runs outside the `identrail` namespace (or outside the cluster), change the `5432` egress destination to the correct namespace/IP allowlist and omit the `identrail-postgres-ingress` policy. Replace `203.0.113.0/24` with the explicit HTTPS egress CIDRs you actually require (for example, corporate proxy/NAT or a managed egress gateway), and avoid broad allowlists like `0.0.0.0/0`.

### TLS Example

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: identrail
  namespace: identrail
spec:
  ingressClassName: nginx
  tls:
    - hosts: ["identrail.example.com"]
      secretName: identrail-tls
  rules:
    - host: identrail.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: identrail-api
                port:
                  number: 8080
```

## 2) Helm Least-Privilege Overrides

Use the chart at `deploy/helm/identrail` with an override file:

```yaml
api:
  podSecurityContext:
    runAsNonRoot: true
  securityContext:
    allowPrivilegeEscalation: false
    readOnlyRootFilesystem: true
    capabilities:
      drop: ["ALL"]
  resources:
    requests:
      cpu: 100m
      memory: 128Mi
    limits:
      cpu: 500m
      memory: 512Mi

worker:
  podSecurityContext:
    runAsNonRoot: true
  securityContext:
    allowPrivilegeEscalation: false
    readOnlyRootFilesystem: true
    capabilities:
      drop: ["ALL"]

serviceAccount:
  create: false
  name: identrail-scanner

secret:
  create: false
  existingSecret: identrail-secrets

ingress:
  enabled: true
  className: nginx
  hosts:
    - host: identrail.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: identrail-tls
      hosts:
        - identrail.example.com
```

Create namespace + scanner RBAC/ServiceAccount first (required because migrations run as a `pre-install` hook):

```bash
kubectl create namespace identrail --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -f deploy/kubernetes/rbac-scanner-readonly.example.yaml
# Create identrail-secrets (or an ExternalSecret with the same name) before Helm install.
kubectl apply -f deploy/kubernetes/secret.example.yaml # after replacing placeholder values
```

Install:

```bash
helm upgrade --install identrail deploy/helm/identrail \
  -n identrail --create-namespace \
  -f /path/to/least-privilege-values.yaml
```

This least-privilege override intentionally sets `serviceAccount.create: false` and expects `ServiceAccount/identrail-scanner` to exist before Helm runs.

## 3) Docker Compose Hardening Example

For single-host production-style runs, use the hardening override at `deploy/docker/docker-compose.security.example.yml`:

```yaml
services:
  api:
    read_only: true
    cap_drop: ["ALL"]
    security_opt:
      - no-new-privileges:true
    tmpfs:
      - /tmp
    user: "65532:65532"
    environment:
      IDENTRAIL_RUN_MIGRATIONS: "false"

  worker:
    read_only: true
    cap_drop: ["ALL"]
    security_opt:
      - no-new-privileges:true
    tmpfs:
      - /tmp
    user: "65532:65532"
    environment:
      IDENTRAIL_RUN_MIGRATIONS: "false"
```

Run with:

```bash
docker compose \
  -f deploy/docker/docker-compose.yml \
  -f deploy/docker/docker-compose.prod.example.yml \
  -f deploy/docker/docker-compose.security.example.yml \
  --env-file deploy/docker/.env \
  run --build --rm migrations

docker compose \
  -f deploy/docker/docker-compose.yml \
  -f deploy/docker/docker-compose.prod.example.yml \
  -f deploy/docker/docker-compose.security.example.yml \
  --env-file deploy/docker/.env \
  up -d --build api worker web
```

## 4) Postgres Role Separation Example

Use one high-privilege role for migrations and a reduced runtime role for API/worker:

```sql
CREATE ROLE identrail_migrator LOGIN PASSWORD 'replace-strong-password';
CREATE ROLE identrail_runtime LOGIN PASSWORD 'replace-strong-password';

GRANT CONNECT, TEMP ON DATABASE identrail TO identrail_migrator;
GRANT USAGE, CREATE ON SCHEMA public TO identrail_migrator;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO identrail_migrator;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO identrail_migrator;

GRANT CONNECT ON DATABASE identrail TO identrail_runtime;
GRANT USAGE ON SCHEMA public TO identrail_runtime;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO identrail_runtime;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO identrail_runtime;

ALTER DEFAULT PRIVILEGES FOR ROLE identrail_migrator IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO identrail_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE identrail_migrator IN SCHEMA public
  GRANT USAGE, SELECT ON SEQUENCES TO identrail_runtime;
```

Operational pattern:

1. Run migration job with `IDENTRAIL_DATABASE_URL` bound to `identrail_migrator`.
2. Run API/worker with `IDENTRAIL_DATABASE_URL` bound to `identrail_runtime`.
3. Keep `IDENTRAIL_RUN_MIGRATIONS=false` for long-running API/worker pods.

## 5) Smoke Tests

Run these checks after deployment:

```bash
# Service account permissions are read-only (or none if k8s scan is disabled).
kubectl auth can-i --as=system:serviceaccount:identrail:identrail-scanner --list

# Pods are healthy and running.
kubectl -n identrail get pods
kubectl -n identrail get deploy

# API readiness is up.
kubectl -n identrail port-forward svc/identrail-api 8080:8080 &
curl -fsS http://127.0.0.1:8080/readyz

# NetworkPolicy objects are present.
kubectl -n identrail get networkpolicy

# Runtime DB role cannot perform DDL (expected permission denied).
psql "$IDENTRAIL_RUNTIME_DATABASE_URL" -c "CREATE TABLE identrail_runtime_should_fail(id int);"
```

If any step requires adding broad privileges, stop and tighten the role/policy before go-live.
