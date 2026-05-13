# Kubernetes Connector

PR 9 adds the standard Kubernetes connector path. The preferred flow is an in-cluster agent installed with Helm. A kubeconfig paste fallback remains available for ad-hoc development and small test clusters.

## In-Cluster Agent Flow

1. A user starts `/v1/connectors/k8s` from the authenticated app.
2. Identrail creates a Kubernetes connector record and returns a single-use enrollment token that expires after 24 hours.
3. The app shows a Helm install command for `deploy/connectors/k8s/identrail-agent`.
4. The agent exchanges the enrollment token at `/v1/connectors/k8s/enroll`, which promotes the same Kubernetes Secret value into the agent bearer credential so pod restarts keep working without granting the agent write access to Secrets.
5. The agent heartbeats to `/v1/connectors/k8s/heartbeat` every 30 seconds.
6. If no heartbeat arrives for more than 5 minutes, Identrail reports the connector as degraded.

The enrollment token and agent credential are stored only as SHA-256 hashes. The plaintext enrollment token is shown once in the start response and then lives only in the Kubernetes Secret created by Helm.

## RBAC Boundaries

The Helm chart grants only `get`, `list`, and `watch`. It reads namespaces, nodes, pods, service accounts, roles, role bindings, cluster roles, and cluster role bindings.

The chart does not grant:

- `secrets`
- `pods/exec`
- mutating verbs such as `create`, `update`, `patch`, or `delete`

Secret value scanning is disabled by default. The agent flag is present for future controlled scans, but the default connector posture is metadata-only.

## Kubeconfig Fallback

`/v1/connectors/k8s/kubeconfig` accepts a kubeconfig for manual development workflows. The API validates the kubeconfig structure and stores the raw kubeconfig through the connector secret envelope table. It is not returned through status APIs.

Production deployments should prefer the Helm agent because it avoids long-lived human kubeconfigs and gives Identrail a heartbeat signal.

## Feature Flags

Backend:

```
IDENTRAIL_FEATURE_CONNECTOR_K8S=true
IDENTRAIL_CONNECTOR_SECRET_KEYS=<versioned keyset when IDENTRAIL_DATABASE_URL is set>
```

Frontend:

```
VITE_FEATURE_CONNECTOR_K8S=true
```

When `IDENTRAIL_FEATURE_CONNECTOR_K8S=false`, the standard `/v1/connectors/k8s*` API returns `404`. When `VITE_FEATURE_CONNECTOR_K8S=false`, the Kubernetes connector UI is hidden.
