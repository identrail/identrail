# Kubernetes Connector

PR 9 adds the standard Kubernetes connector path. The preferred flow is an in-cluster agent installed with Helm. A kubeconfig paste fallback remains available for ad-hoc development and small test clusters.

## In-Cluster Agent Flow

1. A user starts `/v1/connectors/k8s` from the authenticated app.
2. Identrail creates a Kubernetes connector record and returns a single-use enrollment token that expires after 24 hours.
3. The app shows a Helm install command for `deploy/connectors/k8s/identrail-agent`.
4. The agent exchanges the enrollment token at `/v1/connectors/k8s/enroll`, receives a distinct agent bearer credential, and patches that value into the Helm-managed Secret so pod restarts keep using the durable agent credential.
5. The agent heartbeats to `/v1/connectors/k8s/heartbeat` every 30 seconds.
6. If no heartbeat arrives for more than 5 minutes, Identrail reports the connector as degraded.

The enrollment token and agent credential are stored by Identrail only as SHA-256 hashes. The plaintext enrollment token is shown once in the start response and then lives only in the Kubernetes Secret created by Helm. After first enrollment, the agent writes the returned `agent-token` into the same Secret using a namespace Role restricted to that one Secret.

## RBAC Boundaries

The Helm chart grants cluster-wide `get`, `list`, and `watch` for metadata reads. It reads namespaces, nodes, pods, service accounts, roles, role bindings, cluster roles, and cluster role bindings.

The chart also grants a namespaced Role with `get`, `patch`, and `update` on only the Helm-managed enrollment Secret. The agent uses that narrow write permission once after enrollment to persist the issued `agent-token` for pod restarts.

The chart does not grant:

- `pods/exec`
- broad Secret reads or writes
- mutating verbs such as `create` or `delete`
- `update` or `patch` outside the single enrollment Secret

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
