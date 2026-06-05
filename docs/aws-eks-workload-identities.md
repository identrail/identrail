# AWS EKS Workload Identities

## Purpose

Issue #1480 adds EKS workload identity inventory to the AWS machine identity
graph. AWS metadata maps EKS Pod Identity associations, managed node groups,
and Fargate profiles back to the IAM roles they use. IRSA service-account
annotations are Kubernetes-side evidence and are only complete when a
Kubernetes-backed source supplies those annotations.

## Endpoint

```text
GET /v1/workspaces/{workspace_id}/projects/{project_id}/aws/eks-workload-identities
```

Optional query parameters:

- `connector_id`: scopes account and region context to a configured AWS connector.
- `fixture_state`: one of `success`, `empty`, `degraded`, `partial_failure`, or
  `permission_denied` for deterministic UI and contract validation.

The response returns `inventory`, including records, graph relationships,
diagnostics, status, confidence, and issue evidence links.

## Evidence Collected

Each record includes:

- EKS cluster ARN, name, status, Kubernetes version, OIDC issuer, and inferred
  IAM OIDC provider ARN.
- IRSA service account namespace/name, Kubernetes subject, annotation key names,
  IAM role ARN, and role name when Kubernetes API evidence is available.
- Pod Identity association ARN, ID, namespace, service account, owner ARN,
  external ID, target role ARN, IAM role ARN, and role name.
- Managed node group ARN, name, status, and node role ARN.
- Fargate profile ARN, name, status, selectors, subnet IDs, and pod execution
  role ARN.
- Connector, account, region, source, evidence ref, confidence, timestamp, and
  graph node IDs.

The collector does not read Kubernetes secret values, pod logs, object contents,
customer payloads, prompts, completions, browser output, code-interpreter
output, database rows, or AWS data-plane payloads.

## Diagnostics

Permission denial blocks inventory because the EKS metadata reads are required
entry points. Per-cluster failures for Pod Identity associations, node groups,
or Fargate profiles are degraded partial failures; successful records remain
visible.

IRSA annotations are Kubernetes-side evidence. AWS-only scans carry
`kubernetes_access_status: "aws_metadata_only"` on AWS-sourced records and emit
`irsa_annotation_collection_unconfigured` when OIDC metadata exists but no
Kubernetes service-account annotation source is configured. That keeps Pod
Identity, node role, and Fargate evidence visible while preventing a false claim
of complete IRSA coverage. The deterministic `degraded` fixture can still emit
`kubernetes_api_unavailable` when validating UI handling for a Kubernetes-access
failure.

## Graph Shape

EKS workload identities emit:

```text
eks_service_account --runs_as--> iam_role
eks_node_group --runs_as--> iam_role
eks_fargate_pod_execution_role --attached_to--> iam_role
```

That gives downstream graph, blast-radius, and least-privilege engines a
deterministic workload-to-role edge without adding live mutation or payload
reads.

## Required AWS Permissions

The EKS collector uses these metadata-only actions:

- `eks:ListClusters`
- `eks:DescribeCluster`
- `eks:ListPodIdentityAssociations`
- `eks:DescribePodIdentityAssociation`
- `eks:ListNodegroups`
- `eks:DescribeNodegroup`
- `eks:ListFargateProfiles`
- `eks:DescribeFargateProfile`

Kubernetes IRSA annotation coverage also requires a Kubernetes connector or
runtime identity that can list service accounts. Without that source, the AWS
collector reports metadata-only EKS evidence and an explicit IRSA annotation
coverage diagnostic.

## Validation

Run the focused API and UI checks:

```bash
go test ./internal/providers/aws ./internal/api
npm test -- --run src/api/client.test.ts src/productShell.test.tsx
```
