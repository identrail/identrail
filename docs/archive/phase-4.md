# Phase 4: Kubernetes Integration (Foundation)

## Goal

Add first Kubernetes support for identity/workload mapping and core risk detections.

## Implemented in this milestone

- Kubernetes fixture collector:
  - reads `ServiceAccount`, `Role`/`ClusterRole`, `RoleBinding`/`ClusterRoleBinding`, and `Pod` objects
  - supports file and directory fixture paths
  - deduplicates by stable source IDs
- Kubernetes normalizer:
  - maps service accounts to normalized identities
  - maps pods to workloads and links workloads to service account identities
  - maps role bindings into normalized policies from actual Role/ClusterRole rules
  - falls back to safe built-in role-name semantics only if role objects are missing
- Kubernetes permission resolver:
  - expands normalized statements into permission tuples
- Kubernetes graph resolver:
  - builds `bound_to`, `attached_policy`, and `can_access` relationships
- Kubernetes risk rules:
  - detects overprivileged service accounts
  - detects escalation paths from workload -> service account -> privileged access
  - detects ownerless service accounts
- Runtime and CLI wiring:
  - provider switch now supports `aws` and `kubernetes`
  - new config support: `IDENTRAIL_K8S_FIXTURES`
  - collection source mode: `IDENTRAIL_K8S_SOURCE=fixture|kubectl`
  - optional live collection controls: `IDENTRAIL_KUBECTL_PATH`, `IDENTRAIL_KUBE_CONTEXT`
- Kubernetes kubectl collector:
  - read-only `kubectl get` calls for service accounts, roles, cluster roles, role bindings, cluster role bindings, and pods
  - deterministic deduplication and typed raw assets
  - unit tests for command errors, malformed output, and context mode args

## User stories covered

- As a platform security engineer, I can scan Kubernetes fixture data and see risky service account privilege paths.
- As an IAM owner, I can identify ownerless service accounts that block accountability.
- As a responder, I can trace workload blast radius through bound identities and permissions.

## Next Kubernetes slices

1. Native Kubernetes API client collector (client-go) as an alternative to kubectl command execution.
2. Additional rules (secret-read concentration, broad binding fanout, default SA abuse).
