# Publish least-privilege production deployment examples

This document turns issue #901 into a concrete production-control work item for Identrail maintainers and operators.

## Problem
## Why this matters
Secure deployment defaults reduce operator error and privilege sprawl.

## Current partial state
Some least-privilege IAM/K8s templates exist, but complete production reference deployments are incomplete.

## Priority
Medium

## Minimal MVP
Create hardened deploy examples for Kubernetes/Helm/compose with SA bindings, NetworkPolicy, TLS, DB role grants, and secret-manager references.

## Acceptance criteria
- Example deploy passes with documented least privileges.
- Security-sensitive roles are explicitly enumerated.
- Deployment smoke test works with no ad-hoc permissions.

## Implementation contract
- Keep the change tenant-aware and workspace-aware.
- Preserve existing API compatibility unless the issue explicitly requires a safer default.
- Emit audit evidence for security-sensitive allow, deny, retry, reject, and recovery paths.
- Avoid storing raw secrets, tokens, webhook payload secrets, or credential material.
- Add deterministic tests for both accepted and rejected behavior before closing follow-up implementation work.

## Review checklist
- The control has a clear owner-facing configuration path.
- Unsafe defaults fail closed or produce an explicit operator warning.
- Acceptance criteria from issue #901 are covered by tests, docs, or both.
- PR validation summary states which checks were run.

## Tracking
- GitHub issue: #901
- Control slug: least-privilege-deploy
