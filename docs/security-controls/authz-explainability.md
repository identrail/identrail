# Add authz decision explainability and history API

This document turns issue #897 into a concrete production-control work item for Identrail maintainers and operators.

## Problem
## Why this matters
Debugging and incident response need stable explanations for allow/deny decisions.

## Current partial state
Decision simulation exists, but operators lack a persistent admin-facing decision history.

## Priority
Medium

## Minimal MVP
Add admin query/API to fetch authz decisions with correlated reason, policy component, scope, and policy version.

## Acceptance criteria
- Every deny includes a stable reason code and correlation ID.
- Support ticket workflow can retrieve decision explanation after the fact.
- Regression test covers tenant/RBAC/ABAC/ReBAC and default deny explainability.

## Implementation contract
- Keep the change tenant-aware and workspace-aware.
- Preserve existing API compatibility unless the issue explicitly requires a safer default.
- Emit audit evidence for security-sensitive allow, deny, retry, reject, and recovery paths.
- Avoid storing raw secrets, tokens, webhook payload secrets, or credential material.
- Add deterministic tests for both accepted and rejected behavior before closing follow-up implementation work.

## Review checklist
- The control has a clear owner-facing configuration path.
- Unsafe defaults fail closed or produce an explicit operator warning.
- Acceptance criteria from issue #897 are covered by tests, docs, or both.
- PR validation summary states which checks were run.

## Tracking
- GitHub issue: #897
- Control slug: authz-explainability
