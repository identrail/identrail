# Add tenant/key-aware abuse controls and quotas

This document turns issue #904 into a concrete production-control work item for Identrail maintainers and operators.

## Problem
## Why this matters
Per-IP limits alone are easy to evade in API-key and tenant abuse patterns.

## Current partial state
Global `/v1` IP limiter exists, but key/tenant and action-sensitive limits are incomplete.

## Priority
Medium

## Minimal MVP
Add per-key, per-tenant, and per-action quotas plus webhook and queue admission controls.

## Acceptance criteria
- One tenant/key cannot starve other tenants.
- Scan trigger endpoints are tighter than read endpoints.
- Attack burst returns predictable 429 behavior.

## Implementation contract
- Keep the change tenant-aware and workspace-aware.
- Preserve existing API compatibility unless the issue explicitly requires a safer default.
- Emit audit evidence for security-sensitive allow, deny, retry, reject, and recovery paths.
- Avoid storing raw secrets, tokens, webhook payload secrets, or credential material.
- Add deterministic tests for both accepted and rejected behavior before closing follow-up implementation work.

## Review checklist
- The control has a clear owner-facing configuration path.
- Unsafe defaults fail closed or produce an explicit operator warning.
- Acceptance criteria from issue #904 are covered by tests, docs, or both.
- PR validation summary states which checks were run.

## Tracking
- GitHub issue: #904
- Control slug: tenant-key-abuse-controls
