# Add explicit OIDC/JWKS cache refresh and rotation handling

This document turns issue #900 into a concrete production-control work item for Identrail maintainers and operators.

## Problem
## Why this matters
OIDC/JWKS rotation is normal in IdPs and must not break auth.

## Current partial state
OIDC verification exists but unknown-kid refresh and cache semantics are not explicit hardening controls.

## Priority
Medium

## Minimal MVP
Add explicit JWKS prewarm/refresh-on-unknown-kid policy with bounded staleness and failure metrics.

## Acceptance criteria
- Unknown-kid token triggers key refresh.
- Key rotation works without restart.
- Failure mode is safe and observable.
- CI includes JWKS rollover tests.

## Implementation contract
- Keep the change tenant-aware and workspace-aware.
- Preserve existing API compatibility unless the issue explicitly requires a safer default.
- Emit audit evidence for security-sensitive allow, deny, retry, reject, and recovery paths.
- Avoid storing raw secrets, tokens, webhook payload secrets, or credential material.
- Add deterministic tests for both accepted and rejected behavior before closing follow-up implementation work.

## Review checklist
- The control has a clear owner-facing configuration path.
- Unsafe defaults fail closed or produce an explicit operator warning.
- Acceptance criteria from issue #900 are covered by tests, docs, or both.
- PR validation summary states which checks were run.

## Tracking
- GitHub issue: #900
- Control slug: oidc-jwks-rotation
