# Implement API key lifecycle management (revoke, expiry, rotation)

This document turns issue #899 into a concrete production-control work item for Identrail maintainers and operators.

## Problem
This PR is intentionally a design and implementation-planning document. It does not implement lifecycle enforcement changes in code.
## Why this matters
Static API keys are hard to revoke quickly during compromise.

## Current partial state
Rotation guidance exists, but there is no managed key lifecycle (revoke/expire/status) beyond config values.

## Follow-up required
- This document only defines the target behavior and test expectations.
- Runtime enforcement, API key persistence changes, and rollout mechanics are intentionally deferred to follow-up implementation PRs.
- Issue #899 should only be marked resolved once those implementation and test changes land.

## Priority
Critical

## Minimal MVP
Store API keys in DB/secure config with hash, status, scope, created/expiry/revoked timestamps, and last-used metadata.

## Acceptance criteria
- Revoked/expired keys are denied promptly.
- Overlapping rotation window is supported.
- Tests cover revoke, expiry, and cutover.

## Implementation contract
- Keep the change tenant-aware and workspace-aware.
- Preserve existing API compatibility unless the issue explicitly requires a safer default.
- Emit audit evidence for security-sensitive allow, deny, retry, reject, and recovery paths.
- Avoid storing raw secrets, tokens, webhook payload secrets, or credential material.
- Add deterministic tests for both accepted and rejected behavior before closing follow-up implementation work.

## Review checklist
- The control has a clear owner-facing configuration path.
- Unsafe defaults fail closed or produce an explicit operator warning.
- Acceptance criteria from issue #899 are covered by tests, docs, or both.
- PR validation summary states which checks were run.

## Tracking
- GitHub issue: #899
- Control slug: api-key-lifecycle
