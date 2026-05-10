# Add dedicated security regression tests for hardening controls

This document turns issue #912 into a concrete production-control work item for Identrail maintainers and operators.

## Problem
## Why this matters
Security controls regress silently without dedicated guards.

## Current partial state
Authz regression coverage is strong; other controls lack dedicated regression test lanes.

## Priority
High

## Minimal MVP
Create a dedicated security-regression suite for API key lifecycle, JWKS rollover, webhook replay, secret redaction, job recovery, and scan integrity.

## Acceptance criteria
- CI runs the security-regression suite for every merge.
- Tests include negative paths for each control.
- Missing tests fail PR checks.

## Implementation contract
- Keep the change tenant-aware and workspace-aware.
- Preserve existing API compatibility unless the issue explicitly requires a safer default.
- Emit audit evidence for security-sensitive allow, deny, retry, reject, and recovery paths.
- Avoid storing raw secrets, tokens, webhook payload secrets, or credential material.
- Add deterministic tests for both accepted and rejected behavior before closing follow-up implementation work.

## Review checklist
- The control has a clear owner-facing configuration path.
- Unsafe defaults fail closed or produce an explicit operator warning.
- Acceptance criteria from issue #912 are covered by tests, docs, or both.
- PR validation summary states which checks were run.

## Tracking
- GitHub issue: #912
- Control slug: security-regression-tests
