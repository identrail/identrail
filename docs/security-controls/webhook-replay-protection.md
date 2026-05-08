# Add webhook replay protection with dedupe TTL

This document turns issue #902 into a concrete production-control work item for Identrail maintainers and operators.

## Problem
## Why this matters
Valid signatures do not stop replay attacks.

## Current partial state
Webhook signature verification exists, but replay dedupe and TTL checks are not fully implemented.

## Priority
High

## Minimal MVP
Persist webhook delivery IDs and reject duplicate/stale deliveries.

## Acceptance criteria
- Duplicate payload is idempotently ignored or rejected.
- Replay beyond allowed age is blocked.
- Concurrency test ensures one processing path for a duplicate delivery.

## Implementation contract
- Keep the change tenant-aware and workspace-aware.
- Preserve existing API compatibility unless the issue explicitly requires a safer default.
- Emit audit evidence for security-sensitive allow, deny, retry, reject, and recovery paths.
- Avoid storing raw secrets, tokens, webhook payload secrets, or credential material.
- Add deterministic tests for both accepted and rejected behavior before closing follow-up implementation work.

## Review checklist
- The control has a clear owner-facing configuration path.
- Unsafe defaults fail closed or produce an explicit operator warning.
- Acceptance criteria from issue #902 are covered by tests, docs, or both.
- PR validation summary states which checks were run.

## Tracking
- GitHub issue: #902
- Control slug: webhook-replay-protection
