# Add durable audit trail for security-sensitive actions

This document turns issue #896 into a concrete production-control work item for Identrail maintainers and operators.

## Problem
## Why this matters
Operators need a durable, queryable audit trail for incident response, forensics, and compliance.

## Current partial state
Request IDs and some action logs exist, but audit coverage is inconsistent across APIs, webhooks, queues, and connector lifecycle events.

## Priority
High

## Minimal MVP
Persist audit events for security-relevant actions (API authz, tenant mutations, secret lifecycle, scan/job transitions, webhook receive/accept/reject) with actor, tenant/workspace, action, target, result, correlation ID, source context, and timestamp.

## Acceptance criteria
- Sensitive and failed operations always emit an audit record.
- Raw secrets are never present in audit payload.
- Basic CI/security test covers API deny, webhook handling, and queue lifecycle events.

## Implementation contract
- Keep the change tenant-aware and workspace-aware.
- Preserve existing API compatibility unless the issue explicitly requires a safer default.
- Emit audit evidence for security-sensitive allow, deny, retry, reject, and recovery paths.
- Avoid storing raw secrets, tokens, webhook payload secrets, or credential material.
- Add deterministic tests for both accepted and rejected behavior before closing follow-up implementation work.

## Review checklist
- The control has a clear owner-facing configuration path.
- Unsafe defaults fail closed or produce an explicit operator warning.
- Acceptance criteria from issue #896 are covered by tests, docs, or both.
- PR validation summary states which checks were run.

## Tracking
- GitHub issue: #896
- Control slug: audit-trail
