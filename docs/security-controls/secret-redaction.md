# Standardize secret redaction across all channels

This document turns issue #903 into a concrete production-control work item for Identrail maintainers and operators.

## Problem
## Why this matters
Leaks through logs/alerts can expose secrets indirectly.

## Current partial state
Some redaction is implemented but not consistently across all output channels.

## Priority
High

## Minimal MVP
Create central redaction contract + tests used by logs, audit, alerts, findings, and connector APIs.

## Acceptance criteria
- Seeded secret canaries never appear in any exported logs/events.
- Redaction behavior is tested in CI.
- Only safe fingerprints/references remain visible.

## Implementation contract
- Keep the change tenant-aware and workspace-aware.
- Preserve existing API compatibility unless the issue explicitly requires a safer default.
- Emit audit evidence for security-sensitive allow, deny, retry, reject, and recovery paths.
- Avoid storing raw secrets, tokens, webhook payload secrets, or credential material.
- Add deterministic tests for both accepted and rejected behavior before closing follow-up implementation work.

## Review checklist
- The control has a clear owner-facing configuration path.
- Unsafe defaults fail closed or produce an explicit operator warning.
- Acceptance criteria from issue #903 are covered by tests, docs, or both.
- PR validation summary states which checks were run.

## Tracking
- GitHub issue: #903
- Control slug: secret-redaction
