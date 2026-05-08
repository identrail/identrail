# Standardize alert signing/HMAC verification contract

This document turns issue #908 into a concrete production-control work item for Identrail maintainers and operators.

## Problem
## Why this matters
Consumers need a stable contract to verify outbound alerts.

## Current partial state
Alert HMAC header exists, but format/version and receiver guidance are not standardized.

## Priority
Medium

## Minimal MVP
Versioned signature format with timestamp, key id, and canonical payload spec plus verification examples.

## Acceptance criteria
- Invalid body or skewed timestamp fails verification.
- Key rotation behavior is documented.
- Test vectors added for multiple languages/clients.

## Implementation contract
- Keep the change tenant-aware and workspace-aware.
- Preserve existing API compatibility unless the issue explicitly requires a safer default.
- Emit audit evidence for security-sensitive allow, deny, retry, reject, and recovery paths.
- Avoid storing raw secrets, tokens, webhook payload secrets, or credential material.
- Add deterministic tests for both accepted and rejected behavior before closing follow-up implementation work.

## Review checklist
- The control has a clear owner-facing configuration path.
- Unsafe defaults fail closed or produce an explicit operator warning.
- Acceptance criteria from issue #908 are covered by tests, docs, or both.
- PR validation summary states which checks were run.

## Tracking
- GitHub issue: #908
- Control slug: alert-signing-contract
