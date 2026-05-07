# Add scan result integrity and tamper-evident manifest

This document turns issue #906 into a concrete production-control work item for Identrail maintainers and operators.

## Problem
## Why this matters
Integrity of findings is foundational for trust and compliance evidence.

## Current partial state
No end-to-end tamper-evidence manifest exists for persisted scan results.

## Priority
High

## Minimal MVP
Add signed/HMACed scan manifest over findings+metadata and verify command/endpoint.

## Acceptance criteria
- Mutated stored results fail verification.
- Deterministic input -> stable manifest.
- CI includes tamper test.

## Implementation contract
- Keep the change tenant-aware and workspace-aware.
- Preserve existing API compatibility unless the issue explicitly requires a safer default.
- Emit audit evidence for security-sensitive allow, deny, retry, reject, and recovery paths.
- Avoid storing raw secrets, tokens, webhook payload secrets, or credential material.
- Add deterministic tests for both accepted and rejected behavior before closing follow-up implementation work.

## Review checklist
- The control has a clear owner-facing configuration path.
- Unsafe defaults fail closed or produce an explicit operator warning.
- Acceptance criteria from issue #906 are covered by tests, docs, or both.
- PR validation summary states which checks were run.

## Tracking
- GitHub issue: #906
- Control slug: scan-result-integrity
