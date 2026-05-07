# Expand threat model into control/risk coverage matrix

This document turns issue #911 into a concrete production-control work item for Identrail maintainers and operators.

## Problem
## Why this matters
Teams need a living map from threats to controls and tests.

## Current partial state
Threat model exists but does not yet include all residual risks and control coverage for the latest gaps.

## Priority
Medium

## Minimal MVP
Expand threat model to a control matrix with owner, control, detection, residual risk, and test coverage status.

## Acceptance criteria
- Each new security control updates threat matrix.
- Residual risk is explicit for each critical threat.
- Release checklist references matrix updates for security work.

## Implementation contract
- Keep the change tenant-aware and workspace-aware.
- Preserve existing API compatibility unless the issue explicitly requires a safer default.
- Emit audit evidence for security-sensitive allow, deny, retry, reject, and recovery paths.
- Avoid storing raw secrets, tokens, webhook payload secrets, or credential material.
- Add deterministic tests for both accepted and rejected behavior before closing follow-up implementation work.

## Review checklist
- The control has a clear owner-facing configuration path.
- Unsafe defaults fail closed or produce an explicit operator warning.
- Acceptance criteria from issue #911 are covered by tests, docs, or both.
- PR validation summary states which checks were run.

## Tracking
- GitHub issue: #911
- Control slug: threat-model-control-matrix
