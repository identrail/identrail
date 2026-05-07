# Add allowlists for all scan target sources

This document turns issue #905 into a concrete production-control work item for Identrail maintainers and operators.

## Problem
## Why this matters
Scan boundaries must match organization policy and blast radius.

## Current partial state
Repository scan allowlist is present, but live scan sources (AWS, K8s, etc.) need equivalent target constraints.

## Priority
Medium

## Minimal MVP
Add allowlist/denylist for AWS account IDs, role ARNs, cluster contexts, and other runtime targets.

## Acceptance criteria
- Scan target outside allowlist is rejected before execution.
- Allowed target proceeds normally.
- Startup logs/report warnings on wildcard or broad target config.

## Implementation contract
- Keep the change tenant-aware and workspace-aware.
- Preserve existing API compatibility unless the issue explicitly requires a safer default.
- Emit audit evidence for security-sensitive allow, deny, retry, reject, and recovery paths.
- Avoid storing raw secrets, tokens, webhook payload secrets, or credential material.
- Add deterministic tests for both accepted and rejected behavior before closing follow-up implementation work.

## Review checklist
- The control has a clear owner-facing configuration path.
- Unsafe defaults fail closed or produce an explicit operator warning.
- Acceptance criteria from issue #905 are covered by tests, docs, or both.
- PR validation summary states which checks were run.

## Tracking
- GitHub issue: #905
- Control slug: scan-target-allowlists
