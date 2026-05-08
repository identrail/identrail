# Make tenant/workspace isolation fail-closed by default

This document turns issue #898 into a concrete production-control work item for Identrail maintainers and operators.

## Problem
## Why this matters
Multi-tenant blast-radius boundaries must be reliable by default.

## Current partial state
Scope helpers and optional DB guardrails exist, but defaults and operator enablement can still leave cross-tenant risk.

## Priority
Critical

## Minimal MVP
Production mode should require explicit non-default tenant scope and enforce tenant-bound DB/API guardrails by default; fail startup otherwise.

## Acceptance criteria
- Tenant A cannot read/write tenant B.
- Missing scope/guardrail config blocks production start.
- Tests validate unscoped SQL paths are denied.

## Implementation contract
- Keep the change tenant-aware and workspace-aware.
- Preserve existing API compatibility unless the issue explicitly requires a safer default.
- Emit audit evidence for security-sensitive allow, deny, retry, reject, and recovery paths.
- Avoid storing raw secrets, tokens, webhook payload secrets, or credential material.
- Add deterministic tests for both accepted and rejected behavior before closing follow-up implementation work.

## Review checklist
- The control has a clear owner-facing configuration path.
- Unsafe defaults fail closed or produce an explicit operator warning.
- Acceptance criteria from issue #898 are covered by tests, docs, or both.
- PR validation summary states which checks were run.

## Tracking
- GitHub issue: #898
- Control slug: tenant-workspace-isolation
