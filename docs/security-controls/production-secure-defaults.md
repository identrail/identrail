# Enforce secure-by-default production configuration

This document turns issue #910 into a concrete production-control work item for Identrail maintainers and operators.

## Problem
## Why this matters
Opt-in security hardening is fragile; safe defaults reduce human failure.

## Current partial state
Hardening options exist, but defaults still permit insecure modes.

## Priority
Critical

## Minimal MVP
Add production mode that refuses insecure config (default scope, unsafe auth settings, disabled audit persistence, weak signing settings).

## Acceptance criteria
- Startup fails early when unsafe defaults are used in production mode.
- Deployment docs show secure defaults as baseline.
- Regression test validates misconfiguration rejection.

## Implementation contract
- Keep the change tenant-aware and workspace-aware.
- Preserve existing API compatibility unless the issue explicitly requires a safer default.
- Emit audit evidence for security-sensitive allow, deny, retry, reject, and recovery paths.
- Avoid storing raw secrets, tokens, webhook payload secrets, or credential material.
- Add deterministic tests for both accepted and rejected behavior before closing follow-up implementation work.

## Review checklist
- The control has a clear owner-facing configuration path.
- Unsafe defaults fail closed or produce an explicit operator warning.
- Acceptance criteria from issue #910 are covered by tests, docs, or both.
- PR validation summary states which checks were run.

## Tracking
- GitHub issue: #910
- Control slug: production-secure-defaults
