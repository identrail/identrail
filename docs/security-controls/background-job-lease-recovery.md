# Implement durable background job locking with lease recovery

This document turns issue #907 into a concrete production-control work item for Identrail maintainers and operators.

## Problem
## Why this matters
Worker failures should not leave scans stuck or duplicated.

## Current partial state
Queue claims exist, but stale/crashed-job recovery with heartbeat leases is not comprehensive.

## Priority
High

## Minimal MVP
Introduce claim lease + heartbeat + stale-job reaper and deterministic requeue policy.

## Acceptance criteria
- Crashed workers' running jobs are reclaimed after expiry.
- Single job not processed by two active workers.
- Regression covers crash + replay recovery.

## Implementation contract
- Keep the change tenant-aware and workspace-aware.
- Preserve existing API compatibility unless the issue explicitly requires a safer default.
- Emit audit evidence for security-sensitive allow, deny, retry, reject, and recovery paths.
- Avoid storing raw secrets, tokens, webhook payload secrets, or credential material.
- Add deterministic tests for both accepted and rejected behavior before closing follow-up implementation work.

## Review checklist
- The control has a clear owner-facing configuration path.
- Unsafe defaults fail closed or produce an explicit operator warning.
- Acceptance criteria from issue #907 are covered by tests, docs, or both.
- PR validation summary states which checks were run.

## Tracking
- GitHub issue: #907
- Control slug: background-job-lease-recovery
