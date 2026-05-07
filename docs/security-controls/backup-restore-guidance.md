# Add backup and restore guidance plus recovery drills

This document turns issue #909 into a concrete production-control work item for Identrail maintainers and operators.

## Problem
## Why this matters
Disaster recovery is incomplete without tested data restore procedures.

## Current partial state
Runbooks focus on deployment and rollback, with limited backup/restore guidance.

## Priority
High

## Minimal MVP
Publish backup/restore playbook with DB, connector secrets, and key material, plus periodic restore drills.

## Acceptance criteria
- Staging restore drill documented and executable.
- Post-restore smoke tests confirm scan/connectors/audit readable.
- Key recovery/resync steps are clearly documented.

## Implementation contract
- Keep the change tenant-aware and workspace-aware.
- Preserve existing API compatibility unless the issue explicitly requires a safer default.
- Emit audit evidence for security-sensitive allow, deny, retry, reject, and recovery paths.
- Avoid storing raw secrets, tokens, webhook payload secrets, or credential material.
- Add deterministic tests for both accepted and rejected behavior before closing follow-up implementation work.

## Review checklist
- The control has a clear owner-facing configuration path.
- Unsafe defaults fail closed or produce an explicit operator warning.
- Acceptance criteria from issue #909 are covered by tests, docs, or both.
- PR validation summary states which checks were run.

## Tracking
- GitHub issue: #909
- Control slug: backup-restore-guidance
