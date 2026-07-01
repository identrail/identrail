# AWS post-remediation verification and rollback

Issue #1542 adds a metadata-only projection of the deterministic post-apply
verification and rollback contract Identrail generates for every approved
wave-8 executor: low-risk live remediation (#1538), trust-policy hardening
executor (#1539), permission boundary executor (#1540), and SCP guardrail
executor (#1541).

The endpoint is read-only. It never calls IAM, STS, or Organizations write
APIs and never reads, exposes, logs, or persists rendered policy documents,
secret values, customer payloads, prompts, completions, browser pages,
code-interpreter output, database rows, or object contents.

## API

`GET /v1/workspaces/{workspace_id}/projects/{project_id}/aws/post-remediation-verification`

Response shape: `{ "post_remediation_verification": AWSPostRemediationVerificationResult }`.

Supported filters: `connector_id`, `fixture_state`, `account_id`, `region`,
`source_type`, `execution_id`, `dry_run_id`, `case_id`, `state`, `severity`,
`operation`, and `search`.

## Entry Shape

Each entry pairs one upstream executor projection with:

- Deterministic verification checks (CloudTrail, graph re-normalization, and
  runtime denial checks; plus planner success/failure signals). Checks stay in
  the `pending` state until the wave-8 apply runtime records the observed
  outcome.
- A rollback record that mirrors the upstream planner rollback plan
  (`strategy`, `steps`, `evidence_ref`, success/failure signals) and carries a
  state (`ready`, `not_available`, or `blocked_by_kill_switch`).
- Precondition gates: upstream projection status, kill-switch off,
  ready-for-live-apply, idempotency key present, rollback plan present,
  verification plan present, and any propagated upstream precondition failures.
- Immutable audit trail (the upstream executor's audit rows plus the
  verification-projected row).
- Graph relationships tying the verification record to the upstream execution
  and any impacted graph nodes.

## States

- `verification_pending`: upstream executor is projected and ready; the apply
  runtime should record check outcomes and advance to verified or failed.
- `verification_verified`: all checks have passed.
- `verification_failed`: at least one check failed; follow the rollback record
  and refresh upstream evidence before retrying.
- `rollback_planned`: verification failed and rollback is queued.
- `blocked`: a safety gate failed, the tenant kill switch is engaged, or an
  upstream precondition failed.
- `not_ready`: upstream executor has not projected `ready_for_live_apply`.
- `skipped`: the upstream executor did not project a live-apply record.

## App Surface

The AWS Runtime page renders an **AWS post-remediation verification and
rollback** panel that shows the execution title, upstream source, verification
check pass/fail/pending counts, rollback strategy/state, severity, and state
pill. The panel exposes loading, empty, blocked, degraded, and error states
without operators needing to read logs or database rows.

## Safety, evidence, and out of scope

- Metadata-only projection. No IAM/STS/Organizations write APIs are called at
  this layer; live execution belongs to the wave-8 apply runtime and its own
  feature flag.
- Rollback records mirror the upstream planner metadata; they never carry
  rendered policy bodies or secret values.
- Tenant, workspace, project, connector, account, and region boundaries are
  preserved at every layer.
- Unknown, permission-denied, and partial-failure states are surfaced as
  explicit states, not as successful findings.
