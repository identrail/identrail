# AWS advisory authorization decision API

Issue #1543 adds a metadata-only projection of deterministic advisory
authorization decisions. Each decision joins one remediation case (#1529)
with its corresponding post-remediation verification and rollback record
(#1542) and returns a recommended outcome plus provenance.

The endpoint is advisory-only. Identrail never enforces the recommendation
at this layer and never calls IAM, STS, or Organizations write APIs. Live
enforcement belongs to downstream governance executors and their own feature
flags.

## API

`GET /v1/workspaces/{workspace_id}/projects/{project_id}/aws/advisory-authorization`

Response shape: `{ "advisory_authorization": AWSAdvisoryAuthorizationResult }`.

Supported filters: `connector_id`, `fixture_state`, `account_id`, `region`,
`principal_id`, `action`, `outcome`, `severity`, `source_type`, `case_id`,
`verification_id`, and `search`.

## Decision shape

Each decision carries:

- `outcome`: one of `allow`, `warn`, `require_approval`, `recommend_deny`,
  `quarantine`.
- `mode`: currently always `advisory`. Identrail does not enforce.
- `principal_node_id`, `principal_arn`, `principal_type`, `action`,
  `resource_scope`: the subject of the recommendation.
- `provenance.policy_version` and `provenance.policy_rule`: the deterministic
  policy rule name that produced the outcome. Every change to the policy
  bumps the version so operators can trace drift.
- `input_hash`: deterministic hash of every input the classifier reads
  (case ID, lifecycle, approval state, approval-required flag, severity,
  verification state, kill-switch flag, policy version). Log it on both
  sides of a policy decision point to detect drift.
- `evidence`, `evidence_links`: metadata refs only. No rendered policy
  bodies, secret values, or workload payloads.
- `audit_trail`: immutable rows including the projection event.

## Outcome policy

Ordered so safety signals win over general approval state. Any present
verification entry is evaluated before the case-only rules so a
projected-but-not-yet-verified execution can never be recorded as `allow`:

1. `verification.kill_switch_engaged=true` → `quarantine`.
2. Verification state `verification_failed` or `rollback_planned` →
   `quarantine`.
3. Verification state `verification_verified` → `allow`.
4. Verification state `blocked` → `recommend_deny`.
5. Verification state `verification_pending` → `require_approval`.
6. Verification state `not_ready` or `skipped` → `warn`.
7. Case lifecycle `resolved` (no verification present) → `allow`.
8. Case `approval_state=blocked` → `recommend_deny`.
9. Case `approval_state=approved` (not yet applied+verified) →
   `require_approval`.
10. Case `approval_required=true` → `require_approval`.
11. Case severity `critical` or `high` with no in-flight execution → `warn`.
12. Otherwise → `allow` with advisory monitoring.

## App Surface

The AWS Runtime page renders an **AWS advisory authorization** panel showing
the decision title, outcome pill, policy rule, principal, action, severity,
and next action. The panel exposes loading, empty, blocked, degraded, and
error states without operators needing to read logs or database rows.

## Safety, evidence, and out of scope

- Advisory-only. No IAM/STS/Organizations write APIs are called at this
  layer.
- Kill-switch and verification-failed states always classify as `quarantine`
  regardless of upstream approval state, so a compromised or reverted
  execution can never be recorded as `allow`.
- Tenant, workspace, project, connector, account, and region boundaries are
  preserved.
- Unknown, permission-denied, and partial-failure states are surfaced as
  explicit states, not as successful findings.
