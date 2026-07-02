# AWS session policy recommendation path

Issue #1544 adds a metadata-only projection of advisory AWS STS session-policy
recommendations. Each entry derives from a least-privilege recommendation
(#1522) and projects the scope (allow list, deny list, resource scope) an
operator should attach on STS `AssumeRole` / `AssumeRoleWithWebIdentity` to
constrain downstream sessions.

The endpoint is advisory-only. Identrail never calls IAM or STS write APIs at
this layer and never inlines rendered session-policy JSON. The recommended
policy body stays behind a `session_policy_ref` metadata reference the
downstream apply runtime can resolve when a controlled execution runs.

## API

`GET /v1/workspaces/{workspace_id}/projects/{project_id}/aws/session-policy-recommendations`

Response shape: `{ "session_policy_recommendations": AWSSessionPolicyRecommendationResult }`.

Supported filters: `connector_id`, `fixture_state`, `account_id`, `region`,
`principal_id`, `recommendation_id`, `decision`, `severity`, and `search`.

## Entry shape

Each entry carries:

- `decision`: `remove` (unused actions can be dropped from the session) or
  `review` (surface for operator review before enabling).
- `principal_node_id`, `principal_arn`, `principal_display_name`: the target
  IAM principal.
- `session_policy_ref`: metadata reference to the recommended session-policy
  JSON. The policy body is never inlined here.
- `session_duration_hint`: baseline session duration (`3600s`) operators can
  pair with the recommended policy.
- `allow_actions`, `deny_actions`, `resource_scope`, `condition_keys`: the
  projected session-policy shape.
- `expected_behavior`: `allowed_action_count`, `denied_action_count`, and
  `observed_action_count` so operators can compare projected outcome against
  runtime evidence at a glance.
- `validation_signals`: deterministic runtime and analyzer signals
  (observed-action coverage, projected removed-action count, breakage
  prediction) that back the recommendation.
- `provenance.policy_version` / `provenance.source_rule_name`: the
  deterministic rule that produced the recommendation. Every policy change
  bumps the version so operators can trace drift.
- `evidence`, `impacted_nodes`, `impacted_path`: metadata refs only. No
  rendered policy bodies, secret values, or workload payloads.
- `audit_trail`: immutable projection audit row.

## Admission

The projection only admits least-privilege recommendations whose decision is
`remove` or `review` and that carry either a `KeepActions` list or an
`ObservedActions` list. Records without an actionable observed-usage profile
are skipped so operators never see session-policy recommendations that would
scope to zero actions.

## Safety, evidence, and out of scope

- Advisory-only. No IAM or STS write APIs are called at this layer.
- Rendered session-policy JSON is never inlined; the endpoint exposes scope,
  expected behavior, validation signals, and audit metadata only.
- Downstream apply runtime is responsible for attaching the policy to STS
  `AssumeRole` calls; the recommendation itself never mutates AWS.
- Tenant, workspace, project, connector, account, and region boundaries are
  preserved.
- Unknown, permission-denied, and partial-failure states are surfaced as
  explicit states, not as successful findings.

## App Surface

The AWS Runtime page renders an **AWS session policy recommendations** panel
with the recommendation title, decision pill, principal, projected allow/deny
counts, breakage prediction, and severity/decision status pill. The panel
exposes loading, empty, blocked, degraded, and error states without operators
needing to read logs or database rows.
