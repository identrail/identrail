# AWS limited enforcement framework

Issue #1546 adds a metadata-only framework for moving AWS machine-identity
governance from warn-only and advisory behavior toward controlled limited
enforcement. It joins advisory authorization decisions (#1543) and AgentCore
gateway policy advisories (#1545), then records the safety config operators
must satisfy before any downstream executor can act.

The endpoint does not enforce. Identrail never calls IAM, STS,
Organizations, Bedrock, or AgentCore write APIs at this layer.

## API

`GET /v1/workspaces/{workspace_id}/projects/{project_id}/aws/limited-enforcement`

Response shape: `{ "limited_enforcement": AWSLimitedEnforcementResult }`.

Supported filters: `connector_id`, `fixture_state`, `account_id`, `region`,
`mode`, `enforcement_state`, `decision_id`, `source_type`, `outcome`,
`cohort`, `feature_flag`, `kill_switch`, `canary_percent`, and `search`.

## Modes and states

Supported modes:

- `warn_only`: surface warning behavior only.
- `advisory`: record recommendation and evidence without enforcement.
- `approval_required`: require an operator approval workflow before any
  downstream control change.
- `limited_enforce`: mark a scoped canary or full limited-enforcement rollout
  as ready only when every safety gate passes.

Important states:

- `blocked_by_safety_config`: requested limited enforcement is missing an
  explicit feature flag, cohort, canary percentage, rollback, audit, or
  confidence gate.
- `blocked_by_kill_switch`: the tenant or source kill switch is active.
- `rollback_required`: upstream advisory state says quarantine or block.
- `canary_ready`: feature flag, cohort, canary, confidence, rollback, audit,
  and kill-switch gates are satisfied for a bounded rollout.
- `limited_enforce_ready`: all gates are satisfied with a 100 percent canary.

## Safety gates

Every entry records:

- feature flag state;
- tenant/source kill-switch state;
- canary percentage and cohort;
- rollback metadata;
- audit metadata;
- confidence floor;
- unsafe-outcome blocker.

Limited enforcement is never marked ready from defaults. Operators must
provide explicit safety config before the framework can leave advisory mode.

## Evidence boundary

Entries include source decision/advisory IDs, policy version, input hash,
confidence, evidence refs, rollback intent, gates, and audit rows. They do
not include rendered policy bodies, secret values, prompts, completions,
database rows, object contents, browser pages, or workload payloads.

Tenant, workspace, project, connector, account, and region boundaries are
preserved in the API route, authz policy, and app surface.

## App surface

The AWS Governance page renders an **AWS limited enforcement framework**
panel showing each entry's mode, source, enforcement state, cohort, gate
readiness, outcome, and canary percentage. Loading, empty, blocked,
degraded, permission-denied, and error states are explicit.

## Out of scope

- No live AWS mutation.
- No broad scanner behavior.
- No secret or customer payload collection.
- No downstream executor implementation beyond framework readiness metadata.
