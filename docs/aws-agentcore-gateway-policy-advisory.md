# AWS AgentCore gateway policy advisory

Issue #1545 adds a metadata-only projection of advisory AgentCore
gateway/tool policy recommendations. Each advisory derives from an AI
agent risk finding (#1528) and projects the tool-namespace scope operators
should apply through the AgentCore gateway policy decision point.

The endpoint is advisory-only. Identrail never enforces the recommendation
at this layer and never inlines prompt text, tool payloads, or workload
data. Tool restrictions, approvals, and warnings reference the agent's
tool namespace by name only.

## API

`GET /v1/workspaces/{workspace_id}/projects/{project_id}/aws/agentcore-gateway-policy-advisory`

Response shape:
`{ "agentcore_gateway_policy_advisory": AWSAgentCoreGatewayPolicyAdvisoryResult }`.

Supported filters: `connector_id`, `fixture_state`, `account_id`, `region`,
`agent_id`, `outcome`, `risk_type`, `severity`, `finding_id`, and `search`.

## Advisory shape

Each advisory carries:

- `outcome`: one of `allow_tools`, `warn`, `require_approval`,
  `restrict_tools`, `block_tools`.
- `pilot_state` / `enforcement_state`: governance posture for the
  recommendation. This wave remains advisory-only, so enforcement is always
  `advisory_only`; pilot state is `candidate`, `operator_review`, or
  `blocked` based on the projected outcome.
- `agent_node_id`, `agent_id`, `agent_name`, `agent_type`, `provider`,
  `runtime_role_arn`, `runtime_role_node_id`: the target agent gateway
  runtime.
- `allowed_tool_names`, `restricted_tool_names`, `blocked_tool_names`:
  disjoint partition of the finding's tool namespace based on the
  recommended outcome.
- `sensitive_resources`: the sensitive-reachability set that scoped the
  recommendation.
- `recommended_actions`: operator-facing directives derived from the
  outcome and the affected tool/resource scope.
- `provenance.policy_version` / `provenance.policy_rule`: the deterministic
  rule that produced the advisory. Every policy change bumps the version.
- `input_hash`: deterministic hash of the classifier inputs (finding ID,
  agent node ID, risk type, severity, status, tool count, normalized
  tool-name digest, sensitive reachability count, normalized sensitive
  resource digest, outcome, policy version). Log both sides of a gateway
  policy decision to detect drift.
- `evidence`, `impacted_nodes`, `impacted_path`: metadata refs only. No
  prompt text or tool payloads.
- `audit_trail`: immutable projection audit row.

## Outcome policy

Ordered so safety signals win over general tool-scope warnings:

1. Severity `critical` AND at least one sensitive reachability →
   `block_tools`.
2. Risk type `external_credential`, `external_credentials`, or upstream
   `external_credential_exposure` → `require_approval`.
3. Risk type `broad_tool_access` / `broad_tool_scope` → `restrict_tools`.
4. Risk type `sensitive_reachability` or upstream
   `sensitive_data_reachability` → `restrict_tools`.
5. Risk type `undeclared_tool_runtime` or `backing_role_mismatch` →
   `require_approval`.
6. Risk type `runtime_tool_anomaly`, `declared_unused_tool`, or
   `backing_role_scope` → `restrict_tools`.
7. Risk type `ownerless_agent` → `warn`.
8. Severity `critical` or `high` without matching risk type →
   `require_approval`.
9. Finding carries no resolved tool namespace → `warn`.
10. Otherwise → `allow_tools` with advisory monitoring.

## Admission

The projection only admits findings that carry an addressable
`agent_node_id`. Findings without an agent target cannot be surfaced as
a gateway policy recommendation because there is no gateway to advise on.

## Safety, evidence, and out of scope

- Advisory-only. No gateway or IAM write APIs are called at this layer.
- Critical-severity findings with sensitive reachability always classify
  as `block_tools` regardless of any other signal so a compromised
  gateway can never be recorded as `allow_tools`.
- Tenant, workspace, project, connector, account, and region boundaries
  are preserved.
- Unknown, permission-denied, and partial-failure states are surfaced as
  explicit states, not as successful findings.

## App Surface

The AWS Runtime page renders an **AWS AgentCore gateway policy advisory**
panel showing the advisory title, agent, outcome pill, restricted/blocked
tool counts, sensitive reachability count, severity/outcome status pill,
and next action.
