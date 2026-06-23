# AWS AI agent risk engine

Issue #1528 (Wave 6.08) adds a metadata-only engine that turns AWS AI agent
inventory, runtime/tool-call evidence, secret-permission equivalence, and
least-privilege role-scope signals into ranked, explainable risk findings.

## What it produces

The engine emits `AWSAIAgentRiskFinding` records for these risk types:

- **`broad_tool_access`** - an agent or gateway declares a wide tool/action
  surface.
- **`sensitive_data_reachability`** - an agent can reach memory, browser,
  code-interpreter, storage, or KMS-backed capability metadata.
- **`ownerless_agent`** - an agent has no accountable owner metadata or has
  degraded ownership coverage.
- **`external_credential_exposure`** - an agent references external provider
  credential metadata or secret-permission equivalence evidence.
- **`undeclared_tool_runtime`**, **`backing_role_mismatch`**,
  **`declared_unused_tool`**, and **`runtime_tool_anomaly`** -
  runtime/tool-call correlation found an undeclared tool, role drift,
  a declared-but-unused tool surface, or another runtime caveat.
- **`backing_role_scope`** - least-privilege analysis found removable or
  review-required scope on the agent backing role.

Each finding carries a stable id, calculation version, severity, score,
confidence, agent identity, backing role, provider, tools, sensitive resources,
rationale, impacted path, evidence refs, source signals, next action, and
read-only remediation case preview.

## API

`GET /v1/workspaces/{workspace_id}/projects/{project_id}/aws/ai-agent-risk`

| Query param | Purpose |
|---|---|
| `connector_id` | scope to one AWS connector |
| `fixture_state` | `success` / `empty` / `degraded` / `partial_failure` / `permission_denied` for deterministic demos and tests |
| `account_id`, `region` | account and region filters |
| `agent_id` | agent id, agent name, node id, or backing-role search |
| `risk_type` | one of the finding types above |
| `severity` | `critical`, `high`, `medium`, or `low` |
| `status` | `action_required`, `review`, or `monitor` |
| `evidence` | `runtime-backed`, `inventory-backed`, `secret-backed`, or evidence text search |
| `search` | free-text search across agent, role, provider, evidence, rationale, and resources |

Response shape: `{ "findings": AWSAIAgentRiskResult }` with summary, ranked
findings, graph relationships, caveats, failure reasons, remediation hints,
evidence links, coverage gaps, diagnostics, and standard
tenant/workspace/project issue metadata.

## Evidence boundary

The engine never reads, stores, logs, or displays secret values, prompt text,
completions, tool inputs or outputs, browser pages, code-interpreter output,
database rows, object contents, or customer payloads. It only composes:

- AI agent identity, tool, capability, credential-reference, and runtime-role
  metadata
- CloudTrail event ids, redacted runtime action metadata, and correlation
  statuses
- secret-permission equivalence finding refs and provider classifications
- least-privilege recommendation refs for backing roles

## AWS permissions

This capability adds no live mutation and does not require payload-reading
permissions. It reuses read-only metadata permissions from AI agent identity
inventory, runtime event correlation, secret-permission equivalence, and
least-privilege recommendation sources.

Do not grant permissions that read prompts, invocations, memory records,
browser pages, code-interpreter output, database rows, object contents, or
secret values for this issue.

## Failure handling

- **Ready**: source engines are available and no blocking diagnostics were
  emitted.
- **Degraded**: at least one source is partial, empty because live evidence is
  unavailable, capability-limited, or produced retryable diagnostics. Retained
  evidence remains visible.
- **Blocked**: required source evidence is permission denied. The response has
  zero deterministic findings plus diagnostics and failure reasons.

Unknown, unsupported, partial, degraded, and permission-denied evidence remains
explicit and is not treated as proof that an agent is safe.

## App surface

The AWS Runtime app surface renders the **AWS AI agent risk engine** panel with
ranked findings, agent/backing-role context, scope, confidence, evidence,
severity/status, and next action. Operators can inspect the decision without
reading logs or database rows.

## Live validation

1. Confirm blockers #1512, #1520, and #1527 are closed.
2. Run AI agent identities, agent runtime access, least privilege, and
   secret-permission equivalence with `fixture_state=success`.
3. Run the AI agent risk endpoint with `fixture_state=success` and confirm
   broad-tool, sensitive-capability, external-credential, runtime, and
   backing-role findings are ranked.
4. Filter by `risk_type=external_credential_exposure`, `agent_id`,
   `evidence=runtime-backed`, and `search` to verify deterministic drill-down.
5. Run `fixture_state=permission_denied`, `empty`, `degraded`, and
   `partial_failure` and confirm blocked/degraded states are explicit.
6. Confirm the AWS Runtime app panel renders success, empty, degraded,
   permission-denied, and partial-failure states without exposing payloads or
   secret values.
