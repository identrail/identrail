# AWS agent runtime / tool-call access correlation

Issue #1520 adds a correlation layer that ties **observed** agent runtime /
tool-call events back to the static **AI-agent inventory** Identrail already
discovered (#1512: declared agents, their backing runtime role, and their
declared tools). Without it, runtime evidence and the agent inventory live in
separate surfaces and an operator cannot tell whether an agent actually
exercised a declared tool, ran a tool it never declared, or is a shadow agent
not in the inventory at all.

The correlation is **metadata-only**. It never reads, logs, or persists
prompts, completions, tool inputs/outputs, browser pages, code-interpreter
output, or any other customer payload — only the already-redacted
runtime-event (#1513) and agent-inventory (#1512) metadata.

## What it correlates

For each `(agent, tool)` pair the engine
(`internal/runtime/agentaccess`) joins:

- **Observed tool-calls** — `agent-tool` runtime events, keyed by agent node id
  and tool name, with the backing role (the machine identity that ran the
  agent), target resource, and outcome.
- **Declared tools** — the agent inventory's declared tools per agent, with the
  agent's declared backing runtime role.

## Correlation statuses

| Status | Meaning | Confidence |
|---|---|---|
| `confirmed` | The agent and tool are declared in the inventory **and** a tool-call was observed. | 0.95 (capped to 0.85 on unresolved lineage; capped to 0.8 on backing-role mismatch) |
| `observed_without_declaration` | A tool-call was observed for an agent not in the inventory (**shadow agent**) or for a tool the agent does not declare (**undeclared tool**). | 0.6 |
| `declared_unused` | The agent declares the tool but no tool-call was observed in the window. | 0.7, reduced to 0.5 when tool-call telemetry coverage is unknown |

### Caveats

Stable caveat codes attached to correlations or the result:

- `agent_tool_telemetry_may_be_incomplete` — agent tool-call telemetry is not
  guaranteed complete from the available runtime sources, so `declared_unused`
  may reflect missing telemetry. **Absence of evidence is not evidence of
  absence.**
- `agent_not_in_inventory` — a shadow agent: a tool-call from an agent not in
  the inventory.
- `tool_not_declared_by_agent` — a known agent invoking a tool it does not
  declare.
- `observed_backing_role_differs_from_declared` — the observed backing role
  differs from the agent's declared runtime role (privilege drift).
- `observed_tool_call_failed` — a failed tool-call outcome was observed.
- `agent_inventory_unavailable_for_confirmation` — the inventory could not be
  loaded, so an observed tool-call is surfaced neutrally rather than being
  mislabeled as a shadow agent.
- `session_lineage_unresolved`.

## API

`GET /v1/workspaces/{workspace_id}/projects/{project_id}/aws/agent-runtime-access`

Query parameters: `connector_id`, `fixture_state` (`success` default, `empty`,
`degraded`, `partial_failure`, `permission_denied`), `delivery_source`
(`lookup_events` / `s3` / `eventbridge` / `all`, **defaults to `all`** because
agent tool-call telemetry arrives as data events LookupEvents does not index),
`account_id`, `region`, `identity` (backing role), `agent_id`, `tool`,
`resource`, `outcome` (`succeeded` / `failed` / `unknown`), and `status`.

The response (`AWSAgentRuntimeAccessResult`) carries one record per `(agent,
tool)` correlation with the status, confidence, backing roles, declared backing
role, target resources, outcomes, caveats, evidence references, and graph
relationships (`confirmed_agent_tool_call`,
`observed_tool_call_without_declaration`, `unused_declared_tool`, and
`agent_tool_targeted_resource`) joining back to the identity, agent, and
resource nodes. It also returns a summary, coverage gaps, diagnostics, and the
`ready` / `degraded` / `blocked` status.

## Live vs fixture

Live composition is attempted when the connector is active and healthy, the
operator did not pin a `fixture_state`, the connector's effective capability set
includes `runtime_evidence`, and the CloudTrail delivery factory is wired. In
that case the handler composes runtime-events (driven through the resolved
`delivery_source`) and the AI-agent inventory. The inventory reader is
fixture-shaped today, so live mode forces an empty inventory and reports it as
unavailable — the engine then surfaces observed tool-calls with the neutral
`agent_inventory_unavailable_for_confirmation` caveat rather than mislabeling
real agents as shadow agents. When the connector is healthy but no delivery
factory is wired, the endpoint returns an explicit delivery-unavailable degraded
state. Otherwise it returns the deterministic correlation fixtures, which
exercise all statuses (including a shadow agent, an undeclared tool, a
backing-role mismatch, and a failed tool-call).

## AWS permissions

This capability adds **no** new AWS permissions. It reuses the read-only,
metadata-only permissions the runtime-events (`cloudtrail:LookupEvents` and
optional delivery-channel reads) and AI-agent inventory collectors already
require. No prompt, completion, or tool-payload read is requested or used.

## Intentionally not collected / not modeled

- **Prompts, completions, tool inputs/outputs, browser pages, code-interpreter
  output.** Never collected. Only metadata (agent, tool, backing role, target
  resource) is correlated.
- **Explicit tool-call outcomes.** Live success/failure outcomes are not yet
  extracted from the runtime sources (it requires error-code extraction in the
  ingestion layer), so live outcomes are reported as `unknown` with a coverage
  gap.
- **IAM identity-policy reachability** of the backing role is out of scope; this
  correlation compares observed agents/tools against the agent inventory only.

## Live validation and troubleshooting

1. Confirm the connector is active and healthy, has the `runtime_evidence`
   capability, and a wired CloudTrail delivery channel.
2. Query the endpoint with no `fixture_state`. A `blocked` status with a
   `permission_denied` diagnostic means CloudTrail access is missing; a
   `degraded` status with a `delivery_unavailable` gap means no delivery channel
   is wired for the data events.
3. `observed_without_declaration` with `agent_not_in_inventory` flags a shadow
   agent worth urgent review; with `tool_not_declared_by_agent` it flags a known
   agent using an undeclared tool.
4. `observed_backing_role_differs_from_declared` flags an agent running under a
   different role than the inventory declares — investigate before trusting the
   tool-call.
