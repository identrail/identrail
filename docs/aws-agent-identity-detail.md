# AWS agent identity detail page

Issue #1550 adds the read-only detail surface for a single AWS AI agent
identity. It composes agent inventory, observed runtime tool calls, AI-agent
risk findings, least-privilege recommendations, remediation cases, governance
decisions, and graph relationships into one scoped response that backs the app
route `/app/{tenant_id}/{workspace_id}/aws/agents/detail`.

## API

`GET /v1/workspaces/{workspace_id}/projects/{project_id}/aws/agent-identity-detail`

Required query parameters:

- `agent`: agent ID, agent ARN, agent node id, or agent name to inspect.

Supported optional filters:

- `connector_id`
- `fixture_state`: `success`, `empty`, `degraded`, `partial_failure`, or `permission_denied`
- `account_id`
- `region`
- `tab`: `overview`, `tools`, `runtime`, `secrets`, `findings`, `recommendations`, `remediation`, or `governance`
- `tool`
- `resource`
- `severity`
- `status`

The response is returned as `{ "detail": ... }` and includes:

- tenant, workspace, project, connector, account, region, issue, version, status, confidence, and applied filters
- normalized agent metadata with provider, model, runtime role, gateway, account, region, confidence, and evidence boundary
- explicit candidate and low-confidence flags for inferred or unresolved agents
- tab counts for overview, tools, runtime, secrets, findings, recommendations, remediation, and governance
- declared and observed tools, memory/browser/code-interpreter capability metadata, and secret reference metadata
- runtime calls, risk findings, least-privilege recommendations, remediation cases, governance decisions, and graph relationships
- diagnostics, coverage gaps, failure reasons, remediation hints, and evidence links

## App behavior

The AWS agents inventory links agent rows to the detail route with the selected
environment and exact agent identifier. The detail page keeps the environment
selector active and reloads when the environment, agent, connector, or tab
changes.

The UI exposes eight tabs:

- `overview`: memory/browser/code-interpreter capabilities and graph relationships
- `tools`: declared tools, observed tools, and undeclared runtime observations
- `runtime`: observed agent/tool runtime calls
- `secrets`: provider-key and credential reference metadata
- `findings`: AI-agent risk findings
- `recommendations`: least-privilege recommendations for the agent or backing role
- `remediation`: read-only remediation case projections
- `governance`: advisory, approval, remediation, enforcement, and exception records for the agent or backing role; role-wide decisions stay visible, while agent-scoped decisions that belong to other agents sharing the backing role are excluded

The page also links to the broader AWS runtime, graph, remediation, and
governance surfaces so operators can move from the scoped agent view back to the
cross-agent evidence flows.

## Safety boundaries

The contract is read-only and metadata-only. It must not read, expose, log, or
persist secret values, prompt text, completions, tool payloads, browser pages,
code-interpreter output, database rows, customer object contents, or workload
data.

The response evidence boundary is
`metadata_only_no_secret_values_no_prompt_text_no_tool_payloads_no_workload_data_tenant_workspace_project_connector_account_region_scoped`.
Downstream collectors may contribute ARNs, names, ids, hashes, timestamps,
action names, capability flags, safe reference identifiers, and safe evidence
references, but not sensitive values or document bodies.

## Failure states

- `empty`: the selected scope has no matching evidence after collectors run.
- `degraded`: evidence exists, but one or more collectors returned partial or low-confidence data.
- `partial_failure`: at least one downstream capability failed while retained evidence remains visible.
- `permission_denied`: the selected connector lacks required read-only metadata permissions.
- `unknown`: the requested agent was not found in the AI-agent inventory and is shown as a candidate, low-confidence agent.

These states remain visible in the detail page through status panels,
diagnostics, coverage gaps, and remediation hints rather than being collapsed
into a successful view.
