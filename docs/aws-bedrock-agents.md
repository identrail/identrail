# AWS Bedrock Agents collector

Implements [#1506](https://github.com/identrail/identrail/issues/1506). This
collector extends the AWS AI agent identity model with first-class Bedrock
Agents coverage so operators can govern AWS-hosted agents as machine
identities.

The implementation is **read-only** and **metadata-only**. Instructions,
prompt overrides, completions, knowledge-base document contents, embeddings,
memory contents, browser pages, code-interpreter output, secret values, and
customer payloads are never collected.

## What this issue ships

- A deterministic Bedrock Agents collector in
  `internal/providers/aws/bedrock_agents_collector.go` that emits
  `AIAgentIdentity`-shaped raw assets so the merged Wave 4.01 AI agent
  identity model adapter consumes Bedrock records without any new normalization
  layer.
- A narrowly scoped `BedrockAgentsAPI` surface (`ListAgents` +
  `GetAgentDetail`) with bounded retry, pagination, and explicit per-agent
  partial-failure diagnostics so a single agent's detail failure never aborts
  the whole scan.
- A fixture-backed `FixtureBedrockAgentsAPI` (and a canonical
  `DefaultBedrockAgentsFixture`) in
  `internal/providers/aws/sdk_bedrock_agents.go` for local dev, contract
  tests, and the demo flow. The live SDK adapter slots in behind the same
  interface once the Bedrock SDK module is vetted.
- A project-scoped API at
  `GET /v1/workspaces/{workspace_id}/projects/{project_id}/aws/bedrock-agents`
  with `success`, `empty`, `degraded`, `partial_failure`, and
  `permission_denied` fixture states plus `agent_id`, `identity`, and
  `provider` filters. The response includes per-agent records (with tool /
  knowledge-base / guardrail / runtime-role context), graph relationships
  (`runs_with_role`, `uses_tool`, `uses_secret`, `reads_knowledge_base`),
  derived counts, coverage gaps, diagnostics, and an operator-facing next
  action.
- An app surface in `web/src/productShell.tsx` (`AWS → Agents`) that renders
  the validation status, agent count, tools, knowledge bases, guardrails,
  credential references, diagnostics, and coverage gaps next to the existing
  AI agent identity surface.

## AWS permissions required

The collector consumes the following read-only Bedrock actions. They are not
auto-granted by the read-only stack; operators add them to the connector role
when they are ready to expose Bedrock agent data.

- `bedrock:ListAgents`
- `bedrock:GetAgent`
- `bedrock:ListAgentActionGroups`
- `bedrock:ListAgentKnowledgeBases`
- `bedrock:ListAgentAliases`
- `bedrock:GetAgentAlias` (for alias ARNs only)
- `bedrock:GetGuardrail` (metadata only — never the guardrail policy text)

## What is intentionally not collected

- Agent instructions, prompt overrides, prompt configuration text.
- Action-group OpenAPI bodies, action-group Lambda payloads, action-group
  parameter values.
- Knowledge-base documents, embeddings, index data, or query text.
- Memory store contents.
- Customer payloads, secret values, or any data routed through Bedrock at
  runtime.

The collector reports two coverage gaps on every response so operators see
these boundaries inline:

| Capability                       | Status                       | Reason                                                                                                 |
| -------------------------------- | ---------------------------- | ------------------------------------------------------------------------------------------------------ |
| `prompt_and_completion_contents` | `intentionally_not_collected` | The collector reads metadata, role bindings, tool names, knowledge-base IDs, and guardrail IDs only.   |
| `knowledge_base_contents`        | `intentionally_not_collected` | Knowledge bases are linked by ID only; documents, embeddings, and index payloads stay in their owner.  |

## Record contract

Each `AWSBedrockAgentRecord` carries the AI agent identity fields plus Bedrock
specifics:

- `agent_id`, `agent_arn`, `agent_name`, `agent_type=bedrock_agent`,
  `provider=amazon-bedrock`, `model_id` (foundation model id).
- `runtime_role_arn`, `runtime_role_name`, `runtime_role_account_id`.
- `tool_names` (action group names), `tool_count`, derived
  `capability_names` (`tool_use`, `knowledge_base`, `foundation_model`,
  `guardrail`, `customer_encryption_kms`, `aliases`, `instruction_configured`,
  `prompt_override_configured`).
- `memory_store_refs` (`bedrock-knowledge-base/<id>` form),
  `memory_enabled=true` whenever ≥1 knowledge base is linked.
- `credential_reference_refs` for action-group executors
  (`action_group_executor:<arn>`) and customer encryption KMS keys
  (`kms:<arn>`). These stitch into the credential reference mapper (#1496)
  without any new edge type.
- `guardrail_id`, `agent_node_id`, `runtime_role_node_id`,
  `relationship_types`, `confidence`, `coverage_status`, `next_action`,
  `evidence_ref`, `collected_at`, `status`, `tags`.

The contract record (`awscontract.ServiceCollectorRecord`) is validated for
every fixture in CI, so the boundary stays compatible with downstream graph,
runtime, risk, and remediation pipelines.

## Live validation

1. Grant the read-only Bedrock permissions listed above to the connector role.
2. From the project AWS surface, open **AWS → Agents** once the connector is
   active. The Bedrock Agents panel renders alongside the AI agent identity
   panel.
3. Verify the validation status, target counts, agent table, recovery
   diagnostics, and remediation hints.
4. For partial-failure simulation, use the
   `fixture_state=partial_failure` query parameter; the response surfaces a
   per-agent `bedrock_agent_detail_failed` diagnostic and surviving agents
   remain authoritative.

## Runtime composition boundary (intentionally out of scope)

This PR ships the collector, its small `BedrockAgentsAPI` interface, the
`FixtureBedrockAgentsAPI`, and the project-scoped inventory API at
`GET .../aws/bedrock-agents`. The live aws-sdk-go-v2 adapter is deliberately
**not** introduced in this PR because the Bedrock SDK module is not yet vetted
in `go.mod`. The follow-up issue that wires the live adapter must also:

- add a case for `rawKindAIAgentIdentity` to `RoleNormalizer.Normalize` so the
  collector's raw assets are picked up during scans instead of being silently
  dropped; and
- compose `NewBedrockAgentsCollector(NewSDKBedrockAgentsAPI(...))` inside
  `internal/runtime/service_builder.go` alongside the other Wave 1 collectors.

Until then the collector is reachable only through the inventory API, which
consumes `RawAsset` payloads directly without going through the normalizer.

## Out of scope (next-wave issues)

- AgentCore Runtime, Gateway, and Memory collectors land in #1507–#1509.
- Custom-agent detection across non-Bedrock workloads lands in #1511.
- Runtime evidence ingestion for Bedrock agent tool calls lands in
  #1520.
- Live mutation of any Bedrock agent or guardrail is out of scope; the
  collector is read-only.
