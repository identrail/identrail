# AWS AI Agent Identities

Issue #1505 adds a normalized AI agent identity model for AWS machine-identity governance.

## What Is Collected

The model is metadata-only. Each `agent_identity` record can describe:

- Bedrock agents
- AgentCore runtimes
- custom AWS-hosted agents
- external-provider-backed agents
- agent gateways
- runtime IAM role ARN/name/account
- AgentCore runtime version, workload identity ARN, execution endpoints, observability links, network mode, and server protocol
- provider and model identifiers
- tool names and capability names
- memory/browser/code-interpreter capability flags
- credential-reference identifiers
- agent-to-endpoint `invokes` relationships for AgentCore runtime execution surfaces
- evidence references, confidence, account, region, connector, scan, workspace, and project context

The public API is:

`GET /v1/workspaces/{workspace_id}/projects/{project_id}/aws/ai-agent-identities`

Optional query parameters:

- `connector_id`
- `fixture_state=success|empty|degraded|partial_failure|permission_denied`

## What Is Not Collected

Identrail does not collect prompt text, completions, memory contents, browser pages, code-interpreter output, database rows, object contents, secret values, or customer payloads for this capability.

External AI provider credentials are represented as credential references only. The secret value remains hidden.

## Operator States

- `ready`: normalized agent metadata is available.
- `degraded`: some metadata is incomplete, but retained records remain visible.
- `blocked`: read-only metadata permission is missing.
- `empty`: the scan completed without AI agent records for the selected account and region.
- `partial_failure`: at least one agent sub-listing failed while other records remain usable.

## Permissions

Use metadata-only list and describe permissions for the relevant agent, runtime, gateway, and IAM-role surfaces. Do not grant invoke, prompt/session reads, memory-content reads, browser-output reads, code-output reads, database-row reads, object-content reads, or secret-value reads for this issue.

## UI Surface

The AWS Agents inventory page shows normalized agent rows, runtime role anchors, provider/model metadata, tools, credential-reference counts, confidence, diagnostics, sensitive-boundary coverage gaps, account/region context, and retry guidance.

## Troubleshooting

- Permission denied: grant the missing metadata-only list/describe actions, then retry the selected environment.
- Partial failure: retry the failed sub-listing and keep successful records visible.
- Unresolved credential reference: join to the credential-reference metadata surface for ownership and rotation, never to secret values.
- Empty result: confirm that the selected connector account and region actually hosts Bedrock, AgentCore, custom, external-provider-backed, or gateway agent resources.
- Missing runtime endpoints: confirm the runtime has published execution endpoints in the selected region and account.
