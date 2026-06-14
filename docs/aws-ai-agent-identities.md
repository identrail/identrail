# AWS AI Agent Identities

Issue #1505 adds a normalized AI agent identity model for AWS machine-identity governance. Issue #1508 extends the same model with AgentCore Gateway and MCP tool mapping. Issue #1509 extends it again with AgentCore Memory, Browser, and Code Interpreter capability metadata mapping. Issue #1510 maps external AI provider key metadata onto agent identities without reading credential values. Issue #1511 detects custom AWS-hosted agents across existing workload metadata.

## What Is Collected

The model is metadata-only. Each `agent_identity` record can describe:

- Bedrock agents
- AgentCore runtimes
- custom AWS-hosted agents
- external-provider-backed agents
- agent gateways
- AgentCore capability surfaces (`agentcore_capability`) for Memory, Browser, and Code Interpreter resources, identified by `capability_kind` (`memory`, `browser`, `code_interpreter`)
- runtime IAM role ARN/name/account
- AgentCore runtime version, workload identity ARN, execution endpoints, observability links, network mode, and server protocol
- provider and model identifiers
- gateway auth mode, tool target references, allowed action names, tool names, and capability names
- memory/browser/code-interpreter capability flags
- per-capability execution role bindings, storage references (`storage_reference_refs` such as a browser recording `s3://bucket/prefix` destination or a memory stream-delivery resource count), customer encryption key ARN (`encryption_key_arn`), and network posture (`vpc`, `sandbox`, etc.)
- credential-reference identifiers
- classified external provider key references (`provider_key_references`) for OpenAI, Anthropic/Claude, Bedrock, and generic credential metadata
- custom-agent detector metadata (`custom-agent-detector-v1`) with candidate/confirmed confidence, detector signals, source workload family, and metadata-only evidence
- agent-to-endpoint `invokes` relationships for AgentCore runtime execution surfaces
- agent-to-tool `calls_tool` relationships for AgentCore Gateway and MCP tool surfaces
- an `agentcore_capability` resource node per Memory/Browser/Code Interpreter surface, linked to its agent identity, carrying the kind, storage references, encryption key, network mode, and execution role — but never the capability's contents
- evidence references, confidence, account, region, connector, scan, workspace, and project context

### AgentCore Memory / Browser / Code Interpreter mapping (issue #1509)

The capability adapter lists `ListMemories`, `ListBrowsers`, and `ListCodeInterpreters`, then describes each resource with `GetMemory` / `GetBrowser` / `GetCodeInterpreter`. It captures:

- **Memory**: id/ARN/name, status, event-expiry days, strategy names and types, encryption key ARN, memory execution role ARN, and the presence/count of stream-delivery resources. Memory records (the stored conversation/event data) are never read.
- **Browser**: id/ARN/name, status, execution role ARN, network mode and VPC posture (subnet/security-group counts only), recording enablement and the recording S3 destination reference, and enterprise-policy presence. Browser pages and recorded session content are never read.
- **Code Interpreter**: id/ARN/name, status, execution role ARN, and network mode/VPC posture. Code, inputs, and execution output are never read.

Inventory counts expose `capability_agent_count`, `memory_store_count`, `browser_count`, and `code_interpreter_count`. Per-resource describe failures degrade only that record (`coverage_status=degraded`) and emit a scoped `agentcore_memory_describe_failed` / `agentcore_browser_describe_failed` / `agentcore_code_interpreter_describe_failed` diagnostic without dropping the surviving capability records.

The public API is:

`GET /v1/workspaces/{workspace_id}/projects/{project_id}/aws/ai-agent-identities`

Optional query parameters:

- `connector_id`
- `fixture_state=success|empty|degraded|partial_failure|permission_denied`

### External AI provider key metadata mapping (issue #1510)

Agent records expose `provider_key_references` derived from safe names, ARNs, source markers, and workload references such as `OPENAI_API_KEY=secretsmanager:...` or `ANTHROPIC_API_KEY=ssm:...`. Each reference includes:

- provider classification (`openai`, `anthropic`, `bedrock`, `secretsmanager`, `ssm`, or `generic`)
- reference kind (`secrets_manager`, `ssm_parameter`, `environment_variable`, or `credential_reference`)
- sensitivity (`ai_provider_api_key`, `aws_managed_secret`, or `generic_secret`)
- evidence reference, target credential-reference node id, and confidence

Inventory aggregates include `external_provider_key_count`, `ai_provider_key_count`, and `provider_key_breakdown`, alongside the existing `credential_reference_count` and `uses_secret` relationships. These fields let operators filter and drill into provider-key ownership from the AWS Agents surface while keeping values hidden.

### Custom AWS-hosted agent detector (issue #1511)

The custom-agent detector runs over existing workload metadata from ECS, EKS, Lambda, EC2, SageMaker, Step Functions, and CodeBuild. It does not add new payload-reading AWS calls. It uses only metadata already collected by the workload collectors:

- workload names, ARNs, resource types, runtime names, handlers, descriptions, service-account names, and tags
- container image URIs and SageMaker image URIs
- environment variable names and secret/source reference names
- Step Functions service-integration resource identifiers and SageMaker storage/KMS references
- runtime role bindings, account, region, connector, scan, workspace, and project context

Detected workloads emit `custom_agent` records with:

- `status=ready` and `coverage_status=covered` when multiple strong signals confirm the custom agent
- `status=candidate` and `coverage_status=candidate` when metadata is suggestive but not strong enough to call confirmed
- `capability_names` including the detector version and safe signal categories such as `external_provider_key`, `container_image_signal`, `role_binding`, or `ai_runtime_metadata`
- `credential_reference_refs` for AI-provider key references such as OpenAI, Anthropic/Claude, and Bedrock provider keys
- graph `runs_as` edges to the runtime IAM role and `uses_secret` edges to credential-reference nodes when provider-key metadata is present

The detector intentionally does not infer tool names from opaque commands, prompt text, source code, logs, execution history, or object contents. Tool names remain populated only when an upstream metadata source provides explicit tool identifiers.

## What Is Not Collected

Identrail does not collect prompt text, completions, memory contents, browser pages, code-interpreter output, database rows, object contents, secret values, or customer payloads for this capability.

External AI provider credentials are represented as credential references only. The secret value remains hidden.

## Operator States

- `ready`: normalized agent metadata is available.
- `candidate`: custom-agent metadata is suggestive but not strong enough to mark confirmed.
- `degraded`: some metadata is incomplete, but retained records remain visible.
- `blocked`: read-only metadata permission is missing.
- `empty`: the scan completed without AI agent records for the selected account and region.
- `partial_failure`: at least one agent sub-listing failed while other records remain usable.

## Permissions

Use metadata-only list and describe permissions for the relevant agent, runtime, gateway target, IAM-role, and workload metadata surfaces. For the AgentCore Memory/Browser/Code Interpreter capability mapping, grant the read-only control-plane actions `bedrock-agentcore:ListMemories`, `bedrock-agentcore:GetMemory`, `bedrock-agentcore:ListBrowsers`, `bedrock-agentcore:GetBrowser`, `bedrock-agentcore:ListCodeInterpreters`, and `bedrock-agentcore:GetCodeInterpreter` (control-plane metadata only). Do not grant invoke, prompt/session reads, memory-content reads, browser-output reads, code-output reads, database-row reads, object-content reads, source-code reads, build-log reads, or secret-value reads for this issue. Inline MCP schemas are used only for declared tool names; S3-backed schemas are retained as references and are not fetched.

## UI Surface

The AWS Agents inventory page shows normalized agent rows, custom-agent candidates, runtime role anchors, provider/model metadata, Gateway/MCP tools, auth mode, allowed-action counts, external provider key counts, credential-reference counts, confidence, diagnostics, sensitive-boundary coverage gaps, account/region context, and retry guidance.

## Troubleshooting

- Permission denied: grant the missing metadata-only list/describe actions, then retry the selected environment.
- Partial failure: retry the failed sub-listing and keep successful records visible.
- Unresolved credential reference: join to the credential-reference metadata surface for ownership and rotation, never to secret values.
- Empty result: confirm that the selected connector account and region actually hosts Bedrock, AgentCore, custom, external-provider-backed, or gateway agent resources.
- Missing runtime endpoints: confirm the runtime has published execution endpoints in the selected region and account.
- Missing Gateway tools: confirm the gateway has targets, target describe permissions, and inline MCP/API tool metadata or schema references in the selected region and account.
