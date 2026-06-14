# AWS runtime event contract

Issue #1513 adds the metadata-only contract Identrail uses to show what AWS
machine identities did at runtime. It covers API calls, STS sessions, Secrets
Manager reads, KMS decrypt activity, S3 access metadata, and agent tool calls.

## API

`GET /v1/workspaces/{workspace_id}/projects/{project_id}/aws/runtime-events`

Supported filters:

- `connector_id`
- `fixture_state`: `success`, `empty`, `degraded`, `partial_failure`, or `permission_denied`
- `account_id`
- `region`
- `event_type`: `sts-session`, `api-call`, `secret-read`, `kms-decrypt`, or `agent-tool`
- `identity`
- `agent_id`
- `resource`
- `evidence`: `cloudtrail` or `agent-runtime`
- `owner`: `security`, `platform`, or `application`
- `status`: `observed`, `delayed`, or `permission-denied`

The response is returned as `{ "runtime": ... }` and includes:

- scoped account, region, connector, issue, version, status, confidence, and applied filters
- summary counts for event types, owners, identities, resources, sessions, and relationships
- event records with actor, session, action, target resource metadata, agent context, timestamp, confidence, evidence, and next action
- graph relationships from observed actors or agents to target resources
- explicit diagnostics, coverage gaps, failure reasons, and remediation hints

## Safety boundaries

The runtime contract is read-only and metadata-only. It must not read, expose,
log, or persist secret values, decrypted plaintext, object bodies, prompts,
completions, browser pages, code-interpreter output, database rows, or customer
payloads by default.

The fixture contract uses redacted resource identifiers and the
`metadata_only_no_payloads_no_secret_values` boundary so UI and API tests can
prove the safe shape without requiring live AWS credentials.

## Failure states

- `empty`: no runtime events matched the scoped account and region.
- `degraded`: runtime events were returned, but evidence is delayed or lower confidence.
- `partial_failure`: one runtime source failed while retained events remain visible.
- `permission_denied`: required metadata-only event lookup permissions are missing.

These states are explicit and are not treated as successful runtime coverage.
