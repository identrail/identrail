# AWS runtime event contract

Issue #1513 adds the metadata-only contract Identrail uses to show what AWS
machine identities did at runtime. It covers API calls, STS sessions, Secrets
Manager reads, KMS decrypt activity, S3 access metadata, and agent tool calls.

Issue #1514 wires real CloudTrail `LookupEvents` ingestion behind the same
contract. When an AWS connector is active and healthy and the operator has
not pinned a `fixture_state`, the API drives a bounded
`internal/runtime/cloudtrail.Ingester` instead of the fixture path. The
response shape is identical so operator UI, filters, evidence links, and
graph relationships behave the same whether the data came from CloudTrail or
the fixture.

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

## CloudTrail LookupEvents ingestion (#1514)

Live ingestion is implemented in `internal/runtime/cloudtrail` and wired
into `internal/api.Service.AWSCloudTrailLookupEventsFactory`. The factory
is invoked once per request when the connector is active and healthy and
no explicit `fixture_state` was supplied. The fixture path remains the
fallback for tests, demos, and any connector that is not currently live.

### Required AWS permissions

The connector role must grant exactly:

- `cloudtrail:LookupEvents` on `*`

Identrail never grants or requests payload, secret-value, decrypt, or
object-body permissions. CloudTrail's `LookupEvents` already surfaces
`CloudTrailEvent` JSON containing `requestParameters` and
`responseElements`; the ingester deliberately ignores both. The
allow-listed extraction is restricted to: `awsRegion`,
`recipientAccountId`, `sourceIPAddress`, `userAgent`, and a small subset
of `userIdentity` metadata (`type`, `arn`, `principalId`, and
`sessionContext.attributes.creationDate` /
`sessionContext.sessionIssuer.arn`).

### What LookupEvents can (and can't) surface

CloudTrail's `LookupEvents` API only searches **management events** (and
Insights events when explicitly requested). AWS classifies high-volume
data-plane activity as **data events**, which are not indexed by
`LookupEvents` and require a separate CloudTrail trail with data-event
selectors (or CloudTrail Lake).

| Runtime event type | Source | Reaches `LookupEvents`? |
|---|---|---|
| `sts-session` (AssumeRole/GetSessionToken/GetFederationToken) | `sts.amazonaws.com` | ✓ Management |
| `secret-read` (GetSecretValue, BatchGetSecretValue) | `secretsmanager.amazonaws.com` | ✓ Management |
| `kms-decrypt` (Decrypt, GenerateDataKey, ReEncrypt) | `kms.amazonaws.com` | ✓ Management |
| `api-call` (control-plane API operations) | various | ✓ Management |
| `api-call` (S3 `GetObject`, Lambda `Invoke`, DynamoDB item reads) | `s3.amazonaws.com`, `lambda.amazonaws.com`, `dynamodb.amazonaws.com` | ✗ Data event |
| `agent-tool` (Bedrock `InvokeAgent` / AgentCore tool calls) | `bedrock-agent.amazonaws.com`, `bedrock-agentcore.amazonaws.com` | ✗ Data event |

For the data-event rows, the ingester does not advertise live coverage
through this code path. The fixture contract retains those event types
so the API/UI surface stays stable; wiring CloudTrail Lake or a
data-events trail to populate them is a separate capability tracked
outside this PR.

### Bounded budgets

Each ingestion run enforces:

| Budget | Default | Purpose |
|---|---|---|
| `LookbackWindow` | 90 minutes (clamped to ≤ 90 days) | Window of CloudTrail history scanned per run. |
| `MaxPages` | 20 | Caps paginated `LookupEvents` calls per run. |
| `MaxEvents` | 1000 | Caps total events ingested across all pages. |
| `MaxThrottleRetries` | 4 | Retries one page after `ThrottlingException`. |
| `ThrottleBackoff` | 200 ms × attempt | Linear backoff sleep between throttle retries. |
| `PageSize` | 50 (CloudTrail max) | `LookupEvents.MaxResults`. |

When ingestion stops because of `MaxPages`/`MaxEvents`, the response
gains a `history_truncated` coverage gap and a `degraded` status. When
`AccessDeniedException` is observed on any page, the response collapses
to `status=blocked`, drops every record from the partial run, and
attaches a `permission_denied` coverage gap with the metadata-only
remediation hint. Throttling exhaustion and other transient errors are
recorded as `cloudtrail_lookup_events_throttled` or
`cloudtrail_lookup_events_failed` diagnostics; previously-ingested
events on earlier pages are preserved so the response is at worst
`degraded`, never `blocked`.

### Filter pushdown

When the request specifies a typed `event_type` filter
(`secret-read`, `kms-decrypt`, `sts-session`, `agent-tool`), the API
pushes the corresponding CloudTrail `EventSource` attribute into
`LookupEvents` so CloudTrail does the heavy filtering and Identrail
ingests only the events it needs. Other filters
(`identity`, `agent_id`, `resource`, `evidence`, `owner`, `status`,
`account_id`, `region`) are applied to the normalized records.

### Live validation

Hit the runtime events endpoint
(`GET /v1/workspaces/{workspace_id}/projects/{project_id}/aws/runtime-events?connector_id={connector_id}`)
and inspect `.runtime.status`, `.runtime.fixture_state`,
`.runtime.summary`, and `.runtime.diagnostics`.

A live `ready` response carries `fixture_state=success` and a
`total_events` count derived from CloudTrail. A `permission_denied`
response means the role policy is missing
`cloudtrail:LookupEvents`. A `history_truncated` coverage gap means the
window covered more events than the per-run budget; narrow the
`event_type` filter or raise budgets in a future release.
