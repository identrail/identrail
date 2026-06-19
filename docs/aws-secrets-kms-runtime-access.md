# AWS Secrets Manager / KMS runtime access correlation

Issue #1518 adds a correlation layer that ties **observed** Secrets Manager
read and KMS decrypt runtime events back to the **static reachability**
edges Identrail already discovered. Without it, runtime evidence and static
reachability live in separate surfaces and an operator cannot tell whether a
machine identity actually exercised a grant, used access that no modeled
grant explains, or holds a grant it never uses.

The correlation is **metadata-only**. It never reads, logs, or persists
secret values, decrypted plaintext, encryption-context values, or any other
customer payload. It operates entirely on the already-redacted runtime-event
(#1513–#1517) and reachability (#1489 KMS, #1490 Secrets Manager) contracts.

## What it correlates

For each `(identity, resource)` pair the engine
(`internal/runtime/secretsaccess`) joins:

- **Observed access** — `secret-read` and `kms-decrypt` records from the
  runtime event contract, keyed by actor identity node and target resource
  ARN.
- **Static grants** — KMS key-policy / KMS grant `can_decrypt` edges and
  Secrets Manager resource-policy `GetSecretValue` grants for real IAM
  principals (wildcard and non-IAM principals are dropped because they have
  no identity node to join against).

## Correlation statuses

| Status | Meaning | Confidence |
|---|---|---|
| `confirmed` | Observed access **and** a static allow grant exist. Behavior matches policy. | 0.95 (capped to 0.85 when session lineage is unresolved; −0.05 when the grant is conditional). |
| `observed_without_grant` | Access was observed but no static allow edge explains it. Most Secrets Manager access is authorized by IAM **identity** policies, which this wave's static collectors do not enumerate, so this means "needs IAM-policy confirmation", not automatically drift. | 0.6 |
| `granted_unused` | A static allow grant exists but no access was observed in the window. Surfaces over-provisioned grants. | 0.7, reduced to 0.5 when data-event coverage is unknown. |

### Caveats

Each correlation and the result envelope carry stable caveat codes so the
UI and downstream consumers can branch without string-matching prose:

- `runtime_data_events_may_be_incomplete` — Secrets Manager `GetSecretValue`
  and KMS `Decrypt` are CloudTrail **data** events. Unless a data-event
  trail or CloudTrail Lake is configured, observed coverage is incomplete
  and `granted_unused` may reflect missing telemetry rather than a truly
  unused grant. **Absence of evidence is not evidence of absence.**
- `no_static_reachability_edge` — observed access with no modeled grant.
- `observed_despite_explicit_deny` — observed access against a resource that
  carries an explicit `Deny` for the identity; review the condition scoping.
- `static_grant_is_conditional` / `static_grant_is_cross_account` — the
  corroborating grant is condition-scoped or cross-account.
- `session_lineage_unresolved` — the observed event's STS lineage was
  `source_identity_missing` or `ambiguous`.

## API

`GET /v1/workspaces/{workspace_id}/projects/{project_id}/aws/secrets-kms-runtime-access`

Query parameters:

- `connector_id` — scope the account, region, and read-only runtime
  evidence to one AWS connector.
- `fixture_state` — `success` (default), `empty`, `degraded`,
  `partial_failure`, `permission_denied` for deterministic UI validation.
- `delivery_source` — `lookup_events`, `s3`, `eventbridge`, or `all`.
  **Defaults to `all`.** Secrets Manager `GetSecretValue` and KMS `Decrypt`
  are CloudTrail *data* events that the LookupEvents API does not index, so
  the correlation defaults to fanning out across every wired delivery
  channel (and deduping by `EventID`); `lookup_events` alone will not
  observe these accesses.
- `account_id`, `region` — scope filters.
- `identity` — actor principal / identity-node search.
- `agent_id` — agent ID / agent-node search.
- `resource` — secret/key ARN, name, or resource-node search.
- `resource_kind` — `secret` or `kms_key`.
- `status` — `confirmed`, `observed_without_grant`, or `granted_unused`.

The response (`AWSSecretsKMSRuntimeAccessResult`) carries one record per
correlation with the status, confidence, observed-event IDs, static
sources, caveats, evidence references, and a graph relationship
(`confirmed_runtime_access`, `observed_runtime_access_without_grant`, or
`unused_static_grant`) that joins the correlation back to the identity and
resource nodes. It also returns a summary, coverage gaps, diagnostics, and
the `ready` / `degraded` / `blocked` status with explicit failure reasons.

## Live vs fixture

Live composition is attempted when the connector is active and healthy, the
operator did not pin a `fixture_state`, the connector's effective capability
set includes `runtime_evidence`, and at least one CloudTrail ingestion
factory (LookupEvents **or** delivery) is wired. The delivery factory is the
load-bearing one because it carries the data events. In that case the
handler composes the runtime-events (driven through the resolved
`delivery_source`), KMS decrypt reachability, and Secrets Manager metadata
services and joins their results. Otherwise it returns the deterministic
correlation fixtures, which exercise all three statuses (including a
cross-account `granted_unused`).

## AWS permissions

This capability adds **no** new AWS permissions. It reuses the read-only,
metadata-only permissions the runtime-events (`cloudtrail:LookupEvents` and
optional delivery-channel reads), KMS reachability, and Secrets Manager
metadata collectors already require. No `secretsmanager:GetSecretValue`,
`kms:Decrypt`, or any other payload/secret-value/plaintext permission is
requested or used.

## Intentionally not collected / not modeled

- **IAM identity-policy reachability.** Static reachability is sourced from
  KMS key policies / grants and Secrets Manager resource policies only.
  Access authorized by IAM identity policies is not enumerated, so an
  observed read can correctly show as `observed_without_grant`.
- **Data-event completeness.** Without a data-event trail, `granted_unused`
  conclusions are advisory; enable CloudTrail data events for Secrets
  Manager and KMS to make them reliable.
- **Secret values, decrypted plaintext, encryption-context values,** and any
  other customer payload are never read.

## Live validation and troubleshooting

1. Confirm the connector is active and healthy and has the
   `runtime_evidence` capability.
2. Query the endpoint with no `fixture_state`. A `blocked` status with a
   `permission_denied` diagnostic means CloudTrail access is missing —
   grant metadata-only `cloudtrail:LookupEvents`; do **not** grant
   secret-value or decrypt reads.
3. A `degraded` status with a `data_event_completeness` coverage gap and
   `granted_unused` correlations usually means CloudTrail data events are
   not enabled for Secrets Manager / KMS. Enable them before treating
   `granted_unused` as a least-privilege finding.
4. `observed_without_grant` correlations are expected when access is
   authorized by IAM identity policies — confirm the identity policy before
   treating them as drift.
