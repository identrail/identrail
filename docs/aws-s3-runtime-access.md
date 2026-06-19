# AWS S3 runtime data access correlation

Issue #1519 adds a correlation layer that ties **observed** S3 read/write/list
runtime access back to the **static reachability** edges Identrail already
discovered (S3 bucket-policy `can_access` grants from #1488) and each bucket's
**exposure and sensitivity** classification. Without it, runtime evidence and
static reachability live in separate surfaces and an operator cannot tell
whether a machine identity actually exercised a grant, used access no modeled
grant explains, or holds a grant it never uses.

The correlation is **metadata-only and, for S3, never touches object keys or
object contents.** It operates on the already-redacted runtime-event
(#1513–#1517) and S3 reachability (#1488) contracts. Object keys are redacted
into bounded, sanitized "safe prefixes" before they reach the engine; access is
correlated at **bucket granularity**.

## What it correlates

For each `(identity, bucket)` pair the engine
(`internal/runtime/s3access`) joins:

- **Observed access** — S3 runtime events (`EventSource s3.amazonaws.com`),
  keyed by actor identity node and bucket ARN, reduced to read / write / list
  access modes.
- **Static grants** — S3 bucket-policy grants for real IAM principals, with the
  allowed modes derived from the grant's actions, plus the bucket's exposure and
  sensitivity tier.

## Correlation statuses

| Status | Meaning | Confidence |
|---|---|---|
| `confirmed` | Observed access **and** a static allow grant exist. | 0.95 (capped to 0.85 on unresolved lineage; −0.05 conditional; capped to 0.8 when an observed mode exceeds the grant) |
| `observed_without_grant` | Observed but no static allow edge explains it. Most S3 access is authorized by IAM **identity** policies, which this wave's static collector does not enumerate, so this means "needs IAM-policy confirmation", not automatically drift. | 0.6 |
| `granted_unused` | A static allow grant exists but no access was observed in the window. | 0.7, reduced to 0.5 when data-event coverage is unknown |

### Caveats

Stable caveat codes attached to correlations or the result:

- `runtime_data_events_may_be_incomplete` — S3 `GetObject`/`PutObject`/
  `ListBucket` are CloudTrail **data** events. Unless an S3 data-event trail or
  CloudTrail Lake is configured, observed coverage is incomplete and
  `granted_unused` may reflect missing telemetry. **Absence of evidence is not
  evidence of absence.**
- `observed_mode_exceeds_grant` — the bucket is reachable, but an observed mode
  (e.g. write) is not authorized by the static grant (e.g. read-only) — genuine
  drift worth investigating.
- `no_static_reachability_edge` — observed access with no modeled grant.
- `observed_despite_explicit_deny` — observed access against a bucket carrying an
  explicit `Deny` for the identity.
- `sensitive_bucket_publicly_or_cross_account_exposed` — a sensitive bucket that
  is also publicly or cross-account exposed, raising the stakes of the access.
- `static_grant_is_conditional` / `static_grant_is_cross_account` /
  `session_lineage_unresolved`.

## API

`GET /v1/workspaces/{workspace_id}/projects/{project_id}/aws/s3-runtime-access`

Query parameters:

- `connector_id` — scope the account, region, and read-only runtime evidence.
- `fixture_state` — `success` (default), `empty`, `degraded`,
  `partial_failure`, `permission_denied`.
- `delivery_source` — `lookup_events`, `s3`, `eventbridge`, or `all`.
  **Defaults to `all`.** S3 read/write/list are CloudTrail data events that the
  LookupEvents API does not index, so the correlation fans out across every
  wired delivery channel; `lookup_events` alone will not observe these accesses.
- `account_id`, `region` — scope filters.
- `identity` — actor principal / identity-node search.
- `agent_id` — agent ID / agent-node search.
- `resource` — bucket ARN, name, or resource-node search.
- `access_mode` — `read`, `write`, or `list` (matches observed or granted modes).
- `sensitivity` — bucket sensitivity tier (e.g. `standard`, `elevated`, `high`).
- `exposure` — bucket exposure (e.g. `private`, `restricted`, `cross_account`,
  `public`).
- `status` — `confirmed`, `observed_without_grant`, or `granted_unused`.

The response (`AWSS3RuntimeAccessResult`) carries one record per correlation with
the status, confidence, observed access modes, granted modes, safe prefixes,
exposure/sensitivity, caveats, evidence references, and a graph relationship
(`confirmed_runtime_access`, `observed_runtime_access_without_grant`, or
`unused_static_grant`) joining back to the identity and bucket nodes. It also
returns a summary, coverage gaps, diagnostics, and the `ready` / `degraded` /
`blocked` status.

## Live vs fixture

Live composition is attempted when the connector is active and healthy, the
operator did not pin a `fixture_state`, the connector's effective capability set
includes `runtime_evidence`, and the CloudTrail factory for the selected source
is wired (the **delivery** factory carries the data events). In that case the
handler composes runtime-events (driven through the resolved `delivery_source`)
and S3 bucket reachability and joins their results; the reachability reader is
fixture-shaped today, so live mode forces an empty static state to avoid
joining real observed events to synthetic grants. When the connector is healthy
but no delivery factory is wired, the endpoint returns an explicit
delivery-unavailable degraded state rather than serving fixtures as if they were
live. Otherwise it returns the deterministic correlation fixtures, which
exercise all statuses (including a write that exceeds a read-only grant and a
sensitive, cross-account-exposed bucket).

## AWS permissions

This capability adds **no** new AWS permissions. It reuses the read-only,
metadata-only permissions the runtime-events (`cloudtrail:LookupEvents` and
optional delivery-channel reads) and S3 bucket reachability collectors already
require. No `s3:GetObject` or any other object-content permission is requested or
used.

## Intentionally not collected / not modeled

- **Object keys and object contents.** Never collected. Access is correlated at
  bucket granularity; only a bounded, sanitized top-level prefix is surfaced,
  and identifying prefixes (UUIDs, long/hex tokens, anything not a plain folder
  name) are redacted to `<redacted>`.
- **IAM identity-policy reachability.** Static reachability is sourced from S3
  bucket policies only, so an observed access can correctly show as
  `observed_without_grant`.
- **Data-event completeness.** Without an S3 data-event trail, `granted_unused`
  conclusions are advisory.

## Live validation and troubleshooting

1. Confirm the connector is active and healthy and has the `runtime_evidence`
   capability and a wired CloudTrail delivery channel.
2. Query the endpoint with no `fixture_state`. A `blocked` status with a
   `permission_denied` diagnostic means CloudTrail access is missing. A
   `degraded` status with a `delivery_unavailable` gap means no delivery channel
   is wired for the data events.
3. A `data_event_completeness` coverage gap with `granted_unused` correlations
   usually means S3 data events are not enabled — enable them before treating
   `granted_unused` as a least-privilege finding.
4. `observed_without_grant` correlations are expected when access is authorized
   by IAM identity policies — confirm the identity policy before treating them as
   drift.
