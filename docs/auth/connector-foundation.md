# Connector Foundation

Every connector in Identrail (AWS, Kubernetes, GitHub, future ones) shares one Go interface, one status state machine, and one error taxonomy. PR 6 ships this foundation. PRs 7, 8, 9 fill it in for the three providers. Future connectors implement the same shape.

This is a contract document, not an API doc. It describes what every connector promises to look like.

## The Provider Interface

```go
package connectors

type Provider interface {
    // Init is called once when a connector is created in the database.
    // The provider receives whatever per-provider config the user supplied.
    Init(ctx context.Context, cfg Config) error

    // Validate runs a probe against the upstream provider to confirm the
    // credentials work and the expected permissions exist. It is called
    // after Init and again whenever credentials are refreshed.
    Validate(ctx context.Context) (*ValidationResult, error)

    // Scan executes one scan run. The contract is that Scan is idempotent
    // and can be retried without harm.
    Scan(ctx context.Context, opts ScanOptions) (*ScanResult, error)

    // Health returns the current health snapshot. Called every 5 minutes
    // by the heartbeat job and on demand by /v1/connectors/:id/health.
    Health(ctx context.Context) (*HealthStatus, error)

    // Disconnect tears down the connector cleanly. The provider should
    // revoke any agent credentials, clear remote webhooks where possible,
    // and leave no dangling state on the upstream.
    Disconnect(ctx context.Context) error
}
```

Five methods. Every method takes a context. Every method returns a typed error from the taxonomy below.

## Status State Machine

The state model has two parts that work together:

1. A **lifecycle status** persisted in `tenancy_connectors.status`, which is one of `pending`, `active`, `degraded`, or `disconnected` at any moment. These are the four values the existing CHECK constraint already allows (see `migrations/000013_connectors_state_scan_policies.up.sql`), so PR 6 does not need to widen that constraint.
2. A separate `disabled BOOLEAN NOT NULL DEFAULT FALSE` column added in PR 6, orthogonal to the lifecycle status. An admin pause sets this flag to true; resume clears it. The lifecycle status keeps its previous value while paused, which is why `disabled` is a flag and not a status.
3. A **transient in-memory state** called `validating`. It is not persisted. While `Validate()` is running for a connector, in-process code remembers it is validating; if the process dies mid-validation, the row is still recorded as `pending` and the next attempt restarts cleanly.

Specific connectors do not invent their own lifecycle values.

```
              create
                │
                ▼
            ┌────────┐
            │pending │ (also re-entered if a prior validation aborted)
            └───┬────┘
                │ user provides credentials
                │ (Validate runs in-process; transient "validating" state)
                ▼
            ┌────────┐
            │ active │ ◄───────┐
            └───┬────┘         │
                │              │
        scan or │              │ next scan or health succeeds
        health  │              │
        fails   ▼              │
            ┌─────────┐        │
            │degraded │────────┘
            └────┬────┘
                 │ credentials invalid or
                 │ revoked, or extended outage
                 ▼
            ┌──────────────┐
            │disconnected  │
            └──────────────┘

The disabled flag is orthogonal to the diagram. It can be set or cleared
on any row whose lifecycle status is pending, active, or degraded. It is
not set on disconnected rows.
```

Lifecycle status definitions:

| Status | Meaning |
| --- | --- |
| `pending` | Database row exists; no credentials yet (or a previous validation aborted). The user has not finished the connect flow. |
| `active` | Validated, scanning normally, last health check passed. |
| `degraded` | Last scan or health check failed; credentials are still believed valid. Auto-recovers when the next attempt succeeds. |
| `disconnected` | Credentials are invalid, revoked, or the provider has been unreachable for 6+ hours. Requires user action. |

The `disabled` flag is read alongside the lifecycle status. A connector with `status='active'` and `disabled=true` is treated as paused: heartbeat skips it, scheduled scans do not run, and the UI shows it as paused.

Transition events:

| From | Event | To |
| --- | --- | --- |
| pending | credentials submitted, Validate succeeds | active |
| pending | credentials submitted, Validate fails | disconnected |
| active | scan or health failure with code `auth_failed` or `permission_denied` | disconnected (immediate; the credentials are revoked or scope-broken, not transiently degraded) |
| active | scan or health failure with any other taxonomy code | degraded |
| degraded | next scan or health succeeds | active |
| degraded | 6+ hours since last success | disconnected |
| degraded | scan or health failure with code `auth_failed` or `permission_denied` | disconnected (escalates immediately) |
| pending, active, or degraded | `disabled` set true | flag flips; lifecycle status unchanged |
| disabled (flag) | `disabled` cleared | flag flips; lifecycle status unchanged |
| disconnected | `disabled` set true | rejected with 409; the connector must be reconnected first |
| any | user disconnect | disconnected; the API also clears `disabled` to false in the same write so the disconnected-and-not-disabled invariant holds. The row stays in place for audit (see "Disconnect Semantics" below) |

Every transition emits an audit event: `connector.<provider>.state.<from>_to_<to>` for lifecycle changes, `connector.<provider>.disabled.set` and `connector.<provider>.disabled.cleared` for the flag. Each event includes the reason (last error code, last error message).

## Error Taxonomy

Connectors do not invent error codes. Every operational error maps to one of seven taxonomy codes. The UI knows how to render help text for each code; new codes mean new UI work, not a new connector.

| Code | When | Example |
| --- | --- | --- |
| `auth_failed` | Provider credentials are missing, expired, or rejected | AWS `sts:AssumeRole` returns ExpiredToken |
| `permission_denied` | Credentials work, but lack the required scope | AWS role exists but cannot read IAM |
| `network_error` | Transient connectivity failure | DNS failure, TCP timeout |
| `provider_unavailable` | Upstream returned 5xx or is otherwise broken | AWS region degraded, GitHub status page red |
| `rate_limited` | Upstream is throttling us | GitHub secondary rate limit, AWS API throttling |
| `quota_exceeded` | Customer's account has hit a non-throttle limit | GitHub plan rate cap, AWS service quota |
| `invalid_config` | Configuration is structurally wrong | Kubeconfig has unparseable YAML |

Errors are returned as a typed Go struct:

```go
type ConnectorError struct {
    Code    string // one of the taxonomy codes above
    Message string // human-readable, safe to surface in UI
    Cause   error  // wrapped underlying error, server-side only
}
```

Code is shipped to the frontend; Cause is logged server-side and never crosses the API boundary.

## Health Endpoint Contract

Every connector exposes the same health shape via `GET /v1/connectors/:id/health`:

```json
{
  "connector_id": "uuid",
  "lifecycle_status": "pending|active|degraded|disconnected",
  "disabled": false,
  "validating": false,
  "last_success_at": "2026-05-10T14:23:01Z",
  "last_failure_at": "2026-05-10T14:18:00Z",
  "last_error": {
    "code": "rate_limited",
    "message": "GitHub API rate limit hit; retrying after 2 minutes"
  },
  "scan_count_last_24h": 14,
  "next_scheduled_scan_at": "2026-05-10T15:00:00Z"
}
```

The three orthogonal pieces:

- `lifecycle_status` is the persisted value from `tenancy_connectors.status`. One of four values that match the existing CHECK constraint.
- `disabled` is the persisted boolean from the new `tenancy_connectors.disabled` column. True when an admin has paused the connector.
- `validating` is true only while a `Provider.Validate()` call is currently in flight in this server process. It is reported here for UI feedback during the connect flow; it is not stored in the database.

`last_error` is null if there has been no recent failure. `next_scheduled_scan_at` is null for connectors that scan only on demand.

## Heartbeat Job

A scheduled job runs every 5 minutes and calls `Health()` on every connector in `active` or `degraded` lifecycle status whose `disabled` flag is false. The result drives state transitions per the state machine.

| Condition | Action |
| --- | --- |
| Connector active, health succeeds | No transition. Update `last_successful_sync_at`. |
| Connector active, health fails with code `auth_failed` or `permission_denied` | Transition to `disconnected` immediately. Record error. |
| Connector active, health fails with any other taxonomy code | Transition to `degraded`. Record error. |
| Connector degraded, health succeeds | Transition to `active`. Clear last error. |
| Connector degraded, health fails with code `auth_failed` or `permission_denied` | Transition to `disconnected` immediately. Record error. |
| Connector degraded, > 6 hours since `last_successful_sync_at` | Transition to `disconnected`. Notify admins. |
| Connector disconnected | No probing. Heartbeat skips this connector. |
| Connector disabled (flag) | No probing. Heartbeat skips this connector. |

The heartbeat job is idempotent and rate-limited to prevent floods if many connectors fail simultaneously.

## Per-Connector Storage

The shared `tenancy_connectors` table holds the row that represents each connector. Provider-specific non-secret configuration lives in `tenancy_connectors.config` (`JSONB`). Sensitive credentials live in `tenancy_connector_secret_envelopes`, encrypted at rest.

`tenancy_connectors` columns relevant here:

| Column | Notes |
| --- | --- |
| `tenant_id`, `workspace_id`, `project_id`, `connector_id` | Compound primary key (existing schema). |
| `type` | `aws`, `kubernetes`, `github` (existing CHECK constraint). |
| `status` | One of `pending`, `active`, `degraded`, `disconnected` (existing CHECK constraint). |
| `disabled` | `BOOLEAN NOT NULL DEFAULT FALSE`. Added in PR 6 as a separate column from `status`. |
| `config` | `JSONB NOT NULL DEFAULT '{}'::jsonb`. Added in PR 6 for provider-specific non-secret settings (for example GHES base URL, selected repo IDs, or kubeconfig mode). |
| `display_name` | User-facing label. |
| `config_checksum` | Used to detect config changes. |
| `created_at`, `updated_at` | Lifecycle timestamps. |

PR 6's schema change to `tenancy_connectors` adds two columns: `disabled` and `config`. The existing `status` CHECK is unchanged. The existing FK on `(tenant_id, workspace_id, project_id)` to `tenancy_projects` and the existing indexes stay as they are.

`tenancy_connector_states` is the existing health-metadata table (note the plural). It holds `health_status`, `sync_cursor`, `last_successful_sync_at`, `last_error_code`, `last_error_message`, and `metadata`. PR 6 reuses it as-is. The `Health()` implementation reads and writes this table; the heartbeat job updates it on every probe.

## Frontend Contract

Two reusable React components live in `web/src/components/connector/`:

- `<ConnectorStatusBadge lifecycleStatus={...} disabled={...} />` renders the colored pill for any of the four lifecycle statuses (`pending`, `active`, `degraded`, `disconnected`) and overlays a small "Paused" indicator when the `disabled` flag is set. New lifecycle statuses would require new badges; do not invent ad-hoc UI.
- `<ConnectorErrorPanel code={...} message={...} />` renders the help text for any of the seven taxonomy codes plus the provider-supplied message. New codes would require new panels.

Connectors-list page (`/app/{tenant}/{workspace}/connectors`) renders all connectors with the same layout, regardless of provider. Per-provider connect pages live at `/app/{tenant}/{workspace}/connectors/{type}/new` and use shared form components.

## Disconnect Semantics

User-initiated disconnect tears down the upstream integration but keeps the local row for audit. The flow:

1. User clicks Disconnect.
2. Confirmation modal lists what will happen: "Identrail will stop scanning. Your AWS role / GitHub installation / agent will be removed if possible."
3. On confirm, `Provider.Disconnect()` runs. It tears down what it can on the upstream provider (deletes GitHub installation if we have permission, deletes the agent's enrollment record, clears webhook subscriptions).
4. The `tenancy_connectors` row's `status` is set to `disconnected`. The row stays in place for audit. Scan history is retained.
5. The same `connector_id` slug can be re-created later by recording a new row with the same slug after the disconnected row is hard-deleted, or by reusing the existing row through an explicit "reconnect" flow that resets status to `pending`. PR 6 ships the disconnect path; reconnect lands with the per-provider PRs.

Hard delete is admin-only, separate from disconnect, and removes the row entirely along with cascaded `tenancy_connector_states` history. It is a destructive operation.

## Test Matrix (PR 6)

| Test | Expected |
| --- | --- |
| State machine: every defined lifecycle transition is reachable from `pending` | All paths covered |
| State machine: writing an unsupported lifecycle status to the DB | Returns error from the existing CHECK constraint |
| `disabled` flag: setting and clearing on `pending`, `active`, or `degraded` | Flag flips, lifecycle status untouched |
| `disabled` flag: setting `disabled=true` on a `disconnected` row | 409 response, flag unchanged, audit event records the rejection |
| `disabled` flag: user disconnect on a row with `disabled=true` | Single write sets status to `disconnected` and clears the flag back to `false` |
| `disabled` flag: heartbeat skips disabled connectors | Time-mocked test, no probe call |
| Error taxonomy: each code maps to exactly one UI string | Snapshot test |
| Health endpoint: returns 404 for non-existent connector | 404, no DB row touched |
| Health endpoint: returns the right shape for each lifecycle status | Schema test |
| Heartbeat job: connector with no recent success transitions to disconnected after 6h | Time-mocked test |
| Disconnect: row remains, status set to `disconnected`, upstream tear-down attempted | DB and provider mock assertions |
| ConnectorStatusBadge: renders all four lifecycle statuses plus the disabled-flag overlay | Storybook + visual snapshot |
| ConnectorErrorPanel: renders help text for all seven codes | Storybook + visual snapshot |

## What This Foundation Does Not Do

- It does not define the credential format for each provider. AWS uses External ID + role ARN; GitHub uses installation ID; Kubernetes uses an enrollment token or kubeconfig. Each is per-provider.
- It does not define the scan algorithm. That is per-provider.
- It does not implement the per-provider connect UI flow. Each connector ships its own connect page (CloudFormation launch for AWS, App install for GitHub, Helm command for Kubernetes).
- It does not handle the existing legacy connector code paths (`internal/api/github_connect.go` and similar). Those continue working unchanged. PRs 7, 8, 9 add the new paths alongside; old paths get retired in a follow-up after the new paths are proven in production.
