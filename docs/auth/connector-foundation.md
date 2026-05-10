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

A connector is always in exactly one state. The valid transitions are written down once and enforced by the foundation; specific connectors do not invent their own states.

```
              create
                │
                ▼
            ┌────────┐
            │pending │
            └───┬────┘
                │ user provides credentials
                ▼
            ┌──────────┐
            │validating│
            └────┬─────┘
                 │ Validate succeeds
                 ▼
            ┌────────┐
            │ active │ ◄───────┐
            └───┬────┘         │
                │              │
        scan or │              │ next scan succeeds
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

(disabled is a separate side state, set by an admin pause from any
 state other than disconnected, returns to its prior state on resume.)
```

State definitions:

| State | Meaning |
| --- | --- |
| `pending` | Database row exists; no credentials yet. The user has not finished the connect flow. |
| `validating` | Credentials received; Validate is running. Transient state, short-lived. |
| `active` | Validated, scanning normally, last health check passed. |
| `degraded` | Last scan or health check failed; credentials are still believed valid. Auto-recovers when the next attempt succeeds. |
| `disconnected` | Credentials are invalid, revoked, or the provider has been unreachable for 6+ hours. Requires user action. |
| `disabled` | An admin has paused the connector. Independent of the main pipeline; does not progress until enabled again. |

Transition events:

| From | Event | To |
| --- | --- | --- |
| pending | credentials submitted | validating |
| validating | Validate succeeds | active |
| validating | Validate fails | disconnected |
| active | scan or health failure | degraded |
| degraded | next scan or health succeeds | active |
| degraded | 6+ hours since last success | disconnected |
| any (not disconnected) | admin disable | disabled |
| disabled | admin enable | previous state (active by default) |
| any | user disconnect | disconnected, then row marked deleted |

Every transition emits an audit event: `connector.<provider>.state.<from>_to_<to>`. The audit event includes the reason (last error code, last error message).

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
  "status": "active|degraded|disconnected|disabled|pending|validating",
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

`last_error` is null if there has been no recent failure. `next_scheduled_scan_at` is null for connectors that scan only on demand.

## Heartbeat Job

A scheduled job runs every 5 minutes and calls `Health()` on every connector in `active` or `degraded` state. The result drives state transitions per the state machine.

| Condition | Action |
| --- | --- |
| Connector active, health succeeds | No transition. Update `last_success_at`. |
| Connector active, health fails | Transition to `degraded`. Record error. |
| Connector degraded, health succeeds | Transition to `active`. Clear last error. |
| Connector degraded, > 6 hours since `last_success_at` | Transition to `disconnected`. Notify admins. |
| Connector disconnected | No probing. Heartbeat skips this connector. |

The heartbeat job is idempotent and rate-limited to prevent floods if many connectors fail simultaneously.

## Per-Connector Storage

The shared `tenancy_connectors` table holds the row that represents each connector. Provider-specific configuration lives in `config JSONB`. Sensitive credentials live in `tenancy_connector_secret_envelopes`, encrypted at rest.

`tenancy_connectors` columns relevant here:

| Column | Notes |
| --- | --- |
| `id` | UUID primary key |
| `tenant_id`, `workspace_id`, `project_id` | Scope ownership |
| `type` | `aws`, `kubernetes`, `github`, future others |
| `status` | One of the state-machine states |
| `display_name` | User-facing label |
| `config` | JSONB; per-provider, validated by the provider's Init |
| `created_at`, `updated_at`, `disconnected_at` | Lifecycle timestamps |

`tenancy_connector_state` holds health metadata and is updated by the heartbeat job and by Scan completion.

## Frontend Contract

Two reusable React components live in `web/src/components/connector/`:

- `<ConnectorStatusBadge status={...} />` renders the colored pill for any of the six states. New states would require new badges; do not invent ad-hoc UI.
- `<ConnectorErrorPanel code={...} message={...} />` renders the help text for any of the seven taxonomy codes plus the provider-supplied message. New codes would require new panels.

Connectors-list page (`/app/{tenant}/{workspace}/connectors`) renders all connectors with the same layout, regardless of provider. Per-provider connect pages live at `/app/{tenant}/{workspace}/connectors/{type}/new` and use shared form components.

## Disconnect Semantics

User-initiated disconnect is destructive but recoverable. The flow:

1. User clicks Disconnect.
2. Confirmation modal lists what will happen: "Identrail will stop scanning. Your AWS role / GitHub installation / agent will be removed if possible."
3. On confirm, `Provider.Disconnect()` runs. It tears down what it can (deletes GitHub installation if we have permission, deletes the agent's enrollment record, clears webhook subscriptions).
4. The `tenancy_connectors` row is marked `disconnected_at` and stays in place for audit. Scan history is retained.
5. The same connector slug can be re-created later; this creates a new row, not a revival of the old one.

Hard delete is admin-only and rare. It is a separate code path from disconnect.

## Test Matrix (PR 6)

| Test | Expected |
| --- | --- |
| State machine: every defined transition is reachable from `pending` | All paths covered |
| State machine: undefined transition (e.g., active to validating) | Returns error, no state change |
| Error taxonomy: each code maps to exactly one UI string | Snapshot test |
| Health endpoint: returns 404 for non-existent connector | 404, no DB row touched |
| Health endpoint: returns the right shape for each state | Schema test |
| Heartbeat job: connector with no recent success transitions to disconnected after 6h | Time-mocked test |
| ConnectorStatusBadge: renders all six states without prop errors | Storybook + visual snapshot |
| ConnectorErrorPanel: renders help text for all seven codes | Storybook + visual snapshot |

## What This Foundation Does Not Do

- It does not define the credential format for each provider. AWS uses External ID + role ARN; GitHub uses installation ID; Kubernetes uses an enrollment token or kubeconfig. Each is per-provider.
- It does not define the scan algorithm. That is per-provider.
- It does not implement the per-provider connect UI flow. Each connector ships its own connect page (CloudFormation launch for AWS, App install for GitHub, Helm command for Kubernetes).
- It does not handle the existing legacy connector code paths (`internal/api/github_connect.go` and similar). Those continue working unchanged. PRs 7, 8, 9 add the new paths alongside; old paths get retired in a follow-up after the new paths are proven in production.
