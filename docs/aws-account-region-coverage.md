# AWS Account and Region Coverage

Identrail tracks AWS connector health and AWS estate coverage separately. Connector health confirms that the configured AWS connector can be used. Coverage records describe which AWS accounts and regions are known, expected, covered, pending, or blocked for a project.

## Scope

The registry is tenant-, workspace-, project-, and connector-scoped. A coverage row is uniquely identified by:

- connector ID
- AWS account ID
- AWS region

The registry also stores optional organization context, including account name, organization ID, organizational unit ID, AWS partition, and connector role ARN. This lets scanner and onboarding workflows keep AWS Organizations discovery separate from the eventual public UI.

## Coverage status

Use these statuses consistently:

- `unknown`: the account and region are known, but Identrail does not have enough scan state yet.
- `pending`: the account and region are queued or expected to be scanned.
- `covered`: Identrail completed a successful scan for the account and region.
- `gap`: the account and region should be covered but are not currently covered.
- `error`: the latest scan failed. Store a concise operator-facing reason in `last_scan_error`.
- `suspended`: AWS reports the account is suspended.
- `disabled`: the AWS region is disabled for the account.
- `unreachable`: Identrail cannot currently reach the account or region.

## Stored scan state

Coverage rows can include:

- `last_successful_scan_at` for the most recent successful account/region scan.
- `last_scan_error` for the latest failure reason.
- `scan_cursor` for scanner-owned pagination or incremental state.
- `account_suspended`, `region_disabled`, and `region_unreachable` booleans for explicit blocked states.

The scan cursor is a metadata-only JSON object and should not contain secrets.
Service cursor entries are stored below keys such as `services.lambda` and may
include `collector`, `state`, `cursor`, `attempts`, `failure_reason`, and
`observed_at`. Resumable cursors older than 24 hours are treated as stale by the
planner and are not reused.

## Public API posture

Scanner and connector workflows write coverage through the scoped service
methods. Operators read normalized plan and execution views through the AWS
coverage-plan and fan-out execution endpoints instead of reading raw database
rows.
