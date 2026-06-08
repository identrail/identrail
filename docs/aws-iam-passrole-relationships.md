# AWS IAM PassRole Static Relationship Mapper

## Purpose

Issue #1487 adds a read-only, static mapper for `iam:PassRole` grants in the
AWS machine identity graph. It parses the permission policies already
collected by the IAM role collector and emits one normalized record per
PassRole grant, capturing source role, target resource (or wildcard),
service condition, policy/statement evidence, and confidence tier.

The collector is metadata-only and **static** — it never executes AWS
mutations or makes additional AWS calls beyond `ListRoles` (and the
existing IAM SDK adapter's policy reads). It also never reads any object
contents, secret values, or session-token data.

## Endpoint

```text
GET /v1/workspaces/{workspace_id}/projects/{project_id}/aws/iam-passrole-relationships
```

Optional query parameters:

- `connector_id`: scopes the account, region, and read-only inventory
  evidence to a configured AWS connector.
- `fixture_state`: one of `success`, `empty`, `degraded`, `partial_failure`,
  or `permission_denied` for deterministic UI/contract validation.

The response returns `inventory`, including records, `can_pass_role`
relationships, diagnostics, coverage gaps, status, confidence, count
summaries, and issue evidence links.

## Evidence Collected

For each PassRole grant, the collector records:

- Source role ARN, name, and path.
- Target resource (specific ARN or wildcard) and a wildcard classification:
  - `specific` — exact role ARN.
  - `path_wildcard` — `arn:aws:iam::account:role/team/*` style.
  - `account_wildcard` — `arn:aws:iam::*:role/...` style.
  - `all` — `*`.
- Action expression that matched (`iam:PassRole`, `iam:*`, or `*`).
- Effect (`Allow` or `Deny`).
- `iam:PassedToService` condition value and the operator (e.g.
  `StringEquals`, `StringLike`).
- Any other condition keys present (recorded for context, not modelled as
  graph semantics this wave).
- `NotAction` and `NotResource` flags so inverse statements are visible
  rather than silently inverted into massive fan-out.
- Policy name and statement `Sid` for evidence trails.
- Confidence tier:
  - `0.95` for specific role ARNs.
  - `0.78` for path-scoped wildcards.
  - `0.70` for account-position wildcards.
  - `0.55` for `*`.

## Required AWS Permissions

The collector uses the existing IAM read-only adapter — no new actions are
required beyond what is already documented for the IAM role collector:

- `iam:ListRoles`
- `iam:ListRolePolicies`
- `iam:GetRolePolicy`
- `iam:ListAttachedRolePolicies`
- `iam:GetPolicy`
- `iam:GetPolicyVersion`

These are read-only metadata calls. The connector policy in
`internal/connectors/aws/iam_policy.go` already grants them.

## What Is Intentionally Not Collected

- Session-tag-bound PassRole conditions (`aws:RequestTag`,
  `iam:TagSession`). The wave's mapper only surfaces
  `iam:PassedToService`; other condition keys are noted under
  `other_condition_keys` so operators can audit them but are not modelled
  as graph semantics.
- Service-linked roles (path `/aws-service-role/`). AWS provisions these
  implicitly; they are not pass-able through customer policies and are
  excluded as a documented coverage gap.
- Resource-based policies, group/user-attached policies, and SCP-imposed
  boundaries (separate waves).

## Fixture States

| State              | Purpose                                                                                              |
|--------------------|------------------------------------------------------------------------------------------------------|
| `success`          | Specific, path-wildcard, account-wildcard, `*`, and Deny grants — one of each class.                 |
| `empty`            | No grants; coverage gaps still surfaced.                                                             |
| `degraded`         | The wildcard grant is flipped to degraded confidence and emits a `iam_passrole_wildcard_target` diag. |
| `partial_failure`  | Earlier records survive; an `iam_passrole_page_failed` diagnostic explains the gap.                  |
| `permission_denied`| Inventory is blocked; a `permission_denied` diagnostic is returned.                                  |

## Live Validation

When running against a real AWS account:

```bash
export IDENTRAIL_AWS_SOURCE=sdk
export IDENTRAIL_AWS_REGION="<region>"
export IDENTRAIL_AWS_ACCOUNT_ID="<account_id>"

state_file="/tmp/identrail-passrole-state.json"
go run ./cmd/cli --state-file "${state_file}" scan --output table
```

Verify that:

- Every emitted record has a non-empty `source_role_arn`.
- Records with `target_wildcard_kind != "specific"` have `unresolved_target: true`.
- Deny statements appear with `effect: "Deny"` and are visible in the
  inventory alongside Allow grants.
- No secret values or policy contents beyond standard IAM policy fields
  appear in the output.

## Troubleshooting

| Diagnostic code                          | Likely cause                                  | Operator action                                                                                       |
|------------------------------------------|-----------------------------------------------|--------------------------------------------------------------------------------------------------------|
| `permission_denied`                      | Connector role missing IAM read APIs          | Grant the actions listed above; no write or decrypt APIs are needed.                                  |
| `iam_passrole_page_failed`                | IAM ListRoles throttled or denied             | Retry; already-collected records remain visible.                                                       |
| `iam_passrole_policy_parse_failed`        | Policy document is not valid JSON             | Audit the policy in the AWS console; the collector skips unparseable policies rather than guessing.    |
| `iam_passrole_wildcard_target`            | A grant points at a path/account wildcard or `*` | Tighten the grant to a specific ARN and add `iam:PassedToService` where possible.                   |
| `iam_passrole_page_limit_exceeded`        | ListRoles paginated beyond max-pages          | Increase the page cap or scope the connector to a smaller account before retrying.                     |
| `malformed_iam_passrole_record`           | Record has no source or target after normalization | Inspect the source role's policy; the collector skips ambiguous records.                            |
