# AWS cross-account trust and external access engine

Issue #1526 (Wave 6.06) adds a metadata-only engine that turns normalized AWS
trust, resource-policy, runtime, Organizations, Access Analyzer, and graph
evidence into ranked external-access findings.

## What it produces

The engine emits `AWSCrossAccountTrustFinding` records for these finding types:

- **`public_resource_trust`** - a resource policy or grant trusts a wildcard or
  public principal.
- **`cross_account_resource_access`** - a resource policy or grant trusts a
  principal from another account.
- **`runtime_cross_account_assumption`** - CloudTrail runtime evidence observed
  STS `AssumeRole` crossing account boundaries.
- **`access_analyzer_external_access`** - least-privilege reasoning preserved an
  Access Analyzer external-access signal for owner review.
- **`cross_account_graph_path`** - blast-radius graph evidence found a
  cross-account edge in an impacted path.

Each finding carries a stable finding id, calculation version, severity, score,
confidence, account/region context, service/resource context, external
principal account and OU context when available, condition keys, evidence
references, impacted graph path, hardening direction, and read-only
`remediation_case` preview.

## API

`GET /v1/workspaces/{workspace_id}/projects/{project_id}/aws/cross-account-trust`

| Query param | Purpose |
|---|---|
| `connector_id` | scope to one AWS connector |
| `fixture_state` | `success` / `empty` / `degraded` / `partial_failure` / `permission_denied` for deterministic demos and tests |
| `account_id`, `region` | scope filters |
| `service` | filter by AWS service such as `s3`, `kms`, `secretsmanager`, `sqs`, `sns`, `dynamodb`, `rds`, or `sts` |
| `principal` | external principal ARN, account id, or OU path search |
| `resource` | resource ARN, graph node id, or display label search |
| `finding_type` | one of the finding types above |
| `severity` | `critical`, `high`, `medium`, `low` |
| `status` | `review`, `action_required`, or source status |
| `ou` | external principal OU path search when Organizations topology knows the account |

Response shape: `{ "findings": AWSCrossAccountTrustResult }` with summary,
ranked findings, graph relationships, caveats, failure reasons, remediation
hints, evidence links, coverage gaps, diagnostics, and standard
tenant/workspace/project issue metadata.

## Read-only guarantees

The engine performs no AWS mutations and does not read secret values, KMS
plaintext, object bodies, database rows, prompts, completions, browser pages, or
customer payloads. It only composes metadata and evidence references from
read-only upstream collectors.

Remediation output is a planning preview. It can tell an operator which
principal, resource, condition, and graph path need review, but it does not
change AWS or Identrail state.

## Failure handling

- **Ready**: source engines are available and no blocking diagnostics were
  emitted.
- **Degraded**: at least one source is partial, capability-limited, or produced
  diagnostics. Existing partial evidence remains visible.
- **Blocked**: every source required for the calculation is permission denied.
  The result has `confidence=0`, no findings, diagnostics, and failure reasons.

Unknown, degraded, unsupported, and permission-denied evidence lowers confidence
and must not be interpreted as absence of external access.

## Live validation

1. Confirm issue blockers #1498 and #1517 are closed.
2. Run the Organizations, resource reachability, runtime events,
   least-privilege, and blast-radius endpoints with `fixture_state=success`.
3. Run the cross-account trust endpoint with `fixture_state=success` and confirm
   public and cross-account findings are ranked.
4. Filter by `service=kms`, `principal=partner-ingest`, and
   `finding_type=cross_account_resource_access` to verify deterministic
   drill-down behavior.
5. Run `fixture_state=permission_denied` and confirm `status=blocked`, zero
   findings, diagnostics, and failure reasons.
6. Confirm the AWS Runtime app page renders the `AWS cross-account trust` panel
   without exposing secret values or customer payload data.
