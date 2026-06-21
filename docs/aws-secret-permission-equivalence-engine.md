# AWS secret-to-permission equivalence engine

Issue #1527 (Wave 6.07) adds a metadata-only engine that treats readable
secrets, provider keys, and KMS-backed credentials as permission-bearing
capabilities. It composes credential-reference, Secrets Manager, KMS, runtime,
agent, blast-radius, and privilege-escalation evidence into ranked findings.

## What it produces

The engine emits `AWSSecretPermissionEquivalenceFinding` records for these
equivalence types:

- **`workload_provider_key_equivalence`** - a workload references an external
  provider key or credential-bearing secret.
- **`secret_read_policy_equivalence`** - a principal can read a
  permission-bearing Secrets Manager secret through resource-policy metadata.
- **`kms_decrypt_secret_equivalence`** - a principal can decrypt a KMS key that
  protects a permission-bearing secret.
- **`kms_live_grant_secret_equivalence`** - a live KMS grant can decrypt a key
  protecting a permission-bearing secret.
- **`runtime_secret_access_equivalence`** - runtime evidence observed
  Secrets Manager or KMS access to a credential-bearing resource.
- **`agent_provider_key_equivalence`** - an AWS AI agent has a provider-key
  reference, so control of the agent runtime can imply provider permissions.
- **`blast_radius_secret_equivalence`** - blast-radius evidence includes
  credential-bearing secret or KMS paths.
- **`admin_equivalent_secret_permission`** - privilege-escalation evidence found
  secret or KMS admin/read equivalence.

Each finding carries a stable finding id, calculation version, severity, score,
confidence, provider, equivalent permissions, implied AWS actions when known,
impacted nodes, impacted path, rationale, evidence references, explicit
metadata-only evidence boundary, and read-only `remediation_case` preview.

## API

`GET /v1/workspaces/{workspace_id}/projects/{project_id}/aws/secret-permission-equivalence`

| Query param | Purpose |
|---|---|
| `connector_id` | scope to one AWS connector |
| `fixture_state` | `success` / `empty` / `degraded` / `partial_failure` / `permission_denied` for deterministic demos and tests |
| `account_id`, `region` | scope filters |
| `identity` | principal ARN, workload id/name, agent id/name, or identity-node search |
| `secret` | secret ARN, graph node id, display label, or provider-key reference search |
| `provider` | provider classification such as `openai`, `anthropic`, `github`, `database`, `slack`, `webhook`, or `aws_secret` |
| `equivalence_type` | one of the finding types above |
| `severity` | `critical`, `high`, `medium`, `low` |
| `status` | `review`, `action_required`, or source status |

Response shape: `{ "findings": AWSSecretPermissionEquivalenceResult }` with
summary, ranked findings, graph relationships, caveats, failure reasons,
remediation hints, evidence links, coverage gaps, diagnostics, and standard
tenant/workspace/project issue metadata.

## Evidence boundary

The engine never reads, stores, logs, or displays secret values, KMS plaintext,
prompt text, completions, browser pages, code-interpreter output, object
contents, database rows, or customer payloads. It only composes metadata:

- credential reference names, source markers, and resolved secret references
- Secrets Manager metadata, resource-policy grants, and KMS key ids
- KMS policy and live-grant metadata
- CloudTrail event ids and resource/action metadata
- AI agent provider-key references and runtime role metadata
- upstream blast-radius and privilege-escalation evidence references

## AWS permissions

This capability adds no new AWS permissions. It reuses the read-only collectors
from credential-reference mapping, Secrets Manager metadata, KMS decrypt
reachability, runtime events, AI agent identity inventory, blast-radius
intelligence, and privilege-escalation reasoning.

## Failure handling

- **Ready**: source engines are available and no blocking diagnostics were
  emitted.
- **Degraded**: at least one source is partial, empty because runtime evidence
  is unavailable, capability-limited, or produced retryable diagnostics. Partial
  evidence remains visible.
- **Blocked**: required source evidence is permission denied. The result has no
  deterministic findings, diagnostics, and failure reasons.

Unknown, unresolved, degraded, unsupported, partial, and permission-denied
evidence stays explicit. It must not be treated as deterministic proof that a
secret is safe or unused.

## App surface

The AWS Runtime and AWS Findings app surfaces render the
`AWS secret-to-permission equivalence` panel. Operators can see ranked findings
with identity, secret label, equivalent permission, impacted path, confidence,
evidence, risk status, and next action without reading logs or database rows.

## Live validation

1. Confirm issue blockers #1496, #1518, and #1521 are closed.
2. Run the credential references, Secrets Manager metadata, KMS reachability,
   Secrets/KMS runtime access, AI agent identities, blast-radius, and privilege
   escalation endpoints with `fixture_state=success`.
3. Run the secret-permission endpoint with `fixture_state=success` and confirm
   provider-key, secret-policy, KMS-backed, runtime, agent, blast-radius, and
   admin-equivalence findings are ranked.
4. Filter by `provider=openai`, `equivalence_type=agent_provider_key_equivalence`,
   `identity`, and `secret` to verify deterministic drill-down behavior.
5. Run `fixture_state=permission_denied` and confirm `status=blocked`, zero
   findings, diagnostics, and failure reasons.
6. Confirm the AWS app panel renders success, empty/degraded,
   permission-denied, and partial-failure states without exposing secret values
   or customer payload data.
