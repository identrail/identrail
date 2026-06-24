# AWS Secret and Key Rotation Planner

Issue: #1533

The AWS secret/key rotation planner converts metadata-only secret, provider-key,
KMS, and remediation-case evidence into deterministic rotation workflows. It is
read-only: it never reads, exposes, logs, rotates, or persists secret values,
provider key material, rendered policies, prompts, completions, browser pages,
code-interpreter output, database rows, object contents, customer payloads, or
workload payloads.

## Endpoint

`GET /v1/workspaces/{workspace_id}/projects/{project_id}/aws/secret-key-rotation`

Query parameters:

- `connector_id`
- `fixture_state`
- `account_id`
- `region`
- `rotation_type`: `provider_key`, `secrets_manager_secret`, or `kms_related`
- `provider`
- `owner`
- `severity`
- `status`
- `ready_for_apply`
- `search`

## Planner Inputs

- Secret-permission equivalence findings identify identities or agents that
  inherit a permission-bearing secret or provider key.
- Secrets Manager metadata identifies active secrets, rotation posture,
  workload references, KMS key refs, exposure classification, tags, and evidence
  refs.
- KMS decrypt reachability identifies key metadata and grant reachability for
  KMS-backed rotation cases.
- Remediation cases provide lifecycle and approval handoff context for linked
  secret-permission findings.

## Plan Shape

Each plan includes:

- stable `plan_id`, version, status, score, confidence, and issue metadata
- `rotation_type`, provider, account, region, and owner handoff
- target secret refs and KMS key refs as metadata only
- dependent workload refresh order
- ordered `prepare`, `dry_run`, `apply`, `refresh`, and `verify` steps
- before/after intent, tradeoffs, rollback, verification, and readiness gates
- source evidence refs, impacted graph nodes, and relationships

`ready_for_apply` is only a planning signal. Actual rotation must happen in the
owning provider, Secrets Manager, or KMS workflow after approval. Identrail only
records metadata evidence links for dry-run, apply, verify, and rollback.

## Safety Boundary

The planner intentionally excludes secret values and customer payloads. Target
refs use ARNs, node IDs, labels, evidence refs, workload identifiers, and owner
metadata. Unknown, denied, degraded, and partial evidence remain explicit in
status, diagnostics, failure reasons, and coverage gaps rather than becoming
deterministic truth.
