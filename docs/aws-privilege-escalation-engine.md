# AWS privilege escalation path engine

Issue #1525 (Wave 6.05) adds a metadata-only engine that ranks AWS privilege
escalation paths into explainable findings. It composes the read-only evidence
from PassRole, KMS decrypt reachability, Secrets Manager metadata, least
privilege recommendations, and blast-radius graph analysis.

## What it produces

The engine emits `AWSPrivilegeEscalationFinding` records for these path types:

- **`passrole_service_escalation`** — an identity can pass a specific role to a
  scoped AWS service.
- **`passrole_wildcard_escalation`** — an identity can pass a wildcard role
  target.
- **`passrole_unscoped_trust_path`** — a PassRole grant lacks
  `iam:PassedToService` scoping.
- **`policy_attachment_escalation`** — least-privilege evidence found
  escalation-capable policy actions such as `iam:*`, `iam:PassRole`,
  `iam:AttachRolePolicy`, or `sts:AssumeRole`.
- **`kms_admin_equivalence`** — KMS key policy or grant metadata indicates an
  admin-equivalent or decrypt-capable path.
- **`secrets_admin_equivalence`** — Secrets Manager resource policy metadata
  indicates an admin-equivalent or read-capable path.
- **`cross_account_escalation_path`** — blast-radius evidence found a critical
  or cross-account graph path.

Each finding carries a stable finding id, calculation version, severity, score,
confidence, impacted graph path, evidence references, exploitability label,
status, and read-only `remediation_case` preview. Findings are ranked by
descending score with stable id tie-breaking.

## API

`GET /v1/workspaces/{workspace_id}/projects/{project_id}/aws/privilege-escalation`

| Query param | Purpose |
|---|---|
| `connector_id` | scope to one AWS connector |
| `fixture_state` | `success` / `empty` / `degraded` / `partial_failure` / `permission_denied` for deterministic demos and tests |
| `account_id`, `region` | scope filters |
| `identity` | principal ARN, identity-node id, or display-name search |
| `target` | target node id, target label, or impacted-node search |
| `escalation_type` | one of the finding types above |
| `severity` | `critical`, `high`, `medium`, `low` |
| `status` | `review`, `action_required` |

Response shape: `{ "findings": AWSPrivilegeEscalationResult }` with summary,
ranked findings, graph relationships, caveats, failure reasons, remediation
hints, evidence links, coverage gaps, diagnostics, and standard
tenant/workspace/project issue metadata.

## Read-only guarantees

The engine performs no AWS mutations and does not read secret values, KMS
plaintext, prompts, completions, object bodies, database rows, browser pages, or
customer payloads. It only forwards metadata and evidence references from
upstream collectors that are already read-only.

Remediation output is a planning preview. It can tell an operator which policy,
trust, grant, or role path needs review, but it does not change AWS or Identrail
state.

## Failure handling

- **Ready**: all source engines are available and no diagnostics were emitted.
- **Degraded**: at least one source is partial, empty because supporting runtime
  evidence is unavailable, or produced diagnostics. Existing partial evidence
  remains visible.
- **Blocked**: every source required for the calculation is permission denied.
  The result has `confidence=0`, no findings, diagnostics, and failure reasons.

Unknown, degraded, and permission-denied evidence lowers confidence and must not
be interpreted as absence of privilege escalation paths.

## Live validation

1. Run the upstream PassRole, KMS reachability, Secrets Manager metadata,
   least-privilege, and blast-radius endpoints with `fixture_state=success`.
2. Run the privilege escalation endpoint with `fixture_state=success` and
   confirm PassRole and KMS admin-equivalence findings are ranked.
3. Filter by `escalation_type=passrole_unscoped_trust_path`, `severity`, and
   `identity` to verify deterministic drill-down behavior.
4. Run `fixture_state=permission_denied` and confirm `status=blocked`, zero
   findings, diagnostics, and failure reasons.
5. Confirm the app runtime page renders the `AWS privilege escalation paths`
   panel and never exposes secret values or payload data.
