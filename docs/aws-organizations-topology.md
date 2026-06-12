# AWS Organizations topology

AWS Organizations topology is the Wave 3.02 contract for discovering account and OU structure before Identrail fans out AWS machine-identity collection across accounts and regions.

The feature is metadata-only and read-only. It records organization/account/OU facts needed for safe scan planning:

- AWS organization ID, partition, management account, and connector scope
- organizational units, parent IDs, OU paths, enabled/disabled state, and disabled reasons
- accounts, account lifecycle status, OU path, management-account indicator, delegated-admin services, scan eligibility, and parent relationships
- discovery lifecycle state, checkpoint cursor, failure reason, retry attempts, and evidence reference

It intentionally does not collect secret values, customer payloads, prompts, completions, browser output, database rows, object contents, account emails, resource contents, or live mutation output.

## API

```http
GET /v1/workspaces/{workspace_id}/projects/{project_id}/aws/organizations-topology
```

Query parameters:

- `connector_id`: optional AWS connector ID.
- `fixture_state`: optional deterministic fixture state: `success`, `empty`, `degraded`, `partial_failure`, or `permission_denied`.
- `account`: optional 12-digit AWS account ID filter.
- `ou`: optional OU ID or OU path filter.
- `state`: optional discovery state filter: `planned`, `pending`, `in_progress`, `covered`, `partial`, `failed`, `permission_denied`, `unsupported`, `blocked`, or `disabled`.
- `status`: optional account lifecycle filter: `active`, `suspended`, or `closed`.

The response is wrapped as:

```json
{
  "topology": {
    "status": "ready",
    "version": "aws-organizations-topology-v1",
    "organization_id": "o-identrailfixture",
    "summary": {
      "account_count": 4,
      "organizational_unit_count": 4,
      "scan_eligible_accounts": 3
    },
    "organizational_units": [],
    "accounts": [],
    "relationships": []
  }
}
```

## Failure states

- `empty`: no accounts or OUs were discovered; operators should confirm the connector is scoped to an organization management or delegated administrator account.
- `permission_denied`: the connector role cannot read AWS Organizations topology; Identrail reports this as blocked, not successful.
- `partial_failure` / `degraded`: collection stopped part-way through pagination or retries; cursors and attempts remain visible so operators can rerun safely.
- suspended or closed accounts: explicit non-eligible account state, not a scan success.
- disabled OUs: account scan eligibility is blocked with an operator-visible reason.

## AWS permissions

The live collector that feeds this contract should use read-only AWS Organizations actions such as:

- `organizations:DescribeOrganization`
- `organizations:ListRoots`
- `organizations:ListAccounts`
- `organizations:ListAccountsForParent`
- `organizations:ListParents`
- `organizations:ListOrganizationalUnitsForParent`
- `organizations:ListDelegatedAdministrators`

Downstream account/region/service fan-out should join this topology with the coverage planner rather than expanding scan targets from raw connector status alone.

## Validation

Run the focused backend and client checks:

```sh
go test ./internal/providers/awscontract ./internal/api
cd web && pnpm exec vitest run src/api/client.test.ts src/productShell.test.tsx
```

For live validation, use an authorized AWS test organization only. Record account IDs, OU IDs, statuses, delegated-admin services, and failure states; do not record payloads, secrets, account emails, object contents, or resource data.
