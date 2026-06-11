# AWS DynamoDB and RDS reachability

Issue: #1494

Endpoint:

```text
GET /v1/workspaces/{workspace_id}/projects/{project_id}/aws/dynamodb-rds-reachability
```

This inventory maps DynamoDB tables/streams and RDS clusters/instances/proxies into graph-ready metadata records. It is designed for reachability and evidence review, not database-content inspection.

## What It Collects

- DynamoDB table and stream ARNs, names, status, billing mode, stream status, tags, encryption, deletion protection, and resource-policy grants when available.
- RDS cluster, instance, and proxy ARNs, names, engine metadata, status, endpoint presence, public-access flags, encryption, deletion protection, IAM database authentication, performance insights, tags, and associated IAM roles.
- Evidence links, confidence, account/region scope, connector scope, source, scan metadata, coverage gaps, and structured diagnostics.
- Graph-safe relationships from concrete IAM principals or service-associated IAM roles to the database resource.

## What It Never Collects

- DynamoDB item values, query results, scans, PartiQL output, exports, or streams payloads.
- SQL queries, result rows, database contents, credentials, snapshots, backups, or logs.
- Customer payloads, secret values, prompts, completions, browser output, or code-interpreter output.

## Query Parameters

| Parameter | Description |
| --- | --- |
| `connector_id` | Optional AWS connector ID scoped to the project. |
| `fixture_state` | Fixture validation state: `success`, `empty`, `degraded`, `partial_failure`, or `permission_denied`. |
| `resource_type` | Optional filter: `dynamodb_table`, `dynamodb_stream`, `rds_instance`, `rds_cluster`, or `rds_proxy`. |
| `identity` | Optional identity/role/principal substring filter. |

## Expected Statuses

| Status | Meaning |
| --- | --- |
| `ready` | Metadata collection completed and records are safe to use as graph evidence. |
| `degraded` | Some metadata calls failed, but retained records remain visible with diagnostics. |
| `blocked` | Required read-only metadata permissions are missing. |

## Metadata-Only Permissions

The collector expects read-only describe/list/tag/resource-policy permissions such as:

- `dynamodb:ListTables`
- `dynamodb:DescribeTable`
- `dynamodb:ListTagsOfResource`
- `dynamodb:GetResourcePolicy`
- `rds:DescribeDBInstances`
- `rds:DescribeDBClusters`
- `rds:DescribeDBProxies`
- `rds:ListTagsForResource`

Do not add DynamoDB item APIs, RDS snapshot export APIs, database log APIs, mutation APIs, or database credentials to satisfy this collector.

## Validation

```bash
go test ./internal/api -run DynamoDBRDSReachability
go test ./internal/providers/aws -run DynamoDBRDSReachability
```
