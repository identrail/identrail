# AWS Managed Compute Roles

## Purpose

Issue #1485 adds read-only managed compute role inventory to the AWS machine
identity graph. It maps App Runner, AWS Batch, AWS Glue, and Amazon EMR
workloads to the IAM roles they use so operators can see service, job,
execution, access, and autoscaling identities alongside the rest of the AWS
collector evidence.

## Endpoint

```text
GET /v1/workspaces/{workspace_id}/projects/{project_id}/aws/managed-compute-roles
```

Optional query parameters:

- `connector_id`: scopes account and region context to a configured AWS connector.
- `fixture_state`: one of `success`, `empty`, `degraded`, `partial_failure`, or
  `permission_denied` for deterministic UI and contract validation.

The response returns `inventory`, including records, `runs_as` relationships,
diagnostics, coverage gaps, status, confidence, count summaries, and issue
evidence links.

## Evidence Collected

Each record can include:

- App Runner service ARN/name/status with instance role and source access role.
- Batch compute environment and job definition role evidence, including service,
  instance, Spot Fleet, job, and execution roles.
- Glue job and crawler roles with workload status and command/engine metadata.
- EMR cluster service and autoscaling roles with cluster ARN/status.
- Account, region, service, workload identifier, role kind, role ARN/name,
  resource ARN/type/status, compute engine, cluster ARN, job definition ARN,
  revision, tags, source, confidence, and graph node IDs.

The collector is metadata-only. It never stores logs, runtime payloads,
execution history, job input/output data, object contents, database rows, prompt
contents, completions, browser pages, code-interpreter output, or secret values.

## Required AWS Permissions

The live SDK collector uses read-only AWS APIs only:

- `apprunner:ListServices`
- `apprunner:DescribeService`
- `batch:DescribeComputeEnvironments`
- `batch:DescribeJobDefinitions`
- `glue:GetJobs`
- `glue:GetCrawlers`
- `elasticmapreduce:ListClusters`
- `elasticmapreduce:DescribeCluster`

These permissions are enough to collect role and workload metadata without
collecting application logs, payload bodies, execution histories, or secret
values.

## Coverage Gaps

Unsupported managed compute services remain visible as coverage gaps instead of
being silently treated as complete. The first gap is MWAA, because reliable MWAA
role discovery needs dedicated environment metadata handling beyond this issue's
App Runner, Batch, Glue, and EMR scope.

## Diagnostics

Permission denial blocks the inventory when the collector cannot prove managed
compute roles without metadata access. Per-service failures are reported as
partial failures so successful App Runner, Batch, Glue, or EMR role records
remain visible. Disabled or degraded workloads remain visible as degraded or
disabled records instead of being merged into healthy identities.

## Graph Shape

Managed compute role records emit:

```text
apprunner_service --runs_as--> iam_role
batch_compute_environment --runs_as--> iam_role
batch_job_definition --runs_as--> iam_role
glue_job --runs_as--> iam_role
glue_crawler --runs_as--> iam_role
emr_cluster --runs_as--> iam_role
```

This gives downstream graph, runtime, blast-radius, least-privilege, reasoning,
remediation, and governance features deterministic managed compute role evidence
without collecting payloads or secrets.
