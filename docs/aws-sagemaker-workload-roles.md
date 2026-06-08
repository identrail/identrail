# AWS SageMaker Workload Roles

## Purpose

Issue #1486 adds read-only SageMaker workload-role inventory to the AWS
machine identity graph. It maps SageMaker notebook instances, training jobs,
processing jobs, batch transform jobs, models, endpoints, pipelines, and
Studio domains to the IAM execution roles they use, plus the S3, ECR, and KMS
references that anchor downstream blast-radius reasoning.

The collector is metadata-only. It deliberately never reads notebook
contents, training payloads, model artifacts, browser pages, or any object
body — only the URIs and key ARNs that document the role's S3/ECR/KMS reach.

## Endpoint

```text
GET /v1/workspaces/{workspace_id}/projects/{project_id}/aws/sagemaker-workload-roles
```

Optional query parameters:

- `connector_id`: scopes account and region context to a configured AWS
  connector.
- `fixture_state`: one of `success`, `empty`, `degraded`, `partial_failure`,
  or `permission_denied` for deterministic UI and contract validation.

The response returns `inventory`, including records, `runs_as`/`attached_to`
relationships, diagnostics, coverage gaps, status, confidence, count
summaries, and issue evidence links.

## Evidence Collected

For each SageMaker workload, the collector records:

- Account, region, service (`sagemaker`), workload type and name, workload
  ARN, resource ARN, resource status.
- IAM execution role ARN/name/kind/account ID with the corresponding
  `runs_as` or `attached_to` graph edge.
- S3 prefix references (input data, output data, model artifact location) —
  prefixes only, never object contents.
- ECR image URIs used by training, processing, batch transform, and model
  containers.
- KMS key ARNs from volume, output, notebook, endpoint config, and Studio
  domain configurations.
- Optional context: Studio domain ID/ARN, user profile, space name, pipeline
  ARN, model ARN, endpoint config name, and network mode (`vpc` when the
  workload uses a VPC config).
- Source, evidence reference, confidence, and graph node IDs.

## Required AWS Permissions

The live SDK collector uses read-only SageMaker APIs only:

- `sagemaker:ListNotebookInstances`, `sagemaker:DescribeNotebookInstance`
- `sagemaker:ListTrainingJobs`, `sagemaker:DescribeTrainingJob`
- `sagemaker:ListProcessingJobs`, `sagemaker:DescribeProcessingJob`
- `sagemaker:ListTransformJobs`, `sagemaker:DescribeTransformJob`
- `sagemaker:ListModels`, `sagemaker:DescribeModel`
- `sagemaker:ListEndpoints`, `sagemaker:DescribeEndpoint`,
  `sagemaker:DescribeEndpointConfig`
- `sagemaker:ListPipelines`, `sagemaker:DescribePipeline`
- `sagemaker:ListDomains`, `sagemaker:DescribeDomain`

These permissions are enough to enumerate role and workload metadata. They
do not, and must not, include `sagemaker:CreatePresignedNotebookInstanceUrl`,
`sagemaker:CreatePresignedDomainUrl`, `sagemaker:InvokeEndpoint`, or any
write APIs.

The connector read-only IAM policy template
(`deploy/connectors/aws/policies/identrail-readonly-policy.json` and the
canonical `internal/connectors/aws/iam_policy.go`) includes every action
above under the `IdentityTrustGraphReadOnlySageMaker` statement, so new
connectors created from the policy can call the collector without any extra
permission grant.

## What Is Intentionally Not Collected

- Notebook contents, presigned notebook URLs, and shell command output.
- Training, processing, and batch transform job input/output payloads.
- Model artifacts and inference request/response bodies.
- SageMaker FeatureStore record contents or Lineage artifact bodies.
- User-profile-level execution roles and Studio shared space roles — tracked
  as coverage gaps and emitted with `coverage_status=unsupported`.

## Fixture States

| State              | Purpose                                                                                        |
|--------------------|------------------------------------------------------------------------------------------------|
| `success`          | Full set of payload-safe records across all eight workload types.                              |
| `empty`            | No records, but coverage gaps remain visible.                                                  |
| `degraded`         | One workload is stopped/disabled; its role evidence is retained with a `disabled` diagnostic.  |
| `partial_failure`  | One sub-listing fails (e.g. `ListPipelines`); the other workloads' role evidence is preserved. |
| `permission_denied`| Inventory is blocked; a `permission_denied` diagnostic is returned.                            |

## Live Validation

When running against a real AWS account, exercise each fixture state via the
endpoint, then run the SDK collector against the authorized test account:

The CLI reads AWS connection settings from environment variables (or the
config file), not flags. Configure them and then run a scan:

```bash
export IDENTRAIL_AWS_SOURCE=sdk
export IDENTRAIL_AWS_REGION="<region>"
export IDENTRAIL_AWS_ACCOUNT_ID="<account_id>"

state_file="/tmp/identrail-sagemaker-state.json"
go run ./cmd/cli --state-file "${state_file}" scan --output table
```

Verify that:

- No SageMaker payload, notebook contents, or model body data appear in the
  scan output.
- S3 references are prefixes (no leaf object reads).
- Workloads stopped during the scan emit `sagemaker_workload_disabled` with
  the role evidence retained.

## Troubleshooting

| Diagnostic code                          | Likely cause                                            | Operator action                                                                                                                              |
|------------------------------------------|---------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------|
| `permission_denied`                      | Connector role missing SageMaker read APIs              | Grant the permissions listed above; do not enable presigned URLs or invoke APIs.                                                              |
| `sagemaker_pipelines_failed`             | Pipeline listing throttled or denied                    | Retry; other workloads' role evidence stays visible.                                                                                          |
| `sagemaker_endpoint_config_describe_failed` | Endpoint exists but config is gone / access denied   | Inspect the endpoint config in the AWS console; collector records the endpoint role even when the config describe partially fails.            |
| `sagemaker_transform_model_describe_failed` | Transform job references a model the role cannot describe | Confirm the model still exists in this account/region.                                                                                     |
| `missing_sagemaker_role`                 | Workload has no execution role attached                 | Confirm the workload configuration; an empty execution role is not normalized into the graph.                                                 |
