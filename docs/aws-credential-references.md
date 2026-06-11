# AWS Credential and Secret Reference Mapping

Issue #1496 adds a metadata-only mapper that extracts credential and secret
references from AWS workloads, classifies the provider behind each reference,
and emits graph-ready identity-to-reference edges.

## What It Maps

The mapper is a pure derivation over the normalized scan graph — it performs no
AWS calls of its own. It reads the credential references that workload
collectors already surface (`secret_refs` and credential-suggestive
`environment_keys`) for every workload that carries them, currently:

- ECS services and task definitions (`valueFrom` secret references)
- Lambda functions (environment and secret references)
- CodeBuild projects (`SECRETS_MANAGER` / `PARAMETER_STORE` environment
  sources)

Any future workload collector that emits `secret_refs` or `environment_keys`
(for example SageMaker, Step Functions, or EC2 once they surface environment
metadata) is mapped automatically without changing this component.

For each reference it records:

- **Provider** by name/metadata pattern: `openai`, `anthropic`, `bedrock`,
  `github`, `slack`, `database`, `webhook`, plus the AWS-native sources
  `aws_secrets_manager` and `aws_ssm`, falling back to `generic`.
- **Reference kind**: `secrets_manager`, `ssm_parameter`,
  `repository_credentials`, or `environment_variable`.
- **Sensitivity**: `ai_provider_api_key`, `source_control_token`,
  `messaging_token`, `database_credential`, `webhook_url`,
  `aws_managed_secret`, or `generic_secret`.
- **Resolution status**: whether the reference resolves to a collected Secrets
  Manager secret or SSM parameter node (`resolved`), or points outside the
  collected graph (`unresolved`).
- Workload context, source service, evidence reference, and confidence.

## Graph Output

- Resolved references reuse the existing `uses_secret` edge to the collected
  secret or parameter node.
- Unresolved **external** provider keys (AI, source control, database, webhook)
  synthesize a `credential_reference` graph node and a `uses_secret` edge from
  the workload, so an operator can see "this workload uses an OpenAI key" even
  when the key is not an AWS-managed secret.
- Unresolved generic AWS secret references are recorded as evidence but do not
  synthesize a node, avoiding dangling graph entries.

## What It Never Collects

The mapper reads reference names, ARNs, and source markers only. It never reads
or stores secret values, parameter values, environment variable values,
prompts, completions, object contents, database rows, or customer payloads. It
adds no AWS permissions of its own; it depends on the metadata-only workload
collectors that already run.

## API

```http
GET /v1/workspaces/{workspace_id}/projects/{project_id}/aws/credential-references
```

Optional query parameters:

- `connector_id`: scope the response to one AWS connector.
- `fixture_state`: one of `success`, `empty`, `degraded`, `partial_failure`, or
  `permission_denied` for deterministic UI and contract validation.
- `resource_type`: filter to one workload resource type (for example
  `ecs_service`, `lambda_function`, `codebuild_project`).
- `identity`: case-insensitive substring filter over the workload identifier and
  name.
- `provider`: filter to one credential provider classification.

The response includes operator-visible status, confidence, a provider
breakdown, resolved/unresolved and external-provider-key counts, evidence
links, failure reasons, remediation hints, diagnostics, records, and the
identity-to-reference relationships. Unresolved external provider keys are
prioritized in the remediation hints for secret-store migration and rotation.

## Failure States

- `empty`: workloads were inventoried and no credential references were found.
- `degraded`: references are available but one workload's environment was
  partially redacted by its source collector.
- `partial_failure`: some workloads mapped while another workload collector
  partially failed.
- `permission_denied`: the underlying workload inventory permissions are
  missing, so no references can be mapped.

Unknown or denied states are explicit; they are not reported as successful
findings.

## Live Validation

Run fixture validation first:

```sh
go test ./internal/providers/aws ./internal/api
```

For live AWS validation, use only an authorized test account and record
account, region, workload coverage, and the provider breakdown. Do not capture
secret, parameter, or environment values.
