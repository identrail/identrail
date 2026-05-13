# AWS Connector

PR 7 adds the hosted AWS connector onboarding path behind two feature flags:

- Backend: `IDENTRAIL_FEATURE_CONNECTOR_AWS=true`
- Frontend: `VITE_FEATURE_CONNECTOR_AWS=true`

The product path is the standard connector API. Older project-scoped AWS routes are not the product path and should not be used by new UI:

```text
POST /v1/workspaces/{workspace_id}/projects/{project_id}/aws/connection
```

The new CloudFormation flow uses:

```text
POST /v1/connectors/aws
GET  /v1/connectors/aws/{connector_id}/poll
POST /v1/connectors/aws/{connector_id}/validate
POST /v1/connectors/aws/{connector_id}/refresh-policy
```

## Required Runtime Configuration

`IDENTRAIL_AWS_CFN_TEMPLATE_URL` points to the published CloudFormation template.

`IDENTRAIL_AWS_ACCOUNT_ID` is the AWS account ID for the Identrail deployment that customer roles should trust.

When a persistent database is configured and AWS connector setup is enabled, `IDENTRAIL_CONNECTOR_SECRET_KEYS` must also be configured. The generated External ID is stored as a connector secret envelope, not plaintext connector metadata.

## Flow

1. The UI calls `POST /v1/connectors/aws` with `workspace_id` and `project_id`.
2. The API generates a 32-byte External ID, stores it encrypted, creates a pending AWS connector, and returns an AWS CloudFormation launch URL.
3. The user launches the stack in AWS. The stack creates an `IdentrailReadOnly` role with a trust policy requiring the External ID.
4. The user pastes the created role ARN back into Identrail.
5. The API uses the stored External ID, assumes the role with STS, verifies caller identity, checks scanner-critical IAM read access, and marks the connector active or degraded.

The read-only policy and rationale live together under `deploy/connectors/aws/policies/`.
