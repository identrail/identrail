# AWS API Hosting

This document describes the first AWS API hosting layer for Identrail.

The Terraform remains plan-first and safe by default. CI validates the shape, but
does not create AWS resources or move production traffic.

## What The Layer Defines

When `create_api_hosting_resources=true`, `deploy/aws/terraform` can create:

- an ECS/Fargate API cluster, task definition, service, and CPU autoscaling
- an application load balancer with HTTPS listener and optional HTTP redirect
- security groups that allow public HTTPS to the load balancer and private
  traffic from the load balancer to the API tasks
- task execution and task IAM roles
- CloudWatch logs for API runtime output

The ECS task definition sets production-oriented runtime defaults for the hosted
API: `IDENTRAIL_AWS_SOURCE=sdk`, `IDENTRAIL_REQUIRE_LIVE_SOURCES=true`, and
`IDENTRAIL_AWS_REGION` from `aws_region`. It also sets `IDENTRAIL_HTTP_ADDR`
from `api_container_port` so the app listens on the port exposed to the load
balancer, `IDENTRAIL_CORS_ALLOWED_ORIGINS` from `api_cors_allowed_origins`, and
`IDENTRAIL_TRUSTED_PROXIES` from `api_trusted_proxy_cidr_blocks` so browser
requests from the Vercel app and ALB forwarded client IPs work before DNS
cutover. Terraform refuses overrides that would move the hosted API back to
fixture-backed AWS scans. It also sets `IDENTRAIL_RUN_MIGRATIONS=false` and
`IDENTRAIL_RUN_MIGRATIONS_ONLY=false` so rolling ECS API deployments do not run
schema changes during normal service startup.

The API task role receives the read-only IAM discovery permissions that the live
AWS collector uses. Cross-account connector access is still explicit: add
approved connector role ARNs to `api_connector_role_arns` only after those roles
exist and have been reviewed.

## Required Operator Inputs

Before a manual apply, operators must provide:

- `api_vpc_id`
- `api_public_subnet_ids` for the load balancer, with at least two distinct
  public subnets in different Availability Zones; Terraform reads the subnet
  metadata and refuses to plan API hosting when the public subnets collapse to
  one Availability Zone, do not belong to `api_vpc_id`, or do not have route
  tables with an Internet Gateway default route; explicit subnet route-table
  associations and inherited VPC main route tables are both supported
- `api_private_subnet_ids` for Fargate tasks, with at least two distinct private
  subnets that belong to `api_vpc_id`
- `api_private_subnet_egress_ready=true` after confirming those private subnets
  have NAT egress or VPC endpoints for ECR, Secrets Manager, CloudWatch Logs,
  and S3 image-layer access; API tasks run with `assign_public_ip=false`
- for the low-cost first cutover only, `api_task_subnet_ids` may point at the
  same two public subnets used by the load balancer with
  `api_task_assign_public_ip=true`; this avoids NAT Gateway or VPC endpoint
  hourly charges while keeping task ingress restricted to the ALB security group
- `api_certificate_arn` for HTTPS on `api.identrail.com`
- `api_container_image` pinned to an immutable release tag
- `api_cors_allowed_origins`, defaulting to the Identrail Cloud web origins;
  entries must be bare HTTPS origins such as `https://app.identrail.com`, not
  URLs with paths, queries, fragments, or trailing slashes
- `api_trusted_proxy_cidr_blocks`, defaulting to private VPC ranges used by ALB
  nodes in common AWS VPCs
- `api_secrets`, including `IDENTRAIL_DATABASE_URL` as a Secrets Manager ARN
- `api_secret_kms_key_arns` when any referenced secret uses a
  customer-managed KMS key
- at least one supported API authentication mode:
  - scoped API keys with `IDENTRAIL_API_KEY_SCOPES`
  - legacy keys with both `IDENTRAIL_API_KEYS` and `IDENTRAIL_WRITE_API_KEYS`
  - OIDC with both `IDENTRAIL_OIDC_ISSUER_URL` and `IDENTRAIL_OIDC_AUDIENCE`
  - hosted session auth with non-secret `IDENTRAIL_FEATURE_NEW_AUTH=true` and
    `IDENTRAIL_PUBLIC_BASE_URL`, plus `IDENTRAIL_SESSION_KEY` in `api_secrets`

Hosted self-serve onboarding is a post-login flow, not an auth mode. For the
Identrail Cloud path, keep at least one auth mode above configured and enable
`IDENTRAIL_FEATURE_ONBOARDING_WIZARD=true` when first-time users should create
their org and workspace after login.

## Manual GitHub Actions Deployment

Use the `AWS API Manual Deploy` workflow for the first controlled
`api.identrail.com` cutover. The workflow is manual by design: it plans by
default, stores Terraform state in S3, and only applies when an operator selects
`apply` and types `apply-api.identrail.com` in the confirmation field.
Run it from the `dev` branch because the AWS OIDC deployment role trust is
intentionally scoped to that branch.

Repository configuration required before the workflow can plan:

- secret `AWS_ROLE_ARN`: GitHub OIDC deployment role ARN
- variable `AWS_REGION`: AWS region, such as `us-east-1`
- variable `AWS_TERRAFORM_STATE_BUCKET`: existing S3 bucket for Terraform state
- optional variable `AWS_TERRAFORM_STATE_KEY`: defaults to
  `identrail/dev/aws-api.tfstate`
- variable `API_VPC_ID`: VPC for the API load balancer and ECS service
- variable `API_PUBLIC_SUBNET_IDS_JSON`: JSON array of at least two public
  subnet IDs, for example `["subnet-aaa","subnet-bbb"]`
- optional variable `API_TASK_SUBNET_IDS_JSON`: JSON array of task subnet IDs;
  leave blank for the low-cost public-task bootstrap path
- variable `API_CERTIFICATE_ARN`: ACM certificate ARN for `api.identrail.com`
- secret `API_DATABASE_URL_SECRET_ARN`: Secrets Manager ARN containing
  `IDENTRAIL_DATABASE_URL`
- secret `API_SESSION_KEY_SECRET_ARN`: Secrets Manager ARN containing
  `IDENTRAIL_SESSION_KEY`

Hosted WorkOS login is optional. Configure these values only when deploying the
hosted sign-in/sign-up flow:

- variable `API_WORKOS_CLIENT_ID`: WorkOS production client ID, such as
  `client_...`
- variable `API_WORKOS_ENVIRONMENT_ID`: WorkOS production environment ID, such
  as `environment_...`
- secret `API_WORKOS_API_KEY_SECRET_ARN`: Secrets Manager ARN containing
  `IDENTRAIL_WORKOS_API_KEY`
- secret `API_WORKOS_WEBHOOK_SECRET_ARN`: Secrets Manager ARN containing
  `IDENTRAIL_WORKOS_WEBHOOK_SECRET`

The workflow dispatch input `api_container_image` must be immutable, such as
`ghcr.io/identrail/identrail-api:sha-<commit>`. Do not deploy the mutable `dev`
tag to this hosted API path.

Optional repository variables:

- `API_ALLOWED_CIDR_BLOCKS_JSON`
- `API_CORS_ALLOWED_ORIGINS_JSON`
- `API_TRUSTED_PROXY_CIDR_BLOCKS_JSON`
- `API_FEATURE_ONBOARDING_WIZARD`: defaults to `true` for Identrail Cloud; set
  to `false` only as a rollback knob for the onboarding API
- `API_FEATURE_WORKOS_LOGIN`: defaults to `true` when the first-class WorkOS
  deployment settings above are provided
- `API_EXTRA_ENVIRONMENT_JSON`: JSON object for additional non-secret runtime
  variables. Use this to enable native SAML/SCIM, for example
  `{"IDENTRAIL_FEATURE_NATIVE_SSO":"true"}`.
- `API_SECRET_KMS_KEY_ARNS_JSON`
- `API_CONNECTOR_ROLE_ARNS_JSON`

Optional repository secret:

- `API_EXTRA_SECRETS_JSON`: JSON object mapping additional runtime secret
  environment variable names to Secrets Manager ARNs for future provider
  secrets. Prefer the first-class WorkOS settings above for hosted auth.

Do not put database URLs, API keys, cookie secrets, or OAuth credentials directly
in tfvars files, docs, GitHub variables, or Terraform state. Use Secrets Manager
references through `api_secrets`. Terraform rejects known secret-bearing
Identrail variables in `api_environment_variables` when API hosting is enabled.

If a referenced secret uses a customer-managed KMS key, add that key ARN to
`api_secret_kms_key_arns` so ECS can decrypt the secret during task startup.
Leave the list empty for secrets encrypted with the AWS-managed Secrets Manager
key.
`api_secrets` values can use ECS `valueFrom` selectors such as a JSON key or
secret version suffix. Terraform still grants IAM access to the base Secrets
Manager ARN so ECS can fetch the underlying secret during task startup.

For the first manual AWS plan, prefer Secrets Manager references for
`IDENTRAIL_DATABASE_URL`, `IDENTRAIL_API_KEY_SCOPES`, and, when tenant/workspace
isolation is ready, `IDENTRAIL_API_KEY_SCOPE_BINDINGS`. The Terraform guard will
refuse to plan API hosting without a database reference and at least one auth
mode so ECS tasks do not boot into a known-bad configuration. It also refuses to
plan API hosting without at least one HTTPS CORS origin and at least one trusted
proxy CIDR.

Terraform requires either private task egress or the explicit low-cost public
task mode before creating API hosting resources. Use
`api_private_subnet_egress_ready=true` only after the private task subnets can
pull the image, read injected secrets, and write logs through NAT or private VPC
endpoints. For the first budget-conscious Identrail Cloud cutover, set
`api_task_subnet_ids` to two public subnets and `api_task_assign_public_ip=true`
instead. This is cheaper because it avoids NAT Gateway, but it is still treated
as a bootstrap mode: keep task security-group ingress limited to the ALB, keep
`api_allowed_cidr_blocks` on the ALB, and move to private task subnets when
traffic, compliance, or customer requirements justify the extra cost.

The manual workflow uses the low-cost bootstrap mode by default: public task
subnets, `api_task_assign_public_ip=true`, and inbound service traffic limited
to the load balancer security group. That avoids NAT Gateway and private VPC
endpoint hourly charges during first launch.

Run database migrations with the `AWS API Database Migrations` workflow before
deploying or upgrading the hosted API service. Keep long-running API tasks
non-migrating.

The migration workflow is intentionally manual and guarded:

- run it from the `dev` branch
- keep the default `migrations` directory unless a release note says otherwise
- type `run-api-migrations` in the confirmation field
- leave `database_url_secret_arn` blank to use the repository secret
  `API_DATABASE_URL_SECRET_ARN`

The workflow assumes the same `AWS_ROLE_ARN` OIDC deployment role as the manual
deploy workflow, fetches the database URL from Secrets Manager at runtime, masks
the secret value, and runs `go run ./cmd/migrate`. It does not print the
database URL and it does not change the ECS service definition.

Leave `api_connector_role_arns` empty for the first single-account API hosting
plan. Populate it later with reviewed AWS connector role ARNs when the hosted API
needs to validate connector setup or run recurring scans through assumed roles.

## Health Checks

The load balancer uses `GET /healthz` by default. Before DNS cutover, verify the
API with the certificate hostname so TLS SNI and hostname validation match the
`api.identrail.com` certificate:

```bash
load_balancer_dns_name="$(terraform -chdir=deploy/aws/terraform output -raw api_load_balancer_dns_name)"
load_balancer_ip="$(dig +short "$load_balancer_dns_name" | head -n 1)"
curl -fsS --resolve "api.identrail.com:443:${load_balancer_ip}" \
  "https://api.identrail.com/healthz"
```

## Log Diagnostics

Use the `AWS API Log Diagnostics` workflow when the hosted API is healthy but an
operator needs recent CloudWatch application logs, such as a failed WorkOS auth
callback. The workflow is read-only: it assumes the same GitHub OIDC AWS role as
the deployment workflow, reads `/identrail/dev/api`, and redacts common secret,
token, database URL, OAuth code, and OAuth state shapes before printing matching
events.

The default filter pattern is `"authenticate workos callback"`, which targets
the callback exchange failure log emitted before the API returns
`{"error":"login failed"}`. To inspect recent API events without narrowing to
that auth path, use this exact filter pattern:

```text
<none>
```

## DNS Cutover

Do not point `api.identrail.com` at the load balancer until:

- the API health check is passing through the load balancer
- database migrations have been run in the target environment
- runtime secrets have been reviewed
- at least one authenticated API smoke test has passed
- the frontend `VITE_IDENTRAIL_API_URL` production value is ready for
  `https://api.identrail.com`
- rollback has been rehearsed

After those are true, create a DNS record for `api.identrail.com` that targets
the load balancer DNS name. Keep `app.identrail.com` on Vercel.

## Rollback

If the new API service fails before DNS cutover, destroy or disable only the AWS
API hosting resources and keep the frontend pointed at the previous API.

If the failure happens after DNS cutover:

1. Point `api.identrail.com` back to the last known-good API target.
2. Scale the ECS service down only after traffic has drained.
3. Preserve CloudWatch logs and database snapshots for investigation.
4. Re-run `GET /healthz` and one authenticated API smoke test on the restored
   target.

## What Still Comes Later

- production database provisioning and backups
- runtime secret creation and rotation workflow
- migration job wiring
- worker hosting
- final `api.identrail.com` DNS cutover
