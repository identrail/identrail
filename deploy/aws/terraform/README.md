# AWS Terraform Foundation

This Terraform root prepares AWS deployment primitives for Identrail. It can
validate the foundation in CI and, when explicitly enabled by an operator,
define the API hosting layer that will eventually sit behind `api.identrail.com`.

## What It Can Create

When `create_foundation_resources=true`, the root can create:

- CloudWatch log groups for API and worker workloads.
- A Secrets Manager secret metadata record for future runtime configuration.

When `create_api_hosting_resources=true`, the root can also create:

- an ECS/Fargate cluster, task definition, service, and autoscaling policy for
  the Identrail API
- an internet-facing application load balancer with HTTPS listener and optional
  HTTP-to-HTTPS redirect
- API load balancer and ECS service security groups
- task execution and task IAM roles

It does not write secret values. Runtime secrets should be created by the
operator or a dedicated secrets workflow and referenced through `api_secrets`.
If those secrets use customer-managed KMS keys, list the key ARNs in
`api_secret_kms_key_arns` so ECS secret injection can decrypt them.
`api_secrets` may use ECS `valueFrom` selectors for JSON keys or versions, but
the generated IAM policy grants `GetSecretValue` on the underlying base secret
ARN so task startup has the correct access.
Do not place database URLs, API keys, session keys, or OAuth/webhook/HMAC
secrets in `api_environment_variables`; API hosting rejects known secret-bearing
Identrail variables there so Terraform state does not receive secret material.
When API hosting is enabled, Terraform also validates that the task has a
database reference and at least one supported Identrail authentication mode
before it will plan ECS resources.
The hosted API task also defaults to live AWS collection with
`IDENTRAIL_AWS_SOURCE=sdk`, `IDENTRAIL_REQUIRE_LIVE_SOURCES=true`, and
`IDENTRAIL_AWS_REGION` from `aws_region`. It binds the API process with
`IDENTRAIL_HTTP_ADDR` from `api_container_port`, allows the Identrail Cloud web
origins through `IDENTRAIL_CORS_ALLOWED_ORIGINS`, and configures
`IDENTRAIL_TRUSTED_PROXIES` from `api_trusted_proxy_cidr_blocks` so ALB
`X-Forwarded-For` client IPs are honored by audit and rate-limit paths.
Allowed CORS entries must be bare HTTPS origins such as
`https://app.identrail.com`, with no path, query, fragment, or trailing slash.
Long-running API tasks set `IDENTRAIL_RUN_MIGRATIONS=false`; run migrations
through a dedicated one-off migration step before deploying or upgrading the
service.
The task role includes the read-only IAM discovery calls required by that live
collector. Optional `sts:AssumeRole` access is limited to ARNs listed in
`api_connector_role_arns`.

## Safe Defaults

The default configuration sets both `create_foundation_resources=false` and
`create_api_hosting_resources=false`, so CI and pull requests can run
`terraform init`, `terraform validate`, and `terraform plan` without creating
billable AWS resources.

## Local Validation

```bash
cd deploy/aws/terraform
terraform init -backend=false
terraform fmt -check -recursive
terraform validate
terraform plan -refresh=false -input=false -var-file=environments/dev/terraform.tfvars.example
```

## Manual Dev Plan With Foundation Resources Enabled

Only run this when you intentionally want to see the resources Terraform would
create in the target AWS account:

```bash
cd deploy/aws/terraform
terraform plan \
  -input=false \
  -var-file=environments/dev/terraform.tfvars.example \
  -var='create_foundation_resources=true'
```

## Manual Dev Plan With API Hosting Enabled

Only run this after the VPC, at least two distinct public subnets in different
Availability Zones, at least two distinct private subnets, ACM certificate,
immutable API image, database, auth configuration, and Secrets Manager
references are ready. The API-hosting plan reads public and private subnet
metadata from AWS and fails before apply if the load balancer subnets are not
spread across at least two Availability Zones or if any provided subnet is
outside `api_vpc_id`. It also reads the public subnet route tables and requires
an Internet Gateway default route so the public API load balancer is reachable.
public subnets may use either an explicit subnet route-table association or the
VPC main route table.

```bash
cd deploy/aws/terraform
terraform plan \
  -input=false \
  -var-file=environments/dev/terraform.tfvars.example \
  -var='create_foundation_resources=true' \
  -var='create_api_hosting_resources=true' \
  -var='api_vpc_id=<vpc-id>' \
  -var='api_public_subnet_ids=["<public-subnet-a>","<public-subnet-b>"]' \
  -var='api_private_subnet_ids=["<private-subnet-a>","<private-subnet-b>"]' \
  -var='api_private_subnet_egress_ready=true' \
  -var='api_certificate_arn=<api-certificate-arn>' \
  -var='api_container_image=ghcr.io/identrail/identrail-api:<immutable-release-tag>' \
  -var='api_cors_allowed_origins=["https://app.identrail.com","https://identrail.com","https://www.identrail.com"]' \
  -var='api_trusted_proxy_cidr_blocks=["10.0.0.0/8","172.16.0.0/12","192.168.0.0/16"]' \
  -var='api_secrets={"IDENTRAIL_DATABASE_URL":"<database-url-secret-arn>","IDENTRAIL_API_KEY_SCOPES":"<api-key-scopes-secret-arn>"}' \
  -var='api_secret_kms_key_arns=[]' \
  -var='api_connector_role_arns=[]'
```

Do not run `terraform apply` until the database, runtime secrets, container
image tag, health checks, rollback plan, and DNS cutover plan have all been
reviewed.

Keep `api_connector_role_arns=[]` until reviewed AWS connector roles exist. Add
only those connector role ARNs when the hosted API should validate connector
setup or run recurring scans through assumed roles.

Set `api_private_subnet_egress_ready=true` only after the private task subnets
have NAT egress or private VPC endpoints for the services Fargate needs at
startup, including ECR API, ECR Docker, CloudWatch Logs, Secrets Manager, and
S3 access for image layers. Identrail API tasks run with `assign_public_ip=false`.

Set `api_enable_execute_command=true` only when operator IAM and audit
expectations are ready. The task role receives the required SSM Messages
permissions only when ECS Exec is enabled.
