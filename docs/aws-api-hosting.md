# AWS API Hosting

This document describes the first AWS API and worker hosting layer for Identrail.

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
- a private S3 bucket for self-serve account data export bundles

When `create_worker_hosting_resources=true`, the same Terraform root also
creates a private ECS/Fargate worker service in the API cluster. The hosted
worker uses the same database, auth, connector, and repo-scan runtime settings
as the API, but sets `IDENTRAIL_WORKER_SCAN_ENABLED=false` and
`IDENTRAIL_WORKER_API_JOB_QUEUE_ENABLED=true` by default. That means the first
hosted worker drains queued API jobs, including GitHub repo scans submitted
from the app, without also launching unrelated periodic cloud scans.

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

The worker task has its own execution role, task role, and egress-only security
group. It inherits `api_secrets` and may receive worker-only overrides through
`worker_secrets`; secret values still stay in Secrets Manager rather than
Terraform state.

The hosted API plan also creates and wires `IDENTRAIL_USER_DATA_EXPORT_S3_*`
settings by default. The API and worker task roles can read, write, and delete
objects only under the configured export prefix. The bucket blocks public
access, uses server-side encryption, and expires completed export objects after
`user_data_export_retention_days` days. A downloaded ZIP contains
`manifest.json`, `user.json`, `workspaces.json`, `audit.json`, and
`sessions.json`; it does not include session token material or session ID
hashes.

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

For routine hosted API releases, `Publish Container Images` starts the
`Deploy to prod` workflow after the current `dev` image is available. An
operator approves the protected `production` environment; a manual dispatch is
available for recovery. The workflow resolves the
matching `ghcr.io/identrail/identrail-api:sha-<current-dev-commit>` and
`ghcr.io/identrail/identrail-worker:sha-<current-dev-commit>` images, verifies
that `CI` and `Publish Container Images` passed for that exact commit, confirms
both immutable image tags exist in GHCR, waits for the `production` GitHub
Environment approval when environment protection is configured, runs the
database migration workflow, publishes the CloudFormation connector template
under its SHA-256 digest, deploys the API and worker with that exact URL and
checksum, and then checks `/healthz`, `/readyz`, `/v1/auth/config`, AWS rollout
reconciliation, and connector lifecycle routes. This keeps hosted API code,
worker code, and the database schema in the same release boundary instead of
requiring operators to remember image tags or the migration and deploy order by
hand.

Repository configuration required before the workflow can plan:

- secret `AWS_ROLE_ARN`: GitHub OIDC deployment role ARN
- secret `AWS_CFN_TEMPLATE_SETUP_ROLE_ARN`: dedicated GitHub OIDC role for
  the protected template bucket policy setup workflow
- variable `AWS_REGION`: AWS region, such as `us-east-1`
- variable `AWS_TERRAFORM_STATE_BUCKET`: existing S3 bucket for Terraform state
- variable `AWS_CFN_TEMPLATE_BUCKET`: private-write/public-read bucket used to
  publish immutable connector templates; defaults to
  `identrail-cloudformation-templates`
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

The template bucket name must use lowercase letters, numbers, and hyphens only;
dotted S3 names are rejected because the release uses a virtual-hosted HTTPS
URL whose wildcard certificate does not cover dotted bucket hostnames. The
template bucket is an external, operator-owned prerequisite. Configure S3
Object Ownership as `Bucket owner enforced`, keep public writes blocked, and
merge this statement into the bucket policy (replace `BUCKET_NAME` with the
configured bucket name):

```json
{
  "Sid": "IdentrailCloudFormationTemplatePublicRead",
  "Effect": "Allow",
  "Principal": "*",
  "Action": "s3:GetObject",
  "Resource": "arn:aws:s3:::BUCKET_NAME/connectors/aws/sha256/*"
}
```

Do not grant anonymous `s3:ListBucket` or public write access. The `AWS_ROLE_ARN`
deployment role needs `s3:PutObject` and `s3:GetObject` on
`connectors/aws/sha256/*/identrail-readonly.yaml`; it does not need
`s3:PutObjectAcl`. It also remains separate from the setup role below.

The dedicated setup role needs these least-privilege permissions:

- `s3:GetBucketPolicy`, `s3:PutBucketPolicy`, and
  `s3:GetBucketPublicAccessBlock` on the exact bucket resource
  `arn:aws:s3:::BUCKET_NAME`;
- `s3:ListBucket` on the exact bucket resource
  `arn:aws:s3:::BUCKET_NAME`, conditioned with
  `StringLike: {"s3:prefix": "connectors/aws/sha256/*"}` so the workflow can
  distinguish a missing digest from a public-read failure;
- `s3:GetAccountPublicAccessBlock` and `sts:GetCallerIdentity` on `*`.

Do not grant `s3:PutBucketPolicy` on `*` or on an object ARN: S3 evaluates that
permission against the bucket ARN. Replace `BUCKET_NAME` in the role policy
with the one configured template bucket.

The preferred provisioning path is the manually dispatched
`AWS Template Bucket Policy Setup` workflow
(`.github/workflows/aws-cfn-template-bucket-policy.yml`) from the `dev`
branch. Type `configure-cfn-template-bucket` when dispatching it; the
workflow reads the bucket and region from the repository variables (it has no
free-form bucket or region inputs), pauses at the protected `production`
environment, assumes only the dedicated `AWS_CFN_TEMPLATE_SETUP_ROLE_ARN`,
applies the idempotent helper, and records an anonymous-read probe in the run
summary. The setup role trust must be limited to
`repo:identrail/identrail:ref:refs/heads/dev`, and its bucket-policy mutation
permission must target only the exact configured bucket. Keep the normal
`AWS_ROLE_ARN` deployment role separate and without bucket-policy mutation
permissions.

For a break-glass or local setup, run the same idempotent helper from the
repository root after setting the bucket and region:

```bash
AWS_CFN_TEMPLATE_BUCKET=identrail-cloudformation-templates \
AWS_REGION=us-east-1 \
./scripts/configure_cfn_template_bucket_policy.sh
```

The helper preserves unrelated bucket-policy statements and replaces only its
own statement by `Sid`. The release workflow then verifies the public S3 URL
and its SHA-256 digest before migrations or API deployment begin. It also
publishes with and verifies SSE-S3 (`AES256`); do not use SSE-KMS for this
prefix because the anonymous CloudFormation fetch cannot authorize a KMS key.
An existing digest encrypted with KMS is rejected and never overwritten by the
write-once path. Verify its SHA-256, then perform a controlled one-time
same-key re-encryption with SSE-S3 before retrying the release. ACLs are
intentionally not used.

For that one-time migration, sample the current ETag first, condition the
authenticated download on that ETag, verify the downloaded bytes, and use the
same ETag as the compare-and-swap guard when copying the object onto itself with
SSE-S3:

```bash
key=connectors/aws/sha256/DIGEST/identrail-readonly.yaml
digest=DIGEST
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

etag="$(aws s3api head-object \
  --bucket "$AWS_CFN_TEMPLATE_BUCKET" \
  --key "$key" \
  --query ETag \
  --output text | tr -d '"')"
aws s3api get-object \
  --bucket "$AWS_CFN_TEMPLATE_BUCKET" \
  --key "$key" \
  --if-match "$etag" \
  "$tmp" >/dev/null
test "$(sha256sum "$tmp" | awk '{print $1}')" = "$digest"
aws s3api copy-object \
  --bucket "$AWS_CFN_TEMPLATE_BUCKET" \
  --copy-source "$AWS_CFN_TEMPLATE_BUCKET/$key" \
  --key "$key" \
  --copy-source-if-match "$etag" \
  --metadata-directive REPLACE \
  --content-type "application/x-yaml" \
  --cache-control "public,max-age=31536000,immutable" \
  --server-side-encryption AES256
```

Run this migration with a dedicated, one-time migration role rather than the
GitHub deployment or bucket-policy setup role. Its temporary permissions should
be limited to the exact digest object and source KMS key:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "MigrateOneTemplateObject",
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:PutObject"],
      "Resource": "arn:aws:s3:::BUCKET_NAME/connectors/aws/sha256/DIGEST/identrail-readonly.yaml"
    },
    {
      "Sid": "DecryptOneTemplateObject",
      "Effect": "Allow",
      "Action": "kms:Decrypt",
      "Resource": "KMS_KEY_ARN"
    }
  ]
}
```

The KMS key policy must also allow this migration role to use
`kms:Decrypt`; an identity policy alone is insufficient when the key policy
does not delegate access. The SSE-S3 destination does not require
`kms:Encrypt`. Remove the temporary role permission and key-policy grant after
the migration, then rerun the release.

This is an operator migration for an already-published object; the release
workflow itself remains write-once and will not perform this overwrite.

The helper reads the bucket- and account-level S3 Block Public Access settings
before changing the policy. The effective settings must keep
`BlockPublicAcls=true` and `IgnorePublicAcls=true`, while allowing this narrow
public policy with `BlockPublicPolicy=false` and `RestrictPublicBuckets=false`.
It never changes those settings. If an organization or account policy enforces
all four blocks, this anonymous S3 URL design is incompatible and the helper
fails without changing the bucket policy.

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

Hosted GitHub connector setup is enabled by default for Identrail Cloud API
deploys. Configure these values before running the manual workflow, or set
`API_FEATURE_CONNECTOR_GITHUB_V2=false` as the explicit rollback knob:

- variable `API_GITHUB_APP_ID`: GitHub App numeric id.
- variable `API_GITHUB_APP_NAME`: GitHub App slug used in installation URLs.
- secret `API_GITHUB_APP_PRIVATE_KEY_SECRET_ARN`: Secrets Manager ARN
  containing `IDENTRAIL_GITHUB_APP_PRIVATE_KEY`.
- secret `API_GITHUB_APP_WEBHOOK_SECRET_ARN`: Secrets Manager ARN containing
  `IDENTRAIL_GITHUB_APP_WEBHOOK_SECRET`.
- secret `API_CONNECTOR_SECRET_KEYS_SECRET_ARN`: Secrets Manager ARN containing
  the durable `IDENTRAIL_CONNECTOR_SECRET_KEYS` keyset used to encrypt connector
  credentials.

The GitHub App itself must be public / installable on Any account for GitHub to
show the account picker with personal and organization targets. The app settings
must also use `https://app.identrail.com/app/github/callback` as the setup URL.
Leave "Redirect on update" disabled: update redirects do not carry the install
state token the callback requires, so enabling it would route users to an error
page — repository selection changes are reconciled through the
`installation_repositories` webhook instead. Run this before a production deploy
when GitHub App settings change:

```bash
python3 scripts/check_github_app_manifest.py --slug "${API_GITHUB_APP_NAME}"
```

The `Deploy to prod` workflow always deploys an immutable current-commit image,
such as `ghcr.io/identrail/identrail-api:sha-<commit>`. Do not deploy the
mutable `dev` tag to this hosted API path. Use `AWS API Manual Deploy` only for
lower-level planning, explicit rollback, or emergency overrides that require a
specific immutable image.

Worker hosting is enabled by default in this manual workflow through
`API_WORKER_ENABLED=true`. If `API_WORKER_CONTAINER_IMAGE` is omitted, the
preparation script derives the matching immutable worker image from the API
image tag, for example `ghcr.io/identrail/identrail-worker:sha-<commit>`.
When deploying the API image by digest, set `API_WORKER_CONTAINER_IMAGE`
explicitly to the matching immutable worker digest. Set
`API_WORKER_ENABLED=false` only as a rollback knob when the API should stay up
but queued scan processing must be paused.

Optional repository variables:

- `API_ALLOWED_CIDR_BLOCKS_JSON`
- `API_CORS_ALLOWED_ORIGINS_JSON`
- `API_TRUSTED_PROXY_CIDR_BLOCKS_JSON`
- `API_FEATURE_ONBOARDING_WIZARD`: defaults to `true` for Identrail Cloud; set
  to `false` only as a rollback knob for the onboarding API
- `API_FEATURE_WORKOS_LOGIN`: defaults to `true` when the first-class WorkOS
  deployment settings above are provided
- `API_FEATURE_CONNECTOR_GITHUB_V2`: defaults to `true` for Identrail Cloud; set
  to `false` only as a rollback knob for the GitHub connector API
- `API_REPO_SCAN_ENABLED`: set to `true` only when the hosted API should accept
  repository scan queue requests; omitted means the application default remains
  disabled
- `API_REPO_SCAN_ALLOWLIST`: required when `API_REPO_SCAN_ENABLED=true`;
  comma-separated exact repositories or prefix wildcards, for example
  `identrail/identrail` or `trusted-org/*`
- `API_REPO_SCAN_HISTORY_LIMIT`
- `API_REPO_SCAN_MAX_FINDINGS`
- `API_REPO_SCAN_HISTORY_LIMIT_MAX`
- `API_REPO_SCAN_MAX_FINDINGS_MAX`
- `API_REPO_SCAN_QUEUE_MAX_PENDING`
- `API_EMAIL_PROVIDER`: set to `resend` to enable backend transactional email
  for hosted API signup flows.
- `API_EMAIL_FROM_ADDRESS`: verified sender used by transactional email, such
  as `Identrail <hello@send.identrail.com>`. Required when
  `API_EMAIL_PROVIDER=resend`.
- `API_EMAIL_REPLY_TO_ADDRESS`: optional reply-to address, such as
  `support@identrail.com`.
- `API_EMAIL_APP_BASE_URL`: optional web-app origin used for email CTA links
  when it differs from `IDENTRAIL_PUBLIC_BASE_URL`, such as
  `https://app.identrail.com`.
- `API_EMAIL_TIMEOUT`: optional Resend request timeout. The runtime default is
  `3s`.
- `API_WORKER_ENABLED`: defaults to `true`; set to `false` to deploy only the
  hosted API and leave queued scans pending
- `API_WORKER_CONTAINER_IMAGE`: optional immutable worker image; blank derives
  the matching `identrail-worker` image from `api_container_image`
- `API_WORKER_DESIRED_COUNT`: defaults to `1`
- `API_WORKER_TASK_CPU`: defaults to `256`
- `API_WORKER_TASK_MEMORY`: defaults to `512`
- `API_EXTRA_ENVIRONMENT_JSON`: JSON object for additional non-secret runtime
  variables. Use this to enable native SAML/SCIM, for example
  `{"IDENTRAIL_FEATURE_NATIVE_SSO":"true"}`.
- `API_SECRET_KMS_KEY_ARNS_JSON`
- `API_CONNECTOR_ROLE_ARNS_JSON`

The first-class `API_REPO_SCAN_*` variables override matching
`IDENTRAIL_REPO_SCAN_*` keys in `API_EXTRA_ENVIRONMENT_JSON` when they are set.
The preparation script fails before Terraform if repository scans are enabled
without an effective allowlist. With the default worker deployment enabled, the
workflow configures both sides of the flow: the API accepts and queues
repository scan requests, and the worker processes those queued scans.

Optional repository secret:

- `API_EMAIL_API_KEY_SECRET_ARN`: Secrets Manager ARN containing the Resend API
  key for `IDENTRAIL_EMAIL_API_KEY`. Prefer this first-class secret over
  editing `API_EXTRA_SECRETS_JSON`, because GitHub hides existing secret values
  on update pages. This secret can be created before email is enabled; email is
  enabled by setting `API_EMAIL_PROVIDER=resend`. If email provider/from settings
  already live in `API_EXTRA_ENVIRONMENT_JSON`, this secret still supplies
  `IDENTRAIL_EMAIL_API_KEY` without editing `API_EXTRA_SECRETS_JSON`.
- `API_EXTRA_SECRETS_JSON`: JSON object mapping additional runtime secret
  environment variable names to Secrets Manager ARNs for future provider
  secrets. Prefer the first-class WorkOS and transactional email settings above
  for hosted auth and email.

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
- final `api.identrail.com` DNS cutover
