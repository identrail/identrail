# AWS Terraform Foundation

This Terraform root prepares AWS deployment primitives for Identrail without
deploying the application yet.

## What It Can Create

When `create_foundation_resources=true`, the root can create:

- CloudWatch log groups for API and worker workloads.
- A Secrets Manager secret metadata record for future runtime configuration.

It does not write secret values. Runtime secrets should be injected by the
operator or a dedicated secrets workflow after the hosting stack exists.

## Safe Defaults

The default configuration sets `create_foundation_resources=false`, so CI and
pull requests can run `terraform init`, `terraform validate`, and `terraform
plan` without creating billable AWS resources.

## Local Validation

```bash
cd deploy/aws/terraform
terraform init -backend=false
terraform fmt -check -recursive
terraform validate
terraform plan -refresh=false -input=false -var-file=environments/dev/terraform.tfvars.example
```

## Manual Dev Plan With Resources Enabled

Only run this when you intentionally want to see the resources Terraform would
create in the target AWS account:

```bash
cd deploy/aws/terraform
terraform plan \
  -input=false \
  -var-file=environments/dev/terraform.tfvars.example \
  -var='create_foundation_resources=true'
```

Do not run `terraform apply` from this foundation until the API hosting stack,
database plan, secrets handling, and rollback runbook are ready.
