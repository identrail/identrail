# AWS Deployment Foundation

The AWS deployment foundation is the step after GitHub OIDC verification.

PR 7A proved that GitHub Actions can request short-lived AWS credentials without
long-lived access keys. This foundation gives the repository a safe place to
validate AWS deployment plans before the production API hosting stack is added.

## What This Does Now

- Adds an AWS Terraform root at `deploy/aws/terraform`.
- Adds safe, opt-in foundation resources for future API and worker hosting.
- Adds a dev workflow that assumes the AWS OIDC role and runs Terraform plan.
- Keeps `terraform apply` manual and out of CI.

## What It Does Not Do Yet

- It does not deploy the Identrail API to AWS.
- It does not create a production database.
- It does not change `app.identrail.com` or `api.identrail.com`.
- It does not move traffic away from the current Vercel deployment.

## Why Resource Creation Defaults Off

The first AWS deployment PR should prove the path without spending money or
creating surprise infrastructure. The Terraform root defaults
`create_foundation_resources=false`, so CI can validate the stack and later PRs
can intentionally enable resources when the API hosting design is ready.

## Next Deployment Step

The next PR should add the actual API hosting layer on top of this foundation,
including service shape, database connectivity, runtime secrets, health checks,
and rollback instructions.
