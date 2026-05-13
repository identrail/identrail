# AWS Deployment Foundation

The AWS deployment foundation is the step after GitHub OIDC verification.

PR 7A proved that GitHub Actions can request short-lived AWS credentials without
long-lived access keys. This foundation gives the repository a safe place to
validate AWS deployment plans before production traffic is moved.

## What This Does Now

- Adds an AWS Terraform root at `deploy/aws/terraform`.
- Adds safe, opt-in foundation resources for future API and worker hosting.
- Adds a safe, opt-in API hosting layer for ECS/Fargate, HTTPS load balancing,
  task roles, logs, health checks, and autoscaling.
- Adds a dev workflow that assumes the AWS OIDC role and runs Terraform plan.
- Keeps `terraform apply` manual and out of CI.

## What It Does Not Do Yet

- It does not deploy the Identrail API to AWS unless an operator explicitly
  enables `create_api_hosting_resources=true` and runs a manual apply.
- It does not create a production database.
- It does not change `app.identrail.com` or `api.identrail.com`.
- It does not move traffic away from the current Vercel deployment.

## Why Resource Creation Defaults Off

The first AWS deployment PR should prove the path without spending money or
creating surprise infrastructure. The Terraform root defaults
`create_foundation_resources=false` and
`create_api_hosting_resources=false`, so CI can validate the stack without
creating spend. Operators can intentionally enable each resource group when the
API hosting design, secrets, database, image tag, and rollback plan are ready.

## Next Deployment Step

The next deployment step is a manual AWS plan for a real environment, then the
database, runtime secrets, migration path, and `api.identrail.com` DNS cutover.
See `aws-api-hosting.md`.
