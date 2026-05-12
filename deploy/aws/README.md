# AWS Deployment

This directory contains the AWS-specific deployment foundation for Identrail.

The first foundation module is intentionally safe by default:

- It validates AWS provider wiring and naming conventions.
- It defines production-adjacent primitives needed by later API hosting work.
- It does not create resources unless `create_foundation_resources=true`.
- It does not deploy the Identrail API, worker, database, or public domains yet.

## Current Scope

- Terraform foundation: `terraform/`
- GitHub OIDC role verification: `.github/workflows/aws-oidc-verification.yml`
- Dev-only foundation plan workflow: `.github/workflows/aws-deployment-foundation.yml`

## Expected Order

1. Verify GitHub can assume the AWS deployment role through OIDC.
2. Validate and plan this AWS foundation.
3. Add the API hosting stack.
4. Add database, secrets, migrations, and domain cutover.

Keep production applies manual until the API hosting stack and rollback runbook
are both in place.
