# AWS OIDC Deployment Role

Identrail deploys AWS infrastructure from GitHub Actions through OpenID Connect (OIDC), not long-lived AWS access keys.

## Why This Exists

GitHub Actions receives short-lived AWS credentials only when AWS can verify the workflow identity. The current production trust target is:

```text
repo:identrail/identrail:ref:refs/heads/dev
```

That means PR branches and forks cannot assume the deployment role. The first AWS workflow is intentionally a verification-only workflow before any infrastructure is created.

## GitHub Repository Configuration

Required repository secret:

```text
AWS_ROLE_ARN=arn:aws:iam::263434643405:role/IdentrailGithubDeployRole
```

Required repository variable:

```text
AWS_REGION=us-east-1
```

## AWS Trust Policy

The role trust policy should allow only the `dev` branch in this repository:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::263434643405:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
          "token.actions.githubusercontent.com:sub": "repo:identrail/identrail:ref:refs/heads/dev"
        }
      }
    }
  ]
}
```

## Verification Workflow

The workflow `.github/workflows/aws-oidc-verification.yml` does three things:

1. Requests a GitHub OIDC token for `sts.amazonaws.com`.
2. Assumes `AWS_ROLE_ARN` with `aws sts assume-role-with-web-identity`.
3. Runs `aws sts get-caller-identity` and verifies the returned AWS account and role.

It does not create, modify, or delete AWS resources.

Because the trust policy is scoped to `refs/heads/dev`, the workflow is expected to run only after this workflow file is on `dev` or when manually dispatched from `dev`.
