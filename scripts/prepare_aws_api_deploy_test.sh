#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT

# When this test runs inside GitHub Actions the shell inherits GITHUB_OUTPUT
# from the workflow step. prepare_aws_api_deploy.sh writes deployment paths
# there, which would leak test-only values into the surrounding step's
# outputs. Unset it so the script's step-output behavior stays hermetic.
unset GITHUB_OUTPUT
# Pin the operation to plan so the test is deterministic regardless of the
# caller's API_DEPLOY_OPERATION. Without this, invoking from a shell or
# workflow that exports 'apply' trips the confirmation guard in
# prepare_aws_api_deploy.sh before the tfvars assertions ever run.
export API_DEPLOY_OPERATION=plan

export AWS_REGION=us-east-1
export AWS_ROLE_ARN=arn:aws:iam::111111111111:role/IdentrailGithubDeployRole
export TF_STATE_BUCKET=identrail-test-state
export API_VPC_ID=vpc-0123456789abcdef0
export API_CERTIFICATE_ARN=arn:aws:acm:us-east-1:111111111111:certificate/test
export API_CONTAINER_IMAGE=ghcr.io/identrail/identrail-api:sha-0123456789ab
export API_DATABASE_URL_SECRET_ARN=arn:aws:secretsmanager:us-east-1:111111111111:secret:database
export API_SESSION_KEY_SECRET_ARN=arn:aws:secretsmanager:us-east-1:111111111111:secret:session
export API_PUBLIC_SUBNET_IDS_JSON='["subnet-1"]'
export API_FEATURE_CONNECTOR_GITHUB_V2=false
export API_AWS_CONNECTOR_REGISTRATION_ENABLED=true
digest="$(printf 'a%.0s' {1..64})"
export API_AWS_CFN_TEMPLATE_URL="https://templates.example.com/connectors/aws/sha256/${digest}/identrail-readonly.yaml"
export API_AWS_CFN_TEMPLATE_SHA256="sha256:${digest}"
export OUTPUT_TFVARS_PATH="${tmp}/valid.tfvars.json"
export OUTPUT_BACKEND_CONFIG_PATH="${tmp}/backend.hcl"

"${root}/scripts/prepare_aws_api_deploy.sh" >/dev/null
jq -e --arg url "${API_AWS_CFN_TEMPLATE_URL}" --arg sha "${API_AWS_CFN_TEMPLATE_SHA256}" '
	  .create_aws_connector_registration_provider == true and
	  .api_environment_variables.IDENTRAIL_FEATURE_CONNECTOR_AWS == "true" and
	  .api_environment_variables.IDENTRAIL_AWS_ACCOUNT_ID == "111111111111" and
	  .api_environment_variables.IDENTRAIL_WORKER_AWS_ROLLOUT_ENABLED == "true" and
  .api_environment_variables.IDENTRAIL_AWS_CFN_TEMPLATE_URL == $url and
  .api_environment_variables.IDENTRAIL_AWS_CFN_TEMPLATE_SHA256 == $sha
' "${OUTPUT_TFVARS_PATH}" >/dev/null

wrong_digest="$(printf 'b%.0s' {1..64})"
export API_AWS_CFN_TEMPLATE_SHA256="sha256:${wrong_digest}"
if "${root}/scripts/prepare_aws_api_deploy.sh" >"${tmp}/invalid.out" 2>&1; then
  echo "expected mismatched template digest to fail" >&2
  exit 1
fi
grep -q "digest must match" "${tmp}/invalid.out"

# Registration-disabled path. Without this case a regression that leaked the
# AWS connector env vars, or flipped create_aws_connector_registration_provider
# on, would go unnoticed because every assertion above runs with registration
# enabled.
export API_AWS_CONNECTOR_REGISTRATION_ENABLED=false
export API_AWS_CFN_TEMPLATE_URL=""
export API_AWS_CFN_TEMPLATE_SHA256=""
export OUTPUT_TFVARS_PATH="${tmp}/disabled.tfvars.json"
"${root}/scripts/prepare_aws_api_deploy.sh" >/dev/null
jq -e '
  .create_aws_connector_registration_provider == false and
  (.api_environment_variables | has("IDENTRAIL_FEATURE_CONNECTOR_AWS") | not) and
  (.api_environment_variables | has("IDENTRAIL_AWS_ACCOUNT_ID") | not) and
  (.api_environment_variables | has("IDENTRAIL_WORKER_AWS_ROLLOUT_ENABLED") | not) and
  (.api_environment_variables | has("IDENTRAIL_AWS_CFN_TEMPLATE_URL") | not) and
  (.api_environment_variables | has("IDENTRAIL_AWS_CFN_TEMPLATE_SHA256") | not)
' "${OUTPUT_TFVARS_PATH}" >/dev/null

echo "prepare_aws_api_deploy tests passed"
