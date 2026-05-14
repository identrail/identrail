#!/usr/bin/env bash
set -euo pipefail

trim() {
  local value="${1:-}"
  value="${value//$'\r'/}"
  value="${value//$'\n'/}"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "${value}"
}

fail() {
  echo "error: $*" >&2
  exit 1
}

require_value() {
  local name="$1"
  local value
  value="$(trim "${!name:-}")"
  if [ -z "${value}" ]; then
    fail "missing required environment variable ${name}"
  fi
  printf '%s' "${value}"
}

json_string_array() {
  local name="$1"
  local fallback="${2:-}"
  local raw
  raw="$(trim "${!name:-}")"
  if [ -z "${raw}" ]; then
    raw="${fallback}"
  fi
  if [ -z "${raw}" ]; then
    raw="[]"
  fi
  jq -ce --arg name "${name}" '
    if type == "array" and all(.[]; type == "string" and length > 0) then
      .
    else
      error($name + " must be a JSON array of non-empty strings")
    end
  ' <<< "${raw}"
}

json_string_map() {
  local name="$1"
  local raw
  raw="$(trim "${!name:-}")"
  if [ -z "${raw}" ]; then
    raw="{}"
  fi
  jq -ce --arg name "${name}" '
    if type == "object" and all(to_entries[]; (.key | test("^[A-Z][A-Z0-9_]*$")) and (.value | type == "string") and (.value | length > 0)) then
      .
    else
      error($name + " must be a JSON object whose keys are uppercase environment variable names and whose values are non-empty strings")
    end
  ' <<< "${raw}"
}

operation="$(trim "${API_DEPLOY_OPERATION:-plan}")"
case "${operation}" in
  plan|apply) ;;
  *) fail "API_DEPLOY_OPERATION must be plan or apply" ;;
esac

if [ "${operation}" = "apply" ]; then
  confirm="$(trim "${API_DEPLOY_CONFIRM:-}")"
  if [ "${confirm}" != "apply-api.identrail.com" ]; then
    fail "apply requires API_DEPLOY_CONFIRM=apply-api.identrail.com"
  fi
fi

aws_region="$(require_value AWS_REGION)"
if ! [[ "${aws_region}" =~ ^[a-z]{2}(-gov)?-[a-z]+-[0-9]+$ ]]; then
  fail "AWS_REGION must be an AWS region such as us-east-1"
fi

state_bucket="$(require_value TF_STATE_BUCKET)"
state_key="$(trim "${TF_STATE_KEY:-identrail/dev/aws-api.tfstate}")"
if [ -z "${state_key}" ]; then
  fail "TF_STATE_KEY must not be blank"
fi

api_vpc_id="$(require_value API_VPC_ID)"
if ! [[ "${api_vpc_id}" =~ ^vpc-[0-9a-f]+$ ]]; then
  fail "API_VPC_ID must look like vpc-0123456789abcdef0"
fi

api_certificate_arn="$(require_value API_CERTIFICATE_ARN)"
if ! [[ "${api_certificate_arn}" =~ ^arn:(aws|aws-us-gov|aws-cn):acm:${aws_region}:[0-9]{12}:certificate/.+ ]]; then
  fail "API_CERTIFICATE_ARN must be an ACM certificate ARN in ${aws_region}"
fi

api_container_image="$(require_value API_CONTAINER_IMAGE)"
if ! [[ "${api_container_image}" =~ ^ghcr\.io/identrail/identrail-api:(sha-[0-9a-f]{12,40}|v[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?)$ || "${api_container_image}" =~ ^ghcr\.io/identrail/identrail-api@sha256:[0-9a-f]{64}$ ]]; then
  fail "API_CONTAINER_IMAGE must be an immutable ghcr.io/identrail/identrail-api image, such as ghcr.io/identrail/identrail-api:sha-<commit>"
fi

api_database_secret="$(require_value API_DATABASE_URL_SECRET_ARN)"
api_session_secret="$(require_value API_SESSION_KEY_SECRET_ARN)"
for secret_arn in "${api_database_secret}" "${api_session_secret}"; do
  if ! [[ "${secret_arn}" =~ ^arn:(aws|aws-us-gov|aws-cn):secretsmanager:${aws_region}:[0-9]{12}:secret:.+ ]]; then
    fail "API secret references must be Secrets Manager ARNs in ${aws_region}"
  fi
done

public_subnets="$(json_string_array API_PUBLIC_SUBNET_IDS_JSON)"
task_subnets="$(json_string_array API_TASK_SUBNET_IDS_JSON "${public_subnets}")"
allowed_cidrs="$(json_string_array API_ALLOWED_CIDR_BLOCKS_JSON '["0.0.0.0/0"]')"
cors_origins="$(json_string_array API_CORS_ALLOWED_ORIGINS_JSON '["https://app.identrail.com","https://identrail.com","https://www.identrail.com"]')"
trusted_proxy_cidrs="$(json_string_array API_TRUSTED_PROXY_CIDR_BLOCKS_JSON '["10.0.0.0/8","172.16.0.0/12","192.168.0.0/16"]')"
connector_roles="$(json_string_array API_CONNECTOR_ROLE_ARNS_JSON '[]')"
secret_kms_keys="$(json_string_array API_SECRET_KMS_KEY_ARNS_JSON '[]')"
extra_environment="$(json_string_map API_EXTRA_ENVIRONMENT_JSON)"
extra_secrets="$(json_string_map API_EXTRA_SECRETS_JSON)"

api_desired_count="$(trim "${API_DESIRED_COUNT:-1}")"
api_task_cpu="$(trim "${API_TASK_CPU:-512}")"
api_task_memory="$(trim "${API_TASK_MEMORY:-1024}")"
for numeric in api_desired_count api_task_cpu api_task_memory; do
  if ! [[ "${!numeric}" =~ ^[0-9]+$ ]]; then
    fail "${numeric^^} must be a positive integer"
  fi
done

tfvars_path="$(trim "${OUTPUT_TFVARS_PATH:-${RUNNER_TEMP:-/tmp}/identrail-api.auto.tfvars.json}")"
backend_config_path="$(trim "${OUTPUT_BACKEND_CONFIG_PATH:-${RUNNER_TEMP:-/tmp}/identrail-api.backend.hcl}")"
mkdir -p "$(dirname "${tfvars_path}")" "$(dirname "${backend_config_path}")"

jq -n \
  --arg aws_region "${aws_region}" \
  --arg api_vpc_id "${api_vpc_id}" \
  --arg api_certificate_arn "${api_certificate_arn}" \
  --arg api_container_image "${api_container_image}" \
  --arg api_database_secret "${api_database_secret}" \
  --arg api_session_secret "${api_session_secret}" \
  --argjson api_public_subnet_ids "${public_subnets}" \
  --argjson api_task_subnet_ids "${task_subnets}" \
  --argjson api_allowed_cidr_blocks "${allowed_cidrs}" \
  --argjson api_cors_allowed_origins "${cors_origins}" \
  --argjson api_trusted_proxy_cidr_blocks "${trusted_proxy_cidrs}" \
  --argjson api_connector_role_arns "${connector_roles}" \
  --argjson api_secret_kms_key_arns "${secret_kms_keys}" \
  --argjson extra_environment "${extra_environment}" \
  --argjson extra_secrets "${extra_secrets}" \
  --argjson api_desired_count "${api_desired_count}" \
  --argjson api_task_cpu "${api_task_cpu}" \
  --argjson api_task_memory "${api_task_memory}" \
  '{
    aws_region: $aws_region,
    environment: "dev",
    name_prefix: "identrail",
    create_foundation_resources: true,
    create_api_hosting_resources: true,
    create_runtime_secret: true,
    api_vpc_id: $api_vpc_id,
    api_public_subnet_ids: $api_public_subnet_ids,
    api_task_subnet_ids: $api_task_subnet_ids,
    api_task_assign_public_ip: true,
    api_private_subnet_egress_ready: false,
    api_allowed_cidr_blocks: $api_allowed_cidr_blocks,
    api_cors_allowed_origins: $api_cors_allowed_origins,
    api_trusted_proxy_cidr_blocks: $api_trusted_proxy_cidr_blocks,
    api_certificate_arn: $api_certificate_arn,
    api_container_image: $api_container_image,
    api_desired_count: $api_desired_count,
    api_task_cpu: $api_task_cpu,
    api_task_memory: $api_task_memory,
    api_environment_variables: ($extra_environment + {
      IDENTRAIL_FEATURE_NEW_AUTH: "true",
      IDENTRAIL_PUBLIC_BASE_URL: "https://api.identrail.com"
    }),
    api_secrets: ($extra_secrets + {
      IDENTRAIL_DATABASE_URL: $api_database_secret,
      IDENTRAIL_SESSION_KEY: $api_session_secret
    }),
    api_secret_kms_key_arns: $api_secret_kms_key_arns,
    api_connector_role_arns: $api_connector_role_arns,
    tags: {
      Project: "identrail",
      Stage: "auth-rollout",
      ManagedBy: "github-actions"
    }
  }' > "${tfvars_path}"

cat > "${backend_config_path}" <<EOF
bucket = "${state_bucket}"
key    = "${state_key}"
region = "${aws_region}"
encrypt = true
EOF

if [ -n "${GITHUB_OUTPUT:-}" ]; then
  {
    echo "tfvars_path=${tfvars_path}"
    echo "backend_config_path=${backend_config_path}"
    echo "state_key=${state_key}"
  } >> "${GITHUB_OUTPUT}"
fi

echo "Prepared Terraform inputs for ${operation}."
echo "Terraform state: s3://${state_bucket}/${state_key}"
