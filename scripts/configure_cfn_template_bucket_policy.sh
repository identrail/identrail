#!/usr/bin/env bash
set -euo pipefail

bucket="${AWS_CFN_TEMPLATE_BUCKET:-}"
region="${AWS_REGION:-us-east-1}"

if [ -z "${bucket}" ]; then
  echo "AWS_CFN_TEMPLATE_BUCKET is required." >&2
  exit 1
fi
if ! [[ "${bucket}" =~ ^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$ ]]; then
  echo "AWS_CFN_TEMPLATE_BUCKET must use lowercase letters, numbers, and hyphens only; dotted names are incompatible with the release URL." >&2
  exit 1
fi
if ! [[ "${region}" =~ ^[a-z]{2}(-gov)?-[a-z]+-[0-9]+$ ]]; then
  echo "AWS_REGION must be an AWS region such as us-east-1." >&2
  exit 1
fi

case "${region}" in
  cn-*) partition="aws-cn" ;;
  us-gov-*) partition="aws-us-gov" ;;
  *) partition="aws" ;;
esac

template_resource="arn:${partition}:s3:::${bucket}/connectors/aws/sha256/*"
statement_sid="IdentrailCloudFormationTemplatePublicRead"
temp_dir="$(mktemp -d)"
trap 'rm -rf -- "${temp_dir}"' EXIT

bucket_public_access_block_error="${temp_dir}/get-bucket-public-access-block.err"
if ! bucket_public_access_block="$(
  aws s3api get-public-access-block \
    --bucket "${bucket}" \
    --region "${region}" \
    --query PublicAccessBlockConfiguration \
    --output json 2>"${bucket_public_access_block_error}"
)"; then
  if grep -qi "NoSuchPublicAccessBlockConfiguration\|PublicAccessBlockConfigurationNotFound\|404" "${bucket_public_access_block_error}"; then
    bucket_public_access_block='{}'
  else
    cat "${bucket_public_access_block_error}" >&2
    exit 1
  fi
fi

account_id_error="${temp_dir}/get-account-id.err"
if ! account_id="$(
  aws sts get-caller-identity \
    --query Account \
    --output text 2>"${account_id_error}"
)"; then
  cat "${account_id_error}" >&2
  exit 1
fi
if ! [[ "${account_id}" =~ ^[0-9]{12}$ ]]; then
  echo "AWS did not return a 12-digit account id; refusing to apply a public policy." >&2
  exit 1
fi

account_public_access_block_error="${temp_dir}/get-account-public-access-block.err"
if ! account_public_access_block="$(
  aws s3control get-public-access-block \
    --account-id "${account_id}" \
    --region "${region}" \
    --query PublicAccessBlockConfiguration \
    --output json 2>"${account_public_access_block_error}"
)"; then
  if grep -qi "NoSuchPublicAccessBlockConfiguration\|PublicAccessBlockConfigurationNotFound\|404" "${account_public_access_block_error}"; then
    account_public_access_block='{}'
  else
    cat "${account_public_access_block_error}" >&2
    exit 1
  fi
fi

if ! jq -e 'type == "object"' >/dev/null <<<"${bucket_public_access_block}" || \
  ! jq -e 'type == "object"' >/dev/null <<<"${account_public_access_block}"; then
  echo "S3 returned an invalid public-access-block configuration; refusing to apply a public policy." >&2
  exit 1
fi

effective_public_access_block="$(
  jq -n \
    --argjson bucket "${bucket_public_access_block}" \
    --argjson account "${account_public_access_block}" \
    '
      def enabled($name): (($bucket[$name] // false) or ($account[$name] // false));
      {
        BlockPublicAcls: enabled("BlockPublicAcls"),
        IgnorePublicAcls: enabled("IgnorePublicAcls"),
        BlockPublicPolicy: enabled("BlockPublicPolicy"),
        RestrictPublicBuckets: enabled("RestrictPublicBuckets")
      }
    '
)"
if ! jq -e '
  .BlockPublicAcls == true
  and .IgnorePublicAcls == true
  and .BlockPublicPolicy == false
  and .RestrictPublicBuckets == false
' >/dev/null <<<"${effective_public_access_block}"; then
  echo "The effective S3 public-access-block settings are incompatible with this scoped public-read policy." >&2
  echo "Require BlockPublicAcls=true and IgnorePublicAcls=true, while allowing only this policy path with BlockPublicPolicy=false and RestrictPublicBuckets=false." >&2
  echo "Bucket-level settings:" >&2
  jq . <<<"${bucket_public_access_block}" >&2
  echo "Account-level settings:" >&2
  jq . <<<"${account_public_access_block}" >&2
  exit 1
fi

policy_error="${temp_dir}/get-policy.err"
if ! policy_json="$(
  aws s3api get-bucket-policy \
    --bucket "${bucket}" \
    --region "${region}" \
    --query Policy \
    --output text 2>"${policy_error}"
)"; then
  if grep -qi "NoSuchBucketPolicy\|PolicyNotFound\|404" "${policy_error}"; then
    policy_json='{"Version":"2012-10-17","Statement":[]}'
  else
    cat "${policy_error}" >&2
    exit 1
  fi
fi

if ! jq -e 'type == "object"' >/dev/null <<<"${policy_json}"; then
  echo "The existing bucket policy is not a JSON object; refusing to replace it." >&2
  exit 1
fi

merged_policy="${temp_dir}/bucket-policy.json"
jq \
  --arg statement_sid "${statement_sid}" \
  --arg template_resource "${template_resource}" \
  '
    .Version = (.Version // "2012-10-17")
    | .Statement = (
        if .Statement == null then []
        elif (.Statement | type) == "array" then .Statement
        elif (.Statement | type) == "object" then [.Statement]
        else error("Statement must be an object or array")
        end
        | map(select((.Sid // "") != $statement_sid))
        + [{
            "Sid": $statement_sid,
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": $template_resource
          }]
      )
  ' <<<"${policy_json}" >"${merged_policy}"

aws s3api put-bucket-policy \
  --bucket "${bucket}" \
  --region "${region}" \
  --policy "file://${merged_policy}"

echo "Configured public read for ${template_resource}."
echo "Verified effective public-access-block settings without weakening ACL protections."
echo "Existing bucket policy statements were preserved; ACLs were not changed."
