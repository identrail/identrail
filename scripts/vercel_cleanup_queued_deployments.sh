#!/usr/bin/env bash
set -euo pipefail

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required to parse Vercel API responses."
  exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required to call the Vercel API."
  exit 1
fi

project_ref="${VERCEL_PROJECT_ID:-${VERCEL_PROJECT_NAME:-}}"
raw_token="${VERCEL_TOKEN:-}"
keep_per_ref="${KEEP_QUEUED_PER_REF:-1}"

if [ -z "${project_ref}" ]; then
  echo "Set VERCEL_PROJECT_ID (preferred) or VERCEL_PROJECT_NAME before running this script."
  exit 1
fi

if [ -z "${raw_token}" ]; then
  echo "Set VERCEL_TOKEN before running this script."
  exit 1
fi

if ! [[ "${keep_per_ref}" =~ ^[0-9]+$ ]] || [ "${keep_per_ref}" -eq 0 ]; then
  echo "KEEP_QUEUED_PER_REF must be a positive integer."
  exit 1
fi

token="$(printf '%s' "${raw_token}" | tr -d '\r\n' | sed -e 's/^"//' -e 's/"$//')"
if [ -z "${token}" ]; then
  echo "VERCEL_TOKEN is empty after normalization."
  exit 1
fi
echo "::add-mask::${token}"
team_id="${VERCEL_ORG_ID:-}"
readonly team_id
readonly token

urlencode() {
  jq -rn --arg value "$1" '$value|@uri'
}

build_list_url() {
  local until_token="${1:-}"
  local url="https://api.vercel.com/v6/deployments?projectId=$(urlencode "${project_ref}")&state=QUEUED&limit=100"
  if [ -n "${team_id}" ]; then
    url="${url}&teamId=$(urlencode "${team_id}")"
  fi
  if [ -n "${until_token}" ]; then
    url="${url}&until=$(urlencode "${until_token}")"
  fi
  printf '%s\n' "${url}"
}

build_delete_url() {
  local deployment_id="$1"
  local url="https://api.vercel.com/v13/deployments/${deployment_id}"
  if [ -n "${team_id}" ]; then
    url="${url}?teamId=$(urlencode "${team_id}")"
  fi
  printf '%s\n' "${url}"
}

next_token=""
queued_count=0
declare -a rows_this_page

declare -A kept_by_ref
prune_ids=()

while :; do
  page_payload="$(curl -fsS \
    -H "Authorization: Bearer ${token}" \
    "$(build_list_url "${next_token}")")"
  page_count="$(echo "${page_payload}" | jq '(.deployments // []) | length')"
  queued_count=$((queued_count + page_count))

  mapfile -t rows_this_page < <(
    echo "${page_payload}" | jq -r '
      (.deployments // [])[]
      | [ .uid, (.createdAt // .created // 0), (.meta.githubCommitRef // "no-ref"), (.target // "preview") ]
      | @tsv
    ' | sort -t $'\t' -k2,2nr
  )

  for row in "${rows_this_page[@]}"; do
    IFS=$'\t' read -r deployment_id _created_at branch_ref target <<< "${row}"
    key="${branch_ref}|${target}"
    count="${kept_by_ref["${key}"]:-0}"
    if [ "${count}" -lt "${keep_per_ref}" ]; then
      kept_by_ref["${key}"]="${count}"
      kept_by_ref["${key}"]=$((count + 1))
      continue
    fi
    prune_ids+=("${deployment_id}")
  done

  next_token="$(echo "${page_payload}" | jq -r '.pagination.next // empty')"
  if [ -z "${next_token}" ] || [ "${next_token}" = "null" ]; then
    break
  fi
done

if [ "${queued_count}" -eq 0 ]; then
  echo "No queued deployments found for project '${project_ref}'."
  exit 0
fi

if [ "${#prune_ids[@]}" -eq 0 ]; then
  echo "Queued queue is already compact for project '${project_ref}'."
  exit 0
fi

echo "Queued deploys: ${queued_count}; keeping latest ${keep_per_ref} per branch+target; pruning ${#prune_ids[@]}."
echo "Pruning deployment IDs: ${prune_ids[*]}"

for deployment_id in "${prune_ids[@]}"; do
  if curl -fsS -X DELETE \
    -H "Authorization: Bearer ${token}" \
    "$(build_delete_url "${deployment_id}")" \
    >/dev/null; then
    echo "Removed ${deployment_id}"
  else
    echo "Could not remove ${deployment_id}; skipping."
  fi
done
