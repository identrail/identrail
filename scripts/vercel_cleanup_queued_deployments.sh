#!/usr/bin/env bash
set -euo pipefail

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required to parse Vercel CLI output."
  exit 1
fi

if ! command -v vercel >/dev/null 2>&1; then
  echo "Vercel CLI is required to prune queued deployments."
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
export VERCEL_TOKEN="${token}"
team_id="${VERCEL_ORG_ID:-}"
readonly team_id

scope_args=()
if [ -n "${team_id}" ]; then
  scope_args+=(--scope "${team_id}")
fi

declare -a ls_args
ls_args=(ls "${project_ref}" --status QUEUED -F json "${scope_args[@]}")

next_token=""
queued_count=0
declare -a rows_this_page

declare -A kept_by_ref
prune_ids=()

while :; do
  ls_args=(ls "${project_ref}" --status QUEUED -F json)
  if [ -n "${next_token}" ]; then
    ls_args+=(--next "${next_token}")
  fi

  page_payload="$(vercel "${ls_args[@]}" | sed -n '/^{/,$p')"
  page_count="$(echo "${page_payload}" | jq '.deployments | length // 0')"
  queued_count=$((queued_count + page_count))

  mapfile -t rows_this_page < <(
    echo "${page_payload}" | jq -r '
      .deployments[]
      | [ .id, .createdAt, (.meta.githubCommitRef // "no-ref"), (.target // "preview") ]
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
  if vercel rm "${deployment_id}" --safe --yes "${scope_args[@]}"; then
    echo "Removed ${deployment_id}"
  else
    echo "Could not remove ${deployment_id}; skipping."
  fi
done
