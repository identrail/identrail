#!/usr/bin/env bash
set -euo pipefail

env_files=(
  ".env"
  ".env.local"
  "deploy/docker/.env"
  "web/.env.local"
  "site/.env.local"
)

findings=0

report_finding() {
  local file="$1"
  local kind="$2"
  printf 'Detected local secret-like value in %s: %s\n' "${file}" "${kind}" >&2
  findings=1
}

scan_file() {
  local file="$1"
  local content
  content="$(tr -d '\r' <"${file}")"

  if [[ "${content}" =~ eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+ ]]; then
    report_finding "${file}" "JWT-shaped token"
  fi

  if [[ "${content}" =~ gh[pousr]_[A-Za-z0-9_]{36,} ]] || [[ "${content}" =~ github_pat_[A-Za-z0-9_]+ ]]; then
    report_finding "${file}" "GitHub token"
  fi

  if [[ "${content}" =~ -----BEGIN[[:space:]]+(RSA[[:space:]]+|EC[[:space:]]+|OPENSSH[[:space:]]+|DSA[[:space:]]+)?PRIVATE[[:space:]]+KEY----- ]]; then
    report_finding "${file}" "private key"
  fi

  while IFS= read -r line; do
    if [[ "${line}" =~ postgres(ql)?://[^[:space:]@/]+:[^[:space:]@]+@ ]] && [[ ! "${line}" =~ replace- ]]; then
      report_finding "${file}" "credential-bearing Postgres URL"
      break
    fi
  done <<<"${content}"
}

for env_file in "${env_files[@]}"; do
  if [[ -f "${env_file}" ]]; then
    scan_file "${env_file}"
  fi
done

if [[ "${findings}" -ne 0 ]]; then
  cat <<'MSG' >&2

Local env files contain credential-like values. These files are usually ignored by Git,
but they are easy to leak through copied terminal output, screenshots, logs, or local
artifact sharing. Rotate exposed credentials and redact local files before publishing
debug material.
MSG
  exit 1
fi

exit 0
