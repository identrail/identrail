#!/usr/bin/env bash
set -euo pipefail

env_file=".env.local"

if [[ ! -f "${env_file}" ]]; then
  exit 0
fi

token_line="$(grep -E '^[[:space:]]*VERCEL_OIDC_TOKEN=' "${env_file}" | tail -n1 || true)"
if [[ -z "${token_line}" ]]; then
  exit 0
fi

token_value="${token_line#*=}"
token_value="$(printf '%s' "${token_value}" | tr -d '\r')"

# Strip inline comments (un-quoted # and everything after)
token_value="$(printf '%s' "${token_value}" | sed -E 's/[[:space:]]+#.*$//')"

# Strip surrounding quotes (double or single)
token_value="${token_value%\"}"
token_value="${token_value#\"}"
token_value="${token_value%\'}"
token_value="${token_value#\'}"

# Trim leading/trailing whitespace
token_value="$(printf '%s' "${token_value}" | xargs)"

if [[ -z "${token_value}" ]]; then
  exit 0
fi

# Vercel OIDC tokens are JWT-shaped. Block pushes when one is present locally.
if [[ "${token_value}" =~ ^eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$ ]]; then
  cat <<'MSG' >&2
Detected a JWT-shaped VERCEL_OIDC_TOKEN in .env.local.

For local token hygiene:
1) Rotate/regenerate the token (vercel env pull).
2) Avoid sharing terminal output that includes token values.
3) Redact the token in local files before publishing logs/screenshots.

This pre-push check is intentionally blocking to reduce local credential leak risk.
MSG
  exit 1
fi

exit 0
