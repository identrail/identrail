#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: check_public_api_url.sh [--probe] [--allow-local] [API_URL]

Validates the public Identrail API base URL used by the web frontend.

Inputs:
  API_URL                      Optional. Defaults to VITE_IDENTRAIL_API_URL.
  IDENTRAIL_WEB_ORIGINS        Optional comma-separated web origins to reject.

Options:
  --probe                      Also call /healthz and /v1/auth/config.
  --allow-local                Permit http://localhost and http://127.0.0.1.
  -h, --help                   Show this help text.
USAGE
}

trim() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

lower() {
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]'
}

extract_origin() {
  local value="$1"
  printf '%s' "$value" | sed -E 's#^(https?://[^/]+).*$#\1#'
}

fail() {
  printf 'Identrail API URL check failed: %s\n' "$1" >&2
  exit 1
}

probe=false
allow_local=false
api_url="${VITE_IDENTRAIL_API_URL:-}"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --probe)
      probe=true
      ;;
    --allow-local)
      allow_local=true
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --*)
      fail "unknown option $1"
      ;;
    *)
      api_url="$1"
      ;;
  esac
  shift
done

api_url="$(trim "$api_url")"
api_url="${api_url%/}"

if [ -z "$api_url" ]; then
  fail "VITE_IDENTRAIL_API_URL is required"
fi

if [[ "$api_url" =~ ^http://(localhost|127\.0\.0\.1)(:[0-9]+)?($|/) ]]; then
  if [ "$allow_local" != "true" ]; then
    fail "local HTTP URLs are not allowed for production API wiring"
  fi
elif [[ ! "$api_url" =~ ^https://[^/[:space:]]+($|/) ]]; then
  fail "use an absolute HTTPS API URL such as https://api.identrail.com"
fi

api_origin="$(lower "$(extract_origin "$api_url")")"
web_origins="${IDENTRAIL_WEB_ORIGINS:-https://identrail.com,https://www.identrail.com,https://app.identrail.com}"
IFS=',' read -r -a rejected_origins <<< "$web_origins"
for rejected in "${rejected_origins[@]}"; do
  rejected="$(lower "$(trim "${rejected%/}")")"
  if [ -n "$rejected" ] && [ "$api_origin" = "$rejected" ]; then
    fail "API URL points at web origin $rejected; use a dedicated API origin such as https://api.identrail.com"
  fi
done

if [ "$probe" = "true" ]; then
  for path in /healthz /v1/auth/config; do
    tmp_body="$(mktemp)"
    tmp_headers="$(mktemp)"
    status="$(curl -L -sS -o "$tmp_body" -D "$tmp_headers" -w '%{http_code}' "${api_url}${path}" || true)"
    content_type="$(tr -d '\r' < "$tmp_headers" | awk 'BEGIN{IGNORECASE=1} /^content-type:/ {print $0}' | tail -n 1)"
    body_prefix="$(head -c 256 "$tmp_body" | tr '\n' ' ')"
    rm -f "$tmp_body" "$tmp_headers"

    if [ "$status" != "200" ]; then
      fail "${api_url}${path} returned HTTP ${status}, expected 200"
    fi
    if printf '%s' "$content_type" | grep -Eiq 'text/html'; then
      fail "${api_url}${path} returned HTML, which usually means the URL points at the frontend"
    fi
    if printf '%s' "$body_prefix" | grep -Eiq '<!doctype html|<html'; then
      fail "${api_url}${path} returned an HTML page, not an API response"
    fi
  done
fi

printf 'Identrail API URL check passed: %s\n' "$api_url"
