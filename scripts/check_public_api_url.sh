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
  --probe                      Also call /healthz, /v1/auth/config, and
                               POST /v1/onboarding/start.
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

looks_like_html() {
  local content_type="$1" body_prefix="$2"
  if printf '%s' "$content_type" | grep -Eiq 'text/html'; then
    return 0
  fi
  if printf '%s' "$body_prefix" | grep -Eiq '<!doctype html|<html'; then
    return 0
  fi
  return 1
}

looks_like_json() {
  local content_type="$1" body_prefix="$2"
  if printf '%s' "$content_type" | grep -Eiq 'application/json'; then
    return 0
  fi
  if printf '%s' "$body_prefix" | grep -Eq '^[[:space:]]*[\{\[]'; then
    return 0
  fi
  return 1
}

# classify_onboarding_probe STATUS CONTENT_TYPE BODY_PREFIX
#
# The unauthenticated production preflight expects POST /v1/onboarding/start to
# answer with a JSON 401 ("session required"). Any other shape means the
# onboarding wizard would be enabled against a backend that cannot serve it.
# Prints a single-line diagnostic and returns non-zero on failure. The leading
# token classifies the failure so operators can tell wiring problems from a
# missing route from a non-JSON frontend/404 response.
classify_onboarding_probe() {
  local status="$1" content_type="$2" body_prefix="$3"

  if looks_like_html "$content_type" "$body_prefix"; then
    printf 'api-url-wiring: returned an HTML frontend shell instead of a JSON API response; VITE_IDENTRAIL_API_URL likely points at the web frontend, not the API'
    return 1
  fi

  if [ "$status" = "404" ]; then
    printf 'missing-route: returned HTTP 404; the onboarding route is not registered (deploy the onboarding API fix and set IDENTRAIL_FEATURE_ONBOARDING_WIZARD=true before enabling the web wizard)'
    return 1
  fi

  if [ "$status" != "401" ]; then
    printf 'unexpected-status: returned HTTP %s, expected the unauthenticated JSON 401 session-required response' "$status"
    return 1
  fi

  if ! looks_like_json "$content_type" "$body_prefix"; then
    printf 'non-json: returned HTTP 401 without a JSON body; expected a JSON session-required response, got a framework/plain-text 401'
    return 1
  fi

  return 0
}

probe_endpoint() {
  # probe_endpoint METHOD URL -> sets PROBE_STATUS, PROBE_CONTENT_TYPE,
  # PROBE_BODY_PREFIX in the caller's scope.
  local method="$1" url="$2"
  local tmp_body tmp_headers
  tmp_body="$(mktemp)"
  tmp_headers="$(mktemp)"
  PROBE_STATUS="$(curl -L -sS -X "$method" -o "$tmp_body" -D "$tmp_headers" -w '%{http_code}' "$url" || true)"
  PROBE_CONTENT_TYPE="$(tr -d '\r' < "$tmp_headers" | awk 'BEGIN{IGNORECASE=1} /^content-type:/ {print $0}' | tail -n 1)"
  PROBE_BODY_PREFIX="$(head -c 256 "$tmp_body" | tr '\n' ' ')"
  rm -f "$tmp_body" "$tmp_headers"
}

main() {
  local probe=false
  local allow_local=false
  local api_url="${VITE_IDENTRAIL_API_URL:-}"

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

  local api_origin web_origins
  api_origin="$(lower "$(extract_origin "$api_url")")"
  web_origins="${IDENTRAIL_WEB_ORIGINS:-https://identrail.com,https://www.identrail.com,https://app.identrail.com}"
  local rejected_origins rejected
  IFS=',' read -r -a rejected_origins <<< "$web_origins"
  for rejected in "${rejected_origins[@]}"; do
    rejected="$(lower "$(trim "${rejected%/}")")"
    if [ -n "$rejected" ] && [ "$api_origin" = "$rejected" ]; then
      fail "API URL points at web origin $rejected; use a dedicated API origin such as https://api.identrail.com"
    fi
  done

  if [ "$probe" = "true" ]; then
    local path
    for path in /healthz /v1/auth/config; do
      probe_endpoint GET "${api_url}${path}"
      if [ "$PROBE_STATUS" != "200" ]; then
        fail "${api_url}${path} returned HTTP ${PROBE_STATUS}, expected 200"
      fi
      if looks_like_html "$PROBE_CONTENT_TYPE" "$PROBE_BODY_PREFIX"; then
        fail "${api_url}${path} returned HTML, which usually means the URL points at the frontend"
      fi
    done

    # Onboarding route coverage: a healthy /v1/auth/config alongside a 404 (or
    # frontend shell) onboarding route is exactly the regression that let
    # production enable the wizard against a missing backend route.
    path=/v1/onboarding/start
    probe_endpoint POST "${api_url}${path}"
    local reason
    if ! reason="$(classify_onboarding_probe "$PROBE_STATUS" "$PROBE_CONTENT_TYPE" "$PROBE_BODY_PREFIX")"; then
      fail "${api_url}${path} ${reason}"
    fi
  fi

  printf 'Identrail API URL check passed: %s\n' "$api_url"
}

# Allow the test harness to source this file and exercise the pure
# classification helpers without running the CLI.
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
  main "$@"
fi
