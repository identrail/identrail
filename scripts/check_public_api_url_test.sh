#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
check_script="${script_dir}/check_public_api_url.sh"

expect_pass() {
  local name="$1"
  shift
  if ! "$check_script" "$@" >/tmp/identrail-api-url-test.out 2>/tmp/identrail-api-url-test.err; then
    printf 'FAIL expected pass: %s\n' "$name" >&2
    cat /tmp/identrail-api-url-test.err >&2
    exit 1
  fi
}

expect_fail() {
  local name="$1"
  shift
  if "$check_script" "$@" >/tmp/identrail-api-url-test.out 2>/tmp/identrail-api-url-test.err; then
    printf 'FAIL expected failure: %s\n' "$name" >&2
    cat /tmp/identrail-api-url-test.out >&2
    exit 1
  fi
}

# shellcheck source=scripts/check_public_api_url.sh
. "$check_script"

expect_onboarding_pass() {
  local name="$1" status="$2" content_type="$3" body="$4"
  if ! classify_onboarding_probe "$status" "$content_type" "$body" >/dev/null; then
    printf 'FAIL expected onboarding pass: %s\n' "$name" >&2
    exit 1
  fi
}

expect_onboarding_fail() {
  local name="$1" want_class="$2" status="$3" content_type="$4" body="$5"
  local reason
  if reason="$(classify_onboarding_probe "$status" "$content_type" "$body")"; then
    printf 'FAIL expected onboarding failure: %s\n' "$name" >&2
    exit 1
  fi
  if [ "${reason%%:*}" != "$want_class" ]; then
    printf 'FAIL onboarding classification for %s: want %s, got %q\n' "$name" "$want_class" "$reason" >&2
    exit 1
  fi
}

expect_onboarding_pass "json 401 session required" \
  "401" "content-type: application/json" '{"error":"session required"}'
expect_onboarding_pass "json 401 without content-type header" \
  "401" "" '{"error":"session required"}'

expect_onboarding_fail "missing route 404" missing-route \
  "404" "text/plain; charset=utf-8" "404 page not found"
expect_onboarding_fail "html frontend shell" api-url-wiring \
  "200" "content-type: text/html; charset=utf-8" "<!doctype html><html><head>"
expect_onboarding_fail "html shell served with 401" api-url-wiring \
  "401" "text/html" "<html><body>login</body></html>"
expect_onboarding_fail "plain text 401" non-json \
  "401" "text/plain; charset=utf-8" "Unauthorized"
expect_onboarding_fail "unexpected 500" unexpected-status \
  "500" "application/json" '{"error":"boom"}'
expect_onboarding_fail "unexpected 200 html-free" unexpected-status \
  "200" "application/json" '{"ok":true}'

expect_pass "dedicated https api origin" "https://api.identrail.com"
expect_pass "api origin with base path" "https://api.identrail.com/service"
expect_pass "local dev with opt-in" --allow-local "http://localhost:8080"

expect_fail "empty value"
expect_fail "web apex origin" "https://identrail.com"
expect_fail "web app origin" "https://app.identrail.com"
expect_fail "non-local http" "http://api.identrail.com"
expect_fail "local dev without opt-in" "http://localhost:8080"
expect_fail "relative URL" "/v1"

rm -f /tmp/identrail-api-url-test.out /tmp/identrail-api-url-test.err
printf 'check_public_api_url tests passed\n'
