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
