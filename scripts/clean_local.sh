#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "${repo_root}"

echo "Cleaning local artifacts in ${repo_root}"

removed=0

remove_path() {
  local path="$1"
  if [ -e "${path}" ] || [ -L "${path}" ]; then
    rm -rf "${path}"
    echo "removed: ${path}"
    removed=1
  fi
}

# Known marker files seen in local workflows.
remove_path "canceled"
remove_path "succeeded"

# Coverage outputs outside source of truth.
remove_path "coverage"
remove_path "coverage 2"
remove_path "coverage 3"
remove_path "web/coverage"
remove_path "web/coverage 2"
remove_path "web/coverage 3"

# Delete root-level duplicate artifacts like "README 2.md", "Makefile 3", etc.
while IFS= read -r -d '' candidate; do
  # Never remove tracked files.
  if git ls-files --error-unmatch "${candidate}" >/dev/null 2>&1; then
    continue
  fi
  rm -rf "${candidate}"
  echo "removed duplicate: ${candidate}"
  removed=1
done < <(
  find . -maxdepth 1 \( -name '* 2' -o -name '* 3' -o -name '* 2.*' -o -name '* 3.*' \) -print0
)

if [ "${removed}" -eq 0 ]; then
  echo "No local artifacts found."
fi
