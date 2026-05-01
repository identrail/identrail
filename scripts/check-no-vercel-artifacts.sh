#!/usr/bin/env bash
set -euo pipefail

staged_files="$(git diff --cached --name-only --diff-filter=ACMR)"
if [[ -z "${staged_files}" ]]; then
  exit 0
fi

if printf '%s\n' "${staged_files}" | grep -Eq '(^|/)\.vercel/'; then
  cat <<'MSG' >&2
Detected staged .vercel artifacts.

The following paths must not be committed:
- .vercel/**
- web/.vercel/**
- site/.vercel/**

Remove these paths from the commit before pushing.
MSG
  exit 1
fi

exit 0
