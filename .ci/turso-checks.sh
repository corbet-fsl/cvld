#!/usr/bin/env bash
set -euo pipefail
test "${CI:-}" = true
test -n "${ARTIFACT_ROOT:-}"
mkdir -p "$ARTIFACT_ROOT"
capture() {
  local status=$?
  trap - EXIT
  printf '%s\n' "$status" > "$ARTIFACT_ROOT/validation-status.txt"
  cp package-lock.json "$ARTIFACT_ROOT/package-lock.json"
  (cd "$ARTIFACT_ROOT" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS)
  exit "$status"
}
trap capture EXIT
if test "${RESOLVE_DEPENDENCIES:-0}" = 1; then
  npm install --package-lock-only --ignore-scripts --no-audit --no-fund
fi
cp package-lock.json "$ARTIFACT_ROOT/package-lock.json"
node --version > "$ARTIFACT_ROOT/node-version.txt"
npm ci --ignore-scripts --no-audit --no-fund
npm run prepare:native
timeout --kill-after=15 300 npm test 2>&1 | tee "$ARTIFACT_ROOT/durable-entry-tests.log"
cmp package-lock.json "$ARTIFACT_ROOT/package-lock.json"
