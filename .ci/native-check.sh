#!/usr/bin/env bash
set -euo pipefail
: "${CI:?CI only}"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
export CARGO_HTTP_USER_AGENT=door-ci
rustc --version
cargo --version
sha256sum Cargo.lock tests/browser/Cargo.lock
python3 .github/check-first-party.py --archive
cargo fmt --all --check
cargo fmt --manifest-path tests/browser/Cargo.toml --all --check
: "${CARGO_TARGET_DIR:?external target required}"
: "${CI_COMMIT_SHA:?exact source required}"
reports="${CI_ACCEPTANCE_ARTIFACTS:-$CARGO_TARGET_DIR/ci-receipts/$CI_COMMIT_SHA}"
mkdir -p "$reports"
cargo metadata --locked --format-version 1 > "$reports/dependency-metadata.json"
node .github/check-pins.mjs "$reports/dependency-metadata.json"
cargo clippy --locked --all-targets --features development-gate -- -D warnings
cargo test --locked --features development-gate --no-fail-fast
