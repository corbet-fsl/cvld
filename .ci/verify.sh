#!/usr/bin/env bash
# .ci/verify.sh for cvld — ports ALL Linux verification gates from
# .github/workflows/ci.yml (resolve selftest, dependency-policy, check, toy,
# coverage) in CI order, environment, and flags.
# Runs inside .ci/check-shell.nix (see run-cached.sh).
set -euo pipefail
exec 2>&1
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
export CARGO_TERM_COLOR="${CARGO_TERM_COLOR:-always}"
export CARGO_HTTP_USER_AGENT="${CARGO_HTTP_USER_AGENT:-dependency-ci}"
export CARGO_NET_GIT_FETCH_WITH_CLI="${CARGO_NET_GIT_FETCH_WITH_CLI:-true}"

# CI pins Node 22; the job-local pin is nodejs_22 22.23.2, so require major 22.
node --version | grep -q '^v22\.' || { echo 'CI requires Node major 22' >&2; exit 2; }
# C compiler and build tools cover lock-evidenced cc/cmake edges (blake3,
# ring, aws-lc-sys, libsql-ffi, wasmer); the Ubuntu image supplies gcc+cmake,
# the job supplies them via the shell.
command -v cc >/dev/null || { echo 'missing cc for lock-evidenced cc edges' >&2; exit 2; }
command -v cmake >/dev/null || { echo 'missing cmake for lock-evidenced cmake edges' >&2; exit 2; }
# Wasm target on stable is guaranteed by run-cached.sh (helper readiness +
# exclusive provisioning); no toolchain mutation here under the shared lock.

# --- resolve pure selftest (committed graph only; update refresh excluded) ---
python3 .github/check-first-party.py

# --- dependency-policy job (pure selftests; deny advisories separate) ---
python3 .github/check-first-party.py
python3 .github/test-source-coverage.py
node --test .github/test-auto-merge.mjs

# --- check job (ubuntu-24.04, CARGO_TERM_COLOR=never) ---
export CARGO_TERM_COLOR=never
rustc --version
node --test .github/check-pins.test.mjs
cargo metadata --locked --format-version 1 > dependency-metadata.json
node .github/check-pins.mjs dependency-metadata.json
cargo fmt --all --check
cargo clippy --locked --all-targets --features development-gate -- -D warnings
cargo clippy --locked --no-default-features --features client --lib --target wasm32-unknown-unknown -- -D warnings
cargo run --locked -- openapi > docs/openapi.json
npm ci --prefix clients/ts
npm run generate --prefix clients/ts
npm run check --prefix clients/ts
npm test --prefix clients/ts
cargo test --locked --features development-gate --no-fail-fast
cargo test --locked --release
if cargo check --locked --release --features development-gate > release-gate.log 2>&1; then exit 1; fi
grep -q 'development-gate is forbidden in release builds' release-gate.log
if CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=true cargo check --locked --release --features development-gate > release-debug-gate.log 2>&1; then exit 1; fi
grep -q 'development-gate is forbidden in release builds' release-debug-gate.log
git ls-files --error-unmatch docs/openapi.json clients/ts/schema.d.ts
git diff --exit-code -- docs/openapi.json clients/ts/schema.d.ts

# --- toy job (ubuntu-24.04, CARGO_TERM_COLOR=never) ---
export CARGO_HTTP_USER_AGENT=cvld-toy-ci
# Child-process time travel needs the faketime shared object; CI installs it
# via apt (privileged), the job supplies pinned nix libfaketime instead.
# LIBFAKETIME_PATH is resolved job-locally by run-cached.sh.
test -n "${LIBFAKETIME_PATH:-}" || { echo 'LIBFAKETIME_PATH is not set by the job runtime' >&2; exit 2; }
test -f "$LIBFAKETIME_PATH" || { echo "libfaketime missing at $LIBFAKETIME_PATH" >&2; exit 2; }
rustc --version
toy/build.sh
pushd toy/.build > /dev/null
python3 ../../.github/check-first-party.py
python3 -c "import tomllib; from pathlib import Path; a=tomllib.loads(Path('../../Cargo.lock').read_text()); b=tomllib.loads(Path('Cargo.lock').read_text()); key=lambda p:(p['name'],p['version'],p.get('source')); assert {key(p) for p in a['package']} <= {key(p) for p in b['package']}"
popd > /dev/null
rustfmt --edition 2024 --check toy/src/*.rs
set -o pipefail
mkdir -p toy/reports
target_dir="${CARGO_TARGET_DIR:-target}"
case "$target_dir" in /*) ;; *) target_dir="$PWD/$target_dir";; esac
export CVLD_BIN="$target_dir/debug/cvld"
"$target_dir/debug/cvld-toy" scenarios | tee toy/reports/transcript.txt
# Live Turso is explicitly opt-in outside automated verification.

# --- coverage job (nightly only) ---
# CI top-level env carries CARGO_HTTP_USER_AGENT=dependency-ci into this job.
export CARGO_TERM_COLOR=always
export CARGO_HTTP_USER_AGENT=dependency-ci
# Select nightly exactly as CI's nightly job does; every bare cargo/rustc
# below resolves nightly via RUSTC/CARGO/PATH/RUSTUP_TOOLCHAIN.
rustup run nightly rustc --version
NIGHTLY_RUSTC="$(rustup which --toolchain nightly rustc)"
NIGHTLY_CARGO="$(rustup which --toolchain nightly cargo)"
NIGHTLY_BIN="$(dirname "$NIGHTLY_RUSTC")"
export RUSTC="$NIGHTLY_RUSTC"
export CARGO="$NIGHTLY_CARGO"
export PATH="$NIGHTLY_BIN:$PATH"
export RUSTUP_TOOLCHAIN=nightly
"$NIGHTLY_CARGO" llvm-cov --version
# Bug 2 isolation: coverage data must not reuse the shared cargo target
# across jobs (stale checkout paths fail the next gate); scope the
# coverage target to this job only. Native gates keep the shared warm
# target; outer traps and services are untouched.
(
coverage_target="$(mktemp -d)"
case "$coverage_target" in ""|"$PWD"/*) echo 'unsafe coverage target' >&2; exit 2;; esac
trap 'rm -rf -- "$coverage_target"' EXIT
export CARGO_TARGET_DIR="$coverage_target"
"$NIGHTLY_CARGO" llvm-cov --locked --workspace --all-features --branch --no-cfg-coverage --no-cfg-coverage-nightly --ignore-filename-regex '(/tests/|/tests\.rs$)' --json --output-path coverage.json
"$NIGHTLY_CARGO" llvm-cov report --locked --branch --ignore-filename-regex '(/tests/|/tests\.rs$)' --lcov --output-path coverage.lcov
"$NIGHTLY_CARGO" llvm-cov report --locked --branch --ignore-filename-regex '(/tests/|/tests\.rs$)' --text --output-path coverage.txt
)
python3 .github/check-coverage.py coverage.json || true
python3 .github/check-source-coverage.py coverage.lcov coverage.json coverage.txt
