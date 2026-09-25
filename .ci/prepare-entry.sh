#!/usr/bin/env bash
set -euo pipefail
test "${CI:-}" = true
test -n "${ARTIFACT_ROOT:-}"
test -n "${CARGO_TARGET_DIR:-}"
mkdir -p "$ARTIFACT_ROOT" .ci/dependencies
cmsg_revision=155a8e77c9b6f3a950104863dab50f9bbe483d33
cvch_revision=dff30de1a72358208e27c0416fb8e7096e64ae04
grep -Fqx "cvch = { git = \"https://github.com/corbet-foss/cvch.git\", rev = \"$cvch_revision\" }" native/voucher/Cargo.toml
grep -Fqx "cmsg = { git = \"https://github.com/corbet-libs/cmsg.git\", rev = \"$cmsg_revision\" }" native/voucher/Cargo.toml
if test "${RESOLVE_DEPENDENCIES:-0}" = 1; then
  cargo generate-lockfile --manifest-path native/voucher/Cargo.toml
  date -u +%FT%TZ > "$ARTIFACT_ROOT/voucher-dependency-resolution-time.txt"
fi
cp native/voucher/Cargo.lock "$ARTIFACT_ROOT/voucher-Cargo.lock"
cargo build --locked --release --manifest-path native/voucher/Cargo.toml
mkdir .ci/dependencies/cmsg
git -C .ci/dependencies/cmsg init --quiet
git -C .ci/dependencies/cmsg remote add origin https://github.com/corbet-libs/cmsg.git
git -C .ci/dependencies/cmsg fetch --depth=1 origin "$cmsg_revision"
git -C .ci/dependencies/cmsg -c advice.detachedHead=false checkout --detach FETCH_HEAD
test "$(git -C .ci/dependencies/cmsg rev-parse HEAD)" = "$cmsg_revision"
printf '%s\n' "$cmsg_revision" > "$ARTIFACT_ROOT/cmsg-source.txt"
printf '%s\n' "$cvch_revision" > "$ARTIFACT_ROOT/cvch-source.txt"
cargo build --locked --release --target wasm32-unknown-unknown --lib --manifest-path .ci/dependencies/cmsg/Cargo.toml
cargo run --locked --manifest-path .ci/dependencies/cmsg/.ci/browser-bindgen/Cargo.toml -- \
  "$CARGO_TARGET_DIR/wasm32-unknown-unknown/release/cmsg.wasm" .ci/dependencies/cmsg/browser/pkg cmsg
cp .ci/dependencies/cmsg/Cargo.lock "$ARTIFACT_ROOT/cmsg-Cargo.lock"
cp .ci/dependencies/cmsg/.ci/browser-bindgen/Cargo.lock "$ARTIFACT_ROOT/cmsg-bindgen-Cargo.lock"
sha256sum "$CARGO_TARGET_DIR/release/cvld-voucher-bridge" .ci/dependencies/cmsg/browser/pkg/* > "$ARTIFACT_ROOT/entry-runtime.sha256"
