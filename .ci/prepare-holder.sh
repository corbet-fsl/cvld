#!/usr/bin/env bash
# Remote-only preparation of the unchanged upstream AnonCreds algorithms.
set -euo pipefail
test "${CI:-}" = true
test -n "${ARTIFACT_ROOT:-}"
test -n "${CARGO_TARGET_DIR:-}"
mkdir -p "$ARTIFACT_ROOT" .ci/dependencies
anoncreds_revision=08317a7428afe81f7b710669dc64878f98a6447b
cfrm_revision=c924ec5cbd4381bef288e76ef4399c48062a8afc
fetch_source() {
  local name="$1" repository="$2" revision="$3"
  local directory=".ci/dependencies/$name"
  mkdir "$directory"
  git -C "$directory" init --quiet
  git -C "$directory" remote add origin "https://github.com/$repository.git"
  git -C "$directory" fetch --depth=1 origin "$revision"
  git -C "$directory" -c advice.detachedHead=false checkout --detach FETCH_HEAD
  test "$(git -C "$directory" rev-parse HEAD)" = "$revision"
  printf '%s\n' "$revision" > "$ARTIFACT_ROOT/$name-source.txt"
}
fetch_source anoncreds-rs hyperledger/anoncreds-rs "$anoncreds_revision"
fetch_source cfrm cmtymeet/cfrm "$cfrm_revision"
sha256sum .ci/dependencies/anoncreds-rs/Cargo.toml > "$ARTIFACT_ROOT/anoncreds-manifest-before.sha256"
node --input-type=module <<'JS'
import assert from 'node:assert/strict';
import { readFile, writeFile } from 'node:fs/promises';
const path = '.ci/dependencies/anoncreds-rs/Cargo.toml';
const input = await readFile(path, 'utf8');
const original = 'anoncreds-clsignatures = "0.3.2"';
assert.equal(input.split(original).length, 2, 'Exact upstream CL feature declaration required');
await writeFile(path, input.replace(original, 'anoncreds-clsignatures = { version = "0.3.2", default-features = false, features = ["serde"] }'));
JS
git -C .ci/dependencies/anoncreds-rs diff -- Cargo.toml > "$ARTIFACT_ROOT/anoncreds-cargo-feature.patch"
sha256sum .ci/dependencies/anoncreds-rs/Cargo.toml > "$ARTIFACT_ROOT/anoncreds-manifest-after.sha256"
if test "${RESOLVE_DEPENDENCIES:-0}" = 1; then
  # Preserve already resolved versions when a changed feature adds dependencies.
  cargo metadata --format-version 1 --manifest-path native/holder/Cargo.toml > "$ARTIFACT_ROOT/holder-cargo-metadata.json"
  cargo metadata --format-version 1 --manifest-path native/holder-bindgen/Cargo.toml > "$ARTIFACT_ROOT/holder-bindgen-cargo-metadata.json"
  date -u +%FT%TZ > "$ARTIFACT_ROOT/holder-dependency-resolution-time.txt"
fi
cp native/holder/Cargo.lock "$ARTIFACT_ROOT/holder-Cargo.lock"
cp native/holder-bindgen/Cargo.lock "$ARTIFACT_ROOT/holder-bindgen-Cargo.lock"
RUSTFLAGS='--cfg getrandom_backend="wasm_js"' cargo build --locked --release \
  --target wasm32-unknown-unknown --manifest-path native/holder/Cargo.toml
cargo run --locked --manifest-path native/holder-bindgen/Cargo.toml -- \
  "$CARGO_TARGET_DIR/wasm32-unknown-unknown/release/cvld_holder.wasm" generated/holder
