#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$PWD/target}"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
mkdir -p "$CARGO_TARGET_DIR/toy-build"
case "$#:$*" in
  0:)
    python3 toy/prepare.py
    cargo metadata --manifest-path toy/.build/Cargo.toml --format-version 1 \
      > "$CARGO_TARGET_DIR/toy-build/dependency-metadata.json"
    ;;
  1:--frozen-inputs) ;;
  *) printf 'usage: toy/build.sh [--frozen-inputs]\n' >&2; exit 2 ;;
esac
python3 toy/prepare.py --check
read -r toy_meter_hash toy_meter_source < <(sha256sum toy/meter.c)
toy_meter_object="$(realpath "$CARGO_TARGET_DIR")/toy-build/meter-${toy_meter_hash}.o"
cc -O2 -Wall -Wextra -Werror -c toy/meter.c -o "$toy_meter_object"
cargo rustc --locked --features development-gate --bin cvld -- \
  -C "link-arg=$toy_meter_object" -C link-arg=-Wl,--wrap=sqlite3_step
cargo build --locked --manifest-path toy/.build/Cargo.toml
