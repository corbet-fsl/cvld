#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$PWD/target}"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
python3 toy/prepare.py
read -r toy_meter_hash toy_meter_source < <(sha256sum toy/meter.c)
toy_meter_object="$PWD/toy/.build/meter-${toy_meter_hash}.o"
cc -O2 -Wall -Wextra -Werror -c toy/meter.c -o "$toy_meter_object"
cargo rustc --locked --features development-gate --bin cvld -- \
  -C "link-arg=$toy_meter_object" -C link-arg=-Wl,--wrap=sqlite3_step
# The toy root is new; the copied lock retains the door's exact dependency versions.
cargo build --manifest-path toy/.build/Cargo.toml
