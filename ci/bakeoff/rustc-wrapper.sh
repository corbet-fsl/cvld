#!/bin/sh
# RUSTC_WRAPPER: own crates (CARGO_PRIMARY_PACKAGE set) use plain rustc so incremental stays on;
# dependencies go through sccache. Cargo passes the rustc path as $1.
if [ -n "${CARGO_PRIMARY_PACKAGE:-}" ]; then exec "$@"; fi
exec env -u CARGO_INCREMENTAL sccache "$@"
