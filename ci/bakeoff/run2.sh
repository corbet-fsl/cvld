#!/bin/sh
# Runs the steps of ci/bakeoff/commands.tsv (all, or only ONLY_STEP) with the levers named in BAKEOFF_LEVERS.
set -u
out=${1:?output directory}
mkdir -p "$out"
export CARGO_BUILD_JOBS=16 RUST_TEST_THREADS=16 CARGO_TERM_COLOR=never CARGO_INCREMENTAL=1
levers=",${BAKEOFF_LEVERS:-},"
case "$levers" in
 *,mold,*) export CARGO_PROFILE_DEV_DEBUG=line-tables-only CARGO_PROFILE_TEST_DEBUG=line-tables-only RUSTFLAGS="-C link-arg=-fuse-ld=mold" ;;
esac
server=""
case "$levers" in
 *,sccache,*)
    mkdir -p "$SCCACHE_DIR"
    export RUSTC_WRAPPER="$PWD/ci/bakeoff/rustc-wrapper.sh" SCCACHE_CACHE_SIZE=100G SCCACHE_IDLE_TIMEOUT=0 SCCACHE_SERVER_UDS="/tmp/sccache-$$.sock"
    (SCCACHE_START_SERVER=1 SCCACHE_NO_DAEMON=1 exec sccache) > "$out/sccache-start-${ONLY_STEP:-all}.txt" 2>&1 &
    server=$!
    export SCCACHE_SERVER_PID=$server
    sleep 1
    sccache --zero-stats > /dev/null ;;
esac
sha256sum Cargo.lock > "$out/lock-before-${ONLY_STEP:-all}.sha256"
rustc --version > "$out/toolchain.txt"
cargo --version >> "$out/toolchain.txt"
failed=0
while IFS="$(printf '\t')" read -r step command; do
    [ -n "$step" ] || continue
    [ -z "${ONLY_STEP:-}" ] || [ "$step" = "$ONLY_STEP" ] || continue
    printf 'BEGIN %s %s\n' "$step" "$command"
    if [ -n "$server" ]; then python3 ci/bakeoff/server-cpu.py > "$out/$step.server-before.json"; fi
    command time -f '{"wall_s":%e,"user_s":%U,"system_s":%S,"rss_kib":%M,"exit":%x}' -o "$out/$step.time" timeout --kill-after=30 1500 sh -c "$command" > "$out/$step.log" 2>&1
    rc=$?
    if [ -n "$server" ]; then python3 ci/bakeoff/server-cpu.py > "$out/$step.server-after.json"; fi
    printf '%s\n' "$rc" > "$out/$step.exit"
    if [ "$rc" -eq 0 ]; then tail -n 3 "$out/$step.log"; else tail -n 40 "$out/$step.log"; fi
    cat "$out/$step.time"
    [ "$rc" -eq 0 ] || failed=1
done < ci/bakeoff/commands.tsv
if [ -n "$server" ]; then
    sccache --show-stats > "$out/sccache-stats-${ONLY_STEP:-all}.txt" 2>&1
    sccache --stop-server > /dev/null 2>&1
fi
exit "$failed"
