#!/bin/sh
# Round 2 worker. Usage: worker2.sh <A0|A1|A2|C0|C1|C2>; env SCENARIO (setup|S1|S3|S4|S6), REPETITION.
set -eu
variant=${1:?variant}
case "$variant" in A0|A1|A2|C0|C1|C2) ;; *) exit 64 ;; esac
export PATH=/nix/var/nix/profiles/system/sw/bin:/shared:$PATH
scenario=${SCENARIO:-setup}
rep=${REPETITION:-1}
repo=${CI_REPO_NAME:?}
base=/workspaces/bakeoff
common=$base/common/$repo
shared=$base/$variant
vroot=$shared/$repo
mkdir -p "$common" "$vroot"
awk '/MemAvailable:/ { if ($2 < 8388608) exit 1 }' /proc/meminfo || { echo "Insufficient memory headroom"; exit 75; }
export XDG_CACHE_HOME="$base/common/xdg-cache"
export NIX_CONFIG="max-jobs = 1
cores = 16"
dagger=$base/C/bin/dagger
export _EXPERIMENTAL_DAGGER_RUNNER_HOST=${ENGINE:-tcp://10.42.88.194:12345} DAGGER_NO_NAG=1
case "$scenario" in
 setup)
    nix build path:./ci/bakeoff/tools#tools --no-link --print-out-paths > "$common/tools-path"
    tools=$(cat "$common/tools-path")
    printf 'fn main() {}\n' > "$common/probe.rs"
    "$tools/bin/bakeoff-env" rustc "$common/probe.rs" -l pam -C link-arg=-fuse-ld=mold -o "$common/probe"
    "$tools/bin/bakeoff-env" sh -c 'mold --version; sccache --version; rustc --version'
    nix build path:./ci/bakeoff/tools#image --no-link --print-out-paths > "$common/image-path"
    cat "$common/tools-path" "$common/image-path"
    "$dagger" version
    "$dagger" develop --sdk=go > "$common/develop.log" 2>&1 || { cat "$common/develop.log"; exit 1; }
    "$dagger" functions > "$common/functions.log" 2>&1 || { cat "$common/functions.log"; exit 1; }
    rm -rf "$common/generated-module"; cp -r .dagger "$common/generated-module"
    exit 0 ;;
esac
case "$scenario" in S1|S3|S4|S6) ;; *) exit 64 ;; esac
case "$variant" in A0|C0) levers="" ;; A1|C1) levers="mold" ;; A2|C2) levers="mold,sccache" ;; esac
tag=main; [ "$scenario" != S6 ] && [ "$repo" != cvld ] || tag=s6
out="$vroot/runs/$scenario-$rep"
test ! -e "$out"
mkdir -p "$out"
workspace="$vroot/source-$tag"
stamp=$(date +%s)
# Cold scenarios: fresh target (A) or fresh volume names (C), fresh registry download. The first repo also starts the shared sccache empty.
sccdir="$shared/sccache"
if [ "$scenario" = S1 ]; then
  if [ "$repo" = oo7 ]; then
    rm -rf "$shared/sccache"; echo "sccache-$variant-$stamp" > "$shared/sccache-ns"
  else
    sccdir="$shared/sccache-solo"; rm -rf "$sccdir"; echo "sccache-solo-$repo-$variant-$stamp" > "$vroot/sccache-ns-solo"
  fi
fi
if [ "$scenario" = S1 ] || [ "$scenario" = S6 ]; then
  rm -rf "$vroot/target-$tag" "$workspace" "$shared/cargo-home/registry" "$shared/cargo-home/git"
  echo "$repo-$variant-$tag-$stamp" > "$vroot/dagger-ns-$tag"
fi
mkdir -p "$workspace"
rsync -rc --delete --exclude=.git --exclude=bakeoff-results ./ "$workspace/"
git rev-parse HEAD > "$out/commit"
printf '%s\n' "$workspace" > "$out/workspace"
unset RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTC_WRAPPER
cat /proc/net/dev > "$out/net-before.txt"
cd "$workspace"
set +e
case "$variant" in
 A*)
    tools=$(cat "$common/tools-path")
    export CARGO_HOME="$shared/cargo-home" CARGO_TARGET_DIR="$vroot/target-$tag" SCCACHE_DIR="$sccdir" BAKEOFF_LEVERS="$levers"
    command time -v -o "$out/client.time" "$tools/bin/bakeoff-env" dbus-run-session --config-file=ci/bakeoff/session.conf -- sh ci/bakeoff/run2.sh "$out/steps" > "$out/console.log" 2>&1
    rc=$?
    du -sk "$CARGO_HOME" "$CARGO_TARGET_DIR" "$SCCACHE_DIR" > "$out/cache-kib.txt" 2>&1 ;;
 C*)
    rsync -rc --exclude=main.go "$common/generated-module/" .dagger/
    ns=$(cat "$vroot/dagger-ns-$tag")
    sccns=$(cat "$shared/sccache-ns")
    if [ "$repo" != oo7 ] && [ "$scenario" != S6 ] && [ -f "$vroot/sccache-ns-solo" ]; then sccns=$(cat "$vroot/sccache-ns-solo"); fi
    par=false; case "$variant" in C1|C2) par=true ;; esac
    command time -v -o "$out/client.time" "$dagger" --progress=plain call check --source=. --image="$(cat "$common/image-path")" --ns="$ns" --levers="$levers" --sccache-ns="$sccns" --run-id="${CI_PIPELINE_NUMBER:-0}" --parallel="$par" export --path="$out/steps" > "$out/console.log" 2>&1
    rc=$?
    if [ "$rc" -eq 0 ]; then
      for f in "$out"/steps/*.exit; do [ "$(cat "$f")" = 0 ] || rc=1; done
    fi
    cat "$out"/steps/cache-kib-*.txt > "$out/cache-kib.txt" 2>/dev/null ;;
esac
printf '%s\n' "$rc" > "$out/exit"
cat /proc/net/dev > "$out/net-after.txt"
tail -n 60 "$out/console.log"
cat "$out/client.time" | grep -E "Elapsed|Maximum resident|User time|System time"
cat "$out/cache-kib.txt" 2>/dev/null || true
exit "$rc"
