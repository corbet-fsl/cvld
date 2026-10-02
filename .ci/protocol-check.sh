#!/usr/bin/env bash
set -euo pipefail
: "${CI:?CI only}"
: "${CARGO_TARGET_DIR:?persistent target required}"
: "${CI_COMMIT_SHA:?exact source required}"
reports="$CARGO_TARGET_DIR/ci-receipts/$CI_COMMIT_SHA"
mkdir -p "$reports"
rustc --version > "$reports/protocol-runtime.txt"
cargo --version >> "$reports/protocol-runtime.txt"
sha256sum Cargo.lock >> "$reports/protocol-runtime.txt"
cp docs/openapi.json "$reports/openapi.before.json"
cp clients/ts/schema.d.ts "$reports/schema.before.d.ts"
cargo run --locked -- openapi > "$reports/openapi.json"
cp "$reports/openapi.json" docs/openapi.json
npm ci --prefix clients/ts
npm run generate --prefix clients/ts
npm run check --prefix clients/ts
npm test --prefix clients/ts
cp clients/ts/schema.d.ts "$reports/schema.d.ts"
cmp "$reports/openapi.before.json" "$reports/openapi.json"
cmp "$reports/schema.before.d.ts" "$reports/schema.d.ts"
