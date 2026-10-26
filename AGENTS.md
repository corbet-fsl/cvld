# cvld agent notes

Work in a lane (`~/agents/scratch/lane-new <lane>`); never edit `~/agents/scratch/ws`.
Run commands from the lane root (`<lane>/ws`); `<lane>` below is your lane name.

Build and test (quote the verdict line, never infer from a pipe):
- `~/agents/scratch/cbuild <lane> test -p cvld` — lib `121 passed`, second binary
  `11 passed`, integration `56 passed` + 5 pre-existing `native_account_factory`
  failures (fail identically on clean main, `tests/support/mod.rs:139`)
- `~/agents/scratch/cbuild <lane> fmt -p cvld -- --check` — must be clean
- Full gate (clippy matrix, wasm, coverage, generated-client sync, advisories)
  runs in CI only: `.ci/verify.sh` via `bash .ci/run-cached.sh`.

Land: `cargo fmt` in touched repos, rebase on main (never force-push),
`cbuild <lane> xtask land --dry`, then `xtask land`.

Invariants (rule -> enforcing test):
- One action registry; HTTP/OpenAPI/CLI/MCP expose exactly it
  -> `tests/cases/surfaces.rs::openapi_cli_and_mcp_have_exactly_the_registry_actions`
- `development-gate` synthetic action never ships in release
  -> `build.rs` panic + `tests/cases/build_policy.rs`, `tests/cases/production.rs`
- Generated OpenAPI/TS client committed and in sync; portable client has no server graph
  -> CI `git diff --exit-code -- docs/openapi.json clients/ts/schema.d.ts`; `tests/cases/client_contract.rs`
- Hostile input refused (`deny_unknown_fields`, duplicate keys, secret config)
  -> `tests/cases/root_config.rs`, `tests/unit/client_json.rs`
- Global/community DB, keys, auth isolated; DB identity refuses rebinding
  -> `tests/cases/community_http.rs`, `src/global/tests.rs`
- Auth before body: exact host, per-source throttle, `no-store` on every response
  -> `src/service_tests.rs`, `tests/cases/global_http.rs`
- No request logging; fixed redacted failures; `forbid(unsafe_code)`
  -> `tests/cases/startup.rs`, `tests/cases/production.rs::malformed_cli_input_is_not_repeated_in_diagnostics`
- Owner client: HTTPS-only, exact host, uncertain post-dispatch reconciles without retry
  -> `tests/cases/client_contract.rs::committed_logout_with_a_lost_or_malformed_response_is_unknown_and_never_retried`
- Every `tests/cases/*.rs` wired into the single test binary
  -> `tests/cvld.rs::every_case_file_is_wired_into_this_binary`

Pointers: `src/api/mod.rs` (registry), `docs/CONTRACT.md`, `docs/openapi.json`, `.ci/verify.sh`.
Commits: explicit paths, imperative, author per `~/agents/AGENT.md`; no AI trailers.
`publish=false`; no crypto primitives, no npm/crates.io release.
