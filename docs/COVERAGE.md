# Coverage

CI resolves one fresh Cargo.lock per independent workspace and uses each snapshot for stable checks,
advisory policy and nightly LLVM branch instrumentation. Both line and branch
counts must be complete; any reachable gap fails the gate. No production source
is excluded. Only test harness files (`tests/` and `tests.rs`) are omitted from
the measured source; their actual round trips still execute.

A configured gate is not a coverage result. The raw report is retained on failure.

The functional toy scenarios run in this same workflow and verify their dependency
closure against its lock snapshot. The retained 200-holder scale command is for
Crow execution; public CI does not execute scale or load measurements.

The coverage job exports raw JSON and LCOV from the same actual test execution.
The gate requires every emitted production DA line and BRDA branch to have a
nonzero counter, at 100% for both metrics. It cross-checks file inventories,
summaries and emitted branch locations against the companion JSON. Missing,
duplicate, empty or malformed evidence cannot pass. Raw JSON totals remain
as diagnostic evidence for generic instantiations; source coverage does not
claim every generic instantiation is covered. Both artifacts are retained on
failure. No production source exclusions are currently approved.

The browser consumer lives in `tests/browser`, using the exact local production
`cvld` source with `client-browser`. Cargo resolves every optional feature of a
workspace member, so placing the browser runner in the server workspace also
constrains it to the unused server proof engine's JavaScript dependency graph.
An independent consumer resolves only the client features it actually uses,
following [Cargo's feature resolution rules](https://doc.rust-lang.org/cargo/reference/resolver.html#features).
The native fixture still builds and runs the complete server against its original
workspace snapshot. Neither graph pins or replaces an upstream dependency.

The resolver shares both locks with all jobs; browser policy and stable Clippy
check the consumer graph, and nightly executes real Chrome vectors through the
real native door and ephemeral TLS. The stable native job builds that fixture
once; the browser job consumes the same-run executable and checks its lock
against the shared server snapshot. `cargo llvm-cov --dep-coverage cvld` measures
the production dependency, following the [upstream external-test workflow](https://github.com/taiki-e/cargo-llvm-cov#get-coverage-of-external-tests).
JSON, LCOV and annotated reports cover the same execution and retain the strict
source gate. A successful native run cannot substitute for this browser gate.
