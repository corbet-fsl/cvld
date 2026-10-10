# Coverage

CI uses the retained Cargo.lock with `--locked` for stable checks,
advisory policy and nightly LLVM branch instrumentation. Manifest dependencies
follow compatible upstream releases and first-party main branches; lock refreshes
are validated and retained as new tested snapshots. Both line and branch
counts must be complete; any reachable gap fails the gate. No production source
is excluded. Only test harness files (`tests/` and `tests.rs`) are omitted from
the measured source; their actual round trips still execute.

A configured gate is not a coverage result. The raw report is retained on failure.
Crow keeps the three completed reports under the source commit in the existing
CI artifact directory, even when the final coverage check fails.

Only the instrumented test profile uses optimization level zero. Normal native
tests retain their optimized profile and release checks still run separately.
Rust's [coverage documentation](https://doc.rust-lang.org/rustc/instrument-coverage.html#compiling-with-coverage-enabled)
warns that optimized-out functions can make coverage maps inaccurate; this
configuration measures their execution without adding source exclusions.

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
