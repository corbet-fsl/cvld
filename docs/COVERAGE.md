# Coverage

CI resolves one fresh Cargo.lock and uses that snapshot for stable checks,
advisory policy and nightly LLVM branch instrumentation. Both line and branch
counts must be complete; any reachable gap fails the gate. No production source
is excluded. Only test harness files (`tests/` and `tests.rs`) are omitted from
the measured source; their actual round trips still execute.

A configured gate is not a coverage result. The raw report is retained on failure.

The functional toy scenarios run in this same workflow and verify their dependency
closure against its lock snapshot. The retained 200-holder scale command is for
Crow execution; public CI does not execute scale or load measurements.
