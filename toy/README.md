# cvld toy model

A black-box client harness for the public `cvld` CLI. It starts `cvld serve
global` and one `cvld serve community` process per community, with separate
libSQL files, keys and configuration. Every domain operation invokes the public
CLI, which calls the ordinary HTTP door. The harness never opens the databases,
constructs a `Door`, invokes a facade operation, or writes membership state.

Software authenticators create real UV-verified WebAuthn credentials. Each holder
receives a real blind-issued passport and makes origin-bound community proofs.
Holder-side cryptography uses `cpsd`; the test sponsor uses `cvch` and
`ed25519-dalek`. These are synthetic identities, not production accounts.

## Run

Use GitHub Actions or a Linux build host with current stable Rust, Python 3.11+
(for manifest preparation only), a C compiler, OpenSSL development headers and
[libfaketime](https://github.com/wolfcw/libfaketime). Do not run Cargo on the
workstation. The **toy** job in `.github/workflows/toy.yml` builds and runs this
harness automatically on every push to main.

From the repository root on the build host:

```sh
toy/build.sh
target/debug/cvld-toy scenarios
target/debug/cvld-toy scale
# Run a selected readable scenario:
target/debug/cvld-toy scenarios toy/scenarios/03-policy.json
```

Set `CVLD_BIN` for a different development binary, `LIBFAKETIME_PATH` for a
nonstandard `libfaketimeMT.so.1` location, and `TOY_REPORT_DIR` for report output.
The default report directory is `toy/reports/`. Services bind only loopback.
Child processes are terminated and temporary databases/secrets removed when a
scenario finishes. Reports contain fixed assertion messages and aggregate
measurements, never identifiers, handles, tokens, request bodies or SQL.

`prepare.py` creates an ignored test-only crate under `.build/`. Its dependencies
come from the door's manifest and every build starts from the door's lockfile, so
parallel dependency updates do not leave separate hardcoded leaf revisions in
the toy. The generated lock is retained in the CI artifact. The CLI and harness
share dependency build profiles; the cache key includes the build scripts and
only successful runs publish a new cache. Nothing is published.

Only service child processes receive the libfaketime preload. Their wall clock
is frozen and advanced through an atomic timestamp-file replacement; monotonic
time, client latency measurements and normal service timers remain real. The
expiry scenario restarts the same services and databases at the deadline, letting
normal startup maintenance run. Public signed global metadata is distributed via
the existing explicit configuration files, just as an operator would do.

## Scenarios

Each JSON file contains an ordered script. Every step asserts its result and
prints a short description. Unexpected errors or assertion failures exit nonzero.

| File | What it proves |
| --- | --- |
| `01-unlinkable.json` | One wallet produces the expected, distinct pseudonym in each community, with separate account IDs and device keys. A foreign community session is refused. This is functional domain-separation evidence; the cryptographic unlinkability claim belongs to `cpsd`. |
| `02-voucher.json` | The lobby names the missing voucher and warns about expiry and losing all devices. A member-bound voucher permits admission; replay fails. |
| `03-policy.json` | An admin adds the voucher requirement. Epoch, revision and signed settings change; the old credential and rollback feed fail verification. Renewal lapses the member until the new gate passes. |
| `04-red-gate.json` | Withdrawing the required gate lapses an admitted member and invalidates the previously issued credential. |
| `05-expiry.json` | At the registration deadline, maintenance frees the reserved handle, and a different holder reserves it. A fresh proof of the same pseudonym cannot register again: **NO RETURN**. |
| `06-lost-passkeys.json` | Revoking the last passkey releases access, rejects its existing session and credential, and permanently refuses re-registration. Physical loss cannot be observed by a server; this exercises explicit loss/revocation of every registered key. |
| `07-second-device.json` | Register a second UV-required passkey through `passkey_add`, revoke the first and refuse its session, log in with the surviving key, preserve the member and handle, and obtain a fresh independently verified credential. |
| `08-root-force.json` | Root forces a setting; an admin's community override cannot change the effective value, and an admin cannot use the root action. |
| `09-global-suspension.json` | A warned wallet is suspended. It cannot renew its passport, and both communities refuse its next credential renewal after consuming the updated signed global epoch. |
| `10-throttle.json` | With a one-request burst, registration and handle checks independently exhaust their aggregate quotas. |
| `11-offline.json` | A cfrm stand-in pulls all five signed snapshots and the manifest. After every service stops, it verifies the credential locally and refuses tampering, expiry and foreign-community trust. |

Scenario 7 uses the common public CLI action for both ceremony phases and real
WebAuthn user verification. It asserts access through the surviving passkey after
the original is removed, including fresh credential issuance and verification.

## Scale and row metering

The scale script creates **200 distinct wallets**, each joining **all five
communities**: 1,000 community passkeys, voucher redemptions and admissions. Each
member also logs in again and reads the populated lobby. The explicit test
configuration allows 1,024 ephemeral sessions per service, since frozen wall time
keeps the scale run's sessions live. It reports nearest-rank
p50/p95/p99 latency per service scope and action, call/error counts, total rows
read/returned, maximum rows read per call, and the number of calls whose reads
exceed their SQL result rows. Expected voucher replay refusals are included in
error counts. Calls run sequentially; these are CLI end-to-end latencies including
process startup, not a concurrency or production-throughput claim.

`meter.c` is linked **only into the toy's cvld executable**, using GNU ld's
`--wrap=sqlite3_step`. It observes the unmodified libSQL engine's
`LIBSQL_STMTSTATUS_ROWS_READ` counter (1025) before and after each step and counts
`SQLITE_ROW` results. This is the engine's actual row meter, not an estimate from
`EXPLAIN QUERY PLAN` or a count of table contents. EXPLAIN statements are excluded.
The wrapper writes only two integer counters to a private temporary file. It
never changes a query, return value, database row or public API.

Each CLI call samples those counters before and after. Normal maintenance that
runs concurrently is conservatively included. `rows_returned` means SQL result
rows, not JSON objects returned to the client. Reads performed by writes can
therefore also trigger `READS_EXCEED_RETURNED`; the flag is a cost investigation
signal, not proof of an unindexed table scan. `crlt` independently enforces its
indexed-query plan policy. The run fails if the meter records no reads, so a
missing hook cannot silently produce a zero-cost result. Latencies include the
meter's test overhead and should be compared only between equivalent builds.

CI uploads `toy-results`: readable transcripts, `scenarios.json`, `scale.json`,
and the exact harness dependency lock. The reports retain no per-member timing
history or member labels.

## Optional Turso

```sh
# Set both values externally for an explicitly disposable, empty database.
target/debug/cvld-toy turso
```

The command skips without both nonempty `TURSO_URL` and `TURSO_TOKEN`. Neither is
configured in public CI. It uses the supplied database for the global service
and performs a real passkey, development-gate and blind-passport round trip;
community databases remain separate local files. One URL cannot safely stand in
for six isolated databases. This optional smoke run is not a remote scale test,
and the local C row meter does not measure remote reads. No database provisioning,
paid gate, deployment or registry publication is performed. The run uses current
wall time for remote TLS validation and leaves the disposable remote data in place.

The holder uses a test-only resident software authenticator with real PRF
computation. Server options are preserved, only the test PRF input is added, and
PRF outputs are removed before every public CLI call. Scenario 7 restores the
surviving synced passkey without sending a saved member or credential ID and
checks the same local PRF output and membership. This proves the server key flow;
it does not simulate DHT vault storage or browser iframe compatibility.
