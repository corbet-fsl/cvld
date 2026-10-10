#!/usr/bin/env python3
"""Verify that each removed time guard fails its actual integration assertion."""
import os
from pathlib import Path
import re
import subprocess

CONTROLS = (
    ("src/service.rs", b"ctx.now = self.current_time(&ctx)?;", b"", 4,
     "execution_rechecks_session_time_after_waiting_for_authentication",
     "waiting for authentication must not preserve an expired or rolled-back session"),
    ("src/service/publication.rs", b"if publication.check().is_err()", b"if false", 1,
     "a_session_expiring_during_issuance_cannot_publish_a_usable_passport",
     "an expired session published a usable passport"),
    ("src/service.rs", b"publication::expires_at(until)",
     b"publication::expires_at(until.saturating_add(3600))", 1,
     "a_pending_nonce_expiring_during_issuance_cannot_publish_a_usable_passport",
     "an expired pending nonce published a usable passport"),
)
PREFIX = "service::boundaries::timing::"
ASSERTION_SOURCE = "src/service/tests/timing.rs"


def run(test):
    result = subprocess.run(
        ["cargo", "test", "--locked", "--features", "development-gate", "--lib",
         PREFIX + test, "--", "--exact", "--nocapture"], capture_output=True,
        text=True, timeout=900,
        env={**os.environ, "CARGO_TERM_COLOR": "never", "RUST_BACKTRACE": "0"},
    )
    return result.returncode, result.stdout + result.stderr


def selected(output, test, verdict):
    return re.search(r"^test " + re.escape(PREFIX + test) + r" \.\.\. " + verdict + r"$",
                     output, re.M) is not None


def baseline(status, output, test):
    return (status == 0 and selected(output, test, "ok")
            and "test result: ok. 1 passed; 0 failed; 0 ignored;" in output)


def assertion(status, output, test, marker):
    return (status == 101 and selected(output, test, "FAILED")
            and "test result: FAILED. 0 passed; 1 failed; 0 ignored;" in output
            and re.search(r"thread '" + re.escape(PREFIX + test)
                          + r"'(?: \([0-9]+\))? panicked at "
                          + re.escape(ASSERTION_SOURCE) + r":[0-9]+:[0-9]+:", output)
            and marker in output and "error[E" not in output
            and "could not compile" not in output)


def main():
    for source, before, after, count, test, marker in CONTROLS:
        path = Path(source)
        original = path.read_bytes()
        if original.count(before) != count:
            raise SystemExit("Time control source drift: " + test)
        status, output = run(test)
        if not baseline(status, output, test):
            print(output)
            raise SystemExit("Time control requires an exact passing baseline: " + test)
        try:
            path.write_bytes(original.replace(before, after))
            status, output = run(test)
            if not assertion(status, output, test, marker):
                print(output)
                raise SystemExit("Removed time guard did not fail its named assertion")
            print("Removed time guard refused by named assertion: " + test)
        finally:
            path.write_bytes(original)
        if path.read_bytes() != original:
            raise SystemExit("Time control source restoration failed")


if __name__ == "__main__":
    main()
