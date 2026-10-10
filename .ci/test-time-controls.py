#!/usr/bin/env python3
"""Inert checks for selected-test evidence and restoration on every exit."""
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("controls", Path(__file__).with_name("time-controls.py"))
controls = importlib.util.module_from_spec(spec)
spec.loader.exec_module(controls)
TEST = "probe"
MARKER = "exact assertion"


def report(verdict="FAILED", pid=" (123)"):
    summary = "FAILED. 0 passed; 1 failed" if verdict == "FAILED" else "ok. 1 passed; 0 failed"
    return (f"thread '{controls.PREFIX}{TEST}'{pid} panicked at {controls.ASSERTION_SOURCE}:42:5:\n"
            f"{MARKER}\ntest {controls.PREFIX}{TEST} ... {verdict}\n"
            f"test result: {summary}; 0 ignored; 0 measured; 0 filtered out\n")


class Controls(unittest.TestCase):
    def test_exact_panic_with_and_without_process_id(self):
        for pid in ["", " (123)"]:
            self.assertTrue(controls.assertion(101, report(pid=pid), TEST, MARKER))

    def test_build_empty_and_unrelated_failures_refuse(self):
        for status, output in [(1, report()), (101, ""),
                               (101, report().replace(MARKER, "wrong assertion")),
                               (101, report().replace(TEST, "other_test")),
                               (101, report().replace(controls.ASSERTION_SOURCE, "src/other.rs")),
                               (101, report() + "error[E0308]: type mismatch"),
                               (101, report() + "could not compile"),
                               (101, report().replace("0 passed; 1 failed", "0 passed; 2 failed"))]:
            self.assertFalse(controls.assertion(status, output, TEST, MARKER))

    def test_baseline_requires_one_selected_success(self):
        self.assertTrue(controls.baseline(0, report("ok"), TEST))
        for status, output in [(101, report("ok")), (0, ""), (0, report())]:
            self.assertFalse(controls.baseline(status, output, TEST))

    def test_restores_bytes_after_assertion_rejection_or_transport_failure(self):
        for outcome in [(101, report()), (101, "build failed"), RuntimeError("interrupted")]:
            with tempfile.TemporaryDirectory() as directory:
                source = Path(directory) / "source.rs"
                original = b"guard();\n"
                source.write_bytes(original)
                entries = ((str(source), b"guard();", b"", 1, TEST, MARKER),)
                with patch.object(controls, "CONTROLS", entries), patch.object(
                    controls, "run", side_effect=[(0, report("ok")), outcome]
                ):
                    if isinstance(outcome, RuntimeError):
                        with self.assertRaises(RuntimeError):
                            controls.main()
                    elif outcome[1] == "build failed":
                        with self.assertRaises(SystemExit):
                            controls.main()
                    else:
                        controls.main()
                self.assertEqual(source.read_bytes(), original)

    def test_source_drift_refuses_before_cargo(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source.rs"
            source.write_bytes(b"changed\n")
            with patch.object(controls, "CONTROLS", ((str(source), b"guard", b"", 1, TEST, MARKER),)), patch.object(controls, "run") as run:
                with self.assertRaises(SystemExit):
                    controls.main()
                run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
