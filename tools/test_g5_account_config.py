#!/usr/bin/env python3
"""The wave/outcome key group is a reviewed pin, read from its own retained group."""
import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location("g5", Path(__file__).with_name("g5-account-config.py"))
g5 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(g5)

GROUP = "a8a4689889a33c8edd0186ba64f5d65bd2a47e97"


class WaveGroup(unittest.TestCase):
    def retained(self, manifest):
        root = tempfile.TemporaryDirectory()
        self.addCleanup(root.cleanup)
        directory = Path(root.name) / GROUP / "wave-artifacts"
        (directory / "setup").mkdir(parents=True)
        (directory / "manifest.json").write_bytes(manifest)
        return Path(root.name)

    def test_group_has_a_reviewed_pin(self):
        self.assertIn(GROUP, g5.WAVE_GROUPS)
        self.assertEqual(len(g5.WAVE_GROUPS[GROUP]["manifestSha256"]), 64)

    def test_pinned_manifest_yields_wave_files(self):
        manifest = b"{}"
        root = self.retained(manifest)
        pin = {GROUP: {"manifestSha256": hashlib.sha256(manifest).hexdigest()}}
        files = g5.wave_artifact_files(root, GROUP, pin)
        self.assertTrue(files["keys_file"].endswith(f"{GROUP}/wave-artifacts/keys.json"))
        self.assertTrue(files["circuit_file"].endswith("wave-artifacts/circuits.json"))

    def test_other_manifest_refuses(self):
        root = self.retained(b"{}")
        pin = {GROUP: {"manifestSha256": "0" * 64}}
        with self.assertRaises(SystemExit):
            g5.wave_artifact_files(root, GROUP, pin)

    def test_group_without_pin_has_no_wave_group(self):
        self.assertIsNone(g5.wave_artifact_files(Path("/nonexistent"), "0" * 40, {}))


if __name__ == "__main__":
    unittest.main()
