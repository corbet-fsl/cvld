"""Exercise the actual native harness generator without Cargo or network I/O."""
import pathlib
import runpy
import tempfile
import tomllib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


class PrepareTest(unittest.TestCase):
    def test_native_dependencies_optional_flags_and_original_lock(self):
        original = (ROOT / "Cargo.toml").read_text()
        # An overlapping browser-only declaration must not replace a native
        # dependency even when that dependency is on the generator's allowlist.
        original = original.replace(
            '[target.\'cfg(target_arch = "wasm32")\'.dev-dependencies]',
            '[target.\'cfg(target_arch = "wasm32")\'.dev-dependencies]\n'
            'cmty = "browser-only-test-dependency"',
        )
        lock = (ROOT / "Cargo.lock").read_bytes()
        global_cases = [
            "",
            '\n[dev-dependencies]\nchrono = { version = "99-test-only", '
            'optional = true, features = ["sentinel"] }\n',
        ]
        for global_dev in global_cases:
            with (
                self.subTest(global_dev=bool(global_dev)),
                tempfile.TemporaryDirectory() as directory,
            ):
                fixture = pathlib.Path(directory)
                toy = fixture / "toy"
                toy.mkdir()
                manifest = original + global_dev
                (fixture / "Cargo.toml").write_text(manifest)
                (fixture / "Cargo.lock").write_bytes(lock)
                generator = toy / "prepare.py"
                generator.write_bytes((ROOT / "toy" / "prepare.py").read_bytes())
                runpy.run_path(str(generator), run_name="__main__")

                generated = tomllib.loads((toy / ".build" / "Cargo.toml").read_text())
                source = tomllib.loads(manifest)
                native = source["target"]['cfg(not(target_arch = "wasm32"))'][
                    "dev-dependencies"
                ]
                expected = (
                    source["dependencies"] | source.get("dev-dependencies", {}) | native
                )
                dependencies = generated["dependencies"]
                for name in [
                    "cmty", "chrono", "passkey", "async-trait",
                    "webauthn-authenticator-rs", "tempfile", "cvch",
                ]:
                    declaration = expected[name]
                    if isinstance(declaration, dict):
                        declaration = {
                            key: value for key, value in declaration.items()
                            if key != "optional"
                        }
                    self.assertEqual(dependencies[name], declaration)
                self.assertTrue(all(
                    not isinstance(value, dict) or "optional" not in value
                    for value in dependencies.values()
                ))
                self.assertNotIn("wasm-bindgen-test", dependencies)
                self.assertNotIn("gloo-net", dependencies)
                self.assertEqual(dependencies["cvld"]["features"], ["development-gate"])
                self.assertEqual((toy / ".build" / "Cargo.lock").read_bytes(), lock)


if __name__ == "__main__":
    unittest.main()
