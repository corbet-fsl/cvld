"""Exercise the actual lock checker with independent synthetic lock graphs."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("check_lock.py")
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
GIT = "git+https://example.test/owner?branch=main#original-revision"
DOOR = ("cvld", "0.2.0", None)
TOY = ("cvld-toy", "0.0.0", None)
RUNTIME = ("runtime", "1.2.3", REGISTRY, "a" * 64)
OWNER = ("owner", "1.0.0", GIT)


def write_lock(path, packages):
    lines = ["version = 4"]
    for name, version, source, *checksum in packages:
        lines += ["[[package]]", f"name = {json.dumps(name)}",
                  f"version = {json.dumps(version)}"]
        if source is not None:
            lines.append(f"source = {json.dumps(source)}")
        if checksum:
            lines.append(f"checksum = {json.dumps(checksum[0])}")
    path.write_text("\n".join(lines) + "\n")


class LockTest(unittest.TestCase):
    def run_checker(self, toy, root=None):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            root_path, toy_path = directory / "root.lock", directory / "toy.lock"
            write_lock(root_path, root if root is not None else
                       [DOOR, RUNTIME, OWNER, ("unused-browser-test", "9.0.0", REGISTRY)])
            write_lock(toy_path, toy)
            return subprocess.run([sys.executable, str(SCRIPT), str(root_path), str(toy_path)],
                                  capture_output=True, text=True, timeout=10)

    def test_unused_pruning_preserves_exact_used_graph(self):
        result = self.run_checker([TOY, DOOR, RUNTIME, OWNER])
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_changed_registry_version_or_source_refuses(self):
        for changed in [("runtime", "1.2.4", REGISTRY),
                        ("runtime", "1.2.3", "registry+https://other.example.test/index")]:
            with self.subTest(changed=changed):
                self.assertNotEqual(self.run_checker([TOY, DOOR, changed, OWNER]).returncode, 0)

    def test_changed_git_revision_or_branch_refuses(self):
        for changed in [GIT.replace("original-revision", "other-revision"),
                        GIT.replace("branch=main", "branch=other")]:
            with self.subTest(changed=changed):
                self.assertNotEqual(self.run_checker([TOY, DOOR, RUNTIME, ("owner", "1.0.0", changed)]).returncode, 0)

    def test_changed_git_version_refuses(self):
        self.assertNotEqual(self.run_checker([TOY, DOOR, RUNTIME,
                            ("owner", "1.0.1", GIT)]).returncode, 0)

    def test_changed_or_missing_registry_checksum_refuses(self):
        for changed in [("runtime", "1.2.3", REGISTRY, "b" * 64),
                        ("runtime", "1.2.3", REGISTRY)]:
            with self.subTest(changed=changed):
                self.assertNotEqual(self.run_checker([TOY, DOOR, changed, OWNER]).returncode, 0)

    def test_duplicate_identity_cannot_replace_a_locked_package(self):
        self.assertNotEqual(self.run_checker([TOY, DOOR, RUNTIME, RUNTIME, OWNER]).returncode, 0)
        self.assertNotEqual(self.run_checker([TOY, DOOR, RUNTIME, OWNER],
                                           root=[DOOR, DOOR, RUNTIME, OWNER]).returncode, 0)

    def test_unapproved_extra_dependency_refuses_even_with_all_original_packages(self):
        self.assertNotEqual(self.run_checker([TOY, DOOR, RUNTIME, OWNER,
                            ("unapproved", "1.0.0", REGISTRY)]).returncode, 0)

    def test_missing_or_changed_original_door_refuses(self):
        for door in [None, ("cvld", "0.2.1", None), ("cvld", "0.2.0", REGISTRY)]:
            with self.subTest(door=door):
                toy = [TOY, RUNTIME, OWNER] + ([door] if door else [])
                self.assertNotEqual(self.run_checker(toy).returncode, 0)

    def test_exception_is_only_exact_local_toy_root(self):
        for toy in [("cvld-toy", "0.0.1", None), ("cvld-toy", "0.0.0", REGISTRY),
                    ("other-toy", "0.0.0", None)]:
            with self.subTest(toy=toy):
                self.assertNotEqual(self.run_checker([toy, DOOR, RUNTIME, OWNER]).returncode, 0)


if __name__ == "__main__":
    unittest.main()
