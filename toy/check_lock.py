#!/usr/bin/env python3
"""Require the native harness to use only the original locked identities."""
import argparse
from pathlib import Path
import tomllib


def packages(path):
    packages = tomllib.loads(Path(path).read_text())["package"]
    result = {(p["name"], p["version"], p.get("source")): p.get("checksum")
              for p in packages}
    if len(result) != len(packages):
        raise ValueError("duplicate dependency identity in lock")
    return result


def check(root_path, toy_path):
    root_packages = packages(root_path)
    toy_packages = packages(toy_path)
    root, toy = set(root_packages), set(toy_packages)
    local_toy = ("cvld-toy", "0.0.0", None)
    original_door = {p for p in root if p[0] == "cvld" and p[2] is None}
    if len(original_door) != 1 or not original_door <= toy:
        raise ValueError("toy must retain the original local door identity")
    if local_toy not in toy:
        raise ValueError("expected exact local toy root identity")
    if toy_packages[local_toy] is not None:
        raise ValueError("local toy root must not have a registry checksum")
    # Cargo can prune the root's unused dev/browser dependencies. Every package
    # the toy DOES use must keep its original version and full registry/git
    # source (including revision), with only this new local root excepted.
    if not toy - {local_toy} <= root:
        raise ValueError("toy dependency differs from the original locked graph")
    if any(toy_packages[p] != root_packages[p] for p in toy - {local_toy}):
        raise ValueError("toy dependency checksum differs from the original lock")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root_lock")
    parser.add_argument("toy_lock")
    args = parser.parse_args()
    check(args.root_lock, args.toy_lock)
