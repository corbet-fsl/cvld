#!/usr/bin/env python3
"""Temporary native Tor Records components and Wasm compilation, never live Tor."""
from __future__ import annotations

from collections import Counter
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
from types import SimpleNamespace

HELPERS_SHA256 = "86da5ecd1eb81f11ead3ed3f300239c31eddb8937049e7bcff50cc1039af89cb"
RECORDS_URL = "https://github.com/corbet-foss/cdht"
MESH_URL = "https://github.com/corbet-libs/cmsh"
TOR_URL = "https://github.com/corbet-foss/ctrn"
FERRY_URL = "https://github.com/corbet-foss/cfry"
CANDIDATES = {
    RECORDS_URL: "c1cd8d6e21bd74cafdb0e8f16aea493bc0e2c684",
    MESH_URL: "5a0fad0e23da316bbd2c2c1c0b52687e8a5a8d0d",
    TOR_URL: "18820fbdf669ebbe42302629164dda40cb8afb6b",
    "https://github.com/corbet-foss/ckmg": "3bbddd1118b42c573111d2eff6ac02798af929a7",
}
# The remaining 35 manifest entries, including exact Ferry, are preserved from
# the reviewed 39-source Records bundle 96a10654...; canonical JSON, URL order.
PRESERVED_ENTRIES_SHA256 = "342446bc3580b2dcdf6fcd5baec6839bf6df20177e76300a63d48c005274c139"
VEILID_SOURCE = "git+https://gitlab.com/veilid/veilid.git?branch=main#dd8e2cdd72b5bf817172ac31c20872b168c5c8fc"
WASM_TARGET = "wasm32-unknown-unknown"
ORACLE_IGNORED = {
    "rpc::encoding_tests::upstream_watch_vectors":
        "requires actual upstream oracle; mandatory conformance CI",
    "rpc::inspect::tests::upstream_inspect_vectors":
        "requires actual upstream vector generator",
}
# Each row is (source path, Rust test module prefix, positive count).
# These are source inventory expectations; only observed native results pass.
INVENTORIES = {
    "ctrn": {
        "node_info": [("tests/node_info.rs", "", 9)],
    },
    "cdht": {
        "lib": [
            ("tests/support/backend_state.rs", "backend::tests::", 1),
            ("tests/support/network_state.rs", "network::tests::", 4),
            ("tests/support/rpc_encoding.rs", "rpc::encoding_tests::", 10),
            ("tests/support/inspect.rs", "rpc::inspect::tests::", 2),
        ],
        "exact_publication": [("tests/exact_publication.rs", "", 7)],
        "envelope": [("tests/envelope.rs", "", 2)],
        "peers": [("tests/peers.rs", "", 4)],
        "watches": [("tests/watches.rs", "", 3)],
        "network": [("tests/network.rs", "", 21)],
        "records": [("tests/records.rs", "", 21)],
        "adversarial": [("tests/adversarial.rs", "", 6)],
    },
    "cmsh": {
        "lib": [
            ("tests/support/address_unit.rs", "address::tests::", 3),
            ("tests/support/error_unit.rs", "error::tests::", 1),
            ("tests/support/property_unit.rs", "property::tests::", 3),
            ("tests/support/pump.rs", "mesh::pump_tests::", 1),
        ],
        "contracts": [("tests/contracts.rs", "", 8)],
        "tor_port": [("tests/tor_port.rs", "", 1)],
    },
}


def helpers():
    path = Path(__file__).with_name("v01-records.py")
    prefix, separator, _main = path.read_bytes().partition(b"\ndef main():\n")
    if not separator or hashlib.sha256(prefix).hexdigest() != HELPERS_SHA256:
        raise RuntimeError("reviewed Records helper definitions changed")
    namespace = {"__name__": "v01_reviewed_records_helpers", "__file__": str(path)}
    exec(compile(prefix, str(path), "exec"), namespace)
    return SimpleNamespace(**namespace)


h = helpers()


def capture(command, environment):
    return subprocess.check_output(command, env=environment, text=True, timeout=30).strip()


def tool_binding(environment, evidence):
    tools = {}
    for name in ("python3", "git", "rustc", "cargo", "rustdoc", "rustfmt",
                 "cargo-clippy", "clippy-driver", "cc", "ar", "pkg-config"):
        found = shutil.which(name, path=environment["PATH"])
        h.require(found, "existing worker tool missing; installation forbidden: " + name)
        path = Path(found)
        tools[name] = {"path": str(path), "resolved_path": str(path.resolve()),
                       "sha256": h.sha256(path),
                       "version": capture([str(path), "--version"], environment)}
    h.require(tools["rustc"]["version"].startswith("rustc 1.98.1 ")
              and tools["cargo"]["version"].startswith("cargo 1.98.0 ")
              and tools["rustdoc"]["version"].startswith("rustdoc 1.98.1 ")
              and tools["rustfmt"]["version"].startswith("rustfmt 1.9.0"),
              "reviewed stable worker Rust tools required; no toolchain changes")
    environment["CC"], environment["AR"] = tools["cc"]["path"], tools["ar"]["path"]
    library = Path(capture([tools["rustc"]["path"], "--print", "target-libdir", "--target", WASM_TARGET], environment))
    files = sorted([*library.glob("libstd-*.rlib"), *library.glob("libcore-*.rlib")])
    h.require(library.is_absolute() and library.is_dir()
              and any(path.name.startswith("libstd-") for path in files)
              and any(path.name.startswith("libcore-") for path in files),
              "provisioned stable Wasm std is missing; installation forbidden")
    binding = {"tools": tools, "wasm_std": {str(path): h.sha256(path) for path in files}}
    h.save(evidence / "toolchain.json", binding)
    return binding


def unchanged_tools(binding, environment):
    for name, expected in binding["tools"].items():
        h.require(shutil.which(name, path=environment["PATH"]) == expected["path"]
                  and h.sha256(Path(expected["path"])) == expected["sha256"],
                  "worker tool changed during qualification: " + name)
    for name, digest in binding["wasm_std"].items():
        h.require(h.sha256(Path(name)) == digest, "Wasm standard library changed")


def inventory(label, directory, evidence):
    tests, ignored, source_hashes = {}, {}, {}
    pattern = re.compile(r"((?:^#\[[^\n]+\]\n)+)(?:async )?fn (\w+)\(", re.MULTILINE)
    for target, rows in INVENTORIES[label].items():
        tests[target] = []
        for name, prefix, expected_count in rows:
            source = directory / name
            positive = []
            for attributes, function in pattern.findall(source.read_text()):
                if not re.search(r"#\[(?:tokio::)?test\]|not\(target_arch = \"wasm32\"\), (?:tokio::)?test", attributes):
                    continue
                name_in_binary = prefix + function
                reason = re.search(r'#\[ignore = "([^"\n]+)"\]', attributes)
                if reason:
                    ignored[name_in_binary] = reason[1]
                else:
                    positive.append(name_in_binary)
            h.require(len(positive) == expected_count and len(set(positive)) == expected_count,
                      "source test inventory changed: " + name)
            tests[target].extend(positive)
            source_hashes[name] = h.sha256(source)
    h.require(ignored == (ORACLE_IGNORED if label == "cdht" else {}),
              "source oracle ignores differ from the exact reviewed selection")
    result = {"targets": tests, "ignored": ignored, "source_sha256": source_hashes}
    h.save(evidence / (label + "-test-inventory.json"), result)
    return result


def native_receipt(label, expected, evidence):
    text = (evidence / ("test-" + label + ".log")).read_text(errors="replace")
    passed = re.findall(r"^test (\S+) \.\.\. ok\s*$", text, re.MULTILINE)
    ignored = re.findall(r"^test (\S+) \.\.\. ignored(?:, (.*))?$", text, re.MULTILINE)
    summaries = [tuple(map(int, row)) for row in re.findall(
        r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;", text)]
    wanted = [name for names in expected["targets"].values() for name in names]
    counts = [(len(names), 0, len(expected["ignored"]) if target == "lib" else 0, 0, 0)
              for target, names in expected["targets"].items()]
    h.require(Counter(passed) == Counter(wanted) and all(len(names) > 0 for names in expected["targets"].values()),
              "actual native successes differ from every required test name")
    h.require(sorted(ignored) == sorted(expected["ignored"].items()) and Counter(summaries) == Counter(counts),
              "actual native counts or oracle ignores differ from the reviewed scope")
    result = {"passed": len(passed), "ignored": dict(ignored), "targets": expected["targets"],
              "summaries": [dict(zip(("passed", "failed", "ignored", "measured", "filtered"), row)) for row in summaries],
              "execution": "native component tests; no live Tor"}
    h.save(evidence / ("test-" + label + "-counts.json"), result)
    return result


def qualify(label, repository, features, sources, config, environment, evidence, stages, receipt, tools):
    directory = sources[repository]["root"]
    expected = inventory(label, directory, evidence)
    targets = ["--lib"] if "lib" in expected["targets"] else []
    for target in expected["targets"]:
        if target != "lib":
            targets.extend(["--test", target])
    base = ["cargo", "--config", str(config)]
    lockfile = directory / "Cargo.lock"
    if lockfile.is_file():
        shutil.copyfile(lockfile, evidence / (label + "-Cargo.lock.before"))
    metadata = evidence / (label + "-metadata.json")
    unchanged_tools(tools, environment)
    try:
        h.run("resolve-" + label, base + ["metadata", "--format-version", "1", *features],
              directory, environment, evidence, stages, stdout=metadata)
    finally:
        if lockfile.is_file():
            shutil.copyfile(lockfile, evidence / (label + "-Cargo.lock.after-resolve"))
    h.metadata_receipt(metadata, sources, evidence, label)
    resolved = json.loads(metadata.read_text())
    optimized = [package for package in resolved["packages"] if package["name"] == "veilid-core-optimized"]
    if label in ("cdht", "cmsh"):
        h.require(len(optimized) == 1 and optimized[0]["source"] == VEILID_SOURCE,
                  "actual maintained VLD0 fixture must resolve the exact reviewed upstream commit")
    else:
        veilid = [package for package in resolved["packages"]
                  if package["name"].startswith("veilid")
                  or (package.get("source") or "").startswith("git+https://gitlab.com/veilid/veilid.git")]
        h.require(label == "ctrn" and not veilid,
                  "the Tor endpoint owner must not add a Veilid dependency")
    root = next(node for node in resolved["resolve"]["nodes"] if node["id"] == resolved["resolve"]["root"])
    if label in ("ctrn", "cmsh"):
        owner_paths = (FERRY_URL,)
        if label == "cmsh":
            owner_paths = (RECORDS_URL, TOR_URL, FERRY_URL)
        for url in owner_paths:
            name = url.rsplit("/", 1)[-1]
            packages = [package for package in resolved["packages"] if package["name"] == name]
            h.require(len(packages) == 1 and packages[0]["source"] is None
                      and Path(packages[0]["manifest_path"]).resolve() == sources[url]["root"] / "Cargo.toml"
                      and any(dep["name"] == name and dep["pkg"] == packages[0]["id"] for dep in root["deps"]),
                      "wrong original owner path: " + name)
    if label == "cmsh":
        h.require({"tor", "tor-records"}.issubset(root["features"]) and "veilid" not in root["features"],
                  "Mesh must select tor-records without the native Veilid adapter")
    h.require(lockfile.is_file() and not h.manifest(lockfile).get("patch", {}).get("unused"),
              "resolved lock is missing or contains unused candidate patches")
    lock_hash = h.sha256(lockfile)
    shutil.copyfile(lockfile, evidence / (label + "-Cargo.lock"))
    receipt.setdefault("locks", {})[label] = lock_hash
    commands = [
        ("clippy-" + label, base + ["clippy", "--locked", *features, *targets, "--", "-D", "warnings"]),
        ("test-" + label, base + ["test", "--locked", *features, *targets]),
        ("wasm-check-" + label, base + ["check", "--locked", "--target", WASM_TARGET, *features, *targets]),
    ]
    if label == "cmsh":
        commands.insert(2, ("check-tor-discovery-example", base + ["check", "--locked", *features,
                                                                 "--example", "tor_discovery"]))
    for stage, command in commands:
        unchanged_tools(tools, environment)
        h.require(h.sha256(lockfile) == lock_hash, "resolved lock changed before stage")
        h.run(stage, command, directory, environment, evidence, stages)
        h.require(h.sha256(lockfile) == lock_hash, "resolved lock changed during qualification")
        if stage == "test-" + label:
            receipt.setdefault("native_tests", {})[label] = native_receipt(label, expected, evidence)
        elif stage.startswith("wasm-check-"):
            receipt.setdefault("wasm_compilation", {})[label] = {
                "targets": list(expected["targets"]), "triple": WASM_TARGET,
                "command": "cargo check --locked", "execution": False, "linked_test_binaries": False,
                "native_only_tests_not_compiled":
                    ["mesh::pump_tests::consumer_shutdown_terminates_a_real_listener_pump"]
                    if label == "cmsh" else []}
        elif stage == "check-tor-discovery-example":
            receipt["tor_discovery_example"] = {"compiled": True, "execution": False}


def main():
    h.require(os.environ.get("CI", "").lower() not in ("", "0", "false"), "CI worker required")
    h.require(os.environ.get("CI_REPO_CLONE_URL") == "https://forge.corbet.ch/corbet-libs/cvld.git",
              "private Forgejo CVLD qualifier required")
    evidence = Path(h.required("V01_EVIDENCE_DIR")).resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    h.require(not (evidence / "receipt.json").exists(), "evidence already contains a completed attempt")
    stages = []
    receipt = {"qualification": "selected original Tor Records native components and Wasm compilation",
               "status": "started", "stages": stages, "helper_prefix_sha256": HELPERS_SHA256,
               "not_claimed": ["public Tor", "Snowflake connectivity", "nine-onion private fixture execution",
                   "upstream Veilid generated-vector conformance", "browser test execution",
                   "CVLT CompoundRecords composition", "production authority bootstrap",
                   "cmsg v0.1 A or B acceptance", "full suites or coverage", "main freshness"]}
    try:
        cache = Path(h.required("CARGO_TARGET_DIR")).resolve()
        cache.mkdir(parents=True, exist_ok=True)
        h.require(Path(h.required("CARGO_HOME")).is_dir(), "existing Cargo cache required")
        scratch = Path(h.required("RUNNER_TEMP")).resolve()
        h.require(scratch.is_dir(), "existing protected job scratch required")
        environment = os.environ.copy()
        environment.update(CARGO_BUILD_JOBS="2", RUST_TEST_THREADS="2", CARGO_TERM_COLOR="never",
                           CARGO_PROFILE_DEV_DEBUG="0", CARGO_PROFILE_TEST_DEBUG="0",
                           CARGO_NET_GIT_FETCH_WITH_CLI="true", CARGO_HTTP_USER_AGENT="component-ci/1.0",
                           GIT_TERMINAL_PROMPT="0", GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
                           PYTHONDONTWRITEBYTECODE="1")
        for key in tuple(environment):
            if key.startswith(("GH_", "GITHUB_", "GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_")):
                environment.pop(key)
        environment.pop("GIT_CONFIG_COUNT", None)
        with (cache.parent / ".v01-tor-records.lock").open("a") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise h.Refused("another qualification holds the dedicated target output") from error
            with tempfile.TemporaryDirectory(prefix="v01-tor-records-", dir=scratch) as temporary:
                work = Path(temporary)
                settings = [("credential.helper", "")]
                for org in h.FIRST_PARTY:
                    settings.append((f"url.file://{work}/unstaged/{org}/.insteadOf", f"https://github.com/{org}/"))
                environment["GIT_CONFIG_COUNT"] = str(len(settings))
                for index, (key, value) in enumerate(settings):
                    environment[f"GIT_CONFIG_KEY_{index}"] = key
                    environment[f"GIT_CONFIG_VALUE_{index}"] = value
                tools = tool_binding(environment, evidence)
                receipt["toolchain"] = tools
                bundle = Path(h.required("V01_SOURCE_BUNDLE")).resolve()
                h.checked_file(bundle, h.required("V01_SOURCE_BUNDLE_SHA256"))
                h.extract(bundle, work / "bundle", [h.MAX_OUTER_BYTES, h.MAX_FILES])
                bundle_manifest = work / "bundle/manifest.json"
                h.require(bundle_manifest.is_file() and bundle_manifest.stat().st_size <= h.MAX_MANIFEST_BYTES,
                          "missing or oversized source-bundle manifest")
                specification = json.loads(bundle_manifest.read_text())
                shutil.copyfile(bundle_manifest, evidence / "source-manifest.json")
                offered = specification.get("sources")
                h.require(isinstance(offered, list) and len(offered) == 39
                          and all(isinstance(entry, dict) for entry in offered), "exact 39-source bundle required")
                preserved = sorted([entry for entry in offered if entry.get("url") not in CANDIDATES], key=lambda entry: entry["url"])
                digest = hashlib.sha256(json.dumps(preserved, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
                h.require(len(preserved) == 35 and digest == PRESERVED_ENTRIES_SHA256,
                          "the other 35 reviewed source entries must remain exact, including Ferry")
                root_archive = Path(h.required("V01_ROOT_SOURCE_ARCHIVE")).resolve()
                root_commit = h.required("V01_ROOT_SOURCE_COMMIT")
                h.require(root_commit == os.environ["CI_COMMIT_SHA"], "workflow/root source commit mismatch")
                entries = [(dict(url=h.ROOT_URL, commit=root_commit, sha256=h.required("V01_ROOT_SOURCE_SHA256"),
                    packages=[{"manifest": "Cargo.toml", "name": "cvld"}]), root_archive)]
                for entry in offered:
                    entries.append((entry, work / "bundle" / h.relative(entry.get("archive"))))
                sources, budget = {}, [h.MAX_SOURCE_BYTES, h.MAX_FILES]
                source_parent = work / "sources"
                source_parent.mkdir()
                for entry, archive in entries:
                    repository = h.url(entry.get("url"))
                    h.require(repository not in sources, "duplicate source URL")
                    h.checked_file(archive, entry.get("sha256"))
                    h.git_archive_commit(archive, entry.get("commit"), environment)
                    if repository in CANDIDATES:
                        h.require(entry["commit"] == CANDIDATES[repository], "unexpected component candidate: " + repository)
                    location = source_parent / repository.rsplit("/", 1)[-1]
                    h.extract(archive, location, budget)
                    packages, skipped = h.selected_packages(location, entry.get("packages"))
                    sources[repository] = {"root": location, "packages": packages}
                    receipt.setdefault("sources", []).append({"url": repository, "commit": entry["commit"],
                        "archive_sha256": entry["sha256"],
                        "packages": {name: str(path.relative_to(location)) for name, path in packages.items()},
                        "skipped_nonprimary_packages": skipped})
                h.require(all(repository in sources for repository in CANDIDATES), "all four exact candidates required")
                root = sources[h.ROOT_URL]["root"]
                for name in ("v01-tor-records.py", "v01-records.py"):
                    h.require(h.sha256(root / ".ci" / name) == h.sha256(Path(__file__).with_name(name)),
                              "executed harness/helper differs from root source archive")
                external = set()
                for source in sources.values():
                    for file in source["root"].rglob("Cargo.toml"):
                        for dependency in h.git_edges(h.manifest(file)):
                            if h.is_first_party(dependency):
                                h.require(h.url(dependency) in sources, "unmapped first-party manifest dependency")
                            else:
                                external.add(dependency)
                receipt["external_git_sources"] = sorted(external)
                receipt["source_bundle_sha256"] = h.required("V01_SOURCE_BUNDLE_SHA256")
                receipt["preserved_entries_sha256"] = digest
                receipt["manifest_edits"] = h.rewrite_manifests(sources, evidence)
                for source in sources.values():
                    for file in source["root"].rglob("Cargo.toml"):
                        h.require(not any(h.is_first_party(edge) for edge in h.git_edges(h.manifest(file))),
                                  "first-party Git dependency survived exact path composition")
                h.save(evidence / "source-receipt.json", receipt)
                config = work / ".cargo/config.toml"
                config.parent.mkdir()
                config.write_text("# Exact candidate paths are recorded in the disposable manifests.\n")
                shutil.copyfile(config, evidence / "candidate-cargo-config.toml")
                formats = specification.get("format_urls")
                h.require(isinstance(formats, list) and len(formats) == 2
                          and {h.url(value) for value in formats} == {RECORDS_URL, MESH_URL},
                          "format_urls must select exactly CDHT and CMSH")
                for repository in sorted((RECORDS_URL, MESH_URL, TOR_URL)):
                    name = repository.rsplit("/", 1)[-1]
                    unchanged_tools(tools, environment)
                    h.run("fmt-" + name, ["cargo", "fmt", "--package", name, "--check"],
                          sources[repository]["root"], environment, evidence, stages)
                qualify("ctrn", TOR_URL, [], sources, config, environment, evidence, stages, receipt, tools)
                qualify("cdht", RECORDS_URL, [], sources, config, environment, evidence, stages, receipt, tools)
                qualify("cmsh", MESH_URL, ["--features", "tor-records"], sources, config,
                        environment, evidence, stages, receipt, tools)
                unchanged_tools(tools, environment)
                receipt["status"] = "passed-selected-native-components-and-wasm-compilation"
                receipt["scope"] = "9 CTRN endpoint tests, 81 CDHT tests, two exact oracle ignores, 17 Mesh tests; selected Wasm check (native-only pump test excluded) and native discovery example check only"
    except BaseException as error:
        receipt["status"] = "failed"
        receipt["failure"] = f"{type(error).__name__}: {error}"
        print("qualification failed; inspect receipt.json and retained stage logs", file=sys.stderr)
        return 1
    finally:
        h.save(evidence / "receipt.json", receipt)
        h.save(evidence / "SHA256SUMS.json", {path.relative_to(evidence).as_posix(): h.sha256(path)
            for path in sorted(evidence.rglob("*")) if path.is_file() and path.name != "SHA256SUMS.json"})
    print("selected native components and Wasm compilation passed; live Tor remains unexecuted", flush=True)
    return 0


if __name__ == "__main__":
    def interrupted(_signal, _frame):
        raise h.Refused("bounded Tor Records component qualification interrupted")
    signal.signal(signal.SIGTERM, interrupted)
    sys.exit(main())
