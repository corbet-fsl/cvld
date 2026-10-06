#!/usr/bin/env python3
"""Exact original nine-onion Records fixture on retained tools; no provisioning."""
from __future__ import annotations

import difflib
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import select
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
from types import SimpleNamespace

COMPONENT_PREFIX_SHA256 = "96847774469b86d0836a8b1c80a65fd0b542a210295d3298bcd10f63462a7493"
RECORDS_COMMIT = "c1cd8d6e21bd74cafdb0e8f16aea493bc0e2c684"
CHUTNEY_SHA256 = "3d8748142f5d1fc3243371b33ff5a431d444c69b836d22718898f1787eec00ee"
CHUTNEY_COMMIT = "6cc158868d722e652975cb4efd5b278d95ff2fbb"
FIXTURE_SHA256 = "050e6bdb3248a14b2ca5bff51c19d8eb5472b79e5dd4ef8565ef37938039d932"
TOOL_ROOT = Path("/workspaces/component-tools/cmsg")
TOOL_SUFFIX = "20a55ac8159811bbac7c8370ae7f28fc075f2153"
TOOL_RECEIPT = Path("/workspaces/component-releases/cmsg") / TOOL_SUFFIX / "tor-tools/tools.json"
TOOL_RECEIPT_SHA256 = "b3a64bbc373b886dc164e859c1d26e7a4055a7d65b8c2556a0bd2cff4ac152e0"
LIVE_TOOLS = {
    "tor": (TOOL_ROOT / ("tor-0.4.9.12-" + TOOL_SUFFIX) / "bin/tor",
            "3b03c797db84b76bcde96f68997656cc42368b173c0da88b40d5acc2d666cc1b"),
    "tor-gencert": (TOOL_ROOT / ("tor-0.4.9.12-" + TOOL_SUFFIX) / "bin/tor-gencert",
                    "68df7a29ae0bed669df63b4c8d8658240cb951618860623212fdbd8993923114"),
    "python": (TOOL_ROOT / ("python-" + TOOL_SUFFIX) / "bin/python",
               "f5cce9ecc914b0c2eee78056c1c816aa02ae4c73c0aaf958eb5e0bb9281f34ea"),
}
EXAMPLE_FILES = {
    "examples/tor_discovery.rs": "3df7e80e137778472b524a7f1c0d8789e166de0e998fd38175543b40325bccbf",
    "tests/support/tor_discovery/main.rs": "3182d2b9c90273d4a02ad4349cacf0369d9404da89736992ba9d134dd322701d",
    "tests/support/tor_discovery/crypto.rs": "5da658d96d59710fc0a52a656f6da2f845946803c4430098e745e2c182aa74de",
}
ORIGINAL_START_ASSERTION = "    node.start().await.unwrap();\n"
DIAGNOSTIC_START_ASSERTION = ('    let started = node.start().await;\n'
                            '    if let Err(error) = &started {\n'
                            '        eprintln!("private Tor participant {index} startup failed: {error}");\n'
                            '    }\n'
                            '    started.unwrap();\n')
SUCCESS = ("original ENV0/PeerInfo/FindNode and encrypted Get/Set/Watch over nine independent onion services passed; "
           "bootstrap storage absent; dynamic routing loss verified")
OLD_CHECK = ('if subprocess.check_output(["git","-C",str(source),"rev-parse","HEAD"],text=True).strip()!=CHUTNEY_REVISION:\n'
             '    raise RuntimeError("unexpected Chutney revision")\n')
NEW_CHECK = ('from runpy import run_path as _v01_provenance\n'
             '_v01_provenance(os.environ["V01_TOR_LIVE_HARNESS"], run_name="v01_provenance")["verify_chutney_tree"]'
             '(source, Path(os.environ["V01_CHUTNEY_ARCHIVE"]))\n')
OLD_START = '        network.start(launch_phase=1)\n'
NEW_START = ('        try:\n'
             '            network.start(launch_phase=1)\n'
             '        except BaseException:\n'
             '            try:\n'
             '                save_node_diagnostics(network, artifact, "start-failed")\n'
             '            except Exception as diagnostic_error:\n'
             '                print("startup diagnostics failed: " + type(diagnostic_error).__name__, file=sys.stderr)\n'
             '            raise\n')
FIXTURE_SECONDS = 3600
MAX_FIXTURE_LOG = 16 * 1024 * 1024
MAX_FIXTURE_ARTIFACTS = 8 * 1024 * 1024


def components():
    path = Path(__file__).with_name("v01-tor-records.py")
    prefix, separator, _main = path.read_bytes().partition(b"\ndef main():\n")
    if not separator or hashlib.sha256(prefix).hexdigest() != COMPONENT_PREFIX_SHA256:
        raise RuntimeError("reviewed Tor Records component helper definitions changed")
    namespace = {"__name__": "v01_reviewed_components", "__file__": str(path)}
    exec(compile(prefix, str(path), "exec"), namespace)
    return SimpleNamespace(**namespace)


c = components()
h = c.h


def chutney_members(archive):
    h.checked_file(archive, CHUTNEY_SHA256)
    h.require(archive.stat().st_size == 563200, "original Chutney archive size changed")
    h.git_archive_commit(archive, CHUTNEY_COMMIT, os.environ.copy())
    result = {}
    with tarfile.open(archive, mode="r:") as source:
        h.require(source.pax_headers.get("comment") == CHUTNEY_COMMIT, "Chutney PAX commit mismatch")
        for member in source:
            path = h.relative(member.name)
            h.require(path not in result and len(result) < 112 and 0 <= member.size <= 1024 * 1024,
                      "unexpected Chutney member bounds")
            h.require(not member.sparse and not any("sparse" in key.lower() for key in member.pax_headers),
                      "sparse Chutney entry refused")
            entry = {"mode": member.mode}
            if member.isfile():
                data = source.extractfile(member).read()
                h.require(len(data) == member.size, "truncated Chutney source")
                entry.update(kind="file", data=data, sha256=hashlib.sha256(data).hexdigest())
            elif member.isdir():
                h.require(member.size == 0, "nonempty Chutney directory entry")
                entry.update(kind="directory")
            else:
                h.require(member.issym() and member.size == 0, "special Chutney entry refused")
                # All six maintained links have canonical relative targets and
                # no '..'. Require their actual target to be an original entry.
                target = h.relative(member.linkname)
                entry.update(kind="symlink", target=str(target), destination=str(path.parent / target))
            result[path] = entry
    h.require({kind: sum(row["kind"] == kind for row in result.values())
               for kind in ("file", "directory", "symlink")} == {"file": 88, "directory": 18, "symlink": 6},
              "original Chutney inventory changed")
    for path, entry in result.items():
        h.require(all(parent not in result or result[parent]["kind"] == "directory" for parent in path.parents),
                  "Chutney file or link is an archive parent")
        if entry["kind"] == "symlink":
            destination = PurePosixPath(entry["destination"])
            h.require(destination in result and result[destination]["kind"] in ("file", "directory"),
                      "Chutney link target is not an original file/directory")
    return result


def verify_chutney_tree(source, archive):
    source = Path(source).resolve()
    members = chutney_members(Path(archive))
    h.require(source.is_dir() and not (source / ".git").exists(), "fresh archive-only Chutney source required")
    observed = {PurePosixPath(path.relative_to(source).as_posix()) for path in source.rglob("*")}
    h.require(observed == set(members), "Chutney source contains missing or extra paths, including bytecode")
    for name, entry in members.items():
        path = source.joinpath(*name.parts)
        h.require(path.resolve().is_relative_to(source), "Chutney path escaped the private source root")
        if entry["kind"] == "symlink":
            h.require(path.is_symlink() and os.readlink(path) == entry["target"], "Chutney link changed")
        elif entry["kind"] == "directory":
            h.require(path.is_dir() and not path.is_symlink(), "Chutney directory changed")
        else:
            h.require(path.is_file() and not path.is_symlink() and h.sha256(path) == entry["sha256"]
                      and path.stat().st_mode & 0o111 == entry["mode"] & 0o111, "Chutney source file changed")
    result = {"archive_sha256": CHUTNEY_SHA256, "commit": CHUTNEY_COMMIT,
              "members": 112, "files": 88, "directories": 18, "symlinks": 6,
              "all_original_bytes_and_link_targets_verified": True, "extra_paths": 0,
              "fresh_private_source": str(source), "verification_pid": os.getpid()}
    if os.environ.get("V01_CHUTNEY_TREE_RECEIPT"):
        h.save(Path(os.environ["V01_CHUTNEY_TREE_RECEIPT"]), result)
    return result


def stage_chutney(archive, destination):
    members = chutney_members(archive)
    h.require(not destination.exists(), "Chutney scratch already exists")
    destination.mkdir(mode=0o700)
    for name, entry in members.items():
        path = destination.joinpath(*name.parts)
        if entry["kind"] == "directory":
            path.mkdir(parents=True, exist_ok=True)
        elif entry["kind"] == "file":
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("xb") as stream:
                stream.write(entry["data"])
            path.chmod(0o755 if entry["mode"] & 0o111 else 0o644)
    for name, entry in members.items():
        if entry["kind"] == "symlink":
            destination.joinpath(*name.parts).symlink_to(entry["target"])
    return verify_chutney_tree(destination, archive)


def live_tool_binding(evidence):
    h.checked_file(TOOL_RECEIPT, TOOL_RECEIPT_SHA256)
    original = json.loads(TOOL_RECEIPT.read_text())
    h.require(original["torBin"] == str(LIVE_TOOLS["tor"][0])
              and original["torGencert"] == str(LIVE_TOOLS["tor-gencert"][0])
              and original["python"] == str(LIVE_TOOLS["python"][0])
              and original["chutneySourceSha256"] == CHUTNEY_SHA256,
              "retained original tool receipt differs")
    tools = {}
    for name, (path, digest) in LIVE_TOOLS.items():
        h.require(path.is_file() and os.access(path, os.X_OK) and h.sha256(path) == digest,
                  "existing qualified tool is missing or changed; provisioning forbidden: " + name)
        tools[name] = {"path": str(path), "resolved_path": str(path.resolve()), "sha256": digest}
    shutil.copyfile(TOOL_RECEIPT, evidence / "original-tools.json")
    h.save(evidence / "live-tools.json", tools)
    return tools


def compile_probe(sources, config, environment, evidence, stages, receipt, tools):
    directory = sources[c.MESH_URL]["root"]
    for name, digest in EXAMPLE_FILES.items():
        h.require(h.sha256(directory / name) == digest, "original nine-onion fixture source changed")
    h.save(evidence / "original-fixture-source-hashes.json", EXAMPLE_FILES)
    fixture = (directory / "tests/support/tor_discovery/main.rs").read_text()
    h.require(fixture.count(DIAGNOSTIC_START_ASSERTION) == 1 and ORIGINAL_START_ASSERTION not in fixture,
              "exact bounded startup diagnostic required")
    original = fixture.replace(DIAGNOSTIC_START_ASSERTION, ORIGINAL_START_ASSERTION)
    original_hash = hashlib.sha256(original.encode()).hexdigest()
    h.require(original_hash == "5a7237d53d86b3ecf5c6c65a2587269db47d3c3a5610249768e5c4171081f766",
              "fixture changed beyond bounded startup error reporting")
    receipt["probe_diagnostic"] = {"original_main_sha256": original_hash,
        "compiled_main_sha256": EXAMPLE_FILES["tests/support/tor_discovery/main.rs"],
        "only_change": "report actual static CTRN error and synthetic participant index before the same unwrap"}
    metadata = evidence / "cmsh-metadata.json"
    lockfile = directory / "Cargo.lock"
    if lockfile.is_file():
        shutil.copyfile(lockfile, evidence / "cmsh-Cargo.lock.before")
    base = ["cargo", "--config", str(config)]
    features = ["--features", "tor-records"]
    c.unchanged_tools(tools, environment)
    try:
        h.run("resolve-cmsh", base + ["metadata", "--format-version", "1", *features],
              directory, environment, evidence, stages, stdout=metadata)
    finally:
        if lockfile.is_file():
            shutil.copyfile(lockfile, evidence / "cmsh-Cargo.lock.after-resolve")
    h.metadata_receipt(metadata, sources, evidence, "cmsh")
    resolved = json.loads(metadata.read_text())
    root = next(node for node in resolved["resolve"]["nodes"] if node["id"] == resolved["resolve"]["root"])
    h.require({"tor", "tor-records"}.issubset(root["features"]) and "veilid" not in root["features"],
              "original Mesh Tor Records feature graph required")
    for url in (c.RECORDS_URL, c.TOR_URL, c.FERRY_URL):
        name = url.rsplit("/", 1)[-1]
        packages = [package for package in resolved["packages"] if package["name"] == name]
        h.require(len(packages) == 1 and packages[0]["source"] is None
                  and Path(packages[0]["manifest_path"]).resolve() == sources[url]["root"] / "Cargo.toml"
                  and any(dep["name"] == name and dep["pkg"] == packages[0]["id"] for dep in root["deps"]),
                  "wrong original component path: " + name)
    optimized = [package for package in resolved["packages"] if package["name"] == "veilid-core-optimized"]
    h.require(len(optimized) == 1 and optimized[0]["source"] == c.VEILID_SOURCE,
              "exact original VLD0 crypto fixture commit required")
    h.require(lockfile.is_file() and not h.manifest(lockfile).get("patch", {}).get("unused"),
              "resolved lock missing or contains unused candidate patches")
    digest = h.sha256(lockfile)
    shutil.copyfile(lockfile, evidence / "cmsh-Cargo.lock")
    receipt["resolved_lock_sha256"] = digest
    h.run("build-nine-onion-example", base + ["build", "--locked", *features,
          "--example", "tor_discovery", "--message-format=json"], directory, environment, evidence, stages)
    h.require(h.sha256(lockfile) == digest, "resolved lock changed during probe build")
    c.unchanged_tools(tools, environment)
    artifacts = []
    for line in (evidence / "build-nine-onion-example.log").read_text().splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if (item.get("reason") == "compiler-artifact" and item.get("target", {}).get("name") == "tor_discovery"
                and item["target"]["kind"] == ["example"] and not item["profile"]["test"] and item.get("executable")):
            artifacts.append(Path(item["executable"]))
    h.require(len(artifacts) == 1, "one actual native example binary required")
    probe = artifacts[0].resolve()
    h.require(probe.is_file() and os.access(probe, os.X_OK)
              and probe.is_relative_to(Path(environment["CARGO_TARGET_DIR"]).resolve()),
              "probe binary escaped dedicated target output")
    receipt["probe"] = {"path": str(probe), "sha256": h.sha256(probe), "example": "tor_discovery",
                        "features": ["tor-records"], "source_hashes": EXAMPLE_FILES}
    return probe, lockfile, digest


class OwnedTor:
    """Pidfds for this fixture's detached C Tor children, never process names."""
    def __init__(self, temporary):
        h.require(hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal"),
                  "existing Python/kernel pidfd support required")
        # Refuse before starting the original fixture if the running kernel
        # cannot provide process-identity handles.
        os.close(os.pidfd_open(os.getpid()))
        self.temporary, self.controller = temporary.resolve(), None
        self.held = {}

    @staticmethod
    def exited(fd):
        return bool(select.select([fd], [], [], 0)[0])

    def observe(self):
        # Original Network.init creates tor/nodes.<timestamp>/<node>/pid.
        # Match the real directory, never the sibling `nodes` symlink.
        files = list(self.temporary.glob("ctrn-private-tor-*/tor/nodes.*/*/pid"))
        h.require(len(files) <= 27, "unexpected C Tor fixture population")
        for path in files:
            h.require(not path.is_symlink() and path.resolve().is_relative_to(self.temporary), "unsafe fixture pidfile")
            try:
                raw = path.read_bytes()
            except FileNotFoundError:
                continue  # Original cleanup removes exited nodes' pidfiles.
            if not raw.strip():
                continue
            h.require(len(raw) < 32 and raw.strip().isdigit(), "invalid fixture pidfile")
            pid = int(raw)
            if pid in self.held:
                continue
            try:
                fd = os.pidfd_open(pid)
            except ProcessLookupError:
                continue
            try:
                if self.exited(fd):
                    continue
                process = Path("/proc") / str(pid)
                executable = (process / "exe").resolve(strict=True)
                # The original double-fork launcher writes its PID before
                # execvpe. Observe again after exec; do not signal an unbound PID.
                if executable != LIVE_TOOLS["tor"][0].resolve():
                    continue
                args = (process / "cmdline").read_bytes().rstrip(b"\0").split(b"\0")
                h.require(len(args) == 3 and args[1] == b"-f", "unexpected owned Tor invocation")
                config = Path(os.fsdecode(args[2])).resolve()
                h.require(config.parent == path.parent.resolve() and config.is_relative_to(self.temporary)
                          and config.name == "torrc", "pidfile does not identify this fixture's Tor")
                h.require(config.stat().st_size <= 65536
                          and re.findall(r"(?m)^__OwningControllerProcess\s+(\d+)\s*$", config.read_text()) == [str(self.controller)],
                          "Tor controller binding is not this fixture process")
                if self.exited(fd):
                    continue
                self.held[pid] = {"fd": fd, "config": str(config.relative_to(self.temporary))}
                fd = None
                h.require(len(self.held) <= 27, "detached Tor process count exceeded original fixture")
            except FileNotFoundError:
                if not self.exited(fd):
                    raise
            finally:
                if fd is not None:
                    os.close(fd)

    def alive(self):
        return {pid: row for pid, row in self.held.items() if not self.exited(row["fd"])}

    def cleanup(self):
        escalated = []
        for sig, wait in ((signal.SIGTERM, 5), (signal.SIGKILL, 5)):
            remaining = self.alive()
            for pid, row in remaining.items():
                try:
                    signal.pidfd_send_signal(row["fd"], sig)
                    escalated.append({"pid": pid, "signal": int(sig)})
                except ProcessLookupError:
                    pass
            deadline = time.monotonic() + wait
            while self.alive() and time.monotonic() < deadline:
                time.sleep(0.1)
        survivors = list(self.alive())
        result = {"observed_original_c_tor_nodes": len(self.held), "survivors": survivors,
                  "fallback_signals": escalated,
                  "ownership": "exact owned pidfile, original executable, private torrc and controller PID; pidfd signals"}
        return result

    def close(self):
        for row in self.held.values():
            os.close(row["fd"])


def fixture_budget(log, artifacts):
    h.require(not log.exists() or log.stat().st_size <= MAX_FIXTURE_LOG, "fixture log exceeded capture bound")
    total = 0
    for path in artifacts.iterdir():
        h.require(path.is_file() and not path.is_symlink(), "unexpected fixture artifact entry")
        name = path.name
        h.require(name in ("listener-ports.json", "node-status-started.json", "node-status-start-failed.json", "shared-random-readiness.json",
                           "consensus-microdesc-readiness.txt", "consensus-microdesc-start.txt", "contract.txt")
                  or re.fullmatch(r"test\d{3}[arec]-(tor\.stdout|tor\.stderr|notice\.log|info\.log)", name),
                  "unexpected fixture artifact; private state must not be retained")
        total += path.stat().st_size
    h.require(total <= MAX_FIXTURE_ARTIFACTS, "fixture artifacts exceeded capture bound")


def execute_fixture(command, work, environment, temporary, artifacts, evidence, stages):
    log = evidence / "private-nine-onion.log"
    started, status, cleanup = time.monotonic(), 1, None
    failure, child, cancellation = None, None, False
    owned = OwnedTor(temporary)

    def cancelled(_signal, _frame):
        # Keep launch/ownership registration atomic with respect to our own
        # cancellation handling. A signal during Popen is acted on immediately
        # after its child handle has been registered for cleanup.
        nonlocal cancellation
        cancellation = True

    previous = {sig: signal.signal(sig, cancelled) for sig in (signal.SIGTERM, signal.SIGINT)}
    try:
        with log.open("wb") as output:
            h.require(not cancellation, "private Tor qualification cancelled before launch")
            child = subprocess.Popen(command, cwd=work, env=environment,
                stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
            owned.controller = child.pid
            while child.poll() is None:
                h.require(not cancellation, "private Tor qualification cancelled")
                owned.observe()
                fixture_budget(log, artifacts)
                h.require(time.monotonic() - started < FIXTURE_SECONDS, "private Tor fixture deadline exceeded")
                time.sleep(0.2)
            status = child.returncode
            h.require(not cancellation, "private Tor qualification cancelled")
            owned.observe()
            fixture_budget(log, artifacts)
    except BaseException as error:
        failure = error
    finally:
        for sig in previous:
            signal.signal(sig, signal.SIG_IGN)
        if child is not None:
            # Let original network.stop complete its full three 15-second rounds.
            # Detached C Tor is separately tracked; the process group also owns
            # the original Rust probe and any non-detached helper subprocesses.
            try:
                os.killpg(child.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            except OSError as error:
                failure = failure or error
            deadline = time.monotonic() + 65
            while child.poll() is None and time.monotonic() < deadline:
                try:
                    owned.observe()
                except Exception as error:
                    failure = failure or error
                time.sleep(0.2)
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except OSError as error:
                failure = failure or error
            try:
                child.wait(timeout=10)
            except Exception as error:
                failure = failure or error
        try:
            cleanup = owned.cleanup()
        except Exception as error:
            failure = failure or error
            cleanup = {"failed": type(error).__name__, "observed_original_c_tor_nodes": len(owned.held)}
        finally:
            owned.close()
            for sig, handler in previous.items():
                signal.signal(sig, handler)
            stages.append({"name": "private-nine-onion", "command": command, "exit_code": status,
                           "elapsed_seconds": round(time.monotonic() - started, 3),
                           "fixture_timeout_seconds": FIXTURE_SECONDS, "original_cleanup_grace_seconds": 65})
            h.save(evidence / "private-tor-cleanup.json", cleanup)
            h.save(evidence / "stages.json", stages)
    if failure is not None:
        raise failure
    h.require(status == 0 and cleanup["observed_original_c_tor_nodes"] == 27 and not cleanup["survivors"]
              and not cleanup["fallback_signals"], "original fixture or its original complete cleanup failed")
    return cleanup


def live_contract(sources, config, environment, evidence, stages, receipt, work, tools):
    receipt["live_tools"] = live_tool_binding(evidence)
    archive = Path(h.required("V01_CHUTNEY_ARCHIVE")).resolve()
    source = work / "chutney"
    receipt["chutney"] = stage_chutney(archive, source)
    shutil.copyfile(archive, evidence / "chutney-original.tar")
    probe, lockfile, lock_hash = compile_probe(sources, config, environment, evidence, stages, receipt, tools)
    original_path = sources[c.TOR_URL]["root"] / ".ci/private-network.py"
    h.require(h.sha256(original_path) == FIXTURE_SHA256, "original CTRN fixture script changed")
    original = original_path.read_text()
    h.require(original.count(OLD_CHECK) == 1 and NEW_CHECK not in original, "original provenance check is not unique")
    h.require(original.count(OLD_START) == 1 and NEW_START not in original, "original startup call is not unique")
    patched = original.replace(OLD_CHECK, NEW_CHECK).replace(OLD_START, NEW_START)
    h.require(patched.replace(NEW_START, OLD_START).replace(NEW_CHECK, OLD_CHECK) == original,
              "fixture patch changed more than provenance and startup-failure diagnostics")
    script = work / "private-network.py"
    script.write_text(patched)
    shutil.copyfile(original_path, evidence / "private-network.original.py")
    shutil.copyfile(script, evidence / "private-network.task.py")
    (evidence / "private-network-provenance.diff").write_text("".join(difflib.unified_diff(
        original.splitlines(keepends=True), patched.splitlines(keepends=True),
        fromfile="original/private-network.py", tofile="task/private-network.py")))
    receipt["fixture_patch"] = {"original_sha256": FIXTURE_SHA256, "task_sha256": h.sha256(script),
                                "changes": ["replace exact Git checkout test with exact original archive/tree verification",
                                            "retain original bounded node diagnostics on startup failure, then re-raise"]}
    artifacts = evidence / "private-tor"
    artifacts.mkdir()
    runtime = environment.copy()
    for name in tuple(runtime):
        if name.startswith(("TOR_", "CHUTNEY_")) or name in ("PYTHONPATH", "PYTHONHOME"):
            runtime.pop(name)
    runtime.update(TOR_BIN=str(LIVE_TOOLS["tor"][0]), TOR_GENCERT_BIN=str(LIVE_TOOLS["tor-gencert"][0]),
        TOR_PROBE_BIN=str(probe), TOR_ARTIFACT=str(artifacts), CHUTNEY_SOURCE=str(source),
        PYTHONDONTWRITEBYTECODE="1", PYTHONNOUSERSITE="1",
        V01_TOR_LIVE_HARNESS=str(Path(__file__).resolve()), V01_CHUTNEY_ARCHIVE=str(archive),
        V01_CHUTNEY_TREE_RECEIPT=str(evidence / "chutney-runtime-tree.json"))
    h.require("TOR_BROWSER_DRIVER" not in runtime and "TOR_GATEWAY_BIN" not in runtime
              and "TOR_JS_GATEWAY_ALLOW_LOCAL_TARGETS" not in runtime, "old gateway selector survived isolation")
    h.run("retained-tor-version", [str(LIVE_TOOLS["tor"][0]), "--version"], work, runtime, evidence, stages)
    h.run("retained-python-version", [str(LIVE_TOOLS["python"][0]), "--version"], work, runtime, evidence, stages)
    c.unchanged_tools(tools, environment)
    live_tool_binding(evidence)
    h.require(h.sha256(probe) == receipt["probe"]["sha256"] and h.sha256(lockfile) == lock_hash,
              "probe or resolved lock changed before execution")
    # Chutney keeps an original Unix control socket below each node directory.
    # Its current 10-digit timestamp suffix is 60 bytes; bound the private
    # parent below Linux's 107-byte pathname limit without changing any Tor
    # option or shared worker setting.
    with tempfile.TemporaryDirectory(prefix="v01tor-", dir="/tmp") as scratch:
        temporary = Path(scratch)
        attributes = temporary.stat()
        h.require(temporary.resolve() == temporary and len(os.fsencode(temporary)) <= 32
                  and attributes.st_mode & 0o777 == 0o700 and attributes.st_uid == os.geteuid(),
                  "short private fixture scratch must be owned, canonical and mode 0700")
        runtime["TMPDIR"] = str(temporary)
        receipt["fixture_scratch"] = {"path": str(temporary), "mode": "0700",
                                      "maximum_parent_bytes": 32, "cleanup": "after owned process cleanup"}
        cleanup = execute_fixture([str(LIVE_TOOLS["python"][0]), str(script)], work, runtime,
                                  temporary, artifacts, evidence, stages)
    live_tool_binding(evidence)
    verify_chutney_tree(source, archive)
    h.require(h.sha256(lockfile) == lock_hash and h.sha256(probe) == receipt["probe"]["sha256"],
              "probe or lock changed during live execution")
    h.require(h.sha256(script) == receipt["fixture_patch"]["task_sha256"], "task fixture changed during execution")
    h.require((artifacts / "contract.txt").read_text().splitlines().count(SUCCESS) == 1,
              "original nine-onion contract did not reach its exact success marker")
    readiness = json.loads((artifacts / "shared-random-readiness.json").read_text())
    h.require(readiness.get("ready") is True and readiness.get("synthetic") is True,
              "actual signed private consensus did not become ready")
    nodes = json.loads((artifacts / "node-status-started.json").read_text())
    h.require(len(nodes) == 27 and all(node.get("running") is True for node in nodes),
              "original private Tor population did not start")
    gate = json.loads((evidence / "chutney-runtime-tree.json").read_text())
    h.require(gate["archive_sha256"] == CHUTNEY_SHA256 and gate["all_original_bytes_and_link_targets_verified"] is True,
              "runtime did not execute the archive/tree provenance gate")
    receipt["live_contract"] = {"passed": True, "onion_participants": 9, "storage_nodes": 5,
        "bootstrap_nodes": 2, "original_assertions_unchanged": True, "success_marker": SUCCESS,
        "transport": "actual Arti onions on the original signed 27-node private Tor fixture",
        "public_network": False, "gateway": False, "chutney_runtime_gate": gate, "cleanup": cleanup}


def main():
    h.require(os.environ.get("CI", "").lower() not in ("", "0", "false"), "CI worker required")
    h.require(os.environ.get("CI_REPO_CLONE_URL") == "https://forge.corbet.ch/corbet-libs/cvld.git",
              "private Forgejo CVLD qualifier required")
    evidence = Path(h.required("V01_EVIDENCE_DIR")).resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    h.require(not (evidence / "receipt.json").exists(), "evidence already contains a completed attempt")
    stages = []
    receipt = {"qualification": "original private nine-onion Tor Records contract",
               "status": "started", "stages": stages,
               "component_prefix_sha256": COMPONENT_PREFIX_SHA256, "helper_prefix_sha256": c.HELPERS_SHA256,
               "not_claimed": ["public Tor", "Snowflake connectivity", "browser execution",
                   "CVLT CompoundRecords composition", "production authority bootstrap",
                   "cmsg v0.1 A or B acceptance", "full suites or coverage", "main freshness"]}
    try:
        h.require(c.CANDIDATES[c.RECORDS_URL] == RECORDS_COMMIT,
                  "component helper must include the reviewed range-set API repair")
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
        with (cache.parent / ".v01-tor-live.lock").open("a") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise h.Refused("another qualification holds the dedicated live target output") from error
            with tempfile.TemporaryDirectory(prefix="v01-tor-live-", dir=scratch) as temporary:
                work = Path(temporary)
                settings = [("credential.helper", "")]
                for org in h.FIRST_PARTY:
                    settings.append((f"url.file://{work}/unstaged/{org}/.insteadOf", f"https://github.com/{org}/"))
                environment["GIT_CONFIG_COUNT"] = str(len(settings))
                for index, (key, value) in enumerate(settings):
                    environment[f"GIT_CONFIG_KEY_{index}"] = key
                    environment[f"GIT_CONFIG_VALUE_{index}"] = value
                tools = c.tool_binding(environment, evidence)
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
                preserved = sorted([entry for entry in offered if entry.get("url") not in c.CANDIDATES],
                                   key=lambda entry: entry["url"])
                digest = hashlib.sha256(json.dumps(preserved, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
                h.require(len(preserved) == 35 and digest == c.PRESERVED_ENTRIES_SHA256,
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
                    if repository in c.CANDIDATES:
                        h.require(entry["commit"] == c.CANDIDATES[repository], "unexpected component candidate: " + repository)
                    location = source_parent / repository.rsplit("/", 1)[-1]
                    h.extract(archive, location, budget)
                    packages, skipped = h.selected_packages(location, entry.get("packages"))
                    sources[repository] = {"root": location, "packages": packages}
                    receipt.setdefault("sources", []).append({"url": repository, "commit": entry["commit"],
                        "archive_sha256": entry["sha256"],
                        "packages": {name: str(path.relative_to(location)) for name, path in packages.items()},
                        "skipped_nonprimary_packages": skipped})
                h.require(all(repository in sources for repository in c.CANDIDATES), "all four exact candidates required")
                root = sources[h.ROOT_URL]["root"]
                for name in ("v01-tor-live.py", "v01-tor-records.py", "v01-records.py"):
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
                          and {h.url(value) for value in formats} == {c.RECORDS_URL, c.MESH_URL},
                          "original manifest format_urls must select exactly CDHT and CMSH")
                live_contract(sources, config, environment, evidence, stages, receipt, work, tools)
                c.unchanged_tools(tools, environment)
                receipt["status"] = "passed-original-private-nine-onion-contract"
                receipt["scope"] = "actual original nine onions, five storage nodes, two bootstrap nodes on private C Tor; native only"
    except BaseException as error:
        receipt["status"] = "failed"
        receipt["failure"] = f"{type(error).__name__}: {error}"
        print("qualification failed; inspect receipt.json and retained stage logs", file=sys.stderr)
        return 1
    finally:
        h.save(evidence / "receipt.json", receipt)
        h.save(evidence / "SHA256SUMS.json", {path.relative_to(evidence).as_posix(): h.sha256(path)
            for path in sorted(evidence.rglob("*")) if path.is_file() and path.name != "SHA256SUMS.json"})
    print("original private nine-onion contract passed; public Tor and product acceptance remain outside this run", flush=True)
    return 0


if __name__ == "__main__":
    def interrupted(_signal, _frame):
        raise h.Refused("bounded private Tor qualification interrupted")
    signal.signal(signal.SIGTERM, interrupted)
    sys.exit(main())
