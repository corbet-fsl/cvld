#!/usr/bin/env python3
"""Temporary exact-candidate Keys custody execution in Chromium; no public Tor claim."""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import tomllib
from types import SimpleNamespace

HELPERS_SHA256 = "86da5ecd1eb81f11ead3ed3f300239c31eddb8937049e7bcff50cc1039af89cb"
KEYS_URL = "https://github.com/corbet-foss/ckmg"
TOR_URL = "https://github.com/corbet-foss/ctrn"
CANDIDATES = {
    KEYS_URL: "3bbddd1118b42c573111d2eff6ac02798af929a7",
    TOR_URL: "56efa3448421458c6a337b378e2a7e8593b9eb0b",
}
WASM_TARGET = "wasm32-unknown-unknown"
BROWSER_SETUP = Path("/nix/store/21z7gs8b28i9mrgcn0bkmyghv8919p4h-cmty-browser-tools/share/cmty-browser-tools/setup.sh")
BROWSER_SETUP_SHA256 = "4b4687d368b60df48b6c598b947c3a4715adcb7a1d23eca8b2e080fbb0f1866b"
BINDGEN_HASHES = {
    "WASM_BINDGEN_CLI_SHA256": "fb59da714982a04273e9e4b09a85e523e5dd04de35b1a4a8b1641785ee7a71cf",
    "WASM_BINDGEN_RUNNER_SHA256": "fc3146e83e932e0a239b58021bfd7cc804ff7d1a24b7e7509a1608a50f4f86f8",
}
C_TOOLS = {
    "clang": (Path("/nix/store/zl4n7yh8iw3apfjizvxvd525q03fldp1-clang-23.1.0-rc1/bin/clang"),
              "a353ef06a6bedd8a31fdb673161a7268ec368b702bdaa604229d8348dc3d67fb"),
    "llvm-ar": (Path("/nix/store/pzyq900c79cpa67vmvmxlhg0h6xsnjyg-llvm-23.1.0-rc1/bin/llvm-ar"),
                "ed31a4e616af4776fb618c12eee23617319bc4102be73cbead0f744b9711fbaa"),
}
COUNTS = {"browser_tor": 5, "keys": 30}


def helpers():
    # Use only the reviewed definitions from qualifier dc01ab3: a6b9e4b plus
    # the reviewed C-tool constants. Its independent Records main never executes.
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


def browser_tools(environment, lockfile, work, evidence):
    rust_tools = {name: shutil.which(name, path=environment["PATH"])
                  for name in ("rustc", "cargo", "rustdoc")}
    h.require(all(rust_tools.values()), "provisioned Rust tools are missing")
    h.require(h.sha256(BROWSER_SETUP) == BROWSER_SETUP_SHA256, "qualified browser setup changed")
    names = ["PATH", "XDG_CACHE_HOME", "FONTCONFIG_FILE", "FONTCONFIG_PATH", "BROWSER_BIN",
             "CHROME_BIN", "CHROMEDRIVER", "CMEET_BROWSER_PYTHON", "SE_OFFLINE", "SE_AVOID_STATS"]
    loader = 'source "$1"; shift; for name in "$@"; do printf "%s\\0" "${!name}"; done'
    values = subprocess.check_output(
        ["bash", "-euc", loader, "browser-setup", str(BROWSER_SETUP), *names],
        env=environment, timeout=30).decode().split("\0")[:-1]
    h.require(len(values) == len(names), "browser setup output mismatch")
    environment.update(zip(names, values))
    c_tools = {}
    for name, (path, digest) in C_TOOLS.items():
        h.require(path.is_file() and os.access(path, os.X_OK) and h.sha256(path) == digest,
                  "reviewed existing C tool is missing or changed: " + name)
        c_tools[name] = {"path": str(path), "sha256": digest,
                         "version": capture([str(path), "--version"], environment)}
    # minicov explicitly invokes clang; CC alone does not select its compiler.
    environment["PATH"] = str(C_TOOLS["clang"][0].parent) + os.pathsep + environment["PATH"]
    for name in ("AR_wasm32_unknown_unknown", "AR_wasm32-unknown-unknown"):
        environment[name] = str(C_TOOLS["llvm-ar"][0])
    h.require(all(shutil.which(name, path=environment["PATH"]) == original
                  for name, original in rust_tools.items()),
              "browser/C tool selection changed the active Rust toolchain")
    h.require(Path(shutil.which("clang", path=environment["PATH"])) == C_TOOLS["clang"][0],
              "minicov would select a different clang")
    directory = Path(h.required("WASM_BINDGEN_BIN_DIR"))
    h.require(directory.is_absolute(), "pre-existing absolute bindgen directory required")
    bindgen, runner = directory / "wasm-bindgen", directory / "wasm-bindgen-test-runner"
    for binary, variable in ((bindgen, "WASM_BINDGEN_CLI_SHA256"), (runner, "WASM_BINDGEN_RUNNER_SHA256")):
        h.require(binary.is_file() and os.access(binary, os.X_OK), "pre-existing binary missing: " + binary.name)
        h.require(h.required(variable) == BINDGEN_HASHES[variable]
                  and h.sha256(binary) == os.environ[variable], "provisioned binary hash mismatch: " + binary.name)
    packages = tomllib.loads(lockfile.read_text())["package"]
    versions = {package["version"] for package in packages if package["name"] == "wasm-bindgen"}
    h.require(len(versions) == 1, "one resolved wasm-bindgen ABI required")
    abi = versions.pop()
    h.require(capture([str(bindgen), "--version"], environment) == "wasm-bindgen " + abi,
              "retained bindgen ABI mismatch; installation is forbidden")
    runner_version = capture([str(runner), "--version"], environment)
    h.require(runner_version.split()[-1] == abi, "retained runner ABI mismatch")
    tools = {}
    for command in (["rustc", "--version"], ["cargo", "--version"], ["cargo", "clippy", "--version"],
                    ["rustfmt", "--version"], ["wasm-ld", "--version"],
                    [environment["BROWSER_BIN"], "--version"], [environment["CHROMEDRIVER"], "--version"],
                    [environment["CMEET_BROWSER_PYTHON"], "--version"]):
        tools[" ".join(command)] = capture(command, environment)
    h.require(tools["rustc --version"].startswith("rustc 1.98.1 "), "reviewed stable Rust compiler required")
    library = Path(capture(["rustc", "--print", "target-libdir", "--target", WASM_TARGET], environment))
    h.require(library.is_absolute() and any(library.glob("libstd-*.rlib"))
              and any(library.glob("libcore-*.rlib")), "provisioned stable Wasm std is missing")
    h.require(capture([environment["CMEET_BROWSER_PYTHON"], "-c", "import selenium; print(selenium.__version__)"],
                      environment) == "4.40.0", "qualified Selenium library changed")
    h.save(evidence / "toolchain.json", dict(tools, c_tools=c_tools, wasm_bindgen=abi,
           runner=runner_version, bindgen_path=str(bindgen), runner_path=str(runner),
           bindgen_sha256=h.sha256(bindgen), runner_sha256=h.sha256(runner),
           browser_setup_sha256=BROWSER_SETUP_SHA256, wasm_std=str(library)))
    return runner


def inventory(directory):
    patterns = {
        "browser_tor": r"#\[wasm_bindgen_test\]\s*async fn (\w+)\(",
        "keys": (r'#\[cfg_attr\(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test\)\]'
                 r'\s*#\[cfg_attr\(not\(target_arch = "wasm32"\), test\)\]\s*(?:async )?fn (\w+)\('),
    }
    tests = {}
    for target, expected in COUNTS.items():
        source = (directory / "tests" / (target + ".rs")).read_text()
        tests[target] = re.findall(patterns[target], source)
        h.require(len(tests[target]) == expected and len(set(tests[target])) == expected,
                  "review exact browser test inventory before changing expected counts")
    return tests


def browser_stage(name, command, directory, environment, evidence, stages):
    # Same bounded child-session cleanup as the qualified bridge job, including
    # browser/driver descendants left after a test runner exits. Never name-match.
    started, status, child = time.monotonic(), None, None
    print(name + ": started", flush=True)
    try:
        with (evidence / (name + ".log")).open("wb") as log:
            child = subprocess.Popen(command, cwd=directory, env=environment,
                                     stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            status = child.wait(timeout=300)
    finally:
        if child is not None:
            try:
                os.killpg(child.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                pass
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait(timeout=10)
        stages.append({"name": name, "command": command, "exit_code": status,
                       "elapsed_seconds": round(time.monotonic() - started, 3)})
        h.save(evidence / "stages.json", stages)
        print(f"{name}: exit {status}", flush=True)
    h.require(status == 0, name + " failed; inspect retained log (no automatic retry)")


def retain_runner_build(log, temporary, destination):
    # Only copy the explicitly retained bindgen build, never other temporary
    # Chrome files. Preflight regular files and bounds before copying anything.
    try:
        matches = re.findall(r"^Retaining temporary build output folder: (.+)$",
                             log.read_text(), re.MULTILINE)
        if not matches:
            return {"status": "not-reported"}
        h.require(len(matches) == 1, "ambiguous retained runner directory")
        source = Path(matches[0])
        h.require(not source.is_symlink() and source.is_dir()
                  and source.resolve().parent == temporary.resolve(),
                  "retained runner directory escaped private temporary root")
        paths = sorted(source.rglob("*"))
        h.require(len(paths) <= h.MAX_FILES, "retained runner file count exceeded")
        files, size = [], 0
        for path in paths:
            h.require(not path.is_symlink() and (path.is_file() or path.is_dir()),
                      "retained runner link or special file refused")
            if path.is_file():
                files.append(path)
                size += path.stat().st_size
        h.require(size <= h.MAX_OUTER_BYTES, "retained runner byte limit exceeded")
        destination.mkdir()
        for path in files:
            target = destination / path.relative_to(source)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target)
        return {"status": "retained", "path": destination.name, "files": len(files), "bytes": size}
    except Exception as error:
        return {"status": "capture-failed", "error": f"{type(error).__name__}: {error}"}


def execute_browser(directory, environment, evidence, work, stages, config, sources, receipt):
    metadata = evidence / "ckmg-metadata.json"
    lockfile = directory / "Cargo.lock"
    if lockfile.is_file():
        shutil.copyfile(lockfile, evidence / "ckmg-Cargo.lock.before")
    try:
        h.run("resolve-ckmg", ["cargo", "--config", str(config), "metadata", "--format-version", "1",
              "--filter-platform", WASM_TARGET, "--features", "browser-tor"],
              directory, environment, evidence, stages, stdout=metadata)
    finally:
        if lockfile.is_file():
            shutil.copyfile(lockfile, evidence / "ckmg-Cargo.lock.after-resolve")
    h.metadata_receipt(metadata, sources, evidence, "ckmg")
    resolved = json.loads(metadata.read_text())
    tor = [package for package in resolved["packages"] if package["name"] == "ctrn"]
    h.require(len(tor) == 1 and tor[0]["source"] is None
              and Path(tor[0]["manifest_path"]).resolve() == sources[TOR_URL]["root"] / "Cargo.toml",
              "Keys must resolve exactly the reviewed original CTRN path")
    root = next(node for node in resolved["resolve"]["nodes"] if node["id"] == resolved["resolve"]["root"])
    h.require("browser-tor" in root["features"] and any(
        dependency["name"] == "ctrn" and dependency["pkg"] == tor[0]["id"] for dependency in root["deps"]),
        "browser-tor does not activate the exact CTRN dependency")
    h.require(lockfile.is_file() and not h.manifest(lockfile).get("patch", {}).get("unused"),
              "resolved lock is missing or contains unused candidate patches")
    lock_hash = h.sha256(lockfile)
    shutil.copyfile(lockfile, evidence / "ckmg-Cargo.lock")
    receipt["resolved_lock_sha256"] = lock_hash
    runner = browser_tools(environment, lockfile, work, evidence)
    tests = inventory(directory)
    h.save(evidence / "browser-test-inventory.json", tests)
    targets = ["--lib", "--test", "browser_tor", "--test", "keys"]
    base = ["cargo", "--config", str(config)]
    options = ["--locked", "--target", WASM_TARGET, "--features", "browser-tor"]
    for check in ("clippy", "check"):
        h.require(h.sha256(lockfile) == lock_hash, "resolved lock changed before Wasm qualification")
        command = base + [check] + options + targets
        if check == "clippy":
            command += ["--", "-D", "warnings"]
        h.run("wasm-" + check, command, directory, environment, evidence, stages)
        h.require(h.sha256(lockfile) == lock_hash, "resolved lock changed during Wasm qualification")
    h.run("wasm-compile", base + ["test"] + options
          + ["--test", "browser_tor", "--test", "keys", "--no-run", "--message-format=json"],
          directory, environment, evidence, stages)
    h.require(h.sha256(lockfile) == lock_hash, "resolved lock changed during test compilation")
    artifacts = {target: [] for target in COUNTS}
    for line in (evidence / "wasm-compile.log").read_text().splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        target = item.get("target", {}).get("name")
        if item.get("reason") == "compiler-artifact" and target in artifacts and item["profile"]["test"]:
            artifacts[target].extend(Path(name) for name in item["filenames"] if name.endswith(".wasm"))
    for target in COUNTS:
        h.require(len(artifacts[target]) == 1, "one actual " + target + " Wasm test artifact required")
        wasm = artifacts[target][0]
        h.require(wasm.resolve().is_relative_to(Path(environment["CARGO_TARGET_DIR"]).resolve()),
                  "test artifact escaped dedicated target directory")
        shutil.copyfile(wasm, evidence / (target + ".wasm"))
    for target, expected in COUNTS.items():
        wasm = artifacts[target][0]
        # Supported runner controls preserve generated modules and driver logs
        # even when module loading prevents the first test from starting. The
        # runner does not fetch WebDriver browser logs; loggingPrefs alone is
        # therefore not evidence that those console entries were retained.
        driver_log = evidence / (target + "-chromedriver.log")
        browser_log = evidence / (target + "-chromium.log")
        runner_build = evidence / (target + "-runner-build")
        # Chromium creates its Unix-domain socket below TMPDIR (108-byte limit).
        # This caller-owned short /tmp directory lives through diagnostics and cleanup.
        browser_scratch = Path(environment["CMEET_BROWSER_CACHE"])
        runner_temporary = browser_scratch / target
        h.require(len(os.fsencode(runner_temporary)) <= 40, "browser socket parent path is too long")
        runner_temporary.mkdir()
        webdriver = evidence / (target + "-webdriver.json")
        arguments = ["--no-sandbox", "--disable-dev-shm-usage", "--no-first-run", "--no-default-browser-check",
                     "--disable-background-networking", "--disable-component-update", "--disable-sync", "--no-proxy-server",
                     "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE localhost, EXCLUDE 127.0.0.1",
                     "--enable-logging", "--v=1", "--log-file=" + str(browser_log),
                     "--user-data-dir=" + str(browser_scratch / (target + "-profile"))]
        h.save(webdriver, {"goog:chromeOptions": {"binary": environment["BROWSER_BIN"], "args": arguments},
                           "goog:loggingPrefs": {"browser": "ALL", "performance": "ALL"}})
        browser_environment = environment.copy()
        # Driver::find prefers any configured remote or earlier driver. Require
        # this component run to own the already qualified local Chromium pair.
        for driver in ("GECKODRIVER", "SAFARIDRIVER", "CHROMEDRIVER", "MSEDGEDRIVER"):
            browser_environment.pop(driver + "_REMOTE", None)
            if driver != "CHROMEDRIVER":
                browser_environment.pop(driver, None)
        browser_environment.update(WASM_BINDGEN_USE_BROWSER="1", WASM_BINDGEN_TEST_TIMEOUT="120",
            CHROME=environment["BROWSER_BIN"], TMPDIR=str(runner_temporary), WASM_BINDGEN_KEEP_TEST_BUILD="1",
            CHROMEDRIVER_ARGS=shlex.join(["--verbose", "--log-path=" + str(driver_log)]),
            WASM_BINDGEN_TEST_WEBDRIVER_JSON=str(webdriver))
        browser_environment.pop("NO_HEADLESS", None)
        stage = "browser-" + target
        h.require(h.sha256(lockfile) == lock_hash, "resolved lock changed before browser execution")
        try:
            browser_stage(stage, [str(runner), str(wasm), "--nocapture"], directory,
                          browser_environment, evidence, stages)
        finally:
            build_receipt = retain_runner_build(evidence / (stage + ".log"), runner_temporary, runner_build)
            h.save(evidence / (target + "-browser-diagnostics.json"), {
                "runner_log": stage + ".log", "runner_timeout_seconds": 120,
                "test_wasm": target + ".wasm", "wasm_sha256": h.sha256(wasm),
                "driver": environment["CHROMEDRIVER"],
                "driver_args": browser_environment["CHROMEDRIVER_ARGS"],
                "retained_runner_build": build_receipt,
                "runner_fetches_webdriver_console_log": False,
                "logs": [{"path": path.name, "present": path.is_file(),
                          "bytes": path.stat().st_size if path.is_file() else None,
                          "sha256": h.sha256(path) if path.is_file() else None}
                         for path in (driver_log, browser_log)]})
        h.require(build_receipt["status"] == "retained" and driver_log.is_file(),
                  "successful runner did not retain required build/driver diagnostics")
        h.require(h.sha256(lockfile) == lock_hash, "resolved lock changed during browser execution")
        log = (evidence / (stage + ".log")).read_text()
        summaries = re.findall(r"test result: ok\.\s+(\d+) passed;\s+(\d+) failed;\s+(\d+) ignored;\s+(\d+) filtered out;", log)
        h.require(summaries == [(str(expected), "0", "0", "0")], "actual browser test counts do not match inventory")
        passed = re.findall(r"^test (\S+) \.\.\. ok\s*$", log, re.MULTILINE)
        names = [name.rsplit("::", 1)[-1] for name in passed]
        h.require(sorted(names) == sorted(tests[target]), "actual browser success names differ from required inventory")
        receipt.setdefault("browser_tests", {})[target] = {
            "passed": expected, "failed": 0, "ignored": 0, "filtered": 0, "tests": tests[target],
            "wasm_sha256": h.sha256(wasm), "execution": "actual Chromium", "log": stage + ".log"}


def main():
    h.require(os.environ.get("CI", "").lower() not in ("", "0", "false"), "CI worker required")
    h.require(os.environ.get("CI_REPO_CLONE_URL") == "https://forge.corbet.ch/corbet-libs/cvld.git",
              "private Forgejo qualifier required")
    evidence = Path(h.required("V01_EVIDENCE_DIR")).resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    h.require(not (evidence / "receipt.json").exists(), "evidence already contains a completed attempt")
    stages = []
    receipt = {"qualification": "original Keys browser custody and existing Keys tests on an explicit candidate graph",
               "status": "started", "stages": stages, "helper_prefix_sha256": HELPERS_SHA256,
               "not_claimed": ["public Tor", "Snowflake connectivity", "production passkey G3",
                   "vault-frame popup HPKE ceremony", "cmsg v0.1 acceptance", "full coverage",
                   "full repository suites", "borrow-lifetime doctest execution", "main dependency freshness"]}
    try:
        cache = Path(h.required("CARGO_TARGET_DIR")).resolve()
        h.require(cache.is_absolute(), "absolute dedicated target directory required")
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
        with (cache.parent / ".v01-browser-keys.lock").open("a") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise h.Refused("another qualification holds the dedicated target cache") from error
            with tempfile.TemporaryDirectory(prefix="v01-browser-keys-", dir=scratch) as temporary, \
                 tempfile.TemporaryDirectory(prefix="v01-k-", dir="/tmp") as fonts:
                work = Path(temporary)
                environment["CMEET_BROWSER_CACHE"] = fonts
                settings = [("credential.helper", "")]
                for org in h.FIRST_PARTY:
                    settings.append((f"url.file://{work}/unstaged/{org}/.insteadOf", f"https://github.com/{org}/"))
                environment["GIT_CONFIG_COUNT"] = str(len(settings))
                for index, (key, value) in enumerate(settings):
                    environment[f"GIT_CONFIG_KEY_{index}"] = key
                    environment[f"GIT_CONFIG_VALUE_{index}"] = value
                bundle = Path(h.required("V01_SOURCE_BUNDLE")).resolve()
                h.checked_file(bundle, h.required("V01_SOURCE_BUNDLE_SHA256"))
                h.extract(bundle, work / "bundle", [h.MAX_OUTER_BYTES, h.MAX_FILES])
                bundle_manifest = work / "bundle/manifest.json"
                h.require(bundle_manifest.is_file() and bundle_manifest.stat().st_size <= h.MAX_MANIFEST_BYTES,
                          "missing or oversized source-bundle manifest")
                specification = json.loads(bundle_manifest.read_text())
                shutil.copyfile(bundle_manifest, evidence / "source-manifest.json")
                offered = specification.get("sources")
                h.require(isinstance(offered, list) and 0 < len(offered) < h.MAX_SOURCES, "invalid source count")
                root_archive = Path(h.required("V01_ROOT_SOURCE_ARCHIVE")).resolve()
                root_commit = h.required("V01_ROOT_SOURCE_COMMIT")
                h.require(root_commit == os.environ["CI_COMMIT_SHA"], "workflow/root source commit mismatch")
                entries = [(dict(url=h.ROOT_URL, commit=root_commit, sha256=h.required("V01_ROOT_SOURCE_SHA256"),
                    packages=[{"manifest": "Cargo.toml", "name": "cvld"}]), root_archive)]
                for entry in offered:
                    h.require(isinstance(entry, dict), "invalid source entry")
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
                        h.require(entry["commit"] == CANDIDATES[repository], "unexpected Keys or Tor candidate")
                    location = source_parent / repository.rsplit("/", 1)[-1]
                    h.extract(archive, location, budget)
                    packages, skipped = h.selected_packages(location, entry.get("packages"))
                    sources[repository] = {"root": location, "packages": packages}
                    receipt.setdefault("sources", []).append({"url": repository, "commit": entry["commit"],
                        "archive_sha256": entry["sha256"],
                        "packages": {name: str(path.relative_to(location)) for name, path in packages.items()},
                        "skipped_nonprimary_packages": skipped})
                h.require(all(repository in sources for repository in CANDIDATES), "Keys and Tor candidates required")
                root = sources[h.ROOT_URL]["root"]
                for name in ("v01-browser-keys.py", "v01-records.py"):
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
                h.require(isinstance(formats, list) and {h.url(value) for value in formats} == set(CANDIDATES),
                          "format_urls must select exactly the Keys and Tor candidates")
                for repository in sorted(CANDIDATES):
                    name = repository.rsplit("/", 1)[-1]
                    h.run("fmt-" + name, ["cargo", "fmt", "--package", name, "--check"],
                          sources[repository]["root"], environment, evidence, stages)
                execute_browser(sources[KEYS_URL]["root"], environment, evidence, work, stages,
                                config, sources, receipt)
                receipt["status"] = "passed-browser-keys-custody-and-existing-keys"
                receipt["scope"] = "five private browser onion custody cases and thirty original Keys cases in Chromium"
    except BaseException as error:
        receipt["status"] = "failed"
        receipt["failure"] = f"{type(error).__name__}: {error}"
        print("qualification failed; inspect receipt.json and retained stage logs", file=sys.stderr)
        return 1
    finally:
        h.save(evidence / "receipt.json", receipt)
        h.save(evidence / "SHA256SUMS.json", {path.relative_to(evidence).as_posix(): h.sha256(path)
            for path in sorted(evidence.rglob("*")) if path.is_file() and path.name != "SHA256SUMS.json"})
    print("actual browser Keys custody checks passed; component evidence retained", flush=True)
    return 0


if __name__ == "__main__":
    def interrupted(_signal, _frame):
        raise h.Refused("bounded browser Keys qualification interrupted")
    signal.signal(signal.SIGTERM, interrupted)
    sys.exit(main())
