#!/usr/bin/env python3
"""Temporary CI qualification of an explicit candidate graph, never upstream main.

No downloads of tools, global Git/Cargo configuration, or aggregate workspace.
Only existing worker tools and the supplied, digest-bound source archives are used.
"""
from __future__ import annotations

import fcntl
import copy
import difflib
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
import tomllib


ROOT_URL = "https://git.corbet.ch/corbet-libs/cvld"
VAULT_URL = "https://git.corbet.ch/corbet-libs/cvlt"
STORE_URL = "https://git.corbet.ch/corbet-foss/cwst"
KEYHOLE_URL = "https://git.corbet.ch/corbet-foss/ckyh"
MEMBERSHIP_URL = "https://git.corbet.ch/corbet-libs/cmbr"
FIRST_PARTY = ("corbet-foss", "corbet-libs", "corbet-labs", "cmtymeet")
MAX_SOURCES = 96
MAX_FILES = 100_000
MAX_OUTER_BYTES = 512 * 1024 * 1024
MAX_SOURCE_BYTES = 2 * 1024 * 1024 * 1024
MAX_MANIFEST_BYTES = 2 * 1024 * 1024
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
PACKAGE = re.compile(r"[A-Za-z0-9_-]+\Z")
REPOSITORY = re.compile(
    r"https://git\.corbet\.ch/(corbet-foss|corbet-libs|corbet-labs|cmtymeet)/"
    r"[A-Za-z0-9_.-]+(?:\.git)?\Z"
)


class Refused(Exception):
    """Bounded qualification refusal; details stay in the job's evidence."""


def require(value, message):
    if not value:
        raise Refused(message)


def required(name):
    value = os.environ.get(name)
    require(value, f"missing required input: {name}")
    return value


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def relative(value):
    require(isinstance(value, str) and len(value) <= 4096, "invalid archive path")
    clean = value.removesuffix("/")
    path = PurePosixPath(clean)
    require(
        clean and not path.is_absolute() and "\\" not in clean
        and all(part not in (".", "..") for part in path.parts)
        and path.as_posix() == clean,
        "noncanonical archive path",
    )
    return path


def url(value):
    require(isinstance(value, str) and REPOSITORY.fullmatch(value),
            "source URL is not an original first-party HTTPS repository")
    return value.removesuffix(".git")


def checked_file(path, digest):
    require(isinstance(digest, str) and HEX64.fullmatch(digest), "invalid archive SHA-256")
    require(path.is_file() and not path.is_symlink(), "missing regular source archive")
    require(sha256(path) == digest, "source archive SHA-256 mismatch")


def extract(archive, destination, budget):
    """Preflight every member, then copy regular files only into a new directory."""
    require(not destination.exists(), "extraction destination already exists")
    require(archive.stat().st_size <= MAX_SOURCE_BYTES, "archive exceeds input limit")
    with tarfile.open(archive, mode="r:") as source:
        members = []
        seen = set()
        total = 0
        for member in source:
            path = relative(member.name)
            require(path not in seen, "duplicate archive member")
            seen.add(path)
            require(member.isdir() or member.isreg(), "archive links or special files refused")
            require(not member.sparse and not any("sparse" in key.lower()
                    for key in member.pax_headers), "sparse archive member refused")
            require(member.size >= 0 and (member.isreg() or member.size == 0),
                    "invalid member size")
            total += member.size
            require(total <= budget[0] and len(members) < budget[1],
                    "source staging bounds exceeded")
            members.append((member, path))
        # A file may not also be the parent directory of another entry.
        files = {path for member, path in members if member.isreg()}
        require(all(not any(parent in files for parent in path.parents)
                    for _, path in members), "archive file/directory collision")
        destination.mkdir(mode=0o700)
        for member, path in members:
            output = destination.joinpath(*path.parts)
            if member.isdir():
                output.mkdir(parents=True, exist_ok=True)
                continue
            output.parent.mkdir(parents=True, exist_ok=True)
            stream = source.extractfile(member)
            require(stream is not None, "missing archive member data")
            with stream, output.open("xb") as target:
                shutil.copyfileobj(stream, target, length=1024 * 1024)
            require(output.stat().st_size == member.size, "truncated archive member")
            output.chmod(0o755 if member.mode & 0o111 else 0o644)
        budget[0] -= total
        budget[1] -= len(members)


def git_archive_commit(archive, expected, environment):
    require(isinstance(expected, str) and HEX40.fullmatch(expected), "invalid source commit")
    with archive.open("rb") as stream:
        result = subprocess.run(
            ["git", "get-tar-commit-id"], stdin=stream, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, env=environment, check=False, timeout=30,
        )
    require(result.returncode == 0 and result.stdout.decode().strip() == expected,
            "git archive commit does not match declared candidate")


def manifest(path):
    require(path.is_file() and path.stat().st_size <= MAX_MANIFEST_BYTES,
            "missing or oversized Cargo manifest")
    return tomllib.loads(path.read_text())


def primary_manifests(root):
    doc = manifest(root / "Cargo.toml")
    result = {"Cargo.toml"} if "package" in doc else set()
    workspace = doc.get("workspace", {})
    excluded = set()
    for pattern in workspace.get("exclude", []):
        relative(pattern)
        excluded.update(path.resolve() for path in root.glob(pattern))
    for pattern in workspace.get("members", []):
        relative(pattern)
        for path in root.glob(pattern):
            if path.resolve() not in excluded and (path / "Cargo.toml").is_file():
                result.add((path / "Cargo.toml").relative_to(root).as_posix())
    return result


def selected_packages(root, offered):
    require(isinstance(offered, list) and 0 < len(offered) <= 64, "invalid package inventory")
    allowed = primary_manifests(root)
    selected = {}
    skipped = []
    for package in offered:
        require(isinstance(package, dict), "invalid package entry")
        name = package.get("name")
        require(isinstance(name, str) and PACKAGE.fullmatch(name), "invalid package name")
        file = relative(package.get("manifest"))
        doc = manifest(root.joinpath(*file.parts))
        require(doc.get("package", {}).get("name") == name, "package inventory mismatch")
        if file.as_posix() not in allowed or name == "browser-coverage-runtime" or "fuzz" in file.parts:
            skipped.append({"name": name, "manifest": file.as_posix()})
            continue
        require(name not in selected, "duplicate package within source URL")
        selected[name] = root.joinpath(*file.parts).parent
    expected = {manifest(root / file)["package"]["name"] for file in allowed}
    require(set(selected) == expected, "primary/workspace packages omitted from source inventory")
    return selected, skipped


def dependency_tables(document):
    # Package metadata may describe a Git fixture without declaring a crate.
    for kind in ("dependencies", "dev-dependencies", "build-dependencies"):
        yield (kind,), document.get(kind, {})
    for target, options in document.get("target", {}).items():
        for kind in ("dependencies", "dev-dependencies", "build-dependencies"):
            yield ("target", target, kind), options.get(kind, {})
    yield ("workspace", "dependencies"), document.get("workspace", {}).get("dependencies", {})
    for source, entries in document.get("patch", {}).items():
        yield ("patch", source), entries
    yield ("replace",), document.get("replace", {})


def git_edges(document):
    for _, entries in dependency_tables(document):
        for specification in entries.values():
            if isinstance(specification, dict) and isinstance(specification.get("git"), str):
                yield specification["git"]


def is_first_party(value):
    return any(value.startswith(f"https://github.com/{org}/") for org in FIRST_PARTY)


def local_dependency(specification, name, sources, context):
    repository = url(specification["git"])
    require(repository in sources, f"{context}: unmapped first-party source {repository}")
    package = specification.get("package", name)
    require(isinstance(package, str) and package in sources[repository]["packages"],
            f"{context}: dependency {name!r} selects package {package!r} from {repository}; "
            f"available packages: {sorted(sources[repository]['packages'])}")
    require("path" not in specification, f"{context}: ambiguous dependency has both Git and path")
    updated = {key: value for key, value in specification.items()
               if key not in ("git", "branch", "rev", "tag")}
    updated["path"] = str(sources[repository]["packages"][package])
    return updated


def local_manifest_value(document, sources, context):
    expected = copy.deepcopy(document)
    replacements = {}
    for route, entries in dependency_tables(expected):
        for name, value in entries.items():
            if isinstance(value, dict) and isinstance(value.get("git"), str) \
                    and is_first_party(value["git"]):
                entries[name] = local_dependency(value, name, sources,
                    f"{context}: {'.'.join((*route, name))}")
                replacements[(route, name)] = entries[name]
    return expected, replacements


def table_header(line):
    if not line.lstrip().startswith("["):
        return None
    try:
        node = tomllib.loads(line)
    except tomllib.TOMLDecodeError:
        return None
    route = []
    while isinstance(node, dict) and len(node) == 1:
        name, node = next(iter(node.items()))
        route.append(name)
    return tuple(route) if node == {} else ()


def inline_value(value):
    # The observed dependency options are strings, booleans and feature arrays.
    # Fail closed for any new TOML shape instead of reserializing the document.
    if isinstance(value, (str, bool)):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list):
        return "[" + ", ".join(inline_value(item) for item in value) + "]"
    raise Refused("unsupported inline dependency option shape")


def rewrite_manifests(sources, evidence):
    edits = []
    for repository, source in sorted(sources.items()):
        for file in sorted(source["root"].rglob("Cargo.toml")):
            before = file.read_text()
            original = tomllib.loads(before)
            relative_file = file.relative_to(source["root"])
            context = f"{repository}/{relative_file}"
            expected, replacements = local_manifest_value(original, sources, context)
            if expected == original:
                continue
            lines = []
            count = 0
            route = ()
            for line in before.splitlines(keepends=True):
                header = table_header(line)
                if header is not None:
                    route = header
                try:
                    assignment = tomllib.loads(line)
                except tomllib.TOMLDecodeError:
                    assignment = {}
                if len(assignment) == 1:
                    name, value = next(iter(assignment.items()))
                    if (route, name) in replacements:
                        local = replacements[(route, name)]
                        fields = ", ".join(f"{json.dumps(key)} = {inline_value(item)}"
                                           for key, item in local.items())
                        line = f"{json.dumps(name)} = {{ {fields} }}\n"
                        count += 1
                lines.append(line)
            after = "".join(lines)
            require(count > 0 and tomllib.loads(after) == expected,
                    f"{context}: first-party Git dependency is not a supported inline table")
            require(not any(is_first_party(item) for item in git_edges(tomllib.loads(after))),
                    f"{context}: first-party Git dependency remains after candidate path rewrite")
            target = evidence / "manifest-edits" / repository.removeprefix("https://github.com/") / relative_file
            target.parent.mkdir(parents=True, exist_ok=True)
            Path(str(target) + ".before").write_text(before)
            Path(str(target) + ".after").write_text(after)
            Path(str(target) + ".diff").write_text("".join(difflib.unified_diff(
                before.splitlines(keepends=True), after.splitlines(keepends=True),
                fromfile=f"archive/{relative_file}", tofile=f"candidate/{relative_file}")))
            file.write_text(after)
            edits.append({"url": repository, "manifest": relative_file.as_posix(),
                "rewritten_dependencies": count,
                "before_sha256": hashlib.sha256(before.encode()).hexdigest(),
                "after_sha256": hashlib.sha256(after.encode()).hexdigest()})
    save(evidence / "manifest-edits.json", edits)
    return edits


def run(name, command, directory, environment, evidence, stages, stdout=None):
    started = time.monotonic()
    log = evidence / f"{name}.log"
    print(f"{name}: started", flush=True)
    status = 1
    try:
        with log.open("wb") as errors:
            if stdout is None:
                status = process(command, directory, environment, errors, subprocess.STDOUT)
            else:
                with stdout.open("wb") as output:
                    status = process(command, directory, environment, output, errors)
    finally:
        stages.append({"name": name, "command": command, "exit_code": status,
                       "elapsed_seconds": round(time.monotonic() - started, 3)})
        save(evidence / "stages.json", stages)
        print(f"{name}: exit {status}", flush=True)
    require(status == 0, f"{name} failed; inspect its retained log (no automatic retry)")


def process(command, directory, environment, output, errors):
    child = subprocess.Popen(command, cwd=directory, env=environment,
        stdout=output, stderr=errors, start_new_session=True)

    def stop():
        # Only this command's process group; never match by process name.
        try:
            os.killpg(child.pid, signal.SIGTERM)
        except ProcessLookupError:
            return
        try:
            child.wait(timeout=15)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait()

    def cancelled(signum, frame):
        stop()
        raise Refused("qualification cancelled by worker")

    previous = {sig: signal.signal(sig, cancelled) for sig in (signal.SIGTERM, signal.SIGINT)}
    try:
        return child.wait(timeout=3300)
    except subprocess.TimeoutExpired:
        stop()
        return 124
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def test_receipt(evidence, stage, expected):
    text = (evidence / f"{stage}.log").read_text(errors="replace")
    summaries = re.findall(
        r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; "
        r"(\d+) measured; (\d+) filtered out;", text)
    require(len(summaries) == expected and all(int(passed) > 0
        and all(int(value) == 0 for value in (failed, ignored, measured, filtered))
        for passed, failed, ignored, measured, filtered in summaries),
        "selected native test targets did not all execute without skips")
    save(evidence / f"{stage}-counts.json", [{"passed": int(item[0])} for item in summaries])


def generate_api(root, config, environment, evidence, stages):
    generated = evidence / "generated"
    (generated / "docs").mkdir(parents=True)
    (generated / "clients/ts").mkdir(parents=True)
    names = ("docs/openapi.json", "clients/ts/schema.d.ts")
    previous = {name: (root / name).read_text() for name in names}
    original_lock = sha256(root / "clients/ts/package-lock.json")
    completed = False
    try:
        # Production server contract: development-gate must not enter the artifact.
        openapi = generated / "openapi-attempt.json"
        run("generate-openapi", ["cargo", "--config", str(config), "run",
            "--locked", "--", "openapi"], root, environment, evidence, stages,
            stdout=openapi)
        doc = json.loads(openapi.read_text())
        require(isinstance(doc.get("paths"), dict) and doc.get("openapi"),
                "generator did not emit an OpenAPI document")
        shutil.copyfile(openapi, root / "docs/openapi.json")
        for name, command in (
            ("npm-ci", ["npm", "ci", "--prefix", "clients/ts"]),
            ("generate-types", ["npm", "run", "generate", "--prefix", "clients/ts"]),
            ("check-types", ["npm", "run", "check", "--prefix", "clients/ts"]),
            ("test-types", ["npm", "test", "--prefix", "clients/ts"]),
        ):
            run(name, command, root, environment, evidence, stages)
        completed = True
    finally:
        artifacts = []
        for name in names:
            current = (root / name).read_text()
            output = generated / name
            shutil.copyfile(root / name, output)
            diff = "".join(difflib.unified_diff(previous[name].splitlines(keepends=True),
                current.splitlines(keepends=True), fromfile=f"original/{name}",
                tofile=f"generated/{name}"))
            (generated / (Path(name).name + ".diff")).write_text(diff)
            artifacts.append({"path": name,
                "original_sha256": hashlib.sha256(previous[name].encode()).hexdigest(),
                "generated_sha256": sha256(output), "changed": bool(diff)})
        save(generated / "receipt.json", {"status": "passed" if completed else "incomplete",
            "review": "generated differences require parent review/import",
            "artifacts": artifacts, "npm_lock_sha256": original_lock})
        shutil.copyfile(root / "clients/ts/package-lock.json", generated / "clients/ts/package-lock.json")
    require(sha256(root / "clients/ts/package-lock.json") == original_lock,
            "npm changed the supplied dependency lock")


def metadata_receipt(data, sources, evidence, label):
    resolved = json.loads(data.read_text())
    selected_roots = [source["root"].resolve() for source in sources.values()]
    observed = []
    for package in resolved["packages"]:
        origin = package.get("source")
        if origin and origin.startswith("git+") and is_first_party(origin[4:].split("?", 1)[0]):
            raise Refused("Cargo resolved a first-party Git package outside candidate path patches")
        if origin is None:
            location = Path(package["manifest_path"]).resolve()
            require(any(location.is_relative_to(root) for root in selected_roots),
                    "Cargo resolved an unlisted local package")
        observed.append({"id": package["id"], "name": package["name"],
            "version": package["version"], "source": origin,
            "manifest_path": package["manifest_path"]})
    save(evidence / f"{label}-resolved-sources.json", observed)


def main():
    require(os.environ.get("CI", "").lower() not in ("", "0", "false"), "CI worker required")
    evidence = Path(required("V01_EVIDENCE_DIR")).resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    require(not (evidence / "receipt.json").exists(), "evidence already contains a completed attempt")
    stages = []
    receipt = {"qualification": "explicit candidate graph; not main or release qualification",
               "status": "started", "stages": stages}
    try:
        cache = Path(required("CARGO_TARGET_DIR")).resolve()
        require(cache.is_absolute(), "absolute dedicated target directory required")
        cache.mkdir(parents=True, exist_ok=True)
        require(Path(required("CARGO_HOME")).is_dir(), "existing Cargo cache required")
        scratch = Path(required("RUNNER_TEMP")).resolve()
        require(scratch.is_dir(), "existing protected job scratch required")
        environment = os.environ.copy()
        environment.update(CARGO_BUILD_JOBS="2", RUST_TEST_THREADS="2", CARGO_TERM_COLOR="never",
                           CARGO_PROFILE_DEV_DEBUG="0", CARGO_PROFILE_TEST_DEBUG="0",
                           CARGO_NET_GIT_FETCH_WITH_CLI="true", GIT_TERMINAL_PROMPT="0",
                           GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
        for key in tuple(environment):
            if key.startswith(("GH_", "GITHUB_", "GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_")):
                environment.pop(key)
        environment.pop("GIT_CONFIG_COUNT", None)
        with (cache.parent / ".v01-certificates.lock").open("a") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise Refused("another qualification holds the dedicated target cache") from error
            with tempfile.TemporaryDirectory(prefix="v01-certificates-", dir=scratch) as temporary:
                work = Path(temporary)
                # Original first-party URLs must be completely mapped to sources.
                # Missing Git inputs fail locally instead of reaching a different main.
                settings = [("credential.helper", "")]
                for org in FIRST_PARTY:
                    settings.append((f"url.file://{work}/unstaged/{org}/.insteadOf",
                                     f"https://github.com/{org}/"))
                environment["GIT_CONFIG_COUNT"] = str(len(settings))
                for index, (key, value) in enumerate(settings):
                    environment[f"GIT_CONFIG_KEY_{index}"] = key
                    environment[f"GIT_CONFIG_VALUE_{index}"] = value
                run("tools", ["python3", "-c",
                    "import subprocess; [subprocess.run(c, check=True) for c in "
                    "[['git','--version'],['rustc','--version'],['cargo','--version'],"
                    "['cargo','clippy','--version'],['rustfmt','--version'],"
                    "['node','--version'],['npm','--version']]]"],
                    work, environment, evidence, stages)
                bundle = Path(required("V01_SOURCE_BUNDLE")).resolve()
                checked_file(bundle, required("V01_SOURCE_BUNDLE_SHA256"))
                extract(bundle, work / "bundle", [MAX_OUTER_BYTES, MAX_FILES])
                bundle_manifest = work / "bundle/manifest.json"
                require(bundle_manifest.is_file() and bundle_manifest.stat().st_size <= MAX_MANIFEST_BYTES,
                        "missing or oversized source-bundle manifest")
                specification = json.loads(bundle_manifest.read_text())
                shutil.copyfile(bundle_manifest, evidence / "source-manifest.json")
                offered = specification.get("sources")
                require(isinstance(offered, list) and 0 < len(offered) < MAX_SOURCES,
                        "invalid source count")
                root_archive = Path(required("V01_ROOT_SOURCE_ARCHIVE")).resolve()
                root_commit = required("V01_ROOT_SOURCE_COMMIT")
                if os.environ.get("CI_COMMIT_SHA"):
                    require(root_commit == os.environ["CI_COMMIT_SHA"], "workflow/root source commit mismatch")
                entries = [(dict(url=ROOT_URL, commit=root_commit,
                    sha256=required("V01_ROOT_SOURCE_SHA256"),
                    packages=[{"manifest": "Cargo.toml", "name": "cvld"}]), root_archive)]
                for entry in offered:
                    require(isinstance(entry, dict), "invalid source entry")
                    entries.append((entry, work / "bundle" / relative(entry.get("archive"))))
                sources = {}
                budget = [MAX_SOURCE_BYTES, MAX_FILES]
                source_parent = work / "sources"
                source_parent.mkdir()
                for entry, archive in entries:
                    repository = url(entry.get("url"))
                    require(repository not in sources, "duplicate source URL")
                    checked_file(archive, entry.get("sha256"))
                    git_archive_commit(archive, entry.get("commit"), environment)
                    location = source_parent / repository.rsplit("/", 1)[-1]
                    extract(archive, location, budget)
                    packages, skipped = selected_packages(location, entry.get("packages"))
                    sources[repository] = {"root": location, "packages": packages}
                    receipt.setdefault("sources", []).append({"url": repository,
                        "commit": entry["commit"], "archive_sha256": entry["sha256"],
                        "packages": {name: str(path.relative_to(location)) for name, path in packages.items()},
                        "skipped_nonprimary_packages": skipped})
                require(all(item in sources for item in (VAULT_URL, STORE_URL, KEYHOLE_URL, MEMBERSHIP_URL)),
                        "Vault, Store, Keyhole and Membership sources are required")
                root = sources[ROOT_URL]["root"]
                require(sha256(root / ".ci/v01-certificates.py") == sha256(Path(__file__).resolve()),
                        "executed harness differs from root source archive")
                external = set()
                for source in sources.values():
                    for file in source["root"].rglob("Cargo.toml"):
                        for dependency in git_edges(manifest(file)):
                            if is_first_party(dependency):
                                require(url(dependency) in sources, "unmapped first-party manifest dependency")
                            else:
                                external.add(dependency)
                receipt["external_git_sources"] = sorted(external)
                receipt["source_bundle_sha256"] = required("V01_SOURCE_BUNDLE_SHA256")
                # Cargo may query an original Git source even when a path patch
                # replaces every package. Make this disposable graph explicit:
                # change only dependency source selectors, retaining evidence.
                receipt["manifest_edits"] = rewrite_manifests(sources, evidence)
                for source in sources.values():
                    for file in source["root"].rglob("Cargo.toml"):
                        require(not any(is_first_party(edge) for edge in git_edges(manifest(file))),
                                "first-party Git dependency survived exact path composition")
                save(evidence / "source-receipt.json", receipt)
                config = work / ".cargo/config.toml"
                config.parent.mkdir()
                # Every actual first-party edge already names its exact path.
                # Redundant blanket patches create unused lock entries whose
                # order can change between metadata and a locked build.
                config.write_text("# Exact candidate paths are recorded in the disposable manifests.\n")
                shutil.copyfile(config, evidence / "candidate-cargo-config.toml")
                format_urls = specification.get("format_urls")
                require(isinstance(format_urls, list) and 0 < len(format_urls) <= MAX_SOURCES,
                        "explicit changed-source format_urls are required")
                format_urls = {url(item) for item in format_urls} | {ROOT_URL, VAULT_URL}
                for repository in sorted(format_urls):
                    require(repository in sources, "format source missing from bundle")
                    name = repository.rsplit("/", 1)[-1]
                    run(f"fmt-{name}", ["cargo", "fmt", "--all", "--check"],
                        sources[repository]["root"], environment, evidence, stages)
                selections = [
                    ("cmbr", MEMBERSHIP_URL, [], ["--lib"], 1),
                    ("cvld", ROOT_URL, ["--features", "development-gate"],
                     ["--test", "passkey_certificates", "--test", "devices",
                      "--test", "discoverable", "--test", "operator_vault",
                      "--test", "surfaces", "--test", "client_contract"], 6),
                    ("cvlt", VAULT_URL, ["--features", "native-records"],
                     ["--test", "lineage", "--test", "vault", "--lib"], 3),
                    ("cwst", STORE_URL, [], ["--test", "store"], 1),
                    ("ckyh", KEYHOLE_URL, ["--features", "server"], ["--lib"], 1),
                ]
                for label, repository, features, targets, expected_summaries in selections:
                    directory = sources[repository]["root"]
                    metadata = evidence / f"{label}-metadata.json"
                    original_lock = directory / "Cargo.lock"
                    if original_lock.is_file():
                        shutil.copyfile(original_lock, evidence / f"{label}-Cargo.lock.before")
                    # One dependency resolution per independent actual root; no retries.
                    try:
                        run(f"resolve-{label}", ["cargo", "--config", str(config), "metadata",
                            "--format-version", "1", *features], directory,
                            environment, evidence, stages, stdout=metadata)
                    finally:
                        if original_lock.is_file():
                            shutil.copyfile(original_lock, evidence / f"{label}-Cargo.lock.after-resolve")
                    metadata_receipt(metadata, sources, evidence, label)
                    lockfile = directory / "Cargo.lock"
                    require(lockfile.is_file(), "Cargo resolution produced no lockfile")
                    require(not manifest(lockfile).get("patch", {}).get("unused"),
                            "resolved lock contains unused candidate patches")
                    resolved_hash = sha256(lockfile)
                    shutil.copyfile(lockfile, evidence / f"{label}-Cargo.lock")
                    receipt.setdefault("locks", {})[label] = resolved_hash
                    if label == "cvld":
                        generate_api(directory, config, environment, evidence, stages)
                        require(sha256(lockfile) == resolved_hash,
                                "resolved lock changed during API generation")
                    for check in ("clippy", "test"):
                        command = ["cargo", "--config", str(config), check,
                                   "--locked", *features, *targets]
                        if check == "clippy":
                            command.extend(["--", "-D", "warnings"])
                        run(f"{check}-{label}", command, directory, environment, evidence, stages)
                        require(sha256(lockfile) == resolved_hash, "resolved lock changed during qualification")
                        if check == "test":
                            test_receipt(evidence, f"test-{label}", expected_summaries)
                    if label == "cvld":
                        run("test-production", ["cargo", "--config", str(config), "test",
                            "--locked", "--test", "production"], directory,
                            environment, evidence, stages)
                        test_receipt(evidence, "test-production", 1)
                        require(sha256(lockfile) == resolved_hash,
                                "resolved lock changed during production checks")
                receipt["status"] = "passed-selected-native-checks"
                receipt["scope"] = "CVLD certificate/device services, CVLT lineage/existing/chunks, CWST restore and CKYH server certificates"
                receipt["not_claimed"] = ["browser execution", "full coverage", "full repository suites",
                    "public-network checkpoint restore", "cmsg v0.1 acceptance", "main dependency freshness"]
    except Exception as error:
        receipt["status"] = "failed"
        receipt["failure"] = f"{type(error).__name__}: {error}"
        print("qualification failed; inspect receipt.json and retained stage logs", file=sys.stderr)
        return 1
    finally:
        save(evidence / "receipt.json", receipt)
    print("selected native qualification passed; evidence retained", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
