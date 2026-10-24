#!/usr/bin/env python3
"""Assemble one G5 native accounting configuration from retained cblc artifacts.

Nothing here is hand-made: every artifact is read from the write-once retained
areas of the cblc job state, authenticated against a pin that is committed in
this file (never taken from the downloaded manifest), and referenced by its
retained path. Only per-run material is written to --out: ledger and extension
policy, activation statement and proof (cut from the retained activation probe),
fixture seeds (test mode only) and a fresh settlement epoch with its RSA key.

Output: <out>/account-config.json (cvld `AccountConfig`) and
<out>/activation-probe.json (the retained probe, byte-identical) plus its digest and
<out>/template-ledger-policy.json (hub-created communities: rate window = 2 checkpoint periods, admission counts doubled),
printed as shell exports with --exports. Production deployments pass real seed
files (--operator-seed-file/--certificate-seed-file, from sops) and a production
settlement key; test mode derives the fixture seeds named in the cblc request.
"""
import argparse
import base64
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

CBLC_NAMESPACE = "08a9478e457e604aa31f9a54"  # sha256("https://git.corbet.ch/corbet-libs/cblc")[:24]

# Reviewed pins. Adding an artifact generation means adding its pins here in a
# reviewed commit; a different byte anywhere refuses.
EXTENSION_GROUPS = {
    # artifact-conformance group of cblc 4a933fc (bb 5.2.1): extension circuits,
    # keys, setup and the alpha/omega activation probes.
    "4a933fc30a8f8d9e1a5801ed2f826a82efd9b861": {
        "manifestSha256": "81aec00155f28e7b1d064adeb893593e4bedae01bd8334f80bf0c65ce91c8efc",
    },
    # artifact-conformance group of cblc b412abc (branch omega-long-window, bb 5.2.1): the omega
    # activation probe carries a ten-year policy window and the retained native worker is pinned.
    "b412abcbd3d59e899bf27b86c1bae854d128b860": {
        "manifestSha256": "519b5669bd21c3b41e83d7cdbdd1c78e3960bc0d290a222c70efa6a2d56e73b5",
    },
    # artifact-conformance group of cblc eeb879e (voucher accounting, bb 5.2.1): update width 410,
    # voucher_epoch circuit, standingPolicyDigest in the policy, ten-year omega probe.
    "eeb879eb8d5278924de5f665c8c43a5fa6d5bd71": {
        "manifestSha256": "68c5c8b4940800ef4c31df259545812215df665c055a48ff004eb05ea41aaf07",
    },
    # artifact-conformance group of cblc 660e913 (rulebook parameters, standing digest 13869f92):
    # the alpha/omega probes carry the digest the hub-derived terms use.
    "660e913088aa2d4b2a510143e66be31c9daed963": {
        "manifestSha256": "f935b80363c34496463b3b7f2a3270add37f52696e14d048c4c4c96aa478d228",
    },
    # artifact-conformance group of cblc 8d631b9 (chain2: certificate issuer key ring and community
    # identity, deposit width 328, voucher reserved units): run 222.
    "8d631b902d52893dd9480cf80aa75efce66a928a": {
        "manifestSha256": "079028ca859d90a75b51632f0628fabb9a5bc4311615f915ee287ba8bba624f0",
    },
    # artifact-conformance group of cblc a8a4689 (update circuit diet: 455,584 gates, dyadic 2^19,
    # same statement; the update, wave and outcome bytecode and keys changed): run 241.
    "a8a4689889a33c8edd0186ba64f5d65bd2a47e97": {
        "manifestSha256": "73d26cccb5d835ab0101c3910d30c8e554c332e6514c69eab784a6abf9c7809d",
    },
}
ACCOUNT_CAPTURES = {
    # native-startup-fixture-retained capture of cblc 6232481 (account circuit).
    "f0731b7c62ff034c79965fa0c9016bf16b3fd5c2e38f32409cfa00682acb1407": {
        "accountManifestSha256": "12b0248737cf6cc44892cd34a839878ef05689290fc0bd9d76a0bd785833df06",
    },
    # native-startup-fixture-retained capture of the voucher-accounting record-epoch run (cblc 829489a).
    "1e1262a03a6a56caba2ba76e92047799e2323bf986312ccd3ac5b1827b7929a5": {
        "accountManifestSha256": "2b0125c187850a3dbb94b06e16f105d2759cc81413dc844981659c99343f9144",
    },
    # native-startup-fixture-retained capture of the chain2 record-epoch run 221 (cblc e5514337).
    "420e9a0965564966e36fc8d4029f12b90eeb3485777322153a8f8654181cab9c": {
        "accountManifestSha256": "640133361f2ffd5f8b2336ec08ff693f74bcfb59b7e9cd41982490e872bff19f",
    },
    # native-startup-fixture-retained capture of the update circuit diet record-epoch run 243 (cblc a8a4689).
    "24d9ae9df4c7ea35397804ed6168dc172cbb152b77c31dbf4f3823516d775fa9": {
        "accountManifestSha256": "045e0d54e48d9234ece851ce758216c5956efe3a0a8017ad32e1b0e4d8dbc7d1",
    },
}
WORKER_CAPTURES = {
    # gather-record-fixture-retained capture of cblc 6232481 (czkp_bb_worker).
    "23cf333ef4c1bb9acc401e3cf448528978d960fe793dbcc50da7a1ef54f6b212": {
        "workerSha256": "5c5c69cca3ccc1d00e12d7d75bd431b79d68864b88e3c5ba18284c77f2ac46f9",
        "workerBytes": 68078712,
    },
    # gather-record-fixture-retained capture of cblc 829489a (czkp_bb_worker).
    "44452b71ef1d79c60a3f61f128aebefaeb43babee55b0ce701f2f7219d8a22d6": {
        "workerSha256": "20136479f31369532345b1e56e0b95a2e4c82803e03b352b1d19b1cc18eab87a",
        "workerBytes": 68155080,
    },
    # gather-record-fixture-retained capture of cblc e5514337 (czkp_bb_worker, record-epoch run 221).
    "e55d4cafadb748f4e24a7a581208407c2fcb32ea74a1ae37532167e9054c4925": {
        "workerSha256": "7d90df5d29d222545bebba3e10cdbbdeac974856bfe8ae27a235d8b31b8e42e6",
        "workerBytes": 68211552,
    },
    # gather-record-fixture-retained capture of cblc a8a4689 (czkp_bb_worker, record-epoch run 243).
    "5ea7c6c09205cc9b2c8473b515c67ffb0908f72847ebbc05fad30f5b9db0dabd": {
        "workerSha256": "3ab3e187bb283090f1c7a8a363d5c9713608a416f49b95911830f579e5933a17",
        "workerBytes": 68214296,
    },
}
DEFAULT_GROUP = "a8a4689889a33c8edd0186ba64f5d65bd2a47e97"
DEFAULT_ACCOUNT = "24d9ae9df4c7ea35397804ed6168dc172cbb152b77c31dbf4f3823516d775fa9"
DEFAULT_WORKER = "5ea7c6c09205cc9b2c8473b515c67ffb0908f72847ebbc05fad30f5b9db0dabd"


def fail(message):
    raise SystemExit("g5-account-config: " + message)


def digest(path, maximum):
    value = hashlib.sha256()
    count = 0
    with open(path, "rb") as stream:
        while chunk := stream.read(1024 * 1024):
            count += len(chunk)
            if count > maximum:
                fail(f"file bound exceeded: {path}")
            value.update(chunk)
    return value.hexdigest()


def read_bounded(path, maximum):
    with open(path, "rb") as stream:
        data = stream.read(maximum + 1)
    if len(data) > maximum:
        fail(f"file bound exceeded: {path}")
    return data


def retained_root(argument):
    if argument:
        return Path(argument)
    # A cached CI job's own ARTIFACT_ROOT is <cache>/ccid-cached/<namespace>/release-artifacts;
    # cblc's retained area is its sibling namespace.
    own = os.environ.get("ARTIFACT_ROOT")
    if own and own.startswith("/"):
        return Path(own).parent.parent / CBLC_NAMESPACE / "release-artifacts"
    cache = os.environ.get("CI_CACHE_ROOT") or os.environ.get("CARGO_HOME")
    if not cache or not cache.startswith("/"):
        fail("pass --retained or set ARTIFACT_ROOT or an absolute CI_CACHE_ROOT/CARGO_HOME")
    return Path(cache) / "ccid-cached" / CBLC_NAMESPACE / "release-artifacts"


def artifact_files(directory, pin, circuit, keys, label):
    """Return the ArtifactFiles object after checking the independent pin."""
    manifest = directory / "manifest.json"
    if digest(manifest, 65536) != pin:
        fail(f"{label} manifest differs from its reviewed pin")
    return {
        "manifest_file": str(manifest),
        "manifest_sha256": list(bytes.fromhex(pin)),
        "circuit_file": str(directory / circuit),
        "keys_file": str(directory / keys),
        "srs_g1_file": str(directory / "setup" / "g1.dat"),
        "srs_g2_file": str(directory / "setup" / "g2.dat"),
    }


def write_private(path, data):
    path.write_bytes(data)
    path.chmod(0o600)


def settlement_files(out, community, day, key_file):
    """A fresh outcome-deposit epoch for UTC day `day` and its RSA-3072 key."""
    der = out / "outcome-key.der"
    if key_file:
        der_bytes = read_bounded(key_file, 16384)
    else:
        pem = subprocess.check_output(["openssl", "genrsa", "-traditional", "3072"], stderr=subprocess.DEVNULL)
        der_bytes = subprocess.run(
            ["openssl", "rsa", "-traditional", "-inform", "PEM", "-outform", "DER"],
            input=pem, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=True,
        ).stdout
    write_private(der, der_bytes)
    public = subprocess.run(
        ["openssl", "rsa", "-inform", "DER", "-pubout", "-outform", "DER"],
        input=der_bytes, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=True,
    ).stdout
    epoch = {
        "purpose": "outcome-deposit-v1", "community": community, "epoch": day,
        "valid_from": day * 86_400_000, "valid_until": (day + 1) * 86_400_000,
        "public_key_der": list(public),
    }
    epoch_file = out / "epoch.json"
    epoch_file.write_text(json.dumps(epoch))
    rooms = out / "rooms.json"
    rooms.write_text("[]")
    return epoch_file, der, rooms


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--community", required=True, choices=["alpha", "omega"])
    parser.add_argument("--out", required=True)
    parser.add_argument("--retained")
    parser.add_argument("--group", default=DEFAULT_GROUP)
    parser.add_argument("--account-capture", default=DEFAULT_ACCOUNT)
    parser.add_argument("--worker-capture", default=DEFAULT_WORKER)
    parser.add_argument("--now", type=int, help="UTC seconds that pick the settlement day (default: wall clock)")
    parser.add_argument("--operator-seed-file", help="production: 32-byte seed file (default: test seed [9;32])")
    parser.add_argument("--certificate-seed-file", help="production: 32-byte seed file (default: test seed [3;32])")
    parser.add_argument("--settlement-key-file", help="production: PKCS#1 DER RSA-3072 key")
    parser.add_argument("--exports", action="store_true", help="print shell exports for the CVLD_* variables")
    args = parser.parse_args()

    root = retained_root(args.retained)
    if args.group not in EXTENSION_GROUPS or args.account_capture not in ACCOUNT_CAPTURES \
            or args.worker_capture not in WORKER_CAPTURES:
        fail("artifact generation is not a reviewed pin")
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    out.chmod(0o700)

    # Extension group (circuits, keys, setup) and its activation probe.
    group = root / args.group / "artifact-conformance"
    index = json.loads(read_bounded(group / "index.json", 65536))
    group_pin = EXTENSION_GROUPS[args.group]["manifestSha256"]
    if index.get("manifestSha256") != group_pin:
        fail("retained index disagrees with the reviewed group pin")
    extension = artifact_files(group, group_pin, "circuits.json", "keys.json", "extension")
    entry = index["activations"].get(args.community)
    if entry is None:
        fail(f"no retained activation probe for {args.community}")
    probe_path = group / entry["file"]
    probe_bytes = read_bounded(probe_path, 4 * 1024 * 1024)
    probe_sha = hashlib.sha256(probe_bytes).hexdigest()
    if probe_sha != entry["sha256"]:
        fail("retained activation probe differs from its index entry")
    probe = json.loads(probe_bytes)
    if probe["use"] != f"{args.community}-startup-activation-probe" or probe["authority"] != "none" \
            or probe["communityId"] != args.community or probe["manifestSha256"] != group_pin:
        fail("activation probe association differs")
    request = probe["configuration"]
    policy = probe["policy"]
    if policy != request["accountPolicy"] or probe["extension"] != request["extensionPolicy"]:
        fail("activation probe policy differs from its request")
    now = args.now if args.now is not None else int(time.time())
    if args.community == "omega" and not policy["policyValidFrom"] <= now < policy["policyValidUntil"]:
        fail("the retained probe policy window does not cover the current time; regenerate the probe")

    # Account (base) artifacts from the write-once startup capture.
    capture = root / "native-startup-fixture-retained" / args.account_capture
    account_pin = ACCOUNT_CAPTURES[args.account_capture]["accountManifestSha256"]
    startup = json.loads(read_bounded(capture / "startup-artifacts.json", 65536))
    if startup["accountManifestSha256"] != account_pin:
        fail("startup capture disagrees with the reviewed account pin")
    account = artifact_files(capture / "account", account_pin, "circuit.json", "vk.bin", "account")

    # Native verifier worker from its immutable retained capture, never the live gather directory.
    workers = root / "gather-record-fixture-retained" / args.worker_capture
    expected = WORKER_CAPTURES[args.worker_capture]
    receipt = workers / "worker.json"
    if hashlib.sha256(read_bounded(receipt, 65536)).hexdigest() != args.worker_capture:
        fail("worker receipt differs from its capture digest")
    worker = workers / "worker"
    if worker.stat().st_size != expected["workerBytes"] or digest(worker, 512 * 1024 * 1024) != expected["workerSha256"]:
        fail("native verifier worker differs from its reviewed pin")
    for item in json.loads(receipt.read_bytes())["runtime"]["files"]:
        if not Path(item["path"]).is_file() or digest(item["path"], 512 * 1024 * 1024) != item["sha256"]:
            fail("native verifier runtime closure differs")
    execution = {
        "executable": str(worker), "timeout_ms": 120_000, "maximum_parallel": 2,
        "max_proof_bytes": 4 * 1024 * 1024, "threads": 2, "memory_megabytes": 4096,
    }

    # Per-run material.
    ledger = {
        "account": policy,
        "maxAuthorizationSeconds": request["nativeWrapper"]["maxAuthorizationSeconds"],
        "maxProofBytes": request["nativeWrapper"]["maxProofBytes"],
        "checkpointPeriodSeconds": request["nativeWrapper"]["checkpointPeriodSeconds"],
    }
    (out / "ledger-policy.json").write_text(json.dumps(ledger))
    # Hub-created communities prove their own activation against the template's terms, so
    # their rate window is free: two checkpoint periods (cvld refuses a rate window shorter than
    # twice the genesis proof window, and a grant lifetime shorter than the rate window). The static community
    # keeps the retained probe's policy, which its activation proof binds.
    # Only the omega probe feeds that template (toy stack, CVLD_G5_ACCOUNT_CONFIG mode; checkpoint
    # period 300 s). The alpha request has a 86400 s checkpoint period against abandonAfter 100, a
    # template the account policy would refuse (abandon_after >= rate_window, cwlt account/policy.rs),
    # and nothing consumes it there, so no template is derived or checked for alpha.
    if args.community == "omega":
        # Admission counts are per rate window: they scale with it, so the genesis rate per hour is unchanged.
        period = ledger["checkpointPeriodSeconds"]
        template_ledger = dict(ledger, account=dict(policy, rateWindow=2 * period,
            newcomerAdmissions=2 * policy["newcomerAdmissions"],
            maximumAdmissions=2 * policy["maximumAdmissions"]))
        if template_ledger["account"]["abandonAfter"] < template_ledger["account"]["rateWindow"]:
            fail("the template rate window exceeds abandonAfter")
        (out / "template-ledger-policy.json").write_text(json.dumps(template_ledger))
    (out / "extension-policy.json").write_text(json.dumps(probe["extension"]))
    (out / "activation-statement.json").write_text(json.dumps(probe["activation"]["account"]))
    (out / "activation-proof").write_bytes(bytes.fromhex(probe["activation"]["proof"]))
    (out / "activation-probe.json").write_bytes(probe_bytes)

    def seed(argument, fixture, name):
        path = out / name
        if argument:
            data = read_bounded(argument, 33)
            if len(data) != 32:
                fail(f"{name}: a seed file holds exactly 32 bytes")
            write_private(path, data)
        else:
            write_private(path, bytes([fixture]) * 32)
        return path

    operator = seed(args.operator_seed_file, 9, "operator-seed")
    certificate = seed(args.certificate_seed_file, 3, "certificate-seed")
    day = now // 86_400
    epoch_file, key_file, rooms_file = settlement_files(
        out, args.community, day, args.settlement_key_file
    )
    admission = bytes(request["independentAdmissionDigest"])
    if len(admission) != 32:
        fail("admission digest width")
    config = {
        "period_key": request["rulebook"]["periodKey"],
        "ledger_policy_file": str(out / "ledger-policy.json"),
        "extension_policy_file": str(out / "extension-policy.json"),
        "admission_policy_digest": base64.urlsafe_b64encode(admission).rstrip(b"=").decode(),
        "operator_seed_file": str(operator),
        "certificate_seed_file": str(certificate),
        "account_artifacts": account,
        "extension_artifacts": extension,
        "activation_statement_file": str(out / "activation-statement.json"),
        "activation_proof_file": str(out / "activation-proof"),
        "account_execution": execution,
        "update_execution": execution,
        "anonymous_execution": execution,
        "extension_limits": {"global_burst": 8, "subject_burst": 4, "replenish_ms": 1000, "maximum_keys": 1024},
        "enrollment": {"max_members": 64, "max_retained_slots": 8, "max_publication_bytes": 1024 * 1024},
        "settlement": {
            "quota_key": request["rulebook"]["quotaKey"], "epoch_file": str(epoch_file),
            "private_key_file": str(key_file), "room_epochs_file": str(rooms_file),
            "incarnation": f"g5-{args.community}-fixture", "pending_capacity": 8,
            "issuance_members_capacity": 8,
        },
        "max_request_bytes": 1024 * 1024,
    }
    (out / "account-config.json").write_text(json.dumps(config))
    summary = {
        "config": str(out / "account-config.json"), "probe": str(out / "activation-probe.json"),
        "probeSha256": base64.urlsafe_b64encode(hashlib.sha256(probe_bytes).digest()).rstrip(b"=").decode(),
        "community": args.community, "group": args.group,
    }
    if args.exports:
        print(f"export CVLD_G5_ACCOUNT_CONFIG={summary['config']}")
        print(f"export CVLD_ALPHA_ACTIVATION_PROBE={summary['probe']}")
        print(f"export CVLD_ALPHA_ACTIVATION_SHA256={summary['probeSha256']}")
    else:
        print(json.dumps(summary))


if __name__ == "__main__":
    sys.exit(main())
