#!/usr/bin/env python3
"""Generate a test-only crate using precisely the door's dependency declarations."""
import json
import pathlib
import shutil
import sys
import tomllib

root = pathlib.Path(__file__).resolve().parents[1]
manifest = tomllib.loads((root / 'Cargo.toml').read_text())
build = root / 'toy' / '.build'
def value(v):
    if isinstance(v, dict):
        return '{ ' + ', '.join(f'{k} = {value(x)}' for k, x in v.items()) + ' }'
    return json.dumps(v)
lines = ['[package]', 'name = "cvld-toy"', 'version = "0.0.0"',
         'edition = "2024"', 'publish = false', '[workspace]',
         '[[bin]]', 'name = "cvld-toy"', 'path = "../src/main.rs"', '[dependencies]']
lines.append('cvld = { path = "../..", features = ["development-gate"] }')
# The toy runs natively; its authenticator and storage fixtures follow the
# owner's native-only development dependencies after the browser feature split.
deps = (manifest['dependencies'] | manifest.get('dev-dependencies', {})
        | manifest['target']['cfg(not(target_arch = "wasm32"))']['dev-dependencies'])
for name in ['cmty', 'cgbl', 'ckyh', 'cpsd', 'csgn', 'cvch', 'ed25519-dalek',
             'serde', 'serde_json', 'tokio', 'tempfile', 'chrono', 'passkey', 'async-trait', 'webauthn-authenticator-rs']:
    dependency = deps[name]
    if isinstance(dependency, dict):
        # The fixture explicitly uses these dependencies. The owner's optional
        # client/server feature split must not disable them in this separate crate.
        dependency = {key: val for key, val in dependency.items() if key != 'optional'}
    lines.append(f'{name} = {value(dependency)}')
lines.extend(['[profile.dev.package."*"]', 'opt-level = 3',
              '[profile.dev.package.cvld]', 'opt-level = 0',
              '[profile.dev.package.cvld-toy]', 'opt-level = 1'])
generated = '\n'.join(lines) + '\n'
if sys.argv[1:] == ['--check']:
    # The full CI resolver already derived this graph before freezing its source.
    # Checking it must never overwrite the candidate lock with the root seed.
    if (build / 'Cargo.toml').read_text() != generated:
        raise SystemExit('Frozen toy manifest differs from the owner declarations')
    key = lambda package: (package['name'], package['version'], package.get('source'))
    seed = tomllib.loads((root / 'Cargo.lock').read_text())['package']
    candidate = tomllib.loads((build / 'Cargo.lock').read_text())['package']
    if not {key(package) for package in seed} <= {key(package) for package in candidate}:
        raise SystemExit('Frozen toy lock changed the root dependency seed')
elif not sys.argv[1:]:
    build.mkdir(exist_ok=True)
    (build / 'Cargo.toml').write_text(generated)
    # The resolver adds the harness root before the build consumes --locked.
    shutil.copyfile(root / 'Cargo.lock', build / 'Cargo.lock')
else:
    raise SystemExit('usage: toy/prepare.py [--check]')
