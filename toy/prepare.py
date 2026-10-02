#!/usr/bin/env python3
"""Generate a test-only crate using precisely the door's dependency declarations."""
import json
import pathlib
import shutil
import tomllib

root = pathlib.Path(__file__).resolve().parents[1]
manifest = tomllib.loads((root / 'Cargo.toml').read_text())
build = root / 'toy' / '.build'
build.mkdir(exist_ok=True)
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
for name in ['cmty', 'cglb', 'ckyh', 'cpsd', 'csgn', 'cvch', 'ed25519-dalek',
             'serde', 'serde_json', 'tokio', 'tempfile', 'chrono', 'passkey', 'async-trait']:
    dependency = deps[name]
    if isinstance(dependency, dict):
        # The fixture explicitly uses these dependencies. The owner's optional
        # client/server feature split must not disable them in this separate crate.
        dependency = {key: val for key, val in dependency.items() if key != 'optional'}
    lines.append(f'{name} = {value(dependency)}')
lines.extend(['[profile.dev.package."*"]', 'opt-level = 3',
              '[profile.dev.package.cvld]', 'opt-level = 0',
              '[profile.dev.package.cvld-toy]', 'opt-level = 1'])
(build / 'Cargo.toml').write_text('\n'.join(lines) + '\n')
# Resolve the additional harness root against the already locked dependency closure.
shutil.copyfile(root / 'Cargo.lock', build / 'Cargo.lock')
