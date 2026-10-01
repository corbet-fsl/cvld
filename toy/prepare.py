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
deps = manifest['dependencies'] | manifest['dev-dependencies']
for name in ['cmty', 'cglb', 'ckyh', 'cpsd', 'csgn', 'cvch', 'ed25519-dalek',
             'serde', 'serde_json', 'tokio', 'tempfile', 'chrono', 'passkey', 'async-trait']:
    lines.append(f'{name} = {value(deps[name])}')
lines.extend(['[profile.dev.package."*"]', 'opt-level = 3',
              '[profile.dev.package.cvld]', 'opt-level = 0',
              '[profile.dev.package.cvld-toy]', 'opt-level = 1'])
(build / 'Cargo.toml').write_text('\n'.join(lines) + '\n')
# Resolve the additional harness root against the already locked dependency closure.
shutil.copyfile(root / 'Cargo.lock', build / 'Cargo.lock')
