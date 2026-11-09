#!/usr/bin/env python3
"""Require every package of the client's derived lock to equal this repository's lock entry.

Usage: client-lock.py client/Cargo.lock Cargo.lock. The client lock starts as a copy of the root
lock; cargo may only drop entries the client does not use. Any new or changed entry (a version,
source or checksum the root lock does not pin) fails; the per-package dependency lists are not
compared (cargo shortens "name version" to "name" once a version is unique). Silent on success."""
import sys
import tomllib


def entries(path):
    with open(path, 'rb') as f:
        packages = tomllib.load(f).get('package', [])
    return {
        (p['name'], p['version'], p.get('source', '')): p.get('checksum')
        for p in packages
    }


def main(client, root):
    ours, theirs = entries(client), entries(root)
    bad = sorted(k for k, v in ours.items() if k not in theirs or theirs[k] != v)
    if bad:
        for name, version, source in bad:
            print(f'client-lock: {name} {version} {source or "(path)"} is not pinned identically by the root lock', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main(*sys.argv[1:]))
