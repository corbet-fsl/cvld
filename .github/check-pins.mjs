import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';

const corbetSource = /^git\+https:\/\/github\.com\/(?:corbet-(?:foss|libs)|cmtymeet)\//;

function checkSource(source, resolved) {
  const url = new URL(source.slice(4));
  const main = url.searchParams.toString() === 'branch=main';
  if (!main || (resolved && !/^#[a-f0-9]{40}$/.test(url.hash))) {
    throw new Error(`Expected main and a complete resolved revision: ${source}`);
  }
}

export function checkPins(metadata, required = ['crlt']) {
  const names = new Set(required);
  for (const pkg of metadata.packages) {
    if (corbetSource.test(pkg.source ?? '')) {
      names.add(pkg.name);
      checkSource(pkg.source, true);
    }
    // Inspect upstream selectors too; each repository enforces its own main declarations.
    for (const dependency of pkg.dependencies) {
      if (corbetSource.test(dependency.source ?? '')) {
        checkSource(dependency.source, false);
      }
    }
  }
  for (const name of names) {
    const packages = metadata.packages.filter(pkg => pkg.name === name);
    if (packages.length !== 1 || !corbetSource.test(packages[0].source ?? '')) {
      throw new Error(`Missing, invalid or duplicated Corbet dependency: ${name}`);
    }
  }
}

export function checkBrowser(metadata, root) {
  checkPins(metadata, []);
  const owners = metadata.packages.filter(pkg => pkg.name === 'cvld');
  if (owners.length !== 1 || owners[0].source !== null
      || resolve(owners[0].manifest_path) !== resolve(root, 'Cargo.toml')) {
    throw new Error('Browser must exercise the exact local production cvld source');
  }
  const owner = metadata.resolve.nodes.find(node => node.id === owners[0].id);
  if (!owner?.features.includes('client-browser')
      || owner.features.some(feature => ['server', 'client-http', 'development-gate'].includes(feature))) {
    throw new Error('Browser consumer must resolve only the portable owner client');
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const metadata = JSON.parse(readFileSync(process.argv[2], 'utf8'));
  if (process.argv[3] === '--browser') checkBrowser(metadata, process.cwd());
  else checkPins(metadata);
  console.log('Corbet dependencies resolve once each to a complete source revision');
}
