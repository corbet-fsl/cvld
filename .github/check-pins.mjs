import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';

const corbetSource = /^git\+https:\/\/(?:github\.com|git\.corbet\.ch)\/(?:corbet-(?:foss|libs)|cmtymeet)\//;

function checkSource(source, resolved, name, issuers) {
  const issuer = issuers.get(name);
  if (issuer && source === (resolved ? issuer.resolved : issuer.declaration)) return;
  const url = new URL(source.slice(4));
  const main = url.searchParams.toString() === 'branch=main';
  if (!main || (resolved && !/^#[a-f0-9]{40}$/.test(url.hash))) {
    throw new Error(`Expected main and a complete resolved revision: ${source}`);
  }
}

export function checkPins(metadata) {
  // Keep original issuer policy in the resolved-lock validator. The existing
  // metadata checks still enforce all main selectors and singleton identities.
  const policy = fileURLToPath(new URL('./check-first-party.py', import.meta.url));
  const issuers = new Map(JSON.parse(execFileSync('python3', [policy, '--metadata-issuers'], {
    input: JSON.stringify(metadata), encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'],
  })).map(issuer => [issuer.name, issuer]));
  const names = new Set(['crlt']);
  for (const pkg of metadata.packages) {
    if (corbetSource.test(pkg.source ?? '') || issuers.has(pkg.name)) {
      names.add(pkg.name);
      checkSource(pkg.source, true, pkg.name, issuers);
    }
    // Inspect upstream selectors too; each repository enforces its own main declarations.
    for (const dependency of pkg.dependencies) {
      if (corbetSource.test(dependency.source ?? '')) {
        checkSource(dependency.source, false, dependency.name, issuers);
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

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  checkPins(JSON.parse(readFileSync(process.argv[2], 'utf8')));
  console.log('Corbet dependencies resolve once each to a complete source revision');
}
