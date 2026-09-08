import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const work = mkdtempSync(join(tmpdir(), 'cvld-consumer-'));
try {
  const destination = process.env.CVLD_RELEASE_DIR ? resolve(process.env.CVLD_RELEASE_DIR) : work;
  mkdirSync(destination, { recursive: true });
  const [packed] = JSON.parse(execFileSync('npm', ['pack', '--json', '--pack-destination', destination], { encoding: 'utf8' }));
  assert.equal(packed.name, '@corbet-labs/cvld');
  assert.equal(packed.version, '0.1.0-alpha.0');
  for (const file of packed.files) {
    assert.match(file.path, /^(package\.json|README\.md|LICENSE\.md|src\/[A-Za-z0-9._/-]+\.js|scripts\/install-native\.js)$/);
    assert.doesNotMatch(file.path, /(^|\/)(test|fixtures|node_modules|\.github)(\/|$)/);
  }
  const tarball = join(destination, packed.filename);
  const digest = createHash('sha256').update(readFileSync(tarball)).digest('hex');
  const consumer = join(work, 'consumer');
  mkdirSync(consumer);
  writeFileSync(join(consumer, 'package.json'), JSON.stringify({ private: true, type: 'module', dependencies: { '@corbet-labs/cvld': `file:${tarball}` } }));
  execFileSync('npm', ['install', '--ignore-scripts', '--no-audit', '--no-fund'], { cwd: consumer, stdio: 'inherit' });
  const manifest = JSON.parse(readFileSync(join(consumer, 'node_modules/@corbet-labs/cvld/package.json')));
  assert.equal(manifest.name, '@corbet-labs/cvld');
  assert.equal(manifest.private, false);
  assert.equal(manifest.publishConfig.tag, 'alpha');
  assert.equal(manifest.bin['cvld-install-native'], './scripts/install-native.js');
  for (const lifecycle of ['preinstall', 'install', 'postinstall', 'prepare']) assert.equal(manifest.scripts[lifecycle], undefined);
  // This is deliberately explicit. Installing the package above runs no scripts.
  execFileSync('npm', ['exec', '--offline', '--', 'cvld-install-native'], { cwd: consumer, stdio: 'inherit' });
  writeFileSync(join(consumer, 'smoke.mjs'), `
import assert from 'node:assert/strict';
import { createHolder } from '@corbet-labs/cvld';
import { verifyAdmission } from '@corbet-labs/cvld/admission';
import { createWallet, unlockWallet } from '@corbet-labs/cvld/client';
import { createPasskeyService } from '@corbet-labs/cvld/passkeys';
import { createSqliteState } from '@corbet-labs/cvld/storage';
assert.equal(typeof createHolder().present, 'function');
assert.equal(verifyAdmission({}), false);
assert.equal(typeof createPasskeyService, 'function');
const wallet = await createWallet({ prfOutput: new Uint8Array(32).fill(17), scope: 'consumer.example' });
const restored = await unlockWallet({ prfOutput: new Uint8Array(32).fill(17), scope: 'consumer.example', envelope: wallet.envelope });
assert.deepEqual(await restored.storageKey('cmsg'), await wallet.storageKey('cmsg'));
const state = createSqliteState({ path: ':memory:', maxReceipts: 10, maxCredentials: 10, busyTimeoutMs: 1000 });
state.close();
console.log('Actual packed consumer and every public subpath passed');
`);
  execFileSync(process.execPath, ['smoke.mjs'], { cwd: consumer, stdio: 'inherit' });
  if (process.env.CVLD_RELEASE_DIR) {
    writeFileSync(join(destination, 'SHA256SUMS'), `${digest}  ${packed.filename}\n`);
    writeFileSync(join(destination, 'pack-metadata.json'), JSON.stringify({ commit: process.env.GITHUB_SHA ?? null, sha256: digest, ...packed }, null, 2) + '\n');
  }
  console.log(`Verified release tarball SHA256: ${digest}  ${packed.filename}`);
} finally { rmSync(work, { recursive: true, force: true }); }
