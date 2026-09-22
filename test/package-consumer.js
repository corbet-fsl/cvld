// Package/import closure only. Real holder proofs run in the holder contract.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';

const work = mkdtempSync(join(tmpdir(), 'cvld-consumer-'));
const source = process.cwd(), sourceManifest = JSON.parse(readFileSync('package.json'));
const generated = ['cvld_holder.js', 'cvld_holder.d.ts', 'cvld_holder_bg.wasm', 'cvld_holder_bg.wasm.d.ts'];
const sha256 = value => createHash('sha256').update(value).digest('hex');
try {
  const destination = process.env.CVLD_RELEASE_DIR ? resolve(process.env.CVLD_RELEASE_DIR) : work;
  mkdirSync(destination, { recursive: true });
  for (const file of generated) assert(readFileSync(join('generated/holder', file)).length > 0, 'Generated holder assets required before packing');
  const [packed] = JSON.parse(execFileSync('npm', ['pack', '--ignore-scripts', '--json', '--pack-destination', destination], { encoding: 'utf8' }));
  assert.equal(packed.name, '@corbet-labs/cvld'); assert.equal(packed.version, '0.1.0-alpha.0');
  const names = new Set(packed.files.map(file => file.path));
  for (const file of names) {
    assert.match(file, /^(package\.json|README\.md|LICENSE\.md|src\/[A-Za-z0-9._/-]+\.js|scripts\/install-native\.js|generated\/holder\/cvld_holder(?:_bg\.wasm)?(?:\.js|\.d\.ts)?)$/);
    assert.doesNotMatch(file, /(^|\/)(test|fixtures|node_modules|\.github|native)(\/|$)/);
  }
  for (const path of Object.values(sourceManifest.exports)) { assert.equal(typeof path, 'string'); assert(names.has(path.slice(2)), 'Missing export ' + path); }
  for (const file of generated) assert(names.has('generated/holder/' + file));
  const tarball = join(destination, packed.filename), tarBytes = readFileSync(tarball);
  assert.equal('sha512-' + createHash('sha512').update(tarBytes).digest('base64'), packed.integrity);
  const consumer = join(work, 'consumer'); mkdirSync(consumer);
  const manifest = { name: 'cvld-packed-consumer', version: '0.0.0', private: true, type: 'module', dependencies: { '@corbet-labs/cvld': `file:${tarball}` } };
  writeFileSync(join(consumer, 'package.json'), JSON.stringify(manifest));
  // Reuse the committed dependency snapshot; never re-resolve transitive ranges.
  const lock = JSON.parse(readFileSync('package-lock.json'));
  assert.equal(lock.lockfileVersion, 3);
  lock.name = manifest.name; lock.version = manifest.version;
  lock.packages[''] = { name: manifest.name, version: manifest.version, dependencies: manifest.dependencies };
  lock.packages['node_modules/@corbet-labs/cvld'] = { version: packed.version, resolved: `file:${tarball}`, integrity: packed.integrity,
    dependencies: sourceManifest.dependencies, engines: sourceManifest.engines, bin: sourceManifest.bin };
  const lockBytes = JSON.stringify(lock, null, 2) + '\n';
  writeFileSync(join(consumer, 'package-lock.json'), lockBytes);
  execFileSync('npm', ['ci', '--ignore-scripts', '--no-audit', '--no-fund'], { cwd: consumer, stdio: 'inherit' });
  assert.equal(readFileSync(join(consumer, 'package-lock.json'), 'utf8'), lockBytes);
  const installed = join(consumer, 'node_modules/@corbet-labs/cvld');
  assert.deepEqual(readFileSync(join(installed, 'LICENSE.md')), readFileSync('LICENSE.md'));
  const assetHashes = {};
  for (const file of generated) {
    const path = 'generated/holder/' + file;
    assert.deepEqual(readFileSync(join(installed, path)), readFileSync(join(source, path)));
    assetHashes[path] = sha256(readFileSync(join(installed, path)));
  }
  for (const path of names) if (path.endsWith('.js')) {
    const text = readFileSync(join(installed, path), 'utf8');
    for (const match of text.matchAll(/(?:from\s*|import\s*\(|import\s*)['"]([^'"]+)['"]/g)) {
      if (!match[1].startsWith('.')) continue;
      const target = resolve(installed, dirname(path), match[1]);
      assert(target.startsWith(installed + '/'), 'Relative import escapes package');
      assert(names.has(target.slice(installed.length + 1)), 'Missing relative import ' + match[1]);
    }
  }
  execFileSync('npm', ['exec', '--offline', '--', 'cvld-install-native'], { cwd: consumer, stdio: 'inherit' });
  writeFileSync(join(consumer, 'worker-import.mjs'), `
import assert from 'node:assert/strict';
import { parentPort } from 'node:worker_threads';
globalThis.self = {};
await import('@corbet-labs/cvld/holder-worker');
assert.equal(typeof self.onmessage, 'function');
parentPort.postMessage('holder worker import closure passed');
`);
  writeFileSync(join(consumer, 'smoke.mjs'), `
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { Worker } from 'node:worker_threads';
const manifest = JSON.parse(await readFile(new URL('./node_modules/@corbet-labs/cvld/package.json', import.meta.url)));
for (const name of Object.keys(manifest.exports)) {
  const specifier = '@corbet-labs/cvld' + (name === '.' ? '' : name.slice(1));
  if (name === './holder-worker') continue;
  if (name === './holder-wasm-binary') { assert(WebAssembly.validate(await readFile(new URL(import.meta.resolve(specifier))))); continue; }
  const module = await import(specifier); assert(Object.keys(module).length > 0, specifier);
}
const worker = new Worker(new URL('./worker-import.mjs', import.meta.url));
try { await new Promise((resolve, reject) => { worker.once('message', resolve); worker.once('error', reject); worker.once('exit', code => { if (code !== 0) reject(new Error('Worker import failed')); }); }); }
finally { await worker.terminate(); }
console.log('Every packed cvld JavaScript export imports; holder Worker closure and Wasm bytes validate without proving');
`);
  execFileSync(process.execPath, ['smoke.mjs'], { cwd: consumer, stdio: 'inherit', timeout: 60_000 });
  if (process.env.CVLD_RELEASE_DIR) {
    writeFileSync(join(destination, 'pack-metadata.json'), JSON.stringify({ commit: process.env.GITHUB_SHA ?? null, sha256: sha256(tarBytes),
      assetHashes, exportPaths: sourceManifest.exports, dependencyLockSha256: sha256(readFileSync('package-lock.json')), ...packed }, null, 2) + '\n');
  }
  console.log(`Verified complete cvld archive SHA256: ${sha256(tarBytes)}  ${packed.filename}`);
} finally { rmSync(work, { recursive: true, force: true }); }
