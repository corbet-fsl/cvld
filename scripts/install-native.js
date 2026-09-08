import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { createRequire } from 'node:module';

// npm integrity covers package tarballs; upstream's native download is separate.
if (process.platform !== 'linux' || process.arch !== 'x64') throw new Error('This experiment supports Linux x64 only');
const source = 'https://github.com/anoncreds/anoncreds-rs/releases/download/v0.2.3/library-linux-x86_64.tar.gz';
const expected = 'f54f262dd63422830ce15f3240b82ffb729c3159a225d42ddd9e948d6f5582c9';
const response = await fetch(source, { signal: AbortSignal.timeout(30_000) });
if (!response.ok) throw new Error('Native library download failed');
const bytes = Buffer.from(await response.arrayBuffer());
if (createHash('sha256').update(bytes).digest('hex') !== expected) throw new Error('Native library integrity check failed');
const work = await mkdtemp(join(tmpdir(), 'cvld-native-'));
try {
  const archive = join(work, 'library.tar.gz');
  const require = createRequire(import.meta.url);
  const destination = join(dirname(require.resolve('@hyperledger/anoncreds-nodejs/package.json')), 'native');
  await writeFile(archive, bytes);
  await mkdir(destination, { recursive: true });
  execFileSync('tar', ['--extract', '--gzip', '--file', archive, '--directory', destination, './libanoncreds.so'], { stdio: 'inherit' });
} finally { await rm(work, { recursive: true, force: true }); }
