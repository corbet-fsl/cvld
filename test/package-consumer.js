import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const work = mkdtempSync(join(tmpdir(), 'cvld-consumer-'));
try {
  const packed = JSON.parse(execFileSync('npm', ['pack', '--json', '--pack-destination', work], { encoding: 'utf8' }));
  const consumer = join(work, 'consumer');
  mkdirSync(consumer);
  writeFileSync(join(consumer, 'package.json'), JSON.stringify({ private: true, type: 'module', dependencies: { cvld: `file:${join(work, packed[0].filename)}` } }));
  execFileSync('npm', ['install', '--ignore-scripts', '--no-audit', '--no-fund'], { cwd: consumer, stdio: 'inherit' });
  execFileSync(process.execPath, ['node_modules/cvld/scripts/install-native.js'], { cwd: consumer, stdio: 'inherit' });
  const output = execFileSync(process.execPath, ['--input-type=module', '-e', "import {createHolder} from 'cvld'; import {verifyAdmission} from 'cvld/admission'; import {createWallet} from 'cvld/client'; if(typeof verifyAdmission!=='function'||typeof createWallet!=='function') process.exit(1); if(typeof createHolder().present!=='function') process.exit(1); console.log('packed consumer works')"], { cwd: consumer, encoding: 'utf8' });
  assert.match(output, /packed consumer works/);
} finally { rmSync(work, { recursive: true, force: true }); }
