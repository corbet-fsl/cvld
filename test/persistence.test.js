import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createSqliteState } from '../src/index.js';
import { NOW } from './fixtures.js';

function opened(path) { return createSqliteState({ path, maxReceipts: 100, maxCredentials: 100, busyTimeoutMs: 5000 }); }

test('atomic issuance persists one result across duplicate attempts and restart', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'cvld-state-'));
  let state;
  try {
    const path = join(directory, 'state.sqlite');
    state = opened(path);
    const input = { operationId: 'operation', receipts: [{ id: 'receipt', expiresAt: NOW + 100 }], resultExpiresAt: NOW + 50, now: NOW };
    let count = 0;
    const produce = () => ({ serial: ++count });
    const first = await state.receipts.issueOnce(input, produce);
    const second = await state.receipts.issueOnce(input, produce);
    assert.deepEqual(first, second);
    assert.equal(count, 1);
    state.close();
    state = opened(path);
    assert.deepEqual(await state.receipts.issueOnce(input, produce), first);
    assert.equal(count, 1);
    await assert.rejects(state.receipts.issueOnce({ ...input, operationId: 'other' }, produce));
  } finally { state?.close(); rmSync(directory, { recursive: true, force: true }); }
});

test('signing failure rolls back receipt consumption and permits a legitimate retry', async () => {
  const state = opened(':memory:');
  try {
    const input = { operationId: 'operation', receipts: [{ id: 'receipt', expiresAt: NOW + 100 }], resultExpiresAt: NOW + 50, now: NOW };
    await assert.rejects(state.receipts.issueOnce(input, () => { throw new Error('synthetic signing failure'); }));
    assert.deepEqual(await state.receipts.issueOnce(input, () => ({ credential: 'synthetic' })), { credential: 'synthetic' });
  } finally { state.close(); }
});

test('independent SQLite worker connections agree on one atomic issuance result', async () => {
  const { Worker } = await import('node:worker_threads');
  const { once } = await import('node:events');
  const directory = mkdtempSync(join(tmpdir(), 'cvld-race-'));
  const path = join(directory, 'state.sqlite');
  const input = { operationId: 'concurrent-operation', receipts: [{ id: 'concurrent-receipt', expiresAt: NOW + 100 }], resultExpiresAt: NOW + 50, now: NOW };
  const initialized = opened(path); initialized.close();
  const workers = [];
  try {
    for (let serial = 0; serial < 4; serial++) workers.push(new Worker(new URL('./sqlite-worker.js', import.meta.url), { workerData: { path, input, serial } }));
    await Promise.all(workers.map((worker) => once(worker, 'message')));
    const results = workers.map((worker) => once(worker, 'message'));
    for (const worker of workers) worker.postMessage('start');
    const values = await Promise.all(results);
    for (const [result] of values) { assert.equal(result.error, undefined); assert.deepEqual(result.value, values[0][0].value); }
  } finally { await Promise.all(workers.map((worker) => worker.terminate())); rmSync(directory, { recursive: true, force: true }); }
});

test('registered account ownership and monotonic counters survive SQLite restart', () => {
  const directory = mkdtempSync(join(tmpdir(), 'cvld-credential-'));
  const path = join(directory, 'state.sqlite');
  let state = opened(path);
  try {
    const credential = { id: 'credential', publicKey: new Uint8Array([1, 2, 3]), counter: 0, transports: ['internal'] };
    assert.equal(state.credentials.insert('community.example', 'member', credential, 2), true);
    assert.equal(state.credentials.updateCounter('community.example', 'credential', 3), true);
    state.close(); state = opened(path);
    assert.equal(state.credentials.get('community.example', 'credential').memberId, 'member');
    assert.equal(state.credentials.get('community.example', 'credential').counter, 3);
    assert.equal(state.credentials.get('another.example', 'credential'), undefined);
    assert.equal(state.credentials.updateCounter('community.example', 'credential', 0), false);
    assert.equal(state.credentials.insert('community.example', 'impostor', credential, 2), false);
  } finally { state.close(); rmSync(directory, { recursive: true, force: true }); }
});
