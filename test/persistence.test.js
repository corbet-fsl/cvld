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
