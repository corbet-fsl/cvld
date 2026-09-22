import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { createClient } from '@libsql/client';
import { createTursoState } from '../src/turso.js';
import { createTursoApiKeyService } from '../src/api-keys-turso.js';

async function exercise(state) {
  const communityId = `cvld-test-${randomBytes(12).toString('hex')}`;
  const memberId = randomBytes(32).toString('base64url');
  const credential = { id: randomBytes(16).toString('base64url'), publicKey: randomBytes(32), counter: 0, transports: [] };
  const receiptId = randomBytes(32).toString('hex');
  assert.equal(await state.members.registerWithVoucher({
    communityId, memberId, chatPublicKey: randomBytes(32).toString('base64url'),
    authorization: { version: 1 }, receiptId, memberBinding: randomBytes(32).toString('hex'),
    validUntil: 1_001_000, now: 1_000_000, credential, maxPerMember: 4,
  }), true);
  assert.equal(await state.members.registerWithVoucher({
    communityId, memberId: randomBytes(32).toString('base64url'), chatPublicKey: randomBytes(32).toString('base64url'),
    authorization: { version: 1 }, receiptId, memberBinding: randomBytes(32).toString('hex'),
    validUntil: 1_001_000, now: 1_000_000, credential: { ...credential, id: randomBytes(16).toString('base64url') }, maxPerMember: 4,
  }), false);
  assert.equal(await state.credentials.updateCounter(communityId, credential.id, 4), true);
  assert.equal(await state.credentials.updateCounter(communityId, credential.id, 4), false);
  const op = randomBytes(32).toString('hex');
  const request = { operationId: op, receipts: [{ id: randomBytes(32).toString('hex'), expiresAt: 1_001_000 }], resultExpiresAt: 1_001_000, now: 1_000_000 };
  assert.deepEqual(await state.receipts.issueOnce(request, () => ({ ok: true })), { ok: true });
  assert.deepEqual(await state.receipts.issueOnce(request, () => { throw new Error('replay must not produce'); }), { ok: true });
}

test('Turso adapter runs against the supported local-file SDK client', async () => {
  const directory = mkdtempSync(join(process.env.TMPDIR ?? '/tmp', 'cvld-turso-'));
  const client = createClient({ url: `file:${join(directory, 'state.db')}` });
  const state = await createTursoState({ client, maxReceipts: 16, maxCredentials: 16, maxVoucherSpends: 16, clock: () => 1_000_000 });
  try { await exercise(state); } finally { await state.close(); await client.close(); rmSync(directory, { recursive: true, force: true }); }
});

test('Turso registration rolls back all rows when the final credential insert fails', async () => {
  const directory = mkdtempSync(join(process.env.TMPDIR ?? '/tmp', 'cvld-turso-'));
  const base = createClient({ url: `file:${join(directory, 'state.db')}` });
  let failCredentialInsert = true;
  const client = {
    batch: (...args) => base.batch(...args),
    execute: (...args) => base.execute(...args),
    transaction: async mode => {
      const transaction = await base.transaction(mode);
      return {
        execute: statement => {
          if (failCredentialInsert && typeof statement === 'object' && statement.sql?.startsWith('INSERT INTO credentials (community_id')) {
            failCredentialInsert = false;
            return Promise.reject(new Error('injected credential write failure'));
          }
          return transaction.execute(statement);
        },
        commit: () => transaction.commit(),
        rollback: () => transaction.rollback(),
        close: () => typeof transaction.close === 'function' ? transaction.close() : undefined,
      };
    },
  };
  const state = await createTursoState({ client, maxReceipts: 16, maxCredentials: 16, maxVoucherSpends: 16, clock: () => 1_000_000 });
  const communityId = `rollback-${randomBytes(8).toString('hex')}`;
  const memberId = randomBytes(32).toString('base64url');
  try {
    await assert.rejects(state.members.registerWithVoucher({
      communityId, memberId, chatPublicKey: randomBytes(32).toString('base64url'), authorization: { version: 1 },
      receiptId: randomBytes(32).toString('hex'), memberBinding: randomBytes(32).toString('hex'), validUntil: 1_001_000, now: 1_000_000,
      credential: { id: randomBytes(16).toString('base64url'), publicKey: randomBytes(32), counter: 0, transports: [] }, maxPerMember: 4,
    }));
    const rows = await base.execute({ sql: 'SELECT (SELECT count(*) FROM voucher_spends WHERE community_id = ?) AS spends, (SELECT count(*) FROM members WHERE community_id = ?) AS members, (SELECT count(*) FROM credentials WHERE community_id = ?) AS credentials', args: [communityId, communityId, communityId] });
    assert.equal(Number(rows.rows[0].spends), 0);
    assert.equal(Number(rows.rows[0].members), 0);
    assert.equal(Number(rows.rows[0].credentials), 0);
  } finally { await state.close(); await base.close(); rmSync(directory, { recursive: true, force: true }); }
});

test('Turso API keys persist only digests and survive reopen, scope, revoke, and expiry checks', async () => {
  const directory = mkdtempSync(join(process.env.TMPDIR ?? '/tmp', 'cvld-turso-'));
  const path = join(directory, 'state.db');
  let now = 1_000_000;
  const communityId = `keys-${randomBytes(8).toString('hex')}`;
  const memberId = randomBytes(32).toString('base64url');
  const options = { communityId, maxKeys: 8, maxKeysPerMember: 4, maxLifetimeSeconds: 100, allowedScopes: ['discovery:read', 'credentials:issue'], clock: () => now };
  const client = createClient({ url: `file:${path}` });
  const service = await createTursoApiKeyService({ ...options, client });
  try {
    const durable = await service.create({ memberId, name: 'durable', scopes: ['discovery:read'], expiresAt: now + 50 });
    assert.equal((await service.authenticate(durable.token, 'discovery:read')).memberId, memberId);
    assert.equal(await service.authenticate(durable.token, 'credentials:issue'), false);
    const stored = await client.execute({ sql: 'SELECT digest, scopes FROM cvld_api_keys WHERE community = ? AND id = ?', args: [communityId, durable.id] });
    assert.equal(Buffer.from(stored.rows[0].digest).length, 32);
    assert.notEqual(Buffer.from(stored.rows[0].digest).toString('utf8'), durable.token);
    assert.deepEqual(JSON.parse(stored.rows[0].scopes), ['discovery:read']);
    const expiring = await service.create({ memberId, name: 'short', scopes: ['credentials:issue'], expiresAt: now + 1 });
    now += 2;
    assert.equal(await service.authenticate(expiring.token, 'credentials:issue'), false);
    assert.deepEqual((await service.list(memberId)).map(key => key.id), [durable.id]);
    assert.equal(await service.revoke({ memberId, id: durable.id }), true);
    assert.equal(await service.revoke({ memberId, id: durable.id }), false);
  } finally { await service.close(); await client.close(); }
  const reopenedClient = createClient({ url: `file:${path}` });
  const reopened = await createTursoApiKeyService({ ...options, client: reopenedClient });
  try { assert.deepEqual(await reopened.list(memberId), []); } finally { await reopened.close(); await reopenedClient.close(); rmSync(directory, { recursive: true, force: true }); }
});

test('Turso receipt idempotency survives a lost successful commit response and reopen', async () => {
  const directory = mkdtempSync(join(process.env.TMPDIR ?? '/tmp', 'cvld-turso-'));
  const path = join(directory, 'state.db');
  const request = { operationId: randomBytes(32).toString('hex'), receipts: [{ id: randomBytes(32).toString('hex'), expiresAt: 1_001_000 }], resultExpiresAt: 1_001_000, now: 1_000_000 };
  const client = createClient({ url: `file:${path}` });
  let loseCommit = true;
  const uncertain = new Proxy(client, { get(target, name) {
    if (name === 'transaction') return async mode => {
      const tx = await target.transaction(mode);
      return new Proxy(tx, { get(transaction, key) {
        if (key === 'commit') return async () => {
          await transaction.commit();
          if (loseCommit) { loseCommit = false; throw new Error('Committed response lost'); }
        };
        const value = transaction[key];
        return typeof value === 'function' ? value.bind(transaction) : value;
      } });
    };
    const value = target[name];
    return typeof value === 'function' ? value.bind(target) : value;
  } });
  const state = await createTursoState({ client: uncertain, maxReceipts: 16, maxCredentials: 16, maxVoucherSpends: 16, clock: () => 1_000_000 });
  try {
    await assert.rejects(state.receipts.issueOnce(request, () => ({ committed: true })), /Committed response lost/);
    await assert.rejects(state.receipts.issueOnce(request, () => { throw new Error('must reopen'); }), /retired/);
  }
  finally { await state.close(); await client.close(); }
  const reopenedClient = createClient({ url: `file:${path}` });
  const reopened = await createTursoState({ client: reopenedClient, maxReceipts: 16, maxCredentials: 16, maxVoucherSpends: 16, clock: () => 1_000_000 });
  try { assert.deepEqual(await reopened.receipts.issueOnce(request, () => { throw new Error('replay must not produce'); }), { committed: true }); }
  finally { await reopened.close(); await reopenedClient.close(); rmSync(directory, { recursive: true, force: true }); }
});

// This opt-in remote test uses a dedicated random community and never runs
// against a developer's database by accident.
const enabled = process.env.CVLD_TURSO_TEST === '1' && Boolean(process.env.TURSO_DATABASE_URL && process.env.TURSO_AUTH_TOKEN);

test('Turso durable receipt, voucher/member, and counter boundaries', { skip: !enabled }, async () => {
  const state = await createTursoState({
    url: process.env.TURSO_DATABASE_URL,
    authToken: process.env.TURSO_AUTH_TOKEN,
    maxReceipts: 16,
    maxCredentials: 16,
    maxVoucherSpends: 16,
    clock: () => 1_000_000,
    networkTimeoutMs: 15_000,
  });
  try { await exercise(state); } finally { await state.close(); }
});
