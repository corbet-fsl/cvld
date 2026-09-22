// Durable libSQL/Turso state.  This is deliberately asynchronous: the remote
// client is promise based, and every operation that spans more than one table
// uses the same write transaction handle.
import { createClient } from '@libsql/client/http';
import { checkCredential } from './credential-store.js';
import { publicBytes } from './admission.js';
import { requireClock, requirePositive, requireText } from './encoding.js';

const MAX_JSON = 4096;

function blob(value) {
  return value instanceof Uint8Array ? new Uint8Array(value) : new Uint8Array(Buffer.from(value));
}
function count(result) { return Number(result.rows[0]?.n ?? 0); }
function isConstraint(error) { return /constraint|unique/i.test(String(error?.message ?? error)); }
function boundedFetch(baseFetch, timeoutMs) {
  return async (input, init = {}) => {
    const signals = [AbortSignal.timeout(timeoutMs)];
    if (init.signal) signals.push(init.signal);
    const signal = AbortSignal.any(signals);
    return baseFetch(input, { ...init, signal });
  };
}

function validateRemoteUrl(value) {
  let url;
  try { url = new URL(value); } catch { throw new TypeError('Invalid Turso URL'); }
  if (!['https:', 'libsql:'].includes(url.protocol) || !url.hostname || url.username || url.password || url.search || url.hash) throw new TypeError('Invalid Turso URL');
}
function credentialRow(row) {
  return row && {
    id: row.id,
    memberId: row.member_id,
    communityId: row.community_id,
    publicKey: blob(row.public_key),
    counter: Number(row.counter),
    transports: JSON.parse(row.transports),
  };
}
function memberRow(row) {
  return row && {
    communityId: row.community_id,
    memberId: row.member_id,
    chatPublicKey: row.chat_public_key,
    authorization: JSON.parse(row.device_authorization),
    voucherReceiptId: row.voucher_receipt_id,
    voucherValidUntil: Number(row.voucher_valid_until),
  };
}

const SCHEMA = [
  `CREATE TABLE IF NOT EXISTS receipts (id TEXT PRIMARY KEY, expires_at INTEGER NOT NULL) STRICT`,
  `CREATE TABLE IF NOT EXISTS issuances (id TEXT PRIMARY KEY, expires_at INTEGER NOT NULL, result TEXT NOT NULL) STRICT`,
  `CREATE TABLE IF NOT EXISTS credentials (
    community_id TEXT NOT NULL, id TEXT NOT NULL, member_id TEXT NOT NULL,
    public_key BLOB NOT NULL, counter INTEGER NOT NULL, transports TEXT NOT NULL,
    PRIMARY KEY (community_id, id)
  ) STRICT`,
  `CREATE TABLE IF NOT EXISTS voucher_spends (
    receipt_id TEXT PRIMARY KEY, community_id TEXT NOT NULL, member_id TEXT NOT NULL,
    member_binding TEXT NOT NULL, expires_at INTEGER NOT NULL
  ) STRICT`,
  `CREATE TABLE IF NOT EXISTS members (
    community_id TEXT NOT NULL, member_id TEXT NOT NULL, chat_public_key TEXT NOT NULL,
    device_authorization TEXT NOT NULL, voucher_receipt_id TEXT NOT NULL,
    PRIMARY KEY (community_id, member_id)
  ) STRICT`,
];

function validateClientOptions(options) {
  if (!options.client) {
    requireText(options.url, 'Turso URL');
    requireText(options.authToken, 'Turso auth token');
    validateRemoteUrl(options.url);
    if (typeof (options.fetch ?? globalThis.fetch) !== 'function') throw new TypeError('Fetch implementation required');
  }
  requirePositive(options.maxReceipts, 'receipt capacity');
  requirePositive(options.maxCredentials, 'credential capacity');
  requirePositive(options.maxVoucherSpends, 'voucher spend capacity');
  requireClock(options.clock)();
  if (!options.client && requirePositive(options.networkTimeoutMs, 'Turso network timeout') > 60_000) throw new TypeError('Turso network timeout exceeds limit');
}

/**
 * Open and initialize the durable cvld state.  The returned repositories have
 * the same method names as createSqliteState, but methods are asynchronous.
 * `client` is accepted only for trusted server composition and is not exposed
 * in the returned object.
 */
export async function createTursoState(options) {
  validateClientOptions(options);
  const client = options.client ?? createClient({
    url: options.url,
    authToken: options.authToken,
    fetch: boundedFetch(options.fetch ?? globalThis.fetch, options.networkTimeoutMs),
  });
  const ownsClient = !options.client;
  if (!client || typeof client.batch !== 'function' || typeof client.execute !== 'function' || typeof client.transaction !== 'function') throw new TypeError('libSQL client required');
  try { await client.batch(SCHEMA, 'write'); }
  catch (error) {
    if (ownsClient && typeof client.close === 'function') { try { await client.close(); } catch { /* preserve initialization failure */ } }
    throw error;
  }
  const maxReceipts = options.maxReceipts;
  const maxCredentials = options.maxCredentials;
  const maxVoucherSpends = options.maxVoucherSpends;
  const clock = requireClock(options.clock);
  let retired = false;
  function ensureUsable() { if (retired) throw new Error('Turso state retired after ambiguous transaction; reopen required'); }

  async function transaction(work) {
    ensureUsable();
    const tx = await client.transaction('write');
    let commitAttempted = false;
    try {
      const result = await work(tx);
      commitAttempted = true;
      await tx.commit();
      return result;
    } catch (error) {
      if (!commitAttempted) {
        try { await tx.rollback(); } catch { retired = true; }
      } else {
        retired = true;
      }
      throw error;
    } finally {
      if (typeof tx.close === 'function') { try { await tx.close(); } catch { /* never mask the result */ } }
    }
  }
  async function one(handle, sql, args = []) {
    const result = await handle.execute({ sql, args });
    return result.rows[0];
  }
  function json(value, label) {
    let encoded;
    try { encoded = JSON.stringify(value); } catch { throw new TypeError(`Invalid ${label}`); }
    if (typeof encoded !== 'string' || Buffer.byteLength(encoded) > MAX_JSON) throw new TypeError(`Invalid ${label}`);
    return encoded;
  }

  const state = {
    get healthy() { return !retired; },
    async close() {
      retired = true;
      if (ownsClient && typeof client.close === 'function') await client.close();
    },
    receipts: {
      async issueOnce({ operationId, receipts, resultExpiresAt, now }, produce) {
        ensureUsable();
        receipts = structuredClone(receipts);
        requireText(operationId, 'issuance ID'); requirePositive(resultExpiresAt, 'result expiry'); requirePositive(now, 'clock');
        if (!Array.isArray(receipts) || receipts.length < 1 || new Set(receipts.map((r) => r.id)).size !== receipts.length || resultExpiresAt <= now) throw new Error('Invalid issuance transaction');
        for (const receipt of receipts) {
          requireText(receipt.id, 'receipt ID'); requirePositive(receipt.expiresAt, 'receipt expiry');
          if (receipt.expiresAt <= now) throw new Error('Expired receipt');
        }
        return transaction(async (tx) => {
          await tx.execute({ sql: 'DELETE FROM receipts WHERE expires_at <= ?', args: [now] });
          await tx.execute({ sql: 'DELETE FROM issuances WHERE expires_at <= ?', args: [now] });
          const existing = await one(tx, 'SELECT result FROM issuances WHERE id = ?', [operationId]);
          if (existing) return JSON.parse(existing.result);
          if (count(await tx.execute('SELECT count(*) AS n FROM receipts')) + receipts.length > maxReceipts) throw new Error('Receipt unavailable');
          for (const receipt of receipts) {
            if (await one(tx, 'SELECT 1 FROM receipts WHERE id = ?', [receipt.id])) throw new Error('Receipt unavailable');
          }
          const liveNow = clock();
          if (resultExpiresAt <= liveNow || receipts.some(receipt => receipt.expiresAt <= liveNow)) throw new Error('Expired receipt');
          const result = produce();
          if (!result || typeof result.then === 'function') throw new TypeError('Synchronous issuance result required');
          const encoded = JSON.stringify(result);
          if (Buffer.byteLength(encoded) > 262144) throw new Error('Issuance result exceeds protocol limit');
          for (const receipt of receipts) await tx.execute({ sql: 'INSERT INTO receipts VALUES (?, ?)', args: [receipt.id, receipt.expiresAt] });
          await tx.execute({ sql: 'INSERT INTO issuances VALUES (?, ?, ?)', args: [operationId, resultExpiresAt, encoded] });
          return JSON.parse(encoded);
        });
      },
    },
    credentials: {
      async insert(communityId, memberId, credential, maxPerMember) {
        const snapshot = structuredClone(credential);
        snapshot.publicKey = new Uint8Array(snapshot.publicKey);
        snapshot.transports = [...(snapshot.transports ?? [])];
        checkCredential(communityId, memberId, snapshot, maxPerMember);
        return transaction(async (tx) => {
          if (await one(tx, 'SELECT 1 FROM credentials WHERE community_id = ? AND id = ?', [communityId, snapshot.id]) ||
              count(await tx.execute('SELECT count(*) AS n FROM credentials')) >= maxCredentials ||
              count(await tx.execute('SELECT count(*) AS n FROM credentials WHERE community_id = ? AND member_id = ?', [communityId, memberId])) >= maxPerMember) return false;
          try {
            await tx.execute({ sql: 'INSERT INTO credentials VALUES (?, ?, ?, ?, ?, ?)', args: [communityId, snapshot.id, memberId, snapshot.publicKey, snapshot.counter, JSON.stringify(snapshot.transports)] });
            return true;
          } catch (error) { if (isConstraint(error)) return false; throw error; }
        });
      },
      async get(communityId, id) { ensureUsable(); return credentialRow(await one(client, 'SELECT * FROM credentials WHERE community_id = ? AND id = ?', [communityId, id])); },
      async hasMember(communityId, memberId) { ensureUsable(); return Boolean(await one(client, 'SELECT 1 FROM credentials WHERE community_id = ? AND member_id = ?', [communityId, memberId])); },
      async updateCounter(communityId, id, counter) {
        if (!Number.isSafeInteger(counter) || counter < 0) return false;
        return transaction(async (tx) => {
          const result = await tx.execute({ sql: 'UPDATE credentials SET counter = ? WHERE community_id = ? AND id = ? AND ((counter = 0 AND ? = 0) OR counter < ?)', args: [counter, communityId, id, counter, counter] });
          return Number(result.rowsAffected) === 1;
        });
      },
    },
    members: {
      async registerWithVoucher({ communityId, memberId, chatPublicKey, authorization, receiptId, memberBinding, validUntil, now, credential, maxPerMember }) {
        const snapshot = structuredClone(credential);
        snapshot.publicKey = new Uint8Array(snapshot.publicKey);
        snapshot.transports = [...(snapshot.transports ?? [])];
        requireText(communityId, 'community ID'); requireText(memberId, 'member ID'); requireText(chatPublicKey, 'chat public key'); requireText(receiptId, 'voucher receipt'); requireText(memberBinding, 'member binding');
        requirePositive(validUntil, 'voucher expiry'); requirePositive(now, 'clock'); publicBytes(chatPublicKey);
        if (validUntil <= now || !/^[0-9a-f]{64}$/.test(receiptId) || !/^[0-9a-f]{64}$/.test(memberBinding) || typeof authorization !== 'object') throw new TypeError('Invalid voucher redemption');
        checkCredential(communityId, memberId, snapshot, maxPerMember);
        const authorizationJson = json(authorization, 'device authorization');
        return transaction(async (tx) => {
          if (await one(tx, 'SELECT 1 FROM voucher_spends WHERE receipt_id = ?', [receiptId]) ||
              count(await tx.execute('SELECT count(*) AS n FROM voucher_spends')) >= maxVoucherSpends ||
              await one(tx, 'SELECT 1 FROM members WHERE community_id = ? AND member_id = ?', [communityId, memberId]) ||
              await one(tx, 'SELECT 1 FROM credentials WHERE community_id = ? AND member_id = ?', [communityId, memberId]) ||
              await one(tx, 'SELECT 1 FROM credentials WHERE community_id = ? AND id = ?', [communityId, snapshot.id]) ||
              count(await tx.execute('SELECT count(*) AS n FROM credentials')) >= maxCredentials ||
              count(await tx.execute('SELECT count(*) AS n FROM credentials WHERE community_id = ? AND member_id = ?', [communityId, memberId])) >= maxPerMember) return false;
          if (validUntil <= clock()) return false;
          await tx.execute({ sql: 'INSERT INTO voucher_spends VALUES (?, ?, ?, ?, ?)', args: [receiptId, communityId, memberId, memberBinding, validUntil] });
          await tx.execute({ sql: 'INSERT INTO members VALUES (?, ?, ?, ?, ?)', args: [communityId, memberId, chatPublicKey, authorizationJson, receiptId] });
          await tx.execute({ sql: 'INSERT INTO credentials (community_id, id, member_id, public_key, counter, transports) VALUES (?, ?, ?, ?, ?, ?)', args: [communityId, snapshot.id, memberId, snapshot.publicKey, snapshot.counter, JSON.stringify(snapshot.transports)] });
          return true;
        });
      },
      async get(communityId, memberId) {
        ensureUsable();
        return memberRow(await one(client, 'SELECT m.*, v.expires_at AS voucher_valid_until FROM members m JOIN voucher_spends v ON v.receipt_id = m.voucher_receipt_id WHERE m.community_id = ? AND m.member_id = ?', [communityId, memberId]));
      },
      async rebind({ communityId, memberId, chatPublicKey, authorization, now }) {
        ensureUsable();
        requireText(communityId, 'community ID'); requireText(memberId, 'member ID'); requireText(chatPublicKey, 'chat public key'); requirePositive(now, 'clock'); publicBytes(chatPublicKey);
        if (!authorization || typeof authorization !== 'object') throw new TypeError('Invalid device authorization');
        const authorizationJson = json(authorization, 'device authorization');
        return transaction(async (tx) => {
          const liveNow = clock();
          const row = await one(tx, 'SELECT m.member_id, v.expires_at AS voucher_valid_until FROM members m JOIN voucher_spends v ON v.receipt_id = m.voucher_receipt_id WHERE m.community_id = ? AND m.member_id = ? AND v.expires_at > ?', [communityId, memberId, liveNow]);
          if (!row || Number(row.voucher_valid_until) <= clock()) return false;
          const result = await tx.execute({ sql: 'UPDATE members SET chat_public_key = ?, device_authorization = ? WHERE community_id = ? AND member_id = ?', args: [chatPublicKey, authorizationJson, communityId, memberId] });
          return Number(result.rowsAffected) === 1;
        });
      },
    },
  };
  return Object.freeze(state);
}
