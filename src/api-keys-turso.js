// Async API-key service backed by the same trusted Turso database as cvld.
// Tokens are returned only from create and are stored as SHA-256 digests.
import { createClient } from '@libsql/client/http';
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { publicBytes, scopeText } from './admission.js';
import { requireClock, requirePositive, requireText } from './encoding.js';

const SCHEMA = `CREATE TABLE IF NOT EXISTS cvld_api_keys (
  community TEXT NOT NULL, id TEXT NOT NULL, member TEXT NOT NULL,
  digest BLOB NOT NULL, label TEXT NOT NULL, scopes TEXT NOT NULL,
  created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
  PRIMARY KEY (community,id)
) STRICT`;
const CLOCK_SCHEMA = `CREATE TABLE IF NOT EXISTS cvld_api_key_clock (
  community TEXT PRIMARY KEY, floor INTEGER NOT NULL
) STRICT`;

function digest(value) { return createHash('sha256').update(value).digest(); }
function label(value) {
  if (typeof value !== 'string' || value.trim().length < 1 || value.length > 80 || /[\x00-\x1f\x7f]/.test(value)) throw new TypeError('API key label required');
  return value.trim();
}
function member(value) { return publicBytes(value).toString('base64url'); }
function publicRecord(row) { return { id: row.id, label: row.label, scopes: JSON.parse(row.scopes), createdAt: Number(row.created_at), expiresAt: Number(row.expires_at) }; }
function boundedFetch(baseFetch, timeoutMs) {
  return async (input, init = {}) => {
    const signals = [AbortSignal.timeout(timeoutMs)];
    if (init.signal) signals.push(init.signal);
    return baseFetch(input, { ...init, signal: AbortSignal.any(signals) });
  };
}
function validateRemoteUrl(value) {
  let url;
  try { url = new URL(value); } catch { throw new TypeError('Invalid Turso URL'); }
  if (!['https:', 'libsql:'].includes(url.protocol) || !url.hostname || url.username || url.password || url.search || url.hash) throw new TypeError('Invalid Turso URL');
}

/** Create the remote counterpart of createApiKeyService. */
export async function createTursoApiKeyService(options) {
  const communityId = scopeText(options.communityId), clock = requireClock(options.clock);
  const maxKeys = requirePositive(options.maxKeys, 'API key capacity');
  const maxPerMember = requirePositive(options.maxKeysPerMember, 'Member API key capacity');
  const maxLifetime = requirePositive(options.maxLifetimeSeconds, 'API key lifetime');
  const configuredScopes = options.allowedScopes;
  if (!Array.isArray(configuredScopes) || configuredScopes.length < 1 || configuredScopes.length > 32 || configuredScopes.some(scope => typeof scope !== 'string' || !/^[a-z][a-z0-9:._-]{0,63}$/.test(scope)) || new Set(configuredScopes).size !== configuredScopes.length) throw new TypeError('Explicit API scopes required');
  const allowedScopes = new Set(configuredScopes);
  if (!options.client) {
    requireText(options.url, 'Turso URL');
    requireText(options.authToken, 'Turso auth token');
    if (requirePositive(options.networkTimeoutMs, 'Turso network timeout') > 60_000) throw new TypeError('Turso network timeout exceeds limit');
    validateRemoteUrl(options.url);
    if (typeof (options.fetch ?? globalThis.fetch) !== 'function') throw new TypeError('Fetch implementation required');
  }
  const client = options.client ?? createClient({ url: options.url, authToken: options.authToken, fetch: boundedFetch(options.fetch ?? globalThis.fetch, options.networkTimeoutMs) });
  if (!client || typeof client.batch !== 'function' || typeof client.execute !== 'function' || typeof client.transaction !== 'function') throw new TypeError('libSQL client required');
  const ownsClient = !options.client;
  try { await client.batch([SCHEMA, CLOCK_SCHEMA], 'write'); }
  catch (error) {
    if (ownsClient && typeof client.close === 'function') { try { await client.close(); } catch { /* preserve initialization failure */ } }
    throw error;
  }
  let retired = false;
  function ensureUsable() { if (retired) throw new Error('Turso API-key service retired after ambiguous transaction; reopen required'); }

  async function transaction(work) {
    ensureUsable();
    const tx = await client.transaction('write');
    let commitAttempted = false;
    try { const result = await work(tx); commitAttempted = true; await tx.commit(); return result; }
    catch (error) { if (!commitAttempted) { try { await tx.rollback(); } catch { retired = true; } } else retired = true; throw error; }
    finally { if (typeof tx.close === 'function') { try { await tx.close(); } catch { /* never mask the result */ } } }
  }
  async function one(handle, sql, args = []) { return (await handle.execute({ sql, args })).rows[0]; }
  async function number(handle, sql, args = []) { return Number((await one(handle, sql, args))?.n ?? 0); }
  async function current(tx) {
    const value = clock();
    if (!Number.isSafeInteger(value) || value < 1) throw new TypeError('Invalid clock');
    const prior = await one(tx, 'SELECT floor FROM cvld_api_key_clock WHERE community = ?', [communityId]);
    if (prior && value < Number(prior.floor)) throw new Error('Clock moved backwards');
    await tx.execute({ sql: 'INSERT INTO cvld_api_key_clock (community, floor) VALUES (?, ?) ON CONFLICT(community) DO UPDATE SET floor=excluded.floor WHERE floor<excluded.floor', args: [communityId, value] });
    return value;
  }
  return Object.freeze({
    get healthy() { return !retired; },
    async create({ memberId, name, scopes, expiresAt }) {
      const owner = member(memberId), nameValue = label(name), requestedScopes = structuredClone(scopes);
      if (!Array.isArray(requestedScopes) || !requestedScopes.length || requestedScopes.length > allowedScopes.size || new Set(requestedScopes).size !== requestedScopes.length || requestedScopes.some(value => !allowedScopes.has(value))) throw new Error('API scope rejected');
      requirePositive(expiresAt, 'API key expiry');
      return transaction(async (tx) => {
        const createdAt = await current(tx);
        if (expiresAt <= createdAt || expiresAt - createdAt > maxLifetime) throw new Error('API key expiry rejected');
        await tx.execute({ sql: 'DELETE FROM cvld_api_keys WHERE community = ? AND expires_at <= ?', args: [communityId, createdAt] });
        if (await number(tx, 'SELECT count(*) AS n FROM cvld_api_keys WHERE community = ?', [communityId]) >= maxKeys || await number(tx, 'SELECT count(*) AS n FROM cvld_api_keys WHERE community = ? AND member = ?', [communityId, owner]) >= maxPerMember) throw new Error('API key capacity reached');
        const id = randomBytes(16).toString('base64url');
        const token = `cvld.${id}.${randomBytes(32).toString('base64url')}`;
        const sorted = [...requestedScopes].sort();
        await tx.execute({ sql: 'INSERT INTO cvld_api_keys VALUES (?, ?, ?, ?, ?, ?, ?, ?)', args: [communityId, id, owner, digest(token), nameValue, JSON.stringify(sorted), createdAt, expiresAt] });
        return { id, token, label: nameValue, scopes: sorted, createdAt, expiresAt };
      });
    },
    async authenticate(token, requiredScope) {
      if (typeof token !== 'string' || !/^cvld\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}$/.test(token) || (requiredScope !== undefined && !allowedScopes.has(requiredScope))) return false;
      try {
        const principal = await transaction(async (tx) => {
          const now = await current(tx), id = token.split('.')[1];
          const row = await one(tx, 'SELECT * FROM cvld_api_keys WHERE community = ? AND id = ?', [communityId, id]);
          const supplied = digest(token), expected = row ? Buffer.from(row.digest) : Buffer.alloc(32);
          if (expected.length !== supplied.length || !timingSafeEqual(expected, supplied) || !row || Number(row.expires_at) <= now || (requiredScope !== undefined && !JSON.parse(row.scopes).includes(requiredScope))) return false;
          return { kind: 'apiKey', memberId: row.member, communityId, keyId: row.id, scopes: JSON.parse(row.scopes), expiresAt: Number(row.expires_at) };
        });
        const liveNow = clock();
        return principal && principal.expiresAt > liveNow ? principal : false;
      } catch { return false; }
    },
    async list(memberId) {
      const owner = member(memberId);
      return transaction(async (tx) => {
        const now = await current(tx);
        await tx.execute({ sql: 'DELETE FROM cvld_api_keys WHERE community = ? AND expires_at <= ?', args: [communityId, now] });
        const rows = (await tx.execute({ sql: 'SELECT * FROM cvld_api_keys WHERE community = ? AND member = ? AND expires_at > ? ORDER BY created_at,id', args: [communityId, owner, now] })).rows;
        return rows.map(publicRecord);
      });
    },
    async revoke({ memberId, id }) {
      const owner = member(memberId);
      if (typeof id !== 'string' || !/^[A-Za-z0-9_-]{22}$/.test(id)) return false;
      return transaction(async (tx) => { await current(tx); const result = await tx.execute({ sql: 'DELETE FROM cvld_api_keys WHERE community = ? AND member = ? AND id = ?', args: [communityId, owner, id] }); return Number(result.rowsAffected) === 1; });
    },
    async close() { retired = true; if (ownsClient && typeof client.close === 'function') await client.close(); },
  });
}
