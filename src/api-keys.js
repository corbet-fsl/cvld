// Optional automation credentials. These authenticate API callers; they do not
// replace cfrm/cmsg signatures, membership eligibility, or private proofs.
import { DatabaseSync } from 'node:sqlite';
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { publicBytes, scopeText } from './admission.js';
import { requireClock, requirePositive } from './encoding.js';

function digest(value) { return createHash('sha256').update(value).digest(); }
function label(value) {
  if (typeof value !== 'string' || value.trim().length < 1 || value.length > 80
      || /[\x00-\x1f\x7f]/.test(value)) throw new TypeError('API key label required');
  return value.trim();
}

/** Constructor and create/revoke inputs are trusted service calls. An HTTP
 * adapter must take memberId from verified authentication, never request JSON.
 * The raw key is returned once and must never be logged or cached. */
export function createApiKeyService(options) {
  const communityId = scopeText(options.communityId), clock = requireClock(options.clock);
  const maxKeys = requirePositive(options.maxKeys, 'API key capacity');
  const maxPerMember = requirePositive(options.maxKeysPerMember, 'Member API key capacity');
  const maxLifetime = requirePositive(options.maxLifetimeSeconds, 'API key lifetime');
  const busyTimeout = requirePositive(options.busyTimeoutMs, 'API key database timeout');
  const configuredScopes = options.allowedScopes;
  if (!Array.isArray(configuredScopes) || configuredScopes.length < 1 || configuredScopes.length > 32
      || configuredScopes.some(scope => typeof scope !== 'string' || !/^[a-z][a-z0-9:._-]{0,63}$/.test(scope))
      || new Set(configuredScopes).size !== configuredScopes.length) throw new TypeError('Explicit API scopes required');
  const allowedScopes = new Set(configuredScopes);
  const db = new DatabaseSync(options.path);
  db.exec(`PRAGMA busy_timeout=${busyTimeout}; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
    CREATE TABLE IF NOT EXISTS cvld_api_keys (
      community TEXT NOT NULL, id TEXT NOT NULL, member TEXT NOT NULL,
      digest BLOB NOT NULL, label TEXT NOT NULL, scopes TEXT NOT NULL,
      created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
      PRIMARY KEY (community,id)
    ) STRICT;
    CREATE TABLE IF NOT EXISTS cvld_api_key_clock (
      community TEXT PRIMARY KEY, floor INTEGER NOT NULL
    ) STRICT;`);
  const member = value => publicBytes(value).toString('base64url');
  function now() {
    const value = clock();
    const prior = db.prepare('SELECT floor FROM cvld_api_key_clock WHERE community=?').get(communityId);
    if (prior && value < prior.floor) throw new Error('Clock moved backwards');
    db.prepare('INSERT INTO cvld_api_key_clock VALUES (?,?) ON CONFLICT(community) DO UPDATE SET floor=excluded.floor WHERE floor<excluded.floor').run(communityId, value);
    return value;
  }
  function transaction(work) {
    db.exec('BEGIN IMMEDIATE');
    try { const value = work(); db.exec('COMMIT'); return value; }
    catch (error) { db.exec('ROLLBACK'); throw error; }
  }
  function publicRecord(row) {
    return { id: row.id, label: row.label, scopes: JSON.parse(row.scopes), createdAt: row.created_at, expiresAt: row.expires_at };
  }
  return Object.freeze({
    create({ memberId, name, scopes, expiresAt }) {
      const owner = member(memberId), nameValue = label(name);
      if (!Array.isArray(scopes) || !scopes.length || scopes.length > allowedScopes.size
          || new Set(scopes).size !== scopes.length || scopes.some(value => !allowedScopes.has(value))) throw new Error('API scope rejected');
      requirePositive(expiresAt, 'API key expiry');
      return transaction(() => {
        const createdAt = now();
        if (expiresAt <= createdAt || expiresAt - createdAt > maxLifetime) throw new Error('API key expiry rejected');
        db.prepare('DELETE FROM cvld_api_keys WHERE community=? AND expires_at<=?').run(communityId, createdAt);
        const total = db.prepare('SELECT count(*) AS n FROM cvld_api_keys WHERE community=?').get(communityId).n;
        const own = db.prepare('SELECT count(*) AS n FROM cvld_api_keys WHERE community=? AND member=?').get(communityId, owner).n;
        if (total >= maxKeys || own >= maxPerMember) throw new Error('API key capacity reached');
        const id = randomBytes(16).toString('base64url');
        const token = `cvld.${id}.${randomBytes(32).toString('base64url')}`;
        const sorted = [...scopes].sort();
        db.prepare('INSERT INTO cvld_api_keys VALUES (?,?,?,?,?,?,?,?)').run(communityId, id, owner, digest(token), nameValue, JSON.stringify(sorted), createdAt, expiresAt);
        return { id, token, label: nameValue, scopes: sorted, createdAt, expiresAt };
      });
    },
    authenticate(token, requiredScope) {
      if (typeof token !== 'string' || !/^cvld\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}$/.test(token)
          || (requiredScope !== undefined && !allowedScopes.has(requiredScope))) return false;
      try {
        return transaction(() => {
          const current = now(), id = token.split('.')[1];
          const row = db.prepare('SELECT * FROM cvld_api_keys WHERE community=? AND id=?').get(communityId, id);
          const supplied = digest(token), expected = row ? Buffer.from(row.digest) : Buffer.alloc(32);
          if (expected.length !== supplied.length || !timingSafeEqual(expected, supplied) || !row
              || row.expires_at <= current || (requiredScope !== undefined && !JSON.parse(row.scopes).includes(requiredScope))) return false;
          return { kind: 'apiKey', memberId: row.member, communityId, keyId: row.id, scopes: JSON.parse(row.scopes), expiresAt: row.expires_at };
        });
      } catch { return false; }
    },
    list(memberId) {
      const owner = member(memberId);
      return transaction(() => {
        const current = now();
        return db.prepare('SELECT * FROM cvld_api_keys WHERE community=? AND member=? AND expires_at>? ORDER BY created_at,id').all(communityId, owner, current).map(publicRecord);
      });
    },
    revoke({ memberId, id }) {
      const owner = member(memberId);
      if (typeof id !== 'string' || !/^[A-Za-z0-9_-]{22}$/.test(id)) return false;
      return transaction(() => { now(); return db.prepare('DELETE FROM cvld_api_keys WHERE community=? AND member=? AND id=?').run(communityId, owner, id).changes === 1; });
    },
    close() { db.close(); },
  });
}
