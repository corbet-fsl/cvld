import { DatabaseSync } from 'node:sqlite';
import { checkCredential } from './credential-store.js';
import { requirePositive, requireText } from './encoding.js';

export function createSqliteState({ path, maxReceipts, maxCredentials, busyTimeoutMs }) {
  requireText(path, 'database path'); requirePositive(maxReceipts, 'receipt capacity');
  requirePositive(maxCredentials, 'credential capacity'); requirePositive(busyTimeoutMs, 'busy timeout');
  const db = new DatabaseSync(path, { timeout: busyTimeoutMs, allowExtension: false, enableForeignKeyConstraints: true, enableDoubleQuotedStringLiterals: false });
  db.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA synchronous = FULL;
    PRAGMA trusted_schema = OFF;
    CREATE TABLE IF NOT EXISTS receipts (id TEXT PRIMARY KEY, expires_at INTEGER NOT NULL) STRICT;
    CREATE TABLE IF NOT EXISTS issuances (id TEXT PRIMARY KEY, expires_at INTEGER NOT NULL, result TEXT NOT NULL) STRICT;
    CREATE TABLE IF NOT EXISTS credentials (
      community_id TEXT NOT NULL, id TEXT NOT NULL, member_id TEXT NOT NULL,
      public_key BLOB NOT NULL, counter INTEGER NOT NULL, transports TEXT NOT NULL,
      PRIMARY KEY (community_id, id)
    ) STRICT;
  `);
  function transaction(fn) {
    db.exec('BEGIN IMMEDIATE');
    try { const result = fn(); db.exec('COMMIT'); return result; }
    catch (error) { db.exec('ROLLBACK'); throw error; }
  }
  return {
    close() { if (db.isOpen) db.close(); },
    receipts: {
      async issueOnce({ operationId, receipts, resultExpiresAt, now }, produce) {
        requireText(operationId, 'issuance ID'); requirePositive(resultExpiresAt, 'result expiry'); requirePositive(now, 'clock');
        if (!Array.isArray(receipts) || receipts.length < 1 || new Set(receipts.map((r) => r.id)).size !== receipts.length || resultExpiresAt <= now) throw new Error('Invalid issuance transaction');
        for (const receipt of receipts) { requireText(receipt.id, 'receipt ID'); requirePositive(receipt.expiresAt, 'receipt expiry'); if (receipt.expiresAt <= now) throw new Error('Expired receipt'); }
        return transaction(() => {
          db.prepare('DELETE FROM receipts WHERE expires_at <= ?').run(now);
          db.prepare('DELETE FROM issuances WHERE expires_at <= ?').run(now);
          const existing = db.prepare('SELECT result FROM issuances WHERE id = ?').get(operationId);
          if (existing) return JSON.parse(existing.result);
          if (db.prepare('SELECT count(*) AS n FROM receipts').get().n + receipts.length > maxReceipts || receipts.some((r) => db.prepare('SELECT 1 FROM receipts WHERE id = ?').get(r.id))) throw new Error('Receipt unavailable');
          const result = produce();
          if (!result || typeof result.then === 'function') throw new TypeError('Synchronous issuance result required');
          const encoded = JSON.stringify(result);
          if (Buffer.byteLength(encoded) > 262144) throw new Error('Issuance result exceeds protocol limit');
          for (const receipt of receipts) db.prepare('INSERT INTO receipts VALUES (?, ?)').run(receipt.id, receipt.expiresAt);
          db.prepare('INSERT INTO issuances VALUES (?, ?, ?)').run(operationId, resultExpiresAt, encoded);
          return JSON.parse(encoded);
        });
      },
    },
    credentials: {
      insert(communityId, memberId, credential, maxPerMember) {
        checkCredential(communityId, memberId, credential, maxPerMember);
        return transaction(() => {
          if (db.prepare('SELECT 1 FROM credentials WHERE community_id = ? AND id = ?').get(communityId, credential.id) || db.prepare('SELECT count(*) AS n FROM credentials').get().n >= maxCredentials || db.prepare('SELECT count(*) AS n FROM credentials WHERE community_id = ? AND member_id = ?').get(communityId, memberId).n >= maxPerMember) return false;
          db.prepare('INSERT INTO credentials VALUES (?, ?, ?, ?, ?, ?)').run(communityId, credential.id, memberId, credential.publicKey, credential.counter, JSON.stringify(credential.transports ?? []));
          return true;
        });
      },
      get(communityId, id) {
        const row = db.prepare('SELECT * FROM credentials WHERE community_id = ? AND id = ?').get(communityId, id);
        return row ? { id: row.id, memberId: row.member_id, communityId: row.community_id, publicKey: row.public_key, counter: row.counter, transports: JSON.parse(row.transports) } : undefined;
      },
      updateCounter(communityId, id, counter) {
        if (!Number.isSafeInteger(counter) || counter < 0) return false;
        return db.prepare('UPDATE credentials SET counter = ? WHERE community_id = ? AND id = ? AND ((counter = 0 AND ? = 0) OR counter < ?)').run(counter, communityId, id, counter, counter).changes === 1;
      },
    },
  };
}
