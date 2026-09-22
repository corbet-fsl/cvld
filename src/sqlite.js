import { DatabaseSync } from 'node:sqlite';
import { checkCredential } from './credential-store.js';
import { publicBytes } from './admission.js';
import { requirePositive, requireText } from './encoding.js';

export function createSqliteState({ path, maxReceipts, maxCredentials, maxVoucherSpends, busyTimeoutMs }) {
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
    CREATE TABLE IF NOT EXISTS voucher_spends (
      receipt_id TEXT PRIMARY KEY, community_id TEXT NOT NULL, member_id TEXT NOT NULL,
      member_binding TEXT NOT NULL, expires_at INTEGER NOT NULL
    ) STRICT;
    CREATE TABLE IF NOT EXISTS members (
      community_id TEXT NOT NULL, member_id TEXT NOT NULL, chat_public_key TEXT NOT NULL,
      device_authorization TEXT NOT NULL, voucher_receipt_id TEXT NOT NULL,
      PRIMARY KEY (community_id, member_id)
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
      hasMember(communityId, memberId) {
        requireText(communityId, 'community ID'); requireText(memberId, 'member ID');
        return Boolean(db.prepare('SELECT 1 FROM credentials WHERE community_id = ? AND member_id = ?').get(communityId, memberId));
      },
      updateCounter(communityId, id, counter) {
        if (!Number.isSafeInteger(counter) || counter < 0) return false;
        return db.prepare('UPDATE credentials SET counter = ? WHERE community_id = ? AND id = ? AND ((counter = 0 AND ? = 0) OR counter < ?)').run(counter, communityId, id, counter, counter).changes === 1;
      },
    },
    members: {
      registerWithVoucher({ communityId, memberId, chatPublicKey, authorization, receiptId, memberBinding, validUntil, now, credential, maxPerMember }) {
        requireText(communityId, 'community ID'); requireText(memberId, 'member ID'); requireText(chatPublicKey, 'chat public key'); requireText(receiptId, 'voucher receipt'); requireText(memberBinding, 'member binding');
        requirePositive(validUntil, 'voucher expiry'); requirePositive(now, 'clock');
        if (validUntil <= now || !/^[0-9a-f]{64}$/.test(receiptId) || !/^[0-9a-f]{64}$/.test(memberBinding) || typeof authorization !== 'object' || Buffer.byteLength(JSON.stringify(authorization)) > 4096) throw new TypeError('Invalid voucher redemption');
        publicBytes(chatPublicKey);
        checkCredential(communityId, memberId, credential, maxPerMember);
        if (!Number.isSafeInteger(maxVoucherSpends) || maxVoucherSpends <= 0) throw new Error('Voucher spend capacity required');
        return transaction(() => {
          if (db.prepare('SELECT 1 FROM voucher_spends WHERE receipt_id = ?').get(receiptId) ||
              db.prepare('SELECT count(*) AS n FROM voucher_spends').get().n >= maxVoucherSpends ||
              db.prepare('SELECT 1 FROM members WHERE community_id = ? AND member_id = ?').get(communityId, memberId) ||
              db.prepare('SELECT 1 FROM credentials WHERE community_id = ? AND member_id = ?').get(communityId, memberId) ||
              db.prepare('SELECT 1 FROM credentials WHERE community_id = ? AND id = ?').get(communityId, credential.id) ||
              db.prepare('SELECT count(*) AS n FROM credentials').get().n >= maxCredentials ||
              db.prepare('SELECT count(*) AS n FROM credentials WHERE community_id = ? AND member_id = ?').get(communityId, memberId).n >= maxPerMember) return false;
          db.prepare('INSERT INTO voucher_spends VALUES (?, ?, ?, ?, ?)').run(receiptId, communityId, memberId, memberBinding, validUntil);
          db.prepare('INSERT INTO members VALUES (?, ?, ?, ?, ?)').run(communityId, memberId, chatPublicKey, JSON.stringify(authorization), receiptId);
          db.prepare('INSERT INTO credentials (community_id, id, member_id, public_key, counter, transports) VALUES (?, ?, ?, ?, ?, ?)').run(communityId, credential.id, memberId, credential.publicKey, credential.counter, JSON.stringify(credential.transports ?? []));
          return true;
        });
      },
      get(communityId, memberId) {
        const row = db.prepare('SELECT m.*, v.expires_at AS voucher_valid_until FROM members m JOIN voucher_spends v ON v.receipt_id = m.voucher_receipt_id WHERE m.community_id = ? AND m.member_id = ?').get(communityId, memberId);
        return row ? { communityId: row.community_id, memberId: row.member_id, chatPublicKey: row.chat_public_key, authorization: JSON.parse(row.device_authorization), voucherReceiptId: row.voucher_receipt_id, voucherValidUntil: row.voucher_valid_until } : undefined;
      },
      rebind({ communityId, memberId, chatPublicKey, authorization, now }) {
        requireText(communityId, 'community ID'); requireText(memberId, 'member ID'); requireText(chatPublicKey, 'chat public key'); requirePositive(now, 'clock');
        publicBytes(chatPublicKey);
        if (!authorization || typeof authorization !== 'object' || Buffer.byteLength(JSON.stringify(authorization)) > 4096) throw new TypeError('Invalid device authorization');
        return transaction(() => {
          const row = db.prepare('SELECT m.member_id FROM members m JOIN voucher_spends v ON v.receipt_id = m.voucher_receipt_id WHERE m.community_id = ? AND m.member_id = ? AND v.expires_at > ?').get(communityId, memberId, now);
          if (!row) return false;
          db.prepare('UPDATE members SET chat_public_key = ?, device_authorization = ? WHERE community_id = ? AND member_id = ?').run(chatPublicKey, JSON.stringify(authorization), communityId, memberId);
          return true;
        });
      },
    },
  };
}
