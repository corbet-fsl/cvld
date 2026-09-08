import { requirePositive } from './encoding.js';
// Ephemeral implementation with the same atomic result contract as SQLite.
export function createMemoryReceiptStore({ maxEntries }) {
  requirePositive(maxEntries, 'receipt capacity');
  const receipts = new Map();
  const results = new Map();
  return {
    async issueOnce({ operationId, receipts: requested, resultExpiresAt, now }, produce) {
      for (const [id, expiry] of receipts) if (expiry <= now) receipts.delete(id);
      for (const [id, entry] of results) if (entry.expiresAt <= now) results.delete(id);
      if (results.has(operationId)) return structuredClone(results.get(operationId).result);
      if (!Array.isArray(requested) || requested.length < 1 || new Set(requested.map((r) => r.id)).size !== requested.length || requested.some((r) => receipts.has(r.id) || r.expiresAt <= now) || receipts.size + requested.length > maxEntries) throw new Error('Receipt unavailable');
      const result = produce();
      if (result?.then) throw new TypeError('Synchronous atomic producer required');
      const snapshot = structuredClone(result);
      for (const receipt of requested) receipts.set(receipt.id, receipt.expiresAt);
      results.set(operationId, { result: snapshot, expiresAt: resultExpiresAt });
      return structuredClone(snapshot);
    },
  };
}
