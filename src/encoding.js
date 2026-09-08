import { createHash } from 'node:crypto';

export const FACTORS = Object.freeze(['phone', 'payment', 'voucher']);
export function requireText(value, name) {
  if (typeof value !== 'string' || value.length < 1 || value.length > 2048) throw new TypeError(`Invalid ${name}`);
  return value;
}
export function requirePositive(value, name) {
  if (!Number.isSafeInteger(value) || value < 1 || value > 2_147_483_647) throw new TypeError(`Invalid ${name}`);
  return value;
}
export function requireClock(clock) {
  if (typeof clock !== 'function') throw new TypeError('Explicit clock required');
  return () => requirePositive(clock(), 'clock');
}
export function normalizePolicy(policy) {
  requireText(policy?.version, 'policy version');
  if (!['any', 'all'].includes(policy.mode) || !Array.isArray(policy.factors) || policy.factors.length < 1 ||
      policy.factors.some((f) => !FACTORS.includes(f)) || new Set(policy.factors).size !== policy.factors.length) {
    throw new TypeError('Invalid factor policy');
  }
  return { version: policy.version, mode: policy.mode, factors: [...policy.factors].sort() };
}
export const hash = (input) => createHash('sha256').update(input).digest('base64url');
export function policyDigest(policy) {
  const p = normalizePolicy(policy);
  return hash(JSON.stringify(['cvld.policy.v1', p.version, p.mode, p.factors]));
}
function canonical(value) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value;
  if (typeof value === 'number' && Number.isSafeInteger(value)) return value;
  if (Array.isArray(value)) return value.map(canonical);
  if (value && Object.getPrototypeOf(value) === Object.prototype) {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical(value[key])]));
  }
  throw new TypeError('Expected JSON data');
}
export function issuanceDigest(offer, request) {
  return hash(JSON.stringify(['cvld.issuance.v1', canonical(offer), canonical(request)]));
}
export function encodeAttestation(body) {
  for (const key of ['keyId', 'factor', 'receiptId', 'issuanceDigest', 'policyDigest']) requireText(body[key], key);
  if (!FACTORS.includes(body.factor)) throw new TypeError('Invalid factor');
  requirePositive(body.validUntil, 'attestation expiry');
  return Buffer.from(JSON.stringify([
    'cvld.attestation.v1', body.keyId, body.factor, body.receiptId,
    body.issuanceDigest, body.policyDigest, body.validUntil,
  ]));
}
export function jsonAndRelease(object) {
  try { return object.toJson(); } finally { object.handle.clear(); }
}
