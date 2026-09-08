import { createHash, createPublicKey, verify } from 'node:crypto';

export function scopeText(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9._:/-]{1,256}$/.test(value)) throw new TypeError('Invalid community scope');
  return value;
}
export function publicBytes(value, length = 32) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) throw new TypeError('Invalid canonical public bytes');
  const bytes = Buffer.from(value, 'base64url');
  if (bytes.length !== length || bytes.toString('base64url') !== value) throw new TypeError('Invalid public byte length');
  return bytes;
}
export function admissionBytes(grant) {
  if (grant?.version !== 1) throw new TypeError('Invalid admission version');
  scopeText(grant.communityId);
  for (const field of ['issuerKeyId', 'memberId', 'chatPublicKey', 'policyDigest']) publicBytes(grant[field]);
  if (![grant.issuedAt, grant.expiresAt].every((x) => Number.isSafeInteger(x) && x > 0) || grant.expiresAt <= grant.issuedAt) throw new TypeError('Invalid admission validity');
  return new TextEncoder().encode(JSON.stringify(['cvld.admission.v1', grant.issuerKeyId, grant.communityId, grant.memberId, grant.chatPublicKey, grant.policyDigest, grant.issuedAt, grant.expiresAt]));
}
export function admissionKeyId(rawPublicKey) {
  if (!(rawPublicKey instanceof Uint8Array) || rawPublicKey.length !== 32) throw new TypeError('Raw Ed25519 public key required');
  return createHash('sha256').update(rawPublicKey).digest('base64url');
}
export function verifyAdmission({ grant, trustedPublicKey, communityId, policyDigest, now }) {
  try {
    const bytes = admissionBytes(grant);
    if (grant.communityId !== scopeText(communityId) || grant.policyDigest !== policyDigest || grant.issuerKeyId !== admissionKeyId(trustedPublicKey) ||
        !Number.isSafeInteger(now) || now < grant.issuedAt || now >= grant.expiresAt) return false;
    const key = createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: Buffer.from(trustedPublicKey).toString('base64url') }, format: 'jwk' });
    return verify(null, bytes, key, publicBytes(grant.signature, 64));
  } catch { return false; }
}
