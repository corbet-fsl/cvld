import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { writeFileSync, readFileSync } from 'node:fs';
import { admissionBytes, admissionKeyId, verifyAdmission } from '../src/admission.js';
// RFC 8032 public TEST VECTOR seed, intentionally nonsecret and never production.
const seed = Buffer.from('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60', 'hex');
const secret = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]), format: 'der', type: 'pkcs8' });
const publicKey = Buffer.from(createPublicKey(secret).export({ format: 'jwk' }).x, 'base64url');
const unsigned = { version: 1, issuerKeyId: admissionKeyId(publicKey), communityId: 'community.example', memberId: Buffer.alloc(32, 7).toString('base64url'), chatPublicKey: publicKey.toString('base64url'), policyDigest: Buffer.alloc(32, 9).toString('base64url'), issuedAt: 1800000000, expiresAt: 1800000120 };
const grant = { ...unsigned, signature: sign(null, admissionBytes(unsigned), secret).toString('base64url') };
const input = { grant, trustedPublicKey: publicKey, communityId: grant.communityId, policyDigest: grant.policyDigest, now: 1800000060 };

test('the portable admission wire contract authenticates every field and validity boundary', () => {
  const fixture = JSON.parse(readFileSync(new URL('./fixtures/admission-v1.json', import.meta.url)));
  assert.deepEqual(fixture, { publicKey: publicKey.toString('base64url'), now: input.now, grant });
  assert.equal(verifyAdmission(input), true);
  assert.equal(verifyAdmission({ ...input, now: grant.issuedAt - 1 }), false);
  assert.equal(verifyAdmission({ ...input, now: grant.expiresAt }), false);
  assert.equal(verifyAdmission({ ...input, trustedPublicKey: new Uint8Array(32) }), false);
  for (const [name, value] of Object.entries({ version: 2, issuerKeyId: Buffer.alloc(32, 3).toString('base64url'), communityId: 'another.example', memberId: Buffer.alloc(32, 3).toString('base64url'), chatPublicKey: Buffer.alloc(32, 3).toString('base64url'), policyDigest: Buffer.alloc(32, 3).toString('base64url'), issuedAt: grant.issuedAt + 1, expiresAt: grant.expiresAt + 1 })) {
    assert.equal(verifyAdmission({ ...input, grant: { ...grant, [name]: value } }), false, name);
  }
  assert.throws(() => admissionBytes({ ...grant, communityId: 'ünicode.example' }));
  assert.equal(verifyAdmission({ ...input, grant: { ...grant, signature: `${grant.signature}=` } }), false);
});
// This public deterministic fixture can be checked by other runtime implementations.
if (process.env.CVLD_WRITE_PUBLIC_FIXTURE) writeFileSync(process.env.CVLD_WRITE_PUBLIC_FIXTURE, JSON.stringify({ publicKey: publicKey.toString('base64url'), now: input.now, grant }, null, 2) + '\n');
