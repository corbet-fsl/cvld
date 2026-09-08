import assert from 'node:assert/strict';
import { test } from 'node:test';
import { generateKeyPairSync, randomBytes, verify } from 'node:crypto';
import { createIssuer, createHolder, createVerifier, createMemoryReceiptStore, createMemoryCredentialStore, createPasskeyService, restoreIssuer } from '../src/index.js';
import { makeGate, makeAuthenticator, NOW, ORIGIN, RP_ID } from './fixtures.js';

const communityId = 'community.example';
const policy = { version: 'account', mode: 'any', factors: ['phone'] };
let common;
async function setup() {
  if (!common) {
    const gate = makeGate('phone');
    const issuer = createIssuer({ issuerId: 'https://accounts.example/cvld', communityId, policy, attesters: { phone: gate.public }, receiptStore: createMemoryReceiptStore({ maxEntries: 100 }), maxCredentialLifetimeSeconds: 900, clock: () => NOW });
    const store = createMemoryCredentialStore({ maxCredentials: 100 });
    const passkeys = createPasskeyService({ credentialStore: store, communityId, origin: ORIGIN, rpID: RP_ID, rpName: 'Example', clock: () => NOW, challengeLifetimeSeconds: 120, maxPendingChallenges: 100, requireUserVerification: true, maxPasskeysPerMember: 4 });
    const keys = generateKeyPairSync('ed25519');
    common = { issuer, gate, store, passkeys, keys };
  }
  const { issuer, gate, store, passkeys, keys } = common;
  const auth = makeAuthenticator();
  const start = await passkeys.beginRegistration();
  const account = await passkeys.finishRegistration({ id: start.id, response: auth.register(start.options.challenge) });
  const holder = createHolder();
  const offer = issuer.offer();
  const pending = holder.request(issuer.public, offer, account.memberId);
  pending.accept(await issuer.issue({ offer, request: pending.request, attestations: [gate.attest(offer, pending.request, policy)] }));
  const verifier = createVerifier({ publicIssuer: issuer.public, policy, communityId, credentialStore: store, origin: ORIGIN, rpID: RP_ID, clock: () => NOW, challengeLifetimeSeconds: 120, grantLifetimeSeconds: 120, maxPendingChallenges: 100, maxPresentationBytes: 100_000, requireUserVerification: true, grantSigningKey: keys.privateKey.export({ format: 'pem', type: 'pkcs8' }) });
  return { ...common, auth, account, holder, verifier };
}
const chatKey = () => generateKeyPairSync('ed25519').publicKey.export({ format: 'jwk' }).x;

test('verified admission binds stable member identity to an authenticated chat signing key', async () => {
  const { issuer, auth, account, holder, verifier, keys } = await setup();
  const publicKey = chatKey();
  const challenge = verifier.begin(account.credentialId, ORIGIN, publicKey);
  const result = await verifier.authenticate({ id: challenge.id, audience: ORIGIN, presentation: holder.present(issuer.public, challenge), authentication: auth.assert(challenge.authentication.challenge) });
  assert.equal(result.memberId, account.memberId);
  const grant = result.admission;
  assert.equal(grant.chatPublicKey, publicKey);
  assert.equal(grant.communityId, communityId);
  const payload = Buffer.from(JSON.stringify(['cvld.admission.v1', grant.issuerKeyId, grant.communityId, grant.memberId, grant.chatPublicKey, grant.policyDigest, grant.issuedAt, grant.expiresAt]));
  assert.equal(verify(null, payload, keys.publicKey, Buffer.from(grant.signature, 'base64url')), true);
});

test('one account eligibility credential cannot authenticate another registered account', async () => {
  const { issuer, auth, account, holder, verifier, passkeys } = await setup();
  const otherAuth = makeAuthenticator();
  const start = await passkeys.beginRegistration();
  const other = await passkeys.finishRegistration({ id: start.id, response: otherAuth.register(start.options.challenge) });
  const challenge = verifier.begin(other.credentialId, ORIGIN, chatKey());
  const maliciousRequest = { ...challenge, memberId: account.memberId };
  const proof = holder.present(issuer.public, maliciousRequest);
  assert.equal(await verifier.authenticate({ id: challenge.id, audience: ORIGIN, presentation: proof, authentication: otherAuth.assert(challenge.authentication.challenge) }), false);
  assert.throws(() => verifier.begin(auth.credential, ORIGIN, chatKey()));
});

test('additional authenticated passkeys reuse the same eligibility and member identity', async () => {
  const { issuer, auth, account, holder, verifier, passkeys } = await setup();
  const authorization = await passkeys.beginAdditionalRegistration(account.credentialId);
  const registration = await passkeys.authorizeAdditionalRegistration({ id: authorization.id, response: auth.assert(authorization.options.challenge) });
  const extraAuth = makeAuthenticator();
  const extra = await passkeys.finishRegistration({ id: registration.id, response: extraAuth.register(registration.options.challenge) });
  const challenge = verifier.begin(extra.credentialId, ORIGIN, chatKey());
  const result = await verifier.authenticate({ id: challenge.id, audience: ORIGIN, presentation: holder.present(issuer.public, challenge), authentication: extraAuth.assert(challenge.authentication.challenge) });
  assert.equal(result.memberId, account.memberId);
});

test('issuer keys and policy survive an explicitly encrypted export and import', async () => {
  const { issuer } = await setup();
  const key = randomBytes(32);
  const state = await issuer.exportState({ wrappingKey: key });
  assert.equal(JSON.stringify(state).includes('credentialDefinitionPrivate'), false);
  const restored = await restoreIssuer({ encryptedState: state, wrappingKey: key, clock: () => NOW, receiptStore: createMemoryReceiptStore({ maxEntries: 100 }) });
  assert.deepEqual(restored.public, issuer.public);
  await assert.rejects(restoreIssuer({ encryptedState: state, wrappingKey: randomBytes(32), clock: () => NOW, receiptStore: createMemoryReceiptStore({ maxEntries: 100 }) }));
});
