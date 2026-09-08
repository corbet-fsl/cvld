import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createPasskeyService, createMemoryCredentialStore } from '../src/index.js';
import { makeAuthenticator, NOW, ORIGIN, RP_ID } from './fixtures.js';

export function passkeys(store = createMemoryCredentialStore({ maxCredentials: 100 }), clock = () => NOW) {
  return createPasskeyService({
    credentialStore: store, communityId: 'community.example', origin: ORIGIN, rpID: RP_ID, rpName: 'Example community',
    clock, challengeLifetimeSeconds: 120, maxPendingChallenges: 20, requireUserVerification: true, maxPasskeysPerMember: 4,
  });
}

test('only a verified registration creates a durable passkey record', async () => {
  const store = createMemoryCredentialStore({ maxCredentials: 100 });
  const service = passkeys(store);
  const auth = makeAuthenticator();
  const start = await service.beginRegistration();
  const result = await service.finishRegistration({ id: start.id, response: auth.register(start.options.challenge) });
  assert.equal(result.credentialId, auth.credential.id);
  assert.equal(result.memberId, start.memberId);
  assert.equal(store.get('community.example', auth.credential.id).memberId, start.memberId);
});

test('registration rejects wrong origin, RP, UV and tampered signature', async () => {
  for (const mutation of [{ origin: 'https://attacker.example' }, { rpID: 'attacker.example' }, { flags: 65 }, 'signature']) {
    const service = passkeys();
    const auth = makeAuthenticator();
    const start = await service.beginRegistration();
    const response = auth.register(start.options.challenge, mutation === 'signature' ? {} : mutation);
    if (mutation === 'signature') { const bytes = Buffer.from(response.response.attestationObject, 'base64url'); bytes[bytes.length - 1] ^= 1; response.response.attestationObject = bytes.toString('base64url'); }
    assert.equal(await service.finishRegistration({ id: start.id, response }), false);
  }
});

test('a registration challenge cannot be replayed, moved, or used after expiry', async () => {
  let time = NOW;
  const service = passkeys(undefined, () => time);
  const auth = makeAuthenticator();
  const start = await service.beginRegistration();
  const input = { id: start.id, response: auth.register(start.options.challenge) };
  assert.ok(await service.finishRegistration(input));
  assert.equal(await service.finishRegistration(input), false);
  const second = await service.beginRegistration();
  assert.equal(await service.finishRegistration({ ...input, id: second.id }), false);
  const expired = await service.beginRegistration();
  time += 120;
  assert.equal(await service.finishRegistration({ id: expired.id, response: auth.register(expired.options.challenge) }), false);
});

test('additional passkeys require an existing account signature and retain member identity', async () => {
  const service = passkeys();
  const auth = makeAuthenticator();
  const start = await service.beginRegistration();
  const first = await service.finishRegistration({ id: start.id, response: auth.register(start.options.challenge) });
  const addition = await service.beginAdditionalRegistration(first.credentialId);
  const permitted = await service.authorizeAdditionalRegistration({ id: addition.id, response: auth.assert(addition.options.challenge) });
  const next = makeAuthenticator();
  const added = await service.finishRegistration({ id: permitted.id, response: next.register(permitted.options.challenge) });
  assert.equal(added.memberId, first.memberId);
  assert.notEqual(added.credentialId, first.credentialId);
});
