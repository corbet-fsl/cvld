import assert from 'node:assert/strict';
import { test } from 'node:test';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createEntryService } from '../src/entry.js';
import { createEntryHandler } from '../src/http.js';
import { createSqliteState } from '../src/sqlite.js';
import { createApiKeyService } from '../src/api-keys.js';
import { makeAuthenticator, NOW, ORIGIN, RP_ID } from './fixtures.js';

const communityId = 'community.example';
const bytes = () => randomBytes(32).toString('base64url');
function identity() {
  const memberId = bytes(), chatPublicKey = bytes();
  return { memberId, chatPublicKey, voucher: { id: bytes(), valid_until: NOW + 600, signature: randomBytes(64).toString('base64url') },
    authorization: { version: 1, communityId, memberId, rootPublicKey: bytes(), devicePublicKey: chatPublicKey, issuedAt: NOW - 1, expiresAt: NOW + 600, signature: randomBytes(64).toString('base64url') } };
}
function state(path = ':memory:', overrides = {}) {
  return createSqliteState({ path, maxReceipts: 20, maxCredentials: 20, maxVoucherSpends: 20, busyTimeoutMs: 5000, ...overrides });
}
// These protocol tests isolate the authority process boundary. The separate
// voucher-entry-browser contract uses actual cmsg and cvch native verification.
function service(database, overrides = {}) {
  return createEntryService({ communityId, origin: ORIGIN, rpID: RP_ID, rpName: 'Entry contract', clock: () => NOW,
    challengeLifetimeSeconds: 120, maxPendingChallenges: 10, sessionLifetimeSeconds: 300,
    maxSessions: 10, maxPasskeysPerMember: 2, requireUserVerification: true,
    credentialStore: database.credentials, membershipStore: database.members,
    sponsorPublicKey: generateKeyPairSync('ed25519').publicKey.export({ format: 'jwk' }).x,
    voucherBridge: { verifyDeviceAuthorization: async () => true,
      verifyVoucher: async ({ voucher, memberId }) => ({ receiptId: Buffer.from(voucher.id, 'base64url').toString('hex'), memberBinding: Buffer.from(memberId, 'base64url').toString('hex'), validUntil: voucher.valid_until }) },
    admission: { signingKey: generateKeyPairSync('ed25519').privateKey.export({ format: 'pem', type: 'pkcs8' }), policyDigest: bytes(), grantLifetimeSeconds: 60 }, ...overrides });
}
async function register(entry, input = identity(), authenticator = makeAuthenticator()) {
  const start = await entry.beginRegistration(input);
  assert.equal(typeof start.options.challenge, 'string');
  const precommit = await entry.beginRegistrationPrecommit({ id: start.id, response: authenticator.register(start.options.challenge) });
  assert.equal(precommit.options.allowCredentials[0].id, authenticator.credential.id);
  const finish = { id: start.id, walletResponse: authenticator.assert(precommit.options.challenge, { counter: 1 }) };
  return { input, authenticator, start, finish, result: await entry.finishRegistration(finish) };
}
async function login(entry, authenticator, options = {}) {
  const start = await entry.beginAuthentication();
  assert.equal(typeof start.options.challenge, 'string');
  const input = { id: start.id, response: authenticator.assert(start.options.challenge, options) };
  return { input, result: await entry.finishAuthentication(input) };
}

test('voucher registration creates one durable member, admission and passkey; login creates a revocable session', async () => {
  const db = state();
  try {
    const entry = service(db), enrolled = await register(entry);
    assert.equal(enrolled.result.memberId, enrolled.input.memberId);
    assert.equal(db.members.get(communityId, enrolled.input.memberId).chatPublicKey, enrolled.input.chatPublicKey);
    assert.equal(db.credentials.get(communityId, enrolled.authenticator.credential.id).memberId, enrolled.input.memberId);
    assert.equal(db.credentials.get(communityId, enrolled.authenticator.credential.id).counter, 1);
    assert.equal(enrolled.result.admission.expiresAt, NOW + 60);
    assert.equal(await entry.finishRegistration(enrolled.finish), false);
    entry.revokeSession(enrolled.result.sessionId);
    // The mandatory precommit assertion already advanced the counter to one.
    const authenticated = await login(entry, enrolled.authenticator, { counter: 2 });
    assert.equal(entry.getSession(authenticated.result.sessionId).memberId, enrolled.input.memberId);
    assert.equal(await entry.finishAuthentication(authenticated.input), false);
    assert.equal(entry.revokeSession(authenticated.result.sessionId), true);
    assert.equal(entry.getSession(authenticated.result.sessionId), false);
  } finally { db.close(); }
});

test('registration rejects invalid origin, RP, user verification and attestation signature without burning voucher', async () => {
  for (const mutation of [{ origin: 'https://attacker.example' }, { rpID: 'attacker.example' }, { flags: 65 }, 'signature']) {
    const db = state();
    try {
      const entry = service(db), input = identity(), auth = makeAuthenticator();
      const start = await entry.beginRegistration(input);
      const response = auth.register(start.options.challenge, mutation === 'signature' ? {} : mutation);
      if (mutation === 'signature') { const value = Buffer.from(response.response.attestationObject, 'base64url'); value[value.length - 1] ^= 1; response.response.attestationObject = value.toString('base64url'); }
      assert.equal(await entry.beginRegistrationPrecommit({ id: start.id, response }), false);
      assert.equal(db.members.get(communityId, input.memberId), undefined);
      assert.ok((await register(entry, input, auth)).result);
    } finally { db.close(); }
  }
});

test('binding scope, time and delegated cmsg verification are required before a challenge is created', async () => {
  const db = state();
  try {
    const entry = service(db);
    for (const mutate of [x => { x.authorization.memberId = bytes(); }, x => { x.authorization.communityId = 'other'; },
      x => { x.authorization.devicePublicKey = bytes(); }, x => { x.authorization.issuedAt = NOW + 1; },
      x => { x.authorization.expiresAt = NOW; }, x => { x.authorization.extra = true; }]) {
      const input = identity(); mutate(input); await assert.rejects(entry.beginRegistration(input));
    }
    await assert.rejects(service(db, { voucherBridge: { verifyDeviceAuthorization: async () => false, verifyVoucher: async () => false } }).beginRegistration(identity()));
  } finally { db.close(); }
});

test('registration snapshots caller input before asynchronous authority verification', async () => {
  const db = state();
  try {
    let release, saw;
    const ready = new Promise(resolve => { release = resolve; });
    const original = identity(), input = structuredClone(original);
    const entry = service(db, { voucherBridge: { verifyDeviceAuthorization: async () => { await ready; return true; },
      verifyVoucher: async value => { saw = structuredClone(value); return { receiptId: 'a'.repeat(64), memberBinding: 'b'.repeat(64), validUntil: NOW + 600 }; } } });
    const opening = entry.beginRegistration(input);
    input.memberId = bytes(); input.chatPublicKey = bytes(); input.authorization.memberId = input.memberId; input.voucher.id = 'mutated';
    release(); const start = await opening;
    assert.equal(start.memberId, original.memberId);
    const auth = makeAuthenticator();
    const precommit = await entry.beginRegistrationPrecommit({ id: start.id, response: auth.register(start.options.challenge) });
    const result = await entry.finishRegistration({ id: start.id, walletResponse: auth.assert(precommit.options.challenge) });
    assert.equal(result.memberId, original.memberId);
    assert.equal(saw.voucher.id, original.voucher.id);
  } finally { db.close(); }
});

test('expired challenges and authority cannot commit after asynchronous voucher verification', async () => {
  for (const elapsed of [20, 120]) {
    const db = state(); let time = NOW;
    try {
      const entry = service(db, { clock: () => time, voucherBridge: { verifyDeviceAuthorization: async () => true,
        verifyVoucher: async () => { time += elapsed; return { receiptId: 'a'.repeat(64), memberBinding: 'b'.repeat(64), validUntil: NOW + 600 }; } } });
      const input = identity(); if (elapsed === 20) input.authorization.expiresAt = NOW + 10;
      const enrollment = await register(entry, input);
      assert.equal(enrollment.result, false);
      assert.equal(db.credentials.hasMember(communityId, input.memberId), false);
    } finally { db.close(); }
  }
});

test('challenge capacity is bounded and expired challenges free capacity', async () => {
  const db = state(); let time = NOW;
  try {
    const entry = service(db, { clock: () => time, maxPendingChallenges: 1 });
    await entry.beginAuthentication(); await assert.rejects(entry.beginAuthentication(), /capacity/);
    time += 120; assert.equal(typeof (await entry.beginAuthentication()).options.challenge, 'string');
  } finally { db.close(); }
});

test('concurrent nonzero counter assertions produce only one session and capacity rejection preserves counter', async () => {
  const db = state();
  try {
    const entry = service(db, { maxSessions: 1 }), enrolled = await register(entry);
    entry.revokeSession(enrolled.result.sessionId);
    const starts = await Promise.all([entry.beginAuthentication(), entry.beginAuthentication()]);
    const results = await Promise.all(starts.map(start => entry.finishAuthentication({ id: start.id, response: enrolled.authenticator.assert(start.options.challenge, { counter: 2 }) })));
    assert.equal(results.filter(Boolean).length, 1);
    assert.equal((await login(entry, enrolled.authenticator, { counter: 3 })).result, false);
    assert.equal(db.credentials.get(communityId, enrolled.authenticator.credential.id).counter, 2);
    entry.revokeSession(results.find(Boolean).sessionId);
    assert.ok((await login(entry, enrolled.authenticator, { counter: 3 })).result);
  } finally { db.close(); }
});

test('registration cannot spend a voucher before the same passkey completes its wallet challenge', async () => {
  const db = state();
  try {
    const entry = service(db), input = identity(), auth = makeAuthenticator();
    const first = await entry.beginRegistration(input);
    assert.equal(await entry.finishRegistration({ id: first.id, response: auth.register(first.options.challenge) }), false);
    assert.equal(db.members.get(communityId, input.memberId), undefined);
    const next = await entry.beginRegistration(input);
    const precommit = await entry.beginRegistrationPrecommit({ id: next.id, response: auth.register(next.options.challenge) });
    assert.equal(db.members.get(communityId, input.memberId), undefined);
    assert.equal(db.credentials.hasMember(communityId, input.memberId), false);
    assert.equal(await entry.finishRegistration({ id: next.id, walletResponse: makeAuthenticator().assert(precommit.options.challenge) }), false);
    assert.equal(db.members.get(communityId, input.memberId), undefined);
    assert.ok((await register(entry, input, auth)).result);
  } finally { db.close(); }
});

test('credential capacity failure does not claim voucher; successful claim rejects another member after restart', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'cvld-entry-')); const path = join(directory, 'state.sqlite');
  let db = state(path, { maxCredentials: 1 });
  try {
    assert.ok((await register(service(db))).result);
    const input = identity(); assert.equal((await register(service(db), input)).result, false);
    db.close(); db = state(path, { maxCredentials: 2 });
    assert.ok((await register(service(db), input)).result);
    db.close(); db = state(path, { maxCredentials: 3 });
    const attacker = identity(); attacker.voucher = input.voucher;
    assert.equal((await register(service(db), attacker)).result, false);
    assert.equal(db.members.get(communityId, attacker.memberId), undefined);
    assert.ok(db.members.get(communityId, input.memberId));
  } finally { db.close(); rmSync(directory, { recursive: true, force: true }); }
});

test('atomic voucher claim rejects simultaneous distinct members', async () => {
  const db = state();
  try {
    const entry = service(db), first = identity(), second = identity(); second.voucher = first.voucher;
    const results = await Promise.all([register(entry, first), register(entry, second)]);
    assert.equal(results.filter(value => value.result).length, 1);
    assert.equal([first, second].filter(value => db.members.get(communityId, value.memberId)).length, 1);
  } finally { db.close(); }
});

test('HTTP requires same origin and trusted cookie authority, hides session tokens, and sets correct transport cookie flags', async () => {
  for (const origin of [ORIGIN, 'http://localhost:4321']) {
    let calls = 0, rebound;
    const entry = { beginRegistration: async () => ({}), finishRegistration: async () => false, beginAuthentication: async () => ({}),
      finishAuthentication: async () => { calls++; return { sessionId: 'server-session', memberId: 'member' }; },
      rebindDevice: async value => { rebound = value; return false; }, revokeSession() {}, getSession: () => false };
    const handle = createEntryHandler({ entry, origin, maxBodyBytes: 1024, cookieLifetimeSeconds: 300, sessionCookie: 'session', allowInsecureLocalhost: true });
    const request = (path, body = {}, headers = {}) => new Request(`${origin}${path}`, { method: 'POST', headers: { origin, 'content-type': 'application/json', ...headers }, body: JSON.stringify(body) });
    assert.equal((await handle(request('/auth/login/finish', {}, { origin: 'https://attacker.example' }))).status, 403);
    assert.equal(calls, 0);
    const response = await handle(request('/auth/login/finish'));
    assert.deepEqual(await response.json(), { memberId: 'member' });
    assert.match(response.headers.get('set-cookie'), /HttpOnly; SameSite=Strict/);
    assert.equal(response.headers.get('set-cookie').includes('; Secure'), origin.startsWith('https:'));
    await handle(request('/auth/rebind', { sessionId: 'injected', chatPublicKey: bytes(), authorization: {} }, { cookie: 'session=trusted' }));
    assert.equal(rebound.sessionId, 'trusted');
    assert.equal((await handle(request('/auth/register/begin', { oversized: 'x'.repeat(1025) }))).status, 400);
    assert.equal((await handle(new Request(`${origin}/auth/session`))).status, 401);
  }
});

test('rebind snapshots input and rechecks session revocation after asynchronous native verification', async () => {
  const db = state(); let waitForAuthority;
  try {
    const entry = service(db, { voucherBridge: { verifyDeviceAuthorization: async () => { if (waitForAuthority) await waitForAuthority; return true; },
      verifyVoucher: async () => ({ receiptId: 'a'.repeat(64), memberBinding: 'b'.repeat(64), validUntil: NOW + 600 }) } });
    const enrolled = await register(entry), chatPublicKey = bytes();
    const authorization = { ...enrolled.input.authorization, devicePublicKey: chatPublicKey };
    let release; waitForAuthority = new Promise(resolve => { release = resolve; });
    const input = { sessionId: enrolled.result.sessionId, chatPublicKey, authorization: structuredClone(authorization) };
    const pending = entry.rebindDevice(input);
    input.chatPublicKey = bytes(); input.authorization.devicePublicKey = input.chatPublicKey;
    release(); assert.equal((await pending).chatPublicKey, chatPublicKey);
    assert.equal(db.members.get(communityId, enrolled.input.memberId).chatPublicKey, chatPublicKey);
    waitForAuthority = new Promise(resolve => { release = resolve; });
    const nextKey = bytes();
    const revoked = entry.rebindDevice({ sessionId: enrolled.result.sessionId, chatPublicKey: nextKey, authorization: { ...authorization, devicePublicKey: nextKey } });
    entry.revokeSession(enrolled.result.sessionId); release();
    assert.equal(await revoked, false);
    assert.equal(db.members.get(communityId, enrolled.input.memberId).chatPublicKey, chatPublicKey);
  } finally { db.close(); }
});

test('HTTP API key creation and revocation require cookie authentication and ignore body member identity', async () => {
  const owner = bytes(), other = bytes(); let current = true;
  const keys = createApiKeyService({ path: ':memory:', communityId, clock: () => NOW, maxKeys: 5, maxKeysPerMember: 5,
    maxLifetimeSeconds: 300, busyTimeoutMs: 1000, allowedScopes: ['discovery:read', 'api-key:manage'] });
  try {
    const entry = { beginRegistration: async () => ({}), finishRegistration: async () => false, beginAuthentication: async () => ({}), finishAuthentication: async () => false,
      getSession: token => token === 'owner-session' ? { memberId: owner } : false, isCurrentMember: memberId => current && memberId === owner };
    const handle = createEntryHandler({ entry, apiKeys: keys, origin: ORIGIN, maxBodyBytes: 4096, cookieLifetimeSeconds: 300, sessionCookie: 'session' });
    const request = (path, input, headers = {}) => new Request(`${ORIGIN}${path}`, { method: 'POST', headers: { origin: ORIGIN, 'content-type': 'application/json', ...headers }, body: JSON.stringify(input) });
    const created = await handle(request('/auth/api-keys', { memberId: other, name: 'Automation', scopes: ['discovery:read', 'api-key:manage'], expiresAt: NOW + 60 }, { cookie: 'session=owner-session' }));
    assert.equal(created.status, 200); const key = await created.json();
    assert.equal(keys.list(owner).length, 1); assert.deepEqual(keys.list(other), []);
    const listed = await handle(new Request(`${ORIGIN}/auth/api-keys`, { headers: { cookie: 'session=owner-session' } }));
    assert.equal(listed.status, 200); assert.equal((await listed.json())[0].id, key.id);
    assert.equal((await handle(new Request(`${ORIGIN}/auth/api-keys`, { headers: { cookie: 'session=owner-session', origin: 'https://attacker.example' } }))).status, 401);
    const bearer = { authorization: `Bearer ${key.token}` };
    const headless = new Request(`${ORIGIN}/mcp`, { method: 'POST', headers: bearer });
    assert.equal(handle.authenticatedPrincipal(headless, 'discovery:read').memberId, owner);
    assert.equal(handle.authenticatedPrincipal(new Request(`${ORIGIN}/mcp`, { method: 'POST', headers: { ...bearer, origin: 'https://attacker.example' } }), 'discovery:read'), false);
    assert.equal(handle.authenticatedPrincipal(new Request(`${ORIGIN}/mcp`, { method: 'POST', headers: { cookie: 'session=owner-session' } }), 'discovery:read'), false);
    assert.equal((await handle(request('/auth/api-keys', { name: 'Privilege clone', scopes: ['discovery:read'], expiresAt: NOW + 60 }, bearer))).status, 401);
    assert.equal((await handle(request('/auth/api-keys/revoke', { id: key.id }, bearer))).status, 401);
    const authenticated = handle.authenticatedPrincipal(new Request(`${ORIGIN}/discovery`, { headers: bearer }), 'discovery:read');
    assert.equal(authenticated.memberId, owner);
    current = false;
    assert.equal(handle.authenticatedPrincipal(new Request(`${ORIGIN}/discovery`, { headers: bearer }), 'discovery:read'), false);
    current = true;
    const revoked = await handle(request('/auth/api-keys/revoke', { memberId: other, id: key.id }, { cookie: 'session=owner-session' }));
    assert.deepEqual(await revoked.json(), { ok: true }); assert.equal(keys.authenticate(key.token, 'discovery:read'), false);
  } finally { keys.close(); }
});
