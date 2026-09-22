import assert from 'node:assert/strict';
import { test } from 'node:test';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createApiKeyService } from '../src/api-keys.js';
import { NOW } from './fixtures.js';

const member = () => randomBytes(32).toString('base64url');
const configured = { communityId: 'api.example', clock: () => NOW, maxKeys: 4, maxKeysPerMember: 2,
  maxLifetimeSeconds: 600, busyTimeoutMs: 5000, allowedScopes: ['discovery:read', 'messages:send'] };
const open = (options = {}) => createApiKeyService({ ...configured, path: ':memory:', ...options });
const issue = (service, memberId = member(), values = {}) => service.create({ memberId, name: 'Automation', scopes: ['discovery:read'], expiresAt: NOW + 60, ...values });

test('API token authenticates only explicit scopes and returns no secret through list or authenticate', () => {
  const service = open(), owner = member();
  try {
    const key = issue(service, owner);
    assert.match(key.token, /^cvld\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}$/);
    const authority = service.authenticate(key.token, 'discovery:read');
    assert.equal(authority.memberId, owner); assert.equal(authority.communityId, 'api.example'); assert.equal(authority.kind, 'apiKey');
    assert.equal(service.authenticate(key.token, 'messages:send'), false);
    assert.equal(service.authenticate(key.token, 'admin'), false);
    assert.equal(JSON.stringify(service.list(owner)).includes(key.token), false);
    assert.equal(JSON.stringify(authority).includes(key.token), false);
    assert.equal(Object.hasOwn(service.list(owner)[0], 'digest'), false);
    const forged = key.token.slice(0, -1) + (key.token.endsWith('a') ? 'b' : 'a');
    for (const token of [forged, `${key.token}=`, `Bearer ${key.token}`, '', null, randomBytes(48).toString('base64url')]) assert.equal(service.authenticate(token, 'discovery:read'), false);
    for (const scopes of [[], ['admin'], ['discovery:read', 'discovery:read']]) assert.throws(() => issue(service, owner, { scopes }));
  } finally { service.close(); }
});

test('only the owning member can list and revoke a key', () => {
  const service = open(), owner = member(), other = member();
  try {
    const key = issue(service, owner);
    assert.deepEqual(service.list(other), []);
    assert.equal(service.revoke({ memberId: other, id: key.id }), false);
    assert.ok(service.authenticate(key.token, 'discovery:read'));
    assert.equal(service.revoke({ memberId: owner, id: key.id }), true);
    assert.equal(service.authenticate(key.token, 'discovery:read'), false);
    assert.equal(service.revoke({ memberId: owner, id: key.id }), false);
  } finally { service.close(); }
});

test('plaintext tokens are absent from database files and revocation survives restart and community changes', () => {
  const directory = mkdtempSync(join(tmpdir(), 'cvld-api-')); const path = join(directory, 'api.sqlite');
  let service = open({ path }); const owner = member();
  try {
    const key = issue(service, owner);
    for (const file of readdirSync(directory)) {
      const data = readFileSync(join(directory, file));
      assert.equal(data.includes(Buffer.from(key.token)), false);
      assert.equal(data.includes(Buffer.from(key.token.split('.')[2])), false);
    }
    service.close(); service = open({ path, communityId: 'other.example' });
    assert.equal(service.authenticate(key.token, 'discovery:read'), false);
    assert.equal(service.revoke({ memberId: owner, id: key.id }), false);
    assert.deepEqual(service.list(owner), []);
    service.close(); service = open({ path });
    assert.equal(service.authenticate(key.token, 'discovery:read').memberId, owner);
    assert.equal(service.revoke({ memberId: owner, id: key.id }), true);
    service.close(); service = open({ path });
    assert.equal(service.authenticate(key.token, 'discovery:read'), false);
  } finally { service.close(); rmSync(directory, { recursive: true, force: true }); }
});

test('expiry, bounded lifetime and durable clock floor prevent expired token revival', () => {
  const directory = mkdtempSync(join(tmpdir(), 'cvld-api-clock-')); const path = join(directory, 'api.sqlite');
  let time = NOW; let service = open({ path, clock: () => time }); const owner = member();
  try {
    assert.throws(() => issue(service, owner, { expiresAt: NOW }));
    assert.throws(() => issue(service, owner, { expiresAt: NOW + 601 }));
    const key = issue(service, owner);
    time = NOW + 59; assert.ok(service.authenticate(key.token, 'discovery:read'));
    time = NOW + 60; assert.equal(service.authenticate(key.token, 'discovery:read'), false);
    service.close(); time = NOW; service = open({ path, clock: () => time });
    assert.equal(service.authenticate(key.token, 'discovery:read'), false);
    assert.throws(() => issue(service, owner), /Clock moved backwards/);
  } finally { service.close(); rmSync(directory, { recursive: true, force: true }); }
});

test('per-member and community capacities reject atomically and expiry frees capacity', () => {
  let time = NOW; const service = open({ clock: () => time, maxKeys: 2, maxKeysPerMember: 1 });
  const first = member(), second = member();
  try {
    issue(service, first); assert.throws(() => issue(service, first), /capacity/);
    issue(service, second); assert.throws(() => issue(service, member()), /capacity/);
    assert.equal(service.list(first).length, 1); assert.equal(service.list(second).length, 1);
    time = NOW + 60;
    assert.ok(issue(service, first, { expiresAt: time + 60 }));
    assert.deepEqual(service.list(second), []);
  } finally { service.close(); }
});

test('caller mutation of scopes cannot change configured authority or issued key permissions', () => {
  const scopes = ['discovery:read']; const service = open({ allowedScopes: scopes });
  try {
    scopes.push('messages:send'); assert.throws(() => issue(service, member(), { scopes: ['messages:send'] }));
    const requested = ['discovery:read'], owner = member(), key = issue(service, owner, { scopes: requested });
    requested[0] = 'messages:send'; key.scopes[0] = 'messages:send';
    assert.ok(service.authenticate(key.token, 'discovery:read'));
    assert.equal(service.authenticate(key.token, 'messages:send'), false);
    const listed = service.list(owner); listed[0].scopes.push('messages:send');
    assert.deepEqual(service.list(owner)[0].scopes, ['discovery:read']);
  } finally { service.close(); }
});
