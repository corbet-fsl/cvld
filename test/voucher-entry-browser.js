// Real generated cmsg identity, native cvch/cmsg verifier, SQLite and Chromium
// WebAuthn contract. The virtual authenticator does not claim hardware security.
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { createServer } from 'node:http';
import { readFile, writeFile, mkdir, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve, sep } from 'node:path';
import { chromium } from 'playwright';
import { createEntryService } from '../src/entry.js';
import { createEntryHandler } from '../src/http.js';
import { createVoucherBridge } from '../src/voucher-bridge.js';
import { createSqliteState } from '../src/sqlite.js';

const artifact = resolve(process.env.ARTIFACT_ROOT);
const cmsgRoot = resolve(process.env.CMSG_BROWSER_ROOT);
const binary = resolve(process.env.CVLD_VOUCHER_EXECUTABLE);
const work = await mkdtemp(join(tmpdir(), 'cvld-entry-browser-'));
const communityId = 'entry.example', now = Math.floor(Date.now() / 1000);
const sponsor = generateKeyPairSync('ed25519');
const sponsorPublicKey = sponsor.publicKey.export({ format: 'jwk' }).x;
const grantKey = generateKeyPairSync('ed25519').privateKey.export({ format: 'pem', type: 'pkcs8' });
const policyDigest = randomBytes(32).toString('base64url');
const voucher = { id: randomBytes(24).toString('base64url'), valid_until: now + 900 };
// Exact cvch::issuance_bytes public transcript, verified by the pinned cvch Rust
// implementation below; sponsor issuance is a signature, not a mocked verifier.
voucher.signature = sign(null, Buffer.from(JSON.stringify(['cvch.issuance.v1', voucher.id, voucher.valid_until, communityId])), sponsor.privateKey).toString('base64url');
const bridge = createVoucherBridge({ executable: binary, args: [], timeoutMs: 5000, maxRequestBytes: 65536, maxResponseBytes: 16384 });
const checks = [], assets = {}, pageErrors = [];
let handler, database, entry, browser;
const server = createServer(async (request, response) => {
  try {
    const pathname = new URL(request.url, 'http://localhost').pathname;
    if (pathname === '/') { response.writeHead(200, { 'content-type': 'text/html' }); response.end('<!doctype html><title>Voucher entry protocol contract</title>'); return; }
    let file;
    if (pathname === '/client.js') file = new URL('../src/client.js', import.meta.url);
    else if (pathname.startsWith('/cmsg/')) { file = resolve(cmsgRoot, pathname.slice('/cmsg/'.length)); if (!file.startsWith(`${cmsgRoot}${sep}`)) throw new Error('Path rejected'); }
    if (file) {
      const data = await readFile(file); assets[pathname] = createHash('sha256').update(data).digest('hex');
      response.writeHead(200, { 'content-type': pathname.endsWith('.wasm') ? 'application/wasm' : 'text/javascript' }); response.end(data); return;
    }
    const chunks = []; let bytes = 0;
    for await (const chunk of request) { bytes += chunk.length; if (bytes > 65536) throw new Error('Request limit'); chunks.push(chunk); }
    const result = await handler(new Request(`${origin}${request.url}`, { method: request.method, headers: request.headers,
      ...(request.method === 'GET' ? {} : { body: Buffer.concat(chunks) }) }));
    response.writeHead(result.status, Object.fromEntries(result.headers)); response.end(Buffer.from(await result.arrayBuffer()));
  } catch { response.writeHead(400); response.end(); }
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const origin = `http://localhost:${server.address().port}`;
function restart() {
  database?.close();
  database = createSqliteState({ path: join(work, 'state.sqlite'), maxReceipts: 20, maxCredentials: 20, maxVoucherSpends: 20, busyTimeoutMs: 5000 });
  entry = createEntryService({ communityId, origin, rpID: 'localhost', rpName: 'Voucher entry contract', clock: () => Math.floor(Date.now() / 1000),
    challengeLifetimeSeconds: 120, maxPendingChallenges: 20, sessionLifetimeSeconds: 300, maxSessions: 20, maxPasskeysPerMember: 2,
    requireUserVerification: true, credentialStore: database.credentials, membershipStore: database.members, voucherBridge: bridge, sponsorPublicKey,
    admission: { signingKey: grantKey, policyDigest, grantLifetimeSeconds: 120 } });
  handler = createEntryHandler({ entry, origin, maxBodyBytes: 65536, cookieLifetimeSeconds: 300, sessionCookie: 'entrySession', allowInsecureLocalhost: true });
}
try {
  restart();
  browser = await chromium.launch({ executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE, headless: true });
  const page = await browser.newPage(); page.on('pageerror', error => pageErrors.push(error.message));
  const cdp = await page.context().newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', ctap2Version: 'ctap2_1', transport: 'usb', hasResidentKey: true,
    hasUserVerification: true, hasPrf: true, hasHmacSecret: true, isUserVerified: true, automaticPresenceSimulation: true } });
  await page.goto(origin);
  const identity = await page.evaluate(async ({ communityId, now }) => {
    const cmsg = await import('/cmsg/cmsg.js'); await cmsg.default();
    globalThis.entryRoot = new cmsg.BrowserIdentity(communityId); globalThis.entryDevice = new cmsg.BrowserMember();
    const authorization = JSON.parse(entryRoot.authorizeDevice(entryDevice.chatPublicKey(), now, now + 600));
    return { memberId: entryRoot.memberId(), chatPublicKey: authorization.devicePublicKey, authorization };
  }, { communityId, now });
  assert.equal(await bridge.verifyDeviceAuthorization({ ...identity, communityId, now }), true);
  for (const mutation of [value => { value.memberId = randomBytes(32).toString('base64url'); }, value => { value.communityId = 'wrong'; },
    value => { value.chatPublicKey = randomBytes(32).toString('base64url'); }, value => { value.now = now + 600; },
    value => { value.authorization.signature = randomBytes(64).toString('base64url'); },
    value => { value.authorization.rootPublicKey = randomBytes(32).toString('base64url'); }]) {
    const value = structuredClone({ ...identity, communityId, now }); mutation(value); assert.equal(await bridge.verifyDeviceAuthorization(value), false);
  }
  checks.push('actual cmsg root-derived member authorization and six forged/scope/time rejections');
  const redemption = { voucher, communityId, sponsorPublicKey, memberId: identity.memberId, now };
  assert.ok(await bridge.verifyVoucher(redemption));
  for (const mutation of [value => { value.communityId = 'wrong'; }, value => { value.now = voucher.valid_until; },
    value => { value.sponsorPublicKey = generateKeyPairSync('ed25519').publicKey.export({ format: 'jwk' }).x; },
    value => { value.voucher.id += '-changed'; }, value => { value.voucher.signature = randomBytes(64).toString('base64url'); }]) {
    const value = structuredClone(redemption); mutation(value); assert.equal(await bridge.verifyVoucher(value), false);
  }
  checks.push('real cvch voucher verification and five signature/scope/expiry rejections');
  const denied = await fetch(`${origin}/auth/register/begin`, { method: 'POST', headers: { origin: 'https://attacker.example', 'content-type': 'application/json' }, body: JSON.stringify({ ...identity, voucher }) });
  assert.equal(denied.status, 403);
  const registered = await page.evaluate(async input => {
    globalThis.post = async (path, body = {}) => { const response = await fetch(path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }); return { status: response.status, body: await response.json() }; };
    const { registerPasskey, authenticateWithWallet } = await import('/client.js');
    const start = await post('/auth/register/begin', input);
    if (start.status !== 200 || typeof start.body.options?.challenge !== 'string') throw new Error('Registration options unavailable');
    const attestation = { id: start.body.id, response: await registerPasskey(start.body.options) };
    const precommit = await post('/auth/register/precommit', attestation);
    const wallet = await authenticateWithWallet({ options: precommit.body.options, scope: input.authorization.communityId });
    globalThis.walletEnvelope = wallet.wallet.envelope;
    const key = await wallet.wallet.storageKey('cmsg');
    const context = new TextEncoder().encode('cvld.entry-browser.v1');
    try {
      const encrypted = { wallet: walletEnvelope, root: Array.from(entryRoot.seal(key, context)), device: Array.from(entryDevice.snapshot(key, context)) };
      localStorage.setItem('encrypted-member-state', JSON.stringify(encrypted));
      if (!JSON.parse(localStorage.getItem('encrypted-member-state')).root.length) throw new Error('Encrypted persistence failed');
    } finally { key.fill(0); }
    globalThis.registration = { id: start.body.id, walletResponse: wallet.response };
    return await post('/auth/register/finish', registration);
  }, { ...identity, voucher });
  assert.equal(registered.status, 200); assert.equal(registered.body.memberId, identity.memberId);
  assert.ok(registered.body.admission.signature); assert.equal(database.credentials.hasMember(communityId, identity.memberId), true);
  assert.deepEqual(await page.evaluate(async () => (await post('/auth/register/finish', registration)).body), { ok: false });
  checks.push('actual Chromium registration, bound PRF wallet challenge, encrypted root/device persistence before durable voucher/passkey commit, registration replay rejection');
  const authenticate = () => page.evaluate(async communityId => {
    const { authenticateWithWallet } = await import('/client.js');
    const start = await post('/auth/login/begin');
    const unlocked = await authenticateWithWallet({ options: start.body.options, scope: communityId, ...(globalThis.walletEnvelope ? { envelope: walletEnvelope } : {}) });
    globalThis.walletEnvelope = unlocked.wallet.envelope;
    globalThis.authentication = { id: start.body.id, response: unlocked.response };
    const result = await post('/auth/login/finish', authentication);
    if (Object.keys(unlocked.response.clientExtensionResults).length) throw new Error('Unsanitized PRF');
    return { result, sessionStatus: (await fetch('/auth/session')).status, exposedCookie: document.cookie };
  }, communityId);
  assert.equal(await page.evaluate(async () => (await fetch('/auth/session')).status), 200);
  await page.evaluate(async () => { await post('/auth/logout'); });
  assert.equal(await page.evaluate(async () => (await fetch('/auth/session')).status), 401);
  let authenticated = await authenticate();
  assert.equal(authenticated.result.status, 200); assert.equal(authenticated.result.body.memberId, identity.memberId);
  assert.equal(authenticated.result.body.sessionId, undefined); assert.equal(authenticated.sessionStatus, 200); assert.equal(authenticated.exposedCookie, '');
  const cookie = (await page.context().cookies()).find(value => value.name === 'entrySession');
  assert.ok(cookie?.httpOnly); assert.equal(cookie.sameSite, 'Strict'); assert.equal(cookie.secure, false);
  assert.equal(await page.evaluate(async () => (await post('/auth/login/finish', authentication)).status), 401);
  await page.evaluate(async () => { await post('/auth/logout'); });
  assert.equal(await page.evaluate(async () => (await fetch('/auth/session')).status), 401);
  authenticated = await authenticate(); assert.equal(authenticated.result.status, 200);
  restart(); assert.equal(await page.evaluate(async () => (await fetch('/auth/session')).status), 401);
  authenticated = await authenticate(); assert.equal(authenticated.result.status, 200);
  checks.push('discoverable passkey login, stable PRF wallet unlock, HttpOnly same-site localhost cookie, replay/logout/restart session rejection');
  const replay = await page.evaluate(async ({ communityId, now, voucher }) => {
    const cmsg = await import('/cmsg/cmsg.js'); const root = new cmsg.BrowserIdentity(communityId), device = new cmsg.BrowserMember();
    try {
      const authorization = JSON.parse(root.authorizeDevice(device.chatPublicKey(), now, now + 600));
      const start = await post('/auth/register/begin', { memberId: root.memberId(), chatPublicKey: authorization.devicePublicKey, authorization, voucher });
      const client = await import('/client.js');
      const response = await client.registerPasskey(start.body.options);
      const precommit = await post('/auth/register/precommit', { id: start.body.id, response });
      const wallet = await client.authenticateWithWallet({ options: precommit.body.options, scope: communityId });
      return await post('/auth/register/finish', { id: start.body.id, walletResponse: wallet.response });
    } finally { device.free(); root.free(); }
  }, { communityId, now, voucher });
  assert.deepEqual(replay.body, { ok: false });
  checks.push('same real voucher rejected for another cmsg member after SQLite reopen');
  await page.evaluate(() => { entryDevice.free(); entryRoot.free(); });
  assert.deepEqual(pageErrors, []); assert.ok(assets['/cmsg/cmsg_bg.wasm']);
  await mkdir(artifact, { recursive: true });
  const summary = { source: process.env.GITHUB_SHA ?? process.env.CI_COMMIT_SHA, ok: true, checks, assets,
    voucherBinarySha256: createHash('sha256').update(await readFile(binary)).digest('hex'), browserVersion: browser.version(), privateStateRecorded: false };
  await writeFile(join(artifact, 'voucher-entry-browser.json'), `${JSON.stringify(summary, null, 2)}\n`);
  console.log(JSON.stringify({ ok: true, checks }));
} finally {
  await browser?.close(); await new Promise(resolve => server.close(resolve)); database?.close(); await rm(work, { recursive: true, force: true });
}
