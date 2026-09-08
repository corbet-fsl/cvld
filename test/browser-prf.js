import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { chromium } from 'playwright';
import { createPasskeyService } from '../src/passkeys.js';
import { createMemoryCredentialStore } from '../src/credential-store.js';
const client = readFileSync(new URL('../src/client.js', import.meta.url));
const server = createServer((req, res) => {
  if (req.url === '/client.js') { res.setHeader('Content-Type', 'text/javascript'); res.end(client); }
  else { res.setHeader('Content-Type', 'text/html'); res.end('<!doctype html><title>Local synthetic passkey test</title>'); }
});
await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
const origin = `http://localhost:${server.address().port}`;
const communityId = 'browser.example';
const browser = await chromium.launch();
try {
  const page = await browser.newPage();
  const cdp = await page.context().newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  const authenticator = await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', ctap2Version: 'ctap2_1', transport: 'usb', hasResidentKey: true, hasUserVerification: true, hasPrf: true, hasHmacSecret: true, isUserVerified: true, automaticPresenceSimulation: true } });
  await page.goto(origin);
  const passkeys = createPasskeyService({ credentialStore: createMemoryCredentialStore({ maxCredentials: 10 }), communityId, origin, rpID: 'localhost', rpName: 'Synthetic test', clock: () => 1800000000, challengeLifetimeSeconds: 120, maxPendingChallenges: 10, requireUserVerification: true, maxPasskeysPerMember: 3 });
  const registration = await passkeys.beginRegistration();
  const response = await page.evaluate(async (options) => (await import('/client.js')).registerPasskey(options), registration.options);
  assert.deepEqual(response.clientExtensionResults, {});
  const account = await passkeys.finishRegistration({ id: registration.id, response });
  assert.equal(account.memberId, registration.memberId);
  const first = await passkeys.beginAdditionalRegistration(account.credentialId);
  const firstResponse = await page.evaluate(async ({ options, scope }) => {
    const { authenticateWithWallet } = await import('/client.js');
    const result = await authenticateWithWallet({ options, scope });
    window.syntheticWallet = result.wallet;
    window.syntheticKey = Array.from(await result.wallet.storageKey('cmsg'));
    window.syntheticEnvelope = result.wallet.envelope;
    if (JSON.stringify(result).includes('prf')) throw new Error('PRF output serialized');
    return result.response;
  }, { options: first.options, scope: communityId });
  assert.deepEqual(firstResponse.clientExtensionResults, {});
  assert.ok(await passkeys.authorizeAdditionalRegistration({ id: first.id, response: firstResponse }));
  const second = await passkeys.beginAdditionalRegistration(account.credentialId);
  const secondResponse = await page.evaluate(async ({ options, scope }) => {
    const { authenticateWithWallet } = await import('/client.js');
    const result = await authenticateWithWallet({ options, scope, envelope: window.syntheticEnvelope });
    if (JSON.stringify(Array.from(await result.wallet.storageKey('cmsg'))) !== JSON.stringify(window.syntheticKey)) throw new Error('Wallet key changed');
    return result.response;
  }, { options: second.options, scope: communityId });
  assert.ok(await passkeys.authorizeAdditionalRegistration({ id: second.id, response: secondResponse }));
  await cdp.send('WebAuthn.removeVirtualAuthenticator', authenticator);
  await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', ctap2Version: 'ctap2_1', transport: 'usb', hasResidentKey: true, hasUserVerification: true, hasPrf: false, isUserVerified: true, automaticPresenceSimulation: true } });
  const unsupported = await passkeys.beginRegistration();
  await assert.rejects(page.evaluate(async (options) => (await import('/client.js')).registerPasskey(options), unsupported.options), /does not support private wallet/);
  console.log('Chromium virtual authenticator: real registration, real PRF unlock twice, sanitized server responses, unsupported PRF rejection passed');
} finally { await browser.close(); await new Promise((resolve) => server.close(resolve)); }
