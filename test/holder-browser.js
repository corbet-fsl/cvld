// Actual browser AnonCreds holder -> existing native Node issuer/verifier.
// The eligibility fact is an explicitly synthetic signed voucher attestation.
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { createServer } from 'node:http';
import { readFile, writeFile } from 'node:fs/promises';
import { extname, join, resolve, sep } from 'node:path';
import { chromium } from 'playwright';
import anoncreds from '@hyperledger/anoncreds-nodejs';
import { createIssuer } from '../src/issuer.js';
import { createMemoryReceiptStore } from '../src/receipts.js';
import { makeGate, NOW } from './fixtures.js';

assert(process.env.BROWSER_BIN && process.env.ARTIFACT_ROOT, 'Preinstalled browser and evidence directory required');
const root = resolve('.'), generated = resolve('generated/holder'), profiles = resolve('.ci/dependencies/cfrm/browser/profiles');
const mime = { '.js': 'text/javascript', '.wasm': 'application/wasm' };
const evidence = { source: process.env.CI_COMMIT_SHA, ok: false, checks: [], servedAssets: {},
  scope: 'Real AnonCreds browser holder and dedicated Worker runtime with Node verification; synthetic voucher-factor attestation; no product admission or Tor' };
const check = (condition, label) => { assert(condition, label); evidence.checks.push(label); };
const server = createServer(async (request, response) => {
  try {
    if (request.method !== 'GET') { response.writeHead(405).end(); return; }
    const pathname = new URL(request.url, 'http://localhost').pathname;
    if (pathname === '/') { response.writeHead(200, { 'Content-Type': 'text/html' }).end('<!doctype html><title>Credential holder contract</title>'); return; }
    const base = pathname.startsWith('/holder/') || pathname.startsWith('/generated/holder/') ? generated
      : pathname.startsWith('/profiles/') ? profiles : undefined;
    let file;
    if (pathname === '/client.js') file = join(root, 'src/client.js');
    else if (pathname === '/holder-worker.js') file = join(root, 'src/holder-worker.js');
    else if (pathname === '/browser-holder.js') file = join(root, 'src/browser-holder.js');
    else if (base) {
      const prefix = pathname.startsWith('/generated/holder/') ? '/generated/holder' : pathname.slice(0, pathname.indexOf('/', 1));
      file = resolve(base, '.' + decodeURIComponent(pathname.slice(prefix.length)));
      if (!file.startsWith(base + sep)) { response.writeHead(404).end(); return; }
    }
    if (!file || !mime[extname(file)]) { response.writeHead(404).end(); return; }
    const bytes = await readFile(file);
    evidence.servedAssets[pathname] = createHash('sha256').update(bytes).digest('hex');
    response.writeHead(200, { 'Content-Type': mime[extname(file)], 'Cache-Control': 'no-store' }).end(bytes);
  } catch { response.writeHead(500).end(); }
});
await new Promise(accept => server.listen(0, '127.0.0.1', accept));
const origin = `http://localhost:${server.address().port}`;
let browser, page;
const pageErrors = [], externalRequests = [];
try {
  const began = performance.now();
  const communityId = 'holder-browser-fixture', memberId = randomBytes(32).toString('base64url');
  const policy = { version: 'browser-holder', mode: 'any', factors: ['voucher'] }, gate = makeGate('voucher');
  const issuer = createIssuer({ issuerId: 'https://holder-fixture.example/cvld', communityId, policy,
    attesters: { voucher: gate.public }, receiptStore: createMemoryReceiptStore({ maxEntries: 8 }),
    maxCredentialLifetimeSeconds: 900, clock: () => NOW });
  const publicIssuer = issuer.public, offer = issuer.offer();
  evidence.issuerMs = performance.now() - began;
  browser = await chromium.launch({ executablePath: process.env.BROWSER_BIN, headless: true, args: ['--no-sandbox', '--disable-dev-shm-usage'] });
  evidence.browser = browser.version(); evidence.runtime = process.version;
  page = await browser.newPage();
  page.on('pageerror', error => pageErrors.push(error.message));
  await page.route('**/*', route => {
    if (route.request().url().startsWith(origin + '/')) return route.continue();
    externalRequests.push(route.request().url()); return route.abort();
  });
  await page.goto(origin);
  const request = await page.evaluate(async ({ publicIssuer, offer, memberId, communityId }) => {
    const api = await import('/holder/cvld_holder.js');
    await api.default({ module_or_path: '/holder/cvld_holder_bg.wasm' });
    window.holderApi = api; window.holder = new api.BrowserCredential();
    const entropy = Array.from(crypto.getRandomValues(new Uint8Array(32)), value => value.toString(16).padStart(2, '0')).join('');
    return { credentialRequest: JSON.parse(window.holder.request(JSON.stringify(publicIssuer), JSON.stringify(offer), entropy)),
      binding: { communityId, memberId } };
  }, { publicIssuer, offer, memberId, communityId });
  check(!('linkSecret' in request) && !('metadata' in request), 'browser returns only public blinded request and member binding');
  const issued = await issuer.issue({ offer, request, attestations: [gate.attest(offer, request, policy)] });
  const result = await page.evaluate(async ({ publicIssuer, issued, communityId, policyDigest, now }) => {
    const profiles = await import('/profiles/index.js');
    window.holder.accept(JSON.stringify(publicIssuer), JSON.stringify(issued));
    const descriptor = { schemaId: publicIssuer.schemaId, credentialDefinitionId: publicIssuer.credentialDefinitionId };
    const challenge = { communityId, policyDigest, expiresAt: now + 120 };
    const request = await profiles.profileEligibilityRequest(descriptor, crypto.getRandomValues(new Uint8Array(32)), challenge);
    const started = performance.now();
    const proof = JSON.parse(window.holder.presentProfile(JSON.stringify(publicIssuer), JSON.stringify(request)));
    const provingMs = performance.now() - started;
    await profiles.validateEligibilityPresentation(proof, descriptor, challenge, 100_000);
    const browserVerified = window.holderApi.verifyProfilePresentation(JSON.stringify(publicIssuer), JSON.stringify(request), JSON.stringify(proof));
    const relabeled = structuredClone(request); relabeled.requested_attributes.policy.name = 'member_id';
    let disclosureRejected = false;
    try { window.holder.presentProfile(JSON.stringify(publicIssuer), JSON.stringify(relabeled)); } catch { disclosureRejected = true; }
    const { sealLocalState, openLocalState } = await import('/client.js');
    const key = crypto.getRandomValues(new Uint8Array(32)), data = new TextEncoder().encode(window.holder.privateState());
    const encrypted = await sealLocalState({ data, key, context: 'cvld.holder.v1' }); data.fill(0); window.holder.free();
    const opened = await openLocalState({ envelope: encrypted, key, context: 'cvld.holder.v1' });
    window.holder = window.holderApi.BrowserCredential.fromPrivateState(new TextDecoder().decode(opened));
    opened.fill(0); key.fill(0);
    const restoredProof = JSON.parse(window.holder.presentProfile(JSON.stringify(publicIssuer), JSON.stringify(request)));
    return { request, proof, restoredProof, browserVerified, disclosureRejected, provingMs,
      encryptedStateOnly: !JSON.stringify(encrypted).includes('linkSecret') };
  }, { publicIssuer, issued, communityId, policyDigest: publicIssuer.policyDigest, now: NOW });
  const runtimeRequest = await page.evaluate(async ({ publicIssuer, offer, communityId, memberId }) => {
    const { createBrowserCredentialHolder } = await import('/browser-holder.js');
    window.runtimeHolder = await createBrowserCredentialHolder({
      worker: new Worker('/holder-worker.js', { type: 'module' }), publicIssuer, deadlineMs: 15_000,
    });
    return { credentialRequest: await window.runtimeHolder.request(offer), binding: { communityId, memberId } };
  }, { publicIssuer, offer, communityId, memberId });
  check(!('linkSecret' in runtimeRequest) && !('metadata' in runtimeRequest),
    'dedicated Worker returns only the public blinded request');
  const runtimeIssued = await issuer.issue({ offer, request: runtimeRequest,
    attestations: [gate.attest(offer, runtimeRequest, policy)] });
  const runtime = await page.evaluate(async ({ publicIssuer, issued, profileRequest }) => {
    const key = crypto.getRandomValues(new Uint8Array(32));
    const encrypted = await window.runtimeHolder.accept({ credential: issued, key, context: 'cvld.holder.v1' });
    window.runtimeHolder.close();
    const { createBrowserCredentialHolder } = await import('/browser-holder.js');
    const restored = await createBrowserCredentialHolder({
      worker: new Worker('/holder-worker.js', { type: 'module' }), publicIssuer, deadlineMs: 15_000,
    });
    await restored.restore({ envelope: encrypted, key, context: 'cvld.holder.v1' });
    const proof = await restored.presentProfile(profileRequest);
    const workerVerified = await restored.verifyProfile(profileRequest, proof);
    restored.close(); key.fill(0);
    return { proof, workerVerified, encryptedStateOnly: !JSON.stringify(encrypted).includes('linkSecret') };
  }, { publicIssuer, issued: runtimeIssued, profileRequest: result.request });
  check(runtime.workerVerified === true, 'dedicated Worker verifier accepts its actual presentation');
  check(verify(result.request, runtime.proof) === true,
    'independent native Node verifier accepts the dedicated Worker proof');
  check(runtime.encryptedStateOnly, 'dedicated Worker returns encrypted holder persistence only');
  const workerFailures = await page.evaluate(async ({ publicIssuer }) => {
    const { createBrowserCredentialHolder } = await import('/browser-holder.js');
    const makeWorker = source => {
      const url = URL.createObjectURL(new Blob([source], { type: 'text/javascript' }));
      const raw = new Worker(url, { type: 'module' });
      let terminated = false;
      return { url, terminated: () => terminated, worker: {
        postMessage: (...args) => raw.postMessage(...args),
        addEventListener: (...args) => raw.addEventListener(...args),
        terminate: () => { terminated = true; return raw.terminate(); },
      } };
    };
    const brokenSpec = makeWorker('throw new Error("worker failure");');
    brokenSpec.worker.addEventListener('error', event => event.preventDefault());
    const broken = brokenSpec.worker;
    let errorRejected = false;
    try { await createBrowserCredentialHolder({ worker: broken, publicIssuer, deadlineMs: 1_000 }); }
    catch { errorRejected = true; }
    URL.revokeObjectURL(brokenSpec.url);
    const silentSpec = makeWorker('self.onmessage = () => {};');
    const silent = silentSpec.worker;
    let timeoutRejected = false;
    const started = performance.now();
    try { await createBrowserCredentialHolder({ worker: silent, publicIssuer, deadlineMs: 50 }); }
    catch { timeoutRejected = true; }
    URL.revokeObjectURL(silentSpec.url);
    return { errorRejected, errorTerminated: brokenSpec.terminated(), timeoutRejected,
      timeoutTerminated: silentSpec.terminated(),
      timeoutMs: performance.now() - started };
  }, { publicIssuer });
  check(workerFailures.errorRejected && workerFailures.errorTerminated,
    'Worker startup errors reject without exposing crypto details and terminate the Worker');
  check(workerFailures.timeoutRejected && workerFailures.timeoutTerminated && workerFailures.timeoutMs < 2_000,
    'bounded Worker timeout rejects and terminates within the deadline');
  function verify(request, proof) {
    let presentation;
    try {
      presentation = anoncreds.Presentation.fromJson(proof);
      return presentation.verify({ presentationRequest: request, schemas: { [publicIssuer.schemaId]: publicIssuer.schema },
        credentialDefinitions: { [publicIssuer.credentialDefinitionId]: publicIssuer.credentialDefinition } });
    } catch { return false; }
    finally { presentation?.handle.clear(); }
  }
  check(result.browserVerified === true, 'browser verifier accepts the actual browser presentation');
  check(verify(result.request, result.proof) === true, 'independent native Node verifier accepts browser holder proof');
  check(verify(result.request, result.restoredProof) === true, 'encrypted private-state restoration preserves real proving capability');
  check(result.encryptedStateOnly && result.disclosureRejected, 'holder encrypts persistence and rejects member-ID relabel disclosure');
  check(Object.keys(result.proof.requested_proof.revealed_attrs).sort().join(',') === 'community_id,policy'
    && !JSON.stringify(result.proof).includes(memberId), 'private profile presentation reveals no member ID or exact credential expiry');
  const wrongNonce = structuredClone(result.request); wrongNonce.nonce = (BigInt(wrongNonce.nonce) + 1n).toString();
  check(verify(wrongNonce, result.proof) === false, 'native verifier rejects changed challenge nonce');
  const wrongPolicy = structuredClone(result.proof); wrongPolicy.requested_proof.revealed_attrs.policy.raw = 'other-policy';
  wrongPolicy.requested_proof.revealed_attrs.policy.encoded = anoncreds.anoncredsNodeJS.encodeCredentialAttributes({ attributeRawValues: ['other-policy'] })[0];
  check(verify(result.request, wrongPolicy) === false, 'native verifier rejects changed revealed policy');
  const corrupted = structuredClone(result.proof);
  corrupted.proof.aggregated_proof.c_hash = (BigInt(corrupted.proof.aggregated_proof.c_hash) + 1n).toString();
  check(verify(result.request, corrupted) === false, 'native verifier rejects changed cryptographic proof');
  const browserNegatives = await page.evaluate(({ publicIssuer, request, proof, wrongNonce, wrongPolicy, corrupted }) => {
    const verify = (request, proof) => {
      try { return window.holderApi.verifyProfilePresentation(JSON.stringify(publicIssuer), JSON.stringify(request), JSON.stringify(proof)); }
      catch { return false; }
    };
    return [verify(wrongNonce, proof), verify(request, wrongPolicy), verify(request, corrupted)];
  }, { publicIssuer, request: result.request, proof: result.proof, wrongNonce, wrongPolicy, corrupted });
  check(browserNegatives.every(value => value === false), 'browser verifier rejects changed nonce, policy and cryptographic proof');
  check(pageErrors.length === 0 && externalRequests.length === 0, 'browser completes without script errors or external requests');
  evidence.provingMs = result.provingMs; evidence.elapsedMs = performance.now() - began;
  evidence.publicProofBytes = Buffer.byteLength(JSON.stringify(result.proof));
  evidence.privateStateExportedToNode = false; evidence.ok = true;
} catch (error) { evidence.error = String(error.stack ?? error); process.exitCode = 1; }
finally {
  if (page) await page.evaluate(() => { window.runtimeHolder?.close(); window.holder?.free(); }).catch(() => {});
  await browser?.close(); await new Promise(accept => server.close(accept));
  evidence.browserErrors = pageErrors; evidence.externalRequests = externalRequests;
  await writeFile(join(process.env.ARTIFACT_ROOT, 'holder-browser-evidence.json'), JSON.stringify(evidence, null, 2) + '\n');
}
process.stdout.write(JSON.stringify({ ok: evidence.ok, checks: evidence.checks.length, provingMs: evidence.provingMs, error: evidence.error }) + '\n');
