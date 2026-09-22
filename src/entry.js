import { randomBytes, createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { generateAuthenticationOptions, generateRegistrationOptions, verifyAuthenticationResponse, verifyRegistrationResponse } from '@simplewebauthn/server';
import { admissionBytes, admissionKeyId, publicBytes, scopeText } from './admission.js';
import { validateDeviceAuthorization } from './cmsg-binding.js';
import { encodeAttestation, hash, issuanceDigest, requireClock, requirePositive, requireText } from './encoding.js';

function token() { return randomBytes(32).toString('base64url'); }

export function createEntryService(options) {
  const communityId = scopeText(options.communityId);
  const origin = requireText(options.origin, 'origin');
  const rpID = requireText(options.rpID, 'RP ID');
  const rpName = requireText(options.rpName, 'RP name');
  const clock = requireClock(options.clock);
  const challengeLifetime = requirePositive(options.challengeLifetimeSeconds, 'challenge lifetime');
  const maxPending = requirePositive(options.maxPendingChallenges, 'challenge capacity');
  const sessionLifetime = requirePositive(options.sessionLifetimeSeconds, 'session lifetime');
  const maxSessions = requirePositive(options.maxSessions, 'session capacity');
  const maxPerMember = requirePositive(options.maxPasskeysPerMember, 'member passkey limit');
  if (options.requireUserVerification !== true) throw new TypeError('Entry authentication requires user verification');
  const store = options.credentialStore;
  if (typeof store?.get !== 'function' || typeof store?.hasMember !== 'function' || typeof store?.updateCounter !== 'function') throw new TypeError('Credential repository with member lookup required');
  const members = options.membershipStore;
  if (typeof members?.registerWithVoucher !== 'function' || typeof members?.get !== 'function' || typeof members?.rebind !== 'function') throw new TypeError('Atomic membership store required');
  const bridge = options.voucherBridge;
  if (typeof bridge?.verifyVoucher !== 'function' || typeof bridge?.verifyDeviceAuthorization !== 'function') throw new TypeError('Voucher/authority bridge required');
  const sponsorPublicKey = publicBytes(options.sponsorPublicKey).toString('base64url');
  const pending = new Map();
  const sessions = new Map();
  let sessionReservations = 0;
  const issuerPending = new Map();
  const admission = options.admission;
  if (!admission || typeof admission !== 'object') throw new TypeError('Admission signing configuration required');
  const signingKey = createPrivateKey(admission.signingKey);
  if (signingKey.asymmetricKeyType !== 'ed25519') throw new TypeError('Ed25519 admission signing key required');
  const rawIssuerKey = publicBytes(createPublicKey(signingKey).export({ format: 'jwk' }).x);
  const issuerKeyId = admissionKeyId(rawIssuerKey);
  const policyDigest = publicBytes(admission.policyDigest).toString('base64url');
  const grantLifetime = requirePositive(admission.grantLifetimeSeconds, 'admission lifetime');
  const issuer = options.issuer;
  const issuerAttester = options.voucherAttester;
  const issuerChallengeLifetime = options.issuerChallengeLifetimeSeconds === undefined ? undefined : requirePositive(options.issuerChallengeLifetimeSeconds, 'issuer challenge lifetime');
  const maxIssuerPending = options.maxIssuerPendingChallenges === undefined ? undefined : requirePositive(options.maxIssuerPendingChallenges, 'issuer challenge capacity');
  const issuerCredentialLifetime = options.issuerCredentialLifetimeSeconds === undefined ? undefined : requirePositive(options.issuerCredentialLifetimeSeconds, 'issuer credential lifetime');
  if ((issuer || issuerAttester || issuerChallengeLifetime || maxIssuerPending || issuerCredentialLifetime) &&
      (typeof issuer?.offer !== 'function' || typeof issuer?.issue !== 'function' || !issuerAttester || issuerChallengeLifetime === undefined || maxIssuerPending === undefined || issuerCredentialLifetime === undefined)) throw new TypeError('Complete issuer configuration required');
  let attesterKey;
  if (issuer) {
    if (typeof issuerAttester.keyId !== 'string' || !issuerAttester.keyId || !issuerAttester.signingKey) throw new TypeError('Voucher attester configuration required');
    attesterKey = createPrivateKey(issuerAttester.signingKey);
    if (attesterKey.asymmetricKeyType !== 'ed25519') throw new TypeError('Voucher attester must use Ed25519');
    if (!issuer.public?.policyDigest || issuer.public.communityId !== communityId || issuer.public.policyDigest !== policyDigest) throw new TypeError('Issuer public configuration required');
  }

  function prune(now) {
    for (const [id, state] of pending) if (state.expiresAt <= now) pending.delete(id);
    for (const [id, state] of sessions) if (state.expiresAt <= now) sessions.delete(id);
  }
  function reserve(value, now) {
    prune(now);
    if (pending.size >= maxPending) throw new Error('Challenge capacity reached');
    const id = token();
    pending.set(id, { ...value, expiresAt: requirePositive(now + challengeLifetime, 'challenge expiry') });
    return id;
  }
  function consume(id, kind) {
    const state = pending.get(id);
    if (!state || state.kind !== kind) return undefined;
    pending.delete(id);
    return clock() < state.expiresAt ? state : undefined;
  }
  function newSession(memberId, credentialId, now, reserved = false) {
    prune(now);
    if (sessions.size + sessionReservations - (reserved ? 1 : 0) >= maxSessions) return false;
    const sessionId = token();
    const expiresAt = requirePositive(now + sessionLifetime, 'session expiry');
    sessions.set(sessionId, { memberId, credentialId, expiresAt });
    return { sessionId, memberId, expiresAt };
  }
  function currentMember(memberId) {
    const value = members.get(communityId, memberId);
    const check = member => {
      const now = clock();
      return member && member.communityId === communityId && member.memberId === memberId && member.voucherValidUntil > now ? member : false;
    };
    return value && typeof value.then === 'function' ? value.then(check) : check(value);
  }
  function actorMember(actor) {
    if (!actor || typeof actor !== 'object') return false;
    if (actor.kind === 'session') {
      const session = sessions.get(actor.sessionId);
      if (!session || session.memberId !== actor.memberId || session.expiresAt <= clock()) return false;
      const value = currentMember(session.memberId);
      const resolve = member => {
        const live = sessions.get(actor.sessionId);
        return member && live === session && live.expiresAt > clock() ? session.memberId : false;
      };
      return value && typeof value.then === 'function' ? value.then(resolve) : resolve(value);
    }
    if (actor.kind === 'apiKey') {
      const value = currentMember(actor.memberId);
      const resolve = member => member ? actor.memberId : false;
      return value && typeof value.then === 'function' ? value.then(resolve) : resolve(value);
    }
    return false;
  }
  async function verifyBinding(input, now) {
    if (!validateDeviceAuthorization({
      authorization: input.authorization, communityId, memberId: input.memberId,
      chatPublicKey: input.chatPublicKey, now,
    }) || !(await bridge.verifyDeviceAuthorization({ authorization: input.authorization, communityId, memberId: input.memberId, chatPublicKey: input.chatPublicKey, now }))) throw new Error('Device authorization rejected');
  }
  function certificate({ memberId, chatPublicKey, issuedAt, voucherValidUntil, authorization }) {
    const expiresAt = Math.min(issuedAt + grantLifetime, voucherValidUntil, authorization.expiresAt);
    if (expiresAt <= issuedAt) return undefined;
    const result = { version: 1, issuerKeyId, communityId, memberId, chatPublicKey, policyDigest, issuedAt, expiresAt };
    result.signature = sign(null, admissionBytes(result), signingKey).toString('base64url');
    return result;
  }
  async function finishRegistration(input) {
    try {
      input = structuredClone(input);
      const state = consume(input?.id, 'registration-wallet');
      if (!state || !input.walletResponse) return false;
      const credential = state.credential;
      const wallet = await verifyAuthenticationResponse({ response: input.walletResponse, expectedChallenge: state.walletChallenge, expectedOrigin: origin, expectedRPID: rpID, credential, requireUserVerification: true });
      if (!wallet.verified || clock() >= state.expiresAt || !Number.isSafeInteger(wallet.authenticationInfo.newCounter)) return false;
      const committedCredential = { ...credential, counter: wallet.authenticationInfo.newCounter };
      const now = clock();
      const redeemed = await bridge.verifyVoucher({ voucher: state.voucher, communityId, sponsorPublicKey, memberId: state.memberId, now });
      const commitNow = clock();
      if (!redeemed || redeemed.validUntil <= commitNow || commitNow >= state.expiresAt || commitNow >= state.authorization.expiresAt) return false;
      prune(commitNow);
      if (sessions.size + sessionReservations >= maxSessions) return false;
      sessionReservations += 1;
      try {
        if (!await members.registerWithVoucher({ communityId, memberId: state.memberId, chatPublicKey: state.chatPublicKey, authorization: state.authorization, receiptId: redeemed.receiptId, memberBinding: redeemed.memberBinding, validUntil: redeemed.validUntil, now: commitNow, credential: committedCredential, maxPerMember })) return false;
        const publishedAt = clock();
        if (publishedAt >= state.expiresAt || publishedAt >= state.authorization.expiresAt || publishedAt >= redeemed.validUntil) return false;
        const session = newSession(state.memberId, committedCredential.id, publishedAt, true);
        if (!session) return false;
        return { ...session, chatPublicKey: state.chatPublicKey, credentialId: committedCredential.id, admission: certificate({ memberId: state.memberId, chatPublicKey: state.chatPublicKey, issuedAt: publishedAt, voucherValidUntil: redeemed.validUntil, authorization: state.authorization }) };
      } finally { sessionReservations -= 1; }
    } catch { return false; }
  }
  async function beginRegistration(input) {
    input = structuredClone(input);
    const bindingNow = clock();
    await verifyBinding(input, bindingNow);
    if (await store.hasMember(communityId, input.memberId)) throw new Error('Member already registered');
    if (!input.voucher || typeof input.voucher !== 'object') throw new TypeError('Voucher required');
    const generated = await generateRegistrationOptions({
      rpName, rpID, userID: Buffer.from(input.memberId, 'base64url'), userName: input.memberId, userDisplayName: 'Member',
      attestationType: 'none', supportedAlgorithmIDs: [-7],
      authenticatorSelection: { residentKey: 'required', userVerification: 'required' }, extensions: { prf: {} },
    });
    const now = clock();
    if (!validateDeviceAuthorization({ authorization: input.authorization, communityId, memberId: input.memberId, chatPublicKey: input.chatPublicKey, now })) throw new Error('Device authorization expired');
    const id = reserve({ kind: 'registration', memberId: input.memberId, chatPublicKey: input.chatPublicKey, authorization: structuredClone(input.authorization), voucher: structuredClone(input.voucher), challenge: generated.challenge }, now);
    return { id, memberId: input.memberId, options: generated };
  }
  async function beginRegistrationPrecommit({ id, response }) {
    try {
      const state = pending.get(id);
      if (!state || state.kind !== 'registration') return false;
      pending.delete(id);
      const now = clock();
      const result = await verifyRegistrationResponse({ response: structuredClone(response), expectedChallenge: state.challenge, expectedOrigin: origin, expectedRPID: rpID, requireUserVerification: true, supportedAlgorithmIDs: [-7] });
      if (!result.verified || !result.registrationInfo || clock() >= state.expiresAt) return false;
      const credential = result.registrationInfo.credential;
      const walletOptions = await generateAuthenticationOptions({ rpID, userVerification: 'required', allowCredentials: [{ id: credential.id, type: 'public-key' }] });
      const ready = clock();
      prune(ready);
      if (ready >= state.expiresAt || pending.size >= maxPending) return false;
      pending.set(id, { ...state, kind: 'registration-wallet', credential: structuredClone(credential), walletChallenge: walletOptions.challenge });
      return { id, options: walletOptions };
    } catch { return false; }
  }
  async function beginAuthentication() {
    const generated = await generateAuthenticationOptions({ rpID, userVerification: 'required', residentKey: 'required' });
    const now = clock();
    const id = reserve({ kind: 'authentication', challenge: generated.challenge }, now);
    return { id, options: generated };
  }
  async function finishAuthentication(input) {
    try {
      input = structuredClone(input);
      const state = consume(input?.id, 'authentication');
      if (!state || !input.response?.id) return false;
      const credential = await store.get(communityId, input.response.id);
      if (!credential) return false;
      const beforeVerify = clock(); prune(beforeVerify);
      if (sessions.size >= maxSessions) return false;
      const result = await verifyAuthenticationResponse({ response: input.response, expectedChallenge: state.challenge, expectedOrigin: origin, expectedRPID: rpID, credential, requireUserVerification: true });
      if (!result.verified || clock() >= state.expiresAt) return false;
      const afterVerify = clock(); prune(afterVerify);
      if (sessions.size + sessionReservations >= maxSessions) return false;
      sessionReservations += 1;
      try {
        if (!await store.updateCounter(communityId, credential.id, result.authenticationInfo.newCounter)) return false;
        const now = clock();
        if (now >= state.expiresAt) return false;
        return newSession(credential.memberId, credential.id, now, true);
      } finally { sessionReservations -= 1; }
    } catch { return false; }
  }
  async function rebindDevice(input) {
    try {
      input = structuredClone(input);
      const { sessionId, chatPublicKey, authorization } = input;
      const session = sessions.get(sessionId);
      const now = clock();
      if (!session || session.expiresAt <= now || !validateDeviceAuthorization({ authorization, communityId, memberId: session.memberId, chatPublicKey, now }) ||
          !(await bridge.verifyDeviceAuthorization({ authorization, communityId, memberId: session.memberId, chatPublicKey, now }))) return false;
      const current = sessions.get(sessionId); const afterBridge = clock();
      if (!current || current !== session || current.expiresAt <= afterBridge) return false;
      const member = await members.get(communityId, session.memberId);
      const commitNow = clock();
      const liveSession = sessions.get(sessionId);
      if (!liveSession || liveSession !== session || liveSession.expiresAt <= commitNow || !member || member.communityId !== communityId || member.memberId !== session.memberId || member.voucherValidUntil <= commitNow) return false;
      const result = certificate({ memberId: session.memberId, chatPublicKey, issuedAt: commitNow, voucherValidUntil: member.voucherValidUntil, authorization });
      if (!result || !await members.rebind({ communityId, memberId: session.memberId, chatPublicKey, authorization, now: commitNow })) return false;
      return { memberId: session.memberId, chatPublicKey, admission: result };
    } catch { return false; }
  }
  function beginCredential({ sessionId, principal }) {
    if (!issuer) return false;
    const actor = structuredClone(principal ?? { kind: 'session', sessionId, memberId: sessions.get(sessionId)?.memberId });
    const finish = memberId => {
      if (!memberId) return false;
      const value = members.get(communityId, memberId);
      const make = member => {
        const now = clock();
        for (const [id, state] of issuerPending) if (state.expiresAt <= now) issuerPending.delete(id);
        if (issuerPending.size >= maxIssuerPending) return false;
        if (actor.kind === 'session') {
          const live = sessions.get(actor.sessionId);
          if (!live || live.memberId !== memberId || live.expiresAt <= now) return false;
        }
        if (!member || member.voucherValidUntil <= now) return false;
        const id = token(); const expiresAt = requirePositive(now + issuerChallengeLifetime, 'issuer challenge expiry');
        const offer = issuer.offer();
        issuerPending.set(id, { actor, memberId, offer, expiresAt, voucherReceiptId: member.voucherReceiptId, issuanceReceiptId: hash(JSON.stringify(['cvld.member-credential.v1', member.voucherReceiptId, id, memberId])) });
        return { id, offer, issuer: issuer.public, expiresAt };
      };
      return value && typeof value.then === 'function' ? value.then(make) : make(value);
    };
    const memberId = actorMember(actor);
    return memberId && typeof memberId.then === 'function' ? memberId.then(finish) : finish(memberId);
  }
  async function issueCredential({ sessionId, principal, id, request }) {
    try {
      if (!issuer) return false;
      const state = issuerPending.get(id); issuerPending.delete(id);
      const actor = structuredClone(principal ?? { kind: 'session', sessionId, memberId: sessions.get(sessionId)?.memberId });
      const snapshot = structuredClone(request);
      const memberId = await actorMember(actor);
      const now = clock();
      if (!state || state.expiresAt <= now || !memberId || state.memberId !== memberId) return false;
      const member = await members.get(communityId, state.memberId);
      const commitNow = clock();
      if (!member || member.voucherReceiptId !== state.voucherReceiptId || member.voucherValidUntil <= commitNow) return false;
      if (state.expiresAt <= commitNow) return false;
      if (actor.kind === 'session') {
        const live = sessions.get(actor.sessionId);
        if (!live || live.memberId !== state.memberId || live.expiresAt <= commitNow) return false;
      }
      if (snapshot?.binding?.communityId !== communityId || snapshot.binding.memberId !== state.memberId) return false;
      const digest = issuanceDigest(state.offer, snapshot);
      const validUntil = Math.min(member.voucherValidUntil, commitNow + issuerCredentialLifetime);
      if (validUntil <= commitNow) return false;
      const attestation = { keyId: issuerAttester.keyId, factor: 'voucher', receiptId: state.issuanceReceiptId, issuanceDigest: digest, policyDigest: issuer.public.policyDigest, validUntil };
      attestation.signature = sign(null, encodeAttestation(attestation), attesterKey).toString('base64url');
      return await issuer.issue({ offer: state.offer, request: snapshot, attestations: [attestation] });
    } catch { return false; }
  }
  return Object.freeze({
    beginRegistration,
    beginRegistrationPrecommit,
    finishRegistration,
    beginAuthentication,
    finishAuthentication,
    rebindDevice,
    beginCredential,
    issueCredential,
    getSession(sessionId) {
      const state = sessions.get(sessionId); if (!state || clock() >= state.expiresAt) { sessions.delete(sessionId); return false; }
      return { ...state };
    },
    revokeSession(sessionId) { return sessions.delete(sessionId); },
    isCurrentMember(memberId) {
      const value = currentMember(memberId);
      return value && typeof value.then === 'function' ? value.then(Boolean) : Boolean(value);
    },
    authenticatedSession(sessionId) {
      const session = sessions.get(sessionId);
      const value = session && actorMember({ kind: 'session', sessionId, memberId: session.memberId });
      const resolve = valid => {
        const live = sessions.get(sessionId);
        return valid && live === session && live.expiresAt > clock() ? { ...live } : false;
      };
      return value && typeof value.then === 'function' ? value.then(resolve) : resolve(value);
    },
    get admissionTrust() { return { issuerKeyId, publicKey: new Uint8Array(rawIssuerKey), communityId, policyDigest }; },
  });
}
