import { randomBytes } from 'node:crypto';
import { generateRegistrationOptions, verifyRegistrationResponse, verifyAuthenticationResponse } from '@simplewebauthn/server';
import { requireClock, requirePositive, requireText } from './encoding.js';

export function createPasskeyService(options) {
  const store = options.credentialStore;
  if (typeof store?.insert !== 'function' || typeof store.get !== 'function' || typeof store.updateCounter !== 'function') throw new TypeError('Credential store required');
  const communityId = requireText(options.communityId, 'community ID');
  const origin = requireText(options.origin, 'origin');
  const rpID = requireText(options.rpID, 'RP ID');
  const rpName = requireText(options.rpName, 'RP name');
  const clock = requireClock(options.clock);
  const lifetime = requirePositive(options.challengeLifetimeSeconds, 'challenge lifetime');
  const capacity = requirePositive(options.maxPendingChallenges, 'challenge capacity');
  const maxPerMember = requirePositive(options.maxPasskeysPerMember, 'member passkey limit');
  if (typeof options.requireUserVerification !== 'boolean') throw new TypeError('Explicit user verification policy required');
  const requireUV = options.requireUserVerification;
  const pending = new Map();
  function reserve(value) {
    const now = clock();
    for (const [id, state] of pending) if (state.expiresAt <= now) pending.delete(id);
    if (pending.size >= capacity) throw new Error('Challenge capacity reached');
    const id = randomBytes(32).toString('base64url');
    pending.set(id, { ...value, expiresAt: now + lifetime });
    return id;
  }
  function consume(id, kind) {
    const state = pending.get(id); pending.delete(id);
    return state?.kind === kind && clock() < state.expiresAt ? state : undefined;
  }
  async function registration(memberId) {
    const generated = await generateRegistrationOptions({
      rpName, rpID, userID: Buffer.from(memberId, 'base64url'), userName: memberId, userDisplayName: 'Member',
      attestationType: 'none', supportedAlgorithmIDs: [-7],
      authenticatorSelection: { residentKey: 'required', userVerification: requireUV ? 'required' : 'preferred' },
      extensions: { prf: {} },
    });
    const id = reserve({ kind: 'registration', memberId, challenge: generated.challenge });
    return { id, memberId, options: generated };
  }
  return {
    beginRegistration() { return registration(randomBytes(32).toString('base64url')); },
    async finishRegistration({ id, response }) {
      try {
        const state = consume(id, 'registration'); if (!state) return false;
        const result = await verifyRegistrationResponse({ response, expectedChallenge: state.challenge, expectedOrigin: origin, expectedRPID: rpID, requireUserVerification: requireUV, supportedAlgorithmIDs: [-7] });
        if (!result.verified || !result.registrationInfo || clock() >= state.expiresAt) return false;
        const credential = result.registrationInfo.credential;
        if (!store.insert(communityId, state.memberId, credential, maxPerMember)) return false;
        return { memberId: state.memberId, credentialId: credential.id };
      } catch { return false; }
    },
    async beginAdditionalRegistration(credentialId) {
      const credential = store.get(communityId, credentialId);
      if (!credential) throw new Error('Registered passkey required');
      const challenge = randomBytes(32).toString('base64url');
      const id = reserve({ kind: 'additional', credential, challenge });
      return { id, options: { challenge, rpId: rpID, allowCredentials: [{ id: credential.id, type: 'public-key' }], userVerification: requireUV ? 'required' : 'preferred' } };
    },
    async authorizeAdditionalRegistration({ id, response }) {
      try {
        const state = consume(id, 'additional'); if (!state) return false;
        const result = await verifyAuthenticationResponse({ response, expectedChallenge: state.challenge, expectedOrigin: origin, expectedRPID: rpID, credential: state.credential, requireUserVerification: requireUV });
        if (!result.verified || clock() >= state.expiresAt || !store.updateCounter(communityId, state.credential.id, result.authenticationInfo.newCounter)) return false;
        return registration(state.credential.memberId);
      } catch { return false; }
    },
  };
}
