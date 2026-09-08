import { randomBytes, createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { presentationRequest } from './requests.js';
import { admissionBytes, admissionKeyId, scopeText, publicBytes } from './admission.js';
import anoncreds from '@hyperledger/anoncreds-nodejs';
import { verifyAuthenticationResponse } from '@simplewebauthn/server';
import { hash, policyDigest, requireClock, requirePositive, requireText } from './encoding.js';
const { Nonce, Presentation, anoncredsNodeJS } = anoncreds;

export function createVerifier(options) {
  const publicIssuer = structuredClone(options.publicIssuer);
  const digest = policyDigest(options.policy);
  const communityId = scopeText(options.communityId);
  if (publicIssuer?.policyDigest !== digest || publicIssuer.communityId !== communityId) throw new TypeError('Issuer policy or community does not match');
  const clock = requireClock(options.clock);
  const lifetime = requirePositive(options.challengeLifetimeSeconds, 'challenge lifetime');
  const grantLifetime = requirePositive(options.grantLifetimeSeconds, 'admission lifetime');
  const maxPending = requirePositive(options.maxPendingChallenges, 'challenge capacity');
  const maxBytes = requirePositive(options.maxPresentationBytes, 'presentation limit');
  const origin = requireText(options.origin, 'origin');
  const rpID = requireText(options.rpID, 'RP ID');
  const store = options.credentialStore;
  if (typeof store?.get !== 'function' || typeof store?.updateCounter !== 'function') throw new TypeError('Registered credential repository required');
  if (typeof options.requireUserVerification !== 'boolean') throw new TypeError('Explicit user verification policy required');
  const requireUV = options.requireUserVerification;
  const signingKey = createPrivateKey(options.grantSigningKey);
  if (signingKey.asymmetricKeyType !== 'ed25519') throw new TypeError('Ed25519 admission signing key required');
  const rawKey = publicBytes(createPublicKey(signingKey).export({ format: 'jwk' }).x);
  const issuerKeyId = admissionKeyId(rawKey);
  const pending = new Map();
  async function authenticate(input) {
    try {
      const state = pending.get(input?.id);
      if (!state) return false;
      pending.delete(input.id);
      // Snapshot external request objects before the asynchronous WebAuthn verifier.
      input = structuredClone(input);
      if (state.audience !== input.audience || clock() >= Math.min(state.expiresAt, state.grantExpiresAt)) return false;
      const encoded = JSON.stringify(input.presentation);
      if (!encoded || Buffer.byteLength(encoded) > maxBytes || typeof input.presentation !== 'object' || input.presentation === null) return false;
      const proof = input.presentation.requested_proof;
      const expected = { policy: digest, member_id: state.memberId, community_id: communityId };
      if (Object.keys(proof?.revealed_attrs ?? {}).length !== 3 || Object.keys(proof?.self_attested_attrs ?? {}).length !== 0) return false;
      for (const [name, raw] of Object.entries(expected)) {
        const value = proof.revealed_attrs[name];
        if (value?.raw !== raw || value.encoded !== anoncredsNodeJS.encodeCredentialAttributes({ attributeRawValues: [raw] })[0]) return false;
      }
      if (input.presentation.identifiers?.length !== 1 || input.presentation.identifiers[0].cred_def_id !== publicIssuer.credentialDefinitionId ||
          input.presentation.identifiers[0].schema_id !== publicIssuer.schemaId || input.presentation.identifiers[0].rev_reg_id !== null) return false;
      const presentation = Presentation.fromJson(input.presentation);
      let eligible;
      try {
        eligible = presentation.verify({ presentationRequest: state.request, schemas: { [publicIssuer.schemaId]: publicIssuer.schema }, credentialDefinitions: { [publicIssuer.credentialDefinitionId]: publicIssuer.credentialDefinition } });
      } finally { presentation.handle.clear(); }
      if (!eligible) return false;
      const result = await verifyAuthenticationResponse({ response: input.authentication, expectedChallenge: state.authentication.challenge, expectedOrigin: origin, expectedRPID: rpID, credential: state.credential, requireUserVerification: requireUV });
      if (!result.verified || clock() >= Math.min(state.expiresAt, state.grantExpiresAt) || !store.updateCounter(communityId, state.credential.id, result.authenticationInfo.newCounter)) return false;
      const admission = { version: 1, issuerKeyId, communityId, memberId: state.memberId, chatPublicKey: state.chatPublicKey, policyDigest: digest, issuedAt: state.issuedAt, expiresAt: state.grantExpiresAt };
      admission.signature = sign(null, admissionBytes(admission), signingKey).toString('base64url');
      return { eligible: true, communityId, memberId: state.memberId, admission };
    } catch { return false; }
  }
  return {
    get admissionTrust() { return { issuerKeyId, publicKey: new Uint8Array(rawKey), communityId, policyDigest: digest }; },
    begin(credentialId, audience, chatPublicKey) {
      requireText(credentialId, 'credential ID'); requireText(audience, 'audience'); publicBytes(chatPublicKey);
      const credential = store.get(communityId, credentialId);
      if (!credential) throw new Error('Registered passkey required');
      publicBytes(credential.memberId);
      const now = clock();
      for (const [id, value] of pending) if (value.expiresAt <= now) pending.delete(id);
      if (pending.size >= maxPending) throw new Error('Challenge capacity reached');
      const id = randomBytes(32).toString('base64url');
      const expiresAt = requirePositive(now + lifetime, 'challenge expiry');
      const grantExpiresAt = requirePositive(now + grantLifetime, 'admission expiry');
      const proofValidUntil = Math.max(expiresAt, grantExpiresAt);
      const request = presentationRequest(publicIssuer, Nonce.generate(), proofValidUntil);
      const authentication = {
        challenge: hash(JSON.stringify(['cvld.login.v2', id, audience, communityId, credential.memberId, chatPublicKey, digest, request.nonce, expiresAt, grantExpiresAt, credential.id, hash(credential.publicKey)])),
        rpId: rpID, userVerification: requireUV ? 'required' : 'preferred', allowCredentials: [{ id: credential.id, type: 'public-key' }],
      };
      const challenge = { id, audience, communityId, memberId: credential.memberId, chatPublicKey, policyDigest: digest, expiresAt, proofValidUntil, request, authentication };
      pending.set(id, { ...structuredClone(challenge), issuedAt: now, grantExpiresAt, credential: structuredClone(credential) });
      return challenge;
    },
    authenticate,
    async verify(input) { return (await authenticate(input)) !== false; },
  };
}
