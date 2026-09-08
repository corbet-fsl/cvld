import { createPublicKey, verify } from 'node:crypto';
import anoncreds from '@hyperledger/anoncreds-nodejs';
import { encodeAttestation, issuanceDigest, hash, jsonAndRelease, normalizePolicy, policyDigest, requireClock, requirePositive, requireText } from './encoding.js';
import { scopeText, publicBytes } from './admission.js';
import { sealLocalState, openLocalState } from './client.js';
const { Schema, CredentialDefinition, CredentialOffer, Credential } = anoncreds;
const stateContext = 'cvld.issuer.v1';
export function createIssuer(options) { return buildIssuer(options); }
export async function restoreIssuer({ encryptedState, wrappingKey, clock, receiptStore }) {
  const decoded = await openLocalState({ envelope: encryptedState, key: wrappingKey, context: stateContext });
  const state = JSON.parse(new TextDecoder().decode(decoded));
  if (state.version !== 1) throw new Error('Unknown issuer state');
  return buildIssuer({ ...state.config, clock, receiptStore }, state.keys);
}
function buildIssuer(options, restored) {
  const issuerId = requireText(options.issuerId, 'issuer ID');
  const communityId = scopeText(options.communityId);
  const policy = normalizePolicy(options.policy);
  const digest = policyDigest(policy);
  const clock = requireClock(options.clock);
  const maximumLifetime = requirePositive(options.maxCredentialLifetimeSeconds, 'credential lifetime');
  if (typeof options.receiptStore?.issueOnce !== 'function') throw new TypeError('Atomic idempotent issuance store required');
  const receiptStore = options.receiptStore;
  const attesterConfig = structuredClone(options.attesters ?? {});
  const attesters = new Map(Object.entries(attesterConfig).map(([id, entry]) => {
    requireText(id, 'attester ID');
    if (!policy.factors.includes(entry.factor)) throw new TypeError('Attester factor is disabled');
    const publicKey = createPublicKey(entry.publicKey);
    if (publicKey.asymmetricKeyType !== 'ed25519') throw new TypeError('Ed25519 attester key required');
    return [id, { factor: entry.factor, publicKey }];
  }));
  if (!policy.factors.every((factor) => [...attesters.values()].some((entry) => entry.factor === factor))) throw new TypeError('Missing factor attester');
  const schemaId = `${issuerId}/schema/2`;
  const credentialDefinitionId = `${issuerId}/credential/${digest}`;
  const schema = jsonAndRelease(Schema.create({ name: 'cvld-eligibility', issuerId, version: '2', attributeNames: ['policy', 'eligible', 'valid_until', 'member_id', 'community_id'] }));
  let keys = restored;
  if (!keys) {
    const created = CredentialDefinition.create({ schemaId, issuerId, schema, signatureType: 'CL', supportRevocation: false, tag: digest });
    keys = { credentialDefinition: jsonAndRelease(created.credentialDefinition), credentialDefinitionPrivate: jsonAndRelease(created.credentialDefinitionPrivate), keyCorrectnessProof: jsonAndRelease(created.keyCorrectnessProof) };
  }
  const { credentialDefinition, credentialDefinitionPrivate, keyCorrectnessProof } = keys;
  const publicIssuer = { issuerId, communityId, schemaId, credentialDefinitionId, schema, credentialDefinition, keyCorrectnessProof, policyDigest: digest };
  return {
    get public() { return structuredClone(publicIssuer); },
    async exportState({ wrappingKey }) {
      const state = { version: 1, config: { issuerId, communityId, policy, attesters: attesterConfig, maxCredentialLifetimeSeconds: maximumLifetime }, keys };
      return sealLocalState({ data: new TextEncoder().encode(JSON.stringify(state)), key: wrappingKey, context: stateContext });
    },
    offer() { return jsonAndRelease(CredentialOffer.create({ schemaId, credentialDefinitionId, keyCorrectnessProof })); },
    async issue(input) {
      try {
        const { offer, request, attestations } = structuredClone(input);
        const now = clock();
        if (!Array.isArray(attestations) || attestations.length < 1 || attestations.length > policy.factors.length) throw new Error();
        publicBytes(request.binding?.memberId);
        if (request.binding.communityId !== communityId || offer.cred_def_id !== credentialDefinitionId || offer.schema_id !== schemaId || request.credentialRequest.cred_def_id !== credentialDefinitionId) throw new Error();
        const requestHash = issuanceDigest(offer, request);
        const factors = new Set();
        const receipts = [];
        let validUntil = now + maximumLifetime;
        for (const attestation of attestations) {
          const attester = attesters.get(attestation.keyId);
          if (!attester || attestation.factor !== attester.factor || factors.has(attestation.factor) ||
              attestation.issuanceDigest !== requestHash || attestation.policyDigest !== digest ||
              !Number.isSafeInteger(attestation.validUntil) || attestation.validUntil <= now || attestation.validUntil > now + maximumLifetime ||
              !verify(null, encodeAttestation(attestation), attester.publicKey, Buffer.from(attestation.signature, 'base64url'))) throw new Error();
          factors.add(attestation.factor);
          receipts.push({ id: JSON.stringify([issuerId, attestation.keyId, attestation.receiptId]), expiresAt: attestation.validUntil });
          validUntil = Math.min(validUntil, attestation.validUntil);
        }
        if (policy.mode === 'all' && !policy.factors.every((factor) => factors.has(factor))) throw new Error();
        const operationId = hash(JSON.stringify(['cvld.issue.v2', credentialDefinition, requestHash, attestations.map((a) => [a.keyId, a.receiptId, a.validUntil, a.signature]).sort()]));
        return await receiptStore.issueOnce({ operationId, receipts, resultExpiresAt: validUntil, now }, () => jsonAndRelease(Credential.create({
          credentialDefinition, credentialDefinitionPrivate, credentialOffer: offer, credentialRequest: request.credentialRequest,
          attributeRawValues: { policy: digest, eligible: '1', valid_until: String(validUntil), member_id: request.binding.memberId, community_id: communityId },
        })));
      } catch { throw new Error('Eligibility issuance rejected'); }
    },
  };
}
