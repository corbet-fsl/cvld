import { randomBytes } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';
import { sealLocalState, openLocalState } from './client.js';
import { publicBytes } from './admission.js';
import { presentationRequest } from './requests.js';
import anoncreds from '@hyperledger/anoncreds-nodejs';
import { jsonAndRelease } from './encoding.js';
const { LinkSecret, CredentialRequest, Credential, Presentation } = anoncreds;

// This object belongs in the holder's process, never in the verifier service.
export function createHolder() { return buildHolder(LinkSecret.create()); }
export async function restoreHolder({ encryptedState, wrappingKey }) {
  const data = await openLocalState({ envelope: encryptedState, key: wrappingKey, context: 'cvld.holder.v1' });
  const state = JSON.parse(new TextDecoder().decode(data));
  if (state.version !== 1 || typeof state.linkSecret !== 'string' || !/^[0-9]+$/.test(state.linkSecret) || !state.credential) throw new Error('Invalid holder state');
  const credential = Credential.fromJson(state.credential);
  try { return buildHolder(state.linkSecret, credential.toJson()); } finally { credential.handle.clear(); }
}
function buildHolder(linkSecret, credential) {
  return {
    async exportState({ wrappingKey }) {
      if (!credential) throw new Error('No processed holder credential');
      const data = new TextEncoder().encode(JSON.stringify({ version: 1, linkSecret, credential }));
      return sealLocalState({ data, key: wrappingKey, context: 'cvld.holder.v1' });
    },
    request(publicIssuer, offer, memberId) {
      publicBytes(memberId);
      const requestPair = CredentialRequest.create({
        entropy: randomBytes(32).toString('base64url'),
        credentialDefinition: publicIssuer.credentialDefinition,
        linkSecret, linkSecretId: 'cvld-wallet', credentialOffer: offer,
      });
      const request = { credentialRequest: jsonAndRelease(requestPair.credentialRequest), binding: { communityId: publicIssuer.communityId, memberId } };
      const metadata = jsonAndRelease(requestPair.credentialRequestMetadata);
      let accepted = false;
      return {
        request,
        accept(issued) {
          if (accepted) throw new Error('Credential already processed');
          const received = Credential.fromJson(issued);
          try {
            received.process({ credentialDefinition: publicIssuer.credentialDefinition, credentialRequestMetadata: metadata, linkSecret });
            credential = received.toJson();
            accepted = true;
          } finally { received.handle.clear(); }
        },
      };
    },
    present(publicIssuer, challenge) {
      if (!credential) throw new Error('No holder credential');
      const permittedRequest = presentationRequest(publicIssuer, challenge.request?.nonce, challenge.proofValidUntil);
      if (!isDeepStrictEqual(challenge.request, permittedRequest)) throw new Error('Unapproved disclosure request');
      if (credential.values.member_id.raw !== challenge.memberId || credential.values.community_id.raw !== challenge.communityId) throw new Error('Credential account does not match');
      if (credential.values.policy.raw !== challenge.policyDigest) throw new Error('Credential policy does not match');
      if (Number(credential.values.valid_until.raw) < challenge.proofValidUntil) throw new Error('Credential expires before challenge');
      return jsonAndRelease(Presentation.create({
        presentationRequest: challenge.request,
        credentials: [{ credential }],
        credentialsProve: [
          ...['policy', 'member_id', 'community_id'].map((referent) => ({ entryIndex: 0, isPredicate: false, referent, reveal: true })),
          { entryIndex: 0, isPredicate: true, referent: 'eligible', reveal: true },
          { entryIndex: 0, isPredicate: true, referent: 'valid_until', reveal: true },
        ],
        schemas: { [publicIssuer.schemaId]: publicIssuer.schema },
        credentialDefinitions: { [publicIssuer.credentialDefinitionId]: publicIssuer.credentialDefinition },
        selfAttest: {}, linkSecret,
      }));
    },
  };
}
