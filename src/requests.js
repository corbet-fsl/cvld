import { requirePositive, requireText } from './encoding.js';

// The holder and verifier agree on the complete disclosure request, not just names.
export function presentationRequest(publicIssuer, nonce, expiresAt) {
  requireText(nonce, 'proof nonce');
  if (!/^[0-9]+$/.test(nonce)) throw new TypeError('Invalid proof nonce');
  requirePositive(expiresAt, 'challenge expiry');
  const restrictions = [{ cred_def_id: publicIssuer.credentialDefinitionId }];
  return {
    nonce, name: 'cvld-admission', version: '1',
    requested_attributes: Object.fromEntries(['policy', 'member_id', 'community_id'].map((name) => [name, { name, restrictions }])),
    requested_predicates: {
      eligible: { name: 'eligible', p_type: '>=', p_value: 1, restrictions },
      valid_until: { name: 'valid_until', p_type: '>=', p_value: expiresAt, restrictions },
    },
  };
}
