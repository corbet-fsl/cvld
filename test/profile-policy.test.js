import assert from 'node:assert/strict';
import { test } from 'node:test';
import { randomBytes } from 'node:crypto';
import { createEligibleMemberProfilePolicy } from '../src/profile-policy.js';

test('eligible-member policy requires matching challenge, owner community and already verified revealed claims', async () => {
  const communityId = 'policy.example', policyDigest = randomBytes(32).toString('base64url');
  const policy = createEligibleMemberProfilePolicy({ communityId, policyDigest, mode: 'eligible-members' });
  // This is the post-verification policy callback, not a credential-verification
  // test. The real cfrm key-service chain must verify the separate presentation.
  const input = { challenge: { communityId, policyDigest }, publication: { envelope: { communityId }, admission: { policyDigest } },
    presentation: { requested_proof: { revealed_attrs: { community_id: { raw: communityId }, policy: { raw: policyDigest } } } },
    accessProof: { policy: 'eligible-members' } };
  assert.deepEqual(await policy.proveAccess(input), input.accessProof);
  assert.equal(await policy.authorizeAccess(input), true);
  for (const change of [x => { x.challenge.communityId = 'other'; }, x => { x.challenge.policyDigest = randomBytes(32).toString('base64url'); },
    x => { x.publication.envelope.communityId = 'other'; }, x => { x.publication.admission.policyDigest = randomBytes(32).toString('base64url'); },
    x => { x.presentation.requested_proof.revealed_attrs.community_id.raw = 'other'; }, x => { delete x.presentation.requested_proof.revealed_attrs.policy; },
    x => { x.accessProof = { policy: 'hidden-profile' }; }, x => { x.accessProof.memberId = 'injected'; }]) {
    const altered = structuredClone(input); change(altered); assert.equal(await policy.authorizeAccess(altered), false);
  }
  await assert.rejects(policy.proveAccess({ ...input, challenge: { communityId: 'other', policyDigest } }));
  assert.throws(() => createEligibleMemberProfilePolicy({ communityId, policyDigest, mode: 'private-block-proof' }));
});
