/** Policy adapter for a community that explicitly allows all eligible members
 * to read profiles. Use only inside cfrm's profile key service AFTER its real
 * eligibility verifier accepts the challenge-bound presentation. This is not a
 * standalone credential verifier and implements no per-reader profile hiding. */
export function createEligibleMemberProfilePolicy({ communityId, policyDigest, mode }) {
  if (mode !== 'eligible-members' || typeof communityId !== 'string' || !communityId
      || typeof policyDigest !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(policyDigest)) {
    throw new TypeError('Explicit eligible-member profile policy required');
  }
  return Object.freeze({
    async proveAccess({ challenge, publication }) {
      if (challenge?.communityId !== communityId || challenge.policyDigest !== policyDigest
          || publication?.envelope?.communityId !== communityId) throw new Error('Profile policy rejected');
      // No second credential or identifying pseudonym is needed for this policy.
      // The genuine AnonCreds proof is the separate presentation in cfrm's frame.
      return { policy: 'eligible-members' };
    },
    async authorizeAccess({ challenge, publication, presentation, accessProof }) {
      const revealed = presentation?.requested_proof?.revealed_attrs;
      return accessProof?.policy === 'eligible-members' && Object.keys(accessProof).length === 1
        && challenge?.communityId === communityId && challenge.policyDigest === policyDigest
        && publication?.envelope?.communityId === communityId
        && publication?.admission?.policyDigest === policyDigest
        && revealed?.community_id?.raw === communityId && revealed?.policy?.raw === policyDigest;
    },
  });
}
