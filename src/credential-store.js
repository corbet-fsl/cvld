import { requirePositive, requireText } from './encoding.js';

export function checkCredential(communityId, memberId, credential, maxPerMember) {
  requireText(communityId, 'community ID'); requireText(memberId, 'member ID');
  requireText(credential?.id, 'credential ID'); requirePositive(maxPerMember, 'member passkey limit');
  if (!(credential.publicKey instanceof Uint8Array) || !Number.isSafeInteger(credential.counter) || credential.counter < 0) throw new TypeError('Invalid credential');
}
export function createMemoryCredentialStore({ maxCredentials }) {
  requirePositive(maxCredentials, 'credential capacity');
  const records = new Map();
  const key = (community, id) => JSON.stringify([community, id]);
  return {
    insert(communityId, memberId, credential, maxPerMember) {
      checkCredential(communityId, memberId, credential, maxPerMember);
      const id = key(communityId, credential.id);
      if (records.has(id) || records.size >= maxCredentials || [...records.values()].filter((r) => r.communityId === communityId && r.memberId === memberId).length >= maxPerMember) return false;
      records.set(id, structuredClone({ ...credential, communityId, memberId }));
      return true;
    },
    get(communityId, id) { const value = records.get(key(communityId, id)); return value ? structuredClone(value) : undefined; },
    updateCounter(communityId, id, counter) {
      const record = records.get(key(communityId, id));
      if (!record || !Number.isSafeInteger(counter) || counter < 0 || ((counter > 0 || record.counter > 0) && counter <= record.counter)) return false;
      record.counter = counter; return true;
    },
  };
}
