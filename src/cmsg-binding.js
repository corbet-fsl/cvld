import { publicBytes, scopeText } from './admission.js';

// Structural adapter for cmsg's signed DeviceAuthorization wire contract.
// Signature and root-derived identity verification are delegated to cmsg's
// native implementation; this module only canonicalizes bounded JSON input.
function exactObject(value, fields) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).length !== fields.length || fields.some((field) => !Object.hasOwn(value, field))) throw new TypeError('Invalid device authorization');
}

export function authorityBytes(value) {
  exactObject(value, ['version', 'communityId', 'memberId', 'rootPublicKey', 'devicePublicKey', 'issuedAt', 'expiresAt', 'signature']);
  if (value.version !== 1) throw new TypeError('Invalid device authorization');
  scopeText(value.communityId);
  for (const field of ['memberId', 'rootPublicKey', 'devicePublicKey']) publicBytes(value[field]);
  for (const field of ['issuedAt', 'expiresAt']) if (!Number.isSafeInteger(value[field]) || value[field] <= 0) throw new TypeError('Invalid device authorization');
  if (value.expiresAt <= value.issuedAt) throw new TypeError('Invalid device authorization');
  publicBytes(value.signature, 64);
  return new TextEncoder().encode(JSON.stringify([
    'cmsg.device.v1', value.communityId, value.memberId, value.rootPublicKey,
    value.devicePublicKey, value.issuedAt, value.expiresAt,
  ]));
}

export function validateDeviceAuthorization({ authorization, communityId, memberId, chatPublicKey, now }) {
  try {
    authorityBytes(authorization);
    publicBytes(memberId); publicBytes(chatPublicKey); scopeText(communityId);
    if (!Number.isSafeInteger(now) || now <= 0 || authorization.communityId !== communityId ||
        authorization.memberId !== memberId || authorization.devicePublicKey !== chatPublicKey ||
        authorization.issuedAt > now || authorization.expiresAt <= now) return false;
    return true;
  } catch { return false; }
}
