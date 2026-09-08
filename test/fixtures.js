import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { encodeCBOR } from '@levischuck/tiny-cbor';
import { encodeAttestation, issuanceDigest, policyDigest } from '../src/index.js';

export const NOW = 1_800_000_000;
export const ORIGIN = 'https://community.example';
export const RP_ID = 'community.example';
export const POLICY = Object.freeze({ version: '1', mode: 'any', factors: ['phone', 'payment', 'voucher'] });
export const sha256 = (value) => createHash('sha256').update(value).digest();

export function makeGate(factor) {
  const keys = generateKeyPairSync('ed25519');
  return {
    public: { factor, publicKey: keys.publicKey.export({ format: 'pem', type: 'spki' }) },
    attest(offer, request, policy = POLICY, overrides = {}) {
      const body = {
        keyId: factor,
        factor,
        receiptId: randomBytes(24).toString('base64url'),
        issuanceDigest: issuanceDigest(offer, request),
        policyDigest: policyDigest(policy),
        validUntil: NOW + 600,
        ...overrides,
      };
      return { ...body, signature: sign(null, encodeAttestation(body), keys.privateKey).toString('base64url') };
    },
  };
}

// A software authenticator for protocol tests, not a hardware-security claim.
export function makeAuthenticator() {
  const keys = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const jwk = keys.publicKey.export({ format: 'jwk' });
  const id = randomBytes(32).toString('base64url');
  const publicKey = encodeCBOR(new Map([
    [1, 2], [3, -7], [-1, 1],
    [-2, Buffer.from(jwk.x, 'base64url')], [-3, Buffer.from(jwk.y, 'base64url')],
  ]));
  return {
    credential: { id, publicKey, counter: 0, transports: ['internal'] },
    register(challenge, { origin = ORIGIN, rpID = RP_ID, flags = 69 } = {}) {
      const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.create', challenge, origin, crossOrigin: false }));
      const rawId = Buffer.from(id, 'base64url');
      const length = Buffer.alloc(2); length.writeUInt16BE(rawId.length);
      const authData = Buffer.concat([sha256(rpID), Buffer.from([flags]), Buffer.alloc(4), Buffer.alloc(16), length, rawId, publicKey]);
      const signature = sign('sha256', Buffer.concat([authData, sha256(clientDataJSON)]), keys.privateKey);
      const attestationObject = encodeCBOR(new Map([
        ['fmt', 'packed'], ['authData', authData], ['attStmt', new Map([['alg', -7], ['sig', signature]])],
      ]));
      return { id, rawId: id, type: 'public-key', clientExtensionResults: { credProps: { rk: true } }, response: {
        clientDataJSON: clientDataJSON.toString('base64url'), attestationObject: Buffer.from(attestationObject).toString('base64url'), transports: ['internal'],
      } };
    },
    assert(challenge, { origin = ORIGIN, rpID = RP_ID, flags = 5, counter = 0 } = {}) {
      const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin, crossOrigin: false }));
      const counterBytes = Buffer.alloc(4);
      counterBytes.writeUInt32BE(counter);
      const authenticatorData = Buffer.concat([sha256(rpID), Buffer.from([flags]), counterBytes]);
      const signature = sign('sha256', Buffer.concat([authenticatorData, sha256(clientDataJSON)]), keys.privateKey);
      return {
        id, rawId: id, type: 'public-key', clientExtensionResults: {},
        response: {
          clientDataJSON: clientDataJSON.toString('base64url'),
          authenticatorData: authenticatorData.toString('base64url'),
          signature: signature.toString('base64url'),
        },
      };
    },
  };
}
