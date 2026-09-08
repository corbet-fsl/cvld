// Portable browser/native-adapter byte contract. No server or native-addon imports.
const utf8 = new TextEncoder();
function bytes(value, length) {
  if (!(value instanceof Uint8Array) || (length !== undefined && value.length !== length)) throw new TypeError('Required byte material is unavailable');
  return new Uint8Array(value);
}
function label(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9._:/-]{1,256}$/.test(value)) throw new TypeError('Invalid key scope');
  return value;
}
function b64(value) { let result = ''; for (const byte of value) result += String.fromCharCode(byte); return btoa(result).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', ''); }
function unb64(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) throw new TypeError('Invalid byte encoding');
  const decoded = Uint8Array.from(atob(value.replaceAll('-', '+').replaceAll('_', '/')), (x) => x.charCodeAt(0));
  if (b64(decoded) !== value) throw new TypeError('Noncanonical byte encoding');
  return decoded;
}
async function derive(secret, domain, scope, purpose) {
  const material = await crypto.subtle.importKey('raw', bytes(secret, 32), 'HKDF', false, ['deriveBits']);
  const salt = await crypto.subtle.digest('SHA-256', utf8.encode(domain));
  const info = utf8.encode(JSON.stringify([domain, label(scope), ...(purpose === undefined ? [] : [label(purpose)])]));
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info }, material, 256));
}
export async function sealLocalState({ data, key, context }) {
  const plaintext = bytes(data); label(context);
  const aes = await crypto.subtle.importKey('raw', bytes(key, 32), 'AES-GCM', false, ['encrypt']);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: utf8.encode(JSON.stringify(['cvld.state.v1', context])), tagLength: 128 }, aes, plaintext);
  return { version: 1, context, nonce: b64(nonce), ciphertext: b64(new Uint8Array(ciphertext)) };
}
export async function openLocalState({ envelope, key, context }) {
  label(context);
  if (envelope?.version !== 1 || envelope.context !== context) throw new Error('State context mismatch');
  const aes = await crypto.subtle.importKey('raw', bytes(key, 32), 'AES-GCM', false, ['decrypt']);
  const nonce = bytes(unb64(envelope.nonce), 12);
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce, additionalData: utf8.encode(JSON.stringify(['cvld.state.v1', context])), tagLength: 128 }, aes, unb64(envelope.ciphertext)));
}
async function wrap(root, prfOutput, scope) {
  return sealLocalState({ data: root, key: await derive(prfOutput, 'cvld.wrap.v1', scope), context: scope });
}
function session(root, scope, envelope) {
  return Object.freeze({
    envelope: structuredClone(envelope),
    storageKey: (purpose) => derive(root, 'cvld.storage.v1', scope, purpose),
    rewrap: ({ prfOutput }) => wrap(root, prfOutput, scope),
  });
}
export async function createWallet({ prfOutput, scope }) {
  label(scope); bytes(prfOutput, 32);
  const root = crypto.getRandomValues(new Uint8Array(32));
  return session(root, scope, await wrap(root, prfOutput, scope));
}
export async function unlockWallet({ prfOutput, scope, envelope }) {
  const root = bytes(await openLocalState({ envelope, key: await derive(prfOutput, 'cvld.wrap.v1', scope), context: scope }), 32);
  return session(root, scope, envelope);
}
// Never forward PRF extension results: these are wallet secrets, not server evidence.
function serverResponse(credential, registration) {
  const response = credential.response;
  const wire = { id: credential.id, rawId: b64(new Uint8Array(credential.rawId)), type: 'public-key', clientExtensionResults: {}, response: { clientDataJSON: b64(new Uint8Array(response.clientDataJSON)) } };
  if (credential.authenticatorAttachment) wire.authenticatorAttachment = credential.authenticatorAttachment;
  if (registration) {
    wire.response.attestationObject = b64(new Uint8Array(response.attestationObject));
    wire.response.transports = response.getTransports();
  } else {
    wire.response.authenticatorData = b64(new Uint8Array(response.authenticatorData));
    wire.response.signature = b64(new Uint8Array(response.signature));
    if (response.userHandle) wire.response.userHandle = b64(new Uint8Array(response.userHandle));
  }
  return wire;
}
export async function registerPasskey(options) {
  const parsed = PublicKeyCredential.parseCreationOptionsFromJSON(options);
  parsed.extensions = { ...parsed.extensions, prf: {} };
  const credential = await navigator.credentials.create({ publicKey: parsed });
  if (!credential?.getClientExtensionResults().prf?.enabled) throw new Error('This passkey does not support private wallet unlocking');
  return serverResponse(credential, true);
}
export async function authenticateWithWallet({ options, scope, envelope }) {
  label(scope);
  const parsed = PublicKeyCredential.parseRequestOptionsFromJSON(options);
  const input = await crypto.subtle.digest('SHA-256', utf8.encode(JSON.stringify(['cvld.prf.v1', scope])));
  parsed.extensions = { ...parsed.extensions, prf: { eval: { first: input } } };
  const credential = await navigator.credentials.get({ publicKey: parsed });
  const output = credential?.getClientExtensionResults().prf?.results?.first;
  if (!output) throw new Error('This passkey did not supply private wallet unlocking material');
  const prfOutput = bytes(new Uint8Array(output), 32);
  const wallet = envelope ? await unlockWallet({ prfOutput, scope, envelope }) : await createWallet({ prfOutput, scope });
  return { response: serverResponse(credential, false), wallet };
}
