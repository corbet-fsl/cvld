// Dedicated Worker entry. No DOM, networking, server, or plaintext persistence.
import init, { BrowserCredential, verifyProfilePresentation } from '../generated/holder/cvld_holder.js';
import { sealLocalState, openLocalState } from './client.js';

const encoder = new TextEncoder(), decoder = new TextDecoder('utf-8', { fatal: true });
const MAX_BYTES = 1_048_576;
let issuer, holder, initialized = false, busy = false;
const wire = value => {
  const result = JSON.stringify(value);
  if (typeof result !== 'string' || encoder.encode(result).length > MAX_BYTES) throw new Error('Rejected');
  return result;
};
function keyBytes(value) {
  if (!(value instanceof Uint8Array) || value.length !== 32) throw new Error('Rejected');
  return value;
}

self.onmessage = async ({ data }) => {
  const id = data?.id;
  if (!Number.isSafeInteger(id) || id < 1) return;
  if (busy) { self.postMessage({ id, ok: false }); return; }
  busy = true;
  let key, plaintext;
  try {
    let result = null;
    switch (data.op) {
      case 'init':
        if (initialized) throw new Error('Rejected');
        issuer = wire(data.issuer);
        await init({ module_or_path: new URL('../generated/holder/cvld_holder_bg.wasm', import.meta.url) });
        initialized = true;
        break;
      case 'request': {
        if (!initialized || holder) throw new Error('Rejected');
        holder = new BrowserCredential();
        const entropy = Array.from(crypto.getRandomValues(new Uint8Array(32)), byte => byte.toString(16).padStart(2, '0')).join('');
        result = JSON.parse(holder.request(issuer, wire(data.offer), entropy));
        break;
      }
      case 'accept':
        if (!initialized || !holder) throw new Error('Rejected');
        key = keyBytes(data.key);
        holder.accept(issuer, wire(data.credential));
        plaintext = encoder.encode(holder.privateState());
        result = await sealLocalState({ data: plaintext, key, context: data.context });
        break;
      case 'restore':
        if (!initialized || holder) throw new Error('Rejected');
        key = keyBytes(data.key);
        wire(data.envelope);
        plaintext = await openLocalState({ envelope: data.envelope, key, context: data.context });
        holder = BrowserCredential.fromPrivateState(decoder.decode(plaintext));
        break;
      case 'presentProfile':
        if (!initialized || !holder) throw new Error('Rejected');
        result = JSON.parse(holder.presentProfile(issuer, wire(data.request)));
        break;
      case 'verifyProfile':
        if (!initialized) throw new Error('Rejected');
        result = verifyProfilePresentation(issuer, wire(data.request), wire(data.proof));
        break;
      default: throw new Error('Rejected');
    }
    self.postMessage({ id, ok: true, result });
  } catch {
    // Never post crypto exceptions or holder private state to the embedding.
    self.postMessage({ id, ok: false });
  } finally {
    key?.fill(0); plaintext?.fill(0); busy = false;
  }
};
