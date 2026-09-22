/** Client-only AnonCreds operations. The embedding supplies a dedicated Worker
 * created from @corbet-labs/cvld/holder-worker. Holder state leaves it only as
 * authenticated ciphertext; proving never runs on the UI thread. */
export async function createBrowserCredentialHolder({ worker, publicIssuer, deadlineMs }) {
  if (!worker || typeof worker.postMessage !== 'function' || typeof worker.terminate !== 'function'
      || !Number.isSafeInteger(deadlineMs) || deadlineMs < 1 || deadlineMs > 300_000) {
    throw new TypeError('Dedicated credential Worker and bounded deadline required');
  }
  let sequence = 0, active = null, closed = false;
  const rejected = () => new Error('Credential operation could not complete');
  function close() {
    if (closed) return;
    closed = true;
    if (active) { clearTimeout(active.timer); active.reject(rejected()); active = null; }
    worker.terminate();
  }
  worker.addEventListener('error', close);
  worker.addEventListener('messageerror', close);
  worker.addEventListener('message', ({ data }) => {
    if (!active || data?.id !== active.id) { close(); return; }
    const pending = active; active = null; clearTimeout(pending.timer);
    if (data.ok === true) pending.resolve(data.result);
    else pending.reject(rejected());
  });
  function call(op, args = {}, transfer = []) {
    if (closed || active) return Promise.reject(rejected());
    return new Promise((resolve, reject) => {
      const id = ++sequence;
      active = { id, resolve, reject, timer: setTimeout(close, deadlineMs) };
      try { worker.postMessage({ ...args, op, id }, transfer); }
      catch { close(); }
    });
  }
  function privateCall(op, args) {
    if (!(args.key instanceof Uint8Array) || args.key.length !== 32) return Promise.reject(rejected());
    const key = args.key.slice();
    return call(op, { ...args, key }, [key.buffer]);
  }
  try { await call('init', { issuer: publicIssuer }); } catch (error) { close(); throw error; }
  return Object.freeze({
    request: offer => call('request', { offer }),
    accept: ({ credential, key, context }) => privateCall('accept', { credential, key, context }),
    restore: ({ envelope, key, context }) => privateCall('restore', { envelope, key, context }),
    presentProfile: request => call('presentProfile', { request }),
    verifyProfile: (request, proof) => call('verifyProfile', { request, proof }),
    close,
  });
}
