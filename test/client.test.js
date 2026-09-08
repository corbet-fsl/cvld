import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createWallet, unlockWallet, sealLocalState, openLocalState } from '../src/client.js';

const scope = 'community.example';
const prf = Uint8Array.from({ length: 32 }, (_, index) => index);

test('PRF unlock restores scope-separated 32-byte storage keys without plaintext state', async () => {
  const wallet = await createWallet({ prfOutput: prf, scope });
  const restored = await unlockWallet({ prfOutput: prf, scope, envelope: wallet.envelope });
  const messaging = await wallet.storageKey('cmsg');
  assert.equal(messaging.length, 32);
  assert.deepEqual(await restored.storageKey('cmsg'), messaging);
  assert.notDeepEqual(await wallet.storageKey('cvld'), messaging);
  assert.equal(JSON.stringify(wallet).includes(Buffer.from(prf).toString('base64url')), false);
});

test('wrong PRF, wrong scope and modified wallet ciphertext fail closed', async () => {
  const wallet = await createWallet({ prfOutput: prf, scope });
  const wrong = new Uint8Array(prf); wrong[0] ^= 1;
  await assert.rejects(unlockWallet({ prfOutput: wrong, scope, envelope: wallet.envelope }));
  await assert.rejects(unlockWallet({ prfOutput: prf, scope: 'another.example', envelope: wallet.envelope }));
  const changed = structuredClone(wallet.envelope); changed.ciphertext = 'AAAA';
  await assert.rejects(unlockWallet({ prfOutput: prf, scope, envelope: changed }));
  await assert.rejects(createWallet({ scope }));
});

test('an additional passkey can wrap the same wallet without changing message keys', async () => {
  const first = await createWallet({ prfOutput: prf, scope });
  const nextPrf = new Uint8Array(32).fill(99);
  const envelope = await first.rewrap({ prfOutput: nextPrf });
  const second = await unlockWallet({ prfOutput: nextPrf, scope, envelope });
  assert.deepEqual(await second.storageKey('cmsg'), await first.storageKey('cmsg'));
});

test('local issuer or holder state encryption authenticates both bytes and context', async () => {
  const key = new Uint8Array(32).fill(7);
  const data = new TextEncoder().encode('synthetic secret state');
  const encrypted = await sealLocalState({ data, key, context: 'cvld.issuer.v1' });
  assert.deepEqual(await openLocalState({ envelope: encrypted, key, context: 'cvld.issuer.v1' }), data);
  assert.equal(JSON.stringify(encrypted).includes('synthetic secret state'), false);
  await assert.rejects(openLocalState({ envelope: encrypted, key, context: 'cvld.holder.v1' }));
});
