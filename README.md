# cvld

Passkey authentication, independently attested eligibility, and a stable pseudonymous member identity inside one community. cvld binds an authenticated member to a public chat signing key so other components can recognize the same participant.

**Experimental `0.1.0-alpha.0`:** real AnonCreds and WebAuthn integrations with synthetic provider attestations, encrypted wallets and durable SQLite state. No compatible live phone, payment or voucher provider is integrated. External-provider uniqueness, production traffic privacy, recovery and native mobile device compatibility remain incomplete. APIs may change before a stable release.

## Install and native support

```sh
npm install --ignore-scripts @corbet-labs/cvld@0.1.0-alpha.0
```

The server and Node holder experiment require **Node 24 or newer on Linux x64 with glibc** (tested on Ubuntu 24.04). The aggregate `@corbet-labs/cvld` export loads the native AnonCreds library. Install that library explicitly before importing the aggregate export:

```sh
npm exec --offline -- cvld-install-native
```

This opt-in command downloads the official AnonCreds Rust 0.2.3 Linux x64 archive from GitHub, verifies the pinned SHA-256, and extracts `libanoncreds.so` into the resolved dependency directory. It requires network access and `tar`. cvld adds no install/postinstall hook or service installation. Its upstream AnonCreds and FFI dependencies do declare install scripts: keep `--ignore-scripts` on the initial install to bypass them, as CI does. A plain npm install may run those upstream installers. The `--offline` flag prevents npm from obtaining a missing command package; the explicitly invoked downloader itself uses the network. The artifact URL and checksum are readable in [`scripts/install-native.js`](https://github.com/corbet-labs/cvld/blob/main/scripts/install-native.js).

macOS, Windows, Linux ARM, musl/Alpine, Android and iOS native holder builds are not supported by this release. `@corbet-labs/cvld/client` contains portable WebCrypto wallet functions and a browser WebAuthn adapter without Node or native-addon imports. Native mobile adapters are future work; passkey support alone does not guarantee PRF support.

## Exports and composition

| Import | Purpose |
|---|---|
| `@corbet-labs/cvld` | Issuer/holder issuance and proofs, passkey service, account-bound verifier and state repositories; loads native AnonCreds |
| `@corbet-labs/cvld/passkeys` | SimpleWebAuthn registration and additional-passkey authorization without loading AnonCreds |
| `@corbet-labs/cvld/storage` | Durable Node SQLite receipt/result and registered-credential stores |
| `@corbet-labs/cvld/admission` | Ed25519 admission verification and canonical bytes using Node crypto; no native addon |
| `@corbet-labs/cvld/client` | Client-only PRF wallet wrapping, component storage keys and encrypted state envelopes |

The host supplies explicit community scope, policy, trusted provider keys, origin/RP ID, clocks, lifetimes, capacities and storage. `createPasskeyService` verifies enrollment into a credential repository. `createVerifier` accepts a registered credential ID, verifies eligibility for the same member and issues an admission certificate bound to the requested chat public key. Registering additional passkeys requires authentication from an existing passkey and preserves the member ID.

The result of `verifier.authenticate(...)` is `{eligible: true, communityId, memberId, admission}` or `false`. `verifier.verify(...)` returns a boolean; either operation consumes its challenge. The [synthetic account integration example](https://github.com/corbet-labs/cvld/blob/main/test/account.test.js) shows the complete issuance and authentication sequence with real signatures and synthetic external facts.

A component can verify a certificate independently:

```js
import { verifyAdmission } from '@corbet-labs/cvld/admission';

const admitted = verifyAdmission({
  grant,
  trustedPublicKey, // Configured raw 32-byte Ed25519 key: Uint8Array
  communityId,
  policyDigest,
  now: Math.floor(Date.now() / 1000),
});
```

The certificate is public evidence of account/chat-key binding. It is not a secret bearer credential: a forum or messaging protocol must separately verify possession of the certified chat signing key. Trust keys, scope and policy must come from host configuration, not the person presenting the grant.

## Local encrypted wallets

In a supported secure browser context:

```js
import { registerPasskey, authenticateWithWallet } from '@corbet-labs/cvld/client';

const registrationResponse = await registerPasskey(registrationOptions);
// Send registrationResponse to the passkey service and complete enrollment.

const { response, wallet } = await authenticateWithWallet({
  options: authenticationOptions,
  scope: communityId,
  envelope: savedEncryptedWallet, // Omit only when creating a new local wallet.
});
// Send only response to the verifier, together with the eligibility proof.
// Persist wallet.envelope locally; pass this key only to local message storage.
const messageStorageKey = await wallet.storageKey('cmsg');
```

PRF output and wallet root never enter the sanitized server response. `wallet.rewrap(...)` lets another authorized passkey wrap the same root. Missing PRF support fails closed. Callers must retrieve an existing envelope when one exists; creating a new wallet generates new storage keys. Loss of every usable passkey/envelope can mean loss of encrypted data. There is no password or server recovery key.

Holder credentials/link secrets and issuer keys/configuration have explicit encrypted export/import APIs. Their trust domains must stay separate: the holder wallet belongs on the client. Never run it inside the verifier service or send its wrapping key to that service.

## Guarantees and limits

- A verified eligibility credential names one member in one community. It cannot authenticate another registered account. A provider must still prevent issuing separate account-bound attestations for the same external subject where uniqueness is required.
- SQLite transactions atomically consume opaque receipts and cache issuance results. Exact retries survive restart when the issuer keys and database are restored. Public credential records and monotonic passkey counters are durable. Pending challenges are ephemeral and fail closed after restart.
- The operator intentionally knows opaque member IDs, public passkeys and gate status. It does not receive raw phone or payment fields through this interface. Issuance/presentation account linkage is intentional; this is not issuer/verifier account unlinkability.
- No individual bans or sanction/revocation records are implemented. Expiration is explicit policy, not a moderation decision.
- These primitives do not hide network addresses, timing or private communication graphs by themselves. They do not protect against malicious client code, colluding external providers or voluntary credential sharing. Serialized proofs hide exact expiry, but adaptive validity queries can reveal bounds.

Public CI verifies genuine credentials, registration/assertion failures, cross-account rejection, encrypted state restoration, SQLite concurrency/restart, Chromium virtual-authenticator PRF behavior and installation from the actual npm tarball. This is executable integration evidence, not a production anonymity or physical-device security claim.

- [Behavioral contract](https://github.com/corbet-labs/cvld/blob/main/docs/contract.md)
- [Implementation, byte contracts and test evidence](https://github.com/corbet-labs/cvld/blob/main/studies/implementation-status.md)
- [Independent provider candidates](https://github.com/corbet-labs/cvld/blob/main/studies/independent-providers.md)
- [Studies](https://github.com/corbet-labs/cvld/blob/main/studies/README.md)
- [Experiments](https://github.com/corbet-labs/cvld/blob/main/experiments/README.md)

License: [FSL-1.1-ALv2](https://github.com/corbet-labs/cvld/blob/main/LICENSE.md). Third-party libraries retain their own licenses.
