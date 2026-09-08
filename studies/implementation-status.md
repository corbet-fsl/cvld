# Executable authentication and eligibility boundary

cvld encapsulates passkey authentication, independent eligibility evidence, account binding and local wallet encryption. The current implementation exercises real signatures, AnonCreds issuance/presentation and WebAuthn verification using synthetic external-provider facts. No compatible real phone, payment or voucher provider is integrated.

## Implemented behavior

1. `createPasskeyService` generates a random 32-byte community member ID and verifies registration through SimpleWebAuthn before inserting a credential into the configured repository. Another passkey can join that same account only after an assertion from an already registered passkey. A signed public admission certificate cannot authorize this management operation.
2. The holder creates an AnonCreds secret locally. Its blinded request envelope includes the intended community and member ID. A separately trusted external provider must attest to that exact request, configured factor/policy, opaque receipt and validity. Test signers provide genuine Ed25519 signatures over synthetic facts; they do not demonstrate an actual phone or payment check.
3. The issuer verifies provider signatures and any/all factor policy. It signs a nonrevocable credential containing eligibility, policy, validity, community and member ID. An atomic transaction stores the issued result and consumes opaque receipts together. Repeating an identical valid request returns the same credential; a conflicting reuse fails.
4. `createVerifier.begin(credentialId, audience, chatPublicKey)` looks up registered verification material. Its fresh challenge binds the account, community, audience, chat key, proof nonce, policy and validity. It accepts no client-supplied registered public-key record. A proof reveals the signed community/member/policy and demonstrates eligibility and validity through both challenge and admission horizons.
5. `authenticate` verifies the proof and WebAuthn assertion, atomically updates the stored counter, and returns `{eligible, communityId, memberId, admission}` or `false`. `verify` is the boolean variant. Both consume the challenge. A credential for one account cannot authenticate a different registered account; additional passkeys on the same account work.
6. The admission certificate binds that stable community member to a raw Ed25519 chat public key. `cvld/admission` verifies this independently of the native credential library. Participants can authenticate the same member across a live forum and private messaging.

A malicious person could still obtain separate eligible accounts if an independent provider issues separate valid attestations for the same external subject. Provider-side subject deduplication, authenticated account binding, recovery and independence remain integration requirements. This library neither sees nor validates raw identity factors. There is no global account directory, sanction field or individual revocation mechanism.

## State, persistence and wallet ownership

`createSqliteState` uses Node's SQLite binding, WAL, FULL synchronization and immediate transactions. Its receipt store retains each opaque receipt through that attestation's expiry and caches the issued credential through the result's expiry. A failed synchronous signer rolls back; a lost response can be recovered after reopening the database and restoring issuer keys. Four worker connections exercise the same transaction boundary. The credential repository persists account ownership, registered public keys and monotonic counters. A bounded memory implementation is also available for experiments.

Issuer configuration/private keys and processed holder credentials/link secrets have explicit AES-256-GCM encrypted export/import interfaces. Callers supply a 32-byte wrapping key; cvld never creates automatic plaintext secret files. An issuer operator must protect and back up its own encryption key. Holder exports belong on the client and must never be produced in the verifier's trust domain. In-progress blinded-request metadata is not currently resumable after a client restart.

`cvld/client` has no Node or native-addon imports. Its browser adapter requests WebAuthn PRF output locally, removes extension results from the server response, and wraps a random 32-byte wallet root. Unsupported PRF fails closed. Additional passkeys can wrap the same root without changing message-storage keys. `wallet.storageKey('cmsg')` supplies cmsg with a scope-separated 32-byte key. The root and PRF output remain in local closures; only encrypted envelopes serialize. JavaScript cannot guarantee zeroization or protect a wallet from malicious code running in its origin.

The portable byte contract uses UTF-8 compact JSON arrays, SHA-256, HKDF-SHA256 and AES-GCM with a fresh random 12-byte nonce and a 128-bit tag:

| Operation | Inputs / encoding |
|---|---|
| WebAuthn PRF input | SHA256(JSON `["cvld.prf.v1", communityId]`); exported as `walletPrfInput` |
| Wallet wrapping key | HKDF: IKM=32-byte PRF result; salt=SHA256(`cvld.wrap.v1`); info=JSON `["cvld.wrap.v1", communityId]`; output32 |
| Component storage key | HKDF: IKM=32-byte wallet root; salt=SHA256(`cvld.storage.v1`); info=JSON `["cvld.storage.v1", communityId, purpose]`; output32 |
| Encrypted state | AES-GCM AAD=JSON `["cvld.state.v1", context]`; `{version:1,context,nonce,ciphertext}` with unpadded base64url bytes; ciphertext includes tag |

A native adapter must supply the WebAuthn PRF result with the same semantics. Raw CTAP HMAC-secret input/output is not automatically interchangeable with WebAuthn PRF: the [WebAuthn extension](https://www.w3.org/TR/webauthn-3/#prf-extension) specifies its input transformation. Do not substitute a passkey public key or signature for a PRF result.

## Admission wire contract

The signed UTF-8 JSON array is exactly:

```json
["cvld.admission.v1", "issuerKeyId", "communityId", "memberId", "chatPublicKey", "policyDigest", 1800000000, 1800000120]
```

Those strings stand for the grant's corresponding values, not literal labels. `version` is exactly 1. The issuer key ID is SHA256(raw32 Ed25519 signing public key). Member ID, chat key, policy digest and issuer key ID are canonical unpadded base64url32-byte values. The signature is canonical unpadded base64url64-byte Ed25519. Community scope is ASCII matching `[A-Za-z0-9._:/-]{1,256}`. Integer Unix validity is `issuedAt <= now < expiresAt`, with no implicit clock skew. Trust comes from a configured public key, community and policy, never a key carried by the certificate. A public deterministic test vector is in `test/fixtures/admission-v1.json`.

## Runtime and dependency evidence

| Component | Implementation / license | Executable evidence and remaining boundary |
|---|---|---|
| Anonymous credentials | [AnonCreds JS 0.4.0](https://github.com/anoncreds/anoncreds-wrapper-javascript), Rust 0.2.3; Apache-2.0 | Real Node24/Linux x64 issuance and proofs. Browser/native holder integration remains future work. |
| Passkey service | [SimpleWebAuthn server 14.0.1](https://github.com/MasterKale/SimpleWebAuthn); MIT | Genuine ES256 registration/assertion negatives plus browser-created registration/assertions. |
| Browser wallet | WebCrypto + WebAuthn PRF; Playwright1.63.0 test-only, Apache-2.0 | Chromium virtual authenticator: registration, two PRF unlocks, sanitized responses and unsupported-PRF rejection. Hardware availability and synchronized-device behavior are not established. |
| Mobile credential candidate | [AnonCreds React Native](https://github.com/anoncreds/anoncreds-wrapper-javascript/tree/main/packages/anoncreds-react-native); Apache-2.0 | Upstream Android Gradle/JNI and iOS CocoaPods/C++ bindings exist, sharing the Rust core. cvld has not built a native mobile holder or audited wrapper installation. |
| Native passkey candidates | [Apple AuthenticationServices PRF](https://developer.apple.com/documentation/authenticationservices/asauthorizationpublickeycredentialprfassertioninput-swift.struct), [Android Credential Manager](https://developer.android.com/identity/passkeys/sign-in-with-passkeys) | These are future adapters to the JSON/byte contract. PRF support must be checked on the actual OS/provider/device. No paid accounts, signing or mobile app distribution were used. |

The Node aggregate export loads AnonCreds; browser consumers must use `cvld/client`. The admission export uses Node crypto but no native addon. Protocol JSON and raw-byte interfaces allow independent mobile implementations; this is not a claim that every export already runs on Android or iOS.

The npm lockfile pins artifacts. CI disables lifecycle scripts, including the install hooks declared by upstream AnonCreds and Koffi. Consumers must preserve `--ignore-scripts` to avoid those upstream installers. The explicit native installer verifies SHA256 before extracting the official Linux x64 artifact and resolves the actual dependency directory, including hoisted installs. A separate consumer installs the actual npm tarball outside the checkout and imports the package and subpaths. Source reproducibility and independent native-binary auditing remain unverified. The experimental release manifest targets npm version `0.1.0-alpha.0` under the `alpha` tag. CI uploads the tested tarball, npm pack metadata and SHA-256 after all checks pass; publication is a separate authorized action. The native downloader is an explicit `cvld-install-native` command, with no lifecycle hook.

## Security limits

Challenges are bounded and ephemeral; restart invalidates outstanding sessions. Policy, trusted keys, origin/RP ID, clocks, lifetimes, capacities, proof size and user-verification requirements are explicit. Timestamps used for AnonCreds predicates remain in the signed 32-bit range. An admission cannot outlive the eligibility horizon proved at login.

The operator intentionally knows opaque community member IDs and public passkeys. Issuance and presentation reveal the intended account; this is not issuer/verifier account unlinkability. No raw phone/payment fields or private communication edges are required. Network addresses, timing, colluding providers, deployment logs and malicious client distribution remain outside the cryptographic boundary. Sharing a passkey or holder secret is not prevented by a proof of possession.

The holder validates the complete disclosure request, preventing substitution of private expiry into a revealed attribute. Serialized proofs omit exact expiry and gate receipts. Adaptive future-horizon queries can still bound expiry via success/failure; a trusted holder clock and approved horizon policy or expiry cohorts are needed before stronger claims. A shared RP ID or deliberately reused account record can also correlate communities. Scope-separated cryptographic labels do not hide transport metadata.

## Test-driven evidence

All tests execute on standard public Ubuntu GitHub Actions runners with synthetic data, no application secrets or caches. The release job uploads only the reviewed package tarball, public pack metadata and its checksum with one-day retention. These runners are [free for public repositories](https://docs.github.com/en/billing/concepts/product-billing/github-actions). No local desktop tests or builds were used.

| Cycle | Public evidence |
|---|---|
| Initial genuine credential implementation | Red16: `73961ae`, [34253627108](https://github.com/corbet-labs/cvld/actions/runs/34253627108). Green16: `df097e8`, [34254060753](https://github.com/corbet-labs/cvld/actions/runs/34254060753). |
| Adversarial receipt/disclosure/counter fixes | Red regressions: `e31fde8` and `814b03e`. Green24: `8ba1d8d`, [34255291362](https://github.com/corbet-labs/cvld/actions/runs/34255291362). |
| Registration, durable transactions and actual packed consumer | Red: `330da2c`, [34256507413](https://github.com/corbet-labs/cvld/actions/runs/34256507413). Green: `ac9257e`, [34256812934](https://github.com/corbet-labs/cvld/actions/runs/34256812934). |
| Account binding and local wallet wrapping | Red: `29319a5`, [34257231458](https://github.com/corbet-labs/cvld/actions/runs/34257231458). Green: `0f5515b`, [34258235838](https://github.com/corbet-labs/cvld/actions/runs/34258235838). |
| Browser PRF and SQLite worker concurrency | Green41 plus browser and packed consumer: `353e2d6`, [34258469924](https://github.com/corbet-labs/cvld/actions/runs/34258469924). |
| Encrypted holder restore and shorter admission lifetime | Red42/44: `6a120d9`, [34258615348](https://github.com/corbet-labs/cvld/actions/runs/34258615348). Green44 plus browser and packed consumer: `9d8dfb6`, [34258786567](https://github.com/corbet-labs/cvld/actions/runs/34258786567). |

Tests establish observable protocol and integration behavior. They do not establish external-provider truthfulness, production anonymity, hardware security, mobile deployment compatibility or operational compliance.
