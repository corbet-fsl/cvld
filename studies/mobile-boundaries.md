# Native Android and iOS boundaries

Reviewed 2026-09-08. Native clients are feasible using existing AnonCreds and passkey implementations. The published `@corbet-labs/cvld@0.1.0-alpha.0` holder is nevertheless a Node/Linux experiment; this study adds no mobile implementation or device evidence. The main unresolved compatibility boundary is obtaining repeatable, local WebAuthn PRF output from the actual OS and credential provider.

## Current evidence

| Component | Established | Still unverified |
|---|---|---|
| cvld issuer and holder | Real AnonCreds Rust 0.2.3 through the Node 0.4.0 wrapper; registration, proofs, encrypted holder state and packed-consumer tests | A native holder, native packaging, interrupted mobile issuance and mobile performance |
| cvld wallet | WebCrypto byte contract; Chromium virtual-authenticator PRF registration, repeated unlock and rewrapping | Hardware/provider PRF support, synchronized passkeys, native/browser equivalence and recovery on replacement phones |
| cmsg core | At `b4ac4f9`, [run 34258758551](https://github.com/corbet-labs/cmsg/actions/runs/34258758551) passed native behavioral tests plus `cargo check --locked --lib` for Android arm64 and iOS arm64 | Those checks did not link an Android/iOS application, run on either OS, exercise passkeys or establish background networking. Later Crow native runs do not repeat mobile target checks. |
| cfrm profiles | Real anonymous-reader credential tests and authenticated owner protocol in a Node-backed client experiment | Native/browser holder adapter and a real profile onion listener; an in-memory transport capability establishes no mobile anonymity |

See [implementation evidence](implementation-status.md) and the [published alpha artifact](npm-alpha-release.md). Importing `@corbet-labs/cvld/client` avoids Node imports, but does not supply a missing WebCrypto or WebAuthn runtime in React Native.

The current CI limitation is verified, not assumed: [Crow repository 10, pipeline 8](https://crow.corbet.ch/repos/10/pipeline/8), native step `21025`, source `4d141953833818dced13c97cc7b9ff806a05ec80`, recorded Rust 1.97.1 and Cargo 1.97.0, no `rustup` on the workflow PATH, and no target standard-library directories for either `aarch64-linux-android` or `aarch64-apple-ios`. That worker cannot repeat the latest mobile target checks without additional toolchain components. That historical source declared Rust 1.91, which the run did not verify; the subsequent release candidate conservatively declares the tested Rust 1.97.1 minimum. No tools were added for the inventory.

The newer cmsg clock, roster handles and encrypted-outbox persistence callbacks introduce no apparent OS-specific dependency in source review. They still need native bindings and application-owned execution/lifecycle handling. When an appropriately provisioned worker is available, rerun both target checks on the exact latest validated revision. A successful [`cargo check`](https://doc.rust-lang.org/cargo/commands/cargo-check.html) remains compiler-metadata evidence: final code generation, application linking, native SDK integration and device execution are separate checks.

## Existing credential implementations

| Path | Primary-source evidence | Engineering use |
|---|---|---|
| Official React Native wrapper | At `d020c62`, [`@hyperledger/anoncreds-react-native` 0.4.0](https://github.com/anoncreds/anoncreds-wrapper-javascript/blob/d020c62fd168d54302f1ce9a6d99536971cf4631/packages/anoncreds-react-native/package.json) selects Rust **0.2.3**, matching this alpha. Its manifest requires React Native >=0.71. Apache-2.0. | Closest existing path for a React Native holder; use its shared API rather than the Node aggregate export. This does not require choosing React Native for every application. |
| Android/iOS native artifacts | The wrapper's [Gradle source](https://github.com/anoncreds/anoncreds-wrapper-javascript/blob/d020c62fd168d54302f1ce9a6d99536971cf4631/packages/anoncreds-react-native/android/build.gradle) loads JNI libraries; its [CocoaPods specification](https://github.com/anoncreds/anoncreds-wrapper-javascript/blob/d020c62fd168d54302f1ce9a6d99536971cf4631/packages/anoncreds-react-native/anoncreds.podspec) uses an XCFramework and C++/Objective-C++ bridge. | Real upstream integration scaffolding exists. Review exact artifacts, checksums, architectures and toolchain requirements before building; their presence is not a successful cvld mobile build. |
| Swift/Kotlin UniFFI wrappers | [LFDT Labs wrappers](https://github.com/LF-Decentralized-Trust-labs/aries-uniffi-wrappers/blob/0c33e423a5a96e52f2c8e795adc26931806ca0d5/README.md) generate Swift and Kotlin bindings. Apache-2.0; inspected revision has an August 2026 commit. | Existing typed wrappers are useful references. However, their [AnonCreds dependency](https://github.com/LF-Decentralized-Trust-labs/aries-uniffi-wrappers/blob/0c33e423a5a96e52f2c8e795adc26931806ca0d5/anoncreds/Cargo.toml) still pins Rust **0.2.0**. Kotlin binary distribution also requires GitHub Packages authentication. Do not describe this as an anonymous, version-matched drop-in dependency. |
| Official Rust/C interface | AnonCreds 0.2.3 exposes an existing [C header](https://github.com/anoncreds/anoncreds-rs/blob/v0.2.3/include/libanoncreds.h) for credential requests, processing, presentations, JSON objects and handle ownership. | Preferred common native protocol boundary: reuse this exact engine and existing wrappers, adding narrowly typed Swift/Kotlin glue where needed. No new signature or proof construction is necessary. |

The React Native package declares an installation hook that downloads native artifacts. The next integration must preserve explicit dependency installation and reviewed, checksum-pinned native acquisition; it must not inherit uncontrolled installation behavior. Upstream activity is evidence of an available project, not a maintenance or security guarantee.

## Native passkeys and PRF

**iOS:** AuthenticationServices exposes [PRF assertion input](https://developer.apple.com/documentation/authenticationservices/asauthorizationpublickeycredentialprfassertioninput-swift.struct) and the platform request's [PRF property](https://developer.apple.com/documentation/authenticationservices/asauthorizationplatformpublickeycredentialassertionrequest/prf-47uoa) from iOS 18. The API describes deterministic symmetric output for the same passkey and inputs. Registration capability and actual assertion output must both be checked. This establishes API availability, not support by every selected credential provider.

Repeatability deserves an explicit test: [Apple engineering confirmed](https://developer.apple.com/forums/thread/764730) a historical discrepancy between local and hybrid PRF results and identified the iOS 18.4/macOS 15.4 betas as the correction. That is not a reason to assume old encrypted envelopes recover after an OS change. Test local, synchronized-device and hybrid ceremonies with required user verification; never replace an unreadable wallet with a newly generated root.

**Android:** [Credential Manager registration](https://developer.android.com/identity/passkeys/create-passkeys) supports passkeys on Android 9/API 28 and later. [Authentication](https://developer.android.com/identity/passkeys/sign-in-with-passkeys) accepts WebAuthn request JSON and returns assertion JSON. The reviewed official guides do not establish a universal provider/version guarantee for PRF. The adapter must request the extension, retain its result locally and require an actual 32-byte result before wallet access.

The AOSP [`IdentityKey.createFromPrf`](https://android.googlesource.com/platform/frameworks/support/+/7ce39ea7a20531ecc6b2ce9bed6c624da021c6a0/credentials/credentials-e2ee/src/main/java/androidx/credentials/e2ee/IdentityKey.kt) helper accepts an already obtained PRF value. It does not perform a passkey ceremony, establish provider support or implement cvld's wallet derivation. It must not replace the random, rewrappable wallet root. [Yubico's Android SDK](https://developers.yubico.com/yubikit-android/fido-android-ui/index.html) separately documents PRF/HMAC-secret support for its security-key path; that is not evidence for every phone's platform passkey provider.

The [WebAuthn PRF extension](https://www.w3.org/TR/webauthn-3/#prf-extension) transforms inputs before invoking CTAP HMAC-secret. Native adapters must match WebAuthn semantics exactly, including user-verification behavior; raw HMAC-secret bytes, a public key or an assertion signature are not interchangeable wallet keys. Missing or inconsistent PRF is an unsupported capability, with no password, plaintext or server-secret fallback.

## App identity and community scope

Apple requires [Associated Domains with the webcredentials service](https://developer.apple.com/documentation/authenticationservices/supporting-passkeys) for native RP requests. Android requires Digital Asset Links and verification of the native application's signing-certificate origin. A reusable native application is not automatically authorized for arbitrary unrelated community RP domains. Deployment must supply the appropriate domain/app association.

Current cvld service/verifier configuration accepts one explicit origin. Supporting a browser plus native applications therefore needs an explicit allowed-origin model, or appropriately scoped service instances sharing the intended credential repository. Do not allow arbitrary caller origins or obtain portability by silently combining community accounts under a global identity. Domain separation still applies to member IDs, holder state, wallet keys and participation state.

## Implementation direction and acceptance gates

Keep the issuer, SQLite repositories and SimpleWebAuthn service on the server. Extract holder orchestration from its Node-specific import so the existing shared AnonCreds API can register a Node or React Native backend. For direct Swift/Kotlin integration, keep the same Rust/C object-and-JSON boundary. Align engine versions before claiming interoperability with UniFFI's current 0.2.0 build.

For a shared native wallet backend, reuse maintained [RustCrypto HKDF](https://github.com/RustCrypto/KDFs) and [AES-GCM](https://github.com/RustCrypto/AEADs) implementations behind a narrow byte interface. Both projects offer MIT/Apache-2.0 licensing. Preserve the existing HKDF labels, SHA-256 salts, UTF-8 JSON, 12-byte nonce, 128-bit tag, AAD and unpadded base64url envelope exactly. This is adapter work inside cvld, not a new cryptographic design or another repository.

| Required check | What it establishes |
|---|---|
| Native holder processes a Node-issued credential; Node verifies native account and anonymous-profile presentations | Actual schema, attribute encoding, hidden-member behavior and full 256-bit transcript nonce interoperability |
| Fixed synthetic wallet vectors agree across JavaScript and the native backend | PRF-input bytes, HKDF outputs, authenticated envelopes and component keys match; changed scope/AAD and corrupt envelopes fail |
| Native registration/assertion pass through the real cvld verifier | Correct RP, app origin, challenge, account binding and server-response sanitization; PRF output is absent from transmitted JSON |
| Real supported device/provider performs repeated unlock, browser/native comparison and extra-passkey rewrap | Actual PRF availability and preservation of the same wallet root; passkey synchronization alone is insufficient evidence |
| App restart, cancellation and storage-write failure | Atomic encrypted persistence, recoverable pending state and no plaintext fallback; anti-rollback and concurrent-device MLS ownership require separate design |
| Native app lifecycle and onion integration | Suspension/disconnect stops live profile serving and transport never uses a direct fallback; cross-target Rust checks cannot establish this |

`wallet.storageKey('cmsg')` must remain stable across passkey rewrapping. cfrm's stable anonymous participation identity likewise needs material derived from that persistent wallet root, not a per-passkey PRF value or rotating chat key. Losing the encrypted envelope or all working wrappers remains a recovery problem; OS keychain storage cannot silently redefine that lifetime contract.

This review used public documentation and source inspection only. No application, native dependency installation, simulator, device ceremony, account registration, service or paid action was performed. Device/provider capability and secure recovery are the material remaining blockers; existing libraries cover the cryptographic building blocks.
