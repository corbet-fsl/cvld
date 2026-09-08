# Executable credential and passkey boundary

cvld encapsulates authentication and anonymous eligibility in one repository. This first implementation uses genuine cryptography with synthetic external-gate facts. It is an integration experiment, not a deployed independent verification service.

## Implemented path

1. The holder creates its secret locally and constructs an AnonCreds blinded credential request.
2. Independently controlled gate adapters are expected to sign minimal attestations binding a factor, an opaque one-use receipt, a validity interval, a policy digest and that exact issuance request. Synthetic signers in `test/` implement this interface solely to exercise the protocol. No compatible real provider is integrated.
3. The cvld issuer verifies those signatures against configured attester keys, enforces the explicit any/all factor policy, atomically consumes receipts and signs a non-revocable AnonCreds credential. It never receives the holder secret or passkey record.
4. The holder processes the credential locally. A fresh proof demonstrates eligibility and validity through the verifier's challenge lifetime. Its serialized proof reveals the shared policy digest and omits the exact expiry value and gate receipts. The wallet validates the complete permitted disclosure request before generating a proof.
5. The verifier binds its proof nonce and passkey assertion to the same fresh challenge, audience, policy, passkey and expiry. Both cryptographic checks must succeed. Each challenge is consumed before asynchronous verification, including failed attempts. The result is a boolean.

The gate signature proves what its configured signer asserted. It does not prove the signer actually checked a phone, payment or uniqueness rule. A signer cannot redirect an already authenticated attestation to another blinded request. Provider-specific authentication, privacy, independence, custody and uniqueness guarantees remain separate integration work. There are no raw phone, payment callback or merchant-customer fields in this interface.

Passkey verification currently accepts trusted, previously registered WebAuthn public verification material. Test software authenticators produce real ES256 signatures. This does not implement browser enrollment, hardware attestation, PRF-backed wallet encryption, device migration or account recovery. The issuer and holder modules must execute in their respective trust domains; running the holder wallet inside the verifier service would violate the design.

## Dependencies and distribution

| Component | Pinned implementation | Role | License |
|---|---|---|---|
| Anonymous credentials | [AnonCreds Node 0.4.0](https://github.com/anoncreds/anoncreds-wrapper-javascript), native Rust 0.2.3 | Blind issuance, holder-secret binding, proofs and verification | Apache-2.0 |
| Passkey verification | [SimpleWebAuthn server 14.0.1](https://github.com/MasterKale/SimpleWebAuthn) | Existing WebAuthn assertion validation | MIT |
| Synthetic authenticator encoding | [tiny-cbor 0.3.6](https://github.com/LeviSchuck/tiny-cbor) | Test-only COSE public-key encoding | MIT |

The lockfile pins npm artifacts. CI disables dependency lifecycle scripts and installs the official Linux x64 AnonCreds native artifact only after checking the SHA-256 pinned in `scripts/install-native.js`. The FFI dependency's Linux x64 binary is already covered by its npm integrity entry. Native source reproducibility and independent binary auditing remain unverified. This slice supports Node 24 on Linux x64; it does not yet provide a browser holder.

Public CI uses a standard Ubuntu runner, synthetic keys/data, no application secrets, and no uploaded artifacts or caches. Standard runners are [free for public repositories](https://docs.github.com/en/billing/concepts/product-billing/github-actions). The package is private in its npm manifest and has not been published.

## State and limits

The receipt-store interface requires atomic all-or-nothing claims. Its included bounded memory implementation is for experiments: restart loses issuance replay history. Deployment requires durable external receipt storage with atomic transactions. It keeps opaque receipt consumption only, with no sanction or per-person revocation records. Claims currently precede credential signing: a signing failure or lost response can consume admission without delivering a credential. Durable idempotent issuance/retry transactions remain integration work. Expiry must retain each receipt until that attestation can no longer authorize issuance.

Pending verifier challenges are bounded and ephemeral. Restart forgets them, so old responses fail closed. Passkey counter updates occur on the trusted credential record in this process; persistence and synchronization across verifier instances are not implemented. Callers must not accept client-supplied public keys as already registered records.

Policy, clocks, factor combinations, credential lifetimes, challenge lifetimes, capacity limits, presentation limits, origin/RP ID and the user-verification requirement are explicit configuration. Expiring credentials are not bans. A credential must remain valid for an entire challenge, so one near expiry may require renewal or a shorter explicitly configured challenge. The prototype bounds numeric timestamps to the AnonCreds signed 32-bit predicate range.

No shared global member ID is issued. A relying community sees its passkey identity during login. Gate issuance does not receive that identity. This does not establish unlinkability against colluding gate/verifier network observers, IP/timing correlation, voluntary credential sharing, or a malicious deployment. A private holder secret alone does not prove unique humanity, and this slice does not provide an unlinkable stable uniqueness identifier for community rules. The explicit limitation experiment successfully uses one eligibility credential with two different passkeys. Sharing one fresh challenge proves possession of both inputs in that session; it does not establish one credential per account or prevent account multiplication.

Exact request-shape validation prevents substituting a hidden attribute into a revealed slot. It does not prevent a verifier from adaptively probing validity with different future challenge horizons. Success/failure can reveal expiry bounds. A trusted holder clock and approved challenge-time policy or shared expiry cohorts are required before claiming resistance to that attack. The serialization test is deliberately a narrower claim. Communities sharing an RP ID/passkey record can also correlate those login identities; audience binding alone is not cross-community identity unlinkability.

## Test evidence

- Initial red: commit `73961ae`, [run 34253627108](https://github.com/corbet-labs/cvld/actions/runs/34253627108), all 16 acceptance tests failed on the absent implementation.
- First real integration green: commit `df097e8`, [run 34254060753](https://github.com/corbet-labs/cvld/actions/runs/34254060753), 16 tests passed.
- Added adversarial red: commit `e31fde8`, [run 34254332279](https://github.com/corbet-labs/cvld/actions/runs/34254332279), 18 passed and two exposed receipt-retention and asynchronous input-substitution failures.

- Disclosure-request negative: commit `3d757b0`, [run 34254439974](https://github.com/corbet-labs/cvld/actions/runs/34254439974), 19 passed with the same two pre-fix failures.

- Integrity and issuance fixes green: commit `5a4b516`, [run 34254680566](https://github.com/corbet-labs/cvld/actions/runs/34254680566), 21 tests passed, including native integrity installation and package dry-run.
- Independent-review regressions red: commit `814b03e`, [run 34255027602](https://github.com/corbet-labs/cvld/actions/runs/34255027602), 21 passed; two tests demonstrated passkey-counter rollback and combined attribute/predicate disclosure substitution before their fixes.

The final suite additionally includes the explicit multiple-passkey limitation experiment. Its final result is reported in the repository Actions run for the fixing commit. Tests exercise signatures, proof verification and observable boundary behavior. They do not prove a deployment cannot observe identities or traffic. No live phone/payment provider, browser passkey or production database was exercised.
