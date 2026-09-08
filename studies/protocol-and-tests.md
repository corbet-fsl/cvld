# cvld: verifier boundary and adversarial test plan

Research checked 2026-09-08. No implementation, provider, protocol suite or expiry policy is selected. These are acceptance specifications; no implementation tests have run.

## Recommended boundary

`cvld` means eligibility, not social standing and not an identity directory. A relying component supplies a policy, a fresh challenge and a bounded presentation. It receives yes/no about the presenter meeting that policy. Prefer local public-key verification rather than a central `GET /users/{globalId}/valid` call for each action.

A stable global user ID would join forum, messaging, login and issuance observations. Make any persistent identifier scoped to its purpose. Whether cvld needs a stable verifier-specific pseudonym at all depends on whether admission is a reusable membership credential or anonymous consumable entry permits. Deriving scoped identifiers from a hidden credential secret and proving their binding is a cryptographic requirement, not a feature supplied automatically by every anonymous-credential library.

cvld owns passkey authentication and eligibility. Distinguish these internal protocol roles without introducing a separate login repository:

| Role | Input/knowledge | Output | State |
|---|---|---|---|
| External attester adapter | Phone possession, successful payment, or voucher evidence | Authenticated permission to issue a credential, bound to its issuance request | Issuance/deduplication and provider-required records, isolated from community IDs |
| Anonymous credential issuer | Authenticated attestation and blinded holder request | Credential/proof material | Keys/configuration; bounded anti-replay/issuance state |
| Holder wallet | Credential secret, issued proofs, local identity keys | Fresh eligibility presentations | Encrypted local secrets and credential state |
| cvld verifier | Proof, policy, challenge, accepted issuer keys | Boolean eligibility | Trusted keys/policy; replay state when protocol requires it |
| Internal passkey/wallet module | Passkey assertion/PRF locally; RP stores verification material if server login exists | Unlocked wallet and/or authenticated session | Passkey public verification material; no SMS/payment data |

If an adapter runs in the operator's ordinary process and receives raw phone numbers or merchant callbacks, the operator can know those details. Returning only a boolean to another function does not change that. The operating model requires an independent external phone/payment provider. A self-operated protected attester is not the selected architecture. Hosted payment UI does not by itself hide merchant dashboard data; provider API and account access must be examined.

## Existing building blocks

| Candidate | Useful part | Important limit | License |
|---|---|---|---|
| [AnonCreds v1 / anoncreds-rs](https://github.com/anoncreds/anoncreds-rs) | Rust issuer, holder and verifier; hidden holder secret; selective disclosure/predicates | Evaluate proof size, browser distribution and linking to an application session. Do not assume built-in domain pseudonyms. | Apache-2.0 |
| [Cloudflare privacypass-ts](https://github.com/cloudflare/privacypass-ts) | Privacy Pass issuance; blind-RSA public verification and VOPRF private verification; batch issuance | Useful for unlinkable consumable permits. Standard bearer tokens do not establish one stable member or prevent voluntary token transfer. Metadata-token verification has a browser limitation documented upstream. | Apache-2.0 |
| [Cloudflare pat-go](https://github.com/cloudflare/pat-go) | Basic and rate-limited Privacy Pass protocol reference/test vectors | Upstream explicitly describes experimental/interop use and says not production. | BSD-3-Clause |
| [facebook/voprf](https://github.com/facebook/voprf) | Rust RFC 9497 implementation | A primitive only: neither SMS binding nor deduplication attestations are included. | MIT OR Apache-2.0 |
| [Signal libsignal / zkcredential / zkgroup](https://github.com/signalapp/libsignal) | Production-used anonymous-credential machinery and research precedent | Signal-specific integration; external use unsupported; APIs may change. Inspect component and transitive license obligations before composing. | Repository [AGPLv3](https://github.com/signalapp/libsignal/blob/main/LICENSE) |
| [webauthn-rs](https://github.com/kanidm/webauthn-rs) / [SimpleWebAuthn](https://github.com/MasterKale/SimpleWebAuthn) | Established WebAuthn server verification | Authentication does not establish phone uniqueness, humanity, or eligibility. | MPL-2.0 / MIT |

Suggested first comparison: AnonCreds for reusable holder credentials versus Privacy Pass for consumable entry permits. These are alternative models, not interchangeable packages. Select only after resolving continuity and reuse semantics.

[AnonCreds specification](https://anoncreds.github.io/anoncreds-spec/) supports blind binding to a holder's link secret and proving multiple credentials use that same secret. Revocation is optional. It does not stop a holder creating other secrets; verifiers must enforce required common-secret binding. A copied credential without its holder secret must fail. Voluntary sharing of the complete secret remains a separate problem; do not promise one-person nontransferability.

[Privacy Pass architecture, RFC 9576](https://www.rfc-editor.org/rfc/rfc9576.html) separates attester, issuer, origin and client. Blind issuance can unlink redemption tokens from issuance transcripts. IPs, timestamps, issuer/key choice, and small anonymity sets can reconnect those contexts. The attestation procedure itself remains deployment-specific. Cryptographic unlinkability is consequently one layer of the design, not a claim that network observations disappear.

## Uniqueness and validity

A system cannot reliably remember that one phone has already obtained a credential after forgetting every distinguishable trace of that fact. Options remain open:

1. Long-lived opaque per-phone deduplication entry: persistent gate state, strong continuity for that phone, number-recycling/recovery policy needed.
2. Epoch-limited deduplication: erase old state after the maximum applicable credential/replay lifetime; the same number can return in a new epoch. Consequences for quota farming must be handled in cfrm.
3. Delegate uniqueness entirely to an attester that retains its own records: cvld learns no phone mapping, but the system trusts the attester's enforcement and privacy.

These cannot assert one unique human. Separate payment and phone credentials also do not establish one unique human unless linked with a deliberate policy. If gates are OR alternatives, multiple vouchers or payments may admit multiple credentials; decide whether that is accepted economic friction.

An opaque phone hash is enumerable. [RFC 9497](https://www.rfc-editor.org/rfc/rfc9497.html) VOPRF protects the client's input from the evaluator, and proves evaluation used the expected server key. It does not prove that the client used its SMS-verified phone, or that a submitted final anchor is the correct finalized output. Both bindings need authenticated end-to-end treatment. A party holding the PRF key can evaluate guessed numbers; key custody and access limits matter.

No bans or per-person revocation list belongs in cvld. Expiry is separate: proof says a condition held for a defined interval. Never-expiring proofs can outlive phone possession, monthly payment and lost/stolen credentials. Short validity bounds that stale interval without individual bans. A payment reversal either waits for expiry or requires a different agreed validity mechanism. Loss recovery and system-wide compromised issuer-key retirement need their own explicit policies.

## Passkeys: separate responsibilities

Keep authentication and eligibility distinct internally within the cvld repository; no separate login repository is planned. The risks of mixing are correlating every login with gate issuance, broadening compromise impact, making recovery alter eligibility, and coupling RP/domain changes to credentials. Separate services with one shared identifier/database would still correlate them.

[WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/) supplies RP-scoped authentication credentials; the RP learns its credential ID and public key. The PRF extension can support a local wrapping key for an independently random wallet/database key. PRF output and unwrapped storage keys must stay client-side. PRF support and device migration require actual supported-device tests. No PRF support must never silently create plaintext storage. An ordinary WebAuthn signature is not anonymous credential presentation and not a bulk encryption key.

## First honest TDD slice

Build a verifier boundary against one real upstream anonymous-credential implementation using synthetic issuer/holder fixtures. Write failing adversarial tests first, then implement the thin integration. This proves the integration's defined behavior, not the complete deployment privacy objective. Keep raw provider adapters and their trust assumptions outside the first slice. Do not ship a mock adapter as a verified phone/payment service.

| Test first | Required observation |
|---|---|
| A valid credential and proof for the chosen policy/challenge | Accept exactly once when the selected protocol has one-use redemption semantics |
| Valid signature but issuer key absent from allowlist | Reject; attacker cannot supply its own trusted key |
| One bit changed in proof, claimed factor, expiry or policy binding | Reject; malformed/oversized encodings are bounded and fail closed |
| Proof made for challenge A presented for challenge B | Reject; retained challenge context binds the exact intended action/session |
| Proof for audience A/session public key A replayed for B | Reject; session/audience binding uses the selected proof protocol's supported transcript/context mechanism |
| Same proof or redemption submitted concurrently twice | At most one acceptance when one-use; atomic replay check survives restart through the required retention interval |
| Two fresh presentations of one reusable credential | Both can be valid in separate permitted sessions; freshness is not a ban on legitimate re-presentation |
| Payment credential from holder A combined with phone credential from holder B under an AND policy | Reject unless policy explicitly permits pooled credentials |
| OR policy changed to AND or factor disabled under new policy version | Old proof must not bypass current semantics; lifecycle/grandfathering branch selected explicitly |
| Clock at just-before, at and after expiry; unexpected skew | Follow one documented validity interval and skew policy; no accidental indefinite acceptance |
| Provider success event reused, forged or bound to a different issuance request | No additional credential; network retry is idempotent, not new issuance |
| Two simultaneous first admissions for the same deduplication anchor | One new admission; no race to two credentials |
| Client supplies arbitrary anchor or substitutes a different blinded phone input | Reject before issuing; initially mark cryptographic/provider integration unresolved, never pass using client assertions |
| Accepted proof, error and telemetry envelopes inspected | No phone, payment/customer reference, raw voucher, credential secret or cross-service global ID; debugging paths follow the same boundary |
| Verifier process has no issuer/attester network access during presentation verification | Local eligibility verification still succeeds with applicable public verifier design |
| Unsupported PRF or altered encrypted wallet blob | Fail closed; no plaintext fallback or server recovery key |

An output/schema test catches accidental fields but does not prove a malicious operator cannot log memory or correlate traffic. End-to-end privacy requires separate deployment tests (network captures, logging/configuration audit, dependency review) and independent cryptographic review. No pass/fail unit test establishes anonymity against all observers.

## Engineering choices to resolve through implementation and tests

- Is a trusted external gate allowed to see phone/payment details while the community operator cannot link those records to a member, or must even gate execution be inaccessible to the operator?
- Does cvld certify a one-time completed gate, or a currently valid condition that expires? Are lost credentials recoverable, replaceable, or intentionally unrecoverable?
- Should cvld know a stable pseudonymous account, or should it verify a holder's proof without recognizing repeat visits? cfrm rules continuity can be separate.
- Is one phone one credential the required uniqueness scope, or must phone/payment/voucher routes converge on one wallet? What transfer/re-entry tolerance is acceptable?

No provider integration or dependency implementation has been tested.

## Evidence boundary

| Evidence | Establishes | Does not establish |
|---|---|---|
| Upstream proof vectors plus adversarial verifier tests | Correct handling of tested valid/invalid protocol inputs | New protocol security or SMS/payment binding |
| Adapter event authentication/replay tests | Accepted event came from the configured signer and cannot be re-used under tested state transitions | The signer actually checked the phone/payment, or cannot identify the person |
| API/log schema tests | Tested outputs omit forbidden fields | Malicious logging, memory access or infrastructure retention is impossible |
| Public code and reproducible artifact checks | Inspectable implementation and build correspondence | An operator deploys that build or never changes its configuration |
| Anonymous transport integration tests | Tested paths meet the selected routing requirement without direct fallback | Universal protection against traffic correlation or all colluding observers |

cfrm/cmsg must hide peers' IP addresses and have no direct transport fallback. cvld issuance/redemption transport also requires an explicit threat model if those contexts must not be correlated; a private content transport does not automatically protect gate traffic.
