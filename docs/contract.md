# Eligibility boundary

## Required behavior

cvld owns passkey authentication and eligibility in one repository. A relying application receives a binary result for a holder-presented proof. It must not receive the underlying phone number, payment record, voucher sponsor identity or an identifier that allows those records to be looked up.

Phone, payment and voucher adapters are independently configurable. The combination policy must be explicit and versioned. cvld does not impose behavioral bans, maintain sanction histories or accept abuse reports. Application conduct and quotas belong to a separate rules layer.

A verification result is not a proof of one-human uniqueness or good character. A phone factor establishes possession subject to the selected gate's guarantees. Anti-replay and opaque duplicate-use prevention are distinct from sanctions.

## Proposed interfaces, not selected cryptography

Prefer verify(presentation, audience, challenge, policy) -> boolean to a public lookup of an arbitrary global user ID. The holder proves eligibility and control of an audience-scoped identity. A global shared ID would create an unnecessary cross-service correlation key.

Phone checking and payment processing are performed by independent providers; the application operator does not own or operate either service. cvld integrates provider-issued evidence. Provider selection must examine API responses, dashboards, callbacks, lookup handles and correlation paths, not only a boolean response schema. The selected protocol must state its protection against provider/verifier collusion. A self-operated checker or enclave is not the operating model.

Authentication proves control of a credential. Eligibility proves satisfaction of an admission rule. Both belong inside cvld; use established libraries and test their integration. Internal interfaces, keys and identifier domains should avoid unnecessary correlation. There is no separate clgn repository. Passkeys do not by themselves prove phone possession, payment, uniqueness or privacy-preserving eligibility.

A stable pseudonymous member identity inside one deployment must authenticate the same counterpart in forum and private chat. Registration, eligibility and chat-key certification must bind to that account; one credential must not silently authorize unlimited new member identities. Additional passkeys belong to the same authenticated account. A stable in-community identity does not authorize an operator to collect the private contact graph.

Client-facing functionality must support future native Android/iOS integration. The server may use a server runtime; holder and local-key interfaces must have a portable boundary and verified platform support.

## Data boundaries

| Location | Candidate minimum state | Forbidden application disclosure |
|---|---|---|
| External factor gate | Provider-required factor records; protected opaque duplicate-use state | Raw factors, lookup handles, receipts or callback records tied to application identity |
| Holder | Credential secret and private factor credentials | Export of private credentials or local-storage keys to operator |
| Eligibility verifier | Issuer public keys, explicit policy, bounded replay state where needed | Phone/payment details, private conversation identities, sanction history |

Exact retention and secret custody require protocol selection. No ordinary hash of a phone number is an anonymity guarantee. Small input spaces permit enumeration. Blind issuance alone does not prove that the blinded value corresponds to the verified phone or that the final submitted credential was correctly derived.

## Tests before implementation

These are acceptance-test specifications, not executed test results. The first implementation must demonstrate a failing test before the corresponding behavior is added.

1. Authentic holder-bound evidence satisfying the selected policy succeeds.
2. A forged issuer, altered factor claim or unsupported proof fails closed.
3. Changing the audience, challenge or bound holder identity invalidates a presentation.
4. An expired proof fails when expiry is required by the selected policy; expiry is not a ban.
5. Combining factors belonging to different holders cannot satisfy a multi-factor policy.
6. Concurrent attempts to spend one single-use voucher or claim one protected duplicate-use slot cannot both succeed.
7. An invented final anchor, or a valid proof for a different verified phone, cannot bypass the gate.
8. Disabling a factor or changing the policy follows explicit policy-version semantics; no implicit bypass appears.
9. Failure paths, logs and telemetry contain no raw factor, provider lookup identifier or holder secret.
10. Repeated eligible presentations use the unlinkability properties promised by the selected protocol; a stable identifier must not silently replace them.
11. Replay retention expires according to the proof lifetime without opening a valid replay window.
12. Behavioral standing changes in a relying application do not create cvld bans or revocation records.

Unit tests can verify boundary behavior and arithmetic. Cryptographic unlinkability requires an appropriate security construction and review; passing tests over mocked adapters does not prove it. Packet-level and concurrency tests are also required for deployment claims.

## Open decisions

- Compatible independent phone and payment providers, including their exact evidence interface and correlation limits.
- Credential lifetime, renewal and phone-number recycling.
- Exact credential scheme, language and maintained upstream libraries.
- Passkey recovery and client-held key portability.
- Duplicate-use scope and accepted limits on multiple numbers or vouchers.
