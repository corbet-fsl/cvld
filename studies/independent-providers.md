# Independent verification providers

Research snapshot: 2026-09-08. These are candidates, not adopted providers. No signup, SMS, payment or external contact was performed. Phone checking and payment processing are independently operated services; cvld must not receive raw identity or an operator-accessible lookup handle for it.

| Candidate | Documented interface | Fit and unresolved evidence |
|---|---|---|
| [humanID](https://docs.human-id.org/web-sdk-integration-guide) | Hosted phone login; server exchange returns an application-specific pseudonymous ID | Closest simple external checker. It is not a documented anonymous-credential issuer. Full production dashboard/API lookup access, session binding and repeat-registration lifecycle remain unverified. |
| [Human.tech / Holonym](https://docs.passport.human.tech/building-with-passport/individual-verifications/api-reference) | Phone credential/uniqueness proofs with wallet-address verification and expiry | Existing privacy-credential machinery, but public wallet linkage and supported application-scoped off-chain integration need scrutiny. No compatible cvld issuer interface is established. |
| [Taler Operations](https://www.taler-ops.ch/en/merchants.html) | Externally operated fiat digital cash and hosted merchant infrastructure | Stronger payment-privacy alignment than ordinary card checkout; current geographical limits, hosted blind-pass support, credential binding and transaction metadata remain unresolved. |

A hosted card form or SMS SDK alone does not meet the boundary when the application operator can inspect payer/phone records through its service account. cvld consumes externally checked evidence; an internal mock gate cannot establish that a compatible provider exists.

## humanID

The hosted Web SDK requests a login URL, then exchanges a returned token server-to-server. The documented result contains an app-specific ID and country metadata, not a phone number. This supports pseudonymous application recognition, not necessarily unlinkability from the provider's authentication session. Do not forward unneeded country data or exchange tokens into chat identity.

The [main integration guide](https://docs.human-id.org/web-sdk-integration-guide) says web integration requires provider setup; the [example guide](https://docs.human-id.org/web-sdk-integration-guide/example-web-sdk-integration) refers to console setup. Current provisioning must be verified. Documented callback examples do not establish end-to-end binding to a blinded cvld issuance request. [Provider data and pricing claims](https://www.human-internet.org/partner-with-us) are not a substitute for examining the actual API and operator dashboard.

## Human.tech

The standard phone-status API queries a wallet address. A true result alone does not prove that the presenter controls that wallet, and a reused wallet may link activity across applications. [Credential documentation](https://docs.id.human.tech/how-it-works/credentials) describes private phone fields and scope-related cryptographic machinery; compatible production scope, proof, renewal and recovery semantics still need executable validation. No government-ID or biometric requirement is selected by this research.

## Payment credentials

GNU Taler uses blind payments and documents [merchant tokens](https://docs.taler.net/core/api-merchant.html). Its [Paivana passes](https://docs.taler.net/taler-paivana-manual.html) are time-limited access credentials, not automatic recurring charges. The concrete Swiss provider currently lists CH IBAN/+41 prerequisites on its [service page](https://www.taler-ops.ch/en/index.html). Hosted token functionality, holder binding and replay handling must be confirmed before adopting an adapter. Merchant order/amount/time information remains distinct from payer identity and still deserves minimization.

## Acceptance work

- Authenticated provider success must bind to the correct issuance request and configured policy.
- Repeated verification, recovery or expiry must not silently reset the provider's promised uniqueness scope.
- Enumerate callback, API, dashboard, export and support lookup access; a filtered response is not inability to know.
- Reject forged browser success and replay/concurrent redemption.
- Verify provider availability, exact costs and allowed integrations before any live use. No real-money spending is authorized.

The current cvld cryptographic tests use synthetic signed facts. They prove tested integration behavior, not provider independence, real-world uniqueness or deployment anonymity.
