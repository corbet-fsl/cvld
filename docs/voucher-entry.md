# Voucher-gated passkey entry

This document defines the backend-only entry boundary. It has no browser UI and
does not add account recovery. A relying application may expose these calls as
its own HTTP routes.

## Trust and identity

Initial registration requires all of `memberId`, `chatPublicKey`, and a cmsg
`DeviceAuthorization`. cvld verifies the exact `cmsg.device.v1` transcript with
the authorization's Ed25519 root key, checks the community, clock window and
device key, and derives the member ID from
`SHA-256(JSON.stringify(["cmsg.member.v1", communityId, rootPublicKey]))`.
The caller cannot choose a different member ID or chat key. A member that
already has a credential cannot use the initial-registration route again.

The trusted sponsor public key, community identifier, policy digest, admission
signing key, origin, RP ID, server clock and every capacity/lifetime are
constructor configuration. They are never accepted from a request. The
admission certificate has the existing `cvld.admission.v1` format and is
available in the successful registration result.

## Registration and sign-in API

`createEntryService` exposes:

* `beginRegistration({ memberId, chatPublicKey, authorization, voucher })`
  verifies the root-authorized device, rejects an existing member, and returns
  a single-use WebAuthn registration challenge. The voucher remains in bounded
  server memory until the matching precommit call. Registration cannot spend
  the voucher directly. The caller should persist the cmsg root/device
  envelope and any PRF wallet state before completing registration; cvld
  intentionally has no recovery path.
* `beginRegistrationPrecommit({ id, response })` verifies the registration
  response and moves the bounded pending entry to a wallet-confirmation state
  without spending the voucher. It returns a second UV-required assertion
  challenge restricted to the newly registered credential. The client must
  persist its PRF-unlocked cmsg state, then call `finishRegistration` with the
  returned `id` and `walletResponse`; only that finish call spends the voucher
  and creates the session.
* `finishRegistration({ id, walletResponse })` consumes only the wallet
  confirmation state, invokes the cvch bridge, and atomically claims the
  returned receipt and inserts the credential. Any failure leaves the voucher
  unspent; a successful transaction cannot be replayed after restart. SQLite
  writes the member's cmsg chat key and public device authorization in the same
  transaction as that credential.
* `beginAuthentication()` returns a discoverable, user-verification-required
  WebAuthn assertion challenge. `finishAuthentication({ id, response })`
  validates the origin and pinned RP ID, advances the durable counter, and
  creates a bounded server session.
* `rebindDevice({ sessionId, chatPublicKey, authorization })` requires that
  session, re-verifies the cmsg root authorization through the native bridge,
  checks the still-valid persisted voucher membership, updates the member
  device binding atomically, and returns a fresh signed admission certificate.

When configured with the existing cvld issuer and a trusted voucher attester,
`beginCredential({ sessionId })` returns a bounded offer challenge and public
issuer data. `issueCredential({ sessionId, id, request })` accepts the holder's
blinded credential request, checks its authenticated member binding and current
voucher membership, then creates the authoritative voucher attestation bound to
the exact offer/request digest and calls `issuer.issue`. The consumed voucher
receipt remains the durable membership anchor. Each bounded offer receives a
fresh deterministic issuance receipt derived from that anchor, the member and
the random offer ID, so `issuer.issueOnce` can reject replayed requests without
spending the signup voucher again. Failed or replayed requests cannot mint
another credential. Holder link secrets and raw holder secrets remain in the
client process.
Issuer challenge lifetime, pending capacity, credential lifetime, attester key
ID and attester signing key are explicit configuration. The issuer itself must
be configured with a voucher factor; policies requiring additional factors will
reject the voucher-only issuance.

`createEntryHandler` supplies thin Web `Request`/`Response` routes:

* `POST /auth/register/begin`
* `POST /auth/register/precommit`
* `POST /auth/register/finish`
* `POST /auth/login/begin`
* `POST /auth/login/finish`
* `POST /auth/logout`
* `POST /auth/rebind`
* `POST /auth/api-keys`
* `GET /auth/api-keys`
* `POST /auth/api-keys/revoke`
* `POST /credential/begin`
* `POST /credential/issue`
* `GET /auth/session`

When an API-key service is configured, bearer authentication is accepted only
with the explicitly configured `credentials:issue` scope on credential
operations and only after cvld rechecks that
the member still has valid voucher-backed membership. API-key management
routes require the passkey session cookie, so an API key cannot mint or revoke
another key. The handler exposes its trusted `authenticatedPrincipal(request,
scope)` resolver for an outer API layer; member IDs are never taken from JSON.
That resolver validates the request transport and origin before returning an
API-key principal; direct service callers must supply only this private,
already-validated principal object.

State-changing routes require an exact configured `Origin`. Responses do not
log or echo voucher material. HTTPS responses set Secure, HttpOnly,
SameSite=Strict cookies. HTTP is accepted only when
`allowInsecureLocalhost: true` and the request is localhost; this is an
explicit development exception.

## cvch bridge

The native helper is `native/voucher`, pinned to cvch commit
`dff30de1a72358208e27c0416fb8e7096e64ae04` and cmsg commit
`155a8e77c9b6f3a950104863dab50f9bbe483d33`. It accepts one bounded JSON
request on stdin and emits one bounded JSON response. The voucher operation is:

```json
{
  "op": "verify",
  "voucher": { "id": "…", "valid_until": 1800000100, "signature": "…" },
  "community_id": "community.example",
  "sponsor_public_key": "…",
  "member_id": "…",
  "now_secs": 1800000000
}
```

Success contains only `{ ok, receipt_id, member_binding, valid_until }`.
`receipt_id` and `member_binding` are the cvch outputs. Rejection is uniformly
`{"ok":false}`. The helper does not spend receipts and does not persist
membership; cvld's SQLite transaction does both together. The executable path,
argument vector, timeout and input/output caps must be explicit bridge config.

The second operation is `verify_device`, carrying the cmsg camelCase
`authorization`, `community_id`, `member_id`, `chat_public_key` and
`now_secs`. It returns only `{ "ok": true }` on success. It delegates root
signature, weak-key and member derivation checks to cmsg's
`verify_device_authorization` and `member_id_for_root`; the Node adapter only
checks bounded canonical input before invoking the bridge.

SQLite stores voucher spend rows permanently within the configured bounded
capacity. It never re-arms a receipt merely because the voucher expired. A
failed credential-capacity or membership insert does not claim the receipt.
