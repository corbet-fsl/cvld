# cvld

The permanent door of the cmtymeet trust stack. One Rust library and binary,
FSL-1.1-ALv2. The JavaScript/AnonCreds prototype is preserved at annotated tag
`js-prototype-0.1.0-alpha.0`. This package is not published to any registry.

The door composes the global `cglb` and community `cmty` facades. Separate
processes and databases preserve their information boundary. The API registry
owns actions, roles and check/record classification; HTTP, OpenAPI, MCP and CLI
are projections of that registry.

## Dependency choices

Surveyed crates.io, official documentation and GitHub on 2026-09-30:

| Dependency | Why |
|---|---|
| [axum](https://github.com/tokio-rs/axum) 0.8 | Maintained Tokio HTTP routing and bounded JSON extraction. |
| [tower-http](https://github.com/tower-rs/tower-http) 0.6 | Standard CORS handling with an exact host/origin allow-list; shares the existing HTTP middleware dependency. |
| [utoipa](https://github.com/juhaku/utoipa) 6 | Rust request/response schemas and OpenAPI 3.1. |
| [rmcp](https://github.com/modelcontextprotocol/rust-sdk) 3.5 | Official Rust MCP SDK; reuse protocol and transport handling. |
| [clap](https://github.com/clap-rs/clap) 4.6 | Build subcommands directly from action metadata. |
| [openapi-typescript](https://github.com/openapi-ts/openapi-typescript) 7.13 | Generate the TypeScript interface from the emitted OpenAPI. |
| [cglb](https://github.com/corbet-libs/cglb) | Own global uniqueness, gate execution, suspension and blind issuance. |
| [cmty](https://github.com/corbet-libs/cmty) | Compose membership, gates and policy without copying their domain logic. |
| [ed25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek) 2.2 | Parse the configured public sponsor key for cgts; signing and verification stay in the facades and leaves. |
| [ckyh](https://github.com/corbet-foss/ckyh) | UV-required wallet/operator WebAuthn; no new passkey implementation. |
| [subtle](https://docs.rs/subtle/latest/subtle/trait.ConstantTimeEq.html) 2.6 | Compare bootstrap capability contents without ordinary string-comparison timing; already shared by cryptographic dependencies. |
| [cthl](https://github.com/corbet-foss/cthl) | Maintained governor-backed throttling with bounded memory. |

Storage and cryptography remain in the existing crlt, cpsd and csgn leaves.
No ORM, second authorization engine or direct cryptographic implementation is
needed. Configuration is supplied in files; the service never searches for
credentials. Rust compilation and tests run in GitHub Actions only.

## Run and call the door

Build and validate through GitHub Actions. Supply explicit configuration and
separate service databases; [the global example](examples/global.json) contains
paths and synthetic identifiers, not keys or credentials.
The database records its service identity at initialization and refuses a later
configuration that assigns it to another community.

```sh
cvld serve global --config ./global.json
cvld openapi
cvld --url https://wallet.example.test --host wallet.example.test global_public
cvld --url https://wallet.example.test --host wallet.example.test \
  --session-file ./wallet.session passport_challenge
cvld --url https://wallet.example.test --host wallet.example.test \
  --session-file ./wallet.session mcp
```

CLI action input is `--request '<JSON>'`. MCP uses the official SDK's stdio
transport and the same HTTP client. Both require HTTPS except for loopback
integration tests; neither follows redirects. Session files contain only the
opaque bearer token. The TypeScript wrapper in `clients/ts/index.ts` uses the
committed generated types with `openapi-fetch`.

For a global service, provision a 32-byte csgn signing seed, a cpsd issuer secret
in its leaf wire format, a 32-byte uniqueness key, a COSE-signed cglb policy,
and that policy authority's public key ring. The supplied operator UUID and
random initial registration capability (32–1024 bytes) select the root account; the caller cannot
request a role. Registering a passkey requires a real WebAuthn ceremony with
user verification. No key generation, credential discovery or deployment runs
as a side effect of starting the door.
Choose the passport cohort's common expiry at a UTC-day boundary, as required
by the community gate facade. Global status publication uses whole UTC days
and a configured lifetime of at least two days. Each blind issuance challenge
is bound to the verified session with an independent random identifier; bearer
tokens are never written into issuance storage. Discoverable sign-in starts with
`login_discoverable_begin({})`, so a restored device needs no account identifier
or credential list. Keyhole verifies the authenticator's handle and selected key
before the existing login completion returns an exact-key session. The older
identified sign-in still accepts the account UUID and credential ID.

`development-gate` is an opt-in Cargo feature for development builds. Enabling
it in a release build is a compilation error, including releases with debug
assertions enabled. Production builds and their
generated clients omit the synthetic gate.

## Community process and trust consumers

```sh
cvld serve community --config ./community.json
cvld --url https://api.example.cmeet.me --host api.example.cmeet.me \
  --session-file ./member.session lobby
cvld --url https://api.admin.example.cmeet.me --host api.admin.example.cmeet.me \
  --session-file ./admin.session setting_set \
  --request '{"key":"quota","value":5,"inherit":false,"effective_at":1800000001}'
```

Each community process opens its own database and signer. Supply its canonical
slug, domain, rulebook, schema, voucher verification key, operator bootstrap
capabilities and the global service's authenticated **public** material. It never
opens a global database, issuer secret or uniqueness key. The global process
never opens a community database or accepts community domain actions.

Member calls use `api.<community>.<domain>`, administrators use
`api.admin.<community>.<domain>`, and root uses `api.admin.root.<domain>`. Each listener
serves one configured backend. Sessions belong to that process and exact host;
operators authenticate directly, without cfrm. A TLS ingress must direct each
operator request to its selected backend and preserve the exact Host header.
This repository performs no ingress configuration or deployment.

A holder fetches a signed presentation challenge from the intended community,
authenticates its origin and key ring, and uses cpsd to present the blind passport.
The first presentation starts a community-local WebAuthn registration. The
pseudonym becomes the member ID; the global wallet identity never enters that
community. A fresh presentation is required at credential issuance. The lobby
reports current enrolment, missing requirements, gate steps and no-return
warnings. It does not persist a visit or change membership merely because it
was read.

Sponsors create member-bound cvch vouchers off band. The voucher endpoint
passes their wire format to cgts. Pin values and salts remain on the device;
only the versioned, context-bound cpns digest enters cmbr. Policy, enrolment,
leases, lapse and credential lifetimes remain owned by the facades.

`trust_feed` returns the signed settings, current schema and schema-version
collection (with change classifications), public community directory,
revocations and a purpose-separated signed manifest containing the key ring,
schema version, policy epoch and durable revision. `trust_changes` performs a
bounded long poll against that public revision. cfrm pulls at startup and after
an announcement, verifies COSE and enforces revision/epoch floors locally.
Neither call accepts a member identifier. No member lookup is required at runtime.

Communities re-read the explicitly configured public global status before
presentation and issuance, and during maintenance. Valid COSE status can extend
freshness without restarting. Public epoch/revision floors persist across
restart, so replaying an older signed file fails closed. Installing a different
issuer key requires explicit configuration and restart.

A live community session can use `passkey_add` with `step: "begin"` and then
`step: "finish"` to register another UV-required passkey for the same membership.
The ceremony is bound to that session and expires after five minutes. Removing
a key through `passkey_revoke` immediately invalidates its sessions; other
passkeys retain access. There is no manual approval or recovery identity.
Removing the last passkey permanently releases membership under NO RETURN.

## Current limits

Production global gate providers are not configured by this door yet; the only
interactive global gate adapter in this build is the development feature. The
community voucher gate is real and requires a configured sponsor public key.
Legal-order/self-ban authority integration remains unconfigured. The mandatory legal veto still runs on every community gate check.

Pin changes use cmbr's sealed cblc interface and remain disabled in the facade
integration. Initial v2 pins and reads work. Credentials
require device signing keys bound to a current live passkey by `device_authorize`.
The issuer reads those bindings independently while holding the member lease;
requested public keys cannot authorize themselves. Removing the associated
passkey immediately removes its authority. Full device pairing and restored Keys
authority remain integration obligations. Schema changes currently advance the
epoch immediately; archived definitions do not authorize grandfathering.

The optional remote Turso test needs an explicitly supplied disposable database.
Public CI uses local libSQL and synthetic credentials only. TLS ingress, operational
public-key distribution and deployment are outside this repository's test run.
