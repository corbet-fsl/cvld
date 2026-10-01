# cvld door contract

One FSL-1.1-ALv2 Rust package, library and binary. No registry publishing.
The previous JavaScript tree is preserved by the annotated
`js-prototype-0.1.0-alpha.0` tag. Domain state and decisions belong to cglb and
cmty; storage and cryptography remain in their leaves.

## Actions and transports

`src/api/mod.rs` is the action registry. Every action has a typed request and
response, exact allowed role, service scope and check/record classification.
The macro registers `/v1/<action>` POST routes. OpenAPI uses utoipa schemas;
clap and the official rmcp SDK project the same registry. Operational commands
`serve`, `openapi` and `mcp` are transport utilities, not extra domain actions.
MCP runs over local stdio and forwards to HTTP, preserving host and session
checks. It never receives a passkey private key. Requests and responses are JSON;
cryptographic leaf wire formats are opaque byte arrays.

An unknown action cannot execute. Inputs reject unknown envelope fields and
HTTP allocation is bounded. Errors are fixed categories, without leaf errors,
request data or identifiers. Checks create no member activity record; records
may alter permanent domain state. Authentication counter commits are records.
Pending ceremonies and bearer sessions are bounded, ephemeral and single-use
or expiring; restarting the process discards them.

## Global process

`cvld serve global --config <file>` owns one crlt database, cglb's issuer,
uniqueness key and durable csgn signer. Wallet authentication uses cpky at
`wallet.<domain>`. Root authentication uses a separate RP and namespace at
`api.root.<domain>`. Hosts match exactly; forwarded-host headers are ignored.
Only UV-verified passkeys create sessions. Each use rechecks its exact credential
for revocation. A member cannot request an operator role. Operator UUIDs and a
one-time initial registration capability are explicit service configuration.
Existing operator credentials prevent reuse of bootstrap across restart.

The global service calls cglb for uniqueness, gates, blind issuance, warning and
temporary suspension. It never receives a community identifier or pseudonym.
Public material contains only issuer keys, policy revision, epoch and common
expiry. The purpose-bound global status uses csgn SettingsSnapshot, with UTC-day
publication boundaries. A challenge binds to one UV-verified session; replay
and another session cannot use it. Cpsd owns durable issuance nonce storage. Private global revocations are not sent to communities. Cglb's current
revocation mechanism advances the passport cohort epoch; it is not an individual
zero-knowledge revocation accumulator. Global providers beyond the development
gate remain leaf integrations.

The `development-gate` Cargo feature enables the synthetic gate for development
builds. A release build with that feature fails compilation. Default release
schemas, routes, commands and tools omit it.

## Runtime privacy and configuration

No logging/tracing subscriber, request logger, member metrics or identifier labels
are installed. Every action passes cthl's bounded aggregate per-action throttle;
changing an IP, handle or session cannot bypass that quota. Failed checks fail
closed. A proxy must preserve these privacy properties and provide TLS.

Configuration and secret file paths are explicit. The service does not search for
operator credentials, use a secret store implicitly or provision a deployment.
It uses a generic HTTP User-Agent. No client credential is sent across redirects.
Database access is only through crlt; the pool defaults to one connection.
A single service-identity row binds the physical database to its configured
service and scope. Reusing a community database under another community name
is refused; this row contains no member information.
Maintenance prunes expired global challenges and refreshes signed public status.
An unsuccessful refresh leaves the old expiry in force rather than extending it.

## Verification

GitHub Actions runs stable Rust formatting, strict Clippy, real libSQL/WebAuthn/
blind-passport HTTP tests, CLI and official MCP-client process round trips,
surface parity, default release tests and a negative release-feature build.
OpenAPI and the TypeScript client are regenerated and compared with committed
output. No Cargo command runs on the workstation. The optional Turso test connects
only if both TURSO_URL and TURSO_TOKEN are nonempty; use a disposable database.

## Community process

`cvld serve community --config <file>` owns one database for one canonical
community and its own durable csgn signer. The immutable database identity
prevents assigning the same file to another community. There is no global
service handle, global member identifier, issuer secret or uniqueness key in
this backend. Global status and issuer keys arrive only as authenticated public
configuration. The global API refuses community actions before reading a body;
community listeners likewise refuse global actions.

Member authentication delegates to cmbr/cpky. The RP is the canonical
`<community>.<domain>` and allowed origins are that site and its member API.
Admin and root have separate RPs, stored credential namespaces and ephemeral
sessions. Public API host headers are exact; forwarded headers are ignored.
A session cannot cross hosts, communities or processes. The service validates
its exact live credential on each authenticated call. No caller chooses a role.

A community presentation challenge is single-use, server-held and short-lived.
The response carries cplc's signed cpsd request. A holder must authenticate the
intended community's origin/key ring before producing a presentation. First
registration consumes the presentation and binds a random community-local UUID
to its verified pseudonym through cmty. Registration never grants admission.
A fresh presentation is needed for credential issuance; proof bytes and global
gate disclosures are not persisted. Different communities receive different
pseudonyms, relying on cpsd's BBS/SyRA construction.

The lobby reports cmbr's enrolment state, cplc's current missing requirements,
cgts's gate steps, the canonical handle and mandatory no-return warnings. It
creates no visit record and does not lapse a member merely because a fresh
passport was not supplied to this read. Voucher verification and atomic
single-use storage belong to cgts/cvch. Handles use cmbr's cgrd/crgs operations.
Withdrawing a gate supplies a fresh passport and immediately reevaluates
admission through cmty; an absent required gate lapses the member.
Pins contain only a context-bound v2 digest; schema values and salts stay on
devices. A changed digest needs the owning facade's spent-token capability.

cmty owns admission, gate decisions and credential issuance through the three
facades. cplc reads authoritative membership facts from cmbr and holds its member
guard until signing completes. Probation and coarse leases come from membership;
request bodies cannot select established standing or a credential expiry.
Credentials contain the community pseudonym, handle, public device keys,
community gate metadata, pins, schema version and community policy epoch.
Global gate disclosures are excluded. The signer returns Ed25519 COSE bytes,
which verify using the published community key ring.

The door serializes composed writes and maintenance in its process. Deploy one
writer process per database. Every request uses one trusted operation timestamp;
this timestamp is transient and never a member activity record. A failed or
ambiguous operation returns a redacted error, never an earlier credential.
Retrying issuance needs a fresh presentation. Maintenance delegates pending
expiry, handle retention/release and challenge pruning to the facades.

## Administration and public trust feed

Community administrators may edit sparse community settings and validate or
publish schema changes. Root alone may edit platform values and force switches.
Both call these APIs directly. Setting resolution, null versus inheritance,
bounds, notice and prospective epochs remain crbk/cplc rules. Schema validation
and change classification remain cshm rules; no profile values are collected.

`trust_feed` serves five signed snapshots (settings, current schema, schema
versions and their cshm change classifications, public community directory,
revocations), the public key ring and a signed manifest.
The manifest's fixed `cplc.trust.v1` purpose separates it from flat settings;
it binds community, durable revision, effective epoch, key ring and schema
version. Each snapshot has its own revision and the same effective policy epoch.
Consumers authenticate the origin/ring, verify the protected COSE kind and scope,
and retain monotonic revision and epoch floors.

`trust_changes` accepts a public revision and returns an announcement immediately
when newer material exists, or after a bounded 25-second wait. cfrm pulls this
public material at startup and on announcements. No trust-feed request includes
a member ID; cfrm verifies credentials locally without runtime member queries.
An expired snapshot is never made fresh by a failed maintenance attempt.

## Action registry

Every name below is an HTTP POST, CLI subcommand and MCP tool with its request
and response described by the generated OpenAPI. `Public` requires a valid
service host; `Authenticated` means the session's exact host-selected role.

| Action | Role | Service | Effect |
|---|---|---|---|
| register_begin | Public | Both | Record |
| register_finish | Public | Both | Record |
| login_begin | Public | Both | Check |
| login_finish | Public | Both | Record |
| logout | Authenticated | Both | Check |
| global_public | Public | Global | Check |
| passport_challenge | Member | Global | Record |
| passport_issue | Member | Global | Record |
| global_warn | Root | Global | Record |
| global_suspend | Root | Global | Record |
| presentation_challenge | Public | Community | Record |
| lobby | Member | Community | Check |
| handle_available | Public | Community | Check |
| handle_reserve | Member | Community | Record |
| gate_voucher | Member | Community | Record |
| gate_withdraw | Member | Community | Record |
| credential_issue | Member | Community | Record |
| pin_set | Member | Community | Record |
| pin_get | Member | Community | Check |
| pin_change | Member | Community | Record |
| passkey_revoke | Member | Community | Record |
| setting_set | Admin | Community | Record |
| platform_set | Root | Community | Record |
| schema_check | Admin | Community | Check |
| schema_set | Admin | Community | Record |
| trust_feed | Public | Community | Check |
| trust_changes | Public | Community | Check |

The opt-in development build adds `development_gate` (Member, Global, Record).
No production route, CLI command, MCP tool or OpenAPI path contains it.

Community admission re-verifies the configured public global status on every
presentation start, first registration and credential attempt. The door retains
public epoch/revision floors in its community database; expired or rolled-back
metadata is refused, including after restart. cmty atomically refreshes policy
and its freshness deadline; changed metadata invalidates old challenges. Local
cleanup continues when global metadata expires. Issuer-key changes require an
explicit service restart; no global secret or account data enters this path.

## Current limits

Production global gate providers are not configured by this door yet; the only
interactive global gate adapter in this build is the development feature. The
community voucher gate is real and requires a configured sponsor public key.
Legal-order/self-ban authority integration remains unconfigured. The mandatory legal veto still runs on every community gate check.

Pin changes use cmbr's sealed cblc interface and remain disabled in the facade
integration. Initial v2 pins and reads work. Credentials
require caller-authorized public device keys; this door does not implement a
separate device-key attestation protocol. Schema changes currently advance the
epoch immediately; archived definitions do not authorize grandfathering.

The optional remote Turso test needs an explicitly supplied disposable database.
Public CI uses local libSQL and synthetic credentials only. TLS ingress, operational
public-key distribution and deployment are outside this repository's test run.

## Request admission and public read isolation

Aggregate action quotas and nonwaiting in-flight permits precede body allocation
or execution queues. The process admits at most 32 ordinary public requests,
32 protected requests and 16 long polls at a time. Overflow returns the fixed
throttled category. Body receipt has a ten-second deadline and a 256-KiB limit;
it holds no execution lock. After receipt, mutation serialization and a fresh
exact-credential check prevent a body or queue wait from extending an expired,
logged-out or revoked session. Maintenance uses the same mutation boundary.

Public global material and community trust feeds use immutable watch snapshots,
independent of private operation locks and member credentials. Only a completed
publication replaces the public snapshot. Ordinary enrolment, login and renewal
do not change its bytes. Public epoch updates still announce policy/revocation
changes; shared-machine CPU and network timing are not an anonymity guarantee.
All HTTP successes, failures and fallbacks carry `Cache-Control: no-store`.

Initial seals are refused for Free fields. cmty omits a formerly restricted
field's stored seal while that field is Free, permitting renewal after loosening.

The TypeScript and Rust clients accept HTTPS service origins and explicit HTTP
loopback only. The TypeScript fetch boundary refuses redirects and cross-origin
per-call overrides, disables ambient cookies, storage and referrer transmission.
CI checks full matching first-party Git pins in resolved metadata and dependency
declarations, including transitive dependencies. Workflow actions use immutable
upstream commits; the Rust compiler remains current stable.
Community startup and global-ring refresh reject any community signing key also
present in the authenticated global signing ring, including retained keys. The
startup check runs before storing the community signer.

## Additional passkeys

The `passkey_add` action has `begin` and `finish` phases in one registry entry,
shared by HTTP, OpenAPI, CLI, MCP and the generated TypeScript client. It requires
a live community-member session. The five-minute, single-use ceremony is bound
to that exact session; replacement, logout, expiry and authorizer revocation
invalidate it. cpky verifies user verification and atomically checks the old key
while inserting the new one; cmbr checks membership. The new key uses the same
community UUID and pseudonym. There is no manual approval or recovery identity.

Removing a passkey immediately removes its sessions and outstanding additions.
Members retain access through other passkeys. Losing every key permanently
releases membership under NO RETURN.
