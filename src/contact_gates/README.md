# Production contact operations

This host module composes `cphn`, `cmbx`, `cfbk` and `cgbl`. It does not verify
invented flags or accept a serialized verified fact. The supported integration
is Twilio Verify production phone control (SMS, WhatsApp, call) and mailbox
control through the service's configured email integration. An adapter's presence
does not enable it. Sandbox execution is unsupported by these leaf adapters.
Control of a phone/mailbox is the actual guarantee; it is not personhood.

The caller supplies configured option IDs, the global policy's provider IDs,
account/service IDs, explicit credential files, separate stable identity-key
files, required ceremony duration, capacity, operator budget/attempt caps and
all-in begin/check tariffs. Member-supplied limits can only lower the operator
caps. Keys must remain stable
across enabled options of the same identity domain. The module neither discovers
accounts or credentials nor obtains prices from a network endpoint. Tariff scope
and provenance describe an operator-vouched bound for the actual account,
service, channel, request conditions, failed attempts and provider-managed
delivery changes. They must cover the destinations offered by the caller. No
current vendor price, exchange rate or free sandbox claim is shipped here.
Each tariff requires typed `AllAcceptedRequests` coverage. Descriptive scope
does not implement geographic/account eligibility: partial tariffs are refused,
and narrower routing support is not claimed.

The asynchronous constructor atomically installs/checks nonsecret comparison-key
commitments before serving any operation. The existing maintained cgbl HMAC
engine binds the exact key, comparison scope and fixed leaf identity domain;
only temporary key copies are wiped by the helper. Changed keys/scopes refuse
reopen, while replaceable provider credentials do not change those commitments.
Migration 9 adds the caller-owned binding table after the operational ledger.
When older cphn/cmbx gate or comparison-reservation records exist without a key
commitment, startup refuses with migration required. It does not bless whichever
key file happens to be supplied. A safe migration requires independently
establishing the original scope/key provenance; this implementation provides no
automatic acceptance, erasure or administrative bypass for that case.

Amounts preserve integer atoms, denomination and scale. Unknown, mismatched or
expired pricing cannot authorize dispatch. The public preview displays the
actual eligible cfbk ordering and exclusions, costs and provenance. Every
potentially billable check gets a separate request-bound preview. A caller must
show that preview before explicit dispatch consent. The returned authorization
identifies that exact preparation; an earlier begin/check consent cannot execute
a later check preparation.

The door first obtains read-only `authorize_contact` through its actual global
facade: enabled gate/provider, live policy and an unblocked subject, with a clock
sample after the database read. It derives each `ContactBinding`
for the independently authenticated subject, check, configured gate and
provider. `prepare_begin` receives those bindings plus `Owner` and explicit
`Constraints`, retaining the independently chosen original `CheckId` in RAM.
The fact lifetime comes from the authenticated policy cohort; callers cannot
select it through the member API. Pending is capped by the actual session and
the configured host ceremony duration. Caller-selected options must all establish the same phone or
mailbox control domain. Cheapest ordering compares their actual compatible
bounds; it does not assume one channel is cheaper. `execute` uses real leaf
preparation, permits, HTTP parsing and projection. Pending stops fallback.
`prepare_check` consumes the RAM-held leaf session and bounded OTP, then creates
a new preview. Before each potentially billable dispatch, including after
awaited durable reservation, the door rechecks every possibly attempted policy
pair and reauthenticates the exact live subject/session. It retains the latest
policy/reauthentication observation floor in the single-use leaf seal rather
than falling back to an older ceremony time. A successful execution retains a real typed gate. The door uses
`gate` and `input` with `cgbl::run_gate`; retries verify the same fact without
provider I/O. The existing global facade alone owns its uniqueness claim.

Only definitive `NotDispatched` enables cfbk to select the next authorized option
under the same budget and attempt cap. Refusal stops. Non-success HTTP,
malformed/correlated-invalid replies, transport errors, cancellation and late
completion cannot reset money exposure or silently send another code. Exposure
is the conservative sum of reserved bounds, not an invented actual charge.
Twilio Verify does not return a reliable final fee in this integration, so this
module does not reclaim an attempt's reservation or offer a fabricated fee
reconciliation. A fresh operation requires fresh explicit caller consent.

`state::SCHEMA` belongs in the caller's global migration sequence. The host's
libSQL transaction atomically fixes the ceremony's whole budget, denomination,
scale, attempt cap and deadline, rejects reused operation IDs and reserves each
attempt. An async reservation produces a move-only RAM seal checked once by the
leaf against exact terms and a fresh clock. Rows contain only opaque ceremony,
operation and keyed request bindings, bounds, deadlines and outcome categories.
Their initial outcome is uncertain. No destination, OTP, provider body,
credential, subject or login/session data is stored. Operational reservations
remain after restart; losing RAM sessions does not authorize a resend.

Fresh host observations after transaction acquisition/commit and immediately
before transport suppress late I/O. The existing database interface does not
execute a trusted live-clock predicate inside its commit, so this is not an
engine-atomic expiry guarantee. A reservation committed while time advances
remains conservatively retained even when the transport refuses to send. The
transport limits each reqwest operation with a monotonic timeout, requires the
fixed Twilio HTTPS route, disables redirects, retries and proxy discovery, and
bounds response bodies to 64 KiB. A wall-clock check before reqwest receives the
request cannot prove when a remote provider processes it.

`simulation::simulate` is a separate local function. It takes explicit dummy
inputs, hypothetical costs and outcomes and exercises the real leaf
normalization/transformation and cfbk planner without credentials, transport or
database access. Its response is marked simulated and contains no production
operation or gate. A simulated fact cannot be promoted to `Gate`.

Preparations, canonical destinations, pending provider references, OTP bodies
and facts stay in bounded RAM. Expiry/capacity checks remove transient sessions.
Default projections omit comparison bytes and upstream bodies; dependency
errors are reduced to fixed categories. Maintained HTTP/parsing libraries may
make transient copies that this application cannot guarantee to erase. Swap,
core dumps and process-memory inspection are controlled by the host.

The registry exposes plan, check-preview, explicit execute, status, typed accept
and simulation consistently through HTTP, CLI and MCP. The normal constructor
always selects strict `HttpTransport`. The explicit trusted-host constructor
accepts a type-erased `TrustedTransport` forwarding only original external HTTP
requests/responses; member JSON cannot select it or construct a verified fact.

Authored tests in `tests/contact_gates.rs` use actual libSQL, genuine leaf parsing,
signed global policies, blind passport issuance/presentation, real identity
deduplication and inert external HTTP. They cover budgets across begin/check,
durable concurrent reservations/reopen, stale consent, wrong owner/session,
phase preservation, fallback stops, cancellation, expiry and privacy. Real
signed-policy/block changes after durable reservation leave conservative
exposure and send no provider request. Key-binding contention, changed-key
reopen, provider credential replacement and populated legacy migrations use
actual libSQL and genuine leaf/gate records. Formatter
and whitespace checks have passed during implementation. Rust compilation,
test execution and coverage are pending; no live vendor or sandbox contract has
been executed. `tests/contact_routes.rs` adds actual production-mode registry
plan/execute/check/execute/accept and blind passport/presentation, replacing only
external HTTP with inert responses. It also covers configuration, policy and
operator cost refusals and local simulation. Independent review and required
execution/schema-generation evidence remain necessary before readiness claims.
