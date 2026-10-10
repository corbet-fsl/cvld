# Configured paid access

This host integration executes one explicitly configured x402 v2 settlement
through `crpt` and the general `cpmt` executor. The caller supplies the actual
offer, provider account/HTTPS endpoint, authentication headers when required,
access level and interval, stable journal key, resource limits and sourced
all-in service-fee bound. The fee bound must cover discovery, verification,
settlement and failures; principal remains distinct. There are no default
prices, exchange rates, access levels, enabled providers or settlement retries.
Verification alone never establishes this settlement-based access condition.

Set the optional community `payments` configuration to a `PaymentConfig`; when
absent, production payment actions refuse. Its `id`, `provider` and `gate` must
match the caller's enabled rulebook option. Supply the original v2 `offer`,
`access`, `account`, HTTPS `facilitator_url`, `budget`, and all capacity, byte and
time limits explicitly. `journal_key_file` contains exactly 32 nonzero key bytes
and must remain stable for this journal. Optional `authentication_file` contains
a JSON map of header names to string values; replacing these credentials does
not change the account identity. Both files are operator inputs, never member
request fields. The required tariff `coverage` is `all_accepted_requests`:
the operator attests that its sourced bound covers every accepted request and
every protocol phase, including failures. Descriptive tariff `scope` alone
does not restrict destinations or establish coverage.

The member reads `payment_offer`, signs its exact original terms, then submits
the payload, option and lowered fee budget to `payment_plan`. Its preview
returns the operation and one-use authorization without dispatch. Explicit
`payment_execute` supplies both values unchanged. `payment_status` reads the
minimal own outcome; `payment_accept` consumes retained genuine paid access
through the configured community gate. `payment_simulate` accepts separate
dummy inputs and produces no usable production payment fact.

Planning and simulation have no provider I/O. Execution consumes the exact
prepared consent and original live member/session/key/policy binding. Each
original protocol phase runs a genuine current authorization check after
awaited reservation work. Clock observations survive the Journal/transport
boundary, and the original monotonic ceremony limit is checked after samples.
These are fresh host observations, not an engine-atomic policy/clock lease.
A late reservation or uncertain settlement retains exposure and never rearms
the same operation. Single-option execution provides no automatic fallback.

The caller applies `state::SCHEMA` in its complete migration history. The host
atomically binds the journal to the maintained domain commitment for the exact
scope/provider/account/endpoint/mode and stable key. Replaceable authentication
tokens are excluded; changed namespace/key refuses existing state. This equality
commitment does not authenticate a provider account or establish payment.

Durable records contain only the approved local opaque binding, keyed operation,
request and receipt identities, revision/outcome/validity and operator fee
exposure/provenance. They do not contain the signed member payload, principal,
offer, wallet/payer, raw chain network/transaction, provider reply or checkout
handover. `Record::without_continuation` preserves actual domain metadata while
dropping native continuation from persistence. This tranche has no ReceiptReader
or observation API, so the host retains no continuation cache either. Native
references die with the transient domain record.

Raw request buffers remain in bounded RAM only while Prepared. First authorized
execution moves the actual Instruction into its future. Completion, error and
cancellation drop its private buffers; Running/Finished state keeps only minimal
operation/context information and a genuine sealed PaidAccess when available.
The static caller-owned configured offer remains available for future planning.
Upstream parsing/HTTP libraries may make temporary copies; host swap/dumps and
perfect process-memory erasure are outside this application's guarantee.

After restart, fresh genuine own-member authentication can inspect minimal
durable settlement/uncertainty. Missing original RAM terms cannot mint access or
trigger another settlement. Reconciliation is unsupported without an original
trusted ReceiptReader; neither a transaction string nor arbitrary JSON replaces
that authority. Unknown fees retain the maximum. Reported over-bound/foreign-unit
fees poison further journal reservations rather than fabricating a conversion.

Only the genuine domain paid-access projection enters `cgts::PaidAccessGate`.
It checks exact level, current period, original scope/member/action and provider;
the existing gatekeeper owns atomic receipt consumption and UTC-day retention.
Short intervals cannot be extended. Existing maximum-proof-age refusal remains
because these facts provide no authenticated original proof timestamp.
Acceptance rechecks the original key/session and policy after its final awaited
status read, then checks the retained clock floor and original ceremony lifetime.
The member receives only requested level/period plus minimal operation outcome;
original x402 offer negotiation and explicit fee consent precede dispatch.

Authored tests use actual libSQL, the actual payment/protocol executor, inert
external transport and genuine WebAuthn/signed passport/community credential
fixtures. They cover restart/retry, uncertainty/cancellation, concurrent budget,
exact consent/ownership, configuration identity, real key revocation after
reservation/discovery, simulation separation and no raw durable data. Owned-state
unit tests inspect the actual Flow's removed Instruction after terminal results
and cancellation. The HTTP identity fixture uses the separately guarded
development global gate; the paid adapter itself runs in Production mode.

Formatting, whitespace and manifest parsing checks passed during authoring.
Compilation, Rust tests, coverage, generated schemas and live vendor/chain
qualification remain unexecuted. No provider calls or spending were performed.
