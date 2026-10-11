# Explicit community creation composition

`cvld serve platform --config FILE` is the configured launcher. FILE names the
global configuration and the community configurations (`global_config`,
`community_configs`); every community must share the global domain, a unique
name and a distinct bind address. The launcher constructs the original Global
Door and each target Community Door in one process and calls
`global.link_community_creation(&target).await` for each; no server is exposed
until every link validates and every bind succeeds. A library caller may do the
same composition itself. It does not provision a database, deploy a service, or
infer an administrative control plane. A target that is not listed refuses
creation. Separate `serve global` and `serve community` processes cannot create.
The Global platform Root uses its original `api.admin.root.<domain>` passkey
session. A target recipient uses its own member host and a genuine first
registration bound to its verified passport presentation.

The target member calls `community_creation_recipient` with an explicit
`expires_at`. Omit `id` for the first preparation, then retain the returned
original UUID and expiry for recovery. The host bounds these terms by the
actual target session and authenticated Policy deadline. Its returned opaque
`recipient` references only that exact target session and those immutable
terms. It never contains a bearer token, target user UUID, or Global identity.

The authorized Global Root calls `community_creation_initialize` with the
explicitly linked community name and that recipient reference. Root Auth and
the original Root credential database writer remain held while the actual
target Policy signs and verifies the original CVCH BootstrapRoot invitation
and Membership initializes its exact Creating tuple under its own writer.
Current target key, legal state, session, Policy and original deadlines are
checked. Public factories refuse incompatible same-file migration histories;
the original bounded writer acquisition also refuses physical database
contention without guessing database identity from URLs or handles.

The response contains the original signed invitation, ID, expiry and actual
checked time. It grants no membership or Root role. The recipient includes
these exact invitation bytes as `creation` in the existing `credential_issue`
request, with a fresh genuine passport presentation and every configured
admission gate. The original domain transaction joins the one-use receipt,
Register Root, enrolment, probation and Active phase. No ordinary role setter
substitutes for that redemption. FounderAdmin has its own purpose below; this route never issues it.

References are bounded RAM state and single use. Cancellation or restart drops
them; no session, raw COSE or producer payload is journaled. A lost/late commit
returns `reconcile` and never implies that Creating rolled back. With new
genuine current target and Root authorization, prepare again using the SAME
original ID and expiry, then request a newly signed invitation. The original
receipt, recipient binding and exclusive expiry must match the retained tuple;
different terms refuse. Expiry is never renewed and Creating is never reset.
Callers must retain their original public terms before requesting initialization.

Source-reviewed lower storage and target-owner tests are distinct from actual
GlobalRoot HTTP qualification. New host tests require the current composed
dependency graph and execution before a functioning-production claim.

## FounderAdmin

A distinct founder prepares with `purpose: "founder"` in
`community_creation_recipient`. The purpose is fixed in the single-use
reference; a Root reference cannot be initialized as a founder and the reverse
refuses. Only a member still joining (`PasskeyRegistered`, `HandleReserved` or
`GatesInProgress`) may prepare; an admitted or lapsed member is never promoted.

The Global Root calls `community_founder_issue`, with the same Root Auth and
original Root writer discipline as creation. The target must already be
`Active` (or explicitly `LegacyActive`): it admits nobody while Creating. Nothing
is committed by issuance; the target Policy signs the original CVCH
`FounderAdmin` invitation for that exact member binding and the current Root
session is rechecked afterwards.

The founder redeems it in `credential_issue` as `founder`, never together with
`creation` or a root-board challenge. The original admission verifies the same
passport and every configured gate, then the lower owner writes the one-use
receipt, RegisterAdmin and the exact effect under one writer. An exact retry is
read-only and never regrants; it cannot extend the original lease.
