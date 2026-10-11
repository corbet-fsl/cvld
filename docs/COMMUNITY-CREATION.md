# Explicit community creation composition

The trusted hosting caller constructs the original Global Door and target
Community Door, then calls `global.link_community_creation(&target).await`.
This links existing owners in one process. It does not provision a database,
deploy a service, or infer an administrative control plane. The ordinary
launcher has not yet installed these links; unlinked targets refuse creation.
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
substitutes for that redemption. FounderAdmin redemption is a separate
remaining slice and is not enabled by this creation route.

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
