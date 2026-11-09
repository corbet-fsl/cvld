//! Why an `initial_creation` request was refused with 401 (journey row 13, 2026-11-09: a
//! restarted device got 401 from `initial_creation` and nothing named the check).
//!
//! The refusing check notes its [`Reason`] in a request-scoped slot; the HTTP route of the
//! action writes ONE line when the request ends in `Unauthorized`:
//!
//! `refusal action=initial_creation reason=<reason> member=<h12|-> session=<h12|->`
//!
//! The ids are the first 12 hex digits of a domain-separated SHA-256 of the member's UUID and
//! of the session id, never the values themselves. Tokens, keys, credentials and request
//! bodies never reach a note: a note takes only a reason and those two ids.
//!
//! Like `redact_at`, the line is written only under the development gate (toy and test
//! services): a default build keeps no identifier or timing logs and prints nothing. The wire
//! format, the status codes and the API are unchanged: a note never changes an outcome.
use sha2::{Digest, Sha256};
use std::cell::RefCell;

/// The check that refused. The first note of a request wins: it is the innermost check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Reason {
    /// The request carried no bearer token.
    NoToken,
    /// No session for the token (never issued, logged out, or lost with a restart).
    SessionMissing,
    /// The token's session existed and the expiry of a family member ended the family.
    FamilyEnded,
    /// The session's grant had expired at the request's time.
    SessionExpired,
    /// The session starts after the request's time.
    SessionNotStarted,
    /// A garden session used outside the garden.
    GardenSession,
    /// The passkey of the session's credential is revoked or gone.
    CredentialRevoked,
    /// The passkey store could not be read.
    PasskeyStore,
    /// The membership facade could not confirm the device session.
    MembershipCheck,
    /// The membership facade says the session is no longer active.
    SessionInactive,
    /// The clock is below a time this request already observed.
    ClockBehind,
    /// The request outlived its monotonic deadline.
    DeadlinePassed,
    /// A time outside the representable range.
    TimeInvalid,
    /// The session changed or ended while the request ran.
    SessionChanged,
    /// The enrollment state is not current at the checked time.
    StateNotCurrent,
}

impl Reason {
    fn name(self) -> &'static str {
        match self {
            Self::NoToken => "no_token",
            Self::SessionMissing => "session_missing",
            Self::FamilyEnded => "family_ended",
            Self::SessionExpired => "session_expired",
            Self::SessionNotStarted => "session_not_started",
            Self::GardenSession => "garden_session",
            Self::CredentialRevoked => "credential_revoked",
            Self::PasskeyStore => "passkey_store",
            Self::MembershipCheck => "membership_check",
            Self::SessionInactive => "session_inactive",
            Self::ClockBehind => "clock_behind",
            Self::DeadlinePassed => "deadline_passed",
            Self::TimeInvalid => "time_invalid",
            Self::SessionChanged => "session_changed",
            Self::StateNotCurrent => "state_not_current",
        }
    }
}

/// The actions whose 401 is written.
const LOGGED: &[&str] = &["initial_creation"];

#[derive(Clone, Copy)]
struct Note {
    reason: Reason,
    member: Option<[u8; 6]>,
    session: Option<[u8; 6]>,
}

tokio::task_local! {
    static SLOT: RefCell<Option<Note>>;
}

fn short(domain: &[u8], value: &[u8]) -> [u8; 6] {
    let digest = Sha256::new()
        .chain_update(b"cvld.refusal.v1\0")
        .chain_update(domain)
        .chain_update([0])
        .chain_update(value)
        .finalize();
    let mut out = [0; 6];
    out.copy_from_slice(&digest[..6]);
    out
}

fn store(note: Note) {
    let _ = SLOT.try_with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.is_none() {
            *slot = Some(note);
        }
    });
}

/// Note the refusing check, without ids.
pub(crate) fn note(reason: Reason) {
    store(Note {
        reason,
        member: None,
        session: None,
    });
}

/// Note the refusing check with the member and the session it concerned.
pub(crate) fn note_for(reason: Reason, member: &uuid::Uuid, session: &[u8; 32]) {
    store(Note {
        reason,
        member: Some(short(b"member", member.as_bytes())),
        session: Some(short(b"session", session)),
    });
}

/// `Err` with the reason noted, for `ok_or_else`/`map_err` sites.
pub(crate) fn refuse(reason: Reason) -> crate::error::Error {
    note(reason);
    crate::error::Error::Unauthorized
}

fn hex(bytes: Option<[u8; 6]>) -> String {
    match bytes {
        Some(bytes) => bytes.iter().map(|b| format!("{b:02x}")).collect(),
        None => "-".into(),
    }
}

fn line(action: &str, note: Option<Note>) -> String {
    match note {
        Some(note) => format!(
            "refusal action={action} reason={} member={} session={}",
            note.reason.name(),
            hex(note.member),
            hex(note.session)
        ),
        None => format!("refusal action={action} reason=unnoted member=- session=-"),
    }
}

#[cfg(test)]
thread_local! {
    /// The lines written on this thread (a `#[tokio::test]` runs its tasks on the test's thread).
    pub(crate) static WRITTEN: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
}

#[allow(unused_variables)]
fn write(text: String) {
    #[cfg(feature = "development-gate")]
    eprintln!("{text}");
    #[cfg(test)]
    WRITTEN.with(|written| written.borrow_mut().push(text));
}

/// Run one request of `action`; when it ends in `Unauthorized` and the action is logged, write
/// its one refusal line. The outcome is returned unchanged.
pub(crate) async fn scope<T>(
    action: &'static str,
    request: impl std::future::Future<Output = crate::error::Result<T>>,
) -> crate::error::Result<T> {
    SLOT.scope(RefCell::new(None), async move {
        let result = request.await;
        if matches!(result, Err(crate::error::Error::Unauthorized)) && LOGGED.contains(&action) {
            write(line(action, SLOT.with(|slot| *slot.borrow())));
        }
        result
    })
    .await
}

#[cfg(test)]
pub(crate) mod tests;
