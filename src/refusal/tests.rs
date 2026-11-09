//! One line per refused request, the reason it names, and nothing secret in it.
use super::*;
use crate::error::Error;

const ALL: [Reason; 15] = [
    Reason::NoToken,
    Reason::SessionMissing,
    Reason::FamilyEnded,
    Reason::SessionExpired,
    Reason::SessionNotStarted,
    Reason::GardenSession,
    Reason::CredentialRevoked,
    Reason::PasskeyStore,
    Reason::MembershipCheck,
    Reason::SessionInactive,
    Reason::ClockBehind,
    Reason::DeadlinePassed,
    Reason::TimeInvalid,
    Reason::SessionChanged,
    Reason::StateNotCurrent,
];

/// Exhaustive: a new reason must be added to `ALL` (its index) or this does not compile.
fn index(reason: Reason) -> usize {
    match reason {
        Reason::NoToken => 0,
        Reason::SessionMissing => 1,
        Reason::FamilyEnded => 2,
        Reason::SessionExpired => 3,
        Reason::SessionNotStarted => 4,
        Reason::GardenSession => 5,
        Reason::CredentialRevoked => 6,
        Reason::PasskeyStore => 7,
        Reason::MembershipCheck => 8,
        Reason::SessionInactive => 9,
        Reason::ClockBehind => 10,
        Reason::DeadlinePassed => 11,
        Reason::TimeInvalid => 12,
        Reason::SessionChanged => 13,
        Reason::StateNotCurrent => 14,
    }
}

/// Lines written on this thread since the last call.
pub(crate) fn taken() -> Vec<String> {
    WRITTEN.with(|written| std::mem::take(&mut *written.borrow_mut()))
}

/// No line carries anything but the fixed words, the reason name and two 12-digit ids.
pub(crate) fn assert_shape(line: &str) {
    let parts: Vec<&str> = line.split(' ').collect();
    assert_eq!(parts.len(), 5, "{line}");
    assert_eq!(parts[0], "refusal");
    assert!(parts[1].starts_with("action="), "{line}");
    assert!(parts[2].starts_with("reason="), "{line}");
    for (part, key) in [(parts[3], "member="), (parts[4], "session=")] {
        let value = part.strip_prefix(key).expect(key);
        assert!(
            value == "-" || (value.len() == 12 && value.bytes().all(|b| b.is_ascii_hexdigit())),
            "{line}"
        );
    }
}

#[tokio::test]
async fn every_reason_writes_its_one_line() {
    for (i, reason) in ALL.into_iter().enumerate() {
        assert_eq!(index(reason), i);
        taken();
        let result: crate::error::Result<()> = scope("initial_creation", async move {
            note(reason);
            // A later, outer check does not replace the innermost one.
            note(Reason::SessionChanged);
            Err(Error::Unauthorized)
        })
        .await;
        assert_eq!(result, Err(Error::Unauthorized));
        let lines = taken();
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert_eq!(
            lines[0],
            format!(
                "refusal action=initial_creation reason={} member=- session=-",
                reason.name()
            )
        );
        assert_shape(&lines[0]);
    }
}

#[tokio::test]
async fn ids_are_short_domain_separated_hashes_and_secrets_never_appear() {
    let member = uuid::Uuid::new_v4();
    let session = [0x5a; 32];
    let token = "tok-0123456789abcdef-secret";
    taken();
    let result: crate::error::Result<()> = scope("initial_creation", async move {
        let _ = token;
        note_for(Reason::SessionExpired, &member, &session);
        Err(Error::Unauthorized)
    })
    .await;
    assert_eq!(result, Err(Error::Unauthorized));
    let lines = taken();
    assert_eq!(lines.len(), 1);
    let line = &lines[0];
    assert_shape(line);
    assert!(line.contains("reason=session_expired"));
    assert_ne!(
        short(b"member", member.as_bytes()),
        short(b"session", member.as_bytes())
    );
    for secret in [
        token.to_owned(),
        member.to_string(),
        member.simple().to_string(),
        "5a5a5a".to_owned(),
    ] {
        assert!(!line.contains(&secret), "{line} contains {secret}");
    }
}

#[tokio::test]
async fn only_a_refused_logged_action_writes_and_outcomes_are_unchanged() {
    taken();
    let ok: crate::error::Result<u8> = scope("initial_creation", async {
        note(Reason::ClockBehind);
        Ok(7)
    })
    .await;
    assert_eq!(ok, Ok(7));
    let other: crate::error::Result<()> = scope("initial_creation", async {
        note(Reason::ClockBehind);
        Err(Error::Unavailable)
    })
    .await;
    assert_eq!(other, Err(Error::Unavailable));
    let unlogged: crate::error::Result<()> = scope("login_finish", async {
        note(Reason::ClockBehind);
        Err(Error::Unauthorized)
    })
    .await;
    assert_eq!(unlogged, Err(Error::Unauthorized));
    assert!(taken().is_empty());
    let unnoted: crate::error::Result<()> =
        scope("initial_creation", async { Err(Error::Unauthorized) }).await;
    assert_eq!(unnoted, Err(Error::Unauthorized));
    assert_eq!(
        taken(),
        vec!["refusal action=initial_creation reason=unnoted member=- session=-".to_owned()]
    );
    // Outside a request scope a note is dropped and nothing panics.
    note(Reason::ClockBehind);
    assert!(taken().is_empty());
}
